// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! I/O guards for trim-safe block lifecycle management.
//!
//! [`ReadIoGuard`] and [`WriteIoGuard`] are returned by
//! [`VhdxFile::resolve_read`] and [`VhdxFile::resolve_write`].
//! These guards hold per-block refcounts that prevent `trim()` from
//! freeing blocks during active I/O.

use crate::AsyncFile;
use crate::error::VhdxError;
use crate::open::VhdxFile;

/// Guard for read I/O. Drop after file reads are complete.
///
/// Returned by [`VhdxFile::resolve_read`]. Dropping this guard decrements
/// per-block refcounts, allowing trim to proceed.
pub struct ReadIoGuard<'a, F: AsyncFile> {
    vhdx: &'a VhdxFile<F>,
    /// First payload block number with incremented refcount.
    start_block: u32,
    /// Number of consecutive payload blocks with incremented refcounts.
    block_count: u32,
}

impl<'a, F: AsyncFile> ReadIoGuard<'a, F> {
    /// Create a new read guard with refcount tracking.
    pub(crate) fn new(vhdx: &'a VhdxFile<F>, start_block: u32, block_count: u32) -> Self {
        Self {
            vhdx,
            start_block,
            block_count,
        }
    }

    /// The first payload block number tracked by this guard.
    #[cfg(test)]
    pub(crate) fn start_block(&self) -> u32 {
        self.start_block
    }

    /// The number of consecutive payload blocks tracked by this guard.
    #[cfg(test)]
    pub(crate) fn block_count(&self) -> u32 {
        self.block_count
    }
}

impl<F: AsyncFile> Drop for ReadIoGuard<'_, F> {
    fn drop(&mut self) {
        if self.block_count == 0 {
            return;
        }
        let mut bat_state = self.vhdx.bat_state.write();
        let mut any_zero = false;
        for block in self.start_block..self.start_block + self.block_count {
            if bat_state.decrement_io_refcount(block) == 0 {
                any_zero = true;
            }
        }
        drop(bat_state);
        if any_zero {
            self.vhdx.trim_event.notify(usize::MAX);
        }
    }
}

/// Guard for write I/O. Call [`complete()`](Self::complete) to finalize,
/// or drop to abort.
///
/// Returned by [`VhdxFile::resolve_write`]. Dropping without calling
/// `complete()` aborts the write, reverting TFP blocks and releasing
/// allocated space. In both cases, per-block refcounts are decremented.
pub struct WriteIoGuard<'a, F: AsyncFile> {
    vhdx: &'a VhdxFile<F>,
    /// First payload block number with incremented refcount.
    start_block: u32,
    /// Number of consecutive payload blocks with incremented refcounts.
    block_count: u32,
    /// The guest offset of the write (needed for complete_write logic).
    offset: u64,
    /// The length of the write in bytes.
    len: u32,
    /// Whether `complete()` was called. If false on drop, the write is aborted.
    completed: bool,
}

impl<'a, F: AsyncFile> WriteIoGuard<'a, F> {
    /// Create a new write guard with refcount tracking.
    pub(crate) fn new(
        vhdx: &'a VhdxFile<F>,
        offset: u64,
        len: u32,
        start_block: u32,
        block_count: u32,
    ) -> Self {
        Self {
            vhdx,
            start_block,
            block_count,
            offset,
            len,
            completed: false,
        }
    }

    /// Create a write guard that is already completed (for zero-length writes).
    pub(crate) fn new_completed(vhdx: &'a VhdxFile<F>) -> Self {
        Self {
            vhdx,
            start_block: 0,
            block_count: 0,
            offset: 0,
            len: 0,
            completed: true,
        }
    }

    /// Finalize the write after data has been written to resolved ranges.
    ///
    /// Commits TFP -> FullyPresent, updates sector bitmaps.
    /// Consumes the guard. Refcounts are decremented when `self` is dropped
    /// after this method returns.
    pub async fn complete(mut self) -> Result<(), VhdxError> {
        self.completed = true;
        self.vhdx
            .complete_write_inner(self.offset, self.len, true)
            .await
    }
}

impl<F: AsyncFile> Drop for WriteIoGuard<'_, F> {
    fn drop(&mut self) {
        // Decrement refcounts.
        if self.block_count > 0 {
            let mut bat_state = self.vhdx.bat_state.write();
            let mut any_zero = false;
            for block in self.start_block..self.start_block + self.block_count {
                if bat_state.decrement_io_refcount(block) == 0 {
                    any_zero = true;
                }
            }
            drop(bat_state);
            if any_zero {
                self.vhdx.trim_event.notify(usize::MAX);
            }
        }

        // If complete() was not called, abort the write.
        if !self.completed {
            self.vhdx.abort_write_sync(self.offset, self.len);
        }
    }
}
