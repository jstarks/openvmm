// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! I/O guards for trim-safe block lifecycle management.
//!
//! [`ReadIoGuard`] and [`WriteIoGuard`] are returned by
//! [`VhdxFile::resolve_read`] and [`VhdxFile::resolve_write`].
//! These guards will hold per-block refcounts that prevent `trim()` from
//! freeing blocks during active I/O (refcount tracking added in Step 2).

use crate::AsyncFile;
use crate::error::VhdxError;
use crate::open::VhdxFile;

/// Guard for read I/O. Drop after file reads are complete.
///
/// Returned by [`VhdxFile::resolve_read`]. In the future, dropping this
/// guard decrements per-block refcounts, allowing trim to proceed.
pub struct ReadIoGuard<'a, F: AsyncFile> {
    _vhdx: &'a VhdxFile<F>,
}

impl<'a, F: AsyncFile> ReadIoGuard<'a, F> {
    /// Create a new inert read guard.
    pub(crate) fn new(vhdx: &'a VhdxFile<F>) -> Self {
        Self { _vhdx: vhdx }
    }
}

impl<F: AsyncFile> Drop for ReadIoGuard<'_, F> {
    fn drop(&mut self) {
        // Step 1: no-op. Refcount tracking added in Step 2.
    }
}

/// Guard for write I/O. Call [`complete()`](Self::complete) to finalize,
/// or drop to abort.
///
/// Returned by [`VhdxFile::resolve_write`]. Dropping without calling
/// `complete()` aborts the write, reverting TFP blocks and releasing
/// allocated space.
pub struct WriteIoGuard<'a, F: AsyncFile> {
    vhdx: &'a VhdxFile<F>,
    /// The guest offset of the write (needed for complete_write logic).
    offset: u64,
    /// The length of the write in bytes.
    len: u32,
    /// Whether `complete()` was called. If false on drop, the write is aborted.
    completed: bool,
}

impl<'a, F: AsyncFile> WriteIoGuard<'a, F> {
    /// Create a new write guard.
    pub(crate) fn new(vhdx: &'a VhdxFile<F>, offset: u64, len: u32) -> Self {
        Self {
            vhdx,
            offset,
            len,
            completed: false,
        }
    }

    /// Create a write guard that is already completed (for zero-length writes).
    pub(crate) fn new_completed(vhdx: &'a VhdxFile<F>) -> Self {
        Self {
            vhdx,
            offset: 0,
            len: 0,
            completed: true,
        }
    }

    /// Finalize the write after data has been written to resolved ranges.
    ///
    /// Commits TFP -> FullyPresent, updates sector bitmaps.
    /// Consumes the guard.
    pub async fn complete(mut self) -> Result<(), VhdxError> {
        self.completed = true;
        self.vhdx
            .complete_write_inner(self.offset, self.len, true)
            .await
    }
}

impl<F: AsyncFile> Drop for WriteIoGuard<'_, F> {
    fn drop(&mut self) {
        // If complete() was not called, abort the write.
        if !self.completed {
            self.vhdx.abort_write_sync(self.offset, self.len);
        }
    }
}
