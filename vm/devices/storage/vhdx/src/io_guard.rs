// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! I/O guards for trim-safe block lifecycle management.
//!
//! [`ReadIoGuard`] and [`WriteIoGuard`] are returned by
//! [`VhdxFile::resolve_read`] and [`VhdxFile::resolve_write`].
//! These guards hold per-block refcounts that prevent `trim()` from
//! freeing blocks during active I/O.

use crate::AsyncFile;
use crate::bat::BatGuard;
use crate::error::VhdxError;
use crate::io::WriteCompletionRecords;
use crate::open::VhdxFile;

/// Guard for read I/O. Drop after file reads are complete.
///
/// Returned by [`VhdxFile::resolve_read`]. Dropping this guard decrements
/// per-block refcounts, allowing trim to proceed.
pub struct ReadIoGuard<'a, F: AsyncFile> {
    // Significant drop.
    _bat_guard: BatGuard<'a>,
    _phantom: std::marker::PhantomData<&'a VhdxFile<F>>,
}

impl<'a, F: AsyncFile> ReadIoGuard<'a, F> {
    /// Create a new read guard with refcount tracking.
    pub(crate) fn new(bat_guard: BatGuard<'a>) -> Self {
        Self {
            _bat_guard: bat_guard,
            _phantom: std::marker::PhantomData,
        }
    }

    pub(crate) fn empty() -> Self {
        Self {
            _bat_guard: BatGuard::empty(),
            _phantom: std::marker::PhantomData,
        }
    }
}

/// Guard for write I/O. Call [`complete()`](Self::complete) to finalize,
/// or drop to abort.
///
/// Returned by [`VhdxFile::resolve_write`]. Dropping without calling
/// `complete()` aborts the write, reverting TFP blocks and releasing
/// allocated space. In both cases, per-block refcounts are decremented
/// via the owned [`ReadIoGuard`].
pub struct WriteIoGuard<'a, F: AsyncFile> {
    vhdx: &'a VhdxFile<F>,
    // Significant drop.
    _bat_guard: BatGuard<'a>,
    /// The guest offset of the write (needed for SBM bitmap updates).
    offset: u64,
    /// The length of the write in bytes.
    len: u32,
    /// Whether `complete()` was called. If false on drop, the write is aborted.
    completed: bool,
    /// True when at least one TFP block was allocated from space that is
    /// NOT safe (could contain stale data from another block). When true,
    /// `complete_write_inner` must capture the current FSN and apply it
    /// to the BAT pages so the log task waits for the data flush before
    /// logging the BAT update.
    ///
    /// Matches C's `NeedsFlushDuringPostAllocate` flag.
    needs_flush_before_log: bool,
    /// TFP records collected during resolve_write, needed by complete/abort.
    /// `None` after complete() or for zero-length writes.
    records: Option<WriteCompletionRecords>,
}

impl<'a, F: AsyncFile> WriteIoGuard<'a, F> {
    /// Create a new write guard that takes ownership of a [`ReadIoGuard`]
    /// for refcount management.
    pub(crate) fn new(
        vhdx: &'a VhdxFile<F>,
        bat_guard: BatGuard<'a>,
        offset: u64,
        len: u32,
        needs_flush_before_log: bool,
        records: WriteCompletionRecords,
    ) -> Self {
        Self {
            vhdx,
            _bat_guard: bat_guard,
            offset,
            len,
            completed: false,
            needs_flush_before_log,
            records: Some(records),
        }
    }

    /// Create a write guard that is already completed (for zero-length writes).
    pub(crate) fn new_completed(vhdx: &'a VhdxFile<F>) -> Self {
        Self {
            vhdx,
            _bat_guard: BatGuard::empty(),
            offset: 0,
            len: 0,
            completed: true,
            needs_flush_before_log: false,
            records: None,
        }
    }

    /// Create a write guard with no completion records (no allocation was
    /// needed — all blocks were already FullyPresent or PartiallyPresent
    /// with a sub-block write).
    pub(crate) fn new_no_alloc(
        vhdx: &'a VhdxFile<F>,
        bat_guard: BatGuard<'a>,
        offset: u64,
        len: u32,
    ) -> Self {
        Self {
            vhdx,
            _bat_guard: bat_guard,
            offset,
            len,
            completed: false,
            needs_flush_before_log: false,
            records: None,
        }
    }

    /// Finalize the write after data has been written to resolved ranges.
    ///
    /// Commits TFP -> FullyPresent, updates sector bitmaps.
    /// Consumes the guard. Refcounts are decremented when `self` is dropped
    /// after this method returns.
    pub async fn complete(mut self) -> Result<(), VhdxError> {
        self.completed = true;
        let records = self.records.take().unwrap_or(WriteCompletionRecords {
            tfp_records: Vec::new(),
        });
        self.vhdx
            .complete_write_inner(self.offset, self.len, records, self.needs_flush_before_log)
            .await
    }
}

impl<F: AsyncFile> Drop for WriteIoGuard<'_, F> {
    fn drop(&mut self) {
        // If complete() was not called, abort the write.
        if !self.completed {
            if let Some(records) = self.records.take() {
                self.vhdx.abort_write_sync(records);
            }
        }
        // Refcounts are decremented when self.bat_guard drops.
    }
}
