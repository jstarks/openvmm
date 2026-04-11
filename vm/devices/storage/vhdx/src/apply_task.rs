// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Apply task — writes logged pages to their final file offsets.
//!
//! The apply task receives [`ApplyBatch`] items from the log task via a
//! mesh channel. For each batch, it writes all pages to their final file
//! offsets, **releases log permits**, and publishes `applied_lsn` with
//! the flush sequence number (FSN) needed to make the writes durable.
//!
//! The apply task does **not** flush. Flushing is driven by consumers
//! who need durability:
//! - The log task flushes when it needs to advance the log tail
//!   (on `LogFull` or graceful close).
//! - `VhdxFile::flush()` flushes for crash safety.
//!
//! Both callers use `flush_sequencer.flush_through(fsn)` with the FSN
//! from the watermark, which coalesces naturally.

use crate::AsyncFile;
use crate::cache::PAGE_SIZE;
use crate::flush::FlushSequencer;
use crate::log_permits::LogPermits;
use crate::lsn_watermark::LsnWatermark;
use crate::open::FailureFlag;
use std::sync::Arc;

/// A batch of pages that have been logged and need to be applied
/// (written to their final file offsets).
pub(crate) struct ApplyBatch {
    /// The pages to write.
    pub pages: Vec<ApplyPage>,
    /// The LSN of the log entry that contains these pages.
    pub lsn: u64,
}

/// A single page to apply.
pub(crate) struct ApplyPage {
    /// Final file offset where this page should be written.
    pub file_offset: u64,
    /// The 4 KiB page data.
    pub data: Arc<[u8; PAGE_SIZE]>,
}

/// Run the apply task main loop.
///
/// Receives batches from the log task, writes pages to their final
/// file offsets, releases log permits, and publishes `applied_lsn`
/// with the FSN needed for durability.
pub(crate) async fn run_apply_task<F: AsyncFile>(
    mut rx: mesh::Receiver<ApplyBatch>,
    file: Arc<F>,
    flush_sequencer: Arc<FlushSequencer>,
    applied_lsn: Arc<LsnWatermark>,
    log_permits: Arc<LogPermits>,
    failure_flag: Arc<FailureFlag>,
) {
    loop {
        let batch = match rx.recv().await {
            Ok(batch) => batch,
            Err(_) => {
                // Channel closed — log task shut down. Exit.
                break;
            }
        };

        let lsn = batch.lsn;
        let page_count = batch.pages.len();

        // Write each page to its final file offset.
        for page in &batch.pages {
            if let Err(e) = file.write_at(page.file_offset, page.data.as_slice()).await {
                tracing::error!(
                    "VHDX apply task: write error at offset {:#x}: {e}",
                    page.file_offset
                );
                drop(batch);
                log_permits.release(page_count);
                log_permits.fail(format!("apply write failed: {e}"));
                applied_lsn.fail(format!("apply write failed: {e}"));
                failure_flag.set(&e);
                return;
            }
        }

        // Drop the batch to free the Arc page data BEFORE releasing
        // permits. Permits bound memory — they must not be released
        // while the data is still held.
        drop(batch);
        log_permits.release(page_count);

        // Capture the FSN *after* the writes. Flushing through this FSN
        // will make all the writes above durable. We don't flush here —
        // the log task or VhdxFile::flush() will do it when needed.
        let fsn = flush_sequencer.current_fsn();

        // Publish (lsn, fsn): "pages through this LSN are at their final
        // offsets; flush through this FSN to make them durable."
        applied_lsn.advance(lsn, fsn);
    }
}
