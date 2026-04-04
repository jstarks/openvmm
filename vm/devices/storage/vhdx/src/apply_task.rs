// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Apply task — writes logged pages to their final file offsets.
//!
//! The apply task receives [`ApplyBatch`] items from the log task via a
//! mesh channel. For each batch, it writes all pages to their final file
//! offsets, flushes, publishes [`applied_lsn`](crate::lsn_watermark::LsnWatermark),
//! and **releases log permits**.
//!
//! Permits are released here — not at commit time and not by the log
//! task — because the apply task is where the `Arc<[u8; PAGE_SIZE]>`
//! data is finally consumed and can be freed. This bounds memory
//! usage in the cache → log → apply pipeline.

use crate::AsyncFile;
use crate::cache::PAGE_SIZE;
use crate::flush::FlushSequencer;
use crate::log_permits::LogPermits;
use crate::lsn_watermark::LsnWatermark;
use std::sync::Arc;

/// A batch of pages that have been logged and need to be applied
/// (written to their final file offsets).
pub(crate) struct ApplyBatch {
    /// The pages to write.
    pub pages: Vec<ApplyPage>,
    /// The LSN of the log entry that contains these pages.
    pub lsn: u64,
    /// The log-region-relative offset after this entry was written.
    /// The log task can advance its tail to this value once applied.
    pub new_tail: u32,
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
/// file offsets, flushes, publishes `applied_lsn`, and releases
/// log permits.
pub(crate) async fn run_apply_task<F: AsyncFile>(
    mut rx: mesh::Receiver<ApplyBatch>,
    file: Arc<F>,
    flush_sequencer: Arc<FlushSequencer>,
    applied_lsn: Arc<LsnWatermark>,
    log_permits: Arc<LogPermits>,
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
                return;
            }
        }

        // Drop the batch to free the Arc page data BEFORE releasing
        // permits. Permits bound memory — they must not be released
        // while the data is still held.
        drop(batch);

        // Release permits now — writes are complete and Arcs are freed.
        // We don't wait for the flush: permits bound memory, not
        // durability. The flush below is about making the data durable
        // at final offsets so the log tail can advance.
        log_permits.release(page_count);

        // Flush to make the applied writes durable at their final offsets.
        if let Err(e) = flush_sequencer.flush(file.as_ref()).await {
            tracing::error!("VHDX apply task: flush error: {e}");
            log_permits.fail(format!("apply flush failed: {e}"));
            applied_lsn.fail(format!("apply flush failed: {e}"));
            return;
        }

        // Publish that everything through this LSN has been applied.
        applied_lsn.advance(lsn);
    }
}
