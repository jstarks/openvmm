// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Apply task — writes logged pages to their final file offsets.
//!
//! The apply task receives [`ApplyBatch`] items from the log task via a
//! mesh channel. For each batch, it writes all pages to their final file
//! offsets, flushes, and publishes [`applied_lsn`](crate::lsn_watermark::LsnWatermark).
//! The log task reads `applied_lsn` to know when it can advance the
//! log tail.

use crate::AsyncFile;
use crate::cache::PAGE_SIZE;
use crate::error::VhdxError;
use crate::flush::FlushSequencer;
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
/// file offsets, flushes, and publishes `applied_lsn`.
pub(crate) async fn run_apply_task<F: AsyncFile>(
    mut rx: mesh::Receiver<ApplyBatch>,
    file: Arc<F>,
    flush_sequencer: Arc<FlushSequencer>,
    applied_lsn: Arc<LsnWatermark>,
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

        // Write each page to its final file offset.
        let mut write_failed = false;
        for page in &batch.pages {
            if let Err(e) = file.write_at(page.file_offset, page.data.as_slice()).await {
                tracing::warn!(
                    "VHDX apply task: write error at offset {:#x}: {e}",
                    page.file_offset
                );
                write_failed = true;
                break;
            }
        }

        if write_failed {
            // Don't advance applied_lsn — the data isn't durable.
            // The log entry is still valid, so replay on next open will
            // re-apply these pages.
            continue;
        }

        // Flush to make the applied writes durable at their final offsets.
        if let Err(e) = flush_sequencer.flush(file.as_ref()).await {
            tracing::warn!("VHDX apply task: flush error: {e}");
            continue;
        }

        // Publish that everything through this LSN has been applied.
        applied_lsn.advance(lsn);
    }
}
