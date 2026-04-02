// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Log task — a single async task that owns all log state, provides
//! crash-consistent metadata persistence, and applies logged pages to
//! their final file offsets.
//!
//! The log task receives [`LogRequest`] messages via a `mesh` channel.
//! [`LogRequest::Commit`] is fire-and-forget: the cache sends a batch
//! of dirty pages and moves on. The log task writes WAL entries,
//! releases permits, and publishes `logged_through_lsn`. Callers that
//! need durability (e.g., `flush()`) wait on the LSN watermark.
//!
//! # Crash Consistency
//!
//! Metadata changes (BAT entries, sector bitmap bits) are journaled before
//! being committed to their final locations. On crash, `replay_log()` restores
//! them.
//!
//! # Interleaved Apply
//!
//! After logging a batch, the log task applies a previously-logged batch
//! before waiting for the next request. Apply writes pages to their final
//! file offsets and advances the log tail to reclaim space.

use crate::AsyncFile;
use crate::cache::PAGE_SIZE;
use crate::error::VhdxError;
use crate::flush::FlushSequencer;
use crate::format;
use crate::log::DataPage;
use crate::log::LogWriter;
use crate::log_permits::LogPermits;
use crate::lsn_watermark::LsnWatermark;
use guid::Guid;
use mesh::rpc::Rpc;
use std::collections::VecDeque;
use std::sync::Arc;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

/// A request to the log task.
pub(crate) enum LogRequest {
    /// Log a batch of dirty pages (fire-and-forget).
    ///
    /// The cache sends this after collecting dirty pages. No response
    /// is sent — the cache learns about completion via `LogPermits`
    /// (backpressure) and `LsnWatermark` (durability).
    Commit(Transaction),

    /// Graceful shutdown: log and apply all pending batches, clear log GUID.
    Close(Rpc<(), Result<(), VhdxError>>),
}

/// A committed page — file offset + data.
pub(crate) struct CommittedPage {
    /// File offset where this page should ultimately be written.
    pub file_offset: u64,
    /// The 4 KiB page data (shared with the cache via Arc COW).
    pub data: Arc<[u8; PAGE_SIZE]>,
}

/// A batch of dirty pages to be logged atomically.
pub(crate) struct Transaction {
    /// The LSN assigned by the cache at commit time.
    pub lsn: u64,
    /// The pages in this batch.
    pub pages: Vec<CommittedPage>,
    /// If set, the log task must wait for this FSN to complete before
    /// writing the WAL entry. Ensures user data is flushed before the
    /// BAT update that references it.
    pub pre_log_fsn: Option<u64>,
}

/// A batch of pages that have been logged but not yet applied.
struct LoggedBatch {
    pages: Vec<CommittedPage>,
    /// The writer's head offset after this entry was written.
    /// After applying this batch, tail can advance to this value.
    new_tail: u32,
}

/// Run the log task main loop.
///
/// This function is spawned as an async task by `VhdxFile::open_writable()`.
/// It owns all mutable log state and processes [`LogRequest`] messages.
pub(crate) async fn run_log_task<F: AsyncFile>(
    mut rx: mesh::Receiver<LogRequest>,
    file: Arc<F>,
    mut log_writer: LogWriter,
    flush_sequencer: Arc<FlushSequencer>,
    log_permits: Arc<LogPermits>,
    logged_lsn: Arc<LsnWatermark>,
    log_offset: u64,
    log_length: u32,
) {
    let mut pending_apply: VecDeque<LoggedBatch> = VecDeque::new();

    loop {
        let request = match rx.recv().await {
            Ok(req) => req,
            Err(_) => {
                tracing::warn!("VHDX log task: channel closed without close() — file is dirty");
                break;
            }
        };

        match request {
            LogRequest::Commit(txn) => {
                handle_commit(
                    txn,
                    &file,
                    &mut log_writer,
                    &flush_sequencer,
                    &log_permits,
                    &logged_lsn,
                    &mut pending_apply,
                )
                .await;
            }
            LogRequest::Close(rpc) => {
                rpc.handle(async |()| {
                    graceful_close(
                        &file,
                        &mut log_writer,
                        &flush_sequencer,
                        &log_permits,
                        &logged_lsn,
                        &mut pending_apply,
                        log_offset,
                        log_length,
                    )
                    .await
                })
                .await;
                break;
            }
        }
    }
}

/// Handle a Commit request: write WAL entry, release permits, publish LSN.
async fn handle_commit<F: AsyncFile>(
    txn: Transaction,
    file: &Arc<F>,
    log_writer: &mut LogWriter,
    flush_sequencer: &Arc<FlushSequencer>,
    log_permits: &LogPermits,
    logged_lsn: &LsnWatermark,
    pending_apply: &mut VecDeque<LoggedBatch>,
) {
    let page_count = txn.pages.len();
    let lsn = txn.lsn;

    // Ensure pre_log_fsn constraint is met before logging.
    if let Some(fsn) = txn.pre_log_fsn {
        if let Err(e) = flush_sequencer.flush_through(file.as_ref(), fsn).await {
            tracing::error!("VHDX log task: pre_log_fsn flush failed: {e}");
            log_permits.fail(format!("pre_log_fsn flush failed: {e}"));
            return;
        }
    }

    // Write WAL entry.
    match write_log_entry(file, log_writer, flush_sequencer, &txn.pages).await {
        Ok(()) => {
            // Release permits — the pages are now in the WAL.
            log_permits.release(page_count);
            // Publish that this LSN is durable in the log.
            logged_lsn.advance(lsn);

            let new_tail = log_writer.head();
            pending_apply.push_back(LoggedBatch {
                pages: txn.pages,
                new_tail,
            });
        }
        Err(e) => {
            tracing::error!("VHDX log task: WAL write failed: {e}");
            log_permits.fail(format!("WAL write failed: {e}"));
            return;
        }
    }

    // Interleaved apply: apply one previously-logged batch.
    if let Some(batch) = pending_apply.pop_front() {
        let new_tail = batch.new_tail;
        if let Err(e) = apply_batch(file, flush_sequencer, batch).await {
            tracing::warn!("VHDX log task: apply error: {e}");
        } else {
            log_writer.advance_tail(new_tail);
        }
    }
}

/// Write a log entry for the given pages.
async fn write_log_entry<F: AsyncFile>(
    file: &Arc<F>,
    log_writer: &mut LogWriter,
    flush_sequencer: &Arc<FlushSequencer>,
    pages: &[CommittedPage],
) -> Result<(), VhdxError> {
    let data_pages: Vec<DataPage<'_>> = pages
        .iter()
        .map(|p| DataPage {
            file_offset: p.file_offset,
            data: &p.data,
        })
        .collect();

    let _seq = log_writer
        .write_entry(file.as_ref(), &data_pages, &[])
        .await?;

    // Flush to make the log entry durable.
    flush_sequencer.flush(file.as_ref()).await?;

    Ok(())
}

/// Apply a logged batch by writing pages to their final file offsets.
async fn apply_batch<F: AsyncFile>(
    file: &Arc<F>,
    flush_sequencer: &FlushSequencer,
    batch: LoggedBatch,
) -> Result<(), VhdxError> {
    for page in &batch.pages {
        file.write_at(page.file_offset, page.data.as_slice())
            .await?;
    }
    flush_sequencer.flush(file.as_ref()).await?;
    Ok(())
}

/// Graceful close: log + apply all pending, clear log GUID, flush.
async fn graceful_close<F: AsyncFile>(
    file: &Arc<F>,
    log_writer: &mut LogWriter,
    flush_sequencer: &Arc<FlushSequencer>,
    log_permits: &LogPermits,
    logged_lsn: &LsnWatermark,
    pending_apply: &mut VecDeque<LoggedBatch>,
    _log_offset: u64,
    _log_length: u32,
) -> Result<(), VhdxError> {
    // Apply all pending batches.
    while let Some(batch) = pending_apply.pop_front() {
        let new_tail = batch.new_tail;
        apply_batch(file, flush_sequencer, batch).await?;
        log_writer.advance_tail(new_tail);
    }

    // Clear log GUID in the header.
    let mut buf1 = vec![0u8; format::HEADER_SIZE as usize];
    file.read_at(format::HEADER_OFFSET_1, &mut buf1).await?;
    let header1 = format::Header::read_from_prefix(&buf1).ok().map(|(h, _)| h);

    let mut buf2 = vec![0u8; format::HEADER_SIZE as usize];
    file.read_at(format::HEADER_OFFSET_2, &mut buf2).await?;
    let header2 = format::Header::read_from_prefix(&buf2).ok().map(|(h, _)| h);

    let (current_header, first_header_current) = match (&header1, &header2) {
        (Some(h1), Some(h2)) => {
            if h2.sequence_number >= h1.sequence_number {
                (h2.clone(), false)
            } else {
                (h1.clone(), true)
            }
        }
        (Some(h1), None) => (h1.clone(), true),
        (None, Some(h2)) => (h2.clone(), false),
        (None, None) => {
            return Err(VhdxError::Io(std::io::Error::other(
                "no valid header found during close",
            )));
        }
    };

    let mut clean_header = format::Header::new_zeroed();
    clean_header.signature = format::HEADER_SIGNATURE;
    clean_header.sequence_number = current_header.sequence_number + 1;
    clean_header.file_write_guid = current_header.file_write_guid;
    clean_header.data_write_guid = current_header.data_write_guid;
    clean_header.log_guid = Guid::ZERO;
    clean_header.log_version = format::LOG_VERSION;
    clean_header.version = format::VERSION_1;
    clean_header.log_length = current_header.log_length;
    clean_header.log_offset = current_header.log_offset;
    clean_header.checksum = 0;

    let mut buf = vec![0u8; format::HEADER_SIZE as usize];
    let hdr_bytes = clean_header.as_bytes();
    buf[..hdr_bytes.len()].copy_from_slice(hdr_bytes);
    let crc = format::compute_checksum(&buf, 4);
    buf[4..8].copy_from_slice(&crc.to_le_bytes());

    let write_offset = if first_header_current {
        format::HEADER_OFFSET_2
    } else {
        format::HEADER_OFFSET_1
    };
    file.write_at(write_offset, &buf).await?;
    file.flush().await?;

    Ok(())
}
