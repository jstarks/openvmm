// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Log task — a single async task that owns all log state, provides
//! crash-consistent metadata persistence, and applies logged pages to
//! their final file offsets.
//!
//! The log task receives [`LogRequest`] messages via a `mesh` channel. It
//! batches dirty pages into WAL entries using [`LogWriter`], then applies
//! the logged pages to their final file offsets between requests.
//!
//! # Crash Consistency
//!
//! Metadata changes (BAT entries, sector bitmap bits) are journaled before
//! being committed to their final locations. On crash, `replay_log()` restores
//! them.
//!
//! # Interleaved Apply
//!
//! After logging batch N and responding to flush callers, the log task
//! applies a previously-logged batch before waiting for the next request.
//! This ensures flush callers are never blocked behind apply I/O.

use crate::AsyncFile;
use crate::cache::PAGE_SIZE;
use crate::error::VhdxError;
use crate::flush::FlushSequencer;
use crate::format;
use crate::log::DataPage;
use crate::log::LogWriter;
use guid::Guid;
use mesh::rpc::Rpc;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

/// Log completion state constants.
///
/// Each flush creates a **fresh** `Arc<AtomicU8>` per page. The cache
/// stores one clone in `PageData::log_completion`; the `DirtyPage` sent
/// to the log task holds the other clone. Communication is
/// one-directional: the log task stores `LOG_APPLIED` or `LOG_FAILED`,
/// and the cache reads the value on the next flush to learn the outcome.
pub(crate) const LOG_PENDING: u8 = 0;
pub(crate) const LOG_APPLIED: u8 = 1;
pub(crate) const LOG_FAILED: u8 = 2;

/// A request to the log task.
pub(crate) enum LogRequest {
    /// Batch dirty pages into a log entry.
    ///
    /// The Rpc input is a vector of dirty pages. The response is the FSN
    /// after the log entry is durable, or an error.
    Flush(Rpc<Vec<DirtyPage>, Result<u64, VhdxError>>),

    /// Ensure all cached pages with offsets in the given range are fully
    /// applied (written to their final file offsets).
    CleanRange(Rpc<std::ops::Range<u64>, Result<(), VhdxError>>),

    /// Graceful shutdown: flush, apply, clear log GUID.
    Close(Rpc<(), Result<(), VhdxError>>),
}

/// A dirty page to be logged.
pub(crate) struct DirtyPage {
    /// File offset where this page should ultimately be written.
    pub file_offset: u64,
    /// The 4 KiB page data (shared with the cache entry via Arc COW).
    pub data: Arc<[u8; PAGE_SIZE]>,
    /// Completion signal. Created fresh per-page per-flush by the cache.
    /// The log task stores `LOG_APPLIED` after successful apply, or
    /// `LOG_FAILED` on error. The cache reads this on the next flush
    /// to learn whether to re-dirty the page.
    pub state: Arc<AtomicU8>,
    /// If set, the log task must wait for this FSN to complete before
    /// including this page in a log entry. This ensures user data is
    /// flushed to disk BEFORE the BAT update that references it.
    pub pre_log_fsn: Option<u64>,
}

/// A batch of pages that have been logged but not yet applied.
struct LoggedBatch {
    pages: Vec<DirtyPage>,
    fsn: u64,
    /// The writer's head offset after this entry was written.
    /// After applying this batch, tail can advance to this value.
    new_tail: u32,
}

/// Run the log task main loop.
///
/// This function is spawned as an async task by `VhdxFile::open()`.
/// It owns all mutable log state and processes [`LogRequest`] messages.
///
/// After handling each flush request (and responding to callers), the
/// task applies one previously-logged batch before waiting for the next
/// request. This interleaving ensures flush callers are never blocked
/// behind apply I/O.
pub(crate) async fn run_log_task<F: AsyncFile>(
    mut rx: mesh::Receiver<LogRequest>,
    file: Arc<F>,
    mut log_writer: LogWriter,
    flush_sequencer: Arc<FlushSequencer>,
    log_offset: u64,
    log_length: u32,
) {
    let mut pending_apply: VecDeque<LoggedBatch> = VecDeque::new();

    loop {
        // Wait for the next request.
        let request = match rx.recv().await {
            Ok(req) => req,
            Err(_) => {
                // Channel closed (unclean drop). Log task exits.
                // The VHDX file remains dirty — log will be replayed on next open.
                tracing::warn!("VHDX log task: channel closed without close() — file is dirty");
                break;
            }
        };

        match request {
            LogRequest::Flush(rpc) => {
                // NOTE: Group commit (draining multiple queued Flush requests
                // and combining them into a single log entry) is intentionally
                // disabled. Re-enabling it requires solving at least:
                //
                // 1. **Duplicate pages**: Two requests may contain pages for the
                //    same file_offset. Naively extending the page list creates a
                //    log entry with duplicate descriptors. The entry must be
                //    deduplicated so that only the *last* version of each offset
                //    is logged, and earlier duplicates' `state` must be set to
                //    LOG_APPLIED (they were superseded, not failed).
                //
                // 2. **Log overflow**: Each individual flush is sized to fit the
                //    log, but combining N flushes can exceed the log region
                //    capacity. The combined size must be checked against
                //    `LogWriter::free_space()` *before* merging, and requests
                //    that would overflow must be processed in a separate batch.
                //
                // 3. **Close handling**: A Close request arriving during the
                //    drain loop must not be silently dropped — the Close RPC
                //    must be re-queued or handled after the current batch so
                //    the caller gets a response.

                let (pages, response) = rpc.split();

                // Ensure pre_log_fsn constraints are met before logging.
                // flush_through both issues and waits for the flush in a
                // single call, preventing the deadlock that would occur
                // if we only waited without issuing.
                {
                    let max_fsn = pages.iter().filter_map(|p| p.pre_log_fsn).max();
                    if let Some(fsn) = max_fsn {
                        if let Err(e) = flush_sequencer.flush_through(file.as_ref(), fsn).await {
                            for page in &pages {
                                page.state.store(LOG_FAILED, Ordering::Release);
                            }
                            response.complete(Err(VhdxError::Io(std::io::Error::other(format!(
                                "{e}"
                            )))));
                            continue;
                        }
                    }
                }

                // Write log entry.
                let result =
                    write_log_entry(&file, &mut log_writer, &flush_sequencer, &pages).await;

                match &result {
                    Ok(fsn) => {
                        let fsn_val = *fsn;
                        response.complete(Ok(fsn_val));
                        let new_tail = log_writer.head();
                        pending_apply.push_back(LoggedBatch {
                            pages,
                            fsn: fsn_val,
                            new_tail,
                        });
                    }
                    Err(e) => {
                        // On error, signal failure so the cache re-dirties.
                        for page in &pages {
                            page.state.store(LOG_FAILED, Ordering::Release);
                        }
                        response
                            .complete(Err(VhdxError::Io(std::io::Error::other(format!("{e}")))));
                    }
                }

                // After responding to the flush caller, apply one pending batch.
                // This provides interleaved pipelining: apply of batch N
                // happens after logging batch N+1, so the caller is already
                // unblocked.
                if let Some(batch) = pending_apply.pop_front() {
                    let new_tail = batch.new_tail;
                    if let Err(e) = apply_batch(&file, batch).await {
                        tracing::warn!("VHDX log task: apply error: {e}");
                    } else {
                        log_writer.advance_tail(new_tail);
                    }
                }
            }
            LogRequest::CleanRange(rpc) => {
                handle_clean_range(rpc, &file, &mut pending_apply, &mut log_writer).await;
            }
            LogRequest::Close(rpc) => {
                rpc.handle(async |()| {
                    graceful_close(
                        &file,
                        &mut log_writer,
                        &flush_sequencer,
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

/// Handle a CleanRange request by applying all pending batches that
/// overlap the given file offset range.
///
/// Batches must always be applied in order — we cannot skip a
/// non-overlapping batch and apply a later one, because the skipped
/// batch might write to the same offset as the later batch (outside
/// the requested range), and applying out of order would leave stale
/// data at that offset.
///
/// Algorithm: first scan to find the last batch that overlaps the
/// range, then apply all batches from the front through that index.
async fn handle_clean_range<F: AsyncFile>(
    rpc: Rpc<std::ops::Range<u64>, Result<(), VhdxError>>,
    file: &Arc<F>,
    pending_apply: &mut VecDeque<LoggedBatch>,
    log_writer: &mut LogWriter,
) {
    rpc.handle(async |range| {
        // Pass 1: find the index of the last batch that overlaps the range.
        let last_overlapping = pending_apply.iter().rposition(|batch| {
            batch
                .pages
                .iter()
                .any(|p| p.file_offset >= range.start && p.file_offset < range.end)
        });

        // Pass 2: apply all batches from front through last_overlapping (inclusive),
        // preserving order.
        if let Some(last) = last_overlapping {
            for _ in 0..=last {
                let batch = pending_apply.pop_front().unwrap();
                let new_tail = batch.new_tail;
                apply_batch(file, batch).await?;
                log_writer.advance_tail(new_tail);
            }
        }
        Ok(())
    })
    .await;
}

/// Write a log entry for the given dirty pages.
async fn write_log_entry<F: AsyncFile>(
    file: &Arc<F>,
    log_writer: &mut LogWriter,
    flush_sequencer: &Arc<FlushSequencer>,
    pages: &[DirtyPage],
) -> Result<u64, VhdxError> {
    // Build DataPage references for the LogWriter.
    let data_pages: Vec<DataPage<'_>> = pages
        .iter()
        .map(|p| DataPage {
            file_offset: p.file_offset,
            data: &p.data,
        })
        .collect();

    // Write the log entry.
    let _seq = log_writer
        .write_entry(file.as_ref(), &data_pages, &[])
        .await?;

    // Issue a file flush to make the log entry durable, capturing the FSN.
    let fsn = flush_sequencer.flush(file.as_ref()).await?;

    Ok(fsn)
}

/// Apply a logged batch by writing pages to their final file offsets.
async fn apply_batch<F: AsyncFile>(file: &Arc<F>, batch: LoggedBatch) -> Result<(), VhdxError> {
    for page in &batch.pages {
        file.write_at(page.file_offset, page.data.as_slice())
            .await?;
        page.state.store(LOG_APPLIED, Ordering::Release);
    }
    // Flush after applying to ensure pages are durable at final offsets.
    file.flush().await?;
    Ok(())
}

/// Graceful close: apply all pending, clear log GUID, flush.
async fn graceful_close<F: AsyncFile>(
    file: &Arc<F>,
    log_writer: &mut LogWriter,
    _flush_sequencer: &Arc<FlushSequencer>,
    pending_apply: &mut VecDeque<LoggedBatch>,
    _log_offset: u64,
    _log_length: u32,
) -> Result<(), VhdxError> {
    // Apply all pending batches.
    while let Some(batch) = pending_apply.pop_front() {
        let new_tail = batch.new_tail;
        apply_batch(file, batch).await?;
        log_writer.advance_tail(new_tail);
    }

    // Clear log GUID in the header: read both headers, find the current one,
    // write a clean header to the non-current slot.
    // Read header 1.
    let mut buf1 = vec![0u8; format::HEADER_SIZE as usize];
    file.read_at(format::HEADER_OFFSET_1, &mut buf1).await?;
    let header1 = format::Header::read_from_prefix(&buf1).ok().map(|(h, _)| h);

    // Read header 2.
    let mut buf2 = vec![0u8; format::HEADER_SIZE as usize];
    file.read_at(format::HEADER_OFFSET_2, &mut buf2).await?;
    let header2 = format::Header::read_from_prefix(&buf2).ok().map(|(h, _)| h);

    // Find the current header (highest valid sequence number).
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

    // Build a clean header with log_guid cleared.
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

    // Write to the non-current header slot.
    let write_offset = if first_header_current {
        format::HEADER_OFFSET_2
    } else {
        format::HEADER_OFFSET_1
    };
    file.write_at(write_offset, &buf).await?;
    file.flush().await?;

    Ok(())
}
