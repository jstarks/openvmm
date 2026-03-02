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

/// Page state constants used with `AtomicU8`.
pub(crate) const PAGE_CLEAN: u8 = 0;
pub(crate) const PAGE_DIRTY: u8 = 1;
pub(crate) const PAGE_IN_LOG: u8 = 2;

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
    /// State flag shared with the cache entry. Transitions InLog → Clean
    /// after the page is applied to its final file offset.
    pub state: Arc<AtomicU8>,
    /// If set, the log task must wait for this FSN to complete before
    /// including this page in a log entry. This ensures user data is
    /// flushed to disk BEFORE the BAT update that references it.
    pub pre_log_fsn: Option<u64>,
}

/// A batch of pages that have been logged but not yet applied.
struct LoggedBatch {
    pages: Vec<DirtyPage>,
    #[allow(dead_code)]
    fsn: u64,
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
                let (pages, response) = rpc.split();
                let mut all_pages = pages;
                let mut responses = vec![response];

                // Group commit: drain queued flush requests without blocking.
                loop {
                    match rx.try_recv() {
                        Ok(LogRequest::Flush(more)) => {
                            let (p, r) = more.split();
                            all_pages.extend(p);
                            responses.push(r);
                        }
                        Ok(LogRequest::CleanRange(clean_rpc)) => {
                            // A CleanRange arrived during group drain — handle it
                            // after we finish logging this batch.
                            handle_clean_range(clean_rpc, &file, &mut pending_apply).await;
                        }
                        Ok(LogRequest::Close(_close_rpc)) => {
                            // Close during group drain — finish logging first,
                            // then we'll handle close on the next loop iteration
                            // (the sender would have dropped, causing recv to fail).
                            // This shouldn't normally happen. Log and continue.
                            tracing::warn!(
                                "VHDX log task: close received during group commit drain"
                            );
                            break;
                        }
                        Err(_) => break,
                    }
                }

                // Wait for any pre_log_fsn constraints before logging.
                for page in &all_pages {
                    if let Some(fsn) = page.pre_log_fsn {
                        flush_sequencer.wait_for_fsn(fsn).await;
                    }
                }

                // Write log entry.
                let result =
                    write_log_entry(&file, &mut log_writer, &flush_sequencer, &all_pages).await;

                match &result {
                    Ok(fsn) => {
                        let fsn_val = *fsn;
                        for r in responses {
                            r.complete(Ok(fsn_val));
                        }
                        pending_apply.push_back(LoggedBatch {
                            pages: all_pages,
                            fsn: fsn_val,
                        });
                    }
                    Err(e) => {
                        // On error, transition pages back to Dirty so they
                        // can be retried.
                        for page in &all_pages {
                            page.state.store(PAGE_DIRTY, Ordering::Release);
                        }
                        let err_msg = format!("{e}");
                        for r in responses {
                            r.complete(Err(VhdxError::Io(std::io::Error::other(err_msg.clone()))));
                        }
                    }
                }

                // After responding to flush callers, apply one pending batch.
                // This provides interleaved pipelining: apply of batch N
                // happens after logging batch N+1, so callers are already
                // unblocked.
                if let Some(batch) = pending_apply.pop_front() {
                    if let Err(e) = apply_batch(&file, batch).await {
                        tracing::warn!("VHDX log task: apply error: {e}");
                    }
                }
            }
            LogRequest::CleanRange(rpc) => {
                handle_clean_range(rpc, &file, &mut pending_apply).await;
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
async fn handle_clean_range<F: AsyncFile>(
    rpc: Rpc<std::ops::Range<u64>, Result<(), VhdxError>>,
    file: &Arc<F>,
    pending_apply: &mut VecDeque<LoggedBatch>,
) {
    rpc.handle(async |range| {
        while let Some(batch) = pending_apply.front() {
            let overlaps = batch
                .pages
                .iter()
                .any(|p| p.file_offset >= range.start && p.file_offset < range.end);
            if overlaps {
                apply_batch(file, pending_apply.pop_front().unwrap()).await?;
            } else {
                break;
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
            data: &*p.data,
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
        page.state.store(PAGE_CLEAN, Ordering::Release);
    }
    // Flush after applying to ensure pages are durable at final offsets.
    file.flush().await?;
    Ok(())
}

/// Graceful close: apply all pending, clear log GUID, flush.
async fn graceful_close<F: AsyncFile>(
    file: &Arc<F>,
    _log_writer: &mut LogWriter,
    _flush_sequencer: &Arc<FlushSequencer>,
    pending_apply: &mut VecDeque<LoggedBatch>,
    _log_offset: u64,
    _log_length: u32,
) -> Result<(), VhdxError> {
    // Apply all pending batches.
    while let Some(batch) = pending_apply.pop_front() {
        apply_batch(file, batch).await?;
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
