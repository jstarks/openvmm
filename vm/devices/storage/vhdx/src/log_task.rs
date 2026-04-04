// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Log task — a single async task that owns all log state and provides
//! crash-consistent metadata persistence.
//!
//! The log task receives [`LogRequest`] messages via a `mesh` channel.
//! [`LogRequest::Commit`] is fire-and-forget: the cache sends a batch
//! of dirty pages and moves on. The log task writes WAL entries,
//! releases permits, and publishes `logged_through_lsn`.
//!
//! After logging a batch, the log task sends it to the apply task for
//! writing to final file offsets. The apply task publishes
//! `applied_through_lsn`, which the log task reads to advance its tail.
//!
//! # Crash Consistency
//!
//! Metadata changes (BAT entries, sector bitmap bits) are journaled before
//! being committed to their final locations. On crash, `replay_log()` restores
//! them.

use crate::AsyncFile;
use crate::apply_task::ApplyBatch;
use crate::apply_task::ApplyPage;
use crate::cache::PAGE_SIZE;
use crate::error::CorruptionType;
use crate::error::VhdxError;
use crate::flush::FlushSequencer;
use crate::format;
use crate::log::DataPage;
use crate::log::LogWriter;
use crate::log_permits::LogPermits;
use crate::lsn_watermark::LsnWatermark;
use guid::Guid;
use mesh::rpc::Rpc;
use std::sync::Arc;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

/// A request to the log task.
pub(crate) enum LogRequest {
    /// Log a batch of dirty pages (fire-and-forget).
    Commit(Transaction),

    /// Graceful shutdown: log all pending, wait for apply, clear log GUID.
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
    /// writing the WAL entry.
    pub pre_log_fsn: Option<u64>,
}

/// Tracks a batch that has been sent to the applier but whose tail
/// hasn't been advanced yet.
struct PendingTail {
    /// The LSN of the batch. Once `applied_lsn >= lsn`, the tail
    /// can advance to `new_tail`.
    lsn: u64,
    /// The log-region offset to advance the tail to.
    new_tail: u32,
}

/// Run the log task main loop.
pub(crate) async fn run_log_task<F: AsyncFile>(
    mut rx: mesh::Receiver<LogRequest>,
    file: Arc<F>,
    mut log_writer: LogWriter,
    flush_sequencer: Arc<FlushSequencer>,
    log_permits: Arc<LogPermits>,
    logged_lsn: Arc<LsnWatermark>,
    applied_lsn: Arc<LsnWatermark>,
    apply_tx: mesh::Sender<ApplyBatch>,
    log_offset: u64,
    log_length: u32,
) {
    let mut pending_tails: Vec<PendingTail> = Vec::new();

    loop {
        // Before processing the next request, advance the tail for
        // any batches the applier has completed.
        advance_tails(&mut pending_tails, &applied_lsn, &mut log_writer);

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
                    &applied_lsn,
                    &apply_tx,
                    &mut pending_tails,
                )
                .await;
            }
            LogRequest::Close(rpc) => {
                rpc.handle(async |()| {
                    graceful_close(
                        &file,
                        &mut log_writer,
                        &flush_sequencer,
                        &applied_lsn,
                        &mut pending_tails,
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

/// Advance the log tail for all batches whose LSN has been applied.
fn advance_tails(
    pending_tails: &mut Vec<PendingTail>,
    applied_lsn: &LsnWatermark,
    log_writer: &mut LogWriter,
) {
    let applied = applied_lsn.get();
    // Pending tails are in LSN order. Advance all that are <= applied.
    while let Some(front) = pending_tails.first() {
        if front.lsn <= applied {
            log_writer.advance_tail(front.new_tail);
            pending_tails.remove(0);
        } else {
            break;
        }
    }
}

/// Handle a Commit request: write WAL entry, publish LSN, send batch to applier.
/// If the log is full, waits for the applier to drain space and retries.
async fn handle_commit<F: AsyncFile>(
    txn: Transaction,
    file: &Arc<F>,
    log_writer: &mut LogWriter,
    flush_sequencer: &Arc<FlushSequencer>,
    log_permits: &LogPermits,
    logged_lsn: &LsnWatermark,
    applied_lsn: &LsnWatermark,
    apply_tx: &mesh::Sender<ApplyBatch>,
    pending_tails: &mut Vec<PendingTail>,
) {
    let lsn = txn.lsn;

    // Ensure pre_log_fsn constraint is met before logging.
    if let Some(fsn) = txn.pre_log_fsn {
        if let Err(e) = flush_sequencer.flush_through(file.as_ref(), fsn).await {
            tracing::error!("VHDX log task: pre_log_fsn flush failed: {e}");
            log_permits.fail(format!("pre_log_fsn flush failed: {e}"));
            return;
        }
    }

    // Write WAL entry, retrying if the log is full.
    loop {
        match write_log_entry(file, log_writer, flush_sequencer, &txn.pages).await {
            Ok(()) => break,
            Err(VhdxError::Corrupt(CorruptionType::LogFull)) => {
                // Wait for the oldest pending batch to be applied so we
                // can advance the tail and free log space.
                if let Some(front) = pending_tails.first() {
                    let target = front.lsn;
                    if let Err(e) = applied_lsn.wait_for(target).await {
                        tracing::error!("VHDX log task: wait for apply failed while log full: {e}");
                        log_permits.fail(format!("wait for apply failed: {e}"));
                        return;
                    }
                    advance_tails(pending_tails, applied_lsn, log_writer);
                } else {
                    // No pending tails — log is genuinely too small for
                    // this single batch. This is a fatal configuration error.
                    tracing::error!(
                        "VHDX log task: log too small for batch of {} pages",
                        txn.pages.len()
                    );
                    log_permits.fail(format!(
                        "log too small for batch of {} pages",
                        txn.pages.len()
                    ));
                    return;
                }
            }
            Err(e) => {
                tracing::error!("VHDX log task: WAL write failed: {e}");
                log_permits.fail(format!("WAL write failed: {e}"));
                return;
            }
        }
    }

    // Publish that this LSN is durable in the log.
    logged_lsn.advance(lsn);

    let new_tail = log_writer.head();

    // Send to applier for background apply.
    let apply_pages = txn
        .pages
        .into_iter()
        .map(|p| ApplyPage {
            file_offset: p.file_offset,
            data: p.data,
        })
        .collect();

    apply_tx.send(ApplyBatch {
        pages: apply_pages,
        lsn,
        new_tail,
    });

    pending_tails.push(PendingTail { lsn, new_tail });
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

    flush_sequencer.flush(file.as_ref()).await?;

    Ok(())
}

/// Graceful close: wait for all applies, clear log GUID, flush.
async fn graceful_close<F: AsyncFile>(
    file: &Arc<F>,
    log_writer: &mut LogWriter,
    flush_sequencer: &Arc<FlushSequencer>,
    applied_lsn: &LsnWatermark,
    pending_tails: &mut Vec<PendingTail>,
    _log_offset: u64,
    _log_length: u32,
) -> Result<(), VhdxError> {
    // Wait for all pending applies to complete.
    if let Some(last) = pending_tails.last() {
        let target_lsn = last.lsn;
        applied_lsn.wait_for(target_lsn).await?;
    }

    // Now advance all tails.
    for pt in pending_tails.drain(..) {
        log_writer.advance_tail(pt.new_tail);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply_task;
    use crate::cache::PAGE_SIZE;
    use crate::log::LogRegion;
    use crate::tests::support::InMemoryFile;
    use pal_async::async_test;
    use pal_async::task::Spawn;

    const LOG_SIZE: u32 = 64 * 4096; // 256 KiB — deliberately small
    const LOG_OFFSET: u64 = 1024 * 1024; // 1 MiB into the file

    /// Set up a log task + apply task connected via channels.
    /// Returns (log_tx, file, permits, logged_lsn, applied_lsn,
    /// log_task_handle, apply_task_handle).
    async fn setup_pipeline(
        driver: &pal_async::DefaultDriver,
        log_size: u32,
        permit_count: usize,
    ) -> (
        mesh::Sender<LogRequest>,
        Arc<InMemoryFile>,
        Arc<LogPermits>,
        Arc<LsnWatermark>,
        Arc<LsnWatermark>,
        pal_async::task::Task<()>,
        pal_async::task::Task<()>,
    ) {
        let file = Arc::new(InMemoryFile::new(4 * 1024 * 1024));
        let region = LogRegion {
            file_offset: LOG_OFFSET,
            length: log_size,
        };
        let guid = guid::Guid::new_random();
        let log_writer =
            crate::log::LogWriter::initialize(file.as_ref(), region, guid, 4 * 1024 * 1024)
                .await
                .unwrap();

        let flush_sequencer = Arc::new(FlushSequencer::new());
        let log_permits = Arc::new(LogPermits::new(permit_count));
        let logged_lsn = Arc::new(LsnWatermark::new());
        let applied_lsn = Arc::new(LsnWatermark::new());

        let (apply_tx, apply_rx) = mesh::channel::<ApplyBatch>();
        let (log_tx, log_rx) = mesh::channel::<LogRequest>();

        // Spawn apply task.
        let apply_task = driver.spawn(
            "test-apply",
            apply_task::run_apply_task(
                apply_rx,
                file.clone(),
                flush_sequencer.clone(),
                applied_lsn.clone(),
                log_permits.clone(),
            ),
        );

        // Spawn log task.
        let log_task = driver.spawn(
            "test-log",
            run_log_task(
                log_rx,
                file.clone(),
                log_writer,
                flush_sequencer,
                log_permits.clone(),
                logged_lsn.clone(),
                applied_lsn.clone(),
                apply_tx,
                LOG_OFFSET,
                log_size,
            ),
        );

        (
            log_tx,
            file,
            log_permits,
            logged_lsn,
            applied_lsn,
            log_task,
            apply_task,
        )
    }

    /// Build a Transaction with `n` fake pages.
    fn make_txn(lsn: u64, n: usize) -> Transaction {
        let pages = (0..n)
            .map(|i| CommittedPage {
                file_offset: (2 * 1024 * 1024 + i * PAGE_SIZE) as u64,
                data: Arc::new([lsn as u8; PAGE_SIZE]),
            })
            .collect();
        Transaction {
            lsn,
            pages,
            pre_log_fsn: None,
        }
    }

    #[async_test]
    async fn single_commit_publishes_lsn(driver: pal_async::DefaultDriver) {
        let (tx, _file, _permits, logged_lsn, _applied_lsn, _log_task, _apply_task) =
            setup_pipeline(&driver, LOG_SIZE, 100).await;

        tx.send(LogRequest::Commit(make_txn(1, 1)));
        logged_lsn.wait_for(1).await.unwrap();
    }

    #[async_test]
    async fn permits_return_after_apply(driver: pal_async::DefaultDriver) {
        let permit_count = 10;
        let (tx, _file, permits, logged_lsn, _applied_lsn, _log_task, _apply_task) =
            setup_pipeline(&driver, LOG_SIZE, permit_count).await;

        // Consume all permits by acquiring them.
        permits.acquire(permit_count).await.unwrap();

        // Send a commit of 5 pages (the log task doesn't acquire permits,
        // but the apply task will release 5 after applying).
        tx.send(LogRequest::Commit(make_txn(1, 5)));

        // Wait for the commit to be logged.
        logged_lsn.wait_for(1).await.unwrap();

        // The apply task should release 5 permits. Acquiring 5 should
        // succeed (it would block forever if permits weren't released).
        permits.acquire(5).await.unwrap();

        // Clean up: release the permits we acquired so shutdown is clean.
        permits.release(permit_count);
    }

    #[async_test]
    async fn multiple_commits_sequential(driver: pal_async::DefaultDriver) {
        let (tx, _file, _permits, logged_lsn, _applied_lsn, _log_task, _apply_task) =
            setup_pipeline(&driver, LOG_SIZE, 100).await;

        for lsn in 1..=10u64 {
            tx.send(LogRequest::Commit(make_txn(lsn, 1)));
        }

        // All 10 should be logged.
        logged_lsn.wait_for(10).await.unwrap();
    }

    #[async_test]
    async fn log_full_retry_makes_progress(driver: pal_async::DefaultDriver) {
        // Use a small log (256 KiB). Each page + entry overhead ~ 8 KiB.
        // With ~30 entries the log will fill up, forcing the retry path.
        let (tx, _file, _permits, logged_lsn, _applied_lsn, _log_task, _apply_task) =
            setup_pipeline(&driver, LOG_SIZE, 500).await;

        // Send 50 single-page commits. This will exceed the 256 KiB log
        // and force LogFull → wait for apply → advance tail → retry.
        for lsn in 1..=50u64 {
            tx.send(LogRequest::Commit(make_txn(lsn, 1)));
        }

        // If LogFull retry works, all 50 will eventually be logged.
        logged_lsn.wait_for(50).await.unwrap();
    }

    #[async_test]
    async fn large_batches_through_small_log(driver: pal_async::DefaultDriver) {
        // Each batch has 5 pages (~24 KiB with overhead). 256 KiB log
        // fits maybe 10 batches. Send 30 — forces multiple cycles of
        // LogFull → drain → retry.
        let (tx, _file, _permits, logged_lsn, _applied_lsn, _log_task, _apply_task) =
            setup_pipeline(&driver, LOG_SIZE, 500).await;

        for lsn in 1..=30u64 {
            tx.send(LogRequest::Commit(make_txn(lsn, 5)));
        }

        logged_lsn.wait_for(30).await.unwrap();
    }

    #[async_test]
    async fn close_after_commits(driver: pal_async::DefaultDriver) {
        use mesh::rpc::RpcSend;

        let (tx, _file, _permits, logged_lsn, applied_lsn, _log_task, _apply_task) =
            setup_pipeline(&driver, LOG_SIZE, 100).await;

        for lsn in 1..=5u64 {
            tx.send(LogRequest::Commit(make_txn(lsn, 1)));
        }
        logged_lsn.wait_for(5).await.unwrap();

        // Graceful close should wait for all applies and succeed.
        let result = tx.call(LogRequest::Close, ()).await.unwrap();
        result.unwrap();

        // All commits should be applied.
        assert!(applied_lsn.get() >= 5);
    }

    #[async_test]
    async fn applied_data_is_at_final_offset(driver: pal_async::DefaultDriver) {
        let (tx, file, _permits, logged_lsn, applied_lsn, _log_task, _apply_task) =
            setup_pipeline(&driver, LOG_SIZE, 100).await;

        let target_offset: u64 = 2 * 1024 * 1024; // 2 MiB
        let data = Arc::new([0xAB_u8; PAGE_SIZE]);
        tx.send(LogRequest::Commit(Transaction {
            lsn: 1,
            pages: vec![CommittedPage {
                file_offset: target_offset,
                data: data.clone(),
            }],
            pre_log_fsn: None,
        }));

        logged_lsn.wait_for(1).await.unwrap();
        applied_lsn.wait_for(1).await.unwrap();

        // Read back from the final offset — should match.
        let mut buf = [0u8; PAGE_SIZE];
        file.read_at(target_offset, &mut buf).await.unwrap();
        assert!(buf.iter().all(|&b| b == 0xAB));
    }
}
