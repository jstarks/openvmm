// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Log task — a single async task that owns log state and provides
//! crash-consistent metadata persistence.
//!
//! The log task receives [`LogRequest`] messages via a `mesh` channel.
//! [`LogRequest::Commit`] is fire-and-forget: the cache sends a batch
//! of dirty pages and moves on. The log task writes WAL entries,
//! releases permits, and publishes `logged_through_lsn`.

#![allow(dead_code)]

use crate::AsyncFile;
use crate::apply_task::ApplyBatch;
use crate::error::PipelineFailed;
use crate::error::VhdxIoError;
use crate::error::VhdxIoErrorInner;
use crate::flush::FlushSequencer;
use crate::flush::Fsn;
use crate::format::LOG_SECTOR_SIZE;
use crate::log::DataPage;
use crate::log::LogWriter;
use crate::log_permits::LogPermits;
use crate::lsn_watermark::LsnWatermark;
use crate::open::FailureFlag;
use mesh::rpc::Rpc;
use std::collections::VecDeque;
use std::sync::Arc;
use thiserror::Error;

const LOG_DATA_PAGE_SIZE: usize = LOG_SECTOR_SIZE as usize;

/// Internal error type for the log task.
#[derive(Debug, Error)]
pub(crate) enum LogTaskError {
    /// An I/O error from WAL writes or flushes.
    #[error("flush error")]
    Flush(#[source] std::io::Error),
    /// The apply task or another pipeline stage has failed.
    #[error("pipeline failed")]
    PipelineFailed(#[source] PipelineFailed),
    /// Failed to write a log entry.
    #[error("failed to write log entry")]
    Write(#[source] std::io::Error),
    /// The transaction is too large to fit in the log region.
    #[error("log transaction too big ({0} pages)")]
    TransactionTooBig(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Lsn(u64);

impl Lsn {
    pub const ZERO: Lsn = Lsn(0);

    #[cfg(test)]
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// A request to the log task.
pub(crate) enum LogRequest<B> {
    /// Log a batch of dirty pages.
    Commit(Transaction<B>),

    /// Graceful shutdown: wait for apply and flush through all pending work.
    Close(Rpc<(), Result<(), LogTaskError>>),
}

/// Committed data at a log-data-page-aligned file offset.
pub(crate) struct LogData<B> {
    file_offset: u64,
    data: Arc<B>,
}

impl<B: AsRef<[u8]>> LogData<B> {
    pub(crate) fn new(file_offset: u64, data: Arc<B>) -> Self {
        let len = data.as_ref().as_ref().len();
        assert_ne!(len, 0);
        assert!(
            file_offset.is_multiple_of(LOG_DATA_PAGE_SIZE as u64),
            "committed data offset {file_offset:#x} is not {LOG_DATA_PAGE_SIZE}-byte aligned",
        );
        assert!(
            len.is_multiple_of(LOG_DATA_PAGE_SIZE),
            "committed data length {len} is not {LOG_DATA_PAGE_SIZE}-byte aligned",
        );
        Self { file_offset, data }
    }

    pub(crate) fn page_count(&self) -> usize {
        self.data.as_ref().as_ref().len() / LOG_DATA_PAGE_SIZE
    }

    #[cfg(test)]
    pub(crate) fn data(&self) -> &[u8] {
        self.data.as_ref().as_ref()
    }

    pub(crate) fn into_parts(self) -> (u64, Arc<B>) {
        (self.file_offset, self.data)
    }
}

/// A batch of dirty pages to be logged atomically.
pub(crate) struct Transaction<B> {
    /// The LSN assigned by the cache at commit time.
    pub lsn: Lsn,
    /// The data in this batch.
    pub data: Vec<LogData<B>>,
    /// If set, the log task must wait for this FSN before writing the WAL entry.
    pub pre_log_fsn: Option<Fsn>,
}

/// Client-side handle for sending transactions to the log task.
pub(crate) struct LogClient<B> {
    sender: mesh::Sender<LogRequest<B>>,
    current_lsn: Lsn,
}

impl<B: Send + Sync + 'static> LogClient<B> {
    /// Create a new log client wrapping the given sender.
    pub fn new(sender: mesh::Sender<LogRequest<B>>) -> Self {
        Self {
            sender,
            current_lsn: Lsn::ZERO,
        }
    }

    /// Returns the most recently committed LSN.
    pub fn current_lsn(&self) -> Lsn {
        self.current_lsn
    }

    /// Begin a new transaction.
    pub fn begin(&mut self) -> LogTransaction<'_, B> {
        LogTransaction { client: self }
    }

    /// Send a graceful close request to the log task and wait for it to drain.
    pub async fn close(self) -> Result<(), VhdxIoError> {
        use mesh::rpc::RpcSend;
        self.sender
            .call(LogRequest::Close, ())
            .await
            .map_err(|_| VhdxIoErrorInner::Failed(PipelineFailed("log task closed".into())))?
            .map_err(VhdxIoErrorInner::LogClose)?;
        Ok(())
    }
}

/// An in-progress log transaction.
pub(crate) struct LogTransaction<'a, B> {
    client: &'a mut LogClient<B>,
}

impl<B: Send + Sync + 'static> LogTransaction<'_, B> {
    /// The LSN that will be assigned if this transaction is committed.
    pub fn lsn(&self) -> Lsn {
        Lsn(self.client.current_lsn.0 + 1)
    }

    /// Commit the transaction: assign the next LSN and send it to the log task.
    pub fn commit(self, log_data: Vec<LogData<B>>, pre_log_fsn: Option<Fsn>) -> Lsn {
        self.client.current_lsn.0 += 1;
        let lsn = self.client.current_lsn;
        self.client.sender.send(LogRequest::Commit(Transaction {
            lsn,
            data: log_data,
            pre_log_fsn,
        }));
        lsn
    }
}

struct PendingTail {
    lsn: Lsn,
    new_tail: u32,
}

/// All mutable state owned by the log task.
pub(crate) struct LogTask<F: AsyncFile> {
    file: Arc<F>,
    log_writer: LogWriter,
    flush_sequencer: Arc<FlushSequencer>,
    log_permits: Arc<LogPermits>,
    logged_lsn: Arc<LsnWatermark>,
    applied_lsn: Arc<LsnWatermark>,
    apply_tx: mesh::Sender<ApplyBatch<F::Buffer>>,
    pending_tails: VecDeque<PendingTail>,
    failure_flag: Arc<FailureFlag>,
}

impl<F: AsyncFile> LogTask<F> {
    /// Create a new log task with the given dependencies.
    pub(crate) fn new(
        file: Arc<F>,
        log_writer: LogWriter,
        flush_sequencer: Arc<FlushSequencer>,
        log_permits: Arc<LogPermits>,
        logged_lsn: Arc<LsnWatermark>,
        applied_lsn: Arc<LsnWatermark>,
        apply_tx: mesh::Sender<ApplyBatch<F::Buffer>>,
        failure_flag: Arc<FailureFlag>,
    ) -> Self {
        Self {
            file,
            log_writer,
            flush_sequencer,
            log_permits,
            logged_lsn,
            applied_lsn,
            apply_tx,
            pending_tails: VecDeque::new(),
            failure_flag,
        }
    }

    /// Run the log task main loop.
    pub async fn run(mut self, mut rx: mesh::Receiver<LogRequest<F::Buffer>>) {
        loop {
            self.advance_tails();

            let request = match rx.recv().await {
                Ok(req) => req,
                Err(_) => {
                    tracing::warn!("VHDX log task: channel closed without close() - file is dirty");
                    break;
                }
            };

            match request {
                LogRequest::<F::Buffer>::Commit(txn) => {
                    if let Err(err) = self.handle_commit(txn).await {
                        tracing::error!("VHDX log task fatal error: {err}");
                        let message = err.to_string();
                        self.log_permits.fail(message.clone());
                        self.logged_lsn.fail(message);
                        self.failure_flag.set(&err);
                        break;
                    }
                }
                LogRequest::<F::Buffer>::Close(rpc) => {
                    rpc.handle(async |()| self.graceful_close().await).await;
                    break;
                }
            }
        }
    }

    fn advance_tails(&mut self) {
        let flushed_fsn = self.flush_sequencer.completed_fsn();
        let (applied, applied_fsn) = self.applied_lsn.get_with_fsn();
        while let Some(front) = self.pending_tails.front() {
            if front.lsn <= applied && applied_fsn <= flushed_fsn {
                self.log_writer.advance_tail(front.new_tail);
                self.pending_tails.pop_front();
            } else {
                break;
            }
        }
    }

    async fn flush_and_advance_tails(&mut self) -> Result<(), LogTaskError> {
        if let Some(front) = self.pending_tails.front() {
            let target = front.lsn;
            let applied_fsn = self
                .applied_lsn
                .wait_for(target)
                .await
                .map_err(LogTaskError::PipelineFailed)?;
            self.flush_sequencer
                .flush_through(self.file.as_ref(), applied_fsn)
                .await
                .map_err(LogTaskError::Flush)?;
            self.advance_tails();
        }
        Ok(())
    }

    async fn write_log_entry(
        &mut self,
        pages: &[LogData<F::Buffer>],
    ) -> Result<bool, LogTaskError> {
        let page_count = pages.iter().map(LogData::page_count).sum();
        let mut data_pages = Vec::with_capacity(page_count);
        for page in pages {
            for (index, payload) in page.data.as_ref().as_ref().as_chunks().0.iter().enumerate() {
                data_pages.push(DataPage {
                    file_offset: page.file_offset + (index * LOG_DATA_PAGE_SIZE) as u64,
                    payload,
                });
            }
        }

        Ok(self
            .log_writer
            .write_entry(self.file.as_ref(), &data_pages, &[])
            .await
            .map_err(LogTaskError::Write)?
            .is_some())
    }

    async fn handle_commit(&mut self, txn: Transaction<F::Buffer>) -> Result<(), LogTaskError> {
        let lsn = txn.lsn;

        if let Some(fsn) = txn.pre_log_fsn {
            self.flush_sequencer
                .flush_through(self.file.as_ref(), fsn)
                .await
                .map_err(LogTaskError::Flush)?;
        }

        while !self.write_log_entry(&txn.data).await? {
            if self.pending_tails.is_empty() {
                return Err(LogTaskError::TransactionTooBig(
                    txn.data.iter().map(LogData::page_count).sum(),
                ));
            }
            self.flush_and_advance_tails().await?;
        }

        let wal_fsn = self.flush_sequencer.current_fsn();
        self.logged_lsn.advance(lsn, wal_fsn);

        let new_tail = self.log_writer.head();
        self.apply_tx.send(ApplyBatch {
            data: txn.data,
            lsn,
        });
        self.pending_tails.push_back(PendingTail { lsn, new_tail });
        Ok(())
    }

    async fn graceful_close(&mut self) -> Result<(), LogTaskError> {
        if let Some(last) = self.pending_tails.back() {
            let target_lsn = last.lsn;
            let applied_fsn = self
                .applied_lsn
                .wait_for(target_lsn)
                .await
                .map_err(LogTaskError::PipelineFailed)?;
            self.flush_sequencer
                .flush_through(self.file.as_ref(), applied_fsn)
                .await
                .map_err(LogTaskError::Flush)?;
        }

        for pending_tail in self.pending_tails.drain(..) {
            self.log_writer.advance_tail(pending_tail.new_tail);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AsyncFileExt;
    use crate::apply_task;
    use crate::log::LogRegion;
    use crate::open::FailureFlag;
    use crate::tests::support::InMemoryFile;
    use pal_async::async_test;
    use pal_async::task::Spawn;

    const LOG_SIZE: u32 = 64 * 4096;
    const LOG_OFFSET: u64 = 1024 * 1024;

    async fn setup_pipeline(
        driver: &pal_async::DefaultDriver,
        log_size: u32,
        permit_count: usize,
    ) -> (
        mesh::Sender<LogRequest<Vec<u8>>>,
        Arc<InMemoryFile>,
        Arc<LogPermits>,
        Arc<LsnWatermark>,
        Arc<LsnWatermark>,
        pal_async::task::Task<()>,
        pal_async::task::Task<()>,
    ) {
        let file = Arc::new(InMemoryFile::new(4 * 1024 * 1024));
        setup_pipeline_with_file(driver, file, log_size, permit_count).await
    }

    async fn setup_pipeline_with_file(
        driver: &pal_async::DefaultDriver,
        file: Arc<InMemoryFile>,
        log_size: u32,
        permit_count: usize,
    ) -> (
        mesh::Sender<LogRequest<Vec<u8>>>,
        Arc<InMemoryFile>,
        Arc<LogPermits>,
        Arc<LsnWatermark>,
        Arc<LsnWatermark>,
        pal_async::task::Task<()>,
        pal_async::task::Task<()>,
    ) {
        let region = LogRegion {
            file_offset: LOG_OFFSET,
            length: log_size,
        };
        let guid = guid::Guid::new_random();
        let log_writer = LogWriter::initialize(file.as_ref(), region, guid, 4 * 1024 * 1024)
            .await
            .unwrap();

        let flush_sequencer = Arc::new(FlushSequencer::new());
        let log_permits = Arc::new(LogPermits::new(permit_count));
        let logged_lsn = Arc::new(LsnWatermark::new());
        let applied_lsn = Arc::new(LsnWatermark::new());
        let failure_flag = Arc::new(FailureFlag::new());

        let (apply_tx, apply_rx) = mesh::channel::<ApplyBatch<Vec<u8>>>();
        let (log_tx, log_rx) = mesh::channel::<LogRequest<Vec<u8>>>();

        let apply_task = driver.spawn(
            "test-apply",
            apply_task::run_apply_task(
                apply_rx,
                file.clone(),
                flush_sequencer.clone(),
                applied_lsn.clone(),
                log_permits.clone(),
                failure_flag.clone(),
            ),
        );

        let log_task = driver.spawn(
            "test-log",
            LogTask::new(
                file.clone(),
                log_writer,
                flush_sequencer,
                log_permits.clone(),
                logged_lsn.clone(),
                applied_lsn.clone(),
                apply_tx,
                failure_flag,
            )
            .run(log_rx),
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

    fn make_txn(lsn: Lsn, n: usize) -> Transaction<Vec<u8>> {
        let pages = (0..n)
            .map(|i| {
                LogData::new(
                    (2 * 1024 * 1024 + i * LOG_DATA_PAGE_SIZE) as u64,
                    Arc::new(vec![lsn.0 as u8; LOG_DATA_PAGE_SIZE]),
                )
            })
            .collect();
        Transaction {
            lsn,
            data: pages,
            pre_log_fsn: None,
        }
    }

    async fn send_commit(
        tx: &mesh::Sender<LogRequest<Vec<u8>>>,
        permits: &LogPermits,
        lsn: Lsn,
        page_count: usize,
    ) {
        permits.acquire(page_count).await.unwrap();
        tx.send(LogRequest::Commit(make_txn(lsn, page_count)));
    }

    #[async_test]
    async fn single_commit_publishes_lsn(driver: pal_async::DefaultDriver) {
        let (tx, _file, permits, logged_lsn, _applied_lsn, _log_task, _apply_task) =
            setup_pipeline(&driver, LOG_SIZE, 100).await;

        send_commit(&tx, &permits, Lsn(1), 1).await;
        logged_lsn.wait_for(Lsn(1)).await.unwrap();
    }

    #[async_test]
    async fn permits_return_after_apply(driver: pal_async::DefaultDriver) {
        let permit_count = 10;
        let (tx, _file, permits, logged_lsn, applied_lsn, _log_task, _apply_task) =
            setup_pipeline(&driver, LOG_SIZE, permit_count).await;

        send_commit(&tx, &permits, Lsn(1), 5).await;

        logged_lsn.wait_for(Lsn(1)).await.unwrap();
        applied_lsn.wait_for(Lsn(1)).await.unwrap();

        assert_eq!(permits.available(), permit_count);
    }

    #[async_test]
    async fn multiple_commits_sequential(driver: pal_async::DefaultDriver) {
        let (tx, _file, permits, logged_lsn, _applied_lsn, _log_task, _apply_task) =
            setup_pipeline(&driver, LOG_SIZE, 100).await;

        for lsn in 1..=10u64 {
            send_commit(&tx, &permits, Lsn(lsn), 1).await;
        }

        logged_lsn.wait_for(Lsn(10)).await.unwrap();
    }

    #[async_test]
    async fn log_full_retry_makes_progress(driver: pal_async::DefaultDriver) {
        let (tx, _file, permits, logged_lsn, _applied_lsn, _log_task, _apply_task) =
            setup_pipeline(&driver, LOG_SIZE, 500).await;

        for lsn in 1..=50u64 {
            send_commit(&tx, &permits, Lsn(lsn), 1).await;
        }

        logged_lsn.wait_for(Lsn(50)).await.unwrap();
    }

    #[async_test]
    async fn large_batches_through_small_log(driver: pal_async::DefaultDriver) {
        let (tx, _file, permits, logged_lsn, _applied_lsn, _log_task, _apply_task) =
            setup_pipeline(&driver, LOG_SIZE, 500).await;

        for lsn in 1..=30u64 {
            send_commit(&tx, &permits, Lsn(lsn), 5).await;
        }

        logged_lsn.wait_for(Lsn(30)).await.unwrap();
    }

    #[async_test]
    async fn close_after_commits(driver: pal_async::DefaultDriver) {
        use mesh::rpc::RpcSend;

        let (tx, _file, permits, logged_lsn, applied_lsn, _log_task, _apply_task) =
            setup_pipeline(&driver, LOG_SIZE, 100).await;

        for lsn in 1..=5u64 {
            send_commit(&tx, &permits, Lsn(lsn), 1).await;
        }
        logged_lsn.wait_for(Lsn(5)).await.unwrap();

        let result = tx.call(LogRequest::<Vec<u8>>::Close, ()).await.unwrap();
        result.unwrap();

        assert!(applied_lsn.get() >= Lsn(5));
    }

    #[async_test]
    async fn applied_data_is_at_final_offset(driver: pal_async::DefaultDriver) {
        let (tx, file, permits, logged_lsn, applied_lsn, _log_task, _apply_task) =
            setup_pipeline(&driver, LOG_SIZE, 100).await;

        let target_offset: u64 = 2 * 1024 * 1024;
        let data = Arc::new(vec![0xAB_u8; LOG_DATA_PAGE_SIZE]);
        permits.acquire(1).await.unwrap();
        tx.send(LogRequest::Commit(Transaction {
            lsn: Lsn(1),
            data: vec![LogData::new(target_offset, data.clone())],
            pre_log_fsn: None,
        }));

        logged_lsn.wait_for(Lsn(1)).await.unwrap();
        applied_lsn.wait_for(Lsn(1)).await.unwrap();

        let mut buf = [0u8; LOG_DATA_PAGE_SIZE];
        file.read_at(target_offset, &mut buf).await.unwrap();
        assert!(buf.iter().all(|&b| b == 0xAB));
    }

    #[async_test]
    async fn apply_write_failure_poisons_pipeline(driver: pal_async::DefaultDriver) {
        use crate::tests::support::IoInterceptor;

        struct FailApplyInterceptor {
            fail: std::sync::atomic::AtomicBool,
        }

        impl IoInterceptor for FailApplyInterceptor {
            fn before_write(&self, offset: u64, _data: &[u8]) -> Result<(), std::io::Error> {
                if self.fail.load(std::sync::atomic::Ordering::Relaxed) && offset >= 2 * 1024 * 1024
                {
                    return Err(std::io::Error::other("injected apply write failure"));
                }
                Ok(())
            }
        }

        let interceptor = Arc::new(FailApplyInterceptor {
            fail: std::sync::atomic::AtomicBool::new(false),
        });
        let file = Arc::new(InMemoryFile::with_interceptor(
            4 * 1024 * 1024,
            interceptor.clone() as Arc<dyn IoInterceptor>,
        ));

        let (tx, _file, permits, logged_lsn, _applied_lsn, _log_task, _apply_task) =
            setup_pipeline_with_file(&driver, file, LOG_SIZE, 100).await;

        send_commit(&tx, &permits, Lsn(1), 1).await;
        logged_lsn.wait_for(Lsn(1)).await.unwrap();

        interceptor
            .fail
            .store(true, std::sync::atomic::Ordering::Relaxed);

        send_commit(&tx, &permits, Lsn(2), 1).await;
        logged_lsn.wait_for(Lsn(2)).await.unwrap();

        let result = permits.acquire(1).await;
        assert!(result.is_err(), "acquire should fail after apply error");
    }
}
