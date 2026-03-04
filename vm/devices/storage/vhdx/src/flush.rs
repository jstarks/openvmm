// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Flush sequencer — FSN tracking and concurrent flush coalescing.
//!
//! The VHDX write path needs a way to order and coalesce file flush operations.
//! Multiple concurrent callers may request flushes simultaneously (e.g., several
//! I/O threads completing writes at the same time). Rather than issuing one file
//! flush per caller, the [`FlushSequencer`] coalesces them: if a flush is already
//! in progress that will satisfy a caller's flush sequence number (FSN), the
//! caller waits for that flush instead of issuing a new one.
//!
//! FSNs increase monotonically. Each `flush()` call is assigned the next FSN.
//! When the flush I/O completes, the completed FSN advances to match. Callers
//! can ensure all data through a specific FSN is flushed via
//! [`FlushSequencer::flush_through`].

use crate::AsyncFile;
use crate::error::VhdxError;
use event_listener::Event;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Acquire;
use std::sync::atomic::Ordering::Release;

/// Tracks flush sequence numbers and coalesces concurrent flush requests.
///
/// Multiple callers can request flushes concurrently. The sequencer ensures
/// that at most one file flush is in progress at a time. If a flush is
/// in-flight that will satisfy a caller's FSN, the caller waits for that
/// flush instead of issuing a redundant one.
///
/// FSNs increase monotonically. Each [`flush()`](FlushSequencer::flush) call
/// is assigned the next FSN. [`flush_through()`](FlushSequencer::flush_through)
/// ensures all data through a specific FSN is flushed (used by the log task
/// to enforce ordering constraints like "data must be flushed before BAT
/// is logged").
pub(crate) struct FlushSequencer {
    state: Mutex<FlushState>,
}

struct FlushState {
    /// The most recently issued FSN that has been assigned. The next flush
    /// will get `issued_fsn + 1`.
    issued_fsn: u64,
    /// The most recently completed FSN. All FSNs <= this value have been
    /// durably flushed.
    completed_fsn: u64,
    active_flush: Option<Arc<Flush>>,
}

struct Flush {
    fsn: u64,
    done: AtomicBool,
    event: Event,
}

impl FlushSequencer {
    /// Create a new flush sequencer with FSNs starting at 0.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(FlushState {
                issued_fsn: 0,
                completed_fsn: 0,
                active_flush: None,
            }),
        }
    }

    /// Returns the next FSN that will be assigned to a flush request.
    ///
    /// This is `issued_fsn + 1`. Callers use this to capture the "current
    /// point in time" before performing a write, so they can later
    /// [`flush_through()`](Self::flush_through) to ensure that write has been
    /// flushed.
    pub fn current_fsn(&self) -> u64 {
        let state = self.state.lock();
        state.issued_fsn + 1
    }

    /// Request a file flush through the sequencer.
    ///
    /// Assigns the next FSN to this flush request and ensures that a file
    /// flush completes that covers this FSN. Multiple concurrent `flush()`
    /// calls are coalesced: if a flush is already in progress, the caller
    /// waits for it to complete. If the completed FSN is still less than the
    /// caller's FSN after the in-progress flush finishes, a new flush is
    /// issued.
    ///
    /// Returns the FSN that was assigned to this flush request.
    pub async fn flush(&self, file: &impl AsyncFile) -> Result<u64, VhdxError> {
        self.flush_until(file, None).await
    }

    /// Ensure all data through the given FSN is durably flushed.
    ///
    /// If the FSN has already completed, returns immediately. Otherwise,
    /// bumps `issued_fsn` if needed and waits for a flush to complete that
    /// covers the requested FSN.
    ///
    /// This is the safe replacement for the old `require_fsn` + `wait_for_fsn`
    /// pattern — it both issues and waits in a single call.
    pub async fn flush_through(&self, file: &impl AsyncFile, fsn: u64) -> Result<(), VhdxError> {
        self.flush_until(file, Some(fsn)).await?;
        Ok(())
    }

    /// Returns the most recently completed FSN.
    pub fn completed_fsn(&self) -> u64 {
        let state = self.state.lock();
        state.completed_fsn
    }

    /// Inner workhorse: keep flushing until `completed_fsn >= target_fsn`.
    ///
    /// `target_fsn`:
    /// - `None` — assign the next sequential FSN (used by `flush()`).
    /// - `Some(fsn)` — ensure completion through that FSN (used by `flush_through()`).
    ///
    /// Returns the resolved FSN.
    async fn flush_until(
        &self,
        file: &impl AsyncFile,
        mut requested_fsn: Option<u64>,
    ) -> Result<u64, VhdxError> {
        let flush = loop {
            let flush = {
                let mut state = self.state.lock();
                let target_fsn = requested_fsn.unwrap_or(state.issued_fsn + 1);
                requested_fsn = Some(target_fsn);

                if target_fsn <= state.completed_fsn {
                    return Ok(state.completed_fsn);
                }

                if let Some(flush) = &state.active_flush
                    && flush.fsn >= target_fsn
                {
                    flush.clone()
                } else {
                    let fsn = state.issued_fsn + 1;
                    let flush = Arc::new(Flush {
                        fsn,
                        done: false.into(),
                        event: Default::default(),
                    });
                    state.active_flush = Some(flush.clone());
                    state.issued_fsn = fsn;
                    break flush;
                }
            };
            flush.wait_done().await;
        };
        let r = file.flush().await;
        let completed_fsn = {
            let mut state = self.state.lock();
            if r.is_ok() {
                state.completed_fsn = flush.fsn.max(state.completed_fsn);
            }
            if state
                .active_flush
                .as_ref()
                .is_some_and(|p| Arc::ptr_eq(p, &flush))
            {
                state.active_flush = None;
            }
            state.completed_fsn
        };
        flush.done.store(true, Release);
        flush.event.notify(usize::MAX);
        r.map_err(VhdxError::Io)?;
        Ok(completed_fsn)
    }
}

impl Flush {
    async fn wait_done(&self) {
                    loop {
                        let event = self.event.listen();
                        if self.done.load(Acquire) {
                            break;
                        }
                        event.await;
                    }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::support::InMemoryFile;
    use pal_async::async_test;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    // -- Helper wrappers --

    /// File wrapper that counts how many times `flush()` is called.
    struct CountingFile {
        inner: InMemoryFile,
        flush_count: AtomicU32,
    }

    impl CountingFile {
        fn new() -> Self {
            Self {
                inner: InMemoryFile::new(0),
                flush_count: AtomicU32::new(0),
            }
        }

        fn flush_count(&self) -> u32 {
            self.flush_count.load(Ordering::Relaxed)
        }
    }

    impl AsyncFile for CountingFile {
        async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), std::io::Error> {
            self.inner.read_at(offset, buf).await
        }

        async fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), std::io::Error> {
            self.inner.write_at(offset, buf).await
        }

        async fn flush(&self) -> Result<(), std::io::Error> {
            self.flush_count.fetch_add(1, Ordering::Relaxed);
            self.inner.flush().await
        }

        async fn file_size(&self) -> Result<u64, std::io::Error> {
            self.inner.file_size().await
        }

        async fn set_file_size(&self, size: u64) -> Result<(), std::io::Error> {
            self.inner.set_file_size(size).await
        }
    }

    /// File wrapper that can be configured to fail flushes.
    struct FailingFile {
        inner: InMemoryFile,
        fail_flush: AtomicBool,
    }

    impl FailingFile {
        fn new(fail: bool) -> Self {
            Self {
                inner: InMemoryFile::new(0),
                fail_flush: AtomicBool::new(fail),
            }
        }

        fn set_fail(&self, fail: bool) {
            self.fail_flush.store(fail, Ordering::Relaxed);
        }
    }

    impl AsyncFile for FailingFile {
        async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), std::io::Error> {
            self.inner.read_at(offset, buf).await
        }

        async fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), std::io::Error> {
            self.inner.write_at(offset, buf).await
        }

        async fn flush(&self) -> Result<(), std::io::Error> {
            if self.fail_flush.load(Ordering::Relaxed) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "flush failed",
                ));
            }
            self.inner.flush().await
        }

        async fn file_size(&self) -> Result<u64, std::io::Error> {
            self.inner.file_size().await
        }

        async fn set_file_size(&self, size: u64) -> Result<(), std::io::Error> {
            self.inner.set_file_size(size).await
        }
    }

    // -- Tests --

    /// Single `flush()` call → FSN advances from 0 to 1.
    #[async_test]
    async fn test_basic_flush() {
        let file = InMemoryFile::new(0);
        let seq = FlushSequencer::new();
        let fsn = seq.flush(&file).await.unwrap();
        assert_eq!(fsn, 1);
        assert_eq!(seq.completed_fsn(), 1);
    }

    /// Three sequential `flush()` calls → FSNs are 1, 2, 3.
    #[async_test]
    async fn test_fsn_monotonically_increasing() {
        let file = InMemoryFile::new(0);
        let seq = FlushSequencer::new();
        let fsn1 = seq.flush(&file).await.unwrap();
        let fsn2 = seq.flush(&file).await.unwrap();
        let fsn3 = seq.flush(&file).await.unwrap();
        assert_eq!(fsn1, 1);
        assert_eq!(fsn2, 2);
        assert_eq!(fsn3, 3);
        assert_eq!(seq.completed_fsn(), 3);
    }

    /// `current_fsn()` returns 1 initially, advances after each flush.
    #[async_test]
    async fn test_current_fsn() {
        let file = InMemoryFile::new(0);
        let seq = FlushSequencer::new();
        assert_eq!(seq.current_fsn(), 1);
        seq.flush(&file).await.unwrap();
        assert_eq!(seq.current_fsn(), 2);
        seq.flush(&file).await.unwrap();
        assert_eq!(seq.current_fsn(), 3);
    }

    /// Spawn two concurrent `flush()` tasks. Both should complete, and the
    /// total number of actual file flushes should be ≤ 2 (possibly 1 if
    /// coalesced).
    #[async_test]
    async fn test_concurrent_flush_coalescing() {
        let file = Arc::new(CountingFile::new());
        let seq = Arc::new(FlushSequencer::new());

        let file1 = file.clone();
        let seq1 = seq.clone();
        let t1 =
            futures::FutureExt::boxed(async move { seq1.flush(file1.as_ref()).await.unwrap() });

        let file2 = file.clone();
        let seq2 = seq.clone();
        let t2 =
            futures::FutureExt::boxed(async move { seq2.flush(file2.as_ref()).await.unwrap() });

        let (fsn1, fsn2) = futures::join!(t1, t2);

        // Both FSNs should be valid (1 or 2).
        assert!(fsn1 >= 1 && fsn1 <= 2);
        assert!(fsn2 >= 1 && fsn2 <= 2);
        assert_ne!(fsn1, fsn2);

        // Completed FSN should be at least the max of both.
        assert!(seq.completed_fsn() >= fsn1.max(fsn2));

        // At most 2 actual file flushes should have occurred.
        assert!(file.flush_count() <= 2);
    }

    /// Call `flush()`, then `flush_through(fsn)` → returns immediately.
    #[async_test]
    async fn test_flush_through_already_completed() {
        let file = CountingFile::new();
        let seq = FlushSequencer::new();
        let fsn = seq.flush(&file).await.unwrap();
        let count_before = file.flush_count();
        // Should return immediately since the FSN is already completed.
        seq.flush_through(&file, fsn).await.unwrap();
        assert_eq!(seq.completed_fsn(), fsn);
        // No additional flush should have been issued.
        assert_eq!(file.flush_count(), count_before);
    }

    /// Call `flush_through(fsn)` on an un-issued FSN → triggers a flush
    /// and completes.
    #[async_test]
    async fn test_flush_through_triggers_flush() {
        let file = CountingFile::new();
        let seq = FlushSequencer::new();
        // FSN 1 has not been issued yet.
        seq.flush_through(&file, 1).await.unwrap();
        assert!(seq.completed_fsn() >= 1);
        assert!(file.flush_count() >= 1);
    }

    /// Spawn a concurrent `flush()` and `flush_through()` — both complete.
    #[async_test]
    async fn test_flush_through_waits_for_in_progress() {
        let file = Arc::new(CountingFile::new());
        let seq = Arc::new(FlushSequencer::new());

        let file1 = file.clone();
        let seq1 = seq.clone();
        let flusher = futures::FutureExt::boxed(async move {
            seq1.flush(file1.as_ref()).await.unwrap();
        });

        let file2 = file.clone();
        let seq2 = seq.clone();
        let waiter = futures::FutureExt::boxed(async move {
            seq2.flush_through(file2.as_ref(), 1).await.unwrap();
        });

        futures::join!(flusher, waiter);
        assert!(seq.completed_fsn() >= 1);
    }

    /// Use a file wrapper that fails on `flush()` → `flush()` returns error,
    /// `completed_fsn` does NOT advance.
    #[async_test]
    async fn test_flush_error_propagated() {
        let file = FailingFile::new(true);
        let seq = FlushSequencer::new();
        let result = seq.flush(&file).await;
        assert!(result.is_err());
        assert_eq!(seq.completed_fsn(), 0);
    }

    /// Use a file wrapper that fails on the first `flush()` but succeeds on
    /// retry → first call fails, second `flush()` succeeds and FSN advances.
    #[async_test]
    async fn test_flush_error_recovery() {
        let file = FailingFile::new(true);
        let seq = FlushSequencer::new();

        // First flush should fail.
        let result = seq.flush(&file).await;
        assert!(result.is_err());
        assert_eq!(seq.completed_fsn(), 0);

        // Allow flushes to succeed now.
        file.set_fail(false);

        // Second flush should succeed.
        let fsn = seq.flush(&file).await.unwrap();
        assert!(fsn >= 1);
        assert!(seq.completed_fsn() >= fsn);
    }
}
