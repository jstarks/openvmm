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
//! can wait for a specific FSN to complete via [`FlushSequencer::wait_for_fsn`].

#![allow(dead_code)]

use crate::error::VhdxError;
use crate::AsyncFile;
use event_listener::Event;
use parking_lot::Mutex;

/// Tracks flush sequence numbers and coalesces concurrent flush requests.
///
/// Multiple callers can request flushes concurrently. The sequencer ensures
/// that at most one file flush is in progress at a time. If a flush is
/// in-flight that will satisfy a caller's FSN, the caller waits for that
/// flush instead of issuing a redundant one.
///
/// FSNs increase monotonically. Each [`flush()`](FlushSequencer::flush) call
/// is assigned the next FSN. [`wait_for_fsn()`](FlushSequencer::wait_for_fsn)
/// allows callers to block until a specific FSN has completed (used by the log
/// task to enforce ordering constraints like "data must be flushed before BAT
/// is logged").
pub(crate) struct FlushSequencer {
    state: Mutex<FlushState>,
    /// Event notified when `completed_fsn` advances (or a flush error occurs).
    completed_event: Event,
}

struct FlushState {
    /// The most recently issued FSN that has been assigned. The next flush
    /// will get `issued_fsn + 1`.
    issued_fsn: u64,
    /// The most recently completed FSN. All FSNs <= this value have been
    /// durably flushed.
    completed_fsn: u64,
    /// Whether a flush I/O is currently in progress. When true, new flush
    /// requests wait for the in-progress flush and then check whether
    /// their FSN was satisfied.
    flushing: bool,
}

impl FlushSequencer {
    /// Create a new flush sequencer with FSNs starting at 0.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(FlushState {
                issued_fsn: 0,
                completed_fsn: 0,
                flushing: false,
            }),
            completed_event: Event::new(),
        }
    }

    /// Returns the next FSN that will be assigned to a flush request.
    ///
    /// This is `issued_fsn + 1`. Callers use this to capture the "current
    /// point in time" before performing a write, so they can later
    /// [`wait_for_fsn()`](Self::wait_for_fsn) to ensure that write has been
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
        let my_fsn;
        {
            let mut state = self.state.lock();
            state.issued_fsn += 1;
            my_fsn = state.issued_fsn;
        }
        self.flush_until(file, my_fsn).await?;
        Ok(my_fsn)
    }

    /// Wait for a specific FSN to complete.
    ///
    /// Returns immediately if the FSN has already completed. Otherwise,
    /// blocks until a flush completes that has an FSN >= the requested value.
    ///
    /// This does NOT issue a flush — it only waits. If no flush is pending
    /// that will satisfy this FSN, the caller will wait indefinitely. Use
    /// [`require_fsn()`](Self::require_fsn) to ensure a flush will eventually
    /// be issued.
    pub async fn wait_for_fsn(&self, fsn: u64) {
        loop {
            let listener = self.completed_event.listen();
            {
                let state = self.state.lock();
                if state.completed_fsn >= fsn {
                    return;
                }
            }
            listener.await;
        }
    }

    /// Ensure that a flush satisfying the given FSN will be issued.
    ///
    /// If the FSN has already been issued (i.e., `issued_fsn >= fsn`), this
    /// is a no-op — the flush is either in progress or completed. Otherwise,
    /// it triggers a flush. Combined with [`wait_for_fsn()`](Self::wait_for_fsn),
    /// this guarantees the FSN will eventually complete.
    pub async fn require_fsn(
        &self,
        file: &impl AsyncFile,
        fsn: u64,
    ) -> Result<(), VhdxError> {
        {
            let state = self.state.lock();
            if state.issued_fsn >= fsn {
                // A flush has already been issued that covers this FSN.
                return Ok(());
            }
        }
        // No flush has been issued for this FSN yet — trigger one.
        self.flush(file).await?;
        Ok(())
    }

    /// Returns the most recently completed FSN.
    pub fn completed_fsn(&self) -> u64 {
        let state = self.state.lock();
        state.completed_fsn
    }

    /// Inner loop: keep flushing until `completed_fsn >= target_fsn`.
    async fn flush_until(
        &self,
        file: &impl AsyncFile,
        target_fsn: u64,
    ) -> Result<(), VhdxError> {
        enum Action {
            Done,
            Flush(u64),
            Wait,
        }

        loop {
            // Register a listener BEFORE checking state to avoid races.
            let listener = self.completed_event.listen();

            // Decide what to do under the lock, then drop the lock before
            // any `.await` (parking_lot guards are !Send).
            let action = {
                let mut state = self.state.lock();
                if state.completed_fsn >= target_fsn {
                    Action::Done
                } else if !state.flushing {
                    state.flushing = true;
                    Action::Flush(state.issued_fsn)
                } else {
                    Action::Wait
                }
            };

            match action {
                Action::Done => return Ok(()),
                Action::Flush(flush_fsn) => {
                    // Drop the listener — we are flushing, not waiting.
                    drop(listener);

                    match file.flush().await {
                        Ok(()) => {
                            {
                                let mut state = self.state.lock();
                                state.flushing = false;
                                if flush_fsn > state.completed_fsn {
                                    state.completed_fsn = flush_fsn;
                                }
                            }
                            self.completed_event.notify(usize::MAX);
                        }
                        Err(e) => {
                            {
                                let mut state = self.state.lock();
                                state.flushing = false;
                            }
                            // Wake waiters so they can retry.
                            self.completed_event.notify(usize::MAX);
                            return Err(VhdxError::Io(e));
                        }
                    }
                    // Loop back to check if target_fsn is now satisfied.
                }
                Action::Wait => {
                    // A flush is already in progress — wait for it.
                    listener.await;
                    // Loop back and re-check.
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::support::InMemoryFile;
    use pal_async::async_test;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;

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
        let t1 = futures::FutureExt::boxed(async move {
            seq1.flush(file1.as_ref()).await.unwrap()
        });

        let file2 = file.clone();
        let seq2 = seq.clone();
        let t2 = futures::FutureExt::boxed(async move {
            seq2.flush(file2.as_ref()).await.unwrap()
        });

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

    /// Call `flush()`, then `wait_for_fsn(1)` → returns immediately.
    #[async_test]
    async fn test_wait_for_fsn_already_completed() {
        let file = InMemoryFile::new(0);
        let seq = FlushSequencer::new();
        seq.flush(&file).await.unwrap();
        // Should return immediately since FSN 1 is already completed.
        seq.wait_for_fsn(1).await;
        assert_eq!(seq.completed_fsn(), 1);
    }

    /// Spawn a task that calls `wait_for_fsn(1)`, then call `flush()` on
    /// the main task → `wait_for_fsn` completes after the flush.
    #[async_test]
    async fn test_wait_for_fsn_blocks_until_flush() {
        let file = Arc::new(InMemoryFile::new(0));
        let seq = Arc::new(FlushSequencer::new());

        let seq_waiter = seq.clone();
        let waiter = futures::FutureExt::boxed(async move {
            seq_waiter.wait_for_fsn(1).await;
        });

        let file_flusher = file.clone();
        let seq_flusher = seq.clone();
        let flusher = futures::FutureExt::boxed(async move {
            seq_flusher.flush(file_flusher.as_ref()).await.unwrap();
        });

        // Run both concurrently — the waiter should complete once the flusher
        // issues a flush.
        futures::join!(waiter, flusher);
        assert!(seq.completed_fsn() >= 1);
    }

    /// Call `require_fsn(file, 1)` → should issue a flush, and
    /// `completed_fsn()` should be >= 1 afterwards.
    #[async_test]
    async fn test_require_fsn_triggers_flush() {
        let file = CountingFile::new();
        let seq = FlushSequencer::new();
        seq.require_fsn(&file, 1).await.unwrap();
        assert!(seq.completed_fsn() >= 1);
        assert!(file.flush_count() >= 1);
    }

    /// Call `flush()` to get FSN 1, then `require_fsn(file, 1)` → should
    /// NOT issue another flush.
    #[async_test]
    async fn test_require_fsn_noop_if_already_issued() {
        let file = CountingFile::new();
        let seq = FlushSequencer::new();
        seq.flush(&file).await.unwrap();
        let count_before = file.flush_count();
        seq.require_fsn(&file, 1).await.unwrap();
        assert_eq!(file.flush_count(), count_before);
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
