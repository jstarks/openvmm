// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! LSN watermark — a shared monotonic counter with async waiters.
//!
//! Used to publish progress through the log/apply pipeline:
//!
//! - `logged_lsn`: the log task updates this after writing each WAL
//!   entry. The paired FSN lets callers flush through the sequencer
//!   to make the WAL entry durable.
//! - `applied_lsn`: the apply task updates this after writing pages
//!   to their final offsets. The paired FSN lets the log task flush
//!   to make the applied data durable (needed for tail advancement).
//!
//! Both watermarks carry an `(lsn, fsn)` pair. The LSN tracks progress;
//! the FSN tells consumers which flush sequence number to
//! [`flush_through()`](crate::flush::FlushSequencer::flush_through)
//! to make that progress durable on disk.

use crate::error::VhdxError;
use event_listener::Event;
use parking_lot::Mutex;

/// A shared monotonic `(lsn, fsn)` counter with async waiting and poisoning.
///
/// Writers publish new values via [`advance()`](Self::advance).
/// Readers wait for the LSN to reach a target via
/// [`wait_for()`](Self::wait_for), which returns the associated FSN.
///
/// If the producer fails, it calls [`fail()`](Self::fail) to poison the
/// watermark — all pending and future [`wait_for()`](Self::wait_for) calls
/// return an error.
pub(crate) struct LsnWatermark {
    state: Mutex<WatermarkState>,
    event: Event,
}

struct WatermarkState {
    lsn: u64,
    fsn: u64,
    failed: Option<String>,
}

impl LsnWatermark {
    /// Create a new watermark starting at LSN 0, FSN 0.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(WatermarkState {
                lsn: 0,
                fsn: 0,
                failed: None,
            }),
            event: Event::new(),
        }
    }

    /// Read the current LSN value.
    pub fn get(&self) -> u64 {
        self.state.lock().lsn
    }

    /// Read the current `(lsn, fsn)` pair atomically.
    pub fn get_with_fsn(&self) -> (u64, u64) {
        let s = self.state.lock();
        (s.lsn, s.fsn)
    }

    /// Advance the watermark to `(new_lsn, new_fsn)`.
    ///
    /// The LSN must be monotonically increasing.
    pub fn advance(&self, new_lsn: u64, new_fsn: u64) {
        {
            let mut s = self.state.lock();
            s.lsn = s.lsn.max(new_lsn);
            s.fsn = s.fsn.max(new_fsn);
        }
        self.event.notify(usize::MAX);
    }

    /// Wait until the LSN reaches at least `target`.
    ///
    /// Returns the FSN associated with the reached LSN. Callers should
    /// [`flush_through()`](crate::flush::FlushSequencer::flush_through)
    /// the returned FSN to ensure durability.
    ///
    /// Returns an error if the watermark has been poisoned.
    pub async fn wait_for(&self, target: u64) -> Result<u64, VhdxError> {
        loop {
            let listener = self.event.listen();
            {
                let s = self.state.lock();
                if let Some(ref err) = s.failed {
                    return Err(VhdxError::Io(std::io::Error::other(err.clone())));
                }
                if s.lsn >= target {
                    return Ok(s.fsn);
                }
            }
            listener.await;
        }
    }

    /// Poison the watermark. All pending and future `wait_for()` calls
    /// will return an error.
    pub fn fail(&self, error: String) {
        self.state.lock().failed = Some(error);
        self.event.notify(usize::MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pal_async::async_test;

    #[async_test]
    async fn starts_at_zero() {
        let wm = LsnWatermark::new();
        assert_eq!(wm.get(), 0);
        assert_eq!(wm.get_with_fsn(), (0, 0));
    }

    #[async_test]
    async fn advance_and_read() {
        let wm = LsnWatermark::new();
        wm.advance(5, 100);
        assert_eq!(wm.get(), 5);
        assert_eq!(wm.get_with_fsn(), (5, 100));
        wm.advance(10, 200);
        assert_eq!(wm.get(), 10);
        assert_eq!(wm.get_with_fsn(), (10, 200));
    }

    #[async_test]
    async fn advance_is_monotonic() {
        let wm = LsnWatermark::new();
        wm.advance(10, 200);
        wm.advance(5, 100); // no-op (both LSN and FSN stay at max)
        assert_eq!(wm.get(), 10);
        assert_eq!(wm.get_with_fsn(), (10, 200));
    }

    #[async_test]
    async fn wait_for_already_reached() {
        let wm = LsnWatermark::new();
        wm.advance(10, 100);
        let fsn = wm.wait_for(5).await.unwrap();
        assert_eq!(fsn, 100);
        let fsn = wm.wait_for(10).await.unwrap();
        assert_eq!(fsn, 100);
    }

    #[async_test]
    async fn wait_for_returns_fsn() {
        let wm = LsnWatermark::new();
        wm.advance(5, 42);
        let fsn = wm.wait_for(5).await.unwrap();
        assert_eq!(fsn, 42);
    }

    #[async_test]
    async fn wait_for_blocks_then_completes() {
        let wm = std::sync::Arc::new(LsnWatermark::new());

        let w = wm.clone();
        let (done_tx, done_rx) = futures::channel::oneshot::channel();
        let handle = std::thread::spawn(move || {
            futures::executor::block_on(async {
                let fsn = w.wait_for(5).await.unwrap();
                done_tx.send(fsn).unwrap();
            });
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        wm.advance(5, 77);
        let fsn = done_rx.await.unwrap();
        assert_eq!(fsn, 77);
        handle.join().unwrap();
    }

    #[async_test]
    async fn wait_for_zero_returns_immediately() {
        let wm = LsnWatermark::new();
        let fsn = wm.wait_for(0).await.unwrap();
        assert_eq!(fsn, 0);
    }

    #[async_test]
    async fn poison_fails_future_wait() {
        let wm = LsnWatermark::new();
        wm.fail("broken".into());
        assert!(wm.wait_for(1).await.is_err());
    }

    #[async_test]
    async fn poison_fails_pending_wait() {
        let wm = std::sync::Arc::new(LsnWatermark::new());

        let w = wm.clone();
        let (done_tx, done_rx) = futures::channel::oneshot::channel();
        let handle = std::thread::spawn(move || {
            futures::executor::block_on(async {
                let result = w.wait_for(5).await;
                assert!(result.is_err());
                done_tx.send(()).unwrap();
            });
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        wm.fail("task died".into());
        done_rx.await.unwrap();
        handle.join().unwrap();
    }

    #[async_test]
    async fn poison_does_not_affect_already_reached() {
        let wm = LsnWatermark::new();
        wm.advance(10, 100);
        wm.fail("broken".into());
        assert!(wm.wait_for(5).await.is_err());
    }
}
