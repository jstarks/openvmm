// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! LSN watermark — a shared monotonic counter with async waiters.
//!
//! Used to publish progress from the log task back to the cache:
//!
//! - [`LsnWatermark`] for `logged_through_lsn`: the log task updates this
//!   after each WAL write. `flush()` waits on it for durability.
//! - [`LsnWatermark`] for `applied_through_lsn`: the applier updates this
//!   after writing pages to final offsets. Cache eviction checks it.

use event_listener::Event;
use std::sync::atomic::{AtomicU64, Ordering};

/// A shared monotonic counter that supports async waiting.
///
/// Writers publish new values via [`advance()`](Self::advance).
/// Readers wait for the value to reach a target via
/// [`wait_for()`](Self::wait_for).
pub(crate) struct LsnWatermark {
    value: AtomicU64,
    event: Event,
}

impl LsnWatermark {
    /// Create a new watermark starting at 0.
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
            event: Event::new(),
        }
    }

    /// Read the current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Acquire)
    }

    /// Advance the watermark to `new_value`.
    ///
    /// The value must be monotonically increasing. If `new_value` is
    /// less than or equal to the current value, this is a no-op.
    pub fn advance(&self, new_value: u64) {
        self.value.fetch_max(new_value, Ordering::Release);
        self.event.notify(usize::MAX);
    }

    /// Wait until the watermark reaches at least `target`.
    ///
    /// Returns immediately if the current value is already ≥ `target`.
    pub async fn wait_for(&self, target: u64) {
        loop {
            let listener = self.event.listen();
            if self.value.load(Ordering::Acquire) >= target {
                return;
            }
            listener.await;
        }
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
    }

    #[async_test]
    async fn advance_and_read() {
        let wm = LsnWatermark::new();
        wm.advance(5);
        assert_eq!(wm.get(), 5);
        wm.advance(10);
        assert_eq!(wm.get(), 10);
    }

    #[async_test]
    async fn advance_is_monotonic() {
        let wm = LsnWatermark::new();
        wm.advance(10);
        wm.advance(5); // no-op
        assert_eq!(wm.get(), 10);
    }

    #[async_test]
    async fn wait_for_already_reached() {
        let wm = LsnWatermark::new();
        wm.advance(10);
        wm.wait_for(5).await; // returns immediately
        wm.wait_for(10).await; // returns immediately
    }

    #[async_test]
    async fn wait_for_blocks_then_completes() {
        let wm = std::sync::Arc::new(LsnWatermark::new());

        let w = wm.clone();
        let (done_tx, done_rx) = futures::channel::oneshot::channel();
        let handle = std::thread::spawn(move || {
            futures::executor::block_on(async {
                w.wait_for(5).await;
                done_tx.send(()).unwrap();
            });
        });

        // Give the thread time to block.
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Advance past the target.
        wm.advance(5);
        done_rx.await.unwrap();
        handle.join().unwrap();
    }

    #[async_test]
    async fn wait_for_zero_returns_immediately() {
        let wm = LsnWatermark::new();
        wm.wait_for(0).await;
    }
}
