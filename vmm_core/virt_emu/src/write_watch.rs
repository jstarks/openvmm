// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! External-write observations, not permission to skip CPU instruction fetches.
//!
//! A capture excludes tracked external writes through their completion callback.
//! CPU stores remain outside this domain until CPU-side write watching is added.

use guestmem::{WriteObserver, WriteTracker};
use parking_lot::Mutex;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

struct Watch {
    range: Range<u64>,
    valid: AtomicBool,
}

#[derive(Default)]
struct Watches(Mutex<Vec<Weak<Watch>>>);

impl WriteObserver for Watches {
    fn notify_write(&self, range: Range<u64>) {
        self.0.lock().retain(|weak| {
            let Some(watch) = weak.upgrade() else {
                return false;
            };
            if watch.range.start < range.end && range.start < watch.range.end {
                watch.valid.store(false, Ordering::Release);
            }
            watch.valid.load(Ordering::Relaxed)
        });
    }
}

/// Partition-wide coordination for external writes and watched observations.
///
/// The tracker must cover every external writer and backing alias in the
/// supported configuration. Tokens do not cover direct CPU writes, guest fetch
/// authorization, or arbitrary pointers into the allocation.
#[derive(Clone)]
pub struct ExternalWriteWatch {
    watches: Arc<Watches>,
    tracker: WriteTracker,
}

impl Default for ExternalWriteWatch {
    fn default() -> Self {
        let watches = Arc::new(Watches::default());
        Self {
            tracker: WriteTracker::new(watches.clone()),
            watches,
        }
    }
}

/// Failure to establish an externally watched observation.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError<E> {
    /// The observation must cover a nonempty nonwrapping physical range.
    #[error("invalid external-write watch range")]
    InvalidRange,
    /// Failed capture creates no watch.
    #[error("capturing externally watched memory")]
    Read(#[source] E),
}

/// Captured value and its external-write validity token.
pub struct Watched<T> {
    value: T,
    watch: Arc<Watch>,
}

impl<T> Watched<T> {
    /// The original captured value, including after invalidation.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Whether tracked external writes have invalidated this observation.
    ///
    /// This does not authorize instruction execution or cover direct CPU stores.
    pub fn is_valid(&self) -> bool {
        self.watch.valid.load(Ordering::Acquire)
    }
}

impl ExternalWriteWatch {
    /// The same tracker is installed in every supported device-memory view.
    pub fn tracker(&self) -> WriteTracker {
        self.tracker.clone()
    }

    /// Captures and publishes under the external-write registration gate.
    ///
    /// `read` must only read the specified range and must not write, register
    /// another watch, or wait for mapping changes that notify this tracker.
    /// Capturing from already prepared mappings avoids fault-handler cycles.
    pub fn capture<T, E>(
        &self,
        range: Range<u64>,
        read: impl FnOnce() -> Result<T, E>,
    ) -> Result<Watched<T>, CaptureError<E>> {
        if range.start >= range.end {
            return Err(CaptureError::InvalidRange);
        }
        self.tracker.synchronize(|| {
            let value = read().map_err(CaptureError::Read)?;
            let watch = Arc::new(Watch {
                range,
                valid: AtomicBool::new(true),
            });
            let mut watches = self.watches.0.lock();
            watches.retain(|entry| entry.strong_count() != 0);
            watches.push(Arc::downgrade(&watch));
            Ok(Watched { value, watch })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn overlapping_notifications_invalidate_without_changing_captured_values() {
        let watches = ExternalWriteWatch::default();
        let first = watches
            .capture(0x1000..0x1008, || Ok::<_, std::io::Error>(17))
            .unwrap();
        let neighbor = watches
            .capture(0x1008..0x1010, || Ok::<_, std::io::Error>(23))
            .unwrap();
        watches.tracker().notify_write(0x1007, 1).unwrap();
        assert!(!first.is_valid());
        assert!(neighbor.is_valid());
        assert_eq!(*first.value(), 17);
        watches.tracker().notify_write(0x1008, 8).unwrap();
        assert!(!neighbor.is_valid());
        let fresh = watches
            .capture(0x1000..0x1008, || Ok::<_, std::io::Error>(29))
            .unwrap();
        assert!(fresh.is_valid());
        assert!(!first.is_valid());
    }

    #[test]
    fn invalid_ranges_and_failed_captures_publish_nothing() {
        let watches = ExternalWriteWatch::default();
        assert!(matches!(
            watches.capture(9..9, || Ok::<_, std::io::Error>(())),
            Err(CaptureError::InvalidRange)
        ));
        let failure = watches.capture(1..9, || {
            Err::<(), _>(std::io::Error::other("capture failed"))
        });
        assert!(matches!(failure, Err(CaptureError::Read(_))));
        assert!(watches.watches.0.lock().is_empty());
    }
}
