// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CPU/external write observations, not guest fetch authorization.
//!
//! The partition drains CPU leases before acquiring the external capture gate.
//! Observations do not qualify guest execution permissions or replace fetches.

use crate::native_memory::RamError;
use guestmem::{WriteObserver, WriteTracker};
use parking_lot::Mutex;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use x86_system::memory::physical::CopyError;

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

/// Partition-wide coordination for writes and watched observations.
///
/// The tracker must cover every external writer and backing alias in the
/// supported configuration. CPU capture also requires the mapping write lease;
/// it must go through the partition's capture API. Arbitrary backing pointers
/// and guest fetch authorization are outside this contract.
#[derive(Clone)]
pub(crate) struct WriteWatch {
    watches: Arc<Watches>,
    tracker: WriteTracker,
}

impl Default for WriteWatch {
    fn default() -> Self {
        let watches = Arc::new(Watches::default());
        Self {
            tracker: WriteTracker::new(watches.clone()),
            watches,
        }
    }
}

/// Failure to establish a watched observation.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError<E> {
    /// The observation must cover a nonempty nonwrapping physical range.
    #[error("invalid write watch range")]
    InvalidRange,
    /// Failed capture creates no watch.
    #[error("capturing watched memory")]
    Read(#[source] E),
}

/// Failure to establish a CPU/external watched code observation.
#[derive(Debug, thiserror::Error)]
pub enum CodeCaptureError {
    /// The mapping cannot establish watched CPU write qualification.
    #[error("qualifying physical code mappings")]
    Mapping(#[from] RamError),
    /// The code range or captured backing is unavailable.
    #[error("capturing physical code")]
    Capture(#[from] CaptureError<CopyError<RamError>>),
}

/// Captured value and its write-validity token.
pub struct Watched<T> {
    value: T,
    watch: Arc<Watch>,
}

impl<T> Watched<T> {
    /// The original captured value, including after invalidation.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Whether participating writes have invalidated this observation.
    ///
    /// This does not authorize guest instruction execution. The observation
    /// assumes all external writers obey the observed backing configuration.
    pub fn is_valid(&self) -> bool {
        self.watch.valid.load(Ordering::Acquire)
    }
}

impl WriteWatch {
    /// The same tracker is installed in every supported device-memory view.
    pub(crate) fn tracker(&self) -> WriteTracker {
        self.tracker.clone()
    }

    /// Captures under the external gate after CPU watch qualification.
    ///
    /// `read` must only read the specified range and must not write, register
    /// another watch, or wait for mapping changes that notify this tracker.
    /// Capturing from already prepared mappings avoids fault-handler cycles.
    pub(crate) fn capture<T, E>(
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
    use crate::mapped_test_memory::MappedTestMemory;
    use crate::native_memory::PartitionMemory;
    use test_with_tracing::test;
    use x86_system::WordAccess;
    use x86_system::memory::physical::PhysicalRam;
    use x86_system::mmu::translate::{Progress, Request, Translator};

    #[test]
    fn overlapping_notifications_invalidate_without_changing_captured_values() {
        let watches = WriteWatch::default();
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
        let watches = WriteWatch::default();
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

    #[test]
    fn suspended_mmu_store_uses_new_watch_permissions_when_its_batch_resumes() {
        let watches = WriteWatch::default();
        let mappings = Arc::new(PartitionMemory::with_write_tracker(watches.tracker()));
        let memory = MappedTestMemory::observed(
            mappings.clone(),
            &crate::shared_mmu_tests::bytes(),
            watches.tracker(),
        );
        let mut mmu = Translator::new(crate::shared_mmu_tests::config(), 0);
        assert!(mmu.begin_word(0, WordAccess::Write(0x1122_3344_5566_7788), false));
        let mut suspended = false;
        {
            let access = mappings.access();
            let ram = access.ram();
            for _ in 0..128 {
                if matches!(
                    mmu.request(),
                    Request::WriteBytes {
                        address: 0x5000,
                        ..
                    }
                ) {
                    suspended = true;
                    break;
                }
                assert!(matches!(mmu.run(&ram, 1).unwrap(), Progress::Yield));
            }
        }
        assert!(
            suspended,
            "stop after translation but before the physical write"
        );
        let token = mappings
            .with_code_watch(0x5000..0x5008, |ram| {
                watches.capture(0x5000..0x5008, || ram.read::<8>(0x5000))
            })
            .unwrap()
            .unwrap();
        assert_eq!(*token.value(), 0xa1u64.to_le_bytes());
        {
            let access = mappings.access();
            let ram = access.ram();
            assert!(matches!(
                mmu.run(&ram, 1).unwrap(),
                Progress::CompleteWord(_)
            ));
        }
        assert!(!token.is_valid());
        assert_eq!(*token.value(), 0xa1u64.to_le_bytes());
        assert_eq!(
            memory.read_plain::<u64>(0x5000).unwrap(),
            0x1122_3344_5566_7788
        );
    }
}
