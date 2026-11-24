// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CPU/external write observations, not guest fetch authorization.
//!
//! The partition drains CPU leases before acquiring the external capture gate.
//! Observations do not qualify guest execution permissions. A qualified fetch
//! may reuse a decoded receipt while its physical code observation is valid.

use crate::native_memory::RamError;
use guestmem::{WriteObserver, WriteTracker};
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::{Arc, Weak};
use x86_system::memory::physical::{CodeValidity, PageWatch};

struct Watch {
    range: Range<u64>,
    validity: Arc<PageWatch>,
}

impl CodeValidity for Watch {
    fn is_valid(&self) -> bool {
        self.validity.is_valid()
    }
}

#[derive(Default)]
struct WatchIndex {
    pages: BTreeMap<u64, SmallVec<[Weak<PageWatch>; 1]>>,
    ranges: Vec<Weak<Watch>>,
}

#[derive(Default)]
struct Watches(Mutex<WatchIndex>);

impl WriteObserver for Watches {
    fn notify_write(&self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }
        let pages = range.start / 4096..=(range.end - 1) / 4096;
        let mut index = self.0.lock();
        index
            .pages
            .extract_if(pages, |_, watches| {
                for watch in watches.iter().filter_map(Weak::upgrade) {
                    watch.revoke();
                }
                true
            })
            .for_each(drop);
        index.ranges.retain(|weak| {
            let Some(watch) = weak.upgrade() else {
                return false;
            };
            if watch.range.start < range.end && range.start < watch.range.end {
                watch.validity.revoke();
            }
            watch.is_valid()
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
    Capture(#[from] CaptureError<RamError>),
}

/// Captured value and its write-validity token.
pub struct Watched<T> {
    value: T,
    watch: Arc<Watch>,
}

impl<T> Watched<T> {
    pub(crate) fn validity(&self) -> &Arc<PageWatch> {
        &self.watch.validity
    }
    /// The original captured value, including after invalidation.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Whether participating writes have invalidated this observation.
    ///
    /// This does not authorize guest instruction execution. The observation
    /// assumes all external writers obey the observed backing configuration.
    pub fn is_valid(&self) -> bool {
        self.watch.is_valid()
    }
}

impl WriteWatch {
    /// The same tracker is installed in every supported device-memory view.
    pub(crate) fn tracker(&self) -> WriteTracker {
        self.tracker.clone()
    }

    /// Registers a whole physical page without accessing its backing bytes.
    ///
    /// The caller holds the exclusive mapping lease. Publication remains under
    /// the external write gate, after all old CPU leases have been revoked.
    pub(crate) fn capture_page(
        &self,
        page: u64,
        publish: impl FnOnce(Arc<PageWatch>),
    ) -> Result<(), RamError> {
        if !page.is_multiple_of(4096) {
            return Err(RamError::InvalidWatchRange);
        }
        page.checked_add(4096).ok_or(RamError::AddressOverflow)?;
        self.tracker.synchronize(|| {
            let mut index = self.watches.0.lock();
            // The address identifies which watches to revoke, not the
            // observation: an old token can outlive an unmap and remap.
            let watches = index.pages.entry(page / 4096).or_default();
            watches.retain(|weak| weak.upgrade().is_some_and(|watch| watch.is_valid()));
            let watch = Arc::new(PageWatch::default());
            watches.push(Arc::downgrade(&watch));
            drop(index);
            publish(watch);
        });
        Ok(())
    }

    fn register_watch(&self, range: Range<u64>) -> Arc<Watch> {
        let watch = Arc::new(Watch {
            range,
            validity: Arc::new(PageWatch::default()),
        });
        let mut index = self.watches.0.lock();
        let watches = &mut index.ranges;
        watches.retain(|entry| entry.strong_count() != 0);
        watches.push(Arc::downgrade(&watch));
        watch
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
            let watch = self.register_watch(range);
            Ok(Watched { value, watch })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapped_test_memory::MappedTestMemory;
    use crate::native_memory::PartitionMemory;
    use strudel::CodeToken;
    use test_with_tracing::test;
    use virt::PartitionMemoryMap;
    use x86_system::WordAccess;
    use x86_system::memory::physical::PhysicalRam;
    use x86_system::mmu::translate::{Progress, Request, Translator};

    #[test]
    fn borrowed_code_hits_never_clone_the_watch_arc() {
        let watches = WriteWatch::default();
        let mappings = PartitionMemory::with_write_tracker(watches.tracker());
        let backing = sparse_mmap::SparseMapping::new(4096).unwrap();
        // SAFETY: this test unmaps before dropping the reserved backing.
        // UNSAFETY: installs the test-owned reservation for metadata-only queries.
        #[expect(unsafe_code)]
        unsafe { mappings.map_range(backing.as_ptr().cast(), 4096, 0, true, true) }.unwrap();
        {
            let access = mappings.access();
            assert!(access.ram().code_token(0, 1).is_none());
        }
        mappings.prepare_code_pages(&watches).unwrap();
        {
            let access = mappings.access();
            let ram = access.ram();
            let first = ram.code_token(0, 1).unwrap();
            for _ in 0..64 {
                assert!(first.same_observation(ram.code_token(64, 15).unwrap()));
                assert_eq!(watches.watches.0.lock().pages[&0][0].strong_count(), 1);
            }
        }
        mappings.unmap_range(0, 4096).unwrap();
    }

    #[test]
    fn a_cross_page_write_revokes_only_overlapping_pages_and_ranges() {
        let watches = WriteWatch::default();
        let mut tokens = Vec::new();
        for page in [0, 4096, 8192, 4096] {
            watches
                .capture_page(page, |watch| tokens.push(CodeToken::from_page(watch)))
                .unwrap();
        }
        assert!(!tokens[1].same_observation(&tokens[3]));
        let span = watches
            .capture(4095..4097, || Ok::<_, std::io::Error>(()))
            .unwrap();
        watches.tracker().notify_write(4095, 2).unwrap();
        assert_eq!(
            tokens.iter().map(CodeToken::is_valid).collect::<Vec<_>>(),
            [false, false, true, false]
        );
        assert!(!span.is_valid());
        watches
            .capture_page(4096, |token| assert!(token.is_valid()))
            .unwrap();
    }

    #[test]
    fn observed_guest_memory_write_invalidates_a_native_page_identity() {
        let watches = WriteWatch::default();
        let mappings = Arc::new(PartitionMemory::with_write_tracker(watches.tracker()));
        let memory = MappedTestMemory::observed(mappings.clone(), &[0; 8192], watches.tracker());
        {
            let access = mappings.access();
            assert!(access.ram().code_token(0, 1).is_none());
        }
        mappings.prepare_code_pages(&watches).unwrap();
        let token = {
            let access = mappings.access();
            access.ram().code_token(0, 1).unwrap().clone()
        };
        memory.write_at(4096, &[0x90]).unwrap();
        assert!(token.is_valid());
        memory.write_at(4095, &[0x90]).unwrap();
        assert!(!token.is_valid());
        let access = mappings.access();
        assert!(access.ram().code_token(0, 1).is_none());
    }

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
        assert!(watches.watches.0.lock().ranges.is_empty());
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
        let token = mappings.capture_code::<8>(&watches, 0x5000).unwrap();
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
