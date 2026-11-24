// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use guestmem::WriteObserver;
use parking_lot::Mutex;
use sparse_mmap::SparseMapping;
use std::sync::{Arc, mpsc};
use std::thread;
use test_with_tracing::test;

#[derive(Default)]
struct Observer(Mutex<Vec<Range<u64>>>);

impl WriteObserver for Observer {
    fn notify_write(&self, range: Range<u64>) {
        self.0.lock().push(range);
    }
}

struct Memory {
    partition: PartitionMemory,
    backing: SparseMapping,
    observer: Arc<Observer>,
    tracker: WriteTracker,
}

fn fixture(size: usize, committed: usize) -> Memory {
    let backing = SparseMapping::new(size).unwrap();
    backing.alloc(0, committed).unwrap();
    let observer = Arc::new(Observer::default());
    let tracker = WriteTracker::new(observer.clone());
    let partition = PartitionMemory::with_write_tracker(tracker.clone());
    // SAFETY: Memory destroys the table before the backing reservation.
    unsafe { partition.map_range(backing.as_ptr().cast(), size, 0, true, true) }.unwrap();
    Memory {
        partition,
        backing,
        observer,
        tracker,
    }
}

fn operations(width: u8) -> Vec<AtomicOperation> {
    let mut operations = vec![
        AtomicOperation::CompareExchange {
            expected: 0,
            replacement: 7,
        },
        AtomicOperation::CompareExchange {
            expected: u64::MAX,
            replacement: 9,
        },
        AtomicOperation::Exchange { replacement: 11 },
        AtomicOperation::FetchAdd { source: 3 },
    ];
    for operation in [
        integer::Operation::Add,
        integer::Operation::Adc,
        integer::Operation::Sub,
        integer::Operation::Sbb,
        integer::Operation::And,
        integer::Operation::Or,
        integer::Operation::Xor,
        integer::Operation::Inc,
        integer::Operation::Dec,
        integer::Operation::Neg,
        integer::Operation::Not,
        integer::Operation::BitSet,
        integer::Operation::BitReset,
        integer::Operation::BitComplement,
    ] {
        if width == 1
            && matches!(
                operation,
                integer::Operation::BitSet
                    | integer::Operation::BitReset
                    | integer::Operation::BitComplement
            )
        {
            continue;
        }
        operations.push(AtomicOperation::Integer {
            operation,
            source: 3,
            flags: 2,
        });
    }
    operations
}

#[test]
fn pte_compare_only_attempts_aligned_unwatched_ram() {
    use x86_system::memory::physical::TranslatedRam;

    let memory = fixture(12288, 8192);
    memory
        .partition
        .with_code_watch(4096..4104, |_| ())
        .unwrap();
    let access = memory.partition.access();
    let ram = access.ram();
    let mut cache = NativeTranslations::default();
    let mut view = ram.translated(&mut cache);
    for address in [1, 4096, 12288] {
        assert!(view.compare_unwatched_pte(address, 0, 7).is_none());
    }
    assert_eq!(memory.backing.read_plain::<[u8; 8]>(1).unwrap(), [0; 8]);
    assert_eq!(memory.backing.read_plain::<u64>(4096).unwrap(), 0);
    assert_eq!(
        view.compare_unwatched_pte(0, 0, 7).unwrap().unwrap(),
        AtomicResult::Value(0)
    );
    assert_eq!(
        view.compare_unwatched_pte(0, 0, 9).unwrap().unwrap(),
        AtomicResult::Value(7)
    );
    assert_eq!(memory.backing.read_plain::<u64>(0).unwrap(), 7);
    assert!(view.compare_unwatched_pte(8192, 0, 7).unwrap().is_err());
    assert!(memory.observer.0.lock().is_empty());
}

#[test]
fn unwatched_stores_and_atomics_do_not_enter_the_tracker() {
    let memory = fixture(12288, 12288);
    memory
        .partition
        .with_code_watch(4096..4097, |_| ())
        .unwrap();
    let access = memory.partition.access();
    let ram = access.ram();
    // An exclusive tracker gate must not obstruct any untouched-page write.
    memory.tracker.synchronize(|| {
        ram.write(0, [1]).unwrap();
        ram.write(8, [2; 2]).unwrap();
        ram.write(16, [3; 4]).unwrap();
        ram.write(24, [4; 8]).unwrap();
        ram.write_bytes(8192, &[5; 37]).unwrap();
        for width in [1, 2, 4, 8] {
            for operation in operations(width) {
                ram.atomic(64, width, operation).unwrap();
            }
        }
    });
    assert!(memory.observer.0.lock().is_empty());
    ram.write(4096, [7]).unwrap();
    ram.write(8191, [9]).unwrap();
    assert_eq!(*memory.observer.0.lock(), [4096..4097, 8191..8192]);
    assert_eq!(memory.backing.read_plain::<u8>(8192).unwrap(), 5);
}

#[test]
fn cross_span_scalars_or_watch_permissions_and_preserve_neighbors() {
    let memory = fixture(12288, 12288);
    memory.backing.write_at(0, &[0xa5; 12288]).unwrap();
    memory
        .partition
        .with_code_watch(4100..4101, |_| ())
        .unwrap();
    let access = memory.partition.access();
    let ram = access.ram();
    for (address, value) in [(4093, [0x33; 8]), (8189, [0x77; 8])] {
        ram.write(address, value).unwrap();
        assert_eq!(ram.read::<8>(address).unwrap(), value);
        assert_eq!(ram.read::<1>(address - 1).unwrap(), [0xa5]);
        assert_eq!(ram.read::<1>(address + 8).unwrap(), [0xa5]);
    }
    assert_eq!(*memory.observer.0.lock(), [4093..4101, 8189..8197]);
    // Read permission and contiguity remain checked on *every* touched span.
    assert!(matches!(
        ram.write(12285, [0; 8]),
        Err(RamError::Unmapped(12288))
    ));
    assert_eq!(memory.observer.0.lock().len(), 2);
}

#[test]
fn watched_scalar_widths_notify_exact_ranges_and_preserve_neighbors() {
    let memory = fixture(4096, 4096);
    memory.partition.with_code_watch(0..1, |_| ()).unwrap();
    let access = memory.partition.access();
    let ram = access.ram();
    for width in [1, 2, 4, 8] {
        memory.backing.write_at(0, &[0xa5; 16]).unwrap();
        memory.observer.0.lock().clear();
        match width {
            1 => ram.write(3, [0x33]),
            2 => ram.write(3, [0x33; 2]),
            4 => ram.write(3, [0x33; 4]),
            8 => ram.write(3, [0x33; 8]),
            _ => unreachable!(),
        }
        .unwrap();
        let mut expected = [0xa5; 16];
        expected[3..3 + width].fill(0x33);
        assert_eq!(memory.backing.read_plain::<[u8; 16]>(0).unwrap(), expected);
        assert_eq!(*memory.observer.0.lock(), [3..3 + width as u64]);
    }
}

#[test]
fn every_atomic_profile_and_pte_update_notifies_before_returning() {
    let memory = fixture(4096, 4096);
    memory.partition.with_code_watch(0..8, |_| ()).unwrap();
    let access = memory.partition.access();
    let ram = access.ram();
    for width in [1, 2, 4, 8] {
        for operation in operations(width) {
            memory.backing.write_at(8, &[0; 8]).unwrap();
            memory.observer.0.lock().clear();
            let result = ram.atomic(8, width, operation).unwrap();
            assert_eq!(*memory.observer.0.lock(), [8..8 + u64::from(width)]);
            if matches!(
                operation,
                AtomicOperation::CompareExchange {
                    expected: u64::MAX,
                    ..
                }
            ) {
                assert_eq!(result, AtomicResult::Value(0));
                assert_eq!(ram.read::<8>(8).unwrap(), [0; 8]);
            }
        }
    }
    memory.backing.write_volatile(16, &0x2007u64).unwrap();
    memory.observer.0.lock().clear();
    assert_eq!(ram.try_mark_ad(16, 0x2007, true).unwrap(), AdUpdate::Marked);
    assert_eq!(*memory.observer.0.lock(), [16..24]);
    assert_eq!(u64::from_le_bytes(ram.read(16).unwrap()), 0x2067);
}

#[test]
fn faulting_stores_and_atomics_still_notify_and_bulk_keeps_exact_prefix() {
    let memory = fixture(8192, 4096);
    memory.partition.with_code_watch(0..8192, |_| ()).unwrap();
    let access = memory.partition.access();
    let ram = access.ram();
    let error = ram.write_bytes(4085, &[0x33; 19]).unwrap_err();
    assert_eq!(error.completed, 11);
    assert!(matches!(
        error.kind,
        CopyErrorKind::Memory(RamError::Memory(_))
    ));
    assert_eq!(
        *memory.observer.0.lock(),
        [4085..4086, 4086..4088, 4088..4096, 4096..4104]
    );
    assert_eq!(
        memory.backing.read_plain::<[u8; 11]>(4085).unwrap(),
        [0x33; 11]
    );
    for operation in operations(8) {
        memory.observer.0.lock().clear();
        assert!(ram.atomic(4096, 8, operation).is_err());
        assert_eq!(*memory.observer.0.lock(), [4096..4104]);
    }
    memory.observer.0.lock().clear();
    assert!(matches!(ram.write(4096, [1; 8]), Err(RamError::Memory(_))));
    assert_eq!(*memory.observer.0.lock(), [4096..4104]);
}

#[test]
fn watch_activation_drains_all_old_batches_and_captures_latest_writes() {
    let memory = fixture(8192, 8192);
    // Existing watched writes must be able to finish their postnotifications
    // while a new capture is waiting for its exclusive mapping lease.
    memory.partition.with_code_watch(0..8, |_| ()).unwrap();
    thread::scope(|scope| {
        let mut releases = Vec::new();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        for lane in 0..2 {
            let (release_tx, release_rx) = mpsc::channel();
            releases.push(release_tx);
            let ready_tx = ready_tx.clone();
            let done_tx = done_tx.clone();
            let memory = &memory;
            scope.spawn(move || {
                let access = memory.partition.access();
                ready_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                access.ram().write(lane * 8, [lane as u8 + 1; 8]).unwrap();
                // This was an unwatched page when the lease was issued.
                access
                    .ram()
                    .write(4096 + lane * 8, [lane as u8 + 3; 8])
                    .unwrap();
                drop(access);
                done_tx.send(()).unwrap();
            });
        }
        ready_rx.recv().unwrap();
        ready_rx.recv().unwrap();
        assert!(memory.partition.mappings.try_write().is_none());
        let (started_tx, started_rx) = mpsc::channel();
        let (captured_tx, captured_rx) = mpsc::channel();
        let memory = &memory;
        scope.spawn(move || {
            started_tx.send(()).unwrap();
            let captured = memory
                .partition
                .with_code_watch(4096..4112, |ram| {
                    memory.tracker.synchronize(|| {
                        let mut bytes = [0; 16];
                        ram.read_bytes(4096, &mut bytes).unwrap();
                        bytes
                    })
                })
                .unwrap();
            captured_tx.send(captured).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(matches!(
            captured_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        releases[0].send(()).unwrap();
        done_rx.recv().unwrap();
        assert!(memory.partition.mappings.try_write().is_none());
        assert!(matches!(
            captured_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        releases[1].send(()).unwrap();
        done_rx.recv().unwrap();
        let captured = captured_rx.recv().unwrap();
        assert_eq!(captured[..8], [3; 8]);
        assert_eq!(captured[8..], [4; 8]);
    });
    assert_eq!(memory.observer.0.lock().len(), 2);
    let access = memory.partition.access();
    access.ram().write(4096, [5; 8]).unwrap();
    assert_eq!(memory.observer.0.lock().last(), Some(&(4096..4104)));
}

#[test]
fn watch_splits_preserve_original_unmap_identity_and_remap_is_unwatched() {
    let memory = fixture(12288, 12288);
    memory
        .partition
        .with_code_watch(4096..8192, |_| ())
        .unwrap();
    for (address, size) in [(0, 4096), (4096, 4096), (8192, 4096), (0, 8192)] {
        let error = memory.partition.unmap_range(address, size).unwrap_err();
        assert_eq!(
            error.downcast_ref::<MapError>(),
            Some(&MapError::PartialUnmap)
        );
    }
    // Covering adjacent watched pages merges spans from the same original map.
    memory.partition.with_code_watch(0..4096, |_| ()).unwrap();
    assert_eq!(memory.partition.mappings.read().len(), 2);
    memory
        .partition
        .with_code_watch(8192..12288, |_| ())
        .unwrap();
    assert_eq!(memory.partition.mappings.read().len(), 1);
    memory.partition.unmap_range(0, 12288).unwrap();
    // SAFETY: the owner still reserves the same backing.
    unsafe {
        memory
            .partition
            .map_range(memory.backing.as_ptr().cast(), 12288, 0, true, true)
    }
    .unwrap();
    let access = memory.partition.access();
    memory
        .tracker
        .synchronize(|| access.ram().write(4096, [7; 8]).unwrap());
    assert!(memory.observer.0.lock().is_empty());
}

#[test]
fn tracked_mapping_rejects_host_aliases_even_after_watch_splitting() {
    let memory = fixture(12288, 12288);
    memory
        .partition
        .with_code_watch(4096..8192, |_| ())
        .unwrap();
    for offset in [0, 4096, 8192] {
        // SAFETY: these aliases borrow the still-live backing; all must be rejected.
        let error = unsafe {
            memory.partition.map_range(
                memory.backing.as_ptr().cast::<u8>().add(offset),
                4096,
                16384,
                true,
                true,
            )
        }
        .unwrap_err();
        assert_eq!(error.downcast_ref::<MapError>(), Some(&MapError::HostAlias));
    }
}

#[test]
fn invalid_watch_ranges_and_untracked_tables_are_rejected() {
    let memory = fixture(4096, 4096);
    for (start, end) in [(7, 7), (9, 8)] {
        assert!(matches!(
            memory
                .partition
                .with_code_watch(start..end, |_| panic!("invalid callback")),
            Err(RamError::InvalidWatchRange)
        ));
    }
    assert!(matches!(
        PartitionMemory::new().with_code_watch(0..1, |_| panic!("untracked callback")),
        Err(RamError::Untracked)
    ));
    assert!(!memory.partition.mappings.read()[0].watched);
}

#[test]
fn last_physical_page_watch_rounding_does_not_wrap() {
    let memory = fixture(4096, 4096);
    memory.partition.unmap_range(0, 4096).unwrap();
    let start = u64::MAX - 4095;
    // SAFETY: the owner retains the same live backing at a new physical name.
    unsafe {
        memory
            .partition
            .map_range(memory.backing.as_ptr().cast(), 4095, start, true, true)
    }
    .unwrap();
    memory
        .partition
        .with_code_watch(u64::MAX - 1..u64::MAX, |_| ())
        .unwrap();
    let access = memory.partition.access();
    access.ram().write(u64::MAX - 1, [7]).unwrap();
    assert_eq!(*memory.observer.0.lock(), [u64::MAX - 1..u64::MAX]);
    assert_eq!(memory.backing.read_plain::<u8>(4094).unwrap(), 7);
}

#[test]
fn invalid_observer_mapping_ranges_are_rejected_before_any_write() {
    let observer = Arc::new(Observer::default());
    let backing = SparseMapping::new(4096).unwrap();
    backing.alloc(0, 4096).unwrap();
    backing.write_at(0, &[0xa5; 4096]).unwrap();
    for offset in [u64::MAX, u64::MAX - 4095] {
        let tracker = WriteTracker::new(observer.clone())
            .with_offset(offset)
            .unwrap();
        let partition = PartitionMemory::with_write_tracker(tracker);
        // SAFETY: the partition drops before its reservation; invalid observer
        // ranges must be rejected without exposing the otherwise valid backing.
        let error = unsafe { partition.map_range(backing.as_ptr().cast(), 4096, 0, true, true) }
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<MapError>(),
            Some(&MapError::InvalidObserverRange)
        );
        assert!(partition.mappings.read().is_empty());
        assert!(matches!(
            partition.access().ram().write(0, [7]),
            Err(RamError::Unmapped(0))
        ));
        assert_eq!(backing.read_plain::<[u8; 4096]>(0).unwrap(), [0xa5; 4096]);
    }
    assert!(observer.0.lock().is_empty());
}

#[test]
fn accepted_observer_boundary_supports_scalars_atomics_and_copy_prefixes() {
    let observer = Arc::new(Observer::default());
    let offset = u64::MAX - 4096;
    let tracker = WriteTracker::new(observer.clone())
        .with_offset(offset)
        .unwrap();
    let backing = SparseMapping::new(4096).unwrap();
    backing.alloc(0, 4096).unwrap();
    let partition = PartitionMemory::with_write_tracker(tracker);
    // SAFETY: the partition drops before its reservation.
    unsafe { partition.map_range(backing.as_ptr().cast(), 4096, 0, true, true) }.unwrap();
    partition.with_code_watch(0..4096, |_| ()).unwrap();
    let access = partition.access();
    let ram = access.ram();
    ram.write(4095, [7]).unwrap();
    ram.atomic(4088, 8, AtomicOperation::Exchange { replacement: 9 })
        .unwrap();
    ram.write_bytes(4085, &[5; 11]).unwrap();
    assert_eq!(
        *observer.0.lock(),
        [
            u64::MAX - 1..u64::MAX,
            u64::MAX - 8..u64::MAX,
            offset + 4085..offset + 4086,
            offset + 4086..offset + 4088,
            u64::MAX - 8..u64::MAX,
        ]
    );
    assert_eq!(backing.read_plain::<[u8; 11]>(4085).unwrap(), [5; 11]);
}
