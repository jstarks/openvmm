// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::write_watch::WriteWatch;
use sparse_mmap::SparseMapping;
use std::sync::mpsc;
use std::thread;
use test_with_tracing::test;

struct Memory {
    partition: PartitionMemory,
    backing: SparseMapping,
    watches: WriteWatch,
}

fn fixture(committed: bool) -> Memory {
    let watches = WriteWatch::default();
    let partition = PartitionMemory::with_write_tracker(watches.tracker());
    let backing = SparseMapping::new(8192).unwrap();
    if committed {
        backing.alloc(0, 8192).unwrap();
    }
    // SAFETY: the partition is destroyed before its reserved backing.
    unsafe { partition.map_range(backing.as_ptr().cast(), 8192, 0, true, true) }.unwrap();
    Memory {
        partition,
        backing,
        watches,
    }
}

fn request(memory: &Memory, address: u64) {
    let access = memory.partition.access();
    assert!(access.ram().code_token(address, 1).is_none());
}

fn prepare(memory: &Memory) -> CodePreparation {
    memory
        .partition
        .prepare_code_pages(&memory.watches)
        .unwrap()
}

fn token(memory: &Memory, address: u64) -> CodeToken {
    let access = memory.partition.access();
    access.ram().code_token(address, 1).unwrap().clone()
}

fn domain(partition: &PartitionMemory) -> strudel::CodeDomain {
    partition.access().ram().code_domain().unwrap().clone()
}

#[test]
fn normal_leases_share_a_domain_even_when_watches_are_added_or_renewed() {
    let memory = fixture(true);
    let original = domain(&memory.partition);
    request(&memory, 0);
    prepare(&memory);
    assert!(original.same_domain(&domain(&memory.partition)));
    let first = token(&memory, 0);
    request(&memory, 4096);
    prepare(&memory);
    memory.watches.tracker().notify_write(4096, 1).unwrap();
    request(&memory, 4096);
    prepare(&memory);
    assert!(first.is_valid());
    assert!(original.same_domain(memory.partition.access().ram().code_domain().unwrap()));
}

#[test]
fn partitions_sharing_a_tracker_have_distinct_code_domains() {
    let memory = fixture(true);
    let other = PartitionMemory::with_write_tracker(memory.watches.tracker());
    assert!(!domain(&memory.partition).same_domain(&domain(&other)));
}

#[test]
fn cold_query_and_page_registration_do_not_read_backing() {
    let memory = fixture(false);
    {
        let access = memory.partition.access();
        let ram = access.ram();
        assert!(ram.code_token(0, 1).is_none());
        assert!(ram.code_token(4095, 1).is_none());
        assert_eq!(
            *memory.partition.pending_code_pages.lock(),
            BTreeSet::from([0])
        );
    }
    assert_eq!(
        prepare(&memory),
        CodePreparation {
            prepared: 1,
            unavailable: 0,
        }
    );
    let access = memory.partition.access();
    let ram = access.ram();
    let first = ram.code_token(0, 1).unwrap();
    assert!(first.is_valid());
    for _ in 0..32 {
        assert!(std::ptr::eq(first, ram.code_token(8, 15).unwrap()));
    }
    assert!(memory.partition.pending_code_pages.lock().is_empty());
}

#[test]
fn every_cpu_write_kind_and_dma_invalidates_the_whole_page() {
    let memory = fixture(true);
    request(&memory, 0);
    prepare(&memory);
    let mut previous = token(&memory, 0);
    for operation in 0..4 {
        {
            let access = memory.partition.access();
            let ram = access.ram();
            match operation {
                0 => ram.write(4095, [7]).unwrap(),
                1 => ram.write_bytes(4000, &[3; 17]).unwrap(),
                2 => {
                    ram.atomic(4088, 8, AtomicOperation::Exchange { replacement: 9 })
                        .unwrap();
                }
                _ => memory.watches.tracker().notify_write(2048, 1).unwrap(),
            }
            assert!(!previous.is_valid());
            assert!(ram.code_token(0, 1).is_none());
        }
        assert_eq!(prepare(&memory).prepared, 1);
        let fresh = token(&memory, 0);
        assert!(fresh.is_valid());
        assert!(!fresh.same_observation(&previous));
        previous = fresh;
    }
    // External writes to another physical page do not invalidate this one.
    memory.watches.tracker().notify_write(4096, 1).unwrap();
    assert!(previous.is_valid());
}

#[test]
fn queries_qualify_the_exact_physical_span_without_normalizing_aliases() {
    let memory = fixture(true);
    request(&memory, 0);
    prepare(&memory);
    let access = memory.partition.access();
    let ram = access.ram();
    for (address, length) in [
        (0, 0),
        (0, 16),
        (4095, 2),
        (8192, 1),
        (1 << 48, 1),
        (u64::MAX, 1),
    ] {
        assert!(ram.code_token(address, length).is_none());
    }
    assert!(memory.partition.pending_code_pages.lock().is_empty());
    assert!(ram.code_token(4095, 1).is_some());
    assert!(ram.code_token(4096, 1).is_none());
    assert_eq!(
        *memory.partition.pending_code_pages.lock(),
        BTreeSet::from([4096])
    );
}

#[test]
fn discontiguous_host_spans_and_unrepresentable_page_ends_stay_fresh() {
    let watches = WriteWatch::default();
    let partition = PartitionMemory::with_write_tracker(watches.tracker());
    let backing = SparseMapping::new(8192).unwrap();
    // SAFETY: all mappings are removed before the reserved backing is dropped.
    unsafe {
        partition
            .map_range(backing.as_ptr().cast(), 8, 0, true, true)
            .unwrap();
        partition
            .map_range(backing.as_ptr().cast::<u8>().add(4096), 4088, 8, true, true)
            .unwrap();
    }
    {
        let access = partition.access();
        let ram = access.ram();
        assert!(ram.code_token(7, 2).is_none());
        assert!(partition.pending_code_pages.lock().is_empty());
        assert!(ram.code_token(0, 1).is_none());
    }
    assert!(partition.pending_code_pages.lock().is_empty());
    assert_eq!(
        partition.prepare_code_pages(&watches).unwrap(),
        CodePreparation {
            prepared: 0,
            unavailable: 0
        }
    );
    partition.unmap_range(0, 4096).unwrap();
    let last_page = u64::MAX - 4095;
    // SAFETY: the retained reservation supports this distinct physical name.
    unsafe { partition.map_range(backing.as_ptr().cast(), 4095, last_page, true, true) }.unwrap();
    {
        let access = partition.access();
        assert!(access.ram().code_token(last_page, 1).is_none());
        assert!(partition.pending_code_pages.lock().is_empty());
    }
    partition.unmap_range(last_page, 4095).unwrap();
}

#[test]
fn unmap_discards_identity_and_pending_disappearance_is_unavailable() {
    let memory = fixture(true);
    request(&memory, 0);
    prepare(&memory);
    let old = token(&memory, 0);
    let old_domain = domain(&memory.partition);
    request(&memory, 4096);
    memory.partition.unmap_range(0, 8192).unwrap();
    assert!(old.is_valid());
    assert!(!old_domain.same_domain(&domain(&memory.partition)));
    assert_eq!(
        prepare(&memory),
        CodePreparation {
            prepared: 0,
            unavailable: 1,
        }
    );
    // SAFETY: the same reserved backing remains owned by this fixture.
    unsafe {
        memory
            .partition
            .map_range(memory.backing.as_ptr().cast(), 8192, 0, true, true)
    }
    .unwrap();
    assert!(memory.partition.code.read().tokens.is_empty());
    request(&memory, 0);
    prepare(&memory);
    assert!(!token(&memory, 0).same_observation(&old));
}

#[test]
fn untracked_queries_and_mismatched_preparation_publish_nothing() {
    let partition = PartitionMemory::new();
    assert!(partition.access().ram().code_token(0, 1).is_none());
    assert!(partition.pending_code_pages.lock().is_empty());
    let memory = fixture(true);
    request(&memory, 0);
    assert!(matches!(
        memory.partition.prepare_code_pages(&WriteWatch::default()),
        Err(RamError::TrackerMismatch)
    ));
    assert!(memory.partition.code.read().tokens.is_empty());
    assert_eq!(prepare(&memory).prepared, 1);
    let translated =
        PartitionMemory::with_write_tracker(memory.watches.tracker().with_offset(1).unwrap());
    assert!(matches!(
        translated.prepare_code_pages(&memory.watches),
        Err(RamError::TrackerMismatch)
    ));
}

#[test]
fn preparation_drains_requests_before_waiting_for_active_batches() {
    let memory = fixture(true);
    request(&memory, 0);
    thread::scope(|scope| {
        let access = memory.partition.access();
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let memory = &memory;
        scope.spawn(move || {
            started_tx.send(()).unwrap();
            done_tx.send(prepare(memory)).unwrap();
        });
        started_rx.recv().unwrap();
        // Taking this lock must remain possible while preparation waits for
        // the batch, otherwise its cold request would deadlock lease release.
        assert!(access.ram().code_token(4096, 1).is_none());
        assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        drop(access);
        assert!(done_rx.recv().unwrap().prepared >= 1);
    });
    prepare(&memory);
    assert!(token(&memory, 0).is_valid());
    assert!(token(&memory, 4096).is_valid());
}
