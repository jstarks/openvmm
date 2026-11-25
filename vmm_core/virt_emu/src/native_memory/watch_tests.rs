// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::write_watch::WriteWatch;
use sparse_mmap::SparseMapping;
use test_with_tracing::test;

struct Memory {
    partition: PartitionMemory,
    backing: SparseMapping,
    watches: WriteWatch,
}

fn fixture(start: u64, size: usize, committed: usize) -> Memory {
    let backing = SparseMapping::new(size).unwrap();
    backing.alloc(0, committed).unwrap();
    let watches = WriteWatch::default();
    let partition = PartitionMemory::with_write_tracker(watches.tracker());
    // SAFETY: the owned reservation outlives all leases and mappings.
    unsafe { partition.map_range(backing.as_ptr().cast(), size, start, true, true) }.unwrap();
    Memory {
        partition,
        backing,
        watches,
    }
}

#[test]
fn binding_epoch_tracks_backing_and_watches_not_ram_contents() {
    let m = fixture(0, 8192, 8192);
    let epoch = || m.partition.access().binding_epoch().clone();
    let original = epoch();
    m.partition.access().ram().write(0, [1]).unwrap();
    assert!(original.same_generation(&epoch()));
    m.partition.unmap_range(0, 8192).unwrap();
    let unmapped = epoch();
    assert!(!original.same_generation(&unmapped));
    // SAFETY: this remaps the same still-live reservation with narrower permissions.
    unsafe {
        m.partition
            .map_range(m.backing.as_ptr().cast(), 8192, 0, false, true)
    }
    .unwrap();
    let remapped = epoch();
    assert!(!unmapped.same_generation(&remapped));
    let _capture = m.partition.capture_code::<4>(&m.watches, 0).unwrap();
    let captured = epoch();
    assert!(!remapped.same_generation(&captured));
    assert!(m.partition.access().ram().code_token(4096, 1).is_none());
    assert_eq!(
        m.partition.prepare_code_pages(&m.watches).unwrap().prepared,
        1
    );
    assert!(!captured.same_generation(&epoch()));
}

#[test]
fn cpu_watch_downgrades_vtlb_fill_not_backing_permissions() {
    for start in [0, 1 << 40] {
        let m = fixture(start, 8192, 8192);
        let p = start / 4096;
        {
            let lease = m.partition.access();
            assert!(lease.ram().direct_page(p).unwrap().writable());
        }
        let token = m
            .partition
            .capture_code::<8>(&m.watches, start + 24)
            .unwrap();
        let lease = m.partition.access();
        assert_eq!(lease.mappings.len(), 1);
        assert!(lease.mappings[0].writable);
        let ram = lease.ram();
        assert!(!ram.direct_page(p).unwrap().writable());
        assert!(ram.direct_page(p + 1).unwrap().writable());
        // The DMA registration gate is already held. A CPU writer must not
        // enter it, even when it is precisely the writer revoking the token.
        m.watches.tracker().synchronize(|| {
            ram.write(start + 23, [9]).unwrap();
            assert!(token.is_valid());
            assert_eq!(
                ram.atomic(start + 24, 8, AtomicOperation::FetchAdd { source: 5 })
                    .unwrap(),
                AtomicResult::Value(0)
            );
            assert!(!token.is_valid());
        });
        assert_eq!(m.backing.read_plain::<u64>(24).unwrap(), 5);
    }
}

#[test]
fn failed_bulk_write_revokes_only_the_committed_prefix() {
    let m = fixture(0, 8192, 8192);
    m.partition.unmap_range(0, 8192).unwrap();
    // SAFETY: both mappings borrow the fixture's populated reservation.
    unsafe {
        m.partition
            .map_range(m.backing.as_ptr().cast(), 4096, 0, true, true)
            .unwrap();
        m.partition
            .map_range(m.backing.as_ptr().add(4096).cast(), 4096, 4096, false, true)
            .unwrap();
    }
    let prefix = m.partition.capture_code::<4>(&m.watches, 4092).unwrap();
    let suffix = m.partition.capture_code::<8>(&m.watches, 4096).unwrap();
    let access = m.partition.access();
    let ram = access.ram();
    assert_eq!(ram.write_bytes(4092, &[0xa5; 12]).unwrap_err().completed, 4);
    assert!(!prefix.is_valid());
    assert!(suffix.is_valid());
    assert_eq!(ram.read::<4>(4092).unwrap(), [0xa5; 4]);
}

#[test]
fn capture_excludes_old_writable_leases_and_unmap_discards_range_watch() {
    use std::{sync::mpsc, thread};
    let m = fixture(0, 8192, 8192);
    let token = thread::scope(|s| {
        let lease = m.partition.access();
        let (started, wait) = mpsc::channel();
        let m = &m;
        let child = s.spawn(move || {
            started.send(()).unwrap();
            m.partition.capture_code::<8>(&m.watches, 4096).unwrap()
        });
        wait.recv().unwrap();
        assert!(m.partition.mappings.try_write().is_none());
        lease.ram().write(4096, 7u64.to_le_bytes()).unwrap();
        drop(lease);
        child.join().unwrap()
    });
    assert_eq!(u64::from_le_bytes(*token.value()), 7);
    assert!(m.partition.unmap_range(4096, 4096).is_err());
    assert!(token.is_valid());
    m.partition.unmap_range(0, 8192).unwrap();
    assert!(!token.is_valid());
}

#[test]
fn failed_capture_installs_no_cpu_watch() {
    let m = fixture(0, 8192, 4096);
    for addr in [4092, 4096, 8192, u64::MAX] {
        assert!(m.partition.capture_code::<8>(&m.watches, addr).is_err());
    }
    assert!(
        m.partition
            .access()
            .ram()
            .direct_page(0)
            .unwrap()
            .writable()
    );
}

#[test]
fn leased_copy_preserves_prefix_across_read_only_and_discontiguous_ranges() {
    let m = fixture(0, 8192, 8192);
    m.partition.unmap_range(0, 8192).unwrap();
    // SAFETY: the two disjoint extents borrow the fixture's live reservation.
    unsafe {
        m.partition
            .map_range(m.backing.as_ptr().cast(), 2048, 0, true, true)
            .unwrap();
        m.partition
            .map_range(m.backing.as_ptr().add(4096).cast(), 2048, 2048, false, true)
            .unwrap();
    }
    m.backing.write_at(2044, &[3; 4]).unwrap();
    m.backing.write_at(4096, &[9; 4]).unwrap();
    let observed = m.partition.capture_code::<8>(&m.watches, 2044).unwrap();
    assert_eq!(*observed.value(), [3, 3, 3, 3, 9, 9, 9, 9]);
    let lease = m.partition.access();
    let ram = lease.ram();
    assert!(ram.direct_page(0).is_none());
    assert_eq!(ram.write_bytes(2044, &[7; 8]).unwrap_err().completed, 4);
    let mut out = [0; 8];
    ram.read_bytes(2044, &mut out).unwrap();
    assert_eq!(out, [7, 7, 7, 7, 9, 9, 9, 9]);
    assert!(!observed.is_valid());
    assert!(ram.write(2048, [1]).is_err());
}
