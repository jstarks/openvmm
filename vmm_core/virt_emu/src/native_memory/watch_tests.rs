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
fn cpu_watch_downgrades_vtlb_fill_not_backing_permissions() {
    for start in [0, 1 << 40] {
        let m = fixture(start, 8192, 8192);
        let p = start / 4096;
        {
            let lease = m.partition.access();
            assert!(lease.ram_for_execution().direct_page(p).unwrap().writable());
        }
        let token = m
            .partition
            .capture_code::<8>(&m.watches, start + 24)
            .unwrap();
        let lease = m.partition.access();
        assert_eq!(lease.mappings.len(), 1);
        assert!(lease.mappings[0].writable);
        let ram = lease.ram_for_execution();
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
    let prefix = m.partition.capture_code::<4>(&m.watches, 4092).unwrap();
    let suffix = m.partition.capture_code::<8>(&m.watches, 4096).unwrap();
    m.backing.unmap(4096, 4096).unwrap();
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
    for addr in [4096, 8192, u64::MAX] {
        assert!(m.partition.capture_code::<8>(&m.watches, addr).is_err());
    }
    assert!(m.partition.code.read().tokens.is_empty());
}

#[test]
fn leased_locked_operations_match_checked_ram() {
    use integer::Operation::*;
    let m = fixture(0, 4096, 4096);
    let lease = m.partition.access();
    let checked = lease.ram();
    let native = lease.ram_for_execution();
    for n in [1, 2, 4, 8] {
        for op in [
            Add,
            Sub,
            Adc,
            Sbb,
            Inc,
            Dec,
            And,
            Or,
            Xor,
            Neg,
            Not,
            BitSet,
            BitReset,
            BitComplement,
        ] {
            if n == 1 && matches!(op, BitSet | BitReset | BitComplement) {
                continue;
            }
            for old in [0, u64::MAX, 0x807f_8000_8000_0080] {
                checked.write(0, old.to_le_bytes()).unwrap();
                native.write(8, old.to_le_bytes()).unwrap();
                let operation = AtomicOperation::Integer {
                    operation: op,
                    source: 0x105,
                    flags: 0xad7,
                };
                assert_eq!(
                    native.atomic(8, n, operation).unwrap(),
                    checked.atomic(0, n, operation).unwrap(),
                    "{op:?}/{n}"
                );
                assert_eq!(native.read::<8>(8).unwrap(), checked.read::<8>(0).unwrap());
            }
        }
        for operation in [
            AtomicOperation::CompareExchange {
                expected: 3,
                replacement: 5,
            },
            AtomicOperation::Exchange { replacement: 3 },
            AtomicOperation::FetchAdd { source: 7 },
        ] {
            checked.write(0, 3u64.to_le_bytes()).unwrap();
            native.write(8, 3u64.to_le_bytes()).unwrap();
            assert_eq!(
                native.atomic(8, n, operation).unwrap(),
                checked.atomic(0, n, operation).unwrap()
            );
            assert_eq!(native.read::<8>(8).unwrap(), checked.read::<8>(0).unwrap());
        }
    }
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
    let lease = m.partition.access();
    let ram = lease.ram_for_execution();
    assert!(ram.direct_page(0).is_none());
    assert_eq!(ram.write_bytes(2044, &[7; 8]).unwrap_err().completed, 4);
    let mut out = [0; 8];
    ram.read_bytes(2044, &mut out).unwrap();
    assert_eq!(out, [7, 7, 7, 7, 0, 0, 0, 0]);
    assert!(ram.write(2048, [1]).is_err());
}
