// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Scoped native x86-64 access to partition-provided coherent WB mappings.
//!
//! The partition's mapping owner reserves backing until synchronous unmap has
//! returned. Each synchronous CPU batch holds one shared mapping lease, never
//! across an await. Concurrent CPU batches and external DMA share the backing;
//! mapping changes wait for all leases, not for individual memory operations.
//! Registration drains old leases before capture. Strudel manages CPU write
//! observations; the backing tracker reports external writes.

// UNSAFETY: partition-owned reservations are accessed only under a mapping lease,
// without creating Rust references. CPU accesses go through Strudel's lease;
// explicit diagnostic captures use a fault-recovering copy.
#![allow(unsafe_code)]

use guestmem::WriteTracker;
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::collections::BTreeSet;
use std::ops::Range;
use std::sync::atomic::{Ordering, fence};
use virt::PartitionMemoryMap;
use x86_system::memory::physical::{self as physical, PhysicalRam};
use x86_system::ram_ranges::RangeError;
#[cfg(test)]
use x86_system::{
    arch::integer,
    memory::physical::{AtomicOperation, AtomicResult, CodeToken, CopyErrorKind},
};

/// Failure of the physical RAM interface, not an architectural guest exception.
#[derive(Debug, thiserror::Error)]
pub enum RamError {
    /// The requested capture is not covered by a valid mapping.
    #[error(transparent)]
    Range(#[from] RangeError),
    /// The requested range wraps the address space.
    #[error("physical address range overflow")]
    AddressOverflow,
    /// Code watches need a nonempty, ordered physical range.
    #[error("empty or reversed code watch range")]
    InvalidWatchRange,
    /// This mapping table was constructed without write observation.
    #[error("code watching requires a write tracker")]
    Untracked,
    /// Preparation must use this table's canonical write tracker.
    #[error("code preparation uses a different write tracker")]
    TrackerMismatch,
    /// The reserved backing could not be accessed. No recovery is invented.
    #[error("accessing physical RAM")]
    Memory(#[from] trycopy::MemoryError),
}

/// Invalid partition mapping metadata.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MapError {
    /// A mapping must reserve at least one byte.
    #[error("empty physical mapping")]
    Empty,
    /// The physical or host range wraps, or the host pointer is null.
    #[error("invalid physical or host mapping range")]
    InvalidRange,
    /// The tracker cannot represent the mapping's translated exclusive end.
    #[error("physical mapping exceeds the write observer address space")]
    InvalidObserverRange,
    /// Host and guest natural scalar alignment must agree.
    #[error("host and guest mapping alignment differ modulo eight")]
    Misaligned,
    /// Mappings must not overlap.
    #[error("physical mapping overlaps an existing range")]
    Overlap,
    /// Tracked mappings must not give one host range multiple physical names.
    #[error("host mapping overlaps an existing tracked range")]
    HostAlias,
    /// The unmap request must completely contain every intersecting mapping.
    #[error("unmap range only partially contains an existing mapping")]
    PartialUnmap,
    /// Fetch permissions cannot yet be distinguished from data permissions.
    #[error("non-executable mappings require fetch-qualified RAM access")]
    NonExecutable,
}

use x86_system::ram_ranges::RamRange as Mapping;

/// Partition mapping metadata, not an owner of the underlying allocation.
///
/// The unsafe mapping API requires the caller to reserve shared WB backing
/// until `unmap_range` returns (or this object is destroyed). Unmap drains all
/// active leases before returning, so the owner can then reclaim the backing.
/// `PhysicalRam` has no execute access tag, so non-executable mappings are
/// rejected rather than silently permitting instruction fetch. Guest execute
/// permission never changes host executable permissions.
///
/// Tracked tables reject overlapping host virtual ranges. The trusted partition
/// mapper must also avoid distinct virtual aliases of the same backing: raw
/// pointers cannot identify those aliases.
#[derive(Debug, Default)]
pub struct PartitionMemory {
    admission: Mutex<()>,
    vp_control: Option<strudel::VpControl>,
    mappings: RwLock<Vec<Mapping>>,
    tracker: Option<WriteTracker>,
    code: RwLock<CodeObservations>,
    pending_code_pages: Mutex<BTreeSet<u64>>,
}

#[derive(Debug, Default)]
struct CodeObservations {
    binding_epoch: strudel::BindingEpoch,
    domain: strudel::CodeDomain,
    tokens: physical::CpuCodePages,
}

impl CodeObservations {
    fn remove_range(&mut self, range: Range<u64>) {
        self.binding_epoch = Default::default();
        // Mapping changes need not revoke the underlying write watch. Cached
        // observations must not authorize its old span under the new mapping.
        if self.tokens.remove_range(range) {
            self.domain = strudel::CodeDomain::default();
        }
    }
}

/// Outcome of preparing the physical code pages requested by previous batches.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct CodePreparation {
    /// Pages with a current watched identity after preparation.
    pub(crate) prepared: usize,
    /// Pages whose complete backing disappeared or is not representable.
    pub(crate) unavailable: usize,
}

impl PartitionMemory {
    pub(crate) fn for_vp(tracker: WriteTracker, vp_control: strudel::VpControl) -> Self {
        Self {
            vp_control: Some(vp_control),
            ..Self::with_write_tracker(tracker)
        }
    }

    fn change_mappings(&self) -> RwLockWriteGuard<'_, Vec<Mapping>> {
        // Don't let the VP consume the kick and reenter before we queue for
        // the exclusive lease. The gate is never held during guest execution.
        let _gate = self.admission.lock();
        if let Some(control) = &self.vp_control {
            control.request_attention();
        }
        self.mappings.write()
    }

    /// Creates an empty partition mapping table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty table sharing external write observation.
    pub fn with_write_tracker(tracker: WriteTracker) -> Self {
        Self {
            mappings: RwLock::new(Vec::new()),
            tracker: Some(tracker),
            ..Self::default()
        }
    }

    /// Prepares identities between CPU batches without fetching code bytes.
    ///
    /// Pending requests are drained before waiting for a mapping write lease:
    /// active batches may still enqueue requests while that lease is waiting.
    pub(crate) fn prepare_code_pages(
        &self,
        watches: &crate::write_watch::WriteWatch,
    ) -> Result<CodePreparation, RamError> {
        let tracker = self.tracker.as_ref().ok_or(RamError::Untracked)?;
        if !tracker.same_domain(&watches.tracker()) {
            return Err(RamError::TrackerMismatch);
        }
        let pending = std::mem::take(&mut *self.pending_code_pages.lock());
        let mut result = CodePreparation::default();
        for page in pending {
            page.checked_add(4096).ok_or(RamError::AddressOverflow)?;
            let mappings = self.change_mappings();
            match Mapping::span(&mappings, page, 4096, false) {
                Ok(_) => {}
                Err(RangeError::Unmapped(_) | RangeError::Split(_)) => {
                    result.unavailable += 1;
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
            if self.code.read().tokens.token(page).is_none() {
                watches.capture_page(page, |watch| {
                    let mut code = self.code.write();
                    code.binding_epoch = Default::default();
                    code.tokens.install(page, watch);
                })?;
            }
            result.prepared += 1;
        }
        Ok(result)
    }

    /// Revokes old CPU batches, marks physical pages, and captures code.
    ///
    /// Lock order is mapping lease, external tracker, then observer state.
    /// The tracker excludes DMA during capture. The exclusive mapping lease
    /// excludes CPU writes through publication into Strudel's watch registry.
    pub(crate) fn capture_code<const N: usize>(
        &self,
        watches: &crate::write_watch::WriteWatch,
        address: u64,
    ) -> Result<crate::write_watch::Watched<[u8; N]>, crate::write_watch::CodeCaptureError> {
        let end = address
            .checked_add(N as u64)
            .filter(|&end| end > address)
            .ok_or(RamError::InvalidWatchRange)?;
        let tracker = self.tracker.as_ref().ok_or(RamError::Untracked)?;
        if !tracker.same_domain(&watches.tracker()) {
            return Err(RamError::TrackerMismatch.into());
        }
        let mappings = self.change_mappings();
        trycopy::initialize_try_copy();
        let captured = watches.capture(address..end, || {
            let mut bytes = [0; N];
            let mut copied = 0;
            while copied < N {
                let at = address + copied as u64;
                let mapping = Mapping::region(&mappings, at)?;
                let count = (N - copied).min((mapping.end - at) as usize);
                let src = mapping.data.wrapping_add((at - mapping.start) as usize);
                // SAFETY: the mapping lease pins this extent, and the DMA
                // gate excludes external writes. A host fault aborts capture.
                unsafe {
                    trycopy::try_copy(src, bytes[copied..].as_mut_ptr(), count)?;
                }
                copied += count;
            }
            Ok::<_, RamError>(bytes)
        })?;
        let mut code = self.code.write();
        code.binding_epoch = Default::default();
        code.tokens.observe_range(address..end, captured.validity());
        Ok(captured)
    }

    /// Leases the mappings for one synchronous CPU batch.
    ///
    /// Drop the lease before awaiting or calling map/unmap on this table.
    /// Readers may coexist; no exclusive CPU execution lock is acquired.
    ///
    /// ```
    /// let memory = virt_emu::native_memory::PartitionMemory::new();
    /// {
    ///     let access = memory.access();
    ///     let ram = access.ram();
    ///     // Pass &ram to synchronous CPU execution here.
    /// }
    /// // Mapping changes or asynchronous work may now proceed.
    /// ```
    pub fn access(&self) -> NativeAccess<'_> {
        let mappings = {
            let _gate = self.admission.lock();
            self.mappings.read()
        };
        NativeAccess {
            mappings,
            tracker: self.tracker.as_ref(),
            code: self.code.read(),
            pending_code_pages: &self.pending_code_pages,
            vp_control: self.vp_control.as_ref(),
        }
    }

    /// Orders RAM, not translation invalidation or device-I/O completion.
    pub fn barrier(&self) {
        fence(Ordering::SeqCst);
    }
}

impl PartitionMemoryMap for PartitionMemory {
    unsafe fn map_range(
        &self,
        data: *mut u8,
        size: usize,
        addr: u64,
        writable: bool,
        exec: bool,
    ) -> anyhow::Result<()> {
        if !exec {
            return Err(MapError::NonExecutable.into());
        }
        if size == 0 {
            return Err(MapError::Empty.into());
        }
        let end = addr
            .checked_add(u64::try_from(size).map_err(|_| MapError::InvalidRange)?)
            .ok_or(MapError::InvalidRange)?;
        if data.is_null() || (data as usize).checked_add(size).is_none() {
            return Err(MapError::InvalidRange.into());
        }
        if (data as usize & 7) != (addr as usize & 7) {
            return Err(MapError::Misaligned.into());
        }
        if let Some(tracker) = &self.tracker {
            // Validate once before insertion so notification cannot fail after
            // a committed scalar or exact-prefix copy due to address overflow.
            tracker
                .with_offset(end)
                .map_err(|_| MapError::InvalidObserverRange)?;
        }
        let mut mappings = self.change_mappings();
        let index = mappings.partition_point(|mapping| mapping.start < addr);
        if index != 0 && mappings[index - 1].end > addr
            || index < mappings.len() && mappings[index].start < end
        {
            return Err(MapError::Overlap.into());
        }
        if self.tracker.is_some()
            && mappings.iter().any(|mapping| {
                (data as usize) < mapping.data as usize + (mapping.end - mapping.start) as usize
                    && (mapping.data as usize) < data as usize + size
            })
        {
            return Err(MapError::HostAlias.into());
        }
        mappings.insert(
            index,
            Mapping {
                start: addr,
                end,
                data,
                writable,
            },
        );
        self.code.write().remove_range(addr..end);
        Ok(())
    }

    fn unmap_range(&self, addr: u64, size: u64) -> anyhow::Result<()> {
        let end = addr.checked_add(size).ok_or(MapError::InvalidRange)?;
        let mut mappings = self.change_mappings();
        if size == 0 {
            return Ok(());
        }
        if mappings.iter().any(|mapping| {
            mapping.start < end && addr < mapping.end && (mapping.start < addr || end < mapping.end)
        }) {
            return Err(MapError::PartialUnmap.into());
        }
        mappings.retain(|mapping| !(addr <= mapping.start && mapping.end <= end));
        self.code.write().remove_range(addr..end);
        Ok(())
    }

    #[cfg(windows)]
    unsafe fn map_remote_range(
        &self,
        _process: std::os::windows::io::BorrowedHandle<'_>,
        _data: *mut u8,
        _size: usize,
        _addr: u64,
        _writable: bool,
        _exec: bool,
    ) -> anyhow::Result<()> {
        anyhow::bail!("native RAM requires mappings in the current process")
    }
}

/// Read-side mapping lease for a synchronous CPU batch.
///
/// This guard is not Send. Drop it before awaiting or changing mappings.
/// `ram()` lends the ranges to Strudel; backing accessed by a CPU must be populated.
#[derive(Debug)]
#[must_use]
pub struct NativeAccess<'a> {
    mappings: RwLockReadGuard<'a, Vec<Mapping>>,
    tracker: Option<&'a WriteTracker>,
    code: RwLockReadGuard<'a, CodeObservations>,
    pending_code_pages: &'a Mutex<BTreeSet<u64>>,
    vp_control: Option<&'a strudel::VpControl>,
}

impl NativeAccess<'_> {
    pub(crate) fn binding_epoch(&self) -> &strudel::BindingEpoch {
        &self.code.binding_epoch
    }
    /// Borrows Strudel's CPU RAM view for the lifetime of this lease.
    pub fn ram(&self) -> impl PhysicalRam<Error = RangeError> + '_ {
        // SAFETY: the read lease pins the populated coherent WB reservations
        // used for VP execution. map_range validates ordering, aliasing and
        // alignment. New watches and mapping changes require the write lease.
        unsafe {
            x86_system::ram_ranges::borrow_ram(
                &self.mappings,
                &self.code.domain,
                &self.code.tokens,
                |page| {
                    if self.tracker.is_some()
                        && self.pending_code_pages.lock().insert(page)
                        && let Some(control) = self.vp_control
                    {
                        control.request_attention();
                    }
                },
            )
        }
    }
}

#[cfg(test)]
mod watch_tests;

#[cfg(test)]
mod code_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use sparse_mmap::SparseMapping;
    use std::ops::Deref;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use test_with_tracing::test;
    use x86_system::arch::operand::Width;

    struct TestMemory {
        // The metadata must be destroyed before the backing reservation.
        partition: PartitionMemory,
        backing: SparseMapping,
    }

    impl Deref for TestMemory {
        type Target = SparseMapping;

        fn deref(&self) -> &SparseMapping {
            &self.backing
        }
    }

    fn fixture() -> TestMemory {
        let backing = SparseMapping::new(4096).unwrap();
        backing.alloc(0, 4096).unwrap();
        let partition = PartitionMemory::new();
        // SAFETY: TestMemory owns both objects, destroying the table before the
        // allocation. All byte access uses concurrent-capable native primitives.
        unsafe { partition.map_range(backing.as_ptr().cast(), 4096, 0, true, true) }.unwrap();
        TestMemory { partition, backing }
    }

    fn read(ram: &impl PhysicalRam, address: u64, width: u8) -> u64 {
        match width {
            1 => u64::from(u8::from_le_bytes(ram.read(address).unwrap())),
            2 => u64::from(u16::from_le_bytes(ram.read(address).unwrap())),
            4 => u64::from(u32::from_le_bytes(ram.read(address).unwrap())),
            8 => u64::from_le_bytes(ram.read(address).unwrap()),
            _ => panic!("invalid test width"),
        }
    }

    fn write(ram: &impl PhysicalRam, address: u64, width: u8, value: u64) {
        match width {
            1 => ram.write(address, (value as u8).to_le_bytes()),
            2 => ram.write(address, (value as u16).to_le_bytes()),
            4 => ram.write(address, (value as u32).to_le_bytes()),
            8 => ram.write(address, value.to_le_bytes()),
            _ => panic!("invalid test width"),
        }
        .unwrap();
    }

    #[test]
    fn all_contained_widths_preserve_neighbor_bytes() {
        let memory = fixture();
        let access = memory.partition.access();
        let ram = access.ram();
        for width in [1u8, 2, 4, 8] {
            for offset in 0..=8 - width {
                let original = [0xa5; 8];
                memory.write_at(0, &original).unwrap();
                write(&ram, offset.into(), width, 0x1122334455667788);
                let mut expected = original;
                expected[offset as usize..(offset + width) as usize]
                    .copy_from_slice(&0x1122334455667788u64.to_le_bytes()[..width as usize]);
                let mut actual = [0; 8];
                memory.read_at(0, &mut actual).unwrap();
                assert_eq!(actual, expected);
                assert_eq!(
                    read(&ram, offset.into(), width),
                    0x1122334455667788 & (u64::MAX >> ((8 - width) * 8))
                );
            }
        }
        ram.write(7, 0x1234u16.to_le_bytes()).unwrap();
        assert_eq!(read(&ram, 7, 2), 0x1234);
        assert!(matches!(
            ram.write(4096, [1; 8]),
            Err(RangeError::Unmapped(4096))
        ));
    }

    #[test]
    fn byte_copies_share_existing_backing_and_report_partial_failures() {
        let memory = fixture();
        let access = memory.partition.access();
        let ram = access.ram();
        let source: Vec<_> = (0..37).map(|i| (i * 17 + 3) as u8).collect();
        for offset in 0..8 {
            memory.write_at(0, &[0xa5; 64]).unwrap();
            ram.write_bytes(offset, &source).unwrap();
            let mut actual = [0; 64];
            memory.read_at(0, &mut actual).unwrap();
            let mut expected = [0xa5; 64];
            expected[offset as usize..offset as usize + source.len()].copy_from_slice(&source);
            assert_eq!(actual, expected);
            memory.write_at(offset as usize, &[0x77; 37]).unwrap();
            let mut copied = [0; 37];
            ram.read_bytes(offset, &mut copied).unwrap();
            assert_eq!(copied, [0x77; 37]);
        }
        let error = ram.write_bytes(4085, &[0x33; 19]).unwrap_err();
        assert_eq!(error.completed, 11);
        assert!(matches!(
            error.kind,
            CopyErrorKind::Memory(RangeError::Unmapped(4096))
        ));
        let mut prefix = [0; 11];
        memory.read_at(4085, &mut prefix).unwrap();
        assert_eq!(prefix, [0x33; 11]);
        let mut destination = [0xa5; 19];
        let error = ram.read_bytes(4085, &mut destination).unwrap_err();
        assert_eq!(error.completed, 11);
        assert_eq!(destination[..11], [0x33; 11]);
        assert_eq!(destination[11..], [0xa5; 8]);
    }

    #[test]
    fn exact_byte_ranges_and_unaligned_values_preserve_neighbors() {
        let memory = fixture();
        let access = memory.partition.access();
        let ram = access.ram();
        memory.write_at(0, &[0xa5; 16]).unwrap();
        let value = 0x1122_3344_5566_7788u64;
        ram.write_bytes(3, &value.to_le_bytes()).unwrap();
        assert_eq!(read(&ram, 3, 8), value);
        let mut bytes = [0; 5];
        ram.read_bytes(6, &mut bytes).unwrap();
        assert_eq!(bytes, value.to_le_bytes()[3..]);
        ram.write(10, [0x99]).unwrap();
        assert_eq!(read(&ram, 10, 1), 0x99);
        ram.write(4095, [0x33]).unwrap();
        assert_eq!(read(&ram, 4095, 1), 0x33);
        assert!(ram.read::<1>(4096).is_err());
        assert!(ram.read::<2>(4095).is_err());
        assert_eq!(memory.read_plain::<u8>(2).unwrap(), 0xa5);
        assert_eq!(memory.read_plain::<u8>(11).unwrap(), 0xa5);
    }

    #[test]
    fn exact_width_atomics_return_operand_or_flags_and_frame_neighbors() {
        for (width, operand_width) in [
            (1u8, Width::Byte),
            (2, Width::Word),
            (4, Width::Dword),
            (8, Width::Qword),
        ] {
            for address in [0, 8 - u64::from(width), 4096 - u64::from(width)] {
                let mut operations = vec![
                    AtomicOperation::CompareExchange {
                        expected: 0x5a,
                        replacement: 0x33,
                    },
                    AtomicOperation::CompareExchange {
                        expected: 0x5b,
                        replacement: 0x33,
                    },
                    AtomicOperation::Exchange {
                        replacement: u64::MAX,
                    },
                    AtomicOperation::FetchAdd { source: 7 },
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
                        source: 7,
                        flags: 0x202003,
                    });
                }
                for operation in operations {
                    let memory = fixture();
                    let access = memory.partition.access();
                    let ram = access.ram();
                    memory.write_at(0, &[0xa5; 4096]).unwrap();
                    write(&ram, address, width, 0x5a);
                    let mut before = [0; 4096];
                    memory.read_at(0, &mut before).unwrap();
                    let (expected, result) = match operation {
                        AtomicOperation::CompareExchange {
                            expected,
                            replacement,
                        } => (
                            if expected == 0x5a { replacement } else { 0x5a },
                            AtomicResult::Value(0x5a),
                        ),
                        AtomicOperation::Exchange { replacement } => {
                            (replacement, AtomicResult::Value(0x5a))
                        }
                        AtomicOperation::FetchAdd { source } => {
                            (0x5a + source, AtomicResult::Value(0x5a))
                        }
                        AtomicOperation::Integer {
                            operation,
                            source,
                            flags,
                        } => {
                            let outcome =
                                integer::evaluate(operation, 0x5a, source, operand_width, flags);
                            (outcome.value, AtomicResult::Flags(outcome.flags))
                        }
                        AtomicOperation::CompareExchange16 { .. } => {
                            unreachable!("pair operations are outside the scalar atomic matrix")
                        }
                    };
                    assert_eq!(
                        ram.atomic(address, width, operation).unwrap(),
                        result,
                        "{width}/{address}/{operation:?}"
                    );
                    before[address as usize..address as usize + usize::from(width)]
                        .copy_from_slice(&expected.to_le_bytes()[..usize::from(width)]);
                    let mut after = [0; 4096];
                    memory.read_at(0, &mut after).unwrap();
                    assert_eq!(after, before, "{width}/{address}/{operation:?}");
                }
            }
        }
    }

    #[test]
    fn pair_compare_exchange_preserves_or_replaces_the_whole_operand() {
        for matches in [false, true] {
            let memory = fixture();
            let initial = [1u64, 2];
            let replacement = [3u64, 4];
            let mut bytes = [0; 16];
            bytes[..8].copy_from_slice(&initial[0].to_le_bytes());
            bytes[8..].copy_from_slice(&initial[1].to_le_bytes());
            memory.write_at(0, &bytes).unwrap();
            let access = memory.partition.access();
            let ram = access.ram();
            assert_eq!(
                ram.atomic(
                    0,
                    16,
                    AtomicOperation::CompareExchange16 {
                        expected: if matches { initial } else { [9, 2] },
                        replacement,
                    }
                )
                .unwrap(),
                AtomicResult::Pair(initial),
            );
            let expected = if matches { replacement } else { initial };
            memory.read_at(0, &mut bytes).unwrap();
            assert_eq!(
                u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                expected[0]
            );
            assert_eq!(
                u64::from_le_bytes(bytes[8..].try_into().unwrap()),
                expected[1]
            );
        }
    }

    #[test]
    fn invalid_atomic_profiles_never_modify_ram() {
        let memory = fixture();
        let access = memory.partition.access();
        let ram = access.ram();
        memory.write_at(0, &[0x5a; 32]).unwrap();
        let exchange = AtomicOperation::Exchange { replacement: 0 };
        for (address, width, operation) in [
            (0, 0, exchange),
            (0, 3, exchange),
            (1, 2, exchange),
            (2, 4, exchange),
            (4, 8, exchange),
            (
                0,
                8,
                AtomicOperation::Integer {
                    operation: integer::Operation::Cmp,
                    source: 0,
                    flags: 0,
                },
            ),
            (
                0,
                1,
                AtomicOperation::Integer {
                    operation: integer::Operation::BitSet,
                    source: 0,
                    flags: 0,
                },
            ),
        ] {
            let error = ram.atomic(address, width, operation).unwrap_err();
            assert_eq!(error.completed, 0);
            assert!(matches!(error.kind, CopyErrorKind::InvalidAccess));
        }
        assert!(ram.atomic(4096, 8, exchange).is_err());
        assert_eq!(memory.read_plain::<[u8; 32]>(0).unwrap(), [0x5a; 32]);
    }

    #[test]
    fn cpu_and_dma_workers_do_not_lose_disjoint_byte_writes() {
        let memory = fixture();
        let access = memory.partition.access();
        let ram = access.ram();
        let start = Arc::new(Barrier::new(3));
        thread::scope(|scope| {
            for lane in 0..3 {
                let start = start.clone();
                let ram = &ram;
                let memory = &memory;
                scope.spawn(move || {
                    start.wait();
                    for value in 0..2000 {
                        if lane == 2 {
                            memory
                                .write_volatile(lane as usize, &((value + lane) as u8))
                                .unwrap();
                        } else {
                            ram.write(lane, [(value + lane) as u8]).unwrap();
                        }
                    }
                });
            }
        });
        assert_eq!(memory.read_plain::<u64>(0).unwrap(), 0xd1d0cf);
    }

    #[test]
    fn concurrent_native_qword_accesses_do_not_tear() {
        let memory = fixture();
        let access = memory.partition.access();
        let ram = access.ram();
        let start = Arc::new(Barrier::new(3));
        let values = [0x5555aaaa5555aaaau64, 0xaaaa5555aaaa5555];
        thread::scope(|scope| {
            for value in values {
                let start = start.clone();
                let ram = &ram;
                scope.spawn(move || {
                    start.wait();
                    for _ in 0..50_000 {
                        ram.write(0, value.to_le_bytes()).unwrap();
                    }
                });
            }
            let start = start.clone();
            let ram = &ram;
            scope.spawn(move || {
                start.wait();
                for _ in 0..50_000 {
                    let value = read(ram, 0, 8);
                    assert!(value == 0 || values.contains(&value));
                }
            });
        });
    }

    #[test]
    fn pte_replacement_between_read_and_ad_update_is_not_overwritten() {
        let memory = fixture();
        let access = memory.partition.access();
        let ram = access.ram();
        for replacement in [0x3007, 0x3006] {
            memory.write_volatile(0, &0x2007u64).unwrap();
            let seen = Arc::new(Barrier::new(2));
            let changed = Arc::new(Barrier::new(2));
            thread::scope(|scope| {
                let ram = &ram;
                let seen_cpu = seen.clone();
                let changed_cpu = changed.clone();
                scope.spawn(move || {
                    let observed = read(ram, 0, 8);
                    seen_cpu.wait();
                    changed_cpu.wait();
                    assert_eq!(
                        ram.atomic(
                            0,
                            8,
                            AtomicOperation::CompareExchange {
                                expected: observed,
                                replacement: observed | 0x60
                            }
                        )
                        .unwrap(),
                        AtomicResult::Value(replacement)
                    );
                });
                seen.wait();
                memory.write_volatile(0, &replacement).unwrap();
                changed.wait();
            });
            assert_eq!(memory.read_plain::<u64>(0).unwrap(), replacement);
        }
    }

    #[test]
    fn ad_updates_race_with_dma_without_losing_pte_payload() {
        let memory = fixture();
        let access = memory.partition.access();
        let ram = access.ram();
        write(&ram, 0, 8, 0x2007);
        let start = Arc::new(Barrier::new(2));
        thread::scope(|scope| {
            let start_dma = start.clone();
            let ram = &ram;
            let memory = &memory;
            scope.spawn(move || {
                start_dma.wait();
                for value in 1..2000 {
                    memory.write_volatile(4, &(value as u32)).unwrap();
                }
            });
            start.wait();
            for _ in 0..2000 {
                loop {
                    let observed = read(ram, 0, 8);
                    if ram
                        .atomic(
                            0,
                            8,
                            AtomicOperation::CompareExchange {
                                expected: observed,
                                replacement: observed | 0x60,
                            },
                        )
                        .unwrap()
                        == AtomicResult::Value(observed)
                    {
                        break;
                    }
                }
            }
        });
        assert_eq!(read(&ram, 0, 8), (1999u64 << 32) | 0x2067);
    }

    #[test]
    fn native_wb_message_passing_preserves_store_order() {
        let memory = fixture();
        let access = memory.partition.access();
        let ram = access.ram();
        thread::scope(|scope| {
            let ram = &ram;
            scope.spawn(move || {
                write(ram, 0, 8, 0xabcdef0123456789);
                write(ram, 8, 8, 1);
            });
            while read(ram, 8, 8) == 0 {
                thread::yield_now();
            }
            assert_eq!(read(ram, 0, 8), 0xabcdef0123456789);
            ram.barrier();
        });
    }

    #[test]
    fn existing_multi_region_backing_and_direct_writers_are_shared() {
        let memory = fixture();
        let second = SparseMapping::new(4096).unwrap();
        second.alloc(0, 4096).unwrap();
        // SAFETY: second stays reserved until its mapping is explicitly removed.
        unsafe {
            memory
                .partition
                .map_range(second.as_ptr().cast(), 4096, 8192, true, true)
        }
        .unwrap();
        let access = memory.partition.access();
        let ram = access.ram();
        second.write_volatile(0, &0x1122334455667788u64).unwrap();
        assert_eq!(read(&ram, 8192, 8), 0x1122334455667788);
        write(&ram, 16, 8, 0xabcdef);
        assert_eq!(memory.read_plain::<u64>(16).unwrap(), 0xabcdef);
        assert!(matches!(
            ram.read::<8>(4096),
            Err(RangeError::Unmapped(4096))
        ));
        drop(ram);
        drop(access);
        memory.partition.unmap_range(8192, 4096).unwrap();
    }

    #[test]
    fn neutral_core_interface_observes_direct_backing_mutations() {
        fn exercise<M: PhysicalRam<Error = RangeError>>(ram: &M, memory: &SparseMapping) {
            ram.write(0, 7u64.to_le_bytes()).unwrap();
            memory.write_volatile(0, &9u64).unwrap();
            assert_eq!(u64::from_le_bytes(ram.read(0).unwrap()), 9);
            for expected in [7, 9] {
                assert_eq!(
                    ram.atomic(
                        0,
                        8,
                        AtomicOperation::CompareExchange {
                            expected,
                            replacement: 11,
                        }
                    )
                    .unwrap(),
                    AtomicResult::Value(9)
                );
            }
            ram.barrier();
            assert_eq!(memory.read_plain::<u64>(0).unwrap(), 11);
        }
        let memory = fixture();
        let access = memory.partition.access();
        let ram = access.ram();
        exercise(&ram, &memory);
    }

    #[test]
    fn mapping_metadata_and_permissions_are_validated_without_mutation() {
        let memory = fixture();
        let pointer = memory.as_ptr().cast::<u8>();
        for (size, address, writable, exec, expected) in [
            (0, 0, true, true, MapError::Empty),
            (8, u64::MAX - 7, true, true, MapError::InvalidRange),
            (8, 4097, true, true, MapError::Misaligned),
            (8, 0, true, true, MapError::Overlap),
            (4096, 2048, true, true, MapError::Overlap),
            (8, 8192, true, false, MapError::NonExecutable),
        ] {
            // SAFETY: all requests are rejected; the backing remains reserved
            // for the table's entire lifetime even if an overlap is encountered.
            let error = unsafe {
                memory
                    .partition
                    .map_range(pointer, size, address, writable, exec)
            }
            .unwrap_err();
            assert_eq!(error.downcast_ref::<MapError>(), Some(&expected));
        }
        for pointer in [std::ptr::null_mut(), (usize::MAX - 7) as *mut u8] {
            // SAFETY: invalid pointer metadata is rejected before recording a
            // mapping or accessing the host address.
            let error =
                unsafe { memory.partition.map_range(pointer, 8, 8192, true, true) }.unwrap_err();
            assert_eq!(
                error.downcast_ref::<MapError>(),
                Some(&MapError::InvalidRange)
            );
        }
        assert_eq!(
            memory
                .partition
                .unmap_range(1, 4095)
                .unwrap_err()
                .downcast_ref::<MapError>(),
            Some(&MapError::PartialUnmap)
        );
        assert!(memory.partition.unmap_range(u64::MAX, 1).is_err());
        memory.partition.unmap_range(1, 0).unwrap();
        memory.partition.unmap_range(0, 4096).unwrap();
        // SAFETY: the owner retains the same reservation until its table drops.
        unsafe { memory.partition.map_range(pointer, 4096, 0, false, true) }.unwrap();
        let access = memory.partition.access();
        let ram = access.ram();
        assert_eq!(ram.read::<8>(0).unwrap(), [0; 8]);
        assert!(matches!(ram.write(0, [1; 8]), Err(RangeError::ReadOnly(0))));
        let error = ram
            .atomic(
                0,
                8,
                AtomicOperation::CompareExchange {
                    expected: 1,
                    replacement: 2,
                },
            )
            .unwrap_err();
        assert!(matches!(
            error.kind,
            CopyErrorKind::Memory(RangeError::ReadOnly(0))
        ));
        assert_eq!(memory.read_plain::<u64>(0).unwrap(), 0);
    }

    #[test]
    fn bulk_copies_cross_split_mappings_and_stop_at_permission_boundary() {
        let memory = fixture();
        memory.partition.unmap_range(0, 4096).unwrap();
        let pointer = memory.as_ptr().cast::<u8>();
        // SAFETY: both ranges borrow TestMemory's live reservation, and their
        // guest/host offsets agree even at a non-scalar-aligned split.
        unsafe {
            memory
                .partition
                .map_range(pointer, 3, 0, true, true)
                .unwrap();
            memory
                .partition
                .map_range(pointer.add(3), 13, 3, true, true)
                .unwrap();
        }
        {
            let access = memory.partition.access();
            let ram = access.ram();
            ram.write(0, 0x1122334455667788u64.to_le_bytes()).unwrap();
            assert_eq!(read(&ram, 0, 8), 0x1122334455667788);
            ram.write_bytes(0, &[0x33; 16]).unwrap();
            let mut output = [0; 16];
            ram.read_bytes(0, &mut output).unwrap();
            assert_eq!(output, [0x33; 16]);
        }
        memory.partition.unmap_range(3, 13).unwrap();
        // SAFETY: same reservation; the second range is now read-only.
        unsafe {
            memory
                .partition
                .map_range(pointer.add(3), 13, 3, false, true)
        }
        .unwrap();
        let access = memory.partition.access();
        let ram = access.ram();
        assert!(matches!(
            ram.write(0, [0xff; 8]),
            Err(RangeError::ReadOnly(3))
        ));
        assert_eq!(memory.read_plain::<u64>(0).unwrap(), 0x3333333333333333);
        let error = ram.write_bytes(0, &[0x44; 16]).unwrap_err();
        assert_eq!(error.completed, 3);
        assert!(matches!(
            error.kind,
            CopyErrorKind::Memory(RangeError::ReadOnly(3))
        ));
        let mut output = [0; 16];
        memory.read_at(0, &mut output).unwrap();
        assert_eq!(&output[..3], &[0x44; 3]);
        assert_eq!(&output[3..], &[0x33; 13]);
    }

    #[test]
    fn discontiguous_scalar_is_rejected_but_bulk_preserves_exact_prefix() {
        let memory = fixture();
        memory.partition.unmap_range(0, 4096).unwrap();
        let pointer = memory.as_ptr().cast::<u8>();
        // SAFETY: two discontiguous subranges of the owner's live reservation.
        unsafe {
            memory
                .partition
                .map_range(pointer, 3, 0, true, true)
                .unwrap();
            memory
                .partition
                .map_range(pointer.add(19), 13, 3, true, true)
                .unwrap();
        }
        let access = memory.partition.access();
        let ram = access.ram();
        assert!(matches!(ram.write(0, [0x55; 8]), Err(RangeError::Split(3))));
        assert_eq!(memory.read_plain::<u64>(0).unwrap(), 0);
        let error = ram.write_bytes(0, &[0x77; 19]).unwrap_err();
        assert_eq!(error.completed, 16);
        assert!(matches!(
            error.kind,
            CopyErrorKind::Memory(RangeError::Unmapped(16))
        ));
        let mut output = [0xa5; 19];
        let error = ram.read_bytes(0, &mut output).unwrap_err();
        assert_eq!(error.completed, 16);
        assert_eq!(output[..16], [0x77; 16]);
        assert_eq!(output[16..], [0xa5; 3]);
        assert_eq!(memory.read_plain::<u8>(3).unwrap(), 0);
        assert_eq!(memory.read_plain::<u8>(18).unwrap(), 0);
        assert_eq!(memory.read_plain::<u8>(32).unwrap(), 0);
    }

    #[test]
    fn overflow_copies_commit_nothing_and_empty_copies_need_no_mapping() {
        let partition = PartitionMemory::default();
        let access = partition.access();
        let ram = access.ram();
        ram.write_bytes(u64::MAX, &[]).unwrap();
        ram.read_bytes(u64::MAX, &mut []).unwrap();
        let mut output = [0xa5; 8];
        let error = ram.read_bytes(u64::MAX - 3, &mut output).unwrap_err();
        assert_eq!(error.completed, 0);
        assert!(matches!(error.kind, CopyErrorKind::AddressOverflow));
        assert_eq!(output, [0xa5; 8]);
        let error = ram.write_bytes(u64::MAX - 3, &[0; 8]).unwrap_err();
        assert_eq!(error.completed, 0);
        assert!(matches!(error.kind, CopyErrorKind::AddressOverflow));
        assert!(matches!(
            ram.read::<8>(u64::MAX - 3),
            Err(RangeError::Overflow)
        ));
    }

    #[test]
    fn unmap_drains_active_leases_and_remap_observes_only_new_backing() {
        use std::sync::mpsc;

        let memory = fixture();
        let replacement = SparseMapping::new(4096).unwrap();
        replacement.alloc(0, 4096).unwrap();
        memory.write_volatile(0, &11u64).unwrap();
        replacement.write_volatile(0, &22u64).unwrap();
        thread::scope(|scope| {
            let access = memory.partition.access();
            let ram = access.ram();
            let (read_done, read_result) = mpsc::channel();
            let partition = &memory.partition;
            scope.spawn(move || {
                let concurrent = partition.access();
                read_done.send(read(&concurrent.ram(), 0, 8)).unwrap();
            });
            // A second batch must finish while the first lease is still live.
            assert_eq!(read_result.recv().unwrap(), 11);
            let (started, starting) = mpsc::channel();
            let (finished, completion) = mpsc::channel();
            scope.spawn(move || {
                started.send(()).unwrap();
                partition.unmap_range(0, 4096).unwrap();
                finished.send(()).unwrap();
            });
            starting.recv().unwrap();
            // Deterministically establish the held shared lease excludes any
            // mapping writer; completion cannot depend on a scheduling delay.
            assert!(partition.mappings.try_write().is_none());
            assert!(matches!(
                completion.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));
            assert_eq!(read(&ram, 0, 8), 11);
            drop(ram);
            drop(access);
            completion.recv().unwrap();
        });
        assert!(matches!(
            memory.partition.access().ram().read::<8>(0),
            Err(RangeError::Unmapped(0))
        ));
        // SAFETY: explicitly unmapped below before replacement is destroyed.
        unsafe {
            memory
                .partition
                .map_range(replacement.as_ptr().cast(), 4096, 0, true, true)
        }
        .unwrap();
        {
            let access = memory.partition.access();
            let ram = access.ram();
            assert_eq!(read(&ram, 0, 8), 22);
            ram.write(0, 33u64.to_le_bytes()).unwrap();
            assert_eq!(memory.read_plain::<u64>(0).unwrap(), 11);
            assert_eq!(replacement.read_plain::<u64>(0).unwrap(), 33);
        }
        memory.partition.unmap_range(0, 4096).unwrap();
    }
}
