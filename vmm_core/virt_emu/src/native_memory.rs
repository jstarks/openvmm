// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Scoped native x86-64 access to partition-provided coherent WB mappings.
//!
//! The partition's mapping owner reserves backing until synchronous unmap has
//! returned. Each synchronous CPU batch holds one shared mapping lease, never
//! across an await. Concurrent CPU batches and external DMA share the backing;
//! mapping changes wait for all leases, not for individual memory operations.
//! Optional code watches revoke old batches before capture. Only writes touching
//! marked physical spans notify the tracker; untouched RAM remains ungated.

// UNSAFETY: partition-owned reservations are accessed only under a mapping lease
// through fault-recoverable trycopy primitives, without creating Rust references.
#![allow(unsafe_code)]

use guestmem::{WriteTracker, WriteTrackerError};
use parking_lot::{RwLock, RwLockReadGuard};
use std::ops::Range;
use std::sync::atomic::{Ordering, fence};
use virt::PartitionMemoryMap;
use x86_system::arch::integer;
use x86_system::memory::physical::{
    self as physical, AtomicOperation, AtomicResult, CopyError, CopyErrorKind, PhysicalRam,
};

/// Failure of the physical RAM interface, not an architectural guest exception.
#[derive(Debug, thiserror::Error)]
pub enum RamError {
    /// There is no mapping covering the requested address.
    #[error("unmapped physical address {0:#x}")]
    Unmapped(u64),
    /// The mapping does not permit writes.
    #[error("physical mapping at {0:#x} is read-only")]
    ReadOnly(u64),
    /// The requested range wraps the address space.
    #[error("physical address range overflow")]
    AddressOverflow,
    /// Code watches need a nonempty, ordered physical range.
    #[error("empty or reversed code watch range")]
    InvalidWatchRange,
    /// This mapping table was constructed without write observation.
    #[error("code watching requires a write tracker")]
    Untracked,
    /// The observer's translated address range cannot be represented.
    #[error("notifying a physical RAM write")]
    WriteTracker(#[from] WriteTrackerError),
    /// A scalar cannot be lowered to one host memory instruction.
    #[error("scalar access crosses noncontiguous host mappings at {0:#x}")]
    SplitAccess(u64),
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

#[derive(Debug, Clone, Copy)]
struct Mapping {
    start: u64,
    end: u64,
    data: *mut u8,
    writable: bool,
    watched: bool,
    original_start: u64,
    original_end: u64,
}

// SAFETY: map_range's caller keeps the reservation alive and permits shared
// native access until unmap returns. No Rust references to its bytes are made.
unsafe impl Send for Mapping {}
// SAFETY: shared access uses trycopy's concurrent native-memory primitives.
unsafe impl Sync for Mapping {}

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
    mappings: RwLock<Vec<Mapping>>,
    tracker: Option<WriteTracker>,
}

impl PartitionMemory {
    /// Creates an empty partition mapping table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty table sharing external write observation.
    pub fn with_write_tracker(tracker: WriteTracker) -> Self {
        Self {
            mappings: RwLock::new(Vec::new()),
            tracker: Some(tracker),
        }
    }

    /// Revokes old CPU batches, marks physical pages, and captures code.
    ///
    /// Lock order is mapping lease, external tracker, then observer state.
    /// The callback may acquire `WriteTracker::synchronize` to read/register
    /// immutable code, but must not write, reenter this table, or await. It
    /// runs with the exclusive mapping lease, after all old CPU writes and
    /// their notifications have finished. Marks persist until unmap.
    pub(crate) fn with_code_watch<T>(
        &self,
        range: Range<u64>,
        f: impl FnOnce(NativeRam<'_>) -> T,
    ) -> Result<T, RamError> {
        if range.start >= range.end {
            return Err(RamError::InvalidWatchRange);
        }
        let tracker = self.tracker.as_ref().ok_or(RamError::Untracked)?;
        let start = range.start & !4095;
        let end = range.end.checked_add(4095).map_or(u64::MAX, |v| v & !4095);
        let mut mappings = self.mappings.write();
        for boundary in [start, end] {
            let index = mappings.partition_point(|mapping| mapping.end <= boundary);
            if let Some(mapping) = mappings.get(index).copied()
                && mapping.start < boundary
                && boundary < mapping.end
            {
                mappings[index].end = boundary;
                mappings.insert(
                    index + 1,
                    Mapping {
                        start: boundary,
                        data: mapping
                            .data
                            .wrapping_add((boundary - mapping.start) as usize),
                        ..mapping
                    },
                );
            }
        }
        for mapping in mappings.iter_mut() {
            if mapping.start < end && start < mapping.end {
                mapping.watched = true;
            }
        }
        // Only boundaries of changed watch permissions need survive.
        let mut index = 1;
        while index < mappings.len() {
            let previous = &mappings[index - 1];
            let next = &mappings[index];
            if previous.end == next.start
                && previous.original_start == next.original_start
                && previous.original_end == next.original_end
                && previous.watched == next.watched
            {
                mappings[index - 1].end = next.end;
                mappings.remove(index);
            } else {
                index += 1;
            }
        }
        trycopy::initialize_try_copy();
        Ok(f(NativeRam {
            mappings: &mappings,
            tracker: Some(tracker),
        }))
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
        // Default construction must initialize recovery too.
        trycopy::initialize_try_copy();
        NativeAccess {
            mappings: self.mappings.read(),
            tracker: self.tracker.as_ref(),
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
        let mut mappings = self.mappings.write();
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
                watched: false,
                original_start: addr,
                original_end: end,
            },
        );
        Ok(())
    }

    fn unmap_range(&self, addr: u64, size: u64) -> anyhow::Result<()> {
        let end = addr.checked_add(size).ok_or(MapError::InvalidRange)?;
        let mut mappings = self.mappings.write();
        if size == 0 {
            return Ok(());
        }
        if mappings.iter().any(|mapping| {
            mapping.start < end
                && addr < mapping.end
                && (mapping.original_start < addr || end < mapping.original_end)
        }) {
            return Err(MapError::PartialUnmap.into());
        }
        mappings.retain(|mapping| !(addr <= mapping.start && mapping.end <= end));
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

/// Result of conditionally marking the exact PTE a walker observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdUpdate {
    /// The compare-exchange committed, preserving every non-A/D bit.
    Marked,
    /// The PTE changed; the walker must revalidate rather than reuse old checks.
    Changed(u64),
    /// The supplied observation was not present; no backing access was made.
    NotPresent,
}

/// Read-side mapping lease for a synchronous CPU batch.
///
/// This guard is not Send. Drop it before awaiting, even on a local executor,
/// and before changing this partition's mappings. Borrow its native RAM view
/// with `ram()` for the duration of synchronous execution.
#[derive(Debug)]
#[must_use]
pub struct NativeAccess<'a> {
    mappings: RwLockReadGuard<'a, Vec<Mapping>>,
    tracker: Option<&'a WriteTracker>,
}

impl NativeAccess<'_> {
    /// Borrows a concurrent-capable view without acquiring another lock.
    pub fn ram(&self) -> NativeRam<'_> {
        NativeRam {
            mappings: &self.mappings,
            tracker: self.tracker,
        }
    }
}

/// Native RAM view borrowing a live mapping lease.
///
/// No host pointer escapes this view. Callers classify RAM versus MMIO
/// independently of transport failures.
/// A scalar spanning adjacent mappings requires contiguous host backing;
/// discontiguous ranges must use the prefix-reporting bulk interface.
///
/// ```compile_fail
/// let memory = virt_emu::native_memory::PartitionMemory::new();
/// let ram = {
///     let access = memory.access();
///     access.ram()
/// };
/// drop(ram); // A view cannot outlive its mapping lease.
/// ```
#[derive(Debug)]
pub struct NativeRam<'a> {
    mappings: &'a [Mapping],
    tracker: Option<&'a WriteTracker>,
}

impl NativeRam<'_> {
    fn mapping(&self, address: u64, write: bool) -> Result<&Mapping, RamError> {
        let index = self
            .mappings
            .partition_point(|mapping| mapping.start <= address);
        let mapping = index
            .checked_sub(1)
            .and_then(|index| self.mappings.get(index))
            .filter(|mapping| address < mapping.end)
            .ok_or(RamError::Unmapped(address))?;
        if write && !mapping.writable {
            return Err(RamError::ReadOnly(address));
        }
        Ok(mapping)
    }

    fn pointer(&self, address: u64, size: usize, write: bool) -> Result<(*mut u8, bool), RamError> {
        let end = address
            .checked_add(size as u64)
            .ok_or(RamError::AddressOverflow)?;
        let first = self.mapping(address, write)?;
        let pointer = first.data.wrapping_add((address - first.start) as usize);
        let mut current = first.end;
        let mut watched = first.watched;
        while current < end {
            let next = self.mapping(current, write)?;
            if next.data != pointer.wrapping_add((current - address) as usize) {
                return Err(RamError::SplitAccess(current));
            }
            watched |= next.watched;
            current = next.end;
        }
        Ok((pointer, watched))
    }

    fn notify_write(&self, address: u64, size: usize, watched: bool) -> Result<(), RamError> {
        if watched {
            self.tracker
                .ok_or(RamError::Untracked)?
                .notify_write(address, size)?;
        }
        Ok(())
    }

    fn copy_width(&self, address: u64, remaining: usize, write: bool) -> Result<usize, RamError> {
        let mapping = self.mapping(address, write)?;
        let remaining = remaining.min((mapping.end - address) as usize);
        Ok(if remaining >= 8 && address.is_multiple_of(8) {
            8
        } else if remaining >= 4 && address.is_multiple_of(4) {
            4
        } else if remaining >= 2 && address.is_multiple_of(2) {
            2
        } else {
            1
        })
    }

    fn copy_bytes(
        &self,
        address: u64,
        length: usize,
        write: bool,
        mut copy: impl FnMut(u64, usize, usize) -> Result<(), RamError>,
    ) -> Result<(), CopyError<RamError>> {
        if length != 0 && address.checked_add((length - 1) as u64).is_none() {
            return Err(CopyError {
                completed: 0,
                kind: CopyErrorKind::AddressOverflow,
            });
        }
        let mut completed = 0;
        // Naturally aligned scalar chunks cannot cross a host page boundary.
        // Unlike a general memmove, each failure therefore leaves an exact
        // known prefix; never retry a committed store or a faulting chunk.
        while completed < length {
            let current = address + completed as u64;
            let width = self
                .copy_width(current, length - completed, write)
                .map_err(|error| CopyError {
                    completed,
                    kind: CopyErrorKind::Memory(error),
                })?;
            copy(current, completed, width).map_err(|error| CopyError {
                completed,
                kind: CopyErrorKind::Memory(error),
            })?;
            completed += width;
        }
        Ok(())
    }

    /// Marks A and optionally D only if the PTE still equals the observation.
    ///
    /// A replacement/removal is not retried blindly: the walker must revalidate
    /// its address/permission decision against the changed entry.
    pub fn try_mark_ad(
        &self,
        address: u64,
        observed: u64,
        dirty: bool,
    ) -> Result<AdUpdate, CopyError<RamError>> {
        let Some(replacement) = physical::ad_value(observed, dirty) else {
            return Ok(AdUpdate::NotPresent);
        };
        match self.atomic(
            address,
            8,
            AtomicOperation::CompareExchange {
                expected: observed,
                replacement,
            },
        )? {
            AtomicResult::Value(value) if value == observed => Ok(AdUpdate::Marked),
            AtomicResult::Value(value) => Ok(AdUpdate::Changed(value)),
            AtomicResult::Flags(_) => unreachable!("compare-exchange returns an operand"),
        }
    }

    /// Orders RAM, not translation invalidation or device-I/O completion.
    pub fn barrier(&self) {
        fence(Ordering::SeqCst);
    }
}

impl PhysicalRam for NativeRam<'_> {
    type Error = RamError;

    fn read<const N: usize>(&self, address: u64) -> Result<[u8; N], RamError> {
        const { assert!(matches!(N, 1 | 2 | 4 | 8)) };
        let (pointer, _) = self.pointer(address, N, false)?;
        // SAFETY: the lease reserves the complete range. Byte arrays have no
        // validity or alignment restriction; trycopy uses one exact-width load.
        Ok(unsafe { trycopy::try_read_volatile(pointer.cast::<[u8; N]>()) }?)
    }

    fn write<const N: usize>(&self, address: u64, value: [u8; N]) -> Result<(), RamError> {
        const { assert!(matches!(N, 1 | 2 | 4 | 8)) };
        let (pointer, watched) = self.pointer(address, N, true)?;
        // SAFETY: the lease reserves writable shared backing for the complete
        // scalar. One exact-width store performs no destination read.
        let result = unsafe { trycopy::try_write_volatile(pointer.cast(), &value) };
        self.notify_write(address, N, watched)?;
        Ok(result?)
    }

    fn read_bytes(&self, address: u64, destination: &mut [u8]) -> Result<(), CopyError<RamError>> {
        self.copy_bytes(
            address,
            destination.len(),
            false,
            |current, offset, width| {
                macro_rules! read {
                    ($n:literal) => {
                        self.read::<$n>(current)
                            .map(|value| destination[offset..offset + $n].copy_from_slice(&value))
                    };
                }
                match width {
                    8 => read!(8),
                    4 => read!(4),
                    2 => read!(2),
                    _ => read!(1),
                }
            },
        )
    }

    fn write_bytes(&self, address: u64, source: &[u8]) -> Result<(), CopyError<RamError>> {
        self.copy_bytes(address, source.len(), true, |current, offset, width| {
            macro_rules! write {
                ($n:literal) => {{
                    let mut value = [0; $n];
                    value.copy_from_slice(&source[offset..offset + $n]);
                    self.write(current, value)
                }};
            }
            match width {
                8 => write!(8),
                4 => write!(4),
                2 => write!(2),
                _ => write!(1),
            }
        })
    }

    fn atomic(
        &self,
        address: u64,
        width: u8,
        operation: AtomicOperation,
    ) -> Result<AtomicResult, CopyError<RamError>> {
        let invalid = || CopyError {
            completed: 0,
            kind: CopyErrorKind::InvalidAccess,
        };
        if !matches!(width, 1 | 2 | 4 | 8) || !address.is_multiple_of(u64::from(width)) {
            return Err(invalid());
        }
        let failure = |error| CopyError {
            completed: 0,
            kind: CopyErrorKind::Memory(error),
        };
        let (pointer, watched) = self
            .pointer(address, usize::from(width), true)
            .map_err(failure)?;
        if let AtomicOperation::CompareExchange {
            expected,
            replacement,
        } = operation
        {
            macro_rules! exchange {
                ($ty:ty) => {{
                    // SAFETY: the lease reserves writable backing; mapping
                    // alignment preserves the validated natural alignment.
                    let result = unsafe {
                        trycopy::try_compare_exchange(
                            pointer.cast::<$ty>(),
                            expected as $ty,
                            replacement as $ty,
                        )
                    };
                    result.map(|value| {
                        AtomicResult::Value(u64::from(match value {
                            Ok(_) => expected as $ty,
                            Err(observed) => observed,
                        }))
                    })
                }};
            }
            let result = match width {
                1 => exchange!(u8),
                2 => exchange!(u16),
                4 => exchange!(u32),
                8 => exchange!(u64),
                _ => return Err(invalid()),
            }
            .map_err(|error| failure(error.into()));
            self.notify_write(address, usize::from(width), watched)
                .map_err(failure)?;
            return result;
        }
        use trycopy::AtomicOperation as Native;
        let (operation, source, flags) = match operation {
            AtomicOperation::Exchange { replacement } => (Native::Exchange, replacement, 0),
            AtomicOperation::FetchAdd { source } => (Native::FetchAdd, source, 0),
            AtomicOperation::Integer {
                operation,
                source,
                flags,
            } => {
                if width == 1
                    && matches!(
                        operation,
                        integer::Operation::BitSet
                            | integer::Operation::BitReset
                            | integer::Operation::BitComplement
                    )
                {
                    return Err(invalid());
                }
                let operation = match operation {
                    integer::Operation::Add => Native::Add,
                    integer::Operation::Adc => Native::Adc,
                    integer::Operation::Sub => Native::Sub,
                    integer::Operation::Sbb => Native::Sbb,
                    integer::Operation::And => Native::And,
                    integer::Operation::Or => Native::Or,
                    integer::Operation::Xor => Native::Xor,
                    integer::Operation::Inc => Native::Inc,
                    integer::Operation::Dec => Native::Dec,
                    integer::Operation::Neg => Native::Neg,
                    integer::Operation::Not => Native::Not,
                    integer::Operation::BitSet => Native::BitSet,
                    integer::Operation::BitReset => Native::BitReset,
                    integer::Operation::BitComplement => Native::BitComplement,
                    _ => return Err(invalid()),
                };
                (operation, source, flags)
            }
            AtomicOperation::CompareExchange { .. } => return Err(invalid()),
        };
        // SAFETY: the validated operand is naturally aligned and completely
        // reserved and writable for this lease. There is no preliminary read.
        let result = unsafe { trycopy::try_atomic(pointer, width, operation, source, flags) };
        self.notify_write(address, usize::from(width), watched)
            .map_err(failure)?;
        result
            .map(|result| match result {
                trycopy::AtomicResult::Value(value) => AtomicResult::Value(value),
                trycopy::AtomicResult::Flags(flags) => AtomicResult::Flags(flags),
            })
            .map_err(|error| match error {
                trycopy::AtomicError::Memory(error) => failure(error.into()),
                _ => invalid(),
            })
    }

    fn barrier(&self) {
        NativeRam::barrier(self);
    }
}

#[cfg(test)]
mod watch_tests;

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

    fn read(ram: &NativeRam<'_>, address: u64, width: u8) -> u64 {
        match width {
            1 => u64::from(u8::from_le_bytes(ram.read(address).unwrap())),
            2 => u64::from(u16::from_le_bytes(ram.read(address).unwrap())),
            4 => u64::from(u32::from_le_bytes(ram.read(address).unwrap())),
            8 => u64::from_le_bytes(ram.read(address).unwrap()),
            _ => panic!("invalid test width"),
        }
    }

    fn write(ram: &NativeRam<'_>, address: u64, width: u8, value: u64) {
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
            Err(RamError::Unmapped(4096))
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
            CopyErrorKind::Memory(RamError::Unmapped(4096))
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
                        ram.try_mark_ad(0, observed, true).unwrap(),
                        AdUpdate::Changed(replacement)
                    );
                });
                seen.wait();
                memory.write_volatile(0, &replacement).unwrap();
                changed.wait();
            });
            assert_eq!(memory.read_plain::<u64>(0).unwrap(), replacement);
        }
        assert_eq!(ram.try_mark_ad(0, 0, true).unwrap(), AdUpdate::NotPresent);
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
                    if ram.try_mark_ad(0, observed, true).unwrap() == AdUpdate::Marked {
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
        assert!(matches!(ram.read::<8>(4096), Err(RamError::Unmapped(4096))));
        drop(access);
        memory.partition.unmap_range(8192, 4096).unwrap();
    }

    #[test]
    fn neutral_core_interface_observes_direct_backing_mutations() {
        fn exercise<M: PhysicalRam<Error = RamError>>(ram: &M, memory: &SparseMapping) {
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
        assert!(matches!(ram.write(0, [1; 8]), Err(RamError::ReadOnly(0))));
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
            CopyErrorKind::Memory(RamError::ReadOnly(0))
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
            Err(RamError::ReadOnly(3))
        ));
        assert_eq!(memory.read_plain::<u64>(0).unwrap(), 0x3333333333333333);
        let error = ram.write_bytes(0, &[0x44; 16]).unwrap_err();
        assert_eq!(error.completed, 3);
        assert!(matches!(
            error.kind,
            CopyErrorKind::Memory(RamError::ReadOnly(3))
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
        assert!(matches!(
            ram.write(0, [0x55; 8]),
            Err(RamError::SplitAccess(3))
        ));
        assert_eq!(memory.read_plain::<u64>(0).unwrap(), 0);
        let error = ram.write_bytes(0, &[0x77; 19]).unwrap_err();
        assert_eq!(error.completed, 16);
        assert!(matches!(
            error.kind,
            CopyErrorKind::Memory(RamError::Unmapped(16))
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
    fn inaccessible_reservation_reports_fault_and_exact_copy_prefix() {
        let backing = SparseMapping::new(8192).unwrap();
        backing.alloc(0, 4096).unwrap();
        let partition = PartitionMemory::new();
        // SAFETY: the whole VA range is reserved, although its second page is
        // deliberately inaccessible. The table drops before the reservation.
        unsafe { partition.map_range(backing.as_ptr().cast(), 8192, 0, true, true) }.unwrap();
        let access = partition.access();
        let ram = access.ram();
        let error = ram.write_bytes(4085, &[0x33; 19]).unwrap_err();
        assert_eq!(error.completed, 11);
        assert!(matches!(
            error.kind,
            CopyErrorKind::Memory(RamError::Memory(_))
        ));
        let mut output = [0xa5; 19];
        let error = ram.read_bytes(4085, &mut output).unwrap_err();
        assert_eq!(error.completed, 11);
        assert_eq!(output[..11], [0x33; 11]);
        assert_eq!(output[11..], [0xa5; 8]);
        assert!(matches!(
            ram.write(4093, [0xff; 8]),
            Err(RamError::Memory(_))
        ));
        let mut tail = [0; 3];
        backing.read_at(4093, &mut tail).unwrap();
        assert_eq!(tail, [0x33; 3]);
        let error = ram
            .atomic(4096, 8, AtomicOperation::FetchAdd { source: 1 })
            .unwrap_err();
        assert_eq!(error.completed, 0);
        assert!(matches!(
            error.kind,
            CopyErrorKind::Memory(RamError::Memory(_))
        ));
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
            Err(RamError::AddressOverflow)
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
            drop(access);
            completion.recv().unwrap();
        });
        assert!(matches!(
            memory.partition.access().ram().read::<8>(0),
            Err(RamError::Unmapped(0))
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
