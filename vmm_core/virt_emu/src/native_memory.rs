// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native x86-64 lowering for coherent WB RAM, not an MMIO implementation.
//!
//! Data caching and buffering belong to the host CPU. Compiler barriers preserve
//! access order; guest barriers/serializing events must explicitly call `barrier`.
//! This host-ISA-specific implementation does not apply to weaker host ISAs.

use guestmem::{GuestMemory, GuestMemoryError};
use memory_range::MemoryRange;
use std::sync::atomic::{Ordering, compiler_fence, fence};
use x86_system::arch::{integer, operand::Width};
use x86_system::memory::physical::{
    self as shared, AtomicOperation, Beat, BeatError, CopyError, CopyErrorKind, Exchange,
    PhysicalRam,
};

const MASKED_WRITE_ATTEMPTS: usize = 64;

/// Failure of the physical RAM interface, not an architectural guest exception.
#[derive(Debug, thiserror::Error)]
pub enum RamError {
    /// A RAM bank must be nonempty.
    #[error("invalid native RAM bank")]
    Region,
    /// The operation crosses the bank's declared RAM boundary.
    #[error("physical RAM access outside bank: {address:#x}")]
    OutsideBank {
        /// Physical address supplied by the caller.
        address: u64,
    },
    /// The access width is outside the current byte/word/dword/qword profile.
    #[error("unsupported RAM access width")]
    Width,
    /// The caller must decompose this operation into separate RAM beats.
    #[error("RAM access requires multiple quadword beats")]
    Split,
    /// No masked store committed within this bounded attempt.
    #[error("masked RAM store contended; yield and retry without retiring")]
    Contended,
    /// OpenVMM could not access the backing.
    #[error("accessing physical RAM")]
    Memory(#[from] GuestMemoryError),
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

/// Shared view of a host-declared coherent WB RAM bank.
///
/// Clones retain the same OpenVMM backing. No exclusive Rust slice or RAM
/// snapshot is created. Callers must route MMIO and other memory types elsewhere.
#[derive(Clone, Debug)]
pub struct NativeRam {
    memory: GuestMemory,
    bank: MemoryRange,
}

impl NativeRam {
    /// Creates a native RAM view; the caller classifies this bank as coherent WB.
    pub fn new(memory: GuestMemory, bank: MemoryRange) -> Result<Self, RamError> {
        if bank.is_empty() {
            return Err(RamError::Region);
        }
        Ok(Self { memory, bank })
    }

    fn beat(&self, address: u64, width: u8) -> Result<Beat, RamError> {
        let beat = shared::plan(address, width).map_err(|error| match error {
            BeatError::Width => RamError::Width,
            BeatError::Split => RamError::Split,
        })?;
        if beat.address() < self.bank.start()
            || beat.address() >= self.bank.end()
            || self.bank.end() - beat.address() < 8
        {
            return Err(RamError::OutsideBank { address });
        }
        Ok(beat)
    }

    fn range(&self, address: u64, length: usize) -> Result<(), RamError> {
        if length == 0 {
            return Ok(());
        }
        if address < self.bank.start()
            || address >= self.bank.end()
            || u64::try_from(length).map_or(true, |length| length > self.bank.end() - address)
        {
            return Err(RamError::OutsideBank { address });
        }
        Ok(())
    }

    fn compare_word(
        &self,
        address: u64,
        expected: u64,
        replacement: u64,
    ) -> Result<Result<u64, u64>, RamError> {
        compiler_fence(Ordering::SeqCst);
        let result = self.memory.compare_exchange(address, expected, replacement);
        compiler_fence(Ordering::SeqCst);
        Ok(result?)
    }

    /// Reads exactly the requested bytes. Naturally aligned accesses do not tear.
    pub fn read(&self, address: u64, width: u8) -> Result<u64, RamError> {
        self.range(address, usize::from(width))?;
        compiler_fence(Ordering::SeqCst);
        let value = match width {
            1 => u64::from(self.memory.read_plain::<u8>(address)?),
            2 => u64::from(self.memory.read_plain::<u16>(address)?),
            4 => u64::from(self.memory.read_plain::<u32>(address)?),
            8 => self.memory.read_plain::<u64>(address)?,
            _ => return Err(RamError::Width),
        };
        compiler_fence(Ordering::SeqCst);
        Ok(value)
    }

    /// Writes exactly the requested bytes without reading adjacent data.
    pub fn write(&self, address: u64, width: u8, value: u64) -> Result<(), RamError> {
        self.range(address, usize::from(width))?;
        compiler_fence(Ordering::SeqCst);
        match width {
            1 => self.memory.write_plain(address, &(value as u8))?,
            2 => self.memory.write_plain(address, &(value as u16))?,
            4 => self.memory.write_plain(address, &(value as u32))?,
            8 => self.memory.write_plain(address, &value)?,
            _ => return Err(RamError::Width),
        }
        compiler_fence(Ordering::SeqCst);
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
    ) -> Result<AdUpdate, RamError> {
        let beat = self.beat(address, 8)?;
        let Some(replacement) = shared::ad_value(observed, dirty) else {
            return Ok(AdUpdate::NotPresent);
        };
        match self.compare_word(beat.address(), observed, replacement)? {
            Ok(_) => Ok(AdUpdate::Marked),
            Err(current) => Ok(AdUpdate::Changed(current)),
        }
    }

    /// Orders native RAM accesses for a guest barrier or serializing event.
    ///
    /// This does not implement instruction/TLB/code-cache invalidation or MMIO
    /// completion. Callers must perform those distinct architectural effects.
    pub fn barrier(&self) {
        fence(Ordering::SeqCst);
    }
}

impl PhysicalRam for NativeRam {
    type Error = RamError;

    fn read_word(&self, address: u64) -> Result<u64, Self::Error> {
        self.read(address, 8)
    }

    fn read_value(&self, address: u64, size: u8) -> Result<u64, CopyError<RamError>> {
        if matches!(size, 1 | 2 | 4 | 8) {
            return self.read(address, size).map_err(|source| CopyError {
                completed: 0,
                kind: CopyErrorKind::Memory(source),
            });
        }
        if size == 0 || size > 8 {
            return Err(CopyError {
                completed: 0,
                kind: CopyErrorKind::InvalidAccess,
            });
        }
        let mut bytes = [0; 8];
        self.read_bytes(address, &mut bytes[..usize::from(size)])?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn write_word(&self, address: u64, value: u64) -> Result<(), Self::Error> {
        self.write(address, 8, value)
    }

    fn compare_exchange_word(
        &self,
        address: u64,
        expected: u64,
        replacement: u64,
    ) -> Result<Exchange, Self::Error> {
        let beat = self.beat(address, 8)?;
        match self.compare_word(beat.address(), expected, replacement)? {
            Ok(_) => Ok(Exchange::Exchanged),
            Err(current) => Ok(Exchange::Changed(current)),
        }
    }

    fn read_bytes(&self, address: u64, destination: &mut [u8]) -> Result<(), CopyError<RamError>> {
        self.range(address, destination.len())
            .map_err(|source| CopyError {
                completed: 0,
                kind: CopyErrorKind::Memory(source),
            })?;
        let mut completed = 0;
        while completed < destination.len() {
            let current = address + completed as u64;
            let width = copy_width(current, destination.len() - completed);
            let value = self.read(current, width).map_err(|source| CopyError {
                completed,
                kind: CopyErrorKind::Memory(source),
            })?;
            let end = completed + usize::from(width);
            destination[completed..end].copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
            completed = end;
        }
        Ok(())
    }

    fn write_bytes(&self, address: u64, source: &[u8]) -> Result<(), CopyError<RamError>> {
        if address.is_multiple_of(8) {
            if let &[a, b, c, d, e, f, g, h] = source {
                return self
                    .write(address, 8, u64::from_le_bytes([a, b, c, d, e, f, g, h]))
                    .map_err(|source| CopyError {
                        completed: 0,
                        kind: CopyErrorKind::Memory(source),
                    });
            }
        }
        self.range(address, source.len())
            .map_err(|source| CopyError {
                completed: 0,
                kind: CopyErrorKind::Memory(source),
            })?;
        let mut completed = 0;
        while completed < source.len() {
            let current = address + completed as u64;
            let width = copy_width(current, source.len() - completed);
            let end = completed + usize::from(width);
            let mut bytes = [0; 8];
            bytes[..usize::from(width)].copy_from_slice(&source[completed..end]);
            self.write(current, width, u64::from_le_bytes(bytes))
                .map_err(|source| CopyError {
                    completed,
                    kind: CopyErrorKind::Memory(source),
                })?;
            completed = end;
        }
        Ok(())
    }

    fn atomic(
        &self,
        address: u64,
        width: u8,
        operation: AtomicOperation,
    ) -> Result<u64, CopyError<RamError>> {
        let failure = |source| CopyError {
            completed: 0,
            kind: CopyErrorKind::Memory(source),
        };
        self.range(address, usize::from(width)).map_err(failure)?;
        if !matches!(width, 1 | 2 | 4 | 8) || !address.is_multiple_of(u64::from(width)) {
            return Err(CopyError {
                completed: 0,
                kind: CopyErrorKind::InvalidAccess,
            });
        }
        macro_rules! atomic {
            ($ty:ty, $width:expr) => {{
                let exchange = |expected: u64, replacement: u64| {
                    compiler_fence(Ordering::SeqCst);
                    let result =
                        self.memory
                            .compare_exchange(address, expected as $ty, replacement as $ty);
                    compiler_fence(Ordering::SeqCst);
                    result
                        .map(|result| match result {
                            Ok(_) => Ok(expected as $ty as u64),
                            Err(current) => Err(u64::from(current)),
                        })
                        .map_err(RamError::from)
                };
                if let AtomicOperation::CompareExchange {
                    expected,
                    replacement,
                } = operation
                {
                    return exchange(expected, replacement)
                        .map(|result| result.unwrap_or_else(|observed| observed))
                        .map_err(failure);
                }
                let mut observed = self.read(address, width).map_err(failure)?;
                for _ in 0..MASKED_WRITE_ATTEMPTS {
                    let replacement = match operation {
                        AtomicOperation::Exchange { replacement } => replacement,
                        AtomicOperation::Integer {
                            operation,
                            source,
                            flags,
                        } => integer::evaluate(operation, observed, source, $width, flags).value,
                        AtomicOperation::CompareExchange { .. } => {
                            return Err(CopyError {
                                completed: 0,
                                kind: CopyErrorKind::InvalidAccess,
                            });
                        }
                    };
                    match exchange(observed, replacement).map_err(failure)? {
                        Ok(_) => return Ok(observed),
                        Err(current) => observed = current,
                    }
                }
                Err(CopyError {
                    completed: 0,
                    kind: CopyErrorKind::Contended,
                })
            }};
        }
        match width {
            1 => atomic!(u8, Width::Byte),
            2 => atomic!(u16, Width::Word),
            4 => atomic!(u32, Width::Dword),
            8 => atomic!(u64, Width::Qword),
            _ => Err(CopyError {
                completed: 0,
                kind: CopyErrorKind::InvalidAccess,
            }),
        }
    }

    fn barrier(&self) {
        NativeRam::barrier(self);
    }
}

fn copy_width(address: u64, remaining: usize) -> u8 {
    if remaining >= 8 && address.is_multiple_of(8) {
        8
    } else if remaining >= 4 && address.is_multiple_of(4) {
        4
    } else if remaining >= 2 && address.is_multiple_of(2) {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use test_with_tracing::test;

    fn fixture() -> (GuestMemory, NativeRam) {
        let memory = GuestMemory::allocate(4096);
        let ram = NativeRam::new(memory.clone(), MemoryRange::new(0..4096)).unwrap();
        (memory, ram)
    }

    fn write_retry(ram: &NativeRam, address: u64, width: u8, value: u64) {
        loop {
            match ram.write(address, width, value) {
                Ok(()) => return,
                Err(RamError::Contended) => thread::yield_now(),
                Err(error) => panic!("{error}"),
            }
        }
    }

    #[test]
    fn all_contained_widths_preserve_neighbor_bytes() {
        let (memory, ram) = fixture();
        for width in [1u8, 2, 4, 8] {
            for offset in 0..=8 - width {
                let original = [0xa5; 8];
                memory.write_at(0, &original).unwrap();
                ram.write(offset.into(), width, 0x1122334455667788).unwrap();
                let mut expected = original;
                expected[offset as usize..(offset + width) as usize]
                    .copy_from_slice(&0x1122334455667788u64.to_le_bytes()[..width as usize]);
                let mut actual = [0; 8];
                memory.read_at(0, &mut actual).unwrap();
                assert_eq!(actual, expected);
                let mut data = [0; 8];
                data[..width as usize]
                    .copy_from_slice(&expected[offset as usize..(offset + width) as usize]);
                assert_eq!(
                    ram.read(offset.into(), width).unwrap(),
                    u64::from_le_bytes(data)
                );
            }
        }
        ram.write(7, 2, 0x1234).unwrap();
        assert_eq!(ram.read(7, 2).unwrap(), 0x1234);
        assert!(matches!(ram.read(0, 3), Err(RamError::Width)));
        assert!(matches!(
            ram.write(4096, 8, 1),
            Err(RamError::OutsideBank { .. })
        ));
    }

    #[test]
    fn byte_copies_share_existing_backing_and_report_partial_failures() {
        let (memory, ram) = fixture();
        let source: Vec<_> = (0..37).map(|i| (i * 17 + 3) as u8).collect();
        for offset in 0..8 {
            memory.write_at(0, &[0xa5; 64]).unwrap();
            ram.write_bytes(offset, &source).unwrap();
            let mut actual = [0; 64];
            memory.read_at(0, &mut actual).unwrap();
            let mut expected = [0xa5; 64];
            expected[offset as usize..offset as usize + source.len()].copy_from_slice(&source);
            assert_eq!(actual, expected);
            memory.write_at(offset, &[0x77; 37]).unwrap();
            let mut copied = [0; 37];
            ram.read_bytes(offset, &mut copied).unwrap();
            assert_eq!(copied, [0x77; 37]);
        }
        let missing_backing = NativeRam::new(memory.clone(), MemoryRange::new(0..8192)).unwrap();
        let error = missing_backing.write_bytes(4085, &[0x33; 19]).unwrap_err();
        assert_eq!(error.completed, 11);
        assert!(matches!(
            error.kind,
            CopyErrorKind::Memory(RamError::Memory(_))
        ));
        let mut prefix = [0; 11];
        memory.read_at(4085, &mut prefix).unwrap();
        assert_eq!(prefix, [0x33; 11]);
    }

    #[test]
    fn exact_byte_ranges_and_unaligned_values_preserve_neighbors() {
        let memory = GuestMemory::allocate(4096);
        memory.write_at(0, &[0xa5; 16]).unwrap();
        let ram = NativeRam::new(memory.clone(), MemoryRange::new(0..4096)).unwrap();
        let value = 0x1122_3344_5566_7788u64;
        ram.write_bytes(3, &value.to_le_bytes()).unwrap();
        assert_eq!(ram.read_value(3, 8).unwrap(), value);
        assert_eq!(ram.read_value(4, 3).unwrap(), 0x556677);
        let mut bytes = [0; 5];
        ram.read_bytes(6, &mut bytes).unwrap();
        assert_eq!(bytes, value.to_le_bytes()[3..]);
        ram.write(10, 1, 0x99).unwrap();
        assert_eq!(ram.read(10, 1).unwrap(), 0x99);
        ram.write(4095, 1, 0x33).unwrap();
        assert_eq!(ram.read(4095, 1).unwrap(), 0x33);
        assert!(ram.read(4096, 1).is_err());
        assert!(ram.read_value(4095, 2).is_err());
        assert_eq!(memory.read_plain::<u8>(2).unwrap(), 0xa5);
        assert_eq!(memory.read_plain::<u8>(11).unwrap(), 0xa5);
    }

    #[test]
    fn exact_width_atomics_return_the_linearized_operand_and_frame_neighbors() {
        for width in [1u8, 2, 4, 8] {
            let mask = u64::MAX >> ((8 - width) * 8);
            for address in [0, 8 - u64::from(width), 4096 - u64::from(width)] {
                for (operation, expected) in [
                    (
                        AtomicOperation::CompareExchange {
                            expected: 0x5a,
                            replacement: 0x33,
                        },
                        0x33,
                    ),
                    (
                        AtomicOperation::CompareExchange {
                            expected: 0x5b,
                            replacement: 0x33,
                        },
                        0x5a,
                    ),
                    (
                        AtomicOperation::Exchange {
                            replacement: u64::MAX,
                        },
                        mask,
                    ),
                    (
                        AtomicOperation::Integer {
                            operation: integer::Operation::Add,
                            source: 7,
                            flags: 0,
                        },
                        0x61,
                    ),
                    (
                        AtomicOperation::Integer {
                            operation: integer::Operation::Adc,
                            source: 0,
                            flags: 1,
                        },
                        0x5b,
                    ),
                    (
                        AtomicOperation::Integer {
                            operation: integer::Operation::Neg,
                            source: 0,
                            flags: 0,
                        },
                        0u64.wrapping_sub(0x5a) & mask,
                    ),
                ] {
                    let (memory, ram) = fixture();
                    memory.write_at(0, &[0xa5; 4096]).unwrap();
                    ram.write(address, width, 0x5a).unwrap();
                    let mut before = [0; 4096];
                    memory.read_at(0, &mut before).unwrap();
                    assert_eq!(ram.atomic(address, width, operation).unwrap(), 0x5a);
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
    fn cpu_and_dma_workers_do_not_lose_disjoint_byte_writes() {
        let (memory, ram) = fixture();
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
                            memory.write_plain(lane, &((value + lane) as u8)).unwrap();
                        } else {
                            write_retry(ram, lane, 1, value + lane);
                        }
                    }
                });
            }
        });
        assert_eq!(memory.read_plain::<u64>(0).unwrap(), 0xd1d0cf);
    }

    #[test]
    fn concurrent_native_qword_accesses_do_not_tear() {
        let (_, ram) = fixture();
        let start = Arc::new(Barrier::new(3));
        let values = [0x5555aaaa5555aaaa, 0xaaaa5555aaaa5555];
        thread::scope(|scope| {
            for value in values {
                let start = start.clone();
                let ram = &ram;
                scope.spawn(move || {
                    start.wait();
                    for _ in 0..50_000 {
                        ram.write(0, 8, value).unwrap();
                    }
                });
            }
            let start = start.clone();
            let ram = &ram;
            scope.spawn(move || {
                start.wait();
                for _ in 0..50_000 {
                    let value = ram.read(0, 8).unwrap();
                    assert!(value == 0 || values.contains(&value));
                }
            });
        });
    }

    #[test]
    fn pte_replacement_between_read_and_ad_update_is_not_overwritten() {
        let (memory, ram) = fixture();
        for replacement in [0x3007, 0x3006] {
            memory.write_plain(0, &0x2007u64).unwrap();
            let seen = Arc::new(Barrier::new(2));
            let changed = Arc::new(Barrier::new(2));
            thread::scope(|scope| {
                let ram = &ram;
                let seen_cpu = seen.clone();
                let changed_cpu = changed.clone();
                scope.spawn(move || {
                    let observed = ram.read(0, 8).unwrap();
                    seen_cpu.wait();
                    changed_cpu.wait();
                    assert_eq!(
                        ram.try_mark_ad(0, observed, true).unwrap(),
                        AdUpdate::Changed(replacement)
                    );
                });
                seen.wait();
                memory.write_plain(0, &replacement).unwrap();
                changed.wait();
            });
            assert_eq!(memory.read_plain::<u64>(0).unwrap(), replacement);
        }
        assert_eq!(ram.try_mark_ad(0, 0, true).unwrap(), AdUpdate::NotPresent);
    }

    #[test]
    fn ad_updates_race_with_dma_without_losing_pte_payload() {
        let (memory, ram) = fixture();
        ram.write(0, 8, 0x2007).unwrap();
        let start = Arc::new(Barrier::new(2));
        thread::scope(|scope| {
            let start_dma = start.clone();
            let ram = &ram;
            let memory = &memory;
            scope.spawn(move || {
                start_dma.wait();
                for value in 1..2000 {
                    memory.write_plain(4, &(value as u32)).unwrap();
                }
            });
            start.wait();
            for _ in 0..2000 {
                loop {
                    let observed = ram.read(0, 8).unwrap();
                    if ram.try_mark_ad(0, observed, true).unwrap() == AdUpdate::Marked {
                        break;
                    }
                }
            }
        });
        assert_eq!(ram.read(0, 8).unwrap(), (1999u64 << 32) | 0x2067);
    }

    #[test]
    fn native_wb_message_passing_preserves_store_order() {
        let (_, ram) = fixture();
        thread::scope(|scope| {
            let ram = &ram;
            scope.spawn(move || {
                ram.write(0, 8, 0xabcdef0123456789).unwrap();
                ram.write(8, 8, 1).unwrap();
            });
            while ram.read(8, 8).unwrap() == 0 {
                thread::yield_now();
            }
            assert_eq!(ram.read(0, 8).unwrap(), 0xabcdef0123456789);
            ram.barrier();
        });
    }

    #[test]
    fn invalid_banks_are_explicit_errors() {
        let memory = GuestMemory::allocate(4096);
        assert!(matches!(
            NativeRam::new(memory.clone(), MemoryRange::EMPTY),
            Err(RamError::Region)
        ));
        let declared_bank = NativeRam::new(memory, MemoryRange::new(0..8192)).unwrap();
        assert!(matches!(
            declared_bank.read(4096, 8),
            Err(RamError::Memory(_))
        ));
    }

    #[test]
    fn existing_multi_region_backing_and_direct_writers_are_shared() {
        let memory = GuestMemory::new_multi_region(
            "native-ram-multi",
            4096,
            vec![
                Some(guestmem::AlignedHeapMemory::new(4096)),
                None,
                Some(guestmem::AlignedHeapMemory::new(4096)),
            ],
        )
        .unwrap();
        assert!(memory.full_mapping().is_none());
        let first = NativeRam::new(memory.clone(), MemoryRange::new(0..4096)).unwrap();
        let second = NativeRam::new(memory.clone(), MemoryRange::new(8192..12288)).unwrap();
        memory.write_plain(8192, &0x1122334455667788u64).unwrap();
        assert_eq!(second.read(8192, 8).unwrap(), 0x1122334455667788);
        first.write(16, 8, 0xabcdef).unwrap();
        assert_eq!(memory.read_plain::<u64>(16).unwrap(), 0xabcdef);
        assert!(matches!(
            first.read(8192, 8),
            Err(RamError::OutsideBank { .. })
        ));
        let with_hole = NativeRam::new(memory, MemoryRange::new(0..12288)).unwrap();
        assert!(matches!(with_hole.read(4096, 8), Err(RamError::Memory(_))));
    }

    #[test]
    fn neutral_core_interface_observes_direct_backing_mutations() {
        fn exercise<M: PhysicalRam<Error = RamError>>(ram: &M, memory: &GuestMemory) {
            ram.write_word(0, 7).unwrap();
            memory.write_plain(0, &9u64).unwrap();
            assert_eq!(ram.read_word(0).unwrap(), 9);
            assert_eq!(
                ram.compare_exchange_word(0, 7, 11).unwrap(),
                Exchange::Changed(9)
            );
            assert_eq!(
                ram.compare_exchange_word(0, 9, 11).unwrap(),
                Exchange::Exchanged
            );
            ram.barrier();
            assert_eq!(memory.read_plain::<u64>(0).unwrap(), 11);
        }
        let (memory, ram) = fixture();
        exercise(&ram, &memory);
    }
}
