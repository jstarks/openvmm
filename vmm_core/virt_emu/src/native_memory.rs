// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native x86-64 lowering for coherent WB RAM, not an MMIO implementation.
//!
//! Data caching and buffering belong to the host CPU. Accesses use side-effecting
//! native transport; guest barriers/serializing events explicitly call `barrier`.
//! This host-ISA-specific implementation does not apply to weaker host ISAs.

use guestmem::{GuestMemory, GuestMemoryError};
use std::sync::atomic::{Ordering, fence};
use x86_system::arch::integer;
use x86_system::memory::physical::{
    self as physical, AtomicOperation, AtomicResult, CopyError, CopyErrorKind, PhysicalRam,
};

/// Failure of the physical RAM interface, not an architectural guest exception.
#[derive(Debug, thiserror::Error)]
pub enum RamError {
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

/// Shared coherent WB view of existing OpenVMM backing.
///
/// GuestMemory owns backing resolution and bounds. Callers independently classify
/// RAM versus MMIO; transport failures are not device classification.
#[derive(Clone, Debug)]
pub struct NativeRam {
    memory: GuestMemory,
}

impl NativeRam {
    /// Creates a native view without duplicating GuestMemory's backing metadata.
    pub fn new(memory: GuestMemory) -> Self {
        Self { memory }
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

impl PhysicalRam for NativeRam {
    type Error = RamError;

    fn read<const N: usize>(&self, address: u64) -> Result<[u8; N], RamError> {
        const { assert!(matches!(N, 1 | 2 | 4 | 8)) };
        let result = self.memory.read_plain::<[u8; N]>(address);
        Ok(result?)
    }

    fn write<const N: usize>(&self, address: u64, value: [u8; N]) -> Result<(), RamError> {
        const { assert!(matches!(N, 1 | 2 | 4 | 8)) };
        let result = self.memory.write_plain(address, &value);
        Ok(result?)
    }

    fn read_bytes(&self, address: u64, destination: &mut [u8]) -> Result<(), CopyError<RamError>> {
        physical::read_bytes(self, address, destination)
    }

    fn write_bytes(&self, address: u64, source: &[u8]) -> Result<(), CopyError<RamError>> {
        physical::write_bytes(self, address, source)
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
            kind: CopyErrorKind::Memory(RamError::Memory(error)),
        };
        if let AtomicOperation::CompareExchange {
            expected,
            replacement,
        } = operation
        {
            macro_rules! exchange {
                ($ty:ty) => {{
                    let result =
                        self.memory
                            .compare_exchange(address, expected as $ty, replacement as $ty);
                    result.map(|value| {
                        AtomicResult::Value(u64::from(match value {
                            Ok(_) => expected as $ty,
                            Err(observed) => observed,
                        }))
                    })
                }};
            }
            return match width {
                1 => exchange!(u8),
                2 => exchange!(u16),
                4 => exchange!(u32),
                8 => exchange!(u64),
                _ => return Err(invalid()),
            }
            .map_err(failure);
        }
        use guestmem::AtomicOperation as Native;
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
        let result = self.memory.atomic(address, width, operation, source, flags);
        result
            .map(|result| match result {
                guestmem::AtomicResult::Value(value) => AtomicResult::Value(value),
                guestmem::AtomicResult::Flags(flags) => AtomicResult::Flags(flags),
            })
            .map_err(failure)
    }

    fn barrier(&self) {
        NativeRam::barrier(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use test_with_tracing::test;
    use x86_system::arch::operand::Width;

    fn fixture() -> (GuestMemory, NativeRam) {
        let memory = GuestMemory::allocate(4096);
        let ram = NativeRam::new(memory.clone());
        (memory, ram)
    }

    fn read(ram: &NativeRam, address: u64, width: u8) -> u64 {
        match width {
            1 => u64::from(u8::from_le_bytes(ram.read(address).unwrap())),
            2 => u64::from(u16::from_le_bytes(ram.read(address).unwrap())),
            4 => u64::from(u32::from_le_bytes(ram.read(address).unwrap())),
            8 => u64::from_le_bytes(ram.read(address).unwrap()),
            _ => panic!("invalid test width"),
        }
    }

    fn write(ram: &NativeRam, address: u64, width: u8, value: u64) {
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
        let (memory, ram) = fixture();
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
        assert!(matches!(ram.write(4096, [1; 8]), Err(RamError::Memory(_))));
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
        let error = ram.write_bytes(4085, &[0x33; 19]).unwrap_err();
        assert_eq!(error.completed, 11);
        assert!(matches!(
            error.kind,
            CopyErrorKind::Memory(RamError::Memory(_))
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
        let (memory, ram) = fixture();
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
                    let (memory, ram) = fixture();
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
        let (memory, ram) = fixture();
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
        let (_, ram) = fixture();
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
                    let observed = read(ram, 0, 8);
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
        write(&ram, 0, 8, 0x2007);
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
        let (_, ram) = fixture();
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
        let ram = NativeRam::new(memory.clone());
        memory.write_plain(8192, &0x1122334455667788u64).unwrap();
        assert_eq!(read(&ram, 8192, 8), 0x1122334455667788);
        write(&ram, 16, 8, 0xabcdef);
        assert_eq!(memory.read_plain::<u64>(16).unwrap(), 0xabcdef);
        assert!(matches!(ram.read::<8>(4096), Err(RamError::Memory(_))));
    }

    #[test]
    fn neutral_core_interface_observes_direct_backing_mutations() {
        fn exercise<M: PhysicalRam<Error = RamError>>(ram: &M, memory: &GuestMemory) {
            ram.write(0, 7u64.to_le_bytes()).unwrap();
            memory.write_plain(0, &9u64).unwrap();
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
        let (memory, ram) = fixture();
        exercise(&ram, &memory);
    }
}
