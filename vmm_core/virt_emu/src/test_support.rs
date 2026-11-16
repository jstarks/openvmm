// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test-only production-protocol drivers, not an instruction oracle.
//! Vector/native comparisons check transport and host integration; independent
//! architectural expectations remain in the core's memory/event contracts.

use parking_lot::Mutex;
use std::io;
use x86_system::arch::system::{SegmentState, SystemState};
use x86_system::arch::{integer, operand::Width};
use x86_system::execute::{Batch, Machine};
use x86_system::memory::physical::{
    self as physical, AtomicOperation, AtomicResult, CopyError, CopyErrorKind, PhysicalRam,
};
use x86_system::mmu::translate::RunError;
use x86_system::reference::ReferenceMachine;

pub(super) fn long64_system() -> SystemState {
    let data = SegmentState {
        base: 0,
        limit: u32::MAX,
        selector: 16,
        attributes: 0xc093,
    };
    SystemState {
        cs: SegmentState {
            base: 0,
            limit: u32::MAX,
            selector: 8,
            attributes: 0xa09b,
        },
        ss: data,
        ds: data,
        es: data,
        ..SystemState::empty()
    }
}

/// Carries the explicit system image alongside the bounded ring-zero event snapshot.
pub(super) struct EventFixture {
    pub snapshot: ReferenceMachine,
    pub system: SystemState,
}

impl std::ops::Deref for EventFixture {
    type Target = ReferenceMachine;

    fn deref(&self) -> &ReferenceMachine {
        &self.snapshot
    }
}

impl std::ops::DerefMut for EventFixture {
    fn deref_mut(&mut self) -> &mut ReferenceMachine {
        &mut self.snapshot
    }
}

struct VectorRam<'a>(Mutex<&'a mut Vec<u8>>);

impl PhysicalRam for VectorRam<'_> {
    type Error = io::Error;

    fn read<const N: usize>(&self, address: u64) -> io::Result<[u8; N]> {
        const { assert!(matches!(N, 1 | 2 | 4 | 8)) };
        let memory = self.0.lock();
        let bytes = memory
            .get(fixture_range(address, N)?)
            .ok_or_else(|| io::Error::other("outside fixture RAM"))?;
        Ok(bytes.try_into().unwrap())
    }

    fn write<const N: usize>(&self, address: u64, value: [u8; N]) -> io::Result<()> {
        const { assert!(matches!(N, 1 | 2 | 4 | 8)) };
        self.0
            .lock()
            .get_mut(fixture_range(address, N)?)
            .ok_or_else(|| io::Error::other("outside fixture RAM"))?
            .copy_from_slice(&value);
        Ok(())
    }

    fn read_bytes(
        &self,
        address: u64,
        destination: &mut [u8],
    ) -> Result<(), CopyError<Self::Error>> {
        physical::read_bytes(self, address, destination)
    }

    fn write_bytes(&self, address: u64, source: &[u8]) -> Result<(), CopyError<Self::Error>> {
        physical::write_bytes(self, address, source)
    }

    fn atomic(
        &self,
        address: u64,
        width: u8,
        operation: AtomicOperation,
    ) -> Result<AtomicResult, CopyError<Self::Error>> {
        let invalid = || CopyError {
            completed: 0,
            kind: CopyErrorKind::InvalidAccess,
        };
        let operand_width = match width {
            1 => Width::Byte,
            2 => Width::Word,
            4 => Width::Dword,
            8 => Width::Qword,
            _ => return Err(invalid()),
        };
        if !address.is_multiple_of(u64::from(width)) {
            return Err(invalid());
        }
        let failure = |source| CopyError {
            completed: 0,
            kind: CopyErrorKind::Memory(source),
        };
        let mut memory = self.0.lock();
        let bytes = memory
            .get_mut(fixture_range(address, usize::from(width)).map_err(failure)?)
            .ok_or_else(|| failure(io::Error::other("outside fixture RAM")))?;
        let mut data = [0; 8];
        data[..usize::from(width)].copy_from_slice(bytes);
        let observed = u64::from_le_bytes(data);
        let mask = u64::MAX >> ((8 - width) * 8);
        let (replacement, result) = match operation {
            AtomicOperation::CompareExchange {
                expected,
                replacement,
            } => {
                if observed != expected & mask {
                    return Ok(AtomicResult::Value(observed));
                }
                (replacement, AtomicResult::Value(observed))
            }
            AtomicOperation::Exchange { replacement } => {
                (replacement, AtomicResult::Value(observed))
            }
            AtomicOperation::FetchAdd { source } => {
                (observed.wrapping_add(source), AtomicResult::Value(observed))
            }
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
                if !matches!(
                    operation,
                    integer::Operation::Add
                        | integer::Operation::Adc
                        | integer::Operation::Sub
                        | integer::Operation::Sbb
                        | integer::Operation::And
                        | integer::Operation::Or
                        | integer::Operation::Xor
                        | integer::Operation::Inc
                        | integer::Operation::Dec
                        | integer::Operation::Neg
                        | integer::Operation::Not
                        | integer::Operation::BitSet
                        | integer::Operation::BitReset
                        | integer::Operation::BitComplement
                ) {
                    return Err(invalid());
                }
                let result = integer::evaluate(operation, observed, source, operand_width, flags);
                (result.value, AtomicResult::Flags(result.flags))
            }
        };
        bytes.copy_from_slice(&replacement.to_le_bytes()[..usize::from(width)]);
        Ok(result)
    }

    fn barrier(&self) {}
}

fn fixture_range(address: u64, length: usize) -> io::Result<std::ops::Range<usize>> {
    let start = usize::try_from(address).map_err(io::Error::other)?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| io::Error::other("fixture range overflow"))?;
    Ok(start..end)
}

pub(super) fn map_copy_error<E: std::error::Error + Send + Sync + 'static>(
    error: CopyError<E>,
) -> CopyError<io::Error> {
    CopyError {
        completed: error.completed,
        kind: match error.kind {
            CopyErrorKind::Memory(error) => CopyErrorKind::Memory(io::Error::other(error)),
            CopyErrorKind::InvalidAccess => CopyErrorKind::InvalidAccess,
            CopyErrorKind::AddressOverflow => CopyErrorKind::AddressOverflow,
            CopyErrorKind::Contended => CopyErrorKind::Contended,
        },
    }
}

pub(super) fn run_fixture(fixture: &mut EventFixture, bytes: &mut Vec<u8>, steps: u64) -> Batch {
    let mut cpu = Machine::from_event_fixture(fixture.snapshot, fixture.system).unwrap();
    let batch = cpu
        .run_decoded(&VectorRam(Mutex::new(bytes)), u32::MAX, steps)
        .unwrap();
    fixture.snapshot = cpu
        .event_fixture()
        .expect("fixture did not reach a CPU boundary");
    fixture.system = cpu.state().system;
    batch
}

pub(super) trait RunDecoded {
    fn run_decoded<R: PhysicalRam>(
        &mut self,
        ram: &R,
        effects: u32,
        steps: u64,
    ) -> Result<Batch, RunError<R::Error>>;
    fn run_mmio_decoded<R: PhysicalRam>(
        &mut self,
        ram: &R,
        effects: u32,
        steps: u64,
        classify: impl FnMut(u64, u8) -> bool,
    ) -> Result<Batch, RunError<R::Error>>;
}

impl RunDecoded for Machine {
    fn run_decoded<R: PhysicalRam>(
        &mut self,
        ram: &R,
        effects: u32,
        steps: u64,
    ) -> Result<Batch, RunError<R::Error>> {
        self.run_mmio_decoded(ram, effects, steps, |_, _| false)
    }

    fn run_mmio_decoded<R: PhysicalRam>(
        &mut self,
        ram: &R,
        effects: u32,
        steps: u64,
        classify: impl FnMut(u64, u8) -> bool,
    ) -> Result<Batch, RunError<R::Error>> {
        self.run_with_window(
            ram,
            effects,
            steps,
            classify,
            |window| Some((window.input.length, x86_decode::admit(window.input))),
            |_| false,
        )
    }
}
