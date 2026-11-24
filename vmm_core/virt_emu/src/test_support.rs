// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test-only production-protocol drivers, not an instruction oracle.
//! Budgeted runs are compared with uninterrupted runs on independent RAM images;
//! independent architectural expectations remain in the core's memory/event contracts.

use x86_system::arch::system::{SegmentState, SystemState};
use x86_system::execute::{Batch, Machine};
use x86_system::memory::physical::PhysicalRam;
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

pub(super) fn run_fixture(fixture: &mut EventFixture, bytes: &mut [u8], steps: u64) -> Batch {
    let mut cpu = Machine::from_event_fixture(fixture.snapshot, fixture.system).unwrap();
    let image = super::mapped_test_memory::MappedTestMemory::fixture(bytes);
    let lease = image.access();
    let batch = cpu.run_decoded(&lease.ram(), u32::MAX, steps).unwrap();
    image.read_at(0, bytes).unwrap();
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
        self.run_with_decoder(
            ram,
            effects,
            steps,
            classify,
            |request| match request {
                x86_system::execute::decode::DecodeRequest::Execution(_)
                | x86_system::execute::decode::DecodeRequest::Fetch(_) => None,
                x86_system::execute::decode::DecodeRequest::Bytes(input) => Some(
                    x86_system::execute::decode::DecodeResponse::Decoded(x86_decode::admit(input)),
                ),
            },
            |_| false,
        )
    }
}
