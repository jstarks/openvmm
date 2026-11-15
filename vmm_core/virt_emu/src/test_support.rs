// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test-only production-protocol drivers, not an instruction oracle.
//! Vector/native comparisons check transport and host integration; independent
//! architectural expectations remain in the core's memory/event contracts.

use parking_lot::Mutex;
use std::io;
use x86_system::execute::{Batch, Machine};
use x86_system::memory::physical::{Exchange, PhysicalRam};
use x86_system::mmu::translate::RunError;
use x86_system::reference::ReferenceMachine;

struct VectorRam<'a>(Mutex<&'a mut Vec<u8>>);

impl PhysicalRam for VectorRam<'_> {
    type Error = io::Error;

    fn read_word(&self, address: u64) -> io::Result<u64> {
        let memory = self.0.lock();
        let bytes = memory
            .get(address as usize..address as usize + 8)
            .ok_or_else(|| io::Error::other("outside fixture RAM"))?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn write_word(&self, address: u64, value: u64) -> io::Result<()> {
        self.0
            .lock()
            .get_mut(address as usize..address as usize + 8)
            .ok_or_else(|| io::Error::other("outside fixture RAM"))?
            .copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn compare_exchange_word(&self, address: u64, old: u64, new: u64) -> io::Result<Exchange> {
        let mut memory = self.0.lock();
        let bytes = memory
            .get_mut(address as usize..address as usize + 8)
            .ok_or_else(|| io::Error::other("outside fixture RAM"))?;
        let observed = u64::from_le_bytes(bytes.try_into().unwrap());
        if observed != old {
            return Ok(Exchange::Changed(observed));
        }
        bytes.copy_from_slice(&new.to_le_bytes());
        Ok(Exchange::Exchanged)
    }

    fn barrier(&self) {}
}

pub(super) fn run_fixture(
    snapshot: &mut ReferenceMachine,
    bytes: &mut Vec<u8>,
    steps: u64,
) -> Batch {
    let mut cpu = Machine::from_event_fixture(*snapshot);
    let batch = cpu
        .run_decoded(&VectorRam(Mutex::new(bytes)), u32::MAX, steps)
        .unwrap();
    *snapshot = cpu
        .event_fixture()
        .expect("fixture did not reach a CPU boundary");
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
