// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Initial owned-core integration with OpenVMM register and memory types.
//!
//! The host-x86 `backend` implements a restricted long-mode VP lifecycle with
//! shared paging, events and device continuation. It is not a selectable
//! Linux-capable machine backend. Pretranslated instruction-window experiments
//! are test-only; the backend uses Strudel's self-contained machine.

#![forbid(unsafe_code)]
#![cfg(guest_arch = "x86_64")]

#[cfg(test)]
use guestmem::{GuestMemory, GuestMemoryError};
use virt::vp::Registers;
use x86_system::State;
#[cfg(test)]
use x86_system::arch::{Diagnostic, Profile, decoder};

// xtask-fmt allow-target-arch cpu-intrinsic -- Depends on host x86 WB ordering.
#[cfg(target_arch = "x86_64")]
pub mod native_memory;

// xtask-fmt allow-target-arch cpu-intrinsic -- Uses the native x86 WB RAM transport.
#[cfg(target_arch = "x86_64")]
pub mod backend;

// xtask-fmt allow-target-arch cpu-intrinsic -- Exercises the native WB RAM provider.
#[cfg(all(test, target_arch = "x86_64"))]
mod shared_mmu_tests;

// xtask-fmt allow-target-arch cpu-intrinsic -- Exercises the native WB RAM provider.
#[cfg(all(test, target_arch = "x86_64"))]
mod shared_cpu_tests;

// xtask-fmt allow-target-arch cpu-intrinsic -- Exercises the native WB RAM provider.
#[cfg(all(test, target_arch = "x86_64"))]
mod shared_event_tests;

// xtask-fmt allow-target-arch cpu-intrinsic -- Exercises the native WB RAM provider.
#[cfg(all(test, target_arch = "x86_64"))]
mod shared_io_tests;

// xtask-fmt allow-target-arch cpu-intrinsic -- Exercises the native x86 backend.
#[cfg(all(test, target_arch = "x86_64"))]
mod backend_tests;

/// Failure to read or execute a supported instruction window.
#[derive(Debug, thiserror::Error)]
#[cfg(test)]
pub enum Error {
    /// The supplied physical instruction window could not be read.
    #[error("reading pretranslated instruction window")]
    Memory(#[from] GuestMemoryError),
    /// The owned core explicitly rejected the instruction or execution profile.
    #[error("owned core stopped: {0:?}")]
    Instruction(Diagnostic),
}

/// Executes one supported register instruction from a caller-translated GPA.
///
/// The caller supplies the instruction's GPA independently of architectural
/// RIP. This does not walk page tables, inject architectural fetch faults, or
/// establish that the supplied GPA is the correct translation.
/// Only GPRs, RFLAGS and RIP are changed, and only on successful execution.
#[cfg(test)]
fn execute_pretranslated(
    registers: &mut Registers,
    memory: &GuestMemory,
    instruction_gpa: u64,
) -> Result<u8, Error> {
    let mut bytes = [0; 3];
    memory.read_at(instruction_gpa, &mut bytes)?;
    let mut state = state_from_registers(registers);
    let step = decoder::step(&mut state, &bytes, Profile::Long64);
    if step.status != Diagnostic::Advanced {
        return Err(Error::Instruction(step.status));
    }
    update_registers(registers, state);
    Ok(step.consumed)
}

fn state_from_registers(registers: &Registers) -> State {
    State {
        gpr: [
            registers.rax,
            registers.rcx,
            registers.rdx,
            registers.rbx,
            registers.rsp,
            registers.rbp,
            registers.rsi,
            registers.rdi,
            registers.r8,
            registers.r9,
            registers.r10,
            registers.r11,
            registers.r12,
            registers.r13,
            registers.r14,
            registers.r15,
        ],
        flags: registers.rflags,
        rip: registers.rip,
    }
}

fn update_registers(registers: &mut Registers, state: State) {
    [
        registers.rax,
        registers.rcx,
        registers.rdx,
        registers.rbx,
        registers.rsp,
        registers.rbp,
        registers.rsi,
        registers.rdi,
        registers.r8,
        registers.r9,
        registers.r10,
        registers.r11,
        registers.r12,
        registers.r13,
        registers.r14,
        registers.r15,
    ] = state.gpr;
    registers.rflags = state.flags;
    registers.rip = state.rip;
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn carry_chain_uses_guest_memory_and_preserves_other_vp_state() {
        let memory = GuestMemory::allocate(4096);
        memory
            .write_at(0x100, &[0x4c, 0x01, 0xc0, 0x4c, 0x11, 0xc9])
            .unwrap();
        let mut registers = Registers {
            rax: u64::MAX,
            rcx: 7,
            r8: 1,
            r9: 2,
            r15: 0xabcdef,
            rip: 0x8000005000,
            rflags: 0x202,
            cr3: 0x1234,
            ..Default::default()
        };
        let mut expected = registers;
        expected.rax = 0;
        expected.rcx = 10;
        expected.rip += 6;
        expected.rflags = 0x206;
        assert_eq!(
            execute_pretranslated(&mut registers, &memory, 0x100).unwrap(),
            3
        );
        assert_eq!(registers.rax, 0);
        assert_eq!(registers.rflags & 1, 1);
        assert_eq!(
            execute_pretranslated(&mut registers, &memory, 0x103).unwrap(),
            3
        );
        assert_eq!(registers, expected);
    }

    #[test]
    fn rejected_instruction_and_memory_failure_preserve_registers() {
        let memory = GuestMemory::allocate(4096);
        memory.write_at(0, &[0x90; 3]).unwrap();
        let mut registers = Registers {
            rip: 0x1234,
            rflags: 2,
            ..Default::default()
        };
        let before = registers;
        assert!(matches!(
            execute_pretranslated(&mut registers, &memory, 0),
            Err(Error::Instruction(Diagnostic::UnsupportedEncoding))
        ));
        assert_eq!(registers, before);
        assert!(matches!(
            execute_pretranslated(&mut registers, &memory, 8192),
            Err(Error::Memory(_))
        ));
        assert_eq!(registers, before);
    }

    #[test]
    fn high_register_and_stack_pointer_destinations_round_trip() {
        let memory = GuestMemory::allocate(4096);
        memory
            .write_at(0, &[0x4d, 0x01, 0xf7, 0x48, 0x11, 0xec])
            .unwrap();
        let mut registers = Registers {
            r14: 5,
            r15: 7,
            rsp: 0x1000,
            rbp: 8,
            rflags: 2,
            ..Default::default()
        };
        let mut expected = registers;
        expected.r15 = 12;
        expected.rsp = 0x1008;
        expected.rip = 6;
        expected.rflags = 2;
        execute_pretranslated(&mut registers, &memory, 0).unwrap();
        execute_pretranslated(&mut registers, &memory, 3).unwrap();
        assert_eq!(registers, expected);
    }
}
