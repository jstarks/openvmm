// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Initial owned-core integration with OpenVMM register and memory types.
//!
//! The host-x86 `backend` implements a restricted long-mode VP lifecycle with
//! shared paging, events and device continuation. Full OpenVMM can select
//! the native Strudel executor with `--hypervisor strudel` for Linux direct boot.

#![deny(unsafe_code)]
#![cfg(guest_arch = "x86_64")]

use virt::vp::Registers;
use x86_system::State;

// xtask-fmt allow-target-arch cpu-intrinsic -- Depends on host x86 WB ordering.
#[cfg(target_arch = "x86_64")]
pub mod native_memory;

// xtask-fmt allow-target-arch cpu-intrinsic -- Native partition coherence foundation.
#[cfg(target_arch = "x86_64")]
pub mod write_watch;

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

// xtask-fmt allow-target-arch cpu-intrinsic -- Native transport comparison drivers.
#[cfg(all(test, target_arch = "x86_64"))]
mod test_support;

// xtask-fmt allow-target-arch cpu-intrinsic -- Native partition-mapping fixtures.
#[cfg(all(test, target_arch = "x86_64"))]
mod mapped_test_memory;

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
    fn cpu_register_conversion_round_trips_all_gprs_and_preserves_other_vp_state() {
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
        let untouched = registers;
        let state = State {
            gpr: std::array::from_fn(|i| 0xfedc_ba98_7654_3210u64.wrapping_mul(i as u64 + 1)),
            rip: 0x9876_5432,
            flags: 0x206,
        };
        update_registers(&mut registers, state);
        assert_eq!(state_from_registers(&registers), state);
        update_registers(&mut registers, state_from_registers(&untouched));
        assert_eq!(registers, untouched);
    }
}
