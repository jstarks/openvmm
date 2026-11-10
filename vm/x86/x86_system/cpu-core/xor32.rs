// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::arithmetic;
#[cfg(verus_keep_ghost)]
use super::operand;
use super::operand::{Register, ScalarStatus, Width};
use vstd::prelude::*;

verus! {

pub open spec fn transition(registers: Seq<u64>, rip: u64, flags: u64,
    dst: Register, src: Register, length: u8) -> (Seq<u64>, u64, u64, ScalarStatus) {
    if length == 0 || length > 15 {
        (registers, rip, flags, ScalarStatus::InvalidLength)
    } else if flags & 0x10100u64 != 0 {
        (registers, rip, flags, ScalarStatus::DebugRequired)
    } else if !dst.valid() || !src.valid() {
        (registers, rip, flags, ScalarStatus::InvalidOperand)
    } else if dst@.width != Width::Dword || src@.width != Width::Dword {
        (registers, rip, flags, ScalarStatus::WidthMismatch)
    } else {
        let value = operand::model::read(registers, dst) ^ operand::model::read(registers, src);
        let flags = (flags & !0x8d5u64)
            | (if arithmetic::model::population((value % 256) as int) % 2 == 0 { 4u64 } else { 0u64 })
            | (if value == 0 { 64u64 } else { 0u64 })
            | (if value >= 0x8000_0000u64 { 128u64 } else { 0u64 });
        (operand::model::write(registers, dst, value),
            ((rip as int + length as int) % 0x1_0000_0000_0000_0000int) as u64,
            flags, ScalarStatus::Advanced)
    }
}

/// XOR32 commits defined flags and chooses zero for architecturally undefined AF.
pub fn commit(registers: &mut [u64; 16], rip: &mut u64, flags: &mut u64,
    dst: Register, src: Register, length: u8) -> (status: ScalarStatus)
    ensures
        (final(registers)@, *final(rip), *final(flags), status) ==
            transition(old(registers)@, *old(rip), *old(flags), dst, src, length),
        status != ScalarStatus::Advanced ==>
            final(registers)@ == old(registers)@ && *final(rip) == *old(rip)
                && *final(flags) == *old(flags),
        forall|i: int| 0 <= i < 16 && i != dst@.gpr as int
            ==> #[trigger] final(registers)@[i] == old(registers)@[i],
    {
        if length == 0 || length > 15 { return ScalarStatus::InvalidLength; }
        if *flags & 0x10100u64 != 0 { return ScalarStatus::DebugRequired; }
        if !dst.is_valid() || !src.is_valid() { return ScalarStatus::InvalidOperand; }
        if dst.width() != Width::Dword || src.width() != Width::Dword {
            return ScalarStatus::WidthMismatch;
        }
        let value = dst.read(registers) ^ src.read(registers);
        let even = arithmetic::parity((value % 256) as u8);
        let next_flags = (*flags & !0x8d5u64)
            | (if even { 4u64 } else { 0u64 })
            | (if value == 0 { 64u64 } else { 0u64 })
            | (if value >= 0x8000_0000u64 { 128u64 } else { 0u64 });
        dst.write(registers, value);
        *rip = (*rip).wrapping_add(length as u64);
        *flags = next_flags;
        ScalarStatus::Advanced
    }
}
