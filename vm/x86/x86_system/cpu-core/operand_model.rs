// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

verus! {

pub open spec fn bits(width: Width) -> u32 {
    match width { Width::Byte => 8, Width::Word => 16, Width::Dword => 32, Width::Qword => 64 }
}

pub open spec fn mask(width: Width) -> u64 {
    match width {
        Width::Byte => 0xff, Width::Word => 0xffff, Width::Dword => 0xffff_ffff,
        Width::Qword => u64::MAX,
    }
}

pub open spec fn read(registers: Seq<u64>, reg: Register) -> u64 {
    (registers[reg@.gpr as int] >> (if reg@.high_byte { 8u32 } else { 0u32 })) & mask(reg@.width)
}

pub open spec fn put(before: u64, reg: Register, value: u64) -> u64 {
    let value = value & mask(reg@.width);
    match reg@.width {
        Width::Dword | Width::Qword => value,
        _ => {
            let shift = if reg@.high_byte { 8u32 } else { 0u32 };
            (before & !(mask(reg@.width) << shift)) | (value << shift)
        },
    }
}

pub open spec fn write(registers: Seq<u64>, reg: Register, value: u64) -> Seq<u64> {
    registers.update(reg@.gpr as int, put(registers[reg@.gpr as int], reg, value))
}

pub open spec fn scale(value: Scale) -> u64 {
    match value { Scale::One => 1, Scale::Two => 2, Scale::Four => 4, Scale::Eight => 8 }
}

pub open spec fn offset(registers: Seq<u64>, next_rip: u64, address: Address) -> u64 {
    let base = match address.base {
        Base::None => 0u64,
        Base::Register(reg) => registers[reg@ as int],
        Base::NextRip => next_rip,
    };
    let index = match address.index { Some(reg) => registers[reg@ as int], None => 0u64 };
    let sum = base as int + index as int * scale(address.scale) as int
        + address.displacement as int;
    let modulus = match address.size {
        AddressSize::Bits32 => 0x1_0000_0000int,
        AddressSize::Bits64 => 0x1_0000_0000_0000_0000int,
    };
    (sum % modulus) as u64
}

pub open spec fn linear(registers: Seq<u64>, next_rip: u64, address: Address, bases: SegmentBases) -> u64 {
    let segment = match address.segment { Segment::Fs => bases.fs, Segment::Gs => bases.gs, _ => 0u64 };
    ((offset(registers, next_rip, address) as int + segment as int)
        % 0x1_0000_0000_0000_0000int) as u64
}

pub open spec fn commit(registers: Seq<u64>, rip: u64, flags: u64, dst: Register,
    source: Operand, length: u8) -> (Seq<u64>, u64, ScalarStatus) {
    if length == 0 || length > 15 { (registers, rip, ScalarStatus::InvalidLength) }
    else if flags & 0x10100u64 != 0 { (registers, rip, ScalarStatus::DebugRequired) }
    else if !dst.valid() { (registers, rip, ScalarStatus::InvalidOperand) }
    else {
        let next = ((rip as int + length as int) % 0x1_0000_0000_0000_0000int) as u64;
        match source {
            Operand::Register(src) =>
                if !src.valid() { (registers, rip, ScalarStatus::InvalidOperand) }
                else if src@.width != dst@.width { (registers, rip, ScalarStatus::WidthMismatch) }
                else { (write(registers, dst, read(registers, src)), next, ScalarStatus::Advanced) },
            Operand::Immediate(imm) =>
                if imm.width != dst@.width { (registers, rip, ScalarStatus::WidthMismatch) }
                else { (write(registers, dst, imm.value), next, ScalarStatus::Advanced) },
            Operand::Address(address) =>
                if dst@.high_byte || dst@.width == Width::Byte || !address.valid() {
                    (registers, rip, ScalarStatus::InvalidOperand)
                } else { (write(registers, dst, offset(registers, next, address)), next, ScalarStatus::Advanced) },
            Operand::Memory { .. } => (registers, rip, ScalarStatus::UnsupportedMemory),
        }
    }
}

}
