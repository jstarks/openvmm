// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use vstd::prelude::*;

#[path = "operand_model.rs"]
pub mod model;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum Width {
    Byte,
    Word,
    Dword,
    Qword,
}

impl Width {
    pub fn bits(self) -> (out: u32)
        ensures out == model::bits(self),
    {
        match self {
            Self::Byte => 8,
            Self::Word => 16,
            Self::Dword => 32,
            Self::Qword => 64,
        }
    }

    pub fn mask(self) -> (out: u64)
        ensures out == model::mask(self),
    {
        match self {
            Self::Byte => 0xff, Self::Word => 0xffff, Self::Dword => 0xffff_ffff,
            Self::Qword => u64::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gpr(u8);

impl View for Gpr {
    type V = u8;
    closed spec fn view(&self) -> u8 { self.0 }
}

impl Gpr {
    pub fn new(index: u8) -> (out: Option<Self>)
        ensures out.is_some() == (index < 16),
            match out { Some(gpr) => gpr@ == index && gpr.valid(), None => true },
    {
        if index < 16 {
            Some(Self(index))
        } else {
            None
        }
    }

    pub open spec fn valid(self) -> bool { self@ < 16 }

    pub fn index(self) -> (out: usize)
        ensures out == self@ as usize,
    {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Register {
    gpr: Gpr,
    width: Width,
    high_byte: bool,
}

pub struct RegisterView { pub gpr: u8, pub width: Width, pub high_byte: bool }
impl View for Register {
    type V = RegisterView;
    closed spec fn view(&self) -> RegisterView {
        RegisterView { gpr: self.gpr.0, width: self.width, high_byte: self.high_byte }
    }
}

impl Register {
    pub fn new(gpr: Gpr, width: Width, high_byte: bool) -> (out: Option<Self>)
        requires gpr.valid(),
        ensures out.is_some() == (!high_byte || (width == Width::Byte && gpr@ < 4)),
            match out { Some(reg) => reg.valid() && reg@.gpr == gpr@ && reg@.width == width
                && reg@.high_byte == high_byte, None => true },
    {
        if high_byte && (!matches!(width, Width::Byte) || gpr.0 >= 4) {
            None
        } else {
            Some(Self {
                gpr,
                width,
                high_byte,
            })
        }
    }

    pub open spec fn valid(self) -> bool {
        self@.gpr < 16 && (!self@.high_byte || (self@.width == Width::Byte && self@.gpr < 4))
    }

    pub fn gpr(self) -> (out: Gpr)
        ensures out@ == self@.gpr,
    {
        self.gpr
    }

    pub fn width(self) -> (out: Width)
        ensures out == self@.width,
    {
        self.width
    }

    pub fn high_byte(self) -> (out: bool)
        ensures out == self@.high_byte,
    {
        self.high_byte
    }

    pub fn read(self, registers: &[u64; 16]) -> (out: u64)
        requires self.valid(),
        ensures out == model::read(registers@, self),
    {
        (registers[self.gpr.index()] >> self.shift()) & self.width.mask()
    }

    pub fn write(self, registers: &mut [u64; 16], value: u64)
        requires self.valid(),
        ensures final(registers)@ == model::write(old(registers)@, self, value),
            forall|i: int| 0 <= i < 16 && i != self@.gpr as int
                ==> #[trigger] final(registers)@[i] == old(registers)@[i],
            self@.width == Width::Dword ==> final(registers)@[self@.gpr as int] <= 0xffff_ffff,
    {
        proof { reveal(<Register as View>::view); reveal(<Gpr as View>::view); }
        let ghost before = registers@;
        let width_mask = self.width.mask();
        let masked = value & width_mask;
        let index = self.gpr.index();
        let previous = registers[index];
        if self.width == Width::Dword || self.width == Width::Qword {
            registers[index] = masked;
        } else {
            let mask = width_mask << self.shift();
            registers[index] = (previous & !mask) | (masked << self.shift());
        }
        proof {
            assert(registers@[index as int] == model::put(previous, self, value));
            assert(registers@ =~= before.update(index as int,
                model::put(previous, self, value)));
            if self.width == Width::Dword {
                assert(masked <= 0xffff_ffffu64) by(bit_vector)
                    requires masked == value & 0xffff_ffffu64;
            }
        }
    }

    fn shift(self) -> (out: u32)
        ensures out == if self.high_byte { 8u32 } else { 0u32 },
    {
        if self.high_byte {
            8
        } else {
            0
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressSize {
    Bits32,
    Bits64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Segment {
    Es,
    Cs,
    Ss,
    Ds,
    Fs,
    Gs,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SegmentBases {
    pub fs: u64,
    pub gs: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base {
    None,
    Register(Gpr),
    NextRip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scale {
    One,
    Two,
    Four,
    Eight,
}

impl Scale {
    pub fn value(self) -> (out: u64)
        ensures out == model::scale(self), out <= 8,
    {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
            Self::Eight => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub size: AddressSize,
    pub segment: Segment,
    pub base: Base,
    pub index: Option<Gpr>,
    pub scale: Scale,
    pub displacement: u64,
}

impl Address {
    pub open spec fn valid(self) -> bool {
        (match self.base { Base::Register(reg) => reg.valid(), _ => true })
        && (match self.index { Some(reg) => reg.valid(), None => true })
    }

    /// Effective offset only: LEA must not add segment bases or access memory.
    pub fn offset(self, registers: &[u64; 16], next_rip: u64) -> (out: u64)
        requires self.valid(),
        ensures out == model::offset(registers@, next_rip, self),
            self.size == AddressSize::Bits32 ==> out <= 0xffff_ffff,
    {
        let base = match self.base {
            Base::None => 0,
            Base::Register(reg) => registers[reg.index()],
            Base::NextRip => next_rip,
        };
        let index = match self.index { Some(reg) => registers[reg.index()], None => 0 };
        let scale = self.scale.value();
        let offset = base
            .wrapping_add(index.wrapping_mul(scale))
            .wrapping_add(self.displacement);
        proof {
            assert(offset as int == (base as int + index as int * scale as int
                + self.displacement as int) % 0x1_0000_0000_0000_0000int);
        }
        match self.size {
            AddressSize::Bits32 => {
                proof {
                    vstd::arithmetic::div_mod::lemma_mod_mod(
                        base as int + index as int * scale as int + self.displacement as int,
                        0x1_0000_0000int, 0x1_0000_0000int);
                }
                assert(offset & 0xffff_ffffu64 <= 0xffff_ffffu64) by(bit_vector);
                assert(offset & 0xffff_ffffu64 == offset % 0x1_0000_0000u64) by(bit_vector);
                offset & 0xffff_ffff
            },
            AddressSize::Bits64 => offset,
        }
    }

    /// Canonicality, segment faults and translation belong to the access layer.
    pub fn linear(self, registers: &[u64; 16], next_rip: u64, bases: SegmentBases) -> (out: u64)
        requires self.valid(),
        ensures out == model::linear(registers@, next_rip, self, bases),
    {
        let segment = match self.segment {
            Segment::Fs => bases.fs,
            Segment::Gs => bases.gs,
            _ => 0,
        };
        self.offset(registers, next_rip).wrapping_add(segment)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Immediate {
    pub encoded_width: Width,
    pub width: Width,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operand {
    Register(Register),
    Immediate(Immediate),
    Memory { address: Address, width: Width },
    Address(Address),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarStatus {
    Advanced,
    InvalidOperand,
    WidthMismatch,
    UnsupportedMemory,
    InvalidLength,
    DebugRequired,
}

/// Register/immediate MOV and LEA commit only; no memory accesses are issued.
pub fn commit_scalar(registers: &mut [u64; 16], rip: &mut u64, flags: u64,
    dst: Register, source: Operand, length: u8) -> (status: ScalarStatus)
    ensures
        (final(registers)@, *final(rip), status) ==
            model::commit(old(registers)@, *old(rip), flags, dst, source, length),
        status != ScalarStatus::Advanced ==>
            final(registers)@ == old(registers)@ && *final(rip) == *old(rip),
        forall|i: int| 0 <= i < 16 && i != dst@.gpr as int
            ==> #[trigger] final(registers)@[i] == old(registers)@[i],
{
    proof { reveal(<Register as View>::view); reveal(<Gpr as View>::view); }
    if length == 0 || length > 15 { return ScalarStatus::InvalidLength; }
    if flags & 0x10100u64 != 0 { return ScalarStatus::DebugRequired; }
    if !dst.is_valid() { return ScalarStatus::InvalidOperand; }
    let value = match source {
        Operand::Register(src) => {
            if !src.is_valid() { return ScalarStatus::InvalidOperand; }
            if src.width != dst.width { return ScalarStatus::WidthMismatch; }
            src.read(registers)
        },
        Operand::Immediate(imm) => {
            if imm.width != dst.width { return ScalarStatus::WidthMismatch; }
            imm.value
        },
        Operand::Address(address) => {
            if dst.high_byte || dst.width == Width::Byte || !address.is_valid() {
                return ScalarStatus::InvalidOperand;
            }
            address.offset(registers, (*rip).wrapping_add(length as u64))
        },
        Operand::Memory { .. } => { return ScalarStatus::UnsupportedMemory; },
    };
    dst.write(registers, value);
    *rip = (*rip).wrapping_add(length as u64);
    ScalarStatus::Advanced
}

impl Register {
    pub fn is_valid(self) -> (out: bool)
        ensures out == self.valid(),
    {
        proof { reveal(<Register as View>::view); }
        assert(self@.gpr == self.gpr.0);
        assert(self@.width == self.width);
        assert(self@.high_byte == self.high_byte);
        self.gpr.0 < 16 && (!self.high_byte || (self.width == Width::Byte && self.gpr.0 < 4))
    }
}

impl Address {
    pub fn is_valid(self) -> (out: bool)
        ensures out == self.valid(),
    {
        let base = match self.base { Base::Register(reg) => reg.0 < 16, _ => true };
        let index = match self.index { Some(reg) => reg.0 < 16, None => true };
        base && index
    }
}

}
