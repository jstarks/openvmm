// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{
    State, integer,
    operand::{Gpr, Register, Width},
};
use vstd::prelude::*;

pub mod model {
    #[cfg(verus_keep_ghost)]
    use super::super::{model::State as Cpu, operand};
    use super::*;

    verus! {
    pub open spec fn accumulator(width: Width) -> Register {
        choose|reg: Register| #![auto] reg.valid() && reg@.gpr == 0
            && reg@.width == width && !reg@.high_byte
    }

    pub open spec fn values(cpu: Cpu) -> Seq<u64> {
        cpu.gpr.map(|i: int, value: int| value as u64)
    }

    pub open spec fn memory(cpu: Cpu, observed: u64, width: Width) -> Cpu {
        let acc = accumulator(width);
        let before = values(cpu);
        let left = operand::model::read(before, acc);
        let right = observed & operand::model::mask(width);
        let result = integer::model::evaluate(integer::Operation::Cmp,
            left, right, width, cpu.flags);
        let after = if left == right { before }
            else { operand::model::write(before, acc, right) };
        Cpu { gpr: after.map(|i: int, value: u64| value as int),
            flags: result.flags, ..cpu }
    }

    pub open spec fn registers(cpu: Cpu, dst: Register, src: Register) -> Option<Cpu> {
        if !dst.valid() || !src.valid() || dst@.width != src@.width { None }
        else {
            let acc = accumulator(dst@.width);
            let before = values(cpu);
            let left = operand::model::read(before, acc);
            let right = operand::model::read(before, dst);
            let source = operand::model::read(before, src);
            let result = integer::model::evaluate(integer::Operation::Cmp,
                left, right, dst@.width, cpu.flags);
            let after = if left == right { operand::model::write(before, dst, source) }
                else { operand::model::write(before, acc, right) };
            Some(Cpu { gpr: after.map(|i: int, value: u64| value as int),
                flags: result.flags, ..cpu })
        }
    }
    }
}

verus! {

fn accumulator(width: Width) -> (out: Register)
    ensures out.valid(),
        out@.gpr == 0, out@.width == width, !out@.high_byte,
        model::accumulator(width).valid(),
        model::accumulator(width)@.gpr == 0,
        model::accumulator(width)@.width == width,
        !model::accumulator(width)@.high_byte,
{
    let gpr = Gpr::new(0).unwrap();
    let reg = Register::new(gpr, width, false).unwrap();
    proof {
        assert(exists|r: Register| #![auto] r.valid() && r@.gpr == 0
            && r@.width == width && !r@.high_byte);
    }
    reg
}

proof fn values_refine(cpu: State)
    ensures model::values(cpu@) == cpu.gpr@,
{
    assert(model::values(cpu@) =~= cpu.gpr@);
}

/// CPU commit after the caller has completed the memory read-modify-write.
/// AMD APM Vol. 3 rev. 3.39, CMPXCHG, pp. 167–168 (PDF 205–206).
/// The caller owns memory effects, LOCK, faults, and retirement.
/// A successful dword memory comparison does not write EAX; only failure
/// zero-extends the observed dword into RAX.
pub fn memory(mut cpu: State, observed: u64, width: Width) -> (out: State)
    ensures out@ == model::memory(cpu@, observed, width),
        out.rip == cpu.rip,
        out.flags & !0x8d5u64 == cpu.flags & !0x8d5u64,
        forall|i: int| 0 <= i < 16 && i != 0
            ==> #[trigger] out.gpr@[i] == cpu.gpr@[i],
        cpu.gpr[0] & super::operand::model::mask(width)
            == observed & super::operand::model::mask(width)
            ==> out.gpr@ == cpu.gpr@,
        cpu.gpr[0] & super::operand::model::mask(width)
            != observed & super::operand::model::mask(width)
            ==> out.gpr@ == super::operand::model::write(cpu.gpr@,
                model::accumulator(width), observed),
        width == Width::Dword && cpu.gpr[0] & 0xffff_ffffu64 != observed & 0xffff_ffffu64
            ==> out.gpr@[0] == observed & 0xffff_ffffu64,
{
    let ghost before = cpu;
    proof { values_refine(cpu); }
    let acc = accumulator(width);
    let left = acc.read(&cpu.gpr);
    proof {
        let value = before.gpr@[0];
        let mask = super::operand::model::mask(width);
        assert(left == value & mask) by(bit_vector)
            requires left == (value >> 0u32) & mask;
    }
    let right = observed & width.mask();
    let result = integer::evaluate(integer::Operation::Cmp, left, right, width, cpu.flags);
    if left != right {
        acc.write(&mut cpu.gpr, right);
    }
    cpu.flags = result.flags;
    proof {
        assert(cpu@.gpr =~= model::memory(before@, observed, width).gpr);
        let value = observed;
        let mask = super::operand::model::mask(width);
        assert((value & mask) & mask == value & mask) by(bit_vector);
    }
    cpu
}

/// Captures all three operands before either write, including AL/AH aliases.
pub fn registers(mut cpu: State, dst: Register, src: Register) -> (out: Option<State>)
    ensures
        out.is_some() == (dst.valid() && src.valid() && dst@.width == src@.width),
        match out {
            Some(next) => model::registers(cpu@, dst, src) == Some(next@)
                && next.rip == cpu.rip
                && next.flags & !0x8d5u64 == cpu.flags & !0x8d5u64
                && (forall|i: int| 0 <= i < 16 && i != 0 && i != dst@.gpr as int
                    ==> #[trigger] next.gpr@[i] == cpu.gpr@[i])
                && next.gpr@ == (
                    if super::operand::model::read(cpu.gpr@, model::accumulator(dst@.width))
                        == super::operand::model::read(cpu.gpr@, dst) {
                        super::operand::model::write(cpu.gpr@, dst,
                            super::operand::model::read(cpu.gpr@, src))
                    } else {
                        super::operand::model::write(cpu.gpr@, model::accumulator(dst@.width),
                            super::operand::model::read(cpu.gpr@, dst))
                    }),
            None => model::registers(cpu@, dst, src).is_none(),
        },
{
    if !dst.is_valid() || !src.is_valid() || dst.width() != src.width() {
        return None;
    }
    let ghost before = cpu;
    proof { values_refine(cpu); }
    let width = dst.width();
    let acc = accumulator(width);
    let left = acc.read(&cpu.gpr);
    let right = dst.read(&cpu.gpr);
    let source = src.read(&cpu.gpr);
    let result = integer::evaluate(integer::Operation::Cmp, left, right, width, cpu.flags);
    if left == right {
        dst.write(&mut cpu.gpr, source);
    } else {
        acc.write(&mut cpu.gpr, right);
    }
    cpu.flags = result.flags;
    proof {
        assert(cpu@.gpr =~= model::registers(before@, dst, src).unwrap().gpr);
    }
    Some(cpu)
}

}
