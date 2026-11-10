// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use crate::Stop;
use crate::model;
use vstd::prelude::*;

verus! {

pub enum Op { Alu(model::Decoded), Load(int, int), Store(int, int), Unsupported }

pub open spec fn window(base: int, length: int) -> bool {
    0 <= base < 18446744073709551616int && 0 <= length
        && base + length <= 18446744073709551616int
}

pub open spec fn span(base: int, length: int, address: int, width: int) -> bool {
    window(base, length) && 0 <= width && base <= address && address + width <= base + length
}

#[verifier::opaque]
pub open spec fn decode(rex: u8, opcode: u8, modrm: u8) -> Op {
    match model::decode(seq![rex, opcode, modrm]) {
        model::Decode::Success(op) => Op::Alu(op),
        _ => {
            let r = rex as int;
            let m = modrm as int;
            if 72 <= r <= 79 && (opcode == 0x8bu8 || opcode == 0x89u8)
                && m / 64 == 0 && m % 8 != 4 && m % 8 != 5 {
                let reg = (m / 8) % 8 + ((r / 4) % 2) * 8;
                let base = m % 8 + (r % 2) * 8;
                if opcode == 0x8bu8 { Op::Load(reg, base) } else { Op::Store(reg, base) }
            } else { Op::Unsupported }
        },
    }
}

pub open spec fn word(b: Seq<u8>, i: int) -> int {
    b[i] as int + b[i+1] as int * 256 + b[i+2] as int * 65536
        + b[i+3] as int * 16777216 + b[i+4] as int * 4294967296
        + b[i+5] as int * 1099511627776 + b[i+6] as int * 281474976710656
        + b[i+7] as int * 72057594037927936
}

pub open spec fn put(b: Seq<u8>, i: int, v: int) -> Seq<u8> {
    b.update(i, (v % 256) as u8)
        .update(i+1, ((v / 256) % 256) as u8)
        .update(i+2, ((v / 65536) % 256) as u8)
        .update(i+3, ((v / 16777216) % 256) as u8)
        .update(i+4, ((v / 4294967296) % 256) as u8)
        .update(i+5, ((v / 1099511627776) % 256) as u8)
        .update(i+6, ((v / 281474976710656) % 256) as u8)
        .update(i+7, ((v / 72057594037927936) % 256) as u8)
}

#[verifier::opaque]
pub open spec fn mov(s: model::State, b: Seq<u8>, base: int, op: Op) -> (model::State, Seq<u8>, Stop) {
    match op {
        Op::Load(reg, address_reg) => {
            let address = s.gpr[address_reg];
            if !span(base, b.len() as int, address, 8) { (s, b, Stop::Read) }
            else { (model::State {
                gpr: s.gpr.update(reg, word(b, address - base)),
                flags: s.flags, rip: (s.rip + 3) % 18446744073709551616int,
            }, b, Stop::Advanced) }
        },
        Op::Store(reg, address_reg) => {
            let address = s.gpr[address_reg];
            if !span(base, b.len() as int, address, 8) { (s, b, Stop::Write) }
            else { (model::State { rip: (s.rip + 3) % 18446744073709551616int, ..s },
                put(b, address - base, s.gpr[reg]), Stop::Advanced) }
        },
        _ => (s, b, Stop::Unsupported),
    }
}

#[verifier::opaque]
pub open spec fn step(s: model::State, b: Seq<u8>, base: int) -> (model::State, Seq<u8>, Stop) {
    if !window(base, b.len() as int) { (s, b, Stop::InvalidWindow) }
    else if !span(base, b.len() as int, s.rip, 3) { (s, b, Stop::Fetch) }
    else {
        let i = s.rip - base;
        let op = decode(b[i], b[i+1], b[i+2]);
        if op is Unsupported { (s, b, Stop::Unsupported) }
        else if s.flags & 0x10100u64 != 0 { (s, b, Stop::DebugRequired) }
        else {
            match op {
                Op::Alu(op) => (model::execute(s, op).0, b, Stop::Advanced),
                Op::Load(_, _) | Op::Store(_, _) => mov(s, b, base, op),
                Op::Unsupported => (s, b, Stop::Unsupported),
            }
        }
    }
}

#[verifier::opaque]
pub open spec fn run(s: model::State, b: Seq<u8>, base: int, budget: nat)
    -> (model::State, Seq<u8>, int, Stop)
    decreases budget,
{
    if budget == 0 { (s, b, 0, Stop::Budget) }
    else {
        let one = step(s, b, base);
        if one.2 != Stop::Advanced { (one.0, one.1, 0, one.2) }
        else {
            let tail = run(one.0, one.1, base, (budget - 1) as nat);
            (tail.0, tail.1, 1 + tail.2, tail.3)
        }
    }
}

pub proof fn step_frame(s: model::State, b: Seq<u8>, base: int)
    ensures step(s, b, base).1.len() == b.len(),
        step(s, b, base).2 != Stop::Budget,
        step(s, b, base).2 != Stop::Advanced ==> step(s, b, base).0 == s && step(s, b, base).1 == b,
{
    reveal(step);
    reveal(mov);
}

pub proof fn run_bounds(s: model::State, b: Seq<u8>, base: int, budget: nat)
    ensures
        0 <= run(s, b, base, budget).2 <= budget,
        run(s, b, base, budget).2 == 0 ==> run(s, b, base, budget).0 == s && run(s, b, base, budget).1 == b,
        run(s, b, base, budget).3 == Stop::Budget ==> run(s, b, base, budget).2 == budget,
        run(s, b, base, budget).1.len() == b.len(),
    decreases budget,
{
    reveal(run);
    if budget > 0 {
        let one = step(s, b, base);
        step_frame(s, b, base);
        if one.2 == Stop::Advanced { run_bounds(one.0, one.1, base, (budget - 1) as nat); }
    }
}

}
