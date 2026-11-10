// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![forbid(unsafe_code)]
use vstd::prelude::*;

#[path = "../cpu-core/lib.rs"]
pub mod cpu_core;
pub use cpu_core::{
    Decoded, Diagnostic, Kind, Profile, State, adc64, add_two_words, add64, arithmetic, decoder,
    execute, merge_flags, model,
};
pub mod memory_model;
pub mod shared;
pub mod shared_model;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop { Advanced, Fetch, Read, Write, InvalidWindow, Budget, Unsupported, DebugRequired }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op { Alu(Decoded), Load { reg: u8, base: u8 }, Store { reg: u8, base: u8 }, Unsupported }

impl View for Op {
    type V = memory_model::Op;
    open spec fn view(&self) -> memory_model::Op {
        match *self {
            Op::Alu(op) => memory_model::Op::Alu(op@),
            Op::Load { reg, base } => memory_model::Op::Load(reg as int, base as int),
            Op::Store { reg, base } => memory_model::Op::Store(reg as int, base as int),
            Op::Unsupported => memory_model::Op::Unsupported,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report { pub completed: u64, pub stop: Stop }

pub fn window(base: u64, length: usize) -> (valid: bool)
    ensures valid == memory_model::window(base as int, length as int),
{
    (base as u128) + (length as u128) <= 0x1_0000_0000_0000_0000u128
}

pub fn span(base: u64, length: usize, address: u64, width: usize) -> (offset: Option<usize>)
    ensures
        offset.is_some() == memory_model::span(base as int, length as int, address as int, width as int),
        match offset { Some(i) => i as int == address as int - base as int
            && i as int + width as int <= length as int, None => true },
{
    if !window(base, length) || address < base { return None; }
    let delta = address - base;
    if (delta as u128) + (width as u128) > length as u128 { return None; }
    Some(delta as usize)
}

pub fn decode(rex: u8, opcode: u8, modrm: u8) -> (op: Op)
    ensures op@ == memory_model::decode(rex, opcode, modrm),
        match op {
            Op::Load { reg, base } | Op::Store { reg, base } => reg < 16 && base < 16,
            Op::Alu(alu) => alu.dst < 16 && alu.src < 16 && alu.length == 3
                && alu.profile == Profile::Long64 && (alu.kind == Kind::Add || alu.kind == Kind::Adc),
            _ => true,
        },
{
    proof { reveal(memory_model::decode); }
    let bytes = [rex, opcode, modrm];
    match decoder::decode(&bytes) {
        decoder::Decode::Success(op) => { return Op::Alu(op); },
        _ => {},
    }
    proof {
        assert(((rex & 0xf8u8) == 0x48u8) == (72u8 <= rex && rex <= 79u8)) by(bit_vector);
        assert(((modrm & 0xc0u8) == 0u8) == (modrm / 64u8 == 0u8)) by(bit_vector);
        assert(modrm & 7u8 == modrm % 8u8) by(bit_vector);
    }
    if rex & 0xf8 != 0x48 || (opcode != 0x8b && opcode != 0x89)
        || modrm & 0xc0 != 0 || modrm & 7 == 4 || modrm & 7 == 5 {
        return Op::Unsupported;
    }
    proof {
        assert(((modrm >> 3u8) & 7u8) == (modrm / 8u8) % 8u8) by(bit_vector);
        assert((rex & 1u8) == rex % 2u8) by(bit_vector);
        assert(((rex >> 2u8) & 1u8) == (rex / 4u8) % 2u8) by(bit_vector);
        assert((modrm >> 3u8) & 7u8 <= 7u8 && (rex >> 2u8) & 1u8 <= 1u8
            && modrm & 7u8 <= 7u8 && rex & 1u8 <= 1u8) by(bit_vector);
    }
    let reg = ((modrm >> 3) & 7) + ((rex >> 2) & 1) * 8;
    let base = (modrm & 7) + (rex & 1) * 8;
    if opcode == 0x8b { Op::Load { reg, base } } else { Op::Store { reg, base } }
}

pub fn load(ram: &Vec<u8>, i: usize) -> (value: u64)
    requires i as int + 8 <= ram@.len(), i <= usize::MAX - 7,
    ensures value as int == memory_model::word(ram@, i as int),
{
    let value = (ram[i] as u128)
        + (ram[i + 1] as u128) * 256
        + (ram[i + 2] as u128) * 65536
        + (ram[i + 3] as u128) * 16777216
        + (ram[i + 4] as u128) * 4294967296
        + (ram[i + 5] as u128) * 1099511627776
        + (ram[i + 6] as u128) * 281474976710656
        + (ram[i + 7] as u128) * 72057594037927936;
    value as u64
}

pub fn store(ram: &mut Vec<u8>, i: usize, value: u64)
    requires i as int + 8 <= old(ram)@.len(), i <= usize::MAX - 7,
    ensures final(ram)@ == memory_model::put(old(ram)@, i as int, value as int),
        final(ram)@.len() == old(ram)@.len(),
        forall|j: int| 0 <= j < old(ram)@.len() && !(i as int <= j < i as int + 8)
            ==> #[trigger] final(ram)@[j] == old(ram)@[j],
{
    ram.set(i, (value % 256) as u8);
    ram.set(i + 1, ((value / 256) % 256) as u8);
    ram.set(i + 2, ((value / 65536) % 256) as u8);
    ram.set(i + 3, ((value / 16777216) % 256) as u8);
    ram.set(i + 4, ((value / 4294967296) % 256) as u8);
    ram.set(i + 5, ((value / 1099511627776) % 256) as u8);
    ram.set(i + 6, ((value / 281474976710656) % 256) as u8);
    ram.set(i + 7, ((value / 72057594037927936) % 256) as u8);
}

fn execute_mov(s: &mut State, ram: &mut Vec<u8>, base: u64, op: Op) -> (stop: Stop)
    requires
        match op { Op::Load { reg, base } | Op::Store { reg, base } => reg < 16 && base < 16, _ => false },
        memory_model::window(base as int, old(ram)@.len() as int),
        old(s).flags & 0x10100u64 == 0,
    ensures
        (final(s)@, final(ram)@, stop) == memory_model::mov(old(s)@, old(ram)@, base as int, op@),
        stop != Stop::Advanced ==> final(s)@ == old(s)@ && final(ram)@ == old(ram)@,
        stop != Stop::Budget,
        final(ram)@.len() == old(ram)@.len(),
        final(s).flags == old(s).flags,
{
    proof { reveal(memory_model::mov); }
    let ghost before = s@;
    match op {
        Op::Load { reg, base: address_reg } => {
            let address = s.gpr[address_reg as usize];
            assert(address as int == before.gpr[address_reg as int]);
            let i = match span(base, ram.len(), address, 8) { Some(i) => i, None => { return Stop::Read; } };
            let value = load(ram, i);
            s.gpr[reg as usize] = value;
            s.rip = s.rip.wrapping_add(3);
            proof { assert(s@.gpr =~= before.gpr.update(reg as int, value as int)); }
        },
        Op::Store { reg, base: address_reg } => {
            let address = s.gpr[address_reg as usize];
            assert(address as int == before.gpr[address_reg as int]);
            let value = s.gpr[reg as usize];
            let i = match span(base, ram.len(), address, 8) { Some(i) => i, None => { return Stop::Write; } };
            let ghost ram_before_store = ram@;
            store(ram, i, value);
            assert(ram@[i as int] as int == value as int % 256);
            assert(ram@ =~= memory_model::put(ram_before_store, i as int, value as int));
            assert(s.flags == before.flags);
            s.rip = s.rip.wrapping_add(3);
        },
        _ => { return Stop::Unsupported; },
    }
    Stop::Advanced
}

pub fn step(s: &mut State, ram: &mut Vec<u8>, base: u64) -> (stop: Stop)
    ensures
        (final(s)@, final(ram)@, stop) == memory_model::step(old(s)@, old(ram)@, base as int),
        stop != Stop::Advanced ==> final(s)@ == old(s)@ && final(ram)@ == old(ram)@,
        stop != Stop::Budget,
        final(ram)@.len() == old(ram)@.len(),
{
    proof { reveal(memory_model::step); }
    if !window(base, ram.len()) { return Stop::InvalidWindow; }
    let fetch = match span(base, ram.len(), s.rip, 3) { Some(i) => i, None => { return Stop::Fetch; } };
    let op = decode(ram[fetch], ram[fetch + 1], ram[fetch + 2]);
    assert(op@ == memory_model::decode(ram@[fetch as int], ram@[fetch as int + 1], ram@[fetch as int + 2]));
    if let Op::Unsupported = op { return Stop::Unsupported; }
    if s.flags & 0x10100u64 != 0 { return Stop::DebugRequired; }
    match op {
        Op::Alu(op) => {
            let _status = execute(s, op);
            assert(_status == Diagnostic::Advanced);
            Stop::Advanced
        },
        Op::Load { .. } | Op::Store { .. } => execute_mov(s, ram, base, op),
        Op::Unsupported => Stop::Unsupported,
    }
}

pub fn run(s: &mut State, ram: &mut Vec<u8>, base: u64, budget: u64) -> (report: Report)
    ensures
        (final(s)@, final(ram)@, report.completed as int, report.stop)
            == memory_model::run(old(s)@, old(ram)@, base as int, budget as nat),
        report.completed <= budget,
        report.completed == 0 ==> final(s)@ == old(s)@ && final(ram)@ == old(ram)@,
        budget == 0 ==> report.stop == Stop::Budget,
        report.stop == Stop::Budget ==> report.completed == budget,
        final(ram)@.len() == old(ram)@.len(),
{
    proof {
        reveal_with_fuel(memory_model::run, 2);
        memory_model::run_bounds(s@, ram@, base as int, budget as nat);
    }
    let ghost initial_cpu = s@;
    let ghost initial_ram = ram@;
    let mut completed = 0u64;
    while completed < budget
        invariant
            completed <= budget,
            initial_cpu == old(s)@,
            initial_ram == old(ram)@,
            ram@.len() == initial_ram.len(),
            ({
                let tail = memory_model::run(s@, ram@, base as int, (budget - completed) as nat);
                memory_model::run(initial_cpu, initial_ram, base as int, budget as nat)
                    =~= (tail.0, tail.1, completed as int + tail.2, tail.3)
            }),
            completed == 0 ==> s@ == initial_cpu && ram@ == initial_ram,
        decreases budget - completed,
    {
        let ghost before_cpu = s@;
        let ghost before_ram = ram@;
        let ghost total = memory_model::run(initial_cpu, initial_ram, base as int, budget as nat);
        let ghost tail = memory_model::run(before_cpu, before_ram, base as int, (budget - completed) as nat);
        assert(total =~= (tail.0, tail.1, completed as int + tail.2, tail.3));
        proof { reveal_with_fuel(memory_model::run, 2); }
        let ghost one = memory_model::step(before_cpu, before_ram, base as int);
        let ghost next_tail = memory_model::run(one.0, one.1, base as int, (budget - completed - 1) as nat);
        assert(tail =~= if one.2 == Stop::Advanced {
            (next_tail.0, next_tail.1, 1 + next_tail.2, next_tail.3)
        } else { (one.0, one.1, 0int, one.2) });
        assert(tail.2 == if one.2 == Stop::Advanced { 1 + next_tail.2 } else { 0int });
        assert(tail.3 == if one.2 == Stop::Advanced { next_tail.3 } else { one.2 });
        assert(tail.0 == if one.2 == Stop::Advanced { next_tail.0 } else { one.0 });
        assert(tail.1 == if one.2 == Stop::Advanced { next_tail.1 } else { one.1 });
        let stop = step(s, ram, base);
        assert(one =~= (s@, ram@, stop));
        match stop {
            Stop::Advanced => {},
            _ => {
                assert(total =~= (s@, ram@, completed as int, stop));
                return Report { completed, stop };
            },
        }
        completed = completed + 1;
        proof {
            reveal_with_fuel(memory_model::run, 2);
            let next = memory_model::run(s@, ram@, base as int, (budget - completed) as nat);
            assert(total =~= (next.0, next.1, completed as int + next.2, next.3));
        }
    }
    Report { completed, stop: Stop::Budget }
}

}
