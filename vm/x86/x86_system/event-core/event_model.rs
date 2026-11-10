// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use crate::{
    Access, Event, EventOutcome, Injection, MmuResult, PagedDiagnostic, Stage, StepOutcome,
    WordAccess, WordResult, mmu_model, model, word_model,
};
use crate::{EventDiagnostic, Tables, paged_model};
use vstd::prelude::*;

verus! {

pub struct State {
    pub core: paged_model::State,
    pub tables: Tables,
    pub stopped: Option<EventDiagnostic>,
    pub handler_pending: bool,
    pub pending: Option<u8>,
    pub shadow: bool,
    pub halted: bool,
}

pub open spec fn flags_supported(flags: u64) -> bool {
    flags & !0x0021_0ed7u64 == 0 && flags & 2u64 != 0
}
pub open spec fn tables_supported(t: Tables) -> bool {
    t.idt_base % 16 == 0 && t.gdt_base % 8 == 0
        && t.idt_base <= u64::MAX - 239 && t.gdt_base <= u64::MAX - 24
        && t.gdt_limit >= 23
}
pub open spec fn gate_supported(low: u64, high: u64) -> bool {
    low & 0x0000_feff_ffff_0000u64 == 0x0000_8e00_0008_0000u64
        && high <= 4294967295u64
}
pub open spec fn gate_target(low: u64, high: u64) -> int {
    low as int % 65536 + low as int / 281474976710656int * 65536
        + high as int * 4294967296int
}
pub open spec fn live_flags(flags: u64, low: u64) -> u64 {
    (flags & !0x10000u64)
        & (if low / 1099511627776u64 % 2 == 0 { !0x200u64 } else { u64::MAX })
}
pub open spec fn vector(event: Event) -> u8 {
    match event { Event::PageFault(_) => 14, Event::GeneralProtection => 13, Event::External(v) => v }
}
pub open spec fn error(event: Event) -> u64 {
    match event { Event::PageFault(code) => code as u64, _ => 0 }
}
pub open spec fn inject(s: State, vector: u8) -> (State, Injection) {
    if let Some(reason) = s.stopped { (s, Injection::Stopped(reason)) }
    else if vector < 32 { (s, Injection::InvalidVector) }
    else if s.pending is Some { (s, Injection::Busy) }
    else { (State { pending: Some(vector), ..s }, Injection::Queued) }
}
pub open spec fn stopped(s: State, b: Seq<u8>, reason: EventDiagnostic, reads: nat)
    -> (State, Seq<u8>, EventOutcome, nat) {
    (State { stopped: Some(reason), ..s }, b, EventOutcome::Stopped(reason), reads)
}

#[verifier::opaque]
pub open spec fn read_words(s: mmu_model::State, b: Seq<u8>, base: int, start: int,
    i: nat, count: nat, words: Seq<u64>, stage: Stage)
    -> (mmu_model::State, Seq<u8>, Seq<u64>, Option<EventDiagnostic>, nat)
    decreases count - i,
{
    if i >= count { (s, b, words, None, 0) }
    else {
        let address = start + i * 8;
        let one = word_model::access(s, b, base, address, WordAccess::Read, false);
        match one.2 {
            WordResult::Success(v) => {
                let tail = read_words(one.0, one.1, base, start, i + 1, count,
                    words.update(i as int, v), stage);
                (tail.0, tail.1, tail.2, tail.3, one.3 + tail.4)
            },
            r => (one.0, one.1, words,
                Some(EventDiagnostic::Memory { stage, address: address as u64, result: r }), one.3),
        }
    }
}

#[verifier::opaque]
pub open spec fn push_words(s: mmu_model::State, b: Seq<u8>, base: int, stack: int,
    i: nat, words: Seq<u64>)
    -> (mmu_model::State, Seq<u8>, Option<EventDiagnostic>, nat)
    decreases 6 - i,
{
    if i >= 6 { (s, b, None, 0) }
    else {
        let address = stack - 8;
        let one = word_model::access(s, b, base, address, WordAccess::Write(words[i as int]), false);
        match one.2 {
            WordResult::Success(_) => {
                let tail = push_words(one.0, one.1, base, address, i + 1, words);
                (tail.0, tail.1, tail.2, one.3 + tail.3)
            },
            r => (one.0, one.1,
                Some(EventDiagnostic::Memory { stage: Stage::Push, address: address as u64, result: r }), one.3),
        }
    }
}

#[verifier::opaque]
pub open spec fn enter(s: State, b: Seq<u8>, base: int, event: Event)
    -> (State, Seq<u8>, EventOutcome, nat) {
    if let Some(reason) = s.stopped {
        (s, b, EventOutcome::Stopped(reason), 0)
    } else if s.handler_pending {
        stopped(s, b, EventDiagnostic::HandlerFault {
            vector: vector(event), code: error(event) as u8,
        }, 0)
    } else if event is External && vector(event) < 32 {
        stopped(s, b, EventDiagnostic::InterruptWindow, 0)
    } else if !flags_supported(s.core.cpu.flags) || !tables_supported(s.tables)
        || !mmu_model::canonical(s.core.cpu.rip)
        || !mmu_model::canonical(s.core.cpu.gpr[4])
        || s.core.cpu.gpr[4] / 16 * 16 < (if event is External { 40int } else { 48int }) {
        stopped(s, b, EventDiagnostic::Profile, 0)
    } else {
        let offset = vector(event) as int * 16;
        if offset + 15 > s.tables.idt_limit as int
            || s.tables.idt_base as int + offset + 15 > 18446744073709551615int {
            stopped(s, b, EventDiagnostic::Descriptor(Stage::Idt), 0)
        } else {
            let gate = read_words(s.core.mmu, b, base, s.tables.idt_base as int + offset,
                0, 2, seq![0u64, 0u64, 0u64, 0u64, 0u64], Stage::Idt);
            let next = State { core: paged_model::State { mmu: gate.0, ..s.core }, ..s };
            if let Some(reason) = gate.3 { stopped(next, gate.1, reason, gate.4) }
            else if !gate_supported(gate.2[0], gate.2[1])
                || !mmu_model::canonical(gate_target(gate.2[0], gate.2[1])) {
                stopped(next, gate.1, EventDiagnostic::Descriptor(Stage::Idt), gate.4)
            } else {
                let code = read_words(next.core.mmu, gate.1, base, s.tables.gdt_base as int + 8,
                    0, 1, seq![0u64, 0u64, 0u64, 0u64, 0u64], Stage::Code);
                let next = State { core: paged_model::State { mmu: code.0, ..next.core }, ..next };
                let reads = gate.4 + code.4;
                if let Some(reason) = code.3 { stopped(next, code.1, reason, reads) }
                else if code.2[0] != 0x00af9b000000ffffu64 {
                    stopped(next, code.1, EventDiagnostic::Descriptor(Stage::Code), reads)
                } else {
                    let stack = s.core.cpu.gpr[4] / 16 * 16;
                    let words = seq![16u64, s.core.cpu.gpr[4] as u64,
                        s.core.cpu.flags | 0x10000u64, 8u64, s.core.cpu.rip as u64, error(event)];
                    let words = if event is External {
                        seq![0u64, 16u64, s.core.cpu.gpr[4] as u64, s.core.cpu.flags, 8u64, s.core.cpu.rip as u64]
                    } else { words };
                    let pushed = push_words(next.core.mmu, code.1, base, stack,
                        if event is External { 1nat } else { 0nat }, words);
                    let next = State { core: paged_model::State { mmu: pushed.0, ..next.core }, ..next };
                    if let Some(reason) = pushed.2 { stopped(next, pushed.1, reason, reads + pushed.3) }
                    else {
                        let cpu = model::State {
                            gpr: s.core.cpu.gpr.update(4, stack - (if event is External { 40int } else { 48int })),
                            flags: live_flags(s.core.cpu.flags, gate.2[0]),
                            rip: gate_target(gate.2[0], gate.2[1]),
                        };
                        (State { core: paged_model::State { cpu, ..next.core },
                            handler_pending: true, halted: false, shadow: false, ..next },
                            pushed.1, EventOutcome::Delivered(vector(event)), reads + pushed.3)
                    }
                }
            }
        }
    }
}

#[verifier::opaque]
pub open spec fn iret(s: State, b: Seq<u8>, base: int)
    -> (State, Seq<u8>, EventOutcome, nat) {
    if let Some(reason) = s.stopped {
        (s, b, EventOutcome::Stopped(reason), 0)
    } else if !flags_supported(s.core.cpu.flags) || !tables_supported(s.tables)
        || s.core.cpu.gpr[4] > 18446744073709551575int {
        stopped(s, b, EventDiagnostic::Profile, 0)
    } else {
        let popped = read_words(s.core.mmu, b, base, s.core.cpu.gpr[4], 0, 5,
            seq![0u64, 0u64, 0u64, 0u64, 0u64], Stage::Pop);
        let next = State { core: paged_model::State { mmu: popped.0, ..s.core }, ..s };
        if let Some(reason) = popped.3 { stopped(next, popped.1, reason, popped.4) }
        else if popped.2[1] != 8 || popped.2[4] != 16
            || !flags_supported(popped.2[2])
            || !mmu_model::canonical(popped.2[0] as int)
            || !mmu_model::canonical(popped.2[3] as int) {
            stopped(next, popped.1, EventDiagnostic::ReturnImage, popped.4)
        } else {
            let code = read_words(next.core.mmu, popped.1, base, s.tables.gdt_base as int + 8,
                0, 1, seq![0u64, 0u64, 0u64, 0u64, 0u64], Stage::Code);
            let next = State { core: paged_model::State { mmu: code.0, ..next.core }, ..next };
            let reads = popped.4 + code.4;
            if let Some(reason) = code.3 { stopped(next, code.1, reason, reads) }
            else if code.2[0] != 0x00af9b000000ffffu64 {
                stopped(next, code.1, EventDiagnostic::Descriptor(Stage::Code), reads)
            } else {
                let stack = read_words(next.core.mmu, code.1, base, s.tables.gdt_base as int + 16,
                    0, 1, seq![0u64, 0u64, 0u64, 0u64, 0u64], Stage::Stack);
                let next = State { core: paged_model::State { mmu: stack.0, ..next.core }, ..next };
                let reads = reads + stack.4;
                if let Some(reason) = stack.3 { stopped(next, stack.1, reason, reads) }
                else if stack.2[0] != 0x00cf93000000ffffu64 {
                    stopped(next, stack.1, EventDiagnostic::Descriptor(Stage::Stack), reads)
                } else {
                    let cpu = model::State { gpr: s.core.cpu.gpr.update(4, popped.2[3] as int),
                        flags: popped.2[2], rip: popped.2[0] as int };
                    (State { core: paged_model::State { cpu, ..next.core },
                        handler_pending: false, shadow: false, ..next },
                        stack.1, EventOutcome::Advanced, reads)
                }
            }
        }
    }
}

pub open spec fn add_reads(r: (State, Seq<u8>, EventOutcome, nat), reads: nat)
    -> (State, Seq<u8>, EventOutcome, nat) {
    (r.0, r.1, r.2, reads + r.3)
}
pub open spec fn byte_failure(s: State, b: Seq<u8>, base: int, address: int, r: MmuResult)
    -> (State, Seq<u8>, EventOutcome, nat) {
    match r {
        MmuResult::PageFault(code) => enter(s, b, base, Event::PageFault(code)),
        MmuResult::GeneralProtection => enter(s, b, base, Event::GeneralProtection),
        _ => stopped(s, b, EventDiagnostic::Fetch { address: address as u64, byte_result: r }, 0),
    }
}
#[verifier::opaque]
pub open spec fn ordinary(s: State, b: Seq<u8>, base: int)
    -> (State, Seq<u8>, EventOutcome, nat) {
    let active = paged_model::State {
        cpu: model::State { flags: s.core.cpu.flags & !0x10000u64, ..s.core.cpu }, ..s.core
    };
    let one = paged_model::step(active, b, base, false);
    let next = State { core: one.0, ..s };
    if one.2 == StepOutcome::Advanced {
        (State { handler_pending: false, shadow: false, ..next }, one.1, EventOutcome::Advanced, one.3)
    } else {
        let next = State { core: paged_model::State {
            cpu: model::State { flags: s.core.cpu.flags, ..next.core.cpu }, ..next.core
        }, ..next };
        match one.2 {
            StepOutcome::PageFault { code, .. } =>
                add_reads(enter(next, one.1, base, Event::PageFault(code)), one.3),
            StepOutcome::GeneralProtection { .. } =>
                add_reads(enter(next, one.1, base, Event::GeneralProtection), one.3),
            StepOutcome::Diagnostic(d) => stopped(next, one.1, EventDiagnostic::Instruction(d), one.3),
            _ => stopped(next, one.1, EventDiagnostic::Profile, one.3),
        }
    }
}
pub open spec fn invlpg(s: State) -> State {
    State { core: paged_model::State {
        mmu: mmu_model::invalidate(s.core.mmu, s.core.cpu.gpr[7]),
        cpu: model::State { flags: s.core.cpu.flags & !0x10000u64,
            rip: (s.core.cpu.rip + 3) % 18446744073709551616int, ..s.core.cpu },
    }, handler_pending: false, shadow: false, ..s }
}
pub open spec fn unsupported(s: State, b: Seq<u8>, reads: nat)
    -> (State, Seq<u8>, EventOutcome, nat) {
    stopped(s, b, EventDiagnostic::Instruction(PagedDiagnostic::Unsupported), reads)
}
pub open spec fn after_fetch(s: State, mmu: mmu_model::State) -> State {
    State { core: paged_model::State { mmu, ..s.core }, ..s }
}
pub open spec fn control(s: State, op: u8) -> State {
    let flags = s.core.cpu.flags & !0x10000u64;
    State {
        core: paged_model::State { cpu: model::State {
            flags: if op == 0xfa { flags & !0x200u64 }
                else if op == 0xfb { flags | 0x200u64 } else { flags },
            rip: (s.core.cpu.rip + 1) % 18446744073709551616int, ..s.core.cpu
        }, ..s.core },
        shadow: op == 0xfb && s.core.cpu.flags & 0x200u64 == 0,
        halted: op == 0xf4, handler_pending: false, ..s
    }
}

#[verifier::opaque]
pub open spec fn instruction(s: State, b: Seq<u8>, base: int)
    -> (State, Seq<u8>, EventOutcome, nat) {
    if let Some(reason) = s.stopped {
        (s, b, EventOutcome::Stopped(reason), 0)
    } else if !flags_supported(s.core.cpu.flags) {
        stopped(s, b, EventDiagnostic::Profile, 0)
    } else {
        let ip = s.core.cpu.rip;
        let first = mmu_model::access(s.core.mmu, b, base, ip, Access::Fetch, false);
        let next = after_fetch(s, first.0);
        match first.2 {
            MmuResult::Success(a) => {
                if a == 0xfa || a == 0xfb || a == 0xf4 {
                    (control(next, a), first.1, EventOutcome::Advanced, first.3)
                } else if a != 0x0f && (a < 0x48 || a > 0x4f) {
                    unsupported(next, first.1, first.3)
                } else if ip == 18446744073709551615int {
                    stopped(next, first.1, EventDiagnostic::Instruction(PagedDiagnostic::FetchWrap), first.3)
                } else {
                    let second = mmu_model::access(next.core.mmu, first.1, base, ip + 1, Access::Fetch, false);
                    let next = after_fetch(next, second.0);
                    let reads = first.3 + second.3;
                    match second.2 {
                        MmuResult::Success(op) => {
                            if a == 0x48 && op == 0xcf { add_reads(iret(next, second.1, base), reads) }
                            else if a != 0x0f { add_reads(ordinary(next, second.1, base), reads) }
                            else if op != 0x01 { unsupported(next, second.1, reads) }
                            else if ip == 18446744073709551614int {
                                stopped(next, second.1,
                                    EventDiagnostic::Instruction(PagedDiagnostic::FetchWrap), reads)
                            } else {
                                let third = mmu_model::access(next.core.mmu, second.1, base, ip + 2, Access::Fetch, false);
                                let next = after_fetch(next, third.0);
                                let reads = reads + third.3;
                                match third.2 {
                                    MmuResult::Success(c) => {
                                        if c != 0x3f || !mmu_model::canonical(next.core.cpu.gpr[7]) {
                                            unsupported(next, third.1, reads)
                                        } else { (invlpg(next), third.1, EventOutcome::Advanced, reads) }
                                    },
                                    r => add_reads(byte_failure(next, third.1, base, ip + 2, r), reads),
                                }
                            }
                        },
                        r => add_reads(byte_failure(next, second.1, base, ip + 1, r), reads),
                    }
                }
            },
            r => add_reads(byte_failure(next, first.1, base, ip, r), first.3),
        }
    }
}

#[verifier::opaque]
pub open spec fn step(s: State, b: Seq<u8>, base: int)
    -> (State, Seq<u8>, EventOutcome, nat) {
    if let Some(reason) = s.stopped { (s, b, EventOutcome::Stopped(reason), 0) }
    else if !flags_supported(s.core.cpu.flags) {
        stopped(s, b, EventDiagnostic::Profile, 0)
    } else if s.pending is Some && !s.shadow && s.core.cpu.flags & 0x200u64 != 0 {
        let accepted = enter(s, b, base, Event::External(s.pending.unwrap()));
        (if accepted.2 is Delivered { State { pending: None, ..accepted.0 } } else { accepted.0 },
            accepted.1, accepted.2, accepted.3)
    } else if s.halted { (s, b, EventOutcome::Waiting, 0) }
    else { instruction(s, b, base) }
}

#[verifier::opaque]
pub open spec fn run(s: State, b: Seq<u8>, base: int, budget: nat)
    -> (State, Seq<u8>, nat, nat, nat, EventOutcome, nat)
    decreases budget,
{
    if budget == 0 { (s, b, 0, 0, 0, EventOutcome::Budget, 0) }
    else {
        let one = step(s, b, base);
        match one.2 {
            EventOutcome::Stopped(_) | EventOutcome::Waiting => (one.0, one.1, 1, 0, 0, one.2, one.3),
            _ => {
                let tail = run(one.0, one.1, base, (budget - 1) as nat);
                (tail.0, tail.1, 1 + tail.2,
                    (if one.2 == EventOutcome::Advanced { 1nat } else { 0nat }) + tail.3,
                    (if one.2 is Delivered { 1nat } else { 0nat }) + tail.4,
                    tail.5, one.3 + tail.6)
            },
        }
    }
}

}
