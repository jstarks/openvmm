// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![forbid(unsafe_code)]
#![expect(missing_docs)]
use vstd::prelude::*;

#[path = "../paged-core/lib.rs"]
pub mod paged_core;
pub use mmu_core::{Report, update_invalidate_access};
pub use paged_core::*;
pub mod event_model;
pub mod shared;
pub mod shared_model;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tables {
    pub idt_base: u64, pub idt_limit: u16, pub gdt_base: u64, pub gdt_limit: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event { PageFault(u8), GeneralProtection, InvalidOpcode, Breakpoint, External(u8) }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Injection { Queued, Busy, InvalidVector, Stopped(EventDiagnostic) }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage { Idt, Code, Stack, Push, Pop }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventDiagnostic {
    Profile, Descriptor(Stage), ReturnImage,
    Memory { stage: Stage, address: u64, result: WordResult },
    Fetch { address: u64, byte_result: MmuResult },
    Instruction(PagedDiagnostic),
    HandlerFault { vector: u8, code: u8 },
    InterruptWindow,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventOutcome { Advanced, Delivered(u8), Stopped(EventDiagnostic), Waiting, Budget }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventReport { pub outcome: EventOutcome, pub table_reads: u16 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventRun {
    pub steps: u64, pub retired: u64, pub delivered: u64,
    pub outcome: EventOutcome, pub table_reads: u128,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventMachine {
    pub core: Machine, pub tables: Tables, pub stopped: Option<EventDiagnostic>,
    pub handler_pending: bool,
    pub pending: Option<u8>, pub shadow: bool, pub halted: bool,
}
impl View for EventMachine {
    type V = event_model::State;
    open spec fn view(&self) -> event_model::State {
        event_model::State { core: self.core@, tables: self.tables, stopped: self.stopped,
            handler_pending: self.handler_pending, pending: self.pending,
            shadow: self.shadow, halted: self.halted }
    }
}
impl EventMachine {
    pub open spec fn invariant(&self) -> bool { self.core.invariant() }
    fn stop(&mut self, reason: EventDiagnostic) -> (out: EventOutcome)
        requires old(self).invariant(),
        ensures final(self)@ == (event_model::State { stopped: Some(reason), ..old(self)@ }),
            out == EventOutcome::Stopped(reason), final(self).invariant(),
    {
        self.stopped = Some(reason);
        EventOutcome::Stopped(reason)
    }
    pub fn inject(&mut self, vector: u8) -> (r: Injection)
        ensures (final(self)@, r) == event_model::inject(old(self)@, vector),
            final(self).invariant() == old(self).invariant(),
    {
        if let Some(reason) = self.stopped { return Injection::Stopped(reason); }
        if vector < 32 { return Injection::InvalidVector; }
        if self.pending.is_some() { return Injection::Busy; }
        self.pending = Some(vector);
        Injection::Queued
    }
}

fn flags_supported(flags: u64) -> (v: bool)
    ensures v == event_model::flags_supported(flags),
{ flags & !0x0021_0ed7u64 == 0 && flags & 2 != 0 }
fn has_error_code(event: Event) -> (v: bool)
    ensures v == event_model::has_error_code(event),
{ matches!(event, Event::PageFault(_) | Event::GeneralProtection) }
fn tables_supported(t: Tables) -> (v: bool)
    ensures v == event_model::tables_supported(t),
{
    t.idt_base % 16 == 0 && t.gdt_base % 8 == 0
        && t.idt_base <= u64::MAX - 239 && t.gdt_base <= u64::MAX - 24
        && t.gdt_limit >= 23
}
fn canonical(va: u64) -> (v: bool)
    ensures v == mmu_model::canonical(va as int),
{ va < 0x8000_0000_0000 || va >= 0xffff_8000_0000_0000 }
fn gate_supported(low: u64, high: u64) -> (v: bool)
    ensures v == event_model::gate_supported(low, high),
{ low & 0x0000_9eff_ffff_0000u64 == 0x0000_8e00_0008_0000u64 && high <= 4294967295 }
fn gate_target(low: u64, high: u64) -> (v: u64)
    requires high <= 4294967295,
    ensures v as int == event_model::gate_target(low, high),
{
    low % 65536 + (low / 281474976710656) * 65536 + high * 4294967296
}
fn live_flags(flags: u64, low: u64) -> (v: u64)
    ensures v == event_model::live_flags(flags, low),
{
    (flags & !0x10000u64)
        & (if low / 1099511627776u64 % 2 == 0 { !0x200u64 } else { u64::MAX })
}
fn zeros() -> (v: [u64; 5])
    ensures v@ == seq![0u64, 0u64, 0u64, 0u64, 0u64],
{
    let v = [0u64; 5];
    assert(v@ =~= seq![0u64, 0u64, 0u64, 0u64, 0u64]);
    v
}

struct ReadReport { words: [u64; 5], stop: Option<EventDiagnostic>, reads: u16 }
fn read_words(mmu: &mut Mmu, ram: &mut Vec<u8>, base: u64, start: u64,
    i: u8, count: u8, mut words: [u64; 5], stage: Stage) -> (r: ReadReport)
    requires old(mmu).invariant(), i <= count <= 5,
        start as int + 8 * count as int <= 18446744073709551616int,
    ensures
        (final(mmu)@, final(ram)@, r.words@, r.stop, r.reads as nat)
            == event_model::read_words(old(mmu)@, old(ram)@, base as int, start as int,
                i as nat, count as nat, words@, stage),
        final(mmu).invariant(), final(ram)@.len() == old(ram)@.len(),
        r.reads <= 4 * (count - i) as u16,
    decreases count - i,
{
    proof { reveal(event_model::read_words); }
    if i >= count { return ReadReport { words, stop: None, reads: 0 }; }
    let address = start + i as u64 * 8;
    let one = mmu.access_word(ram, base, address, WordAccess::Read, false);
    match one.result {
        WordResult::Success(value) => {
            let ghost before = words@;
            words[i as usize] = value;
            assert(words@ =~= before.update(i as int, value));
            let tail = read_words(mmu, ram, base, start, i + 1, count, words, stage);
            ReadReport { words: tail.words, stop: tail.stop, reads: one.table_reads as u16 + tail.reads }
        },
        result => ReadReport { words,
            stop: Some(EventDiagnostic::Memory { stage, address, result }), reads: one.table_reads as u16 },
    }
}

fn push_words(mmu: &mut Mmu, ram: &mut Vec<u8>, base: u64, stack: u64,
    i: u8, words: [u64; 6]) -> (r: (Option<EventDiagnostic>, u16))
    requires old(mmu).invariant(), i <= 6, stack >= 8 * (6 - i) as u64,
    ensures
        (final(mmu)@, final(ram)@, r.0, r.1 as nat)
            == event_model::push_words(old(mmu)@, old(ram)@, base as int, stack as int, i as nat, words@),
        final(mmu).invariant(), final(ram)@.len() == old(ram)@.len(), r.1 <= 4 * (6 - i) as u16,
    decreases 6 - i,
{
    proof { reveal(event_model::push_words); }
    if i >= 6 { return (None, 0); }
    let address = stack - 8;
    let one = mmu.access_word(ram, base, address, WordAccess::Write(words[i as usize]), false);
    match one.result {
        WordResult::Success(_) => {
            let tail = push_words(mmu, ram, base, address, i + 1, words);
            (tail.0, one.table_reads as u16 + tail.1)
        },
        result => (Some(EventDiagnostic::Memory { stage: Stage::Push, address, result }),
            one.table_reads as u16),
    }
}

impl EventMachine {
    pub fn enter(&mut self, ram: &mut Vec<u8>, base: u64, event: Event) -> (r: EventReport)
        requires old(self).invariant(),
        ensures
            (final(self)@, final(ram)@, r.outcome, r.table_reads as nat)
                == event_model::enter(old(self)@, old(ram)@, base as int, event),
            final(self).invariant(), final(ram)@.len() == old(ram)@.len(), r.table_reads <= 36,
            r.outcome != EventOutcome::Budget,
    {
        proof { reveal(event_model::enter); }
        if let Some(reason) = self.stopped {
            return EventReport { outcome: EventOutcome::Stopped(reason), table_reads: 0 };
        }
        if self.handler_pending {
            let (vector, code) = match event {
                Event::PageFault(code) => (14, code), Event::GeneralProtection => (13, 0),
                Event::InvalidOpcode => (6, 0),
                Event::Breakpoint => (3, 0),
                Event::External(v) => (v, 0),
            };
            return EventReport { outcome: self.stop(EventDiagnostic::HandlerFault { vector, code }), table_reads: 0 };
        }
        let old_rsp = self.core.cpu.gpr[4];
        let stack = old_rsp / 16 * 16;
        let external = matches!(event, Event::External(_));
        if external && match event { Event::External(v) => v < 32, _ => false } {
            return EventReport { outcome: self.stop(EventDiagnostic::InterruptWindow), table_reads: 0 };
        }
        let count = if has_error_code(event) { 6u64 } else { 5u64 };
        if !flags_supported(self.core.cpu.flags) || !tables_supported(self.tables)
            || !canonical(self.core.cpu.rip) || !canonical(old_rsp) || stack < 8 * count {
            return EventReport { outcome: self.stop(EventDiagnostic::Profile), table_reads: 0 };
        }
        let (vector, error): (u8, u64) = match event {
            Event::PageFault(code) => (14, code as u64), Event::GeneralProtection => (13, 0),
            Event::InvalidOpcode => (6, 0),
            Event::Breakpoint => (3, 0),
            Event::External(v) => (v, 0),
        };
        let offset = vector as u64 * 16;
        if offset + 15 > self.tables.idt_limit as u64
            || self.tables.idt_base > u64::MAX - offset - 15 {
            return EventReport { outcome: self.stop(EventDiagnostic::Descriptor(Stage::Idt)), table_reads: 0 };
        }
        let gate = read_words(&mut self.core.mmu, ram, base, self.tables.idt_base + offset,
            0, 2, zeros(), Stage::Idt);
        if let Some(reason) = gate.stop {
            return EventReport { outcome: self.stop(reason), table_reads: gate.reads };
        }
        let low = gate.words[0];
        let high = gate.words[1];
        if !gate_supported(low, high) {
            return EventReport { outcome: self.stop(EventDiagnostic::Descriptor(Stage::Idt)), table_reads: gate.reads };
        }
        let target = gate_target(low, high);
        if !canonical(target) {
            return EventReport { outcome: self.stop(EventDiagnostic::Descriptor(Stage::Idt)), table_reads: gate.reads };
        }
        let code = read_words(&mut self.core.mmu, ram, base, self.tables.gdt_base + 8,
            0, 1, zeros(), Stage::Code);
        let reads = gate.reads + code.reads;
        if let Some(reason) = code.stop {
            return EventReport { outcome: self.stop(reason), table_reads: reads };
        }
        if code.words[0] != 0x00af9b000000ffffu64 {
            return EventReport { outcome: self.stop(EventDiagnostic::Descriptor(Stage::Code)), table_reads: reads };
        }
        let words = [16u64, old_rsp, self.core.cpu.flags | 0x10000u64, 8u64, self.core.cpu.rip, error];
        assert(words@ =~= seq![16u64, old_rsp, self.core.cpu.flags | 0x10000u64,
            8u64, self.core.cpu.rip, error]);
        let words = if external || matches!(event,Event::Breakpoint) {
            [0u64, 16u64, old_rsp, self.core.cpu.flags, 8u64, self.core.cpu.rip]
        } else { words };
        if external || matches!(event,Event::Breakpoint) {
            assert(words@ =~= seq![0u64, 16u64, old_rsp, self.core.cpu.flags, 8u64, self.core.cpu.rip]);
        }
        let words = if matches!(event, Event::InvalidOpcode) {
            let v = [0u64, 16u64, old_rsp, self.core.cpu.flags | 0x10000u64, 8u64, self.core.cpu.rip];
            assert(v@ =~= seq![0u64, 16u64, old_rsp, self.core.cpu.flags | 0x10000u64, 8u64, self.core.cpu.rip]);
            v
        } else { words };
        let start = if has_error_code(event) { 0u8 } else { 1u8 };
        let pushed = push_words(&mut self.core.mmu, ram, base, stack, start, words);
        let reads = reads + pushed.1;
        if let Some(reason) = pushed.0 {
            return EventReport { outcome: self.stop(reason), table_reads: reads };
        }
        let ghost before = self.core.cpu@;
        self.core.cpu.gpr[4] = stack - 8 * count;
        assert(self.core.cpu@.gpr =~= before.gpr.update(4, stack as int - 8 * count as int));
        self.core.cpu.flags = live_flags(self.core.cpu.flags, low);
        self.core.cpu.rip = target;
        self.handler_pending = true;
        self.halted = false;
        self.shadow = false;
        EventReport { outcome: EventOutcome::Delivered(vector), table_reads: reads }
    }

    pub fn iret(&mut self, ram: &mut Vec<u8>, base: u64) -> (r: EventReport)
        requires old(self).invariant(),
        ensures
            (final(self)@, final(ram)@, r.outcome, r.table_reads as nat)
                == event_model::iret(old(self)@, old(ram)@, base as int),
            final(self).invariant(), final(ram)@.len() == old(ram)@.len(), r.table_reads <= 28,
            r.outcome != EventOutcome::Budget,
    {
        proof { reveal(event_model::iret); }
        if let Some(reason) = self.stopped {
            return EventReport { outcome: EventOutcome::Stopped(reason), table_reads: 0 };
        }
        let stack = self.core.cpu.gpr[4];
        if !flags_supported(self.core.cpu.flags) || !tables_supported(self.tables)
            || stack > u64::MAX - 40 {
            return EventReport { outcome: self.stop(EventDiagnostic::Profile), table_reads: 0 };
        }
        let popped = read_words(&mut self.core.mmu, ram, base, stack, 0, 5, zeros(), Stage::Pop);
        if let Some(reason) = popped.stop {
            return EventReport { outcome: self.stop(reason), table_reads: popped.reads };
        }
        if popped.words[1] != 8 || popped.words[4] != 16
            || !flags_supported(popped.words[2]) || !canonical(popped.words[0])
            || !canonical(popped.words[3]) {
            return EventReport { outcome: self.stop(EventDiagnostic::ReturnImage), table_reads: popped.reads };
        }
        let code = read_words(&mut self.core.mmu, ram, base, self.tables.gdt_base + 8,
            0, 1, zeros(), Stage::Code);
        let reads = popped.reads + code.reads;
        if let Some(reason) = code.stop {
            return EventReport { outcome: self.stop(reason), table_reads: reads };
        }
        if code.words[0] != 0x00af9b000000ffffu64 {
            return EventReport { outcome: self.stop(EventDiagnostic::Descriptor(Stage::Code)), table_reads: reads };
        }
        let descriptor = read_words(&mut self.core.mmu, ram, base, self.tables.gdt_base + 16,
            0, 1, zeros(), Stage::Stack);
        let reads = reads + descriptor.reads;
        if let Some(reason) = descriptor.stop {
            return EventReport { outcome: self.stop(reason), table_reads: reads };
        }
        if descriptor.words[0] != 0x00cf93000000ffffu64 {
            return EventReport { outcome: self.stop(EventDiagnostic::Descriptor(Stage::Stack)), table_reads: reads };
        }
        let ghost before = self.core.cpu@;
        self.core.cpu.gpr[4] = popped.words[3];
        assert(self.core.cpu@.gpr =~= before.gpr.update(4, popped.words[3] as int));
        self.core.cpu.flags = popped.words[2];
        self.core.cpu.rip = popped.words[0];
        self.handler_pending = false;
        self.shadow = false;
        EventReport { outcome: EventOutcome::Advanced, table_reads: reads }
    }

    fn byte_failure(&mut self, ram: &mut Vec<u8>, base: u64, address: u64, result: MmuResult)
        -> (r: EventReport)
        requires old(self).invariant(),
        ensures
            (final(self)@, final(ram)@, r.outcome, r.table_reads as nat)
                == event_model::byte_failure(old(self)@, old(ram)@, base as int, address as int, result),
            final(self).invariant(), final(ram)@.len() == old(ram)@.len(), r.table_reads <= 36,
            r.outcome != EventOutcome::Budget,
    {
        match result {
            MmuResult::PageFault(code) => self.enter(ram, base, Event::PageFault(code)),
            MmuResult::GeneralProtection => self.enter(ram, base, Event::GeneralProtection),
            _ => EventReport { outcome: self.stop(EventDiagnostic::Fetch { address, byte_result: result }), table_reads: 0 },
        }
    }

    fn ordinary(&mut self, ram: &mut Vec<u8>, base: u64) -> (r: EventReport)
        requires old(self).invariant(),
        ensures
            (final(self)@, final(ram)@, r.outcome, r.table_reads as nat)
                == event_model::ordinary(old(self)@, old(ram)@, base as int),
            final(self).invariant(), final(ram)@.len() == old(ram)@.len(), r.table_reads <= 52,
            r.outcome != EventOutcome::Budget,
    {
        proof { reveal(event_model::ordinary); }
        let flags = self.core.cpu.flags;
        self.core.cpu.flags = flags & !0x10000u64;
        let one = self.core.step(ram, base, false);
        match one.outcome {
            StepOutcome::Advanced => {
                self.handler_pending = false;
                self.shadow = false;
                EventReport { outcome: EventOutcome::Advanced, table_reads: one.table_reads as u16 }
            },
            _ => {
                self.core.cpu.flags = flags;
                let report = match one.outcome {
                    StepOutcome::PageFault { code, .. } => self.enter(ram, base, Event::PageFault(code)),
                    StepOutcome::GeneralProtection { .. } => self.enter(ram, base, Event::GeneralProtection),
                    StepOutcome::Diagnostic(d) => EventReport {
                        outcome: self.stop(EventDiagnostic::Instruction(d)), table_reads: 0,
                    },
                    _ => EventReport { outcome: self.stop(EventDiagnostic::Profile), table_reads: 0 },
                };
                EventReport { outcome: report.outcome, table_reads: one.table_reads as u16 + report.table_reads }
            },
        }
    }

    fn retire_invlpg(&mut self)
        requires old(self).invariant(),
        ensures final(self)@ == event_model::invlpg(old(self)@), final(self).invariant(),
    {
        self.core.mmu.invalidate(self.core.cpu.gpr[7]);
        self.core.cpu.flags &= !0x10000u64;
        self.core.cpu.rip = self.core.cpu.rip.wrapping_add(3);
        self.handler_pending = false;
        self.shadow = false;
    }

    fn control(&mut self, op: u8)
        requires op == 0xfa || op == 0xfb || op == 0xf4, old(self).invariant(),
        ensures final(self)@ == event_model::control(old(self)@, op), final(self).invariant(),
    {
        let flags = self.core.cpu.flags;
        self.core.cpu.flags = flags & !0x10000u64;
        if op == 0xfa { self.core.cpu.flags &= !0x200u64; }
        else if op == 0xfb { self.core.cpu.flags |= 0x200u64; }
        self.core.cpu.rip = self.core.cpu.rip.wrapping_add(1);
        self.shadow = op == 0xfb && flags & 0x200u64 == 0;
        self.halted = op == 0xf4;
        self.handler_pending = false;
    }

    fn instruction(&mut self, ram: &mut Vec<u8>, base: u64) -> (r: EventReport)
        requires old(self).invariant(),
        ensures
            (final(self)@, final(ram)@, r.outcome, r.table_reads as nat)
                == event_model::instruction(old(self)@, old(ram)@, base as int),
            final(self).invariant(), final(ram)@.len() == old(ram)@.len(),
            r.table_reads <= 64, r.outcome != EventOutcome::Budget,
    {
        proof { reveal(event_model::instruction); }
        if let Some(reason) = self.stopped {
            return EventReport { outcome: EventOutcome::Stopped(reason), table_reads: 0 };
        }
        if !flags_supported(self.core.cpu.flags) {
            return EventReport { outcome: self.stop(EventDiagnostic::Profile), table_reads: 0 };
        }
        let ip = self.core.cpu.rip;
        let first = self.core.mmu.access(ram, base, ip, Access::Fetch, false);
        let a = match first.result {
            MmuResult::Success(v) => v,
            r => {
                let report = self.byte_failure(ram, base, ip, r);
                return EventReport { outcome: report.outcome, table_reads: first.table_reads as u16 + report.table_reads };
            },
        };
        let reads = first.table_reads as u16;
        if a == 0xfa || a == 0xfb || a == 0xf4 {
            self.control(a);
            return EventReport { outcome: EventOutcome::Advanced, table_reads: reads };
        }
        if a != 0x0f && (a < 0x48 || a > 0x4f) {
            return EventReport { outcome: self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)), table_reads: reads };
        }
        if ip == u64::MAX {
            return EventReport { outcome: self.stop(EventDiagnostic::Instruction(PagedDiagnostic::FetchWrap)), table_reads: reads };
        }
        let second = self.core.mmu.access(ram, base, ip + 1, Access::Fetch, false);
        let reads = reads + second.table_reads as u16;
        let op = match second.result {
            MmuResult::Success(v) => v,
            r => {
                let report = self.byte_failure(ram, base, ip + 1, r);
                return EventReport { outcome: report.outcome, table_reads: reads + report.table_reads };
            },
        };
        if a == 0x48 && op == 0xcf {
            let report = self.iret(ram, base);
            return EventReport { outcome: report.outcome, table_reads: reads + report.table_reads };
        }
        if a != 0x0f {
            let report = self.ordinary(ram, base);
            return EventReport { outcome: report.outcome, table_reads: reads + report.table_reads };
        }
        if op != 0x01 {
            return EventReport { outcome: self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)), table_reads: reads };
        }
        if ip == u64::MAX - 1 {
            return EventReport { outcome: self.stop(EventDiagnostic::Instruction(PagedDiagnostic::FetchWrap)), table_reads: reads };
        }
        let third = self.core.mmu.access(ram, base, ip + 2, Access::Fetch, false);
        let reads = reads + third.table_reads as u16;
        let c = match third.result {
            MmuResult::Success(v) => v,
            r => {
                let report = self.byte_failure(ram, base, ip + 2, r);
                return EventReport { outcome: report.outcome, table_reads: reads + report.table_reads };
            },
        };
        if c != 0x3f || !canonical(self.core.cpu.gpr[7]) {
            return EventReport { outcome: self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)), table_reads: reads };
        }
        self.retire_invlpg();
        EventReport { outcome: EventOutcome::Advanced, table_reads: reads }
    }

    pub fn step(&mut self, ram: &mut Vec<u8>, base: u64) -> (r: EventReport)
        requires old(self).invariant(),
        ensures
            (final(self)@, final(ram)@, r.outcome, r.table_reads as nat)
                == event_model::step(old(self)@, old(ram)@, base as int),
            final(self).invariant(), final(ram)@.len() == old(ram)@.len(),
            r.table_reads <= 64, r.outcome != EventOutcome::Budget,
    {
        proof { reveal(event_model::step); }
        if let Some(reason) = self.stopped {
            return EventReport { outcome: EventOutcome::Stopped(reason), table_reads: 0 };
        }
        if !flags_supported(self.core.cpu.flags) {
            return EventReport { outcome: self.stop(EventDiagnostic::Profile), table_reads: 0 };
        }
        if let Some(vector) = self.pending {
            if !self.shadow && self.core.cpu.flags & 0x200u64 != 0 {
                let report = self.enter(ram, base, Event::External(vector));
                if let EventOutcome::Delivered(_) = report.outcome { self.pending = None; }
                return report;
            }
        }
        if self.halted {
            return EventReport { outcome: EventOutcome::Waiting, table_reads: 0 };
        }
        self.instruction(ram, base)
    }

    pub fn run(&mut self, ram: &mut Vec<u8>, base: u64, budget: u64) -> (r: EventRun)
        requires old(self).invariant(),
        ensures
            (final(self)@, final(ram)@, r.steps as nat, r.retired as nat,
                r.delivered as nat, r.outcome, r.table_reads as nat)
                == event_model::run(old(self)@, old(ram)@, base as int, budget as nat),
            final(self).invariant(), final(ram)@.len() == old(ram)@.len(),
            r.steps <= budget, r.retired as u128 + r.delivered as u128 <= r.steps as u128,
            r.table_reads <= 64u128 * budget as u128,
            r.outcome == EventOutcome::Budget ==> r.steps == budget,
            budget == 0 ==> final(self)@ == old(self)@ && final(ram)@ == old(ram)@,
    {
        let ghost initial = self@;
        let ghost initial_ram = ram@;
        let mut steps = 0u64;
        let mut retired = 0u64;
        let mut delivered = 0u64;
        let mut reads = 0u128;
        proof { reveal_with_fuel(event_model::run, 2); }
        while steps < budget
            invariant
                self.invariant(), ram@.len() == initial_ram.len(),
                initial == old(self)@, initial_ram == old(ram)@,
                steps <= budget, retired as u128 + delivered as u128 <= steps as u128,
                reads <= 64u128 * steps as u128,
                ({
                    let tail = event_model::run(self@, ram@, base as int, (budget - steps) as nat);
                    event_model::run(initial, initial_ram, base as int, budget as nat)
                        =~= (tail.0, tail.1, steps as nat + tail.2,
                            retired as nat + tail.3, delivered as nat + tail.4, tail.5, reads as nat + tail.6)
                }),
            decreases budget - steps,
        {
            let ghost total = event_model::run(initial, initial_ram, base as int, budget as nat);
            let ghost remaining = event_model::run(self@, ram@, base as int, (budget - steps) as nat);
            assert(total =~= (remaining.0, remaining.1, steps as nat + remaining.2,
                retired as nat + remaining.3, delivered as nat + remaining.4, remaining.5,
                reads as nat + remaining.6));
            let ghost one = event_model::step(self@, ram@, base as int);
            let ghost next = event_model::run(one.0, one.1, base as int, (budget - steps - 1) as nat);
            proof { reveal_with_fuel(event_model::run, 2); }
            assert(remaining =~= match one.2 {
                EventOutcome::Stopped(_) | EventOutcome::Waiting => (one.0, one.1, 1nat, 0nat, 0nat, one.2, one.3),
                _ => (next.0, next.1, 1nat + next.2,
                    (if one.2 == EventOutcome::Advanced { 1nat } else { 0nat }) + next.3,
                    (if one.2 is Delivered { 1nat } else { 0nat }) + next.4, next.5, one.3 + next.6),
            });
            let report = self.step(ram, base);
            assert(one =~= (self@, ram@, report.outcome, report.table_reads as nat));
            reads = reads + report.table_reads as u128;
            steps = steps + 1;
            match report.outcome {
                EventOutcome::Advanced => { retired = retired + 1; },
                EventOutcome::Delivered(_) => { delivered = delivered + 1; },
                EventOutcome::Stopped(_) | EventOutcome::Waiting => {
                    assert(total =~= (self@, ram@, steps as nat, retired as nat,
                        delivered as nat, report.outcome, reads as nat));
                    return EventRun { steps, retired, delivered, outcome: report.outcome, table_reads: reads };
                },
                EventOutcome::Budget => { assert(false); panic!("step cannot return budget"); },
            }
            proof {
                let tail = event_model::run(self@, ram@, base as int, (budget - steps) as nat);
                assert(next == tail);
                assert(total =~= (tail.0, tail.1, steps as nat + tail.2,
                    retired as nat + tail.3, delivered as nat + tail.4, tail.5, reads as nat + tail.6));
            }
        }
        proof { reveal(event_model::run); }
        EventRun { steps, retired, delivered, outcome: EventOutcome::Budget, table_reads: reads }
    }
}

}
