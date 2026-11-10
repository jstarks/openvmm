// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resumable same-CPL event delivery over the shared CPU/MMU protocol.
use super::shared_model as spec;
use super::*;
use memory_core::shared::PhysicalRam;
use mmu_core::shared::io::{IoReply, IoRequest, IoRoute, Operand};
use mmu_core::shared::{self as memory, Reply, Request, RunError};
#[cfg(verus_keep_ghost)]
use paged_core::shared::CpuPhase;
use paged_core::shared::{SharedMachine, Tick as CpuTick};

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReturnWords { pub ip: u64, pub cs: u64, pub flags: u64, pub rsp: u64, pub ss: u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Ready, First, Second { first: u8 }, Third,
    Ordinary { flags: u64 },
    GateLow { event: Event, address: u64 },
    GateHigh { event: Event, low: u64 },
    Code { event: Event, low: u64, target: u64 },
    Push { event: Event, low: u64, target: u64, stack: u64, index: u8 },
    Pop { index: u8, words: ReturnWords },
    ReturnCode { words: ReturnWords }, ReturnStack { words: ReturnWords },
    Stopped { reason: EventDiagnostic },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tick { Pending, Waiting, Retired(bool), Delivered(u8), Halted, Stopped(EventDiagnostic) }

pub struct SharedEventMachine {
    core: SharedMachine, tables: Tables, phase: Phase,
    pending: Option<u8>, shadow: bool, halted: bool, handler_pending: bool,
}
impl View for SharedEventMachine {
    type V = spec::State;
    closed spec fn view(&self) -> spec::State {
        spec::State { core: self.core@, tables: self.tables, phase: self.phase,
            pending: self.pending, shadow: self.shadow, halted: self.halted,
            handler_pending: self.handler_pending }
    }
}
impl SharedEventMachine {
    pub closed spec fn invariant(&self) -> bool {
        self.core.invariant()
        && match self.phase {
            Phase::Ready => self.core@.phase == CpuPhase::Ready
                && !mmu_core::shared_model::active(self.core@.mmu.phase),
            Phase::Ordinary { .. } => self.core@.phase != CpuPhase::Boundary,
            Phase::Stopped { .. } => !mmu_core::shared_model::active(self.core@.mmu.phase),
            _ => self.core@.phase == CpuPhase::Boundary,
        }
        && match self.phase {
            Phase::Second { .. } => self.core@.cpu.rip < u64::MAX,
            Phase::Third => self.core@.cpu.rip < u64::MAX - 1,
            Phase::GateLow { event, address } => address <= u64::MAX - 15
                && address as int == self.tables.idt_base as int + event_model::vector(event) as int * 16,
            Phase::GateHigh { event, .. } =>
                self.tables.idt_base as int + event_model::vector(event) as int * 16 + 15 <= u64::MAX,
            Phase::Push { event, stack, index, .. } => index < 6
                && index >= (if event is External { 1u8 } else { 0u8 })
                && stack >= 8 * (if event is External { 5u64 } else { 6u64 }),
            Phase::Pop { index, .. } => index < 5 && self.core@.cpu.gpr[4] <= u64::MAX - 40,
            _ => true,
        }
        && match self.phase {
            Phase::GateLow { event, .. } | Phase::GateHigh { event, .. }
                | Phase::Code { event, .. } | Phase::Push { event, .. } =>
                spec::entry_profile(self.core@.cpu, self.tables, event),
            Phase::Pop { .. } | Phase::ReturnCode { .. } | Phase::ReturnStack { .. } =>
                event_model::tables_supported(self.tables),
            _ => true,
        }
    }

    pub fn new(cpu: State, config: Config, cr2: u64, tables: Tables) -> (s: Self)
        ensures s.invariant(), s@.core.cpu == cpu@, s@.phase == Phase::Ready,
            s@.tables == tables, s@.pending is None, !s@.shadow, !s@.halted, !s@.handler_pending,
    {
        let core = SharedMachine::new(cpu, config, cr2, false);
        proof { core.boundary_facts(); }
        Self { core, tables, phase: Phase::Ready,
            pending: None, shadow: false, halted: false, handler_pending: false }
    }

    pub fn cpu(&self) -> (v: State) ensures v@ == spec::visible_cpu(self@) {
        let mut cpu = self.core.cpu();
        if let Phase::Ordinary { flags } = self.phase { cpu.flags = flags; }
        cpu
    }
    pub fn cr2(&self) -> (v: u64) ensures v as int == self@.core.mmu.inner.cr2 { self.core.cr2() }
    pub fn config(&self) -> (v: Config) ensures v == self@.core.mmu.inner.config { self.core.config() }
    pub fn tables(&self) -> (v: Tables) ensures v == self@.tables { self.tables }
    pub fn pending(&self) -> (v: Option<u8>) ensures v == self@.pending { self.pending }
    pub fn halted(&self) -> (v: bool) ensures v == self@.halted { self.halted }
    pub fn shadow(&self) -> (v: bool) ensures v == self@.shadow { self.shadow }
    pub fn handler_pending(&self) -> (v: bool) ensures v == self@.handler_pending { self.handler_pending }

    pub fn io_operand(&self) -> (out: Option<Operand>)
        requires self.invariant(),
        ensures out == spec::io_operand(self@),
    {
        if matches!(self.phase, Phase::Ordinary { .. }) { self.core.io_operand() } else { None }
    }
    pub fn route_io(&mut self) -> (out: IoRoute)
        requires old(self).invariant(),
        ensures final(self).invariant(), (final(self)@, out) == spec::route_io(old(self)@),
    {
        if matches!(self.phase, Phase::Ordinary { .. }) { self.core.route_io() } else { IoRoute::NotReady }
    }
    pub fn complete_io(&mut self, sequence: u64, reply: IoReply) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            (final(self)@, accepted) == spec::complete_io(old(self)@, sequence, reply),
    {
        if matches!(self.phase, Phase::Ordinary { .. }) { self.core.complete_io(sequence, reply) } else { false }
    }

    pub fn inject(&mut self, vector: u8) -> (r: Injection)
        requires old(self).invariant(),
        ensures final(self).invariant(), (final(self)@, r) == spec::inject(old(self)@, vector),
    {
        if let Phase::Stopped { reason } = self.phase { return Injection::Stopped(reason); }
        if vector < 32 { return Injection::InvalidVector; }
        if self.pending.is_some() { return Injection::Busy; }
        self.pending = Some(vector);
        Injection::Queued
    }

    pub fn request(&self) -> (r: Request)
        requires self.invariant(),
        ensures r == mmu_core::shared_model::request(self@.core.mmu),
    { self.core.request() }

    pub fn respond(&mut self, reply: Reply) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(), (final(self)@, accepted) == spec::respond(old(self)@, reply),
    { self.core.respond(reply) }

    fn stop(&mut self, reason: EventDiagnostic) -> (tick: Tick)
        requires old(self).core.invariant(), !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(), (final(self)@, tick) == spec::stop(old(self)@, reason),
    { self.phase = Phase::Stopped { reason }; Tick::Stopped(reason) }

    fn begin_word(&mut self, address: u64, request: WordAccess, phase: Phase)
        requires old(self).core.invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).core.invariant(), final(self)@ == spec::word(old(self)@, address, request, phase),
    {
        let _accepted = self.core.boundary_word(address, request);
        assert(_accepted);
        self.phase = phase;
    }

    fn start_entry(&mut self, event: Event) -> (tick: Tick)
        requires old(self).core.invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(), (final(self)@, tick) == spec::entry(old(self)@, event),
    {
        if self.handler_pending {
            let (vector, code) = match event { Event::PageFault(c) => (14, c),
                Event::GeneralProtection => (13, 0), Event::External(v) => (v, 0) };
            return self.stop(EventDiagnostic::HandlerFault { vector, code });
        }
        let cpu = self.core.cpu();
        let external = matches!(event, Event::External(_));
        if external && match event { Event::External(v) => v < 32, _ => false } {
            return self.stop(EventDiagnostic::InterruptWindow);
        }
        let count = if external { 5u64 } else { 6u64 };
        let stack = cpu.gpr[4] / 16 * 16;
        if !flags_supported(cpu.flags) || !tables_supported(self.tables)
            || !canonical(cpu.rip) || !canonical(cpu.gpr[4]) || stack < count * 8 {
            return self.stop(EventDiagnostic::Profile);
        }
        let vector: u8 = match event { Event::PageFault(_) => 14, Event::GeneralProtection => 13, Event::External(v) => v };
        let offset = vector as u64 * 16;
        if offset + 15 > self.tables.idt_limit as u64 || self.tables.idt_base > u64::MAX - offset - 15 {
            return self.stop(EventDiagnostic::Descriptor(Stage::Idt));
        }
        let address = self.tables.idt_base + offset;
        self.begin_word(address, WordAccess::Read, Phase::GateLow { event, address });
        Tick::Pending
    }

    fn start_iret(&mut self) -> (tick: Tick)
        requires old(self).core.invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(), (final(self)@, tick) == spec::iret(old(self)@),
    {
        let cpu = self.core.cpu();
        if !flags_supported(cpu.flags) || !tables_supported(self.tables) || cpu.gpr[4] > u64::MAX - 40 {
            return self.stop(EventDiagnostic::Profile);
        }
        self.begin_word(cpu.gpr[4], WordAccess::Read, Phase::Pop { index: 0,
            words: ReturnWords { ip: 0, cs: 0, flags: 0, rsp: 0, ss: 0 } });
        Tick::Pending
    }

    pub fn advance(&mut self) -> (tick: Tick)
        requires old(self).invariant(),
        ensures final(self).invariant(), (final(self)@, tick) == spec::advance(old(self)@),
    {
        match self.phase {
            Phase::Stopped { reason } => Tick::Stopped(reason),
            Phase::Ready => {
                let cpu = self.core.cpu();
                if !flags_supported(cpu.flags) { return self.stop(EventDiagnostic::Profile); }
                if let Some(vector) = self.pending {
                    if !self.shadow && cpu.flags & 0x200u64 != 0 {
                        let _accepted = self.core.boundary(); assert(_accepted);
                        return self.start_entry(Event::External(vector));
                    }
                }
                if self.halted { return Tick::Halted; }
                let _accepted = self.core.boundary(); assert(_accepted);
                let _accepted = self.core.boundary_fetch(cpu.rip); assert(_accepted);
                self.phase = Phase::First;
                Tick::Pending
            },
            Phase::Ordinary { flags } => {
                let result = self.core.advance();
                proof { self.core.boundary_facts(); }
                match result {
                    CpuTick::Pending => Tick::Pending,
                    CpuTick::Waiting => Tick::Waiting,
                    CpuTick::Retired => {
                        self.phase = Phase::Ready; self.shadow = false; self.handler_pending = false;
                        Tick::Retired(false)
                    },
                    CpuTick::Stopped(outcome) => {
                        let _accepted = self.core.boundary(); assert(_accepted);
                        let mut cpu = self.core.cpu(); cpu.flags = flags;
                        let _accepted = self.core.boundary_commit(cpu, false); assert(_accepted);
                        match outcome {
                            StepOutcome::PageFault { code, .. } => self.start_entry(Event::PageFault(code)),
                            StepOutcome::GeneralProtection { .. } => self.start_entry(Event::GeneralProtection),
                            StepOutcome::Diagnostic(d) => self.stop(EventDiagnostic::Instruction(d)),
                            _ => self.stop(EventDiagnostic::Profile),
                        }
                    },
                    CpuTick::Boundary => { assert(false); Tick::Waiting },
                }
            },
            Phase::First | Phase::Second { .. } | Phase::Third => {
                match self.core.request() {
                    Request::Complete(report) => match report.result {
                        MmuResult::Success(value) => self.byte(value),
                        MmuResult::PageFault(code) => self.start_entry(Event::PageFault(code)),
                        MmuResult::GeneralProtection => self.start_entry(Event::GeneralProtection),
                        other => {
                            let address = match self.phase { Phase::First => self.core.cpu().rip,
                                Phase::Second { .. } => self.core.cpu().rip + 1,
                                _ => self.core.cpu().rip + 2 };
                            self.stop(EventDiagnostic::Fetch { address, byte_result: other })
                        },
                    },
                    _ => Tick::Waiting,
                }
            },
            _ => match self.core.request() {
                Request::CompleteWord { report } => match report.result {
                    WordResult::Success(value) => self.word_value(value),
                    result => {
                        let (stage, address) = self.word_location();
                        self.stop(EventDiagnostic::Memory { stage, address, result })
                    },
                },
                _ => Tick::Waiting,
            },
        }
    }

    fn byte(&mut self, value: u8) -> (tick: Tick)
        requires old(self).invariant(),
            matches!(old(self).phase, Phase::First | Phase::Second { .. } | Phase::Third),
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(), (final(self)@, tick) == spec::byte(old(self)@, value),
    {
        let mut cpu = self.core.cpu();
        match self.phase {
            Phase::First => {
                if value == 0xfa || value == 0xfb || value == 0xf4 {
                    let flags = cpu.flags;
                    cpu.flags &= !0x10000u64;
                    if value == 0xfa { cpu.flags &= !0x200u64; }
                    else if value == 0xfb { cpu.flags |= 0x200u64; }
                    cpu.rip = cpu.rip.wrapping_add(1);
                    let _accepted = self.core.boundary_commit(cpu, true); assert(_accepted);
                    self.phase = Phase::Ready;
                    self.shadow = value == 0xfb && flags & 0x200u64 == 0;
                    self.halted = value == 0xf4; self.handler_pending = false;
                    return Tick::Retired(false);
                }
                if value != 0x0f && (value < 0x48 || value > 0x4f) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                if cpu.rip == u64::MAX { return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::FetchWrap)); }
                let _accepted = self.core.boundary_fetch(cpu.rip + 1); assert(_accepted);
                self.phase = Phase::Second { first: value }; Tick::Pending
            },
            Phase::Second { first } => {
                if first == 0x48 && value == 0xcf { return self.start_iret(); }
                if first != 0x0f {
                    let flags = cpu.flags; cpu.flags &= !0x10000u64;
                    let _accepted = self.core.boundary_commit(cpu, true); assert(_accepted);
                    self.phase = Phase::Ordinary { flags }; return Tick::Pending;
                }
                if value != 1 { return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)); }
                if cpu.rip == u64::MAX - 1 { return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::FetchWrap)); }
                let _accepted = self.core.boundary_fetch(cpu.rip + 2); assert(_accepted);
                self.phase = Phase::Third; Tick::Pending
            },
            Phase::Third => {
                if value != 0x3f || !canonical(cpu.gpr[7]) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let _accepted = self.core.invalidate(cpu.gpr[7]); assert(_accepted);
                cpu.flags &= !0x10000u64; cpu.rip = cpu.rip.wrapping_add(3);
                let _accepted = self.core.boundary_commit(cpu, true); assert(_accepted);
                self.phase = Phase::Ready; self.handler_pending = false; self.shadow = false;
                Tick::Retired(true)
            },
            _ => { assert(false); Tick::Waiting },
        }
    }

    fn word_location(&self) -> (out: (Stage, u64))
        requires self.invariant(),
            !matches!(self.phase, Phase::Ready | Phase::First | Phase::Second { .. }
                | Phase::Third | Phase::Ordinary { .. } | Phase::Stopped { .. }),
        ensures out == spec::word_location(self@),
    {
        let cpu = self.core.cpu();
        match self.phase {
            Phase::GateLow { address, .. } => (Stage::Idt, address),
            Phase::GateHigh { event, .. } => (Stage::Idt, self.tables.idt_base
                + (match event { Event::PageFault(_) => 14u64, Event::GeneralProtection => 13, Event::External(v) => v as u64 }) * 16 + 8),
            Phase::Code { .. } | Phase::ReturnCode { .. } => (Stage::Code, self.tables.gdt_base + 8),
            Phase::ReturnStack { .. } => (Stage::Stack, self.tables.gdt_base + 16),
            Phase::Push { event, stack, index, .. } =>
                (Stage::Push, stack - 8 * (index as u64 - if matches!(event, Event::External(_)) { 1 } else { 0 } + 1)),
            Phase::Pop { index, .. } => (Stage::Pop, cpu.gpr[4] + index as u64 * 8),
            _ => { assert(false); (Stage::Idt, 0) },
        }
    }

    fn word_value(&mut self, value: u64) -> (tick: Tick)
        requires old(self).invariant(),
            !matches!(old(self).phase, Phase::Ready | Phase::First | Phase::Second { .. }
                | Phase::Third | Phase::Ordinary { .. } | Phase::Stopped { .. }),
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(), (final(self)@, tick) == spec::word_value(old(self)@, value),
    {
        let mut cpu = self.core.cpu();
        match self.phase {
            Phase::GateLow { event, address } => {
                self.begin_word(address + 8, WordAccess::Read, Phase::GateHigh { event, low: value });
            },
            Phase::GateHigh { event, low } => {
                if !gate_supported(low, value) { return self.stop(EventDiagnostic::Descriptor(Stage::Idt)); }
                let target = gate_target(low, value);
                if !canonical(target) { return self.stop(EventDiagnostic::Descriptor(Stage::Idt)); }
                self.begin_word(self.tables.gdt_base + 8, WordAccess::Read, Phase::Code { event, low, target });
            },
            Phase::Code { event, low, target } => {
                if value != 0x00af9b000000ffffu64 { return self.stop(EventDiagnostic::Descriptor(Stage::Code)); }
                let index = if matches!(event, Event::External(_)) { 1u8 } else { 0u8 };
                let stack = cpu.gpr[4] / 16 * 16;
                let word = frame_word(cpu, event, index);
                self.begin_word(stack - 8, WordAccess::Write(word), Phase::Push { event, low, target, stack, index });
            },
            Phase::Push { event, low, target, stack, index } => {
                if index == 5 {
                    let count = if matches!(event, Event::External(_)) { 5u64 } else { 6u64 };
                    let ghost before = cpu@;
                    cpu.gpr[4] = stack - count * 8;
                    assert(cpu@.gpr =~= before.gpr.update(4, stack as int - count as int * 8));
                    cpu.flags = live_flags(cpu.flags, low); cpu.rip = target;
                    let _accepted = self.core.boundary_commit(cpu, true); assert(_accepted);
                    self.phase = Phase::Ready; self.handler_pending = true; self.shadow = false; self.halted = false;
                    if matches!(event, Event::External(_)) { self.pending = None; }
                    return Tick::Delivered(match event { Event::PageFault(_) => 14,
                        Event::GeneralProtection => 13, Event::External(v) => v });
                }
                let next = index + 1;
                let start = if matches!(event, Event::External(_)) { 1u64 } else { 0u64 };
                let address = stack - 8 * (next as u64 - start + 1);
                self.begin_word(address, WordAccess::Write(frame_word(cpu, event, next)),
                    Phase::Push { event, low, target, stack, index: next });
            },
            Phase::Pop { index, mut words } => {
                match index { 0 => words.ip = value, 1 => words.cs = value, 2 => words.flags = value,
                    3 => words.rsp = value, _ => words.ss = value };
                if index < 4 {
                    self.begin_word(cpu.gpr[4] + (index as u64 + 1) * 8, WordAccess::Read,
                        Phase::Pop { index: index + 1, words });
                } else {
                    if words.cs != 8 || words.ss != 16 || !flags_supported(words.flags)
                        || !canonical(words.ip) || !canonical(words.rsp) { return self.stop(EventDiagnostic::ReturnImage); }
                    self.begin_word(self.tables.gdt_base + 8, WordAccess::Read, Phase::ReturnCode { words });
                }
            },
            Phase::ReturnCode { words } => {
                if value != 0x00af9b000000ffffu64 { return self.stop(EventDiagnostic::Descriptor(Stage::Code)); }
                self.begin_word(self.tables.gdt_base + 16, WordAccess::Read, Phase::ReturnStack { words });
            },
            Phase::ReturnStack { words } => {
                if value != 0x00cf93000000ffffu64 { return self.stop(EventDiagnostic::Descriptor(Stage::Stack)); }
                let ghost before = cpu@;
                cpu.gpr[4] = words.rsp;
                assert(cpu@.gpr =~= before.gpr.update(4, words.rsp as int));
                cpu.flags = words.flags; cpu.rip = words.ip;
                let _accepted = self.core.boundary_commit(cpu, true); assert(_accepted);
                self.phase = Phase::Ready; self.handler_pending = false; self.shadow = false;
                return Tick::Retired(true);
            },
            _ => { assert(false); },
        }
        Tick::Pending
    }
}

fn frame_word(cpu: State, event: Event, index: u8) -> (value: u64)
    requires index < 6,
    ensures value == spec::frame_word(cpu@, event, index),
{
    if matches!(event, Event::External(_)) {
        match index { 0 => 0, 1 => 16, 2 => cpu.gpr[4], 3 => cpu.flags, 4 => 8, _ => cpu.rip }
    } else {
        match index { 0 => 16, 1 => cpu.gpr[4], 2 => cpu.flags | 0x10000u64, 3 => 8, 4 => cpu.rip,
            _ => match event { Event::PageFault(code) => code as u64, _ => 0 } }
    }
}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchStop {
    Budget,
    Yield,
    Waiting,
    Stopped(EventDiagnostic),
    Io(IoRequest),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Batch {
    pub retired: u64,
    pub delivered: u64,
    pub stop: BatchStop,
}

impl SharedEventMachine {
    pub fn run<R: PhysicalRam>(
        &mut self,
        ram: &R,
        io_budget: u32,
        step_budget: u64,
    ) -> Result<Batch, RunError<R::Error>> {
        self.run_with_mmio(ram, io_budget, step_budget, |_, _| false)
    }

    pub fn run_with_mmio<R: PhysicalRam>(
        &mut self,
        ram: &R,
        io_budget: u32,
        step_budget: u64,
        mut is_mmio: impl FnMut(u64, u8) -> bool,
    ) -> Result<Batch, RunError<R::Error>> {
        let (mut steps, mut effects, mut retired, mut delivered) = (0, 0, 0, 0);
        loop {
            if steps == step_budget {
                return Ok(Batch {
                    retired,
                    delivered,
                    stop: BatchStop::Budget,
                });
            }
            match self.advance() {
                Tick::Pending => {}
                Tick::Retired(serializing) => {
                    if serializing {
                        ram.barrier();
                    }
                    steps += 1;
                    retired += 1;
                }
                Tick::Delivered(_) => {
                    ram.barrier();
                    steps += 1;
                    delivered += 1;
                }
                Tick::Halted => {
                    return Ok(Batch {
                        retired,
                        delivered,
                        stop: BatchStop::Waiting,
                    });
                }
                Tick::Stopped(reason) => {
                    return Ok(Batch {
                        retired,
                        delivered,
                        stop: BatchStop::Stopped(reason),
                    });
                }
                Tick::Waiting => {
                    if let Some(operand) = self.io_operand() {
                        if is_mmio(operand.address, 8) {
                            let route = self.route_io();
                            if route != IoRoute::Accepted {
                                return Err(RunError::IoProfile(route));
                            }
                            continue;
                        }
                    }
                    if let Request::Io(request) = self.request() {
                        return Ok(Batch {
                            retired,
                            delivered,
                            stop: BatchStop::Io(request),
                        });
                    }
                    if effects == io_budget {
                        return Ok(Batch {
                            retired,
                            delivered,
                            stop: BatchStop::Yield,
                        });
                    }
                    let request = self.request();
                    if !self.respond(memory::perform(ram, request)?) {
                        return Err(RunError::Protocol(request));
                    }
                    effects += 1;
                }
            }
        }
    }
}
