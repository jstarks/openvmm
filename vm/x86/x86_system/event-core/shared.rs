// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resumable same-CPL event delivery over the shared CPU/MMU protocol.
use super::shared_model as spec;
use super::*;
#[cfg(verus_keep_ghost)]
use memory_core::cpu_core::system;
use memory_core::cpu_core::system::{SegmentState, SystemState};
use memory_core::cpu_core::{descriptor, exception};
use memory_core::shared::PhysicalRam;
use mmu_core::shared::io::{IoReply, IoRequest, IoRoute, Operand};
use mmu_core::shared::{self as memory, Reply, Request, RunError};
#[cfg(verus_keep_ghost)]
use paged_core::shared::CpuPhase;
use paged_core::shared::{SharedMachine, Tick as CpuTick};
#[path = "shared_alu.rs"]
pub mod alu;
#[path = "shared_decode.rs"]
pub mod decode;
#[path = "shared_entry.rs"]
pub mod entry;
#[path = "shared_privilege.rs"]
pub mod privilege;
#[path = "shared_repeat.rs"]
pub mod repeat;
use decode::{DecodeDecision, DecodeInput};

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReturnWords { pub ip: u64, pub cs: u64, pub flags: u64, pub rsp: u64, pub ss: u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Ready, First, Second { first: u8 }, Third,
    Ordinary { flags: u64 },
    Decode { input: DecodeInput },
    DecodeFetch { input: DecodeInput },
    Admitted { input: DecodeInput, decision: DecodeDecision },
    NearCall { target: u64, stack: u64 },
    EntryMemory { address: u64, length: u8, task: entry::MemoryTask },
    PortIo { request: entry::PortRequest, length: u8, reply: Option<IoReply> },
    Timestamp {sequence:u64,length:u8,value:Option<u64>},
    Repeat { width: memory_core::cpu_core::operand::Width, length: u8 },
    RepeatMove { width: memory_core::cpu_core::operand::Width, length: u8 },
    GateLow { event: Event, address: u64 },
    GateHigh { event: Event, low: u64 },
    Code { event: Event, low: u64, target: u64, selector: u16 },
    Push { event: Event, low: u64, target: u64, cs: SegmentState, stack: u64, index: u8 },
    Pop { index: u8, words: ReturnWords },
    ReturnCode { words: ReturnWords }, ReturnStack { words: ReturnWords, cs: SegmentState },
    Stopped { reason: EventDiagnostic },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tick { Pending, Waiting, Retired(bool), Delivered(u8), Halted, Stopped(EventDiagnostic),
    Decode(DecodeInput) }

pub struct SharedEventMachine {
    core: SharedMachine, tables: Tables, phase: Phase,
    pending: Option<u8>, shadow: bool, halted: bool, handler_pending: bool,
    external_decode: bool, decode_sequence: u64,
    system: Option<SystemState>,
}
impl View for SharedEventMachine {
    type V = spec::State;
    closed spec fn view(&self) -> spec::State {
        spec::State { core: self.core@, tables: self.tables, phase: self.phase,
            pending: self.pending, shadow: self.shadow, halted: self.halted,
            handler_pending: self.handler_pending, external_decode: self.external_decode,
            decode_sequence: self.decode_sequence, system: self.system }
    }
}
impl SharedEventMachine {
    pub closed spec fn system_supported(&self) -> bool {
        match self.system { Some(s) => system::model::supported(s), None => true }
    }

    pub closed spec fn invariant(&self) -> bool {
        self.core.invariant()
        && self.system_supported()
        && match self.phase {
            Phase::PortIo {request,length,reply} =>
                request.width != memory_core::cpu_core::operand::Width::Qword
                && request.sequence == self.decode_sequence && 1 <= length <= 15
                && match (request.access,reply) {
                    (WordAccess::Read,Some(IoReply::Written))
                    | (WordAccess::Write(_),Some(IoReply::Read(_)))=>false,
                    _=>true,
                },
            Phase::Timestamp {sequence,length,..}=>sequence==self.decode_sequence &&1<=length<=15,
            _=>true,
        }
        && match self.phase {
            Phase::Decode { input } | Phase::Admitted { input, .. } =>
                spec::decode::valid_input(self@, input)
                && !mmu_core::shared_model::active(self.core@.mmu.phase),
            Phase::DecodeFetch { input } => spec::decode::valid_input(self@, input)
                && input.length < 15 && input.rip as int + input.length as int <= u64::MAX
                && self.core@.mmu.va == input.rip + input.length,
            _ => true,
        }
        && match self.phase {
            Phase::Ready => self.core@.phase == CpuPhase::Ready
                && !mmu_core::shared_model::active(self.core@.mmu.phase),
            Phase::Ordinary { .. } => self.core@.phase != CpuPhase::Boundary,
            Phase::Stopped { .. } => !mmu_core::shared_model::active(self.core@.mmu.phase),
            Phase::Repeat { .. } | Phase::RepeatMove { .. } | Phase::PortIo { .. }
                | Phase::Timestamp {..} => self.core@.phase == CpuPhase::Boundary
                && !mmu_core::shared_model::active(self.core@.mmu.phase),
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
                && index >= (if event_model::has_error_code(event) { 0u8 } else { 1u8 })
                && stack >= 8 * (if event_model::has_error_code(event) { 6u64 } else { 5u64 }),
            Phase::Pop { index, .. } => index < 5 && self.core@.cpu.gpr[4] <= u64::MAX - 40,
            _ => true,
        }
        && match self.phase {
            Phase::GateLow { event, .. } | Phase::GateHigh { event, .. }
                | Phase::Code { event, .. } | Phase::Push { event, .. } =>
                spec::entry_profile(self.core@.cpu, self.tables, event, self.system),
            Phase::Pop { .. } | Phase::ReturnCode { .. } | Phase::ReturnStack { .. } =>
                spec::tables_supported(self.tables, self.system),
            _ => true,
        }
        && match self.phase {
            Phase::Code { selector, .. } => spec::descriptor_address(self.tables, selector),
            Phase::Push { cs, .. } => system::model::supported_code(cs),
            Phase::ReturnCode { words } => spec::return_image(words, self.tables, self.system),
            Phase::ReturnStack { words, cs } =>
                spec::return_image(words, self.tables, self.system)
                && words.ss != 0 && system::model::supported_code(cs),
            _ => true,
        }
    }

    pub fn new(cpu: State, config: Config, cr2: u64, tables: Tables) -> (s: Self)
        ensures s.invariant(), s@.core.cpu == cpu@, s@.phase == Phase::Ready,
            s@.tables == tables, s@.pending is None, !s@.shadow, !s@.halted, !s@.handler_pending,
            s@.system is None,
    {
        let core = SharedMachine::new(cpu, config, cr2, false);
        proof { core.boundary_facts(); }
        Self { core, tables, phase: Phase::Ready,
            pending: None, shadow: false, halted: false, handler_pending: false,
            external_decode: false, decode_sequence: 0, system: None }
    }

    pub fn system(&self) -> (out: Option<SystemState>)
        ensures out == self@.system,
    { self.system }

    pub fn at_instruction_boundary(&self) -> (out:bool)
        ensures out == (self@.phase == Phase::Ready),
    { matches!(self.phase,Phase::Ready) }

    pub fn configure_system(&mut self, system: SystemState) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            (final(self)@, accepted) == spec::configure_system(old(self)@, system),
            final(self)@.core == old(self)@.core,
    {
        if !matches!(self.phase, Phase::Ready) || !system.is_supported() { return false; }
        self.system = Some(system);
        true
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
        requires old(self).core.invariant(), old(self).system_supported(),
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
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
        requires old(self).core.invariant(), old(self).system_supported(),
            old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(), (final(self)@, tick) == spec::entry(old(self)@, event),
    {
        if self.handler_pending {
            let (vector, code) = match event { Event::PageFault(c) => (14, c),
                Event::GeneralProtection => (13, 0), Event::InvalidOpcode => (6, 0),
                Event::Breakpoint=>(3,0), Event::External(v) => (v, 0) };
            return self.stop(EventDiagnostic::HandlerFault { vector, code });
        }
        let cpu = self.core.cpu();
        let external = matches!(event, Event::External(_));
        if external && match event { Event::External(v) => v < 32, _ => false } {
            return self.stop(EventDiagnostic::InterruptWindow);
        }
        let count = if has_error_code(event) { 6u64 } else { 5u64 };
        let stack = cpu.gpr[4] / 16 * 16;
        if !flags_supported(cpu.flags) || !shared_tables_supported(self.tables, self.system)
            || !canonical(cpu.rip) || !canonical(cpu.gpr[4]) || stack < count * 8
        {
            return self.stop(EventDiagnostic::Profile);
        }
        let vector: u8 = match event { Event::PageFault(_) => 14, Event::GeneralProtection => 13,
            Event::InvalidOpcode => 6, Event::Breakpoint=>3, Event::External(v) => v };
        let offset = vector as u64 * 16;
        if offset + 15 > self.tables.idt_limit as u64 || self.tables.idt_base > u64::MAX - offset - 15 {
            return self.stop(EventDiagnostic::Descriptor(Stage::Idt));
        }
        let address = self.tables.idt_base + offset;
        self.begin_word(address, WordAccess::Read, Phase::GateLow { event, address });
        Tick::Pending
    }

    fn start_iret(&mut self) -> (tick: Tick)
        requires old(self).core.invariant(), old(self).system_supported(),
            old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(), (final(self)@, tick) == spec::iret(old(self)@),
    {
        let cpu = self.core.cpu();
        if !flags_supported(cpu.flags) || !shared_tables_supported(self.tables, self.system)
            || cpu.gpr[4] > u64::MAX - 40 {
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
            Phase::Repeat {width,length} => self.execute_repeat(width,length),
            Phase::RepeatMove {width,length} => self.execute_move(width,length),
            Phase::Decode { input } => Tick::Decode(input),
            Phase::Admitted { .. } => self.advance_admitted(),
            Phase::PortIo { .. } => self.finish_port_io(),
            Phase::Timestamp {..}=>self.finish_timestamp(),
            Phase::DecodeFetch { input } => match self.core.request() {
                Request::Complete(report) => match report.result {
                    MmuResult::Success(value) => self.append_decode(value),
                    MmuResult::PageFault(code) => self.start_entry(Event::PageFault(code)),
                    MmuResult::GeneralProtection => self.start_entry(Event::GeneralProtection),
                    other => self.stop(EventDiagnostic::Fetch {
                        address: input.rip + input.length as u64, byte_result: other }),
                },
                _ => Tick::Waiting,
            },
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
                        if let WordResult::PageFault(code) = result {
                            let far_return = match self.phase {
                                Phase::EntryMemory { task, .. } => matches!(task,
                                    entry::MemoryTask::FarTarget { .. } | entry::MemoryTask::FarSelector { .. }
                                    | entry::MemoryTask::FarCode { .. }),
                                _ => false,
                            };
                            if !far_return && matches!(self.phase, Phase::NearCall { .. } | Phase::EntryMemory { .. }) {
                                return self.start_entry(Event::PageFault(code));
                            }
                        }
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
                if self.external_decode && value != 0x48 && value != 0x0f {
                    return self.offer_decode(value, 0, 0, 1);
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
                if self.external_decode && (first != 0x0f || value != 1) {
                    return self.offer_decode(first, value, 0, 2);
                }
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
                if self.external_decode && value != 0x3f {
                    return self.offer_decode(0x0f, 1, value, 3);
                }
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
                | Phase::Third | Phase::Ordinary { .. } | Phase::Stopped { .. }
                | Phase::Decode { .. } | Phase::DecodeFetch { .. } | Phase::Admitted { .. }
                | Phase::Repeat { .. } | Phase::RepeatMove { .. } | Phase::PortIo { .. }
                | Phase::Timestamp {..}),
        ensures out == spec::word_location(self@),
    {
        let cpu = self.core.cpu();
        match self.phase {
            Phase::GateLow { address, .. } => (Stage::Idt, address),
            Phase::GateHigh { event, .. } => (Stage::Idt, self.tables.idt_base
                + (match event { Event::PageFault(_) => 14u64, Event::GeneralProtection => 13,
                    Event::InvalidOpcode => 6, Event::Breakpoint=>3, Event::External(v) => v as u64 }) * 16 + 8),
            Phase::Code { selector, .. } => (Stage::Code, self.tables.gdt_base + selector as u64),
            Phase::ReturnCode { words } => (Stage::Code, self.tables.gdt_base + words.cs),
            Phase::ReturnStack { words, .. } => (Stage::Stack, self.tables.gdt_base + words.ss),
            Phase::Push { event, stack, index, .. } =>
                (Stage::Push, stack - 8 * (index as u64 - if has_error_code(event) { 0 } else { 1 } + 1)),
            Phase::Pop { index, .. } => (Stage::Pop, cpu.gpr[4] + index as u64 * 8),
            Phase::NearCall { stack, .. } => (Stage::Push, stack),
            Phase::EntryMemory { address, .. } => (Stage::Stack, address),
            _ => { assert(false); (Stage::Idt, 0) },
        }
    }

    fn word_value(&mut self, value: u64) -> (tick: Tick)
        requires old(self).invariant(),
            !matches!(old(self).phase, Phase::Ready | Phase::First | Phase::Second { .. }
                | Phase::Third | Phase::Ordinary { .. } | Phase::Stopped { .. }
                | Phase::Decode { .. } | Phase::DecodeFetch { .. } | Phase::Admitted { .. }
                | Phase::Repeat { .. } | Phase::RepeatMove { .. } | Phase::PortIo { .. }
                | Phase::Timestamp {..}),
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(), (final(self)@, tick) == spec::word_value(old(self)@, value),
    {
        let mut cpu = self.core.cpu();
        match self.phase {
            Phase::EntryMemory { .. } => return self.entry_value(value),
            Phase::NearCall { target, stack } => {
                let ghost before = cpu@;
                cpu.gpr[4] = stack;
                assert(cpu@.gpr =~= before.gpr.update(4, stack as int));
                cpu.rip = target;
                cpu.flags &= !0x10000u64;
                let _accepted = self.core.boundary_commit(cpu, true);
                assert(_accepted);
                self.phase = Phase::Ready; self.shadow = false; self.handler_pending = false;
                return Tick::Retired(false);
            },
            Phase::GateLow { event, address } => {
                self.begin_word(address + 8, WordAccess::Read, Phase::GateHigh { event, low: value });
            },
            Phase::GateHigh { event, low } => {
                let gate = match exception::gate(low, value) {
                    Some(gate) => gate,
                    None => return self.stop(EventDiagnostic::Descriptor(Stage::Idt)),
                };
                if self.system.is_none() && gate.selector != 8 {
                    return self.stop(EventDiagnostic::Descriptor(Stage::Idt));
                }
                if !descriptor_address(self.tables, gate.selector) {
                    return self.stop(EventDiagnostic::Descriptor(Stage::Code));
                }
                self.begin_word(self.tables.gdt_base + gate.selector as u64, WordAccess::Read,
                    Phase::Code { event, low, target: gate.target, selector: gate.selector });
            },
            Phase::Code { event, low, target, selector } => {
                let cs = match descriptor::load_code(value, selector) {
                    Some(cs) => cs,
                    None => return self.stop(EventDiagnostic::Descriptor(Stage::Code)),
                };
                let index = if has_error_code(event) { 0u8 } else { 1u8 };
                let stack = cpu.gpr[4] / 16 * 16;
                let word = frame_word(cpu, self.system, event, index);
                self.begin_word(stack - 8, WordAccess::Write(word),
                    Phase::Push { event, low, target, cs, stack, index });
            },
            Phase::Push { event, low, target, cs, stack, index } => {
                if index == 5 {
                    let count = if has_error_code(event) { 6u64 } else { 5u64 };
                    let ghost before = cpu@;
                    cpu.gpr[4] = stack - count * 8;
                    assert(cpu@.gpr =~= before.gpr.update(4, stack as int - count as int * 8));
                    cpu.flags = live_flags(cpu.flags, low); cpu.rip = target;
                    let _accepted = self.core.boundary_commit(cpu, true); assert(_accepted);
                    if let Some(system) = self.system {
                        proof { system::lemma_replace_code(system, cs); }
                        self.system = Some(SystemState { cs, ..system });
                    }
                    self.phase = Phase::Ready; self.handler_pending = true; self.shadow = false; self.halted = false;
                    if matches!(event, Event::External(_)) { self.pending = None; }
                    return Tick::Delivered(match event { Event::PageFault(_) => 14,
                        Event::GeneralProtection => 13, Event::InvalidOpcode => 6,
                        Event::Breakpoint=>3, Event::External(v) => v });
                }
                let next = index + 1;
                let start = if has_error_code(event) { 0u64 } else { 1u64 };
                let address = stack - 8 * (next as u64 - start + 1);
                self.begin_word(address, WordAccess::Write(frame_word(cpu, self.system, event, next)),
                    Phase::Push { event, low, target, cs, stack, index: next });
            },
            Phase::Pop { index, mut words } => {
                match index { 0 => words.ip = value, 1 => words.cs = value, 2 => words.flags = value,
                    3 => words.rsp = value, _ => words.ss = value };
                if index < 4 {
                    self.begin_word(cpu.gpr[4] + (index as u64 + 1) * 8, WordAccess::Read,
                        Phase::Pop { index: index + 1, words });
                } else {
                    if !return_image(words, self.tables, self.system) {
                        return self.stop(EventDiagnostic::ReturnImage);
                    }
                    self.begin_word(self.tables.gdt_base + words.cs, WordAccess::Read, Phase::ReturnCode { words });
                }
            },
            Phase::ReturnCode { words } => {
                let cs = match descriptor::load_code(value, words.cs as u16) {
                    Some(cs) => cs,
                    None => return self.stop(EventDiagnostic::Descriptor(Stage::Code)),
                };
                if words.ss == 0 {
                    let ss = exception::stack(0, 0).unwrap();
                    return self.commit_return(words, cs, ss);
                }
                self.begin_word(self.tables.gdt_base + words.ss, WordAccess::Read,
                    Phase::ReturnStack { words, cs });
            },
            Phase::ReturnStack { words, cs } => {
                let ss = match exception::stack(value, words.ss as u16) {
                    Some(ss) => ss,
                    None => return self.stop(EventDiagnostic::Descriptor(Stage::Stack)),
                };
                return self.commit_return(words, cs, ss);
            },
            _ => { assert(false); },
        }
        Tick::Pending
    }

    fn commit_return(&mut self, words: ReturnWords, cs: SegmentState, ss: SegmentState) -> (tick: Tick)
        requires old(self).core.invariant(), old(self).system_supported(),
            old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
            system::model::supported_code(cs), system::model::supported_data_or_null(ss),
        ensures final(self).invariant(),
            (final(self)@, tick) == spec::commit_return(old(self)@, words, cs, ss),
    {
        let mut cpu = self.core.cpu();
        let ghost before = cpu@;
        cpu.gpr[4] = words.rsp;
        assert(cpu@.gpr =~= before.gpr.update(4, words.rsp as int));
        cpu.flags = words.flags; cpu.rip = words.ip;
        let _accepted = self.core.boundary_commit(cpu, true); assert(_accepted);
        if let Some(system) = self.system {
            proof {
                system::lemma_replace_code(system, cs);
                system::lemma_replace_data(SystemState { cs, ..system }, ss, system.ds, system.es);
            }
            self.system = Some(SystemState { cs, ss, ..system });
        }
        self.phase = Phase::Ready; self.handler_pending = false; self.shadow = false;
        Tick::Retired(true)
    }
}

fn shared_tables_supported(t: Tables, system: Option<SystemState>) -> (out: bool)
    ensures out == spec::tables_supported(t, system),
{
    if system.is_none() { tables_supported(t) }
    else { t.idt_base % 16 == 0 && t.gdt_base % 8 == 0 }
}

fn descriptor_address(t: Tables, selector: u16) -> (out: bool)
    ensures out == spec::descriptor_address(t, selector),
{
    selector != 0 && selector & 7 == 0
        && selector as u64 + 7 <= t.gdt_limit as u64
        && t.gdt_base <= u64::MAX - selector as u64 - 7
}

fn return_image(w: ReturnWords, t: Tables, system: Option<SystemState>) -> (out: bool)
    ensures out == spec::return_image(w, t, system),
{
    (system.is_some() || (w.cs == 8 && w.ss == 16))
        && w.cs <= u16::MAX as u64 && w.ss <= u16::MAX as u64
        && descriptor_address(t, w.cs as u16)
        && (w.ss == 0 || descriptor_address(t, w.ss as u16))
        && flags_supported(w.flags) && canonical(w.ip) && canonical(w.rsp)
}

fn frame_word(cpu: State, system: Option<SystemState>, event: Event, index: u8) -> (value: u64)
    requires index < 6,
    ensures value == spec::frame_word(cpu@, system, event, index),
{
    exception::frame_word(cpu.rip, cpu.gpr[4], cpu.flags, exception::selectors(system),
        has_error_code(event), matches!(event, Event::External(_) | Event::Breakpoint),
        match event { Event::PageFault(code) => code, _ => 0 }, index)
}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchStop {
    Budget,
    Yield,
    Waiting,
    Stopped(EventDiagnostic),
    Io(IoRequest),
    PortIo(entry::PortRequest),
    Timestamp { sequence: u64 },
    Decode(DecodeInput),
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
                Tick::Decode(input) => {
                    return Ok(Batch {
                        retired,
                        delivered,
                        stop: BatchStop::Decode(input),
                    });
                }
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
                    if let Phase::Timestamp {
                        sequence,
                        value: None,
                        ..
                    } = self.phase
                    {
                        return Ok(Batch {
                            retired,
                            delivered,
                            stop: BatchStop::Timestamp { sequence },
                        });
                    }
                    if let Phase::PortIo {
                        request,
                        reply: None,
                        ..
                    } = self.phase
                    {
                        return Ok(Batch {
                            retired,
                            delivered,
                            stop: BatchStop::PortIo(request),
                        });
                    }
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
