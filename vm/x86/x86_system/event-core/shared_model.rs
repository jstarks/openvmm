// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::Tables;
use super::memory_core::cpu_core::system::SystemState;
#[cfg(verus_keep_ghost)]
use super::memory_core::cpu_core::{descriptor, exception};
#[cfg(verus_keep_ghost)]
use super::mmu_core::shared::Request;
#[cfg(verus_keep_ghost)]
use super::mmu_core::shared_model as m;
#[cfg(verus_keep_ghost)]
use super::paged_core::shared::Tick as CpuTick;
use super::paged_core::shared_model as c;
use super::shared::Phase;
#[cfg(verus_keep_ghost)]
use super::shared::{ReturnWords, Tick};
#[cfg(verus_keep_ghost)]
use super::{
    Event, EventDiagnostic, Injection, MmuResult, PagedDiagnostic, Stage, StepOutcome, WordAccess,
    WordResult, event_model as e, mmu_model, model,
};
use vstd::prelude::*;
#[path = "shared_alu_model.rs"]
pub mod alu;
#[path = "shared_control_model.rs"]
pub mod control_io;
#[path = "shared_decode_model.rs"]
pub mod decode;
#[path = "shared_entry_model.rs"]
pub mod entry;
#[path = "shared_privilege_model.rs"]
pub mod privilege;
#[path = "shared_repeat_model.rs"]
pub mod repeat;

verus! {

pub struct State {
    pub core: c::State, pub tables: Tables, pub phase: Phase,
    pub pending: Option<u8>, pub shadow: bool, pub halted: bool, pub handler_pending: bool,
    pub external_decode: bool, pub decode_sequence: u64,
    pub system: Option<SystemState>,
    pub fp_restore:Option<super::memory_core::cpu_core::system::LegacyFpState>,
    pub apic_id:Option<u32>,
}
pub open spec fn configure_system(s: State, system: SystemState) -> (State, bool) {
    if s.phase is Ready && super::memory_core::cpu_core::system::model::supported(system) {
        (State { system: Some(system), ..s }, true)
    } else { (s, false) }
}
pub open spec fn visible_cpu(s: State) -> model::State {
    match s.phase { Phase::Ordinary { flags } => model::State { flags, ..s.core.cpu },
        _ => s.core.cpu }
}
pub open spec fn io_permitted(s:State)->bool {
    match s.phase {
        Phase::Ordinary {..}=>true,
        Phase::EntryMemory {task,..}=>task is Load || task is Store,
        _=>false,
    }
}
pub open spec fn io_operand(s: State) -> Option<super::mmu_core::shared::io::Operand> {
    if io_permitted(s) { c::io_operand(s.core) } else { None }
}
pub open spec fn route_io(s: State) -> (State, super::mmu_core::shared::io::IoRoute) {
    if io_permitted(s) {
        let (core, result) = c::route_io(s.core);
        (State { core, ..s }, result)
    } else { (s, super::mmu_core::shared::io::IoRoute::NotReady) }
}
pub open spec fn complete_io(s: State, sequence: u64, reply: super::mmu_core::shared::io::IoReply) -> (State, bool) {
    if io_permitted(s) {
        let (core, accepted) = c::complete_io(s.core, sequence, reply);
        (State { core, ..s }, accepted)
    } else { (s, false) }
}
pub open spec fn stop(s: State, reason: EventDiagnostic) -> (State, Tick) {
    (State { phase: Phase::Stopped { reason }, ..s }, Tick::Stopped(reason))
}
pub open spec fn inject(s: State, vector: u8) -> (State, Injection) {
    match s.phase {
        Phase::Stopped { reason } => (s, Injection::Stopped(reason)),
        _ => if vector < 32 { (s, Injection::InvalidVector) }
            else if s.pending is Some { (s, Injection::Busy) }
            else { (State { pending: Some(vector), ..s }, Injection::Queued) },
    }
}
pub open spec fn respond(s: State, reply: super::mmu_core::shared::Reply) -> (State, bool) {
    let response = m::respond(s.core.mmu, reply);
    (State { core: c::State { mmu: response.0, ..s.core }, ..s }, response.1)
}
pub open spec fn word(s: State, address: u64, request: WordAccess, phase: Phase) -> State {
    State { core: c::boundary_begin(s.core, address, Some(request)).0, phase, ..s }
}
pub open spec fn fetch(s: State, address: u64, phase: Phase) -> State {
    State { core: c::boundary_begin(s.core, address, None).0, phase, ..s }
}
pub open spec fn fetch_next(s:State,address:u64,phase:Phase)->State {
    State {core:c::boundary_fetch_next(s.core,address).0,phase,..s}
}
pub open spec fn tables_supported(t: Tables, system: Option<SystemState>) -> bool {
    if system is None { e::tables_supported(t) }
    else { t.idt_base % 16 == 0 && t.gdt_base % 8 == 0 }
}
pub open spec fn descriptor_address(t: Tables, selector: u16) -> bool {
    selector != 0 && selector & 7u16 == 0
        && selector as int + 7 <= t.gdt_limit as int
        && t.gdt_base as int + selector as int + 7 <= u64::MAX
}
pub open spec fn return_image(w: ReturnWords, t: Tables, system: Option<SystemState>) -> bool {
    (system is Some || (w.cs == 8 && w.ss == 16))
        && w.cs <= u16::MAX && w.ss <= u16::MAX
        && descriptor_address(t, w.cs as u16)
        && (w.ss == 0 || descriptor_address(t, w.ss as u16))
        && e::flags_supported(w.flags) && mmu_model::canonical(w.ip as int)
        && mmu_model::canonical(w.rsp as int)
}
pub open spec fn entry_profile(cpu: model::State, t: Tables, event: Event,
    system: Option<SystemState>) -> bool {
    e::flags_supported(cpu.flags) && tables_supported(t, system)
        && mmu_model::canonical(cpu.rip) && mmu_model::canonical(cpu.gpr[4])
        && cpu.gpr[4] / 16 * 16 >= if e::has_error_code(event) { 48int } else { 40int }
}
pub open spec fn entry(s: State, event: Event) -> (State, Tick) {
    if s.handler_pending {
        stop(s, EventDiagnostic::HandlerFault { vector: e::vector(event), code: e::error(event) as u8 })
    } else if event is External && e::vector(event) < 32 {
        stop(s, EventDiagnostic::InterruptWindow)
    } else if !entry_profile(s.core.cpu, s.tables, event, s.system) {
        stop(s, EventDiagnostic::Profile)
    } else {
        let offset = e::vector(event) as int * 16;
        if offset + 15 > s.tables.idt_limit as int || s.tables.idt_base as int + offset + 15 > u64::MAX {
            stop(s, EventDiagnostic::Descriptor(Stage::Idt))
        } else {
            let address = (s.tables.idt_base as int + offset) as u64;
            (word(s, address, WordAccess::Read, Phase::GateLow { event, address }), Tick::Pending)
        }
    }
}
pub open spec fn iret(s: State) -> (State, Tick) {
    if !e::flags_supported(s.core.cpu.flags) || !tables_supported(s.tables, s.system)
        || s.core.cpu.gpr[4] > u64::MAX - 40 {
        stop(s, EventDiagnostic::Profile)
    } else {
        (word(s, s.core.cpu.gpr[4] as u64, WordAccess::Read,
            Phase::Pop { index: 0, words: ReturnWords { ip: 0, cs: 0, flags: 0, rsp: 0, ss: 0 } }), Tick::Pending)
    }
}
pub open spec fn byte(s: State, value: u8) -> (State, Tick) {
    let cpu = s.core.cpu;
    match s.phase {
        Phase::First => {
            if value == 0xfa || value == 0xfb || value == 0xf4 {
                let flags = (cpu.flags & !0x10000u64);
                let next = model::State { flags: if value == 0xfa { flags & !0x200u64 }
                    else if value == 0xfb { flags | 0x200u64 } else { flags },
                    rip: (cpu.rip + 1) % 18446744073709551616int, ..cpu };
                (State { core: c::boundary_commit(s.core, next, true).0, phase: Phase::Ready,
                    shadow: value == 0xfb && cpu.flags & 0x200u64 == 0,
                    halted: value == 0xf4, handler_pending: false, ..s }, Tick::Retired(false))
            } else if s.external_decode && value != 0x48 && value != 0x0f {
                decode::offer(s, value, 0, 0, 1)
            } else if value != 0x0f && (value < 0x48 || value > 0x4f) {
                stop(s, EventDiagnostic::Instruction(PagedDiagnostic::Unsupported))
            } else if cpu.rip == u64::MAX {
                stop(s, EventDiagnostic::Instruction(PagedDiagnostic::FetchWrap))
            } else {
                (fetch_next(s, (cpu.rip + 1) as u64, Phase::Second { first: value }), Tick::Pending)
            }
        },
        Phase::Second { first } => {
            if first == 0x48 && value == 0xcf { iret(s) }
            else if s.external_decode && (first != 0x0f || value != 1) {
                decode::offer(s, first, value, 0, 2)
            }
            else if first != 0x0f {
                (State { core: c::boundary_commit(s.core,
                    model::State { flags: cpu.flags & !0x10000u64, ..cpu }, true).0,
                    phase: Phase::Ordinary { flags: cpu.flags }, ..s }, Tick::Pending)
            } else if value != 1 {
                stop(s, EventDiagnostic::Instruction(PagedDiagnostic::Unsupported))
            } else if cpu.rip == u64::MAX - 1 {
                stop(s, EventDiagnostic::Instruction(PagedDiagnostic::FetchWrap))
            } else { (fetch_next(s, (cpu.rip + 2) as u64, Phase::Third), Tick::Pending) }
        },
        Phase::Third => {
            if s.external_decode && value != 0x3f {
                decode::offer(s, 0x0f, 1, value, 3)
            } else if value != 0x3f || !mmu_model::canonical(cpu.gpr[7]) {
                stop(s, EventDiagnostic::Instruction(PagedDiagnostic::Unsupported))
            } else {
                let invalidated = c::State { mmu: m::State {
                    inner: mmu_model::invalidate(s.core.mmu.inner, cpu.gpr[7]),
                    phase: super::mmu_core::shared::Phase::Idle, ..s.core.mmu }, ..s.core };
                let next = model::State { flags: cpu.flags & !0x10000u64,
                    rip: (cpu.rip + 3) % 18446744073709551616int, ..cpu };
                (State { core: c::boundary_commit(invalidated, next, true).0,
                    phase: Phase::Ready, handler_pending: false, shadow: false, ..s }, Tick::Retired(true))
            }
        },
        _ => (s, Tick::Waiting),
    }
}
pub open spec fn frame_word(cpu: model::State, system: Option<SystemState>, event: Event, index: u8) -> u64 {
    exception::model::frame_word(cpu.rip as u64, cpu.gpr[4] as u64, cpu.flags,
        exception::model::selectors(system), e::has_error_code(event),
        event is External || event is Breakpoint, e::error(event) as u8, index)
}
pub open spec fn commit_return(s: State, words: ReturnWords, cs: SegmentState,
    ss: SegmentState) -> (State, Tick) {
    let cpu = model::State { gpr: s.core.cpu.gpr.update(4, words.rsp as int),
        flags: words.flags, rip: words.ip as int };
    (State { core: c::boundary_commit(s.core, cpu, true).0, phase: Phase::Ready,
        handler_pending: false, shadow: false,
        system: match s.system {
            Some(system) => Some(SystemState { cs, ss, ..system }), None => None,
        }, ..s }, Tick::Retired(true))
}
pub open spec fn word_location(s: State) -> (Stage, u64) {
    match s.phase {
        Phase::GateLow { address, .. } => (Stage::Idt, address),
        Phase::GateHigh { event, .. } => (Stage::Idt, (s.tables.idt_base as int + e::vector(event) as int * 16 + 8) as u64),
        Phase::Code { selector, .. } => (Stage::Code, (s.tables.gdt_base as int + selector as int) as u64),
        Phase::ReturnCode { words } => (Stage::Code, (s.tables.gdt_base as int + words.cs as int) as u64),
        Phase::ReturnStack { words, .. } => (Stage::Stack, (s.tables.gdt_base as int + words.ss as int) as u64),
        Phase::Push { event, stack, index, .. } => (Stage::Push,
            (stack as int - 8 * (index as int - if e::has_error_code(event) { 0int } else { 1int } + 1)) as u64),
        Phase::Pop { index, .. } => (Stage::Pop, (s.core.cpu.gpr[4] + index as int * 8) as u64),
        Phase::NearCall { stack, .. } => (Stage::Push, stack),
        Phase::EntryMemory { address, .. } => (Stage::Stack, address),
        _ => (Stage::Idt, 0),
    }
}
pub open spec fn filled(w: ReturnWords, index: u8, value: u64) -> ReturnWords {
    match index {
        0 => ReturnWords { ip: value, ..w }, 1 => ReturnWords { cs: value, ..w },
        2 => ReturnWords { flags: value, ..w }, 3 => ReturnWords { rsp: value, ..w },
        _ => ReturnWords { ss: value, ..w },
    }
}
pub open spec fn word_value(s: State, value: u64) -> (State, Tick) {
    let cpu = s.core.cpu;
    match s.phase {
        Phase::EntryMemory { .. } => entry::value(s, value),
        Phase::NearCall { target, stack } => {
            let next = model::State { gpr: cpu.gpr.update(4, stack as int),
                rip: target as int, flags: cpu.flags & !0x10000u64 };
            decode::retired(s, c::boundary_commit(s.core, next, true).0)
        },
        Phase::GateLow { event, address } =>
            (word(s, (address + 8) as u64, WordAccess::Read, Phase::GateHigh { event, low: value }), Tick::Pending),
        Phase::GateHigh { event, low } => {
            match exception::model::gate(low, value) {
                None => stop(s, EventDiagnostic::Descriptor(Stage::Idt)),
                Some(gate) => if s.system is None && gate.selector != 8 {
                    stop(s, EventDiagnostic::Descriptor(Stage::Idt))
                } else if !descriptor_address(s.tables, gate.selector) {
                    stop(s, EventDiagnostic::Descriptor(Stage::Code))
                } else {
                    (word(s, (s.tables.gdt_base as int + gate.selector as int) as u64, WordAccess::Read,
                        Phase::Code { event, low, target: gate.target, selector: gate.selector }), Tick::Pending)
                },
            }
        },
        Phase::Code { event, low, target, selector } => {
            match descriptor::model::load_code(value, selector) {
                None => stop(s, EventDiagnostic::Descriptor(Stage::Code)),
                Some(cs) => {
                    let index = if e::has_error_code(event) { 0u8 } else { 1u8 };
                    let stack = (cpu.gpr[4] / 16 * 16) as u64;
                    (word(s, (stack - 8) as u64, WordAccess::Write(frame_word(cpu, s.system, event, index)),
                        Phase::Push { event, low, target, cs, stack, index }), Tick::Pending)
                },
            }
        },
        Phase::Push { event, low, target, cs, stack, index } => {
            if index == 5 {
                let count = if e::has_error_code(event) { 6int } else { 5int };
                let next = model::State { gpr: cpu.gpr.update(4, stack as int - count * 8),
                    flags: e::live_flags(cpu.flags, low), rip: target as int };
                (State { core: c::boundary_commit(s.core, next, true).0, phase: Phase::Ready,
                    handler_pending: true, shadow: false, halted: false,
                    system: match s.system {
                        Some(system) => Some(SystemState { cs, ..system }), None => None,
                    },
                    pending: if event is External { None } else { s.pending }, ..s }, Tick::Delivered(e::vector(event)))
            } else {
                let next = (index + 1) as u8;
                let start = if e::has_error_code(event) { 0int } else { 1int };
                (word(s, (stack as int - 8 * (next as int - start + 1)) as u64,
                    WordAccess::Write(frame_word(cpu, s.system, event, next)),
                    Phase::Push { event, low, target, cs, stack, index: next }), Tick::Pending)
            }
        },
        Phase::Pop { index, words } => {
            let w = filled(words, index, value);
            if index < 4 {
                (word(s, (cpu.gpr[4] + (index as int + 1) * 8) as u64, WordAccess::Read,
                    Phase::Pop { index: (index + 1) as u8, words: w }), Tick::Pending)
            } else if !return_image(w, s.tables, s.system) {
                stop(s, EventDiagnostic::ReturnImage)
            } else {
                (word(s, (s.tables.gdt_base as int + w.cs as int) as u64, WordAccess::Read,
                    Phase::ReturnCode { words: w }), Tick::Pending)
            }
        },
        Phase::ReturnCode { words } => match descriptor::model::load_code(value, words.cs as u16) {
            None => stop(s, EventDiagnostic::Descriptor(Stage::Code)),
            Some(cs) => if words.ss == 0 {
                commit_return(s, words, cs, exception::model::stack(0, 0).unwrap())
            } else {
                (word(s, (s.tables.gdt_base as int + words.ss as int) as u64, WordAccess::Read,
                    Phase::ReturnStack { words, cs }), Tick::Pending)
            },
        },
        Phase::ReturnStack { words, cs } => match exception::model::stack(value, words.ss as u16) {
            None => stop(s, EventDiagnostic::Descriptor(Stage::Stack)),
            Some(ss) => commit_return(s, words, cs, ss),
        },
        _ => (s, Tick::Waiting),
    }
}
pub open spec fn advance(s: State) -> (State, Tick) {
    match s.phase {
        Phase::Repeat {width,length}=>repeat::execute(s,width,length),
        Phase::RepeatMove {width,length}=>repeat::execute_move(s,width,length),
        Phase::Decode { input } => (s, Tick::Decode(input)),
        Phase::Admitted { .. } => decode::admitted(s),
        Phase::PortIo { .. } => entry::finish_port_io(s),
        Phase::Timestamp {..}=>entry::finish_timestamp(s),
        Phase::ControlIo {..}=>control_io::finish(s),
        Phase::DecodeFetch { input } => match m::request(s.core.mmu) {
            Request::Complete(report) => match report.result {
                MmuResult::Success(value) => decode::append(s, value),
                MmuResult::PageFault(code) => entry(s, Event::PageFault(code)),
                MmuResult::GeneralProtection => entry(s, Event::GeneralProtection),
                other => stop(s, EventDiagnostic::Fetch {
                    address: (input.rip + input.length) as u64, byte_result: other }),
            },
            _ => (s, Tick::Waiting),
        },
        Phase::Stopped { reason } => (s, Tick::Stopped(reason)),
        Phase::Ready => {
            if !e::flags_supported(s.core.cpu.flags) { stop(s, EventDiagnostic::Profile) }
            else if s.pending is Some && !s.shadow && s.core.cpu.flags & 0x200u64 != 0 {
                entry(State { core: c::boundary(s.core).0, ..s }, Event::External(s.pending.unwrap()))
            } else if s.halted { (s, Tick::Halted) }
            else {
                let next = State { core: c::boundary(s.core).0, ..s };
                (fetch(next, s.core.cpu.rip as u64, Phase::First), Tick::Pending)
            }
        },
        Phase::Ordinary { flags } => {
            let one = c::advance(s.core);
            let next = State { core: one.0, ..s };
            match one.1 {
                CpuTick::Pending => (next, Tick::Pending),
                CpuTick::Waiting => (next, Tick::Waiting),
                CpuTick::Retired => (State { phase: Phase::Ready,
                    shadow: false, handler_pending: false, ..next }, Tick::Retired(false)),
                CpuTick::Stopped(outcome) => {
                    let boundary = c::boundary(next.core).0;
                    let restored = model::State { flags, ..boundary.cpu };
                    let next = State { core: c::boundary_commit(boundary, restored, false).0, ..next };
                    match outcome {
                        StepOutcome::PageFault { code, .. } => entry(next, Event::PageFault(code)),
                        StepOutcome::GeneralProtection { .. } => entry(next, Event::GeneralProtection),
                        StepOutcome::Diagnostic(d) => stop(next, EventDiagnostic::Instruction(d)),
                        _ => stop(next, EventDiagnostic::Profile),
                    }
                },
                CpuTick::Boundary => (next, Tick::Waiting),
            }
        },
        Phase::First | Phase::Second { .. } | Phase::Third => match m::request(s.core.mmu) {
            Request::Complete(report) => match report.result {
                MmuResult::Success(v) => byte(s, v),
                MmuResult::PageFault(code) => entry(s, Event::PageFault(code)),
                MmuResult::GeneralProtection => entry(s, Event::GeneralProtection),
                other => stop(s, EventDiagnostic::Fetch { address: (s.core.cpu.rip + match s.phase {
                    Phase::First => 0int, Phase::Second { .. } => 1int, _ => 2int }) as u64, byte_result: other }),
            },
            _ => (s, Tick::Waiting),
        },
        _ => match m::request(s.core.mmu) {
            Request::CompleteWord { report } => match report.result {
                WordResult::Success(v) => word_value(s, v),
                result => if result is PageFault && (s.phase is NearCall || s.phase is EntryMemory)
                    && !(match s.phase {
                        Phase::EntryMemory { task, .. } => matches!(task,
                            super::shared::entry::MemoryTask::FarTarget { .. }
                            | super::shared::entry::MemoryTask::FarSelector { .. }
                            | super::shared::entry::MemoryTask::FarCode { .. }),
                        _ => false,
                    }) {
                    entry(s, Event::PageFault(match result { WordResult::PageFault(code) => code, _ => 0u8 }))
                } else {
                    stop(s, EventDiagnostic::Memory { stage: word_location(s).0, address: word_location(s).1, result })
                },
            },
            _ => (s, Tick::Waiting),
        },
    }
}

}
#[cfg(verus_keep_ghost)]
use super::memory_core::cpu_core::system::SegmentState;
