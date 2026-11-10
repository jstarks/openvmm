// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::Tables;
use super::memory_core::cpu_core::system::SystemState;
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
#[path = "shared_decode_model.rs"]
pub mod decode;

verus! {

pub struct State {
    pub core: c::State, pub tables: Tables, pub phase: Phase,
    pub pending: Option<u8>, pub shadow: bool, pub halted: bool, pub handler_pending: bool,
    pub external_decode: bool, pub decode_sequence: u64,
    pub system: Option<SystemState>,
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
pub open spec fn io_operand(s: State) -> Option<super::mmu_core::shared::io::Operand> {
    if s.phase is Ordinary { c::io_operand(s.core) } else { None }
}
pub open spec fn route_io(s: State) -> (State, super::mmu_core::shared::io::IoRoute) {
    if s.phase is Ordinary {
        let (core, result) = c::route_io(s.core);
        (State { core, ..s }, result)
    } else { (s, super::mmu_core::shared::io::IoRoute::NotReady) }
}
pub open spec fn complete_io(s: State, sequence: u64, reply: super::mmu_core::shared::io::IoReply) -> (State, bool) {
    if s.phase is Ordinary {
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
pub open spec fn entry_profile(cpu: model::State, t: Tables, event: Event) -> bool {
    e::flags_supported(cpu.flags) && e::tables_supported(t)
        && mmu_model::canonical(cpu.rip) && mmu_model::canonical(cpu.gpr[4])
        && cpu.gpr[4] / 16 * 16 >= if e::has_error_code(event) { 48int } else { 40int }
}
pub open spec fn entry(s: State, event: Event) -> (State, Tick) {
    if s.handler_pending {
        stop(s, EventDiagnostic::HandlerFault { vector: e::vector(event), code: e::error(event) as u8 })
    } else if event is External && e::vector(event) < 32 {
        stop(s, EventDiagnostic::InterruptWindow)
    } else if !entry_profile(s.core.cpu, s.tables, event) {
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
    if !e::flags_supported(s.core.cpu.flags) || !e::tables_supported(s.tables)
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
                (fetch(s, (cpu.rip + 1) as u64, Phase::Second { first: value }), Tick::Pending)
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
            } else { (fetch(s, (cpu.rip + 2) as u64, Phase::Third), Tick::Pending) }
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
pub open spec fn frame_word(cpu: model::State, event: Event, index: u8) -> u64 {
    if event is External {
        match index { 0 => 0, 1 => 16, 2 => cpu.gpr[4] as u64, 3 => cpu.flags, 4 => 8, _ => cpu.rip as u64 }
    } else if event is InvalidOpcode {
        match index { 0 => 0, 1 => 16, 2 => cpu.gpr[4] as u64, 3 => cpu.flags | 0x10000u64, 4 => 8, _ => cpu.rip as u64 }
    } else {
        match index { 0 => 16, 1 => cpu.gpr[4] as u64, 2 => cpu.flags | 0x10000u64,
            3 => 8, 4 => cpu.rip as u64, _ => e::error(event) }
    }
}
pub open spec fn word_location(s: State) -> (Stage, u64) {
    match s.phase {
        Phase::GateLow { address, .. } => (Stage::Idt, address),
        Phase::GateHigh { event, .. } => (Stage::Idt, (s.tables.idt_base as int + e::vector(event) as int * 16 + 8) as u64),
        Phase::Code { .. } | Phase::ReturnCode { .. } => (Stage::Code, (s.tables.gdt_base as int + 8) as u64),
        Phase::ReturnStack { .. } => (Stage::Stack, (s.tables.gdt_base as int + 16) as u64),
        Phase::Push { event, stack, index, .. } => (Stage::Push,
            (stack as int - 8 * (index as int - if e::has_error_code(event) { 0int } else { 1int } + 1)) as u64),
        Phase::Pop { index, .. } => (Stage::Pop, (s.core.cpu.gpr[4] + index as int * 8) as u64),
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
        Phase::GateLow { event, address } =>
            (word(s, (address + 8) as u64, WordAccess::Read, Phase::GateHigh { event, low: value }), Tick::Pending),
        Phase::GateHigh { event, low } => {
            if !e::gate_supported(low, value) || !mmu_model::canonical(e::gate_target(low, value)) {
                stop(s, EventDiagnostic::Descriptor(Stage::Idt))
            } else {
                (word(s, (s.tables.gdt_base as int + 8) as u64, WordAccess::Read,
                    Phase::Code { event, low, target: e::gate_target(low, value) as u64 }), Tick::Pending)
            }
        },
        Phase::Code { event, low, target } => {
            if value != 0x00af9b000000ffffu64 { stop(s, EventDiagnostic::Descriptor(Stage::Code)) }
            else {
                let index = if e::has_error_code(event) { 0u8 } else { 1u8 };
                let stack = (cpu.gpr[4] / 16 * 16) as u64;
                (word(s, (stack - 8) as u64, WordAccess::Write(frame_word(cpu, event, index)),
                    Phase::Push { event, low, target, stack, index }), Tick::Pending)
            }
        },
        Phase::Push { event, low, target, stack, index } => {
            if index == 5 {
                let count = if e::has_error_code(event) { 6int } else { 5int };
                let next = model::State { gpr: cpu.gpr.update(4, stack as int - count * 8),
                    flags: e::live_flags(cpu.flags, low), rip: target as int };
                (State { core: c::boundary_commit(s.core, next, true).0, phase: Phase::Ready,
                    handler_pending: true, shadow: false, halted: false,
                    pending: if event is External { None } else { s.pending }, ..s }, Tick::Delivered(e::vector(event)))
            } else {
                let next = (index + 1) as u8;
                let start = if e::has_error_code(event) { 0int } else { 1int };
                (word(s, (stack as int - 8 * (next as int - start + 1)) as u64,
                    WordAccess::Write(frame_word(cpu, event, next)),
                    Phase::Push { event, low, target, stack, index: next }), Tick::Pending)
            }
        },
        Phase::Pop { index, words } => {
            let w = filled(words, index, value);
            if index < 4 {
                (word(s, (cpu.gpr[4] + (index as int + 1) * 8) as u64, WordAccess::Read,
                    Phase::Pop { index: (index + 1) as u8, words: w }), Tick::Pending)
            } else if w.cs != 8 || w.ss != 16 || !e::flags_supported(w.flags)
                || !mmu_model::canonical(w.ip as int) || !mmu_model::canonical(w.rsp as int) {
                stop(s, EventDiagnostic::ReturnImage)
            } else {
                (word(s, (s.tables.gdt_base as int + 8) as u64, WordAccess::Read, Phase::ReturnCode { words: w }), Tick::Pending)
            }
        },
        Phase::ReturnCode { words } => if value != 0x00af9b000000ffffu64 {
            stop(s, EventDiagnostic::Descriptor(Stage::Code))
        } else {
            (word(s, (s.tables.gdt_base as int + 16) as u64, WordAccess::Read, Phase::ReturnStack { words }), Tick::Pending)
        },
        Phase::ReturnStack { words } => if value != 0x00cf93000000ffffu64 {
            stop(s, EventDiagnostic::Descriptor(Stage::Stack))
        } else {
            let next = model::State { gpr: cpu.gpr.update(4, words.rsp as int),
                flags: words.flags, rip: words.ip as int };
            (State { core: c::boundary_commit(s.core, next, true).0, phase: Phase::Ready,
                handler_pending: false, shadow: false, ..s }, Tick::Retired(true))
        },
        _ => (s, Tick::Waiting),
    }
}
pub open spec fn advance(s: State) -> (State, Tick) {
    match s.phase {
        Phase::Decode { input } => (s, Tick::Decode(input)),
        Phase::Admitted { .. } => decode::admitted(s),
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
                result => stop(s, EventDiagnostic::Memory { stage: word_location(s).0, address: word_location(s).1, result }),
            },
            _ => (s, Tick::Waiting),
        },
    }
}

}
