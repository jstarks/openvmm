// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::operand::{self as scalar, ScalarStatus};
#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::{gsbase, near_call, xor32};
#[cfg(verus_keep_ghost)]
use super::super::shared::decode::{DecodeDecision, DecodeInput};
use super::*;

verus! {

pub open spec fn enable(s: State) -> (State, bool) {
    if s.phase is Ready && !s.external_decode {
        (State { external_decode: true, ..s }, true)
    } else { (s, false) }
}
pub open spec fn request(s: State) -> Option<DecodeInput> {
    match s.phase { Phase::Decode { input } => Some(input), _ => None }
}
pub open spec fn complete(s: State, sequence: u64, decision: DecodeDecision) -> (State, bool) {
    match s.phase {
        Phase::Decode { input } if input.sequence == sequence =>
            (State { phase: Phase::Admitted { input, decision }, ..s }, true),
        _ => (s, false),
    }
}
pub open spec fn valid_input(s: State, input: DecodeInput) -> bool {
    s.external_decode && 1 <= input.length <= 15 && input.sequence == s.decode_sequence
        && input.rip as int == s.core.cpu.rip
        && input.rip as int + input.length as int - 1 <= u64::MAX
}
pub open spec fn offer(s: State, a: u8, b: u8, c: u8, length: u8) -> (State, Tick) {
    if s.decode_sequence == u64::MAX {
        stop(s, EventDiagnostic::Instruction(PagedDiagnostic::DecodeExhausted))
    } else {
        let input = DecodeInput { sequence: (s.decode_sequence + 1) as u64,
            rip: s.core.cpu.rip as u64, length,
            bytes: [a, b, c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] };
        (State { phase: Phase::Decode { input }, decode_sequence: input.sequence, ..s },
            Tick::Decode(input))
    }
}
pub open spec fn extended(input: DecodeInput, value: u8, sequence: u64) -> DecodeInput {
    DecodeInput { length: (input.length + 1) as u8, sequence, bytes: [
        if input.length == 0 { value } else { input.bytes[0] },
        if input.length == 1 { value } else { input.bytes[1] },
        if input.length == 2 { value } else { input.bytes[2] },
        if input.length == 3 { value } else { input.bytes[3] },
        if input.length == 4 { value } else { input.bytes[4] },
        if input.length == 5 { value } else { input.bytes[5] },
        if input.length == 6 { value } else { input.bytes[6] },
        if input.length == 7 { value } else { input.bytes[7] },
        if input.length == 8 { value } else { input.bytes[8] },
        if input.length == 9 { value } else { input.bytes[9] },
        if input.length == 10 { value } else { input.bytes[10] },
        if input.length == 11 { value } else { input.bytes[11] },
        if input.length == 12 { value } else { input.bytes[12] },
        if input.length == 13 { value } else { input.bytes[13] },
        if input.length == 14 { value } else { input.bytes[14] },
    ], ..input }
}
pub open spec fn append(s: State, value: u8) -> (State, Tick) {
    if s.decode_sequence == u64::MAX {
        stop(s, EventDiagnostic::Instruction(PagedDiagnostic::DecodeExhausted))
    } else {
        let input = match s.phase { Phase::DecodeFetch { input } => input,
            _ => arbitrary() };
        let next = extended(input, value, (s.decode_sequence + 1) as u64);
        (State { phase: Phase::Decode { input: next }, decode_sequence: next.sequence, ..s },
            Tick::Decode(next))
    }
}
pub open spec fn retired(s: State, core: c::State) -> (State, Tick) {
    (State { core, phase: Phase::Ready, shadow: false, handler_pending: false, ..s }, Tick::Retired(false))
}
pub open spec fn admitted(s: State) -> (State, Tick) {
    let (input, decision) = match s.phase { Phase::Admitted { input, decision } => (input, decision),
        _ => arbitrary() };
    match decision {
        DecodeDecision::Entry(instruction) => super::entry::execute(s, instruction, input.length),
        DecodeDecision::More => {
            if input.length == 15 { entry(s, Event::GeneralProtection) }
            else if input.rip as int + input.length as int > u64::MAX {
                stop(s, EventDiagnostic::Instruction(PagedDiagnostic::FetchWrap))
            } else {
                (fetch(s, (input.rip + input.length) as u64, Phase::DecodeFetch { input }), Tick::Pending)
            }
        },
        DecodeDecision::Rejected => stop(s, EventDiagnostic::Instruction(PagedDiagnostic::DecodeRejected)),
        DecodeDecision::InvalidOpcode => entry(s, Event::InvalidOpcode),
        DecodeDecision::Overlong => entry(s, Event::GeneralProtection),
        DecodeDecision::Unsupported => stop(s, EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
        DecodeDecision::Xor32 { dst, src } => {
            let result = xor32::transition(s.core.cpu.gpr.map(|i: int, value: int| value as u64),
                s.core.cpu.rip as u64, s.core.cpu.flags & !0x10000u64, dst, src, input.length);
            match result.3 {
                ScalarStatus::Advanced => {
                    let cpu = model::State { gpr: result.0.map(|i: int, value: u64| value as int),
                        rip: result.1 as int, flags: result.2 };
                    retired(s, c::boundary_commit(s.core, cpu, true).0)
                },
                ScalarStatus::DebugRequired => stop(s, EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired)),
                _ => stop(s, EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
            }
        },
        DecodeDecision::Wrmsr => if s.apic_id is Some
            && (((s.core.cpu.gpr[1] as u64)&0xffff_ffffu64)==0x1b
                || 0x800<=((s.core.cpu.gpr[1] as u64)&0xffff_ffffu64)<=0x8ff) {
            control_io::start(s,super::super::shared::control_io::ControlAccess::WriteMsr {
                number:(s.core.cpu.gpr[1] as u64) as u32,
                value:((s.core.cpu.gpr[0] as u64)&0xffff_ffffu64)|(((s.core.cpu.gpr[2] as u64)&0xffff_ffffu64)<<32),
            },input.length)
        } else if ((s.core.cpu.gpr[1] as u64)&0xffff_ffffu64==0x49u64
            && !super::super::memory_core::cpu_core::profile::PRED_CMD_AVAILABLE)
            || super::super::memory_core::cpu_core::profile::absent_core_pmu(
                (s.core.cpu.gpr[1] as u64)&0xffff_ffffu64) {
            if s.core.cpu.flags&0x100u64!=0 {
                stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))
            } else {entry(s,Event::GeneralProtection)}
        } else if (s.core.cpu.gpr[1] as u64)&0xffff_ffffu64==0xc000_0080u64 {
            privilege::write_efer(s,input.length)
        } else {match s.system {
            None => stop(s, EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
            Some(system) => {
                if (s.core.cpu.gpr[1] as u64)&0xffff_ffffu64==0xc0011029
                    || (s.core.cpu.gpr[1] as u64)&0xffff_ffffu64==0xc001001f
                    || super::super::memory_core::cpu_core::privilege::model::read_entry(system.entry,
                    (s.core.cpu.gpr[1] as u64)&0xffff_ffffu64) is Some {
                    privilege::write_entry_msr(s,input.length)
                } else {
                let result = gsbase::transition(system, s.core.cpu.rip as u64,
                    s.core.cpu.flags & !0x10000u64, s.core.cpu.gpr[0] as u64,
                    s.core.cpu.gpr[1] as u64, s.core.cpu.gpr[2] as u64, input.length);
                match result.2 {
                    gsbase::Status::Advanced => {
                        let cpu = model::State { rip: result.1 as int,
                            flags: s.core.cpu.flags & !0x10000u64, ..s.core.cpu };
                        let next = retired(s, c::boundary_commit(s.core, cpu, true).0).0;
                        (State { system: Some(result.0), ..next }, Tick::Retired(true))
                    },
                    gsbase::Status::GeneralProtection => entry(s, Event::GeneralProtection),
                    gsbase::Status::DebugRequired => stop(s, EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired)),
                    _ => stop(s, EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                }
                }
            },
        }},
        DecodeDecision::NearCall { displacement } => {
            match near_call::plan(s.core.cpu.rip as u64, s.core.cpu.gpr[4] as u64,
                s.core.cpu.flags & !0x10000u64, displacement, input.length) {
                near_call::Plan::Ready { target, stack, return_address } =>
                    (word(s, stack, WordAccess::Write(return_address), Phase::NearCall { target, stack }), Tick::Pending),
                near_call::Plan::DebugRequired => stop(s, EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired)),
                _ => stop(s, EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
            }
        },
        DecodeDecision::Scalar { dst, source } => {
            let result = scalar::model::commit(s.core.cpu.gpr.map(|i: int, value: int| value as u64),
                s.core.cpu.rip as u64, s.core.cpu.flags & !0x10000u64, dst, source, input.length);
            match result.2 {
                ScalarStatus::Advanced => {
                    let cpu = model::State { gpr: result.0.map(|i: int, value: u64| value as int),
                        rip: result.1 as int, flags: s.core.cpu.flags & !0x10000u64 };
                    retired(s, c::boundary_commit(s.core, cpu, true).0)
                },
                ScalarStatus::DebugRequired => stop(s, EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired)),
                _ => stop(s, EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
            }
        },
        DecodeDecision::Legacy => {
            if input.length != 3 || super::super::memory_model::decode(input.bytes[0], input.bytes[1], input.bytes[2]) is Unsupported {
                stop(s, EventDiagnostic::Instruction(PagedDiagnostic::Unsupported))
            } else if s.core.cpu.flags & 0x100u64 != 0 {
                stop(s, EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))
            } else {
                let cpu = model::State { flags: s.core.cpu.flags & !0x10000u64, ..s.core.cpu };
                let prepared = c::boundary_commit(s.core, cpu, false).0;
                let one = c::decoded(prepared, input.bytes[0], input.bytes[1], input.bytes[2]);
                match one.1 {
                    CpuTick::Retired => retired(s, one.0),
                    _ => (State { core: one.0, phase: Phase::Ordinary { flags: s.core.cpu.flags }, ..s }, Tick::Pending),
                }
            }
        },
    }
}

}
