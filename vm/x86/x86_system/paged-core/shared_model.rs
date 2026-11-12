// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use super::mmu_core::shared::Request;
use super::shared::CpuPhase;
#[cfg(verus_keep_ghost)]
use super::shared::Tick;
#[cfg(verus_keep_ghost)]
use super::{
    Access, MmuResult, PagedDiagnostic, StepOutcome, WordAccess, WordResult, memory_core,
    memory_model, paged_model, word_model,
};
use super::{mmu_core::shared_model as mm, model};
use vstd::prelude::*;

verus! {

pub struct State { pub cpu: model::State, pub mmu: mm::State, pub phase: CpuPhase, pub user: bool }

pub open spec fn io_operand(s: State) -> Option<super::mmu_core::shared::io::Operand> {
    if s.phase is Data || s.phase is Boundary { mm::operand(s.mmu) } else { None }
}
pub open spec fn route_io(s: State) -> (State, super::mmu_core::shared::io::IoRoute) {
    if s.phase is Data || s.phase is Boundary {
        let (mmu, result) = mm::route_io(s.mmu);
        (State { mmu, ..s }, result)
    } else { (s, super::mmu_core::shared::io::IoRoute::NotReady) }
}
pub open spec fn complete_io(s: State, sequence: u64, reply: super::mmu_core::shared::io::IoReply) -> (State, bool) {
    if s.phase is Data || s.phase is Boundary {
        let (mmu, accepted) = mm::complete_io(s.mmu, sequence, reply);
        (State { mmu, ..s }, accepted)
    } else { (s, false) }
}

pub open spec fn boundary(s: State) -> (State, bool) {
    if (s.phase is Ready || s.phase is Stopped || s.phase is Boundary) && !mm::active(s.mmu.phase) {
        (State { phase: CpuPhase::Boundary, ..s }, true)
    } else { (s, false) }
}
pub open spec fn boundary_begin(s: State, address: u64, word: Option<WordAccess>) -> (State, bool) {
    if s.phase is Boundary && !mm::active(s.mmu.phase) {
        let access = match word { Some(w) => word_model::request(w), None => Access::Fetch };
        (State { mmu: mm::begin(s.mmu, address, access, false, word), ..s }, true)
    } else { (s, false) }
}
pub open spec fn boundary_commit(s: State, cpu: model::State, release: bool) -> (State, bool) {
    if s.phase is Boundary && !mm::active(s.mmu.phase) {
        (State { cpu, phase: if release { CpuPhase::Ready } else { CpuPhase::Boundary }, ..s }, true)
    } else { (s, false) }
}
pub open spec fn boundary_sized(s: State, address: u64, word: WordAccess, size: u8) -> (State, bool) {
    if s.phase is Boundary && !mm::active(s.mmu.phase) {
        (State { mmu: mm::sized(s.mmu, address, word, size), ..s }, true)
    } else { (s, false) }
}
pub open spec fn boundary_modify(s: State, address: u64,
    operation: super::memory_core::cpu_core::integer::Operation, source: u64, flags: u64,
    width: super::memory_core::cpu_core::operand::Width) -> (State, bool) {
    if s.phase is Boundary && !mm::active(s.mmu.phase) && mm::modify_admitted(address, operation, width) {
        (State { mmu: mm::modify_start(s.mmu, address, operation, source, flags, width, true), ..s }, true)
    } else { (s, false) }
}
pub open spec fn boundary_span(s: State, address: u64, word: WordAccess, size: u8) -> (State, bool) {
    if s.phase is Boundary && !mm::active(s.mmu.phase) {
        (State { mmu: mm::access_begin(s.mmu, address, word_model::request(word),
            false, Some(word), size, true), ..s }, true)
    } else { (s, false) }
}
pub open spec fn boundary_locked_modify(s:State,address:u64,
    operation:super::memory_core::cpu_core::integer::Operation,source:u64,flags:u64,
    width:super::memory_core::cpu_core::operand::Width)->(State,bool) {
    if s.phase is Boundary && !mm::active(s.mmu.phase) && mm::locked_admitted(address,operation,width) {
        (State {mmu:mm::locked_begin(s.mmu,address,operation,source,flags,width),..s},true)
    } else {(s,false)}
}
pub open spec fn boundary_reload(s: State, config: super::Config) -> (State, bool) {
    if s.phase is Boundary && !mm::active(s.mmu.phase) {
        (State { mmu: mm::State {
            inner: super::mmu_model::reload(s.mmu.inner, config),
            phase: super::mmu_core::shared::Phase::Idle, ..s.mmu }, ..s }, true)
    } else { (s, false) }
}
pub open spec fn boundary_exchange(s:State,address:u64,replacement:u64,
    width:super::memory_core::cpu_core::operand::Width)->(State,bool) {
    if s.phase is Boundary && !mm::active(s.mmu.phase) && mm::compare_admitted(address,width) {
        (State {mmu:mm::exchange_begin(s.mmu,address,replacement,width),..s},true)
    } else {(s,false)}
}
pub open spec fn boundary_compare_exchange(s:State,address:u64,expected:u64,replacement:u64,
    width:super::memory_core::cpu_core::operand::Width)->(State,bool) {
    if s.phase is Boundary && !mm::active(s.mmu.phase) && mm::compare_admitted(address,width) {
        (State {mmu:mm::compare_begin(s.mmu,address,expected,replacement,width),..s},true)
    } else {(s,false)}
}
pub open spec fn invalidate(s: State, va: u64) -> (State, bool) {
    if (s.phase is Ready || s.phase is Stopped || s.phase is Boundary) && !mm::active(s.mmu.phase) {
        (State { mmu: mm::State { inner: super::mmu_model::invalidate(s.mmu.inner, va as int),
            phase: super::mmu_core::shared::Phase::Idle, ..s.mmu }, ..s }, true)
    } else { (s, false) }
}

pub open spec fn stopped(s: State, outcome: StepOutcome) -> (State, Tick) {
    (State { phase: CpuPhase::Stopped { outcome }, ..s }, Tick::Stopped(outcome))
}
pub open spec fn fetch(s: State, offset: u64, phase: CpuPhase) -> (State, Tick) {
    (State { mmu: if offset==0 {mm::begin(s.mmu,s.cpu.rip as u64,Access::Fetch,s.user,None)}
        else {mm::begin_fetch_next(s.mmu,(s.cpu.rip+offset) as u64,s.user).0},
        phase, ..s }, Tick::Pending)
}
pub open spec fn boundary_fetch_next(s:State,address:u64)->(State,bool) {
    if s.phase is Boundary {
        let next=mm::begin_fetch_next(s.mmu,address,false);
        (State {mmu:next.0,..s},next.1)
    } else {(s,false)}
}
pub open spec fn decoded(s: State, rex: u8, opcode: u8, value: u8) -> (State, Tick) {
    let op = memory_model::decode(rex, opcode, value);
    match op {
        memory_model::Op::Alu(a) => (State { cpu: model::execute(s.cpu, a).0,
            phase: CpuPhase::Ready, ..s }, Tick::Retired),
        memory_model::Op::Unsupported =>
            stopped(s, StepOutcome::Diagnostic(PagedDiagnostic::Unsupported)),
        memory_model::Op::Load(reg, base) | memory_model::Op::Store(reg, base) => {
            let request = match op { memory_model::Op::Store(r, _) =>
                WordAccess::Write(s.cpu.gpr[r] as u64), _ => WordAccess::Read };
            let executable = match op { memory_model::Op::Load(_, _) =>
                memory_core::Op::Load { reg: reg as u8, base: base as u8 },
                _ => memory_core::Op::Store { reg: reg as u8, base: base as u8 } };
            (State { mmu: mm::access_begin(s.mmu, s.cpu.gpr[base] as u64,
                word_model::request(request), s.user, Some(request),8,true),
                phase: CpuPhase::Data { op: executable }, ..s }, Tick::Pending)
        },
    }
}
pub open spec fn byte(s: State, value: u8) -> (State, Tick) {
    match s.phase {
        CpuPhase::First => {
            if value < 0x48 || value > 0x4f {
                stopped(s, StepOutcome::Diagnostic(PagedDiagnostic::Unsupported))
            } else if s.cpu.rip == u64::MAX {
                stopped(s, StepOutcome::Diagnostic(PagedDiagnostic::FetchWrap))
            } else { fetch(s, 1, CpuPhase::Second { rex: value }) }
        },
        CpuPhase::Second { rex } => {
            if value != 0x01 && value != 0x11 && value != 0x8b && value != 0x89 {
                stopped(s, StepOutcome::Diagnostic(PagedDiagnostic::Unsupported))
            } else if s.cpu.rip == u64::MAX - 1 {
                stopped(s, StepOutcome::Diagnostic(PagedDiagnostic::FetchWrap))
            } else { fetch(s, 2, CpuPhase::Third { rex, opcode: value }) }
        },
        CpuPhase::Third { rex, opcode } => {
            decoded(s, rex, opcode, value)
        },
        _ => (s, Tick::Waiting),
    }
}
pub open spec fn advance(s: State) -> (State, Tick) {
    match s.phase {
        CpuPhase::Ready => if s.cpu.flags & 0x10100u64 != 0 {
            stopped(s, StepOutcome::Diagnostic(PagedDiagnostic::DebugRequired))
        } else { fetch(s, 0, CpuPhase::First) },
        CpuPhase::Stopped { outcome } => (s, Tick::Stopped(outcome)),
        CpuPhase::Boundary => (s, Tick::Boundary),
        CpuPhase::First | CpuPhase::Second { .. } | CpuPhase::Third { .. } => {
            match mm::request(s.mmu) {
                Request::Complete(report) => match report.result {
                    MmuResult::Success(v) => byte(s, v),
                    _ => stopped(s, paged_model::byte_outcome(report.result, s.mmu.va as int)),
                },
                _ => (s, Tick::Waiting),
            }
        },
        CpuPhase::Data { op } => match mm::request(s.mmu) {
            Request::CompleteWord { report } => match report.result {
                WordResult::Success(v) => (State { cpu: paged_model::commit(s.cpu, op@, v as int),
                    phase: CpuPhase::Ready, ..s }, Tick::Retired),
                _ => stopped(s, paged_model::word_outcome(report.result, s.mmu.va as int)),
            },
            _ => (s, Tick::Waiting),
        },
    }
}

}
