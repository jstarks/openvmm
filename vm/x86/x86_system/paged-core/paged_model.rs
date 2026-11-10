// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use crate::{Access, MmuResult, PagedDiagnostic, WordAccess, WordResult, memory_model, word_model};
use crate::{StepOutcome, mmu_model, model};
use vstd::prelude::*;

verus! {

pub struct State { pub cpu: model::State, pub mmu: mmu_model::State }
pub enum Fetched { Bytes(u8, u8, u8), Stopped(StepOutcome) }

pub open spec fn byte_outcome(r: MmuResult, address: int) -> StepOutcome {
    match r {
        MmuResult::Success(_) => StepOutcome::Advanced,
        MmuResult::PageFault(code) => StepOutcome::PageFault { code, address: address as u64 },
        MmuResult::GeneralProtection => StepOutcome::GeneralProtection { address: address as u64 },
        MmuResult::InvalidConfig => StepOutcome::Diagnostic(PagedDiagnostic::InvalidConfig),
        MmuResult::Backing => StepOutcome::Diagnostic(PagedDiagnostic::Backing),
        MmuResult::HugePage => StepOutcome::Diagnostic(PagedDiagnostic::HugePage),
        MmuResult::Ambiguous => StepOutcome::Diagnostic(PagedDiagnostic::Ambiguous),
    }
}
pub open spec fn word_outcome(r: WordResult, address: int) -> StepOutcome {
    match r {
        WordResult::Success(_) => StepOutcome::Advanced,
        WordResult::PageFault(code) => StepOutcome::PageFault { code, address: address as u64 },
        WordResult::GeneralProtection => StepOutcome::GeneralProtection { address: address as u64 },
        WordResult::InvalidConfig => StepOutcome::Diagnostic(PagedDiagnostic::InvalidConfig),
        WordResult::Backing => StepOutcome::Diagnostic(PagedDiagnostic::Backing),
        WordResult::HugePage => StepOutcome::Diagnostic(PagedDiagnostic::HugePage),
        WordResult::Ambiguous => StepOutcome::Diagnostic(PagedDiagnostic::Ambiguous),
        WordResult::CrossPage => StepOutcome::Diagnostic(PagedDiagnostic::DataCrossPage),
        WordResult::Wrap => StepOutcome::Diagnostic(PagedDiagnostic::DataWrap),
    }
}

#[verifier::opaque]
pub open spec fn fetch(s: mmu_model::State, b: Seq<u8>, base: int, ip: int, user: bool)
    -> (mmu_model::State, Seq<u8>, Fetched, nat) {
    let first = mmu_model::access(s, b, base, ip, Access::Fetch, user);
    match first.2 {
        MmuResult::Success(a) => {
            if a < 0x48 || a > 0x4f {
                (first.0, first.1, Fetched::Stopped(StepOutcome::Diagnostic(PagedDiagnostic::Unsupported)), first.3)
            } else if ip == 18446744073709551615int {
                (first.0, first.1, Fetched::Stopped(StepOutcome::Diagnostic(PagedDiagnostic::FetchWrap)), first.3)
            } else {
                let second = mmu_model::access(first.0, first.1, base, ip + 1, Access::Fetch, user);
                let reads = first.3 + second.3;
                match second.2 {
                    MmuResult::Success(op) => {
                        if op != 0x01 && op != 0x11 && op != 0x8b && op != 0x89 {
                            (second.0, second.1, Fetched::Stopped(StepOutcome::Diagnostic(PagedDiagnostic::Unsupported)), reads)
                        } else if ip == 18446744073709551614int {
                            (second.0, second.1, Fetched::Stopped(StepOutcome::Diagnostic(PagedDiagnostic::FetchWrap)), reads)
                        } else {
                            let third = mmu_model::access(second.0, second.1, base, ip + 2, Access::Fetch, user);
                            (third.0, third.1, match third.2 {
                                MmuResult::Success(c) => Fetched::Bytes(a, op, c),
                                r => Fetched::Stopped(byte_outcome(r, ip + 2)),
                            }, reads + third.3)
                        }
                    },
                    r => (second.0, second.1, Fetched::Stopped(byte_outcome(r, ip + 1)), reads),
                }
            }
        },
        r => (first.0, first.1, Fetched::Stopped(byte_outcome(r, ip)), first.3),
    }
}

pub open spec fn commit(s: model::State, op: memory_model::Op, value: int) -> model::State {
    model::State { gpr: match op {
        memory_model::Op::Load(reg, _) => s.gpr.update(reg, value),
        _ => s.gpr,
    }, flags: s.flags, rip: (s.rip + 3) % 18446744073709551616int }
}

#[verifier::opaque]
pub open spec fn step(s: State, b: Seq<u8>, base: int, user: bool)
    -> (State, Seq<u8>, StepOutcome, nat) {
    if s.cpu.flags & 0x10100u64 != 0 {
        (s, b, StepOutcome::Diagnostic(PagedDiagnostic::DebugRequired), 0)
    } else {
        let f = fetch(s.mmu, b, base, s.cpu.rip, user);
        match f.2 {
            Fetched::Stopped(o) => (State { mmu: f.0, ..s }, f.1, o, f.3),
            Fetched::Bytes(a, op, c) => {
                let decoded = memory_model::decode(a, op, c);
                match decoded {
                    memory_model::Op::Alu(alu) => (State { cpu: model::execute(s.cpu, alu).0, mmu: f.0 },
                        f.1, StepOutcome::Advanced, f.3),
                    memory_model::Op::Unsupported => (State { mmu: f.0, ..s }, f.1,
                        StepOutcome::Diagnostic(PagedDiagnostic::Unsupported), f.3),
                    memory_model::Op::Load(_, ar) | memory_model::Op::Store(_, ar) => {
                        let address = s.cpu.gpr[ar];
                        let req = match decoded {
                            memory_model::Op::Store(reg, _) => WordAccess::Write(s.cpu.gpr[reg] as u64),
                            _ => WordAccess::Read,
                        };
                        let data = word_model::access(f.0, f.1, base, address, req, user);
                        let next = match data.2 {
                            WordResult::Success(v) => commit(s.cpu, decoded, v as int),
                            _ => s.cpu,
                        };
                        (State { cpu: next, mmu: data.0 }, data.1,
                            word_outcome(data.2, address), f.3 + data.3)
                    },
                }
            },
        }
    }
}

#[verifier::opaque]
pub open spec fn run(s: State, b: Seq<u8>, base: int, user: bool, budget: nat)
    -> (State, Seq<u8>, nat, StepOutcome, nat)
    decreases budget,
{
    if budget == 0 { (s, b, 0, StepOutcome::Budget, 0) }
    else {
        let one = step(s, b, base, user);
        if one.2 != StepOutcome::Advanced { (one.0, one.1, 0, one.2, one.3) }
        else {
            let tail = run(one.0, one.1, base, user, (budget - 1) as nat);
            (tail.0, tail.1, 1 + tail.2, tail.3, one.3 + tail.4)
        }
    }
}

}
