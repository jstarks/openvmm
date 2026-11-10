// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![forbid(unsafe_code)]
use vstd::prelude::*;

#[path = "../mmu-core/lib.rs"]
pub mod mmu_core;
pub use mmu_core::{
    Access, Config, Decoded, Diagnostic, Kind, Mmu, MmuResult, Permissions, Profile, State, Stop,
    arithmetic, decoder, execute, memory_core, memory_model, mmu_model, model, word, word_model,
};
pub use word::{WordAccess, WordResult};
pub mod paged_model;
pub mod shared;
pub mod shared_model;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagedDiagnostic {
    InvalidConfig, Backing, HugePage, Ambiguous, DataCrossPage, DataWrap, FetchWrap,
    Unsupported, DebugRequired, DecodeLimit, DecodeRejected, DecodeExhausted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    Advanced, Budget, PageFault { code: u8, address: u64 },
    GeneralProtection { address: u64 }, Diagnostic(PagedDiagnostic),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepReport { pub outcome: StepOutcome, pub table_reads: u8 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunReport { pub retired: u64, pub outcome: StepOutcome, pub table_reads: u128 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Machine { pub cpu: State, pub mmu: Mmu }
impl View for Machine {
    type V = paged_model::State;
    open spec fn view(&self) -> paged_model::State {
        paged_model::State { cpu: self.cpu@, mmu: self.mmu@ }
    }
}
impl Machine {
    pub open spec fn invariant(&self) -> bool { self.mmu.invariant() }
}

fn byte_outcome(r: MmuResult, address: u64) -> (o: StepOutcome)
    ensures o == paged_model::byte_outcome(r, address as int),
        !(r is Success) ==> o != StepOutcome::Advanced && o != StepOutcome::Budget,
{
    match r {
        MmuResult::Success(_) => StepOutcome::Advanced,
        MmuResult::PageFault(code) => StepOutcome::PageFault { code, address },
        MmuResult::GeneralProtection => StepOutcome::GeneralProtection { address },
        MmuResult::InvalidConfig => StepOutcome::Diagnostic(PagedDiagnostic::InvalidConfig),
        MmuResult::Backing => StepOutcome::Diagnostic(PagedDiagnostic::Backing),
        MmuResult::HugePage => StepOutcome::Diagnostic(PagedDiagnostic::HugePage),
        MmuResult::Ambiguous => StepOutcome::Diagnostic(PagedDiagnostic::Ambiguous),
    }
}
fn word_outcome(r: WordResult, address: u64) -> (o: StepOutcome)
    ensures o == paged_model::word_outcome(r, address as int),
        !(r is Success) ==> o != StepOutcome::Advanced && o != StepOutcome::Budget,
{
    match r {
        WordResult::Success(_) => StepOutcome::Advanced,
        WordResult::PageFault(code) => StepOutcome::PageFault { code, address },
        WordResult::GeneralProtection => StepOutcome::GeneralProtection { address },
        WordResult::InvalidConfig => StepOutcome::Diagnostic(PagedDiagnostic::InvalidConfig),
        WordResult::Backing => StepOutcome::Diagnostic(PagedDiagnostic::Backing),
        WordResult::HugePage => StepOutcome::Diagnostic(PagedDiagnostic::HugePage),
        WordResult::Ambiguous => StepOutcome::Diagnostic(PagedDiagnostic::Ambiguous),
        WordResult::CrossPage => StepOutcome::Diagnostic(PagedDiagnostic::DataCrossPage),
        WordResult::Wrap => StepOutcome::Diagnostic(PagedDiagnostic::DataWrap),
    }
}

enum Fetched { Bytes(u8, u8, u8), Stopped(StepOutcome) }
impl View for Fetched {
    type V = paged_model::Fetched;
    closed spec fn view(&self) -> paged_model::Fetched {
        match *self {
            Fetched::Bytes(a, b, c) => paged_model::Fetched::Bytes(a, b, c),
            Fetched::Stopped(o) => paged_model::Fetched::Stopped(o),
        }
    }
}

fn fetch(m: &mut Mmu, ram: &mut Vec<u8>, base: u64, ip: u64, user: bool)
    -> (r: (Fetched, u8))
    requires old(m).invariant(),
    ensures
        (final(m)@, final(ram)@, r.0@, r.1 as nat)
            == paged_model::fetch(old(m)@, old(ram)@, base as int, ip as int, user),
        final(m).invariant(), final(ram)@.len() == old(ram)@.len(), r.1 <= 12,
        match r.0 { Fetched::Stopped(o) => o != StepOutcome::Advanced && o != StepOutcome::Budget, _ => true },
{
    proof { reveal(paged_model::fetch); }
    let first = m.access(ram, base, ip, Access::Fetch, user);
    let a = match first.result {
        MmuResult::Success(v) => v,
        _ => { return (Fetched::Stopped(byte_outcome(first.result, ip)), first.table_reads); },
    };
    if a < 0x48 || a > 0x4f {
        return (Fetched::Stopped(StepOutcome::Diagnostic(PagedDiagnostic::Unsupported)), first.table_reads);
    }
    if ip == u64::MAX {
        return (Fetched::Stopped(StepOutcome::Diagnostic(PagedDiagnostic::FetchWrap)), first.table_reads);
    }
    let second = m.access(ram, base, ip + 1, Access::Fetch, user);
    let reads = first.table_reads + second.table_reads;
    let b = match second.result {
        MmuResult::Success(v) => v,
        _ => { return (Fetched::Stopped(byte_outcome(second.result, ip + 1)), reads); },
    };
    if b != 0x01 && b != 0x11 && b != 0x8b && b != 0x89 {
        return (Fetched::Stopped(StepOutcome::Diagnostic(PagedDiagnostic::Unsupported)), reads);
    }
    if ip == u64::MAX - 1 {
        return (Fetched::Stopped(StepOutcome::Diagnostic(PagedDiagnostic::FetchWrap)), reads);
    }
    let third = m.access(ram, base, ip + 2, Access::Fetch, user);
    let reads = reads + third.table_reads;
    match third.result {
        MmuResult::Success(c) => (Fetched::Bytes(a, b, c), reads),
        _ => (Fetched::Stopped(byte_outcome(third.result, ip + 2)), reads),
    }
}

fn commit(s: &mut State, op: memory_core::Op, value: u64)
    requires
        match op { memory_core::Op::Load { reg, base } | memory_core::Op::Store { reg, base }
            => reg < 16 && base < 16, _ => false },
    ensures final(s)@ == paged_model::commit(old(s)@, op@, value as int),
{
    let ghost before = s@;
    if let memory_core::Op::Load { reg, .. } = op {
        s.gpr[reg as usize] = value;
        proof { assert(s@.gpr =~= before.gpr.update(reg as int, value as int)); }
    }
    s.rip = s.rip.wrapping_add(3);
}

impl Machine {
    pub fn step(&mut self, ram: &mut Vec<u8>, base: u64, user: bool) -> (r: StepReport)
        requires old(self).invariant(),
        ensures
            (final(self)@, final(ram)@, r.outcome, r.table_reads as nat)
                == paged_model::step(old(self)@, old(ram)@, base as int, user),
            final(self).invariant(), final(ram)@.len() == old(ram)@.len(),
            r.table_reads <= 16, r.outcome != StepOutcome::Budget,
            r.outcome != StepOutcome::Advanced ==> final(self).cpu@ == old(self).cpu@,
    {
        proof { reveal(paged_model::step); }
        if self.cpu.flags & 0x10100u64 != 0 {
            return StepReport { outcome: StepOutcome::Diagnostic(PagedDiagnostic::DebugRequired), table_reads: 0 };
        }
        let fetched = fetch(&mut self.mmu, ram, base, self.cpu.rip, user);
        let (a, b, c) = match fetched.0 {
            Fetched::Bytes(a, b, c) => (a, b, c),
            Fetched::Stopped(outcome) => { return StepReport { outcome, table_reads: fetched.1 }; },
        };
        let op = memory_core::decode(a, b, c);
        match op {
            memory_core::Op::Alu(alu) => {
                let _result = execute(&mut self.cpu, alu);
                assert(_result == Diagnostic::Advanced);
                StepReport { outcome: StepOutcome::Advanced, table_reads: fetched.1 }
            },
            memory_core::Op::Unsupported =>
                StepReport { outcome: StepOutcome::Diagnostic(PagedDiagnostic::Unsupported), table_reads: fetched.1 },
            memory_core::Op::Load { reg: _, base: ar } | memory_core::Op::Store { reg: _, base: ar } => {
                let address = self.cpu.gpr[ar as usize];
                let request = match op {
                    memory_core::Op::Store { reg, .. } => WordAccess::Write(self.cpu.gpr[reg as usize]),
                    _ => WordAccess::Read,
                };
                let data = self.mmu.access_word(ram, base, address, request, user);
                let outcome = match data.result {
                    WordResult::Success(value) => { commit(&mut self.cpu, op, value); StepOutcome::Advanced },
                    _ => word_outcome(data.result, address),
                };
                StepReport { outcome, table_reads: fetched.1 + data.table_reads }
            },
        }
    }

    pub fn run(&mut self, ram: &mut Vec<u8>, base: u64, user: bool, budget: u64) -> (r: RunReport)
        requires old(self).invariant(),
        ensures
            (final(self)@, final(ram)@, r.retired as nat, r.outcome, r.table_reads as nat)
                == paged_model::run(old(self)@, old(ram)@, base as int, user, budget as nat),
            final(self).invariant(), final(ram)@.len() == old(ram)@.len(),
            r.retired <= budget, r.table_reads <= 16u128 * budget as u128,
            r.outcome == StepOutcome::Budget ==> r.retired == budget,
            budget == 0 ==> final(self)@ == old(self)@ && final(ram)@ == old(ram)@,
    {
        let ghost initial = self@;
        let ghost initial_ram = ram@;
        let mut retired = 0u64;
        let mut reads = 0u128;
        proof { reveal_with_fuel(paged_model::run, 2); }
        while retired < budget
            invariant
                self.invariant(), ram@.len() == initial_ram.len(),
                retired <= budget, reads <= 16u128 * retired as u128,
                initial == old(self)@, initial_ram == old(ram)@,
                ({
                    let tail = paged_model::run(self@, ram@, base as int, user, (budget - retired) as nat);
                    paged_model::run(initial, initial_ram, base as int, user, budget as nat)
                        =~= (tail.0, tail.1, retired as nat + tail.2, tail.3, reads as nat + tail.4)
                }),
            decreases budget - retired,
        {
            let ghost total = paged_model::run(initial, initial_ram, base as int, user, budget as nat);
            let ghost remaining = paged_model::run(self@, ram@, base as int, user, (budget - retired) as nat);
            assert(total =~= (remaining.0, remaining.1, retired as nat + remaining.2,
                remaining.3, reads as nat + remaining.4));
            assert(total.0 == remaining.0);
            assert(total.1 == remaining.1);
            assert(total.2 == retired as nat + remaining.2);
            assert(total.4 == reads as nat + remaining.4);
            let ghost one = paged_model::step(self@, ram@, base as int, user);
            let ghost next = paged_model::run(one.0, one.1, base as int, user, (budget - retired - 1) as nat);
            proof { reveal_with_fuel(paged_model::run, 2); }
            assert(remaining =~= if one.2 == StepOutcome::Advanced {
                (next.0, next.1, 1 + next.2, next.3, one.3 + next.4)
            } else { (one.0, one.1, 0nat, one.2, one.3) });
            assert(remaining.0 == if one.2 == StepOutcome::Advanced { next.0 } else { one.0 });
            assert(remaining.1 == if one.2 == StepOutcome::Advanced { next.1 } else { one.1 });
            assert(remaining.2 == if one.2 == StepOutcome::Advanced { 1 + next.2 } else { 0nat });
            assert(remaining.3 == if one.2 == StepOutcome::Advanced { next.3 } else { one.2 });
            assert(remaining.4 == if one.2 == StepOutcome::Advanced { one.3 + next.4 } else { one.3 });
            let report = self.step(ram, base, user);
            assert(one =~= (self@, ram@, report.outcome, report.table_reads as nat));
            assert(one.0 == self@);
            assert(one.1 == ram@);
            assert(one.2 == report.outcome);
            assert(one.3 == report.table_reads as nat);
            reads = reads + report.table_reads as u128;
            match report.outcome {
                StepOutcome::Advanced => {},
                _ => {
                    assert(total =~= (self@, ram@, retired as nat, report.outcome, reads as nat));
                    return RunReport { retired, outcome: report.outcome, table_reads: reads };
                },
            }
            retired = retired + 1;
            proof {
                let tail = paged_model::run(self@, ram@, base as int, user, (budget - retired) as nat);
                assert(next == tail);
                assert(total =~= (tail.0, tail.1, retired as nat + tail.2, tail.3, reads as nat + tail.4));
            }
        }
        proof { reveal(paged_model::run); }
        RunReport { retired, outcome: StepOutcome::Budget, table_reads: reads }
    }
}

}
