// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use memory_core::cpu_core::operand::{
    Operand as ScalarOperand, Register, ScalarStatus, commit_scalar,
};
use memory_core::cpu_core::{gsbase, near_call, profile, xor32};

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub struct DecodeInput {
    pub sequence: u64,
    pub rip: u64,
    pub length: u8,
    pub bytes: [u8; 15],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeDecision {
    More,
    Scalar { dst: Register, source: ScalarOperand },
    Xor32 { dst: Register, src: Register },
    Wrmsr,
    NearCall { displacement: i32 },
    Entry(entry::Instruction),
    Legacy,
    Unsupported,
    Rejected,
    InvalidOpcode,
    Overlong,
}

impl SharedEventMachine {
    pub fn enable_decode(&mut self) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            (final(self)@, accepted) == spec::decode::enable(old(self)@),
    {
        if !matches!(self.phase, Phase::Ready) || self.external_decode { return false; }
        self.external_decode = true;
        true
    }

    pub fn decode_request(&self) -> (out: Option<DecodeInput>)
        requires self.invariant(),
        ensures out == spec::decode::request(self@),
    {
        match self.phase { Phase::Decode { input } => Some(input), _ => None }
    }

    pub fn complete_decode(&mut self, sequence: u64, decision: DecodeDecision) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            (final(self)@, accepted) == spec::decode::complete(old(self)@, sequence, decision),
            final(self)@.core == old(self)@.core,
    {
        match self.phase {
            Phase::Decode { input } if input.sequence == sequence => {
                self.phase = Phase::Admitted { input, decision };
                true
            },
            _ => false,
        }
    }

    pub(super) fn offer_decode(&mut self, a: u8, b: u8, c: u8, length: u8) -> (tick: Tick)
        requires old(self).invariant(), old(self).external_decode,
            old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
            1 <= length <= 3,
            old(self).core@.cpu.rip + length as int - 1 <= u64::MAX,
        ensures final(self).invariant(),
            (final(self)@, tick) == spec::decode::offer(old(self)@, a, b, c, length),
    {
        if self.decode_sequence == u64::MAX {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DecodeExhausted));
        }
        self.decode_sequence += 1;
        let input = DecodeInput { sequence: self.decode_sequence, rip: self.core.cpu().rip,
            length, bytes: [a, b, c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] };
        self.phase = Phase::Decode { input };
        Tick::Decode(input)
    }

    pub(super) fn append_decode(&mut self, value: u8) -> (tick: Tick)
        requires old(self).invariant(), old(self).phase is DecodeFetch,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@, tick) == spec::decode::append(old(self)@, value),
    {
        let mut input = match self.phase { Phase::DecodeFetch { input } => input,
            _ => { assert(false); return Tick::Waiting; } };
        let ghost previous = input;
        if self.decode_sequence == u64::MAX {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DecodeExhausted));
        }
        self.decode_sequence += 1;
        input.bytes[input.length as usize] = value;
        input.length += 1;
        input.sequence = self.decode_sequence;
        proof {
            let expected = spec::decode::extended(previous, value, self.decode_sequence);
            assert(input.bytes@ =~= expected.bytes@);
            assert(input.bytes == expected.bytes);
            assert(input == expected);
        }
        self.phase = Phase::Decode { input };
        Tick::Decode(input)
    }

    pub(super) fn advance_admitted(&mut self) -> (tick: Tick)
        requires old(self).invariant(), old(self).phase is Admitted,
        ensures final(self).invariant(),
            (final(self)@, tick) == spec::decode::admitted(old(self)@),
    {
        let (input, decision) = match self.phase {
            Phase::Admitted { input, decision } => (input, decision),
            _ => { assert(false); return Tick::Waiting; },
        };
        match decision {
            DecodeDecision::Entry(instruction) => self.execute_entry(instruction, input.length),
            DecodeDecision::More => {
                if input.length == 15 {
                    return self.start_entry(Event::GeneralProtection);
                }
                if input.rip > u64::MAX - input.length as u64 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::FetchWrap));
                }
                let _accepted = self.core.boundary_fetch(input.rip + input.length as u64);
                assert(_accepted);
                self.phase = Phase::DecodeFetch { input };
                Tick::Pending
            },
            DecodeDecision::Rejected =>
                self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DecodeRejected)),
            DecodeDecision::InvalidOpcode => self.start_entry(Event::InvalidOpcode),
            DecodeDecision::Overlong => self.start_entry(Event::GeneralProtection),
            DecodeDecision::Unsupported =>
                self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
            DecodeDecision::Xor32 { dst, src } => {
                let mut cpu = self.core.cpu();
                let ghost before = cpu@;
                assert(cpu.gpr@ =~= before.gpr.map(|i: int, value: int| value as u64));
                cpu.flags &= !0x10000u64;
                let status = xor32::commit(&mut cpu.gpr, &mut cpu.rip, &mut cpu.flags, dst, src, input.length);
                proof {
                    let result = xor32::transition(before.gpr.map(|i: int, value: int| value as u64),
                        before.rip as u64, before.flags & !0x10000u64, dst, src, input.length);
                    assert(cpu.gpr@ == result.0);
                    assert(cpu@.gpr =~= result.0.map(|i: int, value: u64| value as int));
                }
                match status {
                    ScalarStatus::Advanced => {
                        let _accepted = self.core.boundary_commit(cpu, true);
                        assert(_accepted);
                        self.phase = Phase::Ready; self.shadow = false; self.handler_pending = false;
                        Tick::Retired(false)
                    },
                    ScalarStatus::DebugRequired =>
                        self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired)),
                    _ => self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                }
            },
            DecodeDecision::Wrmsr => {
                if (self.core.cpu().gpr[1]&0xffff_ffff==0x49 && !profile::PRED_CMD_AVAILABLE)
                    || profile::core_pmu_absent(self.core.cpu().gpr[1]&0xffff_ffff) {
                    if self.core.cpu().flags&0x100!=0 {
                        return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
                    }
                    return self.start_entry(Event::GeneralProtection);
                }
                if self.core.cpu().gpr[1]&0xffff_ffff==0xc000_0080 {
                    return self.write_efer(input.length);
                }
                let Some(mut system) = self.system else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                if self.core.cpu().gpr[1]&0xffff_ffff==0xc0011029
                    || memory_core::cpu_core::privilege::read_entry(system.entry,self.core.cpu().gpr[1]&0xffff_ffff).is_some() {
                    return self.write_entry_msr(input.length);
                }
                let mut cpu = self.core.cpu();
                cpu.flags &= !0x10000u64;
                let status = gsbase::commit(&mut system, &mut cpu.rip, cpu.flags,
                    cpu.gpr[0], cpu.gpr[1], cpu.gpr[2], input.length);
                match status {
                    gsbase::Status::Advanced => {
                        let _accepted = self.core.boundary_commit(cpu, true);
                        assert(_accepted);
                        self.system = Some(system);
                        self.phase = Phase::Ready; self.shadow = false; self.handler_pending = false;
                        Tick::Retired(true)
                    },
                    gsbase::Status::GeneralProtection => self.start_entry(Event::GeneralProtection),
                    gsbase::Status::DebugRequired =>
                        self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired)),
                    _ => self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                }
            },
            DecodeDecision::NearCall { displacement } => {
                let cpu = self.core.cpu();
                match near_call::prepare(cpu.rip, cpu.gpr[4], cpu.flags & !0x10000u64,
                    displacement, input.length) {
                    near_call::Plan::Ready { target, stack, return_address } => {
                        self.begin_word(stack, WordAccess::Write(return_address), Phase::NearCall { target, stack });
                        Tick::Pending
                    },
                    near_call::Plan::DebugRequired =>
                        self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired)),
                    _ => self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                }
            },
            DecodeDecision::Scalar { dst, source } => {
                let mut cpu = self.core.cpu();
                let ghost before = cpu@;
                assert(cpu.gpr@ =~= before.gpr.map(|i: int, value: int| value as u64));
                cpu.flags &= !0x10000u64;
                let status = commit_scalar(&mut cpu.gpr, &mut cpu.rip, cpu.flags, dst, source, input.length);
                proof {
                    let result = memory_core::cpu_core::operand::model::commit(
                        before.gpr.map(|i: int, value: int| value as u64),
                        before.rip as u64, before.flags & !0x10000u64, dst, source, input.length);
                    assert(cpu.gpr@ == result.0);
                    assert(cpu@.gpr =~= result.0.map(|i: int, value: u64| value as int));
                }
                match status {
                    ScalarStatus::Advanced => {
                        let _accepted = self.core.boundary_commit(cpu, true);
                        assert(_accepted);
                        self.phase = Phase::Ready; self.shadow = false; self.handler_pending = false;
                        Tick::Retired(false)
                    },
                    ScalarStatus::DebugRequired =>
                        self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired)),
                    _ => self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                }
            },
            DecodeDecision::Legacy => {
                if input.length != 3 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let op = memory_core::decode(input.bytes[0], input.bytes[1], input.bytes[2]);
                if matches!(op, memory_core::Op::Unsupported) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let mut cpu = self.core.cpu();
                if cpu.flags & 0x100u64 != 0 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
                }
                let flags = cpu.flags;
                cpu.flags &= !0x10000u64;
                let _cleared = cpu.flags;
                assert(_cleared & 0x10100u64 == 0) by(bit_vector)
                    requires flags & 0x100u64 == 0, _cleared == flags & !0x10000u64;
                let _accepted = self.core.boundary_commit(cpu, false);
                assert(_accepted);
                let result = self.core.boundary_decoded(input.bytes[0], input.bytes[1], input.bytes[2]);
                match result {
                    CpuTick::Retired => {
                        self.phase = Phase::Ready; self.shadow = false; self.handler_pending = false;
                        Tick::Retired(false)
                    },
                    CpuTick::Pending => {
                        self.phase = Phase::Ordinary { flags };
                        Tick::Pending
                    },
                    _ => { assert(false); Tick::Waiting },
                }
            },
        }
    }
}

}
