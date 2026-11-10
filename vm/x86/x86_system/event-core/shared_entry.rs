// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
#[cfg(verus_keep_ghost)]
use memory_core::cpu_core::operand;
use memory_core::cpu_core::operand::{Address, Operand, Register, Segment, SegmentBases, Width};
use memory_core::cpu_core::{descriptor, integer};

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instruction {
    Integer { operation: integer::Operation, dst: Register, source: Operand },
    ZeroExtend { dst: Register, src: Register },
    Load { dst: Register, address: Address, width: Width },
    Store { address: Address, width: Width, source: Operand },
    Table { address: Address, idt: bool },
    Segment { segment: Segment, src: Register },
    Push { source: Operand },
    Return,
    Leave,
    Jump { target: u64, zero: Option<bool> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryTask {
    Load { dst: Register },
    Store,
    TableLimit { idt: bool },
    TableBase { idt: bool, limit: u16 },
    Segment { segment: Segment, selector: u16 },
    Push { stack: u64 },
    Return { stack: u64 },
    Leave { stack: u64 },
}

fn scalar(cpu: State, source: Operand) -> (out: Option<u64>)
    ensures out == spec::entry::scalar(cpu@, source),
{
    match source {
        Operand::Register(reg) => if reg.is_valid() { Some(reg.read(&cpu.gpr)) } else { None },
        Operand::Immediate(imm) => Some(imm.value),
        _ => None,
    }
}

impl SharedEventMachine {
    fn retire_entry(&mut self, mut cpu: State, length: u8, shadow: bool, serializing: bool) -> (tick: Tick)
        requires old(self).invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@, tick) == spec::entry::retire(old(self)@, cpu@, length, shadow, serializing),
    {
        cpu.rip = cpu.rip.wrapping_add(length as u64);
        cpu.flags &= !0x10000u64;
        let _accepted = self.core.boundary_commit(cpu, true);
        assert(_accepted);
        self.phase = Phase::Ready; self.shadow = shadow; self.handler_pending = false;
        Tick::Retired(serializing)
    }

    fn entry_memory(&mut self, address: u64, width: Width, request: WordAccess,
        length: u8, task: MemoryTask) -> (tick: Tick)
        requires old(self).invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@, tick) == spec::entry::memory(old(self)@, address, width, request, length, task),
    {
        let size = (width.bits() / 8) as u8;
        if address > u64::MAX - (size as u64 - 1) || address % 4096 + size as u64 > 4096
            || !canonical(address) || !canonical(address + (size as u64 - 1))
            || (size < 8 && address % 8 + size as u64 > 8) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let _accepted = if size == 8 { self.core.boundary_word(address, request) }
            else { self.core.boundary_sized(address, request, size) };
        assert(_accepted);
        self.phase = Phase::EntryMemory { address, length, task };
        Tick::Pending
    }

    #[verifier::spinoff_prover]
    pub(super) fn execute_entry(&mut self, instruction: Instruction, length: u8) -> (tick: Tick)
        requires old(self).invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@, tick) == spec::entry::execute(old(self)@, instruction, length),
    {
        let mut cpu = self.core.cpu();
        assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
        if length == 0 || length > 15 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.flags & 0x100 != 0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        let next = cpu.rip.wrapping_add(length as u64);
        match instruction {
            Instruction::ZeroExtend { dst, src } => {
                if !dst.is_valid() || !src.is_valid() || dst.width().bits() <= src.width().bits()
                    || !matches!(src.width(), Width::Byte | Width::Word) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let value = src.read(&cpu.gpr);
                let ghost registers = cpu.gpr@;
                dst.write(&mut cpu.gpr, value);
                assert(cpu@.gpr =~= operand::model::write(registers, dst, value)
                    .map(|i: int, v: u64| v as int));
                self.retire_entry(cpu, length, false, false)
            },
            Instruction::Integer { operation, dst, source } => {
                if !dst.is_valid() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let Some(right) = scalar(cpu, source) else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                let result = integer::evaluate(operation, dst.read(&cpu.gpr), right, dst.width(), cpu.flags);
                let ghost before = cpu@;
                let ghost registers = cpu.gpr@;
                if result.write { dst.write(&mut cpu.gpr, result.value); }
                assert(cpu@.gpr =~= (if result.write {
                    operand::model::write(registers, dst, result.value)
                } else { registers }).map(|i: int, value: u64| value as int));
                cpu.flags = result.flags;
                self.retire_entry(cpu, length, false, false)
            },
            Instruction::Load { dst, address, width } => {
                if !dst.is_valid() || !address.is_valid() || dst.width().bits() < width.bits() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let linear = address.linear(&cpu.gpr, next, self.entry_bases());
                self.entry_memory(linear, width, WordAccess::Read, length, MemoryTask::Load { dst })
            },
            Instruction::Store { address, width, source } => {
                if !address.is_valid() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let Some(value) = scalar(cpu, source) else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                let linear = address.linear(&cpu.gpr, next, self.entry_bases());
                self.entry_memory(linear, width, WordAccess::Write(value), length, MemoryTask::Store)
            },
            Instruction::Table { address, idt } => {
                if !address.is_valid() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let linear = address.linear(&cpu.gpr, next, self.entry_bases());
                self.entry_memory(linear, Width::Word, WordAccess::Read, length, MemoryTask::TableLimit { idt })
            },
            Instruction::Segment { segment: dst, src } => {
                if !src.is_valid() || !matches!(dst, Segment::Ds | Segment::Ss | Segment::Es)
                    || self.system.is_none() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let selector = (src.read(&cpu.gpr) & 0xffff) as u16;
                let offset = (selector & !7u16) as u64;
                if selector == 0 || selector % 8 != 0 || offset + 7 > self.tables.gdt_limit as u64
                    || self.tables.gdt_base > u64::MAX - offset {
                    return self.stop(EventDiagnostic::Descriptor(Stage::Stack));
                }
                self.entry_memory(self.tables.gdt_base + offset, Width::Qword, WordAccess::Read,
                    length, MemoryTask::Segment { segment: dst, selector })
            },
            Instruction::Push { source } => {
                let Some(value) = scalar(cpu, source) else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                if cpu.gpr[4] < 8 || cpu.gpr[4] % 8 != 0 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let stack = cpu.gpr[4] - 8;
                self.entry_memory(stack, Width::Qword, WordAccess::Write(value),
                    length, MemoryTask::Push { stack })
            },
            Instruction::Return | Instruction::Leave => {
                let stack = if matches!(instruction, Instruction::Return) { cpu.gpr[4] } else { cpu.gpr[5] };
                if stack > u64::MAX - 8 || stack % 8 != 0 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let task = if matches!(instruction, Instruction::Return) { MemoryTask::Return { stack } }
                    else { MemoryTask::Leave { stack } };
                self.entry_memory(stack, Width::Qword, WordAccess::Read, length, task)
            },
            Instruction::Jump { target, zero } => {
                let taken = match zero { None => true, Some(wanted) => (cpu.flags & 0x40 != 0) == wanted };
                if taken {
                    if !canonical(target) {
                        return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                    }
                    cpu.rip = target;
                    self.retire_entry(cpu, 0, false, false)
                } else { self.retire_entry(cpu, length, false, false) }
            },
        }
    }

    fn entry_bases(&self) -> (out: SegmentBases)
        ensures out == spec::entry::bases(self@),
    {
        match self.system {
            Some(system) => SegmentBases { fs: system.fs.base, gs: system.gs.base },
            None => SegmentBases { fs: 0, gs: 0 },
        }
    }

    pub(super) fn entry_value(&mut self, value: u64) -> (tick: Tick)
        requires old(self).invariant(), old(self).phase is EntryMemory,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@, tick) == spec::entry::value(old(self)@, value),
    {
        let (address, length, task) = match self.phase {
            Phase::EntryMemory { address, length, task } => (address, length, task),
            _ => { assert(false); return Tick::Waiting; },
        };
        let mut cpu = self.core.cpu();
        assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
        let ghost before = cpu@;
        match task {
            MemoryTask::Load { dst } => {
                if !dst.is_valid() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let ghost registers = cpu.gpr@;
                dst.write(&mut cpu.gpr, value);
                assert(cpu@.gpr =~= operand::model::write(registers, dst, value)
                    .map(|i: int, v: u64| v as int));
            },
            MemoryTask::Store => {},
            MemoryTask::TableLimit { idt } => {
                if address > u64::MAX - 2 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                return self.entry_memory(address + 2, Width::Qword, WordAccess::Read, length,
                    MemoryTask::TableBase { idt, limit: (value & 0xffff) as u16 });
            },
            MemoryTask::TableBase { idt, limit } => {
                if !canonical(value) {
                    return self.stop(EventDiagnostic::Descriptor(if idt { Stage::Idt } else { Stage::Code }));
                }
                if idt { self.tables.idt_base = value; self.tables.idt_limit = limit; }
                else { self.tables.gdt_base = value; self.tables.gdt_limit = limit; }
                return self.retire_entry(cpu, length, false, false);
            },
            MemoryTask::Segment { segment: dst, selector } => {
                let Some(segment) = descriptor::load_data(value, selector) else {
                    return self.stop(EventDiagnostic::Descriptor(Stage::Stack));
                };
                let Some(mut system) = self.system else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                match dst { Segment::Ds => system.ds = segment, Segment::Ss => system.ss = segment,
                    Segment::Es => system.es = segment,
                    _ => return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                }
                self.system = Some(system);
                return self.retire_entry(cpu, length, matches!(dst, Segment::Ss), false);
            },
            MemoryTask::Push { stack } => {
                cpu.gpr[4] = stack;
                assert(cpu@.gpr =~= before.gpr.update(4, stack as int));
            },
            MemoryTask::Return { stack } => {
                if stack > u64::MAX - 8 || !canonical(value) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                cpu.gpr[4] = stack + 8;
                assert(cpu@.gpr =~= before.gpr.update(4, stack as int + 8));
                cpu.rip = value;
                return self.retire_entry(cpu, 0, false, false);
            },
            MemoryTask::Leave { stack } => {
                if stack > u64::MAX - 8 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                cpu.gpr[4] = stack + 8; cpu.gpr[5] = value;
                assert(cpu@.gpr =~= before.gpr.update(4, stack as int + 8).update(5, value as int));
            },
        }
        self.retire_entry(cpu, length, false, false)
    }
}
}
