// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::entry::MemoryTask;
use super::*;
use memory_core::cpu_core::operand::Width;

verus! {

impl SharedEventMachine {
    pub(super) fn execute_repeat(&mut self, width: Width, length: u8) -> (tick: Tick)
        requires
            old(self).invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures
            final(self).invariant(),
            (final(self)@, tick) == spec::repeat::execute(old(self)@, width, length),
    {
        let cpu = self.core.cpu();
        if length == 0 || length > 15 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.flags & 0x100 != 0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        // Interruptible repetitions and their inhibition rules are outside this profile.
        if !flags_supported(cpu.flags) || cpu.flags & 0x200 != 0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.gpr[1] == 0 {
            return self.retire_entry(cpu, length, false, false);
        }
        self.entry_memory(cpu.gpr[7], width, WordAccess::Write(cpu.gpr[0]), length,
            MemoryTask::RepeatStore { width })
    }

    pub(super) fn finish_repeat(&mut self, width: Width, length: u8) -> (tick: Tick)
        requires
            old(self).invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures
            final(self).invariant(),
            (final(self)@, tick) == spec::repeat::value(old(self)@, width, length),
    {
        let mut cpu = self.core.cpu();
        if cpu.gpr[1] == 0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let ghost before = cpu@;
        let bytes = (width.bits() / 8) as u64;
        cpu.gpr[1] = cpu.gpr[1] - 1;
        cpu.gpr[7] = if cpu.flags & 0x400 == 0 {
            cpu.gpr[7].wrapping_add(bytes)
        } else {
            cpu.gpr[7].wrapping_sub(bytes)
        };
        assert(cpu@.gpr =~= spec::repeat::progress(before, width).gpr);
        assert(cpu@ == spec::repeat::progress(before, width));
        if cpu.gpr[1] == 0 {
            self.retire_entry(cpu, length, false, false)
        } else {
            let _accepted = self.core.boundary_commit(cpu, false);
            assert(_accepted);
            self.phase = Phase::Repeat { width, length };
            Tick::Pending
        }
    }
}

}
