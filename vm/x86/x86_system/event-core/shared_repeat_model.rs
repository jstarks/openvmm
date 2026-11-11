// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::operand::{self, Width};
#[cfg(verus_keep_ghost)]
use super::super::shared::entry::MemoryTask;
use super::*;

verus! {

pub open spec fn bytes(width: Width) -> int {
    (operand::model::bits(width) / 8) as int
}

pub open spec fn progress(cpu: model::State, width: Width) -> model::State {
    let delta = bytes(width);
    let destination = if cpu.flags & 0x400u64 == 0 {
        (cpu.gpr[7] + delta) % 0x1_0000_0000_0000_0000int
    } else {
        (cpu.gpr[7] + 0x1_0000_0000_0000_0000int - delta) % 0x1_0000_0000_0000_0000int
    };
    model::State { gpr: cpu.gpr.update(1, cpu.gpr[1] - 1).update(7, destination), ..cpu }
}

pub open spec fn move_progress(cpu: model::State, width: Width) -> model::State {
    let delta = bytes(width);
    let source = if cpu.flags & 0x400u64 == 0 {
        (cpu.gpr[6] + delta) % 0x1_0000_0000_0000_0000int
    } else {
        (cpu.gpr[6] + 0x1_0000_0000_0000_0000int - delta) % 0x1_0000_0000_0000_0000int
    };
    let moved = progress(cpu, width);
    model::State { gpr: moved.gpr.update(6, source), ..moved }
}

pub open spec fn execute_move(s: State, width: Width, length: u8) -> (State, Tick) {
    let cpu = s.core.cpu;
    if length == 0 || length > 15 { entry::unsupported(s) }
    else if cpu.flags & 0x100u64 != 0 {
        stop(s, EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))
    } else if !e::flags_supported(cpu.flags) || cpu.flags & 0x200u64 != 0 {
        entry::unsupported(s)
    } else if cpu.gpr[1] == 0 {
        entry::retire(s, cpu, length, false, false)
    } else {
        entry::memory(s, cpu.gpr[6] as u64, width, WordAccess::Read,
            length, MemoryTask::RepeatRead { width })
    }
}

pub open spec fn move_read(s: State, width: Width, value: u64, length: u8) -> (State, Tick) {
    entry::memory(s, s.core.cpu.gpr[7] as u64, width, WordAccess::Write(value),
        length, MemoryTask::RepeatWrite { width })
}

pub open spec fn move_value(s: State, width: Width, length: u8) -> (State, Tick) {
    if s.core.cpu.gpr[1] == 0 { entry::unsupported(s) }
    else {
        let cpu = move_progress(s.core.cpu, width);
        if cpu.gpr[1] == 0 { entry::retire(s, cpu, length, false, false) }
        else {
            (State { core: c::boundary_commit(s.core, cpu, false).0,
                phase: Phase::RepeatMove { width, length }, ..s }, Tick::Pending)
        }
    }
}

pub proof fn move_progress_frames(cpu: model::State, width: Width)
    requires cpu.gpr.len() == 16, cpu.gpr[1] > 0,
    ensures
        move_progress(cpu, width).rip == cpu.rip,
        move_progress(cpu, width).flags == cpu.flags,
        move_progress(cpu, width).gpr[1] == cpu.gpr[1] - 1,
        forall|i: int| 0 <= i < 16 && i != 1 && i != 6 && i != 7 ==>
            #[trigger] move_progress(cpu, width).gpr[i] == cpu.gpr[i],
{
}

pub proof fn move_progress_updates_both_indices(cpu: model::State, width: Width)
    requires cpu.gpr.len() == 16, cpu.gpr[1] > 0,
    ensures
        move_progress(cpu, width).gpr[6] == if cpu.flags & 0x400u64 == 0 {
            (cpu.gpr[6] + bytes(width)) % 0x1_0000_0000_0000_0000int
        } else {
            (cpu.gpr[6] + 0x1_0000_0000_0000_0000int - bytes(width))
                % 0x1_0000_0000_0000_0000int
        },
        move_progress(cpu, width).gpr[7] == progress(cpu, width).gpr[7],
{
}

pub proof fn move_zero_count_has_no_memory(s: State, width: Width, length: u8)
    requires
        s.core.cpu.gpr.len() == 16, s.core.cpu.gpr[1] == 0,
        1 <= length <= 15, s.core.cpu.flags & 0x300u64 == 0,
        e::flags_supported(s.core.cpu.flags),
        s.core.phase is Boundary, !m::active(s.core.mmu.phase),
    ensures
        execute_move(s, width, length).1 == Tick::Retired(false),
        execute_move(s, width, length).0.core.mmu == s.core.mmu,
        execute_move(s, width, length).0.core.cpu.gpr == s.core.cpu.gpr,
        execute_move(s, width, length).0.pending == s.pending,
{
    let flags = s.core.cpu.flags;
    assert(flags & 0x100u64 == 0) by (bit_vector)
        requires flags & 0x300u64 == 0;
    assert(flags & 0x200u64 == 0) by (bit_vector)
        requires flags & 0x300u64 == 0;
}

pub proof fn move_partial_progress_is_not_retirement(s: State, width: Width, length: u8)
    requires
        s.core.cpu.gpr.len() == 16, s.core.cpu.gpr[1] > 1,
        s.core.phase is Boundary, !m::active(s.core.mmu.phase),
    ensures
        move_value(s, width, length).1 == Tick::Pending,
        move_value(s, width, length).0.phase == (Phase::RepeatMove { width, length }),
        move_value(s, width, length).0.core.cpu == move_progress(s.core.cpu, width),
        move_value(s, width, length).0.core.cpu.rip == s.core.cpu.rip,
        move_value(s, width, length).0.core.cpu.flags == s.core.cpu.flags,
        move_value(s, width, length).0.core.mmu == s.core.mmu,
        move_value(s, width, length).0.pending == s.pending,
        move_value(s, width, length).0.shadow == s.shadow,
        move_value(s, width, length).0.core.phase is Boundary,
{
}

pub proof fn move_last_element_retires(s: State, width: Width, length: u8)
    requires
        s.core.cpu.gpr.len() == 16, s.core.cpu.gpr[1] == 1,
        s.core.phase is Boundary, !m::active(s.core.mmu.phase),
    ensures
        move_value(s, width, length) == entry::retire(s,
            move_progress(s.core.cpu, width), length, false, false),
        move_value(s, width, length).1 == Tick::Retired(false),
        move_value(s, width, length).0.phase == Phase::Ready,
        move_value(s, width, length).0.core.cpu.gpr[1] == 0,
        move_value(s, width, length).0.core.cpu.flags == s.core.cpu.flags & !0x10000u64,
{
}

pub proof fn move_read_frames_current_element(s: State, width: Width, value: u64, length: u8)
    ensures
        move_read(s, width, value, length).0.core.cpu == s.core.cpu,
        move_read(s, width, value, length).0.pending == s.pending,
        move_read(s, width, value, length).0.shadow == s.shadow,
        move_read(s, width, value, length).1 != Tick::Retired(false),
{
}

pub proof fn move_fault_preserves_current_element(s: State, width: Width, length: u8,
    address: u64, reading: bool, code: u8)
    requires
        s.phase == (Phase::EntryMemory { address, length,
            task: if reading { MemoryTask::RepeatRead { width } }
                else { MemoryTask::RepeatWrite { width } } }),
        match m::request(s.core.mmu) {
            Request::CompleteWord { report } => report.result == WordResult::PageFault(code),
            _ => false,
        },
    ensures
        advance(s) == entry(s, Event::PageFault(code)),
        advance(s).0.core.cpu == s.core.cpu,
        advance(s).1 != Tick::Retired(false),
{
}

pub proof fn move_invalid_completed_count_is_diagnostic(s: State, width: Width, length: u8)
    requires s.core.cpu.gpr.len() == 16, s.core.cpu.gpr[1] == 0,
    ensures
        move_value(s, width, length) == entry::unsupported(s),
        move_value(s, width, length).0.core == s.core,
{
}

pub proof fn move_guards_apply_at_every_element(s: State, width: Width, length: u8)
    requires
        s.core.cpu.gpr.len() == 16,
        length == 0 || length > 15 || s.core.cpu.flags & 0x300u64 != 0,
    ensures
        execute_move(s, width, length).1 is Stopped,
        execute_move(s, width, length).0.core == s.core,
        execute_move(s, width, length).0.pending == s.pending,
{
    let flags = s.core.cpu.flags;
    assert(flags & 0x300u64 != 0 ==> flags & 0x100u64 != 0 || flags & 0x200u64 != 0)
        by (bit_vector);
}

pub open spec fn execute(s: State, width: Width, length: u8) -> (State, Tick) {
    let cpu = s.core.cpu;
    if length == 0 || length > 15 { entry::unsupported(s) }
    else if cpu.flags & 0x100u64 != 0 {
        stop(s, EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))
    } else if !e::flags_supported(cpu.flags) || cpu.flags & 0x200u64 != 0 {
        entry::unsupported(s)
    } else if cpu.gpr[1] == 0 {
        entry::retire(s, cpu, length, false, false)
    } else {
        entry::memory(s, cpu.gpr[7] as u64, width, WordAccess::Write(cpu.gpr[0] as u64),
            length, MemoryTask::RepeatStore { width })
    }
}

pub open spec fn value(s: State, width: Width, length: u8) -> (State, Tick) {
    if s.core.cpu.gpr[1] == 0 { entry::unsupported(s) }
    else {
        let cpu = progress(s.core.cpu, width);
        if cpu.gpr[1] == 0 { entry::retire(s, cpu, length, false, false) }
        else {
            (State { core: c::boundary_commit(s.core, cpu, false).0,
                phase: Phase::Repeat { width, length }, ..s }, Tick::Pending)
        }
    }
}

pub proof fn progress_frames(cpu: model::State, width: Width)
    requires cpu.gpr.len() == 16, cpu.gpr[1] > 0,
    ensures
        progress(cpu, width).rip == cpu.rip,
        progress(cpu, width).flags == cpu.flags,
        progress(cpu, width).gpr[1] == cpu.gpr[1] - 1,
        forall|i: int| 0 <= i < 16 && i != 1 && i != 7 ==>
            #[trigger] progress(cpu, width).gpr[i] == cpu.gpr[i],
{
}

pub proof fn zero_count_has_no_memory(s: State, width: Width, length: u8)
    requires
        s.core.cpu.gpr.len() == 16, s.core.cpu.gpr[1] == 0,
        1 <= length <= 15, s.core.cpu.flags & 0x300u64 == 0,
        e::flags_supported(s.core.cpu.flags),
        s.core.phase is Boundary, !m::active(s.core.mmu.phase),
    ensures
        execute(s, width, length).1 == Tick::Retired(false),
        execute(s, width, length).0.core.mmu == s.core.mmu,
        execute(s, width, length).0.core.cpu.gpr == s.core.cpu.gpr,
        execute(s, width, length).0.pending == s.pending,
{
    let flags = s.core.cpu.flags;
    assert(flags & 0x100u64 == 0) by (bit_vector)
        requires flags & 0x300u64 == 0;
    assert(flags & 0x200u64 == 0) by (bit_vector)
        requires flags & 0x300u64 == 0;
}

pub proof fn partial_progress_is_not_retirement(s: State, width: Width, length: u8)
    requires
        s.core.cpu.gpr.len() == 16, s.core.cpu.gpr[1] > 1,
        s.core.phase is Boundary, !m::active(s.core.mmu.phase),
    ensures
        value(s, width, length).1 == Tick::Pending,
        value(s, width, length).0.phase == (Phase::Repeat { width, length }),
        value(s, width, length).0.core.cpu == progress(s.core.cpu, width),
        value(s, width, length).0.core.cpu.rip == s.core.cpu.rip,
        value(s, width, length).0.core.cpu.flags == s.core.cpu.flags,
        value(s, width, length).0.core.mmu == s.core.mmu,
        value(s, width, length).0.pending == s.pending,
        value(s, width, length).0.shadow == s.shadow,
        value(s, width, length).0.core.phase is Boundary,
{
}

pub proof fn invalid_completed_count_is_diagnostic(s: State, width: Width, length: u8)
    requires s.core.cpu.gpr.len() == 16, s.core.cpu.gpr[1] == 0,
    ensures
        value(s, width, length) == entry::unsupported(s),
        value(s, width, length).0.core == s.core,
{
}

pub proof fn repeat_guards_apply_at_every_element(s: State, width: Width, length: u8)
    requires
        s.core.cpu.gpr.len() == 16,
        length == 0 || length > 15 || s.core.cpu.flags & 0x300u64 != 0,
    ensures
        execute(s, width, length).1 is Stopped,
        execute(s, width, length).0.core == s.core,
        execute(s, width, length).0.pending == s.pending,
{
    let flags = s.core.cpu.flags;
    assert(flags & 0x300u64 != 0 ==> flags & 0x100u64 != 0 || flags & 0x200u64 != 0)
        by (bit_vector);
}

}
