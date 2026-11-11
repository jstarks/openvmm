// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use super::super::Config;
#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::operand::{
    Address, Operand, Segment, SegmentBases, Width,
};
#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::{
    control, descriptor, operand, profile, scalar as operations,
};
#[cfg(verus_keep_ghost)]
use super::super::shared::entry::{Instruction, MemoryTask};
use super::*;

verus! {
pub open spec fn registers(cpu: model::State) -> Seq<u64> {
    cpu.gpr.map(|i: int, value: int| value as u64)
}
pub open spec fn scalar(cpu: model::State, source: Operand) -> Option<u64> {
    match source {
        Operand::Register(reg) => if reg.valid() { Some(operand::model::read(registers(cpu), reg)) } else { None },
        Operand::Immediate(imm) => Some(imm.value),
        _ => None,
    }
}
pub open spec fn bases(s: State) -> SegmentBases {
    match s.system {
        Some(system) => SegmentBases { fs: system.fs.base, gs: system.gs.base },
        None => SegmentBases { fs: 0, gs: 0 },
    }
}
pub open spec fn linear(s: State, address: Address, length: u8) -> u64 {
    operand::model::linear(registers(s.core.cpu),
        ((s.core.cpu.rip + length as int) % 0x1_0000_0000_0000_0000int) as u64, address, bases(s))
}
pub open spec fn unsupported(s: State) -> (State, Tick) {
    stop(s, EventDiagnostic::Instruction(PagedDiagnostic::Unsupported))
}
pub open spec fn retire(s: State, cpu: model::State, length: u8, shadow: bool, serializing: bool) -> (State, Tick) {
    let cpu = model::State { rip: (cpu.rip + length as int) % 0x1_0000_0000_0000_0000int,
        flags: cpu.flags & !0x10000u64, ..cpu };
    (State { core: c::boundary_commit(s.core, cpu, true).0,
        phase: Phase::Ready, shadow, handler_pending: false, ..s }, Tick::Retired(serializing))
}
pub open spec fn memory(s: State, address: u64, width: Width, request: WordAccess,
    length: u8, task: MemoryTask) -> (State, Tick) {
    let size = (operand::model::bits(width) / 8) as u8;
    if !supported_access(address,width) { unsupported(s) }
    else {
        let core = if size == 8 { c::boundary_begin(s.core, address, Some(request)).0 }
            else { c::boundary_sized(s.core, address, request, size).0 };
        (State { core, phase: Phase::EntryMemory { address, length, task }, ..s }, Tick::Pending)
    }
}
pub open spec fn supported_access(address:u64,width:Width)->bool {
    let size=operand::model::bits(width)/8;
    address as int+size-1<=u64::MAX && address%4096+size<=4096
        && mmu_model::canonical(address as int) && mmu_model::canonical(address as int+size-1)
        && (size==8 || address%8+size<=8)
}
#[verifier::opaque]
pub open spec fn execute(s: State, instruction: Instruction, length: u8) -> (State, Tick) {
    let cpu = s.core.cpu;
    if length == 0 || length > 15 { unsupported(s) }
    else if cpu.flags & 0x100u64 != 0 {
        stop(s, EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))
    } else { match instruction {
        Instruction::Nop=>retire(s,cpu,length,false,false),
        Instruction::Cpuid => {
            let values = profile::target(((cpu.gpr[0] as u64) & 0xffff_ffffu64) as u32,
                ((cpu.gpr[1] as u64) & 0xffff_ffffu64) as u32);
            retire(s, model::State { gpr: cpu.gpr.update(0,values[0] as int)
                .update(3,values[1] as int).update(1,values[2] as int).update(2,values[3] as int),
                ..cpu },length,false,true)
        },
        Instruction::Branch { target, condition } => {
            if control::model::condition(condition,cpu.flags) {
                if !mmu_model::canonical(target as int) { unsupported(s) }
                else { retire(s,model::State {rip:target as int,..cpu},0,false,false) }
            } else { retire(s,cpu,length,false,false) }
        },
        Instruction::PushFlags => {
            if cpu.gpr[4] < 8 || cpu.gpr[4] % 8 != 0 { unsupported(s) }
            else { memory(s,(cpu.gpr[4]-8) as u64,Width::Qword,
                WordAccess::Write(control::model::flags_image(cpu.flags)),length,
                MemoryTask::Push {stack:(cpu.gpr[4]-8) as u64}) }
        },
        Instruction::Pop { dst } => {
            if !dst.valid() || dst@.width != Width::Qword || cpu.gpr[4] + 8 > u64::MAX
                || cpu.gpr[4] % 8 != 0 { unsupported(s) }
            else { memory(s,cpu.gpr[4] as u64,Width::Qword,WordAccess::Read,length,
                MemoryTask::Pop {stack:cpu.gpr[4] as u64,dst}) }
        },
        Instruction::PopFlags => {
            if cpu.gpr[4] + 8 > u64::MAX || cpu.gpr[4] % 8 != 0 { unsupported(s) }
            else { memory(s,cpu.gpr[4] as u64,Width::Qword,WordAccess::Read,length,
                MemoryTask::Flags {stack:cpu.gpr[4] as u64}) }
        },
        Instruction::FarReturn => {
            if s.system is None || cpu.gpr[4] + 16 > u64::MAX || cpu.gpr[4] % 8 != 0 { unsupported(s) }
            else { memory(s,cpu.gpr[4] as u64,Width::Qword,WordAccess::Read,length,
                MemoryTask::FarTarget {stack:cpu.gpr[4] as u64}) }
        },
        Instruction::ZeroExtend { dst, src } => {
            if !dst.valid() || !src.valid() || operand::model::bits(dst@.width) <= operand::model::bits(src@.width)
                || !(src@.width is Byte || src@.width is Word) { unsupported(s) }
            else { retire(s, model::State { gpr: operand::model::write(registers(cpu), dst,
                operand::model::read(registers(cpu), src)).map(|i: int, v: u64| v as int),
                ..cpu }, length, false, false) }
        },
        Instruction::Integer {operation,dst,source}=>alu::execute(s,operation,Operand::Register(dst),source,length),
        Instruction::Alu {operation,destination,source}=>alu::execute(s,operation,destination,source,length),
        Instruction::Multiply {dst,source,immediate}=>alu::multiply(s,dst,source,immediate,length),
        Instruction::RepeatStore {width}=>repeat::execute(s,width,length),
        Instruction::SignExtend {dst,source,width}=>{
            if !dst.valid() || operand::model::bits(dst@.width)<=operand::model::bits(width) {unsupported(s)}
            else {match source {
                Operand::Memory {address,width:actual}=>{
                    if !address.valid() || actual!=width {unsupported(s)}
                    else {memory(s,linear(s,address,length),width,WordAccess::Read,length,
                        MemoryTask::SignedLoad {dst,width})}
                },
                _=>match scalar(cpu,source) {
                    None=>unsupported(s),Some(value)=>alu::signed(s,dst,width,value,length),
                },
            }}
        },
        Instruction::SignHigh {width}=>{
            if !(width is Word || width is Dword || width is Qword) {unsupported(s)}
            else {
                let value=operations::model::sign_high(cpu.gpr[0] as u64,width);
                let high=if width==Width::Word {((cpu.gpr[2] as u64)&!0xffffu64)|value} else {value};
                retire(s,model::State {gpr:cpu.gpr.update(2,high as int),..cpu},length,false,false)
            }
        },
        Instruction::Divide {source,width,signed}=>{
            if !(width is Dword || width is Qword) {unsupported(s)}
            else {match source {
                Operand::Memory {address,width:actual}=>{
                    if !address.valid() || actual!=width {unsupported(s)}
                    else {memory(s,linear(s,address,length),width,WordAccess::Read,length,
                        MemoryTask::Division {width,signed})}
                },
                _=>match scalar(cpu,source) {
                    None=>unsupported(s),Some(divisor)=>alu::division(s,divisor,width,signed,length),
                },
            }}
        },
        Instruction::Bit {operation,dst,index}=>{
            if !dst.valid() || !(dst@.width is Word || dst@.width is Dword || dst@.width is Qword)
                || scalar(cpu,index) is None {unsupported(s)}
            else {
                let result=operations::model::bit(operation,operand::model::read(registers(cpu),dst),
                    scalar(cpu,index).unwrap(),dst@.width,cpu.flags);
                let gpr=if result.write {operand::model::write(registers(cpu),dst,result.value)} else {registers(cpu)};
                retire(s,model::State {gpr:gpr.map(|i:int,v:u64|v as int),flags:result.flags,..cpu},length,false,false)
            }
        },
        Instruction::ReadControl {..} | Instruction::WriteControl {..} | Instruction::ReadMsr =>
            privilege::execute(s,instruction,length),
        Instruction::IndirectJump {source} | Instruction::IndirectCall {source}=>match source {
            Operand::Memory {address,width}=>{
                if !address.valid() || width!=Width::Qword {unsupported(s)}
                else {memory(s,linear(s,address,length),width,WordAccess::Read,length,
                    if instruction is IndirectCall {MemoryTask::CallTarget}else{MemoryTask::JumpTarget})}
            },
            _=>match scalar(cpu,source) {None=>unsupported(s),Some(target)=>
                if instruction is IndirectCall {alu::call(s,target,length)}else{alu::jump(s,target)}},
        },
        Instruction::Load { dst, address, width } => {
            if !dst.valid() || !address.valid() || operand::model::bits(dst@.width) < operand::model::bits(width) {
                unsupported(s)
            } else { memory(s, linear(s, address, length), width, WordAccess::Read, length, MemoryTask::Load { dst }) }
        },
        Instruction::Store { address, width, source } => {
            if !address.valid() || scalar(cpu, source) is None { unsupported(s) }
            else { memory(s, linear(s, address, length), width,
                WordAccess::Write(scalar(cpu, source).unwrap()), length, MemoryTask::Store) }
        },
        Instruction::Table { address, idt } => {
            if !address.valid() { unsupported(s) }
            else { memory(s, linear(s, address, length), Width::Word,
                WordAccess::Read, length, MemoryTask::TableLimit { idt }) }
        },
        Instruction::Segment { segment: dst, src } => {
            if !src.valid() || !(dst is Ds || dst is Ss || dst is Es || dst is Fs || dst is Gs) || s.system is None { unsupported(s) }
            else {
                let system=s.system.unwrap();
                let selector = (operand::model::read(registers(cpu), src) & 0xffffu64) as u16;
                let offset = (selector & !7u16) as u64;
                if (dst is Fs && system.fs.base!=0) || (dst is Gs && system.gs.base!=0) {unsupported(s)}
                else if selector==0 {
                    let null=super::super::memory_core::cpu_core::system::NULL_SEGMENT;
                    let system=match dst {
                        Segment::Ds=>SystemState {ds:null,..system},Segment::Ss=>SystemState {ss:null,..system},
                        Segment::Es=>SystemState {es:null,..system},Segment::Fs=>SystemState {fs:null,..system},
                        Segment::Gs=>SystemState {gs:null,..system},_=>system,
                    };
                    retire(State {system:Some(system),..s},cpu,length,dst is Ss,false)
                } else if selector % 8 != 0 || offset as int + 7 > s.tables.gdt_limit as int
                    || s.tables.gdt_base as int + offset as int > u64::MAX {
                    stop(s, EventDiagnostic::Descriptor(Stage::Stack))
                } else { memory(s, (s.tables.gdt_base as int + offset as int) as u64,
                    Width::Qword, WordAccess::Read, length, MemoryTask::Segment { segment: dst, selector }) }
            }
        },
        Instruction::Push { source } => {
            if scalar(cpu, source) is None || cpu.gpr[4] < 8 || cpu.gpr[4] % 8 != 0 { unsupported(s) }
            else { memory(s, (cpu.gpr[4] - 8) as u64, Width::Qword,
                WordAccess::Write(scalar(cpu, source).unwrap()), length,
                MemoryTask::Push { stack: (cpu.gpr[4] - 8) as u64 }) }
        },
        Instruction::Return | Instruction::Leave => {
            let stack = if instruction is Return { cpu.gpr[4] as u64 } else { cpu.gpr[5] as u64 };
            if stack as int + 8 > u64::MAX || stack % 8 != 0 { unsupported(s) }
            else { memory(s, stack, Width::Qword, WordAccess::Read, length,
                if instruction is Return { MemoryTask::Return { stack } } else { MemoryTask::Leave { stack } }) }
        },
        Instruction::Jump { target, zero } => {
            let taken = match zero { None => true, Some(wanted) => (cpu.flags & 0x40u64 != 0) == wanted };
            if taken && !mmu_model::canonical(target as int) { unsupported(s) }
            else if taken { retire(s, model::State { rip: target as int, ..cpu }, 0, false, false) }
            else { retire(s, cpu, length, false, false) }
        },
    } }
}
pub open spec fn value(s: State, value: u64) -> (State, Tick) {
    let (address, length, task) = match s.phase {
        Phase::EntryMemory { address, length, task } => (address, length, task), _ => arbitrary(),
    };
    let cpu = s.core.cpu;
    match task {
        MemoryTask::RepeatStore {width}=>repeat::value(s,width,length),
        MemoryTask::CallTarget=>alu::call(s,value,length),
        MemoryTask::Multiply {dst,immediate}=>alu::multiply_value(s,dst,value,immediate,length),
        MemoryTask::AluRegister {operation,dst}=>{
            if !dst.valid() {unsupported(s)}
            else {alu::finish(s,operation,Some(dst),operand::model::read(registers(cpu),dst),value,dst@.width,length)}
        },
        MemoryTask::AluMemory {operation,source,width}=>alu::finish(s,operation,None,value,source,width,length),
        MemoryTask::SignedLoad {dst,width}=>alu::signed(s,dst,width,value,length),
        MemoryTask::Division {width,signed}=>alu::division(s,value,width,signed,length),
        MemoryTask::JumpTarget=>alu::jump(s,value),
        MemoryTask::Pop {stack,dst} => {
            if !dst.valid() || dst@.width != Width::Qword || stack as int + 8 > u64::MAX { unsupported(s) }
            else {
                let gpr = operand::model::write(
                    cpu.gpr.update(4,stack as int+8).map(|i:int,v:int|v as u64),dst,value);
                retire(s,model::State {gpr:gpr.map(|i:int,v:u64|v as int),..cpu},length,false,false)
            }
        },
        MemoryTask::Flags {stack} => match control::model::restore_flags(value) {
            None => unsupported(s),
            Some(flags) => {
                if stack as int + 8 > u64::MAX {unsupported(s)}
                else {retire(s,model::State {gpr:cpu.gpr.update(4,stack as int+8),
                    flags,..cpu},length,false,false)}
            },
        },
        MemoryTask::FarTarget {stack} => {
            if stack as int + 16 > u64::MAX {unsupported(s)}
            else {memory(s,(stack+8) as u64,Width::Qword,WordAccess::Read,length,
                MemoryTask::FarSelector {stack,target:value})}
        },
        MemoryTask::FarSelector {stack,target} => {
            if value == 0 || value > 0xffff || value % 8 != 0
                || value as int + 7 > s.tables.gdt_limit as int
                || s.tables.gdt_base as int + value as int > u64::MAX || !mmu_model::canonical(target as int) {
                unsupported(s)
            } else {memory(s,(s.tables.gdt_base as int + value as int) as u64,Width::Qword,
                WordAccess::Read,length,MemoryTask::FarCode {stack,target,selector:value as u16})}
        },
        MemoryTask::FarCode {stack,target,selector} => match descriptor::model::load_code(value,selector) {
            None => stop(s,EventDiagnostic::Descriptor(Stage::Code)),
            Some(code) => match s.system {
                None => unsupported(s),
                Some(system) => {
                    if stack as int + 16 > u64::MAX || !mmu_model::canonical(target as int) {unsupported(s)}
                    else {
                        let system = super::super::memory_core::cpu_core::system::SystemState {cs:code,..system};
                        retire(State {system:Some(system),..s},model::State {
                            gpr:cpu.gpr.update(4,stack as int+16),rip:target as int,..cpu},0,false,false)
                    }
                },
            },
        },
        MemoryTask::Load { dst } => {
            if !dst.valid() { unsupported(s) }
            else { retire(s, model::State { gpr: operand::model::write(registers(cpu), dst, value)
                .map(|i: int, v: u64| v as int), ..cpu }, length, false, false) }
        },
        MemoryTask::Store => retire(s, cpu, length, false, false),
        MemoryTask::TableLimit { idt } => {
            if address as int + 2 > u64::MAX { unsupported(s) }
            else { memory(s, (address + 2) as u64, Width::Qword, WordAccess::Read, length,
                MemoryTask::TableBase { idt, limit: (value & 0xffffu64) as u16 }) }
        },
        MemoryTask::TableBase { idt, limit } => {
            if !mmu_model::canonical(value as int) {
                stop(s, EventDiagnostic::Descriptor(if idt { Stage::Idt } else { Stage::Code }))
            } else {
                let tables = if idt { Tables { idt_base: value, idt_limit: limit, ..s.tables } }
                    else { Tables { gdt_base: value, gdt_limit: limit, ..s.tables } };
                retire(State { tables, ..s }, cpu, length, false, false)
            }
        },
        MemoryTask::Segment { segment: dst, selector } => match descriptor::model::load_data(value, selector) {
            None => stop(s, EventDiagnostic::Descriptor(Stage::Stack)),
            Some(segment) => match s.system {
                None => unsupported(s),
                Some(system) => {
                    let system = match dst {
                        Segment::Ds => super::super::memory_core::cpu_core::system::SystemState { ds: segment, ..system },
                        Segment::Ss => super::super::memory_core::cpu_core::system::SystemState { ss: segment, ..system },
                        Segment::Es => super::super::memory_core::cpu_core::system::SystemState { es: segment, ..system },
                        Segment::Fs => super::super::memory_core::cpu_core::system::SystemState { fs: segment, ..system },
                        Segment::Gs => super::super::memory_core::cpu_core::system::SystemState { gs: segment, ..system },
                        _ => system,
                    };
                    if !(dst is Ds || dst is Ss || dst is Es || dst is Fs || dst is Gs) { unsupported(s) }
                    else { retire(State { system: Some(system), ..s }, cpu, length, dst is Ss, false) }
                },
            },
        },
        MemoryTask::Push { stack } => retire(s, model::State {
            gpr: cpu.gpr.update(4, stack as int), ..cpu }, length, false, false),
        MemoryTask::Return { stack } => {
            if stack as int + 8 > u64::MAX || !mmu_model::canonical(value as int) { unsupported(s) }
            else { retire(s, model::State { gpr: cpu.gpr.update(4, stack as int + 8),
                rip: value as int, ..cpu }, 0, false, false) }
        },
        MemoryTask::Leave { stack } => {
            if stack as int + 8 > u64::MAX { unsupported(s) }
            else { retire(s, model::State { gpr: cpu.gpr.update(4, stack as int + 8).update(5, value as int),
                ..cpu }, length, false, false) }
        },
    }
}
}
