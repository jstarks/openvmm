// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use super::super::Config;
#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::operand::{
    Address, Operand, Segment, SegmentBases, Width,
};
#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::{compare, integer};
#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::{
    control, descriptor, operand, profile, scalar as operations, system,
};
#[cfg(verus_keep_ghost)]
use super::super::mmu_core::shared::io::IoReply;
#[cfg(verus_keep_ghost)]
use super::super::shared::entry::{Instruction, MemoryTask, Port, PortRequest};
use super::*;

verus! {
pub open spec fn registers(cpu: model::State) -> Seq<u64> {
    cpu.gpr.map(|i: int, value: int| value as u64)
}
pub open spec fn byte_swap(value:u64,wide:bool)->u64 {
    let swapped=((value&0xffu64)<<56) | ((value&0xff00u64)<<40)
        | ((value&0xff0000u64)<<24) | ((value&0xff000000u64)<<8)
        | ((value>>8)&0xff000000u64) | ((value>>24)&0xff0000u64)
        | ((value>>40)&0xff00u64) | (value>>56);
    if wide {swapped} else {swapped>>32}
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
pub open spec fn exchange_add(s:State,destination:Operand,source:operand::Register,locked:bool,length:u8)->(State,Tick) {
    if !source.valid() || !(destination is Memory) {unsupported(s)}
    else if destination->width!=source@.width {unsupported(s)}
    else {
        let result=if locked {entry::locked_alu(s,integer::Operation::Add,destination,Operand::Register(source),length)}
            else {alu::execute(s,integer::Operation::Add,destination,Operand::Register(source),length)};
        match result.0.phase {
            Phase::EntryMemory {address,length,..}=>(State {phase:Phase::EntryMemory {
                address,length,task:MemoryTask::ExchangeAdd {register:source,locked}},..result.0},result.1),
            _=>result,
        }
    }
}
pub open spec fn load_task(s:State,source:operand::Register,length:u8)->(State,Tick) {
    let selector=operand::model::read(registers(s.core.cpu),source) as u16;
    if !source.valid() || source@.width!=Width::Word || s.system is None {unsupported(s)}
    else if selector==0 || selector&7u16!=0 || selector as int+15>s.tables.gdt_limit as int
        || s.tables.gdt_base as int+selector as int+15>u64::MAX {
        stop(s,EventDiagnostic::Descriptor(Stage::Stack))
    } else {memory(s,(s.tables.gdt_base+selector) as u64,Width::Qword,WordAccess::Read,length,
        MemoryTask::TaskLow {selector})}
}
pub open spec fn timestamp(s:State,length:u8)->(State,Tick) {
    if profile::target(1,0)[3]&16u32==0 {entry(s,Event::InvalidOpcode)}
    else {(State {phase:Phase::Timestamp {sequence:s.decode_sequence,length,value:None},..s},Tick::Pending)}
}
pub open spec fn complete_timestamp(s:State,sequence:u64,clock:u64)->(State,bool) {
    match s.phase {
        Phase::Timestamp {sequence:pending,length,value:None} if pending==sequence=>
            (State {phase:Phase::Timestamp {sequence,length,value:Some(clock)},..s},true),
        _=>(s,false),
    }
}
pub open spec fn finish_timestamp(s:State)->(State,Tick) {
    match s.phase {
        Phase::Timestamp {length,value:Some(value),..}=>retire(s,model::State {
            gpr:s.core.cpu.gpr.update(0,(value as u32) as int).update(2,(value>>32) as int),
            ..s.core.cpu},length,false,false),
        _=>(s,Tick::Waiting),
    }
}
pub open spec fn port_io(s:State,port:Port,width:Width,write:bool,length:u8)->(State,Tick) {
    if width==Width::Qword {unsupported(s)} else {
        let port=match port {Port::Dx=>s.core.cpu.gpr[2] as u16,Port::Immediate(port)=>port as u16};
        let access=if write {WordAccess::Write(s.core.cpu.gpr[0] as u64&operand::model::mask(width))}
            else {WordAccess::Read};
        (State {phase:Phase::PortIo {request:PortRequest {sequence:s.decode_sequence,port,width,access},
            length,reply:None},..s},Tick::Pending)
    }
}
pub open spec fn complete_port_io(s:State,sequence:u64,completion:IoReply)->(State,bool) {
    match s.phase {
        Phase::PortIo {request,length,reply:None}=>{
            if sequence!=request.sequence {(s,false)} else {
                match (request.access,completion) {
                    (WordAccess::Read,IoReply::Read(_)) | (WordAccess::Write(_),IoReply::Written)=>
                        (State {phase:Phase::PortIo {request,length,reply:Some(completion)},..s},true),
                    _=>(s,false),
                }
            }
        },
        _=>(s,false),
    }
}
pub open spec fn finish_port_io(s:State)->(State,Tick) {
    match s.phase {
        Phase::PortIo {request,length,reply:Some(completion)}=>{
            let cpu=match completion {
                IoReply::Read(value)=>{
                    let mask=operand::model::mask(request.width);
                    let value=value&mask;
                    let value=if request.width==Width::Dword || request.width==Width::Qword {value}
                        else {(s.core.cpu.gpr[0] as u64&!mask)|value};
                    model::State {gpr:s.core.cpu.gpr.update(0,value as int),..s.core.cpu}
                },
                IoReply::Written=>s.core.cpu,
            };
            retire(s,cpu,length,false,false)
        },
        _=>(s,Tick::Waiting),
    }
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
        let core = if system_memory_task(task) {c::boundary_system_span(s.core,address,request,size).0}
            else {c::boundary_span(s.core, address, request, size).0};
        (State { core, phase: Phase::EntryMemory { address, length, task }, ..s }, Tick::Pending)
    }
}
pub open spec fn system_memory_task(task:MemoryTask)->bool {
    task is TaskLow || task is TaskHigh || task is TaskBusy || task is Segment || task is FarCode
}
pub open spec fn supported_access(address:u64,width:Width)->bool {
    let size=operand::model::bits(width)/8;
    address as int+size-1<=u64::MAX
        && mmu_model::canonical(address as int) && mmu_model::canonical(address as int+size-1)
}
pub open spec fn conditional_value(s:State,condition:control::Condition,
    dst:operand::Register,value:u64,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    if !dst.valid() || dst@.width==Width::Byte {unsupported(s)}
    else {
        let selected=if control::model::condition(condition,cpu.flags) {value}
            else {operand::model::read(registers(cpu),dst)};
        retire(s,model::State {gpr:operand::model::write(registers(cpu),dst,selected)
            .map(|i:int,v:u64|v as int),..cpu},length,false,false)
    }
}
pub open spec fn compare_exchange(s:State,destination:Operand,source:operand::Register,length:u8)->(State,Tick) {
        let cpu=s.core.cpu;
        if length==0 || length>15 {unsupported(s)}
        else if cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
        else if !source.valid() {unsupported(s)}
        else {match destination {
            Operand::Register(dst)=>match compare::model::registers(cpu,dst,source) {
                Some(updated)=>retire(s,updated,length,false,false),None=>unsupported(s),
            },
            Operand::Memory {address,width}=>{
                if !address.valid() || width!=source@.width {unsupported(s)}
                else {
                    let va=linear(s,address,length);
                    let start=c::boundary_compare_exchange(s.core,va,cpu.gpr[0] as u64,
                        operand::model::read(registers(cpu),source),width);
                    if !start.1 {unsupported(s)}
                    else {
                        (State {core:start.0,phase:Phase::EntryMemory {address:va,length,
                            task:MemoryTask::CompareExchange {width}},..s},Tick::Pending)
                    }
                }
            },
            _=>unsupported(s),
        }}
}
pub open spec fn locked_alu(s:State,operation:integer::Operation,destination:Operand,
    source:Operand,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    if length==0 || length>15 {unsupported(s)}
    else if cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
    else {match destination {
        Operand::Memory {address,width}=>{
            if !address.valid() || scalar(cpu,source) is None {unsupported(s)}
            else {
                let value=scalar(cpu,source).unwrap();
                let adjusted=alu::memory_address(operation,address,source,value,width);
                let va=linear(s,adjusted,length);
                let start=c::boundary_locked_modify(s.core,va,operation,value,cpu.flags,width);
                if !start.1 {unsupported(s)} else {
                    (State {core:start.0,phase:Phase::EntryMemory {address:va,length,
                        task:MemoryTask::LockedAlu {operation,source:value,width}},..s},Tick::Pending)
                }
            }
        },
        _=>unsupported(s),
    }}
}
#[verifier::opaque]
pub open spec fn exchange_memory(s:State,address:Address,source:operand::Register,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    if length==0 || length>15 || !address.valid() || !source.valid() {unsupported(s)}
    else if cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
    else {
        let at=linear(s,address,length);
        let result=c::boundary_exchange(s.core,at,operand::model::read(registers(cpu),source),source@.width);
        if !result.1 {unsupported(s)}
        else {(State {core:result.0,phase:Phase::EntryMemory {address:at,length,
            task:MemoryTask::Exchange {register:source}},..s},Tick::Pending)}
    }
}
#[verifier::opaque]
pub open spec fn execute(s: State, instruction: Instruction, length: u8) -> (State, Tick) {
    let cpu = s.core.cpu;
    if length == 0 || length > 15 { unsupported(s) }
    else if cpu.flags & 0x100u64 != 0 {
        stop(s, EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))
    } else if is_user(s) && (instruction is ReadControl || instruction is WriteControl
        || instruction is ReadDebug || instruction is WriteDebug || instruction is ReadMsr
        || instruction is Table || instruction is LoadTask || instruction is LoadLdt) {
        entry(s,Event::GeneralProtection)
    } else if is_user(s) && (instruction is FarReturn || instruction is PortIo || instruction is Breakpoint) {unsupported(s)}
    else { match instruction {
        Instruction::Syscall=>privilege::fast_entry(s,false,length),
        Instruction::Sysret=>privilege::fast_entry(s,true,length),
        Instruction::XmmLoad {..}|Instruction::XmmStore {..}
            |Instruction::XmmCopyLow {..}|Instruction::XmmUnpack {..}
            |Instruction::XmmUnpackNarrow {..}|Instruction::XmmShuffle {..}
            |Instruction::XmmByteShift {..}
            |Instruction::XmmLogic {..}
            |Instruction::XmmCompare {..}|Instruction::XmmCompareMemory {..}|Instruction::XmmMask {..}
            |Instruction::XmmArithmetic {..}|Instruction::XmmArithmeticMemory {..}
            |Instruction::XmmCopy {..}|Instruction::XmmMerge {..}|Instruction::XmmMemory {..}=>
                privilege::execute_xmm(s,instruction,length),
        Instruction::ByteSwap {dst}=>{
            if !dst.valid() || !(dst@.width is Dword || dst@.width is Qword) {unsupported(s)}
            else {retire(s,model::State {gpr:operand::model::write(registers(cpu),dst,
                byte_swap(operand::model::read(registers(cpu),dst),dst@.width==Width::Qword))
                    .map(|i:int,v:u64|v as int),..cpu},length,false,false)}
        },
        Instruction::ReadTimestamp=>timestamp(s,length),
        Instruction::ExchangeMemory {address,source}=>exchange_memory(s,address,source,length),
        Instruction::ExchangeRegisters {left,right}=>exchange_registers(s,left,right,length),
        Instruction::Breakpoint=>privilege::breakpoint(s,length),
        Instruction::SwapGs=>privilege::swap_gs(s,length),
        Instruction::LoadTask {source}=>load_task(s,source,length),
        Instruction::LoadLdt {source}=>{
            if s.system is None || !source.valid() || source@.width!=Width::Word
                || operand::model::read(registers(cpu),source)!=0 {unsupported(s)}
            else {retire(State {system:Some(super::super::memory_core::cpu_core::system::SystemState {
                ldtr:super::super::memory_core::cpu_core::system::NULL_SEGMENT,
                ..s.system.unwrap()}),..s},cpu,length,false,false)}
        },
        Instruction::PortIo {port,width,write}=>port_io(s,port,width,write,length),
        Instruction::CompareExchange {destination,source}=>compare_exchange(s,destination,source,length),
        Instruction::LockedAlu {operation,destination,source}=>locked_alu(s,operation,destination,source,length),
        Instruction::ExchangeAdd {destination,source,locked}=>exchange_add(s,destination,source,locked,length),
        Instruction::Scan {dst,source,reverse}=>alu::scan(s,dst,source,reverse,length),
        Instruction::ReadSegment {segment,destination}=>match s.system {
            None=>unsupported(s),
            Some(image)=>{
                let value=(match segment {
                    Segment::Cs=>image.cs.selector,Segment::Ss=>image.ss.selector,
                    Segment::Ds=>image.ds.selector,Segment::Es=>image.es.selector,
                    Segment::Fs=>image.fs.selector,Segment::Gs=>image.gs.selector,
                }) as u64;
                match destination {
                    Operand::Register(dst)=>{
                        if !dst.valid() || dst@.width==Width::Byte {unsupported(s)}
                        else {retire(s,model::State {gpr:operand::model::write(registers(cpu),dst,value)
                            .map(|i:int,v:u64|v as int),..cpu},length,false,false)}
                    },
                    Operand::Memory {address,width}=>{
                        if !address.valid() || width!=Width::Word {unsupported(s)}
                        else {memory(s,linear(s,address,length),width,WordAccess::Write(value),
                            length,MemoryTask::Store)}
                    },
                    _=>unsupported(s),
                }
            },
        },
        Instruction::Nop=>retire(s,cpu,length,false,false),
        Instruction::Fence=>retire(s,cpu,length,false,true),
        Instruction::Direction {set}=>retire(s,model::State {
            flags:if set {cpu.flags|0x400u64} else {cpu.flags&!0x400u64},..cpu},length,false,false),
        Instruction::ConditionalMove {condition,dst,source}=>{
            if !dst.valid() || dst@.width==Width::Byte {unsupported(s)}
            else {match source {
                Operand::Register(src)=>{
                    if !src.valid() || src@.width!=dst@.width {unsupported(s)}
                    else {conditional_value(s,condition,dst,operand::model::read(registers(cpu),src),length)}
                },
                Operand::Memory {address,width}=>{
                    if !address.valid() || width!=dst@.width {unsupported(s)}
                    else {memory(s,linear(s,address,length),width,WordAccess::Read,length,
                        MemoryTask::ConditionalMove {condition,dst})}
                },
                _=>unsupported(s),
            }}
        },
        Instruction::SetCondition {condition,destination}=>{
            let value=if control::model::condition(condition,cpu.flags) {1u64} else {0u64};
            match destination {
                Operand::Register(dst)=>{
                    if !dst.valid() || dst@.width!=Width::Byte {unsupported(s)}
                    else {retire(s,model::State {gpr:operand::model::write(registers(cpu),dst,value)
                        .map(|i:int,v:u64|v as int),..cpu},length,false,false)}
                },
                Operand::Memory {address,width}=>{
                    if !address.valid() || width!=Width::Byte {unsupported(s)}
                    else {memory(s,linear(s,address,length),width,WordAccess::Write(value),
                        length,MemoryTask::Store)}
                },
                _=>unsupported(s),
            }
        },
        Instruction::Cpuid => {
            let values = control_io::cpuid(s,((cpu.gpr[0] as u64) & 0xffff_ffffu64) as u32,
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
                MemoryTask::StackCommit {stack:(cpu.gpr[4]-8) as u64}) }
        },
        Instruction::Pop { dst } => {
            if !dst.valid() || dst@.width != Width::Qword || cpu.gpr[4] + 8 > u64::MAX
                || cpu.gpr[4] % 8 != 0 { unsupported(s) }
            else { memory(s,cpu.gpr[4] as u64,Width::Qword,WordAccess::Read,length,
                MemoryTask::Pop {stack:cpu.gpr[4] as u64,dst}) }
        },
        Instruction::PopMemory {address}=>{
            if !address.valid() || cpu.gpr[4]+8>u64::MAX || cpu.gpr[4]%8!=0 {unsupported(s)}
            else {memory(s,cpu.gpr[4] as u64,Width::Qword,WordAccess::Read,length,
                MemoryTask::PopMemory {stack:cpu.gpr[4] as u64,address})}
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
        Instruction::MultiplyWide {source,width,signed}=>alu::wide_multiply(s,source,width,signed,length),
        Instruction::RepeatStore {width}=>repeat::execute(s,width,length),
        Instruction::RepeatMove {width}=>repeat::execute_move(s,width,length),
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
        Instruction::DoubleShift {dst,source,count,left}=>{
            if !dst.valid() || !source.valid() || dst@.width!=source@.width {unsupported(s)}
            else {match scalar(cpu,count) {
                None=>unsupported(s),
                Some(count)=>match operations::model::double_shift(operand::model::read(registers(cpu),dst),
                    operand::model::read(registers(cpu),source),count,dst@.width,left,cpu.flags) {
                    None=>unsupported(s),
                    Some(result)=>retire(s,model::State {gpr:operand::model::write(registers(cpu),dst,result.value)
                        .map(|i:int,v:u64|v as int),flags:result.flags,..cpu},length,false,false),
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
        Instruction::ReadControl {..} | Instruction::WriteControl {..} | Instruction::ReadMsr
            | Instruction::ReadDebug {..} | Instruction::WriteDebug {..} =>
            privilege::execute(s,instruction,length),
        Instruction::InitializeX87=>privilege::control_x87(s,system::X87Control::Initialize,length),
        Instruction::ControlX87 {operation}=>privilege::control_x87(s,operation,length),
        Instruction::SaveFp {address,wide}=>privilege::save_fp(s,address,wide,length),
        Instruction::RestoreFp {address,wide}=>privilege::restore_fp(s,address,wide,length),
        Instruction::LoadX87Integer {address,width,opcode}=>privilege::load_x87_integer(s,address,width,opcode,length),
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
                if is_user(s) && dst is Ss && selector<4 {entry(s,Event::GeneralProtection)}
                else if selector==0 || (selector<4 && (dst is Fs || dst is Gs)) {
                    let null=super::super::memory_core::cpu_core::system::NULL_SEGMENT;
                    let system=match dst {
                        Segment::Ds=>SystemState {ds:null,..system},Segment::Ss=>SystemState {ss:null,..system},
                        Segment::Es=>SystemState {es:null,..system},
                        Segment::Fs=>SystemState {fs:super::super::memory_core::cpu_core::system::SegmentState {
                            base:system.fs.base,selector,..null},..system},
                        Segment::Gs=>SystemState {gs:super::super::memory_core::cpu_core::system::SegmentState {
                            base:system.gs.base,selector,..null},..system},_=>system,
                    };
                    retire(State {system:Some(system),..s},cpu,length,dst is Ss,false)
                } else if (if dst is Fs || dst is Gs || is_user(s) {selector&4u16!=0} else {selector%8!=0})
                    || offset as int + 7 > s.tables.gdt_limit as int
                    || s.tables.gdt_base as int + offset as int > u64::MAX {
                    stop(s, EventDiagnostic::Descriptor(Stage::Stack))
                } else { memory(s, (s.tables.gdt_base as int + offset as int) as u64,
                    Width::Qword, WordAccess::Read, length, MemoryTask::Segment { segment: dst, selector }) }
            }
        },
        Instruction::StoreTable {address,idt}=>{
            let at=linear(s,address,length);
            if !address.valid() || at>u64::MAX-9 || !mmu_model::canonical(at as int)
                || !mmu_model::canonical(at as int+9) {unsupported(s)}
            else if at%4096>4086 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DataCrossPage))}
            else {memory(s,at,Width::Word,WordAccess::Write(
                if idt {s.tables.idt_limit as u64} else {s.tables.gdt_limit as u64}),length,
                MemoryTask::StoreTableBase {base:if idt {s.tables.idt_base} else {s.tables.gdt_base}})}
        },
        Instruction::Push { source } => {
            if cpu.gpr[4] < 8 || cpu.gpr[4] % 8 != 0 { unsupported(s) }
            else if let Operand::Memory {address,width}=source {
                if !address.valid() || width!=Width::Qword {unsupported(s)}
                else {memory(s,linear(s,address,length),Width::Qword,WordAccess::Read,length,
                    MemoryTask::PushValue {stack:(cpu.gpr[4]-8) as u64})}
            } else if scalar(cpu,source) is None {unsupported(s)}
            else {memory(s,(cpu.gpr[4]-8) as u64,Width::Qword,
                WordAccess::Write(scalar(cpu,source).unwrap()),length,
                MemoryTask::StackCommit {stack:(cpu.gpr[4]-8) as u64})}
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
#[verifier::opaque]
#[verifier::opaque]
pub open spec fn exchange_registers(s:State,left:operand::Register,right:operand::Register,length:u8)->(State,Tick) {
    if !left.valid() || !right.valid() || left@.width!=right@.width {unsupported(s)}
    else {
        let registers=registers(s.core.cpu);
        let a=operand::model::read(registers,left);
        let b=operand::model::read(registers,right);
        retire(s,model::State {gpr:operand::model::write(operand::model::write(registers,left,b),right,a)
            .map(|i:int,v:u64|v as int),..s.core.cpu},length,false,false)
    }
}
pub open spec fn exchange_value(s:State,register:operand::Register,value:u64,length:u8)->(State,Tick) {
    if !register.valid() {unsupported(s)}
    else {retire(s,model::State {gpr:operand::model::write(registers(s.core.cpu),register,value)
        .map(|i:int,v:u64|v as int),..s.core.cpu},length,false,true)}
}
#[verifier::opaque]
pub open spec fn segment_value(s:State,dst:Segment,selector:u16,value:u64,length:u8)->(State,Tick) {
    if is_user(s) && (((value>>45)&3u64)!=3 || (dst is Ss && selector&3u16!=3)) {
        stop(s,EventDiagnostic::Descriptor(Stage::Stack))
    } else {
    let loaded=if dst is Fs || dst is Gs || is_user(s) {descriptor::model::load_thread_data(value,selector)}
        else {descriptor::model::load_data(value,selector)};
    match loaded {
        None=>stop(s,EventDiagnostic::Descriptor(Stage::Stack)),
        Some(segment)=>match s.system {
            None=>unsupported(s),
            Some(system)=>{
                let updated=match dst {
                    Segment::Ds=>SystemState {ds:segment,..system},Segment::Ss=>SystemState {ss:segment,..system},
                    Segment::Es=>SystemState {es:segment,..system},Segment::Fs=>SystemState {fs:segment,..system},
                    Segment::Gs=>SystemState {gs:segment,..system},_=>system,
                };
                if !(dst is Ds || dst is Ss || dst is Es || dst is Fs || dst is Gs) {unsupported(s)}
                else {retire(State {system:Some(updated),..s},s.core.cpu,length,dst is Ss,false)}
            },
        },
        }
    }
}
#[verifier::opaque]
pub open spec fn pop_memory_value(s:State,value:u64,destination:Address,stack:u64,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    if !destination.valid() || stack as int+8>u64::MAX {unsupported(s)}
    else {
        let gpr=registers(cpu).update(4,(stack+8) as u64);
        let at=operand::model::linear(gpr,
            ((cpu.rip+length as int)%0x1_0000_0000_0000_0000int) as u64,destination,bases(s));
        memory(s,at,Width::Qword,WordAccess::Write(value),length,
            MemoryTask::StackCommit {stack:(stack+8) as u64})
    }
}
pub open spec fn value(s: State, value: u64) -> (State, Tick) {
    let (address, length, task) = match s.phase {
        Phase::EntryMemory { address, length, task } => (address, length, task), _ => arbitrary(),
    };
    let cpu = s.core.cpu;
    match task {
        MemoryTask::XmmLoad {index,wide}=>privilege::finish_xmm_load(s,index,value,wide,length),
        MemoryTask::XmmHalf {..}|MemoryTask::XmmLow {..}|MemoryTask::XmmHigh {..}=>
            privilege::finish_xmm_memory(s,address,task,value,length),
        MemoryTask::Exchange {register}=>exchange_value(s,register,value,length),
        MemoryTask::FpSaveProbe {base,save,first}=>fp::finish_probe(s,base,save,first,value,length),
        MemoryTask::FpRestoreProbe {base,wide,tail}=>fp::finish_restore_probe(s,base,wide,tail,length),
        MemoryTask::RestoreFp {index,wide}=>privilege::restore_fp_value(s,address,index,value,wide,length),
        MemoryTask::LoadX87Integer {width,opcode}=>privilege::load_x87_value(s,address,value,width,opcode,length),
        MemoryTask::ExchangeAdd {register:source,locked}=>{
            if !source.valid() {unsupported(s)} else {
                let result=integer::model::evaluate(integer::Operation::Add,value,
                    operand::model::read(registers(cpu),source),source@.width,cpu.flags);
                retire(s,model::State {gpr:operand::model::write(registers(cpu),source,value)
                    .map(|i:int,v:u64|v as int),flags:result.flags,..cpu},length,false,locked)
            }
        },
        MemoryTask::TaskLow {selector}=>{
            if address>u64::MAX-8 {unsupported(s)}
            else {memory(s,(address+8) as u64,Width::Qword,WordAccess::Read,length,
                MemoryTask::TaskHigh {selector,low:value})}
        },
        MemoryTask::TaskHigh {selector,low}=>{
            match descriptor::model::load_task(low,value,selector) {
                None=>stop(s,EventDiagnostic::Descriptor(Stage::Stack)),
                Some(image)=>{
                    if address<8 {unsupported(s)}
                    else {
                        let at=(address-8) as u64;
                        let result=c::boundary_compare_exchange(s.core,at,low,low|(1u64<<41),Width::Qword);
                        if !result.1 {unsupported(s)}
                        else {(State {core:result.0,phase:Phase::EntryMemory {address:at,length,
                            task:MemoryTask::TaskBusy {image,low}},..s},Tick::Pending)}
                    }
                },
            }
        },
        MemoryTask::TaskBusy {image,low}=>{
            if value!=low {memory(s,address,Width::Qword,WordAccess::Read,length,
                MemoryTask::TaskLow {selector:image.selector})}
            else if s.system is None || !super::super::memory_core::cpu_core::system::model::supported_task(image) {
                unsupported(s)
            } else {retire(State {system:Some(super::super::memory_core::cpu_core::system::SystemState {
                tr:image,..s.system.unwrap()}),..s},cpu,length,false,false)}
        },
        MemoryTask::Scan {dst,reverse}=>alu::scan_value(s,dst,value,reverse,length),
        MemoryTask::LockedAlu {operation,source,width}=>{
            let result=integer::model::evaluate(operation,value,source,width,cpu.flags);
            retire(s,model::State {flags:result.flags,..cpu},length,false,true)
        },
        MemoryTask::CompareExchange {width}=>
            retire(s,compare::model::memory(cpu,value,width),length,false,true),
        MemoryTask::RepeatStore {width}=>repeat::value(s,width,length),
        MemoryTask::RepeatRead {width}=>repeat::move_read(s,width,value,length),
        MemoryTask::RepeatWrite {width}=>repeat::move_value(s,width,length),
        MemoryTask::ConditionalMove {condition,dst}=>conditional_value(s,condition,dst,value,length),
        MemoryTask::CallTarget=>alu::call(s,value,length),
        MemoryTask::Multiply {dst,immediate}=>alu::multiply_value(s,dst,value,immediate,length),
        MemoryTask::MultiplyWide {width,signed}=>alu::wide_product(s,value,width,signed,length),
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
        MemoryTask::PopMemory {stack,address:destination}=>pop_memory_value(s,value,destination,stack,length),
        MemoryTask::Flags {stack} => match control::model::restore_flags(value) {
            None => unsupported(s),
            Some(flags) => {
                if stack as int + 8 > u64::MAX {unsupported(s)}
                else {retire(s,model::State {gpr:cpu.gpr.update(4,stack as int+8),
                    flags:if is_user(s) {(flags&!0x200u64)|(cpu.flags&0x200u64)} else {flags},..cpu},length,false,false)}
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
        MemoryTask::Store|MemoryTask::XmmWideStore => retire(s, cpu, length, false, false),
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
        MemoryTask::Segment {segment:dst,selector}=>segment_value(s,dst,selector,value,length),
        MemoryTask::StackCommit { stack } => retire(s, model::State {
            gpr: cpu.gpr.update(4, stack as int), ..cpu }, length, false, false),
        MemoryTask::StoreTableBase {base}=>{
            if address>u64::MAX-2 {unsupported(s)}
            else {memory(s,(address+2) as u64,Width::Qword,WordAccess::Write(base),length,MemoryTask::Store)}
        },
        MemoryTask::PushValue {stack}=>memory(s,stack,Width::Qword,WordAccess::Write(value),length,
            MemoryTask::StackCommit {stack}),
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
