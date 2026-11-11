// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::operand::{Operand, Register, Width};
#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::{integer, operand, scalar};
#[cfg(verus_keep_ghost)]
use super::super::shared::entry::MemoryTask;
use super::*;

verus! {
pub open spec fn read_only(operation:integer::Operation)->bool {
    operation is Cmp || operation is Test || operation is BitTest
}
pub open spec fn shift(operation:integer::Operation)->bool {
    operation is Shl || operation is Shr || operation is Sar || operation is Rol || operation is Ror
}
#[verifier::opaque]
pub open spec fn memory_address(operation:integer::Operation,address:operand::Address,
    source:Operand,index:u64,width:Width)->operand::Address {
    if (operation is BitTest || operation is BitSet || operation is BitReset
        || operation is BitComplement) && source is Register {
        let shifted=integer::model::evaluate(integer::Operation::Sar,
            scalar::model::extend(index,width),3,Width::Qword,0).value;
        let delta=shifted & !((operand::model::bits(width) as u64 / 8 - 1) as u64);
        operand::Address {displacement:((address.displacement as int+delta as int)
            % 0x1_0000_0000_0000_0000int) as u64,..address}
    } else {address}
}
pub open spec fn finish(s:State,operation:integer::Operation,destination:Option<Register>,
    left:u64,right:u64,width:Width,length:u8)->(State,Tick) {
    if match destination {Some(dst)=>!dst.valid() || dst@.width!=width,None=>false} {entry::unsupported(s)}
    else {
        let cpu=s.core.cpu;
        let result=integer::model::evaluate(operation,left,right,width,cpu.flags);
        let registers=entry::registers(cpu);
        let gpr=match destination {
            Some(dst)=>if result.write {operand::model::write(registers,dst,result.value)} else {registers},
            None=>registers,
        };
        entry::retire(s,model::State {gpr:gpr.map(|i:int,v:u64|v as int),flags:result.flags,..cpu},
            length,false,false)
    }
}
pub open spec fn execute(s:State,operation:integer::Operation,destination:Operand,source:Operand,length:u8)
    ->(State,Tick) {
    let cpu=s.core.cpu;
    match destination {
        Operand::Register(dst)=>{
            if !dst.valid() {entry::unsupported(s)}
            else {match source {
                Operand::Memory {address,width}=>{
                    if !address.valid() || width!=dst@.width {entry::unsupported(s)}
                    else {entry::memory(s,entry::linear(s,address,length),width,WordAccess::Read,length,
                        MemoryTask::AluRegister {operation,dst})}
                },
                _=>match entry::scalar(cpu,source) {
                    None=>entry::unsupported(s),
                    Some(right)=>finish(s,operation,Some(dst),operand::model::read(entry::registers(cpu),dst),
                        right,dst@.width,length),
                },
            }}
        },
        Operand::Memory {address,width}=>{
            if !address.valid() || shift(operation) {entry::unsupported(s)}
            else {match entry::scalar(cpu,source) {
                None=>entry::unsupported(s),
                Some(right)=>{
                    let adjusted=memory_address(operation,address,source,right,width);
                    let linear=entry::linear(s,adjusted,length);
                    let task=MemoryTask::AluMemory {operation,source:right,width};
                    if read_only(operation) {entry::memory(s,linear,width,WordAccess::Read,length,task)}
                    else if !entry::supported_access(linear,width) {entry::unsupported(s)}
                    else {(State {core:c::boundary_modify(s.core,linear,operation,right,cpu.flags,width).0,
                        phase:Phase::EntryMemory {address:linear,length,task},..s},Tick::Pending)}
                },
            }}
        },
        _=>entry::unsupported(s),
    }
}
pub open spec fn signed(s:State,dst:Register,width:Width,value:u64,length:u8)->(State,Tick) {
    if !dst.valid() || operand::model::bits(dst@.width)<=operand::model::bits(width) {entry::unsupported(s)}
    else {entry::retire(s,model::State {gpr:operand::model::write(entry::registers(s.core.cpu),dst,
        scalar::model::extend(value,width)).map(|i:int,v:u64|v as int),..s.core.cpu},length,false,false)}
}
pub open spec fn scan_value(s:State,dst:Register,value:u64,reverse:bool,length:u8)->(State,Tick) {
    if !dst.valid() || dst@.width==Width::Byte {entry::unsupported(s)}
    else {
        let result=scalar::model::scan(value,dst@.width,reverse);
        let registers=entry::registers(s.core.cpu);
        let gpr=match result {Some(index)=>operand::model::write(registers,dst,index),None=>registers};
        let flags=match result {Some(_)=>s.core.cpu.flags & !0x40u64,None=>s.core.cpu.flags | 0x40u64};
        entry::retire(s,model::State {gpr:gpr.map(|i:int,v:u64|v as int),flags,..s.core.cpu},
            length,false,false)
    }
}
pub open spec fn scan(s:State,dst:Register,source:Operand,reverse:bool,length:u8)->(State,Tick) {
    if !dst.valid() || dst@.width==Width::Byte {entry::unsupported(s)}
    else {match source {
        Operand::Memory {address,width}=>{
            if !address.valid() || width!=dst@.width {entry::unsupported(s)}
            else {entry::memory(s,entry::linear(s,address,length),width,WordAccess::Read,length,
                MemoryTask::Scan {dst,reverse})}
        },
        _=>match entry::scalar(s.core.cpu,source) {
            Some(value)=>scan_value(s,dst,value,reverse,length),None=>entry::unsupported(s),
        },
    }}
}
pub open spec fn division(s:State,divisor:u64,width:Width,signed:bool,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    match scalar::model::divide(cpu.gpr[2] as u64,cpu.gpr[0] as u64,divisor,width,signed) {
        None=>entry::unsupported(s),
        Some(result)=>entry::retire(s,model::State {gpr:cpu.gpr.update(0,result.quotient as int)
            .update(2,result.remainder as int),..cpu},length,false,false),
    }
}
pub open spec fn call(s:State,target:u64,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    if length==0 || length>15 || cpu.rip+length as int>u64::MAX
        || cpu.gpr[4]<8 || cpu.gpr[4]%8!=0 || !mmu_model::canonical(target as int) {entry::unsupported(s)}
    else if cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
    else {(word(s,(cpu.gpr[4]-8) as u64,WordAccess::Write((cpu.rip+length as int) as u64),
        Phase::NearCall {target,stack:(cpu.gpr[4]-8) as u64}),Tick::Pending)}
}
pub open spec fn multiply(s:State,dst:Register,source:Operand,immediate:Option<u64>,length:u8)->(State,Tick) {
    if !dst.valid() || dst@.width==Width::Byte {entry::unsupported(s)}
    else {match source {
        Operand::Memory {address,width}=>{
            if !address.valid() || width!=dst@.width {entry::unsupported(s)}
            else {entry::memory(s,entry::linear(s,address,length),width,WordAccess::Read,length,
                MemoryTask::Multiply {dst,immediate})}
        },
        _=>match entry::scalar(s.core.cpu,source) {
            None=>entry::unsupported(s),Some(value)=>multiply_value(s,dst,value,immediate,length),
        },
    }}
}
pub open spec fn multiply_value(s:State,dst:Register,value:u64,immediate:Option<u64>,length:u8)->(State,Tick) {
    if !dst.valid() || dst@.width==Width::Byte {entry::unsupported(s)}
    else {
        let (left,right)=match immediate {
            Some(right)=>(value,right),
            None=>(operand::model::read(entry::registers(s.core.cpu),dst),value),
        };
        finish(s,integer::Operation::Imul,Some(dst),left,right,dst@.width,length)
    }
}
pub open spec fn jump(s:State,target:u64)->(State,Tick) {
    if !mmu_model::canonical(target as int) {entry::unsupported(s)}
    else {entry::retire(s,model::State {rip:target as int,..s.core.cpu},0,false,false)}
}
}
