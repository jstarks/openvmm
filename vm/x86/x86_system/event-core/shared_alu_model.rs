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
    operation is Cmp || operation is Test
}
pub open spec fn shift(operation:integer::Operation)->bool {
    operation is Shl || operation is Shr || operation is Sar
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
                    let linear=entry::linear(s,address,length);
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
pub open spec fn division(s:State,divisor:u64,width:Width,signed:bool,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    match scalar::model::divide(cpu.gpr[2] as u64,cpu.gpr[0] as u64,divisor,width,signed) {
        None=>entry::unsupported(s),
        Some(result)=>entry::retire(s,model::State {gpr:cpu.gpr.update(0,result.quotient as int)
            .update(2,result.remainder as int),..cpu},length,false,false),
    }
}
pub open spec fn jump(s:State,target:u64)->(State,Tick) {
    if !mmu_model::canonical(target as int) {entry::unsupported(s)}
    else {entry::retire(s,model::State {rip:target as int,..s.core.cpu},0,false,false)}
}
}
