// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::entry::{Instruction, MemoryTask};
use super::*;
#[cfg(verus_keep_ghost)]
use memory_core::cpu_core::operand;
use memory_core::cpu_core::operand::{Address, Operand, Register, Width};
use memory_core::cpu_core::{integer, scalar};

verus! {
fn read_only(operation: integer::Operation) -> (out: bool)
    ensures out == spec::alu::read_only(operation),
{ matches!(operation, integer::Operation::Cmp | integer::Operation::Test | integer::Operation::BitTest) }

fn shift(operation: integer::Operation) -> (out: bool)
    ensures out == spec::alu::shift(operation),
{ matches!(operation, integer::Operation::Shl | integer::Operation::Shr | integer::Operation::Sar
    | integer::Operation::Rol | integer::Operation::Ror) }

pub(super) fn memory_address(operation:integer::Operation,address:Address,
    source:Operand,index:u64,width:Width)->(out:Address)
    ensures out==spec::alu::memory_address(operation,address,source,index,width),
        out.valid()==address.valid(),
{
    reveal(spec::alu::memory_address);
    if matches!(operation,integer::Operation::BitTest | integer::Operation::BitSet
        | integer::Operation::BitReset | integer::Operation::BitComplement)
        && matches!(source,Operand::Register(_)) {
        let extended=scalar::extend(index,width);
        let shifted=integer::evaluate(integer::Operation::Sar,extended,3,Width::Qword,0).value;
        let delta=shifted & !(width.bits() as u64 / 8 - 1);
        Address {displacement:address.displacement.wrapping_add(delta),..address}
    } else {address}
}

impl SharedEventMachine {
    pub(super) fn execute_integer(&mut self,instruction:Instruction,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
            1<=length<=15,old(self).core@.cpu.flags&0x100u64==0,
            instruction is Integer || instruction is Alu || instruction is Multiply,
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::entry::execute(old(self)@,instruction,length),
    {
        reveal(spec::entry::execute);
        match instruction {
            Instruction::Integer {operation,dst,source}=>
                self.execute_alu(operation,Operand::Register(dst),source,length),
            Instruction::Alu {operation,destination,source}=>self.execute_alu(operation,destination,source,length),
            Instruction::Multiply {dst,source,immediate}=>self.execute_multiply(dst,source,immediate,length),
            _=>{assert(false);Tick::Waiting},
        }
    }

    #[verifier::spinoff_prover]
    pub(super) fn execute_scalar(&mut self,instruction:Instruction,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
            1<=length<=15,old(self).core@.cpu.flags&0x100u64==0,
            instruction is SignExtend || instruction is SignHigh || instruction is Divide
                || instruction is Bit || instruction is Scan
                || instruction is IndirectJump || instruction is IndirectCall,
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::entry::execute(old(self)@,instruction,length),
    {
        reveal(spec::entry::execute);
        let mut cpu=self.core.cpu();
        assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
        let next=cpu.rip.wrapping_add(length as u64);
        match instruction {
            Instruction::Scan {dst,source,reverse}=>{
                if !dst.is_valid() || dst.width()==Width::Byte {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                if let Operand::Memory {address,width}=source {
                    if !address.is_valid() || width!=dst.width() {
                        return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                    }
                    return self.entry_memory(address.linear(&cpu.gpr,next,self.entry_bases()),
                        width,WordAccess::Read,length,MemoryTask::Scan {dst,reverse});
                }
                let Some(value)=entry::scalar(cpu,source) else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                self.finish_scan(dst,value,reverse,length)
            },
            Instruction::SignExtend {dst,source,width}=>{
                if !dst.is_valid() || dst.width().bits()<=width.bits() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                if let Operand::Memory {address,width:actual}=source {
                    if !address.is_valid() || actual!=width {
                        return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                    }
                    return self.entry_memory(address.linear(&cpu.gpr,next,self.entry_bases()),
                        width,WordAccess::Read,length,MemoryTask::SignedLoad {dst,width});
                }
                let Some(value)=entry::scalar(cpu,source) else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                self.finish_signed(dst,width,value,length)
            },
            Instruction::SignHigh {width}=>{
                if !matches!(width,Width::Word|Width::Dword|Width::Qword) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let value=scalar::sign_high(cpu.gpr[0],width);
                let ghost before=cpu@;
                cpu.gpr[2]=if width==Width::Word {(cpu.gpr[2]&!0xffffu64)|value} else {value};
                assert(cpu@.gpr =~= before.gpr.update(2,(if width==Width::Word {
                    ((before.gpr[2] as u64)&!0xffffu64)|value
                }else{value}) as int));
                self.retire_entry(cpu,length,false,false)
            },
            Instruction::Divide {source,width,signed}=>{
                if !matches!(width,Width::Dword|Width::Qword) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                if let Operand::Memory {address,width:actual}=source {
                    if !address.is_valid() || actual!=width {
                        return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                    }
                    return self.entry_memory(address.linear(&cpu.gpr,next,self.entry_bases()),
                        width,WordAccess::Read,length,MemoryTask::Division {width,signed});
                }
                let Some(divisor)=entry::scalar(cpu,source) else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                self.finish_division(divisor,width,signed,length)
            },
            Instruction::Bit {operation,dst,index}=>{
                if !dst.is_valid() || !matches!(dst.width(),Width::Word|Width::Dword|Width::Qword) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let Some(index)=entry::scalar(cpu,index) else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                let result=scalar::bit(operation,dst.read(&cpu.gpr),index,dst.width(),cpu.flags);
                let ghost registers=cpu.gpr@;
                if result.write {dst.write(&mut cpu.gpr,result.value);}
                assert(cpu@.gpr =~= (if result.write {operand::model::write(registers,dst,result.value)}
                    else {registers}).map(|i:int,v:u64|v as int));
                cpu.flags=result.flags;
                self.retire_entry(cpu,length,false,false)
            },
            Instruction::IndirectJump {source} | Instruction::IndirectCall {source}=>{
                let call=matches!(instruction,Instruction::IndirectCall {..});
                if let Operand::Memory {address,width}=source {
                    if !address.is_valid() || width!=Width::Qword {
                        return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                    }
                    return self.entry_memory(address.linear(&cpu.gpr,next,self.entry_bases()),
                        width,WordAccess::Read,length,if call {MemoryTask::CallTarget}else{MemoryTask::JumpTarget});
                }
                let Some(target)=entry::scalar(cpu,source) else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                if call {self.begin_indirect_call(target,length)} else {self.finish_jump(target)}
            },
            _=>{assert(false);Tick::Waiting},
        }
    }

    pub(super) fn begin_indirect_call(&mut self,target:u64,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::alu::call(old(self)@,target,length),
    {
        let cpu=self.core.cpu();
        if length==0 || length>15 || cpu.rip>u64::MAX-length as u64
            || cpu.gpr[4]<8 || cpu.gpr[4]%8!=0 || !canonical(target) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.flags&0x100!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        let stack=cpu.gpr[4]-8;
        self.begin_word(stack,WordAccess::Write(cpu.rip+length as u64),Phase::NearCall {target,stack});
        Tick::Pending
    }

    pub(super) fn execute_multiply(&mut self,dst:Register,source:Operand,immediate:Option<u64>,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::alu::multiply(old(self)@,dst,source,immediate,length),
    {
        if !dst.is_valid() || dst.width()==Width::Byte {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let cpu=self.core.cpu();
        if let Operand::Memory {address,width}=source {
            if !address.is_valid() || width!=dst.width() {
                return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
            }
            return self.entry_memory(address.linear(&cpu.gpr,cpu.rip.wrapping_add(length as u64),
                self.entry_bases()),width,WordAccess::Read,length,MemoryTask::Multiply {dst,immediate});
        }
        let Some(value)=entry::scalar(cpu,source) else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        self.finish_multiply(dst,value,immediate,length)
    }

    pub(super) fn finish_multiply(&mut self,dst:Register,value:u64,immediate:Option<u64>,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::alu::multiply_value(old(self)@,dst,value,immediate,length),
    {
        if !dst.is_valid() || dst.width()==Width::Byte {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let cpu=self.core.cpu();
        let (left,right)=match immediate {
            Some(right)=>(value,right),None=>(dst.read(&cpu.gpr),value),
        };
        self.finish_alu(integer::Operation::Imul,Some(dst),left,right,dst.width(),length)
    }

    pub(super) fn finish_alu(&mut self, operation: integer::Operation,
        destination: Option<Register>, left: u64, right: u64, width: Width, length: u8) -> (tick: Tick)
        requires old(self).invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick) == spec::alu::finish(old(self)@,operation,destination,left,right,width,length),
    {
        let mut cpu=self.core.cpu();
        assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
        if let Some(dst)=destination {
            if !dst.is_valid() || dst.width()!=width {
                return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
            }
        }
        let result=integer::evaluate(operation,left,right,width,cpu.flags);
        let ghost registers=cpu.gpr@;
        if let Some(dst)=destination {
            if result.write {dst.write(&mut cpu.gpr,result.value);}
        }
        assert(cpu@.gpr =~= (match destination {
            Some(dst) => if result.write {operand::model::write(registers,dst,result.value)} else {registers},
            None => registers,
        }).map(|i:int,v:u64|v as int));
        cpu.flags=result.flags;
        self.retire_entry(cpu,length,false,false)
    }

    pub(super) fn execute_alu(&mut self, operation: integer::Operation,
        destination: Operand, source: Operand, length: u8) -> (tick: Tick)
        requires old(self).invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick) == spec::alu::execute(old(self)@,operation,destination,source,length),
    {
        let cpu=self.core.cpu();
        match destination {
            Operand::Register(dst) => {
                if !dst.is_valid() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                if let Operand::Memory {address,width}=source {
                    if !address.is_valid() || width!=dst.width() {
                        return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                    }
                    return self.entry_memory(address.linear(&cpu.gpr,cpu.rip.wrapping_add(length as u64),
                        self.entry_bases()),width,WordAccess::Read,length,MemoryTask::AluRegister {operation,dst});
                }
                let Some(right)=entry::scalar(cpu,source) else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                self.finish_alu(operation,Some(dst),dst.read(&cpu.gpr),right,dst.width(),length)
            },
            Operand::Memory {address,width} => {
                if !address.is_valid() || shift(operation) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let Some(right)=entry::scalar(cpu,source) else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                let address=memory_address(operation,address,source,right,width);
                let linear=address.linear(&cpu.gpr,cpu.rip.wrapping_add(length as u64),self.entry_bases());
                let task=MemoryTask::AluMemory {operation,source:right,width};
                if read_only(operation) {
                    return self.entry_memory(linear,width,WordAccess::Read,length,task);
                }
                if !entry::supported_access(linear,width) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let _accepted=self.core.boundary_modify(linear,operation,right,cpu.flags,width);
                assert(_accepted);
                self.phase=Phase::EntryMemory {address:linear,length,task};
                Tick::Pending
            },
            _ => self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
        }
    }

    pub(super) fn finish_scan(&mut self,dst:Register,value:u64,reverse:bool,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==
            spec::alu::scan_value(old(self)@,dst,value,reverse,length),
    {
        if !dst.is_valid() || dst.width()==Width::Byte {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let mut cpu=self.core.cpu();
        assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
        let ghost registers=cpu.gpr@;
        let result=scalar::scan(value,dst.width(),reverse);
        match result {
            Some(index)=>{dst.write(&mut cpu.gpr,index);cpu.flags=cpu.flags & !0x40u64;},
            None=>{cpu.flags=cpu.flags | 0x40u64;},
        }
        assert(cpu@.gpr =~= (match result {
            Some(index)=>operand::model::write(registers,dst,index),None=>registers,
        }).map(|i:int,v:u64|v as int));
        self.retire_entry(cpu,length,false,false)
    }

    pub(super) fn finish_signed(&mut self, dst: Register, width: Width, value: u64, length: u8) -> (tick: Tick)
        requires old(self).invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick) == spec::alu::signed(old(self)@,dst,width,value,length),
    {
        if !dst.is_valid() || dst.width().bits()<=width.bits() {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let mut cpu=self.core.cpu();
        assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
        let value=scalar::extend(value,width);
        let ghost registers=cpu.gpr@;
        dst.write(&mut cpu.gpr,value);
        assert(cpu@.gpr =~= operand::model::write(registers,dst,value).map(|i:int,v:u64|v as int));
        self.retire_entry(cpu,length,false,false)
    }

    pub(super) fn finish_division(&mut self, divisor: u64, width: Width, signed: bool, length: u8) -> (tick: Tick)
        requires old(self).invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick) == spec::alu::division(old(self)@,divisor,width,signed,length),
    {
        let mut cpu=self.core.cpu();
        let Some(result)=scalar::divide(cpu.gpr[2],cpu.gpr[0],divisor,width,signed) else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        let ghost before=cpu@;
        cpu.gpr[0]=result.quotient;
        cpu.gpr[2]=result.remainder;
        assert(cpu@.gpr =~= before.gpr.update(0,result.quotient as int).update(2,result.remainder as int));
        self.retire_entry(cpu,length,false,false)
    }

    pub(super) fn finish_jump(&mut self, target: u64) -> (tick: Tick)
        requires old(self).invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick) == spec::alu::jump(old(self)@,target),
    {
        if !canonical(target) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let mut cpu=self.core.cpu();
        cpu.rip=target;
        self.retire_entry(cpu,0,false,false)
    }
}
}
