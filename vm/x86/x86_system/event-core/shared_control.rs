// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use memory_core::cpu_core::{
    operand::{Register, Width},
    profile,
};

verus! {

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum ControlAccess {
    ReadMsr(u32), WriteMsr {number:u32,value:u64},
    ReadPriority(Register), WritePriority(u64),
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum ControlReply {Value(u64), Written, GeneralProtection}

pub fn apic_msr(number:u32)->(out:bool)
    ensures out==(number==0x1b || 0x800<=number<=0x8ff),
{number==0x1b || (number>=0x800 && number<=0x8ff)}

impl SharedEventMachine {
    pub fn configure_apic(&mut self,id:u32)->(accepted:bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            (final(self)@,accepted)==spec::control_io::configure(old(self)@,id),
    {
        if !matches!(self.phase,Phase::Ready) || self.external_decode {return false;}
        self.apic_id=Some(id);
        true
    }

    pub(super) fn cpuid(&self,function:u32,subleaf:u32)->(out:[u32;4])
        ensures out==spec::control_io::cpuid(self@,function,subleaf),
    {
        let mut values=profile::cpuid(function,subleaf);
        if function==1 {
            if let Some(id)=self.apic_id {
                values[1]=(values[1]&0x00ff_ffff) | ((id&0xff)<<24);
                values[2]|=1<<21;
                values[3]|=1<<9;
            }
        }
        values
    }

    pub(super) fn start_control(&mut self,access:ControlAccess,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::control_io::start(old(self)@,access,length),
    {
        if length==0 || length>15 || self.apic_id.is_none() {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if self.core.cpu().flags&0x100!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        if let ControlAccess::ReadPriority(dst)=access {
            if !dst.is_valid() || dst.width()!=Width::Qword {
                return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
            }
        }
        self.phase=Phase::ControlIo {sequence:self.decode_sequence,length,access,reply:None};
        Tick::Pending
    }

    pub fn complete_control(&mut self,sequence:u64,completion:ControlReply)->(accepted:bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            (final(self)@,accepted)==spec::control_io::complete(old(self)@,sequence,completion),
    {
        match self.phase {
            Phase::ControlIo {sequence:pending,length,access,reply:None} if pending==sequence=>{
                let accepted=match (access,completion) {
                    (_,ControlReply::GeneralProtection)=>true,
                    (ControlAccess::ReadMsr(_),ControlReply::Value(_))=>true,
                    (ControlAccess::ReadPriority(_),ControlReply::Value(value))=>value<=15,
                    (ControlAccess::WriteMsr {..} | ControlAccess::WritePriority(_),ControlReply::Written)=>true,
                    _=>false,
                };
                if accepted {self.phase=Phase::ControlIo {sequence,length,access,reply:Some(completion)};}
                accepted
            },
            _=>false,
        }
    }

    pub(super) fn finish_control(&mut self)->(tick:Tick)
        requires old(self).invariant(),old(self).phase is ControlIo,
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::control_io::finish(old(self)@),
    {
        match self.phase {
            Phase::ControlIo {length,access,reply:Some(reply),..}=>{
                let mut cpu=self.core.cpu();
                assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
                let ghost before=cpu@;
                match (access,reply) {
                    (_,ControlReply::GeneralProtection)=>return self.start_entry(Event::GeneralProtection),
                    (ControlAccess::ReadMsr(_),ControlReply::Value(value))=>{
                        cpu.gpr[0]=value&0xffff_ffff;cpu.gpr[2]=value>>32;
                        assert(cpu@.gpr =~= before.gpr.update(0,(value&0xffff_ffffu64) as int).update(2,(value>>32) as int));
                    },
                    (ControlAccess::ReadPriority(dst),ControlReply::Value(value))=>{
                        let ghost registers=cpu.gpr@;
                        dst.write(&mut cpu.gpr,value);
                        assert(cpu@.gpr =~= memory_core::cpu_core::operand::model::write(registers,dst,value)
                            .map(|i:int,v:u64|v as int));
                    },
                    _=>{},
                }
                let serializing=match access {ControlAccess::WriteMsr {number,..}=>number==0x1b,_=>false};
                self.retire_entry(cpu,length,false,serializing)
            },
            _=>Tick::Waiting,
        }
    }
}

}
