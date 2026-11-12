// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::entry::{Instruction, scalar};
use super::*;
#[cfg(verus_keep_ghost)]
use memory_core::cpu_core::operand;
use memory_core::cpu_core::operand::{Address, Width};
use memory_core::cpu_core::{privilege, profile};

verus! {
impl SharedEventMachine {
    pub(super) fn swap_gs(&mut self,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::privilege::swap_gs(old(self)@,length),
    {
        reveal(spec::privilege::swap_gs);
        let cpu=self.core.cpu();
        if length==0 || length>15 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.flags&0x100!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        let Some(mut system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        let base=system.entry.kernel_gs_base;
        if !canonical(base) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        system.entry.kernel_gs_base=system.gs.base;
        system.gs.base=base;
        self.system=Some(system);
        self.retire_entry(cpu,length,false,false)
    }

    pub(super) fn breakpoint(&mut self,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::privilege::breakpoint(old(self)@,length),
    {
        reveal(spec::privilege::breakpoint);
        let cpu=self.core.cpu();
        if length!=1 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.flags&0x100!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        let _retired=self.retire_entry(cpu,length,false,false);
        let _accepted=self.core.boundary();
        assert(_accepted);
        match self.start_entry(Event::Breakpoint) {
            Tick::Pending=>Tick::Retired(false),
            other=>other,
        }
    }

    #[verifier::spinoff_prover]
    pub(super) fn execute_control(&mut self,instruction:Instruction,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::privilege::execute(old(self)@,instruction,length),
    {
        let mut cpu=self.core.cpu();
        assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
        if length==0 || length>15 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.flags&0x100!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        match instruction {
            Instruction::ReadDebug {number,dst}=>{
                if !dst.is_valid() || dst.width()!=Width::Qword {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let Some(system)=self.system else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                let value=match number {
                    0=>system.dr0,1=>system.dr1,2=>system.dr2,3=>system.dr3,
                    4|6=>0xffff0ff0,5|7=>0x400,
                    _=>return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                };
                let ghost registers=cpu.gpr@;
                dst.write(&mut cpu.gpr,value);
                assert(cpu@.gpr =~= operand::model::write(registers,dst,value).map(|i:int,v:u64|v as int));
                self.retire_entry(cpu,length,false,false)
            },
            Instruction::WriteDebug {number,source}=>{
                if !source.is_valid() || source.width()!=Width::Qword {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let Some(mut system)=self.system else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                let value=source.read(&cpu.gpr);
                if number<=3 && !canonical(value) {
                    return self.start_entry(Event::GeneralProtection);
                }
                match number {
                    0=>system.dr0=value,1=>system.dr1=value,2=>system.dr2=value,3=>system.dr3=value,
                    4|6=>{
                        if value!=0xffff0ff0 {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        }
                    },
                    5|7=>{
                        if value!=0 && value!=0x400 {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        }
                    },
                    _=>return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                }
                self.system=Some(system);
                self.retire_entry(cpu,length,false,false)
            },
            Instruction::ReadControl {number,dst}=>{
                if !dst.is_valid() || dst.width()!=Width::Qword {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let cr0_extra=match self.system {Some(s)=>s.cr0_extra,None=>0};
                let cr4_extra=match self.system {Some(s)=>s.cr4_extra,None=>0};
                let value=match number {
                    0=>privilege::read_cr0(cr0_extra,self.core.config().wp),
                    2=>self.core.cr2(),
                    3=>self.core.config().root,4=>privilege::read_cr4(cr4_extra),
                    _=>return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                };
                let ghost registers=cpu.gpr@;
                dst.write(&mut cpu.gpr,value);
                assert(cpu@.gpr =~= operand::model::write(registers,dst,value).map(|i:int,v:u64|v as int));
                self.retire_entry(cpu,length,false,false)
            },
            Instruction::WriteControl {number,source}=>{
                let Some(value)=scalar(cpu,source) else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                let mut config=self.core.config();
                match number {
                    0=>{
                        let Some(update)=privilege::cr0(value) else {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        };
                        let Some(mut system)=self.system else {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        };
                        assert(update.extra==value&0x40022u64);
                        let extra=update.extra;
                        assert(extra&!0x40022u64==0) by(bit_vector)
                            requires extra==value&0x40022u64;
                        system.cr0_extra=extra;config.wp=update.wp;
                        assert(system::model::supported(system));
                        self.system=Some(system);
                    },
                    3=>{
                        if value>=0x1_0000_0000_0000 || value%4096!=0 {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        }
                        config.root=value;
                    },
                    4=>{
                        let Some(extra)=privilege::cr4(value) else {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        };
                        let Some(mut system)=self.system else {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        };
                        assert(extra==value&0x690u64);
                        assert(extra&!0x690u64==0) by(bit_vector)
                            requires extra==value&0x690u64;
                        system.cr4_extra=extra;self.system=Some(system);
                        assert(system::model::supported(system));
                    },
                    _=>return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                }
                assert(self.system_supported());
                let _accepted=self.core.boundary_reload(config);assert(_accepted);
                self.retire_entry(cpu,length,false,true)
            },
            Instruction::ReadMsr=>{
                if cpu.gpr[1]&0xffff_ffff==0x49 || profile::core_pmu_absent(cpu.gpr[1]&0xffff_ffff) {
                    return self.start_entry(Event::GeneralProtection);
                }
                let Some(system)=self.system else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                let value=match cpu.gpr[1]&0xffff_ffff {
                    0xc000_0080=>privilege::read_efer(system.efer_sce,self.core.config().nxe),
                    0x8b=>profile::MICROCODE_REVISION as u64,
                    0xc0000100=>system.fs.base,
                    0xc0000101=>system.gs.base,
                    0xc0011029=>system.de_cfg,
                    number=>match privilege::read_entry(system.entry,number) {
                        Some(value)=>value,
                        None=>return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                    },
                };
                let ghost before=cpu@;
                cpu.gpr[0]=value&0xffff_ffff;cpu.gpr[2]=value>>32;
                assert(cpu@.gpr =~= before.gpr.update(0,(value&0xffff_ffffu64) as int)
                    .update(2,(value>>32) as int));
                self.retire_entry(cpu,length,false,false)
            },
            _=>self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
        }
    }

    pub(super) fn save_fp(&mut self,address:Address,wide:bool,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::privilege::save_fp(old(self)@,address,wide,length),
    {
        reveal(spec::privilege::save_fp);
        let cpu=self.core.cpu();
        if length==0 || length>15 || !address.is_valid() {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.flags&0x100!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        let Some(system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        // Only reset pointers have a modeled selector image in the 32-bit format.
        if system.cr4_extra&0x200==0 || system.fp.mxcsr&!profile::MXCSR_MASK!=0
            || system.fp.opcode>0x7ff
            || (!wide && (system.fp.ip!=0 || system.fp.dp!=0)) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let linear=address.linear(&cpu.gpr,cpu.rip.wrapping_add(length as u64),self.entry_bases());
        if linear%16!=0 {
            return self.start_entry(Event::GeneralProtection);
        }
        if linear%4096>3584 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DataCrossPage));
        }
        let word=system.fp.save_word(0,wide);
        self.entry_memory(linear,Width::Qword,WordAccess::Write(word),length,
            entry::MemoryTask::SaveFp {index:0,wide})
    }

    pub(super) fn finish_fp_save(&mut self,address:u64,index:u8,wide:bool,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::privilege::save_fp_value(old(self)@,address,index,wide,length),
    {
        reveal(spec::privilege::save_fp_value);
        if index>=52 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let cpu=self.core.cpu();
        if index==51 {
            return self.retire_entry(cpu,length,false,false);
        }
        if address>u64::MAX-8 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let Some(system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        let next=index+1;
        let word=system.fp.save_word(next,wide);
        self.entry_memory(address+8,Width::Qword,WordAccess::Write(word),length,
            entry::MemoryTask::SaveFp {index:next,wide})
    }

    pub(super) fn initialize_x87(&mut self,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::privilege::initialize_x87(old(self)@,length),
    {
        reveal(spec::privilege::initialize_x87);
        let cpu=self.core.cpu();
        if length==0 || length>15 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.flags&0x100!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        let Some(mut system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        system.fp=system.fp.initialize_x87();
        self.system=Some(system);
        self.retire_entry(cpu,length,false,false)
    }

    pub(super) fn write_entry_msr(&mut self,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::privilege::write_entry_msr(old(self)@,length),
    {
        let cpu=self.core.cpu();
        if length==0 || length>15 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.flags&0x100!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        let Some(mut system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        let number=cpu.gpr[1]&0xffff_ffff;
        if number!=0xc0011029 && privilege::read_entry(system.entry,number).is_none() {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let value=(cpu.gpr[0]&0xffff_ffff)|((cpu.gpr[2]&0xffff_ffff)<<32);
        if number==0xc0011029 {
            if value&!2u64!=0 {
                return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
            }
            system.de_cfg=value;
            self.system=Some(system);
            return self.retire_entry(cpu,length,false,true);
        }
        if (number==0xc0000084 && value>0xffff_ffff) || (number==0x174 && value>0xffff) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let Some(entry)=privilege::write_entry(system.entry,number,value) else {
            return self.start_entry(Event::GeneralProtection);
        };
        system.entry=entry;
        self.system=Some(system);
        self.retire_entry(cpu,length,false,true)
    }

    pub(super) fn write_efer(&mut self,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::privilege::write_efer(old(self)@,length),
    {
        let cpu=self.core.cpu();
        if length==0 || length>15 || cpu.gpr[1]&0xffff_ffff!=0xc000_0080 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.flags&0x100!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        let Some(mut system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        let value=(cpu.gpr[0]&0xffff_ffff)|((cpu.gpr[2]&0xffff_ffff)<<32);
        let Some(update)=privilege::efer(value) else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        system.efer_sce=update.sce;
        let config=Config {nxe:update.nxe,..self.core.config()};
        let _accepted=self.core.boundary_reload(config);assert(_accepted);
        self.system=Some(system);
        self.retire_entry(cpu,length,false,true)
    }
}
}
