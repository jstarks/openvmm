// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::entry::{Instruction, scalar};
use super::*;
#[cfg(verus_keep_ghost)]
use memory_core::cpu_core::operand;
use memory_core::cpu_core::operand::Width;
use memory_core::cpu_core::privilege;

verus! {
impl SharedEventMachine {
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
            Instruction::ReadControl {number,dst}=>{
                if !dst.is_valid() || dst.width()!=Width::Qword {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let cr0_extra=match self.system {Some(s)=>s.cr0_extra,None=>0};
                let cr4_extra=match self.system {Some(s)=>s.cr4_extra,None=>0};
                let value=match number {
                    0=>privilege::read_cr0(cr0_extra,self.core.config().wp),
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
                        assert(extra==value&0x90u64);
                        assert(extra&!0x90u64==0) by(bit_vector)
                            requires extra==value&0x90u64;
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
                let Some(system)=self.system else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                if cpu.gpr[1]&0xffff_ffff!=0xc000_0080 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let value=privilege::read_efer(system.efer_sce,self.core.config().nxe);
                let ghost before=cpu@;
                cpu.gpr[0]=value&0xffff_ffff;cpu.gpr[2]=value>>32;
                assert(cpu@.gpr =~= before.gpr.update(0,(value&0xffff_ffffu64) as int)
                    .update(2,(value>>32) as int));
                self.retire_entry(cpu,length,false,false)
            },
            _=>self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
        }
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
