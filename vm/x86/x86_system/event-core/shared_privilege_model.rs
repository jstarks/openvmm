// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use super::super::Config;
#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::operand::Width;
#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::{operand, privilege, profile};
#[cfg(verus_keep_ghost)]
use super::super::shared::entry::Instruction;
use super::*;

verus! {
pub open spec fn reload(s:State,config:Config,system:Option<SystemState>)->State {
    State {core:c::boundary_reload(s.core,config).0,system,..s}
}
pub open spec fn execute(s:State,instruction:Instruction,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    let config=s.core.mmu.inner.config;
    if length==0 || length>15 {entry::unsupported(s)}
    else if cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
    else {match instruction {
        Instruction::ReadControl {number,dst}=>{
            if !dst.valid() || dst@.width!=Width::Qword || (number!=0 && number!=2 && number!=3 && number!=4) {
                entry::unsupported(s)
            } else {
                let cr0_extra=match s.system {Some(system)=>system.cr0_extra,None=>0u64};
                let cr4_extra=match s.system {Some(system)=>system.cr4_extra,None=>0u64};
                let value=if number==0 {privilege::model::read_cr0(cr0_extra,config.wp)}
                    else if number==2 {s.core.mmu.inner.cr2 as u64}
                    else if number==3 {config.root} else {privilege::model::read_cr4(cr4_extra)};
                entry::retire(s,model::State {gpr:operand::model::write(entry::registers(cpu),dst,value)
                    .map(|i:int,v:u64|v as int),..cpu},length,false,false)
            }
        },
        Instruction::WriteControl {number,source}=>match entry::scalar(cpu,source) {
            None=>entry::unsupported(s),
            Some(value)=>match number {
                0=>match (privilege::model::cr0(value),s.system) {
                    (Some(update),Some(system))=>entry::retire(reload(s,Config {wp:update.wp,..config},
                        Some(SystemState {cr0_extra:update.extra,..system})),cpu,length,false,true),
                    _=>entry::unsupported(s),
                },
                3=>if value>=0x1_0000_0000_0000 || value%4096!=0 {entry::unsupported(s)}
                    else {entry::retire(reload(s,Config {root:value,..config},s.system),cpu,length,false,true)},
                4=>match (privilege::model::cr4(value),s.system) {
                    (Some(extra),Some(system))=>entry::retire(reload(s,config,
                        Some(SystemState {cr4_extra:extra,..system})),cpu,length,false,true),
                    _=>entry::unsupported(s),
                },
                _=>entry::unsupported(s),
            },
        },
        Instruction::ReadMsr=>match s.system {
            None=>entry::unsupported(s),
            Some(system)=>{
                let number=(cpu.gpr[1] as u64)&0xffff_ffffu64;
                if number!=0xc000_0080u64 && number!=0x8bu64 {entry::unsupported(s)}
                else {
                    let value=if number==0x8b {profile::MICROCODE_REVISION as u64}
                        else {privilege::model::read_efer(system.efer_sce,config.nxe)};
                    entry::retire(s,model::State {gpr:cpu.gpr.update(0,(value&0xffff_ffffu64) as int)
                        .update(2,(value>>32) as int),..cpu},length,false,false)
                }
            },
        },
        _=>entry::unsupported(s),
    }}
}
pub open spec fn write_efer(s:State,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    if length==0 || length>15 || (cpu.gpr[1] as u64)&0xffff_ffffu64!=0xc000_0080u64 {entry::unsupported(s)}
    else if cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
    else {match s.system {
        None=>entry::unsupported(s),
        Some(system)=>{
            let value=((cpu.gpr[0] as u64)&0xffff_ffffu64)|(((cpu.gpr[2] as u64)&0xffff_ffffu64)<<32);
            match privilege::model::efer(value) {
                None=>entry::unsupported(s),
                Some(update)=>entry::retire(reload(s,Config {nxe:update.nxe,..s.core.mmu.inner.config},
                    Some(SystemState {efer_sce:update.sce,..system})),cpu,length,false,true),
            }
        },
    }}
}
}
