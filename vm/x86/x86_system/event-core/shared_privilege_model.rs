// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use super::super::Config;
#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::operand::{Address, Width};
#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::{operand, privilege, profile, system};
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
        Instruction::ReadDebug {number,dst}=>{
            if !dst.valid() || dst@.width!=Width::Qword || s.system is None || number>7 {
                entry::unsupported(s)
            } else {
                let system=s.system.unwrap();
                let value=match number {
                    0=>system.dr0,1=>system.dr1,2=>system.dr2,3=>system.dr3,
                    4|6=>0xffff0ff0u64,_=>0x400u64,
                };
                entry::retire(s,model::State {gpr:operand::model::write(entry::registers(cpu),dst,value)
                    .map(|i:int,v:u64|v as int),..cpu},length,false,false)
            }
        },
        Instruction::WriteDebug {number,source}=>{
            let value=operand::model::read(entry::registers(cpu),source);
            if !source.valid() || source@.width!=Width::Qword || s.system is None {
                entry::unsupported(s)
            } else if number<=3 && !mmu_model::canonical(value as int) {entry(s,Event::GeneralProtection)}
            else {
                let system=s.system.unwrap();
                let updated=match number {
                    0=>Some(SystemState {dr0:value,..system}),1=>Some(SystemState {dr1:value,..system}),
                    2=>Some(SystemState {dr2:value,..system}),3=>Some(SystemState {dr3:value,..system}),
                    4|6=>if value==0xffff0ff0 {Some(system)} else {None},
                    5|7=>if value==0 || value==0x400 {Some(system)} else {None},
                    _=>None,
                };
                match updated {None=>entry::unsupported(s),
                    Some(system)=>entry::retire(State {system:Some(system),..s},cpu,length,false,false)}
            }
        },
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
        Instruction::ReadMsr=>if (cpu.gpr[1] as u64)&0xffff_ffffu64==0x49u64 {
            entry(s,Event::GeneralProtection)
        } else {match s.system {
            None=>entry::unsupported(s),
            Some(system)=>{
                let number=(cpu.gpr[1] as u64)&0xffff_ffffu64;
                let value=if number==0x8b {Some(profile::MICROCODE_REVISION as u64)}
                    else if number==0xc000_0080 {Some(privilege::model::read_efer(system.efer_sce,config.nxe))}
                    else if number==0xc0000100 {Some(system.fs.base)}
                    else if number==0xc0000101 {Some(system.gs.base)}
                    else if number==0xc0011029 {Some(system.de_cfg)}
                    else {privilege::model::read_entry(system.entry,number)};
                match value {
                    None=>entry::unsupported(s),
                    Some(value)=>entry::retire(s,model::State {gpr:cpu.gpr.update(0,(value&0xffff_ffffu64) as int)
                        .update(2,(value>>32) as int),..cpu},length,false,false),
                }
            },
        }},
        _=>entry::unsupported(s),
    }}
}
#[verifier::opaque]
pub open spec fn save_fp(s:State,address:Address,wide:bool,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    if length==0 || length>15 || !address.valid() {entry::unsupported(s)}
    else if cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
    else {match s.system {
        None=>entry::unsupported(s),
        Some(system)=>{
            let at=entry::linear(s,address,length);
            if system.cr4_extra&0x200u64==0 || system.fp.mxcsr&!profile::MXCSR_MASK!=0
                || system.fp.opcode>0x7ff
                || (!wide && (system.fp.ip!=0 || system.fp.dp!=0)) {entry::unsupported(s)}
            else if at%16!=0 {entry(s,Event::GeneralProtection)}
            else if at%4096>3584 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DataCrossPage))}
            else {entry::memory(s,at,Width::Qword,WordAccess::Write(system::model::fp_word(system.fp,0,wide)),
                length,super::super::shared::entry::MemoryTask::SaveFp {index:0,wide})}
        },
    }}
}
#[verifier::opaque]
pub open spec fn save_fp_value(s:State,address:u64,index:u8,wide:bool,length:u8)->(State,Tick) {
    if index>=52 {entry::unsupported(s)}
    else if index==51 {entry::retire(s,s.core.cpu,length,false,false)}
    else if address>u64::MAX-8 || s.system is None {entry::unsupported(s)}
    else {entry::memory(s,(address+8) as u64,Width::Qword,WordAccess::Write(
        system::model::fp_word(s.system.unwrap().fp,index as int+1,wide)),
        length,super::super::shared::entry::MemoryTask::SaveFp {index:(index+1) as u8,wide})}
}
#[verifier::opaque]
pub open spec fn initialize_x87(s:State,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    if length==0 || length>15 {entry::unsupported(s)}
    else if cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
    else {match s.system {
        None=>entry::unsupported(s),
        Some(system)=>entry::retire(State {system:Some(SystemState {
            fp:system::LegacyFpState {control:0x37f,status:0,tags:0xffff,opcode:0,ip:0,dp:0,..system.fp},
            ..system}),..s},cpu,length,false,false),
    }}
}
pub open spec fn write_entry_msr(s:State,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    let number=(cpu.gpr[1] as u64)&0xffff_ffffu64;
    if length==0 || length>15 {entry::unsupported(s)}
    else if cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
    else {match s.system {
        None=>entry::unsupported(s),
        Some(system)=>{
            if number!=0xc0011029 && privilege::model::read_entry(system.entry,number) is None {entry::unsupported(s)}
            else {
                let value=((cpu.gpr[0] as u64)&0xffff_ffffu64)|(((cpu.gpr[2] as u64)&0xffff_ffffu64)<<32);
                if number==0xc0011029 {
                    if value&!2u64!=0 {entry::unsupported(s)}
                    else {entry::retire(State {system:Some(SystemState {de_cfg:value,..system}),..s},
                        cpu,length,false,true)}
                } else if (number==0xc0000084 && value>0xffff_ffff) || (number==0x174 && value>0xffff) {
                    entry::unsupported(s)
                } else {match privilege::model::write_entry(system.entry,number,value) {
                    None=>entry(s,Event::GeneralProtection),
                    Some(next)=>entry::retire(State {system:Some(SystemState {entry:next,..system}),..s},
                        cpu,length,false,true),
                }}
            }
        },
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
