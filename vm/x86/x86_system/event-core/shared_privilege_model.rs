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
#[verifier::opaque]
pub open spec fn finish_xmm_byte_shift(s:State,index:u8,count:u8,left:bool,length:u8)->(State,Tick) {
    if s.system is None || index>=16 {entry::unsupported(s)}
    else {
        let system=s.system.unwrap();
        entry::retire(State {system:Some(SystemState {
            fp:system::model::xmm_byte_shift(system.fp,index,count,left),..system}),..s},
            s.core.cpu,length,false,false)
    }
}

#[verifier::opaque]
pub open spec fn finish_xmm_arithmetic(s:State,dst:u8,low:u64,high:u64,width:Width,subtract:bool,length:u8)->(State,Tick) {
    if s.system is None || dst>=16 {entry::unsupported(s)}
    else {
        let system=s.system.unwrap();
        entry::retire(State {system:Some(SystemState {
            fp:system::model::xmm_packed(system.fp,dst,low,high,width,
                if subtract {system::PackedOperation::Subtract} else {system::PackedOperation::Add}),..system}),..s},
            s.core.cpu,length,false,false)
    }
}

#[verifier::opaque]
pub open spec fn finish_xmm_compare(s:State,dst:u8,low:u64,high:u64,width:Width,greater:bool,length:u8)->(State,Tick) {
    if s.system is None || dst>=16 || width==Width::Qword {entry::unsupported(s)}
    else {
        let system=s.system.unwrap();
        entry::retire(State {system:Some(SystemState {
            fp:system::model::xmm_packed(system.fp,dst,low,high,width,
                if greater {system::PackedOperation::GreaterSigned} else {system::PackedOperation::Equal}),..system}),..s},
            s.core.cpu,length,false,false)
    }
}
#[verifier::opaque]
pub open spec fn execute_xmm_compare_memory(s:State,address:Address,index:u8,width:Width,greater:bool,length:u8)->(State,Tick) {
    if width==Width::Qword {entry::unsupported(s)}
    else {execute_xmm_read(s,address,index,super::super::shared::entry::XmmReadAction::Compare {width,greater},length)}
}
#[verifier::opaque]
pub open spec fn execute_xmm_read(s:State,address:Address,index:u8,action:super::super::shared::entry::XmmReadAction,length:u8)->(State,Tick) {
    let result=execute_xmm_memory(s,address,index,false,super::super::shared::entry::XmmMemoryKind::Aligned,length);
    match result.0.phase {
        Phase::EntryMemory {address,length,task:super::super::shared::entry::MemoryTask::XmmLow {..}}=>
            (State {phase:Phase::EntryMemory {address,length,
                task:super::super::shared::entry::MemoryTask::XmmLow {
                    index,action}},..result.0},result.1),
        _=>result,
    }
}

#[verifier::opaque]
pub open spec fn finish_xmm_pair(s:State,dst:u8,low:u64,high:u64,length:u8)->(State,Tick) {
    if s.system is None || dst>=16 {entry::unsupported(s)}
    else {
        let system=s.system.unwrap();
        entry::retire(State {system:Some(SystemState {
            fp:system::model::xmm_pair(system.fp,dst,low,high),..system}),..s},
            s.core.cpu,length,false,false)
    }
}
#[verifier::opaque]
pub open spec fn finish_xmm_memory(s:State,address:u64,task:super::super::shared::entry::MemoryTask,value:u64,length:u8)->(State,Tick) {
    match task {
        super::super::shared::entry::MemoryTask::XmmLow {index,action}=>
            if address>u64::MAX-8 {entry::unsupported(s)}
            else {entry::memory(s,(address+8) as u64,Width::Qword,WordAccess::Read,length,
                super::super::shared::entry::MemoryTask::XmmHigh {index,low:value,action})},
        super::super::shared::entry::MemoryTask::XmmHigh {index,low,action}=>match action {
            super::super::shared::entry::XmmReadAction::Move=>finish_xmm_pair(s,index,low,value,length),
            super::super::shared::entry::XmmReadAction::Compare {width,greater}=>finish_xmm_compare(s,index,low,value,width,greater,length),
            super::super::shared::entry::XmmReadAction::Arithmetic {width,subtract}=>
                finish_xmm_arithmetic(s,index,low,value,width,subtract,length),
        },
        super::super::shared::entry::MemoryTask::XmmHalf {index,high}=>
            if s.system is None || index>=16 {entry::unsupported(s)}
            else {
                let pair=s.system.unwrap().fp.xmm[index as int];
                finish_xmm_pair(s,index,if high {pair[0]} else {value},
                    if high {value} else {pair[1]},length)
            },
        _=>entry::unsupported(s),
    }
}
#[verifier::opaque]
pub open spec fn execute_xmm_memory(s:State,address:Address,index:u8,store:bool,
    kind:super::super::shared::entry::XmmMemoryKind,length:u8)->(State,Tick) {
    if s.system is None || !address.valid() || index>=16 {entry::unsupported(s)}
    else {
        let linear=entry::linear(s,address,length);
        let full=kind is Aligned || kind is Unaligned;
        if !entry::supported_access(linear,Width::Qword)
            || (full && (linear>u64::MAX-15 || !mmu_model::canonical(linear as int+15))) {entry::unsupported(s)}
        else if kind is Aligned && linear%16!=0 {entry(s,Event::GeneralProtection)}
        else if !full {
            let high=kind is High;
            entry::memory(s,linear,Width::Qword,
                if store {WordAccess::Write(s.system.unwrap().fp.xmm[index as int][if high {1int} else {0int}])}
                else {WordAccess::Read},length,
                if store {super::super::shared::entry::MemoryTask::Store}
                else {super::super::shared::entry::MemoryTask::XmmHalf {index,high}})
        } else if !store {entry::memory(s,linear,Width::Qword,WordAccess::Read,length,
            super::super::shared::entry::MemoryTask::XmmLow {
                index,action:super::super::shared::entry::XmmReadAction::Move})}
        else if linear%4096>4080 {
            let pair=s.system.unwrap().fp.xmm[index as int];
            fp::start_probe(s,linear,super::super::shared::SaveSource::Vector {low:pair[0],high:pair[1]},
                None,linear,length)
        }
        else {
            let pair=s.system.unwrap().fp.xmm[index as int];
            (State {core:c::boundary_pair_store(s.core,linear,pair[0],pair[1]).0,
                phase:Phase::EntryMemory {address:linear,length,
                    task:super::super::shared::entry::MemoryTask::XmmWideStore},..s},Tick::Pending)
        }
    }
}

#[verifier::opaque]
pub open spec fn finish_xmm_load(s:State,dst:u8,value:u64,wide:bool,length:u8)->(State,Tick) {
    if s.system is None || dst>=16 {entry::unsupported(s)}
    else {
        let system=s.system.unwrap();
        entry::retire(State {system:Some(SystemState {
            fp:system::model::xmm_scalar(system.fp,dst,value,wide),..system}),..s},
            s.core.cpu,length,false,false)
    }
}
pub open spec fn execute_xmm(s:State,instruction:Instruction,length:u8)->(State,Tick) {
    if s.system is None {entry::unsupported(s)}
    else if s.system.unwrap().cr4_extra&0x200u64==0 {entry(s,Event::InvalidOpcode)}
    else {
        let system=s.system.unwrap();
        let cpu=s.core.cpu;
        match instruction {
            Instruction::XmmArithmeticMemory {address,index,width,subtract}=>
                execute_xmm_read(s,address,index,
                    super::super::shared::entry::XmmReadAction::Arithmetic {width,subtract},length),
            Instruction::XmmArithmetic {dst,source,width,subtract}=>
                if source>=16 {entry::unsupported(s)}
                else {
                    let pair=system.fp.xmm[source as int];
                    finish_xmm_arithmetic(s,dst,pair[0],pair[1],width,subtract,length)
                },
            Instruction::XmmCompareMemory {address,index,width,greater}=>
                execute_xmm_compare_memory(s,address,index,width,greater,length),
            Instruction::XmmCompare {dst,source,width,greater}=>
                if source>=16 {entry::unsupported(s)}
                else {
                    let pair=system.fp.xmm[source as int];
                    finish_xmm_compare(s,dst,pair[0],pair[1],width,greater,length)
                },
            Instruction::XmmMask {dst,source}=>
                if source>=16 || !dst.valid() || (dst@.width!=Width::Dword && dst@.width!=Width::Qword) {
                    entry::unsupported(s)
                } else {entry::retire(s,model::State {
                    gpr:operand::model::write(entry::registers(cpu),dst,system::model::xmm_mask(system.fp,source))
                        .map(|i:int,v:u64|v as int),..cpu},length,false,false)},
            Instruction::XmmMemory {address,index,store,kind}=>
                execute_xmm_memory(s,address,index,store,kind,length),
            Instruction::XmmCopy {dst,source}|Instruction::XmmMerge {dst,source,..}=>
                if dst>=16 || source>=16 {entry::unsupported(s)}
                else {
                    let pair=system.fp.xmm[source as int];
                    match instruction {
                        Instruction::XmmMerge {high,..}=>{
                            let previous=system.fp.xmm[dst as int];
                            finish_xmm_pair(s,dst,if high {previous[0]} else {pair[1]},
                                if high {pair[0]} else {previous[1]},length)
                        },
                        _=>finish_xmm_pair(s,dst,pair[0],pair[1],length),
                    }
                },
            Instruction::XmmLoad {dst,source,width}=>{
                if dst>=16 || (width!=Width::Dword && width!=Width::Qword) {entry::unsupported(s)}
                else {match source {
                    operand::Operand::Register(reg)=>{
                        if !reg.valid() || reg@.width!=width {entry::unsupported(s)}
                        else {finish_xmm_load(s,dst,operand::model::read(entry::registers(cpu),reg),width==Width::Qword,length)}
                    },
                    operand::Operand::Memory {address,width:operand_width}=>{
                        if !address.valid() || operand_width!=width {entry::unsupported(s)}
                        else {entry::memory(s,entry::linear(s,address,length),width,WordAccess::Read,length,
                            super::super::shared::entry::MemoryTask::XmmLoad {index:dst,wide:width==Width::Qword})}
                    },
                    _=>entry::unsupported(s),
                }}
            },
            Instruction::XmmStore {destination,source,width}=>{
                if source>=16 || (width!=Width::Dword && width!=Width::Qword) {entry::unsupported(s)}
                else {
                    let value=system.fp.xmm[source as int][0];
                    match destination {
                        operand::Operand::Register(dst)=>{
                            if !dst.valid() || dst@.width!=width {entry::unsupported(s)}
                            else {entry::retire(s,model::State {
                                gpr:operand::model::write(entry::registers(cpu),dst,value)
                                    .map(|i:int,v:u64|v as int),..cpu},length,false,false)}
                        },
                        operand::Operand::Memory {address,width:operand_width}=>{
                            if !address.valid() || operand_width!=width {entry::unsupported(s)}
                            else {entry::memory(s,entry::linear(s,address,length),width,WordAccess::Write(value),length,
                                super::super::shared::entry::MemoryTask::Store)}
                        },
                        _=>entry::unsupported(s),
                    }
                }
            },
            Instruction::XmmCopyLow {dst,source}=>{
                if dst>=16 || source>=16 {entry::unsupported(s)}
                else {finish_xmm_load(s,dst,system.fp.xmm[source as int][0],true,length)}
            },
            Instruction::XmmUnpack {dst,source,wide,high}=>{
                if dst>=16 || source>=16 {entry::unsupported(s)}
                else {entry::retire(State {system:Some(SystemState {
                    fp:system::model::xmm_unpack(system.fp,dst,source,wide,high),..system}),..s},
                    cpu,length,false,false)}
            },
            Instruction::XmmUnpackNarrow {dst,source,word,high}=>{
                if dst>=16 || source>=16 {entry::unsupported(s)}
                else {entry::retire(State {system:Some(SystemState {
                    fp:system::model::xmm_unpack_narrow(system.fp,dst,source,word,high),..system}),..s},
                    cpu,length,false,false)}
            },
            Instruction::XmmShuffle {dst,source,control}=>{
                if dst>=16 || source>=16 {entry::unsupported(s)}
                else {entry::retire(State {system:Some(SystemState {
                    fp:system::model::xmm_shuffle(system.fp,dst,source,control),..system}),..s},
                    cpu,length,false,false)}
            },
            Instruction::XmmByteShift {index,count,left}=>finish_xmm_byte_shift(s,index,count,left,length),
            Instruction::XmmLogic {dst,source,operation}=>{
                if dst>=16 || source>=16 {entry::unsupported(s)}
                else {entry::retire(State {system:Some(SystemState {
                    fp:system::model::xmm_logic(system.fp,dst,source,operation),..system}),..s},
                    cpu,length,false,false)}
            },
            _=>entry::unsupported(s),
        }
    }
}

#[verifier::opaque]
pub open spec fn fast_entry(s:State,returning:bool,length:u8)->(State,Tick) {
    if s.system is None || length<2 || length>15 || !e::flags_supported(s.core.cpu.flags) {
        entry::unsupported(s)
    } else {
        let system=s.system.unwrap();
        let result=if returning {privilege::model::sysret64(s.core.cpu,system)}
            else {privilege::model::syscall64(s.core.cpu,system,length)};
        match result.2 {
            privilege::FastStatus::InvalidOpcode=>entry(s,Event::InvalidOpcode),
            privilege::FastStatus::GeneralProtection=>entry(s,Event::GeneralProtection),
            privilege::FastStatus::Advanced=>{
                if !system::model::supported(result.1) || !e::flags_supported(result.0.flags) {
                    entry::unsupported(s)
                } else {
                    (State {core:c::boundary_transfer(s.core,result.0,result.1.cs.selector&3u16==3).0,
                        system:Some(result.1),phase:Phase::Ready,shadow:false,handler_pending:false,..s},
                        Tick::Retired(false))
                }
            },
        }
    }
}
#[verifier::opaque]
pub open spec fn swap_gs(s:State,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    if is_user(s) {entry(s,Event::GeneralProtection)}
    else if length==0 || length>15 {entry::unsupported(s)}
    else if cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
    else {match s.system {
        None=>entry::unsupported(s),
        Some(system)=>if !mmu_model::canonical(system.entry.kernel_gs_base as int) {entry::unsupported(s)}
            else {entry::retire(State {system:Some(SystemState {
                entry:system::EntryMsrs {kernel_gs_base:system.gs.base,..system.entry},
                gs:system::SegmentState {base:system.entry.kernel_gs_base,..system.gs},..system}),..s},
                cpu,length,false,false)},
    }}
}
#[verifier::opaque]
pub open spec fn breakpoint(s:State,length:u8)->(State,Tick) {
    if length!=1 {entry::unsupported(s)}
    else if s.core.cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
    else {
        let retired=entry::retire(s,s.core.cpu,length,false,false);
        let boundary=State {core:c::boundary(retired.0.core).0,..retired.0};
        let delivered=entry(boundary,Event::Breakpoint);
        (delivered.0,match delivered.1 {Tick::Pending=>Tick::Retired(false),other=>other})
    }
}
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
            if !dst.valid() || dst@.width!=Width::Qword {
                entry::unsupported(s)
            } else if number==8 && s.apic_id is Some {
                control_io::start(s,super::super::shared::control_io::ControlAccess::ReadPriority(dst),length)
            } else if number!=0 && number!=2 && number!=3 && number!=4 {
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
                8=>if s.apic_id is Some {
                    control_io::start(s,super::super::shared::control_io::ControlAccess::WritePriority(value),length)
                } else {entry::unsupported(s)},
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
        Instruction::ReadMsr=>if s.apic_id is Some
            && (((cpu.gpr[1] as u64)&0xffff_ffffu64)==0x1b
                || 0x800<=((cpu.gpr[1] as u64)&0xffff_ffffu64)<=0x8ff) {
            control_io::start(s,super::super::shared::control_io::ControlAccess::ReadMsr((cpu.gpr[1] as u64) as u32),length)
        } else if (cpu.gpr[1] as u64)&0xffff_ffffu64==0x49u64
            || !profile::declared_msr((cpu.gpr[1] as u64)&0xffff_ffffu64,s.apic_id is Some) {
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
                    else if number==0xc001001f {Some(profile::NB_CFG)}
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
                || (!wide && system.fp.status&0x80u16!=0 && (system.fp.ip!=0 || system.fp.dp!=0)) {entry::unsupported(s)}
            else if !mmu_model::canonical(at as int) {entry::unsupported(s)}
            else if at%16!=0 {entry(s,Event::GeneralProtection)}
            else if at>u64::MAX-511 || !mmu_model::canonical(at as int+511) {entry::unsupported(s)}
            else {fp::start_probe(s,at,super::super::shared::SaveSource::Legacy {
                wide,preserve_pointers:system.fp.status&0x80u16==0},None,at,length)}
        },
    }}
}
#[verifier::opaque]
pub open spec fn load_x87_integer(s:State,address:Address,width:Width,opcode:u16,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    if length==0 || length>15 || !address.valid() || width==Width::Byte || opcode>0x7ff {
        entry::unsupported(s)
    } else if cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
    else {match s.system {
        None=>entry::unsupported(s),
        Some(system)=>if !system::model::integer_ready(system.fp)
            || !mmu_model::canonical(entry::linear(s,address,length) as int) {entry::unsupported(s)}
            else {entry::memory(s,entry::linear(s,address,length),width,WordAccess::Read,length,
                super::super::shared::entry::MemoryTask::LoadX87Integer {width,opcode})},
    }}
}
#[verifier::opaque]
pub open spec fn load_x87_value(s:State,address:u64,value:u64,width:Width,opcode:u16,length:u8)->(State,Tick) {
    match s.system {
        None=>entry::unsupported(s),
        Some(system)=>if width==Width::Byte || opcode>0x7ff || !system::model::integer_ready(system.fp) {
            entry::unsupported(s)
        } else {entry::retire(State {system:Some(SystemState {
            fp:system::model::push_integer(system.fp,value,width,s.core.cpu.rip as u64,address,opcode),
            ..system}),..s},s.core.cpu,length,false,false)},
    }
}
#[verifier::opaque]
pub open spec fn restore_fp(s:State,address:Address,wide:bool,length:u8)->(State,Tick) {
    if length==0 || length>15 || !address.valid() {entry::unsupported(s)}
    else if s.core.cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
    else {match s.system {
        None=>entry::unsupported(s),
        Some(system)=>if system.cr4_extra&0x200u64==0 {entry::unsupported(s)}
            else if !mmu_model::canonical(entry::linear(s,address,length) as int) {entry::unsupported(s)}
            else if entry::linear(s,address,length)%16!=0 {entry(s,Event::GeneralProtection)}
            else if entry::linear(s,address,length)>u64::MAX-511
                || !mmu_model::canonical(entry::linear(s,address,length) as int+511) {
                entry::unsupported(s)
            } else {fp::start_restore_probe(s,entry::linear(s,address,length),wide,false,
                entry::linear(s,address,length),length)},
    }}
}
#[verifier::opaque]
pub open spec fn restore_fp_value(s:State,address:u64,index:u8,value:u64,wide:bool,length:u8)->(State,Tick) {
    if index>=52 {entry::unsupported(s)}
    else {match (s.fp_restore,s.system) {
        (Some(fp),Some(system))=>{
            if index==0 && ((value as u16)&0xe080u16!=0 || value&0x40u64==0) {entry::unsupported(s)}
            else if !wide && (index==1 || index==2)
                && ((fp.status&!fp.control)&0x3fu16)!=0 && value&0xffff_ffff_0000_0000u64!=0 {entry::unsupported(s)}
            else if index==3 && (value as u32)&!profile::MXCSR_MASK!=0 {entry(s,Event::GeneralProtection)}
            else {
                let next=system::model::restore_word(fp,index as int,value,wide);
                if index==51 {entry::retire(State {
                    system:Some(SystemState {fp:system::model::finish_restore(next,system.fp),..system}),
                    fp_restore:None,..s},s.core.cpu,length,false,false)}
                else if address>u64::MAX-8 {entry::unsupported(s)}
                else {entry::memory(State {fp_restore:Some(next),..s},(address+8) as u64,Width::Qword,
                    WordAccess::Read,length,super::super::shared::entry::MemoryTask::RestoreFp {
                        index:(index+1) as u8,wide})}
            }
        },
        _=>entry::unsupported(s),
    }}
}
#[verifier::opaque]
pub open spec fn control_x87(s:State,operation:system::X87Control,length:u8)->(State,Tick) {
    let cpu=s.core.cpu;
    if length==0 || length>15 {entry::unsupported(s)}
    else if cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
    else {match s.system {
        None=>entry::unsupported(s),
        Some(system)=>if (if operation==system::X87Control::Wait {
                system.cr0_extra&0xau64==0xa} else {system.cr0_extra&0xcu64!=0})
            || ((operation==system::X87Control::EmptyMmx || operation==system::X87Control::Wait)
                && ((system.fp.status&!system.fp.control)&0x3fu16)!=0) {entry::unsupported(s)}
            else {entry::retire(State {system:Some(SystemState {
                fp:match operation {
                    system::X87Control::Initialize=>system::LegacyFpState {
                        control:0x37f,status:0,tags:0xffff,opcode:0,ip:0,dp:0,..system.fp},
                    system::X87Control::ClearExceptions=>system::LegacyFpState {
                        status:system.fp.status&0x7f00u16,..system.fp},
                    system::X87Control::EmptyMmx=>system::LegacyFpState {
                        status:system.fp.status&0xc7ffu16,tags:0xffff,..system.fp},
                    system::X87Control::Wait=>system.fp,
                },..system}),..s},cpu,length,false,false)},
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
            if number!=0xc0011029 && number!=0xc001001f
                && privilege::model::read_entry(system.entry,number) is None {entry::unsupported(s)}
            else {
                let value=((cpu.gpr[0] as u64)&0xffff_ffffu64)|(((cpu.gpr[2] as u64)&0xffff_ffffu64)<<32);
                if number==0xc001001f {
                    if value!=profile::NB_CFG {entry::unsupported(s)}
                    else {entry::retire(s,cpu,length,false,true)}
                } else if number==0xc0011029 {
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
