// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::{operand, profile};
#[cfg(verus_keep_ghost)]
use super::super::shared::control_io::{ControlAccess, ControlReply};
use super::*;

verus! {
pub open spec fn configure(s:State,id:u32)->(State,bool) {
    if !(s.phase is Ready) || s.external_decode {(s,false)}
    else {(State {apic_id:Some(id),..s},true)}
}
pub open spec fn valid_reply(access:ControlAccess,reply:ControlReply)->bool {
    match (access,reply) {
        (_,ControlReply::GeneralProtection)=>true,
        (ControlAccess::ReadMsr(_),ControlReply::Value(_))=>true,
        (ControlAccess::ReadPriority(_),ControlReply::Value(value))=>value<=15,
        (ControlAccess::WriteMsr {..} | ControlAccess::WritePriority(_),ControlReply::Written)=>true,
        _=>false,
    }
}
pub open spec fn cpuid(s:State,function:u32,subleaf:u32)->[u32;4] {
    let values=profile::target(function,subleaf);
    match s.apic_id {
        Some(id)=>if function==1 {[values[0],(values[1]&0x00ff_ffffu32)|((id&0xffu32)<<24),
            values[2]|(1u32<<21),values[3]|(1u32<<9)]} else {values},
        None=>values,
    }
}
pub open spec fn start(s:State,access:ControlAccess,length:u8)->(State,Tick) {
    if length==0 || length>15 || s.apic_id is None {entry::unsupported(s)}
    else if s.core.cpu.flags&0x100u64!=0 {stop(s,EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired))}
    else if match access {ControlAccess::ReadPriority(dst)=>!dst.valid() || dst@.width!=operand::Width::Qword,_=>false} {
        entry::unsupported(s)
    } else {(State {phase:Phase::ControlIo {sequence:s.decode_sequence,length,access,reply:None},..s},Tick::Pending)}
}
pub open spec fn complete(s:State,sequence:u64,completion:ControlReply)->(State,bool) {
    match s.phase {
        Phase::ControlIo {sequence:pending,length,access,reply:None} if pending==sequence=>{
            let accepted=match (access,completion) {
                (_,ControlReply::GeneralProtection)=>true,
                (ControlAccess::ReadMsr(_),ControlReply::Value(_))=>true,
                (ControlAccess::ReadPriority(_),ControlReply::Value(value))=>value<=15,
                (ControlAccess::WriteMsr {..} | ControlAccess::WritePriority(_),ControlReply::Written)=>true,
                _=>false,
            };
            if accepted {(State {phase:Phase::ControlIo {sequence,length,access,reply:Some(completion)},..s},true)}
            else {(s,false)}
        },
        _=>(s,false),
    }
}
pub open spec fn finish(s:State)->(State,Tick) {
    match s.phase {
        Phase::ControlIo {length,access,reply:Some(reply),..}=>{
            match (access,reply) {
                (_,ControlReply::GeneralProtection)=>entry(s,Event::GeneralProtection),
                _=>{
                    let cpu=match (access,reply) {
                        (ControlAccess::ReadMsr(_),ControlReply::Value(value))=>model::State {
                            gpr:s.core.cpu.gpr.update(0,(value&0xffff_ffffu64) as int).update(2,(value>>32) as int),
                            ..s.core.cpu},
                        (ControlAccess::ReadPriority(dst),ControlReply::Value(value))=>model::State {
                            gpr:operand::model::write(entry::registers(s.core.cpu),dst,value).map(|i:int,v:u64|v as int),
                            ..s.core.cpu},
                        _=>s.core.cpu,
                    };
                    let serializing=match access {ControlAccess::WriteMsr {number,..}=>number==0x1b,_=>false};
                    entry::retire(s,cpu,length,false,serializing)
                },
            }
        },
        _=>(s,Tick::Waiting),
    }
}
}
