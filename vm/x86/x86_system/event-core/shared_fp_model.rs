// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use super::super::memory_core::cpu_core::system::{self, LegacyFpState};
#[cfg(verus_keep_ghost)]
use super::super::mmu_core::shared::Reply;
#[cfg(verus_keep_ghost)]
use super::super::shared::{SaveSource, SaveTarget};
use super::*;

verus! {
pub open spec fn start_restore_probe(s:State,base:u64,wide:bool,tail:bool,at:u64,length:u8)->(State,Tick) {
    (State {core:c::boundary_read_probe(s.core,at).0,
        phase:Phase::EntryMemory {address:at,length,
            task:super::super::shared::entry::MemoryTask::FpRestoreProbe {base,wide,tail}},..s},Tick::Pending)
}
pub open spec fn finish_restore_probe(s:State,base:u64,wide:bool,tail:bool,length:u8)->(State,Tick) {
    if s.system is None || base>u64::MAX-511 {entry::unsupported(s)}
    else if !tail && base%4096+512>4096 {
        start_restore_probe(s,base,wide,true,(base/4096*4096+4096) as u64,length)
    } else {entry::memory(State {fp_restore:Some(s.system.unwrap().fp),..s},base,
        super::super::memory_core::cpu_core::operand::Width::Qword,WordAccess::Read,length,
        super::super::shared::entry::MemoryTask::RestoreFp {index:0,wide})}
}

pub open spec fn valid_target(t:SaveTarget)->bool {
    t.linear<=u64::MAX-511 && t.first<0x1_0000_0000_0000u64 && t.first%4096==0
        && t.second<0x1_0000_0000_0000u64 && t.second%4096==0 && t.offset<size(t.source) && 1<=t.length<=15
}
pub open spec fn size(source:SaveSource)->int {
    match source {SaveSource::Legacy {..}=>416,_=>16}
}
pub open spec fn valid_offset(t:SaveTarget)->bool {
    match t.source {SaveSource::Legacy {preserve_pointers:true,..}=>t.offset<6 || t.offset>=24,_=>true}
}
pub open spec fn start_probe(s:State,base:u64,source:SaveSource,first:Option<u64>,at:u64,length:u8)->(State,Tick) {
    (State {core:c::boundary_write_probe(s.core,at).0,
        phase:Phase::EntryMemory {address:at,length,
            task:super::super::shared::entry::MemoryTask::FpSaveProbe {base,save:source,first}},..s},Tick::Pending)
}
pub open spec fn finish_probe(s:State,base:u64,source:SaveSource,first:Option<u64>,frame:u64,length:u8)->(State,Tick) {
    if s.system is None || length==0 || length>15 || base>u64::MAX-511
        || frame>=0x1_0000_0000_0000u64 || frame%4096!=0 {entry::unsupported(s)}
    else if first is None && base%4096+(match source {SaveSource::Legacy {..}=>512int,_=>16int})>4096 {
        start_probe(s,base,source,Some(frame),(base/4096*4096+4096) as u64,length)
    } else {
        let first=match first {Some(first)=>first,None=>frame};
        if first>=0x1_0000_0000_0000u64 || first%4096!=0 {entry::unsupported(s)}
        else {(State {phase:Phase::FpSave {target:SaveTarget {
            linear:base,first,second:frame,offset:0,source,length}},..s},Tick::Pending)}
    }
}
pub open spec fn byte(fp:LegacyFpState,at:u16,source:SaveSource)->u8 {
    match source {
        SaveSource::Legacy {wide,..}=>if at>=416 {0}
            else {(system::model::fp_word(fp,(at/8) as int,wide)>>((at%8*8) as u32)) as u8},
        SaveSource::Vector {low,high}=>if at>=16 {0}
            else {((if at<8 {low} else {high})>>((at%8*8) as u32)) as u8},
    }
}
pub open spec fn bytes(fp:LegacyFpState,at:u16,source:SaveSource)->[u8;16] {
    [byte(fp,at,source),byte(fp,(at+1) as u16,source),byte(fp,(at+2) as u16,source),byte(fp,(at+3) as u16,source),
        byte(fp,(at+4) as u16,source),byte(fp,(at+5) as u16,source),byte(fp,(at+6) as u16,source),byte(fp,(at+7) as u16,source),
        byte(fp,(at+8) as u16,source),byte(fp,(at+9) as u16,source),byte(fp,(at+10) as u16,source),byte(fp,(at+11) as u16,source),
        byte(fp,(at+12) as u16,source),byte(fp,(at+13) as u16,source),byte(fp,(at+14) as u16,source),byte(fp,(at+15) as u16,source)]
}
pub open spec fn count(t:SaveTarget)->int {
    let remaining=match t.source {
        SaveSource::Legacy {preserve_pointers:true,..} if t.offset<6=>6-t.offset,
        _=>size(t.source)-t.offset,
    };
    let page=4096-(t.linear%4096+t.offset as int)%4096;
    let count=if remaining<16 {remaining} else {16};
    if page<count {page} else {count}
}
pub open spec fn request(s:State,t:SaveTarget)->Request {
    let offset=t.linear%4096+t.offset as int;
    Request::WriteBytes {address:if offset<4096 {(t.first+offset) as u64} else {(t.second+offset-4096) as u64},
        bytes:bytes(s.system.unwrap().fp,t.offset,t.source),offset:0,end:count(t) as u8}
}
pub open spec fn respond(s:State,reply:Reply)->(State,bool) {
    match (s.phase,reply) {
        (Phase::FpSave {target},Reply::Copied(n)) if n>0 && n<=count(target)=>{
            let next=target.offset+n as int;
            let preserve=match target.source {SaveSource::Legacy {preserve_pointers:true,..}=>true,_=>false};
            (State {phase:if next==size(target.source) {Phase::FpSaveDone {length:target.length}}
                else {Phase::FpSave {target:SaveTarget {offset:if next==6 && preserve
                    {24} else {next as u16},..target}}},..s},true)
        },
        _=>(s,false),
    }
}
}
