// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use memory_core::cpu_core::system::LegacyFpState;

verus! {
impl SharedEventMachine {
    pub(super) fn start_restore_probe(&mut self,base:u64,wide:bool,tail:bool,at:u64,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::fp::start_restore_probe(old(self)@,base,wide,tail,at,length),
    {
        let _accepted=self.core.boundary_read_probe(at);assert(_accepted);
        self.phase=Phase::EntryMemory {address:at,length,
            task:entry::MemoryTask::FpRestoreProbe {base,wide,tail}};
        Tick::Pending
    }

    pub(super) fn finish_restore_probe(&mut self,base:u64,wide:bool,tail:bool,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::fp::finish_restore_probe(old(self)@,base,wide,tail,length),
    {
        let Some(system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        if base>u64::MAX-511 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
        if !tail && base%4096+512>4096 {
            return self.start_restore_probe(base,wide,true,base/4096*4096+4096,length);
        }
        self.fp_restore=Some(system.fp);
        self.entry_memory(base,memory_core::cpu_core::operand::Width::Qword,WordAccess::Read,length,
            entry::MemoryTask::RestoreFp {index:0,wide})
    }

    pub(super) fn start_fp_probe(&mut self,base:u64,source:SaveSource,first:Option<u64>,at:u64,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::fp::start_probe(old(self)@,base,source,first,at,length),
    {
        let _accepted=self.core.boundary_write_probe(at);assert(_accepted);
        self.phase=Phase::EntryMemory {address:at,length,
            task:entry::MemoryTask::FpSaveProbe {base,save:source,first}};
        Tick::Pending
    }

    pub(super) fn finish_fp_probe(&mut self,base:u64,source:SaveSource,first:Option<u64>,frame:u64,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::fp::finish_probe(old(self)@,base,source,first,frame,length),
    {
        if self.system.is_none() || length==0 || length>15 || base>u64::MAX-511
            || frame>=0x1_0000_0000_0000u64 || frame%4096!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let size=match source {SaveSource::Legacy {..}=>512u64,_=>16u64};
        if first.is_none() && base%4096+size>4096 {
            return self.start_fp_probe(base,source,Some(frame),base/4096*4096+4096,length);
        }
        let first=match first {Some(first)=>first,None=>frame};
        if first>=0x1_0000_0000_0000u64 || first%4096!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        self.phase=Phase::FpSave {target:SaveTarget {linear:base,first,second:frame,offset:0,source,length}};
        Tick::Pending
    }

    fn fp_byte(fp:LegacyFpState,at:u16,source:SaveSource)->(value:u8)
        ensures value==spec::fp::byte(fp,at,source),
    {
        match source {
            SaveSource::Legacy {wide,..}=>if at>=416 {0}
                else {(fp.save_word((at/8) as u8,wide)>>((at%8*8) as u32)) as u8},
            SaveSource::Vector {low,high}=>if at>=16 {0}
                else {((if at<8 {low} else {high})>>((at%8*8) as u32)) as u8},
        }
    }

    fn fp_bytes(fp:LegacyFpState,at:u16,source:SaveSource)->(bytes:[u8;16])
        requires at<416,
        ensures bytes==spec::fp::bytes(fp,at,source),
    {
        [Self::fp_byte(fp,at,source),Self::fp_byte(fp,at+1,source),
            Self::fp_byte(fp,at+2,source),Self::fp_byte(fp,at+3,source),
            Self::fp_byte(fp,at+4,source),Self::fp_byte(fp,at+5,source),
            Self::fp_byte(fp,at+6,source),Self::fp_byte(fp,at+7,source),
            Self::fp_byte(fp,at+8,source),Self::fp_byte(fp,at+9,source),
            Self::fp_byte(fp,at+10,source),Self::fp_byte(fp,at+11,source),
            Self::fp_byte(fp,at+12,source),Self::fp_byte(fp,at+13,source),
            Self::fp_byte(fp,at+14,source),Self::fp_byte(fp,at+15,source)]
    }

    fn fp_copy_count(target:SaveTarget)->(count:u8)
        requires spec::fp::valid_target(target),
        ensures count as int==spec::fp::count(target),1<=count<=16,
    {
        let end=match target.source {
            SaveSource::Legacy {preserve_pointers:true,..} if target.offset<6=>6u16,
            SaveSource::Legacy {..}=>416u16,_=>16u16,
        };
        let remaining=end-target.offset;
        let count=if remaining<16 {remaining} else {16u16};
        let page=4096-(target.linear%4096+target.offset as u64)%4096;
        (if page<count as u64 {page} else {count as u64}) as u8
    }

    pub(super) fn fp_save_request(&self,target:SaveTarget)->(request:Request)
        requires self.invariant(),self.phase==(Phase::FpSave {target}),
        ensures request==spec::fp::request(self@,target),
    {
        let fp=self.system.unwrap().fp;
        let offset=target.linear%4096+target.offset as u64;
        let address=if offset<4096 {target.first+offset} else {target.second+(offset-4096)};
        Request::WriteBytes {address,bytes:Self::fp_bytes(fp,target.offset,target.source),
            offset:0,end:Self::fp_copy_count(target)}
    }

    pub(super) fn fp_save_response(&mut self,reply:Reply)->(accepted:bool)
        requires old(self).invariant(),old(self).phase is FpSave,
        ensures final(self).invariant(),(final(self)@,accepted)==spec::fp::respond(old(self)@,reply),
    {
        let target=match self.phase {Phase::FpSave {target}=>target,_=>{assert(false);return false;}};
        let Reply::Copied(count)=reply else {return false;};
        if count==0 || count>Self::fp_copy_count(target) {return false;}
        let next=target.offset+count as u16;
        let end=match target.source {SaveSource::Legacy {..}=>416u16,_=>16u16};
        let preserve=matches!(target.source,SaveSource::Legacy {preserve_pointers:true,..});
        if next==end {self.phase=Phase::FpSaveDone {length:target.length};}
        else {self.phase=Phase::FpSave {target:SaveTarget {
            offset:if next==6 && preserve {24} else {next},..target}};}
        true
    }
}
}
