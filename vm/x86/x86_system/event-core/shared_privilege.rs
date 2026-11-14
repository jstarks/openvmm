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
    pub(super) fn finish_xmm_byte_shift(&mut self,index:u8,count:u8,left:bool,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==
            spec::privilege::finish_xmm_byte_shift(old(self)@,index,count,left,length),
    {
        reveal(spec::privilege::finish_xmm_byte_shift);
        let Some(mut system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        if index>=16 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
        system.fp=system.fp.xmm_byte_shift(index,count,left);
        self.system=Some(system);
        self.retire_entry(self.core.cpu(),length,false,false)
    }

    pub(super) fn finish_xmm_arithmetic(&mut self,dst:u8,low:u64,high:u64,width:Width,subtract:bool,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==
            spec::privilege::finish_xmm_arithmetic(old(self)@,dst,low,high,width,subtract,length),
    {
        reveal(spec::privilege::finish_xmm_arithmetic);
        let Some(mut system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        if dst>=16 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
        system.fp=system.fp.xmm_packed(dst,low,high,width,
            if subtract {system::PackedOperation::Subtract} else {system::PackedOperation::Add});
        self.system=Some(system);
        self.retire_entry(self.core.cpu(),length,false,false)
    }

    pub(super) fn finish_xmm_equal(&mut self,dst:u8,low:u64,high:u64,width:Width,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==
            spec::privilege::finish_xmm_equal(old(self)@,dst,low,high,width,length),
    {
        reveal(spec::privilege::finish_xmm_equal);
        let Some(mut system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        if dst>=16 || width==Width::Qword {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        system.fp=system.fp.xmm_equal(dst,low,high,width);
        self.system=Some(system);
        self.retire_entry(self.core.cpu(),length,false,false)
    }

    pub(super) fn execute_xmm_equal_memory(&mut self,address:Address,index:u8,width:Width,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==
            spec::privilege::execute_xmm_equal_memory(old(self)@,address,index,width,length),
    {
        reveal(spec::privilege::execute_xmm_equal_memory);
        if width==Width::Qword {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
        self.execute_xmm_read(address,index,entry::XmmReadAction::Equal(width),length)
    }

    pub(super) fn execute_xmm_read(&mut self,address:Address,index:u8,action:entry::XmmReadAction,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==
            spec::privilege::execute_xmm_read(old(self)@,address,index,action,length),
    {
        reveal(spec::privilege::execute_xmm_read);
        let tick=self.execute_xmm_memory(address,index,false,entry::XmmMemoryKind::Aligned,length);
        if let Phase::EntryMemory {address,length,task:entry::MemoryTask::XmmLow {..}}=self.phase {
            self.phase=Phase::EntryMemory {address,length,
                task:entry::MemoryTask::XmmLow {index,action}};
        }
        tick
    }

    pub(super) fn finish_xmm_pair(&mut self,dst:u8,low:u64,high:u64,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::privilege::finish_xmm_pair(old(self)@,dst,low,high,length),
    {
        reveal(spec::privilege::finish_xmm_pair);
        let Some(mut system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        if dst>=16 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
        system.fp=system.fp.xmm_pair(dst,low,high);
        self.system=Some(system);
        self.retire_entry(self.core.cpu(),length,false,false)
    }

    pub(super) fn finish_xmm_memory(&mut self,address:u64,task:entry::MemoryTask,value:u64,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==
            spec::privilege::finish_xmm_memory(old(self)@,address,task,value,length),
    {
        reveal(spec::privilege::finish_xmm_memory);
        match task {
            entry::MemoryTask::XmmLow {index,action}=>{
                if address>u64::MAX-8 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                self.entry_memory(address+8,Width::Qword,WordAccess::Read,length,
                    entry::MemoryTask::XmmHigh {index,low:value,action})
            },
            entry::MemoryTask::XmmHigh {index,low,action}=>match action {
                entry::XmmReadAction::Move=>self.finish_xmm_pair(index,low,value,length),
                entry::XmmReadAction::Equal(width)=>self.finish_xmm_equal(index,low,value,width,length),
                entry::XmmReadAction::Arithmetic {width,subtract}=>
                    self.finish_xmm_arithmetic(index,low,value,width,subtract,length),
            },
            entry::MemoryTask::XmmHalf {index,high}=>{
                let Some(system)=self.system else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                if index>=16 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
                let pair=system.fp.xmm[index as usize];
                self.finish_xmm_pair(index,if high {pair[0]} else {value},
                    if high {value} else {pair[1]},length)
            },
            _=>self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
        }
    }

    pub(super) fn execute_xmm_memory(&mut self,address:Address,index:u8,store:bool,
        kind:entry::XmmMemoryKind,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==
            spec::privilege::execute_xmm_memory(old(self)@,address,index,store,kind,length),
    {
        reveal(spec::privilege::execute_xmm_memory);
        let Some(system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        if !address.is_valid() || index>=16 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let cpu=self.core.cpu();
        let linear=address.linear(&cpu.gpr,cpu.rip.wrapping_add(length as u64),self.entry_bases());
        let full=matches!(kind,entry::XmmMemoryKind::Aligned|entry::XmmMemoryKind::Unaligned);
        if !entry::supported_access(linear,Width::Qword)
            || (full && (linear>u64::MAX-15 || !canonical(linear+15))) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if matches!(kind,entry::XmmMemoryKind::Aligned) && linear%16!=0 {
            return self.start_entry(Event::GeneralProtection);
        }
        if !full {
            let high=matches!(kind,entry::XmmMemoryKind::High);
            return self.entry_memory(linear,Width::Qword,
                if store {WordAccess::Write(system.fp.xmm[index as usize][if high {1usize} else {0usize}])}
                else {WordAccess::Read},length,
                if store {entry::MemoryTask::Store} else {entry::MemoryTask::XmmHalf {index,high}});
        }
        if !store {
            return self.entry_memory(linear,Width::Qword,WordAccess::Read,length,
                entry::MemoryTask::XmmLow {index,action:entry::XmmReadAction::Move});
        }
        if linear%4096>4080 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let pair=system.fp.xmm[index as usize];
        let _accepted=self.core.boundary_pair_store(linear,pair[0],pair[1]);assert(_accepted);
        self.phase=Phase::EntryMemory {address:linear,length,task:entry::MemoryTask::XmmWideStore};
        Tick::Pending
    }

    pub(super) fn finish_xmm_load(&mut self,dst:u8,value:u64,wide:bool,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::privilege::finish_xmm_load(old(self)@,dst,value,wide,length),
    {
        reveal(spec::privilege::finish_xmm_load);
        let Some(mut system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        if dst>=16 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
        system.fp=system.fp.xmm_scalar(dst,value,wide);
        self.system=Some(system);
        self.retire_entry(self.core.cpu(),length,false,false)
    }

    #[verifier::spinoff_prover]
    pub(super) fn execute_xmm(&mut self,instruction:Instruction,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::privilege::execute_xmm(old(self)@,instruction,length),
    {
        let mut cpu=self.core.cpu();
        let Some(mut system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        if system.cr4_extra&0x200==0 {return self.start_entry(Event::InvalidOpcode);}
        match instruction {
            Instruction::XmmArithmeticMemory {address,index,width,subtract}=>
                self.execute_xmm_read(address,index,entry::XmmReadAction::Arithmetic {width,subtract},length),
            Instruction::XmmArithmetic {dst,source,width,subtract}=>{
                if source>=16 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
                let pair=system.fp.xmm[source as usize];
                self.finish_xmm_arithmetic(dst,pair[0],pair[1],width,subtract,length)
            },
            Instruction::XmmEqualMemory {address,index,width}=>
                self.execute_xmm_equal_memory(address,index,width,length),
            Instruction::XmmEqual {dst,source,width}=>{
                if source>=16 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
                let pair=system.fp.xmm[source as usize];
                self.finish_xmm_equal(dst,pair[0],pair[1],width,length)
            },
            Instruction::XmmMask {dst,source}=>{
                if source>=16 || !dst.is_valid() || (dst.width()!=Width::Dword && dst.width()!=Width::Qword) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let value=system.fp.xmm_mask(source);
                assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
                let ghost registers=cpu.gpr@;
                dst.write(&mut cpu.gpr,value);
                assert(cpu@.gpr =~= operand::model::write(registers,dst,value).map(|i:int,v:u64|v as int));
                self.retire_entry(cpu,length,false,false)
            },
            Instruction::XmmMemory {address,index,store,kind}=>
                self.execute_xmm_memory(address,index,store,kind,length),
            Instruction::XmmCopy {dst,source}|Instruction::XmmMerge {dst,source,..}=>{
                if dst>=16 || source>=16 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
                let pair=system.fp.xmm[source as usize];
                match instruction {
                    Instruction::XmmMerge {high,..}=>{
                        let previous=system.fp.xmm[dst as usize];
                        self.finish_xmm_pair(dst,if high {previous[0]} else {pair[1]},
                            if high {pair[0]} else {previous[1]},length)
                    },
                    _=>self.finish_xmm_pair(dst,pair[0],pair[1],length),
                }
            },
            Instruction::XmmLoad {dst,source,width}=>{
                if dst>=16 || (width!=Width::Dword && width!=Width::Qword) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                match source {
                    memory_core::cpu_core::operand::Operand::Register(reg)=>{
                        if !reg.is_valid() || reg.width()!=width {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        }
                        self.finish_xmm_load(dst,reg.read(&cpu.gpr),width==Width::Qword,length)
                    },
                    memory_core::cpu_core::operand::Operand::Memory {address,width:operand_width}=>{
                        if !address.is_valid() || operand_width!=width {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        }
                        let linear=address.linear(&cpu.gpr,cpu.rip.wrapping_add(length as u64),self.entry_bases());
                        self.entry_memory(linear,width,WordAccess::Read,length,
                            entry::MemoryTask::XmmLoad {index:dst,wide:width==Width::Qword})
                    },
                    _=>self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                }
            },
            Instruction::XmmStore {destination,source,width}=>{
                if source>=16 || (width!=Width::Dword && width!=Width::Qword) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let value=system.fp.xmm[source as usize][0];
                match destination {
                    memory_core::cpu_core::operand::Operand::Register(dst)=>{
                        if !dst.is_valid() || dst.width()!=width {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        }
                        assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
                        let ghost registers=cpu.gpr@;
                        dst.write(&mut cpu.gpr,value);
                        assert(cpu@.gpr =~= operand::model::write(registers,dst,value)
                            .map(|i:int,v:u64|v as int));
                        self.retire_entry(cpu,length,false,false)
                    },
                    memory_core::cpu_core::operand::Operand::Memory {address,width:operand_width}=>{
                        if !address.is_valid() || operand_width!=width {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        }
                        let linear=address.linear(&cpu.gpr,cpu.rip.wrapping_add(length as u64),self.entry_bases());
                        self.entry_memory(linear,width,WordAccess::Write(value),length,entry::MemoryTask::Store)
                    },
                    _=>self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                }
            },
            Instruction::XmmCopyLow {dst,source}=>{
                if dst>=16 || source>=16 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
                self.finish_xmm_load(dst,system.fp.xmm[source as usize][0],true,length)
            },
            Instruction::XmmUnpack {dst,source,wide,high}=>{
                if dst>=16 || source>=16 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
                system.fp=system.fp.xmm_unpack(dst,source,wide,high);
                self.system=Some(system);
                self.retire_entry(cpu,length,false,false)
            },
            Instruction::XmmUnpackNarrow {dst,source,word,high}=>{
                if dst>=16 || source>=16 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
                system.fp=system.fp.xmm_unpack_narrow(dst,source,word,high);
                self.system=Some(system);
                self.retire_entry(cpu,length,false,false)
            },
            Instruction::XmmShuffle {dst,source,control}=>{
                if dst>=16 || source>=16 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
                system.fp=system.fp.xmm_shuffle(dst,source,control);
                self.system=Some(system);
                self.retire_entry(cpu,length,false,false)
            },
            Instruction::XmmByteShift {index,count,left}=>self.finish_xmm_byte_shift(index,count,left,length),
            Instruction::XmmLogic {dst,source,operation}=>{
                if dst>=16 || source>=16 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
                system.fp=system.fp.xmm_logic(dst,source,operation);
                self.system=Some(system);
                self.retire_entry(cpu,length,false,false)
            },
            _=>self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
        }
    }

    pub(super) fn fast_entry(&mut self,returning:bool,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::privilege::fast_entry(old(self)@,returning,length),
    {
        reveal(spec::privilege::fast_entry);
        let mut cpu=self.core.cpu();
        let Some(mut system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        if length<2 || length>15 || !flags_supported(cpu.flags) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let ghost flags=cpu.flags;
        assert(flags&!0x3d7fd7u64==0) by(bit_vector)
            requires flags&!0x210ed7u64==0;
        let status=if returning {privilege::sysret64(&mut cpu,&mut system)}
            else {privilege::syscall64(&mut cpu,&mut system,length)};
        match status {
            privilege::FastStatus::InvalidOpcode=>return self.start_entry(Event::InvalidOpcode),
            privilege::FastStatus::GeneralProtection=>return self.start_entry(Event::GeneralProtection),
            privilege::FastStatus::Advanced=>{},
        }
        if !system.is_supported() || !flags_supported(cpu.flags) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let _accepted=self.core.boundary_transfer(cpu,system.is_user());assert(_accepted);
        self.system=Some(system);
        self.phase=Phase::Ready;self.shadow=false;self.handler_pending=false;
        Tick::Retired(false)
    }

    pub(super) fn swap_gs(&mut self,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::privilege::swap_gs(old(self)@,length),
    {
        reveal(spec::privilege::swap_gs);
        let cpu=self.core.cpu();
        if self.is_user() {return self.start_entry(Event::GeneralProtection);}
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
                if number==8 && self.apic_id.is_some() {
                    return self.start_control(ControlAccess::ReadPriority(dst),length);
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
                if number==8 && self.apic_id.is_some() {
                    return self.start_control(ControlAccess::WritePriority(value),length);
                }
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
                let low=cpu.gpr[1]&0xffff_ffff;
                let _rcx=cpu.gpr[1];
                assert(low<=0xffff_ffff) by(bit_vector) requires low==_rcx&0xffff_ffffu64;
                let number=low as u32;
                assert(number==_rcx as u32) by(bit_vector)
                    requires number==(_rcx&0xffff_ffffu64) as u32;
                if self.apic_id.is_some() && control_io::apic_msr(number) {
                    return self.start_control(ControlAccess::ReadMsr(number),length);
                }
                if number==0x49 || !profile::msr_declared(number as u64,self.apic_id.is_some()) {
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
                    0xc001001f=>profile::NB_CFG,
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
            || (!wide && system.fp.status&0x80!=0 && (system.fp.ip!=0 || system.fp.dp!=0)) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let linear=address.linear(&cpu.gpr,cpu.rip.wrapping_add(length as u64),self.entry_bases());
        if !canonical(linear) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if linear%16!=0 {
            return self.start_entry(Event::GeneralProtection);
        }
        if linear%4096>3584 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DataCrossPage));
        }
        let word=system.fp.save_word(0,wide);
        if system.fp.status&0x80!=0 {
            self.entry_memory(linear,Width::Qword,WordAccess::Write(word),length,
                entry::MemoryTask::SaveFp {index:0,wide})
        } else {
            self.entry_memory(linear,Width::Dword,WordAccess::Write(word&0xffff_ffff),length,
                entry::MemoryTask::SaveFpHeader {wide})
        }
    }

    pub(super) fn finish_fp_header(&mut self,address:u64,wide:bool,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::privilege::save_fp_header(old(self)@,address,wide,length),
    {
        reveal(spec::privilege::save_fp_header);
        let Some(system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        if address>u64::MAX-4 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let word=(system.fp.save_word(0,wide)>>32)&0xffff;
        self.entry_memory(address+4,Width::Word,WordAccess::Write(word),length,
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
        // AMD leaves the error pointers and opcode untouched when ES is clear.
        if index==0 && system.fp.status&0x80==0 {
            if address>u64::MAX-20 {
                return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
            }
            return self.entry_memory(address+20,Width::Qword,WordAccess::Write(system.fp.save_word(3,wide)),
                length,entry::MemoryTask::SaveFp {index:3,wide});
        }
        let next=index+1;
        let word=system.fp.save_word(next,wide);
        self.entry_memory(address+8,Width::Qword,WordAccess::Write(word),length,
            entry::MemoryTask::SaveFp {index:next,wide})
    }

    pub(super) fn load_x87_integer(&mut self,address:Address,width:Width,opcode:u16,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::privilege::load_x87_integer(old(self)@,address,width,opcode,length),
    {
        reveal(spec::privilege::load_x87_integer);
        let cpu=self.core.cpu();
        if length==0 || length>15 || !address.is_valid() || width==Width::Byte || opcode>0x7ff {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.flags&0x100!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        let Some(system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        if !system.fp.integer_ready() {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let linear=address.linear(&cpu.gpr,cpu.rip.wrapping_add(length as u64),self.entry_bases());
        if !canonical(linear) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        self.entry_memory(linear,width,WordAccess::Read,length,
            entry::MemoryTask::LoadX87Integer {width,opcode})
    }

    pub(super) fn finish_x87_integer(&mut self,address:u64,value:u64,width:Width,opcode:u16,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::privilege::load_x87_value(old(self)@,address,value,width,opcode,length),
    {
        reveal(spec::privilege::load_x87_value);
        let cpu=self.core.cpu();
        let Some(mut system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        if width==Width::Byte || opcode>0x7ff || !system.fp.integer_ready() {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        system.fp=system.fp.push_integer(value,width,cpu.rip,address,opcode);
        self.system=Some(system);
        self.retire_entry(cpu,length,false,false)
    }

    pub(super) fn restore_fp(&mut self,address:Address,wide:bool,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::privilege::restore_fp(old(self)@,address,wide,length),
    {
        reveal(spec::privilege::restore_fp);
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
        if system.cr4_extra&0x200==0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let linear=address.linear(&cpu.gpr,cpu.rip.wrapping_add(length as u64),self.entry_bases());
        if !canonical(linear) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if linear%16!=0 {return self.start_entry(Event::GeneralProtection);}
        if linear%4096>3584 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DataCrossPage));
        }
        self.fp_restore=Some(system.fp);
        self.entry_memory(linear,Width::Qword,WordAccess::Read,length,
            entry::MemoryTask::RestoreFp {index:0,wide})
    }

    pub(super) fn finish_fp_restore(&mut self,address:u64,index:u8,value:u64,wide:bool,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::privilege::restore_fp_value(old(self)@,address,index,value,wide,length),
    {
        reveal(spec::privilege::restore_fp_value);
        if index>=52 {return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));}
        let Some(mut fp)=self.fp_restore else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        let Some(mut system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        if index==0 && ((value as u16)&0xe080!=0 || value&0x40==0) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if !wide && (index==1 || index==2)
            && ((fp.status&!fp.control)&0x3f)!=0 && value&0xffff_ffff_0000_0000!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if index==3 && (value as u32)&!profile::MXCSR_MASK!=0 {
            return self.start_entry(Event::GeneralProtection);
        }
        fp=fp.restore_word(index,value,wide);
        if index==51 {
            system.fp=fp.finish_restore(system.fp);
            self.system=Some(system);
            self.fp_restore=None;
            self.retire_entry(self.core.cpu(),length,false,false)
        } else if address>u64::MAX-8 {
            self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported))
        } else {
            self.fp_restore=Some(fp);
            self.entry_memory(address+8,Width::Qword,WordAccess::Read,length,
                entry::MemoryTask::RestoreFp {index:index+1,wide})
        }
    }

    pub(super) fn control_x87(&mut self,operation:system::X87Control,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::privilege::control_x87(old(self)@,operation,length),
    {
        reveal(spec::privilege::control_x87);
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
        if system.cr0_extra&0xcu64!=0
            || (operation==system::X87Control::EmptyMmx
                && ((system.fp.status&!system.fp.control)&0x3fu16)!=0) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        system.fp=system.fp.control_x87(operation);
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
        if number!=0xc0011029 && number!=0xc001001f && privilege::read_entry(system.entry,number).is_none() {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let value=(cpu.gpr[0]&0xffff_ffff)|((cpu.gpr[2]&0xffff_ffff)<<32);
        if number==0xc001001f {
            if value!=profile::NB_CFG {
                return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
            }
            return self.retire_entry(cpu,length,false,true);
        }
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
