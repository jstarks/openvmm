// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use memory_core::cpu_core::compare;
#[cfg(verus_keep_ghost)]
use memory_core::cpu_core::operand;
use memory_core::cpu_core::operand::{Address, Operand, Register, Segment, SegmentBases, Width};
use memory_core::cpu_core::system::NULL_SEGMENT;
use memory_core::cpu_core::{control, descriptor, integer, profile, scalar as operations};

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(inconsistent_fields)]
pub enum Instruction {
    Nop,
    Fence,
    InitializeX87,
    Breakpoint,
    SwapGs,
    SaveFp {address:Address,wide:bool},
    Integer { operation: integer::Operation, dst: Register, source: Operand },
    Alu { operation: integer::Operation, destination: Operand, source: Operand },
    SignExtend { dst: Register, source: Operand, width: Width },
    SignHigh { width: Width },
    DoubleShift {dst:Register,source:Register,count:Operand,left:bool},
    Divide { source: Operand, width: Width, signed: bool },
    Bit { operation: operations::BitOperation, dst: Register, index: Operand },
    Scan { dst:Register,source:Operand,reverse:bool },
    ReadControl { number: u8, dst: Register },
    WriteControl { number: u8, source: Operand },
    ReadDebug {number:u8,dst:Register},
    WriteDebug {number:u8,source:Register},
    IndirectJump { source: Operand },
    IndirectCall { source: Operand },
    Multiply { dst:Register, source:Operand, immediate:Option<u64> },
    MultiplyWide {source:Operand,width:Width,signed:bool},
    RepeatStore { width:Width },
    RepeatMove { width:Width },
    ConditionalMove { condition: control::Condition, dst: Register, source: Operand },
    SetCondition { condition: control::Condition, destination: Operand },
    Direction { set: bool },
    CompareExchange { destination: Operand, source: Register },
    LockedAlu { operation:integer::Operation,destination:Operand,source:Operand },
    ExchangeAdd {destination:Operand,source:Register,locked:bool},
    ExchangeMemory {address:Address,source:Register},
    ReadMsr,
    ReadTimestamp,
    PortIo { port: Port, width: Width, write: bool },
    ZeroExtend { dst: Register, src: Register },
    Load { dst: Register, address: Address, width: Width },
    Store { address: Address, width: Width, source: Operand },
    Table { address: Address, idt: bool },
    StoreTable {address:Address,idt:bool},
    LoadTask {source:Register},
    LoadLdt {source:Register},
    Segment { segment: Segment, src: Register },
    ReadSegment {segment:Segment,destination:Operand},
    Push { source: Operand },
    Pop { dst: Register },
    PopMemory {address:Address},
    PushFlags,
    PopFlags,
    FarReturn,
    Cpuid,
    Branch { target: u64, condition: control::Condition },
    Return,
    Leave,
    Jump { target: u64, zero: Option<bool> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Port { Dx, Immediate(u8) }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRequest {
    pub sequence: u64,
    pub port: u16,
    pub width: Width,
    pub access: WordAccess,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryTask {
    Load { dst: Register },
    Store,
    TableLimit { idt: bool },
    TableBase { idt: bool, limit: u16 },
    StoreTableBase {base:u64},
    SaveFp {index:u8,wide:bool},
    TaskLow {selector:u16},
    TaskHigh {selector:u16,low:u64},
    TaskBusy {image:SegmentState,low:u64},
    Segment { segment: Segment, selector: u16 },
    StackCommit { stack: u64 },
    PushValue {stack:u64},
    PopMemory {stack:u64,address:Address},
    Return { stack: u64 },
    Leave { stack: u64 },
    Pop { stack: u64, dst: Register },
    Flags { stack: u64 },
    FarTarget { stack: u64 },
    FarSelector { stack: u64, target: u64 },
    FarCode { stack: u64, target: u64, selector: u16 },
    AluRegister { operation: integer::Operation, dst: Register },
    AluMemory { operation: integer::Operation, source: u64, width: Width },
    SignedLoad { dst: Register, width: Width },
    Division { width: Width, signed: bool },
    JumpTarget,
    CallTarget,
    Multiply { dst:Register, immediate:Option<u64> },
    MultiplyWide {width:Width,signed:bool},
    RepeatStore { width:Width },
    RepeatRead { width:Width },
    RepeatWrite { width:Width },
    ConditionalMove { condition: control::Condition, dst: Register },
    CompareExchange { width: Width },
    LockedAlu {operation:integer::Operation,source:u64,width:Width},
    ExchangeAdd {register:Register,locked:bool},
    Exchange {register:Register},
    Scan {dst:Register,reverse:bool},
}

pub(super) fn scalar(cpu: State, source: Operand) -> (out: Option<u64>)
    ensures out == spec::entry::scalar(cpu@, source),
{
    match source {
        Operand::Register(reg) => if reg.is_valid() { Some(reg.read(&cpu.gpr)) } else { None },
        Operand::Immediate(imm) => Some(imm.value),
        _ => None,
    }
}

pub(super) fn supported_access(address:u64,width:Width)->(out:bool)
    ensures out == spec::entry::supported_access(address,width),
{
    let size=(width.bits()/8) as u8;
    address <= u64::MAX-(size as u64-1)
        && canonical(address) && canonical(address+(size as u64-1))
}

impl SharedEventMachine {
    #[inline(always)]
    pub(super) fn retire_entry(&mut self, mut cpu: State, length: u8, shadow: bool, serializing: bool) -> (tick: Tick)
        requires old(self).invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@, tick) == spec::entry::retire(old(self)@, cpu@, length, shadow, serializing),
    {
        cpu.rip = cpu.rip.wrapping_add(length as u64);
        cpu.flags &= !0x10000u64;
        let _accepted = self.core.boundary_commit(cpu, true);
        assert(_accepted);
        self.phase = Phase::Ready; self.shadow = shadow; self.handler_pending = false;
        Tick::Retired(serializing)
    }

    pub(super) fn entry_memory(&mut self, address: u64, width: Width, request: WordAccess,
        length: u8, task: MemoryTask) -> (tick: Tick)
        requires old(self).invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@, tick) == spec::entry::memory(old(self)@, address, width, request, length, task),
    {
        let size = (width.bits() / 8) as u8;
        if !supported_access(address,width) {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let _accepted = self.core.boundary_span(address, request, size);
        assert(_accepted);
        self.phase = Phase::EntryMemory { address, length, task };
        Tick::Pending
    }

    pub(super) fn execute_entry(&mut self, instruction: Instruction, length: u8) -> (tick: Tick)
        requires old(self).invariant(), old(self).core@.phase == CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@, tick) == spec::entry::execute(old(self)@, instruction, length),
    {
        let cpu=self.core.cpu();
        if length==0 || length>15 {
            reveal(spec::entry::execute);
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.flags&0x100!=0 {
            reveal(spec::entry::execute);
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        match instruction {
            Instruction::Breakpoint=>{
                reveal(spec::entry::execute);
                self.breakpoint(length)
            },
            Instruction::SwapGs=>{
                reveal(spec::entry::execute);
                self.swap_gs(length)
            },
            Instruction::InitializeX87=>{
                reveal(spec::entry::execute);
                self.initialize_x87(length)
            },
            Instruction::SaveFp {address,wide}=>{
                reveal(spec::entry::execute);
                self.save_fp(address,wide,length)
            },
            Instruction::LoadTask {source}=>{
                reveal(spec::entry::execute);
                self.execute_task(source,length)
            },
            Instruction::LoadLdt {source}=>{
                reveal(spec::entry::execute);
                let Some(mut system)=self.system else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                if !source.is_valid() || source.width()!=Width::Word
                    || source.read(&cpu.gpr)!=0 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                system.ldtr=NULL_SEGMENT;
                self.system=Some(system);
                self.retire_entry(cpu,length,false,false)
            },
            Instruction::ReadTimestamp=>{
                reveal(spec::entry::execute);
                self.start_timestamp(length)
            },
            Instruction::PortIo {port,width,write}=>{
                reveal(spec::entry::execute);
                self.start_port_io(port,width,write,length)
            },
            Instruction::CompareExchange {destination,source}=>{
                reveal(spec::entry::execute);
                self.execute_compare_exchange(destination,source,length)
            },
            Instruction::LockedAlu {operation,destination,source}=>{
                reveal(spec::entry::execute);
                self.execute_locked_alu(operation,destination,source,length)
            },
            Instruction::ExchangeAdd {destination,source,locked}=>{
                reveal(spec::entry::execute);
                self.execute_exchange_add(destination,source,locked,length)
            },
            Instruction::ExchangeMemory {address,source}=>{
                reveal(spec::entry::execute);
                self.execute_exchange_memory(address,source,length)
            },
            Instruction::MultiplyWide {source,width,signed}=>{
                reveal(spec::entry::execute);
                self.execute_wide_multiply(source,width,signed,length)
            },
            Instruction::Integer {..} | Instruction::Alu {..} | Instruction::Multiply {..} =>
                self.execute_integer(instruction,length),
            Instruction::RepeatStore {width} => {
                reveal(spec::entry::execute);
                self.execute_repeat(width,length)
            },
            Instruction::RepeatMove {width} => {
                reveal(spec::entry::execute);
                self.execute_move(width,length)
            },
            Instruction::ReadControl {..} | Instruction::WriteControl {..} | Instruction::ReadMsr
                | Instruction::ReadDebug {..} | Instruction::WriteDebug {..} => {
                reveal(spec::entry::execute);
                self.execute_control(instruction,length)
            },
            Instruction::SignExtend {..} | Instruction::SignHigh {..} | Instruction::Divide {..}
                | Instruction::DoubleShift {..}
                | Instruction::Bit {..} | Instruction::Scan {..}
                | Instruction::IndirectJump {..} | Instruction::IndirectCall {..}
                => self.execute_scalar(instruction,length),
            Instruction::ConditionalMove {..} | Instruction::SetCondition {..} | Instruction::Direction {..}
                | Instruction::ReadSegment {..}
                => self.execute_conditions(instruction,length),
            Instruction::Nop | Instruction::Fence | Instruction::Cpuid | Instruction::Branch {..}
                | Instruction::ZeroExtend {..} | Instruction::Jump {..}
                => self.execute_register(instruction,length),
            _=>self.execute_legacy(instruction,length),
        }
    }

    fn start_timestamp(&mut self,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),1<=length<=15,
        ensures final(self).invariant(),(final(self)@,tick)==spec::entry::timestamp(old(self)@,length),
    {
        if profile::cpuid(1,0)[3]&16==0 {return self.start_entry(Event::InvalidOpcode);}
        self.phase=Phase::Timestamp {sequence:self.decode_sequence,length,value:None};
        Tick::Pending
    }

    fn execute_task(&mut self,source:Register,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==spec::entry::load_task(old(self)@,source,length),
    {
        if !source.is_valid() || source.width()!=Width::Word || self.system.is_none() {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let selector=source.read(&self.core.cpu().gpr) as u16;
        if selector==0 || selector&7!=0 || selector as u64+15>self.tables.gdt_limit as u64
            || self.tables.gdt_base>u64::MAX-selector as u64-15 {
            return self.stop(EventDiagnostic::Descriptor(Stage::Stack));
        }
        self.entry_memory(self.tables.gdt_base+selector as u64,Width::Qword,WordAccess::Read,length,
            MemoryTask::TaskLow {selector})
    }

    pub fn complete_timestamp(&mut self,sequence:u64,clock:u64)->(accepted:bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            (final(self)@,accepted)==spec::entry::complete_timestamp(old(self)@,sequence,clock),
    {
        match self.phase {
            Phase::Timestamp {sequence:pending,length,value:None} if pending==sequence=>{
                self.phase=Phase::Timestamp {sequence,length,value:Some(clock)};
                true
            },
            _=>false,
        }
    }

    pub(super) fn finish_timestamp(&mut self)->(tick:Tick)
        requires old(self).invariant(),old(self).phase is Timestamp,
        ensures final(self).invariant(),(final(self)@,tick)==spec::entry::finish_timestamp(old(self)@),
    {
        match self.phase {
            Phase::Timestamp {length,value:Some(value),..}=>{
                let mut cpu=self.core.cpu();
                let ghost before=cpu@;
                cpu.gpr[0]=(value as u32) as u64;
                cpu.gpr[2]=value>>32;
                assert(cpu@.gpr =~= before.gpr.update(0,(value as u32) as int).update(2,(value>>32) as int));
                self.retire_entry(cpu,length,false,false)
            },
            _=>Tick::Waiting,
        }
    }

    fn start_port_io(&mut self, port: Port, width: Width, write: bool, length: u8) -> (tick: Tick)
        requires old(self).invariant(), old(self).core@.phase == CpuPhase::Boundary,
            1 <= length <= 15,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick) == spec::entry::port_io(old(self)@,port,width,write,length),
    {
        if width == Width::Qword {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let cpu=self.core.cpu();
        let port=match port {Port::Dx=>cpu.gpr[2] as u16,Port::Immediate(port)=>port as u16};
        let access=if write {WordAccess::Write(cpu.gpr[0]&width.mask())} else {WordAccess::Read};
        self.phase=Phase::PortIo {request:PortRequest {sequence:self.decode_sequence,port,width,access},
            length,reply:None};
        Tick::Pending
    }

    pub fn complete_port_io(&mut self, sequence:u64, completion:IoReply) -> (accepted:bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            (final(self)@,accepted)==spec::entry::complete_port_io(old(self)@,sequence,completion),
    {
        match self.phase {
            Phase::PortIo {request,length,reply:None}=>{
                if sequence!=request.sequence {return false;}
                match (request.access,completion) {
                    (WordAccess::Read,IoReply::Read(_)) | (WordAccess::Write(_),IoReply::Written)=>{
                        self.phase=Phase::PortIo {request,length,reply:Some(completion)};
                        true
                    },
                    _=>false,
                }
            },
            _=>false,
        }
    }

    pub(super) fn finish_port_io(&mut self) -> (tick:Tick)
        requires old(self).invariant(), old(self).phase is PortIo,
        ensures final(self).invariant(),(final(self)@,tick)==spec::entry::finish_port_io(old(self)@),
    {
        match self.phase {
            Phase::PortIo {request,length,reply:Some(completion)}=>{
                let mut cpu=self.core.cpu();
                if let IoReply::Read(value)=completion {
                    let dst=Register::new(memory_core::cpu_core::operand::Gpr::new(0).unwrap(),
                        request.width,false).unwrap();
                    let ghost before=cpu@;
                    assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
                    dst.write(&mut cpu.gpr,value);
                    assert(cpu@.gpr =~= operand::model::write(
                        spec::entry::registers(before),dst,value).map(|i:int,v:u64|v as int));
                    proof {
                        let mask=operand::model::mask(request.width);
                        let original=before.gpr[0] as u64;
                        assert((original&!(mask<<0u32))|((value&mask)<<0u32)
                            ==(original&!mask)|(value&mask)) by(bit_vector);
                        assert(cpu@.gpr =~= before.gpr.update(0,
                            (if request.width==Width::Dword {value&mask}
                            else {(original&!mask)|(value&mask)}) as int));
                    }
                }
                self.retire_entry(cpu,length,false,false)
            },
            _=>Tick::Waiting,
        }
    }

    #[verifier::spinoff_prover]
    pub(super) fn execute_conditions(&mut self,instruction:Instruction,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
            1<=length<=15,old(self).core@.cpu.flags&0x100u64==0,
            instruction is ConditionalMove || instruction is SetCondition || instruction is Direction
                || instruction is ReadSegment,
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::entry::execute(old(self)@,instruction,length),
    {
        reveal(spec::entry::execute);
        let mut cpu = self.core.cpu();
        assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
        let next = cpu.rip.wrapping_add(length as u64);
        match instruction {
            Instruction::ReadSegment {segment,destination}=>{
                let Some(image)=self.system else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                let value=(match segment {
                    Segment::Cs=>image.cs.selector,Segment::Ss=>image.ss.selector,
                    Segment::Ds=>image.ds.selector,Segment::Es=>image.es.selector,
                    Segment::Fs=>image.fs.selector,Segment::Gs=>image.gs.selector,
                }) as u64;
                match destination {
                    Operand::Register(dst)=>{
                        if !dst.is_valid() || dst.width()==Width::Byte {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        }
                        let ghost registers=cpu.gpr@;
                        dst.write(&mut cpu.gpr,value);
                        assert(cpu@.gpr =~= operand::model::write(registers,dst,value)
                            .map(|i:int,v:u64|v as int));
                        self.retire_entry(cpu,length,false,false)
                    },
                    Operand::Memory {address,width}=>{
                        if !address.is_valid() || width!=Width::Word {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        }
                        self.entry_memory(address.linear(&cpu.gpr,next,self.entry_bases()),
                            width,WordAccess::Write(value),length,MemoryTask::Store)
                    },
                    _=>self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                }
            },
            Instruction::Direction {set}=>{
                cpu.flags=if set {cpu.flags|0x400} else {cpu.flags&!0x400u64};
                self.retire_entry(cpu,length,false,false)
            },
            Instruction::ConditionalMove {condition,dst,source}=>{
                if !dst.is_valid() || dst.width()==Width::Byte {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                match source {
                    Operand::Register(src)=>{
                        if !src.is_valid() || src.width()!=dst.width() {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        }
                        self.finish_conditional(condition,dst,src.read(&cpu.gpr),length)
                    },
                    Operand::Memory {address,width}=>{
                        if !address.is_valid() || width!=dst.width() {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        }
                        let linear=address.linear(&cpu.gpr,next,self.entry_bases());
                        self.entry_memory(linear,width,WordAccess::Read,length,
                            MemoryTask::ConditionalMove {condition,dst})
                    },
                    _=>self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                }
            },
            Instruction::SetCondition {condition,destination}=>{
                let value=if control::condition(condition,cpu.flags) {1u64} else {0u64};
                match destination {
                    Operand::Register(dst)=>{
                        if !dst.is_valid() || dst.width()!=Width::Byte {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        }
                        let ghost registers=cpu.gpr@;
                        dst.write(&mut cpu.gpr,value);
                        assert(cpu@.gpr =~= operand::model::write(registers,dst,value)
                            .map(|i:int,v:u64|v as int));
                        self.retire_entry(cpu,length,false,false)
                    },
                    Operand::Memory {address,width}=>{
                        if !address.is_valid() || width!=Width::Byte {
                            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                        }
                        let linear=address.linear(&cpu.gpr,next,self.entry_bases());
                        self.entry_memory(linear,width,WordAccess::Write(value),length,MemoryTask::Store)
                    },
                    _=>self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                }
            },
            _=>{assert(false);Tick::Waiting},
        }
    }

    #[verifier::spinoff_prover]
    pub(super) fn execute_register(&mut self, instruction: Instruction, length: u8) -> (tick: Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
            1<=length<=15,old(self).core@.cpu.flags&0x100u64==0,
            instruction is Nop || instruction is Fence || instruction is Cpuid || instruction is Branch
                || instruction is ZeroExtend || instruction is Jump,
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::entry::execute(old(self)@,instruction,length),
    {
        reveal(spec::entry::execute);
        let mut cpu=self.core.cpu();
        assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
        match instruction {
            Instruction::Nop=>self.retire_entry(cpu,length,false,false),
            Instruction::Fence=>self.retire_entry(cpu,length,false,true),
            Instruction::Cpuid => {
                let function = (cpu.gpr[0] & 0xffff_ffff) as u32;
                let subleaf = (cpu.gpr[1] & 0xffff_ffff) as u32;
                let values = self.cpuid(function, subleaf);
                let ghost before = cpu@;
                cpu.gpr[0] = values[0] as u64; cpu.gpr[3] = values[1] as u64;
                cpu.gpr[1] = values[2] as u64; cpu.gpr[2] = values[3] as u64;
                assert(cpu@.gpr =~= before.gpr.update(0, values[0] as int)
                    .update(3, values[1] as int).update(1, values[2] as int).update(2, values[3] as int));
                self.retire_entry(cpu, length, false, true)
            },
            Instruction::Branch { target, condition } => {
                if control::condition(condition, cpu.flags) {
                    if !canonical(target) {
                        return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                    }
                    cpu.rip = target;
                    self.retire_entry(cpu, 0, false, false)
                } else { self.retire_entry(cpu, length, false, false) }
            },
            Instruction::ZeroExtend { dst, src } => {
                if !dst.is_valid() || !src.is_valid() || dst.width().bits() <= src.width().bits()
                    || !matches!(src.width(), Width::Byte | Width::Word) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let value = src.read(&cpu.gpr);
                let ghost registers = cpu.gpr@;
                dst.write(&mut cpu.gpr, value);
                assert(cpu@.gpr =~= operand::model::write(registers, dst, value)
                    .map(|i: int, v: u64| v as int));
                self.retire_entry(cpu, length, false, false)
            },
            Instruction::Jump { target, zero } => {
                let taken = match zero { None => true, Some(wanted) => (cpu.flags & 0x40 != 0) == wanted };
                if taken {
                    if !canonical(target) {
                        return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                    }
                    cpu.rip = target;
                    self.retire_entry(cpu, 0, false, false)
                } else { self.retire_entry(cpu, length, false, false) }
            },
            _=>{assert(false);Tick::Waiting},
        }
    }

    #[verifier::spinoff_prover]
    pub(super) fn execute_legacy(&mut self, instruction: Instruction, length: u8) -> (tick: Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
            1<=length<=15,old(self).core@.cpu.flags&0x100u64==0,
            instruction is PushFlags || instruction is Pop || instruction is PopMemory || instruction is PopFlags
                || instruction is FarReturn || instruction is Load || instruction is Store
                || instruction is Table || instruction is StoreTable || instruction is Segment || instruction is Push
                || instruction is Return || instruction is Leave,
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::entry::execute(old(self)@,instruction,length),
    {
        reveal(spec::entry::execute);
        let cpu=self.core.cpu();
        assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
        let next=cpu.rip.wrapping_add(length as u64);
        match instruction {
            Instruction::PushFlags => {
                if cpu.gpr[4] < 8 || cpu.gpr[4] % 8 != 0 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let stack = cpu.gpr[4] - 8;
                self.entry_memory(stack, Width::Qword, WordAccess::Write(control::flags_image(cpu.flags)),
                    length, MemoryTask::StackCommit { stack })
            },
            Instruction::Pop { dst } => {
                if !dst.is_valid() || dst.width() != Width::Qword || cpu.gpr[4] > u64::MAX - 8
                    || cpu.gpr[4] % 8 != 0 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                self.entry_memory(cpu.gpr[4], Width::Qword, WordAccess::Read, length,
                    MemoryTask::Pop { stack: cpu.gpr[4], dst })
            },
            Instruction::PopMemory {address}=>{
                if !address.is_valid() || cpu.gpr[4]>u64::MAX-8 || cpu.gpr[4]%8!=0 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                self.entry_memory(cpu.gpr[4],Width::Qword,WordAccess::Read,length,
                    MemoryTask::PopMemory {stack:cpu.gpr[4],address})
            },
            Instruction::PopFlags => {
                if cpu.gpr[4] > u64::MAX - 8 || cpu.gpr[4] % 8 != 0 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                self.entry_memory(cpu.gpr[4], Width::Qword, WordAccess::Read, length,
                    MemoryTask::Flags { stack: cpu.gpr[4] })
            },
            Instruction::FarReturn => {
                if self.system.is_none() || cpu.gpr[4] > u64::MAX - 16 || cpu.gpr[4] % 8 != 0 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                self.entry_memory(cpu.gpr[4], Width::Qword, WordAccess::Read, length,
                    MemoryTask::FarTarget { stack: cpu.gpr[4] })
            },
            Instruction::Load { dst, address, width } => {
                if !dst.is_valid() || !address.is_valid() || dst.width().bits() < width.bits() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let linear = address.linear(&cpu.gpr, next, self.entry_bases());
                self.entry_memory(linear, width, WordAccess::Read, length, MemoryTask::Load { dst })
            },
            Instruction::Store { address, width, source } => {
                if !address.is_valid() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let Some(value) = scalar(cpu, source) else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                let linear = address.linear(&cpu.gpr, next, self.entry_bases());
                self.entry_memory(linear, width, WordAccess::Write(value), length, MemoryTask::Store)
            },
            Instruction::StoreTable {address,idt}=>{
                if !address.is_valid() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let linear=address.linear(&cpu.gpr,next,self.entry_bases());
                if linear>u64::MAX-9 || !canonical(linear) || !canonical(linear+9) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                if linear%4096>4086 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DataCrossPage));
                }
                let (base,limit)=if idt {(self.tables.idt_base,self.tables.idt_limit)}
                    else {(self.tables.gdt_base,self.tables.gdt_limit)};
                self.entry_memory(linear,Width::Word,WordAccess::Write(limit as u64),length,
                    MemoryTask::StoreTableBase {base})
            },
            Instruction::Table { address, idt } => {
                if !address.is_valid() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let linear = address.linear(&cpu.gpr, next, self.entry_bases());
                self.entry_memory(linear, Width::Word, WordAccess::Read, length, MemoryTask::TableLimit { idt })
            },
            Instruction::Segment { segment: dst, src } => {
                if !src.is_valid() || !matches!(dst, Segment::Ds | Segment::Ss | Segment::Es | Segment::Fs | Segment::Gs)
                    || self.system.is_none() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let selector = (src.read(&cpu.gpr) & 0xffff) as u16;
                let Some(mut system)=self.system else {assert(false);return Tick::Waiting;};
                if selector==0 || (selector<4 && matches!(dst,Segment::Fs|Segment::Gs)) {
                    // This synthetic profile preserves null-loaded FS/GS bases where AMD leaves them undefined.
                    match dst {
                        Segment::Ds=>system.ds=NULL_SEGMENT,Segment::Ss=>system.ss=NULL_SEGMENT,
                        Segment::Es=>system.es=NULL_SEGMENT,
                        Segment::Fs=>system.fs=SegmentState {base:system.fs.base,selector,..NULL_SEGMENT},
                        Segment::Gs=>system.gs=SegmentState {base:system.gs.base,selector,..NULL_SEGMENT},
                        _=>{assert(false);},
                    }
                    self.system=Some(system);
                    return self.retire_entry(cpu,length,matches!(dst,Segment::Ss),false);
                }
                let offset = (selector & !7u16) as u64;
                if (if matches!(dst,Segment::Fs|Segment::Gs) {selector&4!=0} else {selector%8!=0})
                    || offset + 7 > self.tables.gdt_limit as u64
                    || self.tables.gdt_base > u64::MAX - offset {
                    return self.stop(EventDiagnostic::Descriptor(Stage::Stack));
                }
                self.entry_memory(self.tables.gdt_base + offset, Width::Qword, WordAccess::Read,
                    length, MemoryTask::Segment { segment: dst, selector })
            },
            Instruction::Push { source } => {
                if cpu.gpr[4] < 8 || cpu.gpr[4] % 8 != 0 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let stack = cpu.gpr[4] - 8;
                if let Operand::Memory {address,width}=source {
                    if !address.is_valid() || width!=Width::Qword {
                        return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                    }
                    let linear=address.linear(&cpu.gpr,next,self.entry_bases());
                    return self.entry_memory(linear,Width::Qword,WordAccess::Read,length,MemoryTask::PushValue {stack});
                }
                let Some(value) = scalar(cpu, source) else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                self.entry_memory(stack, Width::Qword, WordAccess::Write(value),
                    length, MemoryTask::StackCommit { stack })
            },
            Instruction::Return | Instruction::Leave => {
                let stack = if matches!(instruction, Instruction::Return) { cpu.gpr[4] } else { cpu.gpr[5] };
                if stack > u64::MAX - 8 || stack % 8 != 0 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let task = if matches!(instruction, Instruction::Return) { MemoryTask::Return { stack } }
                    else { MemoryTask::Leave { stack } };
                self.entry_memory(stack, Width::Qword, WordAccess::Read, length, task)
            },
            _=>{assert(false);Tick::Waiting},
        }
    }

    pub(super) fn entry_bases(&self) -> (out: SegmentBases)
        ensures out == spec::entry::bases(self@),
    {
        match self.system {
            Some(system) => SegmentBases { fs: system.fs.base, gs: system.gs.base },
            None => SegmentBases { fs: 0, gs: 0 },
        }
    }

    fn execute_exchange_add(&mut self,destination:Operand,source:Register,locked:bool,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
            1<=length<=15,old(self).core@.cpu.flags&0x100u64==0,
        ensures final(self).invariant(),(final(self)@,tick)==spec::entry::exchange_add(old(self)@,
            destination,source,locked,length),
    {
        if !source.is_valid() {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let Operand::Memory {width:memory_width,..}=destination else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        if memory_width!=source.width() {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let tick=if locked {
            self.execute_locked_alu(integer::Operation::Add,destination,Operand::Register(source),length)
        } else {
            self.execute_alu(integer::Operation::Add,destination,Operand::Register(source),length)
        };
        if let Phase::EntryMemory {address,length,..}=self.phase {
            self.phase=Phase::EntryMemory {address,length,task:MemoryTask::ExchangeAdd {register:source,locked}};
        }
        tick
    }

    pub(super) fn execute_compare_exchange(&mut self,destination:Operand,source:Register,length:u8)->(tick:Tick)
            requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
                !mmu_core::shared_model::active(old(self).core@.mmu.phase),
            ensures final(self).invariant(),(final(self)@,tick)==
                spec::entry::compare_exchange(old(self)@,destination,source,length),
        {
            let cpu=self.core.cpu();
            if length==0 || length>15 {
                return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
            }
            if cpu.flags&0x100!=0 {
                return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
            }
            if !source.is_valid() {
                return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
            }
            match destination {
                Operand::Register(dst)=>{
                    match compare::registers(cpu,dst,source) {
                        Some(updated)=>self.retire_entry(updated,length,false,false),
                        None=>self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
                    }
                },
                Operand::Memory {address,width}=>{
                    if !address.is_valid() || width!=source.width() {
                        return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                    }
                                let linear=address.linear(&cpu.gpr,cpu.rip.wrapping_add(length as u64),self.entry_bases());
                    let accepted=self.core.boundary_compare_exchange(linear,cpu.gpr[0],source.read(&cpu.gpr),width);
                    if !accepted {
                        return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                    }
                    self.phase=Phase::EntryMemory {address:linear,length,task:MemoryTask::CompareExchange {width}};
                    Tick::Pending
                },
                _=>self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
            }
    }

    pub(super) fn execute_exchange_memory(&mut self,address:Address,source:Register,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::entry::exchange_memory(old(self)@,address,source,length),
    {
        reveal(spec::entry::exchange_memory);
        let cpu=self.core.cpu();
        if length==0 || length>15 || !address.is_valid() || !source.is_valid() {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.flags&0x100!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        let linear=address.linear(&cpu.gpr,cpu.rip.wrapping_add(length as u64),self.entry_bases());
        let accepted=self.core.boundary_exchange(linear,source.read(&cpu.gpr),source.width());
        if !accepted {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        self.phase=Phase::EntryMemory {address:linear,length,task:MemoryTask::Exchange {register:source}};
        Tick::Pending
    }

    #[verifier::spinoff_prover]
    pub(super) fn execute_locked_alu(&mut self,operation:integer::Operation,destination:Operand,
        source:Operand,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),(final(self)@,tick)==
            spec::entry::locked_alu(old(self)@,operation,destination,source,length),
    {
        let cpu=self.core.cpu();
        if length==0 || length>15 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        if cpu.flags&0x100!=0 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::DebugRequired));
        }
        let (address,width)=match destination {
            Operand::Memory {address,width}=>(address,width),
            _=>return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
        };
        if !address.is_valid() {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let Some(value)=scalar(cpu,source) else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        let address=alu::memory_address(operation,address,source,value,width);
        let linear=address.linear(&cpu.gpr,cpu.rip.wrapping_add(length as u64),self.entry_bases());
        let accepted=self.core.boundary_locked_modify(linear,operation,value,cpu.flags,width);
        if !accepted {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        self.phase=Phase::EntryMemory {address:linear,length,
            task:MemoryTask::LockedAlu {operation,source:value,width}};
        Tick::Pending
    }

    pub(super) fn exchange_value(&mut self,register:Register,value:u64,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::entry::exchange_value(old(self)@,register,value,length),
    {
        reveal(spec::entry::exchange_value);
        if !register.is_valid() {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let mut cpu=self.core.cpu();
        assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
        let ghost registers=cpu.gpr@;
        register.write(&mut cpu.gpr,value);
        assert(cpu@.gpr =~= operand::model::write(registers,register,value)
            .map(|i:int,v:u64|v as int));
        self.retire_entry(cpu,length,false,true)
    }

    pub(super) fn segment_value(&mut self,dst:Segment,selector:u16,value:u64,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::entry::segment_value(old(self)@,dst,selector,value,length),
    {
        reveal(spec::entry::segment_value);
        let loaded=if matches!(dst,Segment::Fs|Segment::Gs) {descriptor::load_thread_data(value,selector)}
            else {descriptor::load_data(value,selector)};
        let Some(segment)=loaded else {
            return self.stop(EventDiagnostic::Descriptor(Stage::Stack));
        };
        let Some(mut system)=self.system else {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        };
        match dst {
            Segment::Ds=>system.ds=segment,Segment::Ss=>system.ss=segment,Segment::Es=>system.es=segment,
            Segment::Fs=>system.fs=segment,Segment::Gs=>system.gs=segment,
            _=>return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported)),
        }
        self.system=Some(system);
        let cpu=self.core.cpu();
        self.retire_entry(cpu,length,matches!(dst,Segment::Ss),false)
    }

    pub(super) fn pop_memory_value(&mut self,value:u64,destination:Address,stack:u64,length:u8)->(tick:Tick)
        requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@,tick)==spec::entry::pop_memory_value(old(self)@,value,destination,stack,length),
    {
        reveal(spec::entry::pop_memory_value);
        if !destination.is_valid() || stack>u64::MAX-8 {
            return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
        }
        let mut cpu=self.core.cpu();
        let ghost registers=cpu.gpr@;
        cpu.gpr[4]=stack+8;
        assert(cpu.gpr@ =~= registers.update(4,(stack+8) as u64));
        let linear=destination.linear(&cpu.gpr,cpu.rip.wrapping_add(length as u64),self.entry_bases());
        self.entry_memory(linear,Width::Qword,WordAccess::Write(value),length,
            MemoryTask::StackCommit {stack:stack+8})
    }

    pub(super) fn finish_conditional(&mut self,condition:control::Condition,dst:Register,
            value:u64,length:u8)->(tick:Tick)
            requires old(self).invariant(),old(self).core@.phase==CpuPhase::Boundary,
                !mmu_core::shared_model::active(old(self).core@.mmu.phase),
            ensures final(self).invariant(),
                (final(self)@,tick)==spec::entry::conditional_value(old(self)@,condition,dst,value,length),
        {
            let mut cpu=self.core.cpu();
            if !dst.is_valid() || dst.width()==Width::Byte {
                return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
            }
            assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
            let selected=if control::condition(condition,cpu.flags) {value} else {dst.read(&cpu.gpr)};
            let ghost registers=cpu.gpr@;
            dst.write(&mut cpu.gpr,selected);
            assert(cpu@.gpr =~= operand::model::write(registers,dst,selected)
                .map(|i:int,v:u64|v as int));
            self.retire_entry(cpu,length,false,false)
    }

    #[verifier::spinoff_prover]
    pub(super) fn entry_value(&mut self, value: u64) -> (tick: Tick)
        requires old(self).invariant(), old(self).phase is EntryMemory,
            !mmu_core::shared_model::active(old(self).core@.mmu.phase),
        ensures final(self).invariant(),
            (final(self)@, tick) == spec::entry::value(old(self)@, value),
    {
        let (address, length, task) = match self.phase {
            Phase::EntryMemory { address, length, task } => (address, length, task),
            _ => { assert(false); return Tick::Waiting; },
        };
        let mut cpu = self.core.cpu();
        assert(cpu.gpr@ =~= spec::entry::registers(cpu@));
        let ghost before = cpu@;
        match task {
            MemoryTask::Exchange {register}=>{
                return self.exchange_value(register,value,length);
            },
            MemoryTask::SaveFp {index,wide}=>{
                return self.finish_fp_save(address,index,wide,length);
            },
            MemoryTask::ExchangeAdd {register:source,locked}=>{
                if !source.is_valid() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let result=integer::evaluate(integer::Operation::Add,value,source.read(&cpu.gpr),source.width(),cpu.flags);
                let ghost registers=cpu.gpr@;
                source.write(&mut cpu.gpr,value);
                assert(cpu@.gpr =~= operand::model::write(registers,source,value).map(|i:int,v:u64|v as int));
                cpu.flags=result.flags;
                return self.retire_entry(cpu,length,false,locked);
            },
            MemoryTask::TaskLow {selector}=>{
                if address>u64::MAX-8 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                return self.entry_memory(address+8,Width::Qword,WordAccess::Read,length,
                    MemoryTask::TaskHigh {selector,low:value});
            },
            MemoryTask::TaskHigh {selector,low}=>{
                let Some(image)=descriptor::load_task(low,value,selector) else {
                    return self.stop(EventDiagnostic::Descriptor(Stage::Stack));
                };
                if address<8 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let target=address-8;
                let accepted=self.core.boundary_compare_exchange(target,low,low|(1u64<<41),Width::Qword);
                if !accepted {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                self.phase=Phase::EntryMemory {address:target,length,task:MemoryTask::TaskBusy {image,low}};
                return Tick::Pending;
            },
            MemoryTask::TaskBusy {image,low}=>{
                if value!=low {
                    return self.entry_memory(address,Width::Qword,WordAccess::Read,length,
                        MemoryTask::TaskLow {selector:image.selector});
                }
                let Some(mut system)=self.system else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                if !memory_core::cpu_core::system::supported_task(image) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                system.tr=image;
                self.system=Some(system);
                return self.retire_entry(cpu,length,false,false);
            },
            MemoryTask::Scan {dst,reverse}=>return self.finish_scan(dst,value,reverse,length),
            MemoryTask::LockedAlu {operation,source,width}=>{
                let result=integer::evaluate(operation,value,source,width,cpu.flags);
                cpu.flags=result.flags;
                return self.retire_entry(cpu,length,false,true);
            },
            MemoryTask::CompareExchange {width}=>{
                let updated=compare::memory(cpu,value,width);
                return self.retire_entry(updated,length,false,true);
            },
            MemoryTask::RepeatStore {width} => return self.finish_repeat(width,length),
            MemoryTask::RepeatRead {width} => return self.finish_move_read(width,value,length),
            MemoryTask::RepeatWrite {width} => return self.finish_move(width,length),
            MemoryTask::ConditionalMove {condition,dst} =>
                return self.finish_conditional(condition,dst,value,length),
            MemoryTask::CallTarget => return self.begin_indirect_call(value,length),
            MemoryTask::Multiply {dst,immediate} => return self.finish_multiply(dst,value,immediate,length),
            MemoryTask::MultiplyWide {width,signed}=>return self.finish_wide_multiply(value,width,signed,length),
            MemoryTask::AluRegister {operation,dst} => {
                if !dst.is_valid() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                return self.finish_alu(operation,Some(dst),dst.read(&cpu.gpr),value,dst.width(),length);
            },
            MemoryTask::AluMemory {operation,source,width} =>
                return self.finish_alu(operation,None,value,source,width,length),
            MemoryTask::SignedLoad {dst,width} => return self.finish_signed(dst,width,value,length),
            MemoryTask::Division {width,signed} => return self.finish_division(value,width,signed,length),
            MemoryTask::JumpTarget => return self.finish_jump(value),
            MemoryTask::Pop { stack, dst } => {
                if !dst.is_valid() || dst.width() != Width::Qword || stack > u64::MAX - 8 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                cpu.gpr[4] = stack + 8;
                assert(cpu@.gpr =~= before.gpr.update(4, stack as int + 8));
                let ghost registers = cpu.gpr@;
                assert(registers =~= before.gpr.update(4, stack as int + 8)
                    .map(|i:int,v:int|v as u64));
                dst.write(&mut cpu.gpr, value);
                assert(cpu@.gpr =~= operand::model::write(registers, dst, value)
                    .map(|i: int, v: u64| v as int));
            },
            MemoryTask::PopMemory {stack,address:destination}=>{
                return self.pop_memory_value(value,destination,stack,length);
            },
            MemoryTask::Flags { stack } => {
                let Some(flags) = control::restore_flags(value) else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                if stack > u64::MAX - 8 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                cpu.gpr[4] = stack + 8; cpu.flags = flags;
                assert(cpu@.gpr =~= before.gpr.update(4, stack as int + 8));
            },
            MemoryTask::FarTarget { stack } => {
                if stack > u64::MAX - 16 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                return self.entry_memory(stack + 8, Width::Qword, WordAccess::Read, length,
                    MemoryTask::FarSelector { stack, target: value });
            },
            MemoryTask::FarSelector { stack, target } => {
                if value == 0 || value > 0xffff || value % 8 != 0
                    || value + 7 > self.tables.gdt_limit as u64
                    || self.tables.gdt_base > u64::MAX - value || !canonical(target) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                return self.entry_memory(self.tables.gdt_base + value, Width::Qword,
                    WordAccess::Read, length, MemoryTask::FarCode { stack, target, selector: value as u16 });
            },
            MemoryTask::FarCode { stack, target, selector } => {
                let Some(code) = descriptor::load_code(value, selector) else {
                    return self.stop(EventDiagnostic::Descriptor(Stage::Code));
                };
                let Some(mut system) = self.system else {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                };
                if stack > u64::MAX - 16 || !canonical(target) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                system.cs = code;
                self.system = Some(system);
                cpu.gpr[4] = stack + 16; cpu.rip = target;
                assert(cpu@.gpr =~= before.gpr.update(4, stack as int + 16));
                return self.retire_entry(cpu, 0, false, false);
            },
            MemoryTask::Load { dst } => {
                if !dst.is_valid() {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                let ghost registers = cpu.gpr@;
                dst.write(&mut cpu.gpr, value);
                assert(cpu@.gpr =~= operand::model::write(registers, dst, value)
                    .map(|i: int, v: u64| v as int));
            },
            MemoryTask::Store => {},
            MemoryTask::TableLimit { idt } => {
                if address > u64::MAX - 2 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                return self.entry_memory(address + 2, Width::Qword, WordAccess::Read, length,
                    MemoryTask::TableBase { idt, limit: (value & 0xffff) as u16 });
            },
            MemoryTask::TableBase { idt, limit } => {
                if !canonical(value) {
                    return self.stop(EventDiagnostic::Descriptor(if idt { Stage::Idt } else { Stage::Code }));
                }
                if idt { self.tables.idt_base = value; self.tables.idt_limit = limit; }
                else { self.tables.gdt_base = value; self.tables.gdt_limit = limit; }
                return self.retire_entry(cpu, length, false, false);
            },
            MemoryTask::Segment { segment: dst, selector } => {
                return self.segment_value(dst,selector,value,length);
            },
            MemoryTask::StoreTableBase {base}=>{
                if address>u64::MAX-2 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                return self.entry_memory(address+2,Width::Qword,WordAccess::Write(base),length,MemoryTask::Store);
            },
            MemoryTask::StackCommit { stack } => {
                cpu.gpr[4] = stack;
                assert(cpu@.gpr =~= before.gpr.update(4, stack as int));
            },
            MemoryTask::PushValue {stack}=>{
                return self.entry_memory(stack,Width::Qword,WordAccess::Write(value),length,MemoryTask::StackCommit {stack});
            },
            MemoryTask::Return { stack } => {
                if stack > u64::MAX - 8 || !canonical(value) {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                cpu.gpr[4] = stack + 8;
                assert(cpu@.gpr =~= before.gpr.update(4, stack as int + 8));
                cpu.rip = value;
                return self.retire_entry(cpu, 0, false, false);
            },
            MemoryTask::Leave { stack } => {
                if stack > u64::MAX - 8 {
                    return self.stop(EventDiagnostic::Instruction(PagedDiagnostic::Unsupported));
                }
                cpu.gpr[4] = stack + 8; cpu.gpr[5] = value;
                assert(cpu@.gpr =~= before.gpr.update(4, stack as int + 8).update(5, value as int));
            },
        }
        self.retire_entry(cpu, length, false, false)
    }
}
}
