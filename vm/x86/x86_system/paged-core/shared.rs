// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Instruction execution whose MMU effects may interleave with other RAM clients.
use super::shared_model as spec;
use super::*;
use memory_core::shared::PhysicalRam;
use mmu_core::shared::io::{IoReply, IoRoute, Operand};
use mmu_core::shared::{self as memory, Reply, Request, RunError, SharedMmu};

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuPhase {
    Ready, First, Second { rex: u8 }, Third { rex: u8, opcode: u8 },
    Data { op: memory_core::Op }, Stopped { outcome: StepOutcome }, Boundary,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tick { Pending, Waiting, Retired, Stopped(StepOutcome), Boundary }

pub struct SharedMachine { cpu: State, mmu: SharedMmu, phase: CpuPhase, user: bool }
impl View for SharedMachine {
    type V = spec::State;
    closed spec fn view(&self) -> spec::State {
        spec::State { cpu: self.cpu@, mmu: self.mmu@, phase: self.phase, user: self.user }
    }
}

impl SharedMachine {
    pub closed spec fn invariant(&self) -> bool {
        self.mmu.invariant()
        && (!matches!(self.phase, CpuPhase::Ready | CpuPhase::Stopped { .. } | CpuPhase::Boundary)
            ==> self.cpu.flags & 0x10100u64 == 0)
        && match self.phase {
            CpuPhase::Ready | CpuPhase::Stopped { .. } =>
                !mmu_core::shared_model::active(self.mmu@.phase),
            CpuPhase::Boundary => true,
            CpuPhase::First => self.mmu@.word is None && self.mmu@.va == self.cpu.rip,
            CpuPhase::Second { rex } => self.mmu@.word is None && self.cpu.rip < u64::MAX
                && 0x48 <= rex && rex <= 0x4f && self.mmu@.va == self.cpu.rip + 1,
            CpuPhase::Third { rex, opcode } => self.mmu@.word is None && self.cpu.rip < u64::MAX - 1
                && 0x48 <= rex && rex <= 0x4f && (opcode == 0x01 || opcode == 0x11 || opcode == 0x8b || opcode == 0x89)
                && self.mmu@.va == self.cpu.rip + 2,
            CpuPhase::Data { op } => self.mmu@.word is Some && match op {
                memory_core::Op::Load { reg, base } | memory_core::Op::Store { reg, base } => reg < 16 && base < 16,
                _ => false,
            },
        }
    }

    pub fn new(cpu: State, config: Config, cr2: u64, user: bool) -> (s: Self)
        ensures s.invariant(), s@.cpu == cpu@, s@.phase == CpuPhase::Ready,s@.user==user,
    { Self { cpu, mmu: SharedMmu::new(config, cr2), phase: CpuPhase::Ready, user } }

    #[inline]
    pub fn cpu(&self) -> (out: State) ensures out@ == self@.cpu { self.cpu }
    pub fn cr2(&self) -> (out: u64) ensures out as int == self@.mmu.inner.cr2 { self.mmu.cr2() }
    pub fn config(&self) -> (out: Config) ensures out == self@.mmu.inner.config { self.mmu.config() }

    pub fn io_operand(&self) -> (out: Option<Operand>)
        requires self.invariant(),
        ensures out == spec::io_operand(self@),
    {
        if matches!(self.phase, CpuPhase::Data { .. } | CpuPhase::Boundary) { self.mmu.operand() } else { None }
    }

    pub fn route_io(&mut self) -> (out: IoRoute)
        requires old(self).invariant(),
        ensures final(self).invariant(), (final(self)@, out) == spec::route_io(old(self)@),
    {
        if matches!(self.phase, CpuPhase::Data { .. } | CpuPhase::Boundary) { self.mmu.route_io() } else { IoRoute::NotReady }
    }

    pub fn complete_io(&mut self, sequence: u64, reply: IoReply) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            (final(self)@, accepted) == spec::complete_io(old(self)@, sequence, reply),
    {
        if matches!(self.phase, CpuPhase::Data { .. } | CpuPhase::Boundary) { self.mmu.complete_io(sequence, reply) } else { false }
    }

    pub(crate) proof fn boundary_facts(&self)
        requires self.invariant(),
        ensures (self@.phase is Ready || self@.phase is Stopped)
            ==> !mmu_core::shared_model::active(self@.mmu.phase),
    { }

    pub(crate) fn boundary(&mut self) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(), (final(self)@, accepted) == spec::boundary(old(self)@),
    {
        if !matches!(self.phase, CpuPhase::Ready | CpuPhase::Stopped { .. } | CpuPhase::Boundary)
            || self.mmu.active() { return false; }
        self.phase = CpuPhase::Boundary;
        true
    }

    pub(crate) fn boundary_fetch(&mut self, address: u64) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(), (final(self)@, accepted) ==
            spec::boundary_begin(old(self)@, address, None),
    {
        if !matches!(self.phase, CpuPhase::Boundary) { return false; }
        self.mmu.begin(address, Access::Fetch, self.user)
    }

    #[inline]
    pub(crate) fn fetched_word(&self)->(out:Option<(u64,u64)>)
        requires self.invariant(),
        ensures out==mmu_core::shared_model::fetched_word(self@.mmu),
    {self.mmu.fetched_word()}

    #[inline]
    pub(crate) fn boundary_fetch_next(&mut self,address:u64)->(accepted:bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            (final(self)@,accepted)==spec::boundary_fetch_next(old(self)@,address),
    {
        if !matches!(self.phase,CpuPhase::Boundary) {return false;}
        self.mmu.begin_fetch_next(address,self.user)
    }

    pub(crate) fn boundary_word(&mut self, address: u64, request: WordAccess) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(), (final(self)@, accepted) ==
            spec::boundary_begin(old(self)@, address, Some(request)),
    {
        self.boundary_word_as(address,request,false)
    }
    pub(crate) fn boundary_word_as(&mut self,address:u64,request:WordAccess,user:bool)->(accepted:bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            (final(self)@,accepted)==spec::boundary_word_as(old(self)@,address,request,user),
    {
        if !matches!(self.phase,CpuPhase::Boundary) {return false;}
        self.mmu.begin_word(address,request,user)
    }
    pub(crate) fn boundary_system_span(&mut self,address:u64,word:WordAccess,size:u8)->(accepted:bool)
        requires old(self).invariant(),size==1 || size==2 || size==4 || size==8,
        ensures final(self).invariant(),
            (final(self)@,accepted)==spec::boundary_system_span(old(self)@,address,word,size),
    {
        if !matches!(self.phase,CpuPhase::Boundary) {return false;}
        self.mmu.begin_span(address,word,size,false)
    }

    #[inline(always)]
    pub(crate) fn boundary_commit(&mut self, cpu: State, release: bool) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(), (final(self)@, accepted) ==
            spec::boundary_commit(old(self)@, cpu@, release),
    {
        if !matches!(self.phase, CpuPhase::Boundary) || self.mmu.active() { return false; }
        self.cpu = cpu;
        if release { self.phase = CpuPhase::Ready; }
        true
    }

    pub(crate) fn boundary_transfer(&mut self,cpu:State,user:bool)->(accepted:bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            (final(self)@,accepted)==spec::boundary_transfer(old(self)@,cpu@,user),
    {
        if !matches!(self.phase,CpuPhase::Boundary) || self.mmu.active() {return false;}
        self.cpu=cpu;self.user=user;self.phase=CpuPhase::Ready;
        true
    }

    pub(crate) fn boundary_decoded(&mut self, rex: u8, opcode: u8, modrm: u8) -> (tick: Tick)
        requires old(self).invariant(), old(self)@.phase is Boundary,
            !mmu_core::shared_model::active(old(self)@.mmu.phase),
            old(self)@.cpu.flags & 0x10100u64 == 0,
        ensures final(self).invariant(),
            (final(self)@, tick) == spec::decoded(old(self)@, rex, opcode, modrm),
    {
        self.decoded(rex, opcode, modrm)
    }

    pub(crate) fn boundary_span(&mut self, address: u64, word: WordAccess, size: u8) -> (accepted: bool)
        requires old(self).invariant(), size == 1 || size == 2 || size == 4 || size == 8,
        ensures final(self).invariant(), (final(self)@, accepted) ==
            spec::boundary_span(old(self)@, address, word, size),
    {
        if !matches!(self.phase, CpuPhase::Boundary) { return false; }
        self.mmu.begin_span(address, word, size,self.user)
    }

    pub(crate) fn boundary_modify(&mut self, address: u64,
        operation: memory_core::cpu_core::integer::Operation, source: u64, flags: u64,
        width: memory_core::cpu_core::operand::Width) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(), (final(self)@, accepted) ==
            spec::boundary_modify(old(self)@, address, operation, source, flags, width),
    {
        if !matches!(self.phase, CpuPhase::Boundary) { return false; }
        self.mmu.begin_modify_span(address, operation, source, flags, width,self.user)
    }

    pub(crate) fn boundary_exchange(&mut self,address:u64,replacement:u64,
        width:memory_core::cpu_core::operand::Width)->(accepted:bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),(final(self)@,accepted)==
            spec::boundary_exchange(old(self)@,address,replacement,width),
    {
        if !matches!(self.phase,CpuPhase::Boundary) {return false;}
        self.mmu.begin_exchange_as(address,replacement,width,self.user)
    }

    pub(crate) fn boundary_compare_exchange(&mut self,address:u64,expected:u64,replacement:u64,
        width:memory_core::cpu_core::operand::Width)->(accepted:bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),(final(self)@,accepted)==
            spec::boundary_compare_exchange(old(self)@,address,expected,replacement,width),
    {
        if !matches!(self.phase,CpuPhase::Boundary) {return false;}
        self.mmu.begin_compare_exchange_as(address,expected,replacement,width,self.user)
    }

    pub(crate) fn boundary_locked_modify(&mut self,address:u64,
        operation:memory_core::cpu_core::integer::Operation,source:u64,flags:u64,
        width:memory_core::cpu_core::operand::Width)->(accepted:bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),(final(self)@,accepted)==
            spec::boundary_locked_modify(old(self)@,address,operation,source,flags,width),
    {
        if !matches!(self.phase,CpuPhase::Boundary) {return false;}
        self.mmu.begin_locked_modify_as(address,operation,source,flags,width,self.user)
    }

    pub(crate) fn boundary_reload(&mut self, config: Config) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(), (final(self)@, accepted) ==
            spec::boundary_reload(old(self)@, config),
    {
        if !matches!(self.phase, CpuPhase::Boundary) { return false; }
        self.mmu.reload(config)
    }

    fn decoded(&mut self, rex: u8, opcode: u8, modrm: u8) -> (tick: Tick)
        requires old(self).mmu.invariant(),
            !mmu_core::shared_model::active(old(self).mmu@.phase),
            old(self).cpu.flags & 0x10100u64 == 0,
        ensures final(self).invariant(),
            (final(self)@, tick) == spec::decoded(old(self)@, rex, opcode, modrm),
    {
        let op = memory_core::decode(rex, opcode, modrm);
        match op {
            memory_core::Op::Alu(alu) => {
                let _result = execute(&mut self.cpu, alu);
                assert(_result == Diagnostic::Advanced);
                self.phase = CpuPhase::Ready;
                Tick::Retired
            },
            memory_core::Op::Unsupported =>
                self.stop(StepOutcome::Diagnostic(PagedDiagnostic::Unsupported)),
            memory_core::Op::Load { base, .. } | memory_core::Op::Store { base, .. } => {
                let address = self.cpu.gpr[base as usize];
                let request = match op { memory_core::Op::Store { reg, .. } =>
                    WordAccess::Write(self.cpu.gpr[reg as usize]), _ => WordAccess::Read };
                let _accepted = self.mmu.begin_span(address, request,8,self.user);
                assert(_accepted);
                self.phase = CpuPhase::Data { op };
                Tick::Pending
            },
        }
    }

    fn stop(&mut self, outcome: StepOutcome) -> (tick: Tick)
        requires old(self).mmu.invariant(), !mmu_core::shared_model::active(old(self).mmu@.phase),
        ensures final(self).invariant(), (final(self)@, tick) == spec::stopped(old(self)@, outcome),
    { self.phase = CpuPhase::Stopped { outcome }; Tick::Stopped(outcome) }

    #[inline]
    pub fn request(&self) -> (request: Request)
        requires self.invariant(),
        ensures request == mmu_core::shared_model::request(self@.mmu),
    { self.mmu.request() }

    #[inline]
    pub fn respond(&mut self, reply: Reply) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(), final(self)@ == (spec::State {
            mmu: mmu_core::shared_model::respond(old(self)@.mmu, reply).0, ..old(self)@ }),
            accepted == mmu_core::shared_model::respond(old(self)@.mmu, reply).1,
    { self.mmu.respond(reply) }

    pub fn invalidate(&mut self, va: u64) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(), final(self)@.cpu == old(self)@.cpu,
            (final(self)@, accepted) == spec::invalidate(old(self)@, va),
    {
        match self.phase {
            CpuPhase::Ready | CpuPhase::Stopped { .. } | CpuPhase::Boundary => self.mmu.invalidate(va),
            _ => false,
        }
    }

    pub fn resume(&mut self) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(), final(self)@.cpu == old(self)@.cpu,
            final(self)@.mmu == old(self)@.mmu,
            accepted == (old(self)@.phase is Stopped),
            final(self)@.phase == if accepted { CpuPhase::Ready } else { old(self)@.phase },
    {
        match self.phase {
            CpuPhase::Stopped { .. } => { self.phase = CpuPhase::Ready; true },
            _ => false,
        }
    }

    pub fn advance(&mut self) -> (tick: Tick)
        requires old(self).invariant(),
        ensures final(self).invariant(), (final(self)@, tick) == spec::advance(old(self)@),
    {
        match self.phase {
            CpuPhase::Ready => {
                if self.cpu.flags & 0x10100u64 != 0 {
                    return self.stop(StepOutcome::Diagnostic(PagedDiagnostic::DebugRequired));
                }
                let _accepted = self.mmu.begin(self.cpu.rip, Access::Fetch, self.user);
                assert(_accepted);
                self.phase = CpuPhase::First;
                Tick::Pending
            },
            CpuPhase::Stopped { outcome } => Tick::Stopped(outcome),
            CpuPhase::Boundary => Tick::Boundary,
            CpuPhase::Data { op } => {
                match self.mmu.request() {
                    Request::CompleteWord { report } => match report.result {
                        WordResult::Success(value) => {
                            commit(&mut self.cpu, op, value);
                            self.phase = CpuPhase::Ready;
                            Tick::Retired
                        },
                        _ => {
                            let address = self.mmu.virtual_address();
                            self.stop(word_outcome(report.result, address))
                        },
                    },
                    _ => Tick::Waiting,
                }
            },
            _ => {
                match self.mmu.request() {
                    Request::Complete(report) => match report.result {
                        MmuResult::Success(value) => self.fetched_byte(value),
                        _ => {
                            let address = self.fetch_address();
                            self.stop(byte_outcome(report.result, address))
                        },
                    },
                    _ => Tick::Waiting,
                }
            },
        }
    }

    fn fetch_address(&self) -> (address: u64)
        requires self.invariant(), self.phase is First || self.phase is Second || self.phase is Third,
        ensures address == self@.mmu.va,
    {
        match self.phase {
            CpuPhase::First => self.cpu.rip,
            CpuPhase::Second { .. } => self.cpu.rip + 1,
            CpuPhase::Third { .. } => self.cpu.rip + 2,
            _ => { assert(false); 0 },
        }
    }

    fn fetched_byte(&mut self, value: u8) -> (tick: Tick)
        requires old(self).invariant(),
            old(self).phase is First || old(self).phase is Second || old(self).phase is Third,
            !mmu_core::shared_model::active(old(self).mmu@.phase),
        ensures final(self).invariant(), (final(self)@, tick) == spec::byte(old(self)@, value),
    {
        match self.phase {
            CpuPhase::First => {
                if value < 0x48 || value > 0x4f {
                    return self.stop(StepOutcome::Diagnostic(PagedDiagnostic::Unsupported));
                }
                if self.cpu.rip == u64::MAX {
                    return self.stop(StepOutcome::Diagnostic(PagedDiagnostic::FetchWrap));
                }
                let _accepted = self.mmu.begin_fetch_next(self.cpu.rip + 1, self.user);
                assert(_accepted);
                self.phase = CpuPhase::Second { rex: value };
                Tick::Pending
            },
            CpuPhase::Second { rex } => {
                if value != 0x01 && value != 0x11 && value != 0x8b && value != 0x89 {
                    return self.stop(StepOutcome::Diagnostic(PagedDiagnostic::Unsupported));
                }
                if self.cpu.rip == u64::MAX - 1 {
                    return self.stop(StepOutcome::Diagnostic(PagedDiagnostic::FetchWrap));
                }
                let _accepted = self.mmu.begin_fetch_next(self.cpu.rip + 2, self.user);
                assert(_accepted);
                self.phase = CpuPhase::Third { rex, opcode: value };
                Tick::Pending
            },
            CpuPhase::Third { rex, opcode } => {
                self.decoded(rex, opcode, value)
            },
            _ => { assert(false); Tick::Waiting },
        }
    }
}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchStop {
    Budget,
    Yield,
    Stopped(StepOutcome),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Batch {
    pub retired: u64,
    pub stop: BatchStop,
}

impl SharedMachine {
    /// Bounds logical RAM effects and retirement, not provider wall-clock latency.
    pub fn run<R: PhysicalRam>(
        &mut self,
        ram: &R,
        io_budget: u32,
        instruction_budget: u64,
    ) -> Result<Batch, RunError<R::Error>> {
        let mut retired = 0;
        let mut effects = 0;
        loop {
            if retired == instruction_budget {
                return Ok(Batch {
                    retired,
                    stop: BatchStop::Budget,
                });
            }
            match self.advance() {
                Tick::Boundary => return Err(RunError::Protocol(self.request())),
                Tick::Retired => retired += 1,
                Tick::Stopped(outcome) => {
                    return Ok(Batch {
                        retired,
                        stop: BatchStop::Stopped(outcome),
                    });
                }
                Tick::Pending => {}
                Tick::Waiting => {
                    if effects == io_budget {
                        return Ok(Batch {
                            retired,
                            stop: BatchStop::Yield,
                        });
                    }
                    let request = self.request();
                    let reply = memory::perform(ram, request)?;
                    if !self.respond(reply) {
                        return Err(RunError::Protocol(request));
                    }
                    effects += 1;
                }
            }
        }
    }
}
