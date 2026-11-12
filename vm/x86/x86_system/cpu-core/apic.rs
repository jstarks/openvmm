// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use vstd::prelude::*;

#[path = "apic_bits.rs"]
pub mod bits;
#[path = "apic_registers.rs"]
pub mod registers;
#[path = "apic_route.rs"]
pub mod route;
#[path = "apic_timer.rs"]
pub mod timer;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub struct Interrupts {
    pub irr:bits::Vectors,
    pub isr:bits::Vectors,
    pub tmr:bits::Vectors,
}

pub const EMPTY:Interrupts=Interrupts {irr:bits::EMPTY,isr:bits::EMPTY,tmr:bits::EMPTY};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {ReservedVector, Disabled, Retry, NotReady, Stale}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Eoi {
    pub vector:Option<u8>,
    pub broadcast:bool,
}

impl Interrupts {
    pub fn receive(self,vector:u8,level:bool,enabled:bool)->(out:Result<Self,Rejection>)
        ensures model::receive(self,vector,level,enabled,out),
    {
        if vector<16 {return Err(Rejection::ReservedVector);}
        if !enabled {return Err(Rejection::Disabled);}
        if self.irr.contains(vector) {return Err(Rejection::Retry);}
        Ok(Self {irr:self.irr.with(vector,true),tmr:self.tmr.with(vector,level),..self})
    }

    pub fn priority(self,tpr:u8)->(out:u8)
        ensures out==model::priority(self,tpr),
    {
        let isr=match self.isr.highest() {Some(vector)=>vector, None=>0};
        if isr / 16 > tpr / 16 {isr & 0xf0} else {tpr}
    }

    pub fn candidate(self,tpr:u8,enabled:bool)->(out:Option<u8>)
        ensures out==model::candidate(self,tpr,enabled),
    {
        if !enabled {return None;}
        let vector=match self.irr.highest() {Some(vector)=>vector, None=>return None};
        if vector / 16 > self.priority(tpr) / 16 {Some(vector)} else {None}
    }

    // The CPU owner calls this only when interrupt recognition accepts the offer.
    // Merely polling a candidate, or waking a halted VP, does not move IRR to ISR.
    pub fn accept(self,vector:u8,tpr:u8,enabled:bool,ready:bool)->(out:Result<Self,Rejection>)
        ensures model::accept(self,vector,tpr,enabled,ready,out),
    {
        if !ready {return Err(Rejection::NotReady);}
        if self.candidate(tpr,enabled)!=Some(vector) {return Err(Rejection::Stale);}
        Ok(Self {irr:self.irr.with(vector,false),isr:self.isr.with(vector,true),..self})
    }

    pub fn eoi(self)->(out:(Self,Eoi))
        ensures model::eoi(self,out),
    {
        match self.isr.highest() {
            None=>(self,Eoi {vector:None,broadcast:false}),
            Some(vector)=>(Self {isr:self.isr.with(vector,false),..self},
                Eoi {vector:Some(vector),broadcast:self.tmr.contains(vector)}),
        }
    }
}

pub mod model {
    #[cfg(verus_keep_ghost)]
    use super::*;

    pub open spec fn receive(s:Interrupts,v:u8,level:bool,enabled:bool,out:Result<Interrupts,Rejection>)->bool {
        if v<16 {out==Err(Rejection::ReservedVector)}
        else if !enabled {out==Err(Rejection::Disabled)}
        else if s.irr.bit(v) {out==Err(Rejection::Retry)}
        else {match out {Err(_)=>false,Ok(next)=>
            updated(s.irr,next.irr,v,true) && updated(s.tmr,next.tmr,v,level) && next.isr==s.isr}}
    }

    pub open spec fn updated(s:bits::Vectors,next:bits::Vectors,v:u8,present:bool)->bool {
        next.words@==s.words@.update((v / 32) as int,
            if present {s.words[(v / 32) as int] | (1u32 << (v % 32))}
            else {s.words[(v / 32) as int] & !(1u32 << (v % 32))})
    }

    pub open spec fn priority(s:Interrupts,tpr:u8)->u8 {
        let isr=match s.isr.below(256) {Some(v)=>v,None=>0};
        if isr / 16 > tpr / 16 {isr & 0xf0} else {tpr}
    }

    pub open spec fn candidate(s:Interrupts,tpr:u8,enabled:bool)->Option<u8> {
        if !enabled {None}
        else {match s.irr.below(256) {
            Some(v)=>if v / 16 > priority(s,tpr) / 16 {Some(v)} else {None},
            None=>None,
        }}
    }

    pub open spec fn accept(s:Interrupts,v:u8,tpr:u8,enabled:bool,ready:bool,out:Result<Interrupts,Rejection>)->bool {
        if !ready {out==Err(Rejection::NotReady)}
        else if candidate(s,tpr,enabled)!=Some(v) {out==Err(Rejection::Stale)}
        else {match out {Err(_)=>false,Ok(next)=>
            updated(s.irr,next.irr,v,false) && updated(s.isr,next.isr,v,true) && next.tmr==s.tmr}}
    }

    pub open spec fn eoi(s:Interrupts,out:(Interrupts,Eoi))->bool {
        match s.isr.below(256) {
            None=>out==(s,Eoi {vector:None,broadcast:false}),
            Some(v)=>updated(s.isr,out.0.isr,v,false) && out.0.irr==s.irr && out.0.tmr==s.tmr
                && out.1==(Eoi {vector:Some(v),broadcast:s.tmr.bit(v)}),
        }
    }
}

}
