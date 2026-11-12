// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub struct Timer {
    pub initial:u32,
    pub current:u32,
    pub divisor:u8,
    pub phase:u8,
    pub last:u64,
    pub periodic:bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {BackwardsTime, InvalidDivisor, RunningReconfiguration}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Advance {
    pub timer:Timer,
    pub expirations:u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deadline {Stopped, At(u64), BeyondClock}

impl Timer {
    pub open spec fn valid(self)->bool {
        1<=self.divisor<=128 && self.phase<self.divisor
            && self.current<=self.initial && (self.current>0 ==> self.initial>0)
    }

    pub fn new(now:u64)->(out:Self)
        ensures out.valid(),out.initial==0,out.current==0,out.last==now,out.divisor==2,
    {
        Self {initial:0,current:0,divisor:2,phase:0,last:now,periodic:false}
    }

    pub fn configure(self,dcr:u32,periodic:bool)->(out:Result<Self,Error>)
        requires self.valid(),
        ensures out is Ok ==> out->Ok_0.valid(),
    {
        if dcr & !0xbu32 != 0 {return Err(Error::InvalidDivisor);}
        if self.current!=0 {return Err(Error::RunningReconfiguration);}
        let packed=(dcr & 3) | ((dcr >> 1) & 4);
        assert(packed<=7) by(bit_vector)
            requires packed==(dcr & 3u32) | ((dcr >> 1) & 4u32);
        let shift=if packed==7 {0} else {packed+1};
        let divisor=1u8 << shift;
        assert(1<=divisor<=128) by(bit_vector) requires shift<8u32,divisor==1u8 << shift;
        Ok(Self {divisor,phase:0,periodic,..self})
    }

    pub fn start(self,initial:u32,now:u64)->(out:Result<Self,Error>)
        requires self.valid(),
        ensures out is Ok ==> out->Ok_0.valid(),
    {
        if now<self.last {return Err(Error::BackwardsTime);}
        Ok(Self {initial,current:initial,phase:0,last:now,..self})
    }

    // Inputs are ticks of one declared base clock, not host scheduling time.
    // Masking controls interrupt generation outside this counter transition.
    pub fn advance(self,now:u64)->(out:Result<Advance,Error>)
        requires self.valid(),
        ensures out==model::advance(self,now),
            out is Ok ==> out->Ok_0.timer.valid(),
            out is Ok ==> out->Ok_0.expirations as nat==model::expirations(self,now),
    {
        if now<self.last {return Err(Error::BackwardsTime);}
        if self.current==0 {
            return Ok(Advance {timer:Self {last:now,phase:0,..self},expirations:0});
        }
        let elapsed=(now as u128 - self.last as u128) + self.phase as u128;
        let ticks=elapsed / self.divisor as u128;
        proof {
            let d=self.divisor as int;
            let e=elapsed as int;
            let max=u64::MAX as int;
            assert(e<(max+1)*d) by(nonlinear_arith)
                requires d>=1, (self.phase as int)<d, (now as int)<=max,
                    self.last<=now, e==now as int-self.last as int+self.phase as int;
            assert((ticks as int)<=max) by(nonlinear_arith)
                requires d>=1, 0<=e<(max+1)*d, ticks as int==e/d;
        }
        let phase=(elapsed % self.divisor as u128) as u8;
        if ticks<self.current as u128 {
            return Ok(Advance {timer:Self {current:self.current-ticks as u32,phase,last:now,..self},expirations:0});
        }
        if !self.periodic {
            return Ok(Advance {timer:Self {current:0,phase:0,last:now,..self},expirations:1});
        }
        let tail=ticks-self.current as u128;
        let expirations=1+tail / self.initial as u128;
        assert((expirations as int)<=(ticks as int)) by(nonlinear_arith)
            requires tail as int==ticks as int-self.current as int,
                self.current>=1,self.initial>=1,tail>=0,
                expirations as int==1+(tail as int)/(self.initial as int);
        let current=self.initial-(tail % self.initial as u128) as u32;
        Ok(Advance {timer:Self {current,phase,last:now,..self},expirations:expirations as u64})
    }

    pub fn deadline(self)->(out:Deadline)
        requires self.valid(),
    {
        if self.current==0 {return Deadline::Stopped;}
        let count=self.current as u64;
        let divisor=self.divisor as u64;
        let phase=self.phase as u64;
        assert(count*divisor<=549755813760) by(nonlinear_arith)
            requires count<=4294967295,divisor<=128;
        assert(count*divisor>phase) by(nonlinear_arith)
            requires count>=1,divisor>=1,phase<divisor;
        let remaining=count*divisor-phase;
        if remaining>u64::MAX-self.last {Deadline::BeyondClock}
        else {Deadline::At(self.last+remaining)}
    }
}

pub mod model {
    #[cfg(verus_keep_ghost)]
    use super::*;
    pub open spec fn expirations(s:Timer,now:u64)->nat {
        let ticks=(now as int-s.last as int+s.phase as int) / s.divisor as int;
        if now<s.last || s.current==0 || ticks<s.current as int {0}
        else if !s.periodic {1}
        else {(1+(ticks-s.current as int) / s.initial as int) as nat}
    }

    pub open spec fn advance(s:Timer,now:u64)->Result<Advance,Error> {
        if now<s.last {Err(Error::BackwardsTime)}
        else if s.current==0 {Ok(Advance {timer:Timer {last:now,phase:0,..s},expirations:0})}
        else {
            let elapsed=now as int-s.last as int+s.phase as int;
            let ticks=elapsed / s.divisor as int;
            let phase=(elapsed % s.divisor as int) as u8;
            if ticks<s.current as int {
                Ok(Advance {timer:Timer {current:(s.current as int-ticks) as u32,phase,last:now,..s},expirations:0})
            } else if !s.periodic {
                Ok(Advance {timer:Timer {current:0,phase:0,last:now,..s},expirations:1})
            } else {
                let tail=ticks-s.current as int;
                Ok(Advance {timer:Timer {current:(s.initial as int-tail % s.initial as int) as u32,phase,last:now,..s},
                    expirations:(1+tail / s.initial as int) as u64})
            }
        }
    }
}

}
