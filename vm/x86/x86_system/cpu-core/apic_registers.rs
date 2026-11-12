// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{
    Eoi, Interrupts, Rejection,
    route::{FixedIpi, Interface},
    timer::{Error as TimerError, Timer},
};
use vstd::prelude::*;

verus! {

pub const BASE:u64=0xfee0_0000;
pub const VERSION:u32=0x0005_0010;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {UnsupportedAccess, UnsupportedValue, GeneralProtection, Timer(TimerError)}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {None, Eoi(Eoi), Ipi(FixedIpi)}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalApic {
    pub id:u32,
    pub base:u64,
    pub svr:u32,
    pub tpr:u8,
    pub ldr:u8,
    pub icr:u64,
    pub lvt:[u32;6],
    pub timer:Timer,
    pub interrupts:Interrupts,
}

impl LocalApic {
    pub open spec fn valid(self)->bool {self.timer.valid()}

    pub fn new(id:u32,bsp:bool,now:u64)->(out:Self)
        ensures out.valid(),
    {
        Self {id,base:BASE | 0x800 | if bsp {0x100} else {0},
            svr:0xff,tpr:0,ldr:0,icr:0,lvt:[0x10000,0x10000,0x10000,0x10000,0x10000,0x10000],
            timer:Timer::new(now),interrupts:super::EMPTY}
    }

    pub fn enabled(self)->bool {self.base & 0x800!=0 && self.svr & 0x100!=0}
    pub fn x2apic(self)->bool {self.base & 0x400!=0}

    pub fn write_base(self,value:u64)->Result<Self,Error> {
        if value & !0x0000_ffff_ffff_fd00u64 != 0
            || value & 0xc00==0x400
            || (self.base & 0xc00==0xc00 && value & 0xc00==0x800)
            || (self.base & 0xc00==0 && value & 0xc00==0xc00)
        {return Err(Error::GeneralProtection);}
        // This profile has a fixed APIC window; relocation is not a no-op.
        if value & !0xd00u64 != BASE || value & 0x100 != self.base & 0x100 {
            return Err(Error::UnsupportedValue);
        }
        let entering_x2=value & 0xc00==0xc00 && self.base & 0xc00!=0xc00;
        Ok(Self {base:value,ldr:if entering_x2 {0} else {self.ldr},
            icr:if entering_x2 {self.icr & 0xffff_ffff} else {self.icr},..self})
    }

    pub fn advance(self,now:u64)->(out:Result<Self,Error>)
        requires self.valid(),
        ensures out is Ok ==> out->Ok_0.valid(),
    {
        let advance=match self.timer.advance(now) {Ok(value)=>value,Err(e)=>return Err(Error::Timer(e))};
        let mut next=Self {timer:advance.timer,..self};
        if advance.expirations!=0 && self.enabled() && self.lvt[0] & 0x10000==0 {
            match self.interrupts.receive(self.lvt[0] as u8,false,true) {
                Ok(interrupts)=>next.interrupts=interrupts,
                // Multiple timer expirations coalesce in the occupied IRR slot.
                Err(Rejection::Retry)=>{},
                Err(_)=>return Err(Error::UnsupportedValue),
            }
        }
        Ok(next)
    }

    pub fn receive(self,vector:u8,level:bool)->Result<Self,Rejection> {
        match self.interrupts.receive(vector,level,self.enabled()) {
            Ok(interrupts)=>Ok(Self {interrupts,..self}),Err(error)=>Err(error),
        }
    }

    pub fn candidate(self)->Option<u8> {self.interrupts.candidate(self.tpr,self.enabled())}

    pub fn accept(self,vector:u8,ready:bool)->Result<Self,Rejection> {
        match self.interrupts.accept(vector,self.tpr,self.enabled(),ready) {
            Ok(interrupts)=>Ok(Self {interrupts,..self}),Err(error)=>Err(error),
        }
    }

    pub fn write_cr8(self,value:u64)->Result<Self,Error> {
        if value>15 {Err(Error::GeneralProtection)}
        else {Ok(Self {tpr:(value as u8)<<4,..self})}
    }

    fn register_read(self,offset:u16)->(out:Result<u32,Error>)
        requires self.valid(),
    {
        if offset>=0x100 && offset<=0x270 && offset & 15==0 {
            let bank=(((offset-0x100)/16)%8) as usize;
            return Ok(if offset<0x180 {self.interrupts.isr.words[bank]}
                else if offset<0x200 {self.interrupts.tmr.words[bank]}
                else {self.interrupts.irr.words[bank]});
        }
        if offset>=0x320 && offset<=0x370 && offset & 15==0 {
            return Ok(self.lvt[((offset-0x320)/16) as usize]);
        }
        match offset {
            0x20=>Ok(if self.x2apic() {self.id} else {self.id<<24}),
            0x30=>Ok(VERSION),
            0x80=>Ok(self.tpr as u32),
            0x90=>{
                let ppr=self.interrupts.priority(self.tpr);
                let pending=match self.interrupts.irr.highest() {Some(v)=>v,None=>0};
                Ok(if pending / 16 > ppr / 16 {(pending & 0xf0) as u32} else {ppr as u32})
            },
            0xa0=>Ok(self.interrupts.priority(self.tpr) as u32),
            0xd0=>{
                let id=self.id;
                let bit=id & 15;
                assert(bit<32) by(bit_vector) requires bit==id & 15u32;
                Ok(if self.x2apic() {((id>>4)<<16) | (1u32<<bit)}
                    else {(self.ldr as u32)<<24})
            },
            0xe0=>Ok(u32::MAX),
            0xf0=>Ok(self.svr),
            0x280=>Ok(0),
            0x300=>Ok(self.icr as u32),
            0x310=>Ok((self.icr>>32) as u32),
            0x380=>Ok(self.timer.initial),
            0x390=>Ok(self.timer.current),
            0x3e0=>Ok(match self.timer.divisor {
                1=>11,2=>0,4=>1,8=>2,16=>3,32=>8,64=>9,128=>10,
                _=>return Err(Error::UnsupportedValue),
            }),
            _=>Err(Error::UnsupportedAccess),
        }
    }

    fn register_write(self,offset:u16,value:u32)->(out:Result<(Self,Effect),Error>)
        requires self.valid(),
        ensures out is Ok ==> out->Ok_0.0.valid(),
    {
        let mut next=self;
        if offset>=0x320 && offset<=0x370 && offset & 15==0 {
            let index=((offset-0x320)/16) as usize;
            let allowed=if index==0 {0x300ffu32} else {0x1a7ffu32};
            if value & !allowed!=0 {return Err(Error::UnsupportedValue);}
            if index==0 {
                let periodic=value & 0x20000!=0;
                if self.timer.current!=0 && periodic!=self.timer.periodic {
                    return Err(Error::Timer(TimerError::RunningReconfiguration));
                }
                next.timer.periodic=periodic;
            }
            next.lvt[index]=value | if self.svr & 0x100==0 {0x10000} else {0};
            return Ok((next,Effect::None));
        }
        match offset {
            0x80=>next.tpr=value as u8,
            0xb0=>{
                let (interrupts,eoi)=self.interrupts.eoi();
                return Ok((Self {interrupts,..self},Effect::Eoi(eoi)));
            },
            0xd0=>next.ldr=(value>>24) as u8,
            0xe0=>{
                if value!=u32::MAX {return Err(Error::UnsupportedValue);}
            },
            0xf0=>{
                if value & !0x3ffu32!=0 {return Err(Error::UnsupportedValue);}
                next.svr=value;
                if value & 0x100==0 {
                    let mut index=0usize;
                    while index<6
                        invariant index<=6,next.timer.valid(),
                        decreases 6-index,
                    {
                        next.lvt[index]=next.lvt[index] | 0x10000;
                        index+=1;
                    }
                }
            },
            0x280=>{
                // No error-generating sources are admitted in this bounded slice.
            },
            0x300=>{
                let raw=(self.icr & 0xffff_ffff_0000_0000) | value as u64;
                let command=match FixedIpi::decode(raw,Interface::XApic) {
                    Ok(command)=>command,Err(_)=>return Err(Error::UnsupportedValue),
                };
                return Ok((Self {icr:raw,..self},Effect::Ipi(command)));
            },
            0x310=>next.icr=((value as u64)<<32) | (self.icr & 0xffff_ffff),
            0x380=>next.timer=match self.timer.start(value,self.timer.last) {
                Ok(timer)=>timer,Err(e)=>return Err(Error::Timer(e)),
            },
            0x3e0=>next.timer=match self.timer.configure(value,self.timer.periodic) {
                Ok(timer)=>timer,Err(e)=>return Err(Error::Timer(e)),
            },
            _=>return Err(Error::UnsupportedAccess),
        }
        Ok((next,Effect::None))
    }

    pub fn mmio_read(self,offset:u16,width:u8,now:u64)->(out:Result<(Self,u32),Error>)
        requires self.valid(),
        ensures out is Ok ==> out->Ok_0.0.valid(),
    {
        if self.base & 0x800==0 || self.x2apic() || width!=4 || offset & 15!=0 {
            return Err(Error::UnsupportedAccess);
        }
        let next=match self.advance(now) {Ok(next)=>next,Err(e)=>return Err(e)};
        match next.register_read(offset) {Ok(value)=>Ok((next,value)),Err(e)=>Err(e)}
    }

    pub fn mmio_write(self,offset:u16,width:u8,value:u32,now:u64)->(out:Result<(Self,Effect),Error>)
        requires self.valid(),
        ensures out is Ok ==> out->Ok_0.0.valid(),
    {
        if self.base & 0x800==0 || self.x2apic() || width!=4 || offset & 15!=0 {
            return Err(Error::UnsupportedAccess);
        }
        let next=match self.advance(now) {Ok(next)=>next,Err(e)=>return Err(e)};
        next.register_write(offset,value)
    }

    pub fn msr_read(self,number:u32,now:u64)->(out:Result<(Self,u64),Error>)
        requires self.valid(),
        ensures out is Ok ==> out->Ok_0.0.valid(),
    {
        if !self.x2apic() || number<0x800 || number>0x83f || number==0x80e || number==0x831 || number==0x83f {
            return Err(Error::GeneralProtection);
        }
        let next=match self.advance(now) {Ok(next)=>next,Err(e)=>return Err(e)};
        if number==0x830 {return Ok((next,next.icr));}
        match next.register_read(((number-0x800)<<4) as u16) {
            Ok(value)=>Ok((next,value as u64)),Err(_)=>Err(Error::GeneralProtection),
        }
    }

    pub fn msr_write(self,number:u32,value:u64,now:u64)->(out:Result<(Self,Effect),Error>)
        requires self.valid(),
        ensures out is Ok ==> out->Ok_0.0.valid(),
    {
        if !self.x2apic() || number<0x800 || number>0x83f {return Err(Error::GeneralProtection);}
        let next=match self.advance(now) {Ok(next)=>next,Err(e)=>return Err(e)};
        if number==0x830 || number==0x83f {
            if number==0x830 && (value as u32) & !0x000c_cfffu32!=0 {
                return Err(Error::GeneralProtection);
            }
            if number==0x83f && value>255 {return Err(Error::GeneralProtection);}
            let raw=if number==0x83f {value | 0x40000} else {value};
            let command=match FixedIpi::decode(raw,Interface::X2Apic) {
                Ok(command)=>command,Err(_)=>return Err(Error::UnsupportedValue),
            };
            return Ok((Self {icr:if number==0x830 {value} else {next.icr},..next},Effect::Ipi(command)));
        }
        if value>>32!=0 || number==0x831 || number==0x80d || number==0x80e
            || (number==0x80b && value!=0) || (number==0x828 && value!=0)
        {return Err(Error::GeneralProtection);}
        let writable=match number {
            0x808=>0xffu64,0x80f=>0x3ff,
            0x832=>0x300ff,0x833 | 0x834 | 0x835 | 0x836 | 0x837=>0x1a7ff,
            0x83e=>0xb,
            _=>u64::MAX,
        };
        if value & !writable!=0 {return Err(Error::GeneralProtection);}
        match next.register_write(((number-0x800)<<4) as u16,value as u32) {
            Ok(out)=>Ok(out),Err(Error::UnsupportedAccess)=>Err(Error::GeneralProtection),Err(e)=>Err(e),
        }
    }
}

}
