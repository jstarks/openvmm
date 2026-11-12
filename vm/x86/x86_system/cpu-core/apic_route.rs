// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interface {XApic, X2Apic}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {ReservedVector, UnsupportedCommand}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedIpi {
    pub vector:u8,
    pub destination:u32,
    pub logical:bool,
    pub shorthand:u8,
    pub interface:Interface,
}

impl FixedIpi {
    pub fn decode(value:u64,interface:Interface)->(out:Result<Self,Error>) {
        let low=value as u32;
        // Only fixed edge-triggered messages are admitted in this first slice.
        if low & !0x000c_48ffu32 != 0 {return Err(Error::UnsupportedCommand);}
        let vector=low as u8;
        if vector<16 {return Err(Error::ReservedVector);}
        let high=(value >> 32) as u32;
        let destination=match interface {
            Interface::XApic=>{
                if high & 0x00ff_ffff != 0 {return Err(Error::UnsupportedCommand);}
                high >> 24
            },
            Interface::X2Apic=>high,
        };
        Ok(Self {vector,destination,logical:low & 0x800!=0,
            shorthand:((low >> 18) & 3) as u8,interface})
    }

    pub fn targets(self,sender:u32,target:u32,flat_logical_id:u8,enabled:bool)->(out:bool) {
        if !enabled {return false;}
        if self.shorthand==1 {return target==sender;}
        if self.shorthand==2 {return true;}
        if self.shorthand==3 {return target!=sender;}
        match self.interface {
            Interface::XApic=>{
                if target>255 {return false;}
                if self.destination==255 {return true;}
                if self.logical {self.destination & flat_logical_id as u32 != 0}
                else {self.destination==target}
            },
            Interface::X2Apic=>{
                if self.destination==u32::MAX {return true;}
                if self.logical {
                    let bit=target & 15;
                    assert(bit<32) by(bit_vector) requires bit==target & 15u32;
                    self.destination >> 16 == (target >> 4) & 0xffff
                        && self.destination & (1u32 << bit) != 0
                } else {self.destination==target}
            },
        }
    }
}

}
