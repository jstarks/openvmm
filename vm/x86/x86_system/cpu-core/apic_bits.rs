// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub struct Vectors {
    pub words: [u32; 8],
}

pub const EMPTY: Vectors = Vectors { words: [0,0,0,0,0,0,0,0] };

impl Vectors {
    pub open spec fn bit(self, vector:u8)->bool {
        self.words@[(vector / 32) as int] & (1u32 << (vector % 32)) != 0
    }

    pub open spec fn below(self, count:nat)->Option<u8>
        recommends count<=256,
        decreases count,
    {
        if count==0 {None}
        else if self.bit((count-1) as u8) {Some((count-1) as u8)}
        else {self.below((count-1) as nat)}
    }

    pub fn contains(self, vector:u8)->(out:bool)
        ensures out==self.bit(vector),
    {
        self.words[(vector / 32) as usize] & (1u32 << (vector % 32)) != 0
    }

    pub fn with(self, vector:u8, present:bool)->(out:Self)
        ensures
            out.words@ == self.words@.update((vector / 32) as int,
                if present {self.words@[(vector / 32) as int] | (1u32 << (vector % 32))}
                else {self.words@[(vector / 32) as int] & !(1u32 << (vector % 32))}),
    {
        let mut out=self;
        let bank=(vector / 32) as usize;
        let mask=1u32 << (vector % 32);
        out.words[bank]=if present {out.words[bank] | mask} else {out.words[bank] & !mask};
        out
    }

    pub fn highest(self)->(out:Option<u8>)
        ensures out==self.below(256),
    {
        let mut count=256usize;
        while count>0
            invariant count<=256, self.below(count as nat)==self.below(256),
            decreases count,
        {
            let vector=(count-1) as u8;
            if self.contains(vector) {return Some(vector);}
            count-=1;
        }
        None
    }
}

}
