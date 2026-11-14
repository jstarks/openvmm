// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub struct SegmentState {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub attributes: u16,
}

pub const NULL_SEGMENT: SegmentState = SegmentState {
    base: 0, limit: 0, selector: 0, attributes: 0,
};
pub const CODE_SEGMENT: SegmentState = SegmentState {
    base: 0, limit: u32::MAX, selector: 8, attributes: 0xa09b,
};
pub const DATA_SEGMENT: SegmentState = SegmentState {
    base: 0, limit: u32::MAX, selector: 16, attributes: 0xc093,
};
pub const DEFAULT_PAT: u64 = 0x0007_0406_0007_0406;
pub const FIXED_WB: u64 = 0x0606_0606_0606_0606;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub struct EntryMsrs {
    pub star:u64,pub lstar:u64,pub cstar:u64,pub sfmask:u64,
    pub sysenter_cs:u64,pub sysenter_esp:u64,pub sysenter_eip:u64,pub kernel_gs_base:u64,
}
pub const EMPTY_ENTRY_MSRS:EntryMsrs=EntryMsrs {
    star:0,lstar:0,cstar:0,sfmask:0,sysenter_cs:0,sysenter_esp:0,sysenter_eip:0,kernel_gs_base:0,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum X87Control { Initialize, ClearExceptions, EmptyMmx, Wait }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum XmmLogic {And,AndNot,Or,Xor}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum PackedOperation {Equal,GreaterSigned,Add,Subtract}

fn packed_lane(left:u64,right:u64,width:super::operand::Width,operation:PackedOperation)->(out:u64)
    ensures out==model::packed_lane(left,right,width,operation),
{
    let mask=width.mask();
    let a=left&mask;
    let b=right&mask;
    match operation {
        PackedOperation::Equal=>if a==b {mask} else {0},
        PackedOperation::GreaterSigned=>{
            let greater=match width {
                super::operand::Width::Byte=>(a as i8)>(b as i8),
                super::operand::Width::Word=>(a as i16)>(b as i16),
                super::operand::Width::Dword=>(a as i32)>(b as i32),
                super::operand::Width::Qword=>(a as i64)>(b as i64),
            };
            if greater {mask} else {0}
        },
        PackedOperation::Add=>a.wrapping_add(b)&mask,
        PackedOperation::Subtract=>a.wrapping_sub(b)&mask,
    }
}

impl XmmLogic {
    pub fn apply(self,left:u64,right:u64)->(out:u64)
        ensures out==model::xmm_bits(self,left,right),
    {
        match self {Self::And=>left&right,Self::AndNot=>!left&right,
            Self::Or=>left|right,Self::Xor=>left^right}
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub struct LegacyFpState {
    pub control:u16,pub status:u16,pub tags:u16,pub opcode:u16,
    pub ip:u64,pub dp:u64,
    pub significands:[u64;8],pub exponents:[u16;8],
    pub mxcsr:u32,pub xmm:[[u64;2];16],
}
pub const EMPTY_LEGACY_FP:LegacyFpState=LegacyFpState {
    control:0x37f,status:0,tags:0xffff,opcode:0,ip:0,dp:0,
    significands:[0,0,0,0,0,0,0,0],exponents:[0,0,0,0,0,0,0,0],mxcsr:0x1f80,
    xmm:[[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],
        [0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0]],
};
fn packed_word(left:u64,right:u64,width:super::operand::Width,operation:PackedOperation)->(out:u64)
    ensures out==model::packed_prefix(left,right,width,(64u32/super::operand::model::bits(width)) as nat,operation),
{
    let bits=width.bits();
    let count=64/bits;
    let mut index=0u32;
    let mut value=0u64;
    while index<count
        invariant bits==super::operand::model::bits(width),bits>0,
            count==64u32/bits,count*bits==64,
            index<=count,value==model::packed_prefix(left,right,width,index as nat,operation),
        decreases count-index,
    {
        assert(index*bits<64) by(nonlinear_arith)
            requires index<count,bits>0,count*bits==64;
        let shift=index*bits;
        value|=packed_lane(left>>shift,right>>shift,width,operation)<<shift;
        proof {
            reveal_with_fuel(model::packed_prefix,2);
            assert(value==model::packed_prefix(left,right,width,(index+1) as nat,operation));
        }
        index+=1;
    }
    value
}

fn byte_mask(word:u64)->(out:u64)
    ensures out==model::mask_prefix(word,8),
{
    let mut index=0u32;
    let mut value=0u64;
    while index<8
        invariant index<=8,value==model::mask_prefix(word,index as nat),
        decreases 8-index,
    {
        value|=((word>>(index*8+7))&1)<<index;
        index+=1;
    }
    value
}

impl LegacyFpState {
    pub fn xmm_byte_shift(self,index:u8,count:u8,left:bool)->(out:Self)
        requires index<16,
        ensures out==model::xmm_byte_shift(self,index,count,left),
    {
        let pair=self.xmm[index as usize];
        let value=(pair[0] as u128)|((pair[1] as u128)<<64);
        let shift=(count as u32)*8;
        let result=if count>=16 {0u128} else if left {value<<shift} else {value>>shift};
        self.xmm_pair(index,result as u64,(result>>64) as u64)
    }

    pub fn xmm_unpack_narrow(self,dst:u8,source:u8,word:bool,high:bool)->(out:Self)
        requires dst<16,source<16,
        ensures out==model::xmm_unpack_narrow(self,dst,source,word,high),
    {
        let at=if high {1usize} else {0usize};
        let a=self.xmm[dst as usize][at];
        let b=self.xmm[source as usize][at];
        self.xmm_pair(dst,interleave_low(a,b,word),interleave_low(a>>32,b>>32,word))
    }

    pub fn xmm_shuffle(self,dst:u8,source:u8,control:u8)->(out:Self)
        requires dst<16,source<16,
        ensures out==model::xmm_shuffle(self,dst,source,control),
    {
        let pair=self.xmm[source as usize];
        self.xmm_pair(dst,select_dword(pair,control)|(select_dword(pair,control>>2)<<32),
            select_dword(pair,control>>4)|(select_dword(pair,control>>6)<<32))
    }

    pub fn xmm_equal(self,dst:u8,low:u64,high:u64,width:super::operand::Width)->(out:Self)
        requires dst<16,
        ensures out==model::xmm_equal(self,dst,low,high,width),
    {
        self.xmm_packed(dst,low,high,width,PackedOperation::Equal)
    }

    pub fn xmm_packed(self,dst:u8,low:u64,high:u64,width:super::operand::Width,operation:PackedOperation)->(out:Self)
        requires dst<16,
        ensures out==model::xmm_packed(self,dst,low,high,width,operation),
    {
        let pair=self.xmm[dst as usize];
        self.xmm_pair(dst,packed_word(pair[0],low,width,operation),packed_word(pair[1],high,width,operation))
    }

    pub fn xmm_mask(self,index:u8)->(out:u64)
        requires index<16,
        ensures out==model::xmm_mask(self,index),
    {
        let pair=self.xmm[index as usize];
        byte_mask(pair[0])|(byte_mask(pair[1])<<8)
    }

    pub fn xmm_logic(self,dst:u8,source:u8,operation:XmmLogic)->(out:Self)
        requires dst<16,source<16,
        ensures out==model::xmm_logic(self,dst,source,operation),
    {
        let a=self.xmm[dst as usize];
        let b=self.xmm[source as usize];
        self.xmm_pair(dst,operation.apply(a[0],b[0]),operation.apply(a[1],b[1]))
    }

    pub fn xmm_pair(self,dst:u8,low:u64,high:u64)->(out:Self)
        requires dst<16,
        ensures out==model::xmm_pair(self,dst,low,high),
    {
        let pair=[low,high];
        let mut out=self;
        out.xmm[dst as usize]=pair;
        proof {
            assert(out.xmm@ =~= model::set16(self.xmm,dst as int,pair)@);
            assert(out.xmm==model::set16(self.xmm,dst as int,pair));
        }
        out
    }

    pub fn xmm_scalar(self,dst:u8,value:u64,wide:bool)->(out:Self)
        requires dst<16,
        ensures out==model::xmm_scalar(self,dst,value,wide),
    {
        let value=if wide {value} else {value&0xffff_ffff};
        let pair=[value,0u64];
        let mut out=self;
        out.xmm[dst as usize]=pair;
        proof {
            assert(out.xmm@ =~= model::set16(self.xmm,dst as int,pair)@);
            assert(out.xmm==model::set16(self.xmm,dst as int,pair));
        }
        out
    }

    pub fn xmm_unpack(self,dst:u8,source:u8,wide:bool,high:bool)->(out:Self)
        requires dst<16,source<16,
        ensures out==model::xmm_unpack(self,dst,source,wide,high),
    {
        let at=if high {1usize} else {0usize};
        let a=self.xmm[dst as usize][at];
        let b=self.xmm[source as usize][at];
        let pair=if wide {[a,b]} else {
            [(a&0xffff_ffff)|((b&0xffff_ffff)<<32),(a>>32)|((b>>32)<<32)]
        };
        let mut out=self;
        out.xmm[dst as usize]=pair;
        proof {
            assert(out.xmm@ =~= model::set16(self.xmm,dst as int,pair)@);
            assert(out.xmm==model::set16(self.xmm,dst as int,pair));
        }
        out
    }

    pub fn integer_ready(self)->(out:bool)
        ensures out==model::integer_ready(self),
    {
        let status=self.status;
        let old_top=(status>>11)&7u16;
        assert(old_top<=7) by(bit_vector) requires old_top==(status>>11)&7u16;
        let top=(old_top+7)%8;
        ((self.tags>>(top*2))&3)==3 && ((self.status&!self.control)&0x3f)==0
    }

    pub fn push_integer(self,value:u64,width:super::operand::Width,ip:u64,dp:u64,opcode:u16)->(out:Self)
        ensures out==model::push_integer(self,value,width,ip,dp,opcode),
    {
        let raw=value&width.mask();
        let negative=raw&(1u64<<(width.bits()-1))!=0;
        let magnitude=if negative {0u64.wrapping_sub(raw)&width.mask()} else {raw};
        let sign=if negative {0x8000u16} else {0u16};
        let (significand,exponent)=match super::scalar::scan(magnitude,super::operand::Width::Qword,true) {
            Some(index)=>(magnitude<<(63-index),((0x3fffu64+index) as u16)|sign),
            None=>(0u64,0u16),
        };
        let status=self.status;
        let old_top=(status>>11)&7u16;
        assert(old_top<=7) by(bit_vector) requires old_top==(status>>11)&7u16;
        let top=(old_top+7)%8;
        let mut out=self;
        out.status=(self.status&0xc5ffu16)|(top<<11);
        out.tags=(self.tags&!(3u16<<(top*2)))|((if magnitude==0 {1u16} else {0u16})<<(top*2));
        out.ip=ip;out.dp=dp;out.opcode=opcode;
        out.significands[top as usize]=significand;
        out.exponents[top as usize]=exponent;
        proof {
            assert(out.significands@ =~= model::set8(self.significands,top as int,significand)@);
            assert(out.exponents@ =~= model::set8(self.exponents,top as int,exponent)@);
            assert(out.significands == model::set8(self.significands,top as int,significand));
            assert(out.exponents == model::set8(self.exponents,top as int,exponent));
        }
        out
    }

    pub fn restore_word(self,index:u8,value:u64,wide:bool)->(out:Self)
        requires index<52,
        ensures out==model::restore_word(self,index as int,value,wide),
    {
        let mut out=self;
        if index==0 {
            out.control=(value&0xffff) as u16;
            out.status=((value>>16)&0xffff) as u16;
            out.opcode=((value>>48)&0x7ff) as u16;
            let byte=((value>>32)&0xff) as u16;
            let pairs=(byte|(byte<<4))&0x0f0fu16;
            let quads=(pairs|(pairs<<2))&0x3333u16;
            let bits=(quads|(quads<<1))&0x5555u16;
            out.tags=!(bits|(bits<<1));
        } else if index==1 {
            out.ip=if wide {value} else {value&0xffff_ffff};
        } else if index==2 {
            out.dp=if wide {value} else {value&0xffff_ffff};
        } else if index==3 {
            out.mxcsr=(value&0xffff_ffff) as u32;
        } else if index<20 {
            let status=self.status;
            let top=(status>>11)&7u16;
            assert(top<=7) by(bit_vector) requires top==(status>>11)&7u16;
            let physical=(((index-4)/2+top as u8)%8) as usize;
            if index%2==0 {
                out.significands[physical]=value;
                proof {
                    assert(out.significands@ =~= model::set8(self.significands,physical as int,value)@);
                    assert(out.significands == model::set8(self.significands,physical as int,value));
                }
            } else {
                let exponent=(value&0xffff) as u16;
                out.exponents[physical]=exponent;
                if (self.tags>>(physical*2))&3!=3 {
                    let tag=if exponent&0x7fff==0 && self.significands[physical]==0 {1u16}
                        else if exponent&0x7fff==0 || exponent&0x7fff==0x7fff
                            || self.significands[physical]&0x8000_0000_0000_0000==0 {2u16}
                        else {0u16};
                    out.tags=(self.tags&!(3u16<<(physical*2)))|(tag<<(physical*2));
                }
                proof {
                    assert(out.exponents@ =~= model::set8(self.exponents,physical as int,exponent)@);
                    assert(out.exponents == model::set8(self.exponents,physical as int,exponent));
                }
            }
        } else {
            let register=((index-20)/2) as usize;
            let half=((index-20)%2) as usize;
            let mut xmm=self.xmm[register];
            xmm[half]=value;
            out.xmm[register]=xmm;
            proof {
                assert(xmm@ =~= model::set2(self.xmm@[register as int],half as int,value)@);
                assert(xmm == model::set2(self.xmm@[register as int],half as int,value));
                assert(out.xmm@ =~= model::set16(self.xmm,register as int,xmm)@);
                assert(out.xmm == model::set16(self.xmm,register as int,xmm));
            }
        }
        out
    }

    pub fn finish_restore(self,previous:Self)->(out:Self)
        ensures out==model::finish_restore(self,previous),
    {
        let pending=((self.status&!self.control)&0x3fu16)!=0;
        Self {
            status:(self.status&0x7f7fu16)|(if pending {0x8080u16} else {0u16}),
            ip:if pending {self.ip} else {previous.ip},
            dp:if pending {self.dp} else {previous.dp},
            opcode:if pending {self.opcode} else {previous.opcode},
            ..self
        }
    }

    pub fn control_x87(self,operation:X87Control)->(out:Self)
        ensures out==match operation {
            X87Control::Initialize=>LegacyFpState {control:0x37f,status:0,tags:0xffff,opcode:0,ip:0,dp:0,..self},
            X87Control::ClearExceptions=>LegacyFpState {status:self.status&0x7f00u16,..self},
            X87Control::EmptyMmx=>LegacyFpState {status:self.status&0xc7ffu16,tags:0xffff,..self},
            X87Control::Wait=>self,
        },
    {
        match operation {
            X87Control::Initialize=>self.initialize_x87(),
            X87Control::ClearExceptions=>Self {status:self.status&0x7f00u16,..self},
            X87Control::EmptyMmx=>Self {status:self.status&0xc7ffu16,tags:0xffff,..self},
            X87Control::Wait=>self,
        }
    }
    pub fn initialize_x87(self)->(out:Self)
        ensures out==(LegacyFpState {control:0x37f,status:0,tags:0xffff,opcode:0,ip:0,dp:0,..self}),
    {
        Self {control:0x37f,status:0,tags:0xffff,opcode:0,ip:0,dp:0,..self}
    }
    pub fn save_word(self,index:u8,wide:bool)->(out:u64)
        requires index<52,
        ensures out==model::fp_word(self,index as int,wide),
    {
        if index==0 {
            let tags=self.tags;
            let present=!tags;
            let live=(present|(present>>1))&0x5555u16;
            let pairs=(live|(live>>1))&0x3333u16;
            let quads=(pairs|(pairs>>2))&0x0f0fu16;
            let packed=(quads|(quads>>4))&0xffu16;
            (self.control as u64)|((self.status as u64)<<16)|((packed as u64)<<32)|((self.opcode as u64)<<48)
        } else if index==1 {
            if wide {self.ip} else {self.ip&0xffff_ffff}
        } else if index==2 {
            if wide {self.dp} else {self.dp&0xffff_ffff}
        } else if index==3 {
            (self.mxcsr as u64)|((super::profile::MXCSR_MASK as u64)<<32)
        } else if index<20 {
            let logical=(index-4)/2;
            let status=self.status;
            let top=(status>>11)&7;
            assert(top<=7) by(bit_vector) requires top==(status>>11)&7u16;
            let physical=(logical+top as u8)%8;
            if index%2==0 {self.significands[physical as usize]}
            else {self.exponents[physical as usize] as u64}
        } else {
            self.xmm[((index-20)/2) as usize][((index-20)%2) as usize]
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub struct SystemState {
    // Only DE_CFG.LFENCE_SERIALIZE is in this bounded model-specific profile.
    pub de_cfg:u64,
    pub fp:LegacyFpState,
    pub entry:EntryMsrs,
    pub dr0:u64,pub dr1:u64,pub dr2:u64,pub dr3:u64,
    pub cs: SegmentState, pub ss: SegmentState, pub ds: SegmentState, pub es: SegmentState,
    pub fs: SegmentState, pub gs: SegmentState, pub tr: SegmentState, pub ldtr: SegmentState,
    pub efer_sce: bool,
    /// Retained CR0.MP/NE/AM only; CR0.WP is authoritative in MMU Config.
    pub cr0_extra: u64,
    /// Retained CR4.PSE/PGE/OSFXSR/OSXMMEXCPT; this profile keeps PAE enabled.
    pub cr4_extra: u64,
    pub pat: u64,
    pub mtrr_def: u64,
    pub mtrr_fixed: [u64; 11],
    pub mtrr_variable: [u64; 16],
}

fn interleave_low(a:u64,b:u64,word:bool)->(out:u64)
    ensures out==model::interleave_low(a,b,word),
{
    if word {
        (a&0xffff)|((b&0xffff)<<16)|((a&0xffff_0000)<<16)|((b&0xffff_0000)<<32)
    } else {
        (a&0xff)|((b&0xff)<<8)|((a&0xff00)<<8)|((b&0xff00)<<16)
            |((a&0xff_0000)<<16)|((b&0xff_0000)<<24)
            |((a&0xff00_0000)<<24)|((b&0xff00_0000)<<32)
    }
}

fn select_dword(pair:[u64;2],selector:u8)->(out:u64)
    ensures out==model::select_dword(pair,selector),
{
    let bit=selector&1;
    assert(bit<=1) by(bit_vector) requires bit==selector&1;
    let value=if selector&2==0 {pair[0]} else {pair[1]};
    (value>>((bit as u32)*32))&0xffff_ffff
}

pub mod model {
    #[cfg(verus_keep_ghost)]
    use super::*;

    pub open spec fn xmm_byte_shift(s:LegacyFpState,index:u8,count:u8,left:bool)->LegacyFpState {
        let pair=s.xmm[index as int];
        let value=(pair[0] as u128)|((pair[1] as u128)<<64);
        let shift=((count as u32)*8) as u32;
        let result=if count>=16 {0u128} else if left {value<<shift} else {value>>shift};
        xmm_pair(s,index,result as u64,(result>>64) as u64)
    }

    pub open spec fn interleave_low(a:u64,b:u64,word:bool)->u64 {
        if word {
            (a&0xffffu64)|((b&0xffffu64)<<16)|((a&0xffff_0000u64)<<16)|((b&0xffff_0000u64)<<32)
        } else {
            (a&0xffu64)|((b&0xffu64)<<8)|((a&0xff00u64)<<8)|((b&0xff00u64)<<16)
                |((a&0xff_0000u64)<<16)|((b&0xff_0000u64)<<24)
                |((a&0xff00_0000u64)<<24)|((b&0xff00_0000u64)<<32)
        }
    }
    pub open spec fn select_dword(pair:[u64;2],selector:u8)->u64 {
        ((if selector&2u8==0 {pair[0]} else {pair[1]})>>(((selector&1u8) as u32)*32))&0xffff_ffffu64
    }
    pub open spec fn xmm_unpack_narrow(s:LegacyFpState,dst:u8,source:u8,word:bool,high:bool)->LegacyFpState {
        let at=if high {1int} else {0int};
        let a=s.xmm[dst as int][at];
        let b=s.xmm[source as int][at];
        xmm_pair(s,dst,interleave_low(a,b,word),interleave_low(a>>32,b>>32,word))
    }
    pub open spec fn xmm_shuffle(s:LegacyFpState,dst:u8,source:u8,control:u8)->LegacyFpState {
        let pair=s.xmm[source as int];
        xmm_pair(s,dst,select_dword(pair,control)|(select_dword(pair,control>>2)<<32),
            select_dword(pair,control>>4)|(select_dword(pair,control>>6)<<32))
    }

    pub open spec fn packed_lane(left:u64,right:u64,width:super::super::operand::Width,operation:PackedOperation)->u64 {
        let mask=super::super::operand::model::mask(width);
        let a=left&mask;
        let b=right&mask;
        match operation {
            PackedOperation::Equal=>if a==b {mask} else {0u64},
            PackedOperation::GreaterSigned=>{
                let greater=match width {
                    super::super::operand::Width::Byte=>(a as i8)>(b as i8),
                    super::super::operand::Width::Word=>(a as i16)>(b as i16),
                    super::super::operand::Width::Dword=>(a as i32)>(b as i32),
                    super::super::operand::Width::Qword=>(a as i64)>(b as i64),
                };
                if greater {mask} else {0u64}
            },
            PackedOperation::Add=>(((a as int+b as int)%0x1_0000_0000_0000_0000int) as u64)&mask,
            PackedOperation::Subtract=>(((a as int-b as int)%0x1_0000_0000_0000_0000int) as u64)&mask,
        }
    }
    pub open spec fn packed_prefix(left:u64,right:u64,width:super::super::operand::Width,count:nat,operation:PackedOperation)->u64
        decreases count,
    {
        if count==0 {0u64} else {
            let shift=((count-1)*super::super::operand::model::bits(width)) as u32;
            packed_prefix(left,right,width,(count-1) as nat,operation) |
                (packed_lane(left>>shift,right>>shift,width,operation)<<shift)
        }
    }
    pub open spec fn mask_prefix(word:u64,count:nat)->u64
        decreases count,
    {
        if count==0 {0u64} else {
            mask_prefix(word,(count-1) as nat) |
                (((word>>(((count-1)*8+7) as u32))&1u64)<<((count-1) as u32))
        }
    }
    pub open spec fn xmm_equal(s:LegacyFpState,dst:u8,low:u64,high:u64,width:super::super::operand::Width)->LegacyFpState {
        xmm_packed(s,dst,low,high,width,PackedOperation::Equal)
    }
    pub open spec fn xmm_packed(s:LegacyFpState,dst:u8,low:u64,high:u64,width:super::super::operand::Width,operation:PackedOperation)->LegacyFpState {
        let count=(64u32/super::super::operand::model::bits(width)) as nat;
        xmm_pair(s,dst,packed_prefix(s.xmm[dst as int][0],low,width,count,operation),
            packed_prefix(s.xmm[dst as int][1],high,width,count,operation))
    }
    pub open spec fn xmm_mask(s:LegacyFpState,index:u8)->u64 {
        mask_prefix(s.xmm[index as int][0],8)|(mask_prefix(s.xmm[index as int][1],8)<<8)
    }

    pub open spec fn xmm_bits(operation:XmmLogic,left:u64,right:u64)->u64 {
        match operation {XmmLogic::And=>left&right,XmmLogic::AndNot=>!left&right,
            XmmLogic::Or=>left|right,XmmLogic::Xor=>left^right}
    }
    pub open spec fn xmm_logic(s:LegacyFpState,dst:u8,source:u8,operation:XmmLogic)->LegacyFpState {
        xmm_pair(s,dst,xmm_bits(operation,s.xmm[dst as int][0],s.xmm[source as int][0]),
            xmm_bits(operation,s.xmm[dst as int][1],s.xmm[source as int][1]))
    }

    pub open spec fn xmm_pair(s:LegacyFpState,dst:u8,low:u64,high:u64)->LegacyFpState {
        LegacyFpState {xmm:set16(s.xmm,dst as int,[low,high]),..s}
    }
    pub open spec fn xmm_scalar(s:LegacyFpState,dst:u8,value:u64,wide:bool)->LegacyFpState {
        LegacyFpState {xmm:set16(s.xmm,dst as int,[if wide {value} else {value&0xffff_ffffu64},0u64]),..s}
    }
    pub open spec fn xmm_unpack(s:LegacyFpState,dst:u8,source:u8,wide:bool,high:bool)->LegacyFpState {
        let at=if high {1int} else {0int};
        let a=s.xmm[dst as int][at];
        let b=s.xmm[source as int][at];
        let pair=if wide {[a,b]} else {
            [(a&0xffff_ffffu64)|((b&0xffff_ffffu64)<<32),(a>>32)|((b>>32)<<32)]
        };
        LegacyFpState {xmm:set16(s.xmm,dst as int,pair),..s}
    }
    pub open spec fn set2<T>(a:[T;2],i:int,v:T)->[T;2] {
        [if i==0 {v} else {a[0]},if i==1 {v} else {a[1]}]
    }
    pub open spec fn set8<T>(a:[T;8],i:int,v:T)->[T;8] {
        [if i==0 {v} else {a[0]},if i==1 {v} else {a[1]},
         if i==2 {v} else {a[2]},if i==3 {v} else {a[3]},
         if i==4 {v} else {a[4]},if i==5 {v} else {a[5]},
         if i==6 {v} else {a[6]},if i==7 {v} else {a[7]}]
    }
    pub open spec fn set16<T>(a:[T;16],i:int,v:T)->[T;16] {
        [if i==0 {v} else {a[0]},if i==1 {v} else {a[1]},
         if i==2 {v} else {a[2]},if i==3 {v} else {a[3]},
         if i==4 {v} else {a[4]},if i==5 {v} else {a[5]},
         if i==6 {v} else {a[6]},if i==7 {v} else {a[7]},
         if i==8 {v} else {a[8]},if i==9 {v} else {a[9]},
         if i==10 {v} else {a[10]},if i==11 {v} else {a[11]},
         if i==12 {v} else {a[12]},if i==13 {v} else {a[13]},
         if i==14 {v} else {a[14]},if i==15 {v} else {a[15]}]
    }
    pub open spec fn integer_ready(s:LegacyFpState)->bool {
        let top=(((((s.status>>11)&7u16) as int)+7)%8) as u16;
        ((s.tags>>(top*2))&3)==3 && ((s.status&!s.control)&0x3fu16)==0
    }
    pub open spec fn push_integer(s:LegacyFpState,value:u64,width:super::super::operand::Width,
        ip:u64,dp:u64,opcode:u16)->LegacyFpState {
        let raw=value&super::super::operand::model::mask(width);
        let negative=raw&(1u64<<(super::super::operand::model::bits(width)-1))!=0;
        let magnitude=if negative {0u64.wrapping_sub(raw)&super::super::operand::model::mask(width)} else {raw};
        let sign=if negative {0x8000u16} else {0u16};
        let (significand,exponent)=match super::super::scalar::model::scan(
            magnitude,super::super::operand::Width::Qword,true) {
            Some(index)=>if index<64 {(magnitude<<(63-index),((0x3fffu64+index) as u16)|sign)}
                else {(0u64,0u16)},
            None=>(0u64,0u16),
        };
        let top=(((((s.status>>11)&7u16) as int)+7)%8) as u16;
        LegacyFpState {
            status:(s.status&0xc5ffu16)|(top<<11),
            tags:(s.tags&!(3u16<<(top*2)))|((if magnitude==0 {1u16} else {0u16})<<(top*2)),
            ip,dp,opcode,
            significands:set8(s.significands,top as int,significand),
            exponents:set8(s.exponents,top as int,exponent),..s
        }
    }
    pub open spec fn restore_word(s:LegacyFpState,index:int,value:u64,wide:bool)->LegacyFpState {
        if index==0 {
            let byte=((value>>32)&0xffu64) as u16;
            let pairs=(byte|(byte<<4))&0x0f0fu16;
            let quads=(pairs|(pairs<<2))&0x3333u16;
            let bits=(quads|(quads<<1))&0x5555u16;
            LegacyFpState {control:(value&0xffffu64) as u16,status:((value>>16)&0xffffu64) as u16,
                opcode:((value>>48)&0x7ffu64) as u16,tags:!(bits|(bits<<1)),..s}
        } else if index==1 {LegacyFpState {ip:if wide {value} else {value&0xffff_ffffu64},..s}}
        else if index==2 {LegacyFpState {dp:if wide {value} else {value&0xffff_ffffu64},..s}}
        else if index==3 {LegacyFpState {mxcsr:(value&0xffff_ffffu64) as u32,..s}}
        else if index<20 {
            let physical=((index-4)/2+((s.status>>11)&7u16) as int)%8;
            if index%2==0 {LegacyFpState {significands:set8(s.significands,physical,value),..s}}
            else {
                let exponent=(value&0xffffu64) as u16;
                let tag=if exponent&0x7fffu16==0 && s.significands@[physical]==0 {1u16}
                    else if exponent&0x7fffu16==0 || exponent&0x7fffu16==0x7fff
                        || s.significands@[physical]&0x8000_0000_0000_0000u64==0 {2u16}
                    else {0u16};
                LegacyFpState {exponents:set8(s.exponents,physical,exponent),
                    tags:if (s.tags>>(physical*2))&3u16==3 {s.tags}
                        else {(s.tags&!(3u16<<(physical*2)))|(tag<<(physical*2))},..s}
            }
        } else {LegacyFpState {
            xmm:set16(s.xmm,(index-20)/2,set2(s.xmm@[(index-20)/2],(index-20)%2,value)),..s}}
    }
    pub open spec fn finish_restore(s:LegacyFpState,previous:LegacyFpState)->LegacyFpState {
        let pending=((s.status&!s.control)&0x3fu16)!=0;
        LegacyFpState {status:(s.status&0x7f7fu16)|(if pending {0x8080u16} else {0u16}),
            ip:if pending {s.ip} else {previous.ip},dp:if pending {s.dp} else {previous.dp},
            opcode:if pending {s.opcode} else {previous.opcode},..s}
    }
    pub open spec fn fp_word(s:LegacyFpState,index:int,wide:bool)->u64 {
        if index==0 {
            let present=!s.tags;
            let live=(present|(present>>1))&0x5555u16;
            let pairs=(live|(live>>1))&0x3333u16;
            let quads=(pairs|(pairs>>2))&0x0f0fu16;
            let packed=(quads|(quads>>4))&0xffu16;
            (s.control as u64)|((s.status as u64)<<16)|((packed as u64)<<32)|((s.opcode as u64)<<48)
        } else if index==1 {if wide {s.ip} else {s.ip&0xffff_ffffu64}}
        else if index==2 {if wide {s.dp} else {s.dp&0xffff_ffffu64}}
        else if index==3 {(s.mxcsr as u64)|((super::super::profile::MXCSR_MASK as u64)<<32)}
        else if index<20 {
            let physical=((index-4)/2+((s.status>>11)&7u16) as int)%8;
            if index%2==0 {s.significands@[physical]} else {s.exponents@[physical] as u64}
        } else {s.xmm@[(index-20)/2]@[(index-20)%2]}
    }

    pub open spec fn canonical(base: u64) -> bool {
        base < 0x8000_0000_0000u64 || base >= 0xffff_8000_0000_0000u64
    }
    pub open spec fn supported_code(s: SegmentState) -> bool {
        s.base == 0 && s.limit == u32::MAX && s.attributes == 0xa09b
        && s.selector != 0 && s.selector & 7u16 == 0
    }
    pub open spec fn supported_data(s: SegmentState) -> bool {
        s.base == 0 && s.limit == u32::MAX && s.attributes == 0xc093
        && s.selector != 0 && s.selector & 7u16 == 0
    }
    pub open spec fn supported_data_or_null(s: SegmentState) -> bool {
        s == NULL_SEGMENT || supported_data(s)
    }
    pub open spec fn execution_code(s:SegmentState)->bool {
        s.base==0 && s.limit==u32::MAX && s.attributes&!0x60u16==0xa09b
            && (s.selector&3u16==0 || s.selector&3u16==3)
            && s.selector&3u16==(s.attributes>>5)&3u16
    }
    pub open spec fn execution_stack(s:SegmentState)->bool {
        s==NULL_SEGMENT || (s.base==0 && s.limit==u32::MAX
            && (s.attributes==0xc093 || s.attributes==0xc0f3))
    }
    pub open spec fn outer_data(s:SegmentState)->SegmentState {
        if s.selector<4 || (s.attributes>>5)&3u16<3 {
            SegmentState {selector:0,attributes:0,..s}
        } else {s}
    }
    // APM Volume 2 §§4.5.3, 4.8.2: FS/GS bases can be set independently
    // by their MSRs. This validates retained metadata, not MOV Sreg effects.
    pub open spec fn data_or_null(s: SegmentState) -> bool {
        (s.selector < 4 && s.attributes == 0)
        || (s.limit == u32::MAX && s.selector >= 8 && s.selector & 4u16 == 0
            && s.attributes & !0x60u16 == 0xc093
            && s.selector & 3u16 <= (s.attributes >> 5) & 3u16)
    }
    pub open spec fn unused(s: SegmentState, attributes: u16) -> bool {
        s == NULL_SEGMENT || (s.base == 0 && s.limit == 0xffff
            && s.selector == 0 && s.attributes == attributes)
    }
    pub open spec fn supported_task(s:SegmentState)->bool {
        unused(s,0x8b) || (s.selector!=0 && s.selector&7u16==0 && canonical(s.base)
            && 0x67<=s.limit<=0xfffff && s.attributes==0x8b)
    }
    pub open spec fn fixed_value(def: u64, index: int) -> u64 {
        if def == 0xc00 && index < 2 { FIXED_WB } else { 0u64 }
    }
    pub open spec fn mtrrs_supported(def: u64, fixed: Seq<u64>, variable: Seq<u64>) -> bool {
        (def == 0 || def == 0xc00)
        && (forall|i: int| 0 <= i < 11 ==> #[trigger] fixed[i] == fixed_value(def, i))
        && (forall|i: int| 0 <= i < 16 ==> #[trigger] variable[i] == 0)
    }
    pub open spec fn supported(s: SystemState) -> bool {
        s.de_cfg&!2u64==0 && execution_code(s.cs) && execution_stack(s.ss)
        && data_or_null(s.ds) && s.ds.base==0 && data_or_null(s.es) && s.es.base==0
        && data_or_null(s.fs) && data_or_null(s.gs)
        && canonical(s.fs.base) && canonical(s.gs.base)
        && supported_task(s.tr) && unused(s.ldtr, 0x82)
        && s.pat == DEFAULT_PAT
        && s.cr0_extra & !0x40022u64 == 0 && s.cr4_extra & !0x690u64 == 0
        && mtrrs_supported(s.mtrr_def, s.mtrr_fixed@, s.mtrr_variable@)
    }
    pub open spec fn empty() -> SystemState {
        SystemState {de_cfg:0,fp:EMPTY_LEGACY_FP,entry:EMPTY_ENTRY_MSRS,dr0:0,dr1:0,dr2:0,dr3:0, cs: NULL_SEGMENT, ss: NULL_SEGMENT, ds: NULL_SEGMENT, es: NULL_SEGMENT,
            fs: NULL_SEGMENT, gs: NULL_SEGMENT, tr: NULL_SEGMENT, ldtr: NULL_SEGMENT,
            efer_sce: false, cr0_extra: 0, cr4_extra: 0, pat: DEFAULT_PAT, mtrr_def: 0,
            mtrr_fixed: [0u64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            mtrr_variable: [0u64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }
    }
}

pub proof fn lemma_replace_data(s: SystemState, ss: SegmentState, ds: SegmentState,
    es: SegmentState)
    requires model::supported(s), model::supported_data_or_null(ss),
        model::supported_data_or_null(ds), model::supported_data_or_null(es),
    ensures model::supported(SystemState { ss, ds, es, ..s }),
{
    lemma_kernel_data(ss);lemma_kernel_data(ds);lemma_kernel_data(es);
}
pub proof fn lemma_kernel_data(s:SegmentState)
    requires model::supported_data_or_null(s),
    ensures model::execution_stack(s),model::data_or_null(s),s.base==0,
{
    if s!=NULL_SEGMENT {
        let selector=s.selector;
        assert(selector>=8 && selector&4u16==0 && selector&3u16==0) by(bit_vector)
            requires selector!=0,selector&7u16==0;
        assert(0xc093u16&!0x60u16==0xc093u16 && (0xc093u16>>5)&3u16==0) by(bit_vector);
    }
}

pub proof fn lemma_replace_control(s: SystemState, cr0_extra: u64, cr4_extra: u64,
    efer_sce: bool)
    requires model::supported(s),
        cr0_extra & !0x40022u64 == 0, cr4_extra & !0x690u64 == 0,
    ensures
        model::supported(SystemState { cr0_extra, cr4_extra, efer_sce, ..s }),
        (SystemState { cr0_extra: s.cr0_extra, cr4_extra: s.cr4_extra,
            efer_sce: s.efer_sce,
            ..SystemState { cr0_extra, cr4_extra, efer_sce, ..s } }) == s,
{
}

pub proof fn lemma_replace_code(s: SystemState, cs: SegmentState)
    requires model::supported(s), model::supported_code(cs),
    ensures model::supported(SystemState { cs, ..s }),
{
    let selector=cs.selector;
    assert(selector&3u16==0 && (0xa09bu16>>5)&3u16==0
        && 0xa09bu16&!0x60u16==0xa09bu16) by(bit_vector) requires selector&7u16==0;
}

pub proof fn lemma_return_segments(s:SystemState,cs:SegmentState,ss:SegmentState,outer:bool)
    requires model::supported(s),model::execution_code(cs),model::execution_stack(ss),
    ensures model::supported(SystemState {cs,ss,
        ds:if outer {model::outer_data(s.ds)} else {s.ds},
        es:if outer {model::outer_data(s.es)} else {s.es},
        fs:if outer {model::outer_data(s.fs)} else {s.fs},
        gs:if outer {model::outer_data(s.gs)} else {s.gs},..s}),
{
}

pub fn mtrrs_supported(def: u64, fixed: &[u64; 11], variable: &[u64; 16]) -> (out: bool)
    ensures out == model::mtrrs_supported(def, fixed@, variable@),
{
    if def != 0 && def != 0xc00 { return false; }
    let mut i: usize = 0;
    while i < 11
        invariant i <= 11,
            forall|j: int| 0 <= j < i ==> #[trigger] fixed@[j] == model::fixed_value(def, j),
        decreases 11 - i,
    {
        let expected = if def == 0xc00 && i < 2 { FIXED_WB } else { 0 };
        if fixed[i] != expected { return false; }
        i += 1;
    }
    i = 0;
    while i < 16
        invariant i <= 16,
            forall|j: int| 0 <= j < 11 ==> #[trigger] fixed@[j] == model::fixed_value(def, j),
            forall|j: int| 0 <= j < i ==> #[trigger] variable@[j] == 0,
        decreases 16 - i,
    {
        if variable[i] != 0 { return false; }
        i += 1;
    }
    true
}

fn data_or_null(s: SegmentState) -> (out: bool)
    ensures out == model::data_or_null(s),
{
    (s.selector < 4 && s.attributes == 0)
        || (s.limit == u32::MAX && s.selector >= 8 && s.selector & 4 == 0
            && s.attributes & !0x60 == 0xc093
            && s.selector & 3 <= (s.attributes >> 5) & 3)
}

fn unused(s: SegmentState, attributes: u16) -> (out: bool)
    ensures out == model::unused(s, attributes),
{
    s == NULL_SEGMENT || (s.base == 0 && s.limit == 0xffff
        && s.selector == 0 && s.attributes == attributes)
}

pub fn supported_task(s:SegmentState)->(out:bool)
    ensures out==model::supported_task(s),
{
    unused(s,0x8b) || (s.selector!=0 && s.selector&7==0
        && (s.base<0x8000_0000_0000 || s.base>=0xffff_8000_0000_0000)
        && s.limit>=0x67 && s.limit<=0xfffff && s.attributes==0x8b)
}

impl SystemState {
    pub fn is_user(self)->(out:bool)
        ensures out==(self.cs.selector&3u16==3),
    {self.cs.selector&3==3}
    /// An incomplete import buffer, not an architectural reset CPU image.
    pub fn empty() -> (out: Self)
        ensures out == model::empty(),
    {
        let out = Self {de_cfg:0,fp:EMPTY_LEGACY_FP,entry:EMPTY_ENTRY_MSRS,dr0:0,dr1:0,dr2:0,dr3:0, cs: NULL_SEGMENT, ss: NULL_SEGMENT, ds: NULL_SEGMENT, es: NULL_SEGMENT,
            fs: NULL_SEGMENT, gs: NULL_SEGMENT, tr: NULL_SEGMENT, ldtr: NULL_SEGMENT,
            efer_sce: false, cr0_extra: 0, cr4_extra: 0, pat: DEFAULT_PAT, mtrr_def: 0,
            mtrr_fixed: [0; 11], mtrr_variable: [0; 16] };
        proof {
            assert(out.mtrr_fixed@ =~= model::empty().mtrr_fixed@);
            assert(out.mtrr_fixed == model::empty().mtrr_fixed);
            assert(out.mtrr_variable@ =~= model::empty().mtrr_variable@);
            assert(out.mtrr_variable == model::empty().mtrr_variable);
        }
        out
    }

    pub fn is_supported(self) -> (out: bool)
        ensures out == model::supported(self),
    {
        self.de_cfg&!2==0 && execution_code(self.cs) && execution_stack(self.ss)
            && data_or_null(self.ds) && self.ds.base==0 && data_or_null(self.es) && self.es.base==0
            && data_or_null(self.fs) && data_or_null(self.gs)
            && (self.fs.base < 0x8000_0000_0000 || self.fs.base >= 0xffff_8000_0000_0000)
            && (self.gs.base < 0x8000_0000_0000 || self.gs.base >= 0xffff_8000_0000_0000)
            && supported_task(self.tr) && unused(self.ldtr, 0x82)
            && self.pat == DEFAULT_PAT
            && self.cr0_extra & !0x40022u64 == 0 && self.cr4_extra & !0x690u64 == 0
            && mtrrs_supported(self.mtrr_def, &self.mtrr_fixed, &self.mtrr_variable)
    }
}
    pub fn execution_code(s:SegmentState)->(out:bool)
        ensures out==model::execution_code(s),
    {
        s.base==0 && s.limit==u32::MAX && s.attributes&!0x60u16==0xa09b
            && (s.selector&3==0 || s.selector&3==3)
            && s.selector&3==(s.attributes>>5)&3
    }
    pub fn execution_stack(s:SegmentState)->(out:bool)
        ensures out==model::execution_stack(s),
    {
        s==NULL_SEGMENT || (s.base==0 && s.limit==u32::MAX
            && (s.attributes==0xc093 || s.attributes==0xc0f3))
    }

    /// Outer privilege returns invalidate inaccessible data selectors without
    /// exchanging GS bases. Retaining null base/limit is permitted by the
    /// declared NullSelectorClearsBase=0 profile (APM Vol. 2 section 4.5.1).
    pub fn outer_data(s:SegmentState)->(out:SegmentState)
        ensures out==model::outer_data(s),
    {
        if s.selector<4 || (s.attributes>>5)&3<3 {
            SegmentState {selector:0,attributes:0,..s}
        } else {s}
    }
}
