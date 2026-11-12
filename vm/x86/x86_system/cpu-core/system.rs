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
impl LegacyFpState {
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

pub mod model {
    #[cfg(verus_keep_ghost)]
    use super::*;

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
    // APM Volume 2 §§4.5.3, 4.8.2: FS/GS bases can be set independently
    // by their MSRs. This validates retained metadata, not MOV Sreg effects.
    pub open spec fn data_or_null(s: SegmentState) -> bool {
        (s.limit == 0 && s.selector < 4 && s.attributes == 0)
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
        s.de_cfg&!2u64==0 && supported_code(s.cs) && supported_data_or_null(s.ss) && supported_data_or_null(s.ds)
        && supported_data_or_null(s.es) && data_or_null(s.fs) && data_or_null(s.gs)
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

fn supported_code(s: SegmentState) -> (out: bool)
    ensures out == model::supported_code(s),
{
    s.base == 0 && s.limit == u32::MAX && s.attributes == 0xa09b
        && s.selector != 0 && s.selector & 7 == 0
}

fn supported_data(s: SegmentState) -> (out: bool)
    ensures out == model::supported_data(s),
{
    s.base == 0 && s.limit == u32::MAX && s.attributes == 0xc093
        && s.selector != 0 && s.selector & 7 == 0
}

fn supported_data_or_null(s: SegmentState) -> (out: bool)
    ensures out == model::supported_data_or_null(s),
{
    s == NULL_SEGMENT || supported_data(s)
}

fn data_or_null(s: SegmentState) -> (out: bool)
    ensures out == model::data_or_null(s),
{
    (s.limit == 0 && s.selector < 4 && s.attributes == 0)
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
        self.de_cfg&!2==0 && supported_code(self.cs) && supported_data_or_null(self.ss) && supported_data_or_null(self.ds)
            && supported_data_or_null(self.es) && data_or_null(self.fs) && data_or_null(self.gs)
            && (self.fs.base < 0x8000_0000_0000 || self.fs.base >= 0xffff_8000_0000_0000)
            && (self.gs.base < 0x8000_0000_0000 || self.gs.base >= 0xffff_8000_0000_0000)
            && supported_task(self.tr) && unused(self.ldtr, 0x82)
            && self.pat == DEFAULT_PAT
            && self.cr0_extra & !0x40022u64 == 0 && self.cr4_extra & !0x690u64 == 0
            && mtrrs_supported(self.mtrr_def, &self.mtrr_fixed, &self.mtrr_variable)
    }
}
}
