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
pub struct SystemState {
    pub cs: SegmentState, pub ss: SegmentState, pub ds: SegmentState, pub es: SegmentState,
    pub fs: SegmentState, pub gs: SegmentState, pub tr: SegmentState, pub ldtr: SegmentState,
    pub efer_sce: bool,
    pub pat: u64,
    pub mtrr_def: u64,
    pub mtrr_fixed: [u64; 11],
    pub mtrr_variable: [u64; 16],
}

pub mod model {
    #[cfg(verus_keep_ghost)]
    use super::*;

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
    pub open spec fn data_or_null(s: SegmentState) -> bool {
        (s.limit == 0 && s.selector == 0 && s.attributes == 0)
        || (s.limit == u32::MAX && s.selector == 16 && s.attributes == 0xc093)
    }
    pub open spec fn unused(s: SegmentState, attributes: u16) -> bool {
        s == NULL_SEGMENT || (s.base == 0 && s.limit == 0xffff
            && s.selector == 0 && s.attributes == attributes)
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
        supported_code(s.cs) && supported_data(s.ss) && supported_data(s.ds)
        && supported_data(s.es) && data_or_null(s.fs) && data_or_null(s.gs)
        && canonical(s.fs.base) && canonical(s.gs.base)
        && unused(s.tr, 0x8b) && unused(s.ldtr, 0x82)
        && s.pat == DEFAULT_PAT
        && mtrrs_supported(s.mtrr_def, s.mtrr_fixed@, s.mtrr_variable@)
    }
    pub open spec fn empty() -> SystemState {
        SystemState { cs: NULL_SEGMENT, ss: NULL_SEGMENT, ds: NULL_SEGMENT, es: NULL_SEGMENT,
            fs: NULL_SEGMENT, gs: NULL_SEGMENT, tr: NULL_SEGMENT, ldtr: NULL_SEGMENT,
            efer_sce: false, pat: DEFAULT_PAT, mtrr_def: 0,
            mtrr_fixed: [0u64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            mtrr_variable: [0u64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }
    }
}

pub proof fn lemma_replace_data(s: SystemState, ss: SegmentState, ds: SegmentState,
    es: SegmentState)
    requires model::supported(s), model::supported_data(ss),
        model::supported_data(ds), model::supported_data(es),
    ensures model::supported(SystemState { ss, ds, es, ..s }),
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

fn data_or_null(s: SegmentState) -> (out: bool)
    ensures out == model::data_or_null(s),
{
    (s.limit == 0 && s.selector == 0 && s.attributes == 0)
        || (s.limit == u32::MAX && s.selector == 16 && s.attributes == 0xc093)
}

fn unused(s: SegmentState, attributes: u16) -> (out: bool)
    ensures out == model::unused(s, attributes),
{
    s == NULL_SEGMENT || (s.base == 0 && s.limit == 0xffff
        && s.selector == 0 && s.attributes == attributes)
}

impl SystemState {
    /// An incomplete import buffer, not an architectural reset CPU image.
    pub fn empty() -> (out: Self)
        ensures out == model::empty(),
    {
        let out = Self { cs: NULL_SEGMENT, ss: NULL_SEGMENT, ds: NULL_SEGMENT, es: NULL_SEGMENT,
            fs: NULL_SEGMENT, gs: NULL_SEGMENT, tr: NULL_SEGMENT, ldtr: NULL_SEGMENT,
            efer_sce: false, pat: DEFAULT_PAT, mtrr_def: 0,
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
        supported_code(self.cs) && supported_data(self.ss) && supported_data(self.ds)
            && supported_data(self.es) && data_or_null(self.fs) && data_or_null(self.gs)
            && (self.fs.base < 0x8000_0000_0000 || self.fs.base >= 0xffff_8000_0000_0000)
            && (self.gs.base < 0x8000_0000_0000 || self.gs.base >= 0xffff_8000_0000_0000)
            && unused(self.tr, 0x8b) && unused(self.ldtr, 0x82)
            && self.pat == DEFAULT_PAT
            && mtrrs_supported(self.mtrr_def, &self.mtrr_fixed, &self.mtrr_variable)
    }
}
}
