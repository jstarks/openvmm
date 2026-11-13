// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::descriptor;
use super::system::{self, SegmentState, SystemState};
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub struct Selectors {
    pub cs: u16,
    pub ss: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub struct Gate {
    pub target: u64,
    pub selector: u16,
}

pub mod model {
    #[cfg(verus_keep_ghost)]
    use super::*;

    pub open spec fn selectors(system: Option<SystemState>) -> Selectors {
        match system {
            Some(s) => Selectors { cs: s.cs.selector, ss: s.ss.selector },
            None => Selectors { cs: 8, ss: 16 },
        }
    }

    pub open spec fn gate(low: u64, high: u64) -> Option<Gate> {
        let selector = ((low >> 16) & 0xffffu64) as u16;
        let attributes = (low >> 40) & 0xffu64;
        let target = (low & 0xffffu64) | (((low >> 48) & 0xffffu64) << 16)
            | ((high & 0xffff_ffffu64) << 32);
        if (low >> 32) & 0xffu64 != 0 || high >> 32 != 0
            || (attributes&0x9fu64 != 0x8e && attributes&0x9fu64 != 0x8f)
            || selector == 0 || selector & 7u16 != 0
            || !system::model::canonical(target) {
            None
        } else {
            Some(Gate { target, selector })
        }
    }

    pub open spec fn stack(raw: u64, selector: u16) -> Option<SegmentState> {
        if selector == 0 { Some(system::NULL_SEGMENT) }
        else { descriptor::model::load_data(raw, selector) }
    }
    pub open spec fn return_stack(raw:u64,selector:u16,cpl:u16)->Option<SegmentState> {
        if selector==0 {
            if cpl==0 {Some(system::NULL_SEGMENT)} else {None}
        } else if (selector&3u16)!=cpl || ((raw>>45)&3u64)!=cpl as u64 {None}
        else {match descriptor::model::load_data(raw&!(3u64<<45),selector&!3u16) {
            None=>None,
            Some(s)=>Some(SegmentState {selector,attributes:0xc093u16|(cpl<<5),..s}),
        }}
    }

    pub open spec fn frame_word(rip: u64, rsp: u64, flags: u64,
        selectors: Selectors, error: bool, external: bool, code: u8, index: u8) -> u64
    {
        if error {
            match index {
                0 => selectors.ss as u64,
                1 => rsp,
                2 => flags | 0x10000u64,
                3 => selectors.cs as u64,
                4 => rip,
                5 => code as u64,
                _ => 0,
            }
        } else {
            match index {
                1 => selectors.ss as u64,
                2 => rsp,
                3 => if external { flags } else { flags | 0x10000u64 },
                4 => selectors.cs as u64,
                5 => rip,
                _ => 0,
            }
        }
    }
}

/// Read the sole system image; None retains the older component fixture.
/// The caller checks that a present system image is supported.
pub fn selectors(system: Option<SystemState>) -> (out: Selectors)
    ensures out == model::selectors(system),
{
    match system {
        Some(s) => Selectors { cs: s.cs.selector, ss: s.ss.selector },
        None => Selectors { cs: 8, ss: 16 },
    }
}

/// APM Volume 2 §§8.9.1–8.9.2: bounded present long-mode gates at CPL0.
/// IST, LDT and nonzero RPL are outside this same-CPL0 profile. None is
/// unsupported, not an architectural exception. GDT bounds and the code
/// image remain the caller's checks, using descriptor::load_code.
pub fn gate(low: u64, high: u64) -> (out: Option<Gate>)
    ensures out == model::gate(low, high),
{
    let selector = ((low >> 16) & 0xffff) as u16;
    let attributes = (low >> 40) & 0xff;
    let target = (low & 0xffff) | (((low >> 48) & 0xffff) << 16)
        | ((high & 0xffff_ffff) << 32);
    if (low >> 32) & 0xff != 0 || high >> 32 != 0
        || (attributes&0x9f != 0x8e && attributes&0x9f != 0x8f)
        || selector == 0 || selector & 7 != 0
        || !(target < 0x8000_0000_0000 || target >= 0xffff_8000_0000_0000) {
        None
    } else {
        Some(Gate { target, selector })
    }
}

/// APM Volume 2 §8.9.5 permits null SS on IRET to long64 CPL<3 without
/// loading a descriptor; Volume 3 IRET's #GP table has the same condition.
/// IRET_PROTECTED pops SS:RSP in long64, and the SAME_PRIV path restores them.
/// The caller skips the descriptor read for selector zero. Nonnull stacks
/// reuse the already-accessed flat data profile, not another parser.
pub fn stack(raw: u64, selector: u16) -> (out: Option<SegmentState>)
    ensures
        out == model::stack(raw, selector),
        match out {
            Some(s) => system::model::supported_data_or_null(s),
            None => true,
        },
{
    if selector == 0 { Some(system::NULL_SEGMENT) }
    else { descriptor::load_data(raw, selector) }
}

pub fn return_stack(raw:u64,selector:u16,cpl:u16)->(out:Option<SegmentState>)
    requires cpl==0 || cpl==3,
    ensures out==model::return_stack(raw,selector,cpl),
        out.is_some() ==> system::model::execution_stack(out.unwrap()),
{
    if selector==0 {return if cpl==0 {Some(system::NULL_SEGMENT)} else {None};}
    if selector&3!=cpl || ((raw>>45)&3)!=cpl as u64 {return None;}
    let Some(s)=descriptor::load_data(raw&!(3u64<<45),selector&!3u16) else {return None;};
    let attributes=0xc093|(cpl<<5);
    proof {
        assert(attributes==0xc093u16 || attributes==0xc0f3u16) by(bit_vector)
            requires attributes==0xc093u16|(cpl<<5),cpl==0 || cpl==3;
    }
    Some(SegmentState {selector,attributes,..s})
}

/// Push order, not ascending memory order. APM Volume 2 §8.9.3 always saves
/// old SS:RSP, even at the same CPL; only a CPL change clears the live SS.
/// Non-debug faults save RF=1 (§8.2.2); ordinary external interrupts retain
/// the saved RF. This excludes debug/string interruption and software INT.
/// The caller validates flags, aligns the stack and applies live entry flags.
/// For return, Volume 2 §§3.1.6/8.2.2 explicitly restore RF through IRET,
/// conflicting with Volume 3 IRET SAME_PRIV's "RF cleared" comment. The
/// caller restores the admitted flags image, not a POPF-masked image.
pub fn frame_word(rip: u64, rsp: u64, flags: u64, selectors: Selectors,
    error: bool, external: bool, code: u8, index: u8) -> (out: u64)
    requires index < 6,
    ensures out == model::frame_word(rip, rsp, flags, selectors, error, external, code, index),
{
    if error {
        match index {
            0 => selectors.ss as u64,
            1 => rsp,
            2 => flags | 0x10000,
            3 => selectors.cs as u64,
            4 => rip,
            _ => code as u64,
        }
    } else {
        match index {
            1 => selectors.ss as u64,
            2 => rsp,
            3 => if external { flags } else { flags | 0x10000 },
            4 => selectors.cs as u64,
            5 => rip,
            _ => 0,
        }
    }
}

pub proof fn lemma_gate_fields(low: u64, high: u64)
    ensures match model::gate(low, high) {
        Some(g) => g.selector != 0 && g.selector & 7u16 == 0
            && g.selector as int + 7 <= u16::MAX as int
            && system::model::canonical(g.target)
            && ((low >> 16) & 0xffffu64) == g.selector as u64
            && (low >> 32) & 0xffu64 == 0 && high >> 32 == 0
            && ((low >> 40) & 0x9fu64 == 0x8e
                || (low >> 40) & 0x9fu64 == 0x8f),
        None => true,
    },
{
    assert(((low>>16)&0xffffu64)<=0xffffu64) by(bit_vector);
    assert((((low>>40)&0xffu64)&0x9fu64)==((low>>40)&0x9fu64)) by(bit_vector);
    let selector = ((low >> 16) & 0xffffu64) as u16;
    assert(((low >> 16) & 0xffffu64) == selector as u64) by(bit_vector)
        requires selector == ((low >> 16) & 0xffffu64) as u16;
    assert(selector & 7u16 == 0 ==> selector <= 0xfff8u16) by(bit_vector);
}

pub proof fn lemma_selectors_frame(before: SystemState, after: SystemState)
    requires before.cs == after.cs, before.ss == after.ss,
    ensures model::selectors(Some(before)) == model::selectors(Some(after)),
{
}

/// Segment replacement frames every other retained segment/control/MSR field.
/// Entry and IRET callers still own the descriptor reads and atomic commit.
pub proof fn lemma_segments_frame(before: SystemState, cs: SegmentState, ss: SegmentState)
    requires system::model::supported(before),
        system::model::supported_code(cs), system::model::supported_data_or_null(ss),
    ensures
        system::model::supported(SystemState { cs, ss, ..before }),
        (SystemState { cs: before.cs, ss: before.ss,
            ..SystemState { cs, ss, ..before } }) == before,
{
}

pub proof fn lemma_frame_shape(rip: u64, rsp: u64, flags: u64, selectors: Selectors,
    error: bool, external: bool, code: u8)
    ensures
        model::frame_word(rip, rsp, flags, selectors, error, external, code,
            if error { 0u8 } else { 1u8 }) == selectors.ss as u64,
        model::frame_word(rip, rsp, flags, selectors, error, external, code,
            if error { 1u8 } else { 2u8 }) == rsp,
        model::frame_word(rip, rsp, flags, selectors, error, external, code,
            if error { 3u8 } else { 4u8 }) == selectors.cs as u64,
        model::frame_word(rip, rsp, flags, selectors, error, external, code,
            if error { 4u8 } else { 5u8 }) == rip,
        model::frame_word(rip, rsp, flags, selectors, error, external, code,
            if error { 2u8 } else { 3u8 })
                == if error || !external { flags | 0x10000u64 } else { flags },
        error ==> model::frame_word(rip, rsp, flags, selectors, error, external, code, 5)
            == code as u64,
        !error ==> model::frame_word(rip, rsp, flags, selectors, error, external, code, 0) == 0,
{
}

pub proof fn lemma_frame_flags(flags: u64)
    ensures
        (flags | 0x10000u64) & !0x10000u64 == flags & !0x10000u64,
        (flags | 0x10000u64) & 0x10000u64 != 0,
{
    assert((flags | 0x10000u64) & !0x10000u64 == flags & !0x10000u64
        && (flags | 0x10000u64) & 0x10000u64 != 0) by(bit_vector);
}
}
