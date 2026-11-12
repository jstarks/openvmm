// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use super::system;
use super::system::SegmentState;
use vstd::prelude::*;

verus! {

pub mod model {
    #[cfg(verus_keep_ghost)]
    use super::*;

    // APM Volume 2 §§4.7.1, 4.7.3, 4.8.2: retain the descriptor's hidden
    // fields even where 64-bit address generation ignores them.
    pub open spec fn base(word: u64) -> u64 {
        ((word >> 16) & 0xffffu64)
        | (((word >> 32) & 0xffu64) << 16)
        | (((word >> 56) & 0xffu64) << 24)
    }
    pub open spec fn limit(word: u64) -> u32 {
        let raw = (word & 0xffffu64) | (((word >> 48) & 0xfu64) << 16);
        if word & (1u64 << 55) != 0 { ((raw << 12) | 0xfffu64) as u32 }
        else { raw as u32 }
    }
    pub open spec fn attributes(word: u64) -> u16 {
        (((word >> 40) & 0xffu64) | (((word >> 52) & 0xfu64) << 12)) as u16
    }
    pub open spec fn admitted(word: u64, selector: u16) -> bool {
        selector != 0 && selector & 7u16 == 0
        && base(word) == 0 && limit(word) == u32::MAX
        && attributes(word) == 0xc093
    }
    pub open spec fn image(word: u64, selector: u16) -> SegmentState {
        SegmentState { base: base(word), limit: limit(word), selector,
            attributes: attributes(word) }
    }
    pub open spec fn load_data(word: u64, selector: u16) -> Option<SegmentState> {
        if admitted(word, selector) { Some(image(word, selector)) } else { None }
    }
    pub open spec fn load_thread_data(word:u64,selector:u16)->Option<SegmentState> {
        if admitted(word&!(3u64<<45),selector&!3u16)
            && (selector&3u16) as u64 <= (word>>45)&3u64 {Some(image(word,selector))}
        else {None}
    }
    pub open spec fn admitted_code(word: u64, selector: u16) -> bool {
        selector != 0 && selector & 7u16 == 0
        && base(word) == 0 && limit(word) == u32::MAX
        && attributes(word) == 0xa09b
    }
    pub open spec fn load_code(word: u64, selector: u16) -> Option<SegmentState> {
        if admitted_code(word, selector) { Some(image(word, selector)) } else { None }
    }
    pub open spec fn task_image(low:u64,high:u64,selector:u16)->SegmentState {
        SegmentState {base:base(low)|((high&0xffff_ffffu64)<<32),
            limit:limit(low),selector,attributes:0x8b}
    }
    pub open spec fn load_task(low:u64,high:u64,selector:u16)->Option<SegmentState> {
        let image=task_image(low,high,selector);
        if selector!=0 && selector&7u16==0 && attributes(low)==0x89
            && high>>32==0 && system::model::supported_task(image) {Some(image)}
        else {None}
    }
}

/// Bounded present DPL0 available 64-bit TSS, with byte granularity.
pub fn load_task(low:u64,high:u64,selector:u16)->(out:Option<SegmentState>)
    ensures out==model::load_task(low,high,selector),
        out.is_some() ==> system::model::supported_task(out.unwrap()),
{
    let base=((low>>16)&0x00ff_ffff)|((low>>32)&0xff00_0000)|((high&0xffff_ffff)<<32);
    let raw=(low&0xffff)|((low>>32)&0xf0000);
    proof {
        assert(raw<=0xfffffu64) by(bit_vector)
            requires raw==(low&0xffffu64)|((low>>32)&0xf0000u64);
        assert(((raw<<12)|0xfffu64)<=0xffff_ffffu64) by(bit_vector)
            requires raw<=0xfffffu64;
        assert((((low>>40)&0xffu64)|((low>>40)&0xf000u64))<=0xffffu64) by(bit_vector);
    }
    let limit=if low&(1u64<<55)!=0 {((raw<<12)|0xfff) as u32} else {raw as u32};
    let attributes=(((low>>40)&0xff)|((low>>40)&0xf000)) as u16;
    proof {
        assert(base==model::task_image(low,high,selector).base) by(bit_vector)
            requires base==((low>>16)&0x00ff_ffffu64)|((low>>32)&0xff00_0000u64)|((high&0xffff_ffffu64)<<32);
        assert(limit==model::limit(low)) by(bit_vector)
            requires raw==(low&0xffffu64)|((low>>32)&0xf0000u64),
                limit==if low&(1u64<<55)!=0 {((raw<<12)|0xfffu64) as u32} else {raw as u32};
        assert(attributes==model::attributes(low)) by(bit_vector)
            requires attributes==(((low>>40)&0xffu64)|((low>>40)&0xf000u64)) as u16;
    }
    let image=SegmentState {base,limit,selector,attributes:0x8b};
    if selector==0 || selector&7!=0 || attributes!=0x89 || high>>32!=0
        || !super::system::supported_task(image) {return None;}
    Some(image)
}

/// Flat accessed writable GDT data for FS/GS at CPL0, with RPL <= DPL.
pub fn load_thread_data(word:u64,selector:u16)->(out:Option<SegmentState>)
    ensures out==model::load_thread_data(word,selector),
        out.is_some() ==> system::model::data_or_null(out.unwrap()) && out.unwrap().base==0,
{
    let normalized=word&!(3u64<<45);
    let clean=selector&!3u16;
    proof {lemma_flat_correspondence(normalized,clean);}
    let Some(segment)=load_data(normalized,clean) else {return None;};
    let raw_dpl=(word>>45)&3u64;
    assert(raw_dpl<=3) by(bit_vector) requires raw_dpl==(word>>45)&3u64;
    let dpl=raw_dpl as u16;
    if selector&3>dpl {return None;}
    let attributes=0xc093u16|(dpl<<5);
    proof {
        assert(selector>=8 && selector&4u16==0) by(bit_vector)
            requires clean==selector&!3u16,clean!=0,clean&7u16==0;
        assert((attributes&!0x60u16)==0xc093u16 && ((attributes>>5)&3u16)==dpl) by(bit_vector)
            requires attributes==0xc093u16|(dpl<<5),dpl<=3;
        assert(model::base(word)==0 && model::limit(word)==u32::MAX
            && model::attributes(word)==attributes) by(bit_vector)
            requires normalized==word&!(3u64<<45),normalized==0x00cf_9300_0000_ffffu64,
                dpl==((word>>45)&3u64) as u16,attributes==0xc093u16|(dpl<<5);
    }
    Some(SegmentState {selector,attributes,..segment})
}

/// Bounded CPL0 nonconforming readable/accessed long code, L=G=1,
/// D/B=AVL=0. Ignored long-mode base/limit fields are still retained
/// (APM Volume 2 §§4.7.2, 4.8.1).
pub proof fn lemma_flat_code_correspondence(word: u64, selector: u16)
    ensures
        model::admitted_code(word, selector) <==>
            (word == 0x00af_9b00_0000_ffffu64 && selector != 0 && selector & 7u16 == 0),
        model::admitted_code(word, selector) ==>
            system::model::supported_code(model::image(word, selector)),
{
    assert((model::base(word) == 0 && model::limit(word) == u32::MAX
        && model::attributes(word) == 0xa09b)
        <==> word == 0x00af_9b00_0000_ffffu64) by(bit_vector);
}

/// Unsupported images return None, not an architectural exception. Requiring
/// A=1 avoids descriptor writes; R=1 and the flat hidden fields are profile
/// restrictions, not requirements on every architectural long-mode code segment.
pub fn load_code(word: u64, selector: u16) -> (out: Option<SegmentState>)
    ensures
        out == model::load_code(word, selector),
        out.is_some() == model::admitted_code(word, selector),
        match out {
            Some(segment) => segment == model::image(word, selector)
                && system::model::supported_code(segment),
            None => true,
        },
{
    proof { lemma_flat_code_correspondence(word, selector); }
    if selector == 0 || selector & 7 != 0 || word != 0x00af_9b00_0000_ffff {
        return None;
    }
    Some(SegmentState { base: 0, limit: u32::MAX, selector, attributes: 0xa09b })
}

/// This profile requires a present DPL0 expand-up writable accessed data
/// descriptor, G=D/B=1 and AVL=L=0, with base zero and a full 32-bit limit.
pub proof fn lemma_flat_correspondence(word: u64, selector: u16)
    ensures
        model::admitted(word, selector) <==>
            (word == 0x00cf_9300_0000_ffffu64 && selector != 0 && selector & 7u16 == 0),
        model::admitted(word, selector) ==>
            system::model::supported_data(model::image(word, selector)),
{
    assert((model::base(word) == 0 && model::limit(word) == u32::MAX
        && model::attributes(word) == 0xc093)
        <==> word == 0x00cf_9300_0000_ffffu64) by(bit_vector);
}

/// Unsupported images return None, not an architectural exception. In
/// particular A must already be set: this helper cannot perform the required
/// descriptor write for an unaccessed image (APM Volume 2 §4.7.3).
pub fn load_data(word: u64, selector: u16) -> (out: Option<SegmentState>)
    ensures
        out == model::load_data(word, selector),
        out.is_some() == model::admitted(word, selector),
        match out {
            Some(segment) => segment == model::image(word, selector)
                && system::model::supported_data(segment),
            None => true,
        },
{
    let base = ((word >> 16) & 0x00ff_ffff) | ((word >> 32) & 0xff00_0000);
    let raw_limit = (word & 0xffff) | ((word >> 32) & 0x000f_0000);
    proof {
        assert((((word >> 40) & 0xffu64) | ((word >> 40) & 0xf000u64))
            <= 0xffffu64) by(bit_vector);
    }
    let attributes = (((word >> 40) & 0xff) | ((word >> 40) & 0xf000)) as u16;
    proof {
        assert((((word >> 16) & 0x00ff_ffffu64) | ((word >> 32) & 0xff00_0000u64))
            == model::base(word)) by(bit_vector);
        assert(((((word >> 40) & 0xffu64) | ((word >> 40) & 0xf000u64)) as u16)
            == model::attributes(word)) by(bit_vector);
        assert((((word & 0xffffu64) | ((word >> 32) & 0x000f_0000u64)) == 0xfffff
            && model::attributes(word) == 0xc093)
            <==> (model::limit(word) == u32::MAX
                && model::attributes(word) == 0xc093)) by(bit_vector);
    }
    if selector == 0 || selector & 7 != 0 || base != 0
        || raw_limit != 0xfffff || attributes != 0xc093 {
        return None;
    }
    Some(SegmentState { base, limit: u32::MAX, selector, attributes })
}
}
