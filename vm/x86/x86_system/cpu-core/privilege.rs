// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::State;
use super::system::{CODE_SEGMENT, DATA_SEGMENT, EntryMsrs, SegmentState, SystemState};
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub struct Cr0 {
    pub extra: u64,
    pub wp: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub struct Efer {
    pub sce: bool,
    pub nxe: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum FastStatus { Advanced, InvalidOpcode, GeneralProtection }

pub mod model {
    #[cfg(verus_keep_ghost)]
    use super::*;

    // APM Volume 2 §§3.1.1, 3.1.3, 3.1.7. This bounded long64 profile
    // retains MP/NE/AM and PSE/PGE/OSFXSR/OSXMMEXCPT; WP/NXE belong to the MMU configuration.
    // ET is read-only one, PAE/PG/PE stay enabled, and EFER.LMA must be
    // preserved at one along with LME. Other features/mode changes are outside
    // this profile, not necessarily architecturally invalid.
    pub open spec fn cr0(value: u64) -> Option<Cr0> {
        if value & !0x0005_0022u64 != 0x8000_0011u64 { None }
        else { Some(Cr0 { extra: value & 0x0004_0022u64,
            wp: value & 0x0001_0000u64 != 0 }) }
    }
    pub open spec fn cr4(value: u64) -> Option<u64> {
        if value & !0x690u64 != 0x20u64 { None }
        else { Some(value & 0x690u64) }
    }
    pub open spec fn efer(value: u64) -> Option<Efer> {
        if value & !0x801u64 != 0x500u64 { None }
        else { Some(Efer { sce: value & 1u64 != 0, nxe: value & 0x800u64 != 0 }) }
    }
    pub open spec fn read_cr0(extra: u64, wp: bool) -> u64 {
        0x8000_0011u64 | (extra & 0x0004_0022u64) | if wp { 0x10000u64 } else { 0u64 }
    }
    pub open spec fn read_cr4(extra: u64) -> u64 {
        0x20u64 | (extra & 0x690u64)
    }
    pub open spec fn read_efer(sce: bool, nxe: bool) -> u64 {
        0x500u64 | (if sce { 1u64 } else { 0u64 }) | if nxe { 0x800u64 } else { 0u64 }
    }
    pub open spec fn read_entry(s:EntryMsrs,number:u64)->Option<u64> {
        match number {
            0xc0000081=>Some(s.star),0xc0000082=>Some(s.lstar),0xc0000083=>Some(s.cstar),
            0xc0000084=>Some(s.sfmask),0x174=>Some(s.sysenter_cs),0x175=>Some(s.sysenter_esp),
            0x176=>Some(s.sysenter_eip),0xc0000102=>Some(s.kernel_gs_base),_=>None,
        }
    }
    pub open spec fn write_entry(s:EntryMsrs,number:u64,value:u64)->Option<EntryMsrs> {
        if (number==0xc0000082 || number==0xc0000083 || number==0xc0000102)
            && !super::super::system::model::canonical(value) {None}
        else {match number {
            0xc0000081=>Some(EntryMsrs {star:value,..s}),
            0xc0000082=>Some(EntryMsrs {lstar:value,..s}),
            0xc0000083=>Some(EntryMsrs {cstar:value,..s}),
            0xc0000084=>if value>0xffff_ffff {None} else {Some(EntryMsrs {sfmask:value,..s})},
            0x174=>if value>0xffff {None} else {Some(EntryMsrs {sysenter_cs:value,..s})},
            0x175=>Some(EntryMsrs {sysenter_esp:value&0xffff_ffffu64,..s}),
            0x176=>Some(EntryMsrs {sysenter_eip:value&0xffff_ffffu64,..s}),
            0xc0000102=>Some(EntryMsrs {kernel_gs_base:value,..s}),_=>None,
        }}
    }

    pub open spec fn long64(s:SystemState)->bool {
        s.cs.attributes&!0x60u16==0xa09b
            && s.cs.selector&3u16==(s.cs.attributes>>5)&3u16
    }
    pub open spec fn flags64(flags:u64)->bool {
        flags&!0x3d7fd7u64==0 && flags&2u64!=0
    }
    pub open spec fn syscall64(cpu:super::super::model::State,s:SystemState,length:u8)
        ->(super::super::model::State,SystemState,FastStatus)
    {
        if !s.efer_sce {(cpu,s,FastStatus::InvalidOpcode)}
        else {
            let selector=((s.entry.star>>32)&0xffffu64) as u16;
            (super::super::model::State {
                gpr:cpu.gpr.update(1,(cpu.rip+length as int)%0x1_0000_0000_0000_0000int)
                    .update(11,(cpu.flags&!0x10000u64) as int),
                rip:s.entry.lstar as int,
                flags:(cpu.flags&!s.entry.sfmask&!0x10000u64)|2u64,
            },SystemState {
                cs:SegmentState {selector:selector&!3u16,..CODE_SEGMENT},
                ss:SegmentState {selector:((selector as int+8)%0x10000) as u16,..DATA_SEGMENT},
                ..s
            },FastStatus::Advanced)
        }
    }
    pub open spec fn sysret64(cpu:super::super::model::State,s:SystemState)
        ->(super::super::model::State,SystemState,FastStatus)
    {
        if !s.efer_sce {(cpu,s,FastStatus::InvalidOpcode)}
        else if s.cs.selector&3u16!=0 {(cpu,s,FastStatus::GeneralProtection)}
        else {
            let selector=(s.entry.star>>48) as u16;
            (super::super::model::State {
                rip:cpu.gpr[1],flags:((cpu.gpr[11] as u64)&0x3c7fd5u64)|2u64,..cpu
            },SystemState {
                cs:SegmentState {selector:(((selector as int+16)%0x10000) as u16)|3u16,
                    attributes:0xa0fb,..CODE_SEGMENT},
                ss:SegmentState {selector:((selector as int+8)%0x10000) as u16,..s.ss},
                ..s
            },FastStatus::Advanced)
        }
    }
}

/// Long64 instruction-body proposal, not event/MMU publication. The caller
/// owns decoding, CET exclusion and the atomic CPL/segment/MMU boundary.
/// APM Vol. 3 pp. 488-490: no stack switch, GS exchange or descriptor read.
pub fn syscall64(cpu:&mut State,s:&mut SystemState,length:u8)->(status:FastStatus)
    requires model::long64(*old(s)),model::flags64(old(cpu).flags),2<=length<=15,
    ensures
        (final(cpu)@,*final(s),status)==model::syscall64(old(cpu)@,*old(s),length),
        model::long64(*final(s)),model::flags64(final(cpu).flags),
        final(cpu).gpr@[4]==old(cpu).gpr@[4],
        final(s).gs==old(s).gs,final(s).entry==old(s).entry,
        status!=FastStatus::Advanced ==> final(cpu)@==old(cpu)@ && *final(s)==*old(s),
{
    if !s.efer_sce {return FastStatus::InvalidOpcode;}
    let ghost before=cpu@;
    let flags=cpu.flags;
    let mask=s.entry.sfmask;
    let live=(flags&!mask&!0x10000u64)|2u64;
    let next=cpu.rip.wrapping_add(length as u64);
    cpu.gpr[1]=next;
    cpu.gpr[11]=flags&!0x10000u64;
    assert(cpu@.gpr =~= before.gpr.update(1,next as int).update(11,(flags&!0x10000u64) as int));
    cpu.rip=s.entry.lstar;
    cpu.flags=live;
    let star=s.entry.star;
    let raw=(star>>32)&0xffff;
    assert(raw<=0xffffu64) by(bit_vector) requires raw==(star>>32)&0xffffu64;
    let selector=raw as u16;
    s.cs=SegmentState {selector:selector&!3u16,..CODE_SEGMENT};
    s.ss=SegmentState {selector:selector.wrapping_add(8),..DATA_SEGMENT};
    proof {
        assert((selector&!3u16)&3u16==((0xa09bu16>>5)&3u16)
            && 0xa09bu16&!0x60u16==0xa09bu16) by(bit_vector);
        assert(live&!0x3d7fd7u64==0 && live&2u64!=0) by(bit_vector)
            requires flags&!0x3d7fd7u64==0,
                live==(flags&!mask&!0x10000u64)|2u64;
    }
    FastStatus::Advanced
}

/// APM Vol. 3 pp. 495-498: AMD preserves hidden SS metadata, takes SS.RPL
/// from STAR, and does not check RCX canonicality here. A bad target faults on the
/// subsequent user fetch, not at SYSRET with kernel privilege.
pub fn sysret64(cpu:&mut State,s:&mut SystemState)->(status:FastStatus)
    requires model::long64(*old(s)),model::flags64(old(cpu).flags),
    ensures
        (final(cpu)@,*final(s),status)==model::sysret64(old(cpu)@,*old(s)),
        model::long64(*final(s)),model::flags64(final(cpu).flags),
        final(cpu).gpr@==old(cpu).gpr@,
        final(s).ss.base==old(s).ss.base,final(s).ss.limit==old(s).ss.limit,
        final(s).ss.attributes==old(s).ss.attributes,
        final(s).gs==old(s).gs,final(s).entry==old(s).entry,
        status!=FastStatus::Advanced ==> final(cpu)@==old(cpu)@ && *final(s)==*old(s),
{
    if !s.efer_sce {return FastStatus::InvalidOpcode;}
    if s.cs.selector&3!=0 {return FastStatus::GeneralProtection;}
    cpu.rip=cpu.gpr[1];
    let saved=cpu.gpr[11];
    let flags=(saved&0x3c7fd5)|2;
    cpu.flags=flags;
    let selector=(s.entry.star>>48) as u16;
    let index=selector.wrapping_add(16);
    let cs=index|3;
    s.cs=SegmentState {selector:cs,attributes:0xa0fb,..CODE_SEGMENT};
    s.ss.selector=selector.wrapping_add(8);
    proof {
        assert(cs&3u16==((0xa0fbu16>>5)&3u16)
            && 0xa0fbu16&!0x60u16==0xa09bu16) by(bit_vector)
            requires cs==index|3u16;
        assert(flags&!0x3d7fd7u64==0 && flags&2u64!=0) by(bit_vector)
            requires flags==(saved&0x3c7fd5u64)|2u64;
    }
    FastStatus::Advanced
}

pub proof fn lemma_fast_round_trip(cpu:super::model::State,s:SystemState,length:u8)
    requires cpu.gpr.len()==16,model::flags64(cpu.flags),model::long64(s),
        s.efer_sce,2<=length<=15,
    ensures ({
        let entered=model::syscall64(cpu,s,length);
        let returned=model::sysret64(entered.0,entered.1);
        returned.2==FastStatus::Advanced
            && returned.0.rip==(cpu.rip+length as int)%0x1_0000_0000_0000_0000int
            && returned.0.flags==cpu.flags&!0x10000u64
            && returned.0.gpr==entered.0.gpr
            && returned.0.gpr[4]==cpu.gpr[4]
            && returned.1.gs==s.gs && returned.1.entry==s.entry
    }),
{
    let selector=((s.entry.star>>32)&0xffffu64) as u16;
    let flags=cpu.flags;
    assert((selector&!3u16)&3u16==0) by(bit_vector);
    assert(((flags&!0x10000u64)&0x3c7fd5u64)|2u64==flags&!0x10000u64) by(bit_vector)
        requires flags&!0x3d7fd7u64==0,flags&2u64!=0;
}

pub fn read_entry(s:EntryMsrs,number:u64)->(out:Option<u64>)
    ensures out==model::read_entry(s,number),
{
    match number {
        0xc0000081=>Some(s.star),0xc0000082=>Some(s.lstar),0xc0000083=>Some(s.cstar),
        0xc0000084=>Some(s.sfmask),0x174=>Some(s.sysenter_cs),0x175=>Some(s.sysenter_esp),
        0x176=>Some(s.sysenter_eip),0xc0000102=>Some(s.kernel_gs_base),_=>None,
    }
}
pub fn write_entry(s:EntryMsrs,number:u64,value:u64)->(out:Option<EntryMsrs>)
    ensures out==model::write_entry(s,number,value),
{
    if (number==0xc0000082 || number==0xc0000083 || number==0xc0000102)
        && !(value<0x8000_0000_0000 || value>=0xffff_8000_0000_0000) {return None;}
    match number {
        0xc0000081=>Some(EntryMsrs {star:value,..s}),
        0xc0000082=>Some(EntryMsrs {lstar:value,..s}),
        0xc0000083=>Some(EntryMsrs {cstar:value,..s}),
        0xc0000084=>if value>0xffff_ffff {None} else {Some(EntryMsrs {sfmask:value,..s})},
        0x174=>if value>0xffff {None} else {Some(EntryMsrs {sysenter_cs:value,..s})},
        0x175=>Some(EntryMsrs {sysenter_esp:value&0xffff_ffff,..s}),
        0x176=>Some(EntryMsrs {sysenter_eip:value&0xffff_ffff,..s}),
        0xc0000102=>Some(EntryMsrs {kernel_gs_base:value,..s}),_=>None,
    }
}

/// Pure image validation: None is an explicit unsupported-state diagnostic.
/// The caller commits core state and reloads the quiescent MMU on success.
pub fn cr0(value: u64) -> (out: Option<Cr0>)
    ensures out == model::cr0(value),
{
    if value & !0x0005_0022u64 != 0x8000_0011u64 { None }
    else { Some(Cr0 { extra: value & 0x0004_0022u64,
        wp: value & 0x0001_0000u64 != 0 }) }
}

pub fn cr4(value: u64) -> (out: Option<u64>)
    ensures out == model::cr4(value),
{
    if value & !0x690u64 != 0x20u64 { None }
    else { Some(value & 0x690u64) }
}

pub fn efer(value: u64) -> (out: Option<Efer>)
    ensures out == model::efer(value),
{
    if value & !0x801u64 != 0x500u64 { None }
    else { Some(Efer { sce: value & 1u64 != 0, nxe: value & 0x800u64 != 0 }) }
}

/// Only the declared stored control bits contribute to the read image.
pub fn read_cr0(extra: u64, wp: bool) -> (out: u64)
    ensures out == model::read_cr0(extra, wp),
{
    0x8000_0011u64 | (extra & 0x0004_0022u64) | if wp { 0x10000u64 } else { 0u64 }
}

pub fn read_cr4(extra: u64) -> (out: u64)
    ensures out == model::read_cr4(extra),
{
    0x20u64 | (extra & 0x690u64)
}

pub fn read_efer(sce: bool, nxe: bool) -> (out: u64)
    ensures out == model::read_efer(sce, nxe),
{
    0x500u64 | (if sce { 1u64 } else { 0u64 }) | if nxe { 0x800u64 } else { 0u64 }
}

pub proof fn lemma_cr0_round_trip(value: u64, extra: u64, wp: bool)
    ensures
        match model::cr0(value) {
            Some(image) => image.extra & !0x40022u64 == 0
                && model::read_cr0(image.extra, image.wp) == value,
            None => true,
        },
        model::cr0(model::read_cr0(extra, wp))
            == Some(Cr0 { extra: extra & 0x40022u64, wp }),
{
    assert(value & !0x50022u64 == 0x80000011u64 ==>
        (0x80000011u64 | (value & 0x40022u64)
            | (if value & 0x10000u64 != 0 { 0x10000u64 } else { 0u64 })) == value)
        by(bit_vector);
    assert((value & 0x40022u64) & !0x40022u64 == 0) by(bit_vector);
    assert((value & 0x40022u64) & 0x40022u64 == value & 0x40022u64)
        by(bit_vector);
    let read = 0x80000011u64 | (extra & 0x40022u64)
        | (if wp { 0x10000u64 } else { 0u64 });
    assert(read & !0x50022u64 == 0x80000011u64
        && read & 0x40022u64 == extra & 0x40022u64
        && (read & 0x10000u64 != 0) == wp) by(bit_vector)
        requires read == (0x80000011u64 | (extra & 0x40022u64)
            | (if wp { 0x10000u64 } else { 0u64 }));
}

pub proof fn lemma_cr4_round_trip(value: u64, extra: u64)
    ensures
        match model::cr4(value) {
            Some(image) => image & !0x690u64 == 0 && model::read_cr4(image) == value,
            None => true,
        },
        model::cr4(model::read_cr4(extra)) == Some(extra & 0x690u64),
{
    assert(value & !0x690u64 == 0x20u64 ==> (0x20u64 | (value & 0x690u64)) == value)
        by(bit_vector);
    assert((value & 0x690u64) & !0x690u64 == 0) by(bit_vector);
    assert((value & 0x690u64) & 0x690u64 == value & 0x690u64) by(bit_vector);
    assert((0x20u64 | (extra & 0x690u64)) & !0x690u64 == 0x20u64
        && (0x20u64 | (extra & 0x690u64)) & 0x690u64 == extra & 0x690u64)
        by(bit_vector);
}

pub proof fn lemma_efer_round_trip(value: u64, sce: bool, nxe: bool)
    ensures
        match model::efer(value) {
            Some(image) => model::read_efer(image.sce, image.nxe) == value,
            None => true,
        },
        model::efer(model::read_efer(sce, nxe)) == Some(Efer { sce, nxe }),
{
    assert(value & !0x801u64 == 0x500u64 ==>
        (0x500u64 | (if value & 1u64 != 0 { 1u64 } else { 0u64 })
            | (if value & 0x800u64 != 0 { 0x800u64 } else { 0u64 })) == value)
        by(bit_vector);
    let read = 0x500u64 | (if sce { 1u64 } else { 0u64 })
        | (if nxe { 0x800u64 } else { 0u64 });
    assert(read & !0x801u64 == 0x500u64
        && (read & 1u64 != 0) == sce && (read & 0x800u64 != 0) == nxe) by(bit_vector)
        requires read == (0x500u64 | (if sce { 1u64 } else { 0u64 })
            | (if nxe { 0x800u64 } else { 0u64 }));
}
}
