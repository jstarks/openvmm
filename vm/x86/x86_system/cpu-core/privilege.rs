// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::system::EntryMsrs;
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
