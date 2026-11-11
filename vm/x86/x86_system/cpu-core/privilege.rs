// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
    // retains MP/NE/AM and PSE/PGE; WP/NXE belong to the MMU configuration.
    // ET is read-only one, PAE/PG/PE stay enabled, and EFER.LMA must be
    // preserved at one along with LME. Other features/mode changes are outside
    // this profile, not necessarily architecturally invalid.
    pub open spec fn cr0(value: u64) -> Option<Cr0> {
        if value & !0x0005_0022u64 != 0x8000_0011u64 { None }
        else { Some(Cr0 { extra: value & 0x0004_0022u64,
            wp: value & 0x0001_0000u64 != 0 }) }
    }
    pub open spec fn cr4(value: u64) -> Option<u64> {
        if value & !0x90u64 != 0x20u64 { None }
        else { Some(value & 0x90u64) }
    }
    pub open spec fn efer(value: u64) -> Option<Efer> {
        if value & !0x801u64 != 0x500u64 { None }
        else { Some(Efer { sce: value & 1u64 != 0, nxe: value & 0x800u64 != 0 }) }
    }
    pub open spec fn read_cr0(extra: u64, wp: bool) -> u64 {
        0x8000_0011u64 | (extra & 0x0004_0022u64) | if wp { 0x10000u64 } else { 0u64 }
    }
    pub open spec fn read_cr4(extra: u64) -> u64 {
        0x20u64 | (extra & 0x90u64)
    }
    pub open spec fn read_efer(sce: bool, nxe: bool) -> u64 {
        0x500u64 | (if sce { 1u64 } else { 0u64 }) | if nxe { 0x800u64 } else { 0u64 }
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
    if value & !0x90u64 != 0x20u64 { None }
    else { Some(value & 0x90u64) }
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
    0x20u64 | (extra & 0x90u64)
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
            Some(image) => image & !0x90u64 == 0 && model::read_cr4(image) == value,
            None => true,
        },
        model::cr4(model::read_cr4(extra)) == Some(extra & 0x90u64),
{
    assert(value & !0x90u64 == 0x20u64 ==> (0x20u64 | (value & 0x90u64)) == value)
        by(bit_vector);
    assert((value & 0x90u64) & !0x90u64 == 0) by(bit_vector);
    assert((value & 0x90u64) & 0x90u64 == value & 0x90u64) by(bit_vector);
    assert((0x20u64 | (extra & 0x90u64)) & !0x90u64 == 0x20u64
        && (0x20u64 | (extra & 0x90u64)) & 0x90u64 == extra & 0x90u64)
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
