// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::system::SystemState;
#[cfg(verus_keep_ghost)]
use super::system::{self, SegmentState};
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status { Advanced, InvalidLength, DebugRequired, UnsupportedMsr, GeneralProtection }

pub open spec fn value(rax: u64, rdx: u64) -> u64 {
    ((rdx as int % 0x1_0000_0000int) * 0x1_0000_0000int
        + rax as int % 0x1_0000_0000int) as u64
}

pub open spec fn transition(s: SystemState, rip: u64, flags: u64,
    rax: u64, rcx: u64, rdx: u64, length: u8) -> (SystemState, u64, Status) {
    if length != 2 { (s, rip, Status::InvalidLength) }
    else if flags & 0x10100u64 != 0 { (s, rip, Status::DebugRequired) }
    else if rcx as int % 0x1_0000_0000int != 0xc0000101int
        && rcx as int % 0x1_0000_0000int != 0xc0000100int {
        (s, rip, Status::UnsupportedMsr)
    } else if !system::model::canonical(value(rax, rdx)) {
        (s, rip, Status::GeneralProtection)
    } else {
        (if rcx as int % 0x1_0000_0000int==0xc0000100int {
            SystemState {fs:SegmentState {base:value(rax,rdx),..s.fs},..s}
        } else {SystemState { gs: SegmentState { base: value(rax, rdx), ..s.gs }, ..s }},
            ((rip as int + 2) % 0x1_0000_0000_0000_0000int) as u64, Status::Advanced)
    }
}

pub fn commit(s: &mut SystemState, rip: &mut u64, flags: u64,
    rax: u64, rcx: u64, rdx: u64, length: u8) -> (status: Status)
    requires system::model::supported(*old(s)),
    ensures system::model::supported(*final(s)),
        (*final(s), *final(rip), status) ==
            transition(*old(s), *old(rip), flags, rax, rcx, rdx, length),
        status != Status::Advanced ==> *final(s) == *old(s) && *final(rip) == *old(rip),
{
    if length != 2 { return Status::InvalidLength; }
    if flags & 0x10100u64 != 0 { return Status::DebugRequired; }
    if rcx % 0x1_0000_0000u64 != 0xc0000101 && rcx % 0x1_0000_0000u64 != 0xc0000100 {
        return Status::UnsupportedMsr;
    }
    let base = (rdx % 0x1_0000_0000u64) * 0x1_0000_0000u64 + rax % 0x1_0000_0000u64;
    if base >= 0x8000_0000_0000 && base < 0xffff_8000_0000_0000 {
        return Status::GeneralProtection;
    }
    if rcx % 0x1_0000_0000u64==0xc0000100 {s.fs.base=base;}
    else {s.gs.base = base;}
    *rip = (*rip).wrapping_add(2);
    Status::Advanced
}
}
