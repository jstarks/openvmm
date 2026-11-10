// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use super::system;
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    Ready { target: u64, return_address: u64, stack: u64 },
    InvalidLength, DebugRequired, UnsupportedTarget, UnsupportedStack,
}

pub open spec fn plan(rip: u64, rsp: u64, flags: u64, displacement: i32, length: u8) -> Plan {
    let next = ((rip as int + length as int) % 0x1_0000_0000_0000_0000int) as u64;
    let target = ((next as int + displacement as int) % 0x1_0000_0000_0000_0000int) as u64;
    if length != 5 { Plan::InvalidLength }
    else if flags & 0x10100u64 != 0 { Plan::DebugRequired }
    else if !system::model::canonical(target) { Plan::UnsupportedTarget }
    else if rsp < 8 || rsp as int % 8 != 0
        || !system::model::canonical((rsp - 8) as u64) { Plan::UnsupportedStack }
    else { Plan::Ready { target, return_address: next, stack: (rsp - 8) as u64 } }
}

/// Plans only canonical targets and aligned single-page pushes.
/// Other targets are diagnostic: architectural CALL validates them after pushing.
pub fn prepare(rip: u64, rsp: u64, flags: u64, displacement: i32, length: u8) -> (out: Plan)
    ensures out == plan(rip, rsp, flags, displacement, length),
        match out {
            Plan::Ready { target, return_address, stack } =>
                system::model::canonical(target) && system::model::canonical(stack)
                && stack as int + 8 == rsp as int && stack as int % 8 == 0
                && stack as int % 4096 <= 4088
                && return_address as int == (rip as int + 5) % 0x1_0000_0000_0000_0000int,
            _ => true,
        },
{
    if length != 5 { return Plan::InvalidLength; }
    if flags & 0x10100u64 != 0 { return Plan::DebugRequired; }
    let next = rip.wrapping_add(length as u64);
    let target = if displacement >= 0 {
        next.wrapping_add(displacement as u64)
    } else {
        next.wrapping_sub((-(displacement as i64)) as u64)
    };
    if target >= 0x8000_0000_0000 && target < 0xffff_8000_0000_0000 {
        return Plan::UnsupportedTarget;
    }
    if rsp < 8 || rsp % 8 != 0 { return Plan::UnsupportedStack; }
    let stack = rsp - 8;
    if stack >= 0x8000_0000_0000 && stack < 0xffff_8000_0000_0000 {
        return Plan::UnsupportedStack;
    }
    assert(stack % 4096 <= 4088) by(nonlinear_arith)
        requires stack % 8 == 0;
    Plan::Ready { target, return_address: next, stack }
}
}
