// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Synthetic AMD first-boot target, not a claim of a complete implemented ISA.
use vstd::prelude::*;

verus! {

// The synthetic AMD profile starts without a microcode patch and has no updater.
pub const MICROCODE_REVISION:u32=0;

// Neither IBPB nor SBPB is exposed by this target; PRED_CMD is absent.
pub const PRED_CMD_AVAILABLE:bool=false;

pub open spec fn target(function: u32, _subleaf: u32) -> [u32; 4] {
    match function {
        0 => [1, 0x6874_7541, 0x444d_4163, 0x6974_6e65],
        1 => [0x00a0_0f11, 0x0001_0000, 0, 0x0780_a179],
        0x8000_0000 => [0x8000_0008, 0, 0, 0],
        0x8000_0001 => [0, 0, 0, 0x2190_a979],
        0x8000_0008 => [0x3030, 0, 0, 0],
        _ => [0, 0, 0, 0],
    }
}

pub fn cpuid(function: u32, _subleaf: u32) -> (out: [u32; 4])
    ensures out == target(function, _subleaf),
{
    match function {
        0 => [1, 0x6874_7541, 0x444d_4163, 0x6974_6e65],
        1 => [0x00a0_0f11, 0x0001_0000, 0, 0x0780_a179],
        0x8000_0000 => [0x8000_0008, 0, 0, 0],
        0x8000_0001 => [0, 0, 0, 0x2190_a979],
        0x8000_0008 => [0x3030, 0, 0, 0],
        _ => [0, 0, 0, 0],
    }
}
}
