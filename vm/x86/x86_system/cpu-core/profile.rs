// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Synthetic AMD first-boot target, not a claim of a complete implemented ISA.
use vstd::prelude::*;

verus! {

// The synthetic AMD profile starts without a microcode patch and has no updater.
pub const MICROCODE_REVISION:u32=0;

// Neither IBPB nor SBPB is exposed by this target; PRED_CMD is absent.
pub const PRED_CMD_AVAILABLE:bool=false;

// Neither legacy core counters nor their extended aliases are implemented.
pub const CORE_PMU_AVAILABLE:bool=false;

pub open spec fn absent_core_pmu(number:u64)->bool {
    !CORE_PMU_AVAILABLE && ((0xc0010000<=number<=0xc0010007)
        || (0xc0010200<=number<=0xc001020b))
}
pub fn core_pmu_absent(number:u64)->(out:bool)
    ensures out==absent_core_pmu(number),
{
    !CORE_PMU_AVAILABLE && ((number>=0xc0010000 && number<=0xc0010007)
        || (number>=0xc0010200 && number<=0xc001020b))
}

// MSRs outside this closed synthetic inventory are architecturally absent.
// Presence is separate from whether every access has an execution model.
pub open spec fn declared_msr(number:u64,apic:bool)->bool {
    matches!(number,0x10 | 0x8b | 0x174 | 0x175 | 0x176
        | 0xc0000080 | 0xc0000081 | 0xc0000082 | 0xc0000083 | 0xc0000084
        | 0xc0000100 | 0xc0000101 | 0xc0000102 | 0xc001001f | 0xc0011029)
        || (apic && (number==0x1b || 0x800<=number<=0x8ff))
        || (PRED_CMD_AVAILABLE && number==0x49)
        || (CORE_PMU_AVAILABLE && ((0xc0010000<=number<=0xc0010007)
            || (0xc0010200<=number<=0xc001020b)))
}
pub fn msr_declared(number:u64,apic:bool)->(out:bool)
    ensures out==declared_msr(number,apic),
{
    matches!(number,0x10 | 0x8b | 0x174 | 0x175 | 0x176
        | 0xc0000080 | 0xc0000081 | 0xc0000082 | 0xc0000083 | 0xc0000084
        | 0xc0000100 | 0xc0000101 | 0xc0000102 | 0xc001001f | 0xc0011029)
        || (apic && (number==0x1b || (number>=0x800 && number<=0x8ff)))
        || (PRED_CMD_AVAILABLE && number==0x49)
        || (CORE_PMU_AVAILABLE && ((number>=0xc0010000 && number<=0xc0010007)
            || (number>=0xc0010200 && number<=0xc001020b)))
}

pub const TSC_HZ:u64=1_000_000_000;

// The initial AMD platform keeps extended CF8 configuration permanently enabled.
pub const NB_CFG:u64=1u64<<46;

// DAZ is not exposed by the bounded legacy SSE state profile.
pub const MXCSR_MASK:u32=0xffbf;

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
