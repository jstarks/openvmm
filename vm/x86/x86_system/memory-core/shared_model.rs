// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use vstd::prelude::*;

verus! {

pub struct Beat {
    pub address: u64,
    pub shift: u32,
    pub mask: u64,
}

pub open spec fn width_supported(width: u8) -> bool {
    width == 1 || width == 2 || width == 4 || width == 8
}

pub open spec fn mask(width: u8) -> u64 {
    if width == 1 { 0xffu64 }
    else if width == 2 { 0xffffu64 }
    else if width == 4 { 0xffff_ffffu64 }
    else { u64::MAX }
}

pub open spec fn replace(word: u64, value: u64, mask: u64, shift: u32) -> u64 {
    (word & !mask) | ((value << shift) & mask)
}

pub open spec fn ad_value(observed: u64, dirty: bool) -> Option<u64> {
    if observed & 1 == 0 { None }
    else { Some(observed | 32u64 | if dirty { 64u64 } else { 0u64 }) }
}

}
