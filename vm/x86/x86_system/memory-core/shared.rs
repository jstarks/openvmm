// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::shared_model;
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeatError { Width, Split }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exchange { Exchanged, Changed(u64) }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Beat {
    pub(crate) address: u64,
    pub(crate) shift: u32,
    pub(crate) mask: u64,
}

impl View for Beat {
    type V = shared_model::Beat;
    closed spec fn view(&self) -> shared_model::Beat {
        shared_model::Beat { address: self.address, shift: self.shift, mask: self.mask }
    }
}

impl Beat {
    pub(crate) fn masked(address: u64, shift: u32, mask: u64) -> (out: Self)
        requires address % 8 == 0, shift < 64,
        ensures out.valid(), out@.address == address, out@.shift == shift, out@.mask == mask,
    { Self { address, shift, mask } }

    pub closed spec fn valid(&self) -> bool {
        self.address % 8 == 0 && self.shift < 64
    }

    pub fn address(&self) -> (out: u64)
        ensures out == self@.address,
    { self.address }

    pub fn whole(&self) -> (out: bool)
        ensures out == (self@.mask == u64::MAX),
    { self.mask == u64::MAX }

    pub fn extract(&self, word: u64) -> (out: u64)
        requires self.valid(),
        ensures out == ((word & self@.mask) >> self@.shift),
    { (word & self.mask) >> self.shift }

    pub fn replace(&self, word: u64, value: u64) -> (out: u64)
        requires self.valid(),
        ensures out == shared_model::replace(word, value, self@.mask, self@.shift),
            out & !self@.mask == word & !self@.mask,
            out & self@.mask == (value << self@.shift) & self@.mask,
    {
        let mask = self.mask;
        let shift = self.shift;
        let out = (word & !mask) | ((value << shift) & mask);
        assert(out & !mask == word & !mask
            && out & mask == (value << shift) & mask) by(bit_vector)
            requires out == (word & !mask) | ((value << shift) & mask);
        out
    }
}

pub fn plan(address: u64, width: u8) -> (out: Result<Beat, BeatError>)
    ensures
        match out {
            Ok(beat) => beat.valid()
                && beat@.address == address / 8 * 8
                && beat@.shift == (address % 8) * 8
                && beat@.mask == shared_model::mask(width) << (((address % 8) * 8) as u32),
            Err(_) => true,
        },
        (out == Err(BeatError::Width)) == !shared_model::width_supported(width),
        (out == Err(BeatError::Split)) ==
            (shared_model::width_supported(width) && address % 8 + width as u64 > 8),
{
    if width != 1 && width != 2 && width != 4 && width != 8 {
        return Err(BeatError::Width);
    }
    let offset = address % 8;
    if offset + width as u64 > 8 { return Err(BeatError::Split); }
    let mask: u64 = match width {
        1 => 0xff, 2 => 0xffff, 4 => 0xffff_ffff, _ => u64::MAX,
    };
    let shift = (offset * 8) as u32;
    Ok(Beat { address: address / 8 * 8, shift, mask: mask << shift })
}

pub fn ad_value(observed: u64, dirty: bool) -> (out: Option<u64>)
    ensures out == shared_model::ad_value(observed, dirty),
        match out {
            Some(value) => value & !0x60u64 == observed & !0x60u64,
            None => true,
        },
{
    if observed & 1 == 0 { return None; }
    let extra: u64 = if dirty { 64 } else { 0 };
    let out = observed | 32u64 | extra;
    assert(out & !0x60u64 == observed & !0x60u64) by(bit_vector)
        requires out == observed | 32u64 | extra, extra == 0 || extra == 64;
    Some(out)
}

}

/// Platform-neutral coherent WB RAM interface. Implementations share backing
/// with external writers; no operation promises an unchanged whole-RAM image.
/// Accesses preserve WB ordering and may strengthen it. Failed accesses must
/// report an error rather than fabricate data.
/// These signatures are not a proof of a platform implementation's contract.
pub trait PhysicalRam: Send + Sync {
    /// Platform access failure, distinct from an architectural guest exception.
    type Error: core::error::Error + Send + Sync + 'static;

    /// Reads one naturally aligned, non-tearing little-endian quadword.
    fn read_word(&self, address: u64) -> Result<u64, Self::Error>;

    /// Writes one naturally aligned quadword atomically.
    fn write_word(&self, address: u64, value: u64) -> Result<(), Self::Error>;

    /// Atomically compares and replaces one naturally aligned quadword with
    /// full memory-barrier ordering.
    /// Failure returns the observed value, not a stale earlier load.
    fn compare_exchange_word(
        &self,
        address: u64,
        expected: u64,
        replacement: u64,
    ) -> Result<Exchange, Self::Error>;

    /// Orders preceding RAM accesses before following RAM accesses. Translation
    /// invalidation and device-I/O completion are separate responsibilities.
    fn barrier(&self);
}
