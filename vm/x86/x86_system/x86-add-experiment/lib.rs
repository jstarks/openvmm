// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![forbid(unsafe_code)]
use vstd::prelude::*;

pub mod model;

verus! {

pub const MASK: u64 = 0x8d5;
pub const HALF: u64 = 0x8000_0000_0000_0000;

pub struct Outcome {
    pub result: u64,
    pub cf: bool,
    pub pf: bool,
    pub af: bool,
    pub zf: bool,
    pub sf: bool,
    pub of: bool,
}

impl View for Outcome {
    type V = model::Outcome;
    open spec fn view(&self) -> model::Outcome {
        model::Outcome {
            result: self.result as int,
            cf: self.cf, pf: self.pf, af: self.af,
            zf: self.zf, sf: self.sf, of: self.of,
        }
    }
}

pub fn parity(byte: u8) -> (even: bool)
    ensures even == (model::population(byte as int) % 2 == 0),
{
    let mut rest = byte;
    let mut count: u8 = 0;
    while rest != 0
        invariant
            count as int + model::population(rest as int)
                == model::population(byte as int),
            count as int + rest as int <= 255,
        decreases rest,
    {
        proof { reveal(model::population); }
        count = count + rest % 2;
        rest = rest / 2;
    }
    proof { reveal(model::population); }
    count % 2 == 0
}

pub fn add64(a: u64, b: u64) -> (out: Outcome)
    ensures
        out@ == model::add(a as int, b as int),
        out.cf == model::add(a as int, b as int).cf,
        out.of == model::add(a as int, b as int).of,
        out.af == model::add(a as int, b as int).af,
        out.pf == model::add(a as int, b as int).pf,
{
    let sum = (a as u128) + (b as u128);
    let result = (sum % 18446744073709551616u128) as u64;
    let cf = sum > (u64::MAX as u128);
    let of = (a >= HALF) == (b >= HALF) && (a >= HALF) != (result >= HALF);
    let af = (a % 16) + (b % 16) >= 16;
    let pf = parity((result % 256) as u8);
    proof {
        assert(result as int == (a as int + b as int) % model::modulus());
        assert(cf == model::add(a as int, b as int).cf);
        assert(of == model::add(a as int, b as int).of);
        assert(af == model::add(a as int, b as int).af);
        assert(pf == model::add(a as int, b as int).pf);
    }
    Outcome { result, cf, pf, af, zf: result == 0, sf: result >= HALF, of }
}

pub fn adc64(a: u64, b: u64, carry_in: bool) -> (out: Outcome)
    ensures
        out@ == model::adc(a as int, b as int, carry_in),
        out.result as int == model::adc(a as int, b as int, carry_in).result,
        out.cf == model::adc(a as int, b as int, carry_in).cf,
        out.of == model::adc(a as int, b as int, carry_in).of,
        out.af == model::adc(a as int, b as int, carry_in).af,
        out.pf == model::adc(a as int, b as int, carry_in).pf,
        out.zf == model::adc(a as int, b as int, carry_in).zf,
        out.sf == model::adc(a as int, b as int, carry_in).sf,
{
    let incoming = if carry_in { 1u128 } else { 0u128 };
    let wide = (a as u128) + (b as u128) + incoming;
    let value = (wide % 18446744073709551616u128) as u64;
    let carry_out = wide > (u64::MAX as u128);
    let overflow = (a >= HALF) == (b >= HALF) && (a >= HALF) != (value >= HALF);
    let auxiliary = (a % 16) + (b % 16) + (incoming as u64) >= 16;
    let even = parity((value % 256) as u8);
    proof {
        assert(value as int == model::adc(a as int, b as int, carry_in).result);
        assert(carry_out == model::adc(a as int, b as int, carry_in).cf);
        assert(overflow == model::adc(a as int, b as int, carry_in).of);
        assert(auxiliary == model::adc(a as int, b as int, carry_in).af);
        assert(even == model::adc(a as int, b as int, carry_in).pf);
    }
    Outcome {
        result: value, cf: carry_out, pf: even, af: auxiliary,
        zf: value == 0, sf: value >= HALF, of: overflow,
    }
}

pub struct TwoWord {
    pub low: u64,
    pub high: u64,
    pub carry: bool,
}

impl View for TwoWord {
    type V = model::TwoWord;
    open spec fn view(&self) -> model::TwoWord {
        model::TwoWord { low: self.low as int, high: self.high as int, carry: self.carry }
    }
}

pub fn add_two_words(al: u64, ah: u64, bl: u64, bh: u64) -> (out: TwoWord)
    ensures
        out@ == model::add_two(al as int, ah as int, bl as int, bh as int),
        out.low as int + out.high as int * model::modulus()
            == model::total(al as int, ah as int, bl as int, bh as int)
                % model::wide_modulus(),
        out.carry == (model::total(al as int, ah as int, bl as int, bh as int)
            >= model::wide_modulus()),
{
    let low = add64(al, bl);
    let high = adc64(ah, bh, low.cf);
    let final_carry = high.cf;
    proof {
        let math_low = model::add(al as int, bl as int);
        let math_high = model::adc(ah as int, bh as int, math_low.cf);
        model::two_word_composition(
            al as int, ah as int, bl as int, bh as int, math_low, math_high,
        );
        assert(low.result as int + high.result as int * model::modulus()
            == model::total(al as int, ah as int, bl as int, bh as int)
                % model::wide_modulus());
        assert(final_carry == (model::total(al as int, ah as int, bl as int, bh as int)
            >= model::wide_modulus()));
    }
    TwoWord { low: low.result, high: high.result, carry: final_carry }
}

// This is an ALU merge, not complete instruction retirement.
pub fn merge_flags(old: u64, out: &Outcome) -> (flags: u64)
    ensures
        flags & !MASK == old & !MASK,
        flags & 1 != 0 == out.cf,
        flags & 4 != 0 == out.pf,
        flags & 16 != 0 == out.af,
        flags & 64 != 0 == out.zf,
        flags & 128 != 0 == out.sf,
        flags & 2048 != 0 == out.of,
{
    let cf = out.cf;
    let pf = out.pf;
    let af = out.af;
    let zf = out.zf;
    let sf = out.sf;
    let of = out.of;
    let bits = (if cf { 1u64 } else { 0 })
        | (if pf { 4u64 } else { 0 })
        | (if af { 16u64 } else { 0 })
        | (if zf { 64u64 } else { 0 })
        | (if sf { 128u64 } else { 0 })
        | (if of { 2048u64 } else { 0 });
    let flags = (old & !MASK) | bits;
    let ghost expected = (old & !MASK) | bits;
    assert(
        expected & !MASK == old & !MASK
        && (expected & 1 != 0) == cf
        && (expected & 4 != 0) == pf
        && (expected & 16 != 0) == af
        && (expected & 64 != 0) == zf
        && (expected & 128 != 0) == sf
        && (expected & 2048 != 0) == of
    ) by(bit_vector)
        requires
            MASK == 0x8d5u64,
            expected == (old & !MASK) | bits,
            bits == (if cf { 1u64 } else { 0 })
                | (if pf { 4u64 } else { 0 })
                | (if af { 16u64 } else { 0 })
                | (if zf { 64u64 } else { 0 })
                | (if sf { 128u64 } else { 0 })
                | (if of { 2048u64 } else { 0 }),
        ;
    assert(flags & !MASK == old & !MASK);
    flags
}

}
