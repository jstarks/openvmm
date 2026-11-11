// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{integer, operand::Width};
use vstd::prelude::*;

// AMD APM Volume 3, revision 3.39: BT/BTC/BTR/BTS, CBW/CWDE/CDQE,
// CWD/CDQ/CQO and DIV/IDIV. This module owns only register-value semantics.
pub mod model {
    #[cfg(verus_keep_ghost)]
    use super::*;
    use vstd::prelude::*;
    verus! {
    pub open spec fn extend(value: u64, width: Width) -> u64 {
        let mask = super::super::operand::model::mask(width);
        let low = value & mask;
        if low & (1u64 << (super::super::operand::model::bits(width) - 1)) != 0 {
            low | !mask
        } else { low }
    }

    pub open spec fn scan_bits(value:u64,bits:u32,reverse:bool)->Option<u64>
        decreases bits,
    {
        if bits==0 || value==0 {None}
        else if !reverse && value&1u64!=0 {Some(0)}
        else {match scan_bits(value>>1,(bits-1) as u32,reverse) {
            Some(index)=>Some((index+1) as u64),
            None=>if value&1u64!=0 {Some(0)} else {None},
        }}
    }

    #[verifier::opaque]
    pub open spec fn scan(value:u64,width:Width,reverse:bool)->Option<u64> {
        scan_bits(value & super::super::operand::model::mask(width),
            super::super::operand::model::bits(width),reverse)
    }

    pub open spec fn sign_high(value: u64, width: Width) -> u64 {
        let mask = super::super::operand::model::mask(width);
        if value & (1u64 << (super::super::operand::model::bits(width) - 1)) != 0 {
            mask
        } else { 0 }
    }

    #[verifier::opaque]
    pub open spec fn multiply_wide(left:u64,right:u64,width:Width,signed:bool,flags:u64)->Product {
        let mask=super::super::operand::model::mask(width);
        let bits=super::super::operand::model::bits(width);
        let product=if signed {
            integer::signed((left&mask) as int,integer::modulus(width))
                *integer::signed((right&mask) as int,integer::modulus(width))
        } else {(left&mask) as int*(right&mask) as int};
        let exact=(product%0x1_0000_0000_0000_0000_0000_0000_0000_0000int) as u128;
        let low=(exact as u64)&mask;
        let high=((exact>>bits) as u64)&mask;
        let overflow=if signed {high!=sign_high(low,width)} else {high!=0};
        Product {low,high,flags:(flags&!0x801u64)|if overflow {0x801u64} else {0u64}}
    }

    pub open spec fn bit(operation: BitOperation, value: u64, index: u64,
        width: Width, flags: u64) -> integer::Outcome
    {
        let mask = super::super::operand::model::mask(width);
        let selected = 1u64 << (index % super::super::operand::model::bits(width) as u64);
        let low = value & mask;
        integer::Outcome {
            value: match operation {
                BitOperation::Test => low,
                BitOperation::Set => (low | selected) & mask,
                BitOperation::Reset => low & !selected,
                BitOperation::Complement => (low ^ selected) & mask,
            },
            flags: (flags & !1u64) | (if low & selected != 0 { 1u64 } else { 0u64 }),
            write: operation != BitOperation::Test,
        }
    }

    pub open spec fn modulus(width: Width) -> u128 {
        if width == Width::Dword { 0x1_0000_0000u128 }
        else { 0x1_0000_0000_0000_0000u128 }
    }

    pub open spec fn raw(high: u64, low: u64, width: Width) -> u128 {
        let mask = super::super::operand::model::mask(width);
        (((high & mask) as u128) << super::super::operand::model::bits(width))
            | (low & mask) as u128
    }

    pub open spec fn full_mask(width: Width) -> u128 {
        if width == Width::Dword { 0xffff_ffff_ffff_ffffu128 } else { u128::MAX }
    }

    pub open spec fn negative(value: u64, width: Width) -> bool {
        value & (1u64 << (super::super::operand::model::bits(width) - 1)) != 0
    }

    pub open spec fn dividend_magnitude(high: u64, low: u64, width: Width,
        signed: bool) -> u128
    {
        let value = raw(high, low, width);
        if signed && negative(high, width) { ((value ^ full_mask(width)) + 1) as u128 }
        else { value }
    }

    pub open spec fn divisor_magnitude(divisor: u64, width: Width, signed: bool) -> u128 {
        let value = divisor & super::super::operand::model::mask(width);
        if signed && negative(divisor, width) { (modulus(width) - value as u128) as u128 }
        else { value as u128 }
    }

    pub open spec fn encode(value: u128, negative: bool, width: Width) -> u64 {
        if negative && value != 0 { (modulus(width) - value) as u64 }
        else { value as u64 }
    }

    /// Division of positive magnitudes supplies truncation toward zero for
    /// either sign, including a dividend whose magnitude is 2^127.
    pub open spec fn divide(high: u64, low: u64, divisor: u64, width: Width,
        signed: bool) -> Option<Division>
    {
        if width != Width::Dword && width != Width::Qword { None }
        else {
            let d = divisor_magnitude(divisor, width, signed);
            if d == 0 { None }
            else {
                let n = dividend_magnitude(high, low, width, signed);
                let q = n / d;
                let r = n % d;
                let q_negative = signed && (negative(high, width) != negative(divisor, width));
                let limit = if !signed { (modulus(width) - 1) as u128 }
                    else if q_negative { modulus(width) / 2 }
                    else { (modulus(width) / 2 - 1) as u128 };
                if q > limit { None }
                else { Some(Division {
                    quotient: encode(q, q_negative, width),
                    remainder: encode(r, signed && negative(high, width), width),
                }) }
            }
        }
    }
    }
}

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum BitOperation { Test, Set, Reset, Complement }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Division {
    pub quotient: u64,
    pub remainder: u64,
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Product {pub low:u64,pub high:u64,pub flags:u64}

pub fn multiply_wide(left:u64,right:u64,width:Width,signed:bool,flags:u64)->(out:Product)
    ensures out==model::multiply_wide(left,right,width,signed,flags),
{
    reveal(model::multiply_wide);
    let mask=width.mask();
    let bits=width.bits();
    let a=left&mask;
    let b=right&mask;
    let exact=if signed {
        let modulus=mask as u128+1;
        proof {assert(a<=mask && b<=mask) by(bit_vector)
            requires a==left&mask,b==right&mask;}
        let exact=integer::signed_product(a,b,width,modulus);
        if exact<0 {0u128.wrapping_sub((-exact) as u128)} else {exact as u128}
    } else {
        proof {
            assert(a as int*b as int<=u128::MAX) by(nonlinear_arith)
                requires 0<=a as int<=u64::MAX,0<=b as int<=u64::MAX;
            vstd::arithmetic::div_mod::lemma_small_mod(a as nat*b as nat,
                0x1_0000_0000_0000_0000_0000_0000_0000_0000nat);
        }
        a as u128*b as u128
    };
    let low=(exact as u64)&mask;
    let high=((exact>>bits) as u64)&mask;
    let overflow=if signed {high!=sign_high(low,width)} else {high!=0};
    Product {low,high,flags:(flags&!0x801u64)|if overflow {0x801u64} else {0u64}}
}

pub fn extend(value: u64, width: Width) -> (out: u64)
    ensures out == model::extend(value, width),
{
    let mask = width.mask();
    let low = value & mask;
    if low & (1u64 << (width.bits() - 1)) != 0 { low | !mask } else { low }
}

fn scan_bits(value:u64,bits:u32,reverse:bool)->(out:Option<u64>)
    requires bits<=64,
    ensures out==model::scan_bits(value,bits,reverse),
        match out {Some(index)=>index<bits,None=>true},
    decreases bits,
{
    if bits==0 || value==0 {None}
    else if !reverse && value&1!=0 {Some(0)}
    else {match scan_bits(value>>1,bits-1,reverse) {
        Some(index)=>Some(index+1),
        None=>if value&1!=0 {Some(0)} else {None},
    }}
}

pub fn scan(value:u64,width:Width,reverse:bool)->(out:Option<u64>)
    ensures out==model::scan(value,width,reverse),
        match out {Some(index)=>index<super::operand::model::bits(width),None=>true},
{
    reveal(model::scan);
    scan_bits(value & width.mask(),width.bits(),reverse)
}

pub fn sign_high(value: u64, width: Width) -> (out: u64)
    ensures out == model::sign_high(value, width),
{
    if value & (1u64 << (width.bits() - 1)) != 0 { width.mask() } else { 0 }
}

pub fn bit(operation: BitOperation, value: u64, index: u64, width: Width, flags: u64)
    -> (out: integer::Outcome)
    ensures out == model::bit(operation, value, index, width, flags),
{
    let mask = width.mask();
    let selected = 1u64 << (index % width.bits() as u64);
    let low = value & mask;
    integer::Outcome {
        value: match operation {
            BitOperation::Test => low,
            BitOperation::Set => (low | selected) & mask,
            BitOperation::Reset => low & !selected,
            BitOperation::Complement => (low ^ selected) & mask,
        },
        flags: (flags & !1u64) | (if low & selected != 0 { 1u64 } else { 0u64 }),
        write: operation != BitOperation::Test,
    }
}

fn encode(value: u128, negative: bool, _width: Width, modulus: u128) -> (out: u64)
    requires modulus == model::modulus(_width), value < modulus,
    ensures out == model::encode(value, negative, _width),
        (out as u128) < modulus,
{
    if negative && value != 0 { (modulus - value) as u64 } else { value as u64 }
}

/// Byte/word division is outside the current execution profile. Failure is a
/// diagnostic result; architectural #DE delivery belongs to the caller.
pub fn divide(high: u64, low: u64, divisor: u64, width: Width, signed: bool)
    -> (out: Option<Division>)
    ensures out == model::divide(high, low, divisor, width, signed),
        match out {
            Some(result) => (width == Width::Dword || width == Width::Qword)
                && (result.quotient as u128) < model::modulus(width)
                && (result.remainder as u128) < model::modulus(width),
            None => true,
        },
{
    if width != Width::Dword && width != Width::Qword { return None; }
    let mask = width.mask();
    let bits = width.bits();
    let modulus = if width == Width::Dword { 0x1_0000_0000u128 }
        else { 0x1_0000_0000_0000_0000u128 };
    let raw = (((high & mask) as u128) << bits) | (low & mask) as u128;
    let full_mask = if width == Width::Dword { 0xffff_ffff_ffff_ffffu128 }
        else { u128::MAX };
    let n_negative = signed && high & (1u64 << (bits - 1)) != 0;
    let d_negative = signed && divisor & (1u64 << (bits - 1)) != 0;
    let n = if n_negative {
        proof {
            if width == Width::Dword {
                assert(raw <= 0xffff_ffff_ffff_ffffu128) by (bit_vector)
                    requires raw == (((high & 0xffff_ffffu64) as u128) << 32)
                        | (low & 0xffff_ffffu64) as u128;
                assert((raw ^ full_mask) < u128::MAX) by (bit_vector)
                    requires raw <= 0xffff_ffff_ffff_ffffu128,
                        full_mask == 0xffff_ffff_ffff_ffffu128;
            } else {
                assert(raw == ((high as u128) << 64) | low as u128) by (bit_vector)
                    requires raw == (((high & u64::MAX) as u128) << 64)
                        | (low & u64::MAX) as u128;
                assert(high & 0x8000_0000_0000_0000u64 != 0) by (bit_vector)
                    requires high & (1u64 << 63) != 0;
                assert(raw != 0) by (bit_vector)
                    requires raw == ((high as u128) << 64) | low as u128,
                        high & 0x8000_0000_0000_0000u64 != 0;
                assert((raw ^ full_mask) < u128::MAX) by (bit_vector)
                    requires raw != 0, full_mask == u128::MAX;
            }
        }
        (raw ^ full_mask) + 1
    } else { raw };
    proof {
        assert(divisor & mask <= mask) by (bit_vector);
    }
    let d = if d_negative { modulus - (divisor & mask) as u128 }
        else { (divisor & mask) as u128 };
    if d == 0 { return None; }
    let q = n / d;
    let r = n % d;
    let q_negative = n_negative != d_negative;
    let limit = if !signed { modulus - 1 }
        else if q_negative { modulus / 2 } else { modulus / 2 - 1 };
    if q > limit { None }
    else {
        Some(Division {
            quotient: encode(q, q_negative, width, modulus),
            remainder: encode(r, n_negative, width, modulus),
        })
    }
}

/// Extending a source preserves its low bits, and a negative source has all
/// higher bits set. These are width-parametric facts, not encoding cases.
pub proof fn extension_bits(value: u64, width: Width)
    ensures
        model::extend(value, width) & super::operand::model::mask(width)
            == value & super::operand::model::mask(width),
        model::extend(value, width) & !super::operand::model::mask(width)
            == if model::negative(value, width) {
                !super::operand::model::mask(width)
            } else { 0 },
{
    let mask = super::operand::model::mask(width);
    let sign = 1u64 << (super::operand::model::bits(width) - 1);
    match width {
        Width::Byte => { assert(sign == 0x80) by (bit_vector)
            requires sign == 1u64 << 7; },
        Width::Word => { assert(sign == 0x8000) by (bit_vector)
            requires sign == 1u64 << 15; },
        Width::Dword => { assert(sign == 0x8000_0000) by (bit_vector)
            requires sign == 1u64 << 31; },
        Width::Qword => { assert(sign == 0x8000_0000_0000_0000) by (bit_vector)
            requires sign == 1u64 << 63; },
    }
    assert(mask & sign == sign) by (bit_vector)
        requires (mask == 0xff && sign == 0x80)
            || (mask == 0xffff && sign == 0x8000)
            || (mask == 0xffff_ffff && sign == 0x8000_0000)
            || (mask == u64::MAX && sign == 0x8000_0000_0000_0000);
    let extended = if value & mask & sign != 0 { (value & mask) | !mask }
        else { value & mask };
    assert(extended & mask == value & mask
        && extended & !mask == if value & sign != 0 { !mask } else { 0 }
    ) by (bit_vector)
        requires mask & sign == sign,
            extended == if value & mask & sign != 0 { (value & mask) | !mask }
                else { value & mask };
}

pub proof fn bit_frame(operation: BitOperation, value: u64, index: u64,
    width: Width, flags: u64)
    ensures
        model::bit(operation, value, index, width, flags).flags & !1u64 == flags & !1u64,
        model::bit(operation, value, index, width, flags).write
            == (operation != BitOperation::Test),
        model::bit(operation, value, index, width, flags).value
            & !super::operand::model::mask(width) == 0,
{
    let selected = 1u64 << (index % super::operand::model::bits(width) as u64);
    let mask = super::operand::model::mask(width);
    assert((value & mask & !selected) & !mask == 0) by (bit_vector);
    assert(((flags & !1u64) | 0u64) & !1u64 == flags & !1u64) by (bit_vector);
    assert(((flags & !1u64) | 1u64) & !1u64 == flags & !1u64) by (bit_vector);
    assert(((value & mask | selected) & mask) & !mask == 0) by (bit_vector);
    assert(((value & mask ^ selected) & mask) & !mask == 0) by (bit_vector);
    assert((value & mask) & !mask == 0) by (bit_vector);
}

pub proof fn register_bit_index(index: u64, width: Width)
    ensures
        index % super::operand::model::bits(width) as u64
            == index & ((super::operand::model::bits(width) - 1) as u64),
{
    let n = super::operand::model::bits(width) as u64;
    assert(index % n == index & ((n - 1) as u64)) by (bit_vector)
        requires n == 8 || n == 16 || n == 32 || n == 64;
}

/// The positive-magnitude algorithm is valid over the entire double-width
/// domain. Applying the dividend sign to the remainder gives signed truncation
/// toward zero without a signed host divide or a MIN/-1 overflow.
pub proof fn magnitude_division(n: u128, d: u128)
    requires d > 0,
    ensures
        n as int == (n / d) as int * d as int + (n % d) as int,
        0 <= n % d < d,
        -(n as int) == -((n / d) as int) * d as int - (n % d) as int,
{
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(n as int, d as int);
    assert(n as int == (n / d) as int * d as int + (n % d) as int)
        by (nonlinear_arith)
        requires n as int == d as int * (n / d) as int + (n % d) as int;
    assert(-(n as int) == -((n / d) as int) * d as int - (n % d) as int)
        by (nonlinear_arith)
        requires n as int == (n / d) as int * d as int + (n % d) as int;
}

/// Applying the XOR of operand signs to the quotient, and only the dividend
/// sign to the remainder, reconstructs the original dividend for all four
/// sign combinations. The magnitude bound is independent of operand width.
pub proof fn signed_division_equation(n: u128, d: u128,
    n_negative: bool, d_negative: bool)
    requires d > 0,
    ensures
        (if n_negative { -(n as int) } else { n as int })
            == (if n_negative != d_negative { -((n / d) as int) }
                else { (n / d) as int })
                * (if d_negative { -(d as int) } else { d as int })
                + (if n_negative { -((n % d) as int) } else { (n % d) as int }),
        0 <= n % d < d,
{
    magnitude_division(n, d);
    let q = (n / d) as int;
    let r = (n % d) as int;
    assert((if n_negative { -(n as int) } else { n as int })
        == (if n_negative != d_negative { -q } else { q })
            * (if d_negative { -(d as int) } else { d as int })
            + (if n_negative { -r } else { r }))
        by (nonlinear_arith)
        requires n as int == q * d as int + r;
}

}
