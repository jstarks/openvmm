// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{arithmetic, operand::Width};
use vstd::prelude::*;

pub mod model {
    use super::*;
    verus! {
    pub open spec fn evaluate(operation: Operation, left: u64, right: u64,
        width: Width, flags: u64) -> Outcome
    {
        let t = super::transition(operation, left, right, width, flags);
        Outcome { value: t.0, flags: t.1, write: t.2 }
    }
    }
}

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum Operation { Add, Sub, And, Or, Test, Shl, Shr }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub value: u64,
    pub flags: u64,
    pub write: bool,
}

pub open spec fn modulus(width: Width) -> int {
    match width {
        Width::Byte => 256,
        Width::Word => 65536,
        Width::Dword => 4294967296,
        Width::Qword => 18446744073709551616,
    }
}

pub open spec fn signed(value: int, modulus: int) -> int {
    if value < modulus / 2 { value } else { value - modulus }
}

/// Mathematical unsigned carry/borrow and signed-range overflow, not a
/// restatement of the executable sign-bit overflow test.
pub open spec fn arithmetic_model(sub: bool, a: int, b: int, m: int)
    -> (int, bool, bool, bool)
{
    let exact = if sub { a - b } else { a + b };
    let signed_exact = if sub { signed(a, m) - signed(b, m) }
        else { signed(a, m) + signed(b, m) };
    (exact % m,
        if sub { exact < 0 } else { exact >= m },
        if sub { a % 16 < b % 16 } else { a % 16 + b % 16 >= 16 },
        signed_exact < -(m / 2) || signed_exact >= m / 2)
}

pub open spec fn count(right: u64, width: Width) -> u32 {
    (right & (if width == Width::Qword { 63u64 } else { 31u64 })) as u32
}

pub open spec fn core(operation: Operation, a: u64, b: u64, width: Width)
    -> (u64, bool, bool, bool)
{
    let n = super::operand::model::bits(width);
    let mask = super::operand::model::mask(width);
    let c = count(b, width);
    match operation {
        Operation::Add | Operation::Sub => {
            let t = arithmetic_model(operation == Operation::Sub,
                a as int, b as int, modulus(width));
            (t.0 as u64, t.1, t.2, t.3)
        },
        Operation::And | Operation::Test => (a & b, false, false, false),
        Operation::Or => (a | b, false, false, false),
        Operation::Shl => {
            let value = if c >= n { 0u64 } else { (a << c) & mask };
            let cf = c > 0 && c <= n && ((a >> (n - c)) & 1u64) != 0;
            (value, cf, false,
                c == 1 && ((value >> (n - 1)) != 0) != cf)
        },
        Operation::Shr => {
            let value = if c >= n { 0u64 } else { a >> c };
            let cf = c > 0 && c <= n && ((a >> (c - 1)) & 1u64) != 0;
            (value, cf, false, c == 1 && (a >> (n - 1)) != 0)
        },
    }
}

pub open spec fn packed(old: u64, value: u64, half: u64,
    cf: bool, af: bool, of: bool) -> u64
{
    (old & !0x8d5u64) | (
        (if cf { 1u64 } else { 0u64 })
        | (if arithmetic::model::population((value % 256) as int) % 2 == 0 { 4u64 } else { 0u64 })
        | (if af { 16u64 } else { 0u64 })
        | (if value == 0 { 64u64 } else { 0u64 })
        | (if value >= half { 128u64 } else { 0u64 })
        | (if of { 2048u64 } else { 0u64 }))
}

pub open spec fn transition(operation: Operation, left: u64, right: u64,
    width: Width, flags: u64) -> (u64, u64, bool)
{
    let mask = super::operand::model::mask(width);
    let a = left & mask;
    let b = right & mask;
    if (operation == Operation::Shl || operation == Operation::Shr)
        && count(right, width) == 0
    {
        (a, flags, true)
    } else {
        let t = core(operation, a, b, width);
        (t.0, packed(flags, t.0, (modulus(width) / 2) as u64, t.1, t.2, t.3),
            operation != Operation::Test)
    }
}

fn arithmetic_value(sub: bool, a: u64, b: u64, m: u128)
    -> (out: (u64, bool, bool, bool))
    requires
        2 <= m <= 18446744073709551616,
        m % 2 == 0, a < m, b < m,
    ensures
        (out.0 as int, out.1, out.2, out.3)
            == arithmetic_model(sub, a as int, b as int, m as int),
{
    let half = (m / 2) as u64;
    let value = if sub {
        if a >= b { a - b } else { (m - ((b - a) as u128)) as u64 }
    } else {
        let sum = (a as u128) + (b as u128);
        if sum >= m { (sum - m) as u64 } else { sum as u64 }
    };
    let cf = if sub { a < b } else { (a as u128) + (b as u128) >= m };
    let af = if sub { a % 16 < b % 16 } else { a % 16 + b % 16 >= 16 };
    let of = if sub {
        (a >= half) != (b >= half) && (a >= half) != (value >= half)
    } else {
        (a >= half) == (b >= half) && (a >= half) != (value >= half)
    };
    proof {
        let exact = if sub { a as int - b as int } else { a as int + b as int };
        if exact < 0 {
            assert(value as int == exact + m);
            vstd::arithmetic::div_mod::lemma_fundamental_div_mod_converse_mod(
                exact, m as int, -1, value as int);
        } else if exact >= m {
            assert(value as int == exact - m);
            vstd::arithmetic::div_mod::lemma_fundamental_div_mod_converse_mod(
                exact, m as int, 1, value as int);
        } else {
            assert(value as int == exact);
            vstd::arithmetic::div_mod::lemma_fundamental_div_mod_converse_mod(
                exact, m as int, 0, value as int);
        }
        assert(value as int == exact % (m as int));
    }
    (value, cf, af, of)
}

/// AMD APM Volume 3 ADD/SUB, AND/OR/TEST, SAL/SHL and SHR, with the
/// arithmetic flag meanings from Volume 1 section 3.1.4.
///
/// Undefined AF is chosen zero for logical operations and nonzero shifts.
/// Shift OF is chosen zero beyond count one. At count == width we retain
/// the last shifted-out bit; beyond width CF is chosen zero. Counts are
/// masked before either decision. A zero count preserves every flag.
/// Inputs are already semantically extended by the decoder; this function
/// neither extends immediates nor commits register aliases or memory.
pub fn evaluate(operation: Operation, left: u64, right: u64, width: Width, flags: u64)
    -> (out: Outcome)
    ensures
        out == model::evaluate(operation, left, right, width, flags),
        out.flags & !0x8d5u64 == flags & !0x8d5u64,
        out.write == (operation != Operation::Test),
{
    let mask = width.mask();
    let n = width.bits();
    let a = left & mask;
    let b = right & mask;
    let m = match width {
        Width::Byte => 256u128,
        Width::Word => 65536u128,
        Width::Dword => 4294967296u128,
        Width::Qword => 18446744073709551616u128,
    };
    let c = (right % (if width == Width::Qword { 64u64 } else { 32u64 })) as u32;
    assert(right % 64u64 == right & 63u64) by(bit_vector);
    assert(right % 32u64 == right & 31u64) by(bit_vector);
    assert(c == count(right, width));
    let ghost count_mask = if width == Width::Qword { 63u64 } else { 31u64 };
    assert(c == ((b & count_mask) as u32)) by(bit_vector)
        requires b == right & mask,
            mask == 0xffu64 || mask == 0xffffu64 || mask == 0xffff_ffffu64 || mask == u64::MAX,
            count_mask == 63u64 || count_mask == 31u64,
            c == (right & count_mask) as u32;
    if (operation == Operation::Shl || operation == Operation::Shr) && c == 0 {
        return Outcome { value: a, flags, write: true };
    }
    let (value, cf, af, of) = match operation {
        Operation::Add | Operation::Sub => {
            proof {
                match width {
                    Width::Byte => { assert(a < 256 && b < 256) by(bit_vector)
                        requires a == left & 0xffu64, b == right & 0xffu64; },
                    Width::Word => { assert(a < 65536 && b < 65536) by(bit_vector)
                        requires a == left & 0xffffu64, b == right & 0xffffu64; },
                    Width::Dword => { assert(a < 4294967296 && b < 4294967296) by(bit_vector)
                        requires a == left & 0xffff_ffffu64, b == right & 0xffff_ffffu64; },
                    Width::Qword => {},
                }
            }
            arithmetic_value(operation == Operation::Sub, a, b, m)
        },
        Operation::And | Operation::Test => (a & b, false, false, false),
        Operation::Or => (a | b, false, false, false),
        Operation::Shl => {
            let value = if c >= n { 0u64 } else { (a << c) & mask };
            let cf = c <= n && ((a >> (n - c)) & 1u64) != 0;
            (value, cf, false, c == 1 && ((value >> (n - 1)) != 0) != cf)
        },
        Operation::Shr => {
            let value = if c >= n { 0u64 } else { a >> c };
            let cf = c <= n && ((a >> (c - 1)) & 1u64) != 0;
            (value, cf, false, c == 1 && (a >> (n - 1)) != 0)
        },
    };
    assert((value, cf, af, of) == core(operation, a, b, width));
    let even = arithmetic::parity((value % 256) as u8);
    let zf = value == 0;
    let sf = value >= (m / 2) as u64;
    let bits =
        (if cf { 1u64 } else { 0u64 })
        | (if even { 4u64 } else { 0u64 })
        | (if af { 16u64 } else { 0u64 })
        | (if zf { 64u64 } else { 0u64 })
        | (if sf { 128u64 } else { 0u64 })
        | (if of { 2048u64 } else { 0u64 });
    assert(bits & !0x8d5u64 == 0u64) by(bit_vector)
        requires bits == (if cf { 1u64 } else { 0u64 })
            | (if even { 4u64 } else { 0u64 })
            | (if af { 16u64 } else { 0u64 })
            | (if zf { 64u64 } else { 0u64 })
            | (if sf { 128u64 } else { 0u64 })
            | (if of { 2048u64 } else { 0u64 });
    let next_flags = (flags & !0x8d5u64) | bits;
    assert(m as int == modulus(width));
    assert(sf == (value >= (modulus(width) / 2) as u64));
    assert(even == (arithmetic::model::population((value % 256) as int) % 2 == 0));
    assert(next_flags == packed(flags, value, (modulus(width) / 2) as u64, cf, af, of));
    assert(next_flags & !0x8d5u64 == flags & !0x8d5u64) by(bit_vector)
        requires next_flags == (flags & !0x8d5u64) | bits, bits & !0x8d5u64 == 0u64;
    Outcome { value, flags: next_flags, write: operation != Operation::Test }
}

}
