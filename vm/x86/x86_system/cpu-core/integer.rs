// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{arithmetic, operand::Width, scalar};
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
pub enum Operation {
    Add, Sub, Cmp, And, Or, Xor, Test, Shl, Shr, Adc, Sbb, Inc, Dec, Neg, Not, Sar,
    Imul, BitTest, BitSet, BitReset, BitComplement, Rol, Ror,
}

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

#[verifier::opaque]
pub open spec fn product(left: u64, right: u64, width: Width) -> int {
    let mask = super::operand::model::mask(width);
    signed((left & mask) as int, modulus(width))
        * signed((right & mask) as int, modulus(width))
}

pub open spec fn product_overflow(exact: int, width: Width) -> bool {
    exact < -(modulus(width) / 2) || exact >= modulus(width) / 2
}

pub open spec fn bit_operation(operation: Operation) -> scalar::BitOperation {
    match operation {
        Operation::BitSet => scalar::BitOperation::Set,
        Operation::BitReset => scalar::BitOperation::Reset,
        Operation::BitComplement => scalar::BitOperation::Complement,
        _ => scalar::BitOperation::Test,
    }
}

/// Mathematical unsigned carry/borrow and signed-range overflow, not a
/// restatement of the executable sign-bit overflow test.
pub open spec fn arithmetic_model(sub: bool, a: int, b: int, m: int)
    -> (int, bool, bool, bool)
{
    arithmetic_carry_model(sub, a, b, false, m)
}

pub open spec fn arithmetic_carry_model(sub: bool, a: int, b: int,
    carry: bool, m: int) -> (int, bool, bool, bool)
{
    let c = if carry { 1int } else { 0int };
    let exact = if sub { a - b - c } else { a + b + c };
    let signed_exact = if sub { signed(a, m) - signed(b, m) - c }
        else { signed(a, m) + signed(b, m) + c };
    (exact % m,
        if sub { exact < 0 } else { exact >= m },
        if sub { a % 16 < b % 16 + c } else { a % 16 + b % 16 + c >= 16 },
        signed_exact < -(m / 2) || signed_exact >= m / 2)
}

pub open spec fn count(right: u64, width: Width) -> u32 {
    (right & (if width == Width::Qword { 63u64 } else { 31u64 })) as u32
}

pub open spec fn rotate_result(left:u64,right:u64,width:Width,flags:u64,reverse:bool)->Outcome {
    let n=super::operand::model::bits(width);
    let mask=super::operand::model::mask(width);
    let a=left & mask;
    let c=count(right,width);
    let r=c%n;
    let value=if r==0 {a} else if reverse {((a>>r)|(a<<(n-r))) & mask}
        else {((a<<r)|(a>>(n-r))) & mask};
    let cf=if reverse {value>>(n-1)!=0} else {value&1u64!=0};
    let of=if reverse {((value>>(n-1))^(value>>(n-2)))&1u64!=0}
        else {(value>>(n-1)!=0)!=cf};
    let next=if c==0 {flags} else {
        let carry=(flags & !1u64) | if cf {1u64} else {0u64};
        if c==1 {(carry & !0x800u64) | if of {0x800u64} else {0u64}} else {carry}
    };
    Outcome {value,flags:next,write:true}
}

pub open spec fn core(operation: Operation, a: u64, b: u64, width: Width)
    -> (u64, bool, bool, bool)
{
    core_with_carry(operation, a, b, width, false)
}

pub open spec fn core_with_carry(operation: Operation, a: u64, b: u64,
    width: Width, carry: bool) -> (u64, bool, bool, bool)
{
    let n = super::operand::model::bits(width);
    let mask = super::operand::model::mask(width);
    let c = count(b, width);
    match operation {
        Operation::Rol | Operation::Ror => {
            let out=rotate_result(a,b,width,0,operation==Operation::Ror);
            (out.value,out.flags&1u64!=0,false,out.flags&0x800u64!=0)
        },
        Operation::Add | Operation::Adc | Operation::Sub | Operation::Sbb
            | Operation::Cmp | Operation::Inc | Operation::Dec | Operation::Neg => {
            let sub = operation == Operation::Sub || operation == Operation::Sbb
                || operation == Operation::Cmp || operation == Operation::Dec
                || operation == Operation::Neg;
            let x = if operation == Operation::Neg { 0u64 } else { a };
            let y = if operation == Operation::Inc || operation == Operation::Dec { 1u64 }
                else if operation == Operation::Neg { a } else { b };
            let t = arithmetic_carry_model(sub, x as int, y as int,
                carry && (operation == Operation::Adc || operation == Operation::Sbb),
                modulus(width));
            (t.0 as u64, t.1, t.2, t.3)
        },
        Operation::Not => ((!a) & mask, false, false, false),
        Operation::And | Operation::Test => (a & b, false, false, false),
        Operation::Or => (a | b, false, false, false),
        Operation::Xor => (a ^ b, false, false, false),
        Operation::Imul => {
            let exact = product(a, b, width);
            let overflow = product_overflow(exact, width);
            ((exact % modulus(width)) as u64, overflow, false, overflow)
        },
        Operation::BitTest | Operation::BitSet | Operation::BitReset
            | Operation::BitComplement => {
            let out = scalar::model::bit(bit_operation(operation), a, b, width, 0);
            (out.value, out.flags & 1u64 != 0, false, false)
        },
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
        Operation::Sar => {
            let negative = (a >> (n - 1)) != 0;
            let value = if c >= n { if negative { mask } else { 0u64 } }
                else { (a >> c) | (if negative { mask ^ (mask >> c) } else { 0u64 }) };
            let cf = c > 0 && (if c >= n { negative }
                else { ((a >> (c - 1)) & 1u64) != 0 });
            (value, cf, false, false)
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
    if operation==Operation::Rol || operation==Operation::Ror {
        let out=rotate_result(left,right,width,flags,operation==Operation::Ror);
        (out.value,out.flags,true)
    } else if operation == Operation::BitTest || operation == Operation::BitSet
        || operation == Operation::BitReset || operation == Operation::BitComplement {
        let out = scalar::model::bit(bit_operation(operation), left, right, width, flags);
        (out.value, out.flags, out.write)
    } else if operation == Operation::Imul {
        let exact = product(left, right, width);
        let overflow = product_overflow(exact, width);
        ((exact % modulus(width)) as u64,
            (flags & !0x801u64) | (if overflow { 0x801u64 } else { 0u64 }), true)
    } else if operation == Operation::Not {
        ((!a) & mask, flags, true)
    } else if (operation == Operation::Shl || operation == Operation::Shr
        || operation == Operation::Sar)
        && count(right, width) == 0
    {
        (a, flags, true)
    } else {
        let t = core_with_carry(operation, a, b, width, flags & 1u64 != 0);
        let cf = if operation == Operation::Inc || operation == Operation::Dec {
            flags & 1u64 != 0
        } else { t.1 };
        (t.0, packed(flags, t.0, (modulus(width) / 2) as u64, cf, t.2, t.3),
            operation != Operation::Test && operation != Operation::Cmp)
    }
}

/// A signed width-limited product fits i128 even for two Qword minima.
pub proof fn product_bounds(a: int, b: int)
    requires
        -9223372036854775808 <= a <= 9223372036854775807,
        -9223372036854775808 <= b <= 9223372036854775807,
    ensures
        -85070591730234615865843651857942052864 <= a * b
            <= 85070591730234615865843651857942052864,
{
    assert(-85070591730234615865843651857942052864 <= a * b
        <= 85070591730234615865843651857942052864) by(nonlinear_arith)
        requires
            -9223372036854775808 <= a <= 9223372036854775807,
            -9223372036854775808 <= b <= 9223372036854775807;
}

fn multiply(a: u64, b: u64, _width: Width, m: u128) -> (out: (u64, bool))
    requires
        m as int == modulus(_width), a < m, b < m,
    ensures
        out.0 as int == (signed(a as int, m as int)
            * signed(b as int, m as int)) % (m as int),
        out.1 == product_overflow(signed(a as int, m as int)
            * signed(b as int, m as int), _width),
{
    let half = (m / 2) as i128;
    let x = if (a as u128) < m / 2 { a as i128 } else { (a as i128) - m as i128 };
    let y = if (b as u128) < m / 2 { b as i128 } else { (b as i128) - m as i128 };
    proof { product_bounds(x as int, y as int); }
    let exact = x * y;
    // Adding a multiple of every scalar modulus avoids a negative remainder
    // without overflowing i128, including the minimum-times-minimum case.
    let offset = 85070591730234615865843651857942052864i128;
    let positive = if exact < 0 { exact + offset } else { exact };
    let value = ((positive as u128) % m) as u64;
    proof {
        assert(offset as int % (m as int) == 0);
        vstd::arithmetic::div_mod::lemma_mod_equivalence(
            positive as int, exact as int, m as int);
        vstd::arithmetic::div_mod::lemma_mod_bound(positive as int, m as int);
    }
    (value, exact < -half || exact >= half)
}

pub proof fn imul_family(left: u64, right: u64, width: Width, flags: u64)
    ensures
        model::evaluate(Operation::Imul, left, right, width, flags).value as int
            == product(left, right, width) % modulus(width),
        model::evaluate(Operation::Imul, left, right, width, flags).write,
        model::evaluate(Operation::Imul, left, right, width, flags).flags & !0x801u64
            == flags & !0x801u64,
        (model::evaluate(Operation::Imul, left, right, width, flags).flags & 0x801u64
            == 0x801u64) == product_overflow(product(left, right, width), width),
        !product_overflow(product(left, right, width), width) ==>
            signed(model::evaluate(Operation::Imul, left, right, width, flags).value as int,
                modulus(width)) == product(left, right, width),
{
    let exact = product(left, right, width);
    let m = modulus(width);
    vstd::arithmetic::div_mod::lemma_mod_bound(exact, m);
    if !product_overflow(exact, width) {
        if exact < 0 {
            vstd::arithmetic::div_mod::lemma_fundamental_div_mod_converse_mod(
                exact, m, -1, exact + m);
        } else {
            vstd::arithmetic::div_mod::lemma_fundamental_div_mod_converse_mod(
                exact, m, 0, exact);
        }
    }
    let overflow = product_overflow(exact, width);
    let next = model::evaluate(Operation::Imul, left, right, width, flags).flags;
    assert(next & !0x801u64 == flags & !0x801u64
        && (next & 0x801u64 == 0x801u64) == overflow) by(bit_vector)
        requires next == (flags & !0x801u64) | (if overflow { 0x801u64 } else { 0u64 });
}

pub proof fn bit_family(operation: Operation, left: u64, right: u64,
    width: Width, flags: u64)
    requires operation == Operation::BitTest || operation == Operation::BitSet
        || operation == Operation::BitReset || operation == Operation::BitComplement,
    ensures model::evaluate(operation, left, right, width, flags)
        == scalar::model::bit(bit_operation(operation), left, right, width, flags),
        model::evaluate(operation, left, right, width, flags).write
            == (operation != Operation::BitTest),
        model::evaluate(operation, left, right, width, flags).flags & !1u64 == flags & !1u64,
{
    let out = scalar::model::bit(bit_operation(operation), left, right, width, flags);
    let selected = 1u64 << (right % super::operand::model::bits(width) as u64);
    let old_bit = (left & super::operand::model::mask(width)) & selected != 0;
    let next_flags = out.flags;
    assert(next_flags & !1u64 == flags & !1u64) by(bit_vector)
        requires next_flags == (flags & !1u64) | (if old_bit { 1u64 } else { 0u64 });
}

fn arithmetic_value(sub: bool, a: u64, b: u64, carry: bool, m: u128)
    -> (out: (u64, bool, bool, bool))
    requires
        2 <= m <= 18446744073709551616,
        m % 2 == 0, a < m, b < m,
    ensures
        (out.0 as int, out.1, out.2, out.3)
            == arithmetic_carry_model(sub, a as int, b as int, carry, m as int),
{
    let half = (m / 2) as u64;
    let c = if carry { 1u128 } else { 0u128 };
    let rhs = (b as u128) + c;
    let value = if sub {
        if (a as u128) >= rhs { ((a as u128) - rhs) as u64 }
        else { (m - (rhs - (a as u128))) as u64 }
    } else {
        let sum = (a as u128) + rhs;
        if sum >= m { (sum - m) as u64 } else { sum as u64 }
    };
    let cf = if sub { (a as u128) < rhs } else { (a as u128) + rhs >= m };
    let af = if sub { ((a % 16) as u128) < (b % 16) as u128 + c }
        else { (a % 16) as u128 + (b % 16) as u128 + c >= 16 };
    let of = if sub {
        (a >= half) != (b >= half) && (a >= half) != (value >= half)
    } else {
        (a >= half) == (b >= half) && (a >= half) != (value >= half)
    };
    proof {
        let exact = if sub { a as int - b as int - c as int }
            else { a as int + b as int + c as int };
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

pub proof fn cmp_matches_sub(left: u64, right: u64, width: Width, flags: u64)
    ensures
        model::evaluate(Operation::Cmp, left, right, width, flags).value
            == model::evaluate(Operation::Sub, left, right, width, flags).value,
        model::evaluate(Operation::Cmp, left, right, width, flags).flags
            == model::evaluate(Operation::Sub, left, right, width, flags).flags,
        !model::evaluate(Operation::Cmp, left, right, width, flags).write,
{
}

pub proof fn unary_family(operation: Operation, left: u64, right: u64,
    width: Width, flags: u64)
    requires
        operation == Operation::Inc || operation == Operation::Dec
            || operation == Operation::Neg || operation == Operation::Not,
    ensures
        model::evaluate(operation, left, right, width, flags)
            == model::evaluate(operation, left, 0, width, flags),
        model::evaluate(operation, left, right, width, flags).write,
        operation == Operation::Neg ==> (
            model::evaluate(operation, left, right, width, flags).value
                == model::evaluate(Operation::Sub, 0, left, width, flags).value
            && model::evaluate(operation, left, right, width, flags).flags
                == model::evaluate(Operation::Sub, 0, left, width, flags).flags),
        operation == Operation::Not ==>
            model::evaluate(operation, left, right, width, flags).flags == flags,
        operation == Operation::Inc || operation == Operation::Dec ==>
            model::evaluate(operation, left, right, width, flags).flags & 1u64
                == flags & 1u64,
{
    if operation == Operation::Neg {
        let mask = super::operand::model::mask(width);
        assert(0u64 & mask == 0u64) by(bit_vector);
    }
    if operation == Operation::Inc || operation == Operation::Dec {
        let out = model::evaluate(operation, left, right, width, flags);
        let even = arithmetic::model::population((out.value % 256) as int) % 2 == 0;
        let zf = out.value == 0;
        let sf = out.value >= (modulus(width) / 2) as u64;
        let t = core_with_carry(operation, left & super::operand::model::mask(width),
            right & super::operand::model::mask(width), width, flags & 1u64 != 0);
        let af = t.2;
        let of = t.3;
        let next_flags = out.flags;
        assert(next_flags & 1u64 == flags & 1u64) by(bit_vector)
            requires next_flags == (flags & !0x8d5u64)
                | ((if flags & 1u64 != 0 { 1u64 } else { 0u64 })
                    | (if even { 4u64 } else { 0u64 })
                    | (if af { 16u64 } else { 0u64 })
                    | (if zf { 64u64 } else { 0u64 })
                    | (if sf { 128u64 } else { 0u64 })
                    | (if of { 2048u64 } else { 0u64 }));
    }
}

pub proof fn logical_family(operation: Operation, left: u64, right: u64,
    width: Width, flags: u64)
    requires
        operation == Operation::And || operation == Operation::Or
            || operation == Operation::Xor || operation == Operation::Test,
    ensures
        model::evaluate(operation, left, right, width, flags).value
            & !super::operand::model::mask(width) == 0,
        model::evaluate(operation, left, right, width, flags).flags & 0x811u64 == 0,
        model::evaluate(operation, left, right, width, flags).write
            == (operation != Operation::Test),
{
    let mask = super::operand::model::mask(width);
    let a = left & mask;
    let b = right & mask;
    let is_or = operation == Operation::Or;
    let is_xor = operation == Operation::Xor;
    let value = model::evaluate(operation, left, right, width, flags).value;
    assert(value & !mask == 0) by(bit_vector)
        requires value == (if is_or { a | b } else if is_xor { a ^ b } else { a & b }),
            a == left & mask, b == right & mask;
    let even = arithmetic::model::population((value % 256) as int) % 2 == 0;
    let zf = value == 0;
    let sf = value >= (modulus(width) / 2) as u64;
    let next_flags = model::evaluate(operation, left, right, width, flags).flags;
    assert(next_flags & 0x811u64 == 0) by(bit_vector)
        requires next_flags == (flags & !0x8d5u64)
            | (0u64 | (if even { 4u64 } else { 0u64 }) | 0u64
                | (if zf { 64u64 } else { 0u64 })
                | (if sf { 128u64 } else { 0u64 }) | 0u64);
}

/// AMD APM Volume 3 ADC/ADD/SBB/SUB/CMP, INC/DEC/NEG/NOT, AND/OR/XOR/TEST
/// SAL/SHL/SHR/SAR, IMUL and BT/BTS/BTR/BTC, with flag meanings from
/// Volume 1 section 3.1.4.
///
/// CMP shares SUB's result and flags but does not write the destination.
/// Undefined AF is chosen zero for logical operations and nonzero shifts.
/// Shift OF is chosen zero beyond count one. At count == width we retain
/// the last shifted-out bit; beyond width CF is chosen zero. Counts are
/// masked before either decision. A zero count preserves every flag.
/// SAR retains the sign bit at/beyond width, including CF, and chooses
/// undefined OF zero beyond count one. INC/DEC preserve CF; NOT preserves
/// every flag. Unary operations ignore right.
/// IMUL returns the low signed product, sets CF/OF on signed overflow and
/// preserves all undefined flags. Bit operations reuse scalar semantics;
/// indexes wrap within width, only CF changes, and BT does not write.
/// Inputs are already semantically extended by the decoder; this function
/// neither extends immediates nor commits register aliases or memory.
pub fn rotate_value(left:u64,right:u64,width:Width,flags:u64,reverse:bool)->(out:Outcome)
    ensures out==rotate_result(left,right,width,flags,reverse),
        out.flags & !0x801u64 == flags & !0x801u64,
{
    let n=width.bits();
    let a=left & width.mask();
    let c=(right & if width==Width::Qword {63u64} else {31u64}) as u32;
    let r=c%n;
    let value=if r==0 {a} else if reverse {((a>>r)|(a<<(n-r))) & width.mask()}
        else {((a<<r)|(a>>(n-r))) & width.mask()};
    let cf=if reverse {value>>(n-1)!=0} else {value&1!=0};
    let of=if reverse {((value>>(n-1))^(value>>(n-2)))&1!=0}
        else {(value>>(n-1)!=0)!=cf};
    let next=if c==0 {flags} else {
        let carry=(flags & !1u64) | if cf {1u64} else {0u64};
        if c==1 {(carry & !0x800u64) | if of {0x800u64} else {0u64}} else {carry}
    };
    assert(next & !0x801u64 == flags & !0x801u64) by(bit_vector)
        requires next==if c==0 {flags} else {
            let carry=(flags & !1u64) | if cf {1u64} else {0u64};
            if c==1 {(carry & !0x800u64) | if of {0x800u64} else {0u64}} else {carry}
        };
    Outcome {value,flags:next,write:true}
}

#[verifier::rlimit(30)]
pub fn evaluate(operation: Operation, left: u64, right: u64, width: Width, flags: u64)
    -> (out: Outcome)
    ensures
        out == model::evaluate(operation, left, right, width, flags),
        out.flags & !0x8d5u64 == flags & !0x8d5u64,
        out.write == (operation != Operation::Test && operation != Operation::Cmp
            && operation != Operation::BitTest),
{
    if operation==Operation::Rol || operation==Operation::Ror {
        let out=rotate_value(left,right,width,flags,operation==Operation::Ror);
        let ghost next=out.flags;
        assert(next & !0x8d5u64 == flags & !0x8d5u64) by(bit_vector)
            requires next & !0x801u64 == flags & !0x801u64;
        return out;
    }
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
    if operation == Operation::BitTest || operation == Operation::BitSet
        || operation == Operation::BitReset || operation == Operation::BitComplement {
        let selected = match operation {
            Operation::BitSet => scalar::BitOperation::Set,
            Operation::BitReset => scalar::BitOperation::Reset,
            Operation::BitComplement => scalar::BitOperation::Complement,
            _ => scalar::BitOperation::Test,
        };
        let out = scalar::bit(selected, left, right, width, flags);
        proof {
            bit_family(operation, left, right, width, flags);
            let next_flags = out.flags;
            assert(next_flags & !0x8d5u64 == flags & !0x8d5u64) by(bit_vector)
                requires next_flags & !1u64 == flags & !1u64;
        }
        return out;
    }
    if operation == Operation::Imul {
        proof {
            reveal(product);
            assert(a <= mask && b <= mask) by(bit_vector)
                requires a == left & mask, b == right & mask;
        }
        let (value, overflow) = multiply(a, b, width, m);
        let next_flags = (flags & !0x801u64) | (if overflow { 0x801u64 } else { 0u64 });
        proof {
            assert(next_flags & !0x8d5u64 == flags & !0x8d5u64) by(bit_vector)
                requires next_flags == (flags & !0x801u64)
                    | (if overflow { 0x801u64 } else { 0u64 });
        }
        return Outcome { value, flags: next_flags, write: true };
    }
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
    if operation == Operation::Not {
        return Outcome { value: (!a) & mask, flags, write: true };
    }
    if (operation == Operation::Shl || operation == Operation::Shr
        || operation == Operation::Sar) && c == 0 {
        return Outcome { value: a, flags, write: true };
    }
    let (value, cf, af, of) = match operation {
        Operation::Add | Operation::Adc | Operation::Sub | Operation::Sbb
            | Operation::Cmp | Operation::Inc | Operation::Dec | Operation::Neg => {
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
            let sub = operation == Operation::Sub || operation == Operation::Sbb
                || operation == Operation::Cmp || operation == Operation::Dec
                || operation == Operation::Neg;
            let x = if operation == Operation::Neg { 0u64 } else { a };
            let y = if operation == Operation::Inc || operation == Operation::Dec { 1u64 }
                else if operation == Operation::Neg { a } else { b };
            let carry = (flags & 1u64 != 0)
                && (operation == Operation::Adc || operation == Operation::Sbb);
            arithmetic_value(sub, x, y, carry, m)
        },
        Operation::Not => { return Outcome { value: (!a) & mask, flags, write: true }; },
        Operation::Rol | Operation::Ror | Operation::Imul | Operation::BitTest | Operation::BitSet
            | Operation::BitReset | Operation::BitComplement => {
            assert(false);
            panic!("operation returned before the arithmetic dispatch");
        },
        Operation::And | Operation::Test => (a & b, false, false, false),
        Operation::Or => (a | b, false, false, false),
        Operation::Xor => (a ^ b, false, false, false),
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
        Operation::Sar => {
            let negative = (a >> (n - 1)) != 0;
            let value = if c >= n { if negative { mask } else { 0u64 } }
                else { (a >> c) | (if negative { mask ^ (mask >> c) } else { 0u64 }) };
            let cf = if c >= n { negative } else { ((a >> (c - 1)) & 1u64) != 0 };
            (value, cf, false, false)
        },
    };
    assert((value, cf, af, of) == core_with_carry(operation, a, b, width, flags & 1u64 != 0));
    let cf = if operation == Operation::Inc || operation == Operation::Dec {
        flags & 1u64 != 0
    } else { cf };
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
    Outcome { value, flags: next_flags,
        write: operation != Operation::Test && operation != Operation::Cmp }
}

}
