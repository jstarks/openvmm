// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use vstd::prelude::*;

verus! {

pub open spec fn modulus() -> int { 18446744073709551616 }
pub open spec fn half() -> int { 9223372036854775808 }

pub open spec fn signed(x: int) -> int {
    if x < half() { x } else { x - modulus() }
}

// Population count is mathematical recursion, not an executable helper.
pub open spec fn population(x: int) -> int
    decreases x,
{
    if x <= 0 { 0 } else { x % 2 + population(x / 2) }
}

pub struct Outcome {
    pub result: int,
    pub cf: bool,
    pub pf: bool,
    pub af: bool,
    pub zf: bool,
    pub sf: bool,
    pub of: bool,
}

pub open spec fn add(a: int, b: int) -> Outcome {
    let sum = a + b;
    let result = sum % modulus();
    let signed_sum = signed(a) + signed(b);
    Outcome {
        result,
        cf: sum >= modulus(),
        pf: population(result % 256) % 2 == 0,
        af: a % 16 + b % 16 >= 16,
        zf: result == 0,
        sf: result >= half(),
        of: signed_sum < -half() || signed_sum >= half(),
    }
}

pub open spec fn adc(a: int, b: int, carry_in: bool) -> Outcome {
    let incoming = if carry_in { 1int } else { 0int };
    let sum = a + b + incoming;
    let result = sum % modulus();
    let signed_sum = signed(a) + signed(b) + incoming;
    Outcome {
        result,
        cf: sum >= modulus(),
        pf: population(result % 256) % 2 == 0,
        af: a % 16 + b % 16 + incoming >= 16,
        zf: result == 0,
        sf: result >= half(),
        of: signed_sum < -half() || signed_sum >= half(),
    }
}

pub struct TwoWord {
    pub low: int,
    pub high: int,
    pub carry: bool,
}

pub open spec fn wide_modulus() -> int { modulus() * modulus() }

pub open spec fn total(al: int, ah: int, bl: int, bh: int) -> int {
    al + bl + (ah + bh) * modulus()
}

pub open spec fn add_two(al: int, ah: int, bl: int, bh: int) -> TwoWord {
    let sum = total(al, ah, bl, bh);
    let result = sum % wide_modulus();
    TwoWord {
        low: result % modulus(),
        high: result / modulus(),
        carry: sum >= wide_modulus(),
    }
}

pub proof fn two_word_composition(
    al: int, ah: int, bl: int, bh: int, low: Outcome, high: Outcome,
)
    requires
        0 <= al < modulus(), 0 <= ah < modulus(),
        0 <= bl < modulus(), 0 <= bh < modulus(),
        low == add(al, bl),
        high == adc(ah, bh, low.cf),
    ensures
        (TwoWord { low: low.result, high: high.result, carry: high.cf })
            == add_two(al, ah, bl, bh),
        low.result + high.result * modulus()
            == total(al, ah, bl, bh) % wide_modulus(),
{
    let low_sum = al + bl;
    let incoming = if low.cf { 1int } else { 0int };
    if low_sum >= modulus() {
        assert(low.result == low_sum - modulus());
    } else {
        assert(low.result == low_sum);
    }
    assert(low_sum == low.result + incoming * modulus());
    let high_sum = ah + bh + incoming;
    let sum = total(al, ah, bl, bh);
    assert(sum == low.result + high_sum * modulus());
    if high_sum >= modulus() {
        assert(high.result == high_sum - modulus());
        assert(sum >= wide_modulus());
        assert(sum % wide_modulus() == sum - wide_modulus());
    } else {
        assert(high.result == high_sum);
        assert(sum < wide_modulus());
        assert(sum % wide_modulus() == sum);
    }
    let combined = low.result + high.result * modulus();
    assert(combined == sum % wide_modulus());
    assert(combined % modulus() == low.result);
    assert(combined / modulus() == high.result);
}

}
