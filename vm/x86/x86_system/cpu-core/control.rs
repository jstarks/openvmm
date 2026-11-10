// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use vstd::prelude::*;

pub mod model {
    use super::*;

    verus! {
    /// AMD APM Volume 1, section 3.3 conditional-jump flag predicates.
    pub open spec fn condition(cc: Condition, flags: u64) -> bool {
        let cf = flags & 1u64 != 0;
        let pf = flags & 4u64 != 0;
        let zf = flags & 0x40u64 != 0;
        let sf = flags & 0x80u64 != 0;
        let of = flags & 0x800u64 != 0;
        match cc {
            Condition::Overflow => of,
            Condition::NotOverflow => !of,
            Condition::Below => cf,
            Condition::AboveEqual => !cf,
            Condition::Equal => zf,
            Condition::NotEqual => !zf,
            Condition::BelowEqual => cf || zf,
            Condition::Above => !cf && !zf,
            Condition::Sign => sf,
            Condition::NotSign => !sf,
            Condition::Parity => pf,
            Condition::NotParity => !pf,
            Condition::Less => sf != of,
            Condition::GreaterEqual => sf == of,
            Condition::LessEqual => zf || sf != of,
            Condition::Greater => !zf && sf == of,
        }
    }

    /// AMD APM Volume 3, PUSHF/PUSHFD/PUSHFQ: only the saved image loses RF/VM.
    pub open spec fn flags_image(flags: u64) -> u64 {
        flags & !0x0003_0000u64
    }

    /// CPL0 long64 with the event profile's incoming VIF/VIP/VM all zero.
    /// AMD APM Volume 3, POPF_PROTECTED: VIF/VIP/VM are unchanged, RF is
    /// cleared, and CPL0 can write IF/IOPL. TF/IOPL/NT/AC requests outside
    /// this execution profile are diagnostic, not architectural exceptions.
    /// Reserved inputs do not change RFLAGS; bit 1 remains fixed to one
    /// (Volume 1 section 3.1.4 and Volume 2 section 3.1.6).
    pub open spec fn restore_flags(value: u64) -> Option<u64> {
        if value & 0x0004_7100u64 != 0 {
            None
        } else {
            Some((value & 0x0020_0ed5u64) | 2u64)
        }
    }
    }
}

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum Condition {
    Overflow, NotOverflow, Below, AboveEqual, Equal, NotEqual, BelowEqual, Above,
    Sign, NotSign, Parity, NotParity, Less, GreaterEqual, LessEqual, Greater,
}

pub fn condition(cc: Condition, flags: u64) -> (taken: bool)
    ensures taken == model::condition(cc, flags),
{
    let cf = flags & 1 != 0;
    let pf = flags & 4 != 0;
    let zf = flags & 0x40 != 0;
    let sf = flags & 0x80 != 0;
    let of = flags & 0x800 != 0;
    match cc {
        Condition::Overflow => of,
        Condition::NotOverflow => !of,
        Condition::Below => cf,
        Condition::AboveEqual => !cf,
        Condition::Equal => zf,
        Condition::NotEqual => !zf,
        Condition::BelowEqual => cf || zf,
        Condition::Above => !cf && !zf,
        Condition::Sign => sf,
        Condition::NotSign => !sf,
        Condition::Parity => pf,
        Condition::NotParity => !pf,
        Condition::Less => sf != of,
        Condition::GreaterEqual => sf == of,
        Condition::LessEqual => zf || sf != of,
        Condition::Greater => !zf && sf == of,
    }
}

pub fn flags_image(flags: u64) -> (image: u64)
    ensures image == model::flags_image(flags),
{
    flags & !0x0003_0000u64
}

/// Returns only a supported completed POPFQ image. The caller owns the stack
/// read, state commit and retirement; None must remain an unsupported diagnostic.
pub fn restore_flags(value: u64) -> (flags: Option<u64>)
    ensures flags == model::restore_flags(value),
{
    if value & 0x0004_7100u64 != 0 {
        None
    } else {
        Some((value & 0x0020_0ed5u64) | 2u64)
    }
}
}
