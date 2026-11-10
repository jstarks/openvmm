// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![forbid(unsafe_code)]
use vstd::prelude::*;

#[path = "../x86-add-experiment/lib.rs"]
pub mod arithmetic;
pub mod decoder;
pub mod descriptor;
pub mod gsbase;
pub mod integer;
pub mod model;
pub mod near_call;
pub mod operand;
pub mod profile;
pub mod system;
pub mod xor32;

pub use arithmetic::{adc64, add_two_words, add64, merge_flags};

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind { Add, Adc, Unsupported }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile { Long64, Unsupported }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Diagnostic {
    Advanced,
    InvalidRegisters,
    UnsupportedLength,
    UnsupportedProfile,
    UnsupportedOperation,
    DebugRequired,
    TruncatedInput,
    UnsupportedEncoding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub gpr: [u64; 16],
    pub flags: u64,
    pub rip: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoded {
    pub kind: Kind,
    pub dst: u8,
    pub src: u8,
    pub length: u8,
    pub profile: Profile,
}

impl View for State {
    type V = model::State;
    open spec fn view(&self) -> model::State {
        model::State {
            gpr: self.gpr@.map(|i: int, x: u64| x as int),
            flags: self.flags,
            rip: self.rip as int,
        }
    }
}

impl View for Decoded {
    type V = model::Decoded;
    open spec fn view(&self) -> model::Decoded {
        model::Decoded {
            kind: self.kind, dst: self.dst as int, src: self.src as int,
            length: self.length as int, profile: self.profile,
        }
    }
}

pub proof fn representation_valid(s: State)
    ensures model::valid(s@),
{
    assert forall|i: int| 0 <= i < 16 implies
        0 <= #[trigger] s@.gpr[i] < arithmetic::model::modulus() by {
        assert(0 <= s.gpr@[i] <= u64::MAX);
    }
}

// The sibling merge has per-bit contracts. This checked lemma establishes
// equality with this core's independently stated mathematical flag vector.
pub proof fn merge_refines(old: u64, out: &arithmetic::Outcome, merged: u64)
    requires
        merged & !0x8d5u64 == old & !0x8d5u64,
        (merged & 1u64 != 0) == out.cf,
        (merged & 4u64 != 0) == out.pf,
        (merged & 16u64 != 0) == out.af,
        (merged & 64u64 != 0) == out.zf,
        (merged & 128u64 != 0) == out.sf,
        (merged & 2048u64 != 0) == out.of,
    ensures merged == model::flags(old, out@),
{
    let cf = out.cf;
    let pf = out.pf;
    let af = out.af;
    let zf = out.zf;
    let sf = out.sf;
    let of = out.of;
    assert(merged == (old & !0x8d5u64)
        | (if cf { 1u64 } else { 0u64 })
        | (if pf { 4u64 } else { 0u64 })
        | (if af { 16u64 } else { 0u64 })
        | (if zf { 64u64 } else { 0u64 })
        | (if sf { 128u64 } else { 0u64 })
        | (if of { 2048u64 } else { 0u64 })) by(bit_vector)
        requires
            merged & !0x8d5u64 == old & !0x8d5u64,
            (merged & 1u64 != 0) == cf,
            (merged & 4u64 != 0) == pf,
            (merged & 16u64 != 0) == af,
            (merged & 64u64 != 0) == zf,
            (merged & 128u64 != 0) == sf,
            (merged & 2048u64 != 0) == of,
        ;
}

pub fn execute(s: &mut State, op: Decoded) -> (status: Diagnostic)
    ensures
        (final(s)@, status) == model::execute(old(s)@, op@),
        status != Diagnostic::Advanced ==> final(s)@ == old(s)@,
        forall|i: int| 0 <= i < 16 && i != op.dst as int
            ==> #[trigger] final(s)@.gpr[i] == old(s)@.gpr[i],
        final(s).flags & !0x8d5u64 == old(s).flags & !0x8d5u64,
{
    if op.dst >= 16 || op.src >= 16 { return Diagnostic::InvalidRegisters; }
    if op.length != 3 { return Diagnostic::UnsupportedLength; }
    match op.profile {
        Profile::Unsupported => { return Diagnostic::UnsupportedProfile; },
        Profile::Long64 => {},
    }
    match op.kind {
        Kind::Unsupported => { return Diagnostic::UnsupportedOperation; },
        _ => {},
    }
    if s.flags & 0x10100u64 != 0 { return Diagnostic::DebugRequired; }
    let ghost before = s@;
    let a = s.gpr[op.dst as usize];
    let b = s.gpr[op.src as usize];
    let incoming = s.flags & 1u64 != 0;
    let out = match op.kind {
        Kind::Adc => adc64(a, b, incoming),
        _ => add64(a, b),
    };
    proof {
        reveal(model::outcome);
        assert(out@ == model::outcome(before, op@));
    }
    let merged = merge_flags(s.flags, &out);
    proof { merge_refines(s.flags, &out, merged); }
    s.gpr[op.dst as usize] = out.result;
    s.flags = merged;
    s.rip = s.rip.wrapping_add(op.length as u64);
    proof {
        assert(s.gpr[op.dst as int] == out.result);
        assert forall|i: int| 0 <= i < 16 && i != op.dst as int implies
            #[trigger] s@.gpr[i] == before.gpr[i] by {}
        assert(s@.gpr =~= before.gpr.update(op.dst as int, out@.result));
    }
    Diagnostic::Advanced
}

}
