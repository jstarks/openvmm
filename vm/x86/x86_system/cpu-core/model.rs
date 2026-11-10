// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use crate::arithmetic::model as alu;
use crate::{Diagnostic, Kind, Profile};
use vstd::prelude::*;

verus! {

pub struct State {
    pub gpr: Seq<int>,
    // A mathematical bit vector, deliberately not a hardware-legality predicate.
    pub flags: u64,
    pub rip: int,
}

pub struct Decoded {
    pub kind: Kind,
    pub dst: int,
    pub src: int,
    pub length: int,
    pub profile: Profile,
}

pub open spec fn valid(s: State) -> bool {
    s.gpr.len() == 16
        && (forall|i: int| 0 <= i < 16 ==> 0 <= #[trigger] s.gpr[i] < alu::modulus())
        && 0 <= s.rip < alu::modulus()
}

pub open spec fn diagnostic(s: State, op: Decoded) -> Diagnostic {
    if !(0 <= op.dst < 16 && 0 <= op.src < 16) {
        Diagnostic::InvalidRegisters
    } else if op.length != 3 {
        Diagnostic::UnsupportedLength
    } else if op.profile != Profile::Long64 {
        Diagnostic::UnsupportedProfile
    } else if op.kind == Kind::Unsupported {
        Diagnostic::UnsupportedOperation
    } else if s.flags & 0x10100u64 != 0 {
        Diagnostic::DebugRequired
    } else {
        Diagnostic::Advanced
    }
}

#[verifier::opaque]
pub open spec fn outcome(s: State, op: Decoded) -> alu::Outcome {
    if op.kind == Kind::Adc {
        alu::adc(s.gpr[op.dst], s.gpr[op.src], s.flags & 1u64 != 0)
    } else {
        alu::add(s.gpr[op.dst], s.gpr[op.src])
    }
}

pub open spec fn flags(old: u64, out: alu::Outcome) -> u64 {
    (old & !0x8d5u64)
        | (if out.cf { 1u64 } else { 0u64 })
        | (if out.pf { 4u64 } else { 0u64 })
        | (if out.af { 16u64 } else { 0u64 })
        | (if out.zf { 64u64 } else { 0u64 })
        | (if out.sf { 128u64 } else { 0u64 })
        | (if out.of { 2048u64 } else { 0u64 })
}

pub open spec fn execute(s: State, op: Decoded) -> (State, Diagnostic) {
    let status = diagnostic(s, op);
    if status != Diagnostic::Advanced {
        (s, status)
    } else {
        let out = outcome(s, op);
        (State {
            gpr: s.gpr.update(op.dst, out.result),
            flags: flags(s.flags, out),
            rip: (s.rip + op.length) % alu::modulus(),
        }, status)
    }
}

pub proof fn alias_and_frame(s: State, op: Decoded)
    requires valid(s), diagnostic(s, op) == Diagnostic::Advanced,
    ensures
        execute(s, op).0.gpr[op.dst] == outcome(s, op).result,
        forall|i: int| 0 <= i < 16 && i != op.dst
            ==> #[trigger] execute(s, op).0.gpr[i] == s.gpr[i],
        op.dst == op.src ==> outcome(s, op) == (
            if op.kind == Kind::Adc {
                alu::adc(s.gpr[op.dst], s.gpr[op.dst], s.flags & 1u64 != 0)
            } else {
                alu::add(s.gpr[op.dst], s.gpr[op.dst])
            }),
{
    reveal(outcome);
}

pub enum Decode {
    Success(Decoded),
    Stop(Diagnostic),
}

// Integer field-selection rule, independent of executable bit extraction.
pub open spec fn decode(bytes: Seq<u8>) -> Decode {
    if bytes.len() < 3 {
        Decode::Stop(Diagnostic::TruncatedInput)
    } else {
        let rex = bytes[0] as int;
        let opcode = bytes[1] as int;
        let modrm = bytes[2] as int;
        if !(72 <= rex <= 79) || !(opcode == 1 || opcode == 17) || modrm / 64 != 3 {
            Decode::Stop(Diagnostic::UnsupportedEncoding)
        } else {
            Decode::Success(Decoded {
                kind: if opcode == 17 { Kind::Adc } else { Kind::Add },
                dst: modrm % 8 + (rex % 2) * 8,
                src: (modrm / 8) % 8 + ((rex / 4) % 2) * 8,
                length: 3, profile: Profile::Long64,
            })
        }
    }
}

pub open spec fn step(s: State, bytes: Seq<u8>, profile: Profile)
    -> (State, (Diagnostic, int))
{
    match decode(bytes) {
        Decode::Stop(status) => (s, (status, 0)),
        Decode::Success(op) => {
            let executed = execute(s, Decoded { profile, ..op });
            (executed.0, (executed.1,
                if executed.1 == Diagnostic::Advanced { 3 } else { 0 }))
        },
    }
}

// Two externally supplied instruction buffers; there is no fetch or scheduler.
pub open spec fn two(s: State, first: Seq<u8>, second: Seq<u8>, profile: Profile)
    -> (State, (int, Diagnostic, int))
{
    let one = step(s, first, profile);
    if one.1.0 != Diagnostic::Advanced {
        (one.0, (0, one.1.0, 0))
    } else {
        let two = step(one.0, second, profile);
        (two.0, (if two.1.0 == Diagnostic::Advanced { 2 } else { 1 },
            two.1.0, one.1.1 + two.1.1))
    }
}

pub proof fn decoder_bounds_and_suffix(bytes: Seq<u8>)
    ensures
        match decode(bytes) {
            Decode::Success(op) => 0 <= op.dst < 16 && 0 <= op.src < 16
                && op.length == 3 && op.profile == Profile::Long64
                && (op.kind == Kind::Add || op.kind == Kind::Adc),
            Decode::Stop(status) => status == Diagnostic::TruncatedInput
                || status == Diagnostic::UnsupportedEncoding,
        },
        bytes.len() >= 3 ==> decode(bytes) == decode(bytes.take(3)),
{
}

pub proof fn partial_progress(s: State, first: Seq<u8>, second: Seq<u8>, profile: Profile)
    requires
        step(s, first, profile).1.0 == Diagnostic::Advanced,
        step(step(s, first, profile).0, second, profile).1.0 != Diagnostic::Advanced,
    ensures
        two(s, first, second, profile).0 == step(s, first, profile).0,
        two(s, first, second, profile).1.0 == 1,
        two(s, first, second, profile).1.2 == 3,
{
}

pub proof fn flag_properties(old: u64, out: alu::Outcome)
    ensures
        (flags(old, out) & 1u64 != 0) == out.cf,
        flags(old, out) & 0x10100u64 == old & 0x10100u64,
{
    let cf = out.cf;
    let pf = out.pf;
    let af = out.af;
    let zf = out.zf;
    let sf = out.sf;
    let of = out.of;
    let merged = flags(old, out);
    assert((merged & 1u64 != 0) == cf
        && merged & 0x10100u64 == old & 0x10100u64) by(bit_vector)
        requires merged == (old & !0x8d5u64)
            | (if cf { 1u64 } else { 0u64 })
            | (if pf { 4u64 } else { 0u64 })
            | (if af { 16u64 } else { 0u64 })
            | (if zf { 64u64 } else { 0u64 })
            | (if sf { 128u64 } else { 0u64 })
            | (if of { 2048u64 } else { 0u64 }),
        ;
}

pub proof fn high_register_carry_trace(s: State)
    requires valid(s), s.flags & 0x10100u64 == 0,
    ensures ({
        let result = two(s, seq![0x4du8, 0x01u8, 0xc8u8],
            seq![0x4du8, 0x11u8, 0xdau8], Profile::Long64);
        result.1 == (2int, Diagnostic::Advanced, 6int)
            && result.0.gpr[8] + result.0.gpr[10] * alu::modulus()
                == alu::total(s.gpr[8], s.gpr[10], s.gpr[9], s.gpr[11])
                    % alu::wide_modulus()
            && (result.0.flags & 1u64 != 0)
                == (alu::total(s.gpr[8], s.gpr[10], s.gpr[9], s.gpr[11])
                    >= alu::wide_modulus())
    }),
{
    reveal(outcome);
    let low = alu::add(s.gpr[8], s.gpr[9]);
    flag_properties(s.flags, low);
    let high = alu::adc(s.gpr[10], s.gpr[11], low.cf);
    flag_properties(flags(s.flags, low), high);
    alu::two_word_composition(s.gpr[8], s.gpr[10], s.gpr[9], s.gpr[11], low, high);
}

}
