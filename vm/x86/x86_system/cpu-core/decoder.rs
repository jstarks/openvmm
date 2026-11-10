// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::{Decoded, Diagnostic, Kind, Profile, State, execute, model};
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decode {
    Success(Decoded),
    Stop(Diagnostic),
}

impl View for Decode {
    type V = model::Decode;
    open spec fn view(&self) -> model::Decode {
        match *self {
            Decode::Success(op) => model::Decode::Success(op@),
            Decode::Stop(status) => model::Decode::Stop(status),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    pub status: Diagnostic,
    pub consumed: u8,
}

impl View for Step {
    type V = (Diagnostic, int);
    open spec fn view(&self) -> (Diagnostic, int) { (self.status, self.consumed as int) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trace {
    pub completed: u8,
    pub status: Diagnostic,
    pub consumed: u8,
}

impl View for Trace {
    type V = (int, Diagnostic, int);
    open spec fn view(&self) -> (int, Diagnostic, int) {
        (self.completed as int, self.status, self.consumed as int)
    }
}

pub fn decode(bytes: &[u8]) -> (result: Decode)
    ensures
        result@ == model::decode(bytes@),
        match result {
            Decode::Success(op) => op.dst < 16 && op.src < 16 && op.length == 3
                && op.profile == Profile::Long64
                && (op.kind == Kind::Add || op.kind == Kind::Adc),
            _ => true,
        },
{
    if bytes.len() < 3 { return Decode::Stop(Diagnostic::TruncatedInput); }
    let rex = bytes[0];
    let opcode = bytes[1];
    let modrm = bytes[2];
    proof {
        assert(((rex & 0xf8u8) == 0x48u8) == (0x48u8 <= rex && rex <= 0x4fu8))
            by(bit_vector);
        assert(((modrm & 0xc0u8) == 0xc0u8) == (modrm / 64u8 == 3u8))
            by(bit_vector);
    }
    if rex & 0xf8 != 0x48 || (opcode != 0x01 && opcode != 0x11)
        || modrm & 0xc0 != 0xc0
    { return Decode::Stop(Diagnostic::UnsupportedEncoding); }
    proof {
        assert((modrm & 7u8) == modrm % 8u8) by(bit_vector);
        assert(((modrm >> 3u8) & 7u8) == (modrm / 8u8) % 8u8) by(bit_vector);
        assert((rex & 1u8) == rex % 2u8) by(bit_vector);
        assert(((rex >> 2u8) & 1u8) == (rex / 4u8) % 2u8) by(bit_vector);
        assert(modrm & 7u8 <= 7u8 && rex & 1u8 <= 1u8
            && (modrm >> 3u8) & 7u8 <= 7u8 && (rex >> 2u8) & 1u8 <= 1u8)
            by(bit_vector);
    }
    let dst = (modrm & 7) + (rex & 1) * 8;
    let src = ((modrm >> 3) & 7) + ((rex >> 2) & 1) * 8;
    proof {
        assert(dst as int == modrm as int % 8 + (rex as int % 2) * 8);
        assert(src as int == (modrm as int / 8) % 8 + ((rex as int / 4) % 2) * 8);
    }
    Decode::Success(Decoded {
        kind: if opcode == 0x11 { Kind::Adc } else { Kind::Add },
        dst, src, length: 3, profile: Profile::Long64,
    })
}

pub fn step(s: &mut State, bytes: &[u8], profile: Profile) -> (result: Step)
    ensures
        (final(s)@, result@) == model::step(old(s)@, bytes@, profile),
        result.status != Diagnostic::Advanced ==> final(s)@ == old(s)@,
        result.consumed == (if result.status == Diagnostic::Advanced { 3u8 } else { 0u8 }),
{
    match decode(bytes) {
        Decode::Stop(status) => Step { status, consumed: 0 },
        Decode::Success(mut op) => {
            op.profile = profile;
            let status = execute(s, op);
            let consumed = match status { Diagnostic::Advanced => 3u8, _ => 0u8 };
            Step { status, consumed }
        },
    }
}

pub fn two(s: &mut State, first: &[u8], second: &[u8], profile: Profile)
    -> (result: Trace)
    ensures
        (final(s)@, result@) == model::two(old(s)@, first@, second@, profile),
        result.completed <= 2,
        result.consumed == result.completed * 3,
        result.completed == 0 ==> final(s)@ == old(s)@,
        result.completed == 1 ==> final(s)@ == model::step(old(s)@, first@, profile).0,
{
    let one = step(s, first, profile);
    match one.status {
        Diagnostic::Advanced => {
            let two = step(s, second, profile);
            let completed = match two.status { Diagnostic::Advanced => 2u8, _ => 1u8 };
            Trace { completed, status: two.status, consumed: one.consumed + two.consumed }
        },
        status => Trace { completed: 0, status, consumed: 0 },
    }
}

}
