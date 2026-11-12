// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Device requests are distinct from RAM observations and completion replies.
use super::*;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Operand { pub address: u64, pub access: WordAccess, pub size:u8 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoRequest { pub sequence: u64, pub address: u64, pub access: WordAccess, pub size:u8 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoReply { Read(u64), Written }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoRoute { Accepted, NotReady, Unaligned, Exhausted }

impl SharedMmu {
    pub fn operand(&self) -> (out: Option<Operand>)
        requires self.invariant(),
        ensures out == spec::operand(self@),
    {
        if self.modifier.is_some() { return None; }
        match (self.phase, self.word) {
            (Phase::Data { frame, .. }, Some(access)) =>
                Some(Operand { address: frame + self.walk_va() % 4096, access, size:self.size }),
            _ => None,
        }
    }

    #[verifier::spinoff_prover]
    pub fn route_io(&mut self) -> (out: IoRoute)
        requires old(self).invariant(),
        ensures final(self).invariant(), (final(self)@, out) == spec::route_io(old(self)@),
    {
        if self.modifier.is_some() || self.comparison.is_some() || self.head.is_some() { return IoRoute::NotReady; }
        match (self.phase, self.word) {
            (Phase::Data { frame, leaf, reads, .. }, Some(access)) => {
                if self.va % self.size as u64 != 0 { return IoRoute::Unaligned; }
                if self.sequence == u64::MAX { return IoRoute::Exhausted; }
                let va = self.va;
                let address = frame + va % 4096;
                proof {
                    let size=self.size as u64;
                    assert(address % size == 0) by(bit_vector)
                        requires address == frame + va % 4096, frame % 4096 == 0,
                            va % size == 0, size==1 || size==2 || size==4 || size==8;
                }
                let phase = match access {
                    WordAccess::Read => Phase::IoReady { address, access, reads },
                    WordAccess::Write(value) => match leaf {
                        Some(pte) => Phase::IoDirty { pte, address, value, reads },
                        None => return IoRoute::NotReady,
                    },
                };
                self.sequence = self.sequence + 1;
                self.phase = phase;
                IoRoute::Accepted
            },
            _ => IoRoute::NotReady,
        }
    }

    pub fn complete_io(&mut self, sequence: u64, reply: IoReply) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            (final(self)@, accepted) == spec::complete_io(old(self)@, sequence, reply),
    {
        match self.phase {
            Phase::IoReady { access, reads, .. } => {
                if sequence != self.sequence { return false; }
                let value = match (access, reply) {
                    (WordAccess::Read, IoReply::Read(value)) => value,
                    (WordAccess::Write(value), IoReply::Written) => value,
                    _ => return false,
                };
                self.word_store_done(value, reads);
                true
            },
            _ => false,
        }
    }
}
}
