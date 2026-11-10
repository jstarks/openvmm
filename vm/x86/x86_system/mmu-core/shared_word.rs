// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use memory_core::shared::Beat;

verus! {

impl SharedMmu {
    /// Small RAM operands fit in one atomic physical beat; crossing forms are not admitted.
    pub(crate) fn begin_sized(&mut self, va: u64, request: WordAccess, size: u8) -> (accepted: bool)
        requires old(self).invariant(), size == 1 || size == 2 || size == 4,
            va % 8 + size as u64 <= 8,
        ensures final(self).invariant(), accepted == !spec::active(old(self)@.phase),
            final(self)@ == if accepted { spec::sized(old(self)@, va, request, size) } else { old(self)@ },
    {
        let access = match request { WordAccess::Read => Access::Read, WordAccess::Write(_) => Access::Write(0) };
        self.begin_access(va, access, false, Some(request), size)
    }

    fn size_mask(&self) -> (mask: u64)
        ensures mask == spec::size_mask(self.size),
    {
        match self.size { 1 => 0xff, 2 => 0xffff, 4 => 0xffff_ffff, _ => u64::MAX }
    }

    pub(super) fn sized_store_request(&self, data: WordData) -> (out: Request)
        requires spec::valid_span(data, self.size),
        ensures out == spec::sized_request(data, self.size),
    {
        let shift = (data.address % 8 * 8) as u32;
        let mask = self.size_mask() << shift;
        Request::DataCompare { address: data.address / 8 * 8, expected: data.first,
            replacement: (data.first & !mask) | ((data.value << shift) & mask) }
    }
    pub fn begin_word(&mut self, va: u64, request: WordAccess, user: bool) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(), accepted == !spec::active(old(self)@.phase),
            final(self)@ == if accepted { spec::begin(old(self)@, va,
                word_model::request(request), user, Some(request)) } else { old(self)@ },
    {
        let access = match request { WordAccess::Read => Access::Read, WordAccess::Write(_) => Access::Write(0) };
        self.begin_access(va, access, user, Some(request), 8)
    }

    pub(super) fn set_failure(&mut self, result: MmuResult, reads: u8)
        requires !(result is Success),
        ensures final(self)@ == (spec::State { phase: spec::terminal(old(self)@, result, reads), ..old(self)@ }),
    {
        self.phase = if self.word.is_some() {
            Phase::WordDone { report: WordReport { result: word::failure(result),
                table_reads: reads, virtual_address: self.va } }
        } else { Phase::Done(Report { result, table_reads: reads, virtual_address: self.va }) };
    }

    pub(super) fn precheck_failure(&mut self, result: MmuResult)
        requires old(self).inner.invariant(), old(self).valid_size(), !(result is Success),
            old(self).word is Some ==> old(self).access == word_model::request(old(self).word.unwrap()),
        ensures final(self).invariant(),
            final(self)@ == (spec::State { phase: spec::terminal(old(self)@, result, 0), ..old(self)@ }),
    { self.set_failure(result, 0); }

    pub(super) fn word_loaded(&mut self, frame: u64, permissions: Permissions,
        leaf: Option<Leaf>, first: u64, tail: u64, reads: u8)
        requires old(self).invariant(), old(self).word is Some,
            old(self).phase is Data || old(self).phase is WordTail,
            frame < 0x1_0000_0000_0000u64, frame % 4096 == 0,
            old(self).va as int + old(self).size as int - 1 <= u64::MAX,
            old(self).va % 4096 + old(self).size as int <= 4096,
            old(self).access is Write ==> leaf is Some,
            match leaf { Some(l) => spec::valid_leaf(l), None => true },
        ensures final(self).invariant(), final(self)@ ==
            spec::word_loaded(old(self)@, frame, permissions, leaf, first, tail, reads),
    {
        let large = match self.phase {
            Phase::Data { large, .. } | Phase::WordTail { large, .. } => large,
            _ => { assert(false); return; },
        };
        let address = frame + self.va % 4096;
        match self.word {
            Some(WordAccess::Read) => {
                let offset = self.va % 8;
                let value = if self.size < 8 {
                    (first >> ((offset * 8) as u32)) & self.size_mask()
                } else if offset == 0 { first } else {
                    let shift = (offset * 8) as u32;
                    (first >> shift) | (tail << (64 - shift))
                };
                self.inner.cache = Some(Mapping { page: self.va / 4096,
                    root: self.inner.config.root, frame, permissions, large });
                self.phase = Phase::WordDone { report: WordReport { result: WordResult::Success(value),
                    table_reads: reads, virtual_address: self.va } };
            },
            Some(WordAccess::Write(value)) => {
                match leaf {
                    Some(pte) => self.phase = Phase::WordDirty { pte,
                        data: WordData { address, first, tail, value }, reads },
                    None => { proof { assert(false); } },
                }
            },
            None => { proof { assert(false); } },
        }
    }

    pub(super) fn word_data_read(&mut self, word: u64)
        requires old(self).invariant(), old(self).word is Some, old(self).phase is Data,
        ensures final(self).invariant(), final(self)@ == spec::word_data(old(self)@, word),
    {
        match self.phase {
            Phase::Data { frame, permissions, leaf, reads, large } => {
                if self.va % 8 == 0 || self.size < 8 {
                    self.word_loaded(frame, permissions, leaf, word, 0, reads);
                } else {
                    self.phase = Phase::WordTail { frame, permissions, leaf, first: word, reads, large };
                }
            },
            _ => { proof { assert(false); } },
        }
    }

    pub(super) fn word_tail_read(&mut self, word: u64)
        requires old(self).invariant(), old(self).phase is WordTail,
        ensures final(self).invariant(), final(self)@ == spec::word_tail(old(self)@, word),
    {
        match self.phase {
            Phase::WordTail { frame, permissions, leaf, first, reads, .. } =>
                self.word_loaded(frame, permissions, leaf, first, word, reads),
            _ => { proof { assert(false); } },
        }
    }

    pub(super) fn word_store_done(&mut self, value: u64, reads: u8)
        requires old(self).inner.invariant(), old(self).valid_size(), old(self).word is Some,
            old(self).word is Some ==> old(self).access == word_model::request(old(self).word.unwrap()),
        ensures final(self).invariant(), final(self)@ == spec::word_store_done(old(self)@, value, reads),
    {
        self.inner.cache = None;
        self.phase = Phase::WordDone { report: WordReport { result: WordResult::Success(value),
            table_reads: reads, virtual_address: self.va } };
    }

    pub(super) fn word_head_request(&self, data: WordData) -> (out: Request)
        requires spec::valid_data(data), data.address % 8 != 0,
        ensures out == spec::head_request(data),
            match out { Request::DataCompare { address, .. } =>
                address < 0x1_0000_0000_0000u64 && address % 8 == 0, _ => false },
    {
        let shift = (data.address % 8 * 8) as u32;
        let beat = Beat::masked(data.address / 8 * 8, shift, u64::MAX << shift);
        Request::DataCompare { address: beat.address(), expected: data.first,
            replacement: beat.replace(data.first, data.value) }
    }

    pub(super) fn word_last_request(&self, data: WordData) -> (out: Request)
        requires spec::valid_data(data), data.address % 8 != 0,
        ensures out == spec::last_request(data),
            match out { Request::DataCompare { address, .. } =>
                address < 0x1_0000_0000_0000u64 && address % 8 == 0, _ => false },
    {
        let shift = (64 - data.address % 8 * 8) as u32;
        let beat = Beat::masked(data.address / 8 * 8 + 8, 0, u64::MAX >> shift);
        let value = data.value >> shift;
        proof { assert(value << 0u32 == value) by(bit_vector); }
        Request::DataCompare { address: beat.address(), expected: data.tail,
            replacement: beat.replace(data.tail, value) }
    }
}
}
