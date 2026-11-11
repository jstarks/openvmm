// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use memory_core::shared::Beat;

verus! {

impl SharedMmu {
    /// WRITE-checked, naturally aligned RAM CAS in one physical beat.
    /// Completion reports the operand observed by the successful host CAS,
    /// including on architectural mismatch (a same-value write cycle).
    /// No CPU state is changed here; classified device operands are rejected by
    /// route_io rather than silently executed as ordinary device writes.
    pub fn begin_compare_exchange(&mut self, va: u64, expected: u64,
        replacement: u64, width: Width) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            accepted == (!spec::active(old(self)@.phase) && spec::compare_admitted(va, width)),
            final(self)@ == if accepted {
                spec::compare_begin(old(self)@, va, expected, replacement, width)
            } else { old(self)@ },
    {
        let size = match width { Width::Byte => 1u8, Width::Word => 2,
            Width::Dword => 4, Width::Qword => 8 };
        if va % size as u64 != 0 || va % 8 + size as u64 > 8
            || va % 4096 + size as u64 > 4096 || va > u64::MAX - (size as u64 - 1) {
            return false;
        }
        let accepted = self.begin_access(va, Access::Write(0), false, Some(WordAccess::Write(0)), size);
        if accepted { self.comparison = Some(Comparison {
            operation: AtomicOperation::CompareExchange { expected, replacement }, width }); }
        accepted
    }

    /// Locked integer operations share the conditional-CAS retry protocol.
    /// Every data conflict recomputes from the current target while retaining
    /// the captured source/flags and the already validated writable mapping.
    pub fn begin_locked_modify(&mut self, va: u64, operation: integer::Operation,
        source: u64, flags: u64, width: Width) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            accepted == (!spec::active(old(self)@.phase) && spec::locked_admitted(va, operation, width)),
            final(self)@ == if accepted {
                spec::locked_begin(old(self)@, va, operation, source, flags, width)
            } else { old(self)@ },
    {
        if !matches!(operation, integer::Operation::Add | integer::Operation::Adc
            | integer::Operation::Sub | integer::Operation::Sbb | integer::Operation::And
            | integer::Operation::Or | integer::Operation::Xor | integer::Operation::Inc
            | integer::Operation::Dec | integer::Operation::Neg | integer::Operation::Not
            | integer::Operation::BitSet | integer::Operation::BitReset
            | integer::Operation::BitComplement)
            || (matches!(operation,integer::Operation::BitSet | integer::Operation::BitReset
                | integer::Operation::BitComplement) && width==Width::Byte) {
            return false;
        }
        let size = match width { Width::Byte => 1u8, Width::Word => 2,
            Width::Dword => 4, Width::Qword => 8 };
        if va % size as u64 != 0 || va % 8 + size as u64 > 8
            || va % 4096 + size as u64 > 4096 || va > u64::MAX - (size as u64 - 1) {
            return false;
        }
        let accepted = self.begin_access(va, Access::Write(0), false, Some(WordAccess::Write(0)), size);
        if accepted { self.comparison = Some(Comparison {
            operation: AtomicOperation::Integer { operation, source, flags }, width }); }
        accepted
    }

    pub(super) fn atomic_observed(&self, data: WordData) -> (value: u64)
        ensures value == spec::atomic_observed(data, self.size),
    {
        (data.first >> ((data.address % 8 * 8) as u32)) & self.size_mask()
    }

    pub(super) fn atomic_store_request(&self, data: WordData) -> (out: Request)
        requires self.comparison is Some, spec::valid_span(data, self.size),
        ensures out == spec::atomic_request(data, self.size, self.comparison.unwrap()),
            match out { Request::DataCompare { address, .. } =>
                address < 0x1_0000_0000_0000u64 && address % 8 == 0, _ => false },
    {
        let comparison = self.comparison.unwrap();
        let original = self.atomic_observed(data);
        let value = match comparison.operation {
            AtomicOperation::CompareExchange { expected, replacement } =>
                if original == expected & self.size_mask() { replacement } else { original },
            AtomicOperation::Integer { operation, source, flags } =>
                integer::evaluate(operation, original, source, comparison.width, flags).value,
        };
        self.sized_store_request(WordData { value, ..data })
    }

    /// One WRITE-checked RAM translation, operand capture, and non-locked store.
    /// Operands retain the single-page checks and may span two physical beats.
    /// Completion returns the original operand, not the stored result. Flags
    /// remain the caller's responsibility. Leaf replacement recaptures data;
    /// data-beat contention preserves neighbors without recomputing the result.
    /// Compare/test are rejected without mutation.
    pub fn begin_modify(&mut self, va: u64, operation: integer::Operation,
        source: u64, flags: u64, width: Width) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            accepted == (!spec::active(old(self)@.phase) && spec::modify_admitted(va, operation, width)),
            final(self)@ == if accepted {
                spec::modify_begin(old(self)@, va, operation, source, flags, width)
            } else { old(self)@ },
    { self.begin_modify_mode(va, operation, source, flags, width, false) }

    pub(crate) fn begin_modify_span(&mut self, va: u64, operation: integer::Operation,
        source: u64, flags: u64, width: Width) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            accepted == (!spec::active(old(self)@.phase) && spec::modify_admitted(va, operation, width)),
            final(self)@ == if accepted {
                spec::modify_start(old(self)@, va, operation, source, flags, width, true)
            } else { old(self)@ },
    { self.begin_modify_mode(va, operation, source, flags, width, true) }

    fn begin_modify_mode(&mut self, va: u64, operation: integer::Operation,
        source: u64, flags: u64, width: Width, allow_cross: bool) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            accepted == (!spec::active(old(self)@.phase) && spec::modify_admitted(va, operation, width)),
            final(self)@ == if accepted {
                spec::modify_start(old(self)@, va, operation, source, flags, width, allow_cross)
            } else { old(self)@ },
    {
        let size = match width { Width::Byte => 1u8, Width::Word => 2,
            Width::Dword => 4, Width::Qword => 8 };
        if matches!(operation, integer::Operation::Cmp | integer::Operation::Test | integer::Operation::BitTest) {
            return false;
        }
        let accepted = self.begin_access_mode(va, Access::Write(0), false,
            Some(WordAccess::Write(0)), size, allow_cross);
        if accepted {
            self.modifier = Some(Modifier { operation, source, flags, width, original: 0 });
        }
        accepted
    }

    pub(crate) fn begin_span(&mut self, va: u64, request: WordAccess, size: u8) -> (accepted: bool)
        requires old(self).invariant(), size == 1 || size == 2 || size == 4 || size == 8,
        ensures final(self).invariant(), accepted == !spec::active(old(self)@.phase),
            final(self)@ == if accepted {
                spec::access_begin(old(self)@, va, word_model::request(request),
                    false, Some(request), size, true)
            } else { old(self)@ },
    {
        let access = match request { WordAccess::Read => Access::Read, WordAccess::Write(_) => Access::Write(0) };
        self.begin_access_mode(va, access, false, Some(request), size, true)
    }

    fn size_mask(&self) -> (mask: u64)
        ensures mask == spec::size_mask(self.size),
    {
        match self.size { 1 => 0xff, 2 => 0xffff, 4 => 0xffff_ffff, _ => u64::MAX }
    }

    pub(super) fn sized_store_request(&self, data: WordData) -> (out: Request)
        requires spec::valid_span(data, self.size),
        ensures out == spec::sized_request(data, self.size),
            match out { Request::DataCompare { address, .. } =>
                address < 0x1_0000_0000_0000u64 && address % 8 == 0, _ => false },
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
        requires old(self).inner.invariant(), old(self).valid_size(), old(self).valid_modifier(),
            old(self).head is None,
            old(self).valid_comparison(), !(result is Success),
            old(self).word is Some ==> old(self).access == word_model::request(old(self).word.unwrap()),
        ensures final(self).invariant(),
            final(self)@ == (spec::State { phase: spec::terminal(old(self)@, result, 0), ..old(self)@ }),
    { self.set_failure(result, 0); }

    fn loaded_value(&self, first: u64, tail: u64) -> (value: u64)
        requires self.valid_size(),
        ensures value == spec::observed(self@, first, tail),
    {
        let offset = self.va % 8;
        let value=if offset == 0 { first } else {
            let shift = (offset * 8) as u32;
            (first >> shift) | (tail << (64 - shift))
        };
        value & self.size_mask()
    }

    fn modify_value(&mut self, original: u64, value: u64) -> (replacement: u64)
        requires old(self).valid_modifier(),
        ensures final(self).valid_modifier(),
            final(self)@ == (spec::State {
                modifier: spec::captured_modifier(old(self)@.modifier, original), ..old(self)@ }),
            replacement == spec::modified_value(old(self)@.modifier, original, value),
    {
        match self.modifier {
            Some(m) => {
                let result = integer::evaluate(m.operation, original, m.source, m.width, m.flags);
                self.modifier = Some(Modifier { original, ..m });
                result.value
            },
            None => value,
        }
    }

    #[verifier::spinoff_prover]
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
        let original = self.loaded_value(first, tail);
        match self.word {
            Some(WordAccess::Read) => {
                self.inner.cache = Some(Mapping { page: self.va / 4096,
                    root: self.inner.config.root, frame, permissions, large });
                self.phase = Phase::WordDone { report: WordReport { result: WordResult::Success(original),
                    table_reads: reads, virtual_address: self.va } };
            },
            Some(WordAccess::Write(value)) => {
                let value = self.modify_value(original, value);
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
        if self.va % 4096 + self.size as u64 > 4096 {
            self.page_data_read(word);
            return;
        }
        match self.phase {
            Phase::Data { frame, permissions, leaf, reads, large } => {
                if self.va % 8 + self.size as u64 <= 8 {
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
        requires old(self).inner.invariant(), old(self).valid_size(), old(self).valid_modifier(),
            old(self).valid_comparison(), old(self).word is Some,
            old(self).word is Some ==> old(self).access == word_model::request(old(self).word.unwrap()),
        ensures final(self).invariant(), final(self)@ == spec::word_store_done(old(self)@, value, reads),
    {
        self.inner.cache = None;
        self.head = None;
        let original = match self.modifier { Some(m) => m.original, None => value };
        self.phase = Phase::WordDone { report: WordReport { result: WordResult::Success(original),
            table_reads: reads, virtual_address: self.va } };
    }

    pub(super) fn word_head_request(&self, data: WordData) -> (out: Request)
        requires data.address < 0x1_0000_0000_0000u64, data.address % 8 != 0,
        ensures out == spec::head_request(data, self.size),
            match out { Request::DataCompare { address, .. } =>
                address < 0x1_0000_0000_0000u64 && address % 8 == 0, _ => false },
    {
        let shift = (data.address % 8 * 8) as u32;
        let beat = Beat::masked(data.address / 8 * 8, shift, self.size_mask() << shift);
        Request::DataCompare { address: beat.address(), expected: data.first,
            replacement: beat.replace(data.first, data.value) }
    }

    pub(super) fn word_last_request(&self, data: WordData) -> (out: Request)
        requires spec::valid_data(data), data.address % 8 != 0,
        ensures out == spec::last_request(data, self.size),
            match out { Request::DataCompare { address, .. } =>
                address < 0x1_0000_0000_0000u64 && address % 8 == 0, _ => false },
    {
        let shift = (64 - data.address % 8 * 8) as u32;
        let beat = Beat::masked(data.address / 8 * 8 + 8, 0, self.size_mask() >> shift);
        let value = data.value >> shift;
        proof { assert(value << 0u32 == value) by(bit_vector); }
        Request::DataCompare { address: beat.address(), expected: data.tail,
            replacement: beat.replace(data.tail, value) }
    }

    #[verifier::spinoff_prover]
    fn page_data_read(&mut self, word: u64)
        requires old(self).invariant(), old(self).word is Some, old(self).phase is Data,
            old(self).va % 4096 + old(self).size as int > 4096,
        ensures final(self).invariant(), final(self)@ == spec::page_data(old(self)@, word),
    {
        match self.phase {
            Phase::Data { frame, leaf, reads, .. } => match self.head {
                None => {
                    self.head = Some(PageHead { address: frame + self.va % 4096, first: word, leaf });
                    self.inner.cache = None;
                    self.phase = Phase::Walk { table: self.inner.config.root, level: 0,
                        permissions: Permissions { rw: true, user: true, nx: false } };
                },
                Some(head) => {
                    let original = self.loaded_value(head.first, word);
                    match self.word {
                        Some(WordAccess::Read) => self.word_store_done(original, reads),
                        Some(WordAccess::Write(value)) => {
                            let value = self.modify_value(original, value);
                            match leaf {
                                Some(tail) => self.phase = Phase::PageDirtyHead { tail, reads,
                                    span: PageData { tail_address: frame, word: WordData {
                                        address: head.address, first: head.first, tail: word, value } } },
                                None => { proof { assert(false); } },
                            }
                        },
                        None => { proof { assert(false); } },
                    }
                },
            },
            _ => { proof { assert(false); } },
        }
    }

    pub(super) fn dirty_request(pte: Leaf) -> (out: Request)
        requires spec::valid_leaf(pte),
        ensures out == spec::dirty_request(pte),
            match out { Request::Compare { address, expected, replacement } =>
                address < 0x1_0000_0000_0000u64 && address % 8 == 0
                    && expected & 1 == 1 && replacement & !0x60u64 == expected & !0x60u64,
                _ => false },
    {
        let word = pte.word;
        let replacement = dirty(word);
        proof { assert((word | 64u64) == word + if word / 64u64 % 2u64 == 1u64 { 0u64 } else { 64u64 }) by(bit_vector); }
        proof { assert(word & 1 == 1 && replacement & !0x60u64 == word & !0x60u64)
            by(bit_vector) requires word % 2 == 1, replacement == word | 64u64; }
        Request::Compare { address: pte.address, expected: word, replacement }
    }

    pub(super) fn page_tail_request(&self, data: PageData) -> (out: Request)
        requires spec::valid_page_data(data),
        ensures out == spec::page_tail_request(data, self.size),
            match out { Request::DataCompare { address, .. } =>
                address < 0x1_0000_0000_0000u64 && address % 8 == 0, _ => false },
    {
        let shift = (64 - data.word.address % 8 * 8) as u32;
        let mask = self.size_mask() >> shift;
        Request::DataCompare { address: data.tail_address, expected: data.word.tail,
            replacement: (data.word.tail & !mask) | ((data.word.value >> shift) & mask) }
    }
}
}
