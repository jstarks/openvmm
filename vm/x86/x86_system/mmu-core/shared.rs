// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resumable MMU effects over concurrently modified physical RAM.
use super::word::{WordAccess, WordReport, WordResult};
use super::{shared_model as spec, *};
use memory_core::cpu_core::{integer, operand::Width};
use memory_core::shared::{BeatError, Exchange, PhysicalRam};
#[path = "shared_io.rs"]
pub mod io;
#[path = "shared_word.rs"]
mod words;
use io::{IoRequest, IoRoute};

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leaf { pub address: u64, pub word: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordData { pub address: u64, pub first: u64, pub tail: u64, pub value: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageHead { pub address: u64, pub first: u64, pub leaf: Option<Leaf> }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageData { pub word: WordData, pub tail_address: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Modifier {
    pub operation: integer::Operation,
    pub source: u64,
    pub flags: u64,
    pub width: Width,
    pub original: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicOperation {
    CompareExchange { expected: u64, replacement: u64 },
    Exchange {replacement:u64},
    Integer { operation: integer::Operation, source: u64, flags: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Comparison {
    pub operation: AtomicOperation,
    pub width: Width,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Walk { table: u64, level: u8, permissions: Permissions },
    Mark { address: u64, word: u64, level: u8, frame: u64, permissions: Permissions },
    Data { frame: u64, permissions: Permissions, leaf: Option<Leaf>, reads: u8, large: bool },
    Dirty { pte: Leaf, address: u64, word: u64, reads: u8 },
    Store { address: u64, word: u64, reads: u8 },
    Done(Report),
    WordTail { frame: u64, permissions: Permissions, leaf: Option<Leaf>, first: u64, reads: u8, large: bool },
    WordDirty { pte: Leaf, data: WordData, reads: u8 },
    WordStore { data: WordData, reads: u8 },
    WordHead { data: WordData, reads: u8 },
    WordLast { data: WordData, reads: u8 },
    SizedStore { data: WordData, reads: u8 },
    AtomicStore { data: WordData, reads: u8 },
    PageDirtyHead { tail: Leaf, span: PageData, reads: u8 },
    PageDirtyTail { pte: Leaf, span: PageData, reads: u8 },
    PageStoreHead { span: PageData, reads: u8 },
    PageStoreTail { span: PageData, reads: u8 },
    WordDone { report: WordReport },
    IoDirty { pte: Leaf, address: u64, value: u64, reads: u8 },
    IoReady { address: u64, access: WordAccess, reads: u8 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Idle,
    Read(u64),
    Compare { address: u64, expected: u64, replacement: u64 },
    WriteByte { address: u64, expected: u64, value: u8 },
    Complete(Report),
    DataCompare { address: u64, expected: u64, replacement: u64 },
    WriteWord { address: u64, word_value: u64 },
    CompleteWord { report: WordReport },
    Io(IoRequest),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply { Read(u64), Committed, Changed(u64) }

pub struct SharedMmu {
    inner: Mmu,
    phase: Phase,
    va: u64,
    access: Access,
    user: bool,
    word: Option<WordAccess>,
    sequence: u64,
    size: u8,
    modifier: Option<Modifier>,
    comparison: Option<Comparison>,
    head: Option<PageHead>,
}

impl View for SharedMmu {
    type V = spec::State;
    closed spec fn view(&self) -> spec::State {
        spec::State { inner: self.inner@, phase: self.phase,
            va: self.va, access: self.access, user: self.user, word: self.word,
            sequence: self.sequence, size: self.size, modifier: self.modifier,
            comparison: self.comparison, head: self.head }
    }
}

impl SharedMmu {
    pub closed spec fn valid_comparison(&self) -> bool {
        match self.comparison {
            Some(c) => self.word == Some(WordAccess::Write(0))
                && self.access == Access::Write(0) && self.modifier is None
                && self.size == spec::modify_size(c.width)
                && spec::compare_admitted(self.va, c.width)
                && match c.operation {
                    AtomicOperation::CompareExchange { .. } | AtomicOperation::Exchange {..} => true,
                    AtomicOperation::Integer { operation, .. } =>
                        spec::locked_admitted(self.va, operation, c.width),
                }
                && !(self.phase is IoDirty) && !(self.phase is IoReady)
                && match self.phase {
                    Phase::WordDirty { data, .. } | Phase::AtomicStore { data, .. } =>
                        data.address % 8 + self.size as int <= 8,
                    _ => true,
                },
            None => true,
        }
    }

    pub closed spec fn valid_modifier(&self) -> bool {
        match self.modifier {
            Some(m) => self.word == Some(WordAccess::Write(0))
                && self.access == Access::Write(0)
                && self.size == spec::modify_size(m.width)
                && spec::modify_admitted(self.va, m.operation, m.width)
                && !(self.phase is IoDirty) && !(self.phase is IoReady),
            None => true,
        }
    }

    pub closed spec fn valid_size(&self) -> bool {
        self.size == 1 || self.size == 2 || self.size == 4 || self.size == 8
    }

    pub closed spec fn valid_head(&self) -> bool {
        match self.head {
            Some(h) => spec::valid_page_head(h) && spec::active(self.phase)
                && self.word is Some && self.comparison is None
                && h.address % 4096 == self.va % 4096
                && self.va % 4096 + self.size as int > 4096
                && self.va as int + self.size as int - 1 <= u64::MAX
                && (self.access is Write ==> h.leaf is Some),
            None => true,
        }
    }

    pub closed spec fn invariant(&self) -> bool {
        self.inner.invariant()
        && self.valid_size()
        && self.valid_modifier()
        && self.valid_comparison()
        && self.valid_head()
        && (spec::active(self.phase) ==> mmu_model::valid_config(self.inner.config))
        && (spec::active(self.phase) && self.word is Some ==>
            self.va as int + self.size as int - 1 <= u64::MAX)
        && (self.word is Some ==> self.access == word_model::request(self.word.unwrap()))
        && match self.phase {
            Phase::Done(_) | Phase::Dirty { .. } | Phase::Store { .. } => self.word is None,
            Phase::WordTail { .. } | Phase::WordDirty { .. } | Phase::WordStore { .. }
                | Phase::WordHead { .. } | Phase::WordLast { .. } | Phase::WordDone { .. }
                | Phase::SizedStore { .. } | Phase::AtomicStore { .. }
                | Phase::PageDirtyHead { .. } | Phase::PageDirtyTail { .. }
                | Phase::PageStoreHead { .. } | Phase::PageStoreTail { .. }
                | Phase::IoDirty { .. } | Phase::IoReady { .. } => self.word is Some,
            _ => true,
        }
        && match self.phase {
            Phase::Walk { table, level, .. } =>
                level < 4 && table < 0x1_0000_0000_0000u64 && table % 4096 == 0,
            Phase::Mark { address, word, frame, level, .. } =>
                level < 4 && frame < 0x1_0000_0000_0000u64 && frame % 4096 == 0
                    && address < 0x1_0000_0000_0000u64 && address % 8 == 0 && word % 2 == 1,
            Phase::Data { frame, leaf, .. } =>
                frame < 0x1_0000_0000_0000u64 && frame % 4096 == 0
                    && (self.access is Write ==> leaf is Some)
                    && match leaf { Some(l) => l.address < 0x1_0000_0000_0000u64
                        && l.address % 8 == 0 && l.word % 2 == 1, None => true },
            Phase::Dirty { pte, address, .. } => self.access is Write
                && pte.address < 0x1_0000_0000_0000u64 && pte.address % 8 == 0
                && pte.word % 2 == 1 && address < 0x1_0000_0000_0000u64,
            Phase::Store { address, .. } => self.access is Write && address < 0x1_0000_0000_0000u64,
            Phase::WordTail { frame, leaf, .. } => self.word is Some
                && self.va % 8 + self.size as int > 8
                && self.va % 4096 + self.size as int <= 4096
                && frame < 0x1_0000_0000_0000u64 && frame % 4096 == 0
                && (self.access is Write ==> leaf is Some)
                && match leaf { Some(l) => spec::valid_leaf(l), None => true },
            Phase::WordDirty { pte, data, .. } => self.word is Some
                && self.access is Write && spec::valid_leaf(pte) && spec::valid_span(data, self.size),
            Phase::WordStore { data, .. } => self.word is Some
                && self.access is Write && spec::valid_data(data) && data.address % 8 == 0,
            Phase::WordHead { data, .. } | Phase::WordLast { data, .. } => self.word is Some
                && self.access is Write && spec::valid_data(data) && data.address % 8 != 0,
            Phase::SizedStore { data, .. } => self.word is Some
                && self.access is Write && spec::valid_span(data, self.size) && self.size < 8
                && data.address % 8 + self.size as int <= 8,
            Phase::AtomicStore { data, .. } => self.comparison is Some
                && spec::valid_span(data, self.size),
            Phase::PageDirtyHead { tail, span: data, .. } =>
                self.access is Write && self.head is Some && spec::valid_leaf(tail)
                && spec::valid_page_data(data) && data.word.address == self.head.unwrap().address,
            Phase::PageDirtyTail { pte, span: data, .. } =>
                self.access is Write && self.head is Some && spec::valid_leaf(pte)
                && spec::valid_page_data(data) && data.word.address == self.head.unwrap().address,
            Phase::PageStoreHead { span: data, .. } | Phase::PageStoreTail { span: data, .. } =>
                self.access is Write && self.head is Some && spec::valid_page_data(data)
                && data.word.address == self.head.unwrap().address,
            Phase::IoDirty { pte, address, value, .. } => spec::valid_leaf(pte)
                && address < 0x1_0000_0000_0000u64 && address % self.size as u64 == 0
                && self.word == Some(WordAccess::Write(value)),
            Phase::IoReady { address, access, .. } =>
                address < 0x1_0000_0000_0000u64 && address % self.size as u64 == 0
                && self.word == Some(access),
            _ => true,
        }
    }

    pub fn new(config: Config, cr2: u64) -> (s: Self)
        ensures s.invariant(), s@.inner == (mmu_model::State {
                config, cache: None, fetch_cache:None, cr2: cr2 as int }),
            s@.phase == Phase::Idle, s@.sequence == 0,
    {
        Self { inner: Mmu::new(config, cr2), phase: Phase::Idle,
            va: 0, access: Access::Read, user: false, word: None,
            sequence: 0, size: 8, modifier: None, comparison: None, head: None }
    }

    pub fn cr2(&self) -> (v: u64)
        ensures v as int == self@.inner.cr2,
    { self.inner.cr2() }

    pub fn config(&self) -> (v: Config) ensures v == self@.inner.config { self.inner.config }

    pub fn virtual_address(&self) -> (v: u64) ensures v == self@.va { self.va }

    pub fn cache_count(&self) -> (v: u8)
        ensures v as int==(if self@.inner.cache is Some {1int} else {0int})
            +(if self@.inner.fetch_cache is Some {1int} else {0int}),
    { self.inner.cache_count() }

    /// False means another access is pending; state is unchanged.
    pub fn begin(&mut self, va: u64, access: Access, user: bool) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            accepted == !spec::active(old(self)@.phase),
            final(self)@ == if accepted { spec::begin(old(self)@, va, access, user, None) } else { old(self)@ },
    { self.begin_access(va, access, user, None, 8) }

    fn begin_access(&mut self, va: u64, access: Access, user: bool, word: Option<WordAccess>, size: u8) -> (accepted: bool)
        requires old(self).invariant(),
            size == 1 || size == 2 || size == 4 || size == 8,
            word is Some ==> access == word_model::request(word.unwrap()),
        ensures final(self).invariant(),
            accepted == !spec::active(old(self)@.phase),
            final(self)@ == if accepted { spec::span_begin(old(self)@, va, access, user, word, size) } else { old(self)@ },
    { self.begin_access_mode(va, access, user, word, size, false) }

    fn begin_access_mode(&mut self, va: u64, access: Access, user: bool,
        word: Option<WordAccess>, size: u8, allow_cross: bool) -> (accepted: bool)
        requires old(self).invariant(),
            size == 1 || size == 2 || size == 4 || size == 8,
            word is Some ==> access == word_model::request(word.unwrap()),
        ensures final(self).invariant(), accepted == !spec::active(old(self)@.phase),
            final(self)@ == if accepted {
                spec::access_begin(old(self)@, va, access, user, word, size, allow_cross)
            } else { old(self)@ },
    {
        if self.active() { return false; }
        self.va = va; self.access = access; self.user = user;
        self.word = word;
        self.size = size;
        self.modifier = None;
        self.comparison = None;
        self.head = None;
        if word.is_some() {
            if va > u64::MAX - (size as u64 - 1) {
                self.phase = Phase::WordDone { report: WordReport { result: WordResult::Wrap,
                    table_reads: 0, virtual_address: va } };
                return true;
            }
            if !allow_cross && va % 4096 + size as u64 > 4096 {
                self.phase = Phase::WordDone { report: WordReport { result: WordResult::CrossPage,
                    table_reads: 0, virtual_address: va } };
                return true;
            }
        }
        if !valid_config(self.inner.config) {
            self.precheck_failure(MmuResult::InvalidConfig);
        } else if !canonical(va) || (allow_cross && word.is_some()
            && !canonical(va + (size as u64 - 1))) {
            self.precheck_failure(MmuResult::GeneralProtection);
        } else {
            if let Some(m) = if matches!(access,Access::Fetch) {self.inner.fetch_cache} else {self.inner.cache} {
                if m.page == va / 4096 && m.root == self.inner.config.root
                    && !matches!(access, Access::Write(_)) && allowed(m.permissions, self.inner.config, access, user) {
                    self.phase = Phase::Data { frame: m.frame, permissions: m.permissions,
                        leaf: None, reads: 0, large: m.large };
                    return true;
                }
            }
            self.restart();
        }
        true
    }

    pub fn active(&self) -> (out: bool)
        ensures out == spec::active(self@.phase),
    { !matches!(self.phase, Phase::Idle | Phase::Done(_) | Phase::WordDone { .. }) }

    pub fn reload(&mut self, config: Config) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(), accepted == !spec::active(old(self)@.phase),
            final(self)@ == if accepted {
                spec::State { inner: mmu_model::reload(old(self)@.inner, config),
                    phase: Phase::Idle, ..old(self)@ }
            } else { old(self)@ },
    {
        if self.active() { return false; }
        self.inner.reload(config);
        self.phase = Phase::Idle;
        true
    }

    pub fn invalidate(&mut self, va: u64) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(), accepted == !spec::active(old(self)@.phase),
            final(self)@ == if accepted {
                spec::State { inner: mmu_model::invalidate(old(self)@.inner, va as int),
                    phase: Phase::Idle, ..old(self)@ }
            } else { old(self)@ },
    {
        if self.active() { return false; }
        self.inner.invalidate(va);
        self.phase = Phase::Idle;
        true
    }

    fn restart(&mut self)
        requires old(self).inner.invariant(), old(self).valid_size(), old(self).valid_modifier(),
            old(self).valid_comparison(),
            mmu_model::valid_config(old(self).inner.config),
            old(self).word is Some ==> old(self).va as int + old(self).size as int - 1 <= u64::MAX,
            old(self).word is Some ==> old(self).access == word_model::request(old(self).word.unwrap()),
        ensures final(self)@ == spec::restart(old(self)@), final(self).invariant(),
    {
        self.head = None;
        self.phase = Phase::Walk { table: self.inner.config.root, level: 0,
            permissions: Permissions { rw: true, user: true, nx: false } };
    }

    fn fail(&mut self, result: MmuResult, reads: u8)
        requires old(self).inner.invariant(), old(self).valid_size(), old(self).valid_modifier(),
            old(self).valid_comparison(), !(result is Success),
            old(self).word is Some ==> old(self).access == word_model::request(old(self).word.unwrap()),
        ensures final(self)@ == spec::fault(old(self)@, result, reads), final(self).invariant(),
    {
        self.inner.fault(result, self.walk_va());
        self.head = None;
        self.set_failure(result, reads);
    }

    fn walk_va(&self) -> (va: u64)
        ensures va == spec::walk_va(self@),
    {
        if self.head.is_some() { self.va.wrapping_add(4096 - self.va % 4096) }
        else { self.va }
    }

    #[verifier::spinoff_prover]
    pub fn request(&self) -> (out: Request)
        requires self.invariant(),
        ensures out == spec::request(self@),
            match out {
                Request::Read(address) => address < 0x1_0000_0000_0000u64 && address % 8 == 0,
                Request::WriteWord { address, .. } | Request::DataCompare { address, .. } =>
                    address < 0x1_0000_0000_0000u64 && address % 8 == 0,
                Request::Compare { address, expected, replacement } =>
                    address < 0x1_0000_0000_0000u64 && address % 8 == 0
                        && expected & 1 == 1 && replacement & !0x60u64 == expected & !0x60u64,
                _ => true,
            },
    {
        match self.phase {
            Phase::Idle => Request::Idle,
            Phase::Done(r) => Request::Complete(r),
            Phase::Walk { table, level, .. } => Request::Read(table + index(self.walk_va(), level) * 8),
            Phase::Mark { address, word, .. } => {
                let replacement = accessed(word);
                proof { assert((word | 32u64) == word + if word / 32u64 % 2u64 == 1u64 { 0u64 } else { 32u64 }) by(bit_vector); }
                proof { assert(word & 1 == 1 && replacement & !0x60u64 == word & !0x60u64)
                    by(bit_vector) requires word % 2 == 1, replacement == word | 32u64; }
                Request::Compare { address, expected: word, replacement }
            },
            Phase::Data { frame, .. } => Request::Read((frame + self.walk_va() % 4096) / 8 * 8),
            Phase::Dirty { pte, .. } => {
                let word = pte.word;
                let replacement = dirty(word);
                proof { assert((word | 64u64) == word + if word / 64u64 % 2u64 == 1u64 { 0u64 } else { 64u64 }) by(bit_vector); }
                proof { assert(word & 1 == 1 && replacement & !0x60u64 == word & !0x60u64)
                    by(bit_vector) requires word % 2 == 1, replacement == word | 64u64; }
                Request::Compare { address: pte.address, expected: word, replacement }
            },
            Phase::Store { address, word, .. } =>
                Request::WriteByte { address, expected: word,
                    value: match self.access { Access::Write(v) => v, _ => 0 } },
            Phase::WordDone { report } => Request::CompleteWord { report },
            Phase::WordTail { frame, .. } => Request::Read((frame + self.va % 4096) / 8 * 8 + 8),
            Phase::WordDirty { pte, .. } | Phase::IoDirty { pte, .. } => {
                let word = pte.word;
                let replacement = dirty(word);
                proof { assert((word | 64u64) == word + if word / 64u64 % 2u64 == 1u64 { 0u64 } else { 64u64 }) by(bit_vector); }
                proof { assert(word & 1 == 1 && replacement & !0x60u64 == word & !0x60u64)
                    by(bit_vector) requires word % 2 == 1, replacement == word | 64u64; }
                Request::Compare { address: pte.address, expected: word, replacement }
            },
            Phase::WordStore { data, .. } => Request::WriteWord { address: data.address, word_value: data.value },
            Phase::WordHead { data, .. } => self.word_head_request(data),
            Phase::WordLast { data, .. } => self.word_last_request(data),
            Phase::SizedStore { data, .. } => self.sized_store_request(data),
            Phase::AtomicStore { data, .. } => self.atomic_store_request(data),
            Phase::PageDirtyHead { .. } => Self::dirty_request(self.head.unwrap().leaf.unwrap()),
            Phase::PageDirtyTail { pte, .. } => Self::dirty_request(pte),
            Phase::PageStoreHead { span: data, .. } => self.word_head_request(data.word),
            Phase::PageStoreTail { span: data, .. } => self.page_tail_request(data),
            Phase::IoReady { address, access, .. } =>
                Request::Io(IoRequest { sequence: self.sequence, address, access, size:self.size }),
        }
    }

    /// False rejects a response of the wrong kind without advancing.
    pub fn read(&mut self, word: u64) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            accepted == (old(self)@.phase is Walk || old(self)@.phase is Data || old(self)@.phase is WordTail),
            final(self)@ == spec::read(old(self)@, word),
    {
        match self.phase {
            Phase::Walk { table, level, permissions } => {
                let e = entry(word, level, self.inner.config.nxe);
                let next = combine(permissions, &e);
                if !e.present {
                    let result = if !allowed(permissions, self.inner.config, self.access, self.user) {
                        MmuResult::Ambiguous
                    } else { MmuResult::PageFault(pfec(self.inner.config, self.access, self.user, false, false)) };
                    self.fail(result, level + 1);
                } else if e.reserved {
                    let result = if !allowed(next, self.inner.config, self.access, self.user) {
                        MmuResult::Ambiguous
                    } else { MmuResult::PageFault(pfec(self.inner.config, self.access, self.user, true, true)) };
                    self.fail(result, level + 1);
                } else if e.huge && level == 1 {
                    self.fail(MmuResult::HugePage, level + 1);
                } else {
                    self.phase = Phase::Mark { address: table + index(self.walk_va(), level) * 8,
                        word, level, frame: if e.huge { leaf_frame(e.base, self.walk_va(), level) } else { e.base },
                        permissions: next };
                }
                true
            },
            Phase::Data { frame, permissions, leaf, reads, large } => {
                if self.word.is_some() {
                    self.word_data_read(word);
                    return true;
                }
                let address = frame + self.va % 4096;
                match self.access {
                    Access::Write(_) => {
                        match leaf {
                            Some(l) => self.phase = Phase::Dirty { pte: l, address, word, reads },
                            None => { proof { assert(false); } return false; },
                        }
                    },
                    _ => {
                        let mapping=Some(Mapping { page: self.va / 4096,
                            root: self.inner.config.root, frame, permissions, large });
                        if matches!(self.access,Access::Fetch) {self.inner.fetch_cache=mapping;}
                        else {self.inner.cache=mapping;}
                        self.phase = Phase::Done(Report { result: MmuResult::Success(
                            ((word >> ((self.va % 8 * 8) as u32)) & 255) as u8),
                            table_reads: reads, virtual_address: self.va });
                    },
                }
                true
            },
            Phase::WordTail { .. } => { self.word_tail_read(word); true },
            _ => false,
        }
    }

    #[verifier::spinoff_prover]
    pub fn exchanged(&mut self) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            accepted == spec::can_commit(old(self)@.phase),
            final(self)@ == spec::exchanged(old(self)@),
    {
        match self.phase {
            Phase::Mark { address, word, level, frame, permissions } => {
                if level < 3 && !(level == 2 && word / 128 % 2 == 1) {
                    self.phase = Phase::Walk { table: frame, level: level + 1, permissions };
                } else if !allowed(permissions, self.inner.config, self.access, self.user) {
                    self.fail(MmuResult::PageFault(pfec(self.inner.config, self.access, self.user, true, false)), level + 1);
                } else {
                    self.phase = Phase::Data { frame, permissions, reads: level + 1, large: level == 2,
                        leaf: Some(Leaf { address, word: accessed(word) }) };
                }
                true
            },
            Phase::Dirty { address, word, reads, .. } => {
                self.phase = Phase::Store { address, word, reads };
                true
            },
            Phase::Store { reads, .. } => {
                self.inner.cache = None;
                self.phase = Phase::Done(Report { result: MmuResult::Success(
                    match self.access { Access::Write(v) => v, _ => 0 }),
                    table_reads: reads, virtual_address: self.va });
                true
            },
            Phase::WordDirty { data, reads, .. } => {
                self.phase = if self.comparison.is_some() { Phase::AtomicStore { data, reads } }
                    else if self.size < 8 && data.address % 8 + self.size as u64 <= 8 {
                        Phase::SizedStore { data, reads }
                    }
                    else if data.address % 8 == 0 { Phase::WordStore { data, reads } }
                    else { Phase::WordHead { data, reads } };
                true
            },
            Phase::WordHead { data, reads } => {
                self.phase = Phase::WordLast { data, reads };
                true
            },
            Phase::IoDirty { address, value, reads, .. } => {
                self.phase = Phase::IoReady { address, access: WordAccess::Write(value), reads };
                true
            },
            Phase::WordStore { data, reads } | Phase::WordLast { data, reads } | Phase::SizedStore { data, reads } => {
                self.word_store_done(data.value, reads);
                true
            },
            Phase::AtomicStore { data, reads } => {
                let observed = self.atomic_observed(data);
                self.word_store_done(observed, reads);
                true
            },
            Phase::PageDirtyHead { tail, span: data, reads } => {
                let head = self.head.unwrap().leaf.unwrap();
                self.phase = if head.address == tail.address && head.word == tail.word { Phase::PageStoreHead { span: data, reads } }
                    else { Phase::PageDirtyTail { pte: tail, span: data, reads } };
                true
            },
            Phase::PageDirtyTail { span: data, reads, .. } => {
                self.phase = Phase::PageStoreHead { span: data, reads }; true
            },
            Phase::PageStoreHead { span: data, reads } => {
                self.phase = Phase::PageStoreTail { span: data, reads }; true
            },
            Phase::PageStoreTail { span: data, reads } => {
                self.word_store_done(data.word.value, reads); true
            },
            _ => false,
        }
    }

    pub fn changed(&mut self, current: u64) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            accepted == spec::can_change(old(self)@.phase),
            final(self)@ == spec::changed(old(self)@, current),
    {
        match self.phase {
            Phase::Mark { .. } | Phase::Dirty { .. } => { self.restart(); true },
            Phase::WordDirty { .. } | Phase::IoDirty { .. } => { self.restart(); true },
            Phase::PageDirtyHead { .. } | Phase::PageDirtyTail { .. } => { self.restart(); true },
            Phase::Store { address, reads, .. } => {
                self.phase = Phase::Store { address, word: current, reads };
                true
            },
            Phase::WordHead { data, reads } => {
                self.phase = Phase::WordHead { data: WordData { first: current, ..data }, reads }; true
            },
            Phase::WordLast { data, reads } => {
                self.phase = Phase::WordLast { data: WordData { tail: current, ..data }, reads }; true
            },
            Phase::SizedStore { data, reads } => {
                self.phase = Phase::SizedStore { data: WordData { first: current, ..data }, reads }; true
            },
            Phase::AtomicStore { data, reads } => {
                self.phase = Phase::AtomicStore { data: WordData { first: current, ..data }, reads }; true
            },
            Phase::PageStoreHead { span: data, reads } => {
                self.phase = Phase::PageStoreHead { span: PageData {
                    word: WordData { first: current, ..data.word }, ..data }, reads }; true
            },
            Phase::PageStoreTail { span: data, reads } => {
                self.phase = Phase::PageStoreTail { span: PageData {
                    word: WordData { tail: current, ..data.word }, ..data }, reads }; true
            },
            _ => false,
        }

    }

    pub fn respond(&mut self, reply: Reply) -> (accepted: bool)
        requires old(self).invariant(),
        ensures final(self).invariant(),
            (final(self)@, accepted) == spec::respond(old(self)@, reply),
    {
        match reply {
            Reply::Read(word) => self.read(word),
            Reply::Committed => self.exchanged(),
            Reply::Changed(current) => self.changed(current),
        }
    }
}
}

/// A bounded batch either finishes or retains the exact pending request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    Complete(Report),
    CompleteWord(WordReport),
    Yield,
}

#[derive(Debug)]
pub enum RunError<E> {
    Memory { request: Request, source: E },
    Protocol(Request),
    InvalidBeat(BeatError),
    IoProfile(IoRoute),
}

impl<E: core::fmt::Display> core::fmt::Display for RunError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Memory { request, source } => write!(f, "MMU RAM request {request:?}: {source}"),
            Self::Protocol(request) => write!(f, "invalid MMU response for {request:?}"),
            Self::InvalidBeat(error) => write!(f, "invalid MMU byte beat: {error:?}"),
            Self::IoProfile(route) => write!(f, "unsupported MMIO admission: {route:?}"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for RunError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Memory { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl SharedMmu {
    /// Dispatches atomic effects; provider/compiler correctness remains trusted.
    /// Memory failure retains the request and is not an architectural exception.
    pub fn run<R: PhysicalRam>(
        &mut self,
        ram: &R,
        budget: u32,
    ) -> Result<Progress, RunError<R::Error>> {
        for _ in 0..budget {
            let request = self.request();
            match request {
                Request::Complete(report) => return Ok(Progress::Complete(report)),
                Request::CompleteWord { report } => return Ok(Progress::CompleteWord(report)),
                _ => {}
            }
            let accepted = self.respond(perform(ram, request)?);
            if !accepted {
                return Err(RunError::Protocol(request));
            }
        }
        match self.request() {
            Request::Idle => Err(RunError::Protocol(Request::Idle)),
            Request::Complete(report) => Ok(Progress::Complete(report)),
            Request::CompleteWord { report } => Ok(Progress::CompleteWord(report)),
            _ => Ok(Progress::Yield),
        }
    }
}

/// Performs exactly one requested physical effect; never advances a CPU/MMU.
pub fn perform<R: PhysicalRam>(ram: &R, request: Request) -> Result<Reply, RunError<R::Error>> {
    let exchange = match request {
        Request::Read(address) => {
            return ram
                .read_word(address)
                .map(Reply::Read)
                .map_err(|source| RunError::Memory { request, source });
        }
        Request::WriteWord {
            address,
            word_value,
        } => {
            ram.write_word(address, word_value)
                .map_err(|source| RunError::Memory { request, source })?;
            return Ok(Reply::Committed);
        }
        Request::Compare {
            address,
            expected,
            replacement,
        }
        | Request::DataCompare {
            address,
            expected,
            replacement,
        } => ram.compare_exchange_word(address, expected, replacement),
        Request::WriteByte {
            address,
            expected,
            value,
        } => {
            let beat = memory_core::shared::plan(address, 1).map_err(RunError::InvalidBeat)?;
            ram.compare_exchange_word(
                beat.address(),
                expected,
                beat.replace(expected, value.into()),
            )
        }
        _ => return Err(RunError::Protocol(request)),
    }
    .map_err(|source| RunError::Memory { request, source })?;
    Ok(match exchange {
        Exchange::Exchanged => Reply::Committed,
        Exchange::Changed(current) => Reply::Changed(current),
    })
}
