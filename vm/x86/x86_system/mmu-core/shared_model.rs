// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use super::memory_core::cpu_core::{integer, operand::Width};
use super::shared::Phase;
#[cfg(verus_keep_ghost)]
use super::shared::io::{IoReply, IoRequest, IoRoute, Operand};
#[cfg(verus_keep_ghost)]
use super::shared::{Leaf, Modifier, Reply, Request, WordData};
use super::word::WordAccess;
#[cfg(verus_keep_ghost)]
use super::word::{WordReport, WordResult};
#[cfg(verus_keep_ghost)]
use super::word_model;
use super::{Access, mmu_model as m};
#[cfg(verus_keep_ghost)]
use super::{MmuResult, Permissions, Report};
use vstd::prelude::*;

verus! {

pub struct State {
    pub inner: m::State,
    pub phase: Phase,
    pub va: u64,
    pub access: Access,
    pub user: bool,
    pub word: Option<WordAccess>,
    pub sequence: u64,
    pub size: u8,
    pub modifier: Option<super::shared::Modifier>,
}

pub open spec fn active(p: Phase) -> bool {
    !(p is Idle) && !(p is Done) && !(p is WordDone)
}

pub open spec fn can_commit(p: Phase) -> bool {
    p is Mark || p is Dirty || p is Store || p is WordDirty
        || p is WordStore || p is WordHead || p is WordLast || p is SizedStore || p is IoDirty
}
pub open spec fn can_change(p: Phase) -> bool { can_commit(p) && !(p is WordStore) }
pub open spec fn respond(s: State, reply: Reply) -> (State, bool) {
    match reply {
        Reply::Read(word) => (read(s, word), s.phase is Walk || s.phase is Data || s.phase is WordTail),
        Reply::Committed => (exchanged(s), can_commit(s.phase)),
        Reply::Changed(current) => (changed(s, current), can_change(s.phase)),
    }
}
pub open spec fn valid_leaf(l: Leaf) -> bool {
    l.address < 0x1_0000_0000_0000u64 && l.address % 8 == 0 && l.word % 2 == 1
}
pub open spec fn valid_data(d: WordData) -> bool {
    d.address < 0x1_0000_0000_0000u64 && d.address % 4096 <= 4088
}
pub open spec fn valid_span(d: WordData, size: u8) -> bool {
    if size == 8 { valid_data(d) }
    else { d.address < 0x1_0000_0000_0000u64 && d.address % 8 + size as int <= 8 }
}
pub open spec fn terminal(s: State, result: MmuResult, reads: u8) -> Phase {
    if s.word is Some {
        Phase::WordDone { report: WordReport { result: word_model::lift(result),
            table_reads: reads, virtual_address: s.va } }
    } else { Phase::Done(Report { result, table_reads: reads, virtual_address: s.va }) }
}
pub open spec fn restart(s: State) -> State {
    State { phase: Phase::Walk { table: s.inner.config.root, level: 0,
        permissions: Permissions { rw: true, user: true, nx: false } }, ..s }
}

pub open spec fn begin(s: State, va: u64, access: Access, user: bool, word: Option<WordAccess>) -> State {
    span_begin(s, va, access, user, word, 8)
}
pub open spec fn span_begin(s: State, va: u64, access: Access, user: bool, word: Option<WordAccess>, size: u8) -> State {
    let t = State { va, access, user, word, size, modifier: None, ..s };
    if word is Some && va as int + size as int - 1 > u64::MAX {
        State { phase: Phase::WordDone { report: WordReport { result: WordResult::Wrap,
            table_reads: 0, virtual_address: va } }, ..t }
    } else if word is Some && va % 4096 + size as int > 4096 {
        State { phase: Phase::WordDone { report: WordReport { result: WordResult::CrossPage,
            table_reads: 0, virtual_address: va } }, ..t }
    } else if !m::valid_config(s.inner.config) {
        State { phase: terminal(t, MmuResult::InvalidConfig, 0), ..t }
    } else if !m::canonical(va as int) {
        State { phase: terminal(t, MmuResult::GeneralProtection, 0), ..t }
    } else {
        match s.inner.cache {
            Some(c) => if c.page == va as int / 4096 && c.root == s.inner.config.root as int
                && !(access is Write) && m::allowed(c.permissions, s.inner.config, access, user) {
                State { phase: Phase::Data { frame: c.frame as u64,
                    permissions: c.permissions, leaf: None, reads: 0, large: c.large }, ..t }
            } else { restart(t) },
            None => restart(t),
        }
    }
}

pub open spec fn sized(s: State, va: u64, word: WordAccess, size: u8) -> State {
    span_begin(s, va, word_model::request(word), false, Some(word), size)
}
pub open spec fn modify_size(width: Width) -> u8 {
    match width { Width::Byte => 1, Width::Word => 2, Width::Dword => 4, Width::Qword => 8 }
}
pub open spec fn modify_admitted(va: u64, operation: integer::Operation, width: Width) -> bool {
    operation != integer::Operation::Cmp && operation != integer::Operation::Test
        && (width == Width::Qword || va % 8 + modify_size(width) as int <= 8)
}
pub open spec fn modify_begin(s: State, va: u64, operation: integer::Operation,
    source: u64, flags: u64, width: Width) -> State {
    if !modify_admitted(va, operation, width) { s } else {
        let t = span_begin(s, va, Access::Write(0), false,
            Some(WordAccess::Write(0)), modify_size(width));
        State { modifier: Some(Modifier { operation, source, flags, width, original: 0 }), ..t }
    }
}
pub open spec fn size_mask(size: u8) -> u64 {
    match size { 1 => 0xffu64, 2 => 0xffffu64, 4 => 0xffff_ffffu64, _ => u64::MAX }
}
pub open spec fn sized_request(data: WordData, size: u8) -> Request {
    let shift = (data.address % 8 * 8) as u32;
    let mask = size_mask(size) << shift;
    Request::DataCompare { address: (data.address / 8 * 8) as u64, expected: data.first,
        replacement: (data.first & !mask) | ((data.value << shift) & mask) }
}

pub open spec fn fault(s: State, result: MmuResult, reads: u8) -> State {
    State { inner: m::State { cache: None,
        cr2: if result is PageFault { s.va as int } else { s.inner.cr2 }, ..s.inner },
        phase: terminal(s, result, reads), ..s }
}

pub open spec fn request(s: State) -> Request {
    match s.phase {
        Phase::Idle => Request::Idle,
        Phase::Done(r) => Request::Complete(r),
        Phase::Walk { table, level, .. } =>
            Request::Read((table as int + m::index(s.va as int, level as nat) * 8) as u64),
        Phase::Mark { address, word, .. } =>
            Request::Compare { address, expected: word, replacement: m::accessed(word as int) as u64 },
        Phase::Data { frame, .. } => Request::Read(((frame as int + s.va % 4096) / 8 * 8) as u64),
        Phase::Dirty { pte, .. } =>
            Request::Compare { address: pte.address, expected: pte.word,
                replacement: m::dirty(pte.word as int) as u64 },
        Phase::Store { address, word, .. } =>
            Request::WriteByte { address, expected: word,
                value: match s.access { Access::Write(v) => v, _ => 0 } },
        Phase::WordDone { report } => Request::CompleteWord { report },
        Phase::WordTail { frame, .. } => Request::Read((((frame as int + s.va % 4096) / 8 * 8) + 8) as u64),
        Phase::WordDirty { pte, .. } | Phase::IoDirty { pte, .. } => Request::Compare { address: pte.address,
            expected: pte.word, replacement: m::dirty(pte.word as int) as u64 },
        Phase::WordStore { data, .. } => Request::WriteWord { address: data.address, word_value: data.value },
        Phase::WordHead { data, .. } => head_request(data),
        Phase::WordLast { data, .. } => last_request(data),
        Phase::SizedStore { data, .. } => sized_request(data, s.size),
        Phase::IoReady { address, access, .. } =>
            Request::Io(IoRequest { sequence: s.sequence, address, access }),
    }
}

pub open spec fn read(s: State, word: u64) -> State {
    match s.phase {
        Phase::Walk { table, level, permissions } => {
            let e = m::entry(word as int, level as nat, s.inner.config.nxe);
            let next = m::combine(permissions, e);
            if !e.present {
                fault(s, if !m::allowed(permissions, s.inner.config, s.access, s.user) {
                    MmuResult::Ambiguous
                } else { MmuResult::PageFault(m::pfec(s.inner.config, s.access, s.user, false, false)) },
                (level + 1) as u8)
            } else if e.reserved {
                fault(s, if !m::allowed(next, s.inner.config, s.access, s.user) {
                    MmuResult::Ambiguous
                } else { MmuResult::PageFault(m::pfec(s.inner.config, s.access, s.user, true, true)) },
                (level + 1) as u8)
            } else if e.huge && level == 1 {
                fault(s, MmuResult::HugePage, (level + 1) as u8)
            } else {
                State { phase: Phase::Mark {
                    address: (table as int + m::index(s.va as int, level as nat) * 8) as u64,
                    word, level, frame: if e.huge { m::leaf_frame(e.base, s.va as int, level as nat) as u64 } else { e.base as u64 },
                    permissions: next }, ..s }
            }
        },
        Phase::Data { frame, permissions, leaf, reads, large } => {
            if s.word is Some { word_data(s, word) } else {
            let address = (frame as int + s.va % 4096) as u64;
            match s.access {
                Access::Write(_) => match leaf {
                    Some(l) => State { phase: Phase::Dirty { pte: l, address, word, reads }, ..s },
                    None => s,
                },
                _ => State { inner: m::State { cache: Some(m::Mapping {
                        page: s.va as int / 4096, root: s.inner.config.root as int,
                        frame: frame as int, permissions, large }), ..s.inner },
                    phase: Phase::Done(Report { result: MmuResult::Success(
                        ((word >> ((s.va % 8 * 8) as u32)) & 255) as u8),
                        table_reads: reads, virtual_address: s.va }), ..s },
            } }
        },
        Phase::WordTail { .. } => word_tail(s, word),
        _ => s,
    }
}

pub open spec fn exchanged(s: State) -> State {
    match s.phase {
        Phase::Mark { address, word, level, frame, permissions } => {
            if level < 3 && !(level == 2 && m::bit(word as int, 128)) {
                State { phase: Phase::Walk { table: frame, level: (level + 1) as u8, permissions }, ..s }
            } else if !m::allowed(permissions, s.inner.config, s.access, s.user) {
                fault(s, MmuResult::PageFault(m::pfec(
                    s.inner.config, s.access, s.user, true, false)), (level + 1) as u8)
            } else {
                State { phase: Phase::Data { frame, permissions, reads: (level + 1) as u8, large: level == 2,
                    leaf: Some(Leaf { address, word: m::accessed(word as int) as u64 }) }, ..s }
            }
        },
        Phase::Dirty { address, word, reads, .. } =>
            State { phase: Phase::Store { address, word, reads }, ..s },
        Phase::Store { reads, .. } => State { inner: m::State { cache: None, ..s.inner },
            phase: Phase::Done(Report { result: MmuResult::Success(
                match s.access { Access::Write(v) => v, _ => 0 }),
                table_reads: reads, virtual_address: s.va }), ..s },
        Phase::WordDirty { data, reads, .. } => State { phase: if s.size < 8 {
            Phase::SizedStore { data, reads }
        } else if data.address % 8 == 0 {
            Phase::WordStore { data, reads }
        } else { Phase::WordHead { data, reads } }, ..s },
        Phase::WordHead { data, reads } => State { phase: Phase::WordLast { data, reads }, ..s },
        Phase::IoDirty { address, value, reads, .. } => State {
            phase: Phase::IoReady { address, access: WordAccess::Write(value), reads }, ..s },
        Phase::WordStore { data, reads } | Phase::WordLast { data, reads } | Phase::SizedStore { data, reads } =>
            word_store_done(s, data.value, reads),
        _ => s,
    }
}

pub open spec fn changed(s: State, current: u64) -> State {
    match s.phase {
        Phase::Mark { .. } | Phase::Dirty { .. } => restart(s),
        Phase::WordDirty { .. } | Phase::IoDirty { .. } => restart(s),
        Phase::Store { address, reads, .. } =>
            State { phase: Phase::Store { address, word: current, reads }, ..s },
        Phase::WordHead { data, reads } =>
            State { phase: Phase::WordHead { data: WordData { first: current, ..data }, reads }, ..s },
        Phase::WordLast { data, reads } =>
            State { phase: Phase::WordLast { data: WordData { tail: current, ..data }, reads }, ..s },
        Phase::SizedStore { data, reads } =>
            State { phase: Phase::SizedStore { data: WordData { first: current, ..data }, reads }, ..s },
        _ => s,
    }
}

pub open spec fn joined(first: u64, tail: u64, offset: u64) -> u64 {
    if offset == 0 { first } else {
        (first >> ((offset * 8) as u32)) | (tail << ((64 - offset * 8) as u32))
    }
}
pub open spec fn observed(s: State, first: u64, tail: u64) -> u64 {
    if s.size == 8 { joined(first, tail, s.va % 8) }
    else { (first >> ((s.va % 8 * 8) as u32)) & size_mask(s.size) }
}
pub open spec fn captured_modifier(modifier: Option<Modifier>, original: u64) -> Option<Modifier> {
    match modifier { Some(m) => Some(Modifier { original, ..m }), None => None }
}
pub open spec fn modified_value(modifier: Option<Modifier>, original: u64, value: u64) -> u64 {
    match modifier {
        Some(m) => integer::model::evaluate(
            m.operation, original, m.source, m.width, m.flags).value,
        None => value,
    }
}
pub open spec fn head_request(data: WordData) -> Request {
    let shift = (data.address % 8 * 8) as u32;
    let mask = u64::MAX << shift;
    Request::DataCompare { address: (data.address / 8 * 8) as u64, expected: data.first,
        replacement: (data.first & !mask) | ((data.value << shift) & mask) }
}
pub open spec fn last_request(data: WordData) -> Request {
    let shift = (64 - data.address % 8 * 8) as u32;
    let mask = u64::MAX >> shift;
    Request::DataCompare { address: (data.address / 8 * 8 + 8) as u64, expected: data.tail,
        replacement: (data.tail & !mask) | ((data.value >> shift) & mask) }
}
pub open spec fn word_loaded(s: State, frame: u64, permissions: Permissions,
    leaf: Option<Leaf>, first: u64, tail: u64, reads: u8) -> State {
    let large = match s.phase {
        Phase::Data { large, .. } | Phase::WordTail { large, .. } => large, _ => false,
    };
    let address = (frame as int + s.va % 4096) as u64;
    match s.word {
        Some(WordAccess::Read) => State { inner: m::State { cache: Some(m::Mapping {
            page: s.va as int / 4096, root: s.inner.config.root as int,
            frame: frame as int, permissions, large }), ..s.inner },
            phase: Phase::WordDone { report: WordReport { result: WordResult::Success(
                observed(s, first, tail)),
                table_reads: reads, virtual_address: s.va } }, ..s },
        Some(WordAccess::Write(value)) => match leaf {
            Some(pte) => {
                let original = observed(s, first, tail);
                let replacement = modified_value(s.modifier, original, value);
                State { modifier: captured_modifier(s.modifier, original),
                    phase: Phase::WordDirty { pte,
                        data: WordData { address, first, tail, value: replacement }, reads }, ..s }
            },
            None => s,
        },
        None => s,
    }
}
pub open spec fn word_data(s: State, word: u64) -> State {
    match s.phase {
        Phase::Data { frame, permissions, leaf, reads, large } => {
            if s.va % 8 == 0 || s.size < 8 { word_loaded(s, frame, permissions, leaf, word, 0, reads) }
            else { State { phase: Phase::WordTail { frame, permissions, leaf, first: word, reads, large }, ..s } }
        },
        _ => s,
    }
}
pub open spec fn word_tail(s: State, word: u64) -> State {
    match s.phase {
        Phase::WordTail { frame, permissions, leaf, first, reads, .. } =>
            word_loaded(s, frame, permissions, leaf, first, word, reads),
        _ => s,
    }
}
pub open spec fn word_store_done(s: State, value: u64, reads: u8) -> State {
    State { inner: m::State { cache: None, ..s.inner },
        phase: Phase::WordDone { report: WordReport { result: WordResult::Success(
            match s.modifier { Some(m) => m.original, None => value }),
            table_reads: reads, virtual_address: s.va } }, ..s }
}

/// The same operand observation determines the store and the eventual flag input.
pub proof fn modify_capture(s: State, frame: u64, permissions: Permissions,
    pte: Leaf, first: u64, tail: u64, reads: u8)
    requires s.word == Some(WordAccess::Write(0)), s.modifier is Some,
    ensures ({
        let m = s.modifier.unwrap();
        let original = observed(s, first, tail);
        let t = word_loaded(s, frame, permissions, Some(pte), first, tail, reads);
        t.modifier == Some(Modifier { original, ..m })
            && t.phase == (Phase::WordDirty { pte, data: WordData {
                address: (frame as int + s.va % 4096) as u64, first, tail,
                value: integer::model::evaluate(
                    m.operation, original, m.source, m.width, m.flags).value }, reads })
    }),
{ }

/// PTE replacement requires a fresh walk; data contention only merges the beat.
pub proof fn modify_retry(s: State, current: u64)
    ensures changed(s, current).modifier == s.modifier,
        s.phase is WordDirty ==> changed(s, current) == restart(s),
        match s.phase {
            Phase::SizedStore { data, reads } =>
                changed(s, current).phase == (Phase::SizedStore {
                    data: WordData { first: current, ..data }, reads }),
            Phase::WordHead { data, reads } =>
                changed(s, current).phase == (Phase::WordHead {
                    data: WordData { first: current, ..data }, reads }),
            Phase::WordLast { data, reads } =>
                changed(s, current).phase == (Phase::WordLast {
                    data: WordData { tail: current, ..data }, reads }),
            _ => true,
        },
{ }

pub proof fn modify_completion(s: State, value: u64, reads: u8)
    requires s.modifier is Some,
    ensures word_store_done(s, value, reads).phase == (Phase::WordDone {
        report: WordReport { result: WordResult::Success(s.modifier.unwrap().original),
            table_reads: reads, virtual_address: s.va } }),
        s.phase is WordDone ==> changed(s, value) == s && exchanged(s) == s && read(s, value) == s,
{ }

pub open spec fn operand(s: State) -> Option<Operand> {
    if s.modifier is Some { None } else { match (s.phase, s.word) {
        (Phase::Data { frame, .. }, Some(access)) =>
            Some(Operand { address: (frame as int + s.va % 4096) as u64, access }),
        _ => None,
    } }
}
pub open spec fn route_io(s: State) -> (State, IoRoute) {
    if s.modifier is Some { (s, IoRoute::NotReady) } else {
    match (s.phase, s.word) {
        (Phase::Data { frame, leaf, reads, .. }, Some(access)) => {
            if s.va % 8 != 0 { (s, IoRoute::Unaligned) }
            else if s.sequence == u64::MAX { (s, IoRoute::Exhausted) }
            else {
                let address = (frame as int + s.va % 4096) as u64;
                match access {
                    WordAccess::Read => (State { sequence: (s.sequence + 1) as u64,
                        phase: Phase::IoReady { address, access, reads }, ..s }, IoRoute::Accepted),
                    WordAccess::Write(value) => match leaf {
                        Some(pte) => (State { sequence: (s.sequence + 1) as u64,
                            phase: Phase::IoDirty { pte, address, value, reads }, ..s }, IoRoute::Accepted),
                        None => (s, IoRoute::NotReady),
                    },
                }
            }
        },
        _ => (s, IoRoute::NotReady),
    }
    }
}
pub open spec fn complete_io(s: State, sequence: u64, reply: IoReply) -> (State, bool) {
    match s.phase {
        Phase::IoReady { access, reads, .. } => {
            if sequence != s.sequence { (s, false) }
            else { match (access, reply) {
                (WordAccess::Read, IoReply::Read(value)) => (word_store_done(s, value, reads), true),
                (WordAccess::Write(value), IoReply::Written) => (word_store_done(s, value, reads), true),
                _ => (s, false),
            } }
        },
        _ => (s, false),
    }
}
}
