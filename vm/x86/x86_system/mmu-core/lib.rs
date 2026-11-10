// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![forbid(unsafe_code)]
use vstd::prelude::*;

#[path = "../memory-core/lib.rs"]
pub mod memory_core;
pub use memory_core::{
    Decoded, Diagnostic, Kind, Profile, State, Stop, arithmetic, decoder, execute, memory_model,
    model,
};
pub mod mmu_model;
pub mod shared;
pub mod shared_model;
pub mod word;
pub mod word_model;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config { pub root: u64, pub wp: bool, pub nxe: bool }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access { Fetch, Read, Write(u8) }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions { pub rw: bool, pub user: bool, pub nx: bool }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmuResult {
    Success(u8), PageFault(u8), GeneralProtection, InvalidConfig, Backing, HugePage, Ambiguous,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report { pub result: MmuResult, pub table_reads: u8, pub virtual_address: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mapping { page: u64, root: u64, frame: u64, permissions: Permissions }
impl View for Mapping {
    type V = mmu_model::Mapping;
    closed spec fn view(&self) -> mmu_model::Mapping {
        mmu_model::Mapping { page: self.page as int, root: self.root as int,
            frame: self.frame as int, permissions: self.permissions }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mmu { config: Config, cache: Option<Mapping>, cr2: u64 }
impl View for Mmu {
    type V = mmu_model::State;
    closed spec fn view(&self) -> mmu_model::State {
        mmu_model::State { config: self.config, cr2: self.cr2 as int,
            cache: match self.cache { Some(m) => Some(m@), None => None } }
    }
}
impl Mmu {
    pub closed spec fn invariant(&self) -> bool {
        match self.cache {
            Some(m) => m.frame < 0x1_0000_0000_0000u64 && m.frame % 4096 == 0,
            None => true,
        }
    }
    pub fn new(config: Config, cr2: u64) -> (s: Self)
        ensures s.invariant(), s@ == (mmu_model::State { config, cache: None, cr2: cr2 as int }),
    { Self { config, cache: None, cr2 } }
    pub fn cr2(&self) -> (v: u64) ensures v as int == self@.cr2 { self.cr2 }
    pub fn cache_count(&self) -> (v: u8)
        ensures v == if self@.cache is Some { 1u8 } else { 0u8 },
    { if self.cache.is_some() { 1 } else { 0 } }
    pub fn reload(&mut self, config: Config)
        ensures final(self)@ == mmu_model::reload(old(self)@, config), final(self).invariant(),
    { self.config = config; self.cache = None; }
    pub fn invalidate(&mut self, va: u64)
        requires old(self).invariant(),
        ensures final(self)@ == mmu_model::invalidate(old(self)@, va as int), final(self).invariant(),
    {
        if let Some(m) = self.cache {
            if m.page == va / 4096 { self.cache = None; }
        }
    }
}

fn canonical(va: u64) -> (v: bool) ensures v == mmu_model::canonical(va as int)
{ va < 0x8000_0000_0000 || va >= 0xffff_8000_0000_0000 }
fn valid_config(c: Config) -> (v: bool) ensures v == mmu_model::valid_config(c)
{ c.root < 0x1_0000_0000_0000 && c.root % 4096 == 0 }
fn index(va: u64, level: u8) -> (v: u64)
    requires level < 4,
    ensures v as int == mmu_model::index(va as int, level as nat), v < 512,
{
    let divisor: u64 = if level == 0 { 549755813888 }
        else if level == 1 { 1073741824 }
        else if level == 2 { 2097152 } else { 4096 };
    (va / divisor) % 512
}

struct Entry { base: u64, present: bool, rw: bool, user: bool, nx: bool, reserved: bool, huge: bool }
impl View for Entry {
    type V = mmu_model::Entry;
    closed spec fn view(&self) -> mmu_model::Entry {
        mmu_model::Entry { base: self.base as int, present: self.present, rw: self.rw,
            user: self.user, nx: self.nx, reserved: self.reserved, huge: self.huge }
    }
}
fn entry(word: u64, level: u8, nxe: bool) -> (e: Entry)
    requires level < 4,
    ensures e@ == mmu_model::entry(word as int, level as nat, nxe),
        e.base < 0x1_0000_0000_0000u64, e.base % 4096 == 0,
{
    let base = (word / 4096 % 68719476736) * 4096;
    Entry { base, present: word % 2 == 1, rw: word / 2 % 2 == 1,
        user: word / 4 % 2 == 1, nx: word / 9223372036854775808 % 2 == 1,
        reserved: word / 281474976710656 % 16 != 0
            || (!nxe && word / 9223372036854775808 % 2 == 1)
            || (level == 0 && (word / 128 % 2 == 1 || word / 256 % 2 == 1)),
        huge: (level == 1 || level == 2) && word / 128 % 2 == 1 }
}
fn combine(p: Permissions, e: &Entry) -> (next: Permissions)
    ensures next == mmu_model::combine(p, e@),
{ Permissions { rw: p.rw && e.rw, user: p.user && e.user, nx: p.nx || e.nx } }
fn allowed(p: Permissions, c: Config, a: Access, user: bool) -> (v: bool)
    ensures v == mmu_model::allowed(p, c, a, user),
{
    let write = match a { Access::Write(_) => true, _ => false };
    let fetch = match a { Access::Fetch => true, _ => false };
    (!user || p.user) && (!write || (!(user || c.wp) || p.rw))
        && (!fetch || !c.nxe || !p.nx)
}
fn pfec(c: Config, a: Access, user: bool, present: bool, reserved: bool) -> (v: u8)
    ensures v == mmu_model::pfec(c, a, user, present, reserved),
{
    let write = match a { Access::Write(_) => true, _ => false };
    let fetch = match a { Access::Fetch => true, _ => false };
    (if present { 1 } else { 0 }) + (if write { 2 } else { 0 })
        + (if user { 4 } else { 0 }) + (if reserved { 8 } else { 0 })
        + (if fetch && c.nxe { 16 } else { 0 })
}
fn accessed(w: u64) -> (v: u64) ensures v as int == mmu_model::accessed(w as int)
{
    proof { assert((w | 32u64) == w + if w / 32u64 % 2u64 == 1u64 { 0u64 } else { 32u64 }) by(bit_vector); }
    w | 32
}
fn dirty(w: u64) -> (v: u64) ensures v as int == mmu_model::dirty(w as int)
{
    proof { assert((w | 64u64) == w + if w / 64u64 % 2u64 == 1u64 { 0u64 } else { 64u64 }) by(bit_vector); }
    w | 64
}

enum Walk { Mapped { frame: u64, leaf: usize, permissions: Permissions }, Failed(MmuResult) }
impl View for Walk {
    type V = mmu_model::Walk;
    closed spec fn view(&self) -> mmu_model::Walk {
        match *self {
            Walk::Mapped { frame, leaf, permissions } => mmu_model::Walk::Mapped {
                frame: frame as int, leaf: leaf as int, permissions },
            Walk::Failed(r) => mmu_model::Walk::Failed(r),
        }
    }
}

fn descend(ram: &mut Vec<u8>, base: u64, table: u64, va: u64,
    level: u8, p: Permissions, c: Config, a: Access, user: bool, i: usize, aw: u64)
    -> (r: (Walk, u8))
    requires
        level < 4, table < 0x1_0000_0000_0000u64, table % 4096 == 0,
        i as int + 8 <= old(ram)@.len(), i <= usize::MAX - 7,
        aw as int == mmu_model::accessed(memory_model::word(old(ram)@, i as int)),
    ensures
        (final(ram)@, r.0@, r.1 as nat) == mmu_model::walk(
            memory_model::put(old(ram)@, i as int, aw as int), base as int,
            table as int, va as int, level as nat, p, c, a, user),
        final(ram)@.len() == old(ram)@.len(), r.1 <= 4 - level,
        match r.0 { Walk::Mapped { frame, leaf, .. } =>
            frame < 0x1_0000_0000_0000u64 && frame % 4096 == 0
                && leaf as int + 8 <= final(ram)@.len() && leaf <= usize::MAX - 7, _ => true },
    decreases 2 * (4 - level) + 1,
{
    memory_core::store(ram, i, aw);
    let ghost updated = ram@;
    let rest = walk(ram, base, table, va, level, p, c, a, user);
    let ghost expected = mmu_model::walk(updated, base as int, table as int,
        va as int, level as nat, p, c, a, user);
    assert(ram@[i as int] == expected.0[i as int]);
    assert(ram@ == expected.0);
    rest
}

fn walk(ram: &mut Vec<u8>, base: u64, table: u64, va: u64,
    level: u8, p: Permissions, c: Config, a: Access, user: bool) -> (r: (Walk, u8))
    requires level < 4, table < 0x1_0000_0000_0000u64, table % 4096 == 0,
    ensures
        (final(ram)@, r.0@, r.1 as nat) == mmu_model::walk(old(ram)@, base as int,
            table as int, va as int, level as nat, p, c, a, user),
        final(ram)@.len() == old(ram)@.len(), r.1 <= 4 - level,
        match r.0 { Walk::Mapped { frame, leaf, .. } =>
            frame < 0x1_0000_0000_0000u64 && frame % 4096 == 0
                && leaf as int + 8 <= final(ram)@.len() && leaf <= usize::MAX - 7, _ => true },
    decreases 2 * (4 - level),
{
    let ghost initial = ram@;
    let address = table + index(va, level) * 8;
    let i = match memory_core::span(base, ram.len(), address, 8) {
        Some(i) => i, None => {
            proof { reveal(mmu_model::walk); }
            return (Walk::Failed(MmuResult::Backing), 0);
        },
    };
    let w = memory_core::load(ram, i);
    assert(w as int % 256 == initial[i as int] as int);
    let e = entry(w, level, c.nxe);
    let next = combine(p, &e);
    if !e.present {
        let fault = if !allowed(p, c, a, user) { MmuResult::Ambiguous }
            else { MmuResult::PageFault(pfec(c, a, user, false, false)) };
        assert(ram@[i as int] == initial[i as int]);
        assert(ram@ == initial);
        proof { reveal(mmu_model::walk); }
        return (Walk::Failed(fault), 1);
    }
    if e.reserved {
        let fault = if !allowed(next, c, a, user) { MmuResult::Ambiguous }
            else { MmuResult::PageFault(pfec(c, a, user, true, true)) };
        proof { reveal(mmu_model::walk); }
        return (Walk::Failed(fault), 1);
    }
    if e.huge {
        proof { reveal(mmu_model::walk); }
        return (Walk::Failed(MmuResult::HugePage), 1);
    }
    let aw = accessed(w);
    assert(aw as int == mmu_model::accessed(w as int));
    if level == 3 {
        memory_core::store(ram, i, aw);
        proof { reveal(mmu_model::walk); }
        if !allowed(next, c, a, user) {
            return (Walk::Failed(MmuResult::PageFault(pfec(c, a, user, true, false))), 1);
        }
        (Walk::Mapped { frame: e.base, leaf: i, permissions: next }, 1)
    } else {
        let rest = descend(ram, base, e.base, va, level + 1, next, c, a, user, i, aw);
        proof { reveal(mmu_model::walk); }
        (rest.0, rest.1 + 1)
    }
}

fn write_byte(ram: &mut Vec<u8>, i: usize, value: u8)
    requires (i as int) < old(ram)@.len(),
    ensures final(ram)@ == old(ram)@.update(i as int, value),
{
    ram.set(i, value);
}

impl Mmu {
    fn fault(&mut self, result: MmuResult, va: u64)
        ensures final(self)@ == (mmu_model::State {
            cache: None, cr2: if result is PageFault { va as int } else { old(self).cr2 as int },
            ..old(self)@ }), final(self).invariant(),
    {
        self.cache = None;
        if let MmuResult::PageFault(_) = result { self.cr2 = va; }
    }
    pub fn access(&mut self, ram: &mut Vec<u8>, base: u64, va: u64, a: Access, user: bool)
        -> (report: Report)
        requires old(self).invariant(),
        ensures
            (final(self)@, final(ram)@, report.result, report.table_reads as nat)
                == mmu_model::access(old(self)@, old(ram)@, base as int, va as int, a, user),
            final(self).invariant(), final(ram)@.len() == old(ram)@.len(), report.table_reads <= 4,
            report.virtual_address == va,
    {
        proof { reveal(mmu_model::access); }
        if !valid_config(self.config) || !memory_core::window(base, ram.len()) {
            return Report { result: MmuResult::InvalidConfig, table_reads: 0, virtual_address: va };
        }
        if !canonical(va) {
            return Report { result: MmuResult::GeneralProtection, table_reads: 0, virtual_address: va };
        }
        let write = match a { Access::Write(_) => true, _ => false };
        if let Some(m) = self.cache {
            if m.page == va / 4096 && m.root == self.config.root
                && !write && allowed(m.permissions, self.config, a, user) {
                assert(m.page as int == va as int / 4096 && m.root == self.config.root);
                assert(!write && mmu_model::allowed(m.permissions, self.config, a, user));
                let pa = m.frame + va % 4096;
                assert(pa as int == m.frame as int + va as int % 4096);
                match memory_core::span(base, ram.len(), pa, 1) {
                    Some(i) => { return Report { result: MmuResult::Success(ram[i]), table_reads: 0, virtual_address: va }; },
                    None => {
                        self.fault(MmuResult::Backing, va);
                        return Report { result: MmuResult::Backing, table_reads: 0, virtual_address: va };
                    },
                }
            }
        }
        let walked = walk(ram, base, self.config.root, va, 0,
            Permissions { rw: true, user: true, nx: false }, self.config, a, user);
        match walked.0 {
            Walk::Failed(result) => {
                self.fault(result, va);
                Report { result, table_reads: walked.1, virtual_address: va }
            },
            Walk::Mapped { frame, leaf, permissions } => {
                let pa = frame + va % 4096;
                let i = match memory_core::span(base, ram.len(), pa, 1) {
                    Some(i) => i, None => {
                        self.fault(MmuResult::Backing, va);
                        return Report { result: MmuResult::Backing, table_reads: walked.1, virtual_address: va };
                    },
                };
                let value = match a {
                    Access::Write(value) => {
                        let w = memory_core::load(ram, leaf);
                        let dw = dirty(w);
                        memory_core::store(ram, leaf, dw);
                        let ghost before_byte = ram@;
                        write_byte(ram, i, value);
                        if i > 0 { assert(ram@[i as int - 1] == before_byte[i as int - 1]); }
                        assert(ram@ == before_byte.update(i as int, value));
                        self.cache = None;
                        value
                    },
                    _ => {
                        self.cache = Some(Mapping { page: va / 4096, root: self.config.root,
                            frame, permissions });
                        ram[i]
                    },
                };
                Report { result: MmuResult::Success(value), table_reads: walked.1, virtual_address: va }
            },
        }
    }
}

pub fn update_invalidate_access(s: &mut Mmu, ram: &mut Vec<u8>, base: u64,
    entry_address: u64, word: u64, va: u64, a: Access, user: bool) -> (r: Option<Report>)
    requires old(s).invariant(),
    ensures final(s).invariant(), final(ram)@.len() == old(ram)@.len(),
        match r {
            None => final(s)@ == old(s)@ && final(ram)@ == old(ram)@
                && !memory_model::span(base as int, old(ram)@.len() as int, entry_address as int, 8),
            Some(report) => memory_model::span(base as int, old(ram)@.len() as int, entry_address as int, 8)
                && (final(s)@, final(ram)@, report.result, report.table_reads as nat)
                    == mmu_model::access(mmu_model::invalidate(old(s)@, va as int),
                        memory_model::put(old(ram)@, entry_address as int - base as int, word as int),
                        base as int, va as int, a, user)
                && report.virtual_address == va,
        },
{
    let i = match memory_core::span(base, ram.len(), entry_address, 8) {
        Some(i) => i, None => { return None; },
    };
    memory_core::store(ram, i, word);
    s.invalidate(va);
    Some(s.access(ram, base, va, a, user))
}

}
