// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use crate::{Access, memory_model};
use crate::{Config, MmuResult, Permissions};
use vstd::prelude::*;

verus! {

pub struct Mapping {
    pub page: int,
    pub root: int,
    pub frame: int,
    pub permissions: Permissions,
    pub large: bool,
}

pub struct State {
    pub config: Config,
    pub cache: Option<Mapping>,
    pub cr2: int,
}

pub struct Entry {
    pub base: int,
    pub present: bool,
    pub rw: bool,
    pub user: bool,
    pub nx: bool,
    pub reserved: bool,
    pub huge: bool,
}

pub enum Walk {
    Mapped { frame: int, leaf: int, permissions: Permissions, large: bool },
    Failed(MmuResult),
}

pub open spec fn bit(word: int, weight: int) -> bool { word / weight % 2 == 1 }
pub open spec fn canonical(va: int) -> bool {
    va < 140737488355328int || 18446603336221196288int <= va
}
pub open spec fn valid_config(c: Config) -> bool {
    (c.root as int) < 281474976710656int && c.root as int % 4096 == 0
}
pub open spec fn index(va: int, level: nat) -> int {
    (va / (if level == 0 { 549755813888int }
        else if level == 1 { 1073741824int }
        else if level == 2 { 2097152int } else { 4096int })) % 512
}
pub open spec fn entry(word: int, level: nat, nxe: bool) -> Entry {
    Entry {
        base: if level == 2 && bit(word, 128) {
            (word / 2097152 % 134217728int) * 2097152
        } else { (word / 4096 % 68719476736int) * 4096 },
        present: bit(word, 1),
        rw: bit(word, 2),
        user: bit(word, 4),
        nx: bit(word, 9223372036854775808int),
        reserved: word / 281474976710656int % 16 != 0
            || (!nxe && bit(word, 9223372036854775808int))
            || (level == 2 && bit(word, 128) && word / 8192 % 256 != 0)
            || (level == 0 && (bit(word, 128) || bit(word, 256))),
        huge: (level == 1 || level == 2) && bit(word, 128),
    }
}
pub open spec fn combine(p: Permissions, e: Entry) -> Permissions {
    Permissions { rw: p.rw && e.rw, user: p.user && e.user, nx: p.nx || e.nx }
}
pub open spec fn allowed(p: Permissions, c: Config, a: Access, user: bool) -> bool {
    (!user || p.user)
        && (!(a is Write) || (!(user || c.wp) || p.rw))
        && (!(a is Fetch) || !c.nxe || !p.nx)
}
pub open spec fn pfec(c: Config, a: Access, user: bool, present: bool, reserved: bool) -> u8 {
    ((if present { 1int } else { 0int })
        + (if a is Write { 2int } else { 0int })
        + (if user { 4int } else { 0int })
        + (if reserved { 8int } else { 0int })
        + (if a is Fetch && c.nxe { 16int } else { 0int })) as u8
}
pub open spec fn accessed(word: int) -> int {
    word + if bit(word, 32) { 0int } else { 32int }
}
pub open spec fn dirty(word: int) -> int {
    word + if bit(word, 64) { 0int } else { 64int }
}
pub open spec fn leaf_frame(base: int, va: int, level: nat) -> int {
    base + if level == 2 { (va / 4096 % 512) * 4096 } else { 0int }
}

// Only structural/permission intersections without a sourced ordering are stopped.
#[verifier::opaque]
pub open spec fn walk(b: Seq<u8>, base: int, table: int, va: int,
    level: nat, p: Permissions, c: Config, a: Access, user: bool)
    -> (Seq<u8>, Walk, nat)
    decreases 4 - level,
{
    let address = table + index(va, level) * 8;
    if !memory_model::span(base, b.len() as int, address, 8) {
        (b, Walk::Failed(MmuResult::Backing), 0)
    } else {
        let i = address - base;
        let w = memory_model::word(b, i);
        let e = entry(w, level, c.nxe);
        let next = combine(p, e);
        if !e.present {
            (b, Walk::Failed(if !allowed(p, c, a, user) { MmuResult::Ambiguous }
                else { MmuResult::PageFault(pfec(c, a, user, false, false)) }), 1)
        } else if e.reserved {
            (b, Walk::Failed(if !allowed(next, c, a, user) { MmuResult::Ambiguous }
                else { MmuResult::PageFault(pfec(c, a, user, true, true)) }), 1)
        } else if e.huge && level == 1 {
            (b, Walk::Failed(MmuResult::HugePage), 1)
        } else {
            let updated = memory_model::put(b, i, accessed(w));
            if level >= 3 || e.huge {
                if !allowed(next, c, a, user) {
                    (updated, Walk::Failed(MmuResult::PageFault(pfec(c, a, user, true, false))), 1)
                } else {
                    (updated, Walk::Mapped { frame: leaf_frame(e.base, va, level),
                        leaf: i, permissions: next, large: level == 2 }, 1)
                }
            } else {
                let rest = walk(updated, base, e.base, va, level + 1, next, c, a, user);
                (rest.0, rest.1, 1 + rest.2)
            }
        }
    }
}

pub open spec fn invalidate(s: State, va: int) -> State {
    State { cache: match s.cache {
        Some(m) => if m.page == va / 4096 || (m.large && m.page / 512 == va / 2097152) {
            None
        } else { Some(m) },
        None => None,
    }, ..s }
}
pub open spec fn reload(s: State, c: Config) -> State {
    State { config: c, cache: None, ..s }
}
pub open spec fn finish(s: State, b: Seq<u8>, r: MmuResult, reads: nat)
    -> (State, Seq<u8>, MmuResult, nat) {
    (s, b, r, reads)
}
pub open spec fn fault(s: State, b: Seq<u8>, r: MmuResult, va: int, reads: nat)
    -> (State, Seq<u8>, MmuResult, nat) {
    (State { cache: None, cr2: if r is PageFault { va } else { s.cr2 }, ..s }, b, r, reads)
}

#[verifier::opaque]
pub open spec fn access(s: State, b: Seq<u8>, base: int, va: int, a: Access, user: bool)
    -> (State, Seq<u8>, MmuResult, nat) {
    if !valid_config(s.config) || !memory_model::window(base, b.len() as int) {
        finish(s, b, MmuResult::InvalidConfig, 0)
    } else if !canonical(va) {
        finish(s, b, MmuResult::GeneralProtection, 0)
    } else {
        let hit = match s.cache {
            Some(m) => m.page == va / 4096 && m.root == s.config.root as int
                && !(a is Write) && allowed(m.permissions, s.config, a, user),
            None => false,
        };
        if hit {
            let m = s.cache.unwrap();
            let pa = m.frame + va % 4096;
            if memory_model::span(base, b.len() as int, pa, 1) {
                finish(s, b, MmuResult::Success(b[pa - base]), 0)
            } else { fault(s, b, MmuResult::Backing, va, 0) }
        } else {
            let walked = walk(b, base, s.config.root as int, va, 0,
                Permissions { rw: true, user: true, nx: false }, s.config, a, user);
            match walked.1 {
                Walk::Failed(r) => fault(s, walked.0, r, va, walked.2),
                Walk::Mapped { frame, leaf, permissions, large } => {
                    let pa = frame + va % 4096;
                    if !memory_model::span(base, walked.0.len() as int, pa, 1) {
                        fault(s, walked.0, MmuResult::Backing, va, walked.2)
                    } else {
                        match a {
                            Access::Write(value) => {
                                let d = memory_model::put(walked.0, leaf,
                                    dirty(memory_model::word(walked.0, leaf)));
                                finish(State { cache: None, ..s },
                                    d.update(pa - base, value), MmuResult::Success(value), walked.2)
                            },
                            _ => finish(State { cache: Some(Mapping {
                                page: va / 4096, root: s.config.root as int, frame, permissions, large,
                            }), ..s }, walked.0, MmuResult::Success(walked.0[pa - base]), walked.2),
                        }
                    }
                },
            }
        }
    }
}

}
