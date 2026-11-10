// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(verus_keep_ghost)]
use super::word::{WordAccess, WordResult};
#[cfg(verus_keep_ghost)]
use crate::{Access, MmuResult, Permissions, memory_model, mmu_model};
use vstd::prelude::*;

verus! {

pub open spec fn request(a: WordAccess) -> Access {
    match a { WordAccess::Read => Access::Read, WordAccess::Write(_) => Access::Write(0) }
}

pub proof fn walk_failure(b: Seq<u8>, base: int, table: int, va: int, level: nat,
    p: Permissions, c: crate::Config, a: Access, user: bool)
    requires level < 4,
    ensures match mmu_model::walk(b, base, table, va, level, p, c, a, user).1 {
        mmu_model::Walk::Failed(r) => !(r is Success), _ => true,
    },
    decreases 4 - level,
{
    reveal(mmu_model::walk);
    let address = table + mmu_model::index(va, level) * 8;
    if memory_model::span(base, b.len() as int, address, 8) {
        let i = address - base;
        let w = memory_model::word(b, i);
        let e = mmu_model::entry(w, level, c.nxe);
        if e.present && !e.reserved && !e.huge && level < 3 {
            walk_failure(memory_model::put(b, i, mmu_model::accessed(w)), base, e.base,
                va, level + 1, mmu_model::combine(p, e), c, a, user);
        }
    }
}

pub open spec fn lift(r: MmuResult) -> WordResult {
    match r {
        MmuResult::Success(v) => WordResult::Success(v as u64),
        MmuResult::PageFault(code) => WordResult::PageFault(code),
        MmuResult::GeneralProtection => WordResult::GeneralProtection,
        MmuResult::InvalidConfig => WordResult::InvalidConfig,
        MmuResult::Backing => WordResult::Backing,
        MmuResult::HugePage => WordResult::HugePage,
        MmuResult::Ambiguous => WordResult::Ambiguous,
    }
}

pub open spec fn fault(s: mmu_model::State, b: Seq<u8>, r: WordResult, va: int, n: nat)
    -> (mmu_model::State, Seq<u8>, WordResult, nat) {
    (mmu_model::State { cache: None,
        cr2: if r is PageFault { va } else { s.cr2 }, ..s }, b, r, n)
}

#[verifier::opaque]
pub open spec fn access(s: mmu_model::State, b: Seq<u8>, base: int, va: int,
    a: WordAccess, user: bool) -> (mmu_model::State, Seq<u8>, WordResult, nat) {
    // These are profile prechecks, not architectural exception priorities.
    if va + 7 >= 18446744073709551616int { (s, b, WordResult::Wrap, 0) }
    else if va % 4096 > 4088 { (s, b, WordResult::CrossPage, 0) }
    else if !mmu_model::valid_config(s.config) || !memory_model::window(base, b.len() as int) {
        (s, b, WordResult::InvalidConfig, 0)
    } else if !mmu_model::canonical(va) { (s, b, WordResult::GeneralProtection, 0) }
    else {
        let req = request(a);
        let hit = match s.cache {
            Some(m) => m.page == va / 4096 && m.root == s.config.root as int
                && a is Read && mmu_model::allowed(m.permissions, s.config, req, user),
            None => false,
        };
        if hit {
            let pa = s.cache.unwrap().frame + va % 4096;
            if memory_model::span(base, b.len() as int, pa, 8) {
                (s, b, WordResult::Success(memory_model::word(b, pa - base) as u64), 0)
            } else { fault(s, b, WordResult::Backing, va, 0) }
        } else {
            let walked = mmu_model::walk(b, base, s.config.root as int, va, 0,
                Permissions { rw: true, user: true, nx: false }, s.config, req, user);
            match walked.1 {
                mmu_model::Walk::Failed(r) => fault(s, walked.0, lift(r), va, walked.2),
                mmu_model::Walk::Mapped { frame, leaf, permissions, large } => {
                    let pa = frame + va % 4096;
                    if !memory_model::span(base, walked.0.len() as int, pa, 8) {
                        fault(s, walked.0, WordResult::Backing, va, walked.2)
                    } else {
                        match a {
                            WordAccess::Read => (mmu_model::State { cache: Some(mmu_model::Mapping {
                                page: va / 4096, root: s.config.root as int, frame, permissions, large,
                            }), ..s }, walked.0,
                                WordResult::Success(memory_model::word(walked.0, pa - base) as u64), walked.2),
                            WordAccess::Write(value) => {
                                let d = memory_model::put(walked.0, leaf,
                                    mmu_model::dirty(memory_model::word(walked.0, leaf)));
                                (mmu_model::State { cache: None, ..s },
                                    memory_model::put(d, pa - base, value as int),
                                    WordResult::Success(value), walked.2)
                            },
                        }
                    }
                },
            }
        }
    }
}

}
