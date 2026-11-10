// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{Mapping, Mmu, Walk, allowed, canonical, dirty, valid_config, walk};
use crate::{Access, MmuResult, Permissions, memory_core};
#[cfg(verus_keep_ghost)]
use crate::{memory_model, mmu_model, word_model};
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordAccess { Read, Write(u64) }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordResult {
    Success(u64), PageFault(u8), GeneralProtection, InvalidConfig, Backing, HugePage, Ambiguous,
    CrossPage, Wrap,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordReport { pub result: WordResult, pub table_reads: u8, pub virtual_address: u64 }

pub(super) fn failure(r: MmuResult) -> (v: WordResult)
    requires !(r is Success),
    ensures v == word_model::lift(r), !(v is Success),
{
    match r {
        MmuResult::Success(_) => { assert(false); panic!("invalid walk failure"); },
        MmuResult::PageFault(code) => WordResult::PageFault(code),
        MmuResult::GeneralProtection => WordResult::GeneralProtection,
        MmuResult::InvalidConfig => WordResult::InvalidConfig,
        MmuResult::Backing => WordResult::Backing,
        MmuResult::HugePage => WordResult::HugePage,
        MmuResult::Ambiguous => WordResult::Ambiguous,
    }
}

impl Mmu {
    fn word_fault(&mut self, r: WordResult, va: u64)
        ensures final(self)@ == (mmu_model::State {
            cache: None, cr2: if r is PageFault { va as int } else { old(self).cr2 as int },
            ..old(self)@ }), final(self).invariant(),
    {
        self.cache = None;
        if let WordResult::PageFault(_) = r { self.cr2 = va; }
    }

    pub fn access_word(&mut self, ram: &mut Vec<u8>, base: u64, va: u64,
        a: WordAccess, user: bool) -> (report: WordReport)
        requires old(self).invariant(),
        ensures
            (final(self)@, final(ram)@, report.result, report.table_reads as nat)
                == word_model::access(old(self)@, old(ram)@, base as int, va as int, a, user),
            final(self).invariant(), final(ram)@.len() == old(ram)@.len(),
            report.table_reads <= 4, report.virtual_address == va,
    {
        proof { reveal(word_model::access); }
        if va > u64::MAX - 7 {
            return WordReport { result: WordResult::Wrap, table_reads: 0, virtual_address: va };
        }
        if va % 4096 > 4088 {
            return WordReport { result: WordResult::CrossPage, table_reads: 0, virtual_address: va };
        }
        if !valid_config(self.config) || !memory_core::window(base, ram.len()) {
            return WordReport { result: WordResult::InvalidConfig, table_reads: 0, virtual_address: va };
        }
        if !canonical(va) {
            return WordReport { result: WordResult::GeneralProtection, table_reads: 0, virtual_address: va };
        }
        let req = match a { WordAccess::Read => Access::Read, WordAccess::Write(_) => Access::Write(0) };
        if let Some(m) = self.cache {
            if m.page == va / 4096 && m.root == self.config.root
                && matches!(a, WordAccess::Read) && allowed(m.permissions, self.config, req, user) {
                let pa = m.frame + va % 4096;
                let i = match memory_core::span(base, ram.len(), pa, 8) {
                    Some(i) => i, None => {
                        self.word_fault(WordResult::Backing, va);
                        return WordReport { result: WordResult::Backing, table_reads: 0, virtual_address: va };
                    },
                };
                let value = memory_core::load(ram, i);
                return WordReport { result: WordResult::Success(value), table_reads: 0, virtual_address: va };
            }
        }
        proof {
            word_model::walk_failure(ram@, base as int, self.config.root as int, va as int, 0,
                Permissions { rw: true, user: true, nx: false }, self.config, req, user);
        }
        let walked = walk(ram, base, self.config.root, va, 0,
            Permissions { rw: true, user: true, nx: false }, self.config, req, user);
        match walked.0 {
            Walk::Failed(r) => {
                let result = failure(r);
                self.word_fault(result, va);
                WordReport { result, table_reads: walked.1, virtual_address: va }
            },
            Walk::Mapped { frame, leaf, permissions, large } => {
                let pa = frame + va % 4096;
                let i = match memory_core::span(base, ram.len(), pa, 8) {
                    Some(i) => i, None => {
                        self.word_fault(WordResult::Backing, va);
                        return WordReport { result: WordResult::Backing, table_reads: walked.1, virtual_address: va };
                    },
                };
                let value = match a {
                    WordAccess::Read => {
                        self.cache = Some(Mapping { page: va / 4096, root: self.config.root,
                            frame, permissions, large });
                        memory_core::load(ram, i)
                    },
                    WordAccess::Write(value) => {
                        let w = memory_core::load(ram, leaf);
                        let dw = dirty(w);
                        memory_core::store(ram, leaf, dw);
                        let ghost before_data = ram@;
                        memory_core::store(ram, i, value);
                        assert(ram@ == memory_model::put(before_data, i as int, value as int));
                        self.cache = None;
                        value
                    },
                };
                WordReport { result: WordResult::Success(value), table_reads: walked.1, virtual_address: va }
            },
        }
    }
}

}
