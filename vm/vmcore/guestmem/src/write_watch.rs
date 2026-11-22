// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::PAGE_SIZE64;
use std::ops::Range;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Dirty epochs for ordinary `GuestMemory` stores to a contiguous RAM region.
/// A write is recorded *after* the access, including a possibly partial write
/// that returned an error. A writer racing collection is thus either observed
/// by that collection or left dirty for the next. Stop writers before the last
/// collection. Raw mappings, locked buffers and external DMA are not observed.
#[derive(Debug)]
pub struct WriteWatch {
    range: Range<u64>,
    enabled: AtomicBool,
    words: OnceLock<Box<[AtomicU64]>>,
}

impl WriteWatch {
    pub fn new(range: Range<u64>) -> Self {
        assert!(range.start < range.end && (range.start | range.end).is_multiple_of(PAGE_SIZE64));
        Self {
            range,
            enabled: AtomicBool::new(false),
            words: OnceLock::new(),
        }
    }

    /// Start before taking the initial full copy. Control operations
    /// (`start`, `collect`, `stop`) must be serialized by the migration owner.
    pub fn start(&self) {
        let words = self.words.get_or_init(|| {
            let count = ((self.range.end - self.range.start) / PAGE_SIZE64).div_ceil(64);
            (0..count).map(|_| AtomicU64::new(0)).collect()
        });
        for word in words {
            word.store(0, Ordering::Relaxed);
        }
        self.enabled.store(true, Ordering::Release);
    }

    pub fn stop(&self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// OR the completed software writes into the hardware dirty bitmap.
    pub fn collect(&self, into: &mut [u64]) {
        let words = self.words.get().expect("start before collecting writes");
        assert_eq!(words.len(), into.len());
        for (word, out) in words.iter().zip(into) {
            *out |= word.swap(0, Ordering::AcqRel);
        }
    }

    pub(super) fn record(&self, gpa: u64, len: usize) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        let start = gpa.max(self.range.start);
        let end = gpa.saturating_add(len as u64).min(self.range.end);
        if start >= end {
            return;
        }
        let first = (start - self.range.start) / PAGE_SIZE64;
        let last = (end - 1 - self.range.start) / PAGE_SIZE64;
        let words = self.words.get().unwrap();
        for i in first / 64..=last / 64 {
            let low = first.saturating_sub(i * 64);
            let high = (last - i * 64).min(63);
            words[i as usize].fetch_or(
                (u64::MAX << low) & (u64::MAX >> (63 - high)),
                Ordering::Release,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GuestMemory;
    use std::sync::Arc;

    #[test]
    fn offsets_and_epochs() {
        let watch = Arc::new(WriteWatch::new(4096..67 * 4096));
        let mem = GuestMemory::allocate(68 * 4096).with_write_watch(watch.clone());
        let view = mem.subrange(64 * 4096, 8192, false).unwrap();
        view.fill_at(0, 1, 3).unwrap();
        watch.start();
        view.write_at(4095, &[1, 2]).unwrap();
        let mut bits = [4, 0];
        watch.collect(&mut bits);
        assert_eq!(bits, [4 | 1 << 63, 1]);
        bits.fill(0);
        mem.read_at(4096, &mut [0]).unwrap();
        watch.collect(&mut bits);
        assert_eq!(bits, [0, 0]);
        watch.stop();
    }
}
