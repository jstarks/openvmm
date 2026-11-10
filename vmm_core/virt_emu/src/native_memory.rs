// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native x86-64 lowering for coherent WB RAM, not an MMIO implementation.
//!
//! Data caching and buffering belong to the host CPU. Compiler barriers preserve
//! access order; guest barriers/serializing events must explicitly call `barrier`.
//! This host-ISA-specific implementation does not apply to weaker host ISAs.

use guestmem::{GuestMemory, GuestMemoryError};
use memory_range::MemoryRange;
use std::sync::atomic::{Ordering, compiler_fence, fence};
use x86_system::memory_core::shared::{self, Beat, BeatError, Exchange, PhysicalRam};

const MASKED_WRITE_ATTEMPTS: usize = 64;

/// Failure of the physical RAM interface, not an architectural guest exception.
#[derive(Debug, thiserror::Error)]
pub enum RamError {
    /// A RAM bank must be nonempty and quadword-aligned.
    #[error("invalid native RAM bank")]
    Region,
    /// The operation crosses the bank's declared RAM boundary.
    #[error("physical RAM access outside bank: {address:#x}")]
    OutsideBank {
        /// Physical address supplied by the caller.
        address: u64,
    },
    /// The access width is outside the current byte/word/dword/qword profile.
    #[error("unsupported RAM access width")]
    Width,
    /// The caller must decompose this operation into separate RAM beats.
    #[error("RAM access requires multiple quadword beats")]
    Split,
    /// No masked store committed within this bounded attempt.
    #[error("masked RAM store contended; yield and retry without retiring")]
    Contended,
    /// OpenVMM could not access the backing.
    #[error("accessing physical RAM")]
    Memory(#[from] GuestMemoryError),
}

/// Result of conditionally marking the exact PTE a walker observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdUpdate {
    /// The compare-exchange committed, preserving every non-A/D bit.
    Marked,
    /// The PTE changed; the walker must revalidate rather than reuse old checks.
    Changed(u64),
    /// The supplied observation was not present; no backing access was made.
    NotPresent,
}

/// Shared view of a host-declared coherent WB RAM bank.
///
/// Clones retain the same OpenVMM backing. No exclusive Rust slice or RAM
/// snapshot is created. Callers must route MMIO and other memory types elsewhere.
#[derive(Clone, Debug)]
pub struct NativeRam {
    memory: GuestMemory,
    bank: MemoryRange,
}

impl NativeRam {
    /// Creates a native RAM view; the caller classifies this bank as coherent WB.
    pub fn new(memory: GuestMemory, bank: MemoryRange) -> Result<Self, RamError> {
        if bank.is_empty() || !bank.start().is_multiple_of(8) || !bank.end().is_multiple_of(8) {
            return Err(RamError::Region);
        }
        Ok(Self { memory, bank })
    }

    fn beat(&self, address: u64, width: u8) -> Result<Beat, RamError> {
        let beat = shared::plan(address, width).map_err(|error| match error {
            BeatError::Width => RamError::Width,
            BeatError::Split => RamError::Split,
        })?;
        if beat.address() < self.bank.start()
            || beat.address() >= self.bank.end()
            || self.bank.end() - beat.address() < 8
        {
            return Err(RamError::OutsideBank { address });
        }
        Ok(beat)
    }

    fn load_word(&self, address: u64) -> Result<u64, RamError> {
        compiler_fence(Ordering::SeqCst);
        let result = self.memory.read_plain::<u64>(address);
        compiler_fence(Ordering::SeqCst);
        Ok(result?)
    }

    fn compare_word(
        &self,
        address: u64,
        expected: u64,
        replacement: u64,
    ) -> Result<Result<u64, u64>, RamError> {
        compiler_fence(Ordering::SeqCst);
        let result = self.memory.compare_exchange(address, expected, replacement);
        compiler_fence(Ordering::SeqCst);
        Ok(result?)
    }

    /// Reads one atomic RAM beat, including subword accesses inside a quadword.
    pub fn read(&self, address: u64, width: u8) -> Result<u64, RamError> {
        let beat = self.beat(address, width)?;
        Ok(beat.extract(self.load_word(beat.address())?))
    }

    /// Writes one RAM beat without losing concurrent updates to adjacent bytes.
    ///
    /// Naturally aligned qword stores use native stores. Narrow stores use
    /// compare-exchange; their additional ordering is permitted, not simulated
    /// store-buffer behavior. Contention returns without committing this store.
    pub fn write(&self, address: u64, width: u8, value: u64) -> Result<(), RamError> {
        let beat = self.beat(address, width)?;
        if beat.whole() {
            compiler_fence(Ordering::SeqCst);
            let result = self.memory.write_plain(beat.address(), &value);
            compiler_fence(Ordering::SeqCst);
            return Ok(result?);
        }
        let mut observed = self.load_word(beat.address())?;
        for _ in 0..MASKED_WRITE_ATTEMPTS {
            let replacement = beat.replace(observed, value);
            match self.compare_word(beat.address(), observed, replacement)? {
                Ok(_) => return Ok(()),
                Err(current) => observed = current,
            }
        }
        Err(RamError::Contended)
    }

    /// Marks A and optionally D only if the PTE still equals the observation.
    ///
    /// A replacement/removal is not retried blindly: the walker must revalidate
    /// its address/permission decision against the changed entry.
    pub fn try_mark_ad(
        &self,
        address: u64,
        observed: u64,
        dirty: bool,
    ) -> Result<AdUpdate, RamError> {
        let beat = self.beat(address, 8)?;
        let Some(replacement) = shared::ad_value(observed, dirty) else {
            return Ok(AdUpdate::NotPresent);
        };
        match self.compare_word(beat.address(), observed, replacement)? {
            Ok(_) => Ok(AdUpdate::Marked),
            Err(current) => Ok(AdUpdate::Changed(current)),
        }
    }

    /// Orders native RAM accesses for a guest barrier or serializing event.
    ///
    /// This does not implement instruction/TLB/code-cache invalidation or MMIO
    /// completion. Callers must perform those distinct architectural effects.
    pub fn barrier(&self) {
        fence(Ordering::SeqCst);
    }
}

impl PhysicalRam for NativeRam {
    type Error = RamError;

    fn read_word(&self, address: u64) -> Result<u64, Self::Error> {
        self.read(address, 8)
    }

    fn write_word(&self, address: u64, value: u64) -> Result<(), Self::Error> {
        self.write(address, 8, value)
    }

    fn compare_exchange_word(
        &self,
        address: u64,
        expected: u64,
        replacement: u64,
    ) -> Result<Exchange, Self::Error> {
        let beat = self.beat(address, 8)?;
        match self.compare_word(beat.address(), expected, replacement)? {
            Ok(_) => Ok(Exchange::Exchanged),
            Err(current) => Ok(Exchange::Changed(current)),
        }
    }

    fn barrier(&self) {
        NativeRam::barrier(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use test_with_tracing::test;

    fn fixture() -> (GuestMemory, NativeRam) {
        let memory = GuestMemory::allocate(4096);
        let ram = NativeRam::new(memory.clone(), MemoryRange::new(0..4096)).unwrap();
        (memory, ram)
    }

    fn write_retry(ram: &NativeRam, address: u64, width: u8, value: u64) {
        loop {
            match ram.write(address, width, value) {
                Ok(()) => return,
                Err(RamError::Contended) => thread::yield_now(),
                Err(error) => panic!("{error}"),
            }
        }
    }

    #[test]
    fn all_contained_widths_preserve_neighbor_bytes() {
        let (memory, ram) = fixture();
        for width in [1u8, 2, 4, 8] {
            for offset in 0..=8 - width {
                let original = [0xa5; 8];
                memory.write_at(0, &original).unwrap();
                ram.write(offset.into(), width, 0x1122334455667788).unwrap();
                let mut expected = original;
                expected[offset as usize..(offset + width) as usize]
                    .copy_from_slice(&0x1122334455667788u64.to_le_bytes()[..width as usize]);
                let mut actual = [0; 8];
                memory.read_at(0, &mut actual).unwrap();
                assert_eq!(actual, expected);
                let mut data = [0; 8];
                data[..width as usize]
                    .copy_from_slice(&expected[offset as usize..(offset + width) as usize]);
                assert_eq!(
                    ram.read(offset.into(), width).unwrap(),
                    u64::from_le_bytes(data)
                );
            }
        }
        assert!(matches!(ram.write(7, 2, 1), Err(RamError::Split)));
        assert!(matches!(ram.read(0, 3), Err(RamError::Width)));
        assert!(matches!(
            ram.write(4096, 8, 1),
            Err(RamError::OutsideBank { .. })
        ));
    }

    #[test]
    fn cpu_and_dma_workers_do_not_lose_disjoint_byte_writes() {
        let (memory, ram) = fixture();
        let start = Arc::new(Barrier::new(3));
        thread::scope(|scope| {
            for lane in 0..3 {
                let start = start.clone();
                let ram = &ram;
                let memory = &memory;
                scope.spawn(move || {
                    start.wait();
                    for value in 0..2000 {
                        if lane == 2 {
                            memory.write_plain(lane, &((value + lane) as u8)).unwrap();
                        } else {
                            write_retry(ram, lane, 1, value + lane);
                        }
                    }
                });
            }
        });
        assert_eq!(memory.read_plain::<u64>(0).unwrap(), 0xd1d0cf);
    }

    #[test]
    fn concurrent_native_qword_accesses_do_not_tear() {
        let (_, ram) = fixture();
        let start = Arc::new(Barrier::new(3));
        let values = [0x5555aaaa5555aaaa, 0xaaaa5555aaaa5555];
        thread::scope(|scope| {
            for value in values {
                let start = start.clone();
                let ram = &ram;
                scope.spawn(move || {
                    start.wait();
                    for _ in 0..50_000 {
                        ram.write(0, 8, value).unwrap();
                    }
                });
            }
            let start = start.clone();
            let ram = &ram;
            scope.spawn(move || {
                start.wait();
                for _ in 0..50_000 {
                    let value = ram.read(0, 8).unwrap();
                    assert!(value == 0 || values.contains(&value));
                }
            });
        });
    }

    #[test]
    fn pte_replacement_between_read_and_ad_update_is_not_overwritten() {
        let (memory, ram) = fixture();
        for replacement in [0x3007, 0x3006] {
            memory.write_plain(0, &0x2007u64).unwrap();
            let seen = Arc::new(Barrier::new(2));
            let changed = Arc::new(Barrier::new(2));
            thread::scope(|scope| {
                let ram = &ram;
                let seen_cpu = seen.clone();
                let changed_cpu = changed.clone();
                scope.spawn(move || {
                    let observed = ram.read(0, 8).unwrap();
                    seen_cpu.wait();
                    changed_cpu.wait();
                    assert_eq!(
                        ram.try_mark_ad(0, observed, true).unwrap(),
                        AdUpdate::Changed(replacement)
                    );
                });
                seen.wait();
                memory.write_plain(0, &replacement).unwrap();
                changed.wait();
            });
            assert_eq!(memory.read_plain::<u64>(0).unwrap(), replacement);
        }
        assert_eq!(ram.try_mark_ad(0, 0, true).unwrap(), AdUpdate::NotPresent);
    }

    #[test]
    fn ad_updates_race_with_dma_without_losing_pte_payload() {
        let (memory, ram) = fixture();
        ram.write(0, 8, 0x2007).unwrap();
        let start = Arc::new(Barrier::new(2));
        thread::scope(|scope| {
            let start_dma = start.clone();
            let ram = &ram;
            let memory = &memory;
            scope.spawn(move || {
                start_dma.wait();
                for value in 1..2000 {
                    memory.write_plain(4, &(value as u32)).unwrap();
                }
            });
            start.wait();
            for _ in 0..2000 {
                loop {
                    let observed = ram.read(0, 8).unwrap();
                    if ram.try_mark_ad(0, observed, true).unwrap() == AdUpdate::Marked {
                        break;
                    }
                }
            }
        });
        assert_eq!(ram.read(0, 8).unwrap(), (1999u64 << 32) | 0x2067);
    }

    #[test]
    fn native_wb_message_passing_preserves_store_order() {
        let (_, ram) = fixture();
        thread::scope(|scope| {
            let ram = &ram;
            scope.spawn(move || {
                ram.write(0, 8, 0xabcdef0123456789).unwrap();
                ram.write(8, 8, 1).unwrap();
            });
            while ram.read(8, 8).unwrap() == 0 {
                thread::yield_now();
            }
            assert_eq!(ram.read(0, 8).unwrap(), 0xabcdef0123456789);
            ram.barrier();
        });
    }

    #[test]
    fn invalid_banks_are_explicit_errors() {
        let memory = GuestMemory::allocate(4096);
        assert!(matches!(
            NativeRam::new(memory.clone(), MemoryRange::EMPTY),
            Err(RamError::Region)
        ));
        let declared_bank = NativeRam::new(memory, MemoryRange::new(0..8192)).unwrap();
        assert!(matches!(
            declared_bank.read(4096, 8),
            Err(RamError::Memory(_))
        ));
    }

    #[test]
    fn existing_multi_region_backing_and_direct_writers_are_shared() {
        let memory = GuestMemory::new_multi_region(
            "native-ram-multi",
            4096,
            vec![
                Some(guestmem::AlignedHeapMemory::new(4096)),
                None,
                Some(guestmem::AlignedHeapMemory::new(4096)),
            ],
        )
        .unwrap();
        assert!(memory.full_mapping().is_none());
        let first = NativeRam::new(memory.clone(), MemoryRange::new(0..4096)).unwrap();
        let second = NativeRam::new(memory.clone(), MemoryRange::new(8192..12288)).unwrap();
        memory.write_plain(8192, &0x1122334455667788u64).unwrap();
        assert_eq!(second.read(8192, 8).unwrap(), 0x1122334455667788);
        first.write(16, 8, 0xabcdef).unwrap();
        assert_eq!(memory.read_plain::<u64>(16).unwrap(), 0xabcdef);
        assert!(matches!(
            first.read(8192, 8),
            Err(RamError::OutsideBank { .. })
        ));
        let with_hole = NativeRam::new(memory, MemoryRange::new(0..12288)).unwrap();
        assert!(matches!(with_hole.read(4096, 8), Err(RamError::Memory(_))));
    }

    #[test]
    fn neutral_core_interface_observes_direct_backing_mutations() {
        fn exercise<M: PhysicalRam<Error = RamError>>(ram: &M, memory: &GuestMemory) {
            ram.write_word(0, 7).unwrap();
            memory.write_plain(0, &9u64).unwrap();
            assert_eq!(ram.read_word(0).unwrap(), 9);
            assert_eq!(
                ram.compare_exchange_word(0, 7, 11).unwrap(),
                Exchange::Changed(9)
            );
            assert_eq!(
                ram.compare_exchange_word(0, 9, 11).unwrap(),
                Exchange::Exchanged
            );
            ram.barrier();
            assert_eq!(memory.read_plain::<u64>(0).unwrap(), 11);
        }
        let (memory, ram) = fixture();
        exercise(&ram, &memory);
    }
}
