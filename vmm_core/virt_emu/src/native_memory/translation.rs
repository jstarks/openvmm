// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use x86_system::memory::physical::{
    DirectPage, TranslatedRam, Translation, TranslationCache, TranslationDiagnostics,
    TranslationSlot,
};

const DATA_SLOTS: usize = if cfg!(feature = "direct-ram") { 256 } else { 1 };
const SLOTS: usize = 5 + DATA_SLOTS;

fn data_index(page: u64) -> usize {
    5 + (page as usize & (DATA_SLOTS - 1))
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    translation: Translation,
    // A derived transport span, never a map/unmap ownership unit.
    mapping: Option<Mapping>,
}

/// Opaque persistent host payloads for fetch/data and four walker slots.
/// Cached pointers are unusable until a live lease validates their domain.
#[derive(Debug)]
pub struct NativeTranslations {
    domain: Option<Arc<BindingDomain>>,
    generation: u64,
    slots: [Option<Slot>; SLOTS],
    diagnostics: TranslationDiagnostics,
}

impl Default for NativeTranslations {
    fn default() -> Self {
        Self {
            domain: None,
            generation: 0,
            slots: [None; SLOTS],
            diagnostics: Default::default(),
        }
    }
}

impl TranslationCache for NativeTranslations {
    fn diagnostics(&self) -> TranslationDiagnostics {
        self.diagnostics
    }
}

/// Domain-validated access to cached host bindings under one live mapping lease.
pub struct NativeTranslated<'a> {
    ram: &'a NativeRam<'a>,
    cache: &'a mut NativeTranslations,
    enabled: bool,
}

impl<'a> NativeTranslated<'a> {
    pub(super) fn new(ram: &'a NativeRam<'a>, cache: &'a mut NativeTranslations) -> Self {
        let current = ram.binding_domain.and_then(|domain| {
            let generation = domain.generation.load(Ordering::Relaxed);
            (generation != u64::MAX).then_some((domain, generation))
        });
        let unchanged = current.is_some_and(|(domain, generation)| {
            cache
                .domain
                .as_ref()
                .is_some_and(|old| Arc::ptr_eq(old, domain))
                && cache.generation == generation
        });
        if !unchanged {
            if cache.domain.is_some() {
                cache.diagnostics.invalidations = cache.diagnostics.invalidations.wrapping_add(1);
            }
            cache.slots.fill(None);
            cache.domain = current.map(|(domain, _)| Arc::clone(domain));
            cache.generation = current.map_or(0, |(_, generation)| generation);
        }
        Self {
            ram,
            cache,
            enabled: current.is_some(),
        }
    }

    fn bind(&self, physical_page: u64) -> Option<Mapping> {
        let start = physical_page.checked_mul(4096)?;
        let end = start.checked_add(4096)?;
        let first = *self.ram.mapping(start, false).ok()?;
        let data = first.data.wrapping_add((start - first.start) as usize);
        let (mut current, mut writable) = (first.end, first.writable);
        while current < end {
            let next = self.ram.mapping(current, false).ok()?;
            if next.data != data.wrapping_add((current - start) as usize) {
                return None;
            }
            // A single write binding must describe every destination on the page.
            writable &= next.writable && next.watched == first.watched;
            current = next.end;
        }
        Some(Mapping {
            start,
            end,
            data,
            writable,
            ..first
        })
    }

    #[inline(never)]
    fn fill(&mut self, index: usize, translation: Translation) {
        self.cache.diagnostics.misses = self.cache.diagnostics.misses.wrapping_add(1);
        self.cache.slots[index] = Some(Slot {
            translation,
            mapping: self.bind(translation.physical_page),
        });
    }

    #[inline]
    fn pointer(
        &mut self,
        translation: &Translation,
        address: u64,
        size: usize,
        write: bool,
    ) -> Option<(*mut u8, bool)> {
        if !self.enabled || size == 0 || address / 4096 != translation.physical_page {
            return None;
        }
        let end = address.checked_add(u64::try_from(size).ok()?)?;
        let page_end = (address & !4095).checked_add(4096)?;
        if end > page_end {
            return None;
        }
        let index = match translation.slot {
            TranslationSlot::Fetch => 0,
            TranslationSlot::Data => data_index(translation.physical_page),
            TranslationSlot::Table(level) if level < 4 => usize::from(level) + 1,
            TranslationSlot::Table(_) => return None,
        };
        let hit = self.cache.slots[index].is_some_and(|slot| slot.translation == *translation);
        if !hit {
            self.fill(index, *translation);
        }
        let mapping = self.cache.slots[index]?.mapping?;
        if write && !mapping.writable {
            return None;
        }
        if hit {
            self.cache.diagnostics.hits = self.cache.diagnostics.hits.wrapping_add(1);
        }
        Some((
            mapping
                .data
                .wrapping_add((address - mapping.start) as usize),
            mapping.watched,
        ))
    }

    fn fallback(&mut self) {
        self.cache.diagnostics.fallbacks = self.cache.diagnostics.fallbacks.wrapping_add(1);
    }
}

impl TranslatedRam for NativeTranslated<'_> {
    type Error = RamError;

    #[inline]
    fn compare_unwatched_pte(
        &mut self,
        address: u64,
        expected: u64,
        replacement: u64,
    ) -> Option<Result<AtomicResult, CopyError<RamError>>> {
        if !address.is_multiple_of(8) {
            return None;
        }
        let qualified @ (_, false) = self.ram.pointer(address, 8, true).ok()? else {
            return None;
        };
        Some(self.ram.atomic_pointer(
            address,
            8,
            AtomicOperation::CompareExchange {
                expected,
                replacement,
            },
            Some(qualified),
        ))
    }

    #[inline]
    fn direct_page(&self, physical_page: u64) -> Option<DirectPage<'_, Self>> {
        if !self.ram.direct_pages || !self.enabled {
            return None;
        }
        let slot = self.cache.slots[data_index(physical_page)]?;
        if slot.translation.physical_page != physical_page {
            return None;
        }
        let mapping = slot.mapping?;
        // SAFETY: bind qualified a complete, contiguous page. This view
        // validated its domain/generation under a lease excluding remapping
        // and new watches. The VM worker opts into unguarded native accesses.
        Some(unsafe { DirectPage::new(mapping.data, mapping.writable && !mapping.watched) })
    }

    #[inline]
    fn read_value(
        &mut self,
        translation: &Translation,
        address: u64,
        size: u8,
    ) -> Result<u64, CopyError<RamError>> {
        if matches!(size, 1 | 2 | 4 | 8)
            && let Some((pointer, _)) = self.pointer(translation, address, usize::from(size), false)
        {
            macro_rules! read {
                ($n:literal, $convert:expr) => {{
                    // SAFETY: this domain-validated page is reserved by the live lease.
                    unsafe { self.ram.read_pointer::<$n>(pointer) }.map($convert)
                }};
            }

            return match size {
                1 => read!(1, |b: [u8; 1]| u64::from(b[0])),
                2 => read!(2, |b| u64::from(u16::from_le_bytes(b))),
                4 => read!(4, |b| u64::from(u32::from_le_bytes(b))),
                _ => read!(8, u64::from_le_bytes),
            }
            .map_err(|source| CopyError {
                completed: 0,
                kind: CopyErrorKind::Memory(source),
            });
        }
        self.fallback();
        physical::read_value(self.ram, address, size)
    }

    #[inline]
    fn write_bytes(
        &mut self,
        translation: &Translation,
        address: u64,
        bytes: &[u8],
    ) -> Result<WriteOutcome, CopyError<RamError>> {
        if bytes.is_empty() {
            return Ok(WriteOutcome::Ordinary);
        }
        let Some((pointer, watched)) = self.pointer(translation, address, bytes.len(), true) else {
            self.fallback();
            return self.ram.write_bytes_observed(address, bytes);
        };
        let mut completed = 0;
        while completed < bytes.len() {
            let current = address + completed as u64;
            let width = scalar_width(current, bytes.len() - completed);
            macro_rules! write {
                ($n:literal) => {{
                    let value = bytes[completed..completed + $n].try_into().unwrap();
                    // SAFETY: the qualified page is writable for this entire lease.
                    unsafe {
                        self.ram.write_pointer::<$n>(
                            current,
                            value,
                            pointer.wrapping_add(completed),
                            watched,
                        )
                    }
                }};
            }
            match width {
                8 => write!(8),
                4 => write!(4),
                2 => write!(2),
                _ => write!(1),
            }
            .map_err(|source| CopyError {
                completed,
                kind: CopyErrorKind::Memory(source),
            })?;
            completed += width;
        }
        Ok(if watched {
            WriteOutcome::Watched
        } else {
            WriteOutcome::Ordinary
        })
    }

    #[inline]
    fn atomic(
        &mut self,
        translation: &Translation,
        address: u64,
        size: u8,
        operation: AtomicOperation,
    ) -> Result<AtomicResult, CopyError<RamError>> {
        if let Some(pointer) = self.pointer(translation, address, usize::from(size), true) {
            self.ram
                .atomic_pointer(address, size, operation, Some(pointer))
        } else {
            self.fallback();
            self.ram.atomic(address, size, operation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guestmem::WriteObserver;
    use sparse_mmap::SparseMapping;
    use test_with_tracing::test;

    struct Memory {
        partition: PartitionMemory,
        backing: SparseMapping,
    }

    fn memory(tracker: Option<WriteTracker>, bias: usize, committed: usize) -> Memory {
        let backing = SparseMapping::new(8192).unwrap();
        backing.alloc(0, committed).unwrap();
        let partition =
            tracker.map_or_else(PartitionMemory::new, PartitionMemory::with_write_tracker);
        // SAFETY: Memory destroys the mapping table before this reservation.
        unsafe { partition.map_range(backing.as_ptr().add(bias).cast(), 4096, 0, true, true) }
            .unwrap();
        Memory { partition, backing }
    }

    fn key() -> Translation {
        Translation {
            slot: TranslationSlot::Data,
            physical_page: 0,
        }
    }

    #[test]
    fn direct_page_only_peeks_at_the_current_data_slot_and_lease() {
        let first = memory(None, 0, 8192);
        let second = memory(None, 0, 8192);
        let mut cache = NativeTranslations::default();
        {
            let access = first.partition.access();
            let ram = access.ram_for_execution();
            let mut view = ram.translated(&mut cache);
            for slot in [TranslationSlot::Fetch, TranslationSlot::Table(1)] {
                view.read_value(&Translation { slot, ..key() }, 0, 1)
                    .unwrap();
                assert!(view.direct_page(0).is_none());
            }
            view.read_value(&key(), 0, 1).unwrap();
            assert!(view.direct_page(1).is_none());
            let page = view.direct_page(0).unwrap();
            assert!(page.writable());
            assert_eq!(page.as_ptr(), first.backing.as_ptr().cast());
        }
        // The same slot is still cached but a fault-recovering caller has
        // not opted into direct loads or stores.
        let access = first.partition.access();
        assert!(access.ram().translated(&mut cache).direct_page(0).is_none());
        let access = second.partition.access();
        assert!(
            access
                .ram_for_execution()
                .translated(&mut cache)
                .direct_page(0)
                .is_none()
        );
        assert_eq!(cache.diagnostics.misses, 3);
    }

    #[cfg(feature = "direct-ram")]
    #[test]
    fn data_bindings_coexist_until_index_collision_or_domain_revocation() {
        let memory = memory(None, 0, 8192);
        let mut cache = NativeTranslations::default();
        // SAFETY: the reservation outlives both mappings. This untracked
        // fixture permits two physical names for the second host page.
        unsafe {
            for page in [1, DATA_SLOTS] {
                memory
                    .partition
                    .map_range(
                        memory.backing.as_ptr().add(4096).cast(),
                        4096,
                        page as u64 * 4096,
                        true,
                        true,
                    )
                    .unwrap();
            }
        }
        {
            let access = memory.partition.access();
            let ram = access.ram_for_execution();
            let mut view = ram.translated(&mut cache);
            for page in [0, 1, DATA_SLOTS as u64] {
                view.read_value(
                    &Translation {
                        physical_page: page,
                        ..key()
                    },
                    page * 4096,
                    1,
                )
                .unwrap();
                assert!(view.direct_page(page).is_some());
                if page == 1 {
                    assert!(view.direct_page(0).is_some());
                }
            }
            assert!(view.direct_page(1).is_some());
            assert!(view.direct_page(0).is_none());
        }
        memory.partition.unmap_range(4096, 4096).unwrap();
        let access = memory.partition.access();
        let ram = access.ram_for_execution();
        let view = ram.translated(&mut cache);
        assert!(view.direct_page(1).is_none());
        assert!(view.direct_page(DATA_SLOTS as u64).is_none());
    }

    #[test]
    fn split_page_requires_contiguous_host_bytes_and_combines_permissions() {
        for (offset, readable) in [(2048, true), (4096, false)] {
            let memory = memory(None, 0, 8192);
            memory.partition.unmap_range(0, 4096).unwrap();
            // SAFETY: both nonoverlapping host spans belong to `memory`.
            unsafe {
                memory
                    .partition
                    .map_range(memory.backing.as_ptr().cast(), 2048, 0, true, true)
                    .unwrap();
                memory
                    .partition
                    .map_range(
                        memory.backing.as_ptr().add(offset).cast(),
                        2048,
                        2048,
                        false,
                        true,
                    )
                    .unwrap();
            }
            let access = memory.partition.access();
            let ram = access.ram_for_execution();
            let mut cache = NativeTranslations::default();
            let mut view = ram.translated(&mut cache);
            view.read_value(&key(), 0, 1).unwrap();
            assert_eq!(
                view.direct_page(0).map(|page| page.writable()),
                readable.then_some(false)
            );
        }
    }

    #[test]
    fn bindings_survive_batches_and_ordinary_content_writes() {
        let memory = memory(None, 0, 8192);
        let mut cache = NativeTranslations::default();
        for value in 1u64..=8 {
            memory.backing.write_at(0, &value.to_le_bytes()).unwrap();
            let access = memory.partition.access();
            let ram = access.ram();
            let mut view = ram.translated(&mut cache);
            assert_eq!(view.read_value(&key(), 0, 8).unwrap(), value);
        }
        assert_eq!(cache.diagnostics.misses, 1);
        assert_eq!(cache.diagnostics.hits, 7);
        assert_eq!(cache.diagnostics.invalidations, 0);
    }

    #[test]
    fn walker_bindings_read_fresh_table_contents_without_rebinding() {
        let memory = memory(None, 0, 8192);
        let mut cache = NativeTranslations::default();
        for value in [11u64, 22] {
            memory.backing.write_at(0, &value.to_le_bytes()).unwrap();
            let access = memory.partition.access();
            let ram = access.ram();
            let mut view = ram.translated(&mut cache);
            for level in 0..4 {
                let translation = Translation {
                    slot: TranslationSlot::Table(level),
                    physical_page: 0,
                };
                assert_eq!(view.read_value(&translation, 0, 8).unwrap(), value);
            }
        }
        assert_eq!(cache.diagnostics.misses, 4);
        assert_eq!(cache.diagnostics.hits, 4);
        assert_eq!(cache.diagnostics.invalidations, 0);
    }

    #[test]
    fn remap_revokes_cached_addresses_before_old_backing_is_released() {
        let mut memory = memory(None, 0, 8192);
        let mut cache = NativeTranslations::default();
        memory.backing.write_at(0, &11u64.to_le_bytes()).unwrap();
        {
            let access = memory.partition.access();
            let ram = access.ram();
            assert_eq!(
                ram.translated(&mut cache).read_value(&key(), 0, 8).unwrap(),
                11
            );
        }
        let replacement = SparseMapping::new(8192).unwrap();
        replacement.alloc(0, 8192).unwrap();
        replacement.write_at(0, &22u64.to_le_bytes()).unwrap();
        memory.partition.unmap_range(0, 4096).unwrap();
        // SAFETY: replacement becomes Memory's reservation before further access.
        unsafe {
            memory
                .partition
                .map_range(replacement.as_ptr().cast(), 4096, 0, true, true)
        }
        .unwrap();
        drop(std::mem::replace(&mut memory.backing, replacement));
        {
            let access = memory.partition.access();
            let ram = access.ram();
            assert_eq!(
                ram.translated(&mut cache).read_value(&key(), 0, 8).unwrap(),
                22
            );
        }
        assert_eq!(
            (cache.diagnostics.misses, cache.diagnostics.invalidations),
            (2, 1)
        );
        memory.partition.unmap_range(0, 4096).unwrap();
        let access = memory.partition.access();
        let ram = access.ram();
        assert!(matches!(
            ram.translated(&mut cache).read_value(&key(), 0, 8),
            Err(CopyError {
                kind: CopyErrorKind::Memory(RamError::Unmapped(0)),
                ..
            })
        ));
    }

    #[test]
    fn provider_domains_and_write_permissions_cannot_reuse_old_payloads() {
        let first = memory(None, 0, 8192);
        let second = memory(None, 0, 8192);
        first.backing.write_at(0, &11u64.to_le_bytes()).unwrap();
        second.backing.write_at(0, &22u64.to_le_bytes()).unwrap();
        let mut cache = NativeTranslations::default();
        for (memory, value) in [(&first, 11), (&second, 22)] {
            let access = memory.partition.access();
            let ram = access.ram();
            assert_eq!(
                ram.translated(&mut cache).read_value(&key(), 0, 8).unwrap(),
                value
            );
        }
        assert_eq!(cache.diagnostics.invalidations, 1);
        second.partition.unmap_range(0, 4096).unwrap();
        // SAFETY: the same reserved backing remains owned by second.
        unsafe {
            second
                .partition
                .map_range(second.backing.as_ptr().cast(), 4096, 0, false, true)
        }
        .unwrap();
        let access = second.partition.access();
        let ram = access.ram();
        assert!(matches!(
            ram.translated(&mut cache)
                .write_bytes(&key(), 0, &33u64.to_le_bytes()),
            Err(CopyError {
                completed: 0,
                kind: CopyErrorKind::Memory(RamError::ReadOnly(0))
            })
        ));
        assert_eq!(ram.read::<8>(0).unwrap(), 22u64.to_le_bytes());
    }

    #[derive(Default)]
    struct Observer(Mutex<Vec<Range<u64>>>);

    impl WriteObserver for Observer {
        fn notify_write(&self, range: Range<u64>) {
            self.0.lock().push(range);
        }
    }

    #[test]
    fn split_store_reports_only_the_watched_destination_chunks() {
        let observer = Arc::new(Observer::default());
        let memory = memory(Some(WriteTracker::new(observer.clone())), 0, 8192);
        memory.partition.unmap_range(0, 4096).unwrap();
        // SAFETY: Memory owns both halves of this reservation throughout.
        unsafe {
            memory
                .partition
                .map_range(memory.backing.as_ptr().cast(), 2048, 0, true, true)
        }
        .unwrap();
        memory.partition.with_code_watch(0..2048, |_| ()).unwrap();
        let mut cache = NativeTranslations::default();
        {
            let access = memory.partition.access();
            let ram = access.ram();
            let error = ram
                .translated(&mut cache)
                .write_bytes(&key(), 2044, &[1; 8])
                .unwrap_err();
            assert_eq!(error.completed, 4);
            assert!(matches!(
                error.kind,
                CopyErrorKind::Memory(RamError::Unmapped(2048))
            ));
            assert_eq!(ram.read::<4>(2044).unwrap(), [1; 4]);
        }
        // The newly mapped half is ordinary despite sharing the watched half's physical page.
        // SAFETY: the second half remains reserved by Memory.
        unsafe {
            memory.partition.map_range(
                memory.backing.as_ptr().add(2048).cast(),
                2048,
                2048,
                true,
                true,
            )
        }
        .unwrap();
        let access = memory.partition.access();
        let ram = access.ram();
        let mut view = ram.translated(&mut cache);
        assert_eq!(
            view.write_bytes(&key(), 2044, &[2; 8]).unwrap(),
            WriteOutcome::Watched
        );
        assert_eq!(
            view.write_bytes(&key(), 2048, &[3; 4]).unwrap(),
            WriteOutcome::Ordinary
        );
        assert_eq!(ram.read::<8>(2044).unwrap(), [2, 2, 2, 2, 3, 3, 3, 3]);
        assert_eq!(&*observer.0.lock(), &[2044..2048, 2044..2048]);
    }

    #[test]
    fn watch_activation_revokes_store_qualification_but_writes_do_not() {
        let observer = Arc::new(Observer::default());
        let memory = memory(Some(WriteTracker::new(observer.clone())), 0, 8192);
        let mut cache = NativeTranslations::default();
        {
            let access = memory.partition.access();
            let ram = access.ram_for_execution();
            let mut view = ram.translated(&mut cache);
            assert_eq!(
                view.write_bytes(&key(), 0, &1u64.to_le_bytes()).unwrap(),
                WriteOutcome::Ordinary
            );
            assert!(view.direct_page(0).unwrap().writable());
        }
        assert!(observer.0.lock().is_empty());
        memory.partition.with_code_watch(0..4096, |_| ()).unwrap();
        for address in [8, 16] {
            let access = memory.partition.access();
            let ram = access.ram_for_execution();
            let mut view = ram.translated(&mut cache);
            if address == 8 {
                assert!(view.direct_page(0).is_none());
            }
            assert_eq!(
                view.write_bytes(&key(), address, &2u64.to_le_bytes())
                    .unwrap(),
                WriteOutcome::Watched
            );
            assert!(!view.direct_page(0).unwrap().writable());
        }
        assert_eq!(&*observer.0.lock(), &[8..16, 16..24]);
        assert_eq!(
            (cache.diagnostics.misses, cache.diagnostics.invalidations),
            (2, 1)
        );
        assert_eq!(cache.diagnostics.hits, 1);
    }

    #[test]
    fn bound_copies_report_the_committed_prefix_on_host_fault() {
        let memory = memory(None, 8, 4096);
        let mut cache = NativeTranslations::default();
        let access = memory.partition.access();
        let ram = access.ram();
        let error = ram
            .translated(&mut cache)
            .write_bytes(&key(), 4080, &[0xa5; 16])
            .unwrap_err();
        assert_eq!(error.completed, 8);
        assert!(matches!(
            error.kind,
            CopyErrorKind::Memory(RamError::Memory(_))
        ));
        let mut prefix = [0; 8];
        memory.backing.read_at(4088, &mut prefix).unwrap();
        assert_eq!(prefix, [0xa5; 8]);
    }

    #[test]
    fn bound_atomics_share_native_results_and_flags() {
        let memory = memory(None, 0, 8192);
        let mut cache = NativeTranslations::default();
        let access = memory.partition.access();
        let ram = access.ram();
        for operation in [
            AtomicOperation::CompareExchange {
                expected: 0,
                replacement: 7,
            },
            AtomicOperation::CompareExchange {
                expected: 1,
                replacement: 7,
            },
            AtomicOperation::Exchange { replacement: 9 },
            AtomicOperation::FetchAdd { source: 3 },
            AtomicOperation::Integer {
                operation: integer::Operation::Add,
                source: 3,
                flags: 2,
            },
        ] {
            memory.backing.write_at(0, &[0; 32]).unwrap();
            let result = ram
                .translated(&mut cache)
                .atomic(&key(), 0, 8, operation)
                .unwrap();
            assert_eq!(result, ram.atomic(16, 8, operation).unwrap());
            assert_eq!(ram.read::<8>(0).unwrap(), ram.read::<8>(16).unwrap());
        }
        assert_eq!(
            (cache.diagnostics.misses, cache.diagnostics.invalidations),
            (1, 0)
        );
    }

    #[test]
    fn exhausted_revocation_generation_disables_bindings_without_wrapping() {
        let memory = memory(None, 0, 8192);
        memory
            .partition
            .binding_domain
            .generation
            .store(u64::MAX - 1, Ordering::Relaxed);
        let mut cache = NativeTranslations::default();
        {
            let access = memory.partition.access();
            let ram = access.ram();
            ram.translated(&mut cache).read_value(&key(), 0, 8).unwrap();
        }
        // A mapping change reaches the disabled sentinel while readers are excluded.
        memory.partition.unmap_range(0, 4096).unwrap();
        // SAFETY: Memory still owns the reservation.
        unsafe {
            memory
                .partition
                .map_range(memory.backing.as_ptr().cast(), 4096, 0, true, true)
        }
        .unwrap();
        let access = memory.partition.access();
        let ram = access.ram();
        ram.translated(&mut cache).read_value(&key(), 0, 8).unwrap();
        assert_eq!(
            memory
                .partition
                .binding_domain
                .generation
                .load(Ordering::Relaxed),
            u64::MAX
        );
        assert_eq!(cache.diagnostics.misses, 1);
        assert_eq!(cache.diagnostics.fallbacks, 1);
    }

    #[test]
    fn incomplete_pages_keep_exact_width_access_without_premature_faults() {
        let memory = memory(None, 0, 8192);
        memory.backing.write_at(0, &11u64.to_le_bytes()).unwrap();
        memory.partition.unmap_range(0, 4096).unwrap();
        // SAFETY: Memory owns this smaller reserved range until unmap/drop.
        unsafe {
            memory
                .partition
                .map_range(memory.backing.as_ptr().cast(), 8, 0, true, true)
        }
        .unwrap();
        let mut cache = NativeTranslations::default();
        let access = memory.partition.access();
        let ram = access.ram_for_execution();
        let mut view = ram.translated(&mut cache);
        assert_eq!(view.read_value(&key(), 0, 8).unwrap(), 11);
        assert!(view.direct_page(0).is_none());
        assert_eq!(view.read_value(&key(), 0, 1).unwrap(), 11);
        assert!(matches!(
            view.read_value(&key(), 8, 1),
            Err(CopyError {
                kind: CopyErrorKind::Memory(RamError::Unmapped(8)),
                ..
            })
        ));
        assert_eq!(cache.diagnostics.misses, 1);
        assert_eq!(cache.diagnostics.fallbacks, 3);
    }
}
