// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BAT (Block Allocation Table) lookup and management.
//!
//! Provides on-demand BAT entry lookup through the [`PageCache`], computing
//! the correct BAT page offset for any given block number. Handles the
//! interleaving of payload block entries with sector bitmap entries.

use crate::AsyncFile;
use crate::cache::PageCache;
use crate::cache::PageKey;
use crate::cache::WriteMode;
use crate::create::ceil_div;
use crate::create::chunk_block_count;
use crate::error::CorruptionType;
use crate::error::VhdxError;
use crate::format::BatEntry;
use crate::format::BatEntryState;
use crate::format::CACHE_PAGE_SIZE;
use crate::format::ENTRIES_PER_BAT_PAGE;
use crate::format::MB1;
use bitfield_struct::bitfield;
use parking_lot::RwLock;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use zerocopy::IntoBytes;

use crate::space::EofState;
use crate::space::FreeSpaceTracker;
use zerocopy::FromBytes;

/// Cache tag for BAT region pages.
pub(crate) const BAT_TAG: u8 = 0;

/// Cache tag for metadata region pages.
pub(crate) const METADATA_TAG: u8 = 1;

/// Size of a sector bitmap block in bytes (1 MiB).
pub(crate) const SECTOR_BITMAP_BLOCK_SIZE: u32 = 1024 * 1024;

/// Manages BAT (Block Allocation Table) lookups through the page cache.
///
/// The VHDX BAT interleaves data block entries with sector bitmap entries.
/// Every `chunk_ratio` payload entries are followed by one sector bitmap
/// entry. This struct computes the correct entry index for any block number.
/// Sentinel value stored in an atomic refcount to indicate that trim
/// has claimed the block. IO paths must wait when they see this value.
pub(crate) const TRIM_SENTINEL: u32 = u32::MAX;

pub(crate) struct Bat {
    /// Number of data blocks (payload blocks) in the disk.
    pub data_block_count: u32,
    /// Number of sector bitmap blocks (chunks). Zero if no parent.
    pub sector_bitmap_block_count: u32,
    /// Chunk ratio: number of data blocks per sector bitmap entry.
    pub chunk_ratio: u32,
    /// Block size in bytes.
    pub block_size: u32,
    /// Whether the disk has a parent (differencing).
    pub has_parent: bool,

    pub bat_state: RwLock<BatState>,

    /// Per-payload-block I/O refcounts. Atomic to avoid requiring
    /// the bat_state write lock on the read/write hot path.
    ///
    /// Values:
    /// - `0`: idle — no I/O in progress, trim may claim.
    /// - `1..TRIM_SENTINEL-1`: I/O refcount — trim must wait.
    /// - `TRIM_SENTINEL` (`u32::MAX`): trim has claimed the block — I/O must wait.
    io_refcounts: Vec<AtomicU32>,

    /// Broadcast event notified when any I/O guard is dropped and a block's
    /// refcount reaches zero. Trim (Phase 11) waits on this event when it
    /// finds a block with refcount > 0.
    trim_event: event_listener::Event,

    /// Broadcast event notified when trim releases its claim on a block.
    /// I/O paths wait on this event when they find a block claimed by trim.
    io_wait_event: event_listener::Event,
}

/// In-memory BAT entry. Compact 32-bit representation used in the in-memory
/// BAT array (not on disk).
///
/// Layout: state (3 bits) | transitioning_to_fully_present (1 bit) | file_megabyte (28 bits)
///
/// The 28-bit `file_megabyte` field supports files up to 2^28 MB = 256 TB.
#[bitfield(u32)]
#[derive(PartialEq, Eq)]
pub(crate) struct InternalBlockMapping {
    /// Block state (same values as BatEntryState).
    #[bits(3)]
    pub state: u8,
    /// Set during allocation: space has been allocated but data I/O may still
    /// be in flight. Other writers to this block must wait.
    #[bits(1)]
    pub transitioning_to_fully_present: bool,
    /// File offset in megabytes.
    #[bits(28)]
    pub file_megabyte: u32,
}

impl InternalBlockMapping {
    /// File byte offset (converts the megabyte field to bytes).
    pub fn file_offset(self) -> u64 {
        self.file_megabyte() as u64 * MB1
    }

    /// Parse the block state.
    ///
    /// Panics if the raw state is invalid — this is an internal invariant
    /// since states are validated at BAT load time and only set to known
    /// values at runtime.
    pub fn bat_state(self) -> BatEntryState {
        BatEntryState::from_raw(self.state()).expect("InternalBlockMapping has invalid state")
    }

    /// Create an `InternalBlockMapping` from an on-disk [`BatEntry`].
    ///
    /// For non-differencing disks (`has_parent == false`), normalizes
    /// `PartiallyPresent` to `FullyPresent` at load time so callers
    /// don't need to handle the distinction.
    ///
    /// Panics if the on-disk file offset exceeds the 28-bit megabyte field
    /// (files > 256 TB).
    pub fn from_bat_entry(entry: BatEntry, has_parent: bool) -> Self {
        let file_mb = entry.file_offset_mb();
        assert!(
            file_mb <= 0x0FFF_FFFF,
            "file offset {file_mb} MB exceeds 28-bit InternalBlockMapping limit (256 TB)"
        );
        let mut state = entry.state();
        // Normalize PartiallyPresent → FullyPresent for non-diff disks.
        if !has_parent && state == BatEntryState::PartiallyPresent as u8 {
            state = BatEntryState::FullyPresent as u8;
        }
        InternalBlockMapping::new()
            .with_state(state)
            .with_transitioning_to_fully_present(false)
            .with_file_megabyte(file_mb as u32)
    }

    /// Create an `InternalBlockMapping` from an on-disk SBM [`BatEntry`].
    ///
    /// Normalizes `PartiallyPresent` to `FullyPresent` (compatibility).
    pub fn from_sbm_bat_entry(entry: BatEntry) -> Self {
        let file_mb = entry.file_offset_mb();
        assert!(
            file_mb <= 0x0FFF_FFFF,
            "file offset {file_mb} MB exceeds 28-bit InternalBlockMapping limit (256 TB)"
        );
        let mut state = entry.state();
        if state == BatEntryState::PartiallyPresent as u8 {
            state = BatEntryState::FullyPresent as u8;
        }
        InternalBlockMapping::new()
            .with_state(state)
            .with_transitioning_to_fully_present(false)
            .with_file_megabyte(file_mb as u32)
    }
}

/// Block type discriminator for BAT entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockType {
    /// A data payload block.
    Payload,
    /// A sector bitmap block (differencing disks only).
    SectorBitmap,
}

/// In-memory BAT state. Protected by `parking_lot::RwLock` on `VhdxFile`.
/// All block state lookups read from this structure — no file I/O needed.
///
/// I/O refcounts are stored separately on [`Bat::io_refcounts`] as atomics,
/// outside this lock.
pub(crate) struct BatState {
    /// One entry per payload block (indexed by block number).
    pub payload_mappings: Vec<InternalBlockMapping>,
    /// One entry per sector bitmap block (indexed by chunk number).
    pub sector_bitmap_mappings: Vec<InternalBlockMapping>,
    /// Running count of allocated (FullyPresent or PartiallyPresent) blocks.
    pub allocated_block_count: u32,
}

/// Whether a block state counts as "allocated" for `allocated_block_count`.
fn is_allocated_state(state: u8) -> bool {
    state == BatEntryState::FullyPresent as u8 || state == BatEntryState::PartiallyPresent as u8
}

impl BatState {
    /// Get the in-memory mapping for a payload block.
    pub fn get_payload_mapping(&self, block_number: u32) -> InternalBlockMapping {
        self.payload_mappings[block_number as usize]
    }

    /// Get the in-memory mapping for a sector bitmap block.
    pub fn get_sbm_mapping(&self, chunk_number: u32) -> InternalBlockMapping {
        self.sector_bitmap_mappings[chunk_number as usize]
    }

    /// Update the in-memory mapping for a payload block.
    ///
    /// Adjusts `allocated_block_count` based on the old and new states.
    pub fn set_payload_mapping(
        &mut self,
        bat: &Bat,
        block_number: u32,
        mapping: InternalBlockMapping,
    ) {
        let _ = bat; // Used for consistency; entry index needed only for dirty tracking.
        let old = self.payload_mappings[block_number as usize];
        let was_allocated = is_allocated_state(old.state());
        let now_allocated = is_allocated_state(mapping.state());
        if was_allocated && !now_allocated {
            self.allocated_block_count -= 1;
        } else if !was_allocated && now_allocated {
            self.allocated_block_count += 1;
        }
        self.payload_mappings[block_number as usize] = mapping;
    }

    /// Update the in-memory mapping for a sector bitmap block.
    pub fn set_sbm_mapping(&mut self, bat: &Bat, chunk_number: u32, mapping: InternalBlockMapping) {
        let _ = bat;
        self.sector_bitmap_mappings[chunk_number as usize] = mapping;
    }
}

impl Bat {
    /// Create a new BAT manager from parsed metadata.
    ///
    /// Computes chunk ratio, data block count, and sector bitmap block count.
    pub fn new(
        disk_size: u64,
        block_size: u32,
        logical_sector_size: u32,
        has_parent: bool,
        bat_length: u32,
    ) -> Result<Self, VhdxError> {
        let chunk_ratio = chunk_block_count(block_size, logical_sector_size);
        if chunk_ratio == 0 {
            return Err(VhdxError::Corrupt(CorruptionType::InvalidBlockSize));
        }

        let data_block_count = ceil_div(disk_size, block_size as u64) as u32;
        let sector_bitmap_block_count = if has_parent {
            ceil_div(data_block_count as u64, chunk_ratio as u64) as u32
        } else {
            0
        };

        let entry_count = if has_parent {
            sector_bitmap_block_count as u64 * (chunk_ratio as u64 + 1)
        } else {
            data_block_count as u64
                + (data_block_count.saturating_sub(1) as u64 / chunk_ratio as u64)
        };

        let required_bytes = entry_count * size_of::<BatEntry>() as u64;
        if required_bytes > bat_length as u64 {
            return Err(VhdxError::Corrupt(CorruptionType::BatTooSmall));
        }

        let bat_state = BatState {
            payload_mappings: Vec::with_capacity(data_block_count as usize),
            sector_bitmap_mappings: Vec::with_capacity(sector_bitmap_block_count as usize),
            allocated_block_count: 0,
        };

        let io_refcounts = (0..data_block_count).map(|_| AtomicU32::new(0)).collect();

        Ok(Bat {
            data_block_count,
            sector_bitmap_block_count,
            chunk_ratio,
            block_size,
            has_parent,
            bat_state: bat_state.into(),
            io_refcounts,
            trim_event: event_listener::Event::new(),
            io_wait_event: event_listener::Event::new(),
        })
    }

    /// Try to atomically increment the I/O refcount for a block.
    ///
    /// Returns `true` if the increment succeeded, `false` if trim has
    /// claimed the block (sentinel set). Uses a CAS loop to avoid
    /// needing the bat_state write lock.
    fn try_increment_io_refcount(&self, block_number: u32) -> bool {
        let rc = &self.io_refcounts[block_number as usize];
        loop {
            let old = rc.load(Ordering::Acquire);
            if old == TRIM_SENTINEL {
                return false;
            }
            let new = old.checked_add(1).expect("io_refcount overflow");
            match rc.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    /// Atomically decrement the I/O refcount. Returns the previous value.
    ///
    /// Panics on underflow or if the sentinel is set (trim owns the block).
    fn decrement_io_refcount(&self, block_number: u32) -> u32 {
        let prev = self.io_refcounts[block_number as usize].fetch_sub(1, Ordering::AcqRel);
        assert!(
            prev > 0 && prev != TRIM_SENTINEL,
            "io_refcount underflow or trim sentinel on block {block_number}"
        );
        prev
    }

    /// Try to claim a block for trim by CAS 0 → TRIM_SENTINEL.
    ///
    /// Returns `true` if the claim succeeded (block was idle), `false` if
    /// I/O is active (refcount > 0) or another trim already claimed it.
    pub(crate) async fn claim_for_trim(&self, block_number: u32) -> TrimGuard<'_> {
        loop {
            let listener = self.trim_event.listen();
            match self.io_refcounts[block_number as usize].compare_exchange(
                0,
                TRIM_SENTINEL,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return TrimGuard {
                        bat: self,
                        block_number,
                    };
                }
                Err(_) => {
                    listener.await;
                }
            }
        }
    }

    /// Release a trim claim on a block (store 0).
    fn release_trim_claim(&self, block_number: u32) {
        let prev = self.io_refcounts[block_number as usize].swap(0, Ordering::Release);
        assert_eq!(
            prev, TRIM_SENTINEL,
            "release_trim_claim on block {block_number} that wasn't claimed (was {prev})"
        );
        self.io_wait_event.notify(usize::MAX);
    }

    /// Load the current I/O refcount for a block.
    #[cfg(test)]
    pub(crate) fn io_refcount(&self, block_number: u32) -> u32 {
        self.io_refcounts[block_number as usize].load(Ordering::Acquire)
    }

    /// Compute the BAT entry index for a given data block number.
    ///
    /// For every `chunk_ratio` payload entries, one sector bitmap entry is
    /// interleaved. The entry index accounts for these interleaved entries.
    pub fn payload_entry_index(&self, block_number: u32) -> u32 {
        block_number + (block_number / self.chunk_ratio)
    }

    /// Compute the BAT entry index for a given sector bitmap block (chunk number).
    ///
    /// The sector bitmap entry follows every `chunk_ratio` payload entries.
    pub fn sector_bitmap_entry_index(&self, chunk_number: u32) -> u32 {
        ((chunk_number + 1) * self.chunk_ratio) + chunk_number
    }

    /// Reverse-map a flat BAT entry number to (block_type, block_number).
    ///
    /// Returns `None` if the entry is beyond the end of the disk.
    fn entry_number_to_block_id(&self, entry_number: u32) -> Option<(BlockType, u32)> {
        let group_size = self.chunk_ratio + 1;
        let group = entry_number / group_size;
        let position = entry_number % group_size;

        if self.has_parent && position == self.chunk_ratio {
            // This is a sector bitmap entry.
            if group < self.sector_bitmap_block_count {
                Some((BlockType::SectorBitmap, group))
            } else {
                None
            }
        } else {
            // This is a payload entry.
            let block_number = group * self.chunk_ratio + position;
            if block_number < self.data_block_count {
                Some((BlockType::Payload, block_number))
            } else {
                None
            }
        }
    }

    /// Convert a virtual disk byte offset to a block number.
    pub fn offset_to_block(&self, offset: u64) -> u32 {
        (offset / self.block_size as u64) as u32
    }

    /// Compute the byte offset within a block for a given virtual disk offset.
    pub fn offset_within_block(&self, offset: u64) -> u32 {
        (offset % self.block_size as u64) as u32
    }

    /// Serialize a BAT page from in-memory state.
    ///
    /// Produces all entries for the given page, with TFP blocks having
    /// their `file_offset_mb` masked to zero (allocation not committed
    /// yet). Matches the C code's `Vhd2iProduceBatPageLocked` +
    /// `Vhd2iGenerateBatEntry` behavior.
    fn produce_page(&self, page_index: usize, buf: &mut [u8; CACHE_PAGE_SIZE as usize]) {
        let base_entry = page_index as u32 * ENTRIES_PER_BAT_PAGE as u32;
        let bat_state = self.bat_state.read();
        for i in 0..ENTRIES_PER_BAT_PAGE as u32 {
            let entry_number = base_entry + i;
            let bat_entry = match self.entry_number_to_block_id(entry_number) {
                Some((BlockType::Payload, block_number)) => {
                    let mapping = bat_state.get_payload_mapping(block_number);
                    let file_mb = if mapping.transitioning_to_fully_present() {
                        0
                    } else {
                        mapping.file_megabyte() as u64
                    };
                    BatEntry::new()
                        .with_state(mapping.state())
                        .with_file_offset_mb(file_mb)
                }
                Some((BlockType::SectorBitmap, chunk_number)) => {
                    let mapping = bat_state.get_sbm_mapping(chunk_number);
                    BatEntry::new()
                        .with_state(mapping.state())
                        .with_file_offset_mb(mapping.file_megabyte() as u64)
                }
                None => BatEntry::new(),
            };
            let offset = i as usize * size_of::<BatEntry>();
            buf[offset..offset + size_of::<BatEntry>()].copy_from_slice(bat_entry.as_bytes());
        }
    }

    /// Write a block mapping to the cache, converting from in-memory
    /// representation to on-disk BAT entry format.
    ///
    /// Uses `Overwrite` mode to avoid unnecessary disk reads. If the
    /// page is already cached, patches only the single entry. If not
    /// cached, builds the full page from in-memory state (no disk read).
    ///
    /// The `bat_state` lock is only acquired in the rare uncached path,
    /// after the async cache acquire completes — no lock held across await.
    ///
    /// Matches the C code's `Vhd2iUpdateBlockStateWithNode` pattern.
    pub async fn write_block_mapping<F: AsyncFile>(
        &self,
        cache: &PageCache<F>,
        block_type: BlockType,
        block_number: u32,
        mapping: InternalBlockMapping,
        pre_log_fsn: Option<u64>,
    ) -> Result<(), VhdxError> {
        let entry_number = match block_type {
            BlockType::Payload => self.payload_entry_index(block_number),
            BlockType::SectorBitmap => self.sector_bitmap_entry_index(block_number),
        };
        let page_number = entry_number as usize / ENTRIES_PER_BAT_PAGE as usize;
        let page_offset = page_number as u64 * CACHE_PAGE_SIZE;
        let entry_within_page = entry_number as usize % ENTRIES_PER_BAT_PAGE as usize;

        let mut guard = cache
            .acquire_write(
                PageKey {
                    tag: BAT_TAG,
                    offset: page_offset,
                },
                WriteMode::Overwrite,
            )
            .await?;

        if guard.is_overwriting() {
            // Slow path: page not cached — build from in-memory state.
            // Sync lock only, no await point.
            self.produce_page(page_number, &mut *guard);
        } else {
            // Fast path: page is cached — patch just the one entry.
            let bat_entry = BatEntry::new()
                .with_state(mapping.state())
                .with_file_offset_mb(mapping.file_megabyte() as u64);
            let byte_offset = entry_within_page * size_of::<BatEntry>();
            guard[byte_offset..byte_offset + size_of::<BatEntry>()]
                .copy_from_slice(bat_entry.as_bytes());
        }

        // Set pre-log FSN while the page lock is still held, so
        // that the FSN is visible atomically with the dirty-mark.
        if let Some(fsn) = pre_log_fsn {
            guard.set_pre_log_fsn(fsn);
        }

        // BAT pages are always rebuildable from in-memory BatState,
        // so prefer evicting them over sector bitmap pages.
        guard.demote();

        Ok(())
    }

    /// Load the in-memory BAT state from disk BAT pages.
    ///
    /// During parse, marks allocated blocks in the FreeSpaceTracker and
    /// records soft-anchored blocks.
    pub(crate) async fn load_bat_state<F: AsyncFile>(
        &mut self,
        cache: &PageCache<F>,
        free_space: &FreeSpaceTracker,
        eof_state: &mut EofState,
    ) -> Result<(), VhdxError> {
        // Read all payload entries.
        for block in 0..self.data_block_count {
            let entry_index = self.payload_entry_index(block);
            let entry = Self::read_bat_entry_raw(cache, entry_index).await?;
            // Validate the entry state.
            let raw_state = entry.state();
            if BatEntryState::from_raw(raw_state).is_none() {
                return Err(VhdxError::Corrupt(CorruptionType::InvalidBlockState));
            }
            let internal = InternalBlockMapping::from_bat_entry(entry, self.has_parent);
            if raw_state == BatEntryState::FullyPresent as u8
                || raw_state == BatEntryState::PartiallyPresent as u8
            {
                self.bat_state.get_mut().allocated_block_count += 1;
                // Mark the block's file region as in-use in the space tracker.
                let file_offset = internal.file_offset();
                if file_offset != 0 {
                    free_space.mark_range_in_use(eof_state, file_offset, self.block_size)?;
                }
            } else if (raw_state == BatEntryState::Unmapped as u8
                || raw_state == BatEntryState::Undefined as u8)
                && internal.file_megabyte() != 0
            {
                // Soft-anchored block: unmapped/undefined with non-zero file offset.
                // Mark the space as in-use first (so it's not in the free pool),
                // then register it as a soft anchor for potential reclaim.
                let file_offset = internal.file_offset();
                free_space.mark_range_in_use(eof_state, file_offset, self.block_size)?;
                free_space.mark_trimmed_block(block, file_offset, self.block_size)?;
            }
            self.bat_state.get_mut().payload_mappings.push(internal);
        }

        // Read all sector bitmap entries.
        for chunk in 0..self.sector_bitmap_block_count {
            let entry_index = self.sector_bitmap_entry_index(chunk);
            let entry = Self::read_bat_entry_raw(cache, entry_index).await?;
            let raw_state = entry.state();
            if BatEntryState::from_raw(raw_state).is_none() {
                return Err(VhdxError::Corrupt(CorruptionType::InvalidBlockState));
            }
            let internal = InternalBlockMapping::from_sbm_bat_entry(entry);
            // Mark sector bitmap block's file region as in-use if allocated.
            if raw_state == BatEntryState::FullyPresent as u8
                || raw_state == BatEntryState::PartiallyPresent as u8
            {
                let file_offset = internal.file_offset();
                if file_offset != 0 {
                    free_space.mark_range_in_use(
                        eof_state,
                        file_offset,
                        SECTOR_BITMAP_BLOCK_SIZE,
                    )?;
                }
            }
            self.bat_state
                .get_mut()
                .sector_bitmap_mappings
                .push(internal);
        }

        Ok(())
    }

    /// Read a single raw BAT entry from disk through the cache.
    async fn read_bat_entry_raw<F: AsyncFile>(
        cache: &PageCache<F>,
        entry_index: u32,
    ) -> Result<BatEntry, VhdxError> {
        let page_offset = (entry_index as u64 / ENTRIES_PER_BAT_PAGE) * CACHE_PAGE_SIZE;
        let entry_within_page = entry_index as usize % ENTRIES_PER_BAT_PAGE as usize;

        let guard = cache
            .acquire_read(PageKey {
                tag: BAT_TAG,
                offset: page_offset,
            })
            .await?;

        let byte_offset = entry_within_page * size_of::<BatEntry>();
        let entry_bytes = &guard[byte_offset..byte_offset + size_of::<BatEntry>()];
        let entry = BatEntry::read_from_bytes(entry_bytes)
            .map_err(|_| VhdxError::Corrupt(CorruptionType::InvalidBlockState))?;

        Ok(entry)
    }

    /// Atomically increment I/O refcounts for a range of blocks,
    /// returning a [`ReadIoGuard`] that will release them on drop.
    ///
    /// Uses CAS to increment each block's refcount. If any block has the
    /// trim sentinel set, undoes partial increments, waits for trim to
    /// release, and retries. Returns once all blocks are successfully
    /// claimed.
    pub async fn acquire_io_refcounts(&self, start_block: u32, block_count: u32) -> BatGuard<'_> {
        loop {
            let mut guard = BatGuard {
                bat: Some(self),
                start_block,
                block_count: 0,
            };
            let listener = self.io_wait_event.listen();
            let mut blocked = false;

            for block in start_block..start_block + block_count {
                if self.try_increment_io_refcount(block) {
                    guard.block_count += 1;
                } else {
                    blocked = true;
                    break;
                }
            }

            if !blocked {
                return guard;
            }

            // Undo partial increments.
            drop(guard);

            // LOCK AUDIT: no locks held. Safe to await.
            listener.await;
        }
    }

    /// Look up the payload block mapping for a given data block number.
    ///
    /// Synchronous — reads from the in-memory BAT under a read lock.
    pub(crate) fn get_block_mapping(&self, block_number: u32) -> InternalBlockMapping {
        let bat_state = self.bat_state.read();
        bat_state.get_payload_mapping(block_number)
    }

    /// Look up the sector bitmap block mapping for a given chunk number.
    ///
    /// Synchronous — reads from the in-memory BAT under a read lock.
    pub(crate) fn get_sector_bitmap_mapping(&self, chunk_number: u32) -> InternalBlockMapping {
        let bat_state = self.bat_state.read();
        bat_state.get_sbm_mapping(chunk_number)
    }
}

#[must_use]
pub struct BatGuard<'a> {
    bat: Option<&'a Bat>,
    /// First payload block number with incremented refcount.
    start_block: u32,
    /// Number of consecutive payload blocks with incremented refcounts.
    block_count: u32,
}

impl<'a> BatGuard<'a> {
    pub(crate) fn empty() -> Self {
        Self {
            bat: None,
            start_block: 0,
            block_count: 0,
        }
    }
}

impl Drop for BatGuard<'_> {
    fn drop(&mut self) {
        let Some(bat) = self.bat else { return };
        let mut any_zero = false;
        for block in self.start_block..self.start_block + self.block_count {
            if bat.decrement_io_refcount(block) == 1 {
                // Was 1, now 0 — trim may be waiting.
                any_zero = true;
            }
        }
        if any_zero {
            bat.trim_event.notify(usize::MAX);
        }
    }
}

#[must_use]
pub struct TrimGuard<'a> {
    bat: &'a Bat,
    block_number: u32,
}

impl Drop for TrimGuard<'_> {
    fn drop(&mut self) {
        self.bat.release_trim_claim(self.block_number);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format;

    #[test]
    fn chunk_ratio_default_params() {
        // 2 MiB blocks, 512-byte sectors → chunk_ratio = 2048
        let bat = Bat::new(
            format::GB1,
            format::DEFAULT_BLOCK_SIZE,
            512,
            false,
            MB1 as u32,
        )
        .unwrap();
        assert_eq!(bat.chunk_ratio, 2048);
    }

    #[test]
    fn chunk_ratio_various_sizes() {
        // 1 MiB blocks, 512 sectors
        let bat = Bat::new(format::GB1, MB1 as u32, 512, false, MB1 as u32).unwrap();
        assert_eq!(bat.chunk_ratio, 4096);

        // 4 MiB blocks, 512 sectors
        let bat = Bat::new(format::GB1, 4 * MB1 as u32, 512, false, MB1 as u32).unwrap();
        assert_eq!(bat.chunk_ratio, 1024);

        // 32 MiB blocks, 512 sectors
        let bat = Bat::new(format::GB1, 32 * MB1 as u32, 512, false, MB1 as u32).unwrap();
        assert_eq!(bat.chunk_ratio, 128);

        // 256 MiB blocks, 512 sectors
        let bat = Bat::new(format::GB1, 256 * MB1 as u32, 512, false, MB1 as u32).unwrap();
        assert_eq!(bat.chunk_ratio, 16);

        // 2 MiB blocks, 4096 sectors: sectors_per_block = 512, chunk_ratio = 8388608 / 512 = 16384
        let bat = Bat::new(
            format::GB1,
            format::DEFAULT_BLOCK_SIZE,
            4096,
            false,
            MB1 as u32,
        )
        .unwrap();
        assert_eq!(bat.chunk_ratio, 16384);

        // 1 MiB blocks, 4096 sectors: sectors_per_block = 256, chunk_ratio = 8388608 / 256 = 32768
        let bat = Bat::new(format::GB1, MB1 as u32, 4096, false, MB1 as u32).unwrap();
        assert_eq!(bat.chunk_ratio, 32768);
    }

    #[test]
    fn payload_entry_index_calculations() {
        let bat = Bat::new(
            format::GB1,
            format::DEFAULT_BLOCK_SIZE,
            512,
            false,
            MB1 as u32,
        )
        .unwrap();
        // chunk_ratio = 2048
        assert_eq!(bat.payload_entry_index(0), 0);
        assert_eq!(bat.payload_entry_index(1), 1);
        assert_eq!(
            bat.payload_entry_index(bat.chunk_ratio - 1),
            bat.chunk_ratio - 1
        );
        // At chunk_ratio, we skip one SBM slot.
        assert_eq!(
            bat.payload_entry_index(bat.chunk_ratio),
            bat.chunk_ratio + 1
        );
        assert_eq!(
            bat.payload_entry_index(bat.chunk_ratio + 1),
            bat.chunk_ratio + 2
        );
        // At 2 * chunk_ratio, skip another.
        assert_eq!(
            bat.payload_entry_index(2 * bat.chunk_ratio),
            2 * bat.chunk_ratio + 2
        );
    }

    #[test]
    fn sector_bitmap_entry_index_calculations() {
        let bat = Bat::new(
            format::GB1,
            format::DEFAULT_BLOCK_SIZE,
            512,
            true,
            MB1 as u32,
        )
        .unwrap();
        // SBM entry 0 is at position chunk_ratio.
        assert_eq!(bat.sector_bitmap_entry_index(0), bat.chunk_ratio);
        // SBM entry 1 is at position 2*chunk_ratio + 1.
        assert_eq!(bat.sector_bitmap_entry_index(1), 2 * bat.chunk_ratio + 1);
    }

    #[test]
    fn validate_bat_size_ok() {
        // For 1 GiB / 2 MiB = 512 data blocks, chunk_ratio = 2048.
        // entries = 512 + ((512-1)/2048) = 512 + 0 = 512
        // 512 * 8 = 4096 bytes. Any bat_length >= 4096 is fine.
        Bat::new(
            format::GB1,
            format::DEFAULT_BLOCK_SIZE,
            512,
            false,
            MB1 as u32,
        )
        .unwrap();
    }

    #[test]
    fn validate_bat_size_too_small() {
        // 512 entries * 8 bytes = 4096 bytes needed.
        let result = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, false, 4095);
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::BatTooSmall))
        ));
    }

    #[test]
    fn offset_to_block_calculations() {
        let bat = Bat::new(
            format::GB1,
            format::DEFAULT_BLOCK_SIZE,
            512,
            false,
            MB1 as u32,
        )
        .unwrap();
        assert_eq!(bat.offset_to_block(0), 0);
        assert_eq!(
            bat.offset_to_block(format::DEFAULT_BLOCK_SIZE as u64 - 1),
            0
        );
        assert_eq!(bat.offset_to_block(format::DEFAULT_BLOCK_SIZE as u64), 1);
        assert_eq!(
            bat.offset_to_block(format::DEFAULT_BLOCK_SIZE as u64 * 10 + 42),
            10
        );
    }

    #[test]
    fn offset_within_block_calculations() {
        let bat = Bat::new(
            format::GB1,
            format::DEFAULT_BLOCK_SIZE,
            512,
            false,
            MB1 as u32,
        )
        .unwrap();
        assert_eq!(bat.offset_within_block(0), 0);
        assert_eq!(bat.offset_within_block(512), 512);
        assert_eq!(
            bat.offset_within_block(format::DEFAULT_BLOCK_SIZE as u64),
            0
        );
        assert_eq!(
            bat.offset_within_block(format::DEFAULT_BLOCK_SIZE as u64 + 1024),
            1024
        );
    }

    #[test]
    fn internal_mapping_roundtrip() {
        let mapping = InternalBlockMapping::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_transitioning_to_fully_present(true)
            .with_file_megabyte(12345);
        let raw = u32::from(mapping);
        let restored = InternalBlockMapping::from(raw);
        assert_eq!(restored.state(), BatEntryState::FullyPresent as u8);
        assert!(restored.transitioning_to_fully_present());
        assert_eq!(restored.file_megabyte(), 12345);
    }

    #[test]
    fn internal_mapping_max_file_megabyte() {
        let max_mb: u32 = (1 << 28) - 1; // 268435455
        let mapping = InternalBlockMapping::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_megabyte(max_mb);
        assert_eq!(mapping.file_megabyte(), max_mb);
        assert_eq!(mapping.file_offset(), max_mb as u64 * MB1);
    }

    #[test]
    fn internal_mapping_tfp_flag() {
        let with_tfp = InternalBlockMapping::new()
            .with_state(BatEntryState::NotPresent as u8)
            .with_transitioning_to_fully_present(true);
        assert!(with_tfp.transitioning_to_fully_present());

        let without_tfp = InternalBlockMapping::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_transitioning_to_fully_present(false);
        assert!(!without_tfp.transitioning_to_fully_present());

        // TFP is independent of state.
        assert_eq!(with_tfp.state(), BatEntryState::NotPresent as u8);
        assert_eq!(without_tfp.state(), BatEntryState::FullyPresent as u8);
    }

    #[test]
    fn internal_mapping_from_bat_entry() {
        let entry = BatEntry::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_offset_mb(100);
        let internal = InternalBlockMapping::from_bat_entry(entry, false);
        assert_eq!(internal.state(), BatEntryState::FullyPresent as u8);
        assert_eq!(internal.file_megabyte(), 100);
        assert!(!internal.transitioning_to_fully_present());
    }

    #[test]
    fn entry_number_to_block_id_payload() {
        // Non-differencing: all entries are payload.
        let bat = Bat::new(
            format::GB1,
            format::DEFAULT_BLOCK_SIZE,
            512,
            false,
            MB1 as u32,
        )
        .unwrap();
        // chunk_ratio = 2048, data_block_count = 512
        for i in 0..bat.data_block_count {
            let entry_index = bat.payload_entry_index(i);
            let result = bat.entry_number_to_block_id(entry_index);
            assert_eq!(result, Some((BlockType::Payload, i)), "block {i}");
        }
    }

    #[test]
    fn entry_number_to_block_id_with_sbm() {
        // Differencing disk with SBM entries.
        // Use small chunk_ratio to exercise interleaving.
        // 1 MiB blocks, 4096 sectors → chunk_ratio = 32768.
        // Use 256 MiB blocks, 512 sectors → chunk_ratio = 16.
        let bat = Bat::new(format::GB1, 256 * MB1 as u32, 512, true, MB1 as u32).unwrap();
        assert_eq!(bat.chunk_ratio, 16);
        // data_block_count = 4, sector_bitmap_block_count = 1

        // Payload entries for group 0: positions 0..15 → blocks 0..3
        for i in 0..bat.data_block_count {
            let entry_index = bat.payload_entry_index(i);
            let result = bat.entry_number_to_block_id(entry_index);
            assert_eq!(result, Some((BlockType::Payload, i)), "payload block {i}");
        }

        // SBM entry for chunk 0 at position chunk_ratio = 16
        let sbm_index = bat.sector_bitmap_entry_index(0);
        assert_eq!(
            bat.entry_number_to_block_id(sbm_index),
            Some((BlockType::SectorBitmap, 0))
        );
    }

    #[test]
    fn entry_number_to_block_id_beyond_end() {
        let bat = Bat::new(
            format::GB1,
            format::DEFAULT_BLOCK_SIZE,
            512,
            false,
            MB1 as u32,
        )
        .unwrap();
        // Entry beyond all data blocks should return None.
        let beyond = bat.payload_entry_index(bat.data_block_count);
        assert_eq!(bat.entry_number_to_block_id(beyond), None);
    }

    #[test]
    fn bat_state_allocated_count_tracking() {
        let bat = Bat::new(4 * MB1, format::DEFAULT_BLOCK_SIZE, 512, false, MB1 as u32).unwrap();
        // 2 blocks
        let mut state = BatState {
            payload_mappings: vec![InternalBlockMapping::new(); bat.data_block_count as usize],
            sector_bitmap_mappings: vec![],
            allocated_block_count: 0,
        };

        // Allocate block 0.
        let mapping = InternalBlockMapping::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_megabyte(100);
        state.set_payload_mapping(&bat, 0, mapping);
        assert_eq!(state.allocated_block_count, 1);

        // Allocate block 1.
        let mapping2 = InternalBlockMapping::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_megabyte(102);
        state.set_payload_mapping(&bat, 1, mapping2);
        assert_eq!(state.allocated_block_count, 2);

        // Deallocate block 0 → NotPresent.
        let dealloc = InternalBlockMapping::new().with_state(BatEntryState::NotPresent as u8);
        state.set_payload_mapping(&bat, 0, dealloc);
        assert_eq!(state.allocated_block_count, 1);
    }
}
