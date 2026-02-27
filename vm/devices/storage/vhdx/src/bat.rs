// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BAT (Block Allocation Table) lookup and management.
//!
//! Provides on-demand BAT entry lookup through the [`PageCache`], computing
//! the correct BAT page offset for any given block number. Handles the
//! interleaving of payload block entries with sector bitmap entries.

use bitfield_struct::bitfield;
use crate::AsyncFile;
use crate::cache::AccessMode;
use crate::cache::PageCache;
use crate::cache::PageKey;
use crate::create::ceil_div;
use crate::create::chunk_block_count;
use crate::error::CorruptionType;
use crate::error::VhdxError;
use crate::format::BatEntry;
use crate::format::BatEntryState;
use crate::format::CACHE_PAGE_SIZE;
use crate::format::ENTRIES_PER_BAT_PAGE;
use crate::format::MB1;
use zerocopy::IntoBytes;

/// Cache tag for BAT region pages.
pub(crate) const BAT_TAG: u8 = 0;

/// Cache tag for metadata region pages.
pub(crate) const METADATA_TAG: u8 = 1;

/// Size of a sector bitmap block in bytes (1 MiB).
#[allow(dead_code)] // Phase 9+: used for space management
pub(crate) const SECTOR_BITMAP_BLOCK_SIZE: u32 = 1024 * 1024;

/// Manages BAT (Block Allocation Table) lookups through the page cache.
///
/// The VHDX BAT interleaves data block entries with sector bitmap entries.
/// Every `chunk_ratio` payload entries are followed by one sector bitmap
/// entry. This struct computes the correct entry index for any block number.
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
}

/// The mapping state returned from a BAT lookup.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlockMapping {
    /// The parsed block state.
    pub state: BatEntryState,
    /// File byte offset of the block data (0 if not backed by file data).
    pub file_offset: u64,
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
    /// Convert this in-memory mapping to a [`BlockMapping`] for the read path.
    pub fn to_block_mapping(self) -> BlockMapping {
        let state = BatEntryState::from_raw(self.state())
            .unwrap_or(BatEntryState::NotPresent);
        BlockMapping {
            state,
            file_offset: self.file_megabyte() as u64 * MB1,
        }
    }

    /// Create an `InternalBlockMapping` from an on-disk [`BatEntry`].
    ///
    /// Panics if the on-disk file offset exceeds the 28-bit megabyte field
    /// (files > 256 TB).
    pub fn from_bat_entry(entry: BatEntry) -> Self {
        let file_mb = entry.file_offset_mb();
        assert!(
            file_mb <= 0x0FFF_FFFF,
            "file offset {file_mb} MB exceeds 28-bit InternalBlockMapping limit (256 TB)"
        );
        InternalBlockMapping::new()
            .with_state(entry.state())
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
pub(crate) struct BatState {
    /// One entry per payload block (indexed by block number).
    pub payload_mappings: Vec<InternalBlockMapping>,
    /// One entry per sector bitmap block (indexed by chunk number).
    pub sector_bitmap_mappings: Vec<InternalBlockMapping>,
    /// Running count of allocated (FullyPresent or PartiallyPresent) blocks.
    pub allocated_block_count: u32,
    /// Tracks which BAT pages have been modified and need writeback to disk.
    /// Indexed by BAT page number (entry_index / ENTRIES_PER_BAT_PAGE).
    pub dirty_bat_pages: Vec<bool>,
}

/// Whether a block state counts as "allocated" for `allocated_block_count`.
fn is_allocated_state(state: u8) -> bool {
    state == BatEntryState::FullyPresent as u8
        || state == BatEntryState::PartiallyPresent as u8
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
    /// Does NOT mark the BAT page dirty — callers decide when to mark dirty.
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
    ///
    /// Does NOT mark the BAT page dirty — callers decide when to mark dirty.
    #[allow(dead_code)] // will be used by allocation write path in a later phase
    pub fn set_sbm_mapping(
        &mut self,
        bat: &Bat,
        chunk_number: u32,
        mapping: InternalBlockMapping,
    ) {
        let _ = bat;
        self.sector_bitmap_mappings[chunk_number as usize] = mapping;
    }

    /// Mark the BAT page containing the given block's entry as dirty.
    pub fn mark_bat_page_dirty(&mut self, bat: &Bat, block_type: BlockType, block_number: u32) {
        let entry_index = match block_type {
            BlockType::Payload => bat.payload_entry_index(block_number),
            BlockType::SectorBitmap => bat.sector_bitmap_entry_index(block_number),
        };
        let page_index = entry_index as usize / ENTRIES_PER_BAT_PAGE as usize;
        if page_index < self.dirty_bat_pages.len() {
            self.dirty_bat_pages[page_index] = true;
        }
    }

    /// Yields indices of dirty BAT pages.
    pub fn dirty_page_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.dirty_bat_pages
            .iter()
            .enumerate()
            .filter_map(|(i, &dirty)| dirty.then_some(i))
    }

    /// Clear the dirty flag for a BAT page.
    pub fn clear_dirty(&mut self, page_index: usize) {
        if page_index < self.dirty_bat_pages.len() {
            self.dirty_bat_pages[page_index] = false;
        }
    }

    /// Total number of BAT pages.
    #[allow(dead_code)] // will be used by BAT write-back in a later phase
    pub fn total_bat_pages(&self) -> usize {
        self.dirty_bat_pages.len()
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

        Ok(Bat {
            data_block_count,
            sector_bitmap_block_count,
            chunk_ratio,
            block_size,
            has_parent,
        })
    }

    /// Validate that the BAT region is large enough for all entries.
    pub fn validate_bat_size(&self, bat_length: u32) -> Result<(), VhdxError> {
        let entry_count = if self.has_parent {
            self.sector_bitmap_block_count as u64 * (self.chunk_ratio as u64 + 1)
        } else {
            self.data_block_count as u64
                + (self.data_block_count.saturating_sub(1) as u64 / self.chunk_ratio as u64)
        };

        let required_bytes = entry_count * size_of::<BatEntry>() as u64;
        if required_bytes > bat_length as u64 {
            return Err(VhdxError::Corrupt(CorruptionType::BatTooSmall));
        }

        Ok(())
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
    pub fn entry_number_to_block_id(&self, entry_number: u32) -> Option<(BlockType, u32)> {
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

    /// Compute the total number of BAT pages needed.
    pub fn total_bat_pages(&self) -> usize {
        let total_entries = if self.has_parent {
            self.sector_bitmap_block_count as u64 * (self.chunk_ratio as u64 + 1)
        } else {
            self.data_block_count as u64
                + (self.data_block_count.saturating_sub(1) as u64 / self.chunk_ratio as u64)
                + 1 // account for the partial group's SBM slot
        };
        // Each page holds ENTRIES_PER_BAT_PAGE entries.
        ceil_div(total_entries, ENTRIES_PER_BAT_PAGE) as usize
    }

    /// Look up the payload block mapping from in-memory state.
    ///
    /// Synchronous — no I/O. Reads from the in-memory `BatState`.
    pub fn get_block_mapping_from_state(
        &self,
        bat_state: &BatState,
        block_number: u32,
    ) -> BlockMapping {
        let internal = bat_state.get_payload_mapping(block_number);
        let mut mapping = internal.to_block_mapping();
        // Apply the same validation/normalization as parse_payload_entry:
        // For non-differencing disks, PartiallyPresent → FullyPresent.
        if !self.has_parent && mapping.state == BatEntryState::PartiallyPresent {
            mapping.state = BatEntryState::FullyPresent;
        }
        mapping
    }

    /// Look up the sector bitmap block mapping from in-memory state.
    ///
    /// Synchronous — no I/O. Reads from the in-memory `BatState`.
    pub fn get_sbm_mapping_from_state(
        &self,
        bat_state: &BatState,
        chunk_number: u32,
    ) -> BlockMapping {
        let internal = bat_state.get_sbm_mapping(chunk_number);
        let mut mapping = internal.to_block_mapping();
        // SBM entries: PartiallyPresent → FullyPresent (compatibility).
        if mapping.state == BatEntryState::PartiallyPresent {
            mapping.state = BatEntryState::FullyPresent;
        }
        mapping
    }

    /// Convert a virtual disk byte offset to a block number.
    pub fn offset_to_block(&self, offset: u64) -> u32 {
        (offset / self.block_size as u64) as u32
    }

    /// Compute the byte offset within a block for a given virtual disk offset.
    pub fn offset_within_block(&self, offset: u64) -> u32 {
        (offset % self.block_size as u64) as u32
    }

    /// Parse and validate a payload BAT entry.
    fn parse_payload_entry(&self, entry: BatEntry) -> Result<BlockMapping, VhdxError> {
        let raw_state = entry.state();
        let state = BatEntryState::from_raw(raw_state)
            .ok_or(VhdxError::Corrupt(CorruptionType::InvalidBlockState))?;
        let file_offset = entry.file_offset();

        match state {
            BatEntryState::FullyPresent => {
                if file_offset == 0 {
                    return Err(VhdxError::Corrupt(CorruptionType::InvalidBlockState));
                }
                Ok(BlockMapping {
                    state: BatEntryState::FullyPresent,
                    file_offset,
                })
            }
            BatEntryState::PartiallyPresent => {
                if file_offset == 0 {
                    return Err(VhdxError::Corrupt(CorruptionType::InvalidBlockState));
                }
                // For disks without a parent, treat PartiallyPresent as
                // FullyPresent (compatibility quirk from the C implementation).
                let effective_state = if self.has_parent {
                    BatEntryState::PartiallyPresent
                } else {
                    BatEntryState::FullyPresent
                };
                Ok(BlockMapping {
                    state: effective_state,
                    file_offset,
                })
            }
            BatEntryState::NotPresent => {
                // For differencing disks with has_parent, file_offset must be
                // zero (transparent to parent). For non-parent disks this is
                // "undefined" (zero-filled).
                if self.has_parent && file_offset != 0 {
                    return Err(VhdxError::Corrupt(CorruptionType::InvalidBlockState));
                }
                Ok(BlockMapping {
                    state: BatEntryState::NotPresent,
                    file_offset: 0,
                })
            }
            BatEntryState::Zero => {
                if file_offset != 0 {
                    return Err(VhdxError::Corrupt(CorruptionType::InvalidBlockState));
                }
                Ok(BlockMapping {
                    state: BatEntryState::Zero,
                    file_offset: 0,
                })
            }
            BatEntryState::Unmapped => {
                // Trimmed block — may have non-zero file_offset (soft anchor).
                Ok(BlockMapping {
                    state: BatEntryState::Unmapped,
                    file_offset,
                })
            }
            BatEntryState::Undefined => {
                // Undefined block — may have non-zero file_offset (soft anchor).
                Ok(BlockMapping {
                    state: BatEntryState::Undefined,
                    file_offset,
                })
            }
        }
    }

    /// Write a raw BAT entry to the cache at the given entry index.
    ///
    /// Acquires the page in Modify mode, writes the entry at the correct
    /// offset, and releases the guard (write-through to disk).
    pub async fn write_bat_entry<F: AsyncFile>(
        &self,
        cache: &PageCache<F>,
        entry_index: u32,
        entry: BatEntry,
    ) -> Result<(), VhdxError> {
        let page_offset = (entry_index as u64 / ENTRIES_PER_BAT_PAGE) * CACHE_PAGE_SIZE;
        let entry_within_page = entry_index as usize % ENTRIES_PER_BAT_PAGE as usize;

        let mut guard = cache
            .acquire(
                PageKey {
                    tag: BAT_TAG,
                    offset: page_offset,
                },
                AccessMode::Modify,
            )
            .await?;

        let byte_offset = entry_within_page * size_of::<BatEntry>();
        guard[byte_offset..byte_offset + size_of::<BatEntry>()]
            .copy_from_slice(entry.as_bytes());

        guard.release().await?;
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create;
    use crate::format;
    use crate::region;
    use crate::tests::support::InMemoryFile;
    use pal_async::async_test;
    use std::sync::Arc;
    use zerocopy::IntoBytes;

    #[test]
    fn chunk_ratio_default_params() {
        // 2 MiB blocks, 512-byte sectors → chunk_ratio = 2048
        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
        assert_eq!(bat.chunk_ratio, 2048);
    }

    #[test]
    fn chunk_ratio_various_sizes() {
        // 1 MiB blocks, 512 sectors
        let bat = Bat::new(format::GB1, MB1 as u32, 512, false).unwrap();
        assert_eq!(bat.chunk_ratio, 4096);

        // 4 MiB blocks, 512 sectors
        let bat = Bat::new(format::GB1, 4 * MB1 as u32, 512, false).unwrap();
        assert_eq!(bat.chunk_ratio, 1024);

        // 32 MiB blocks, 512 sectors
        let bat = Bat::new(format::GB1, 32 * MB1 as u32, 512, false).unwrap();
        assert_eq!(bat.chunk_ratio, 128);

        // 256 MiB blocks, 512 sectors
        let bat = Bat::new(format::GB1, 256 * MB1 as u32, 512, false).unwrap();
        assert_eq!(bat.chunk_ratio, 16);

        // 2 MiB blocks, 4096 sectors: sectors_per_block = 512, chunk_ratio = 8388608 / 512 = 16384
        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 4096, false).unwrap();
        assert_eq!(bat.chunk_ratio, 16384);

        // 1 MiB blocks, 4096 sectors: sectors_per_block = 256, chunk_ratio = 8388608 / 256 = 32768
        let bat = Bat::new(format::GB1, MB1 as u32, 4096, false).unwrap();
        assert_eq!(bat.chunk_ratio, 32768);
    }

    #[test]
    fn payload_entry_index_calculations() {
        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
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
        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, true).unwrap();
        // SBM entry 0 is at position chunk_ratio.
        assert_eq!(bat.sector_bitmap_entry_index(0), bat.chunk_ratio);
        // SBM entry 1 is at position 2*chunk_ratio + 1.
        assert_eq!(bat.sector_bitmap_entry_index(1), 2 * bat.chunk_ratio + 1);
    }

    #[test]
    fn validate_bat_size_ok() {
        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
        // For 1 GiB / 2 MiB = 512 data blocks, chunk_ratio = 2048.
        // entries = 512 + 0 = 512 (no SBM entries since 512 < 2048).
        // Actually: entries = 512 + ((512-1)/2048) = 512 + 0 = 512
        // 512 * 8 = 4096 bytes. Round up to 1 MiB.
        // Any bat_length >= 4096 is fine.
        bat.validate_bat_size(MB1 as u32).unwrap();
    }

    #[test]
    fn validate_bat_size_too_small() {
        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
        // 512 entries * 8 bytes = 4096 bytes needed.
        let result = bat.validate_bat_size(4095);
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::BatTooSmall))
        ));
    }

    #[test]
    fn offset_to_block_calculations() {
        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
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
        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
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
    fn parse_payload_zero_must_have_zero_offset() {
        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
        let entry = BatEntry::new().with_state(2).with_file_offset_mb(1);
        let result = bat.parse_payload_entry(entry);
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::InvalidBlockState))
        ));
    }

    #[test]
    fn parse_payload_fully_present_zero_offset_is_corrupt() {
        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
        let entry = BatEntry::new().with_state(6).with_file_offset_mb(0);
        let result = bat.parse_payload_entry(entry);
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::InvalidBlockState))
        ));
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
        let bm = mapping.to_block_mapping();
        assert_eq!(bm.file_offset, max_mb as u64 * MB1);
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
        let internal = InternalBlockMapping::from_bat_entry(entry);
        assert_eq!(internal.state(), BatEntryState::FullyPresent as u8);
        assert_eq!(internal.file_megabyte(), 100);
        assert!(!internal.transitioning_to_fully_present());
    }

    #[test]
    fn entry_number_to_block_id_payload() {
        // Non-differencing: all entries are payload.
        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
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
        let bat = Bat::new(
            format::GB1,
            256 * MB1 as u32,
            512,
            true,
        )
        .unwrap();
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
        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
        // Entry beyond all data blocks should return None.
        let beyond = bat.payload_entry_index(bat.data_block_count);
        assert_eq!(bat.entry_number_to_block_id(beyond), None);
    }

    #[test]
    fn bat_state_allocated_count_tracking() {
        let bat = Bat::new(4 * MB1, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
        // 2 blocks
        let mut state = BatState {
            payload_mappings: vec![InternalBlockMapping::new(); bat.data_block_count as usize],
            sector_bitmap_mappings: vec![],
            allocated_block_count: 0,
            dirty_bat_pages: vec![false; bat.total_bat_pages()],
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
        let dealloc = InternalBlockMapping::new()
            .with_state(BatEntryState::NotPresent as u8);
        state.set_payload_mapping(&bat, 0, dealloc);
        assert_eq!(state.allocated_block_count, 1);
    }

    #[test]
    fn bat_state_dirty_tracking() {
        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
        let mut state = BatState {
            payload_mappings: vec![InternalBlockMapping::new(); bat.data_block_count as usize],
            sector_bitmap_mappings: vec![],
            allocated_block_count: 0,
            dirty_bat_pages: vec![false; bat.total_bat_pages()],
        };

        // No pages dirty initially.
        assert_eq!(state.dirty_page_indices().count(), 0);

        // Mark block 0's BAT page dirty.
        state.mark_bat_page_dirty(&bat, BlockType::Payload, 0);
        let dirty: Vec<_> = state.dirty_page_indices().collect();
        assert_eq!(dirty, vec![0]);

        // Clear it.
        state.clear_dirty(0);
        assert_eq!(state.dirty_page_indices().count(), 0);
    }
}
