// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BAT (Block Allocation Table) lookup and management.
//!
//! Provides on-demand BAT entry lookup through the [`PageCache`], computing
//! the correct BAT page offset for any given block number. Handles the
//! interleaving of payload block entries with sector bitmap entries.

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
use zerocopy::FromBytes;
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

    /// Look up the mapping for a data block, reading from the cache.
    pub async fn get_block_mapping<F: AsyncFile>(
        &self,
        cache: &PageCache<F>,
        block_number: u32,
    ) -> Result<BlockMapping, VhdxError> {
        let entry_index = self.payload_entry_index(block_number);
        let raw = self.read_bat_entry(cache, entry_index).await?;
        self.parse_payload_entry(raw)
    }

    /// Look up the mapping for a sector bitmap block, reading from the cache.
    pub async fn get_sector_bitmap_mapping<F: AsyncFile>(
        &self,
        cache: &PageCache<F>,
        chunk_number: u32,
    ) -> Result<BlockMapping, VhdxError> {
        let entry_index = self.sector_bitmap_entry_index(chunk_number);
        let raw = self.read_bat_entry(cache, entry_index).await?;
        self.parse_sector_bitmap_entry(raw)
    }

    /// Convert a virtual disk byte offset to a block number.
    pub fn offset_to_block(&self, offset: u64) -> u32 {
        (offset / self.block_size as u64) as u32
    }

    /// Compute the byte offset within a block for a given virtual disk offset.
    pub fn offset_within_block(&self, offset: u64) -> u32 {
        (offset % self.block_size as u64) as u32
    }

    /// Read a raw BAT entry from the cache at the given entry index.
    async fn read_bat_entry<F: AsyncFile>(
        &self,
        cache: &PageCache<F>,
        entry_index: u32,
    ) -> Result<BatEntry, VhdxError> {
        let page_offset = (entry_index as u64 / ENTRIES_PER_BAT_PAGE) * CACHE_PAGE_SIZE;
        let entry_within_page = entry_index as usize % ENTRIES_PER_BAT_PAGE as usize;

        let guard = cache
            .acquire(
                PageKey {
                    tag: BAT_TAG,
                    offset: page_offset,
                },
                AccessMode::Read,
            )
            .await?;

        let byte_offset = entry_within_page * size_of::<BatEntry>();
        let entry_bytes = &guard[byte_offset..byte_offset + size_of::<BatEntry>()];
        let entry = BatEntry::read_from_bytes(entry_bytes)
            .map_err(|_| VhdxError::Corrupt(CorruptionType::InvalidBlockState))?;

        guard.release().await?;
        Ok(entry)
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

    /// Parse and validate a sector bitmap BAT entry.
    fn parse_sector_bitmap_entry(&self, entry: BatEntry) -> Result<BlockMapping, VhdxError> {
        let raw_state = entry.state();
        let state = BatEntryState::from_raw(raw_state)
            .ok_or(VhdxError::Corrupt(CorruptionType::InvalidBlockState))?;
        let file_offset = entry.file_offset();

        match state {
            BatEntryState::FullyPresent | BatEntryState::PartiallyPresent => {
                // PartiallyPresent treated as FullyPresent for SBM entries
                // (compatibility quirk).
                if file_offset == 0 {
                    return Err(VhdxError::Corrupt(CorruptionType::InvalidBlockState));
                }
                Ok(BlockMapping {
                    state: BatEntryState::FullyPresent,
                    file_offset,
                })
            }
            BatEntryState::NotPresent => Ok(BlockMapping {
                state: BatEntryState::NotPresent,
                file_offset: 0,
            }),
            _ => Err(VhdxError::Corrupt(CorruptionType::InvalidBlockState)),
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

    /// Update the BAT entry for a data block with the given state and file offset.
    ///
    /// Constructs a `BatEntry` and writes it through the cache.
    pub async fn set_block_mapping<F: AsyncFile>(
        &self,
        cache: &PageCache<F>,
        block_number: u32,
        state: BatEntryState,
        file_offset: u64,
    ) -> Result<(), VhdxError> {
        let file_offset_mb = file_offset / MB1;

        // Validate: FullyPresent and PartiallyPresent require non-zero offset.
        match state {
            BatEntryState::FullyPresent | BatEntryState::PartiallyPresent => {
                debug_assert!(file_offset_mb > 0, "present block must have non-zero offset");
            }
            BatEntryState::Zero | BatEntryState::NotPresent => {
                debug_assert_eq!(file_offset_mb, 0, "zero/not-present block must have zero offset");
            }
            _ => {}
        }

        let entry = BatEntry::new()
            .with_state(state as u8)
            .with_file_offset_mb(file_offset_mb);

        let entry_index = self.payload_entry_index(block_number);
        self.write_bat_entry(cache, entry_index, entry).await
    }
}

/// Allocate a new block by extending the file to the next MB-aligned boundary.
///
/// Returns the file offset of the newly allocated block.
pub(crate) async fn allocate_block_eof<F: AsyncFile>(
    file: &F,
    block_size: u32,
) -> Result<u64, VhdxError> {
    let current_size = file.file_size().await.map_err(VhdxError::Io)?;
    // Round up to next MB boundary.
    let aligned_offset = (current_size + MB1 - 1) & !(MB1 - 1);
    let new_size = aligned_offset + block_size as u64;
    file.set_file_size(new_size).await.map_err(VhdxError::Io)?;
    Ok(aligned_offset)
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
        let bat = Bat::new(format::GB1, format::MB1 as u32, 512, false).unwrap();
        assert_eq!(bat.chunk_ratio, 4096);

        // 4 MiB blocks, 512 sectors
        let bat = Bat::new(format::GB1, 4 * format::MB1 as u32, 512, false).unwrap();
        assert_eq!(bat.chunk_ratio, 1024);

        // 32 MiB blocks, 512 sectors
        let bat = Bat::new(format::GB1, 32 * format::MB1 as u32, 512, false).unwrap();
        assert_eq!(bat.chunk_ratio, 128);

        // 256 MiB blocks, 512 sectors
        let bat = Bat::new(format::GB1, 256 * format::MB1 as u32, 512, false).unwrap();
        assert_eq!(bat.chunk_ratio, 16);

        // 2 MiB blocks, 4096 sectors: sectors_per_block = 512, chunk_ratio = 8388608 / 512 = 16384
        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 4096, false).unwrap();
        assert_eq!(bat.chunk_ratio, 16384);

        // 1 MiB blocks, 4096 sectors: sectors_per_block = 256, chunk_ratio = 8388608 / 256 = 32768
        let bat = Bat::new(format::GB1, format::MB1 as u32, 4096, false).unwrap();
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
        bat.validate_bat_size(format::MB1 as u32).unwrap();
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

    #[async_test]
    async fn get_block_mapping_default() {
        // Create a VHDX, set up cache, look up block 0 → should be NotPresent.
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(BAT_TAG, regions.bat_offset);

        let mapping = bat.get_block_mapping(&cache, 0).await.unwrap();
        assert_eq!(mapping.state, BatEntryState::NotPresent);
        assert_eq!(mapping.file_offset, 0);
    }

    #[async_test]
    async fn get_block_mapping_fully_present() {
        // Create a VHDX, manually write a FullyPresent BAT entry, look it up.
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        // Write a FullyPresent entry for block 0 at the BAT region start.
        let entry = BatEntry::new().with_state(6).with_file_offset_mb(100);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        let bat = Bat::new(format::GB1, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(BAT_TAG, regions.bat_offset);

        let mapping = bat.get_block_mapping(&cache, 0).await.unwrap();
        assert_eq!(mapping.state, BatEntryState::FullyPresent);
        assert_eq!(mapping.file_offset, 100 * format::MB1);
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

    #[async_test]
    async fn get_block_mapping_all_blocks_default() {
        // Create a VHDX, verify all blocks are NotPresent.
        let disk_size = 4 * format::MB1; // small disk: 2 blocks with 2 MiB block size
        let file = InMemoryFile::new(0);
        let mut params = create::CreateParams {
            disk_size,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();

        let regions = region::parse_region_tables(&file).await.unwrap();
        let bat = Bat::new(disk_size, format::DEFAULT_BLOCK_SIZE, 512, false).unwrap();
        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(BAT_TAG, regions.bat_offset);

        for block in 0..bat.data_block_count {
            let mapping = bat.get_block_mapping(&cache, block).await.unwrap();
            assert_eq!(mapping.state, BatEntryState::NotPresent);
            assert_eq!(mapping.file_offset, 0);
        }
    }
}
