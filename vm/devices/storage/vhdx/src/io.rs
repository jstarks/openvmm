// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Read I/O range resolution for VHDX files.
//!
//! Given a guest virtual disk offset and length, [`VhdxFile::resolve_read`]
//! walks the request block-by-block, looks up each block's state in the BAT,
//! and emits [`ReadRange`] entries describing where to find the data.

use crate::AsyncFile;
use crate::error::CorruptionType;
use crate::error::VhdxError;
use crate::format::BatEntryState;
use crate::open::VhdxFile;
use crate::sector_bitmap;

/// Resolved range from a read operation.
///
/// Each range describes a contiguous portion of the read request and its
/// data source. The caller iterates these ranges to perform the actual I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadRange {
    /// Data present at this file offset. Caller should read from the VHDX file.
    Data {
        /// Byte offset within the virtual disk.
        guest_offset: u64,
        /// Length in bytes.
        length: u32,
        /// Byte offset within the VHDX file where the data lives.
        file_offset: u64,
    },
    /// Range is zero-filled. Caller should return zeros.
    Zero {
        /// Byte offset within the virtual disk.
        guest_offset: u64,
        /// Length in bytes.
        length: u32,
    },
    /// Range is unmapped (transparent to parent). Caller should read from
    /// the parent disk in a differencing chain.
    Unmapped {
        /// Byte offset within the virtual disk.
        guest_offset: u64,
        /// Length in bytes.
        length: u32,
    },
}

impl<F: AsyncFile> VhdxFile<F> {
    /// Resolve a read request into file-level ranges.
    ///
    /// Walks the read request block-by-block, looking up each block's state
    /// in the BAT and appending one or more [`ReadRange`] entries to `ranges`.
    /// The caller performs actual file I/O based on the returned ranges.
    ///
    /// # Errors
    ///
    /// Returns an error if the read extends beyond the virtual disk size,
    /// if the offset or length is not aligned to the logical sector size,
    /// or if a BAT entry is corrupt.
    pub async fn resolve_read(
        &self,
        offset: u64,
        len: u32,
        ranges: &mut Vec<ReadRange>,
    ) -> Result<(), VhdxError> {
        // Zero-length reads succeed immediately.
        if len == 0 {
            return Ok(());
        }

        // Validate alignment to logical sector size.
        if !offset.is_multiple_of(self.logical_sector_size as u64)
            || !(len as u64).is_multiple_of(self.logical_sector_size as u64)
        {
            return Err(VhdxError::Corrupt(CorruptionType::UnalignedIo));
        }

        // Validate bounds.
        if offset
            .checked_add(len as u64)
            .is_none_or(|end| end > self.disk_size)
        {
            return Err(VhdxError::Corrupt(CorruptionType::ReadBeyondEndOfDisk));
        }

        let mut current_offset: u32 = 0;

        while current_offset < len {
            let virtual_offset = offset + current_offset as u64;
            let block_number = self.bat.offset_to_block(virtual_offset);
            let block_offset = self.bat.offset_within_block(virtual_offset);
            let block_length = std::cmp::min(
                self.block_size - block_offset,
                len - current_offset,
            );

            let mapping = self.get_block_mapping(block_number).await?;

            match mapping.state {
                BatEntryState::FullyPresent => {
                    let file_offset = mapping.file_offset + block_offset as u64;
                    ranges.push(ReadRange::Data {
                        guest_offset: virtual_offset,
                        length: block_length,
                        file_offset,
                    });
                }
                BatEntryState::PartiallyPresent => {
                    sector_bitmap::resolve_partial_block_read(
                        &self.cache,
                        &self.bat,
                        mapping.file_offset,
                        self.block_size,
                        self.logical_sector_size,
                        virtual_offset,
                        block_length,
                        ranges,
                    )
                    .await?;
                }
                BatEntryState::NotPresent => {
                    if self.has_parent {
                        ranges.push(ReadRange::Unmapped {
                            guest_offset: virtual_offset,
                            length: block_length,
                        });
                    } else {
                        ranges.push(ReadRange::Zero {
                            guest_offset: virtual_offset,
                            length: block_length,
                        });
                    }
                }
                BatEntryState::Zero
                | BatEntryState::Unmapped
                | BatEntryState::Undefined => {
                    ranges.push(ReadRange::Zero {
                        guest_offset: virtual_offset,
                        length: block_length,
                    });
                }
            }

            current_offset += block_length;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{self, CreateParams};
    use crate::format;
    use crate::format::BatEntry;
    use crate::open::VhdxFile;
    use crate::region;
    use crate::tests::support::InMemoryFile;
    use pal_async::async_test;
    use zerocopy::IntoBytes;

    #[async_test]
    async fn read_empty_disk_returns_zero() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: 0,
                length: 4096,
            }
        );
    }

    #[async_test]
    async fn read_zero_length() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        vhdx.resolve_read(0, 0, &mut ranges).await.unwrap();

        assert!(ranges.is_empty());
    }

    #[async_test]
    async fn read_beyond_end_of_disk() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        // Read 512 bytes past the end (both offset and length are sector-aligned).
        let result = vhdx
            .resolve_read(format::GB1 - 512, 1024, &mut ranges)
            .await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::ReadBeyondEndOfDisk))
        ));
    }

    #[async_test]
    async fn read_at_disk_end_exact() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        vhdx.resolve_read(format::GB1 - 4096, 4096, &mut ranges)
            .await
            .unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: format::GB1 - 4096,
                length: 4096,
            }
        );
    }

    #[async_test]
    async fn read_fully_present_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();
        let bat_offset = regions.bat_offset;

        // Write a FullyPresent BAT entry for block 0 at file_offset_mb = 100.
        let entry = BatEntry::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_offset_mb(100);
        file.write_at(bat_offset, entry.as_bytes()).await.unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let mut ranges = Vec::new();
        vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Data {
                guest_offset: 0,
                length: 4096,
                file_offset: 100 * format::MB1,
            }
        );
    }

    #[async_test]
    async fn read_spanning_two_blocks() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let block_size = vhdx.block_size() as u64;
        let mut ranges = Vec::new();
        // Read last 512 bytes of block 0 and first 512 bytes of block 1.
        vhdx.resolve_read((block_size - 512) as u64, 1024, &mut ranges)
            .await
            .unwrap();

        assert_eq!(ranges.len(), 2);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: block_size - 512,
                length: 512,
            }
        );
        assert_eq!(
            ranges[1],
            ReadRange::Zero {
                guest_offset: block_size,
                length: 512,
            }
        );
    }

    #[async_test]
    async fn read_spanning_multiple_blocks() {
        // Use a small disk with 1 MiB blocks so spans are easier to test.
        let file = InMemoryFile::new(0);
        let block_size = format::MB1 as u32;
        let mut params = CreateParams {
            disk_size: 4 * format::MB1,
            block_size,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        // Read across blocks 0, 1, 2: start at 512 KiB, length = 2 MiB.
        // Block 0: 512 KiB remaining. Block 1: full 1 MiB. Block 2: 512 KiB.
        let start = format::MB1 / 2; // middle of block 0
        let len = (2 * format::MB1) as u32; // spans 3 blocks
        vhdx.resolve_read(start, len, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 3);
        // Block 0: remaining half
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: start,
                length: (format::MB1 / 2) as u32,
            }
        );
        // Block 1: full block
        assert_eq!(
            ranges[1],
            ReadRange::Zero {
                guest_offset: format::MB1,
                length: block_size,
            }
        );
        // Block 2: first half
        assert_eq!(
            ranges[2],
            ReadRange::Zero {
                guest_offset: 2 * format::MB1,
                length: (format::MB1 / 2) as u32,
            }
        );
    }

    #[async_test]
    async fn read_unaligned_within_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        // Set block 0 to FullyPresent at file_offset_mb = 50.
        let entry = BatEntry::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_offset_mb(50);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let mut ranges = Vec::new();
        // Read 512 bytes starting at sector 10 (offset 5120).
        vhdx.resolve_read(5120, 512, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Data {
                guest_offset: 5120,
                length: 512,
                file_offset: 50 * format::MB1 + 5120,
            }
        );
    }

    #[async_test]
    async fn read_differencing_not_present() {
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            has_parent: true,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Unmapped {
                guest_offset: 0,
                length: 4096,
            }
        );
    }

    #[async_test]
    async fn read_zero_state_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        // Set block 0 to Zero state.
        let entry = BatEntry::new()
            .with_state(BatEntryState::Zero as u8)
            .with_file_offset_mb(0);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let mut ranges = Vec::new();
        vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: 0,
                length: 4096,
            }
        );
    }

    #[async_test]
    async fn read_unmapped_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        // Set block 0 to Unmapped (trimmed) state.
        let entry = BatEntry::new()
            .with_state(BatEntryState::Unmapped as u8)
            .with_file_offset_mb(0);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let mut ranges = Vec::new();
        vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: 0,
                length: 4096,
            }
        );
    }

    #[async_test]
    async fn read_undefined_state_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        // Set block 0 to Undefined state (value 1).
        let entry = BatEntry::new()
            .with_state(BatEntryState::Undefined as u8)
            .with_file_offset_mb(0);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let mut ranges = Vec::new();
        vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: 0,
                length: 4096,
            }
        );
    }

    #[async_test]
    async fn read_entire_disk() {
        // Small disk: 4 MiB with 2 MiB blocks = 2 blocks.
        let disk_size = 4 * format::MB1;
        let (file, _) = InMemoryFile::create_test_vhdx(disk_size).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        vhdx.resolve_read(0, disk_size as u32, &mut ranges)
            .await
            .unwrap();

        // 2 blocks, each produces one Zero range.
        assert_eq!(ranges.len(), 2);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: 0,
                length: format::DEFAULT_BLOCK_SIZE,
            }
        );
        assert_eq!(
            ranges[1],
            ReadRange::Zero {
                guest_offset: format::DEFAULT_BLOCK_SIZE as u64,
                length: format::DEFAULT_BLOCK_SIZE,
            }
        );
    }

    #[async_test]
    async fn read_4k_sector_disk() {
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            logical_sector_size: 4096,
            physical_sector_size: 4096,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        // Read one 4K sector.
        vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: 0,
                length: 4096,
            }
        );

        // Unaligned read should fail.
        let mut ranges2 = Vec::new();
        let result = vhdx.resolve_read(512, 4096, &mut ranges2).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::UnalignedIo))
        ));
    }
}
