// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Metadata table parsing and item reading for VHDX files.
//!
//! Reads the metadata table from the metadata region, validates entries,
//! and provides lookup and raw-read access for individual metadata items.

use crate::AsyncFile;
use crate::error::CorruptionType;
use crate::error::VhdxError;
use crate::format;
use crate::format::MetadataTableEntry;
use crate::format::MetadataTableHeader;
use guid::Guid;
use zerocopy::FromBytes;

/// In-memory representation of the validated metadata table.
pub(crate) struct MetadataTable {
    /// The validated entries (sorted by offset for free-space scanning).
    entries: Vec<MetadataTableEntry>,
    /// Total size of system metadata items.
    #[allow(dead_code)]
    pub system_metadata_size: u32,
    /// Total size of user metadata items.
    #[allow(dead_code)]
    pub user_metadata_size: u32,
    /// Number of user metadata entries.
    pub user_item_count: u16,
}

impl MetadataTable {
    /// Read and validate the metadata table from the file.
    pub async fn read(
        file: &impl AsyncFile,
        metadata_offset: u64,
        metadata_length: u32,
    ) -> Result<Self, VhdxError> {
        // Read the metadata table (first 64 KiB of the metadata region).
        let mut buf = vec![0u8; format::METADATA_TABLE_SIZE as usize];
        file.read_at(metadata_offset, &mut buf).await?;

        // Validate signature.
        let header = MetadataTableHeader::read_from_prefix(&buf)
            .map_err(|_| CorruptionType::InvalidMetadataTableSignature)?
            .0
            .clone();
        if header.signature != format::METADATA_TABLE_SIGNATURE {
            return Err(CorruptionType::InvalidMetadataTableSignature.into());
        }

        // Validate entry count.
        if header.entry_count as u64 > format::METADATA_ENTRY_MAX_COUNT {
            return Err(CorruptionType::MetadataTableEntryCountTooHigh.into());
        }

        // Validate metadata region size.
        if metadata_length as u64 > format::MAXIMUM_METADATA_REGION_SIZE {
            return Err(CorruptionType::MetadataRegionTooLarge.into());
        }

        // Parse entries.
        let header_size = size_of::<MetadataTableHeader>();
        let entry_size = size_of::<MetadataTableEntry>();
        let mut entries = Vec::with_capacity(header.entry_count as usize);
        for i in 0..header.entry_count as usize {
            let off = header_size + i * entry_size;
            let entry = MetadataTableEntry::read_from_prefix(&buf[off..])
                .unwrap()
                .0
                .clone();
            entries.push(entry);
        }

        // Sort by (is_user, item_id) for duplicate detection.
        entries.sort_by(|a, b| {
            a.flags
                .is_user()
                .cmp(&b.flags.is_user())
                .then_with(|| a.item_id.cmp(&b.item_id))
        });

        // Check for duplicates.
        for i in 1..entries.len() {
            if entries[i].flags.is_user() == entries[i - 1].flags.is_user()
                && entries[i].item_id == entries[i - 1].item_id
            {
                return Err(CorruptionType::MetadataDuplicateGuid.into());
            }
        }

        // Re-sort by offset for overlap checking.
        entries.sort_by_key(|e| e.offset);

        // Validate each entry and check for overlaps.
        let mut user_item_count: u16 = 0;
        let mut system_metadata_size: u64 = 0;
        let mut user_metadata_size: u64 = 0;
        let mut last_end: u32 = 0;

        for entry in &entries {
            // User + required is invalid.
            if entry.flags.is_user() && entry.flags.is_required() {
                return Err(CorruptionType::MetadataUserRequired.into());
            }

            // Item size limit.
            if entry.length as u64 > format::MAXIMUM_METADATA_ITEM_SIZE {
                return Err(CorruptionType::MetadataItemTooLarge.into());
            }

            // Zero GUID is invalid.
            if entry.item_id == Guid::ZERO {
                return Err(CorruptionType::ZeroMetadataItemId.into());
            }

            if entry.length == 0 {
                // Zero-length entries must have zero offset.
                if entry.offset != 0 {
                    return Err(CorruptionType::InvalidMetadataEntryOffset.into());
                }
            } else {
                // Non-zero entries: offset must be >= table size and fit in region.
                if entry.offset < format::METADATA_TABLE_SIZE as u32 {
                    return Err(CorruptionType::MetadataOverlapping.into());
                }
                if entry.offset + entry.length > metadata_length {
                    return Err(CorruptionType::MetadataOverlapping.into());
                }
                // Check overlap with previous entry.
                if entry.offset < last_end {
                    return Err(CorruptionType::MetadataOverlapping.into());
                }
                last_end = entry.offset + entry.length;
            }

            // Track sizes per category.
            if entry.flags.is_user() {
                user_item_count += 1;
                user_metadata_size += entry.length as u64;
            } else {
                system_metadata_size += entry.length as u64;
            }
        }

        // Validate user entry count.
        if user_item_count as u64 > format::METADATA_USER_ENTRY_MAX_COUNT {
            return Err(CorruptionType::MetadataUserCountExceeded.into());
        }

        // Validate total sizes per category.
        if system_metadata_size > format::MAXIMUM_TOTAL_METADATA_SIZE_PER_CATEGORY
            || user_metadata_size > format::MAXIMUM_TOTAL_METADATA_SIZE_PER_CATEGORY
        {
            return Err(CorruptionType::TotalMetadataSizeExceeded.into());
        }

        Ok(MetadataTable {
            entries,
            system_metadata_size: system_metadata_size as u32,
            user_metadata_size: user_metadata_size as u32,
            user_item_count,
        })
    }

    /// Find an entry by GUID and user/system flag.
    pub fn find_entry(&self, is_user: bool, item_id: &Guid) -> Option<&MetadataTableEntry> {
        self.entries
            .iter()
            .find(|e| e.flags.is_user() == is_user && &e.item_id == item_id)
    }

    /// Read the raw bytes of a metadata item from the file.
    pub async fn read_item(
        &self,
        file: &impl AsyncFile,
        metadata_offset: u64,
        is_user: bool,
        item_id: &Guid,
    ) -> Result<Vec<u8>, VhdxError> {
        let entry = self
            .find_entry(is_user, item_id)
            .ok_or(CorruptionType::MissingRequiredMetadata)?;

        let mut data = vec![0u8; entry.length as usize];
        file.read_at(metadata_offset + entry.offset as u64, &mut data)
            .await?;
        Ok(data)
    }

    /// Returns an iterator over all entries.
    pub fn entries(&self) -> &[MetadataTableEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::region;
    use crate::tests::support::InMemoryFile;
    use pal_async::async_test;
    use zerocopy::IntoBytes;

    #[async_test]
    async fn parse_valid_metadata_table() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        let table = MetadataTable::read(&file, regions.metadata_offset, regions.metadata_length)
            .await
            .unwrap();

        // Should have 5 system entries: file params, disk size, logical sector,
        // physical sector, page 83.
        assert_eq!(table.entries.len(), 5);
        assert_eq!(table.user_item_count, 0);
    }

    #[async_test]
    async fn find_entry_by_guid() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();
        let table = MetadataTable::read(&file, regions.metadata_offset, regions.metadata_length)
            .await
            .unwrap();

        // Known GUIDs should be found.
        assert!(
            table
                .find_entry(false, &format::FILE_PARAMETERS_ITEM_GUID)
                .is_some()
        );
        assert!(
            table
                .find_entry(false, &format::VIRTUAL_DISK_SIZE_ITEM_GUID)
                .is_some()
        );
        assert!(
            table
                .find_entry(false, &format::LOGICAL_SECTOR_SIZE_ITEM_GUID)
                .is_some()
        );
        assert!(
            table
                .find_entry(false, &format::PHYSICAL_SECTOR_SIZE_ITEM_GUID)
                .is_some()
        );
        assert!(
            table
                .find_entry(false, &format::PAGE_83_ITEM_GUID)
                .is_some()
        );

        // Unknown GUID should not be found.
        assert!(
            table
                .find_entry(false, &format::PARENT_LOCATOR_ITEM_GUID)
                .is_none()
        );
    }

    #[async_test]
    async fn read_item_bytes() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();
        let table = MetadataTable::read(&file, regions.metadata_offset, regions.metadata_length)
            .await
            .unwrap();

        // Read disk size — should be 1 GiB.
        let data = table
            .read_item(
                &file,
                regions.metadata_offset,
                false,
                &format::VIRTUAL_DISK_SIZE_ITEM_GUID,
            )
            .await
            .unwrap();
        assert_eq!(data.len(), 8);
        let disk_size = u64::from_le_bytes(data.try_into().unwrap());
        assert_eq!(disk_size, format::GB1);
    }

    #[async_test]
    async fn invalid_signature() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        // Corrupt the metadata table signature.
        let mut buf = vec![0u8; format::METADATA_TABLE_SIZE as usize];
        file.read_at(regions.metadata_offset, &mut buf)
            .await
            .unwrap();
        buf[0] ^= 0xFF;
        file.write_at(regions.metadata_offset, &buf).await.unwrap();

        let result =
            MetadataTable::read(&file, regions.metadata_offset, regions.metadata_length).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(
                CorruptionType::InvalidMetadataTableSignature
            ))
        ));
    }

    #[async_test]
    async fn duplicate_guid() {
        let file = InMemoryFile::new(4 * format::MB1);

        // Build a metadata table with two entries sharing the same GUID.
        let mut buf = vec![0u8; format::METADATA_TABLE_SIZE as usize];
        let header = MetadataTableHeader {
            signature: format::METADATA_TABLE_SIGNATURE,
            reserved: 0,
            entry_count: 2,
            reserved2: [0; 5],
        };
        let h_bytes = header.as_bytes();
        buf[..h_bytes.len()].copy_from_slice(h_bytes);

        let entry = MetadataTableEntry {
            item_id: format::FILE_PARAMETERS_ITEM_GUID,
            offset: format::METADATA_TABLE_SIZE as u32,
            length: 8,
            flags: format::MetadataTableEntryFlags::new().with_is_required(true),
            reserved2: 0,
        };
        let e_bytes = entry.as_bytes();
        let entry_start = size_of::<MetadataTableHeader>();
        buf[entry_start..entry_start + e_bytes.len()].copy_from_slice(e_bytes);

        let entry2 = MetadataTableEntry {
            item_id: format::FILE_PARAMETERS_ITEM_GUID,
            offset: format::METADATA_TABLE_SIZE as u32 + 8,
            length: 8,
            flags: format::MetadataTableEntryFlags::new().with_is_required(true),
            reserved2: 0,
        };
        let e2_bytes = entry2.as_bytes();
        let off2 = entry_start + e_bytes.len();
        buf[off2..off2 + e2_bytes.len()].copy_from_slice(e2_bytes);

        let metadata_offset = 2 * format::MB1;
        file.write_at(metadata_offset, &buf).await.unwrap();

        let result = MetadataTable::read(&file, metadata_offset, format::MB1 as u32).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::MetadataDuplicateGuid))
        ));
    }

    #[async_test]
    async fn user_required_invalid() {
        let file = InMemoryFile::new(4 * format::MB1);

        let mut buf = vec![0u8; format::METADATA_TABLE_SIZE as usize];
        let header = MetadataTableHeader {
            signature: format::METADATA_TABLE_SIGNATURE,
            reserved: 0,
            entry_count: 1,
            reserved2: [0; 5],
        };
        let h_bytes = header.as_bytes();
        buf[..h_bytes.len()].copy_from_slice(h_bytes);

        let entry = MetadataTableEntry {
            item_id: format::FILE_PARAMETERS_ITEM_GUID,
            offset: format::METADATA_TABLE_SIZE as u32,
            length: 8,
            flags: format::MetadataTableEntryFlags::new()
                .with_is_user(true)
                .with_is_required(true),
            reserved2: 0,
        };
        let e_bytes = entry.as_bytes();
        let entry_start = size_of::<MetadataTableHeader>();
        buf[entry_start..entry_start + e_bytes.len()].copy_from_slice(e_bytes);

        let metadata_offset = 2 * format::MB1;
        file.write_at(metadata_offset, &buf).await.unwrap();

        let result = MetadataTable::read(&file, metadata_offset, format::MB1 as u32).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::MetadataUserRequired))
        ));
    }
}
