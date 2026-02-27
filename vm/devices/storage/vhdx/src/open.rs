// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VHDX file open orchestration.
//!
//! Ties together header, region, metadata, and BAT parsing into a single
//! [`VhdxFile::open()`] entry point. Produces an open file handle with
//! accessor methods for disk geometry and state.

use crate::AsyncFile;
use crate::bat::BAT_TAG;
use crate::bat::Bat;
use crate::bat::BlockMapping;
use crate::bat::METADATA_TAG;
use crate::cache::PageCache;
use crate::error::CorruptionType;
use crate::error::VhdxError;
use crate::format;
use crate::format::FileIdentifier;
use crate::header::parse_headers;
use crate::known_meta::read_known_metadata;
use crate::known_meta::verify_known_metadata;
use crate::metadata::MetadataTable;
use crate::region::parse_region_tables;
use guid::Guid;
use zerocopy::FromBytes;

/// An open VHDX file handle.
///
/// Created via [`VhdxFile::open()`], this provides read access to the
/// virtual disk's metadata and BAT (block allocation table).
pub struct VhdxFile<F: AsyncFile> {
    cache: PageCache<F>,
    bat: Bat,

    // Parsed metadata
    disk_size: u64,
    block_size: u32,
    logical_sector_size: u32,
    physical_sector_size: u32,
    has_parent: bool,
    is_fully_allocated: bool,
    #[allow(dead_code)] // Phase 7+: used for disk_backend integration
    page_83_data: Guid,

    // Header state
    #[allow(dead_code)] // Phase 7+: used for header updates on write
    sequence_number: u64,
    #[allow(dead_code)] // Phase 7+: used for header updates on write
    file_write_guid: Guid,
    data_write_guid: Guid,
    #[allow(dead_code)] // Phase 7+: used for header updates on write
    first_header_current: bool,

    // Region offsets (for future use)
    #[allow(dead_code)] // Phase 9+: used for space management
    bat_offset: u64,
    #[allow(dead_code)] // Phase 9+: used for space management
    bat_length: u32,
    #[allow(dead_code)] // Phase 9+: used for metadata writes
    metadata_offset: u64,
    #[allow(dead_code)] // Phase 9+: used for metadata writes
    metadata_length: u32,
    #[allow(dead_code)] // Phase 12: used for log replay
    log_offset: u64,
    #[allow(dead_code)] // Phase 12: used for log replay
    log_length: u32,

    // Mode
    read_only: bool,

    // Error state: once set, all operations fail.
    #[allow(dead_code)] // Phase 7+: used for error propagation on I/O path
    failed: Option<VhdxError>,
}

impl<F: AsyncFile> VhdxFile<F> {
    /// Open an existing VHDX file.
    ///
    /// Validates the file identifier, headers, region tables, and metadata.
    /// If the log GUID is non-zero (indicating a dirty log), returns
    /// [`CorruptionType::LogReplayRequired`] since log replay is not yet
    /// implemented.
    pub async fn open(file: F, read_only: bool) -> Result<Self, VhdxError> {
        // 1. Validate minimum file size.
        let file_length = file.file_size().await.map_err(VhdxError::Io)?;
        if file_length < format::HEADER_AREA_SIZE {
            return Err(VhdxError::Corrupt(CorruptionType::EmptyFile));
        }

        // 2. Validate the file identifier signature.
        validate_file_identifier(&file).await?;

        // 3. Parse dual headers.
        let header = parse_headers(&file, file_length).await?;

        // 4. Check for dirty log — reject if log replay is needed.
        if header.log_guid != Guid::ZERO {
            return Err(VhdxError::Corrupt(CorruptionType::LogReplayRequired));
        }

        // 5. Parse region tables.
        let regions = parse_region_tables(&file).await?;

        // 6. Read metadata table.
        let metadata_table =
            MetadataTable::read(&file, regions.metadata_offset, regions.metadata_length).await?;

        // 7. Verify known metadata (all required system items are recognized).
        verify_known_metadata(&metadata_table, false)?;

        // 8. Read known metadata values.
        let known = read_known_metadata(&file, &metadata_table, regions.metadata_offset).await?;

        // 9. Create BAT manager.
        let bat = Bat::new(
            known.disk_size,
            known.block_size,
            known.logical_sector_size,
            known.has_parent,
        )?;

        // 10. Validate BAT region size.
        bat.validate_bat_size(regions.bat_length)?;

        // 11. Create PageCache and register tags.
        let mut cache = PageCache::new(file);
        cache.register_tag(BAT_TAG, regions.bat_offset);
        cache.register_tag(METADATA_TAG, regions.metadata_offset);

        // 12. Construct VhdxFile.
        Ok(VhdxFile {
            cache,
            bat,
            disk_size: known.disk_size,
            block_size: known.block_size,
            logical_sector_size: known.logical_sector_size,
            physical_sector_size: known.physical_sector_size,
            has_parent: known.has_parent,
            is_fully_allocated: known.leave_blocks_allocated,
            page_83_data: known.page_83_data,
            sequence_number: header.sequence_number,
            file_write_guid: header.file_write_guid,
            data_write_guid: header.data_write_guid,
            first_header_current: header.first_header_current,
            bat_offset: regions.bat_offset,
            bat_length: regions.bat_length,
            metadata_offset: regions.metadata_offset,
            metadata_length: regions.metadata_length,
            log_offset: header.log_offset,
            log_length: header.log_length,
            read_only,
            failed: None,
        })
    }

    /// Virtual disk size in bytes.
    pub fn disk_size(&self) -> u64 {
        self.disk_size
    }

    /// Block size in bytes.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Logical sector size (512 or 4096).
    pub fn logical_sector_size(&self) -> u32 {
        self.logical_sector_size
    }

    /// Physical sector size (512 or 4096).
    pub fn physical_sector_size(&self) -> u32 {
        self.physical_sector_size
    }

    /// Whether this is a differencing disk (has a parent).
    pub fn has_parent(&self) -> bool {
        self.has_parent
    }

    /// Whether the disk was created with all blocks pre-allocated (fixed VHD).
    pub fn is_fully_allocated(&self) -> bool {
        self.is_fully_allocated
    }

    /// GUID changed on every virtual-disk data write.
    pub fn data_write_guid(&self) -> Guid {
        self.data_write_guid
    }

    /// Whether the file was opened in read-only mode.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Look up the block mapping for a given data block number.
    pub(crate) async fn get_block_mapping(
        &self,
        block_number: u32,
    ) -> Result<BlockMapping, VhdxError> {
        self.bat.get_block_mapping(&self.cache, block_number).await
    }
}

/// Validate the file identifier signature at offset 0.
async fn validate_file_identifier(file: &impl AsyncFile) -> Result<(), VhdxError> {
    let mut buf = [0u8; size_of::<FileIdentifier>()];
    file.read_at(0, &mut buf).await?;

    let ident = FileIdentifier::read_from_bytes(&buf)
        .map_err(|_| VhdxError::Corrupt(CorruptionType::InvalidFileIdentifier))?;

    if ident.signature != format::FILE_IDENTIFIER_SIGNATURE {
        return Err(VhdxError::Corrupt(CorruptionType::InvalidFileIdentifier));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{self, CreateParams};
    use crate::format::BatEntryState;
    use crate::format::Header;
    use crate::tests::support::InMemoryFile;
    use pal_async::async_test;
    use zerocopy::IntoBytes;

    #[async_test]
    async fn open_default_vhdx() {
        let (file, params) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        assert_eq!(vhdx.disk_size(), format::GB1);
        assert_eq!(vhdx.block_size(), format::DEFAULT_BLOCK_SIZE);
        assert_eq!(vhdx.logical_sector_size(), 512);
        assert_eq!(vhdx.physical_sector_size(), 512);
        assert!(!vhdx.has_parent());
        assert!(!vhdx.is_fully_allocated());
        assert!(!vhdx.is_read_only());
        assert_ne!(vhdx.data_write_guid(), Guid::ZERO);
        assert_eq!(vhdx.data_write_guid(), params.data_write_guid);
    }

    #[async_test]
    async fn open_4k_sector_vhdx() {
        let file = InMemoryFile::new(0);
        let params = CreateParams {
            disk_size: format::GB1,
            logical_sector_size: 4096,
            physical_sector_size: 4096,
            ..Default::default()
        };
        create::create(&file, params).await.unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        assert_eq!(vhdx.logical_sector_size(), 4096);
        assert_eq!(vhdx.physical_sector_size(), 4096);
    }

    #[async_test]
    async fn open_512_sector_vhdx() {
        let file = InMemoryFile::new(0);
        let params = CreateParams {
            disk_size: format::GB1,
            logical_sector_size: 512,
            physical_sector_size: 512,
            ..Default::default()
        };
        create::create(&file, params).await.unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        assert_eq!(vhdx.logical_sector_size(), 512);
        assert_eq!(vhdx.physical_sector_size(), 512);
    }

    #[async_test]
    async fn open_various_block_sizes() {
        for &block_size in &[
            format::MB1 as u32,
            2 * format::MB1 as u32,
            32 * format::MB1 as u32,
            256 * format::MB1 as u32,
        ] {
            let file = InMemoryFile::new(0);
            let params = CreateParams {
                disk_size: format::GB1,
                block_size,
                ..Default::default()
            };
            create::create(&file, params).await.unwrap();

            let vhdx = VhdxFile::open(file, false).await.unwrap();
            assert_eq!(vhdx.block_size(), block_size);
        }
    }

    #[async_test]
    async fn open_differencing_disk() {
        let file = InMemoryFile::new(0);
        let params = CreateParams {
            disk_size: format::GB1,
            has_parent: true,
            ..Default::default()
        };
        create::create(&file, params).await.unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        assert!(vhdx.has_parent());
    }

    #[async_test]
    async fn open_fully_allocated() {
        let file = InMemoryFile::new(0);
        let params = CreateParams {
            disk_size: format::GB1,
            is_fully_allocated: true,
            ..Default::default()
        };
        create::create(&file, params).await.unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        assert!(vhdx.is_fully_allocated());
    }

    #[async_test]
    async fn open_dirty_log_rejected() {
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;

        // Overwrite header 2's log_guid with a non-zero GUID, then fix the CRC.
        let mut buf = vec![0u8; format::HEADER_SIZE as usize];
        file.read_at(format::HEADER_OFFSET_2, &mut buf)
            .await
            .unwrap();

        let mut header = Header::read_from_prefix(&buf).unwrap().0.clone();
        header.log_guid = Guid::new_random();
        header.checksum = 0;

        let header_bytes = header.as_bytes();
        buf[..header_bytes.len()].copy_from_slice(header_bytes);
        let crc = format::compute_checksum(&buf, 4);
        buf[4..8].copy_from_slice(&crc.to_le_bytes());
        file.write_at(format::HEADER_OFFSET_2, &buf).await.unwrap();

        let result = VhdxFile::open(file, false).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::LogReplayRequired))
        ));
    }

    #[async_test]
    async fn open_invalid_file_identifier() {
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;

        // Corrupt the file identifier signature.
        file.write_at(0, b"BADMAGIC").await.unwrap();

        let result = VhdxFile::open(file, false).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::InvalidFileIdentifier))
        ));
    }

    #[async_test]
    async fn open_empty_file() {
        // File smaller than HEADER_AREA_SIZE (1 MiB).
        let file = InMemoryFile::new(512);
        let result = VhdxFile::open(file, false).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::EmptyFile))
        ));
    }

    #[async_test]
    async fn open_bat_block_lookup() {
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        // A newly created dynamic disk has all blocks as NotPresent.
        let mapping = vhdx.get_block_mapping(0).await.unwrap();
        assert_eq!(mapping.state, BatEntryState::NotPresent);
        assert_eq!(mapping.file_offset, 0);
    }

    #[async_test]
    async fn open_bat_all_blocks_default() {
        let disk_size = 4 * format::MB1; // Small disk → 2 blocks.
        let file = InMemoryFile::new(0);
        let params = CreateParams {
            disk_size,
            ..Default::default()
        };
        create::create(&file, params).await.unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let block_count = (disk_size / vhdx.block_size() as u64) as u32;

        for block in 0..block_count {
            let mapping = vhdx.get_block_mapping(block).await.unwrap();
            assert_eq!(mapping.state, BatEntryState::NotPresent);
            assert_eq!(mapping.file_offset, 0);
        }
    }

    #[async_test]
    async fn open_read_only_flag() {
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, true).await.unwrap();
        assert!(vhdx.is_read_only());
    }
}
