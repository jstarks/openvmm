// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! On-disk format types and constants for the VHDX file format.
//!
//! All structures use `#[repr(C)]` and derive zerocopy traits for safe
//! zero-copy parsing.

#![allow(dead_code)]

use bitfield_struct::bitfield;
use guid::Guid;
use guid::guid;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

/// 4 KiB.
pub const KB4: u64 = 4096;
/// 64 KiB.
pub const KB64: u64 = 65536;
/// 1 MiB.
pub const MB1: u64 = 1024 * 1024;
/// 1 GiB.
pub const GB1: u64 = 1024 * MB1;
/// 1 TiB.
pub const TB1: u64 = MB1 * MB1;

/// Size of a log sector.
pub const LOG_SECTOR_SIZE: u64 = KB4;
/// Size of a large sector.
pub const LARGE_SECTOR_SIZE: u64 = KB64;
/// Alignment requirement for VHDX regions.
pub const REGION_ALIGNMENT: u64 = MB1;
/// Size of a sector bitmap block.
pub const SECTOR_BITMAP_BLOCK_SIZE: u64 = MB1;
/// Number of sectors described per chunk.
pub const SECTORS_PER_CHUNK: u64 = SECTOR_BITMAP_BLOCK_SIZE * 8;
/// Minimum file offset that may be covered by log replay.
pub const LOGGABLE_OFFSET: u64 = REGION_TABLE_OFFSET;

/// Total size of the header area.
pub const HEADER_AREA_SIZE: u64 = MB1;
/// On-disk size of a single header.
pub const HEADER_SIZE: u64 = KB4;
/// File offset of the first header.
pub const HEADER_OFFSET_1: u64 = LARGE_SECTOR_SIZE;
/// File offset of the second header.
pub const HEADER_OFFSET_2: u64 = LARGE_SECTOR_SIZE * 2;

/// Signature for [`Header`].
pub const HEADER_SIGNATURE: u32 = u32::from_le_bytes(*b"head");
/// Current VHDX format version.
pub const VERSION_1: u16 = 1;
/// Current log format version.
pub const LOG_VERSION: u16 = 0;

/// Size of a region table.
pub const REGION_TABLE_SIZE: u64 = LARGE_SECTOR_SIZE;
/// File offset of the primary region table.
pub const REGION_TABLE_OFFSET: u64 = LARGE_SECTOR_SIZE * 3;
/// File offset of the alternate region table.
pub const ALT_REGION_TABLE_OFFSET: u64 = LARGE_SECTOR_SIZE * 4;

/// Signature for [`RegionTableHeader`].
pub const REGION_TABLE_SIGNATURE: u32 = u32::from_le_bytes(*b"regi");

/// Maximum number of entries in a region table.
pub const REGION_TABLE_MAX_ENTRY_COUNT: u64 = (REGION_TABLE_SIZE
    - size_of::<RegionTableHeader>() as u64)
    / size_of::<RegionTableEntry>() as u64;

/// Well-known GUID identifying the BAT region.
pub const BAT_REGION_GUID: Guid = guid!("2dc27766-f623-4200-9d64-115e9bfd4a08");

/// Maximum BAT size in bytes.
pub const MAXIMUM_BAT_SIZE: u64 = 513 * MB1;
/// Maximum number of BAT entries.
pub const MAXIMUM_BAT_ENTRY_COUNT: u64 = MAXIMUM_BAT_SIZE / size_of::<BatEntry>() as u64;
/// Absolute maximum BAT entry count.
pub const ABSOLUTE_MAXIMUM_BAT_ENTRY_COUNT: u64 = 1 << 30;
/// Maximum block size.
pub const MAXIMUM_BLOCK_SIZE: u64 = 256 * MB1;
/// Maximum virtual disk size.
pub const MAXIMUM_DISK_SIZE: u64 = 64 * TB1;

/// Well-known GUID identifying the metadata region.
pub const METADATA_REGION_GUID: Guid = guid!("8b7ca206-4790-4b9a-b8fe-575f050f886e");

/// Signature for [`MetadataTableHeader`].
pub const METADATA_TABLE_SIGNATURE: u64 = u64::from_le_bytes(*b"metadata");

/// Size of the metadata table.
pub const METADATA_TABLE_SIZE: u64 = LARGE_SECTOR_SIZE;

/// Maximum number of metadata table entries.
pub const METADATA_ENTRY_MAX_COUNT: u64 = (METADATA_TABLE_SIZE
    - size_of::<MetadataTableHeader>() as u64)
    / size_of::<MetadataTableEntry>() as u64;

/// Maximum number of system metadata entries.
pub const METADATA_SYSTEM_ENTRY_MAX_COUNT: u64 = 1023;
/// Maximum number of user metadata entries.
pub const METADATA_USER_ENTRY_MAX_COUNT: u64 = 1024;

/// Maximum size of the entire metadata region.
pub const MAXIMUM_METADATA_REGION_SIZE: u64 = 128 * MB1;
/// Maximum total metadata size per category.
pub const MAXIMUM_TOTAL_METADATA_SIZE_PER_CATEGORY: u64 = 40 * MB1;
/// Maximum size of a single metadata item.
pub const MAXIMUM_METADATA_ITEM_SIZE: u64 = MB1;

/// File parameters metadata item GUID.
pub const FILE_PARAMETERS_ITEM_GUID: Guid = guid!("caa16737-fa36-4d43-b3b6-33f0aa44e76b");
/// Virtual disk size metadata item GUID.
pub const VIRTUAL_DISK_SIZE_ITEM_GUID: Guid = guid!("2fa54224-cd1b-4876-b211-5dbed83bf4b8");
/// Page 83 data metadata item GUID.
pub const PAGE_83_ITEM_GUID: Guid = guid!("beca12ab-b2e6-4523-93ef-c309e000c746");
/// CHS parameters metadata item GUID.
pub const CHS_PARAMETERS_ITEM_GUID: Guid = guid!("da02d7bc-3d3a-423c-ac88-2a36ab21479b");
/// Logical sector size metadata item GUID.
pub const LOGICAL_SECTOR_SIZE_ITEM_GUID: Guid = guid!("8141bf1d-a96f-4709-ba47-f233a8faab5f");
/// Physical sector size metadata item GUID.
pub const PHYSICAL_SECTOR_SIZE_ITEM_GUID: Guid = guid!("cda348c7-445d-4471-9cc9-e9885251c556");
/// Incomplete file metadata item GUID.
pub const INCOMPLETE_FILE_ITEM_GUID: Guid = guid!("71cc85f0-1b69-4e28-9558-c3bf83ae75d3");

/// Parent locator metadata item GUID.
pub const PARENT_LOCATOR_ITEM_GUID: Guid = guid!("a8d35f2d-b30b-454d-abf7-d3d84834ab0c");
/// Parent locator type GUID for VHDX parent references.
pub const PARENT_LOCATOR_VHDX_TYPE_GUID: Guid = guid!("b04aefb7-d19e-4a81-b789-25b8e9445913");
/// Maximum number of key-value pairs in a parent locator.
pub const PARENT_LOCATOR_MAXIMUM_KEY_VALUE_COUNT: u16 = 256;

/// PMEM label storage area metadata item GUID.
pub const PMEM_LABEL_STORAGE_AREA_ITEM_GUID: Guid = guid!("10e1ae8a-4b7e-4169-a40f-cd70de928393");
/// Version 1 of the PMEM label storage area header.
pub const PMEM_LABEL_STORAGE_AREA_VERSION_1: u16 = 1;

/// Signature for [`LogEntryHeader`].
pub const LOG_ENTRY_HEADER_SIGNATURE: u32 = u32::from_le_bytes(*b"loge");
/// Signature for a data log descriptor.
pub const LOG_DESCRIPTOR_DATA_SIGNATURE: u32 = u32::from_le_bytes(*b"desc");
/// Signature for a zero log descriptor.
pub const LOG_DESCRIPTOR_ZERO_SIGNATURE: u32 = u32::from_le_bytes(*b"zero");
/// Signature for [`LogDataSector`].
pub const LOG_DATA_SECTOR_SIGNATURE: u32 = u32::from_le_bytes(*b"data");

/// Default block size.
pub const DEFAULT_BLOCK_SIZE: u32 = 2 * MB1 as u32;
/// Default logical and physical sector size.
pub const DEFAULT_SECTOR_SIZE: u32 = 512;
/// Default metadata region size.
pub const DEFAULT_METADATA_REGION_SIZE: u32 = MB1 as u32;
/// Default log region size.
pub const DEFAULT_LOG_SIZE: u32 = MB1 as u32;
/// Cache page size.
pub const CACHE_PAGE_SIZE: u64 = KB4;
/// Number of BAT entries per cache page.
pub const ENTRIES_PER_BAT_PAGE: u64 = CACHE_PAGE_SIZE / size_of::<BatEntry>() as u64;
/// Maximum hosting sector size.
pub const MAX_HOSTING_SECTOR_SIZE: u64 = KB64;
/// Signature for [`FileIdentifier`].
pub const FILE_IDENTIFIER_SIGNATURE: u64 = u64::from_le_bytes(*b"vhdxfile");

/// VHDX file identifier.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FileIdentifier {
    /// Must be [`FILE_IDENTIFIER_SIGNATURE`].
    pub signature: u64,
    /// UTF-16LE creator string.
    pub creator: [u16; 256],
}

/// VHDX header.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct Header {
    /// Must be [`HEADER_SIGNATURE`].
    pub signature: u32,
    /// CRC-32C checksum of the 4 KiB header with this field zeroed.
    pub checksum: u32,
    /// Monotonically increasing sequence number.
    pub sequence_number: u64,
    /// GUID changed on every file-level write.
    pub file_write_guid: Guid,
    /// GUID changed on every virtual-disk data write.
    pub data_write_guid: Guid,
    /// GUID identifying the active log.
    pub log_guid: Guid,
    /// Log format version.
    pub log_version: u16,
    /// File format version.
    pub version: u16,
    /// Length of the log region in bytes.
    pub log_length: u32,
    /// File offset of the log region.
    pub log_offset: u64,
}

/// Region table header.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct RegionTableHeader {
    /// Must be [`REGION_TABLE_SIGNATURE`].
    pub signature: u32,
    /// CRC-32C checksum of the entire 64 KiB region table.
    pub checksum: u32,
    /// Number of valid entries following this header.
    pub entry_count: u32,
    /// Reserved, must be zero.
    pub reserved: u32,
}

/// A single entry in the region table.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct RegionTableEntry {
    /// GUID identifying the region type.
    pub guid: Guid,
    /// File offset of the region.
    pub file_offset: u64,
    /// Length of the region in bytes.
    pub length: u32,
    /// Region table entry flags.
    pub flags: RegionTableEntryFlags,
}

/// Flags for a [`RegionTableEntry`].
#[bitfield(u32)]
#[derive(IntoBytes, Immutable, KnownLayout, FromBytes, PartialEq, Eq)]
pub struct RegionTableEntryFlags {
    /// Whether this region is required for the file to be valid.
    pub required: bool,
    /// Reserved bits.
    #[bits(31)]
    _reserved: u32,
}

/// BAT entry.
#[bitfield(u64)]
#[derive(IntoBytes, Immutable, KnownLayout, FromBytes, PartialEq, Eq)]
pub struct BatEntry {
    /// Block state.
    #[bits(3)]
    pub state: u8,
    /// Reserved bits.
    #[bits(17)]
    _reserved: u32,
    /// File offset in MiB units.
    #[bits(44)]
    pub file_offset_mb: u64,
}

impl BatEntry {
    /// Computes the full file offset in bytes.
    pub fn file_offset(&self) -> u64 {
        self.file_offset_mb() << 20
    }
}

/// Block states stored in the low 3 bits of a [`BatEntry`].
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BatEntryState {
    /// Block is not present.
    NotPresent = 0,
    /// Block has undefined content.
    Undefined = 1,
    /// Block is explicitly zero-filled.
    Zero = 2,
    /// Block is unmapped.
    Unmapped = 3,
    /// Block is fully present and backed by file data.
    FullyPresent = 6,
    /// Block is partially present.
    PartiallyPresent = 7,
}

impl BatEntryState {
    /// Attempt to convert a raw state value to a [`BatEntryState`].
    pub fn from_raw(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::NotPresent),
            1 => Some(Self::Undefined),
            2 => Some(Self::Zero),
            3 => Some(Self::Unmapped),
            6 => Some(Self::FullyPresent),
            7 => Some(Self::PartiallyPresent),
            _ => None,
        }
    }

    /// Whether this state counts as backed by file space.
    pub fn is_allocated(self) -> bool {
        matches!(self, Self::FullyPresent | Self::PartiallyPresent)
    }
}

/// Metadata table header.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct MetadataTableHeader {
    /// Must be [`METADATA_TABLE_SIGNATURE`].
    pub signature: u64,
    /// Reserved, must be zero.
    pub reserved: u16,
    /// Number of valid entries following this header.
    pub entry_count: u16,
    /// Reserved, must be zero.
    pub reserved2: [u32; 5],
}

/// A single entry in the metadata table.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct MetadataTableEntry {
    /// GUID identifying the metadata item.
    pub item_id: Guid,
    /// Offset of the item data relative to the metadata region.
    pub offset: u32,
    /// Length of the item data in bytes.
    pub length: u32,
    /// Metadata entry flags.
    pub flags: MetadataTableEntryFlags,
    /// Reserved, must be zero.
    pub reserved2: u32,
}

/// Flags for a [`MetadataTableEntry`].
#[bitfield(u32)]
#[derive(IntoBytes, Immutable, KnownLayout, FromBytes, PartialEq, Eq)]
pub struct MetadataTableEntryFlags {
    /// Whether this is a user metadata entry.
    pub is_user: bool,
    /// Whether this is a virtual disk metadata entry.
    pub is_virtual_disk: bool,
    /// Whether this metadata entry is required.
    pub is_required: bool,
    /// Reserved bits.
    #[bits(29)]
    _reserved: u32,
}

/// File parameters metadata item.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FileParameters {
    /// Block size in bytes.
    pub block_size: u32,
    /// File parameters flags.
    pub flags: FileParametersFlags,
}

/// Flags for [`FileParameters`].
#[bitfield(u32)]
#[derive(IntoBytes, Immutable, KnownLayout, FromBytes, PartialEq, Eq)]
pub struct FileParametersFlags {
    /// Whether blocks are left allocated.
    pub leave_blocks_allocated: bool,
    /// Whether the disk has a parent.
    pub has_parent: bool,
    /// Reserved bits.
    #[bits(30)]
    _reserved: u32,
}

/// CHS parameters metadata item.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ChsParameters {
    /// Number of heads per cylinder.
    pub heads_per_cylinder: u32,
    /// Number of sectors per track.
    pub sectors_per_track: u32,
}

/// Parent locator header.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ParentLocatorHeader {
    /// GUID identifying the locator type.
    pub locator_type: Guid,
    /// Reserved, must be zero.
    pub reserved: u16,
    /// Number of key-value entries following this header.
    pub key_value_count: u16,
}

/// A single key-value entry in a parent locator.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ParentLocatorEntry {
    /// Byte offset of the key string.
    pub key_offset: u32,
    /// Byte offset of the value string.
    pub value_offset: u32,
    /// Length of the key string in bytes.
    pub key_length: u16,
    /// Length of the value string in bytes.
    pub value_length: u16,
}

/// Log entry header.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct LogEntryHeader {
    /// Must be [`LOG_ENTRY_HEADER_SIGNATURE`].
    pub signature: u32,
    /// CRC-32C checksum of the entire log entry with this field zeroed.
    pub checksum: u32,
    /// Total length of this log entry in bytes.
    pub entry_length: u32,
    /// Byte offset of the oldest active log entry.
    pub tail: u32,
    /// Sequence number of this log entry.
    pub sequence_number: u64,
    /// Number of descriptors in this entry.
    pub descriptor_count: u32,
    /// Reserved, must be zero.
    pub reserved: u32,
    /// Must match the log GUID in the active header.
    pub log_guid: Guid,
    /// File size after all entries up to this one are applied.
    pub flushed_file_offset: u64,
    /// File size required to write this entry's data.
    pub last_file_offset: u64,
}

/// Log data descriptor.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct LogDataDescriptor {
    /// Must be [`LOG_DESCRIPTOR_DATA_SIGNATURE`].
    pub signature: u32,
    /// Trailing bytes from the previous 4 KiB sector.
    pub trailing_bytes: u32,
    /// Leading bytes from the next 4 KiB sector.
    pub leading_bytes: u64,
    /// File offset where this data should be written.
    pub file_offset: u64,
    /// Sequence number.
    pub sequence_number: u64,
}

/// Log zero descriptor.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct LogZeroDescriptor {
    /// Must be [`LOG_DESCRIPTOR_ZERO_SIGNATURE`].
    pub signature: u32,
    /// Reserved, must be zero.
    pub reserved: u32,
    /// Length of the zero-filled range in bytes.
    pub length: u64,
    /// File offset where zeroing should begin.
    pub file_offset: u64,
    /// Sequence number.
    pub sequence_number: u64,
}

/// A single 4 KiB data sector within a log entry.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct LogDataSector {
    /// Must be [`LOG_DATA_SECTOR_SIGNATURE`].
    pub signature: u32,
    /// High 32 bits of the sequence number.
    pub sequence_high: u32,
    /// Payload data.
    pub data: [u8; 4084],
    /// Low 32 bits of the sequence number.
    pub sequence_low: u32,
}

/// PMEM label storage area header.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PmemLabelStorageAreaHeader {
    /// Version of this header.
    pub version: u16,
    /// Reserved, must be zero.
    pub reserved: u16,
    /// GUID identifying the address abstraction type.
    pub address_abstraction_type: Guid,
    /// Byte offset of the label data.
    pub data_offset: u32,
    /// Length of the label data in bytes.
    pub data_length: u32,
}

/// Compute the CRC-32C checksum of `data`, treating the four bytes at
/// `checksum_offset` as zero during computation.
pub fn compute_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut crc = crc32c::crc32c(&data[..checksum_offset]);
    crc = crc32c::crc32c_append(crc, &[0; 4]);
    crc32c::crc32c_append(crc, &data[checksum_offset + 4..])
}

/// Validate that the checksum stored in `data` at `checksum_offset` matches.
pub fn validate_checksum(data: &[u8], checksum_offset: usize) -> bool {
    let Some(checksum_end) = checksum_offset.checked_add(4) else {
        return false;
    };
    let Some(checksum_bytes) = data.get(checksum_offset..checksum_end) else {
        return false;
    };
    let stored = u32::from_le_bytes(checksum_bytes.try_into().unwrap());
    let computed = compute_checksum(data, checksum_offset);
    stored == computed
}

/// Parent linkage key name.
pub const PARENT_LOCATOR_KEY_PARENT_LINKAGE: &str = "parent_linkage";
/// Alternative parent linkage key name.
pub const PARENT_LOCATOR_KEY_ALT_PARENT_LINKAGE: &str = "parent_linkage2";
/// Relative path key name.
pub const PARENT_LOCATOR_KEY_RELATIVE_PATH: &str = "relative_path";
/// Absolute Win32 path key name.
pub const PARENT_LOCATOR_KEY_ABSOLUTE_PATH: &str = "absolute_win32_path";
/// Volume path key name.
pub const PARENT_LOCATOR_KEY_VOLUME_PATH: &str = "volume_path";

const _: () = {
    assert!(size_of::<FileIdentifier>() == 8 + 256 * 2);
    assert!(size_of::<Header>() == 80);
    assert!(size_of::<RegionTableHeader>() == 16);
    assert!(size_of::<RegionTableEntry>() == 32);
    assert!(size_of::<MetadataTableHeader>() == 32);
    assert!(size_of::<MetadataTableEntry>() == 32);
    assert!(size_of::<LogEntryHeader>() == 64);
    assert!(size_of::<LogDataDescriptor>() == 32);
    assert!(size_of::<LogZeroDescriptor>() == 32);
    assert!(size_of::<LogDataSector>() == KB4 as usize);
    assert!(
        METADATA_SYSTEM_ENTRY_MAX_COUNT + METADATA_USER_ENTRY_MAX_COUNT == METADATA_ENTRY_MAX_COUNT
    );
};

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::FromZeros;

    #[test]
    fn layout_sizes_match_vhdx_format() {
        assert_eq!(size_of::<FileIdentifier>(), 520);
        assert_eq!(size_of::<Header>(), 80);
        assert_eq!(size_of::<RegionTableHeader>(), 16);
        assert_eq!(size_of::<RegionTableEntry>(), 32);
        assert_eq!(size_of::<MetadataTableHeader>(), 32);
        assert_eq!(size_of::<MetadataTableEntry>(), 32);
        assert_eq!(size_of::<LogEntryHeader>(), 64);
        assert_eq!(size_of::<LogDataDescriptor>(), 32);
        assert_eq!(size_of::<LogZeroDescriptor>(), 32);
        assert_eq!(size_of::<LogDataSector>(), KB4 as usize);
    }

    #[test]
    fn signatures_match_expected_bytes() {
        assert_eq!(FILE_IDENTIFIER_SIGNATURE.to_le_bytes(), *b"vhdxfile");
        assert_eq!(HEADER_SIGNATURE.to_le_bytes(), *b"head");
        assert_eq!(REGION_TABLE_SIGNATURE.to_le_bytes(), *b"regi");
        assert_eq!(METADATA_TABLE_SIGNATURE.to_le_bytes(), *b"metadata");
        assert_eq!(LOG_ENTRY_HEADER_SIGNATURE.to_le_bytes(), *b"loge");
        assert_eq!(LOG_DESCRIPTOR_DATA_SIGNATURE.to_le_bytes(), *b"desc");
        assert_eq!(LOG_DESCRIPTOR_ZERO_SIGNATURE.to_le_bytes(), *b"zero");
        assert_eq!(LOG_DATA_SECTOR_SIGNATURE.to_le_bytes(), *b"data");
    }

    #[test]
    fn bat_entry_accessors() {
        let entry = BatEntry::new().with_state(6).with_file_offset_mb(2);
        assert_eq!(entry.state(), 6);
        assert_eq!(entry.file_offset_mb(), 2);
        assert_eq!(entry.file_offset(), 2 * MB1);
    }

    #[test]
    fn bat_entry_state_roundtrip() {
        for &(raw, expected) in &[
            (0, BatEntryState::NotPresent),
            (1, BatEntryState::Undefined),
            (2, BatEntryState::Zero),
            (3, BatEntryState::Unmapped),
            (6, BatEntryState::FullyPresent),
            (7, BatEntryState::PartiallyPresent),
        ] {
            assert_eq!(BatEntryState::from_raw(raw), Some(expected));
        }
        assert_eq!(BatEntryState::from_raw(4), None);
        assert_eq!(BatEntryState::from_raw(5), None);
    }

    #[test]
    fn checksum_roundtrip() {
        let mut data = vec![0u8; HEADER_SIZE as usize];
        data[0..4].copy_from_slice(&HEADER_SIGNATURE.to_le_bytes());
        let checksum_offset = 4;
        let crc = compute_checksum(&data, checksum_offset);
        data[checksum_offset..checksum_offset + 4].copy_from_slice(&crc.to_le_bytes());
        assert!(validate_checksum(&data, checksum_offset));
        data[16] ^= 0xff;
        assert!(!validate_checksum(&data, checksum_offset));
    }

    #[test]
    fn validate_checksum_rejects_short_input() {
        assert!(!validate_checksum(&[0, 1, 2], 0));
    }

    #[test]
    fn zero_copy_roundtrip_header() {
        let mut header = Header::new_zeroed();
        header.signature = HEADER_SIGNATURE;
        header.version = VERSION_1;
        header.sequence_number = 42;

        let bytes = header.as_bytes();
        let parsed = Header::read_from_bytes(bytes).unwrap();
        assert_eq!(parsed.signature, HEADER_SIGNATURE);
        assert_eq!(parsed.version, VERSION_1);
        assert_eq!(parsed.sequence_number, 42);
    }

    #[test]
    fn zero_copy_roundtrip_bat_entry() {
        let entry = BatEntry::new().with_state(6).with_file_offset_mb(100);
        let bytes = entry.as_bytes();
        let parsed = BatEntry::read_from_bytes(bytes).unwrap();
        assert_eq!(parsed.state(), 6);
        assert_eq!(parsed.file_offset_mb(), 100);
    }
}
