// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types for the VHDX parser.
//!
//! The primary error type is [`VhdxError`], which covers I/O failures,
//! VHDX file corruption, and generic validation errors.

use thiserror::Error;

/// Errors returned by VHDX parser operations.
#[derive(Debug, Error)]
pub enum VhdxError {
    /// An I/O error occurred while reading or writing the VHDX file.
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    /// The VHDX file is corrupt.
    #[error("VHDX file is corrupt")]
    Corrupt(#[from] CorruptionType),

    /// A parameter validation error.
    #[error("invalid format parameters")]
    InvalidFormat(#[from] InvalidFormatReason),
}

/// Specific reasons a VHDX creation or parameter validation may fail.
///
/// Each variant corresponds to a distinct validation error detected
/// when processing VHDX parameters (e.g. during file creation).
#[derive(Debug, Clone, Error)]
pub enum InvalidFormatReason {
    /// The logical sector size is not 512 or 4096.
    #[error("logical sector size must be 512 or 4096")]
    InvalidLogicalSectorSize,

    /// The physical sector size is not 512 or 4096.
    #[error("physical sector size must be 512 or 4096")]
    InvalidPhysicalSectorSize,

    /// The disk size is zero.
    #[error("disk size must be > 0")]
    DiskSizeZero,

    /// The disk size is not a multiple of the logical sector size.
    #[error("disk size must be a multiple of logical sector size")]
    DiskSizeNotAligned,

    /// The disk size exceeds the maximum (64 TiB).
    #[error("disk size exceeds maximum (64 TiB)")]
    DiskSizeTooLarge,

    /// The block size is not a multiple of 1 MiB.
    #[error("block size must be a multiple of 1 MiB")]
    BlockSizeNotAligned,

    /// The block size exceeds the maximum (256 MiB).
    #[error("block size exceeds maximum (256 MiB)")]
    BlockSizeTooLarge,

    /// The block alignment is not a power of 2.
    #[error("block alignment must be a power of 2")]
    BlockAlignmentNotPowerOfTwo,

    /// The block size / logical sector size combination is invalid (chunk ratio is zero).
    #[error("invalid block size / logical sector size combination")]
    InvalidChunkRatio,

    /// The computed BAT entry count exceeds the absolute maximum.
    #[error("BAT entry count exceeds absolute maximum")]
    BatEntryCountTooLarge,

    /// The computed BAT size exceeds the maximum.
    #[error("BAT size exceeds maximum")]
    BatSizeTooLarge,
}

/// Specific reasons a VHDX file may be considered corrupt.
///
/// Each variant corresponds to a distinct corruption condition detected
/// during parsing or validation. Covers all corruption types from the
/// VHDX implementation.
#[derive(Debug, Clone, Error)]
pub enum CorruptionType {
    /// Unspecified corruption.
    #[error("unspecified corruption")]
    Other,

    /// A sector bitmap block is referenced but its BAT entry is not allocated.
    #[error("sector bitmap block is not allocated")]
    UnallocatedSectorBitmapBlock,

    /// A user metadata entry is marked as required, which is invalid.
    #[error("user metadata entry is marked as required")]
    MetadataUserRequired,

    /// The BAT region is too small to cover all blocks and sector bitmaps.
    #[error("BAT region is too small for the disk geometry")]
    BatTooSmall,

    /// Neither header has a valid checksum.
    #[error("no valid VHDX headers found")]
    NoValidHeaders,

    /// The log offset or length in the header is invalid (misaligned or zero when GUID is set).
    #[error("invalid log offset or length in header")]
    InvalidLogOffsetOrLength,

    /// The log region offset is not properly aligned.
    #[error("log offset is not aligned")]
    InvalidLogOffset,

    /// The log region extends beyond the end of the file.
    #[error("log region extends beyond end of file")]
    LogBeyondEndOfFile,

    /// The parent locator metadata item is too small to contain its header.
    #[error("parent locator item is too small for its header")]
    LocatorTooSmallForHeader,

    /// The parent locator metadata item is too small for the declared entries.
    #[error("parent locator item is too small for its entries")]
    LocatorTooSmallForEntries,

    /// A parent locator entry references a key outside the item bounds.
    #[error("parent locator entry key is out of bounds")]
    InvalidLocatorEntryKey,

    /// A parent locator entry has an empty key.
    #[error("parent locator entry has an empty key")]
    EmptyLocatorEntryKey,

    /// A parent locator entry has an empty value.
    #[error("parent locator entry has an empty value")]
    EmptyLocatorEntryValue,

    /// The parent locator metadata item is incorrectly flagged as a virtual disk item.
    #[error("parent locator is marked as virtual disk metadata")]
    ParentLocatorIsVirtualDisk,

    /// The metadata table header has an invalid signature.
    #[error("metadata table has an invalid signature")]
    InvalidMetadataTableSignature,

    /// The metadata table entry count exceeds the maximum allowed.
    #[error("metadata table entry count too high")]
    MetadataTableEntryCountTooHigh,

    /// Two or more metadata entries share the same item GUID.
    #[error("duplicate metadata GUID")]
    MetadataDuplicateGuid,

    /// Two or more metadata entries have overlapping data ranges.
    #[error("metadata entries have overlapping ranges")]
    MetadataOverlapping,

    /// The number of user metadata entries exceeds the maximum allowed.
    #[error("user metadata entry count exceeded")]
    MetadataUserCountExceeded,

    /// The file is empty or truncated before the minimum valid size.
    #[error("file is empty")]
    EmptyFile,

    /// The file parameters metadata item has an invalid size.
    #[error("file parameters item has invalid size")]
    InvalidFileParameterSize,

    /// The file parameters metadata item is incorrectly flagged as virtual disk metadata.
    #[error("file parameters marked as virtual disk metadata")]
    FileParametersMarkedVirtual,

    /// The block size is invalid (not a power of two, or out of range).
    #[error("invalid block size")]
    InvalidBlockSize,

    /// The logical sector size is invalid (not 512 or 4096).
    #[error("invalid logical sector size")]
    InvalidLogicalSectorSize,

    /// The logical sector size metadata item is incorrectly flagged as virtual disk metadata.
    #[error("logical sector size marked as virtual disk metadata")]
    LogicalSectorSizeMarkedVirtual,

    /// The physical sector size is invalid.
    #[error("invalid sector size")]
    InvalidSectorSize,

    /// The logical sector size metadata item has an invalid data length.
    #[error("logical sector size item has invalid size")]
    InvalidLogicalSectorSizeSize,

    /// The virtual disk size metadata item is incorrectly flagged as virtual disk metadata.
    #[error("disk size item marked as virtual disk metadata")]
    DiskMarkedVirtual,

    /// The virtual disk size is invalid (zero, not aligned, or exceeds maximum).
    #[error("invalid virtual disk size")]
    InvalidDiskSize,

    /// Both copies of the region table are corrupt.
    #[error("both region tables are corrupt")]
    RegionTablesBothCorrupt,

    /// The entry count in a region table header is invalid.
    #[error("invalid entry count in region table")]
    InvalidEntryCountInRegionTable,

    /// Two region table entries have the same GUID.
    #[error("duplicate region table entry")]
    DuplicateRegionEntry,

    /// A region table entry has an invalid offset or length (misaligned or overlapping headers).
    #[error("invalid offset or length in region table entry")]
    OffsetOrLengthInRegionTable,

    /// A required region has an unrecognized GUID.
    #[error("unknown required region")]
    UnknownRequiredRegion,

    /// The BAT or metadata region is missing from the region table.
    #[error("BAT or metadata region is missing")]
    MissingBatOrMetadataRegion,

    /// A log entry failed validation during replay.
    #[error("bad log entry encountered during replay")]
    BadLogEntryOnReplay,

    /// The log contains no valid entries but requires replay.
    #[error("no valid log entries found")]
    NoValidLogEntries,

    /// The VHDX file has been truncated below the required size.
    #[error("file is truncated")]
    VhdTruncated,

    /// A BAT entry references a file range beyond the end of the file.
    #[error("BAT entry references range beyond end of file")]
    RangeBeyondEof,

    /// Two or more BAT entries reference overlapping file ranges.
    #[error("BAT entries reference overlapping file ranges")]
    RangeCollision,

    /// A BAT entry contains an invalid block state value.
    #[error("invalid block state in BAT entry")]
    InvalidBlockState,

    /// A trimmed range collides with an allocated range.
    #[error("trimmed range collides with allocated range")]
    TrimmedRangeCollision,

    /// A required metadata item has an unrecognized GUID.
    #[error("unknown required metadata item")]
    UnknownRequiredMetadata,

    /// The file is marked as incompletely created.
    #[error("file is marked as incomplete")]
    IncompleteFile,

    /// A required metadata item is missing from the metadata table.
    #[error("required metadata item is missing")]
    MissingRequiredMetadata,

    /// The log GUID in the header is non-zero but no log region exists.
    #[error("header has log GUID but log is missing")]
    MissingLogHasGuid,

    /// A metadata table entry has an invalid offset (below minimum or misaligned).
    #[error("invalid metadata entry offset")]
    InvalidMetadataEntryOffset,

    /// The metadata region exceeds the maximum allowed size.
    #[error("metadata region is too large")]
    MetadataRegionTooLarge,

    /// A single metadata item exceeds the maximum allowed size.
    #[error("metadata item is too large")]
    MetadataItemTooLarge,

    /// The total size of all metadata items in one category exceeds the limit.
    #[error("total metadata size per category exceeded")]
    TotalMetadataSizeExceeded,

    /// A metadata table entry has a zero item GUID.
    #[error("metadata entry has zero item GUID")]
    ZeroMetadataItemId,

    /// The file identifier at offset 0 has an invalid signature.
    #[error("invalid file identifier signature")]
    InvalidFileIdentifier,

    /// The parent locator has an invalid key-value count.
    #[error("invalid parent locator key-value count")]
    InvalidLocatorKeyValueCount,

    /// The file is unreasonably large (exceeds implementation limits).
    #[error("file size exceeds implementation limits")]
    HugeFile,

    /// The log GUID is non-zero, indicating log replay is required.
    /// Log replay is not yet implemented.
    #[error("log replay required (log GUID is non-zero)")]
    LogReplayRequired,

    /// A read or write request extends beyond the end of the virtual disk.
    #[error("read or write request extends beyond end of virtual disk")]
    ReadBeyondEndOfDisk,

    /// A read or write request is not aligned to the logical sector size.
    #[error("I/O request is not aligned to logical sector size")]
    UnalignedIo,
}
