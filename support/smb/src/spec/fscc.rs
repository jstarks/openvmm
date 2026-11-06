// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! File information layouts from [MS-FSCC] §§2.4–2.6.

use bitfield_struct::bitfield;
use open_enum::open_enum;
use zerocopy::little_endian::{I64, U16, U32, U64};

/// FILE_NOTIFY_INFORMATION record alignment: [MS-FSCC] §2.7.1.
pub const NOTIFY_ALIGNMENT: usize = 4;

open_enum! {
    /// Notification actions: [MS-FSCC] §2.7.1.
    pub enum NotifyAction: u32 {
        #![expect(missing_docs, reason = "Action names follow the cited table.")]
        ADDED = 1,
        REMOVED = 2,
        MODIFIED = 3,
        RENAMED_OLD_NAME = 4,
        RENAMED_NEW_NAME = 5,
        ADDED_STREAM = 6,
        REMOVED_STREAM = 7,
        MODIFIED_STREAM = 8,
    }
}

wire!(
/// FILE_NOTIFY_INFORMATION fixed prefix; filename is UTF-16LE: [MS-FSCC] §2.7.1.
FileNotifyInformation, 12 {
    next_entry_offset: U32,
    action: U32,
    file_name_length: U32,
});

open_enum! {
    /// File information class values: [MS-FSCC] §2.4.
    pub enum FileInformationClass: u8 {
        #![expect(missing_docs, reason = "Names follow the cited information-class table.")]
        DIRECTORY = 1,
        FULL_DIRECTORY = 2,
        BOTH_DIRECTORY = 3,
        BASIC = 4,
        STANDARD = 5,
        INTERNAL = 6,
        EA = 7,
        ACCESS = 8,
        NAME = 9,
        RENAME = 10,
        NAMES = 12,
        DISPOSITION = 13,
        POSITION = 14,
        FULL_EA = 15,
        MODE = 16,
        ALIGNMENT = 17,
        ALL = 18,
        ALLOCATION = 19,
        END_OF_FILE = 20,
        ALTERNATE_NAME = 21,
        STREAM = 22,
        COMPRESSION = 28,
        NETWORK_OPEN = 34,
        ATTRIBUTE_TAG = 35,
        ID_BOTH_DIRECTORY = 37,
        ID_FULL_DIRECTORY = 38,
        NORMALIZED_NAME = 48,
        ID_EXTD_DIRECTORY = 60,
        ID64_EXTD_DIRECTORY = 78,
        ID64_EXTD_BOTH_DIRECTORY = 79,
        ID_ALL_EXTD_DIRECTORY = 80,
        ID_ALL_EXTD_BOTH_DIRECTORY = 81,
    }
}

open_enum! {
    /// Filesystem information class values: [MS-FSCC] §2.5.
    pub enum FileSystemInformationClass: u8 {
        /// FileFsVolumeInformation, §2.5.9.
        VOLUME = 1,
        /// Local-only label update, §2.5.5.
        LABEL = 2,
        /// FileFsSizeInformation, §2.5.8.
        SIZE = 3,
        /// FileFsDeviceInformation, §2.5.10.
        DEVICE = 4,
        /// FileFsAttributeInformation, §2.5.1.
        ATTRIBUTE = 5,
        /// FileFsControlInformation, §2.5.2.
        CONTROL = 6,
        /// FileFsFullSizeInformation, §2.5.4.
        FULL_SIZE = 7,
        /// FileFsObjectIdInformation, §2.5.6.
        OBJECT_ID = 8,
        /// Local-only driver query, §2.5.3.
        DRIVER_PATH = 9,
        /// Local-only volume flags, §2.5.
        VOLUME_FLAGS = 10,
        /// FileFsSectorSizeInformation, §2.5.7.
        SECTOR_SIZE = 11,
    }
}

/// File attributes: [MS-FSCC] §2.6.
#[bitfield(u32, repr = U32, from = U32::new, into = super::u32_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct FileAttributes {
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,
    #[bits(1)]
    reserved0: u8,
    pub directory: bool,
    pub archive: bool,
    #[bits(1)]
    reserved1: u8,
    pub normal: bool,
    pub temporary: bool,
    pub sparse_file: bool,
    pub reparse_point: bool,
    pub compressed: bool,
    pub offline: bool,
    pub not_content_indexed: bool,
    pub encrypted: bool,
    pub integrity_stream: bool,
    #[bits(1)]
    reserved2: u8,
    pub no_scrub_data: bool,
    pub recall_on_open: bool,
    pub pinned: bool,
    pub unpinned: bool,
    #[bits(1)]
    reserved3: u8,
    pub recall_on_data_access: bool,
    #[bits(9)]
    reserved4: u16,
}
le_bitfield_conversions!(FileAttributes, u32, U32);

impl FileAttributes {
    /// Whether all bits are defined by [MS-FSCC] §2.6.
    pub fn is_valid(self) -> bool {
        self.into_bits() & !0x005effb7 == 0
    }
}

/// Filesystem attributes: [MS-FSCC] §2.5.1.
#[bitfield(u32, repr = U32, from = U32::new, into = super::u32_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct FileSystemAttributes {
    pub case_sensitive_search: bool,
    pub case_preserved_names: bool,
    pub unicode_on_disk: bool,
    pub persistent_acls: bool,
    #[bits(14)]
    other0: u16,
    pub named_streams: bool,
    #[bits(4)]
    other1: u8,
    pub extended_attributes: bool,
    #[bits(8)]
    other2: u8,
}
le_bitfield_conversions!(FileSystemAttributes, u32, U32);

/// FILE_DEVICE_DISK: [MS-FSCC] §2.5.10.
pub const FILE_DEVICE_DISK: u32 = 0x00000007;
/// Minimum volume query buffer, including native alignment: [MS-FSA] §2.1.5.13.1.
pub const FILE_FS_VOLUME_MIN_BUFFER_SIZE: usize = 24;
/// Maximum volume label length in characters: [MS-FSCC] §2.5.9.
pub const FILE_FS_VOLUME_MAX_LABEL_LENGTH: usize = 32;
/// Queryable file mode flags, excluding delete mode: [MS-FSCC] §2.4.31.
pub const FILE_MODE_INFORMATION_MASK: u32 = 0x0000003e;
/// Settable file mode flags: [MS-FSCC] §2.4.31.
pub const FILE_MODE_INFORMATION_SET_MASK: u32 = 0x00000036;
/// Minimum complete FileAllInformation buffer: [MS-FSA] §2.1.5.12.3.
pub const FILE_ALL_INFORMATION_MIN_BUFFER_SIZE: usize = 104;
/// Minimum alternate-name buffer: [MS-FSA] §2.1.5.12.4.
pub const FILE_NAME_INFORMATION_MIN_BUFFER_SIZE: usize = 8;
/// Linked directory records are eight-byte aligned: [MS-FSCC] §2.4.
pub const DIRECTORY_ALIGNMENT: usize = 8;
/// ShortName contains at most twelve UTF-16 code units: [MS-FSCC] §2.4.8.
pub const SHORT_NAME_CAPACITY: usize = 12;
/// Maximum pathname length in UTF-16 code units: [MS-FSCC] §2.1.5.
pub const MAX_PATH_LENGTH: usize = 32_760;
/// Leave a timestamp unchanged: [MS-FSCC] §2.4.7.
pub const TIME_UNCHANGED: i64 = 0;
/// Suppress automatic timestamp updates on this open: [MS-FSA] §2.1.5.15.2.
pub const TIME_SUPPRESS: i64 = -1;
/// Restore automatic timestamp updates on this open: [MS-FSA] §2.1.5.15.2.
pub const TIME_RESTORE: i64 = -2;
/// NT FILETIME units per second: [MS-DTYP] §2.3.3.
pub const NT_TICKS_PER_SECOND: u64 = 10_000_000;
/// Difference between the NT and Unix epochs, in NT ticks: [MS-DTYP] §2.3.3.
pub const UNIX_EPOCH_NT_TIME: u64 = 116_444_736_000_000_000;

wire!(
    /// FILE_FULL_EA_INFORMATION prefix, followed by name, NUL and value: [MS-FSCC] §2.4.16.
    FileFullEaInformation, 8 {
        next_entry_offset: U32,
        flags: u8,
        name_length: u8,
        value_length: U16,
    }
);
wire!(
    /// FileAttributeTagInformation: [MS-FSCC] §2.4.6.
    FileAttributeTagInformation, 8 {
        file_attributes: FileAttributes,
        reparse_tag: U32,
    }
);
wire!(
    /// FileBasicInformation: [MS-FSCC] §2.4.7. Signed times also encode update controls.
    FileBasicInformation, 40 {
        creation_time: I64,
        last_access_time: I64,
        last_write_time: I64,
        change_time: I64,
        file_attributes: FileAttributes,
        reserved: U32,
    }
);
wire!(
    /// FileCompressionInformation: [MS-FSCC] §2.4.9.
    FileCompressionInformation, 16 {
        compressed_file_size: U64,
        compression_format: U16,
        compression_unit_shift: u8,
        chunk_shift: u8,
        cluster_shift: u8,
        reserved: [u8; 3],
    }
);
wire!(
    /// FileStandardInformation: [MS-FSCC] §2.4.47.
    FileStandardInformation, 24 {
        allocation_size: U64,
        end_of_file: U64,
        number_of_links: U32,
        delete_pending: u8,
        directory: u8,
        reserved: [u8; 2],
    }
);
wire!(
    /// FileInternalInformation: [MS-FSCC] §2.4.27.
    FileInternalInformation, 8 { index_number: U64 }
);
wire!(
    /// FileNameInformation/alternate-name fixed prefix: [MS-FSCC] §§2.4.32, 2.4.5.
    FileNameInformation, 4 { file_name_length: U32 }
);
wire!(
    /// FilePositionInformation: [MS-FSCC] §2.4.40.
    FilePositionInformation, 8 { current_byte_offset: I64 }
);
wire!(
    /// FileEaInformation: [MS-FSCC] §2.4.13.
    FileEaInformation, 4 { ea_size: U32 }
);
wire!(
    /// FileAccessInformation: [MS-FSCC] §2.4.1.
    FileAccessInformation, 4 { access_flags: super::smb2::AccessMask }
);
wire!(
    /// FileModeInformation: [MS-FSCC] §2.4.31.
    FileModeInformation, 4 { mode: U32 }
);
wire!(
    /// FileAlignmentInformation: [MS-FSCC] §2.4.3.
    FileAlignmentInformation, 4 { alignment_requirement: U32 }
);
wire!(
    /// FileEndOfFileInformation: [MS-FSCC] §2.4.14.
    FileEndOfFileInformation, 8 { end_of_file: I64 }
);
wire!(
    /// FileAllocationInformation: [MS-FSCC] §2.4.4.
    FileAllocationInformation, 8 { allocation_size: I64 }
);
wire!(
    /// FileDispositionInformation: [MS-FSCC] §2.4.11.
    FileDispositionInformation, 1 { delete_pending: u8 }
);
/// Minimum complete FILE_RENAME_INFORMATION_TYPE_2 size: [MS-FSCC] §2.4.42.2.
pub const FILE_RENAME_INFORMATION_MIN_SIZE: usize = 24;
wire!(
    /// FILE_RENAME_INFORMATION_TYPE_2 prefix; UTF-16LE name and padding follow:
    /// [MS-FSCC] §2.4.42.2.
    FileRenameInformation, 20 {
        replace_if_exists: u8,
        reserved: [u8; 7],
        root_directory: U64,
        file_name_length: U32,
    }
);
wire!(
    /// FileAllInformation fixed prefix: [MS-FSCC] §2.4.2.
    FileAllInformation, 100 {
        basic: FileBasicInformation,
        standard: FileStandardInformation,
        internal: FileInternalInformation,
        ea_size: U32,
        access_flags: super::smb2::AccessMask,
        position: FilePositionInformation,
        mode: U32,
        alignment_requirement: U32,
        name: FileNameInformation,
    }
);
wire!(
    /// FileNetworkOpenInformation: [MS-FSCC] §2.4.34.
    FileNetworkOpenInformation, 56 {
        creation_time: I64,
        last_access_time: I64,
        last_write_time: I64,
        change_time: I64,
        allocation_size: U64,
        end_of_file: U64,
        file_attributes: FileAttributes,
        reserved: U32,
    }
);
wire!(
    /// FileFsDeviceInformation: [MS-FSCC] §2.5.10.
    FileFsDeviceInformation, 8 { device_type: U32, characteristics: U32 }
);
wire!(
    /// FileFsVolumeInformation prefix; label is UTF-16LE: [MS-FSCC] §2.5.9.
    FileFsVolumeInformation, 18 {
        volume_creation_time: U64,
        volume_serial_number: U32,
        volume_label_length: U32,
        supports_objects: u8,
        reserved: u8,
    }
);
wire!(
    /// FileFsSizeInformation: [MS-FSCC] §2.5.8.
    FileFsSizeInformation, 24 {
        total_allocation_units: I64,
        available_allocation_units: I64,
        sectors_per_allocation_unit: U32,
        bytes_per_sector: U32,
    }
);
wire!(
    /// FileFsFullSizeInformation: [MS-FSCC] §2.5.4.
    FileFsFullSizeInformation, 32 {
        total_allocation_units: I64,
        caller_available_allocation_units: I64,
        actual_available_allocation_units: I64,
        sectors_per_allocation_unit: U32,
        bytes_per_sector: U32,
    }
);
wire!(
    /// FileFsAttributeInformation fixed prefix: [MS-FSCC] §2.5.1.
    FileFsAttributeInformation, 12 {
        file_system_attributes: FileSystemAttributes,
        maximum_component_name_length: U32,
        file_system_name_length: U32,
    }
);
wire!(
    /// Common linked directory-record prefix: [MS-FSCC] §§2.4.8, 10, 15, 22, 24, 33.
    DirectoryEntryHeader, 8 { next_entry_offset: U32, file_index: U32 }
);
wire!(
    /// FileDirectoryInformation fixed prefix: [MS-FSCC] §2.4.10.
    FileDirectoryInformation, 64 {
        header: DirectoryEntryHeader,
        creation_time: I64,
        last_access_time: I64,
        last_write_time: I64,
        change_time: I64,
        end_of_file: U64,
        allocation_size: U64,
        file_attributes: FileAttributes,
        file_name_length: U32,
    }
);
wire!(
    /// FileFullDirectoryInformation fixed prefix: [MS-FSCC] §2.4.15.
    FileFullDirectoryInformation, 68 {
        directory: FileDirectoryInformation,
        ea_size: U32,
    }
);
wire!(
    /// Short-name tail shared by FileBothDirectoryInformation formats: [MS-FSCC] §2.4.8.
    DirectoryShortName, 26 {
        length: u8,
        reserved: u8,
        name: [U16; SHORT_NAME_CAPACITY],
    }
);
wire!(
    /// FileBothDirectoryInformation fixed prefix: [MS-FSCC] §2.4.8.
    FileBothDirectoryInformation, 94 {
        full: FileFullDirectoryInformation,
        short_name: DirectoryShortName,
    }
);
wire!(
    /// FileIdBothDirectoryInformation fixed prefix: [MS-FSCC] §2.4.22.
    FileIdBothDirectoryInformation, 104 {
        both: FileBothDirectoryInformation,
        reserved: U16,
        file_id: U64,
    }
);
wire!(
    /// FileIdFullDirectoryInformation fixed prefix: [MS-FSCC] §2.4.24.
    FileIdFullDirectoryInformation, 80 {
        full: FileFullDirectoryInformation,
        reserved: U32,
        file_id: U64,
    }
);
wire!(
    /// FileId64ExtdDirectoryInformation prefix: [MS-FSCC] §2.4.19.
    FileId64ExtdDirectoryInformation, 80 {
        full: FileFullDirectoryInformation,
        reparse_point_tag: U32,
        file_id: U64,
    }
);
wire!(
    /// FileId64ExtdBothDirectoryInformation prefix: [MS-FSCC] §2.4.18.
    FileId64ExtdBothDirectoryInformation, 106 {
        extended: FileId64ExtdDirectoryInformation,
        short_name: DirectoryShortName,
    }
);
wire!(
    /// FileIdExtdDirectoryInformation prefix: [MS-FSCC] §2.4.23.
    FileIdExtdDirectoryInformation, 88 {
        full: FileFullDirectoryInformation,
        reparse_point_tag: U32,
        file_id: [u8; 16],
    }
);
wire!(
    /// FileIdAllExtdDirectoryInformation prefix: [MS-FSCC] §2.4.21.
    FileIdAllExtdDirectoryInformation, 96 {
        extended: FileId64ExtdDirectoryInformation,
        file_id128: [u8; 16],
    }
);
wire!(
    /// FileIdAllExtdBothDirectoryInformation prefix: [MS-FSCC] §2.4.20.
    FileIdAllExtdBothDirectoryInformation, 122 {
        extended: FileIdAllExtdDirectoryInformation,
        short_name: DirectoryShortName,
    }
);
wire!(
    /// FileNamesInformation fixed prefix: [MS-FSCC] §2.4.33.
    FileNamesInformation, 12 { header: DirectoryEntryHeader, file_name_length: U32 }
);
