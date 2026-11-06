// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SMB2 layouts and decoded values from [MS-SMB2] §2.2.

use bitfield_struct::bitfield;
use open_enum::open_enum;
use zerocopy::little_endian::{U16, U32, U64};

/// Synchronous SMB2 header length: [MS-SMB2] §2.2.1.2.
pub const HEADER_SIZE: usize = 64;
/// ProtocolId: [MS-SMB2] §2.2.1.
pub const SIGNATURE: [u8; 4] = *b"\xfeSMB";
/// SMB 2.1 dialect: [MS-SMB2] §2.2.3.
pub const DIALECT_210: u16 = 0x0210;
/// CREATE context alignment: [MS-SMB2] §2.2.13.2.
pub const CREATE_CONTEXT_ALIGNMENT: usize = 8;
/// Compound command headers/responses are eight-byte aligned: [MS-SMB2] §3.3.5.2.7.
pub const COMPOUND_ALIGNMENT: usize = 8;
/// Multi-credit payload unit: [MS-SMB2] §3.1.5.2.
pub const CREDIT_PAYLOAD_SIZE: u32 = 65536;

open_enum! {
    /// Command codes: [MS-SMB2] §2.2.1.
    pub enum Command: u16 {
        #![expect(missing_docs, reason = "Command names follow the cited header table.")]
        NEGOTIATE = 0,
        SESSION_SETUP = 1,
        LOGOFF = 2,
        TREE_CONNECT = 3,
        TREE_DISCONNECT = 4,
        CREATE = 5,
        CLOSE = 6,
        FLUSH = 7,
        READ = 8,
        WRITE = 9,
        LOCK = 10,
        IOCTL = 11,
        CANCEL = 12,
        ECHO = 13,
        QUERY_DIRECTORY = 14,
        CHANGE_NOTIFY = 15,
        QUERY_INFO = 16,
        SET_INFO = 17,
        OPLOCK_BREAK = 18,
    }
}

open_enum! {
    /// NTSTATUS values: [MS-ERREF] §2.3. Statuses are not Win32 error codes.
    pub enum Status: u32 {
        #![expect(missing_docs, reason = "Status names follow the cited NTSTATUS table.")]
        SUCCESS = 0,
        PENDING = 0x00000103,
        NOTIFY_CLEANUP = 0x0000010b,
        NOTIFY_ENUM_DIR = 0x0000010c,
        CANCELLED = 0xc0000120,
        INFO_LENGTH_MISMATCH = 0xc0000004,
        EAS_NOT_SUPPORTED = 0xc000004f,
        NONE_MAPPED = 0xc0000073,
        INVALID_ACL = 0xc0000077,
        INVALID_SID = 0xc0000078,
        INVALID_SECURITY_DESCR = 0xc0000079,
        INTERNAL_ERROR = 0xc00000e5,
        INVALID_INFO_CLASS = 0xc0000003,
        BUFFER_OVERFLOW = 0x80000005,
        EA_LIST_INCONSISTENT = 0x80000014,
        NO_MORE_FILES = 0x80000006,
        INVALID_HANDLE = 0xc0000008,
        INVALID_PARAMETER = 0xc000000d,
        INVALID_DEVICE_REQUEST = 0xc0000010,
        MORE_PROCESSING_REQUIRED = 0xc0000016,
        END_OF_FILE = 0xc0000011,
        ACCESS_DENIED = 0xc0000022,
        BUFFER_TOO_SMALL = 0xc0000023,
        OBJECT_NAME_INVALID = 0xc0000033,
        OBJECT_NAME_NOT_FOUND = 0xc0000034,
        OBJECT_NAME_COLLISION = 0xc0000035,
        OBJECT_PATH_NOT_FOUND = 0xc000003a,
        OBJECT_PATH_SYNTAX_BAD = 0xc000003b,
        SHARING_VIOLATION = 0xc0000043,
        FILE_LOCK_CONFLICT = 0xc0000054,
        LOCK_NOT_GRANTED = 0xc0000055,
        DELETE_PENDING = 0xc0000056,
        INVALID_OWNER = 0xc000005a,
        INVALID_PRIMARY_GROUP = 0xc000005b,
        DISK_FULL = 0xc000007f,
        RANGE_NOT_LOCKED = 0xc000007e,
        INSUFFICIENT_RESOURCES = 0xc000009a,
        FILE_IS_A_DIRECTORY = 0xc00000ba,
        NOT_SUPPORTED = 0xc00000bb,
        BAD_NETWORK_NAME = 0xc00000cc,
        DIRECTORY_NOT_EMPTY = 0xc0000101,
        NOT_A_DIRECTORY = 0xc0000103,
        NAME_TOO_LONG = 0xc0000106,
        FILE_CLOSED = 0xc0000128,
        INVALID_LOCK_RANGE = 0xc00001a1,
        INVALID_DEVICE_STATE = 0xc0000184,
        USER_SESSION_DELETED = 0xc0000203,
        NETWORK_NAME_DELETED = 0xc00000c9,
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?} ({:#010x})", self.0)
    }
}

impl std::error::Error for Status {}

impl Command {
    /// Defined command range: [MS-SMB2] §2.2.1. Unknown commands require disconnect (§3.3.5.2.6).
    pub fn is_valid(self) -> bool {
        self.0 <= Self::OPLOCK_BREAK.0
    }
}

impl Status {
    /// Error severity occupies the upper two bits: [MS-ERREF] §2.3.
    pub fn is_error(self) -> bool {
        self.0 >> 30 == 3
    }
}

/// Header flags: [MS-SMB2] §2.2.1.
#[bitfield(u32, repr = U32, from = U32::new, into = super::u32_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct HeaderFlags {
    pub server_to_redir: bool,
    pub async_command: bool,
    pub related_operations: bool,
    pub signed: bool,
    #[bits(3)]
    pub priority: u8,
    #[bits(21)]
    reserved0: u32,
    pub dfs_operations: bool,
    pub replay_operation: bool,
    #[bits(2)]
    reserved1: u8,
}
le_bitfield_conversions!(HeaderFlags, u32, U32);

/// Negotiation security mode: [MS-SMB2] §§2.2.3–2.2.6.
#[bitfield(u16, repr = U16, from = U16::new, into = super::u16_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct SecurityMode {
    pub signing_enabled: bool,
    pub signing_required: bool,
    #[bits(14)]
    reserved: u16,
}
le_bitfield_conversions!(SecurityMode, u16, U16);

/// SESSION_SETUP's byte-sized SecurityMode: [MS-SMB2] §2.2.5.
#[bitfield(u8)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct SessionSecurityMode {
    pub signing_enabled: bool,
    pub signing_required: bool,
    #[bits(6)]
    reserved: u8,
}

/// SESSION_SETUP request flags: [MS-SMB2] §2.2.5.
#[bitfield(u8)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct SessionSetupFlags {
    pub binding: bool,
    #[bits(7)]
    reserved: u8,
}

/// Negotiated capabilities: [MS-SMB2] §§2.2.3–2.2.4.
#[bitfield(u32, repr = U32, from = U32::new, into = super::u32_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct Capabilities {
    pub dfs: bool,
    pub leasing: bool,
    pub large_mtu: bool,
    pub multi_channel: bool,
    pub persistent_handles: bool,
    pub directory_leasing: bool,
    pub encryption: bool,
    #[bits(25)]
    reserved: u32,
}
le_bitfield_conversions!(Capabilities, u32, U32);

/// CLOSE request/response flags: [MS-SMB2] §§2.2.15–2.2.16.
#[bitfield(u16, repr = U16, from = U16::new, into = super::u16_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct CloseFlags {
    pub postquery_attrib: bool,
    #[bits(15)]
    reserved: u16,
}
le_bitfield_conversions!(CloseFlags, u16, U16);

/// Directory query flags: [MS-SMB2] §2.2.33.
#[bitfield(u8)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct QueryDirectoryFlags {
    pub restart_scans: bool,
    pub return_single_entry: bool,
    pub index_specified: bool,
    #[bits(1)]
    reserved0: u8,
    pub reopen: bool,
    #[bits(3)]
    reserved1: u8,
}

/// READ flags: [MS-SMB2] §2.2.19.
#[bitfield(u8)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct ReadFlags {
    pub unbuffered: bool,
    pub request_compressed: bool,
    #[bits(6)]
    reserved: u8,
}

/// WRITE flags: [MS-SMB2] §2.2.21.
#[bitfield(u32, repr = U32, from = U32::new, into = super::u32_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct WriteFlags {
    pub write_through: bool,
    pub unbuffered: bool,
    #[bits(30)]
    reserved: u32,
}
le_bitfield_conversions!(WriteFlags, u32, U32);

/// Byte-range lock flags: [MS-SMB2] §2.2.26.1.
#[bitfield(u32, repr = U32, from = U32::new, into = super::u32_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct LockFlags {
    pub shared_lock: bool,
    pub exclusive_lock: bool,
    pub unlock: bool,
    #[bits(1)]
    reserved_low: u32,
    pub fail_immediately: bool,
    #[bits(27)]
    reserved: u32,
}
le_bitfield_conversions!(LockFlags, u32, U32);

/// File-object access mask: [MS-SMB2] §2.2.13.1.1.
///
/// For directories read_data/write_data/append_data/execute mean
/// list_directory/add_file/add_subdirectory/traverse, respectively (§2.2.13.1.2).
#[bitfield(u32, repr = U32, from = U32::new, into = super::u32_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct AccessMask {
    pub read_data: bool,
    pub write_data: bool,
    pub append_data: bool,
    pub read_ea: bool,
    pub write_ea: bool,
    pub execute: bool,
    pub delete_child: bool,
    pub read_attributes: bool,
    pub write_attributes: bool,
    #[bits(7)]
    reserved0: u8,
    pub delete: bool,
    pub read_control: bool,
    pub write_dac: bool,
    pub write_owner: bool,
    pub synchronize: bool,
    #[bits(3)]
    reserved1: u8,
    pub access_system_security: bool,
    pub maximum_allowed: bool,
    #[bits(2)]
    reserved2: u8,
    pub generic_all: bool,
    pub generic_execute: bool,
    pub generic_write: bool,
    pub generic_read: bool,
}
le_bitfield_conversions!(AccessMask, u32, U32);

impl AccessMask {
    /// File generic-all mapping: [MS-SMB2] §2.2.13.1.1.
    pub const FILE_ALL_ACCESS: Self = Self::new()
        .with_read_data(true)
        .with_write_data(true)
        .with_append_data(true)
        .with_read_ea(true)
        .with_write_ea(true)
        .with_execute(true)
        .with_delete_child(true)
        .with_read_attributes(true)
        .with_write_attributes(true)
        .with_delete(true)
        .with_read_control(true)
        .with_write_dac(true)
        .with_write_owner(true)
        .with_synchronize(true);
    /// File generic-read mapping: [MS-SMB2] §2.2.13.1.1.
    pub const FILE_GENERIC_READ: Self = Self::new()
        .with_read_data(true)
        .with_read_ea(true)
        .with_read_attributes(true)
        .with_read_control(true)
        .with_synchronize(true);
    /// File generic-write mapping: [MS-SMB2] §2.2.13.1.1.
    pub const FILE_GENERIC_WRITE: Self = Self::new()
        .with_write_data(true)
        .with_append_data(true)
        .with_write_ea(true)
        .with_write_attributes(true)
        .with_read_control(true)
        .with_synchronize(true);
    /// File generic-execute mapping: [MS-SMB2] §2.2.13.1.1.
    pub const FILE_GENERIC_EXECUTE: Self = Self::new()
        .with_execute(true)
        .with_read_attributes(true)
        .with_read_control(true)
        .with_synchronize(true);
}

/// ShareAccess: [MS-SMB2] §2.2.13.
#[bitfield(u32, repr = U32, from = U32::new, into = super::u32_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct ShareAccess {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    #[bits(29)]
    reserved: u32,
}
le_bitfield_conversions!(ShareAccess, u32, U32);
impl ShareAccess {
    /// All three specified sharing categories.
    pub const ALL: Self = Self::new()
        .with_read(true)
        .with_write(true)
        .with_delete(true);
    /// Whether the mask contains no undefined sharing bits.
    pub fn is_valid(self) -> bool {
        self.reserved() == 0
    }
}

/// CreateOptions used by the synthetic provider: [MS-SMB2] §2.2.13.
#[bitfield(u32, repr = U32, from = U32::new, into = super::u32_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct CreateOptions {
    pub directory_file: bool,
    pub write_through: bool,
    pub sequential_only: bool,
    pub no_intermediate_buffering: bool,
    pub synchronous_io_alert: bool,
    pub synchronous_io_nonalert: bool,
    pub non_directory_file: bool,
    #[bits(1)]
    other0: u8,
    pub complete_if_oplocked: bool,
    #[bits(3)]
    other1: u8,
    pub delete_on_close: bool,
    #[bits(10)]
    other2: u32,
    pub open_for_free_space_query: bool,
    #[bits(8)]
    other3: u8,
}
le_bitfield_conversions!(CreateOptions, u32, U32);

open_enum! {
    /// CreateDisposition: [MS-SMB2] §2.2.13.
    pub enum CreateDisposition: u32 {
        #![expect(missing_docs, reason = "Names follow the cited CreateDisposition table.")]
        SUPERSEDE = 0, OPEN = 1, CREATE = 2, OPEN_IF = 3, OVERWRITE = 4, OVERWRITE_IF = 5,
    }
}
impl CreateDisposition {
    /// Whether the value names one of the specified dispositions.
    pub fn is_valid(self) -> bool {
        matches!(
            self,
            Self::SUPERSEDE
                | Self::OPEN
                | Self::CREATE
                | Self::OPEN_IF
                | Self::OVERWRITE
                | Self::OVERWRITE_IF
        )
    }
}
open_enum! {
    /// CreateAction: [MS-SMB2] §2.2.14.
    pub enum CreateAction: u32 {
        #![expect(missing_docs, reason = "Names follow the cited CreateAction table.")]
        SUPERSEDED = 0, OPENED = 1, CREATED = 2, OVERWRITTEN = 3,
    }
}
open_enum! {
    /// ImpersonationLevel: [MS-SMB2] §2.2.13.
    pub enum ImpersonationLevel: u32 {
        #![expect(missing_docs, reason = "Names follow the cited ImpersonationLevel table.")]
        ANONYMOUS = 0, IDENTIFICATION = 1, IMPERSONATION = 2, DELEGATE = 3,
    }
}
open_enum! {
    /// Requested/granted oplock level: [MS-SMB2] §§2.2.13–2.2.14.
    #[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
    pub enum OplockLevel: u8 {
        #![expect(missing_docs, reason = "Names follow the cited oplock table.")]
        NONE = 0, LEVEL_II = 1, EXCLUSIVE = 8, BATCH = 9, LEASE = 0xff,
    }
}
open_enum! {
    /// ShareType: [MS-SMB2] §2.2.10.
    #[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
    pub enum ShareType: u8 {
        /// Disk share.
        DISK = 1,
        /// Named-pipe share.
        PIPE = 2,
        /// Printer share.
        PRINT = 3,
    }
}
open_enum! {
    /// Channel: [MS-SMB2] §§2.2.19, 2.2.21.
    pub enum Channel: u32 {
        /// Data is carried in the SMB packet, not a separate RDMA channel.
        NONE = 0,
    }
}
open_enum! {
    /// InfoType: [MS-SMB2] §§2.2.37, 2.2.39.
    #[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
    pub enum InformationType: u8 {
        #![expect(missing_docs, reason = "Names follow the cited InfoType table.")]
        FILE = 1, FILESYSTEM = 2, SECURITY = 3, QUOTA = 4,
    }
}
/// SMB2_SESSION_FLAG_IS_GUEST: [MS-SMB2] §2.2.6.
pub const SESSION_FLAG_IS_GUEST: u16 = 1;

/// Four-byte CREATE context identifiers: [MS-SMB2] §2.2.13.2.
#[repr(transparent)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct CreateContextName(pub [u8; 4]);
impl CreateContextName {
    /// SMB2_CREATE_EA_BUFFER, §2.2.13.2.1.
    pub const EA_BUFFER: Self = Self(*b"ExtA");
    /// SMB2_CREATE_SD_BUFFER, §2.2.13.2.2.
    pub const SECURITY_DESCRIPTOR: Self = Self(*b"SecD");
    /// SMB2_CREATE_DURABLE_HANDLE_REQUEST, §2.2.13.2.3.
    pub const DURABLE_HANDLE_REQUEST: Self = Self(*b"DHnQ");
    /// SMB2_CREATE_DURABLE_HANDLE_RECONNECT, §2.2.13.2.4.
    pub const DURABLE_HANDLE_RECONNECT: Self = Self(*b"DHnC");
    /// SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST, §2.2.13.2.5.
    pub const QUERY_MAXIMAL_ACCESS: Self = Self(*b"MxAc");
    /// SMB2_CREATE_ALLOCATION_SIZE, §2.2.13.2.6.
    pub const ALLOCATION_SIZE: Self = Self(*b"AlSi");
    /// SMB2_CREATE_TIMEWARP_TOKEN, §2.2.13.2.7.
    pub const TIMEWARP: Self = Self(*b"TWrp");
    /// SMB2_CREATE_REQUEST_LEASE, §2.2.13.2.8.
    pub const REQUEST_LEASE: Self = Self(*b"RqLs");
    /// SMB2_CREATE_QUERY_ON_DISK_ID, §2.2.13.2.9.
    pub const QUERY_ON_DISK_ID: Self = Self(*b"QFid");
}

wire!(
/// Synchronous SMB2 header: [MS-SMB2] §2.2.1.2; asynchronous headers are unsupported.
Header, 64 {
    protocol: [u8; 4],
    structure_size: U16,
    credit_charge: U16,
    status: U32,
    command: U16,
    credits: U16,
    flags: HeaderFlags,
    next_command: U32,
    message_id: U64,
    process_id: U32,
    tree_id: U32,
    session_id: U64,
    signature: [u8; 16],
});

wire!(
/// Asynchronous header, replacing ProcessId/TreeId with AsyncId: [MS-SMB2] §2.2.1.1.
AsyncHeader, 64 {
    protocol: [u8; 4],
    structure_size: U16,
    credit_charge: U16,
    status: U32,
    command: U16,
    credits: U16,
    flags: HeaderFlags,
    next_command: U32,
    message_id: U64,
    async_id: U64,
    session_id: U64,
    signature: [u8; 16],
});
wire!(
/// NEGOTIATE request fixed prefix: [MS-SMB2] §2.2.3.
NegotiateRequest, 36, 36 {
    structure_size: U16,
    dialect_count: U16,
    security_mode: SecurityMode,
    reserved: U16,
    capabilities: Capabilities,
    client_guid: [u8; 16],
    reserved2: U64,
});
wire!(
/// NEGOTIATE response fixed prefix: [MS-SMB2] §2.2.4.
NegotiateResponse, 64, 65 {
    structure_size: U16,
    security_mode: SecurityMode,
    dialect: U16,
    reserved: U16,
    server_guid: [u8; 16],
    capabilities: Capabilities,
    max_transact_size: U32,
    max_read_size: U32,
    max_write_size: U32,
    system_time: U64,
    server_start_time: U64,
    security_buffer_offset: U16,
    security_buffer_length: U16,
    reserved2: U32,
});
wire!(
/// SESSION_SETUP request fixed prefix: [MS-SMB2] §2.2.5.
SessionSetupRequest, 24, 25 {
    structure_size: U16,
    flags: SessionSetupFlags,
    security_mode: SessionSecurityMode,
    capabilities: Capabilities,
    channel: U32,
    security_buffer_offset: U16,
    security_buffer_length: U16,
    previous_session_id: U64,
});
wire!(
/// SESSION_SETUP response fixed prefix: [MS-SMB2] §2.2.6.
SessionSetupResponse, 8, 9 {
    structure_size: U16,
    session_flags: U16,
    security_buffer_offset: U16,
    security_buffer_length: U16,
});
wire!(
/// TREE_CONNECT request fixed prefix: [MS-SMB2] §2.2.9.
TreeConnectRequest, 8, 9 {
    structure_size: U16,
    flags: U16,
    path_offset: U16,
    path_length: U16,
});
wire!(
/// TREE_CONNECT response: [MS-SMB2] §2.2.10.
TreeConnectResponse, 16, 16 {
    structure_size: U16,
    share_type: ShareType,
    reserved: u8,
    share_flags: U32,
    capabilities: U32,
    maximal_access: AccessMask,
});
wire!(
/// Shared fixed LOGOFF, TREE_DISCONNECT, FLUSH/LOCK response, ECHO and CANCEL body:
/// [MS-SMB2] §§2.2.7–8, 2.2.11–12, 2.2.18, 2.2.27–30.
SimpleBody, 4, 4 {
    structure_size: U16,
    reserved: U16
});
wire!(
/// CREATE request fixed prefix: [MS-SMB2] §2.2.13.
CreateRequest, 56, 57 {
    structure_size: U16,
    security_flags: u8,
    requested_oplock_level: OplockLevel,
    impersonation_level: U32,
    smb_create_flags: U64,
    reserved: U64,
    desired_access: AccessMask,
    file_attributes: super::fscc::FileAttributes,
    share_access: ShareAccess,
    create_disposition: U32,
    create_options: CreateOptions,
    name_offset: U16,
    name_length: U16,
    contexts_offset: U32,
    contexts_length: U32,
});
wire!(
/// SMB2_FILEID: [MS-SMB2] §2.2.14.1.
FileId, 16 {
    persistent: U64,
    volatile: U64
});
wire!(
/// CREATE response fixed prefix: [MS-SMB2] §2.2.14.
CreateResponse, 88, 89 {
    structure_size: U16,
    oplock_level: OplockLevel,
    flags: u8,
    create_action: U32,
    creation_time: U64,
    last_access_time: U64,
    last_write_time: U64,
    change_time: U64,
    allocation_size: U64,
    end_of_file: U64,
    file_attributes: super::fscc::FileAttributes,
    reserved: U32,
    file_id: FileId,
    contexts_offset: U32,
    contexts_length: U32,
});
wire!(
/// CREATE context container: [MS-SMB2] §2.2.13.2.
CreateContextHeader, 16 {
    next: U32,
    name_offset: U16,
    name_length: U16,
    reserved: U16,
    data_offset: U16,
    data_length: U32,
});
wire!(
/// SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST optional timestamp: [MS-SMB2] §2.2.13.2.5.
MaximalAccessRequest, 8 { timestamp: U64 });
wire!(
/// SMB2_CREATE_DURABLE_HANDLE_REQUEST: [MS-SMB2] §2.2.13.2.3.
DurableHandleRequest, 16 { reserved: [u8; 16] });
wire!(
/// SMB2_CREATE_DURABLE_HANDLE_RECONNECT: [MS-SMB2] §2.2.13.2.4.
DurableHandleReconnect, 16 { file_id: FileId });
wire!(
/// SMB2_CREATE_ALLOCATION_SIZE: [MS-SMB2] §2.2.13.2.6.
AllocationSizeContext, 8 { allocation_size: U64 });
wire!(
/// SMB2_CREATE_TIMEWARP_TOKEN: [MS-SMB2] §2.2.13.2.7.
TimewarpContext, 8 { timestamp: U64 });
wire!(
/// SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE: [MS-SMB2] §2.2.14.2.5.
MaximalAccessResponse, 8 {
    query_status: U32,
    maximal_access: AccessMask,
});
wire!(
/// SMB2_CREATE_QUERY_ON_DISK_ID response: [MS-SMB2] §2.2.14.2.9.
OnDiskIdResponse, 32 {
    file_id: U64,
    volume_id: U64,
    reserved: [u8; 16],
});
wire!(
/// CLOSE request: [MS-SMB2] §2.2.15.
CloseRequest, 24, 24 {
    structure_size: U16,
    flags: CloseFlags,
    reserved: U32,
    file_id: FileId,
});
wire!(
/// CLOSE response: [MS-SMB2] §2.2.16.
CloseResponse, 60, 60 {
    structure_size: U16,
    flags: CloseFlags,
    reserved: U32,
    creation_time: U64,
    last_access_time: U64,
    last_write_time: U64,
    change_time: U64,
    allocation_size: U64,
    end_of_file: U64,
    file_attributes: super::fscc::FileAttributes,
});
wire!(
/// FLUSH request: [MS-SMB2] §2.2.17; reserved fields are not CLOSE flags.
FlushRequest, 24, 24 {
    structure_size: U16, reserved1: U16, reserved2: U32, file_id: FileId
});
wire!(
/// READ request fixed prefix: [MS-SMB2] §2.2.19.
ReadRequest, 48, 49 {
    structure_size: U16,
    padding: u8,
    flags: ReadFlags,
    length: U32,
    offset: U64,
    file_id: FileId,
    minimum_count: U32,
    channel: U32,
    remaining_bytes: U32,
    channel_info_offset: U16,
    channel_info_length: U16,
});
wire!(
/// READ response fixed prefix: [MS-SMB2] §2.2.20.
ReadResponse, 16, 17 {
    structure_size: U16,
    data_offset: u8,
    reserved: u8,
    data_length: U32,
    data_remaining: U32,
    reserved2: U32,
});
wire!(
/// WRITE request fixed prefix: [MS-SMB2] §2.2.21.
WriteRequest, 48, 49 {
    structure_size: U16,
    data_offset: U16,
    length: U32,
    offset: U64,
    file_id: FileId,
    channel: U32,
    remaining_bytes: U32,
    channel_info_offset: U16,
    channel_info_length: U16,
    flags: WriteFlags,
});
wire!(
/// WRITE response: [MS-SMB2] §2.2.22.
WriteResponse, 16, 17 {
    structure_size: U16,
    reserved: U16,
    count: U32,
    remaining: U32,
    channel_info_offset: U16,
    channel_info_length: U16,
});
wire!(
/// LOCK element: [MS-SMB2] §2.2.26.1.
LockElement, 24 {
    offset: U64,
    length: U64,
    flags: LockFlags,
    reserved: U32,
});
wire!(
/// LOCK request through its first element: [MS-SMB2] §2.2.26.
LockRequest, 48, 48 {
    structure_size: U16,
    lock_count: U16,
    lock_sequence: U32,
    file_id: FileId,
    first_lock: LockElement,
});
open_enum! {
    /// SMB-specific FSCTLs: [MS-SMB2] §2.2.31; shared-VHD constants: [MS-RSVD] §2.2.1.
    pub enum FsctlCode: u32 {
        #![expect(missing_docs, reason = "Names follow the cited control-code tables.")]
        DFS_GET_REFERRALS = 0x00060194,
        DFS_GET_REFERRALS_EX = 0x000601b0,
        PIPE_WAIT = 0x00110018,
        QUERY_NETWORK_INTERFACE_INFO = 0x001401fc,
        VALIDATE_NEGOTIATE_INFO = 0x00140204,
        QUERY_SHARED_VIRTUAL_DISK_SUPPORT = 0x00090300,
        SVHDX_SYNC_TUNNEL_REQUEST = 0x00090304,
        SVHDX_ASYNC_TUNNEL_REQUEST = 0x00090364,
    }
}

impl FsctlCode {
    /// These requests address the server/share instead of an open (§3.3.5.15).
    pub fn uses_file(self) -> bool {
        !matches!(
            self,
            Self::DFS_GET_REFERRALS
                | Self::DFS_GET_REFERRALS_EX
                | Self::PIPE_WAIT
                | Self::QUERY_NETWORK_INTERFACE_INFO
                | Self::VALIDATE_NEGOTIATE_INFO
        )
    }
}

/// IOCTL flags: [MS-SMB2] §2.2.31.
#[bitfield(u32, repr = U32, from = U32::new, into = super::u32_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct IoctlFlags {
    pub fsctl: bool,
    #[bits(31)]
    reserved: u32,
}
le_bitfield_conversions!(IoctlFlags, u32, U32);

wire!(
/// IOCTL request fixed prefix: [MS-SMB2] §2.2.31.
IoctlRequest, 56, 57 {
    structure_size: U16,
    reserved: U16,
    control_code: U32,
    file_id: FileId,
    input_offset: U32,
    input_count: U32,
    max_input_response: U32,
    output_offset: U32,
    output_count: U32,
    max_output_response: U32,
    flags: IoctlFlags,
    reserved2: U32,
});
wire!(
/// Oplock break acknowledgment: [MS-SMB2] §2.2.25.1.
OplockBreakAcknowledgement, 24, 24 {
    structure_size: U16,
    oplock_level: OplockLevel,
    reserved: u8,
    reserved2: U32,
    file_id: FileId,
});
wire!(
/// Lease break acknowledgment: [MS-SMB2] §2.2.25.2.
LeaseBreakAcknowledgement, 36, 36 {
    structure_size: U16,
    reserved: U16,
    flags: U32,
    lease_key: [u8; 16],
    lease_state: U32,
    lease_duration: U64,
});
/// Notification scope: [MS-SMB2] §2.2.35.
#[bitfield(u16, repr = U16, from = U16::new, into = super::u16_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct NotifyFlags {
    pub watch_tree: bool,
    #[bits(15)]
    reserved: u16,
}
le_bitfield_conversions!(NotifyFlags, u16, U16);

/// CompletionFilter bits: [MS-SMB2] §2.2.35; unknown bits are ignored (§3.3.5.19).
#[bitfield(u32, repr = U32, from = U32::new, into = super::u32_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct NotifyFilter {
    pub file_name: bool,
    pub dir_name: bool,
    pub attributes: bool,
    pub size: bool,
    pub last_write: bool,
    pub last_access: bool,
    pub creation: bool,
    pub ea: bool,
    pub security: bool,
    pub stream_name: bool,
    pub stream_size: bool,
    pub stream_write: bool,
    #[bits(20)]
    reserved: u32,
}
le_bitfield_conversions!(NotifyFilter, u32, U32);

impl NotifyFilter {
    /// Valid CompletionFilter bits, including optional provider features.
    pub const VALID: u32 = 0x00000fff;
}

wire!(
/// CHANGE_NOTIFY request: [MS-SMB2] §2.2.35.
ChangeNotifyRequest, 32, 32 {
    structure_size: U16,
    flags: NotifyFlags,
    output_buffer_length: U32,
    file_id: FileId,
    completion_filter: NotifyFilter,
    reserved: U32,
});
wire!(
/// QUERY_INFO request fixed prefix: [MS-SMB2] §2.2.37.
QueryInfoRequest, 40, 41 {
    structure_size: U16,
    info_type: InformationType,
    info_class: u8,
    output_buffer_length: U32,
    input_buffer_offset: U16,
    reserved: U16,
    input_buffer_length: U32,
    additional_information: U32,
    flags: U32,
    file_id: FileId,
});
wire!(
/// QUERY_DIRECTORY request fixed prefix: [MS-SMB2] §2.2.33.
QueryDirectoryRequest, 32, 33 {
    structure_size: U16,
    info_class: u8,
    flags: QueryDirectoryFlags,
    file_index: U32,
    file_id: FileId,
    name_offset: U16,
    name_length: U16,
    output_buffer_length: U32,
});
wire!(
/// QUERY_DIRECTORY/CHANGE_NOTIFY/QUERY_INFO prefix: [MS-SMB2] §§2.2.34, 2.2.36, 2.2.38.
BufferResponse, 8, 9 {
    structure_size: U16,
    output_buffer_offset: U16,
    output_buffer_length: U32,
});
wire!(
/// SET_INFO request fixed prefix: [MS-SMB2] §2.2.39.
SetInfoRequest, 32, 33 {
    structure_size: U16,
    info_type: InformationType,
    info_class: u8,
    buffer_length: U32,
    buffer_offset: U16,
    reserved: U16,
    additional_information: U32,
    file_id: FileId,
});
wire!(
/// SET_INFO response: [MS-SMB2] §2.2.40.
SetInfoResponse, 2, 2 { structure_size: U16 });
wire!(
/// ERROR response fixed prefix: [MS-SMB2] §2.2.2.
ErrorResponse, 8, 9 {
    structure_size: U16,
    context_count: u8,
    reserved: u8,
    byte_count: U32,
});

impl Header {
    /// Decode Command without excluding unknown command numbers.
    pub fn command(&self) -> Command {
        Command(self.command.get())
    }

    /// Decode the response NTSTATUS.
    pub fn status(&self) -> Status {
        Status(self.status.get())
    }
}

impl CreateRequest {
    /// Decode CreateDisposition while retaining unknown values for validation.
    pub fn disposition(&self) -> CreateDisposition {
        CreateDisposition(self.create_disposition.get())
    }
}

impl FileId {
    /// Conventional placeholder in related requests: [MS-SMB2] §3.2.4.1.4.
    pub const RELATED: Self = Self {
        persistent: U64::new(u64::MAX),
        volatile: U64::new(u64::MAX),
    };
}
