// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SMB 2.1 wire structures from [MS-SMB2] section 2.2.

#![expect(missing_docs)] // Fields and constants follow the protocol specification.

use open_enum::open_enum;
use zerocopy::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const HEADER_SIZE: usize = 64;
pub const MAX_TRANSFER_SIZE: usize = 1024 * 1024;
pub const MAX_MESSAGE_SIZE: usize = MAX_TRANSFER_SIZE + 1024;
pub const FLAG_SERVER_TO_REDIR: u32 = 1;
pub const FLAG_ASYNC: u32 = 2;
pub const FLAG_RELATED: u32 = 4;
pub const FLAG_SIGNED: u32 = 8;
pub const DIALECT_210: u16 = 0x0210;

open_enum! {
    pub enum Command: u16 {
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
    pub enum Status: u32 {
        SUCCESS = 0,
        CANCELLED = 0xc0000120,
        BUFFER_OVERFLOW = 0x80000005,
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
        SHARING_VIOLATION = 0xc0000043,
        DELETE_PENDING = 0xc0000056,
        DISK_FULL = 0xc000007f,
        INSUFFICIENT_RESOURCES = 0xc000009a,
        FILE_IS_A_DIRECTORY = 0xc00000ba,
        NOT_SUPPORTED = 0xc00000bb,
        BAD_NETWORK_NAME = 0xc00000cc,
        DIRECTORY_NOT_EMPTY = 0xc0000101,
        NOT_A_DIRECTORY = 0xc0000103,
        NAME_TOO_LONG = 0xc0000106,
        FILE_CLOSED = 0xc0000128,
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

macro_rules! wire {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[repr(C)]
        #[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct $name { $(pub $field: $ty),* }
    };
}

wire!(Header {
    protocol: [u8; 4],
    structure_size: U16,
    credit_charge: U16,
    status: U32,
    command: U16,
    credits: U16,
    flags: U32,
    next_command: U32,
    message_id: U64,
    process_id: U32,
    tree_id: U32,
    session_id: U64,
    signature: [u8; 16],
});

wire!(NegotiateRequest {
    structure_size: U16,
    dialect_count: U16,
    security_mode: U16,
    reserved: U16,
    capabilities: U32,
    client_guid: [u8; 16],
    reserved2: U64,
});
wire!(NegotiateResponse {
    structure_size: U16,
    security_mode: U16,
    dialect: U16,
    reserved: U16,
    server_guid: [u8; 16],
    capabilities: U32,
    max_transact_size: U32,
    max_read_size: U32,
    max_write_size: U32,
    system_time: U64,
    server_start_time: U64,
    security_buffer_offset: U16,
    security_buffer_length: U16,
    reserved2: U32,
});
wire!(SessionSetupRequest {
    structure_size: U16,
    flags: u8,
    security_mode: u8,
    capabilities: U32,
    channel: U32,
    security_buffer_offset: U16,
    security_buffer_length: U16,
    previous_session_id: U64,
});
wire!(SessionSetupResponse {
    structure_size: U16,
    session_flags: U16,
    security_buffer_offset: U16,
    security_buffer_length: U16,
});
wire!(TreeConnectRequest {
    structure_size: U16,
    flags: U16,
    path_offset: U16,
    path_length: U16,
});
wire!(TreeConnectResponse {
    structure_size: U16,
    share_type: u8,
    reserved: u8,
    share_flags: U32,
    capabilities: U32,
    maximal_access: U32,
});
wire!(SimpleBody {
    structure_size: U16,
    reserved: U16
});
wire!(CreateRequest {
    structure_size: U16,
    security_flags: u8,
    requested_oplock_level: u8,
    impersonation_level: U32,
    smb_create_flags: U64,
    reserved: U64,
    desired_access: U32,
    file_attributes: U32,
    share_access: U32,
    create_disposition: U32,
    create_options: U32,
    name_offset: U16,
    name_length: U16,
    contexts_offset: U32,
    contexts_length: U32,
});
wire!(FileId {
    persistent: U64,
    volatile: U64
});
wire!(CreateResponse {
    structure_size: U16,
    oplock_level: u8,
    flags: u8,
    create_action: U32,
    creation_time: U64,
    last_access_time: U64,
    last_write_time: U64,
    change_time: U64,
    allocation_size: U64,
    end_of_file: U64,
    file_attributes: U32,
    reserved: U32,
    file_id: FileId,
    contexts_offset: U32,
    contexts_length: U32,
});
wire!(CloseRequest {
    structure_size: U16,
    flags: U16,
    reserved: U32,
    file_id: FileId,
});
wire!(CloseResponse {
    structure_size: U16,
    flags: U16,
    reserved: U32,
    creation_time: U64,
    last_access_time: U64,
    last_write_time: U64,
    change_time: U64,
    allocation_size: U64,
    end_of_file: U64,
    file_attributes: U32,
});
wire!(ReadRequest {
    structure_size: U16,
    padding: u8,
    flags: u8,
    length: U32,
    offset: U64,
    file_id: FileId,
    minimum_count: U32,
    channel: U32,
    remaining_bytes: U32,
    channel_info_offset: U16,
    channel_info_length: U16,
});
wire!(ReadResponse {
    structure_size: U16,
    data_offset: u8,
    reserved: u8,
    data_length: U32,
    data_remaining: U32,
    reserved2: U32,
});
wire!(WriteRequest {
    structure_size: U16,
    data_offset: U16,
    length: U32,
    offset: U64,
    file_id: FileId,
    channel: U32,
    remaining_bytes: U32,
    channel_info_offset: U16,
    channel_info_length: U16,
    flags: U32,
});
wire!(WriteResponse {
    structure_size: U16,
    reserved: U16,
    count: U32,
    remaining: U32,
    channel_info_offset: U16,
    channel_info_length: U16,
});
wire!(QueryInfoRequest {
    structure_size: U16,
    info_type: u8,
    info_class: u8,
    output_buffer_length: U32,
    input_buffer_offset: U16,
    reserved: U16,
    input_buffer_length: U32,
    additional_information: U32,
    flags: U32,
    file_id: FileId,
});
wire!(QueryDirectoryRequest {
    structure_size: U16,
    info_class: u8,
    flags: u8,
    file_index: U32,
    file_id: FileId,
    name_offset: U16,
    name_length: U16,
    output_buffer_length: U32,
});
wire!(BufferResponse {
    structure_size: U16,
    output_buffer_offset: U16,
    output_buffer_length: U32,
});
wire!(SetInfoRequest {
    structure_size: U16,
    info_type: u8,
    info_class: u8,
    buffer_length: U32,
    buffer_offset: U16,
    reserved: U16,
    additional_information: U32,
    file_id: FileId,
});
wire!(ErrorResponse {
    structure_size: U16,
    context_count: u8,
    reserved: u8,
    byte_count: U32,
});

/// Read a fixed structure without assuming guest-provided alignment.
pub fn decode<T: FromBytes + IntoBytes + KnownLayout + Immutable>(
    bytes: &[u8],
    structure_size: u16,
) -> Result<T, Status> {
    let (value, _) = T::read_from_prefix(bytes).map_err(|_| Status::INVALID_PARAMETER)?;
    if bytes.get(..2) != Some(structure_size.to_le_bytes().as_slice()) {
        return Err(Status::INVALID_PARAMETER);
    }
    Ok(value)
}

/// Get a variable field whose offset is relative to the SMB header.
pub fn field(packet: &[u8], offset: usize, length: usize, minimum: usize) -> Result<&[u8], Status> {
    if length == 0 {
        return Ok(&[]);
    }
    if offset < minimum {
        return Err(Status::INVALID_PARAMETER);
    }
    let end = offset
        .checked_add(length)
        .ok_or(Status::INVALID_PARAMETER)?;
    packet.get(offset..end).ok_or(Status::INVALID_PARAMETER)
}

/// Decode a length-delimited UTF-16LE string.
pub fn decode_name(bytes: &[u8]) -> Result<String, Status> {
    if !bytes.len().is_multiple_of(2) {
        return Err(Status::INVALID_PARAMETER);
    }
    let units: Vec<_> = bytes
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    let name = String::from_utf16(&units).map_err(|_| Status::OBJECT_NAME_INVALID)?;
    if name.contains('\0') {
        return Err(Status::OBJECT_NAME_INVALID);
    }
    Ok(name)
}

/// Encode a length-delimited UTF-16LE string.
pub fn encode_name(name: &str) -> Vec<u8> {
    name.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
