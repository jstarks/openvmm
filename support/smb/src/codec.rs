// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Checked packet access and serialization; wire declarations live in `spec`.

use crate::spec::*;
use zerocopy::little_endian::U16;
use zerocopy::{FromBytes, IntoBytes};

pub(crate) fn decode<T: SmbBody>(bytes: &[u8]) -> Result<T, Status> {
    let (value, _) = T::read_from_prefix(bytes).map_err(|_| Status::INVALID_PARAMETER)?;
    if value.structure_size() != T::STRUCTURE_SIZE {
        return Err(Status::INVALID_PARAMETER);
    }
    Ok(value)
}

pub(crate) fn read_body<T: SmbBody>(packet: &[u8]) -> Result<T, Status> {
    decode(packet.get(HEADER_SIZE..).ok_or(Status::INVALID_PARAMETER)?)
}

pub(crate) const fn body_end<T>() -> usize {
    HEADER_SIZE + size_of::<T>()
}

/// Offsets in SMB2 variable fields are header-relative (MS-SMB2 §2.2).
pub(crate) fn variable<T>(packet: &[u8], offset: usize, length: usize) -> Result<&[u8], Status> {
    field(packet, offset, length, body_end::<T>())
}

pub(crate) fn field(
    packet: &[u8],
    offset: usize,
    length: usize,
    minimum: usize,
) -> Result<&[u8], Status> {
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

pub(crate) fn decode_name(bytes: &[u8]) -> Result<String, Status> {
    let units = <[U16]>::ref_from_bytes(bytes).map_err(|_| Status::INVALID_PARAMETER)?;
    let units: Vec<_> = units.iter().map(|unit| unit.get()).collect();
    let name = String::from_utf16(&units).map_err(|_| Status::OBJECT_NAME_INVALID)?;
    if name.contains('\0') {
        return Err(Status::OBJECT_NAME_INVALID);
    }
    Ok(name)
}

pub(crate) fn encode_name(name: &str) -> Vec<u8> {
    name.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

pub(crate) fn align_up(length: usize, alignment: usize) -> Result<usize, Status> {
    length
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(Status::INVALID_PARAMETER)
}

pub(crate) struct CreateContext<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
}

impl CreateContext<'_> {
    pub fn name(&self) -> Option<CreateContextName> {
        CreateContextName::read_from_bytes(self.name).ok()
    }
}

/// Validate the forward-linked containers specified by MS-SMB2 §2.2.13.2.
pub(crate) fn create_contexts(mut bytes: &[u8]) -> Result<Vec<CreateContext<'_>>, Status> {
    let mut contexts = Vec::new();
    while !bytes.is_empty() {
        let (header, _) =
            CreateContextHeader::read_from_prefix(bytes).map_err(|_| Status::INVALID_PARAMETER)?;
        let next = header.next.get() as usize;
        let length = if next == 0 { bytes.len() } else { next };
        if length < size_of::<CreateContextHeader>()
            || length > bytes.len()
            || (next != 0 && !next.is_multiple_of(CREATE_CONTEXT_ALIGNMENT))
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let entry = &bytes[..length];
        let name_offset = header.name_offset.get() as usize;
        let name_length = header.name_length.get() as usize;
        if name_length < size_of::<CreateContextName>()
            || !name_offset.is_multiple_of(CREATE_CONTEXT_ALIGNMENT)
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let name = field(
            entry,
            name_offset,
            name_length,
            size_of::<CreateContextHeader>(),
        )?;
        let data_length = header.data_length.get() as usize;
        let data_offset = header.data_offset.get() as usize;
        let data = if data_length == 0 {
            &[]
        } else {
            if !data_offset.is_multiple_of(CREATE_CONTEXT_ALIGNMENT) {
                return Err(Status::INVALID_PARAMETER);
            }
            let data = field(
                entry,
                data_offset,
                data_length,
                size_of::<CreateContextHeader>(),
            )?;
            if name_offset < data_offset + data_length && data_offset < name_offset + name_length {
                return Err(Status::INVALID_PARAMETER);
            }
            data
        };
        contexts.push(CreateContext { name, data });
        if next == 0 {
            break;
        }
        bytes = &bytes[next..];
        if bytes.is_empty() {
            return Err(Status::INVALID_PARAMETER);
        }
    }
    Ok(contexts)
}

pub(crate) fn append_create_context(
    out: &mut Vec<u8>,
    previous: &mut Option<usize>,
    name: CreateContextName,
    data: &[u8],
) {
    let start = out.len();
    if let Some(previous) = *previous {
        // This prefix was appended by this encoder, not obtained from a guest.
        let (header, _) = CreateContextHeader::mut_from_prefix(&mut out[previous..])
            .expect("encoded create context");
        header.next = ((start - previous) as u32).into();
    }
    let name_offset = size_of::<CreateContextHeader>();
    let data_offset = (name_offset + size_of::<CreateContextName>() + CREATE_CONTEXT_ALIGNMENT - 1)
        & !(CREATE_CONTEXT_ALIGNMENT - 1);
    out.extend_from_slice(
        CreateContextHeader {
            next: 0.into(),
            name_offset: (name_offset as u16).into(),
            name_length: (size_of::<CreateContextName>() as u16).into(),
            reserved: 0.into(),
            data_offset: if data.is_empty() {
                0.into()
            } else {
                (data_offset as u16).into()
            },
            data_length: (data.len() as u32).into(),
        }
        .as_bytes(),
    );
    out.extend_from_slice(name.as_bytes());
    out.resize(start + data_offset, 0);
    out.extend_from_slice(data);
    out.resize(
        (out.len() + CREATE_CONTEXT_ALIGNMENT - 1) & !(CREATE_CONTEXT_ALIGNMENT - 1),
        0,
    );
    *previous = Some(start);
}
