// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Checked packet access and serialization; wire declarations live in `spec`.

use crate::provider::{ExtendedAttribute, validate_ea_name};
use crate::spec::*;
use zerocopy::little_endian::U16;
use zerocopy::{FromBytes, IntoBytes};

fn validate_reparse_tag(tag: u32) -> Result<(), Status> {
    if tag <= 1
        || (tag & 0x40000000 != 0 && tag & 0x80000000 == 0)
        || tag & 0x30000000 == 0x30000000
    {
        return Err(Status::IO_REPARSE_TAG_INVALID);
    }
    Ok(())
}

pub(crate) fn validate_reparse_identity(
    tag: u32,
    guid: Option<[u8; 16]>,
    length: usize,
) -> Result<(), Status> {
    validate_reparse_tag(tag)?;
    if (tag & 0x80000000 == 0) != guid.is_some()
        || guid == Some([0; 16])
        || 8 + usize::from(guid.is_some()) * 16 + length > MAX_REPARSE_DATA_SIZE
    {
        return Err(Status::IO_REPARSE_DATA_INVALID);
    }
    Ok(())
}

pub(crate) fn validate_reparse_data(
    tag: u32,
    guid: Option<[u8; 16]>,
    data: &[u8],
) -> Result<(), Status> {
    validate_reparse_identity(tag, guid, data.len())?;
    let (path, offsets) = if tag == IO_REPARSE_TAG_SYMLINK {
        let (info, path) = SymbolicLinkReparseData::read_from_prefix(data)
            .map_err(|_| Status::IO_REPARSE_DATA_INVALID)?;
        if info.flags.get() > 1 {
            return Err(Status::IO_REPARSE_DATA_INVALID);
        }
        (
            path,
            [
                (
                    info.substitute_name_offset.get(),
                    info.substitute_name_length.get(),
                ),
                (info.print_name_offset.get(), info.print_name_length.get()),
            ],
        )
    } else if tag == IO_REPARSE_TAG_MOUNT_POINT {
        let (info, path) = MountPointReparseData::read_from_prefix(data)
            .map_err(|_| Status::IO_REPARSE_DATA_INVALID)?;
        (
            path,
            [
                (
                    info.substitute_name_offset.get(),
                    info.substitute_name_length.get(),
                ),
                (info.print_name_offset.get(), info.print_name_length.get()),
            ],
        )
    } else {
        return Ok(());
    };
    if offsets[0].1 == 0 {
        return Err(Status::IO_REPARSE_DATA_INVALID);
    }
    for (offset, length) in offsets {
        if offset % 2 != 0 || length % 2 != 0 {
            return Err(Status::IO_REPARSE_DATA_INVALID);
        }
        let name = path
            .get(usize::from(offset)..usize::from(offset) + usize::from(length))
            .ok_or(Status::IO_REPARSE_DATA_INVALID)?;
        let name = decode_name(name).map_err(|_| Status::IO_REPARSE_DATA_INVALID)?;
        if tag == IO_REPARSE_TAG_MOUNT_POINT
            && name.split('\\').any(|part| matches!(part, "." | ".."))
        {
            return Err(Status::IO_REPARSE_DATA_INVALID);
        }
    }
    Ok(())
}

pub(crate) fn decode_reparse_data(
    bytes: &[u8],
    deleting: bool,
) -> Result<(u32, Option<[u8; 16]>, &[u8]), Status> {
    let (header, rest) =
        ReparseDataHeader::read_from_prefix(bytes).map_err(|_| Status::IO_REPARSE_DATA_INVALID)?;
    validate_reparse_tag(header.tag.get())?;
    let (guid, data) = if header.tag.get() & 0x80000000 == 0 {
        let guid = rest.get(..16).ok_or(Status::IO_REPARSE_DATA_INVALID)?;
        (
            Some(
                guid.try_into()
                    .map_err(|_| Status::IO_REPARSE_DATA_INVALID)?,
            ),
            &rest[16..],
        )
    } else {
        (None, rest)
    };
    if data.len() != usize::from(header.data_length.get()) || (deleting && !data.is_empty()) {
        return Err(Status::IO_REPARSE_DATA_INVALID);
    }
    if deleting {
        validate_reparse_identity(header.tag.get(), guid, 0)?;
    } else {
        validate_reparse_data(header.tag.get(), guid, data)?;
    }
    Ok((header.tag.get(), guid, data))
}

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

pub(crate) fn validate_ea_list(mut bytes: &[u8]) -> Result<(), Status> {
    while !bytes.is_empty() {
        let (entry, rest) = FileFullEaInformation::read_from_prefix(bytes)
            .map_err(|_| Status::EA_LIST_INCONSISTENT)?;
        let name = usize::from(entry.name_length);
        let length =
            size_of::<FileFullEaInformation>() + name + 1 + usize::from(entry.value_length.get());
        if rest.get(name) != Some(&0) || bytes.get(..length).is_none() {
            return Err(Status::EA_LIST_INCONSISTENT);
        }
        let next = entry.next_entry_offset.get() as usize;
        if next == 0 {
            return Ok(());
        }
        if next < length || !next.is_multiple_of(4) || next >= bytes.len() {
            return Err(Status::EA_LIST_INCONSISTENT);
        }
        bytes = &bytes[next..];
    }
    Ok(())
}

pub(crate) fn decode_ea_list(mut bytes: &[u8]) -> Result<Vec<ExtendedAttribute>, Status> {
    validate_ea_list(bytes)?;
    let mut entries = Vec::new();
    while !bytes.is_empty() {
        let (entry, rest) = FileFullEaInformation::read_from_prefix(bytes)
            .map_err(|_| Status::EA_LIST_INCONSISTENT)?;
        if entry.flags.into_bits()
            != EaFlags::new()
                .with_need_ea(entry.flags.need_ea())
                .into_bits()
        {
            return Err(Status::INVALID_EA_NAME);
        }
        let name_length = entry.name_length as usize;
        let value_start = name_length + 1;
        let ea = ExtendedAttribute {
            name: rest
                .get(..name_length)
                .ok_or(Status::EA_LIST_INCONSISTENT)?
                .to_vec(),
            value: rest
                .get(value_start..value_start + entry.value_length.get() as usize)
                .ok_or(Status::EA_LIST_INCONSISTENT)?
                .to_vec(),
            need_ea: entry.flags.need_ea(),
        };
        ea.validate()?;
        entries.push(ea);
        if entry.next_entry_offset.get() == 0 {
            break;
        }
        bytes = bytes
            .get(entry.next_entry_offset.get() as usize..)
            .ok_or(Status::EA_LIST_INCONSISTENT)?;
    }
    Ok(entries)
}

pub(crate) fn encode_ea_list(entries: &[ExtendedAttribute]) -> Result<Vec<u8>, Status> {
    let mut out = Vec::new();
    let mut previous = None;
    for entry in entries {
        entry.validate()?;
        if let Some(previous) = previous {
            let start = align_up(out.len(), 4)?;
            out.resize(start, 0);
            FileFullEaInformation::mut_from_prefix(&mut out[previous..])
                .map_err(|_| Status::INTERNAL_ERROR)?
                .0
                .next_entry_offset = ((start - previous) as u32).into();
        }
        previous = Some(out.len());
        out.extend_from_slice(
            FileFullEaInformation {
                next_entry_offset: 0.into(),
                flags: EaFlags::new().with_need_ea(entry.need_ea),
                name_length: entry.name.len() as u8,
                value_length: (entry.value.len() as u16).into(),
            }
            .as_bytes(),
        );
        out.extend_from_slice(&entry.name);
        out.push(0);
        out.extend_from_slice(&entry.value);
    }
    Ok(out)
}

pub(crate) fn decode_ea_names(mut bytes: &[u8]) -> Result<Vec<Vec<u8>>, Status> {
    let mut names = Vec::new();
    while !bytes.is_empty() {
        let (entry, rest) = FileGetEaInformation::read_from_prefix(bytes)
            .map_err(|_| Status::EA_LIST_INCONSISTENT)?;
        let length = entry.name_length as usize;
        if rest.get(length) != Some(&0) {
            return Err(Status::EA_LIST_INCONSISTENT);
        }
        let name = rest.get(..length).ok_or(Status::EA_LIST_INCONSISTENT)?;
        validate_ea_name(name)?;
        names.push(name.to_vec());
        let next = entry.next_entry_offset.get() as usize;
        if next == 0 {
            break;
        }
        if next < size_of::<FileGetEaInformation>() + length + 1
            || !next.is_multiple_of(4)
            || next >= bytes.len()
        {
            return Err(Status::EA_LIST_INCONSISTENT);
        }
        bytes = &bytes[next..];
    }
    Ok(names)
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
