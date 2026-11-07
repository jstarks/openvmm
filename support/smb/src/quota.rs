// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SID-based quota framing and per-open enumeration (MS-SMB2 3.3.5.20.4).

use super::*;
use crate::provider::{QuotaInformation, VolumeControlInformation};
use crate::security::Sid;
use zerocopy::little_endian::{I64, U32};

#[repr(C)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
struct QuotaRecord {
    next: U32,
    sid_length: U32,
    changed: I64,
    used: I64,
    threshold: I64,
    limit: I64,
}

fn word(bytes: &[u8], offset: usize) -> Result<u32, Status> {
    U32::read_from_prefix(bytes.get(offset..).ok_or(Status::INVALID_PARAMETER)?)
        .map(|(value, _)| value.get())
        .map_err(|_| Status::INVALID_PARAMETER)
}

pub(super) fn control(bytes: &[u8]) -> Result<VolumeControlInformation, Status> {
    if bytes.len() < 48 {
        return Err(Status::INFO_LENGTH_MISMATCH);
    }
    let unsigned = |offset| {
        zerocopy::little_endian::U64::read_from_prefix(&bytes[offset..])
            .map(|(value, _)| value.get())
            .map_err(|_| Status::INFO_LENGTH_MISMATCH)
    };
    Ok(VolumeControlInformation {
        quota_threshold: unsigned(24)?,
        quota_limit: unsigned(32)?,
        flags: word(bytes, 40)? & 0xf8,
    })
}

pub(super) fn control_bytes(info: VolumeControlInformation) -> Vec<u8> {
    let mut bytes = vec![0; 24];
    bytes.extend_from_slice(&info.quota_threshold.to_le_bytes());
    bytes.extend_from_slice(&info.quota_limit.to_le_bytes());
    bytes.extend_from_slice(&info.flags.to_le_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes
}

pub(super) fn policies(mut bytes: &[u8]) -> Result<Vec<QuotaInformation>, Status> {
    if bytes.is_empty() {
        return Err(Status::INFO_LENGTH_MISMATCH);
    }
    let mut out = Vec::new();
    loop {
        let (record, data) =
            QuotaRecord::read_from_prefix(bytes).map_err(|_| Status::INFO_LENGTH_MISMATCH)?;
        let length = record.sid_length.get() as usize;
        let sid = Sid::decode(data.get(..length).ok_or(Status::INVALID_PARAMETER)?)
            .map_err(|_| Status::INVALID_PARAMETER)?;
        out.push(QuotaInformation {
            sid,
            changed: 0,
            used: 0,
            threshold: record.threshold.get(),
            limit: record.limit.get(),
        });
        let next = record.next.get() as usize;
        if next == 0 {
            return Ok(out);
        }
        if !next.is_multiple_of(8) || next < size_of::<QuotaRecord>() + length {
            return Err(Status::INVALID_PARAMETER);
        }
        bytes = bytes.get(next..).ok_or(Status::INVALID_PARAMETER)?;
        if bytes.is_empty() {
            return Err(Status::INVALID_PARAMETER);
        }
    }
}

impl<B: FileSystem> Connection<B> {
    pub(super) async fn query_quota(
        &self,
        file: &Arc<OpenFile<B::File>>,
        input: &[u8],
        capacity: u32,
        context: &RequestContext,
    ) -> Result<(Status, Vec<u8>), Status> {
        if input.len() > MAX_TRANSFER_SIZE || capacity as usize > MAX_TRANSFER_SIZE {
            return Err(Status::INVALID_PARAMETER);
        }
        let mut cursor = file.quota_cursor.lock().await;
        let entries = self
            .server
            .backend
            .query_quotas(&file.file, context)
            .await?;
        if input.len() < 16 {
            return Err(Status::INVALID_PARAMETER);
        }
        let list_length = word(input, 4)? as usize;
        let start_length = word(input, 8)? as usize;
        let start_offset = word(input, 12)? as usize;
        if entries.len() > MAX_OPENS {
            return Err(Status::INSUFFICIENT_RESOURCES);
        }
        let mut by_sid = BTreeMap::new();
        for entry in entries {
            if entry.used < 0
                || entry.changed < 0
                || entry.threshold < -1
                || entry.limit < -1
                || by_sid
                    .insert(entry.sid.as_bytes().to_vec(), entry)
                    .is_some()
            {
                return Err(Status::INTERNAL_ERROR);
            }
        }
        let sequential = list_length == 0 && start_length == 0 && start_offset == 0;
        let entries: Vec<_> =
            if list_length != 0 {
                let mut list = input[16..]
                    .get(..list_length)
                    .ok_or(Status::INVALID_PARAMETER)?;
                let mut selected = Vec::new();
                loop {
                    let next = word(list, 0)? as usize;
                    let length = word(list, 4)? as usize;
                    let sid = Sid::decode(
                        list.get(8..)
                            .and_then(|data| data.get(..length))
                            .ok_or(Status::INVALID_PARAMETER)?,
                    )
                    .map_err(|_| Status::INVALID_PARAMETER)?;
                    // MS-SMB2 3.3.5.20.4 requires a zero record for an unknown requested SID.
                    selected.push(by_sid.get(sid.as_bytes()).cloned().unwrap_or(
                        QuotaInformation {
                            sid,
                            changed: 0,
                            used: 0,
                            threshold: 0,
                            limit: 0,
                        },
                    ));
                    if next == 0 {
                        break;
                    }
                    if !next.is_multiple_of(4) || next < 8 + length {
                        return Err(Status::INVALID_PARAMETER);
                    }
                    list = list
                        .get(next..)
                        .filter(|list| !list.is_empty())
                        .ok_or(Status::INVALID_PARAMETER)?;
                }
                selected
            } else if start_length != 0 {
                let sid = Sid::decode(
                    input[16..]
                        .get(start_offset..)
                        .and_then(|data| data.get(..start_length))
                        .ok_or(Status::INVALID_PARAMETER)?,
                )
                .map_err(|_| Status::INVALID_PARAMETER)?;
                by_sid
                    .into_values()
                    .filter(|entry| entry.sid.as_bytes() > sid.as_bytes())
                    .collect()
            } else {
                if start_offset != 0 || input.len() != 16 {
                    return Err(Status::INVALID_PARAMETER);
                }
                if input[1] != 0 {
                    *cursor = 0;
                }
                by_sid.into_values().skip(*cursor).collect()
            };
        if entries.is_empty() {
            return Ok((
                Status::NO_MORE_ENTRIES,
                BufferResponse {
                    structure_size: BufferResponse::STRUCTURE_SIZE.into(),
                    output_buffer_offset: 0.into(),
                    output_buffer_length: 0.into(),
                }
                .as_bytes()
                .to_vec(),
            ));
        }
        let mut bytes = Vec::new();
        let mut previous: Option<usize> = None;
        let mut count = 0;
        for entry in entries {
            let offset = (bytes.len() + 7) & !7;
            let length = size_of::<QuotaRecord>() + entry.sid.as_bytes().len();
            if offset + length > capacity as usize {
                break;
            }
            if let Some(previous) = previous {
                bytes[previous..previous + 4]
                    .copy_from_slice(&((offset - previous) as u32).to_le_bytes());
            }
            bytes.resize(offset, 0);
            bytes.extend_from_slice(
                QuotaRecord {
                    next: 0.into(),
                    sid_length: (entry.sid.as_bytes().len() as u32).into(),
                    changed: entry.changed.into(),
                    used: entry.used.into(),
                    threshold: entry.threshold.into(),
                    limit: entry.limit.into(),
                }
                .as_bytes(),
            );
            bytes.extend_from_slice(entry.sid.as_bytes());
            previous = Some(offset);
            count += 1;
            if input[0] != 0 {
                break;
            }
        }
        if count == 0 {
            return Err(Status::BUFFER_TOO_SMALL);
        }
        if sequential {
            *cursor += count;
        }
        buffer_response(bytes, capacity).map(|body| (Status::SUCCESS, body))
    }
}
