// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bounded copied transfers from page-number descriptors.

use guestmem::GuestMemory;
use smb::{
    spec::Status,
    transfer::{Direction, ExternalData},
};
use std::sync::{
    Arc,
    atomic::{AtomicU32, AtomicU64, Ordering},
};

const PAGE_SIZE: usize = 4096;
const MAX_PAGES: usize = smb::MAX_TRANSFER_SIZE / PAGE_SIZE + 1;

#[derive(inspect::Inspect)]
pub(crate) struct GuestData {
    #[inspect(skip)]
    memory: GuestMemory,
    #[inspect(skip)]
    negotiated: Arc<AtomicU32>,
    reads: AtomicU64,
    writes: AtomicU64,
}

impl GuestData {
    pub(crate) fn new(memory: GuestMemory, negotiated: Arc<AtomicU32>) -> Self {
        Self {
            memory,
            negotiated,
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
        }
    }
}

fn ranges(channel: u32, descriptor: &[u8], length: usize) -> Result<Vec<(u64, usize)>, Status> {
    if channel != 2 || descriptor.len() < 8 || length > smb::MAX_TRANSFER_SIZE {
        return Err(Status::INVALID_PARAMETER);
    }
    let pages = u16::from_le_bytes(descriptor[..2].try_into().expect("checked header")) as usize;
    let offset = u16::from_le_bytes(descriptor[2..4].try_into().expect("checked header")) as usize;
    let capacity =
        u32::from_le_bytes(descriptor[4..8].try_into().expect("checked header")) as usize;
    if pages == 0
        || pages > MAX_PAGES
        || offset >= PAGE_SIZE
        || capacity < length
        || capacity > smb::MAX_TRANSFER_SIZE
        || descriptor.len() != 8 + pages * 8
        || offset + capacity > pages * PAGE_SIZE
    {
        return Err(Status::INVALID_PARAMETER);
    }
    let mut remaining = length;
    let mut ranges = Vec::new();
    for (index, bytes) in descriptor[8..].chunks_exact(8).enumerate() {
        let page = u64::from_le_bytes(bytes.try_into().expect("exact chunk"));
        let start = if index == 0 { offset } else { 0 };
        let address = page
            .checked_mul(PAGE_SIZE as u64)
            .and_then(|v| v.checked_add(start as u64))
            .ok_or(Status::INVALID_PARAMETER)?;
        let count = remaining.min(PAGE_SIZE - start);
        if count != 0 {
            ranges.push((address, count));
            remaining -= count;
        }
    }
    if remaining != 0 {
        return Err(Status::INVALID_PARAMETER);
    }
    Ok(ranges)
}

#[async_trait::async_trait]
impl ExternalData for GuestData {
    fn validate(
        &self,
        channel: u32,
        descriptor: &[u8],
        length: usize,
        direction: Direction,
    ) -> Result<(), Status> {
        if self.negotiated.load(Ordering::Acquire) & super::transport::RDMA_V2 == 0 {
            return Err(Status::INVALID_PARAMETER);
        }
        for (address, count) in ranges(channel, descriptor, length)? {
            for point in [address, address + (count as u64 - 1)] {
                let result = match direction {
                    Direction::Read => self.memory.probe_gpa_readable(point),
                    Direction::Write => self.memory.probe_gpa_writable(point),
                };
                if let Err(error) = result {
                    tracelimit::warn_ratelimited!(?error, "invalid vSMB external buffer");
                    return Err(Status::INVALID_PARAMETER);
                }
            }
        }
        Ok(())
    }
    async fn read(
        &self,
        channel: u32,
        descriptor: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, Status> {
        let mut output = vec![0; length];
        let mut offset = 0;
        for (address, count) in ranges(channel, descriptor, length)? {
            self.memory
                .read_at(address, &mut output[offset..offset + count])
                .map_err(|error| {
                    tracelimit::warn_ratelimited!(?error, "vSMB source transfer failed");
                    Status::INVALID_PARAMETER
                })?;
            offset += count;
        }
        self.reads.fetch_add(1, Ordering::Relaxed);
        Ok(output)
    }
    async fn write(&self, channel: u32, descriptor: &[u8], bytes: &[u8]) -> Result<(), Status> {
        let mut offset = 0;
        for (address, count) in ranges(channel, descriptor, bytes.len())? {
            self.memory
                .write_at(address, &bytes[offset..offset + count])
                .map_err(|error| {
                    tracelimit::warn_ratelimited!(?error, "vSMB destination transfer failed");
                    Status::INVALID_PARAMETER
                })?;
            offset += count;
        }
        self.writes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
