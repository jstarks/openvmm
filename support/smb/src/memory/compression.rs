// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bounded LZNT1 chunk bodies: MS-XCA 2.5.1.3 and 2.5.1.4.
//! Chunk framing is retained as metadata rather than charged payload; all-zero
//! units are implicit, as in MS-FSA's compressed zero-data allocation rules.

use crate::spec::Status;
use std::collections::BTreeMap;

pub(super) const CHUNK_SIZE: usize = 4096;

pub(super) struct Chunk {
    compressed: bool,
    bytes: Vec<u8>,
    length: usize,
    encoded_length: usize,
}

pub(super) struct Compressed {
    chunks: BTreeMap<usize, Chunk>,
    length: usize,
    sparse: bool,
    reserved: usize,
    padding: Vec<u8>,
}

impl Compressed {
    pub(super) fn build(
        length: usize,
        maximum_chunks: usize,
        read: impl FnMut(usize, usize) -> Result<Vec<u8>, Status>,
    ) -> Result<Self, Status> {
        let count = length.div_ceil(CHUNK_SIZE);
        if count > maximum_chunks {
            return Err(Status::INSUFFICIENT_RESOURCES);
        }
        Self::build_sparse(length, maximum_chunks, 0..count, read)
    }

    pub(super) fn build_sparse(
        length: usize,
        maximum_chunks: usize,
        indices: impl IntoIterator<Item = usize>,
        mut read: impl FnMut(usize, usize) -> Result<Vec<u8>, Status>,
    ) -> Result<Self, Status> {
        let mut chunks = BTreeMap::new();
        let mut count = 0;
        for index in indices {
            count += 1;
            if count > maximum_chunks {
                return Err(Status::INSUFFICIENT_RESOURCES);
            }
            if index >= length.div_ceil(CHUNK_SIZE) {
                return Err(Status::INTERNAL_ERROR);
            }
            let start = index * CHUNK_SIZE;
            let end = (start + CHUNK_SIZE).min(length);
            let bytes = read(start, end)?;
            if bytes.len() != end - start {
                return Err(Status::INTERNAL_ERROR);
            }
            let chunk = Chunk::encode(&bytes)?;
            if chunk.allocation() != 0 {
                chunks.insert(index, chunk);
            }
        }
        Ok(Self {
            chunks,
            length,
            sparse: false,
            reserved: 0,
            padding: Vec::new(),
        })
    }

    pub(super) fn allocation(&self) -> usize {
        self.chunks.values().map(Chunk::allocation).sum::<usize>() + self.padding.len()
    }

    pub(super) fn length(&self) -> usize {
        self.length
    }
    pub(super) fn count(&self) -> usize {
        self.chunks.len()
    }
    pub(super) fn reservation(&self) -> usize {
        self.reserved
    }

    pub(super) fn sparse(&self) -> bool {
        self.sparse
    }
    pub(super) fn set_sparse(&mut self, sparse: bool) {
        self.sparse = sparse;
    }
    pub(super) fn indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.chunks.keys().copied()
    }
    pub(super) fn ranges(&self) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        if self.reserved != 0 {
            ranges.push((0, self.reserved.min(self.length)));
        }
        for (&index, chunk) in &self.chunks {
            let start = index * CHUNK_SIZE;
            let end = start + chunk.length;
            if let Some((_, previous_end)) = ranges.last_mut() {
                if start <= *previous_end {
                    *previous_end = (*previous_end).max(end);
                    continue;
                }
            }
            ranges.push((start, end));
        }
        ranges
    }

    #[cfg(test)]
    pub(super) fn capacity(&self) -> usize {
        self.chunks
            .values()
            .map(|chunk| chunk.bytes.capacity())
            .sum::<usize>()
            + self.padding.capacity()
    }

    pub(super) fn fill_zero(&mut self) {
        for chunk in self.chunks.values_mut() {
            chunk.fill_zero();
        }
    }

    pub(super) fn reserve(&mut self, length: usize) -> Result<(), Status> {
        let payload: usize = self.chunks.values().map(Chunk::allocation).sum();
        let padding = length.saturating_sub(payload);
        self.padding
            .try_reserve_exact(padding.saturating_sub(self.padding.len()))
            .map_err(|_| Status::INSUFFICIENT_RESOURCES)?;
        self.padding.resize(padding, 0);
        self.padding.shrink_to_fit();
        self.reserved = length;
        Ok(())
    }

    pub(super) fn read(&self, start: usize, end: usize) -> Result<Vec<u8>, Status> {
        if start > end || end > self.length {
            return Err(Status::INTERNAL_ERROR);
        }
        let mut out = Vec::new();
        out.try_reserve_exact(end - start)
            .map_err(|_| Status::INSUFFICIENT_RESOURCES)?;
        if start != end {
            for index in start / CHUNK_SIZE..end.div_ceil(CHUNK_SIZE) {
                let chunk_start = index * CHUNK_SIZE;
                let from = start.saturating_sub(chunk_start);
                let to = (end - chunk_start).min(CHUNK_SIZE);
                if let Some(chunk) = self.chunks.get(&index) {
                    let bytes = chunk.decode()?;
                    out.extend_from_slice(bytes.get(from..to).ok_or(Status::INTERNAL_ERROR)?);
                } else {
                    out.resize(out.len() + to - from, 0);
                }
            }
        }
        Ok(out)
    }
}

fn length_bits(position: usize) -> u32 {
    let mut previous = position.saturating_sub(1);
    let mut bits = 12;
    while previous >= 16 {
        previous >>= 1;
        bits -= 1;
    }
    bits
}

impl Chunk {
    pub(super) fn encode(input: &[u8]) -> Result<Self, Status> {
        if input.is_empty() || input.len() > CHUNK_SIZE {
            return Err(Status::INTERNAL_ERROR);
        }
        if input.iter().all(|&byte| byte == 0) {
            return Ok(Self {
                compressed: true,
                bytes: Vec::new(),
                length: input.len(),
                encoded_length: 0,
            });
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(input.len() + input.len().div_ceil(8))
            .map_err(|_| Status::INSUFFICIENT_RESOURCES)?;
        let mut position = 0;
        while position < input.len() {
            let flag = bytes.len();
            bytes.push(0);
            for bit in 0..8 {
                if position == input.len() {
                    break;
                }
                let maximum =
                    ((1usize << length_bits(position)) - 1 + 3).min(input.len() - position);
                let run = if position == 0 {
                    0
                } else {
                    input[position..position + maximum]
                        .iter()
                        .take_while(|&&byte| byte == input[position - 1])
                        .count()
                };
                if run >= 3 {
                    bytes[flag] |= 1 << bit;
                    bytes.extend_from_slice(&((run - 3) as u16).to_le_bytes());
                    position += run;
                } else {
                    bytes.push(input[position]);
                    position += 1;
                }
            }
        }
        let compressed = bytes.len() < input.len();
        if !compressed {
            bytes.clear();
            bytes.extend_from_slice(input);
        }
        bytes.shrink_to_fit();
        let encoded_length = bytes.len();
        Ok(Self {
            compressed,
            bytes,
            length: input.len(),
            encoded_length,
        })
    }

    pub(super) fn allocation(&self) -> usize {
        self.bytes.len()
    }

    fn fill_zero(&mut self) {
        self.bytes.fill(0);
        self.encoded_length = 0;
        self.compressed = true;
    }

    pub(super) fn decode(&self) -> Result<Vec<u8>, Status> {
        let mut out = Vec::new();
        out.try_reserve_exact(self.length)
            .map_err(|_| Status::INSUFFICIENT_RESOURCES)?;
        if self.encoded_length == 0 {
            out.resize(self.length, 0);
            return Ok(out);
        }
        let bytes = self
            .bytes
            .get(..self.encoded_length)
            .ok_or(Status::INTERNAL_ERROR)?;
        if !self.compressed {
            out.extend_from_slice(bytes);
        } else {
            let mut cursor = 0;
            while cursor < bytes.len() {
                let flags = bytes[cursor];
                cursor += 1;
                for bit in 0..8 {
                    if cursor == bytes.len() {
                        break;
                    }
                    if flags & (1 << bit) == 0 {
                        if out.len() == self.length {
                            return Err(Status::INTERNAL_ERROR);
                        }
                        out.push(bytes[cursor]);
                        cursor += 1;
                    } else {
                        let word = bytes
                            .get(cursor..cursor + 2)
                            .ok_or(Status::INTERNAL_ERROR)?;
                        let word = u16::from_le_bytes([word[0], word[1]]) as usize;
                        cursor += 2;
                        let bits = length_bits(out.len());
                        let distance = (word >> bits) + 1;
                        let length = (word & ((1 << bits) - 1)) + 3;
                        if distance > out.len() || length > self.length.saturating_sub(out.len()) {
                            return Err(Status::INTERNAL_ERROR);
                        }
                        for _ in 0..length {
                            out.push(out[out.len() - distance]);
                        }
                    }
                }
            }
        }
        if out.len() != self.length {
            return Err(Status::INTERNAL_ERROR);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn lznt1_chunk_handles_overlapping_runs_dynamic_lengths_and_raw_fallback() {
        let run = Chunk::encode(&[b'A'; CHUNK_SIZE]).unwrap();
        assert!(run.compressed);
        assert_eq!(run.bytes, [2, b'A', 0xfc, 0x0f]);
        assert_eq!(run.decode().unwrap(), [b'A'; CHUNK_SIZE]);
        let zero = Chunk::encode(&[0; CHUNK_SIZE]).unwrap();
        assert_eq!(zero.allocation(), 0);
        assert_eq!(zero.decode().unwrap(), [0; CHUNK_SIZE]);
        for prefix in [15, 16, 17, 31, 32, 33, 255, 256, 257, 2048, 4093] {
            let mut input: Vec<_> = (0..prefix).map(|i| (i % 251) as u8).collect();
            input.resize(CHUNK_SIZE, 0xee);
            let encoded = Chunk::encode(&input).unwrap();
            assert_eq!(encoded.decode().unwrap(), input);
        }
        let input: Vec<_> = (0..CHUNK_SIZE).map(|i| (i % 251) as u8).collect();
        let raw = Chunk::encode(&input).unwrap();
        assert!(!raw.compressed);
        assert_eq!(raw.decode().unwrap(), input);
    }
}
