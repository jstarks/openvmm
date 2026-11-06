// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Byte-granular dense and sparse backing, independent of logical EOF.

use crate::provider::ByteRange;
use crate::spec::Status;
use std::collections::BTreeMap;

pub(super) enum Data {
    Dense(Vec<u8>),
    Sparse(BTreeMap<usize, Vec<u8>>),
}

impl Default for Data {
    fn default() -> Self {
        Self::Dense(Vec::new())
    }
}

fn zeros(length: usize) -> Result<Vec<u8>, Status> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Status::INSUFFICIENT_RESOURCES)?;
    bytes.resize(length, 0);
    Ok(bytes)
}

impl Data {
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Dense(bytes) => bytes.len(),
            Self::Sparse(extents) => extents.values().map(Vec::len).sum(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(super) fn is_sparse(&self) -> bool {
        matches!(self, Self::Sparse(_))
    }

    pub(super) fn extent_count(&self) -> usize {
        match self {
            Self::Dense(_) => 0,
            Self::Sparse(extents) => extents.len(),
        }
    }

    pub(super) fn span(&self) -> usize {
        match self {
            Self::Dense(bytes) => bytes.len(),
            Self::Sparse(extents) => extents
                .last_key_value()
                .map_or(0, |(start, bytes)| start + bytes.len()),
        }
    }

    pub(super) fn read(&self, start: usize, end: usize) -> Result<Vec<u8>, Status> {
        let mut out = zeros(end - start)?;
        match self {
            Self::Dense(bytes) => {
                out.copy_from_slice(bytes.get(start..end).ok_or(Status::INTERNAL_ERROR)?)
            }
            Self::Sparse(extents) => {
                for (&offset, bytes) in extents.range(..end) {
                    let from = offset.max(start);
                    let to = (offset + bytes.len()).min(end);
                    if from < to {
                        out[from - start..to - start]
                            .copy_from_slice(&bytes[from - offset..to - offset]);
                    }
                }
            }
        }
        Ok(out)
    }

    pub(super) fn allocate(&mut self, length: usize) -> Result<(), Status> {
        match self {
            Self::Dense(bytes) => {
                if length > bytes.len() {
                    bytes
                        .try_reserve_exact(length - bytes.len())
                        .map_err(|_| Status::INSUFFICIENT_RESOURCES)?;
                }
                bytes.resize(length, 0);
                bytes.shrink_to_fit();
            }
            Self::Sparse(_) => {
                let mut bytes = zeros(length)?;
                let count = self.span().min(length);
                bytes[..count].copy_from_slice(&self.read(0, count)?);
                *self = Self::Sparse(if length == 0 {
                    BTreeMap::new()
                } else {
                    BTreeMap::from([(0, bytes)])
                });
            }
        }
        Ok(())
    }

    pub(super) fn set_sparse(
        &mut self,
        sparse: bool,
        logical_size: usize,
        limit: usize,
        maximum_extents: usize,
    ) -> Result<(), Status> {
        if sparse == self.is_sparse() {
            return Ok(());
        }
        if sparse {
            let Self::Dense(bytes) = self else {
                return Err(Status::INTERNAL_ERROR);
            };
            if !bytes.is_empty() && maximum_extents == 0 {
                return Err(Status::INSUFFICIENT_RESOURCES);
            }
            let bytes = std::mem::take(bytes);
            *self = Self::Sparse(if bytes.is_empty() {
                BTreeMap::new()
            } else {
                BTreeMap::from([(0, bytes)])
            });
        } else {
            let length = self.span().max(logical_size);
            if length > limit {
                return Err(Status::DISK_FULL);
            }
            let mut bytes = zeros(length)?;
            let count = self.span();
            bytes[..count].copy_from_slice(&self.read(0, count)?);
            *self = Self::Dense(bytes);
        }
        Ok(())
    }

    pub(super) fn truncate_sparse(&mut self, length: usize) {
        if let Self::Sparse(extents) = self {
            extents.retain(|&start, bytes| {
                if start >= length {
                    return false;
                }
                bytes.truncate(bytes.len().min(length - start));
                bytes.shrink_to_fit();
                true
            });
        }
    }

    pub(super) fn fill(&mut self, value: u8) {
        match self {
            Self::Dense(bytes) => bytes.fill(value),
            Self::Sparse(extents) => extents.values_mut().for_each(|bytes| bytes.fill(value)),
        }
    }

    pub(super) fn write(
        &mut self,
        start: usize,
        input: &[u8],
        limit: usize,
        maximum_extents: usize,
    ) -> Result<(), Status> {
        let end = start.checked_add(input.len()).ok_or(Status::DISK_FULL)?;
        match self {
            Self::Dense(bytes) => {
                if bytes.len().max(end) > limit {
                    return Err(Status::DISK_FULL);
                }
                if end > bytes.len() {
                    self.allocate(end)?;
                }
                let Self::Dense(bytes) = self else {
                    return Err(Status::INTERNAL_ERROR);
                };
                bytes[start..end].copy_from_slice(input);
            }
            Self::Sparse(extents) => {
                let touched: Vec<_> = extents
                    .range(..=end)
                    .filter(|(offset, bytes)| **offset + bytes.len() >= start)
                    .map(|(&offset, bytes)| (offset, bytes.len()))
                    .collect();
                if extents.len() - touched.len() + 1 > maximum_extents {
                    return Err(Status::INSUFFICIENT_RESOURCES);
                }
                let from = touched
                    .first()
                    .map_or(start, |(offset, _)| start.min(*offset));
                let to = touched
                    .last()
                    .map_or(end, |(offset, length)| end.max(offset + length));
                let old: usize = extents.values().map(Vec::len).sum();
                let removed: usize = touched.iter().map(|(_, length)| length).sum();
                let allocation = old
                    .checked_sub(removed)
                    .and_then(|n| n.checked_add(to - from))
                    .ok_or(Status::DISK_FULL)?;
                if allocation > limit {
                    return Err(Status::DISK_FULL);
                }
                let mut bytes = zeros(to - from)?;
                for &(offset, _) in &touched {
                    let old = &extents[&offset];
                    bytes[offset - from..offset - from + old.len()].copy_from_slice(old);
                }
                bytes[start - from..end - from].copy_from_slice(input);
                for (offset, _) in touched {
                    extents.remove(&offset);
                }
                extents.insert(from, bytes);
            }
        }
        Ok(())
    }

    pub(super) fn zero(
        &mut self,
        start: usize,
        end: usize,
        maximum_extents: usize,
    ) -> Result<(), Status> {
        match self {
            Self::Dense(bytes) => bytes
                .get_mut(start..end)
                .ok_or(Status::INTERNAL_ERROR)?
                .fill(0),
            Self::Sparse(extents) => {
                let touched: Vec<_> = extents
                    .range(..end)
                    .filter(|(offset, bytes)| **offset + bytes.len() > start)
                    .map(|(&offset, _)| offset)
                    .collect();
                let mut fragments = Vec::new();
                for &offset in &touched {
                    let bytes = &extents[&offset];
                    for (from, to) in [
                        (offset, start.min(offset + bytes.len())),
                        (end.max(offset), offset + bytes.len()),
                    ] {
                        if from < to {
                            let mut fragment = zeros(to - from)?;
                            fragment.copy_from_slice(&bytes[from - offset..to - offset]);
                            fragments.push((from, fragment));
                        }
                    }
                }
                if extents.len() - touched.len() + fragments.len() > maximum_extents {
                    return Err(Status::INSUFFICIENT_RESOURCES);
                }
                for offset in touched {
                    extents.remove(&offset);
                }
                extents.extend(fragments);
            }
        }

        Ok(())
    }

    pub(super) fn ranges(&self, range: ByteRange, maximum: usize) -> (Vec<ByteRange>, bool) {
        if range.length == 0 || self.is_empty() {
            return (Vec::new(), false);
        }
        match self {
            Self::Dense(_) => (vec![range], false),
            Self::Sparse(extents) => {
                let end = range.offset + range.length;
                let mut ranges = Vec::new();
                for (&offset, bytes) in extents {
                    let start = (offset as u64).max(range.offset);
                    let to = (offset as u64 + bytes.len() as u64).min(end);
                    if start < to {
                        if ranges.len() == maximum {
                            return (ranges, true);
                        }
                        ranges.push(ByteRange {
                            offset: start,
                            length: to - start,
                        });
                    }
                }
                (ranges, false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn extent_budget_failures_leave_writes_and_hole_punches_unchanged() {
        let mut data = Data::default();
        data.set_sparse(true, 0, 32, 2).unwrap();
        data.write(0, b"AAAA", 32, 2).unwrap();
        data.write(8, b"BBBB", 32, 2).unwrap();
        let original = data.read(0, 12).unwrap();
        assert_eq!(data.zero(1, 2, 2), Err(Status::INSUFFICIENT_RESOURCES));
        assert_eq!(
            data.write(6, b"x", 32, 2),
            Err(Status::INSUFFICIENT_RESOURCES)
        );
        assert_eq!(data.read(0, 12).unwrap(), original);
        assert_eq!(data.len(), 8);
        data.write(4, b"CCCC", 32, 2).unwrap();
        assert_eq!(data.read(0, 12).unwrap(), b"AAAACCCCBBBB");
        data.zero(1, 11, 2).unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(data.read(0, 12).unwrap(), b"A\0\0\0\0\0\0\0\0\0\0B");
    }
}
