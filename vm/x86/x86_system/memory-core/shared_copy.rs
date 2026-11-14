// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{Exchange, PhysicalRam};

#[derive(Debug)]
pub struct CopyError<E> {
    pub completed: usize,
    pub kind: CopyErrorKind<E>,
}

#[derive(Debug)]
pub enum CopyErrorKind<E> {
    Memory(E),
    AddressOverflow,
    Contended,
}

impl<E: core::fmt::Display> core::fmt::Display for CopyError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RAM copy failed after {} bytes: ", self.completed)?;
        match &self.kind {
            CopyErrorKind::Memory(source) => source.fmt(f),
            CopyErrorKind::AddressOverflow => f.write_str("address overflow"),
            CopyErrorKind::Contended => f.write_str("masked store contention"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for CopyError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match &self.kind {
            CopyErrorKind::Memory(source) => Some(source),
            _ => None,
        }
    }
}

fn check_range<E>(address: u64, length: usize) -> Result<(), CopyError<E>> {
    if length != 0
        && u64::try_from(length - 1)
            .ok()
            .and_then(|last| address.checked_add(last))
            .is_none()
    {
        return Err(CopyError {
            completed: 0,
            kind: CopyErrorKind::AddressOverflow,
        });
    }
    Ok(())
}

pub(super) fn read<R: PhysicalRam + ?Sized>(
    ram: &R,
    address: u64,
    destination: &mut [u8],
) -> Result<(), CopyError<R::Error>> {
    check_range(address, destination.len())?;
    let mut completed = 0;
    while completed < destination.len() {
        let current = address + completed as u64;
        let offset = (current % 8) as usize;
        let count = (8 - offset).min(destination.len() - completed);
        let word = ram.read_word(current / 8 * 8).map_err(|source| CopyError {
            completed,
            kind: CopyErrorKind::Memory(source),
        })?;
        destination[completed..completed + count]
            .copy_from_slice(&word.to_le_bytes()[offset..offset + count]);
        completed += count;
    }
    Ok(())
}

pub(super) fn write<R: PhysicalRam + ?Sized>(
    ram: &R,
    address: u64,
    source: &[u8],
) -> Result<(), CopyError<R::Error>> {
    check_range(address, source.len())?;
    let mut completed = 0;
    while completed < source.len() {
        let current = address + completed as u64;
        let offset = (current % 8) as usize;
        let count = (8 - offset).min(source.len() - completed);
        let mut bytes = [0; 8];
        bytes[offset..offset + count].copy_from_slice(&source[completed..completed + count]);
        let value = u64::from_le_bytes(bytes);
        let result = if count == 8 {
            ram.write_word(current, value)
        } else {
            let aligned = current / 8 * 8;
            let mut observed = ram.read_word(aligned).map_err(|source| CopyError {
                completed,
                kind: CopyErrorKind::Memory(source),
            })?;
            let mask = (u64::MAX >> ((8 - count) * 8)) << (offset * 8);
            let mut exchanged = false;
            for _ in 0..64 {
                match ram
                    .compare_exchange_word(aligned, observed, (observed & !mask) | value)
                    .map_err(|source| CopyError {
                        completed,
                        kind: CopyErrorKind::Memory(source),
                    })? {
                    Exchange::Exchanged => {
                        exchanged = true;
                        break;
                    }
                    Exchange::Changed(current) => observed = current,
                }
            }
            if !exchanged {
                return Err(CopyError {
                    completed,
                    kind: CopyErrorKind::Contended,
                });
            }
            Ok(())
        };
        result.map_err(|source| CopyError {
            completed,
            kind: CopyErrorKind::Memory(source),
        })?;
        completed += count;
    }
    Ok(())
}
