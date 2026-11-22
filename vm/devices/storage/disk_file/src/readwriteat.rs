// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helpers for doing IO at a given offset.

use std::fs;
use std::io::Result;

/// A unified extension trait for [`std::fs::File`] for reading/writing at a
/// given offset.
///
/// The semantics are slightly different between Windows and Unix--on Windows,
/// each operation updates the current file pointer, whereas on Unix it does
/// not.
pub trait ReadWriteAt {
    fn write_at(&self, buf: &[u8], offset: u64) -> Result<usize>;
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize>;

    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> Result<()> {
        while !buf.is_empty() {
            match self.read_at(buf, offset) {
                Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset = offset
                        .checked_add(n as u64)
                        .ok_or(std::io::ErrorKind::InvalidInput)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
impl ReadWriteAt for fs::File {
    fn write_at(&self, buf: &[u8], offset: u64) -> Result<usize> {
        std::os::windows::fs::FileExt::seek_write(self, buf, offset)
    }
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        std::os::windows::fs::FileExt::seek_read(self, buf, offset)
    }
}

#[cfg(unix)]
impl ReadWriteAt for fs::File {
    fn write_at(&self, buf: &[u8], offset: u64) -> Result<usize> {
        std::os::unix::fs::FileExt::write_at(self, buf, offset)
    }

    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        std::os::unix::fs::FileExt::read_at(self, buf, offset)
    }
}
