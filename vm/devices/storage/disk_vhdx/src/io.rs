// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Async file I/O backends for the `vhdx` crate.
//!
//! [`BlockingFile`] implements [`vhdx::AsyncFile`] using `blocking::unblock`
//! and positional I/O (pread/pwrite on Unix, seek_read/seek_write on Windows).
//! No Mutex is needed — `Arc<File>` with positional I/O is inherently safe
//! for concurrent access.

use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use vhdx::AsyncFile;

/// Platform-specific positional read.
#[cfg(unix)]
fn file_read_at(file: &fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, offset)
}

/// Platform-specific positional read.
#[cfg(windows)]
fn file_read_at(file: &fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, offset)
}

/// Platform-specific positional write.
#[cfg(unix)]
fn file_write_at(file: &fs::File, buf: &[u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::write_at(file, buf, offset)
}

/// Platform-specific positional write.
#[cfg(windows)]
fn file_write_at(file: &fs::File, buf: &[u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_write(file, buf, offset)
}

/// Read exactly `buf.len()` bytes at `offset`, looping on short reads.
fn read_exact_at(file: &fs::File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        let n = file_read_at(file, buf, offset)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read"));
        }
        offset += n as u64;
        buf = &mut buf[n..];
    }
    Ok(())
}

/// Write exactly `buf.len()` bytes at `offset`, looping on short writes.
fn write_exact_at(file: &fs::File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        let n = file_write_at(file, buf, offset)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write any bytes",
            ));
        }
        offset += n as u64;
        buf = &buf[n..];
    }
    Ok(())
}

/// A concrete [`AsyncFile`] backed by `Arc<std::fs::File>`.
///
/// Uses positional I/O so no seek state or Mutex is needed. Multiple I/Os
/// can be dispatched concurrently. Each operation runs on the `blocking`
/// crate's thread pool via `blocking::unblock`.
#[derive(Clone)]
pub struct BlockingFile {
    file: Arc<fs::File>,
}

impl BlockingFile {
    /// Wrap an existing open file.
    pub fn new(file: fs::File) -> Self {
        Self {
            file: Arc::new(file),
        }
    }

    /// Open a file at the given path.
    ///
    /// If `read_only`, the file is opened for reading only.
    /// Otherwise, it is opened for reading, writing, and creation.
    pub fn open(path: &Path, read_only: bool) -> io::Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(!read_only)
            .create(!read_only)
            .open(path)?;
        Ok(Self::new(file))
    }

    /// Returns a clone of the inner `Arc<File>`.
    ///
    /// Useful when the caller needs to perform additional file operations
    /// (e.g., data I/O on resolved ranges in the LayerIo implementation).
    pub fn clone_arc(&self) -> Arc<fs::File> {
        self.file.clone()
    }
}

impl AsyncFile for BlockingFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), io::Error> {
        let len = buf.len();
        let file = self.file.clone();
        let data = blocking::unblock(move || {
            let mut buffer = vec![0u8; len];
            read_exact_at(&file, &mut buffer, offset)?;
            Ok::<Vec<u8>, io::Error>(buffer)
        })
        .await?;
        buf.copy_from_slice(&data);
        Ok(())
    }

    async fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), io::Error> {
        let data = buf.to_vec();
        let file = self.file.clone();
        blocking::unblock(move || write_exact_at(&file, &data, offset)).await
    }

    async fn flush(&self) -> Result<(), io::Error> {
        let file = self.file.clone();
        blocking::unblock(move || file.sync_all()).await
    }

    async fn file_size(&self) -> Result<u64, io::Error> {
        Ok(self.file.metadata()?.len())
    }

    async fn set_file_size(&self, size: u64) -> Result<(), io::Error> {
        let file = self.file.clone();
        blocking::unblock(move || file.set_len(size)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pal_async::async_test;

    #[async_test]
    async fn round_trip_read_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");

        // Create file, write data, read back
        let bf = BlockingFile::open(&path, false).unwrap();
        // Set a size
        bf.set_file_size(4096).await.unwrap();

        let write_data = vec![0xAB_u8; 512];
        bf.write_at(0, &write_data).await.unwrap();
        bf.write_at(1024, &write_data).await.unwrap();

        let mut read_buf = vec![0u8; 512];
        bf.read_at(0, &mut read_buf).await.unwrap();
        assert_eq!(read_buf, write_data);

        bf.read_at(1024, &mut read_buf).await.unwrap();
        assert_eq!(read_buf, write_data);

        // Verify gap is zeros
        bf.read_at(512, &mut read_buf).await.unwrap();
        assert_eq!(read_buf, vec![0u8; 512]);

        // Verify file_size
        assert_eq!(bf.file_size().await.unwrap(), 4096);
    }

    #[async_test]
    async fn flush_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        let bf = BlockingFile::open(&path, false).unwrap();
        bf.set_file_size(4096).await.unwrap();
        bf.flush().await.unwrap();
    }

    #[async_test]
    async fn open_with_vhdx() {
        // Create a VHDX in memory, write to disk, open with BlockingFile,
        // validate VhdxFile::open works
        use vhdx::create;
        use vhdx::open::VhdxFile;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vhdx");

        // Step 1: Create via BlockingFile
        let bf = BlockingFile::open(&path, false).unwrap();
        let mut params = create::CreateParams {
            disk_size: 1024 * 1024, // 1 MiB
            ..Default::default()
        };
        create::create(&bf, &mut params).await.unwrap();

        // Step 2: Re-open and validate
        let bf = BlockingFile::open(&path, false).unwrap();
        let vhdx = VhdxFile::open_read_only(bf, false).await.unwrap();
        assert_eq!(vhdx.disk_size(), 1024 * 1024);
        assert_eq!(vhdx.logical_sector_size(), 512);
    }
}
