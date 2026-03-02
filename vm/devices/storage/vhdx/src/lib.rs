// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VHDX file format parser and writer.
//!
//! This crate provides types and utilities for working with VHDX virtual hard
//! disk files. It includes on-disk format definitions, error types, CRC-32C
//! checksum helpers, and the [`AsyncFile`] trait for abstracting file I/O.
//!
//! # Modules
//!
//! - [`format`](mod@format) — On-disk structure definitions, constants, and well-known GUIDs.
//! - [`error`] — Error and corruption types.

#![forbid(unsafe_code)]
#![allow(missing_docs)]
#![allow(async_fn_in_trait)]

use std::future::Future;

pub(crate) mod bat;
pub(crate) mod cache;
pub mod create;
pub mod error;
pub(crate) mod flush;
pub mod format;
pub(crate) mod header;
pub mod io;
pub mod io_guard;
pub(crate) mod known_meta;
pub mod locator;
pub(crate) mod log;
pub(crate) mod log_task;
pub(crate) mod metadata;
pub mod open;
pub(crate) mod region;
pub(crate) mod sector_bitmap;
pub(crate) mod space;
pub mod trim;

pub use error::CorruptionType;
pub use error::InvalidFormatReason;
pub use error::VhdxError;
pub use io::ReadRange;
pub use io::WriteRange;
pub use io_guard::ReadIoGuard;
pub use io_guard::WriteIoGuard;
pub use open::VhdxFile;
pub use trim::TrimMode;
pub use trim::TrimRequest;

#[cfg(test)]
mod tests;

/// Trait abstracting file I/O for the VHDX parser.
///
/// All async methods return `Send` futures so that the log task (spawned
/// on a multi-threaded executor) can call them.
///
/// This trait is **not** dyn-compatible due to `impl Future` return types.
/// When dynamic dispatch is needed (e.g. `disk_backend` integration),
/// create a separate dyn-compatible wrapper trait with a blanket impl.
pub trait AsyncFile: Send + Sync {
    /// Read exactly `buf.len()` bytes from the file at the given byte offset.
    fn read_at(
        &self,
        offset: u64,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    /// Write exactly `buf.len()` bytes to the file at the given byte offset.
    fn write_at(
        &self,
        offset: u64,
        buf: &[u8],
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    /// Flush all buffered writes to stable storage.
    fn flush(&self) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    /// Return the current size of the file in bytes.
    fn file_size(&self) -> impl Future<Output = Result<u64, std::io::Error>> + Send;

    /// Set (truncate or extend) the file to the given size in bytes.
    fn set_file_size(&self, size: u64) -> impl Future<Output = Result<(), std::io::Error>> + Send;
}
