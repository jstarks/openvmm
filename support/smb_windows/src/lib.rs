// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows-native SMB provider foundation.
//!
//! This increment supports confined ordinary NTFS files, native sharing,
//! volume/security queries, metadata updates, enumeration, rename/deletion,
//! buffered native notifications, allocation and data I/O. It grants no SMB caching. Reparse
//! traversal, case-sensitive directories, security mutation, streams, EAs,
//! and locking are explicitly unsupported.
//! It is not yet wired to the vSMB device.

#![cfg(windows)]

mod filesystem;
mod io;
mod native;
mod notify;

pub use filesystem::{OpenRootError, WindowsFile, WindowsFs};
