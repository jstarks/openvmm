// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows-native SMB provider foundation.
//!
//! This increment supports confined ordinary NTFS files, native sharing,
//! metadata, enumeration and data I/O. It grants no SMB caching. Reparse
//! traversal, case-sensitive directories, security mutation, streams, EAs,
//! delete mode, rename, locking and notifications are explicitly unsupported.
//! It is not yet wired to the vSMB device.

#![cfg(windows)]

mod filesystem;
mod io;
mod native;

pub use filesystem::{OpenRootError, WindowsFile, WindowsFs};
