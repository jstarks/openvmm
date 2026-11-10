// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows-native SMB provider foundation.
//!
//! This increment supports confined ordinary NTFS files, native sharing,
//! volume/security queries, metadata updates, enumeration, rename/deletion,
//! buffered native notifications, scoped native byte-range locks, allocation
//! and data I/O. It grants no SMB caching. Reparse
//! traversal, case-sensitive directories, security mutation, streams and EAs
//! are explicitly unsupported.
//! The vSMB Windows resource resolver exposes this provider to OpenVMM.
//!
//! Native range locks are the default. Explicit synthetic locking requires the
//! host to promise no mutation outside this provider; it does not enable caching.

#![cfg(windows)]

mod filesystem;
mod io;
mod locking;
mod native;
mod notify;

pub use filesystem::{LockMode, OpenRootError, WindowsFile, WindowsFs};
