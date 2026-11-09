// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Directory-rooted Linux filesystem provider for SMB.
//!
//! File data uses io_uring; operations without usable SQEs use bounded workers.
//! Submitted operations must be retained and drained, including cancellation.
//!
//! The v1 view uses native case lookup and character-projected UTF-8 names.
//! Existing relative symlinks are exposed for client evaluation; absolute
//! traversal is rejected. Security queries describe share policy, not POSIX ACLs.
//! Named streams, guest EAs and Windows-only metadata updates are unsupported.
//! An unavailable native birth time is reported as zero.
//!
//! SMB sharing and byte locks coordinate clients of this provider, not external
//! host processes. Concurrent external namespace changes retain POSIX semantics.
//! No oplocks or leases are granted. Serialization is not supported.

#![cfg(target_os = "linux")]

mod io;
mod names;

mod filesystem;
pub use filesystem::{LinuxFile, LinuxFs, OpenRootError};
