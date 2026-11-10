// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resources for a synthetic vSMB share.

#![forbid(unsafe_code)]

use mesh::MeshPayload;
use vm_resource::{ResourceId, kind::VmbusDeviceHandleKind};

/// A writable, volatile in-memory share over vSMB.
#[derive(MeshPayload)]
pub struct VsmbMemoryDeviceHandle {
    /// SMB share name.
    pub share_name: String,
}

impl ResourceId<VmbusDeviceHandleKind> for VsmbMemoryDeviceHandle {
    const ID: &'static str = "vsmb-memory";
}

/// A writable directory-rooted share on a Linux host.
#[derive(MeshPayload)]
pub struct VsmbLinuxDeviceHandle {
    /// SMB share name.
    pub share_name: String,
    /// Host directory captured when the device is resolved.
    pub root_path: String,
}

impl ResourceId<VmbusDeviceHandleKind> for VsmbLinuxDeviceHandle {
    const ID: &'static str = "vsmb-linux";
}

/// Windows host coordination policy; neither choice enables guest caching.
#[derive(MeshPayload)]
pub enum VsmbWindowsLockMode {
    /// Coordinate byte-range locks with independent native host opens.
    Native,
    /// The host promises not to mutate files outside the SMB server.
    Synthetic,
}

/// A writable ordinary-NTFS directory share on a Windows host.
#[derive(MeshPayload)]
pub struct VsmbWindowsDeviceHandle {
    /// SMB share name.
    pub share_name: String,
    /// Host directory captured when the device is resolved.
    pub root_path: String,
    /// Explicit coordination policy for every open of this provider instance.
    pub lock_mode: VsmbWindowsLockMode,
}

impl ResourceId<VmbusDeviceHandleKind> for VsmbWindowsDeviceHandle {
    const ID: &'static str = "vsmb-windows";
}
