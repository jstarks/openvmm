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
