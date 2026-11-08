// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resolution for the synthetic vSMB device.

use crate::VsmbDevice;
use vm_resource::{ResolveResource, declare_static_resolver, kind::VmbusDeviceHandleKind};
use vmbus_channel::{
    resources::{ResolveVmbusDeviceHandleParams, ResolvedVmbusDevice},
    simple::SimpleDeviceWrapper,
};
use vsmb_resources::VsmbMemoryDeviceHandle;

/// Resolves a volatile MemoryFs share on the VM executor.
pub struct VsmbResolver;

declare_static_resolver! {
    VsmbResolver,
    (VmbusDeviceHandleKind, VsmbMemoryDeviceHandle),
}

impl ResolveResource<VmbusDeviceHandleKind, VsmbMemoryDeviceHandle> for VsmbResolver {
    type Output = ResolvedVmbusDevice;
    type Error = smb::spec::Status;

    fn resolve(
        &self,
        resource: VsmbMemoryDeviceHandle,
        input: ResolveVmbusDeviceHandleParams<'_>,
    ) -> Result<Self::Output, Self::Error> {
        let driver = input.driver_source.simple();
        let device = VsmbDevice::new(resource.share_name, driver.clone())?;
        Ok(SimpleDeviceWrapper::new(driver, device).into())
    }
}
