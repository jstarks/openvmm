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

/// Resolves directory-backed shares on Linux hosts.
#[cfg(target_os = "linux")]
pub struct VsmbLinuxResolver;

#[cfg(target_os = "linux")]
vm_resource::declare_static_async_resolver! {
    VsmbLinuxResolver,
    (VmbusDeviceHandleKind, vsmb_resources::VsmbLinuxDeviceHandle),
}

/// A directory-backed share could not be configured.
#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
pub enum LinuxResolveError {
    /// Required native I/O or root capture failed.
    #[error("failed to initialize Linux vSMB filesystem")]
    FileSystem(#[from] smb_linux::OpenRootError),
    /// The share configuration is invalid.
    #[error("invalid Linux vSMB share: {0:?}")]
    Share(#[from] smb::spec::Status),
}

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl vm_resource::AsyncResolveResource<VmbusDeviceHandleKind, vsmb_resources::VsmbLinuxDeviceHandle>
    for VsmbLinuxResolver
{
    type Output = ResolvedVmbusDevice;
    type Error = LinuxResolveError;

    async fn resolve(
        &self,
        _resolver: &vm_resource::ResourceResolver,
        resource: vsmb_resources::VsmbLinuxDeviceHandle,
        input: ResolveVmbusDeviceHandleParams<'_>,
    ) -> Result<Self::Output, Self::Error> {
        let driver = input.driver_source.simple();
        let filesystem = smb_linux::LinuxFs::new(
            std::path::Path::new(&resource.root_path),
            std::sync::Arc::new(driver.clone()),
        )
        .await?;
        let device = VsmbDevice::with_filesystem(resource.share_name, driver.clone(), filesystem)?;
        Ok(SimpleDeviceWrapper::new(driver, device).into())
    }
}

/// Resolves directory-backed shares on Windows hosts.
#[cfg(windows)]
pub struct VsmbWindowsResolver;

#[cfg(windows)]
vm_resource::declare_static_async_resolver! {
    VsmbWindowsResolver,
    (VmbusDeviceHandleKind, vsmb_resources::VsmbWindowsDeviceHandle),
}

/// A Windows directory-backed share could not be configured.
#[cfg(windows)]
#[derive(Debug, thiserror::Error)]
pub enum WindowsResolveError {
    /// Native root capture failed.
    #[error("failed to initialize Windows vSMB filesystem")]
    FileSystem(#[from] smb_windows::OpenRootError),
    /// The share configuration is invalid.
    #[error("invalid Windows vSMB share: {0:?}")]
    Share(#[from] smb::spec::Status),
}

#[cfg(windows)]
#[async_trait::async_trait]
impl
    vm_resource::AsyncResolveResource<
        VmbusDeviceHandleKind,
        vsmb_resources::VsmbWindowsDeviceHandle,
    > for VsmbWindowsResolver
{
    type Output = ResolvedVmbusDevice;
    type Error = WindowsResolveError;

    async fn resolve(
        &self,
        _resolver: &vm_resource::ResourceResolver,
        resource: vsmb_resources::VsmbWindowsDeviceHandle,
        input: ResolveVmbusDeviceHandleParams<'_>,
    ) -> Result<Self::Output, Self::Error> {
        let driver = input.driver_source.simple();
        let mode = match resource.lock_mode {
            vsmb_resources::VsmbWindowsLockMode::Native => smb_windows::LockMode::Native,
            vsmb_resources::VsmbWindowsLockMode::Synthetic => smb_windows::LockMode::Synthetic,
        };
        let filesystem = smb_windows::WindowsFs::new_with_lock_mode(
            std::path::Path::new(&resource.root_path),
            std::sync::Arc::new(driver.clone()),
            mode,
        )
        .await?;
        let device = VsmbDevice::with_filesystem(resource.share_name, driver.clone(), filesystem)?;
        Ok(SimpleDeviceWrapper::new(driver, device).into())
    }
}
