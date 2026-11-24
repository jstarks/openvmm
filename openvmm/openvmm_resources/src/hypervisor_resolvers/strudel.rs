// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Strudel native-JIT backend resolver.
#![cfg(all(
    target_os = "linux",
    guest_arch = "x86_64",
    guest_is_native,
    feature = "strudel"
))]

use hypervisor_resources::{HypervisorKind, StrudelHandle};
use openvmm_core::hypervisor_backend::ResolvedHypervisorBackend;

/// Constructs the strict native-JIT software partition backend.
pub struct StrudelResolver;

impl vm_resource::ResolveResource<HypervisorKind, StrudelHandle> for StrudelResolver {
    type Output = ResolvedHypervisorBackend;
    type Error = std::convert::Infallible;

    fn resolve(&self, _: StrudelHandle, _: ()) -> Result<Self::Output, Self::Error> {
        Ok(ResolvedHypervisorBackend::new(
            virt_emu::backend::NativeHypervisor,
        ))
    }
}

vm_resource::declare_static_resolver!(StrudelResolver, (HypervisorKind, StrudelHandle),);
