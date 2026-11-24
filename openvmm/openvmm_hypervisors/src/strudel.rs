// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Explicit-only Strudel software backend.
#![cfg(all(
    target_os = "linux",
    guest_arch = "x86_64",
    guest_is_native,
    feature = "strudel"
))]

use hypervisor_resources::{HypervisorKind, HypervisorProbe, StrudelHandle};
use vm_resource::{IntoResource, Resource};

/// User-selected software execution, never a fallback for missing hardware.
pub struct StrudelProbe;

impl HypervisorProbe for StrudelProbe {
    fn name(&self) -> &str {
        "strudel"
    }

    fn try_new_resource(&self) -> anyhow::Result<Option<Resource<HypervisorKind>>> {
        Ok(None)
    }

    fn new_resource(&self, params: &[(&str, &str)]) -> anyhow::Result<Resource<HypervisorKind>> {
        if let Some((key, _)) = params.first() {
            anyhow::bail!("unknown strudel parameter: {key}");
        }
        Ok(StrudelHandle.into_resource())
    }
}
