// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Artifact resolver for the cloud-hypervisor petri backend.
//!
//! Resolves CH-specific artifacts (the `cloud-hypervisor` binary) and
//! delegates shared artifacts (kernel, initrd, pipette) to the OpenVMM
//! known-paths resolver.

#![forbid(unsafe_code)]

use petri_artifacts_core::AsArtifactHandle;
use petri_artifacts_core::ErasedArtifactHandle;
use std::path::Path;
use std::path::PathBuf;

/// An implementation of [`petri_artifacts_core::ResolveTestArtifact`] for the
/// cloud-hypervisor backend.
///
/// Resolves `CH_BINARY` from the `CH_PATH` environment variable, and
/// delegates all other artifacts (kernel, initrd, pipette, test log
/// directory) to the provided fallback resolver.
pub struct ChKnownPathsResolver<F: petri_artifacts_core::ResolveTestArtifact> {
    fallback: F,
}

impl<F: petri_artifacts_core::ResolveTestArtifact> ChKnownPathsResolver<F> {
    /// Create a new CH artifact resolver with the given fallback for
    /// non-CH-specific artifacts.
    pub fn new(fallback: F) -> Self {
        Self { fallback }
    }
}

impl<F: petri_artifacts_core::ResolveTestArtifact> petri_artifacts_core::ResolveTestArtifact
    for ChKnownPathsResolver<F>
{
    fn resolve(&self, id: ErasedArtifactHandle) -> anyhow::Result<PathBuf> {
        if id == petri_backend_ch::artifacts::CH_BINARY.erase() {
            return ch_binary_path();
        }

        // Delegate to the fallback resolver for everything else
        // (kernel, initrd, pipette, logs, etc.).
        self.fallback.resolve(id)
    }
}

/// Resolve the path to the `cloud-hypervisor` binary.
///
/// Checks, in order:
/// 1. The `CH_PATH` environment variable
/// 2. A sibling `cloud-hypervisor` repo checkout (release build)
/// 3. A sibling `cloud-hypervisor` repo checkout (debug build)
fn ch_binary_path() -> anyhow::Result<PathBuf> {
    // 1. Explicit override via environment variable.
    if let Ok(path) = std::env::var("CH_PATH") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Ok(p);
        }
        anyhow::bail!("CH_PATH is set to '{}' but the file does not exist", path);
    }

    // 2. Try sibling cloud-hypervisor repo checkout.
    // The workspace root for openvmm is typically at the repo root.
    // A sibling cloud-hypervisor checkout would be at
    // `../cloud-hypervisor/target/{release,debug}/cloud-hypervisor`.
    let candidates = [
        // Relative to the openvmm repo root
        "target/release/cloud-hypervisor",
        "target/debug/cloud-hypervisor",
    ];

    // Try to find the repo root by looking for Cargo.toml up from current exe.
    if let Ok(exe) = std::env::current_exe() {
        // Walk up from the exe's directory to find a Cargo.toml with [workspace].
        let mut dir = exe.parent().map(Path::to_path_buf);
        while let Some(d) = dir {
            let cargo_toml = d.join("Cargo.toml");
            if cargo_toml.exists() {
                // Check if there's a sibling cloud-hypervisor checkout.
                if let Some(parent) = d.parent() {
                    let ch_dir = parent.join("cloud-hypervisor");
                    for candidate in &candidates {
                        let full = ch_dir.join(candidate);
                        if full.exists() {
                            return Ok(full);
                        }
                    }
                }
            }
            dir = d.parent().map(Path::to_path_buf);
        }
    }

    anyhow::bail!(
        "Could not find cloud-hypervisor binary. Set CH_PATH or build \
         cloud-hypervisor in a sibling checkout: \
         cd ../cloud-hypervisor && cargo build --release"
    )
}
