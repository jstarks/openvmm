// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hosting VM profile definitions.

use anyhow::Context;
use serde::Deserialize;
use std::path::Path;

/// A hosting VM profile describing the emulated platform and how to run it.
#[derive(Debug, Deserialize)]
pub struct HostingVmProfile {
    /// Emulator configuration.
    pub emulator: EmulatorConfig,
}

/// Emulator-specific configuration, tagged by `type`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum EmulatorConfig {
    /// QEMU TCG emulation.
    QemuTcg(QemuTcgConfig),
}

/// QEMU TCG configuration parsed from the profile.
#[derive(Debug, Deserialize)]
pub struct QemuTcgConfig {
    /// Path or name of the QEMU binary (e.g., "qemu-system-aarch64").
    #[serde(default = "default_qemu_binary")]
    pub binary: String,
    /// Machine type (e.g., "virt,virtualization=on,iommu=smmuv3").
    #[serde(default = "default_machine")]
    pub machine: String,
    /// CPU model (e.g., "max").
    #[serde(default = "default_cpu")]
    pub cpu: String,
    /// Memory size (e.g., "4G").
    #[serde(default = "default_memory")]
    pub memory: String,
    /// Number of CPUs (e.g., "2").
    #[serde(default = "default_smp")]
    pub smp: String,
}

fn default_qemu_binary() -> String {
    "qemu-system-aarch64".to_string()
}
fn default_machine() -> String {
    "virt".to_string()
}
fn default_cpu() -> String {
    "max".to_string()
}
fn default_memory() -> String {
    "4G".to_string()
}
fn default_smp() -> String {
    "2".to_string()
}

impl HostingVmProfile {
    /// Load a profile from a TOML file.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let contents =
            std::fs::read_to_string(path).context("failed to read hosting VM profile")?;
        Self::from_toml(&contents)
    }

    /// Parse a profile from a TOML string.
    pub fn from_toml(toml: &str) -> anyhow::Result<Self> {
        toml_edit::de::from_str(toml).context("failed to parse hosting VM profile")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aarch64_pcie_profile() {
        let toml = r#"
[emulator]
type = "qemu-tcg"
binary = "qemu-system-aarch64"
machine = "virt,virtualization=on,iommu=smmuv3"
cpu = "max"
memory = "4G"
smp = "2"
"#;
        let profile = HostingVmProfile::from_toml(toml).unwrap();
        match &profile.emulator {
            EmulatorConfig::QemuTcg(cfg) => {
                assert_eq!(cfg.machine, "virt,virtualization=on,iommu=smmuv3");
                assert_eq!(cfg.cpu, "max");
            }
        }
    }
}
