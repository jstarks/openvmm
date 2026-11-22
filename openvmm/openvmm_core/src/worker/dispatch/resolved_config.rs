// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Source-selected guest configuration needed before destination construction.

use mesh::payload::Protobuf;

#[derive(Debug, Clone, PartialEq, Eq, Protobuf)]
#[mesh(package = "openvmm")]
pub(super) enum ResolvedGicMsi {
    #[mesh(1)]
    Its {
        #[mesh(1)]
        base: u64,
    },
    #[mesh(2)]
    V2m {
        #[mesh(1)]
        base: u64,
        #[mesh(2)]
        spi_base: u32,
        #[mesh(3)]
        spi_count: u32,
    },
}

#[cfg(guest_arch = "aarch64")]
impl ResolvedGicMsi {
    pub(super) const OWNER: &'static str = "platform/gic-msi";
    pub(super) fn capture(
        controller: vm_topology::processor::aarch64::GicMsiController,
    ) -> Option<Self> {
        use vm_topology::processor::aarch64::GicMsiController;
        match controller {
            GicMsiController::Its(info) => Some(Self::Its {
                base: info.its_base,
            }),
            GicMsiController::V2m(info) => Some(Self::V2m {
                base: info.frame_base,
                spi_base: info.spi_base,
                spi_count: info.spi_count,
            }),
            GicMsiController::None => None,
        }
    }

    pub(super) fn apply(
        &self,
        requested: &mut openvmm_defs::config::GicMsiConfig,
    ) -> anyhow::Result<()> {
        use openvmm_defs::config::GicMsiConfig;
        match (&*requested, self) {
            (GicMsiConfig::Auto | GicMsiConfig::Its, Self::Its { .. }) => {
                *requested = GicMsiConfig::Its;
            }
            (
                GicMsiConfig::Auto | GicMsiConfig::V2m { spi_count: None },
                Self::V2m { spi_count, .. },
            ) => {
                *requested = GicMsiConfig::V2m {
                    spi_count: Some(*spi_count),
                };
            }
            (GicMsiConfig::V2m { spi_count: Some(n) }, Self::V2m { spi_count, .. })
                if n == spi_count => {}
            _ => anyhow::bail!(
                "requested GIC MSI configuration {requested:?} conflicts with saved {self:?}"
            ),
        }
        Ok(())
    }
}
#[cfg(all(test, guest_arch = "aarch64"))]
mod tests {
    use super::super::build_aarch64_topology;
    use super::ResolvedGicMsi;
    use openvmm_defs::config::ProcessorTopologyConfig;

    #[test]
    fn auto_msi_restore_across_host_capabilities() {
        let config = ProcessorTopologyConfig {
            proc_count: 1,
            vps_per_socket: None,
            enable_smt: None,
            arch: None,
        };
        let build = |its, saved: Option<&ResolvedGicMsi>| {
            let platform = virt::PlatformInfo {
                platform_gsiv: None,
                supports_gic_v3: true,
                supports_its: its,
                device_assignment_msi_iova: virt::DeviceAssignmentMsiIova::Unsupported,
            };
            let result = build_aarch64_topology(&config, &platform, 0, saved)?;
            Ok::<_, anyhow::Error>(
                ResolvedGicMsi::capture(result.processor_topology.gic_msi()).unwrap(),
            )
        };
        let v2m = build(false, None).unwrap();
        let its = build(true, None).unwrap();
        assert_ne!(v2m, its);
        assert_eq!(build(true, Some(&v2m)).unwrap(), v2m);
        assert!(
            build(false, Some(&its))
                .unwrap_err()
                .to_string()
                .contains("does not support")
        );
    }
}
