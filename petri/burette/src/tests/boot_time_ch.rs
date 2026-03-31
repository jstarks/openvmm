// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cloud-hypervisor boot time performance test.
//!
//! Same methodology as the OpenVMM boot_time test: measures the time from
//! VM launch to pipette agent readiness using Linux direct boot. Uses cold
//! mode: a fresh VM is booted for each iteration.

use crate::report::MetricResult;
use anyhow::Context as _;
use petri_artifacts_common::tags::MachineArch;

fn arch() -> MachineArch {
    MachineArch::host()
}

/// Build the firmware configuration for CH Linux direct boot.
fn build_firmware(resolver: &petri::ArtifactResolver<'_>) -> petri::Firmware {
    petri::Firmware::linux_direct(resolver, arch())
}

/// Build artifacts for the CH backend.
fn build_artifacts(
    resolver: &petri::ArtifactResolver<'_>,
) -> anyhow::Result<petri::PetriVmArtifacts<petri_backend_ch::ChPetriBackend>> {
    let firmware = build_firmware(resolver);
    petri::PetriVmArtifacts::<petri_backend_ch::ChPetriBackend>::new(
        resolver,
        firmware,
        arch(),
        true,
    )
    .context("firmware/arch not compatible with CH backend")
}

/// Register artifacts needed by the CH boot time test.
pub fn register_artifacts(resolver: &petri::ArtifactResolver<'_>) {
    let firmware = build_firmware(resolver);
    petri::PetriVmArtifacts::<petri_backend_ch::ChPetriBackend>::new(
        resolver,
        firmware,
        arch(),
        true,
    );
}

/// CH boot time test: measures launch-to-pipette-connect time via Linux
/// direct boot through cloud-hypervisor.
pub struct ChBootTimeTest {
    /// RAM size in MiB.
    pub mem_mb: u64,
    /// Print guest diagnostics after the first boot.
    pub diag: bool,
    /// Pre-built initrd (kept alive for the duration of the test).
    initrd: tempfile::TempPath,
}

impl ChBootTimeTest {
    /// Create a new CH boot time test, building the initrd up front.
    pub fn new(
        mem_mb: u64,
        diag: bool,
        resolver: &petri::ArtifactResolver<'_>,
    ) -> anyhow::Result<Self> {
        let artifacts = build_artifacts(resolver)?;

        let mut post_test_hooks = Vec::new();
        let log_source = crate::log_source();
        let params = petri::PetriTestParams {
            test_name: "ch_boot_time_initrd_prep",
            logger: &log_source,
            post_test_hooks: &mut post_test_hooks,
        };

        let initrd = pal_async::DefaultPool::run_with(async |driver| {
            let builder = petri::PetriVmBuilder::minimal(params, artifacts, &driver)?;
            builder.prepare_initrd().context("failed to prepare initrd")
        })?;

        Ok(Self {
            mem_mb,
            diag,
            initrd,
        })
    }
}

impl crate::harness::ColdPerfTest for ChBootTimeTest {
    fn name(&self) -> &str {
        "boot_time_ch"
    }

    fn default_iterations(&self) -> u32 {
        10
    }

    fn warmup_iterations(&self) -> u32 {
        1
    }

    async fn run_once(
        &self,
        resolver: &petri::ArtifactResolver<'_>,
        driver: &pal_async::DefaultDriver,
    ) -> anyhow::Result<Vec<MetricResult>> {
        let artifacts = build_artifacts(resolver)?;

        let mut post_test_hooks = Vec::new();
        let log_source = crate::log_source();
        let params = petri::PetriTestParams {
            test_name: "ch_boot_time",
            logger: &log_source,
            post_test_hooks: &mut post_test_hooks,
        };

        let config = petri::PetriVmBuilder::minimal(params, artifacts, driver)?
            .with_processor_topology(petri::ProcessorTopology {
                vp_count: 1,
                ..Default::default()
            })
            .with_memory(petri::MemoryConfig {
                startup_bytes: self.mem_mb * 1024 * 1024,
                ..Default::default()
            })
            .with_prebuilt_initrd(self.initrd.to_path_buf());

        // Measure: start timing right before run(), stop when pipette connects.
        let start = std::time::Instant::now();
        let (vm, agent) = config.run().await.context("failed to boot CH VM")?;
        let elapsed = start.elapsed();

        let boot_time_ms = elapsed.as_secs_f64() * 1000.0;
        tracing::info!(boot_time_ms, "CH boot complete");

        if self.diag {
            // Guest uptime.
            match agent.command("cat").arg("/proc/uptime").output().await {
                Ok(out) => {
                    let text = String::from_utf8_lossy(&out.stdout);
                    eprintln!("\n=== CH /proc/uptime ===\n{text}");
                }
                Err(e) => eprintln!("failed to read /proc/uptime: {e:#}"),
            }

            // Kernel log.
            match agent.command("dmesg").output().await {
                Ok(out) => {
                    let text = String::from_utf8_lossy(&out.stdout);
                    eprintln!("\n=== CH dmesg ===\n{text}");
                }
                Err(e) => eprintln!("failed to read dmesg: {e:#}"),
            }
        }

        // Clean shutdown.
        agent.power_off().await.context("failed to power off")?;
        vm.wait_for_clean_teardown()
            .await
            .context("failed to tear down CH VM")?;

        Ok(vec![MetricResult {
            name: "boot_time_ms".to_string(),
            unit: "ms".to_string(),
            value: boot_time_ms,
        }])
    }
}
