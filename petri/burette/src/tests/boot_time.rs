// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Boot time performance test.
//!
//! Measures the time from VM launch to pipette agent readiness using
//! Linux direct boot (kernel + initrd, no UEFI firmware). This isolates
//! the VMM's launch overhead from firmware initialization time.
//! Uses cold mode: a fresh VM is booted for each iteration.
//!
//! Generic over the VMM backend — the same test struct works for OpenVMM,
//! cloud-hypervisor, or any other `PetriVmmBackend` implementation.

use crate::report::MetricResult;
use anyhow::Context as _;
use petri_artifacts_common::tags::MachineArch;

/// Boot time configuration profile.
///
/// Each profile defines a specific combination of VM features to measure.
/// This lets us track boot time across different configurations and
/// detect regressions in specific code paths.
///
/// Not all profiles are supported by all backends — profiles that require
/// backend-specific configuration (e.g., `MinimalPrivate`) are only
/// available for OpenVMM. Use [`BootProfile::create_openvmm`] for those.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum BootProfile {
    /// Full device set, serial agent, CIDATA disk, shared memory.
    /// The "standard" configuration that vmm_tests use.
    Standard,
    /// Like Standard but with kernel console output suppressed
    /// (`quiet loglevel=0`). Isolates serial emulation overhead.
    QuietSerial,
    /// Pipette-as-init, minimal devices, no serial, shared memory.
    /// Measures VMM + kernel boot without serial overhead.
    Minimal,
    /// Pipette-as-init, minimal devices, no serial, private memory.
    /// Fastest configuration — eliminates mmap overhead for guest RAM.
    MinimalPrivate,
}

impl BootProfile {
    /// Whether this profile uses private memory.
    pub fn uses_private_memory(&self) -> bool {
        matches!(self, Self::MinimalPrivate)
    }

    /// Whether this profile uses the minimal device set.
    pub fn uses_minimal_builder(&self) -> bool {
        matches!(self, Self::Minimal | Self::MinimalPrivate)
    }

    /// Whether this profile suppresses kernel console output.
    pub fn uses_quiet_serial(&self) -> bool {
        matches!(self, Self::QuietSerial)
    }

    /// Whether this profile can be used with any backend (not just OpenVMM).
    pub fn is_generic(&self) -> bool {
        matches!(self, Self::Minimal | Self::Standard)
    }

    /// Create a VM builder for any backend, without backend-specific
    /// configuration. Only `Minimal` and `Standard` profiles are supported.
    pub fn create_builder<T: petri::PetriVmmBackend>(
        &self,
        params: petri::PetriTestParams<'_>,
        artifacts: petri::PetriVmArtifacts<T>,
        driver: &pal_async::DefaultDriver,
    ) -> anyhow::Result<petri::PetriVmBuilder<T>> {
        let builder = if self.uses_minimal_builder() {
            petri::PetriVmBuilder::minimal(params, artifacts, driver)?
        } else {
            petri::PetriVmBuilder::new(params, artifacts, driver)?
        };
        Ok(builder)
    }

    /// Create a VM builder with OpenVMM-specific profile configuration.
    ///
    /// Applies private memory, quiet serial, and other backend-specific
    /// settings on top of the base builder.
    pub fn create_openvmm(
        &self,
        params: petri::PetriTestParams<'_>,
        artifacts: petri::PetriVmArtifacts<petri::openvmm::OpenVmmPetriBackend>,
        driver: &pal_async::DefaultDriver,
    ) -> anyhow::Result<petri::PetriVmBuilder<petri::openvmm::OpenVmmPetriBackend>> {
        let mut builder = self.create_builder(params, artifacts, driver)?;

        if self.uses_private_memory() {
            builder = builder.modify_backend(|c| {
                c.with_custom_config(|c| {
                    c.memory.private_memory = true;
                })
            });
        }

        if self.uses_quiet_serial() {
            builder = builder.modify_backend(|c| {
                c.with_custom_config(|c| {
                    if let openvmm_defs::config::LoadMode::Linux { cmdline, .. } = &mut c.load_mode
                    {
                        *cmdline = cmdline.replace(" debug ", " quiet loglevel=0 ");
                    }
                })
            });
        }

        Ok(builder)
    }
}

/// Boot time test: measures launch-to-pipette-connect time via Linux direct boot.
///
/// Generic over the VMM backend `T`. For OpenVMM, supports all profiles
/// (Standard, QuietSerial, Minimal, MinimalPrivate). For other backends,
/// only generic profiles (Minimal, Standard) are supported.
pub struct BootTimeTest<T: petri::PetriVmmBackend> {
    profile: BootProfile,
    diag: bool,
    mem_mb: u64,
    initrd: tempfile::TempPath,
    /// Optional backend-specific builder modifier, applied after the
    /// profile creates the base builder.
    modifier:
        Option<Box<dyn Fn(petri::PetriVmBuilder<T>) -> petri::PetriVmBuilder<T> + Send + Sync>>,
}

/// Build the firmware configuration for Linux direct boot.
pub fn build_firmware(resolver: &petri::ArtifactResolver<'_>) -> petri::Firmware {
    petri::Firmware::linux_direct(resolver, MachineArch::host())
}

/// Build artifacts for the given backend.
pub fn build_artifacts<T: petri::PetriVmmBackend>(
    resolver: &petri::ArtifactResolver<'_>,
) -> anyhow::Result<petri::PetriVmArtifacts<T>> {
    let firmware = build_firmware(resolver);
    petri::PetriVmArtifacts::<T>::new(resolver, firmware, MachineArch::host(), true)
        .context("firmware/arch not compatible with backend")
}

/// Register artifacts needed by boot time tests for the given backend.
pub fn register_artifacts<T: petri::PetriVmmBackend>(resolver: &petri::ArtifactResolver<'_>) {
    let firmware = build_firmware(resolver);
    petri::PetriVmArtifacts::<T>::new(resolver, firmware, MachineArch::host(), true);
}

/// Prepare an initrd for minimal profiles using the OpenVMM backend.
///
/// Returns `Some(path)` for minimal profiles, `None` for standard profiles.
/// Used by memory and scale_boot tests that are OpenVMM-only.
pub fn prepare_openvmm_initrd(
    profile: &BootProfile,
    resolver: &petri::ArtifactResolver<'_>,
) -> anyhow::Result<Option<tempfile::TempPath>> {
    if !profile.uses_minimal_builder() {
        return Ok(None);
    }

    let artifacts = build_artifacts::<petri::openvmm::OpenVmmPetriBackend>(resolver)?;

    let mut post_test_hooks = Vec::new();
    let log_source = crate::log_source();
    let params = petri::PetriTestParams {
        test_name: "initrd_prep",
        logger: &log_source,
        post_test_hooks: &mut post_test_hooks,
    };

    let initrd = pal_async::DefaultPool::run_with(async |driver| {
        let builder = petri::PetriVmBuilder::minimal(params, artifacts, &driver)?;
        builder.prepare_initrd().context("failed to prepare initrd")
    })?;

    Ok(Some(initrd))
}

impl<T: petri::PetriVmmBackend> BootTimeTest<T> {
    /// Create a new boot time test using a generic (non-backend-specific)
    /// profile. Only `Minimal` and `Standard` profiles are supported.
    pub fn new(
        profile: BootProfile,
        diag: bool,
        mem_mb: u64,
        resolver: &petri::ArtifactResolver<'_>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            profile.is_generic(),
            "profile {profile:?} requires backend-specific configuration; \
             use BootTimeTest::new_openvmm() for OpenVMM"
        );
        Self::new_inner(profile, diag, mem_mb, resolver, None)
    }
}

impl BootTimeTest<petri::openvmm::OpenVmmPetriBackend> {
    /// Create a new boot time test with OpenVMM-specific profile support.
    ///
    /// Supports all profiles including `QuietSerial` and `MinimalPrivate`.
    pub fn new_openvmm(
        profile: BootProfile,
        diag: bool,
        mem_mb: u64,
        resolver: &petri::ArtifactResolver<'_>,
    ) -> anyhow::Result<Self> {
        let modifier: Option<
            Box<
                dyn Fn(
                        petri::PetriVmBuilder<petri::openvmm::OpenVmmPetriBackend>,
                    )
                        -> petri::PetriVmBuilder<petri::openvmm::OpenVmmPetriBackend>
                    + Send
                    + Sync,
            >,
        > = if profile.uses_private_memory() || profile.uses_quiet_serial() {
            Some(Box::new(move |mut builder| {
                if profile.uses_private_memory() {
                    builder = builder.modify_backend(|c| {
                        c.with_custom_config(|c| {
                            c.memory.private_memory = true;
                        })
                    });
                }
                if profile.uses_quiet_serial() {
                    builder = builder.modify_backend(|c| {
                        c.with_custom_config(|c| {
                            if let openvmm_defs::config::LoadMode::Linux { cmdline, .. } =
                                &mut c.load_mode
                            {
                                *cmdline = cmdline.replace(" debug ", " quiet loglevel=0 ");
                            }
                        })
                    });
                }
                builder
            }))
        } else {
            None
        };
        Self::new_inner(profile, diag, mem_mb, resolver, modifier)
    }
}

impl<T: petri::PetriVmmBackend> BootTimeTest<T> {
    fn new_inner(
        profile: BootProfile,
        diag: bool,
        mem_mb: u64,
        resolver: &petri::ArtifactResolver<'_>,
        modifier: Option<
            Box<dyn Fn(petri::PetriVmBuilder<T>) -> petri::PetriVmBuilder<T> + Send + Sync>,
        >,
    ) -> anyhow::Result<Self> {
        let artifacts = build_artifacts::<T>(resolver)?;

        let mut post_test_hooks = Vec::new();
        let log_source = crate::log_source();
        let params = petri::PetriTestParams {
            test_name: "boot_time_initrd_prep",
            logger: &log_source,
            post_test_hooks: &mut post_test_hooks,
        };

        let initrd = pal_async::DefaultPool::run_with(async |driver| {
            let builder = petri::PetriVmBuilder::minimal(params, artifacts, &driver)?;
            builder.prepare_initrd().context("failed to prepare initrd")
        })?;

        Ok(Self {
            profile,
            diag,
            mem_mb,
            initrd,
            modifier,
        })
    }
}

impl<T: petri::PetriVmmBackend> crate::harness::ColdPerfTest for BootTimeTest<T> {
    fn name(&self) -> &str {
        "boot_time"
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
        let artifacts = build_artifacts::<T>(resolver)?;

        let mut post_test_hooks = Vec::new();
        let log_source = crate::log_source();
        let params = petri::PetriTestParams {
            test_name: "boot_time",
            logger: &log_source,
            post_test_hooks: &mut post_test_hooks,
        };

        let mut builder = self
            .profile
            .create_builder(params, artifacts, driver)?
            .with_processor_topology(petri::ProcessorTopology {
                vp_count: 1,
                ..Default::default()
            })
            .with_memory(petri::MemoryConfig {
                startup_bytes: self.mem_mb * 1024 * 1024,
                ..Default::default()
            });

        if self.profile.uses_minimal_builder() {
            builder = builder.with_prebuilt_initrd(self.initrd.to_path_buf());
        }

        // Apply backend-specific configuration (if any).
        if let Some(modifier) = &self.modifier {
            builder = modifier(builder);
        }

        // Measure: start timing right before run(), stop when pipette connects.
        let start = std::time::Instant::now();
        let (vm, agent) = builder.run().await.context("failed to boot VM")?;
        let elapsed = start.elapsed();

        let boot_time_ms = elapsed.as_secs_f64() * 1000.0;
        tracing::info!(boot_time_ms, "boot complete");

        if self.diag {
            print_diagnostics(&agent).await;
        }

        // Clean shutdown.
        agent.power_off().await.context("failed to power off")?;
        vm.wait_for_clean_teardown()
            .await
            .context("failed to tear down VM")?;

        Ok(vec![MetricResult {
            name: "boot_time_ms".to_string(),
            unit: "ms".to_string(),
            value: boot_time_ms,
        }])
    }
}

/// Print guest-side diagnostics (dmesg and /proc/uptime) after the first
/// boot. This runs only when `--diag` is passed and does not affect timing.
async fn print_diagnostics(agent: &petri::pipette::PipetteClient) {
    // Guest uptime (seconds since kernel start).
    match agent.command("cat").arg("/proc/uptime").output().await {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            eprintln!("\n=== /proc/uptime ===\n{text}");
        }
        Err(e) => eprintln!("failed to read /proc/uptime: {e:#}"),
    }

    // Kernel log with timestamps.
    match agent.command("dmesg").output().await {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            eprintln!("\n=== dmesg ===\n{text}");
        }
        Err(e) => eprintln!("failed to read dmesg: {e:#}"),
    }
}
