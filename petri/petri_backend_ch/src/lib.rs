// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cloud-hypervisor petri backend.
//!
//! Implements [`PetriVmmBackend`] and [`PetriVmRuntime`](petri::PetriVmRuntime) for the
//! cloud-hypervisor VMM, enabling petri-based tests (including burette
//! performance benchmarks) to run against CH using the same pipette
//! agent and test infrastructure as OpenVMM.

#![forbid(unsafe_code)]

mod runtime;

use anyhow::Context as _;
use async_trait::async_trait;
use pal_async::socket::PolledSocket;
use petri::Firmware;
use petri::OpenHclServicingFlags;
use petri::PetriVmConfig;
use petri::PetriVmProperties;
use petri::PetriVmResources;
use petri::PetriVmRuntimeConfig;
use petri::PetriVmmBackend;
use petri::VmmQuirks;
use petri_artifacts_common::tags::GuestQuirksInner;
use petri_artifacts_common::tags::MachineArch;
use petri_artifacts_core::ArtifactResolver;
use petri_artifacts_core::ResolvedArtifact;
use pipette_protocol::PIPETTE_VSOCK_PORT;
use runtime::ChVmRuntime;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempPath;
use unix_socket::UnixListener;

pub mod artifacts {
    //! Artifact declarations for the cloud-hypervisor backend.
    use petri_artifacts_core::declare_artifacts;

    declare_artifacts! {
        /// The cloud-hypervisor binary.
        CH_BINARY,
    }
}

/// Cloud-hypervisor petri backend.
#[derive(Debug)]
pub struct ChPetriBackend {
    ch_path: ResolvedArtifact,
}

#[async_trait]
impl PetriVmmBackend for ChPetriBackend {
    type VmmConfig = ();
    type VmRuntime = ChVmRuntime;

    fn check_compat(firmware: &Firmware, arch: MachineArch) -> bool {
        // CH only supports Linux direct boot on the host architecture.
        arch == MachineArch::host() && firmware.is_linux_direct() && !firmware.is_openhcl()
    }

    fn quirks(_firmware: &Firmware) -> (GuestQuirksInner, VmmQuirks) {
        (GuestQuirksInner::default(), VmmQuirks { flaky_boot: None })
    }

    fn default_servicing_flags() -> OpenHclServicingFlags {
        OpenHclServicingFlags {
            enable_nvme_keepalive: false,
            enable_mana_keepalive: false,
            override_version_checks: false,
            stop_timeout_hint_secs: None,
        }
    }

    fn create_guest_dump_disk() -> anyhow::Result<
        Option<(
            Arc<TempPath>,
            Box<dyn FnOnce() -> anyhow::Result<Box<dyn fatfs::ReadWriteSeek>>>,
        )>,
    > {
        Ok(None)
    }

    fn new(resolver: &ArtifactResolver<'_>) -> Self {
        ChPetriBackend {
            ch_path: resolver.require(artifacts::CH_BINARY).erase(),
        }
    }

    async fn run(
        self,
        config: PetriVmConfig,
        _modify_vmm_config: Option<petri::ModifyFn<Self::VmmConfig>>,
        resources: &PetriVmResources,
        properties: PetriVmProperties,
    ) -> anyhow::Result<(Self::VmRuntime, PetriVmRuntimeConfig)> {
        // Extract Linux direct boot parameters.
        let (kernel_path, initrd_path) = match &config.firmware {
            Firmware::LinuxDirect { kernel, initrd } => {
                (kernel.get().to_path_buf(), initrd.get().to_path_buf())
            }
            _ => anyhow::bail!("CH backend only supports LinuxDirect firmware"),
        };

        // If using pipette-as-init, use the prebuilt initrd (the builder
        // guarantees this is set when uses_pipette_as_init is true).
        let effective_initrd = if properties.uses_pipette_as_init {
            properties
                .prebuilt_initrd
                .as_ref()
                .context("uses_pipette_as_init requires prebuilt_initrd")?
                .clone()
        } else {
            initrd_path
        };

        // Build kernel command line.
        let cmdline = if properties.uses_pipette_as_init {
            "rdinit=/pipette panic=-1".to_string()
        } else {
            "console=ttyS0 panic=-1".to_string()
        };

        // Create temp directory for sockets.
        let temp_dir = tempfile::tempdir().context("failed to create temp dir")?;

        // Set up vsock socket path.
        let vsock_socket_path = temp_dir.path().join("vsock");

        // Bind the pipette listener before booting the VM. CH will
        // connect to `{vsock_path}_{port}` when the guest connects
        // to the corresponding vsock port.
        let pipette_socket_path = PathBuf::from(format!(
            "{}_{PIPETTE_VSOCK_PORT}",
            vsock_socket_path.display()
        ));
        let pipette_listener = UnixListener::bind(&pipette_socket_path).with_context(|| {
            format!(
                "failed to bind pipette listener at {}",
                pipette_socket_path.display()
            )
        })?;

        // API socket path.
        let api_socket_path = temp_dir.path().join("api.sock");

        // Build the cloud-hypervisor command.
        let mem_mb = config.memory.startup_bytes / (1024 * 1024);
        let vp_count = config.proc_topology.vp_count;

        let mut cmd = std::process::Command::new(self.ch_path.get());
        cmd.args(["--api-socket", &api_socket_path.display().to_string()])
            .args(["--kernel", &kernel_path.display().to_string()])
            .args(["--initramfs", &effective_initrd.display().to_string()])
            .args(["--cmdline", &cmdline])
            .args(["--memory", &format!("size={mem_mb}M")])
            .args(["--cpus", &format!("boot={vp_count}")])
            .args([
                "--vsock",
                &format!("cid=3,socket={}", vsock_socket_path.display()),
            ])
            .args(["--serial", "off"])
            .args(["--console", "off"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        tracing::info!(
            ch_binary = %self.ch_path.get().display(),
            kernel = %kernel_path.display(),
            initrd = %effective_initrd.display(),
            mem_mb,
            vp_count,
            "launching cloud-hypervisor"
        );

        let child = cmd.spawn().context("failed to spawn cloud-hypervisor")?;

        let driver = resources.driver().clone();
        let output_dir = resources.output_dir().to_path_buf();

        let pipette_listener = PolledSocket::new(&driver, pipette_listener)
            .context("failed to poll pipette listener")?;

        let runtime_config = config
            .firmware
            .into_runtime_config(config.vmbus_storage_controllers);

        let runtime = ChVmRuntime::new(
            child,
            pipette_listener,
            api_socket_path,
            driver,
            output_dir,
            temp_dir,
            properties,
        );

        Ok((runtime, runtime_config))
    }
}
