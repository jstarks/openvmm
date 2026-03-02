// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VM lifecycle management for the containerd shim.
//!
//! Handles building OpenVMM Config, launching VmWorker in-process,
//! setting up vsock relay, and connecting to the guest agent.

use anyhow::Context as _;
use containerd_shim_agent_protocol::AGENT_VSOCK_PORT;
use containerd_shim_agent_protocol::AgentBootstrap;
use containerd_shim_agent_protocol::AgentRequest;
use futures::FutureExt;
use futures::StreamExt;
use mesh::rpc::RpcSend;
use mesh_remote::PointToPointMesh;
use mesh_worker::RegisteredWorkers;
use openvmm_defs::config::Config;
use openvmm_defs::config::DEFAULT_MMIO_GAPS_X86;
use openvmm_defs::config::DEFAULT_PCIE_ECAM_BASE;
use openvmm_defs::config::HypervisorConfig;
use openvmm_defs::config::LoadMode;
use openvmm_defs::config::MemoryConfig;
use openvmm_defs::config::ProcessorTopologyConfig;
use openvmm_defs::config::VirtioBus;
use openvmm_defs::config::VmbusConfig;
use openvmm_defs::rpc::VmRpc;
use openvmm_defs::worker::VM_WORKER;
use openvmm_defs::worker::VmWorkerParameters;
use pal_async::socket::PolledSocket;
use pal_async::task::Spawn;
use pal_async::timer::PolledTimer;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use virtio_resources::fs::VirtioFsBackend;
use virtio_resources::fs::VirtioFsHandle;
use vm_manifest_builder::BaseChipsetType;
use vm_manifest_builder::MachineArch;
use vm_manifest_builder::VmManifestBuilder;
use vm_resource::IntoResource;
use vmm_core_defs::HaltReason;

/// Configuration for launching a VM, resolved from environment variables
/// and sandbox creation options.
pub struct VmConfig {
    /// Path to the vmlinux kernel.
    pub kernel_path: PathBuf,
    /// Path to the agent binary (will be wrapped in a cpio initrd).
    pub agent_path: PathBuf,
    /// Number of vCPUs.
    pub cpus: u32,
    /// RAM in megabytes.
    pub memory_mb: u64,
    /// Directory shared into the VM via virtiofs for container rootfs mounts.
    pub containers_dir: PathBuf,
}

/// A running VM with its control channels.
pub struct RunningVm {
    /// Handle to the mesh worker running the VM.
    pub _worker_handle: mesh_worker::WorkerHandle,
    /// Channel for sending VmRpc commands (Resume, Pause, etc.).
    pub _vm_rpc: mesh::Sender<VmRpc>,
    /// Receives VM halt notifications.
    pub halt_recv: mesh::Receiver<HaltReason>,
    /// Channel for sending AgentRequests to the guest agent.
    pub agent_requests: mesh::Sender<AgentRequest>,
    /// Fires when the agent exits (crash or clean shutdown).
    pub _agent_watch: mesh::OneshotReceiver<()>,
    /// Keeps the PointToPointMesh alive.
    pub _mesh: PointToPointMesh,
    /// Keeps the temp vsock path alive (deleted on drop).
    pub _vsock_path: tempfile::TempPath,
    /// Path to the per-port agent listener socket (cleaned up manually).
    pub _agent_listener_path: String,
}

impl Drop for RunningVm {
    fn drop(&mut self) {
        // Clean up per-port listener socket that tempfile doesn't manage.
        let _ = std::fs::remove_file(&self._agent_listener_path);
    }
}

/// Resolve VM configuration from environment variables.
///
/// `bundle` is the containerd bundle directory — a `containers/` subdirectory
/// is created under it and shared into the VM via virtiofs.
pub fn resolve_config(bundle: &std::path::Path) -> anyhow::Result<VmConfig> {
    let kernel_path = std::env::var("OPENVMM_SHIM_KERNEL")
        .context("OPENVMM_SHIM_KERNEL environment variable not set")?;
    let agent_path = std::env::var("OPENVMM_SHIM_AGENT")
        .context("OPENVMM_SHIM_AGENT environment variable not set")?;
    let containers_dir = bundle.join("containers");
    std::fs::create_dir_all(&containers_dir).context("failed to create containers dir")?;
    Ok(VmConfig {
        kernel_path: PathBuf::from(kernel_path),
        agent_path: PathBuf::from(agent_path),
        cpus: std::env::var("OPENVMM_SHIM_CPUS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1),
        memory_mb: std::env::var("OPENVMM_SHIM_MEMORY_MB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256),
        containers_dir,
    })
}

/// Launch a VM with the given configuration.
pub async fn launch_vm(
    driver: &pal_async::DefaultDriver,
    config: &VmConfig,
) -> anyhow::Result<RunningVm> {
    // 1. Read agent binary and build initrd.
    let mut agent_binary = Vec::new();
    std::fs::File::open(&config.agent_path)
        .with_context(|| {
            format!(
                "failed to open agent binary: {}",
                config.agent_path.display()
            )
        })?
        .read_to_end(&mut agent_binary)
        .context("failed to read agent binary")?;

    let initrd_data = crate::initrd::build_initrd(&agent_binary);

    // 2. Write initrd to a temp file.
    let mut initrd_tmpfile =
        tempfile::NamedTempFile::new().context("failed to create initrd temp file")?;
    initrd_tmpfile
        .write_all(&initrd_data)
        .context("failed to write initrd temp file")?;
    initrd_tmpfile
        .flush()
        .context("failed to flush initrd temp file")?;
    // Reopen as a read-only File for Config.
    let initrd_file =
        std::fs::File::open(initrd_tmpfile.path()).context("failed to reopen initrd temp file")?;

    // 3. Open kernel file.
    let kernel_file = std::fs::File::open(&config.kernel_path)
        .with_context(|| format!("failed to open kernel: {}", config.kernel_path.display()))?;

    // 4. Create vsock temp path for VMBus hvsocket relay.
    let (vmbus_vsock_listener, vmbus_vsock_path) = tempfile::Builder::new()
        .make(|path| unix_socket::UnixListener::bind(path))
        .context("failed to create vsock listener")?
        .into_parts();

    // 5. Pre-bind per-port listener for the agent.
    let agent_listener_path = format!("{}_{}", vmbus_vsock_path.display(), AGENT_VSOCK_PORT);
    let agent_listener = unix_socket::UnixListener::bind(&agent_listener_path)
        .context("failed to bind agent vsock listener")?;
    let mut agent_listener = PolledSocket::new(driver, agent_listener)
        .context("failed to create polled agent listener")?;

    // 6. Build chipset.
    let chipset =
        VmManifestBuilder::new(BaseChipsetType::HyperVGen2LinuxDirect, MachineArch::X86_64)
            .with_serial([None, None, None, None])
            .build()
            .context("failed to build chipset")?;

    // 7. Construct Config.
    let (vm_rpc_send, vm_rpc_recv) = mesh::channel::<VmRpc>();
    let (halt_send, halt_recv) = mesh::channel::<HaltReason>();

    let vm_config = Config {
        load_mode: LoadMode::Linux {
            kernel: kernel_file,
            initrd: Some(initrd_file),
            cmdline: "console=ttyS0 panic=-1".into(),
            custom_dsdt: None,
            enable_serial: true,
        },
        floppy_disks: vec![],
        ide_disks: vec![],
        pcie_root_complexes: vec![],
        pcie_devices: vec![],
        pcie_switches: vec![],
        vpci_devices: vec![],
        memory: MemoryConfig {
            mem_size: config.memory_mb * 1024 * 1024,
            mmio_gaps: DEFAULT_MMIO_GAPS_X86.into(),
            prefetch_memory: false,
            pcie_ecam_base: DEFAULT_PCIE_ECAM_BASE,
        },
        processor_topology: ProcessorTopologyConfig {
            proc_count: config.cpus,
            vps_per_socket: None,
            enable_smt: None,
            arch: Default::default(),
        },
        hypervisor: HypervisorConfig {
            with_hv: true,
            ..Default::default()
        },
        chipset: chipset.chipset,
        vmbus: Some(VmbusConfig {
            vsock_listener: Some(vmbus_vsock_listener),
            vsock_path: Some(vmbus_vsock_path.to_string_lossy().into_owned()),
            vmbus_max_version: None,
            vtl2_redirect: false,
        }),
        vtl2_vmbus: None,
        vmbus_devices: vec![],
        chipset_devices: chipset.chipset_devices,
        input: mesh::Receiver::new(),
        framebuffer: None,
        vga_firmware: None,
        vtl2_gfx: false,
        virtio_devices: vec![(
            VirtioBus::Mmio,
            VirtioFsHandle {
                tag: "containers".into(),
                fs: VirtioFsBackend::HostFs {
                    root_path: config.containers_dir.to_string_lossy().into_owned(),
                    mount_options: String::new(),
                },
            }
            .into_resource(),
        )],
        vmgs: None,
        secure_boot_enabled: false,
        custom_uefi_vars: Default::default(),
        firmware_event_send: None,
        debugger_rpc: None,
        generation_id_recv: None,
        rtc_delta_milliseconds: 0,
        automatic_guest_reset: true,
        efi_diagnostics_log_level: Default::default(),
    };

    // 8. Create worker host.
    let (host, runner) = mesh_worker::worker_host();
    driver
        .spawn("worker-host", runner.run(RegisteredWorkers))
        .detach();

    // 9. Launch VM worker.
    let worker_handle = host
        .launch_worker(
            VM_WORKER,
            VmWorkerParameters {
                hypervisor: None,
                cfg: vm_config,
                saved_state: None,
                rpc: vm_rpc_recv,
                notify: halt_send,
            },
        )
        .await
        .context("failed to launch VM worker")?;

    // 10. Resume VM.
    let resumed = vm_rpc_send
        .call(VmRpc::Resume, ())
        .await
        .context("failed to resume VM")?;
    tracing::info!(resumed, "VM resumed");

    // 11. Accept agent connection (with 30s timeout).
    let mut timer = PolledTimer::new(driver);
    let timeout = timer.sleep(std::time::Duration::from_secs(30)).fuse();
    let accept = agent_listener.accept().fuse();

    futures::pin_mut!(timeout, accept);

    let (conn, _) = futures::select! {
        result = accept => result.context("failed to accept agent connection")?,
        _ = timeout => anyhow::bail!("agent connection timed out after 30 seconds"),
    };

    tracing::info!("agent connected");

    // 12. Set up PointToPointMesh on accepted connection.
    let conn = PolledSocket::new(driver, conn).context("failed to wrap agent connection")?;
    let (bootstrap_send, bootstrap_recv) = mesh::oneshot::<AgentBootstrap>();
    let mesh = PointToPointMesh::new(driver, conn, bootstrap_send.into());
    let bootstrap = bootstrap_recv.await.context("agent bootstrap failed")?;

    tracing::info!("agent bootstrap complete");

    // 13. Return RunningVm with all handles.
    Ok(RunningVm {
        _worker_handle: worker_handle,
        _vm_rpc: vm_rpc_send,
        halt_recv,
        agent_requests: bootstrap.requests,
        _agent_watch: bootstrap.watch,
        _mesh: mesh,
        _vsock_path: vmbus_vsock_path,
        _agent_listener_path: agent_listener_path,
    })
}

/// Shut down a running VM by sending Shutdown to the agent.
pub async fn shutdown_vm(
    driver: &pal_async::DefaultDriver,
    vm: &mut RunningVm,
) -> anyhow::Result<()> {
    // Send Shutdown RPC to agent.
    vm.agent_requests
        .call(AgentRequest::Shutdown, ())
        .await
        .map_err(|e| anyhow::anyhow!("shutdown RPC failed: {e}"))?
        .map_err(|e| anyhow::anyhow!("shutdown failed in guest: {e}"))?;

    // Wait for VM halt (with timeout).
    let mut timer = PolledTimer::new(driver);
    let halt = vm.halt_recv.next().fuse();
    let timeout = timer.sleep(std::time::Duration::from_secs(10)).fuse();

    futures::pin_mut!(halt, timeout);

    futures::select! {
        reason = halt => {
            tracing::info!(?reason, "VM halted");
        }
        _ = timeout => {
            tracing::warn!("VM halt timed out after 10 seconds");
        }
    }

    Ok(())
}
