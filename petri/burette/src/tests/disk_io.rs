// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Block I/O performance test via fio.
//!
//! Boots a minimal Linux VM (linux_direct, pipette as PID 1) with a data disk
//! and a read-only virtio-blk device carrying an erofs image with fio
//! pre-installed. Measures sequential/random read/write bandwidth (MiB/s) and
//! IOPS across multiple iterations. Uses warm mode: the VM is booted once and
//! reused for all iterations.
//!
//! Generic over the VMM backend — the same test struct works for OpenVMM,
//! cloud-hypervisor, or any other `PetriVmmBackend` implementation.
//! OpenVMM supports both virtio-blk and storvsc; other backends use
//! virtio-blk only.

use crate::report::MetricResult;
use anyhow::Context as _;
use petri::pipette::cmd;
use petri_artifacts_common::tags::MachineArch;
use std::path::PathBuf;
use vm_resource::IntoResource;

/// Which disk backend to use for the fio test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum DiskBackend {
    /// Virtio-blk via PCIe (virtio-pci).
    #[value(name = "virtio-blk")]
    VirtioBlk,
    /// Synthetic SCSI (storvsc).
    Storvsc,
}

impl std::fmt::Display for DiskBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use clap::ValueEnum;
        f.write_str(self.to_possible_value().unwrap().get_name())
    }
}

/// Block I/O test via fio, generic over VMM backend.
pub struct DiskIoTest<T: petri::PetriVmmBackend> {
    /// Human-readable label for metric names.
    pub label: String,
    /// Print guest diagnostics.
    pub diag: bool,
    /// Which disk backend to test (affects device discovery in the guest).
    pub disk_backend: DiskBackend,
    /// Path to a raw data disk file on the host, or `None` for a
    /// RAM/temp-file-backed disk.
    pub data_disk: Option<PathBuf>,
    /// Data disk size in GiB.
    pub data_disk_size_gib: u64,
    /// If set, record per-phase perf traces in this directory.
    pub perf_dir: Option<PathBuf>,
    /// Backend-specific builder modifier. Called with the base minimal
    /// builder, erofs path, and data disk path to attach disks.
    pub setup_disks: Box<
        dyn Fn(
                petri::PetriVmBuilder<T>,
                PathBuf,
                PathBuf,
                u64,
            ) -> anyhow::Result<petri::PetriVmBuilder<T>>
            + Send
            + Sync,
    >,
    /// Function to get the VMM process PID from the runtime (for perf recording).
    pub get_pid: fn(&mut T::VmRuntime) -> i32,
}

/// State kept across warm iterations.
pub struct DiskIoTestState<T: petri::PetriVmmBackend> {
    vm: petri::PetriVm<T>,
    agent: petri::pipette::PipetteClient,
    /// Guest device path for the data disk (e.g. "/dev/vda" or "/dev/sdb").
    disk_device: String,
    /// Temp file for the data disk if no explicit path was given.
    _temp_disk: Option<tempfile::NamedTempFile>,
}

fn build_firmware(resolver: &petri::ArtifactResolver<'_>) -> petri::Firmware {
    petri::Firmware::linux_direct(resolver, MachineArch::host())
}

fn require_petritools_erofs(
    resolver: &petri::ArtifactResolver<'_>,
) -> petri_artifacts_core::ResolvedArtifact {
    use petri_artifacts_vmm_test::artifacts::petritools::*;
    match MachineArch::host() {
        MachineArch::X86_64 => resolver.require(PETRITOOLS_EROFS_X64).erase(),
        MachineArch::Aarch64 => resolver.require(PETRITOOLS_EROFS_AARCH64).erase(),
    }
}

/// Register artifacts needed by the disk I/O test for the given backend.
pub fn register_artifacts<T: petri::PetriVmmBackend>(resolver: &petri::ArtifactResolver<'_>) {
    let firmware = build_firmware(resolver);
    petri::PetriVmArtifacts::<T>::new(resolver, firmware, MachineArch::host(), true);
    require_petritools_erofs(resolver);
}

/// GUID for the data disk SCSI controller (used for storvsc backend).
const DATA_DISK_SCSI_CONTROLLER: guid::Guid = guid::guid!("f47ac10b-58cc-4372-a567-0e02b2c3d479");

impl<T: petri::PetriVmmBackend> crate::harness::WarmPerfTest for DiskIoTest<T> {
    type State = DiskIoTestState<T>;

    fn name(&self) -> &str {
        &self.label
    }

    fn warmup_iterations(&self) -> u32 {
        1
    }

    async fn setup(
        &self,
        resolver: &petri::ArtifactResolver<'_>,
        driver: &pal_async::DefaultDriver,
    ) -> anyhow::Result<DiskIoTestState<T>> {
        anyhow::ensure!(
            self.data_disk_size_gib > 0,
            "data_disk_size_gib must be greater than 0"
        );
        let disk_size_bytes = self.data_disk_size_gib * 1024 * 1024 * 1024;

        // Prepare the data disk file.
        let (data_disk_path, temp_disk) =
            prepare_data_disk(&self.data_disk, disk_size_bytes, self.data_disk_size_gib)?;

        let firmware = build_firmware(resolver);

        let artifacts =
            petri::PetriVmArtifacts::<T>::new(resolver, firmware, MachineArch::host(), true)
                .context("firmware/arch not compatible with backend")?;

        let mut post_test_hooks = Vec::new();
        let log_source = crate::log_source();
        let params = petri::PetriTestParams {
            test_name: "disk_io",
            logger: &log_source,
            post_test_hooks: &mut post_test_hooks,
        };

        let erofs_path = require_petritools_erofs(resolver);

        let builder = petri::PetriVmBuilder::minimal(params, artifacts, driver)?
            .with_processor_topology(petri::ProcessorTopology {
                vp_count: 2,
                ..Default::default()
            })
            .with_memory(petri::MemoryConfig {
                startup_bytes: 1024 * 1024 * 1024, // 1 GB
                ..Default::default()
            });

        // Backend-specific disk attachment.
        let builder = (self.setup_disks)(
            builder,
            erofs_path.get().to_path_buf(),
            data_disk_path,
            disk_size_bytes,
        )?;

        let builder = if !self.diag {
            builder.without_screenshots()
        } else {
            builder.with_serial_output()
        };

        let (vm, agent) = builder.run().await.context("failed to boot VM")?;

        // Mount the erofs image and prepare chroot (fio is pre-installed).
        agent
            .mount("/dev/vda", "/perf", "erofs", 1 /* MS_RDONLY */, true)
            .await
            .context("failed to mount erofs on /dev/vda")?;
        agent
            .prepare_chroot("/perf")
            .await
            .context("failed to prepare chroot at /perf")?;

        // Discover the data disk device.
        let disk_device = discover_data_disk(&agent, self.disk_backend)
            .await
            .context("failed to discover data disk device")?;
        tracing::info!(disk_device = %disk_device, label = %self.label, "discovered data disk");

        Ok(DiskIoTestState {
            vm,
            agent,
            disk_device,
            _temp_disk: temp_disk,
        })
    }

    async fn run_once(&self, state: &mut DiskIoTestState<T>) -> anyhow::Result<Vec<MetricResult>> {
        let mut metrics = Vec::new();
        let label = &self.label;
        let pid = (self.get_pid)(state.vm.backend());
        let mut recorder = crate::harness::PerfRecorder::new(self.perf_dir.as_deref(), pid)?;
        let dev = &state.disk_device;

        // Each fio job: 10s runtime + 5s ramp = 15s.
        // For sequential modes we only extract BW; for random modes we extract
        // both BW and IOPS from a single fio run to avoid redundant work.
        let fio_jobs: &[(&str, &str)] = &[
            // (fio_rw_mode, primary_field)
            ("read", "read"),
            ("write", "write"),
            ("randread", "read"),
            ("randwrite", "write"),
        ];

        for &(rw_mode, field) in fio_jobs {
            let is_random = rw_mode.starts_with("rand");
            let phase = if is_random {
                rw_mode.strip_prefix("rand").unwrap()
            } else {
                rw_mode
            };
            let prefix = if is_random { "rand" } else { "seq" };

            let perf_label = format!("fio_{label}_{prefix}_{phase}");
            recorder.start(&perf_label)?;

            let json = run_fio_job(&state.agent, dev, rw_mode)
                .await
                .with_context(|| format!("fio {rw_mode} failed"))?;

            recorder.stop()?;

            let bw_name = format!("fio_{label}_{prefix}_{phase}_bw");
            metrics.push(parse_fio_bw(&json, &bw_name, field)?);

            if is_random {
                let iops_name = format!("fio_{label}_{prefix}_{phase}_iops");
                metrics.push(parse_fio_iops(&json, &iops_name, field)?);
            }
        }

        Ok(metrics)
    }

    async fn teardown(&self, state: DiskIoTestState<T>) -> anyhow::Result<()> {
        state.agent.power_off().await?;
        state.vm.wait_for_clean_teardown().await?;
        Ok(())
    }
}

// ── Constructors ────────────────────────────────────────────────────────

/// Create an OpenVMM disk I/O test.
pub fn openvmm_test(
    diag: bool,
    backend: DiskBackend,
    data_disk: Option<PathBuf>,
    data_disk_size_gib: u64,
    perf_dir: Option<PathBuf>,
) -> DiskIoTest<petri::openvmm::OpenVmmPetriBackend> {
    let label = match backend {
        DiskBackend::VirtioBlk => "disk_io_virtioblk",
        DiskBackend::Storvsc => "disk_io_storvsc",
    };

    DiskIoTest {
        label: label.to_string(),
        diag,
        disk_backend: backend,
        data_disk,
        data_disk_size_gib,
        perf_dir,
        setup_disks: Box::new(
            move |builder, erofs_path, data_disk_path, disk_size_bytes| {
                setup_openvmm_disks(
                    builder,
                    erofs_path,
                    data_disk_path,
                    disk_size_bytes,
                    backend,
                )
            },
        ),
        get_pid: |rt| rt.pid(),
    }
}

/// Create a cloud-hypervisor disk I/O test (virtio-blk only).
pub fn ch_test(
    diag: bool,
    data_disk: Option<PathBuf>,
    data_disk_size_gib: u64,
    perf_dir: Option<PathBuf>,
) -> DiskIoTest<petri_backend_ch::ChPetriBackend> {
    DiskIoTest {
        label: "disk_io_ch_virtioblk".to_string(),
        diag,
        disk_backend: DiskBackend::VirtioBlk,
        data_disk,
        data_disk_size_gib,
        perf_dir,
        setup_disks: Box::new(|builder, erofs_path, data_disk_path, _disk_size_bytes| {
            Ok(
                builder.modify_backend(move |mut c: petri_backend_ch::ChVmmConfig| {
                    c.disks.push(petri_backend_ch::ChDiskConfig {
                        path: erofs_path,
                        readonly: true,
                        direct: false,
                    });
                    c.disks.push(petri_backend_ch::ChDiskConfig {
                        path: data_disk_path,
                        readonly: false,
                        direct: true,
                    });
                    c
                }),
            )
        }),
        get_pid: |rt| rt.pid(),
    }
}

// ── Backend-specific setup ──────────────────────────────────────────────

/// Attach erofs + data disk for OpenVMM (virtio-blk or storvsc).
fn setup_openvmm_disks(
    builder: petri::PetriVmBuilder<petri::openvmm::OpenVmmPetriBackend>,
    erofs_path: PathBuf,
    data_disk_path: PathBuf,
    disk_size_bytes: u64,
    backend: DiskBackend,
) -> anyhow::Result<petri::PetriVmBuilder<petri::openvmm::OpenVmmPetriBackend>> {
    let erofs_file = fs_err::File::open(&erofs_path)?;
    let data_disk_opt = if data_disk_path.exists() {
        Some(data_disk_path)
    } else {
        None
    };

    Ok(match backend {
        DiskBackend::VirtioBlk => {
            let disk = make_disk_resource(&data_disk_opt, disk_size_bytes)
                .context("failed to create data disk resource")?;
            builder.modify_backend(move |b| {
                b.with_nic()
                    .with_pcie_root_topology(1, 1, 2)
                    .with_custom_config(|c| {
                        use disk_backend_resources::FileDiskHandle;
                        use openvmm_defs::config::PcieDeviceConfig;

                        c.pcie_devices.push(PcieDeviceConfig {
                            port_name: "s0rc0rp0".into(),
                            resource: virtio_resources::VirtioPciDeviceHandle(
                                virtio_resources::blk::VirtioBlkHandle {
                                    disk: FileDiskHandle(erofs_file.into()).into_resource(),
                                    read_only: true,
                                }
                                .into_resource(),
                            )
                            .into_resource(),
                        });
                        c.pcie_devices.push(PcieDeviceConfig {
                            port_name: "s0rc0rp1".into(),
                            resource: virtio_resources::VirtioPciDeviceHandle(
                                virtio_resources::blk::VirtioBlkHandle {
                                    disk,
                                    read_only: false,
                                }
                                .into_resource(),
                            )
                            .into_resource(),
                        });
                    })
            })
        }
        DiskBackend::Storvsc => {
            let disk = match &data_disk_opt {
                Some(p) => petri::Disk::Persistent(p.clone()),
                None => petri::Disk::Memory(disk_size_bytes),
            };
            builder
                .modify_backend(move |b| {
                    b.with_nic()
                        .with_pcie_root_topology(1, 1, 1)
                        .with_custom_config(|c| {
                            use disk_backend_resources::FileDiskHandle;
                            use openvmm_defs::config::PcieDeviceConfig;

                            c.pcie_devices.push(PcieDeviceConfig {
                                port_name: "s0rc0rp0".into(),
                                resource: virtio_resources::VirtioPciDeviceHandle(
                                    virtio_resources::blk::VirtioBlkHandle {
                                        disk: FileDiskHandle(erofs_file.into()).into_resource(),
                                        read_only: true,
                                    }
                                    .into_resource(),
                                )
                                .into_resource(),
                            });
                        })
                })
                .add_vmbus_storage_controller(
                    &DATA_DISK_SCSI_CONTROLLER,
                    petri::Vtl::Vtl0,
                    petri::VmbusStorageType::Scsi,
                )
                .add_vmbus_drive(
                    petri::Drive::new(Some(disk), false),
                    &DATA_DISK_SCSI_CONTROLLER,
                    Some(0),
                )
        }
    })
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Prepare the data disk file. Returns `(path, optional_temp_file)`.
///
/// If `data_disk` is `Some`, creates/truncates the file at that path.
/// Otherwise, creates a temporary file (needed for backends like CH that
/// require file-backed disks).
fn prepare_data_disk(
    data_disk: &Option<PathBuf>,
    disk_size_bytes: u64,
    disk_size_gib: u64,
) -> anyhow::Result<(PathBuf, Option<tempfile::NamedTempFile>)> {
    if let Some(path) = data_disk {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .with_context(|| format!("failed to create data disk at {}", path.display()))?;
        file.set_len(disk_size_bytes)
            .with_context(|| format!("failed to set data disk size to {} GiB", disk_size_gib))?;
        drop(file);
        Ok((path.clone(), None))
    } else {
        tracing::info!(size_gib = disk_size_gib, "using temp-file-backed data disk");
        let tmp = tempfile::NamedTempFile::new().context("failed to create temp data disk")?;
        tmp.as_file()
            .set_len(disk_size_bytes)
            .context("failed to set temp data disk size")?;
        let path = tmp.path().to_path_buf();
        Ok((path, Some(tmp)))
    }
}

/// Create a disk resource from either a file path or a RAM-backed disk.
fn make_disk_resource(
    path: &Option<PathBuf>,
    size_bytes: u64,
) -> anyhow::Result<vm_resource::Resource<vm_resource::kind::DiskHandleKind>> {
    match path {
        Some(p) => openvmm_helpers::disk::open_disk_type(p, false)
            .with_context(|| format!("failed to open data disk at {}", p.display())),
        None => {
            use disk_backend_resources::LayeredDiskHandle;
            use disk_backend_resources::layer::RamDiskLayerHandle;
            Ok(LayeredDiskHandle::single_layer(RamDiskLayerHandle {
                len: Some(size_bytes),
                sector_size: None,
            })
            .into_resource())
        }
    }
}

/// Discover the data disk device path in the guest.
async fn discover_data_disk(
    agent: &petri::pipette::PipetteClient,
    backend: DiskBackend,
) -> anyhow::Result<String> {
    let sh = agent.unix_shell();

    match backend {
        DiskBackend::VirtioBlk => {
            let blocks = cmd!(sh, "ls /sys/block")
                .read()
                .await
                .context("failed to list /sys/block")?;

            tracing::debug!(blocks = %blocks, "guest block devices");

            if blocks.split_whitespace().any(|d| d == "vdb") {
                Ok("/dev/vdb".to_string())
            } else {
                anyhow::bail!("data disk /dev/vdb not found in guest; found: {blocks}")
            }
        }
        DiskBackend::Storvsc => {
            let guid = DATA_DISK_SCSI_CONTROLLER;
            let list_cmd =
                format!("ls -d /sys/bus/vmbus/devices/{guid}/host*/target*/*:0:0:0/block/sd*");
            let path = cmd!(sh, "sh -c {list_cmd}")
                .read()
                .await
                .with_context(|| format!("no SCSI data disk found for controller {guid}"))?;
            let dev = path
                .lines()
                .next()
                .and_then(|l| l.rsplit('/').next())
                .context("failed to parse device name from sysfs")?;
            Ok(format!("/dev/{dev}"))
        }
    }
}

/// Run a single fio job and return the raw JSON output.
async fn run_fio_job(
    agent: &petri::pipette::PipetteClient,
    device: &str,
    rw_mode: &str,
) -> anyhow::Result<String> {
    let mut sh = agent.unix_shell();
    sh.chroot("/perf");
    let output: String = cmd!(sh, "fio --name=test --filename={device} --rw={rw_mode} --bs=4k --ioengine=io_uring --direct=1 --runtime=10 --ramp_time=5 --iodepth=32 --numjobs=1 --output-format=json")
        .read()
        .await
        .with_context(|| format!("fio {rw_mode} on {device} failed"))?;

    Ok(output)
}

/// Parse bandwidth (MiB/s) from fio JSON output.
fn parse_fio_bw(json: &str, metric_name: &str, field: &str) -> anyhow::Result<MetricResult> {
    let v: serde_json::Value = serde_json::from_str(json).context("failed to parse fio JSON")?;

    let bw_bytes = v["jobs"][0][field]["bw_bytes"].as_f64().with_context(|| {
        tracing::error!(json = %json, "failed to find {field}.bw_bytes in fio output");
        format!("missing {field}.bw_bytes in fio output for {metric_name}")
    })?;

    let mib_s = bw_bytes / (1024.0 * 1024.0);
    Ok(MetricResult {
        name: metric_name.to_string(),
        unit: "MiB/s".to_string(),
        value: mib_s,
    })
}

/// Parse IOPS from fio JSON output.
fn parse_fio_iops(json: &str, metric_name: &str, field: &str) -> anyhow::Result<MetricResult> {
    let v: serde_json::Value = serde_json::from_str(json).context("failed to parse fio JSON")?;

    let iops = v["jobs"][0][field]["iops"].as_f64().with_context(|| {
        tracing::error!(json = %json, "failed to find {field}.iops in fio output");
        format!("missing {field}.iops in fio output for {metric_name}")
    })?;

    Ok(MetricResult {
        name: metric_name.to_string(),
        unit: "IOPS".to_string(),
        value: iops,
    })
}
