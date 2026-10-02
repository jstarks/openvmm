// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Top-level API to run a command inside an incubator.

use crate::openvmm;
use crate::profile::IncubatorBackend;
use crate::profile::IncubatorProfile;
use crate::qemu;
use anyhow::Context;
use futures_concurrency::future::Race;
use pal_async::pipe::PolledPipe;
use pal_async::task::Spawn;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

/// Configuration for an incubator run.
pub struct IncubatorConfig {
    /// The parsed profile.
    pub profile: IncubatorProfile,
    /// Path to the guest kernel image.
    pub kernel: PathBuf,
    /// Path to the base initrd (gzip-compressed CPIO).
    pub initrd: PathBuf,
    /// Directory to share into the VM at [`crate::GUEST_SHARE_ROOT`].
    pub share_dir: PathBuf,
    /// Host directory where command output and logs should be written.
    pub output_dir: PathBuf,
    /// Path to the pipette binary inside the guest.
    pub guest_pipette_path: String,
    /// The command to run inside the VM: program followed by arguments.
    pub guest_command: Vec<String>,
    /// Environment variables to set for the guest command.
    pub guest_env: BTreeMap<String, String>,
    /// Working directory for the guest command. If unset, the command inherits
    /// pipette's working directory.
    pub guest_current_dir: Option<String>,
    /// Boot timeout for QEMU. For OpenVMM/mshv this bounds the entire VM
    /// session, including the command. Shutdown has a separate 10-second bound.
    pub timeout: Duration,
    /// If set, override the QEMU binary path specified in the profile.
    pub qemu_binary_override: Option<PathBuf>,
    /// Whether to allocate a PTY for the guest command and put the host
    /// terminal into raw mode. Disabled when running non-interactively (e.g.
    /// as a cargo-nextest target runner), where raw mode would interfere with
    /// nextest's Ctrl-C handling.
    pub allocate_pty: bool,
}

/// Result of an incubator run.
pub struct IncubatorOutput {
    /// The guest command's exit code, if it was captured.
    pub exit_code: Option<i32>,
    /// Total wall time for the run.
    pub elapsed: Duration,
}

/// Run a command inside an incubator.
///
/// Boots an emulated VM according to the profile, mounts `share_dir` at
/// [`crate::GUEST_SHARE_ROOT`] inside the guest, connects to pipette over TCP, executes the
/// command, and returns the exit code. Stdout/stderr are relayed to the
/// host process in real time.
pub fn run_in_incubator(config: IncubatorConfig) -> anyhow::Result<IncubatorOutput> {
    let start = Instant::now();

    // --- pick a host port for pipette TCP forwarding ---

    let host_port = pick_free_port().context("failed to find a free port")?;

    let is_mshv = matches!(config.profile.incubator, IncubatorBackend::OpenvmmMshv(_));
    if is_mshv {
        anyhow::ensure!(
            config.profile.devices.is_empty(),
            "openvmm-mshv does not support extra devices"
        );
        anyhow::ensure!(
            config.qemu_binary_override.is_none(),
            "--qemu-binary is not valid for openvmm-mshv"
        );
    }
    let script = match config.profile.incubator {
        IncubatorBackend::QemuTcg(_) => qemu::build_init_script(&config.guest_pipette_path),
        IncubatorBackend::OpenvmmMshv(_) => openvmm::build_init_script(&config.guest_pipette_path),
    };
    let patched_initrd_path = qemu::prepare_initrd(&config.initrd, &config.output_dir, &script)?;
    let boot_dir = tempfile::Builder::new()
        .prefix(".incubator-boot-")
        .tempdir_in(&config.output_dir)?;
    let mut cmd = match &config.profile.incubator {
        IncubatorBackend::QemuTcg(qemu_config) => {
            let mut qemu_config = qemu_config.clone();
            if let Some(binary) = &config.qemu_binary_override {
                qemu_config.binary = binary.display().to_string();
            }
            qemu::build_qemu_command(
                &qemu_config,
                &config.profile.devices,
                &config.kernel,
                &patched_initrd_path,
                &config.share_dir,
                host_port,
            )?
        }
        IncubatorBackend::OpenvmmMshv(openvmm_config) => {
            let image = boot_dir.path().join("mshv.img");
            openvmm::prepare_image(openvmm_config, &config.kernel, &patched_initrd_path, &image)?;
            openvmm::build_command(openvmm_config, &image, &config.share_dir, host_port)?
        }
    };

    let output_dir = config.output_dir.clone();
    std::fs::create_dir_all(&output_dir).context("failed to create test results dir")?;
    // Each incubator process runs a single test, but several run concurrently
    // under nextest sharing this output directory, so disambiguate the serial
    // log by process id to avoid clobbering each other. The path is logged
    // below so it remains discoverable from the test's captured output.
    let serial_log = output_dir.join(format!("incubator-serial.{}.log", std::process::id()));
    let vmm_log = output_dir.join(format!("incubator-vmm.{}.log", std::process::id()));
    tracing::info!(path = %serial_log.display(), "serial log");
    tracing::info!(path = %vmm_log.display(), command = ?cmd, "VMM log");
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(fs_err::File::create(&vmm_log)?.into_file());

    let mut child = VmChild(cmd.spawn().context("failed to launch incubator VMM")?);
    tracing::info!(pid = child.0.id(), "started incubator VMM");
    let stdout = child.0.stdout.take().expect("stdout should be piped");

    // --- run everything inside the async executor ---

    let result: anyhow::Result<_> = pal_async::DefaultPool::run_with(async |driver| {
        // Relay serial output to the log file in a spawned task.
        // Sends a signal when pipette's "PIPETTE READY" marker appears.
        let (ready_tx, ready_rx) = mesh::oneshot::<()>();
        let serial_pipe = PolledPipe::new(&driver, qemu::child_pipe_to_file(stdout))
            .context("failed to create polled pipe for serial output")?;
        let serial_log_path = serial_log.clone();
        let relay_task = driver.spawn("serial-relay", async move {
            qemu::relay_serial_output(serial_pipe, &serial_log_path, ready_tx).await
        });

        let session = run_via_pipette(&driver, host_port, &config, &mut child.0, ready_rx);
        let result = if is_mshv {
            (session, async {
                pal_async::timer::PolledTimer::new(&driver)
                    .sleep(config.timeout)
                    .await;
                anyhow::bail!(
                    "mshv incubator session timed out after {:?}",
                    config.timeout
                )
            })
                .race()
                .await
        } else {
            session.await
        };
        let result = match result {
            Ok(code) => {
                let shutdown = (qemu::wait_for_exit(&driver, &mut child.0), async {
                    pal_async::timer::PolledTimer::new(&driver)
                        .sleep(Duration::from_secs(10))
                        .await;
                    anyhow::bail!("incubator VMM did not exit after poweroff")
                })
                    .race()
                    .await;
                shutdown.and_then(|status| {
                    anyhow::ensure!(status.success(), "incubator VMM failed: {status}");
                    Ok(code)
                })
            }
            Err(error) => Err(error),
        };
        if result.is_err() {
            child.kill_and_wait()?;
        }

        let relay_result = relay_task.await;
        if let Err(error) = &result {
            tracing::error!(%error, serial = %serial_log.display(), vmm = %vmm_log.display(), "incubator failed");
        }
        let code = result?;
        relay_result?;
        Ok(Some(code))
    });

    let elapsed = start.elapsed();

    Ok(IncubatorOutput {
        exit_code: result?,
        elapsed,
    })
}

/// Connect to pipette inside the VM over TCP and execute the command.
async fn run_via_pipette(
    driver: &pal_async::DefaultDriver,
    host_port: u16,
    config: &IncubatorConfig,
    child: &mut std::process::Child,
    ready_rx: mesh::OneshotReceiver<()>,
) -> anyhow::Result<i32> {
    // Wait for pipette to print its readiness marker on the serial
    // console, or for the VMM to exit (indicating a boot failure).
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], host_port));
    tracing::info!(%addr, "waiting for pipette ready signal");
    qemu::wait_for_pipette_ready(driver, config.timeout, child, ready_rx).await?;

    tracing::info!("pipette ready, connecting");
    let conn = pal_async::socket::PolledSocket::connect_tcp(driver, addr)
        .await
        .context("failed to connect to pipette")?;

    let output_dir = config.output_dir.clone();
    std::fs::create_dir_all(&output_dir).context("failed to create test results dir")?;

    let client = pipette_client::PipetteClient::new(&driver, conn, &output_dir)
        .await
        .context("failed to connect to pipette")?;

    tracing::info!("connected to pipette");

    // Set up VFIO devices before running the guest command.
    let vfio_env = qemu::setup_vfio_devices(&client, &config.profile.devices).await?;

    tracing::info!("executing command");

    let (program, args) = config
        .guest_command
        .split_first()
        .context("empty guest command")?;

    let use_pty = config.allocate_pty;

    let mut cmd = client.command(program);
    cmd.args(args);
    for (key, value) in &config.guest_env {
        cmd.env(key, value);
    }

    if let Some(current_dir) = &config.guest_current_dir {
        cmd.current_dir(current_dir);
    }

    // Pass VFIO device BDFs as environment variables
    for (key, value) in &vfio_env {
        cmd.env(key, value);
    }

    if use_pty {
        cmd.pty(true);
    }

    // Put the host terminal into raw mode so that Ctrl-C, etc.
    // flow through to the guest PTY instead of being handled locally.
    let raw_guard = if use_pty {
        Some(RawModeGuard::enter().context("failed to enter raw mode")?)
    } else {
        None
    };

    let result = async {
        let mut child = cmd
            .spawn()
            .await
            .context("failed to spawn command in guest")?;
        child.wait().await.context("failed to wait for command")
    }
    .await;

    // Restore terminal before printing anything.
    drop(raw_guard);

    let status = result?;
    tracing::info!(%status, "command exited");

    let exit_code = if let Some(code) = status.code() {
        code
    } else if let Some(signal) = status.signal() {
        tracing::warn!("command killed by signal {signal}");
        128 + signal
    } else {
        tracing::warn!("command exited with unknown status");
        1
    };

    // Power off the VM
    client
        .power_off()
        .await
        .context("failed to power off incubator")?;

    Ok(exit_code)
}

struct VmChild(std::process::Child);

impl VmChild {
    fn kill_and_wait(&mut self) -> anyhow::Result<()> {
        if self.0.try_wait()?.is_none() {
            self.0.kill().context("failed to kill incubator VMM")?;
            self.0.wait().context("failed to reap incubator VMM")?;
        }
        Ok(())
    }
}

impl Drop for VmChild {
    fn drop(&mut self) {
        if let Err(error) = self.kill_and_wait() {
            tracing::error!(%error, "failed to clean up incubator VMM");
        }
    }
}

/// Find a free TCP port by binding to port 0 and reading the assigned port.
fn pick_free_port() -> anyhow::Result<u16> {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").context("failed to bind ephemeral port")?;
    let port = listener
        .local_addr()
        .context("failed to get local addr")?
        .port();
    Ok(port)
}

/// RAII guard that puts the terminal into raw mode and restores it on drop,
/// so that Ctrl-C and similar control sequences flow through to the guest PTY
/// instead of being interpreted by the host terminal.
struct RawModeGuard;

impl RawModeGuard {
    fn enter() -> anyhow::Result<Self> {
        crossterm::terminal::enable_raw_mode().context("failed to enable raw mode")?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if let Err(e) = crossterm::terminal::disable_raw_mode() {
            tracing::warn!(error = %e, "failed to restore terminal mode");
        }
    }
}
