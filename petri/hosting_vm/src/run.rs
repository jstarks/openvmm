// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Top-level API to run a command inside a hosting VM.

// UNSAFETY: Required for termios raw mode (tcgetattr, tcsetattr, cfmakeraw).
#![expect(unsafe_code)]

use crate::profile::DeviceConfig;
use crate::profile::EmulatorConfig;
use crate::profile::HostingVmProfile;
use crate::qemu;
use anyhow::Context;
use futures_concurrency::future::Race;
use pal_async::process::PolledChild;
use petri::cpio;
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

/// Configuration for a hosting VM run.
pub struct HostingVmConfig {
    /// The parsed profile.
    pub profile: HostingVmProfile,
    /// Path to the guest kernel image.
    pub kernel: PathBuf,
    /// Path to the base initrd (gzip-compressed CPIO).
    pub initrd: PathBuf,
    /// Directory to share into the VM at `/share`.
    pub share_dir: PathBuf,
    /// The command to run inside the VM: program followed by arguments.
    pub guest_command: Vec<String>,
    /// Timeout for the entire run (boot + command + shutdown).
    pub timeout: Duration,
}

/// Result of a hosting VM run.
pub struct HostingVmOutput {
    /// The guest command's exit code, if it was captured.
    pub exit_code: Option<i32>,
    /// Total wall time for the run.
    pub elapsed: Duration,
}

/// Run a command inside a hosting VM.
///
/// Boots an emulated VM according to the profile, mounts `share_dir` at
/// `/share` inside the guest, connects to pipette over TCP, executes the
/// command, and returns the exit code. Stdout/stderr are relayed to the
/// host process in real time.
pub fn run_in_hosting_vm(config: HostingVmConfig) -> anyhow::Result<HostingVmOutput> {
    let start = Instant::now();

    // --- pick a host port for pipette TCP forwarding ---

    let host_port = pick_free_port().context("failed to find a free port")?;

    // --- build the init script ---
    // Sets up the environment, mounts virtio-fs, brings up networking,
    // and launches pipette in TCP mode. Pipette then waits for the host
    // to connect and send commands.

    // QEMU user-mode networking defaults: guest is 10.0.2.15/24, gateway 10.0.2.2,
    // DNS forwarder at 10.0.2.3.
    let init_script = "\
        #!/bin/sh\n\
        /bin/busybox --install /bin 2>/dev/null\n\
        mount -t devtmpfs none /dev\n\
        mount -t proc none /proc\n\
        mount -t sysfs none /sys\n\
        mkdir -p /dev/pts /share /root /tmp /etc\n\
        mount -t devpts devpts /dev/pts\n\
        mount -t virtiofs hostshare /share\n\
        ip link set eth0 up\n\
        ip addr add 10.0.2.15/24 dev eth0\n\
        ip route add default via 10.0.2.2\n\
        echo 'nameserver 10.0.2.3' > /etc/resolv.conf\n\
        export VMM_TESTS_CONTENT_DIR=/share\n\
        export HOME=/root\n\
        cd /share\n\
        exec /share/pipette --transport tcp\n"
        .to_string();

    // --- inject init script into initrd ---

    let initrd_data = std::fs::read(&config.initrd).context("failed to read initrd")?;

    let patched_initrd = cpio::inject_into_initrd(
        &initrd_data,
        "tcg-init.sh",
        init_script.as_bytes(),
        0o100755, // regular file, rwxr-xr-x
    )
    .context("failed to inject init script into initrd")?;

    let patched_initrd_path = config.share_dir.join(".hosting-vm-initrd.gz");
    std::fs::write(&patched_initrd_path, &patched_initrd)
        .context("failed to write patched initrd")?;

    // --- start virtiofsd ---

    let sock = config.share_dir.join(".hosting-vm-virtiofs.sock");
    let virtiofsd =
        qemu::Virtiofsd::start(&config.share_dir, &sock).context("failed to start virtiofsd")?;

    // --- launch QEMU ---

    let EmulatorConfig::QemuTcg(ref qemu_config) = config.profile.emulator;

    let kernel_cmdline = "console=ttyAMA0 rdinit=/tcg-init.sh";

    let mut cmd = qemu::build_qemu_command(
        qemu_config,
        &config.profile.devices,
        &config.kernel,
        &patched_initrd_path,
        virtiofsd.socket_path(),
        host_port,
        kernel_cmdline,
    );

    // QEMU runs in the background. Serial console goes to a log file
    // (kernel dmesg + pipette stderr); pipette handles all command I/O over TCP.
    let serial_log = config.share_dir.join("hosting-vm-serial.log");
    tracing::info!(path = %serial_log.display(), "serial log");
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::from(
        std::fs::File::create(&serial_log).context("failed to create serial log")?,
    ));
    cmd.stderr(std::process::Stdio::inherit());

    let qemu_child = cmd.spawn().context("failed to launch QEMU")?;

    // --- run everything inside the async executor ---

    let result: anyhow::Result<_> = pal_async::DefaultPool::run_with(|driver| async move {
        let mut qemu_child = PolledChild::<std::process::Child>::new(&driver, qemu_child)
            .context("failed to create PolledChild")?;

        let result = run_via_pipette(&driver, host_port, &config, &mut qemu_child).await;

        let exit_code = match result {
            Ok(code) => Some(code),
            Err(e) => {
                tracing::error!("pipette session failed: {e:#}");
                None
            }
        };

        // On success, pipette sent a power_off so QEMU should exit soon.
        // On failure, QEMU is still running — kill it.
        let child = qemu_child.get_mut();
        if exit_code.is_none() {
            let _ = child.kill();
        }
        let _ = child.wait();

        Ok(exit_code)
    });

    drop(virtiofsd);
    let elapsed = start.elapsed();

    Ok(HostingVmOutput {
        exit_code: result?,
        elapsed,
    })
}

/// Connect to pipette inside the VM over TCP and execute the command.
async fn run_via_pipette(
    driver: &pal_async::DefaultDriver,
    host_port: u16,
    config: &HostingVmConfig,
    qemu_child: &mut PolledChild<std::process::Child>,
) -> anyhow::Result<i32> {
    // Retry connecting until pipette is ready (VM is still booting),
    // or QEMU exits early (e.g., bad arguments).
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], host_port));
    tracing::info!(%addr, "waiting for pipette");
    let conn = retry_tcp_connect(driver, addr, config.timeout, qemu_child).await?;

    let output_dir = config.share_dir.join("test_results");
    std::fs::create_dir_all(&output_dir).ok();

    let client = pipette_client::PipetteClient::new(&driver, conn, &output_dir)
        .await
        .context("failed to connect to pipette")?;

    tracing::info!("connected to pipette");
    client.ping().await.context("ping failed")?;
    tracing::info!("ping OK");

    // Set up VFIO devices before running the guest command.
    let vfio_env = setup_vfio_devices(&client, &config.profile.devices).await?;

    tracing::info!("executing command");

    let (program, args) = config
        .guest_command
        .split_first()
        .context("empty guest command")?;

    let use_pty = std::io::stdin().is_terminal();

    let mut cmd = client.command(program);
    cmd.args(args);
    cmd.env("VMM_TESTS_CONTENT_DIR", "/share");
    cmd.env("HOME", "/root");
    cmd.current_dir("/share");

    // Pass VFIO device BDFs as environment variables
    for (key, value) in &vfio_env {
        cmd.env(key, value);
    }

    if use_pty {
        cmd.pty(true);
    }

    // Put the host terminal into raw mode so that Ctrl-C, etc.
    // flow through to the guest PTY instead of being handled locally.
    #[cfg(unix)]
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
    #[cfg(unix)]
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
    let _ = client.power_off().await;

    Ok(exit_code)
}

/// Retry async TCP connection to pipette until it succeeds, timeout
/// expires, or the QEMU process exits.
async fn retry_tcp_connect(
    driver: &impl pal_async::driver::Driver,
    addr: std::net::SocketAddr,
    timeout: Duration,
    qemu_child: &mut PolledChild<std::process::Child>,
) -> anyhow::Result<pal_async::socket::PolledSocket<std::net::TcpStream>> {
    let deadline = Instant::now() + timeout;
    loop {
        enum Event {
            Connected(pal_async::socket::PolledSocket<std::net::TcpStream>),
            ConnectFailed,
            QemuExited(std::process::ExitStatus),
        }

        let event = (
            async {
                match pal_async::socket::PolledSocket::connect_tcp(driver, addr).await {
                    Ok(conn) => Event::Connected(conn),
                    Err(_) => Event::ConnectFailed,
                }
            },
            async {
                match qemu_child.wait().await {
                    Ok(status) => Event::QemuExited(status),
                    Err(_) => Event::QemuExited(std::process::ExitStatus::default()),
                }
            },
        )
            .race()
            .await;

        match event {
            Event::Connected(conn) => return Ok(conn),
            Event::QemuExited(status) => {
                anyhow::bail!("QEMU exited before pipette connected (status: {status})");
            }
            Event::ConnectFailed => {
                if Instant::now() >= deadline {
                    anyhow::bail!("timed out connecting to pipette on {addr}");
                }
            }
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

/// Set up VFIO devices inside the hosting VM.
///
/// Each extra device in the profile sits behind its own PCIe root port
/// at a known PCI device number (see [`qemu::EXTRA_DEVICE_ADDR_BASE`]). This
/// function discovers the child device's BDF by finding the bridge at
/// that slot in sysfs, then unbinds the child from its driver and binds
/// it to vfio-pci.
///
/// Returns a map of environment variables to set for the guest command,
/// e.g., `HOSTING_VM_VFIO_BDF_TEST_DISK=0000:01:00.0`.
async fn setup_vfio_devices(
    client: &pipette_client::PipetteClient,
    devices: &[DeviceConfig],
) -> anyhow::Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();

    // Collect (device_index, config) for devices that need VFIO binding.
    let vfio_devices: Vec<_> = devices
        .iter()
        .enumerate()
        .filter_map(|(i, d)| match d {
            DeviceConfig::VirtioBlk(cfg) if cfg.vfio => Some((i, cfg)),
            DeviceConfig::VirtioBlk(_) => None,
        })
        .collect();

    if vfio_devices.is_empty() {
        return Ok(env);
    }

    tracing::info!("setting up {} VFIO device(s)", vfio_devices.len());

    let sh = client.unix_shell();

    for (device_index, cfg) in &vfio_devices {
        let addr = qemu::EXTRA_DEVICE_ADDR_BASE + device_index;

        // The root port BDF is deterministic: 0000:00:{addr:02x}.0
        // Find the first child device on the secondary bus behind it.
        let rp_bdf = format!("0000:00:{addr:02x}.0");
        let bdf = sh
            .cmd("sh")
            .arg("-c")
            .arg(format!(
                concat!(
                    "bridge=/sys/bus/pci/devices/{rp}; ",
                    "if [ ! -d \"$bridge/pci_bus\" ]; then echo NOTFOUND; exit 0; fi; ",
                    "bus=$(ls $bridge/pci_bus/ | head -1); ",
                    "child=$(ls -d /sys/bus/pci/devices/$bus:* 2>/dev/null | head -1); ",
                    "if [ -n \"$child\" ]; then basename $child; else echo NOTFOUND; fi",
                ),
                rp = rp_bdf,
            ))
            .read()
            .await?;

        let bdf = bdf.trim().to_string();
        if bdf == "NOTFOUND" || bdf.is_empty() {
            anyhow::bail!(
                "could not find child device behind root port at addr {} for device '{}'",
                addr,
                cfg.name
            );
        }

        tracing::info!(name = %cfg.name, %bdf, %addr, "binding device to vfio-pci");

        // Unbind from current driver
        let _ = client
            .write_file(
                format!("/sys/bus/pci/devices/{bdf}/driver/unbind"),
                bdf.as_bytes(),
            )
            .await;

        // Set driver override to vfio-pci
        client
            .write_file(
                format!("/sys/bus/pci/devices/{bdf}/driver_override"),
                b"vfio-pci".as_slice(),
            )
            .await
            .context("failed to set driver_override")?;

        // Bind to vfio-pci
        client
            .write_file("/sys/bus/pci/drivers/vfio-pci/bind", bdf.as_bytes())
            .await
            .context("failed to bind to vfio-pci")?;

        // Export env var: name "test-disk" → HOSTING_VM_VFIO_BDF_TEST_DISK
        let env_name = format!(
            "HOSTING_VM_VFIO_BDF_{}",
            cfg.name.to_uppercase().replace('-', "_")
        );
        tracing::info!(%env_name, %bdf, "VFIO device ready");
        env.insert(env_name, bdf);
    }

    Ok(env)
}

/// RAII guard that puts stdin into raw mode and restores it on drop.
#[cfg(unix)]
struct RawModeGuard {
    original: libc::termios,
}

#[cfg(unix)]
impl RawModeGuard {
    fn enter() -> anyhow::Result<Self> {
        use std::mem::MaybeUninit;
        use std::os::fd::AsRawFd;

        let fd = std::io::stdin().as_raw_fd();
        let mut original = MaybeUninit::zeroed();
        // SAFETY: tcgetattr writes to the provided pointer.
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            anyhow::bail!("tcgetattr failed: {}", std::io::Error::last_os_error());
        }
        // SAFETY: tcgetattr succeeded, so original is initialized.
        let original = unsafe { original.assume_init() };

        let mut raw = original;
        // SAFETY: cfmakeraw modifies the termios struct in place.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: tcsetattr applies the termios settings.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            anyhow::bail!("tcsetattr failed: {}", std::io::Error::last_os_error());
        }

        Ok(Self { original })
    }
}

#[cfg(unix)]
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        // SAFETY: restoring the original termios settings.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &self.original) };
    }
}
