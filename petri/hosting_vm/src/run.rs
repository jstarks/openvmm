// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Top-level API to run a command inside a hosting VM.

// UNSAFETY: Required for termios raw mode (tcgetattr, tcsetattr, cfmakeraw).
#![expect(unsafe_code)]

use crate::profile::EmulatorConfig;
use crate::profile::HostingVmProfile;
use crate::qemu;
use anyhow::Context;
use petri::cpio;
use std::io::IsTerminal;
use std::net::TcpStream;
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

    // QEMU user-mode networking defaults: guest is 10.0.2.15/24, gateway 10.0.2.2
    let init_script = "\
        #!/bin/sh\n\
        /bin/busybox --install /bin 2>/dev/null\n\
        mount -t devtmpfs none /dev\n\
        mount -t proc none /proc\n\
        mount -t sysfs none /sys\n\
        mkdir -p /dev/pts /share /root /tmp\n\
        mount -t devpts devpts /dev/pts\n\
        mount -t virtiofs hostshare /share\n\
        ip link set eth0 up\n\
        ip addr add 10.0.2.15/24 dev eth0\n\
        ip route add default via 10.0.2.2\n\
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
        &config.kernel,
        &patched_initrd_path,
        virtiofsd.socket_path(),
        host_port,
        kernel_cmdline,
    );

    // QEMU runs in the background. Serial console goes to a log file
    // (kernel dmesg + pipette stderr); pipette handles all command I/O over TCP.
    let serial_log = config.share_dir.join("hosting-vm-serial.log");
    eprintln!("Serial log: {}", serial_log.display());
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::from(
        std::fs::File::create(&serial_log).context("failed to create serial log")?,
    ));
    cmd.stderr(std::process::Stdio::inherit());

    let mut qemu_child = cmd.spawn().context("failed to launch QEMU")?;

    // --- connect to pipette over TCP ---

    let result = run_via_pipette(host_port, &config);

    // --- tear down ---

    let exit_code = match result {
        Ok(code) => Some(code),
        Err(e) => {
            tracing::error!("pipette session failed: {e:#}");
            None
        }
    };

    // Wait for QEMU to exit (it should exit after pipette powers off the VM)
    let _ = qemu_child.wait();
    drop(virtiofsd);

    let elapsed = start.elapsed();

    Ok(HostingVmOutput { exit_code, elapsed })
}

/// Connect to pipette inside the VM over TCP and execute the command.
fn run_via_pipette(host_port: u16, config: &HostingVmConfig) -> anyhow::Result<i32> {
    pal_async::DefaultPool::run_with(|driver| async move {
        // Retry connecting until pipette is ready (VM is still booting)
        eprintln!("Waiting for pipette on port {host_port}...");
        let conn = retry_tcp_connect(host_port, config.timeout).await?;
        eprintln!("TCP connected, wrapping in PolledSocket...");
        let conn =
            pal_async::socket::PolledSocket::new(&driver, conn).context("failed to poll socket")?;

        let output_dir = config.share_dir.join("test_results");
        std::fs::create_dir_all(&output_dir).ok();

        eprintln!("Creating PipetteClient...");
        let client = pipette_client::PipetteClient::new(&driver, conn, &output_dir)
            .await
            .context("failed to connect to pipette")?;

        eprintln!("Connected to pipette, pinging...");
        client.ping().await.context("ping failed")?;
        eprintln!("Ping OK, executing command");

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

        if use_pty {
            cmd.pty(true);
        }

        // Put the host terminal into raw mode so that Ctrl-C, etc.
        // flow through to the guest PTY instead of being handled locally.
        let _raw_guard = if use_pty {
            Some(RawModeGuard::enter().context("failed to enter raw mode")?)
        } else {
            None
        };

        eprintln!("Spawning command (pty={use_pty})...");
        let mut child = cmd
            .spawn()
            .await
            .context("failed to spawn command in guest")?;
        eprintln!("Spawn OK, waiting for exit...");
        let status = child.wait().await.context("failed to wait for command")?;
        eprintln!("Command exited: {status}");

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
    })
}

/// Retry TCP connection to pipette until it succeeds or timeout expires.
async fn retry_tcp_connect(port: u16, timeout: Duration) -> anyhow::Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => {
                stream
                    .set_nodelay(true)
                    .context("failed to set TCP_NODELAY")?;
                return Ok(stream);
            }
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(e) => {
                anyhow::bail!("timed out connecting to pipette on port {port}: {e}");
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
