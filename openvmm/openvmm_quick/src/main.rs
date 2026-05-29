// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Quick launcher for Windows (and eventually Linux) VMs with automated remote
//! shell access.
//!
//! This tool boots a Windows VM using openvmm with pipette (a guest agent)
//! pre-configured via an IMC hive, then uses pipette to bootstrap SSH or WinRM
//! inside the guest so the user can connect with standard tools.

#![expect(missing_docs)]

mod cidata;

use anyhow::Context;
use clap::Parser;
use clap::ValueEnum;
use futures::FutureExt;
use pal_async::DefaultDriver;
use pal_async::DefaultPool;
use pal_async::socket::PolledSocket;
use pipette_client::PipetteClient;
use std::net::TcpListener;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use unix_socket::UnixListener;

/// Quick-launch a VM with automated remote shell access.
#[derive(Parser)]
#[clap(name = "openvmm-quick")]
struct Options {
    /// Path or URL to the Windows VHD/VHDX disk image.
    ///
    /// Local paths use a memdiff overlay by default (see --overlay).
    /// HTTP(S) URLs use an autocache + sqldiff layer so only changed
    /// blocks are downloaded and writes go to a local SQLite database.
    #[clap(long)]
    image: String,

    /// Path to the UEFI firmware binary.
    ///
    /// If not specified, checks OPENVMM_UEFI_FIRMWARE and then
    /// X86_64_OPENVMM_UEFI_FIRMWARE / AARCH64_OPENVMM_UEFI_FIRMWARE.
    #[clap(long)]
    firmware: Option<PathBuf>,

    /// Path to pipette.exe (Windows guest agent).
    ///
    /// If not specified, looks for it in the cargo target directory.
    #[clap(long, env = "OPENVMM_QUICK_PIPETTE")]
    pipette: Option<PathBuf>,

    /// Path to the openvmm binary.
    ///
    /// If not specified, looks for it in the cargo target directory.
    #[clap(long, env = "OPENVMM_QUICK_OPENVMM")]
    openvmm: Option<PathBuf>,

    /// Remote shell type to bootstrap.
    #[clap(long, default_value = "ssh")]
    shell: ShellType,

    /// Host port for SSH (default: auto-select a free port).
    #[clap(long)]
    ssh_port: Option<u16>,

    /// Host port for WinRM (default: auto-select a free port).
    #[clap(long)]
    winrm_port: Option<u16>,

    /// Number of virtual processors.
    #[clap(long, short = 'p', default_value = "4")]
    processors: u32,

    /// Memory size (e.g., "4G", "2048M").
    #[clap(long, short = 'm', default_value = "4G")]
    memory: String,

    /// Use a copy-on-write overlay so the original disk image is not modified
    /// (only applies to local images; HTTP images always use sqldiff).
    #[clap(long, default_value = "true")]
    overlay: bool,

    /// Cache directory for the HTTP block cache (read-only, shared).
    ///
    /// Defaults to ~/.cache/openvmm-quick.
    #[clap(long, env = "OPENVMM_QUICK_CACHE_DIR")]
    cache_dir: Option<PathBuf>,

    /// Working directory for the writable disk diff layer.
    ///
    /// Guest writes go here. Defaults to the current directory.
    #[clap(long)]
    work_dir: Option<PathBuf>,

    /// Only print the openvmm command line without running it.
    #[clap(long)]
    dry_run: bool,

    /// Path to the IMC hive file. If not specified, uses the embedded hive.
    #[clap(long)]
    imc_hive: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum ShellType {
    /// Bootstrap OpenSSH Server and connect via SSH.
    Ssh,
    /// Bootstrap WinRM and connect via PowerShell remoting.
    Winrm,
}

pub fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let opts = Options::parse();

    if opts.dry_run {
        return dry_run(&opts);
    }

    DefaultPool::run_with(async |driver| run(driver, opts).await)
}

/// Print the openvmm command line and exit.
fn dry_run(opts: &Options) -> anyhow::Result<()> {
    let firmware_path = find_firmware(&opts.firmware)?;
    let pipette_path = find_pipette(&opts.pipette)?;
    let openvmm_path = find_openvmm(&opts.openvmm)?;

    let temp_dir = tempfile::tempdir().context("failed to create temp directory")?;

    // Build the CIDATA disk.
    let cidata_path = temp_dir.path().join("cidata.img");
    cidata::build_cidata_disk(&cidata_path, &pipette_path)?;

    // Write the IMC hive.
    let imc_path = match &opts.imc_hive {
        Some(p) => p.clone(),
        None => {
            let p = temp_dir.path().join("imc.hiv");
            std::fs::write(&p, include_bytes!("../../../petri/guest-bootstrap/imc.hiv"))
                .context("failed to write IMC hive")?;
            p
        }
    };

    let host_port = pick_port(match opts.shell {
        ShellType::Ssh => opts.ssh_port,
        ShellType::Winrm => opts.winrm_port,
    })?;
    let guest_port = match opts.shell {
        ShellType::Ssh => 22,
        ShellType::Winrm => 5985,
    };

    let vsock_path = temp_dir.path().join("vsock");

    let args = build_openvmm_args(
        opts,
        &firmware_path,
        &cidata_path,
        &imc_path,
        &vsock_path,
        host_port,
        guest_port,
    );
    println!("{} {}", openvmm_path.display(), args.join(" "));
    eprintln!();
    eprintln!("NOTE: temp files are in {}", temp_dir.path().display());
    eprintln!("      the directory will be deleted when this process exits.");
    eprintln!("      Copy files elsewhere or use --imc-hive / --pipette to persist.");

    // Keep temp_dir alive until user presses enter.
    eprintln!();
    eprintln!("Press Enter to clean up and exit...");
    let _ = std::io::stdin().read_line(&mut String::new());

    Ok(())
}

/// Main async entry point: launch openvmm, connect pipette, bootstrap shell.
async fn run(driver: DefaultDriver, opts: Options) -> anyhow::Result<()> {
    let firmware_path = find_firmware(&opts.firmware)?;
    let pipette_path = find_pipette(&opts.pipette)?;
    let openvmm_path = find_openvmm(&opts.openvmm)?;

    let temp_dir = tempfile::tempdir().context("failed to create temp directory")?;

    // Build the CIDATA disk.
    let cidata_path = temp_dir.path().join("cidata.img");
    cidata::build_cidata_disk(&cidata_path, &pipette_path)
        .context("failed to build CIDATA disk")?;

    // Write the IMC hive.
    let imc_path = match &opts.imc_hive {
        Some(p) => p.clone(),
        None => {
            let p = temp_dir.path().join("imc.hiv");
            std::fs::write(&p, include_bytes!("../../../petri/guest-bootstrap/imc.hiv"))
                .context("failed to write IMC hive")?;
            p
        }
    };

    let host_port = pick_port(match opts.shell {
        ShellType::Ssh => opts.ssh_port,
        ShellType::Winrm => opts.winrm_port,
    })?;
    let guest_port = match opts.shell {
        ShellType::Ssh => 22,
        ShellType::Winrm => 5985,
    };

    let vsock_path = temp_dir.path().join("vsock");
    let args = build_openvmm_args(
        &opts,
        &firmware_path,
        &cidata_path,
        &imc_path,
        &vsock_path,
        host_port,
        guest_port,
    );

    // Set up the pipette vsock listener before launching openvmm.
    let pipette_vsock_port = pipette_client::PIPETTE_VSOCK_PORT;
    let pipette_listener_path = format!("{}_{}", vsock_path.display(), pipette_vsock_port);
    let listener = UnixListener::bind(&pipette_listener_path)
        .context("failed to bind pipette vsock listener")?;
    let mut listener =
        PolledSocket::new(&driver, listener).context("failed to create polled listener")?;

    // Launch openvmm.
    eprintln!("Launching openvmm...");
    eprintln!("  {} {}", openvmm_path.display(), args.join(" "));
    let mut cmd = std::process::Command::new(&openvmm_path);
    cmd.args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    // Set OPENVMM_AUTO_CACHE_PATH for HTTP-based images.
    if is_http_url(&opts.image) {
        let cache_dir = resolve_cache_dir(&opts.cache_dir);
        std::fs::create_dir_all(&cache_dir).context("failed to create cache directory")?;
        cmd.env("OPENVMM_AUTO_CACHE_PATH", &cache_dir);
        eprintln!("  cache dir: {}", cache_dir.display());
    }

    let mut child = cmd.spawn().context("failed to launch openvmm")?;

    // Set up a self-pipe for Ctrl+C notification. The signal handler writes
    // to the pipe, waking the async loop immediately.
    let (sigint_read, sigint_write) =
        unix_socket::UnixStream::pair().context("failed to create signal socketpair")?;
    let ctrlc_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let ctrlc_count2 = ctrlc_count.clone();
    ctrlc::set_handler(move || {
        let n = ctrlc_count2.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        match n {
            1 => eprintln!("\nShutting down VM..."),
            2 => eprintln!("\nPress Ctrl+C once more to force kill."),
            _ => {
                eprintln!("\nForce killing VM...");
                std::process::exit(1);
            }
        }
        // Wake the async loop.
        use std::io::Write;
        let _ = (&sigint_write).write(&[n as u8]);
    })
    .context("failed to install Ctrl+C handler")?;

    // Wrap the read end for async polling.
    let sigint_sock =
        PolledSocket::new(&driver, sigint_read).context("failed to poll signal socket")?;
    let mut sigint_reader = futures::io::BufReader::new(sigint_sock);

    // Wait for pipette to connect, racing against Ctrl+C and child exit.
    eprintln!("Waiting for Windows to boot and pipette to connect...");

    // Monitor child exit on a background thread, signaling via a socketpair.
    // The thread owns `child` and calls wait(), avoiding zombie processes.
    let (child_exit_read, child_exit_write) =
        unix_socket::UnixStream::pair().context("failed to create child exit socketpair")?;
    let (child_send, child_recv) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let status = child.wait();
        // Wake the async loop.
        use std::io::Write;
        let _ = (&child_exit_write).write(&[1]);
        // Send the child + status back so the main thread can use them.
        let _ = child_send.send((child, status));
    });
    let child_exit_sock =
        PolledSocket::new(&driver, child_exit_read).context("failed to poll child exit")?;
    let mut child_exit_reader = futures::io::BufReader::new(child_exit_sock);

    let accept_fut = std::pin::pin!(listener.accept());
    let mut sigint_buf = [0u8; 1];
    let sigint_wait = std::pin::pin!(futures::AsyncReadExt::read(
        &mut sigint_reader,
        &mut sigint_buf
    ));
    let mut child_exit_buf = [0u8; 1];
    let child_exit_wait = std::pin::pin!(futures::AsyncReadExt::read(
        &mut child_exit_reader,
        &mut child_exit_buf
    ));
    let conn = futures::select! {
        result = accept_fut.fuse() => {
            result.context("failed to accept pipette connection")?.0
        }
        _ = sigint_wait.fuse() => {
            eprintln!("Interrupted during boot.");
            // Recover child from the waiter thread and kill it.
            if let Ok((mut child, _)) = child_recv.recv() {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Ok(());
        }
        _ = child_exit_wait.fuse() => {
            let (_, status) = child_recv.recv().context("child waiter thread died")?;
            let status = status.context("failed to wait for openvmm")?;
            anyhow::bail!("openvmm exited early with status: {status}");
        }
    };

    // We got a pipette connection. The child waiter thread is still running;
    // set up a new waiter for the post-bootstrap phase. We need `child` back
    // from the boot waiter thread — but it's still blocked in wait(). Instead,
    // reuse the same child_exit_reader and child_recv for the running phase.

    let conn = PolledSocket::new(&driver, conn).context("failed to poll pipette connection")?;

    let output_dir = temp_dir.path().join("pipette-output");
    std::fs::create_dir_all(&output_dir)?;
    let client = PipetteClient::new(&driver, conn, &output_dir)
        .await
        .context("failed to connect to pipette")?;

    eprintln!("Connected to pipette. Bootstrapping remote access...");

    // Bootstrap the requested shell type.
    match opts.shell {
        ShellType::Ssh => bootstrap_ssh(&client, host_port).await?,
        ShellType::Winrm => bootstrap_winrm(&client, host_port).await?,
    }

    // Wait for the child process with progressive Ctrl+C handling.
    eprintln!();
    eprintln!("VM is running. Press Ctrl+C to stop.");

    // Read from the child exit socket again for the running phase.
    let mut child_exit_buf2 = [0u8; 1];
    let child_exit_wait2 = std::pin::pin!(futures::AsyncReadExt::read(
        &mut child_exit_reader,
        &mut child_exit_buf2
    ));
    // Read from the sigint socket for the running phase.
    let mut sigint_buf2 = [0u8; 1];
    let sigint_wait2 = std::pin::pin!(futures::AsyncReadExt::read(
        &mut sigint_reader,
        &mut sigint_buf2
    ));

    futures::select! {
        _ = child_exit_wait2.fuse() => {
            // Child exited on its own.
            let (_, status) = child_recv.recv().context("child waiter thread died")?;
            let status = status.context("failed to wait for openvmm")?;
            if status.success() {
                eprintln!("VM shut down.");
                return Ok(());
            }
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if status.signal().is_some() {
                    return Ok(());
                }
            }
            anyhow::bail!("openvmm exited with status: {status}");
        }
        _ = sigint_wait2.fuse() => {
            // First Ctrl+C: graceful shutdown via pipette.
            match client.power_off().await {
                Ok(()) => eprintln!("Shutdown command sent. Waiting for VM to stop..."),
                Err(e) => eprintln!("Failed to send shutdown: {e}"),
            }
            // Wait for child to actually exit.
            // 2nd Ctrl+C prints warning, 3rd calls process::exit(1).
            if let Ok((_, status)) = child_recv.recv() {
                if let Ok(status) = status {
                    if status.success() {
                        eprintln!("VM shut down cleanly.");
                    }
                }
            }
        }
    }

    Ok(())
}

/// Bootstrap OpenSSH Server inside the Windows guest via pipette.
async fn bootstrap_ssh(client: &PipetteClient, host_port: u16) -> anyhow::Result<()> {
    let shell = client.windows_shell();

    eprintln!("  Installing OpenSSH Server...");
    shell
        .cmd("powershell")
        .arg("-Command")
        .arg("$ErrorActionPreference='Stop'; Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0")
        .run()
        .await
        .context("failed to install OpenSSH Server")?;

    eprintln!("  Starting sshd service...");
    shell
        .cmd("powershell")
        .arg("-Command")
        .arg("$ErrorActionPreference='Stop'; Start-Service sshd; Set-Service -Name sshd -StartupType Automatic")
        .run()
        .await
        .context("failed to start sshd")?;

    // Ensure the firewall allows inbound SSH.
    eprintln!("  Configuring firewall...");
    shell
        .cmd("netsh")
        .arg("advfirewall")
        .arg("firewall")
        .arg("add")
        .arg("rule")
        .arg("name=sshd")
        .arg("dir=in")
        .arg("action=allow")
        .arg("protocol=TCP")
        .arg("localport=22")
        .run()
        .await
        .context("failed to configure firewall for SSH")?;

    // Set password auth as fallback (user can also inject keys).
    eprintln!("  Configuring password authentication...");
    shell
        .cmd("powershell")
        .arg("-Command")
        .arg(concat!(
            "$ErrorActionPreference='Stop'; ",
            "$c = Get-Content $env:ProgramData\\ssh\\sshd_config; ",
            "$c = $c -replace '#PasswordAuthentication yes','PasswordAuthentication yes'; ",
            "Set-Content $env:ProgramData\\ssh\\sshd_config $c; ",
            "Restart-Service sshd",
        ))
        .run()
        .await
        .context("failed to configure sshd")?;

    // Verify sshd is actually listening.
    eprintln!("  Verifying sshd is listening...");
    shell
        .cmd("powershell")
        .arg("-Command")
        .arg("$ErrorActionPreference='Stop'; $n = (Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue); if (-not $n) { throw 'sshd is not listening on port 22' }")
        .run()
        .await
        .context("sshd is not listening on port 22 -- SSH setup may have failed")?;

    // Try to inject the user's SSH public key.
    if let Some(pubkey) = find_ssh_pubkey() {
        eprintln!("  Injecting SSH public key...");
        let script = format!(
            "$ErrorActionPreference='Stop'; \
             $keyDir = Join-Path $env:ProgramData 'ssh'; \
             $keyFile = Join-Path $keyDir 'administrators_authorized_keys'; \
             Set-Content $keyFile '{}'; \
             icacls $keyFile /inheritance:r /grant 'SYSTEM:(F)' /grant 'BUILTIN\\Administrators:(F)'",
            pubkey.replace('\'', "''")
        );
        shell
            .cmd("powershell")
            .arg("-Command")
            .arg(&script)
            .run()
            .await
            .context("failed to inject SSH key")?;
    }

    eprintln!();
    eprintln!("SSH is ready. Connect with:");
    eprintln!("  ssh -p {host_port} Administrator@localhost");
    if find_ssh_pubkey().is_none() {
        eprintln!();
        eprintln!("  No SSH public key found in ~/.ssh/. You'll need the Administrator password.");
    }

    Ok(())
}

/// Bootstrap WinRM inside the Windows guest via pipette.
async fn bootstrap_winrm(client: &PipetteClient, host_port: u16) -> anyhow::Result<()> {
    let shell = client.windows_shell();

    eprintln!("  Enabling WinRM...");
    shell
        .cmd("powershell")
        .arg("-Command")
        .arg("Enable-PSRemoting -Force -SkipNetworkProfileCheck")
        .run()
        .await
        .context("failed to enable WinRM")?;

    // Allow unencrypted for local dev/test. Don't do this in production!
    shell
        .cmd("powershell")
        .arg("-Command")
        .arg("Set-Item WSMan:\\localhost\\Service\\AllowUnencrypted -Value true")
        .run()
        .await
        .context("failed to configure WinRM")?;

    shell
        .cmd("powershell")
        .arg("-Command")
        .arg("Set-Item WSMan:\\localhost\\Service\\Auth\\Basic -Value true")
        .run()
        .await
        .context("failed to configure WinRM auth")?;

    eprintln!();
    eprintln!("WinRM is ready. Connect with:");
    eprintln!(
        "  Enter-PSSession -ComputerName localhost -Port {host_port} -Credential Administrator"
    );

    Ok(())
}

/// Build the openvmm command-line arguments.
fn build_openvmm_args(
    opts: &Options,
    firmware_path: &Path,
    cidata_path: &Path,
    imc_path: &Path,
    vsock_path: &Path,
    host_port: u16,
    guest_port: u16,
) -> Vec<String> {
    let mut args = Vec::new();

    // Processors and memory.
    args.extend(["-p".into(), opts.processors.to_string()]);
    args.extend(["-m".into(), opts.memory.clone()]);

    // UEFI firmware.
    args.extend(["--uefi".into()]);
    args.extend([
        "--uefi-firmware".into(),
        firmware_path.display().to_string(),
    ]);

    // Hyper-V enlightenments (needed for VMBus / vsock / IMC).
    args.push("--hv".into());

    // Send serial output to stderr for boot diagnostics, but don't use
    // "console" mode which puts the terminal into raw mode.
    args.extend(["--com1".into(), "stderr".into()]);

    // Boot disk.
    let disk_spec = boot_disk_spec(opts);
    args.extend(["--disk".into(), disk_spec]);

    // CIDATA disk with pipette (becomes LUN 1).
    args.extend([
        "--disk".into(),
        format!("file:{},ro", cidata_path.display()),
    ]);

    // IMC hive.
    args.extend(["--imc".into(), imc_path.display().to_string()]);

    // Vsock for pipette communication.
    args.extend([
        "--vmbus-vsock-path".into(),
        vsock_path.display().to_string(),
    ]);

    // Networking with port forwarding.
    args.extend([
        "--net".into(),
        format!("consomme:hostfwd=tcp::{host_port}-:{guest_port}"),
    ]);

    args
}

/// Returns true if the image string looks like an HTTP(S) URL.
fn is_http_url(image: &str) -> bool {
    image.starts_with("http://") || image.starts_with("https://")
}

/// Construct the boot disk `--disk` spec.
///
/// For local files: `memdiff:file:<path>` (or `file:<path>` if overlay is off).
/// For HTTP URLs: `sqldiff:<work_dir>/disk-diff.sqlite;create:autocache::blob:vhd1:<url>`
fn boot_disk_spec(opts: &Options) -> String {
    if is_http_url(&opts.image) {
        let work_dir = opts.work_dir.clone().unwrap_or_else(|| PathBuf::from("."));
        let diff_path = work_dir.join("disk-diff.sqlite");
        // sqldiff writable layer on top of autocached HTTP blob.
        // autocache:: (empty key) means "derive cache key from VHD footer UUID".
        format!(
            "sqldiff:{};create:autocache::blob:vhd1:{}",
            diff_path.display(),
            opts.image
        )
    } else if opts.overlay {
        format!("memdiff:file:{}", opts.image)
    } else {
        format!("file:{}", opts.image)
    }
}

/// Resolve the cache directory, creating it if needed.
fn resolve_cache_dir(explicit: &Option<PathBuf>) -> PathBuf {
    if let Some(dir) = explicit {
        return dir.clone();
    }
    // Default: ~/.cache/openvmm-quick
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".cache").join("openvmm-quick")
}

/// Find a free TCP port, or verify the requested one is available.
fn pick_port(requested: Option<u16>) -> anyhow::Result<u16> {
    let port = requested.unwrap_or(0);
    let listener =
        TcpListener::bind(("127.0.0.1", port)).context("failed to bind to requested port")?;
    let actual = listener
        .local_addr()
        .context("failed to get local address")?
        .port();
    // Drop the listener to free the port. There's a small race here but it's
    // fine for dev tooling.
    drop(listener);
    Ok(actual)
}

/// Find the UEFI firmware binary.
///
/// Checks (in order): explicit `--firmware` flag, `OPENVMM_UEFI_FIRMWARE` env
/// var, then arch-prefixed variants like `X86_64_OPENVMM_UEFI_FIRMWARE` (which
/// `.cargo/config.toml` sets with relative paths).
fn find_firmware(explicit: &Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        anyhow::ensure!(path.exists(), "firmware not found at {}", path.display());
        return Ok(path.clone());
    }

    // Same env var fallback logic as openvmm's default_value_from_arch_env.
    let env_vars = [
        "OPENVMM_UEFI_FIRMWARE",
        if cfg!(target_arch = "aarch64") {
            "AARCH64_OPENVMM_UEFI_FIRMWARE"
        } else {
            "X86_64_OPENVMM_UEFI_FIRMWARE"
        },
    ];

    for var in &env_vars {
        if let Ok(val) = std::env::var(var) {
            let path = PathBuf::from(&val);
            if path.exists() {
                eprintln!("Found firmware at {} (from {var})", path.display());
                return Ok(path);
            }
        }
    }

    anyhow::bail!(
        "Could not find UEFI firmware. Set OPENVMM_UEFI_FIRMWARE or \
         X86_64_OPENVMM_UEFI_FIRMWARE, or pass --firmware."
    );
}

/// Find the pipette binary.
fn find_pipette(explicit: &Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        anyhow::ensure!(path.exists(), "pipette not found at {}", path.display());
        return Ok(path.clone());
    }

    // Try common cargo target locations.
    let candidates = [
        "target/x86_64-pc-windows-msvc/release/pipette.exe",
        "target/x86_64-pc-windows-msvc/debug/pipette.exe",
        "target/x86_64-pc-windows-gnu/release/pipette.exe",
        "target/x86_64-pc-windows-gnu/debug/pipette.exe",
        "target/release/pipette.exe",
        "target/debug/pipette.exe",
    ];

    for candidate in &candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            eprintln!("Found pipette at {}", path.display());
            return Ok(path);
        }
    }

    anyhow::bail!(
        "Could not find pipette.exe. Build it with:\n\
         \n\
         \x20 cargo build --target x86_64-pc-windows-msvc -p pipette --release\n\
         \n\
         Or specify the path with --pipette or OPENVMM_QUICK_PIPETTE."
    );
}

/// Find the openvmm binary.
fn find_openvmm(explicit: &Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        anyhow::ensure!(path.exists(), "openvmm not found at {}", path.display());
        return Ok(path.clone());
    }

    // Look next to this binary first (same target directory).
    if let Ok(self_path) = std::env::current_exe() {
        if let Some(dir) = self_path.parent() {
            let sibling = dir.join("openvmm");
            if sibling.exists() {
                eprintln!("Found openvmm at {}", sibling.display());
                return Ok(sibling);
            }
        }
    }

    // Try common cargo target locations.
    let candidates = [
        "target/release/openvmm",
        "target/debug/openvmm",
        "target/x86_64-unknown-linux-gnu/release/openvmm",
        "target/x86_64-unknown-linux-gnu/debug/openvmm",
        "target/aarch64-unknown-linux-gnu/release/openvmm",
        "target/aarch64-unknown-linux-gnu/debug/openvmm",
    ];

    for candidate in &candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            eprintln!("Found openvmm at {}", path.display());
            return Ok(path);
        }
    }

    // Try PATH.
    if let Ok(path) = which::which("openvmm") {
        return Ok(path);
    }

    anyhow::bail!(
        "Could not find openvmm. Build it with:\n\
         \n\
         \x20 cargo build -p openvmm --release\n\
         \n\
         Or specify the path with --openvmm or OPENVMM_QUICK_OPENVMM."
    );
}

/// Try to find the user's SSH public key.
fn find_ssh_pubkey() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let ssh_dir = PathBuf::from(home).join(".ssh");

    for name in &["id_ed25519.pub", "id_rsa.pub", "id_ecdsa.pub"] {
        let path = ssh_dir.join(name);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            let key = contents.trim().to_string();
            if !key.is_empty() {
                return Some(key);
            }
        }
    }
    None
}
