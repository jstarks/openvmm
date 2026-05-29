// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Quick launcher for Windows (and eventually Linux) VMs with automated remote
//! shell access.
//!
//! This tool boots a Windows VM using openvmm with pipette (a guest agent)
//! pre-configured via an IMC hive, then uses pipette to bootstrap SSH or WinRM
//! inside the guest so the user can connect with standard tools.

#![forbid(unsafe_code)]
#![expect(missing_docs)]

mod cidata;

use anyhow::Context;
use clap::Parser;
use clap::ValueEnum;
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
    /// Path to the Windows VHD/VHDX disk image.
    #[clap(long)]
    image: PathBuf,

    /// Path to the UEFI firmware binary.
    ///
    /// Can also be set via OPENVMM_UEFI_FIRMWARE environment variable.
    #[clap(long, env = "OPENVMM_UEFI_FIRMWARE")]
    firmware: PathBuf,

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

    /// Use a copy-on-write overlay so the original disk image is not modified.
    #[clap(long, default_value = "true")]
    overlay: bool,

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
    let mut child = std::process::Command::new(&openvmm_path)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to launch openvmm")?;

    // Wait for pipette to connect.
    eprintln!("Waiting for Windows to boot and pipette to connect...");
    let (conn, _) = listener
        .accept()
        .await
        .context("failed to accept pipette connection")?;
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

    // Wait for the child process.
    eprintln!();
    eprintln!("VM is running. Press Ctrl+C to stop.");
    let status = child.wait().context("failed to wait for openvmm")?;
    if !status.success() {
        anyhow::bail!("openvmm exited with status: {status}");
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
        .arg("Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0")
        .run()
        .await
        .context("failed to install OpenSSH Server")?;

    eprintln!("  Starting sshd service...");
    shell
        .cmd("powershell")
        .arg("-Command")
        .arg("Start-Service sshd; Set-Service -Name sshd -StartupType Automatic")
        .run()
        .await
        .context("failed to start sshd")?;

    // Set password auth as fallback (user can also inject keys).
    eprintln!("  Configuring password authentication...");
    shell
        .cmd("powershell")
        .arg("-Command")
        .arg(concat!(
            "$c = Get-Content $env:ProgramData\\ssh\\sshd_config; ",
            "$c = $c -replace '#PasswordAuthentication yes','PasswordAuthentication yes'; ",
            "Set-Content $env:ProgramData\\ssh\\sshd_config $c; ",
            "Restart-Service sshd",
        ))
        .run()
        .await
        .context("failed to configure sshd")?;

    // Try to inject the user's SSH public key.
    if let Some(pubkey) = find_ssh_pubkey() {
        eprintln!("  Injecting SSH public key...");
        let script = format!(
            "$keyDir = Join-Path $env:ProgramData 'ssh'; \
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
        opts.firmware.display().to_string(),
    ]);

    // Hyper-V enlightenments (needed for VMBus / vsock / IMC).
    args.push("--hv".into());

    // Boot disk.
    let disk_spec = if opts.overlay {
        format!("memdiff:file:{}", opts.image.display())
    } else {
        format!("file:{}", opts.image.display())
    };
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

    // Try common cargo target locations.
    let candidates = ["target/release/openvmm", "target/debug/openvmm"];

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
