// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Top-level API to run a command inside a hosting VM.

use crate::profile::EmulatorConfig;
use crate::profile::HostingVmProfile;
use crate::qemu;
use anyhow::Context;
use petri::cpio;
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
    /// The command to run inside the VM.
    pub guest_command: String,
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
/// `/share` inside the guest, runs `guest_command`, and returns the exit
/// code. Console output streams to the host's stdout in real time.
pub fn run_in_hosting_vm(config: HostingVmConfig) -> anyhow::Result<HostingVmOutput> {
    let start = Instant::now();
    let work_dir = tempfile::tempdir().context("failed to create temp dir")?;

    // --- build the init script ---

    let init_script = format!(
        "#!/bin/sh\n\
         /bin/busybox --install /bin 2>/dev/null\n\
         mount -t devtmpfs none /dev\n\
         mount -t proc none /proc\n\
         mount -t sysfs none /sys\n\
         mkdir -p /share\n\
         mount -t virtiofs hostshare /share\n\
         export VMM_TESTS_CONTENT_DIR=/share\n\
         export HOME=/root\n\
         mkdir -p /root\n\
         cd /share\n\
         {cmd}\n\
         echo $? > /share/.hosting-vm-exit-code\n\
         poweroff -f\n",
        cmd = config.guest_command,
    );

    // --- inject init script into initrd ---

    let initrd_data = std::fs::read(&config.initrd).context("failed to read initrd")?;

    let patched_initrd = cpio::inject_into_initrd(
        &initrd_data,
        "tcg-init.sh",
        init_script.as_bytes(),
        0o100755, // regular file, rwxr-xr-x
    )
    .context("failed to inject init script into initrd")?;

    let patched_initrd_path = work_dir.path().join("initrd.gz");
    std::fs::write(&patched_initrd_path, &patched_initrd)
        .context("failed to write patched initrd")?;

    // --- clean stale exit code ---

    let exit_code_path = config.share_dir.join(".hosting-vm-exit-code");
    let _ = std::fs::remove_file(&exit_code_path);

    // --- start virtiofsd ---

    let sock = work_dir.path().join("virtiofs.sock");
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
        kernel_cmdline,
    );

    // Inherit stdio so console streams to the host in real time
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let status = cmd.status().context("failed to launch QEMU")?;

    let elapsed = start.elapsed();

    // --- virtiofsd cleanup happens on drop ---

    drop(virtiofsd);

    // --- read exit code ---

    let exit_code = if exit_code_path.exists() {
        let code_str =
            std::fs::read_to_string(&exit_code_path).context("failed to read guest exit code")?;
        code_str.trim().parse::<i32>().ok()
    } else if !status.success() {
        // QEMU itself failed (timeout, crash, etc.)
        status.code()
    } else {
        None
    };

    Ok(HostingVmOutput { exit_code, elapsed })
}
