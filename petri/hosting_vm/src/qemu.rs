// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! QEMU process management.

use crate::profile::QemuTcgConfig;
use anyhow::Context;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;

/// A running virtiofsd process.
pub struct Virtiofsd {
    child: Child,
    socket_path: PathBuf,
}

impl Virtiofsd {
    /// Start virtiofsd sharing the given directory.
    pub fn start(share_dir: &Path, socket_path: &Path) -> anyhow::Result<Self> {
        // Find virtiofsd binary
        let binary = find_virtiofsd()?;

        let child = Command::new(&binary)
            .arg("--socket-path")
            .arg(socket_path)
            .arg("--shared-dir")
            .arg(share_dir)
            .arg("--log-level=error")
            .arg("--sandbox=none")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start virtiofsd at {}", binary.display()))?;

        // Wait for the socket to appear
        for _ in 0..20 {
            if socket_path.exists() {
                return Ok(Self {
                    child,
                    socket_path: socket_path.to_owned(),
                });
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }

        anyhow::bail!(
            "virtiofsd did not create socket at {} within 5 seconds",
            socket_path.display()
        );
    }

    /// Get the socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for Virtiofsd {
    fn drop(&mut self) {
        // Best-effort kill
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn find_virtiofsd() -> anyhow::Result<PathBuf> {
    for path in ["/usr/libexec/virtiofsd", "/usr/lib/qemu/virtiofsd"] {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }
    // Try PATH
    if let Ok(output) = Command::new("which").arg("virtiofsd").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }
    anyhow::bail!("virtiofsd not found. Install it: apt install virtiofsd")
}

/// Build the QEMU command line for a TCG launch.
pub fn build_qemu_command(
    config: &QemuTcgConfig,
    kernel: &Path,
    initrd: &Path,
    virtiofsd_socket: &Path,
    host_pipette_port: u16,
    kernel_cmdline: &str,
) -> Command {
    let mut cmd = Command::new(&config.binary);

    cmd.arg("-machine").arg(&config.machine);
    cmd.arg("-cpu").arg(&config.cpu);
    cmd.arg("-m").arg(&config.memory);
    cmd.arg("-smp").arg(&config.smp);
    cmd.arg("-nographic");
    cmd.arg("-kernel").arg(kernel);
    cmd.arg("-initrd").arg(initrd);
    cmd.arg("-append").arg(kernel_cmdline);
    cmd.arg("-no-reboot");

    // virtio-fs: shared memory backend + vhost-user-fs device
    cmd.arg("-chardev")
        .arg(format!("socket,id=vfs,path={}", virtiofsd_socket.display()));
    cmd.arg("-device")
        .arg("vhost-user-fs-pci,chardev=vfs,tag=hostshare");
    cmd.arg("-object").arg(format!(
        "memory-backend-memfd,id=mem,size={},share=on",
        config.memory
    ));
    cmd.arg("-numa").arg("node,memdev=mem");

    // User-mode networking with port forwarding for pipette TCP
    cmd.arg("-netdev").arg(format!(
        "user,id=net0,hostfwd=tcp::{host_pipette_port}-:{guest_port}",
        guest_port = pipette_client::PIPETTE_PORT,
    ));
    cmd.arg("-device").arg("virtio-net-pci,netdev=net0");

    // Console on serial (diagnostic only)
    cmd.arg("-serial").arg("mon:stdio");

    cmd
}
