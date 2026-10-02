// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cold-boot an mshv root partition using a separate native OpenVMM/KVM build.

use crate::mshv_image::MshvImage;
use crate::profile::OpenvmmMshvConfig;
use crate::qemu;
use anyhow::Context;
use std::path::Path;
use std::process::Command;

// xtask-fmt allow-target-arch oneoff-petri-host-arch
const SUPPORTED_HOST: bool = cfg!(all(target_os = "linux", target_arch = "x86_64"));

pub(crate) fn build_init_script(pipette: &str) -> String {
    let pipette = qemu::shell_single_quote(pipette);
    format!(
        "#!/bin/sh\n\
         set -eu\n\
         /bin/busybox --install /bin\n\
         mount -t devtmpfs none /dev\n\
         mount -t proc none /proc\n\
         mount -t sysfs none /sys\n\
         mkdir -p /dev/pts /share /root /tmp /etc\n\
         mount -t devpts devpts /dev/pts\n\
         uname -a\n\
         cat /proc/cmdline\n\
         test -c /dev/mshv || {{ echo 'missing /dev/mshv'; exit 1; }}\n\
         ls -l /dev/mshv\n\
         mount -t 9p -o trans=virtio,version=9p2000.L hostshare /share\n\
         ip link set eth0 up\n\
         ip addr add 10.0.0.2/24 dev eth0\n\
         ip route add default via 10.0.0.1\n\
         echo 'nameserver 10.0.0.1' > /etc/resolv.conf\n\
         export HOME=/root\n\
         export SSL_CERT_FILE=/incubator-ca-certificates.crt\n\
         cd /share\n\
         exec {pipette} --transport tcp\n"
    )
}

pub(crate) fn prepare_image(
    config: &OpenvmmMshvConfig,
    kernel: &Path,
    initrd: &Path,
    output: &Path,
) -> anyhow::Result<()> {
    let boot = config.boot_artifacts.join("boot");
    MshvImage {
        shim: &boot.join("EFI/BOOT/bootx64.efi"),
        grub: &boot.join("EFI/BOOT/grubx64.efi"),
        payload: &boot,
        kernel,
        initrd,
        kernel_cmdline: "console=ttyS0 rdinit=/tcg-init.sh panic=-1",
    }
    .build(output)
    .context("composing mshv Incubator image")
}

pub(crate) fn build_command(
    config: &OpenvmmMshvConfig,
    image: &Path,
    share: &Path,
    port: u16,
) -> anyhow::Result<Command> {
    anyhow::ensure!(
        SUPPORTED_HOST,
        "openvmm-mshv requires an x86-64 Linux/KVM host"
    );
    for path in [image, share] {
        anyhow::ensure!(
            !path.as_os_str().as_encoded_bytes().contains(&b','),
            "OpenVMM device paths cannot contain commas: {}",
            path.display()
        );
    }
    let mut cmd = Command::new(&config.binary);
    cmd.args([
        "--single-process",
        "--headless",
        "--hypervisor",
        "kvm",
        "--nested-virt",
    ])
    .args(["--uefi", "--uefi-firmware"])
    .arg(&config.firmware)
    .args(["--no-vmbus", "--memory"])
    .arg(&config.memory)
    .arg("--processors")
    .arg(config.processors.to_string())
    // Segment zero selects legacy CF8/CFC accesses in the root kernel.
    // A nonzero segment ensures enumeration uses the advertised ECAM.
    .args(["--pcie-root-complex", "rc0,segment=1"]);
    for name in ["boot", "share", "net"] {
        cmd.arg("--pcie-root-port").arg(format!("rc0:{name}"));
    }
    cmd.arg("--virtio-blk")
        .arg(format!("memdiff:file:{},pcie_port=boot", image.display()))
        .arg("--virtio-9p")
        .arg(format!("pcie_port=share:hostshare,{}", share.display()))
        .arg("--virtio-net")
        .arg(format!(
            "pcie_port=net:consomme:hostfwd=tcp:127.0.0.1:{port}-:{}",
            pipette_client::PIPETTE_PORT
        ))
        .args(["--com1", "console", "--uefi-console-mode", "com1"])
        .args([
            "--guest-shutdown-action",
            "exit",
            "--guest-crash-action",
            "exit:1",
        ])
        .args(["--guest-reset-action", "exit:1"]);
    Ok(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::IncubatorBackend;
    use crate::profile::IncubatorProfile;
    use test_with_tracing::test;

    #[test]
    fn explicit_mshv_profile() {
        let profile = IncubatorProfile::from_toml(
            "[incubator]\n\
             type = 'openvmm-mshv'\n\
             binary = '/host/openvmm'\n\
             firmware = '/host/MSVM.fd'\n\
             boot-artifacts = '/host/artifacts'\n\
             memory = '4G'\n\
             processors = 2\n",
        )
        .unwrap();
        assert_eq!(profile.incubator.arch(), crate::Arch::X86_64);
        let IncubatorBackend::OpenvmmMshv(config) = profile.incubator else {
            panic!("wrong backend");
        };
        if SUPPORTED_HOST {
            let cmd = build_command(
                &config,
                Path::new("/boot.img"),
                Path::new("/share dir"),
                1234,
            )
            .unwrap();
            let args: Vec<_> = cmd.get_args().map(|a| a.to_str().unwrap()).collect();
            assert!(args.contains(&"--headless"));
            assert!(args.contains(&"--no-vmbus"));
            assert!(args.contains(&"rc0,segment=1"));
            assert!(args.contains(&"memdiff:file:/boot.img,pcie_port=boot"));
            assert!(args.contains(&"pcie_port=share:hostshare,/share dir"));
            assert!(
                args.iter()
                    .any(|a| a.contains("hostfwd=tcp:127.0.0.1:1234-:"))
            );
            assert!(
                build_command(&config, Path::new("/bad,image"), Path::new("/share"), 1234).is_err()
            );
        }
    }

    #[test]
    fn init_requires_mshv_and_quotes_pipette() {
        let script = build_init_script("/share/a'b/pipette");
        assert!(script.contains("test -c /dev/mshv"));
        assert!(script.contains("exec '/share/a'\\''b/pipette' --transport tcp"));
        assert!(script.contains("10.0.0.2/24"));
    }
}
