// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Compose an mshv boot disk without host filesystem utilities.

#![forbid(unsafe_code)]

use clap::Parser;
use incubator::Arch;
use petri::mshv_image::MshvImage;
use petri_artifacts_common::tags::MachineArch;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    /// Architecture of the supplied boot executables.
    #[arg(long, value_enum, default_value = "x86-64")]
    arch: Arch,
    /// Development-only mshv_host_boot.efi built for the matching UEFI target.
    #[arg(long)]
    host_boot: PathBuf,
    /// Directory containing HvLoader.efi, lxhvloader.dll, and Windows/System32.
    #[arg(long)]
    payload: PathBuf,
    /// mshv-enabled Linux kernel with EFI stub support.
    #[arg(long)]
    kernel: PathBuf,
    /// Initramfs containing /init and the desired runtime.
    #[arg(long)]
    initrd: PathBuf,
    /// Linux command line, passed literally to its EFI stub.
    #[arg(long)]
    kernel_cmdline: Option<String>,
    /// Hypervisor options passed literally to HvLoader.
    #[arg(long)]
    hypervisor_cmdline: Option<String>,
    /// New raw GPT/FAT32 image path. Existing files are never overwritten.
    #[arg(long)]
    output: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let (arch, kernel_cmdline, hypervisor_cmdline) = match args.arch {
        Arch::X86_64 => (
            MachineArch::X86_64,
            "console=ttyS0,115200 rdinit=/init".into(),
            mshv_host_boot::DEFAULT_HYPERVISOR_CMDLINE,
        ),
        Arch::Aarch64 => (
            MachineArch::Aarch64,
            format!("{} rdinit=/init", mshv_host_boot::AARCH64_KERNEL_CMDLINE),
            mshv_host_boot::AARCH64_HYPERVISOR_CMDLINE,
        ),
    };
    MshvImage {
        arch,
        host_boot: &args.host_boot,
        payload: &args.payload,
        kernel: &args.kernel,
        initrd: &args.initrd,
        kernel_cmdline: args.kernel_cmdline.as_deref().unwrap_or(&kernel_cmdline),
        hypervisor_cmdline: args
            .hypervisor_cmdline
            .as_deref()
            .unwrap_or(hypervisor_cmdline),
    }
    .build(&args.output)?;
    eprintln!("Created {}", args.output.display());
    Ok(())
}
