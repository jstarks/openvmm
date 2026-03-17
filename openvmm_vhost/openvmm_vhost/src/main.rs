// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! openvmm-vhost: a vhost-user backend binary that hosts OpenVMM virtio
//! devices over a Unix domain socket.

#![forbid(unsafe_code)]

use anyhow::Context as _;
use clap::Parser;
use clap::Subcommand;
use disk_backend::Disk;
use disk_file::FileDisk;
use guestmem::GuestMemory;
use pal_async::DefaultPool;
use std::path::PathBuf;
use vhost_user_device::VhostUserDeviceServer;
use virtio_blk::VirtioBlkDevice;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;

/// openvmm-vhost: vhost-user backend for OpenVMM virtio devices.
#[derive(Parser)]
#[command(name = "openvmm-vhost")]
struct Cli {
    /// Path to the Unix domain socket.
    #[arg(long)]
    socket: PathBuf,

    /// Device type to expose.
    #[command(subcommand)]
    device: DeviceCommand,
}

#[derive(Subcommand)]
enum DeviceCommand {
    /// Expose a virtio-blk device.
    Blk {
        /// Path to the disk image file.
        #[arg(long)]
        disk: PathBuf,

        /// Open the disk as read-only.
        #[arg(long, default_value_t = false)]
        read_only: bool,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    DefaultPool::run_with(|driver: pal_async::DefaultDriver| async move {
        let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()));

        let server = match &cli.device {
            DeviceCommand::Blk { disk, read_only } => {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(!read_only)
                    .open(disk)
                    .with_context(|| format!("failed to open disk: {}", disk.display()))?;

                let file_disk =
                    FileDisk::open(file, *read_only).context("failed to create file disk")?;

                let disk = Disk::new(file_disk).context("invalid disk")?;

                let read_only = *read_only;
                VhostUserDeviceServer::new(move |guest_memory: GuestMemory| {
                    Box::new(VirtioBlkDevice::new(
                        &driver_source,
                        guest_memory,
                        disk,
                        read_only,
                    ))
                })
            }
        };

        server
            .run(&driver, &cli.socket)
            .await
            .context("vhost-user server failed")
    })
}
