// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Containerd shim guest agent.
//!
//! A minimal PID 1 agent that runs inside a microVM, communicates with the
//! host shim over AF_VSOCK, and handles `Ping` and `Shutdown` RPCs.

#![expect(unsafe_code)]

use anyhow::Context;
use containerd_shim_agent_protocol::AgentBootstrap;
use containerd_shim_agent_protocol::AgentRequest;
use containerd_shim_agent_protocol::AGENT_VSOCK_PORT;
use mesh_remote::PointToPointMesh;
use pal_async::DefaultDriver;
use pal_async::socket::PolledSocket;
use std::ffi::CString;
use vmsocket::VmAddress;
use vmsocket::VmSocket;

fn main() {
    eprintln!("containerd-shim-agent: starting as PID 1");
    if let Err(e) = init_filesystems() {
        eprintln!("containerd-shim-agent: failed to init filesystems: {e:#}");
    }
    let result = pal_async::DefaultPool::run_with(|driver| async move { run_agent(driver).await });
    if let Err(e) = result {
        eprintln!("containerd-shim-agent: agent error: {e:#}");
    }
    eprintln!("containerd-shim-agent: shutting down");
    // SAFETY: sync() and reboot() are standard libc calls for PID 1 shutdown.
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
}

fn init_filesystems() -> anyhow::Result<()> {
    c_mkdir("/proc", 0o755).ok();
    c_mount("proc", "/proc", "proc", 0, "").context("mount /proc")?;
    c_mkdir("/sys", 0o755).ok();
    c_mount("sysfs", "/sys", "sysfs", 0, "").context("mount /sys")?;
    c_mkdir("/dev", 0o755).ok();
    c_mount("devtmpfs", "/dev", "devtmpfs", 0, "").context("mount /dev")?;
    c_mkdir("/tmp", 0o755).ok();
    c_mount("tmpfs", "/tmp", "tmpfs", 0, "").context("mount /tmp")?;
    Ok(())
}

async fn run_agent(driver: DefaultDriver) -> anyhow::Result<()> {
    let socket = connect_to_host(&driver).await?;

    let (bootstrap_send, bootstrap_recv) = mesh::oneshot::<AgentBootstrap>();
    let mesh = PointToPointMesh::new(&driver, socket, bootstrap_recv.into());

    let (request_send, mut request_recv) = mesh::channel();
    let (watch_send, watch_recv) = mesh::oneshot();

    bootstrap_send.send(AgentBootstrap {
        requests: request_send,
        watch: watch_recv,
    });

    eprintln!("containerd-shim-agent: connected to host, entering dispatch loop");

    loop {
        match request_recv.recv().await {
            Ok(req) => handle_request(req),
            Err(_) => {
                eprintln!("containerd-shim-agent: request channel closed");
                break;
            }
        }
    }

    watch_send.send(());
    mesh.shutdown().await;
    Ok(())
}

fn handle_request(req: AgentRequest) {
    match req {
        AgentRequest::Ping(rpc) => {
            eprintln!("containerd-shim-agent: ping");
            rpc.handle_sync(|()| {});
        }
        AgentRequest::Shutdown(rpc) => {
            eprintln!("containerd-shim-agent: shutdown requested");
            rpc.handle_failable_sync(|()| -> Result<(), anyhow::Error> { Ok(()) });
        }
    }
}

async fn connect_to_host(
    driver: &DefaultDriver,
) -> anyhow::Result<PolledSocket<socket2::Socket>> {
    let socket = VmSocket::new().context("failed to create vsock")?;
    let mut socket: PolledSocket<socket2::Socket> = PolledSocket::new(driver, socket)
        .context("failed to create polled socket")?
        .convert();
    socket
        .connect(&VmAddress::vsock_host(AGENT_VSOCK_PORT).into())
        .await
        .context("failed to connect to host")?;
    Ok(socket)
}

fn c_mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: u64,
    data: &str,
) -> std::io::Result<()> {
    let source = CString::new(source).unwrap();
    let target = CString::new(target).unwrap();
    let fstype = CString::new(fstype).unwrap();
    let data = CString::new(data).unwrap();
    // SAFETY: Calling libc::mount with valid C string pointers.
    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags as libc::c_ulong,
            data.as_ptr() as *const libc::c_void,
        )
    };
    if ret != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn c_mkdir(path: &str, mode: u32) -> std::io::Result<()> {
    let path = CString::new(path).unwrap();
    // SAFETY: Calling libc::mkdir with a valid C string pointer.
    let ret = unsafe { libc::mkdir(path.as_ptr(), mode as libc::mode_t) };
    if ret != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
