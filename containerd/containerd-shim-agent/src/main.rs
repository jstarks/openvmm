// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Containerd shim guest agent.
//!
//! A minimal PID 1 agent that runs inside a microVM, communicates with the
//! host shim over AF_VSOCK, and handles container lifecycle RPCs.

#![expect(unsafe_code)]

use anyhow::Context;
use containerd_shim_agent_protocol::AgentBootstrap;
use containerd_shim_agent_protocol::AgentRequest;
use containerd_shim_agent_protocol::CreateContainerRequest;
use containerd_shim_agent_protocol::CreateContainerResponse;
use containerd_shim_agent_protocol::DeleteContainerRequest;
use containerd_shim_agent_protocol::ExitStatus;
use containerd_shim_agent_protocol::KillRequest;
use containerd_shim_agent_protocol::StartContainerRequest;
use containerd_shim_agent_protocol::StartContainerResponse;
use containerd_shim_agent_protocol::AGENT_VSOCK_PORT;
use futures::executor::block_on;
use futures::io::AllowStdIo;
use mesh::pipe::ReadPipe;
use mesh::pipe::WritePipe;
use mesh_remote::PointToPointMesh;
use pal_async::DefaultDriver;
use pal_async::socket::PolledSocket;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::process::CommandExt;
use std::process::Stdio;
use vmsocket::VmAddress;
use vmsocket::VmSocket;

// ---------------------------------------------------------------------------
// Container state
// ---------------------------------------------------------------------------

struct ContainerState {
    rootfs_path: String,
    spec: oci_spec::runtime::Spec,
    stdin: Option<ReadPipe>,
    stdout: Option<WritePipe>,
    stderr: Option<WritePipe>,
    process: Option<RunningProcess>,
}

struct RunningProcess {
    pid: u32,
    /// Keep relay threads alive; they exit when their pipes close.
    _io_threads: Vec<std::thread::JoinHandle<()>>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

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
    c_mkdir("/run", 0o755).ok();
    c_mkdir("/run/containers", 0o755).ok();
    c_mount("containers", "/run/containers", "virtiofs", 0, "")
        .context("mount virtiofs at /run/containers")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Agent main loop
// ---------------------------------------------------------------------------

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

    let mut containers: HashMap<String, ContainerState> = HashMap::new();

    loop {
        match request_recv.recv().await {
            Ok(req) => {
                if handle_request(req, &mut containers) {
                    break;
                }
            }
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

/// Handle one request. Returns `true` if the agent should shut down.
fn handle_request(
    req: AgentRequest,
    containers: &mut HashMap<String, ContainerState>,
) -> bool {
    match req {
        AgentRequest::Ping(rpc) => {
            eprintln!("containerd-shim-agent: ping");
            rpc.handle_sync(|()| {});
            false
        }
        AgentRequest::Shutdown(rpc) => {
            eprintln!("containerd-shim-agent: shutdown requested");
            rpc.handle_failable_sync(|()| -> Result<(), anyhow::Error> { Ok(()) });
            true
        }
        AgentRequest::CreateContainer(rpc) => {
            rpc.handle_failable_sync(|req| handle_create_container(req, containers));
            false
        }
        AgentRequest::StartContainer(rpc) => {
            rpc.handle_failable_sync(|req| handle_start_container(req, containers));
            false
        }
        AgentRequest::KillContainer(rpc) => {
            rpc.handle_failable_sync(|req| handle_kill_container(req, containers));
            false
        }
        AgentRequest::DeleteContainer(rpc) => {
            rpc.handle_failable_sync(|req| handle_delete_container(req, containers));
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Container RPCs
// ---------------------------------------------------------------------------

fn handle_create_container(
    req: CreateContainerRequest,
    containers: &mut HashMap<String, ContainerState>,
) -> anyhow::Result<CreateContainerResponse> {
    eprintln!("containerd-shim-agent: CreateContainer id={}", req.id);

    let spec: oci_spec::runtime::Spec =
        serde_json::from_str(&req.spec_json).context("failed to parse OCI spec")?;

    // Validate rootfs exists.
    if !std::path::Path::new(&req.rootfs_path).exists() {
        anyhow::bail!(
            "rootfs path does not exist: {} (this likely means the virtiofs share is not ready)",
            req.rootfs_path
        );
    }

    containers.insert(
        req.id.clone(),
        ContainerState {
            rootfs_path: req.rootfs_path,
            spec,
            stdin: req.stdin,
            stdout: req.stdout,
            stderr: req.stderr,
            process: None,
        },
    );

    Ok(CreateContainerResponse {})
}

fn handle_start_container(
    req: StartContainerRequest,
    containers: &mut HashMap<String, ContainerState>,
) -> anyhow::Result<StartContainerResponse> {
    eprintln!("containerd-shim-agent: StartContainer id={}", req.id);

    let container = containers
        .get_mut(&req.id)
        .context("container not found")?;

    if container.process.is_some() {
        anyhow::bail!("container {} already started", req.id);
    }

    let process = container
        .spec
        .process()
        .as_ref()
        .context("no process in OCI spec")?;

    let args = process
        .args()
        .as_ref()
        .context("no args in OCI process")?;

    if args.is_empty() {
        anyhow::bail!("empty args in OCI process spec");
    }

    let rootfs = container.rootfs_path.clone();

    // Build command.
    let mut command = std::process::Command::new(&args[0]);
    command.args(&args[1..]);

    // Environment variables.
    if let Some(env) = process.env() {
        for var in env {
            if let Some((key, value)) = var.split_once('=') {
                command.env(key, value);
            }
        }
    }

    // Working directory.
    let cwd = process.cwd().to_string_lossy().to_string();

    // Mount essential filesystems in container rootfs before exec.
    prepare_container_rootfs(&rootfs).ok();

    // Setup stdio.
    if container.stdin.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    if container.stdout.is_some() {
        command.stdout(Stdio::piped());
    } else {
        command.stdout(Stdio::null());
    }
    if container.stderr.is_some() {
        command.stderr(Stdio::piped());
    } else {
        command.stderr(Stdio::null());
    }

    // Pre-exec: mount namespace + chroot.
    let rootfs_for_exec = rootfs.clone();
    let cwd_for_exec = cwd.clone();
    // SAFETY: pre_exec closure runs in the forked child between fork and exec.
    // We call async-signal-safe libc functions. The CString allocations happen
    // before the closure captures, but the closure itself only uses the
    // pre-built CStrings.
    unsafe {
        command.pre_exec(move || {
            // Create mount namespace.
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Chroot into container rootfs.
            let rootfs_c = CString::new(rootfs_for_exec.as_str()).unwrap();
            if libc::chroot(rootfs_c.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Change to the working directory.
            let cwd_c = CString::new(cwd_for_exec.as_str()).unwrap();
            if libc::chdir(cwd_c.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn().context("failed to spawn container process")?;
    let pid = child.id();

    eprintln!("containerd-shim-agent: container {} spawned with PID {}", req.id, pid);

    // Bridge I/O.
    let mut io_threads = Vec::new();

    // stdin: mesh ReadPipe → child's stdin OS pipe
    if let (Some(child_stdin), Some(stdin_read)) = (child.stdin.take(), container.stdin.take()) {
        io_threads.push(std::thread::spawn(move || {
            let _ = block_on(futures::io::copy(
                stdin_read,
                &mut AllowStdIo::new(child_stdin),
            ));
        }));
    }

    // stdout: child's stdout OS pipe → mesh WritePipe
    if let (Some(child_stdout), Some(mut stdout_write)) =
        (child.stdout.take(), container.stdout.take())
    {
        io_threads.push(std::thread::spawn(move || {
            let _ = block_on(futures::io::copy(
                AllowStdIo::new(child_stdout),
                &mut stdout_write,
            ));
        }));
    }

    // stderr: child's stderr OS pipe → mesh WritePipe
    if let (Some(child_stderr), Some(mut stderr_write)) =
        (child.stderr.take(), container.stderr.take())
    {
        io_threads.push(std::thread::spawn(move || {
            let _ = block_on(futures::io::copy(
                AllowStdIo::new(child_stderr),
                &mut stderr_write,
            ));
        }));
    }

    // Wait for exit in a dedicated thread.
    let (exit_send, exit_recv) = mesh::oneshot();
    let container_id = req.id.clone();
    std::thread::spawn(move || {
        let exit_status = child.wait();
        let code = match exit_status {
            Ok(s) => s.code().unwrap_or(-1),
            Err(_) => -1,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        eprintln!(
            "containerd-shim-agent: container {} exited with code {}",
            container_id, code
        );
        exit_send.send(ExitStatus {
            code,
            exited_at: now,
        });
    });

    container.process = Some(RunningProcess {
        pid,
        _io_threads: io_threads,
    });

    Ok(StartContainerResponse {
        pid,
        exit_status: exit_recv,
    })
}

fn handle_kill_container(
    req: KillRequest,
    containers: &mut HashMap<String, ContainerState>,
) -> anyhow::Result<()> {
    eprintln!(
        "containerd-shim-agent: KillContainer id={} signal={}",
        req.id, req.signal
    );

    let container = containers
        .get(&req.id)
        .context("container not found")?;

    let proc = container
        .process
        .as_ref()
        .context("container not started")?;

    // SAFETY: Sending a signal to a valid PID.
    let ret = unsafe { libc::kill(proc.pid as i32, req.signal as i32) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        // ESRCH = process already exited, which is OK
        if err.raw_os_error() != Some(libc::ESRCH) {
            return Err(err).context("kill failed");
        }
    }
    Ok(())
}

fn handle_delete_container(
    req: DeleteContainerRequest,
    containers: &mut HashMap<String, ContainerState>,
) -> anyhow::Result<()> {
    eprintln!("containerd-shim-agent: DeleteContainer id={}", req.id);
    // Remove from map — dropping the RunningProcess will drop the IO threads
    // (they'll exit when their pipe counterparts are dropped).
    containers.remove(&req.id);
    Ok(())
}

// ---------------------------------------------------------------------------
// Container rootfs preparation
// ---------------------------------------------------------------------------

/// Mount essential pseudo-filesystems inside the container rootfs.
fn prepare_container_rootfs(rootfs: &str) -> anyhow::Result<()> {
    let proc = format!("{}/proc", rootfs);
    let dev = format!("{}/dev", rootfs);
    let sys = format!("{}/sys", rootfs);

    c_mkdir(&proc, 0o755).ok();
    c_mount("proc", &proc, "proc", 0, "").ok();
    c_mkdir(&dev, 0o755).ok();
    c_mount("devtmpfs", &dev, "devtmpfs", 0, "").ok();
    c_mkdir(&sys, 0o755).ok();
    c_mount("sysfs", &sys, "sysfs", 0, "").ok();

    Ok(())
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
