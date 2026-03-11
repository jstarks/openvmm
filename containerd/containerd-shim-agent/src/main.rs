// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Containerd shim guest agent.
//!
//! A minimal PID 1 agent that runs inside a microVM, communicates with the
//! host shim over AF_VSOCK, and handles container lifecycle RPCs.

#![expect(unsafe_code)]

use anyhow::Context;
use containerd_shim_agent_protocol::AGENT_VSOCK_PORT;
use containerd_shim_agent_protocol::AgentBootstrap;
use containerd_shim_agent_protocol::AgentConfig;
use containerd_shim_agent_protocol::AgentRequest;
use containerd_shim_agent_protocol::CreateContainerRequest;
use containerd_shim_agent_protocol::CreateContainerResponse;
use containerd_shim_agent_protocol::DeleteContainerRequest;
use containerd_shim_agent_protocol::ExecProcessRequest;
use containerd_shim_agent_protocol::ExecProcessResponse;
use containerd_shim_agent_protocol::ExitStatus;
use containerd_shim_agent_protocol::KillRequest;
use containerd_shim_agent_protocol::ListPidsRequest;
use containerd_shim_agent_protocol::ListPidsResponse;
use containerd_shim_agent_protocol::ProcessInfo;
use containerd_shim_agent_protocol::StartContainerRequest;
use containerd_shim_agent_protocol::StartContainerResponse;
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
    /// Exec processes tracked by exec_id.
    execs: HashMap<String, ExecProcess>,
}

struct ExecProcess {
    pid: u32,
    /// Keep relay threads alive; they exit when their pipes close.
    _io_threads: Vec<std::thread::JoinHandle<()>>,
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
    // Networking is initialized after connecting to the host, which tells us
    // whether a NIC is attached (avoids a 5s polling timeout when it isn't).
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

/// Configure networking using ioctl and netlink.
///
/// Sets up eth0 with IP 10.0.0.2/24, default gateway 10.0.0.1,
/// and DNS via /etc/resolv.conf pointing to 10.0.0.1.
/// These are the consomme userspace NAT defaults.
fn init_networking() -> anyhow::Result<()> {
    // Wait a moment for the network device to appear.
    let mut found = false;
    for _ in 0..50 {
        if std::path::Path::new("/sys/class/net/eth0").exists() {
            found = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !found {
        anyhow::bail!("eth0 not found (no network device?), skipping network setup");
    }

    // Open a socket for ioctl.
    // SAFETY: Creating a UDP socket for ioctl operations.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to create ioctl socket");
    }

    // Bring eth0 up.
    let ifname = b"eth0\0";
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_name[..ifname.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(ifname.as_ptr() as *const i8, ifname.len())
    });

    // Get current flags.
    // SAFETY: ioctl with SIOCGIFFLAGS on a valid socket and ifreq.
    if unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) } != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(e).context("SIOCGIFFLAGS failed");
    }

    // Set IFF_UP.
    unsafe {
        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
    }
    // SAFETY: ioctl with SIOCSIFFLAGS on a valid socket and ifreq.
    if unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) } != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(e).context("SIOCSIFFLAGS failed");
    }

    // Set IP address 10.0.0.2
    let mut ifr_addr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr_addr.ifr_name[..ifname.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(ifname.as_ptr() as *const i8, ifname.len())
    });
    let addr: libc::sockaddr_in = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([10, 0, 0, 2]),
        },
        sin_zero: [0; 8],
    };
    ifr_addr.ifr_ifru.ifru_addr =
        unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(addr) };
    // SAFETY: ioctl with SIOCSIFADDR on a valid socket and ifreq.
    if unsafe { libc::ioctl(sock, libc::SIOCSIFADDR as _, &ifr_addr) } != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(e).context("SIOCSIFADDR failed");
    }

    // Set netmask 255.255.255.0
    let mut ifr_mask: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr_mask.ifr_name[..ifname.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(ifname.as_ptr() as *const i8, ifname.len())
    });
    let mask: libc::sockaddr_in = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([255, 255, 255, 0]),
        },
        sin_zero: [0; 8],
    };
    ifr_mask.ifr_ifru.ifru_addr =
        unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(mask) };
    // SAFETY: ioctl with SIOCSIFNETMASK on a valid socket and ifreq.
    if unsafe { libc::ioctl(sock, libc::SIOCSIFNETMASK as _, &ifr_mask) } != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(e).context("SIOCSIFNETMASK failed");
    }

    // SAFETY: closing the ioctl socket.
    unsafe { libc::close(sock) };

    // Add default route via 10.0.0.1 using netlink.
    add_default_route([10, 0, 0, 1])?;

    // Write /etc/resolv.conf
    c_mkdir("/etc", 0o755).ok();
    std::fs::write("/etc/resolv.conf", "nameserver 10.0.0.1\n")
        .context("failed to write /etc/resolv.conf")?;

    eprintln!("containerd-shim-agent: networking configured (eth0 = 10.0.0.2/24, gw = 10.0.0.1)");
    Ok(())
}

/// Add a default route via `gateway` using a netlink RTM_NEWROUTE message.
fn add_default_route(gateway: [u8; 4]) -> anyhow::Result<()> {
    // Netlink message structures (packed for wire format).
    #[repr(C)]
    struct NlMsgHdr {
        nlmsg_len: u32,
        nlmsg_type: u16,
        nlmsg_flags: u16,
        nlmsg_seq: u32,
        nlmsg_pid: u32,
    }

    #[repr(C)]
    struct RtMsg {
        rtm_family: u8,
        rtm_dst_len: u8,
        rtm_src_len: u8,
        rtm_tos: u8,
        rtm_table: u8,
        rtm_protocol: u8,
        rtm_scope: u8,
        rtm_type: u8,
        rtm_flags: u32,
    }

    #[repr(C)]
    struct RtAttr {
        rta_len: u16,
        rta_type: u16,
    }

    const RTM_NEWROUTE: u16 = 24;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_CREATE: u16 = 0x400;
    const NLM_F_ACK: u16 = 4;
    const RT_TABLE_MAIN: u8 = 254;
    const RTPROT_BOOT: u8 = 3;
    const RT_SCOPE_UNIVERSE: u8 = 0;
    const RTN_UNICAST: u8 = 1;
    const RTA_GATEWAY: u16 = 5;

    let nlmsg_hdr_size = size_of::<NlMsgHdr>();
    let rtmsg_size = size_of::<RtMsg>();
    let rtattr_size = size_of::<RtAttr>();
    let gw_attr_len = rtattr_size + 4; // 4 bytes for IPv4 address
    let total_len = nlmsg_hdr_size + rtmsg_size + gw_attr_len;

    let mut buf = vec![0u8; total_len];

    // Fill NlMsgHdr.
    let hdr = NlMsgHdr {
        nlmsg_len: total_len as u32,
        nlmsg_type: RTM_NEWROUTE,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };
    // SAFETY: hdr is a plain C struct; copying its bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            &hdr as *const NlMsgHdr as *const u8,
            buf.as_mut_ptr(),
            nlmsg_hdr_size,
        );
    }

    // Fill RtMsg.
    let rtm = RtMsg {
        rtm_family: libc::AF_INET as u8,
        rtm_dst_len: 0, // default route
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RT_TABLE_MAIN,
        rtm_protocol: RTPROT_BOOT,
        rtm_scope: RT_SCOPE_UNIVERSE,
        rtm_type: RTN_UNICAST,
        rtm_flags: 0,
    };
    // SAFETY: rtm is a plain C struct; copying its bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            &rtm as *const RtMsg as *const u8,
            buf.as_mut_ptr().add(nlmsg_hdr_size),
            rtmsg_size,
        );
    }

    // Fill RTA_GATEWAY attribute.
    let rta = RtAttr {
        rta_len: gw_attr_len as u16,
        rta_type: RTA_GATEWAY,
    };
    let attr_offset = nlmsg_hdr_size + rtmsg_size;
    // SAFETY: rta is a plain C struct; copying its bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            &rta as *const RtAttr as *const u8,
            buf.as_mut_ptr().add(attr_offset),
            rtattr_size,
        );
    }
    buf[attr_offset + rtattr_size..attr_offset + rtattr_size + 4].copy_from_slice(&gateway);

    // Open a netlink socket.
    // SAFETY: Creating a netlink route socket.
    let nl_sock = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if nl_sock < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to create netlink socket");
    }

    // Send the message.
    // SAFETY: Sending a valid netlink message on a valid socket.
    let sent = unsafe { libc::send(nl_sock, buf.as_ptr() as *const _, buf.len(), 0) };
    if sent < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(nl_sock) };
        return Err(e).context("netlink send failed");
    }

    // Read the ACK. Check for error.
    let mut ack_buf = [0u8; 1024];
    // SAFETY: Reading from a valid netlink socket into a valid buffer.
    let n = unsafe { libc::recv(nl_sock, ack_buf.as_mut_ptr() as *mut _, ack_buf.len(), 0) };
    // SAFETY: closing the netlink socket.
    unsafe { libc::close(nl_sock) };

    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("netlink recv failed");
    }
    if (n as usize) >= nlmsg_hdr_size + 4 {
        // The error code is an i32 right after the nlmsghdr in the ACK.
        let err_code = i32::from_ne_bytes(
            ack_buf[nlmsg_hdr_size..nlmsg_hdr_size + 4]
                .try_into()
                .unwrap(),
        );
        if err_code < 0 {
            return Err(std::io::Error::from_raw_os_error(-err_code))
                .context("netlink RTM_NEWROUTE failed");
        }
    }

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
    let (config_send, config_recv) = mesh::oneshot::<AgentConfig>();

    bootstrap_send.send(AgentBootstrap {
        requests: request_send,
        watch: watch_recv,
        config: config_send,
    });

    // Wait for configuration from the host before doing hardware init.
    let config = config_recv
        .await
        .context("failed to receive agent config")?;
    eprintln!(
        "containerd-shim-agent: received config from host (networking={})",
        config.networking
    );

    if config.networking {
        if let Err(e) = init_networking() {
            eprintln!("containerd-shim-agent: failed to init networking: {e:#}");
        }
    } else {
        eprintln!("containerd-shim-agent: skipping network init (no NIC)");
    }

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
fn handle_request(req: AgentRequest, containers: &mut HashMap<String, ContainerState>) -> bool {
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
        AgentRequest::ExecProcess(rpc) => {
            rpc.handle_failable_sync(|req| handle_exec_process(req, containers));
            false
        }
        AgentRequest::ListPids(rpc) => {
            rpc.handle_failable_sync(|req| handle_list_pids(req, containers));
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
            execs: HashMap::new(),
        },
    );

    Ok(CreateContainerResponse {})
}

fn handle_start_container(
    req: StartContainerRequest,
    containers: &mut HashMap<String, ContainerState>,
) -> anyhow::Result<StartContainerResponse> {
    eprintln!("containerd-shim-agent: StartContainer id={}", req.id);

    let container = containers.get_mut(&req.id).context("container not found")?;

    if container.process.is_some() {
        anyhow::bail!("container {} already started", req.id);
    }

    let process = container
        .spec
        .process()
        .as_ref()
        .context("no process in OCI spec")?;

    let args = process.args().as_ref().context("no args in OCI process")?;

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

    // Extract uid/gid from OCI spec.
    let uid = process.user().uid();
    let gid = process.user().gid();
    let additional_gids: Vec<libc::gid_t> = process
        .user()
        .additional_gids()
        .as_ref()
        .map(|gids| gids.iter().map(|&g| g as libc::gid_t).collect())
        .unwrap_or_default();

    // Mount essential filesystems in container rootfs before exec.
    if let Err(e) = prepare_container_rootfs(&rootfs) {
        eprintln!("containerd-shim-agent: warning: failed to prepare container rootfs: {e:#}");
    }

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
    // Pre-build CStrings before the closure to avoid allocation in the forked child.
    let rootfs_c = CString::new(rootfs.as_str())
        .map_err(|e| anyhow::anyhow!("invalid rootfs path for CString: {e}"))?;
    let cwd_c =
        CString::new(cwd.as_str()).map_err(|e| anyhow::anyhow!("invalid cwd for CString: {e}"))?;
    // SAFETY: pre_exec closure runs in the forked child between fork and exec.
    // We call async-signal-safe libc functions. The CStrings are pre-built above.
    unsafe {
        command.pre_exec(move || {
            // Create mount namespace.
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Chroot into container rootfs.
            if libc::chroot(rootfs_c.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Change to the working directory.
            if libc::chdir(cwd_c.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Set supplementary groups (must be done before setgid/setuid).
            if !additional_gids.is_empty() {
                if libc::setgroups(additional_gids.len(), additional_gids.as_ptr()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // Set gid before uid.
            if gid != 0 {
                if libc::setgid(gid as libc::gid_t) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if uid != 0 {
                if libc::setuid(uid as libc::uid_t) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let mut child = command
        .spawn()
        .context("failed to spawn container process")?;
    let pid = child.id();

    eprintln!(
        "containerd-shim-agent: container {} spawned with PID {}",
        req.id, pid
    );

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
            Err(e) => {
                eprintln!(
                    "containerd-shim-agent: error waiting for container {}: {e}",
                    container_id
                );
                -1
            }
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
        "containerd-shim-agent: KillContainer id={} exec_id={:?} signal={}",
        req.id, req.exec_id, req.signal
    );

    let container = containers.get(&req.id).context("container not found")?;

    let pid = if let Some(exec_id) = &req.exec_id {
        // Kill a specific exec process.
        let exec = container
            .execs
            .get(exec_id)
            .context("exec process not found")?;
        exec.pid as i32
    } else {
        // Kill the init process.
        let proc = container
            .process
            .as_ref()
            .context("container not started")?;
        proc.pid as i32
    };

    // SAFETY: Sending a signal to a valid PID.
    let ret = unsafe { libc::kill(pid, req.signal as i32) };
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
    if let Some(exec_id) = &req.exec_id {
        eprintln!(
            "containerd-shim-agent: DeleteExec id={} exec_id={}",
            req.id, exec_id
        );
        let container = containers.get_mut(&req.id).context("container not found")?;
        container.execs.remove(exec_id);
    } else {
        eprintln!("containerd-shim-agent: DeleteContainer id={}", req.id);
        // Remove from map — dropping the RunningProcess will drop the IO threads
        // (they'll exit when their pipe counterparts are dropped).
        containers.remove(&req.id);
    }
    Ok(())
}

fn handle_exec_process(
    req: ExecProcessRequest,
    containers: &mut HashMap<String, ContainerState>,
) -> anyhow::Result<ExecProcessResponse> {
    eprintln!(
        "containerd-shim-agent: ExecProcess container_id={} exec_id={}",
        req.container_id, req.exec_id
    );

    let container = containers
        .get_mut(&req.container_id)
        .context("container not found")?;

    // Verify the container is running.
    if container.process.is_none() {
        anyhow::bail!("container {} not started", req.container_id);
    }

    let rootfs = container.rootfs_path.clone();

    // Parse the OCI process spec JSON.
    let process_spec: oci_spec::runtime::Process =
        serde_json::from_str(&req.spec_json).context("failed to parse exec process spec")?;

    let args = process_spec
        .args()
        .as_ref()
        .context("no args in exec process spec")?;

    if args.is_empty() {
        anyhow::bail!("empty args in exec process spec");
    }

    let mut command = std::process::Command::new(&args[0]);
    command.args(&args[1..]);

    // Environment variables.
    if let Some(env) = process_spec.env() {
        for var in env {
            if let Some((key, value)) = var.split_once('=') {
                command.env(key, value);
            }
        }
    }

    // Working directory.
    let cwd = process_spec.cwd().to_string_lossy().to_string();

    // Extract uid/gid from exec process spec.
    let uid = process_spec.user().uid();
    let gid = process_spec.user().gid();
    let additional_gids: Vec<libc::gid_t> = process_spec
        .user()
        .additional_gids()
        .as_ref()
        .map(|gids| gids.iter().map(|&g| g as libc::gid_t).collect())
        .unwrap_or_default();

    // Setup stdio.
    if req.stdin.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    if req.stdout.is_some() {
        command.stdout(Stdio::piped());
    } else {
        command.stdout(Stdio::null());
    }
    if req.stderr.is_some() {
        command.stderr(Stdio::piped());
    } else {
        command.stderr(Stdio::null());
    }

    // Pre-build CStrings.
    let rootfs_c = CString::new(rootfs.as_str())
        .map_err(|e| anyhow::anyhow!("invalid rootfs path for CString: {e}"))?;
    let cwd_c =
        CString::new(cwd.as_str()).map_err(|e| anyhow::anyhow!("invalid cwd for CString: {e}"))?;

    // SAFETY: pre_exec closure runs in forked child.
    unsafe {
        command.pre_exec(move || {
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::chroot(rootfs_c.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::chdir(cwd_c.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if !additional_gids.is_empty() {
                if libc::setgroups(additional_gids.len(), additional_gids.as_ptr()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if gid != 0 {
                if libc::setgid(gid as libc::gid_t) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if uid != 0 {
                if libc::setuid(uid as libc::uid_t) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let mut child = command.spawn().context("failed to spawn exec process")?;
    let pid = child.id();

    eprintln!(
        "containerd-shim-agent: exec {} in container {} spawned with PID {}",
        req.exec_id, req.container_id, pid
    );

    // Bridge I/O.
    let mut io_threads = Vec::new();

    if let (Some(child_stdin), Some(stdin_read)) = (child.stdin.take(), req.stdin) {
        io_threads.push(std::thread::spawn(move || {
            let _ = block_on(futures::io::copy(
                stdin_read,
                &mut AllowStdIo::new(child_stdin),
            ));
        }));
    }

    if let (Some(child_stdout), Some(mut stdout_write)) = (child.stdout.take(), req.stdout) {
        io_threads.push(std::thread::spawn(move || {
            let _ = block_on(futures::io::copy(
                AllowStdIo::new(child_stdout),
                &mut stdout_write,
            ));
        }));
    }

    if let (Some(child_stderr), Some(mut stderr_write)) = (child.stderr.take(), req.stderr) {
        io_threads.push(std::thread::spawn(move || {
            let _ = block_on(futures::io::copy(
                AllowStdIo::new(child_stderr),
                &mut stderr_write,
            ));
        }));
    }

    // Wait for exit in a dedicated thread.
    let (exit_send, exit_recv) = mesh::oneshot();
    let exec_id_clone = req.exec_id.clone();
    let container_id_clone = req.container_id.clone();
    std::thread::spawn(move || {
        let exit_status = child.wait();
        let code = match exit_status {
            Ok(s) => s.code().unwrap_or(-1),
            Err(e) => {
                eprintln!(
                    "containerd-shim-agent: error waiting for exec {} in {}: {e}",
                    exec_id_clone, container_id_clone
                );
                -1
            }
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        eprintln!(
            "containerd-shim-agent: exec {} in container {} exited with code {}",
            exec_id_clone, container_id_clone, code
        );
        exit_send.send(ExitStatus {
            code,
            exited_at: now,
        });
    });

    container.execs.insert(
        req.exec_id,
        ExecProcess {
            pid,
            _io_threads: io_threads,
        },
    );

    Ok(ExecProcessResponse {
        pid,
        exit_status: exit_recv,
    })
}

fn handle_list_pids(
    req: ListPidsRequest,
    containers: &mut HashMap<String, ContainerState>,
) -> anyhow::Result<ListPidsResponse> {
    eprintln!(
        "containerd-shim-agent: ListPids container_id={}",
        req.container_id
    );

    let container = containers
        .get(&req.container_id)
        .context("container not found")?;

    let mut pids = Vec::new();

    // Add init process PID.
    if let Some(proc) = &container.process {
        pids.push(ProcessInfo { pid: proc.pid });

        // Read child PIDs from /proc.
        if let Ok(children) =
            std::fs::read_to_string(format!("/proc/{}/task/{}/children", proc.pid, proc.pid))
        {
            for pid_str in children.split_whitespace() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    pids.push(ProcessInfo { pid });
                }
            }
        }
    }

    // Add exec process PIDs.
    for exec in container.execs.values() {
        pids.push(ProcessInfo { pid: exec.pid });
    }

    Ok(ListPidsResponse { pids })
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

async fn connect_to_host(driver: &DefaultDriver) -> anyhow::Result<PolledSocket<socket2::Socket>> {
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
    let source = CString::new(source)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let target = CString::new(target)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let fstype = CString::new(fstype)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let data =
        CString::new(data).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
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
    let path =
        CString::new(path).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: Calling libc::mkdir with a valid C string pointer.
    let ret = unsafe { libc::mkdir(path.as_ptr(), mode as libc::mode_t) };
    if ret != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
