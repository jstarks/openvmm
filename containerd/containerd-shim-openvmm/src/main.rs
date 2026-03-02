// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! containerd shim v2 runtime for OpenVMM.
//!
//! Binary name: `containerd-shim-openvmm-v2`
//!
//! Implements the containerd shim v2 protocol with Task v3 and Sandbox v1 APIs.
//! Boots a microVM via OpenVMM, connects to an in-guest agent over vsock, and
//! manages container lifecycle (create/start/exec/kill/delete) inside the VM.
//! Supports both standalone mode (VM per container) and sandbox mode (shared VM).

#![allow(unsafe_code)]

mod initrd;
mod vm;

// Force-link openvmm_resources to register workers and resource resolvers.
extern crate openvmm_resources as _;

use anyhow::Context as _;
use containerd_shim_agent_protocol::AgentRequest;
use containerd_shim_agent_protocol::CreateContainerRequest;
use containerd_shim_agent_protocol::DeleteContainerRequest;
use containerd_shim_agent_protocol::ExecProcessRequest;
use containerd_shim_agent_protocol::KillRequest;
use containerd_shim_agent_protocol::ListPidsRequest;
use containerd_shim_agent_protocol::StartContainerRequest;
use containerd_shim_protos as protos;
use futures::StreamExt;
use futures::executor::block_on;
use futures::io::AllowStdIo;
use mesh::rpc::RpcSend;
use mesh_rpc::service::Code;
use mesh_rpc::service::ServiceRpc;
use mesh_rpc::service::Status;
use pal_async::task::Spawn;
use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// CLI parsing
// ---------------------------------------------------------------------------

struct ShimArgs {
    namespace: String,
    id: String,
    address: String,
    publish_binary: String,
    bundle: String,
}

enum Command {
    Start(ShimArgs),
    Serve { args: ShimArgs, pipe_fd: i32 },
    Delete(ShimArgs),
}

fn parse_args() -> anyhow::Result<Command> {
    let raw: Vec<String> = std::env::args().collect();
    if raw.len() < 2 {
        anyhow::bail!("usage: containerd-shim-openvmm-v2 [flags] <start|serve|delete>");
    }

    // Containerd invokes the shim as: binary [flags...] <subcommand>
    // Our own re-exec uses:            binary serve [flags...]
    // Parse flexibly: the subcommand can appear anywhere as a positional arg.

    let mut subcommand = None;
    let mut namespace = None;
    let mut id = None;
    let mut address = None;
    let mut publish_binary = None;
    let mut bundle = None;
    let mut pipe_fd = None;

    let mut i = 1;
    while i < raw.len() {
        match raw[i].as_str() {
            "-namespace" => {
                i += 1;
                namespace = Some(raw.get(i).context("missing -namespace value")?.clone());
            }
            "-id" => {
                i += 1;
                id = Some(raw.get(i).context("missing -id value")?.clone());
            }
            "-address" => {
                i += 1;
                address = Some(raw.get(i).context("missing -address value")?.clone());
            }
            "-publish-binary" => {
                i += 1;
                publish_binary = Some(raw.get(i).context("missing -publish-binary value")?.clone());
            }
            "-bundle" => {
                i += 1;
                bundle = Some(raw.get(i).context("missing -bundle value")?.clone());
            }
            "-pipe-fd" => {
                i += 1;
                pipe_fd = Some(
                    raw.get(i)
                        .context("missing -pipe-fd value")?
                        .parse::<i32>()
                        .context("invalid -pipe-fd value")?,
                );
            }
            "start" | "serve" | "delete" if subcommand.is_none() => {
                subcommand = Some(raw[i].clone());
            }
            other => {
                anyhow::bail!("unknown flag: {other}");
            }
        }
        i += 1;
    }

    let subcommand = subcommand.context("missing subcommand (start, serve, or delete)")?;

    let args = ShimArgs {
        namespace: namespace.unwrap_or_default(),
        id: id.unwrap_or_default(),
        address: address.unwrap_or_default(),
        publish_binary: publish_binary.unwrap_or_default(),
        bundle: bundle.unwrap_or_default(),
    };

    match subcommand.as_str() {
        "start" => Ok(Command::Start(args)),
        "serve" => {
            let fd = pipe_fd.context("-pipe-fd is required for serve")?;
            Ok(Command::Serve { args, pipe_fd: fd })
        }
        "delete" => Ok(Command::Delete(args)),
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Bootstrap JSON printed to stdout for containerd
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct Bootstrap {
    version: u32,
    address: String,
    protocol: String,
}

// ---------------------------------------------------------------------------
// `start` subcommand
// ---------------------------------------------------------------------------

fn cmd_start(args: ShimArgs) -> anyhow::Result<()> {
    // When containerd calls `start`, it sets CWD to the bundle directory
    // but may not pass `-bundle`. Use CWD as the bundle path if not provided.
    let bundle = if args.bundle.is_empty() {
        std::env::current_dir().context("failed to get current directory")?
    } else {
        PathBuf::from(&args.bundle)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(&args.bundle))
    };

    let socket_path = bundle.join("shim.sock");
    let address = format!("unix://{}", socket_path.display());

    // Idempotent start: if socket already exists, return it.
    if socket_path.exists() {
        let bootstrap = Bootstrap {
            version: 3,
            address,
            protocol: "ttrpc".into(),
        };
        println!("{}", serde_json::to_string(&bootstrap)?);
        return Ok(());
    }

    // Create bundle directory if it doesn't exist.
    std::fs::create_dir_all(&bundle)?;

    // Create pipe for readiness signaling.
    let mut fds = [0i32; 2];
    // SAFETY: libc::pipe writes two fds into the array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to create readiness pipe");
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);

    // Re-exec self as `serve` mode.
    let exe = std::env::current_exe().context("failed to get current exe")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("serve")
        .arg("-namespace")
        .arg(&args.namespace)
        .arg("-id")
        .arg(&args.id)
        .arg("-address")
        .arg(&args.address)
        .arg("-publish-binary")
        .arg(&args.publish_binary)
        .arg("-bundle")
        .arg(&bundle)
        .arg("-pipe-fd")
        .arg(write_fd.to_string());

    // Detach from parent's session.
    // SAFETY: setsid() is safe to call in the post-fork, pre-exec context.
    // We also close the read end of the pipe in the child (it only needs the
    // write end).
    unsafe {
        let read_fd_copy = read_fd;
        cmd.pre_exec(move || {
            libc::setsid();
            libc::close(read_fd_copy);
            Ok(())
        });
    }

    // Detach stdio.
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());

    let _child = cmd.spawn().context("failed to spawn serve process")?;

    // Close write end of pipe in parent.
    // SAFETY: write_fd is a valid fd we just created via pipe().
    unsafe {
        libc::close(write_fd);
    }

    // Wait for readiness signal (child writes "ready" to pipe).
    // SAFETY: read_fd is a valid fd we just created via pipe().
    let mut read_file = unsafe { std::fs::File::from_raw_fd(read_fd) };
    let mut buf = [0u8; 64];
    let _n = read_file
        .read(&mut buf)
        .context("failed to read readiness signal")?;

    // Print bootstrap JSON.
    let bootstrap = Bootstrap {
        version: 3,
        address,
        protocol: "ttrpc".into(),
    };
    println!("{}", serde_json::to_string(&bootstrap)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// `serve` subcommand
// ---------------------------------------------------------------------------

fn cmd_serve(args: ShimArgs, pipe_fd: i32) -> anyhow::Result<()> {
    // Set up file logging.
    let log_path = PathBuf::from(&args.bundle).join("shim.log");
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .context("failed to open shim log file")?;

    tracing_subscriber::fmt()
        .with_writer(std::sync::Mutex::new(log_file))
        .with_ansi(false)
        .init();

    tracing::info!(
        namespace = %args.namespace,
        id = %args.id,
        pid = std::process::id(),
        "shim starting"
    );

    pal_async::DefaultPool::run_with(async |driver| {
        let socket_path = PathBuf::from(&args.bundle).join("shim.sock");

        // Bind Unix socket.
        let listener =
            unix_socket::UnixListener::bind(&socket_path).context("failed to bind shim socket")?;

        tracing::info!(path = %socket_path.display(), "listening");

        // Signal readiness to parent.
        // SAFETY: pipe_fd is a valid fd passed from the parent process.
        let mut pipe_file = unsafe { std::fs::File::from_raw_fd(pipe_fd) };
        pipe_file
            .write_all(b"ready")
            .context("failed to signal readiness")?;
        drop(pipe_file); // closes the fd

        // Run the ttrpc server.
        run_server(driver, listener, args).await
    })
}

// ---------------------------------------------------------------------------
// ttrpc server
// ---------------------------------------------------------------------------

async fn run_server(
    driver: pal_async::DefaultDriver,
    listener: unix_socket::UnixListener,
    args: ShimArgs,
) -> anyhow::Result<()> {
    let mut server = mesh_rpc::Server::new();
    let mut task_recv = server.add_service::<protos::Task>();
    let mut sandbox_recv = server.add_service::<protos::Sandbox>();

    let (cancel_send, cancel_recv) = mesh::oneshot();
    let server_task = driver.spawn("ttrpc-server", {
        let driver = driver.clone();
        async move {
            match server.run(&driver, listener, cancel_recv).await {
                Ok(()) => tracing::debug!("ttrpc server shut down"),
                Err(e) => tracing::error!(
                    error = e.as_ref() as &dyn std::error::Error,
                    "ttrpc server error"
                ),
            }
        }
    });

    let mut state = ShimState::new(args, driver.clone());

    loop {
        futures::select! {
            msg = task_recv.next() => match msg {
                Some((_ctx, request)) => {
                    if state.handle_task(request).await {
                        break;
                    }
                }
                None => break,
            },
            msg = sandbox_recv.next() => match msg {
                Some((_ctx, request)) => {
                    state.handle_sandbox(request).await;
                }
                None => break,
            },
        }
    }

    tracing::info!("shim shutting down");

    // Clean up socket.
    let socket_path = PathBuf::from(&state.args.bundle).join("shim.sock");
    let _ = std::fs::remove_file(&socket_path);

    drop(cancel_send);
    server_task.await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Shim state + RPC handlers
// ---------------------------------------------------------------------------

struct ShimState {
    args: ShimArgs,
    driver: pal_async::DefaultDriver,
    /// VM lifecycle state.
    vm_state: VmState,
    /// Task metadata (container tracking).
    containers: HashMap<String, ContainerState>,
}

enum VmState {
    /// No sandbox created yet. VM will be booted on first Task.Create (standalone mode).
    Initial,
    /// Sandbox created, VM config resolved, but VM not yet booted.
    Configured(vm::VmConfig),
    /// VM is running, agent connected.
    Running(vm::RunningVm),
    /// VM has stopped.
    Stopped,
}

struct ContainerState {
    #[allow(dead_code)]
    bundle: String,
    status: i32,
    pid: u32,
    /// Receives exit status from agent. Set by Task.Start, consumed by Task.Wait.
    exit_recv: Option<mesh::OneshotReceiver<containerd_shim_agent_protocol::ExitStatus>>,
    /// Cached after Wait completes, returned by Delete.
    exit_code: Option<i32>,
    exited_at: Option<prost_types::Timestamp>,
    /// Host-side overlay mount path for cleanup on Delete.
    rootfs_mount_path: Option<PathBuf>,
    /// FIFO paths for reporting in State response.
    stdin_path: String,
    stdout_path: String,
    stderr_path: String,
    /// Host-side stdin pipe for CloseIO support.
    stdin_pipe: Option<mesh::pipe::WritePipe>,
    /// Keep relay threads alive (they exit when their pipes close).
    _io_threads: Vec<std::thread::JoinHandle<()>>,
    /// Exec processes tracked by exec_id.
    execs: HashMap<String, ExecState>,
}

/// Tracks a buffered exec process (created by Task.Exec, started by Task.Start).
struct ExecState {
    #[allow(dead_code)]
    container_id: String,
    spec_json: String,
    stdin: Option<mesh::pipe::ReadPipe>,
    stdout: Option<mesh::pipe::WritePipe>,
    stderr: Option<mesh::pipe::WritePipe>,
    terminal: bool,
    /// Set after Start:
    pid: u32,
    /// Pre-created exit channel. Wait takes the receiver; Start spawns a task
    /// that feeds agent exit status into the sender. This allows Wait to arrive
    /// before Start (containerd sends Wait before Start for exec processes).
    exit_send: Option<mesh::OneshotSender<containerd_shim_agent_protocol::ExitStatus>>,
    exit_recv: Option<mesh::OneshotReceiver<containerd_shim_agent_protocol::ExitStatus>>,
    /// Shared exit result cache. Written by the background wait task so that
    /// Delete can read it even though Wait ran in a spawned task.
    exit_result: std::sync::Arc<std::sync::Mutex<Option<(i32, prost_types::Timestamp)>>>,
    /// FIFO paths for State response.
    stdin_path: String,
    stdout_path: String,
    stderr_path: String,
    /// Host-side stdin pipe for CloseIO support.
    stdin_pipe: Option<mesh::pipe::WritePipe>,
    /// Keep relay threads alive.
    _io_threads: Vec<std::thread::JoinHandle<()>>,
}

impl ShimState {
    fn new(args: ShimArgs, driver: pal_async::DefaultDriver) -> Self {
        Self {
            args,
            driver,
            vm_state: VmState::Initial,
            containers: HashMap::new(),
        }
    }

    fn sandbox_created(&self) -> bool {
        !matches!(self.vm_state, VmState::Initial)
    }

    /// Handle a Task RPC. Returns `true` if the shim should shut down.
    async fn handle_task(&mut self, request: protos::Task) -> bool {
        match request {
            protos::Task::Create(req, resp) => {
                tracing::info!(id = %req.id, bundle = %req.bundle, "task.Create");

                // Standalone mode: if no VM running, boot one now.
                if matches!(self.vm_state, VmState::Initial) {
                    let bundle_path = PathBuf::from(&req.bundle);
                    match vm::resolve_config(&bundle_path, &HashMap::new()) {
                        Ok(config) => match vm::launch_vm(&self.driver, &config).await {
                            Ok(running) => {
                                self.vm_state = VmState::Running(running);
                                tracing::info!("standalone mode: VM booted");
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "failed to boot VM in standalone mode");
                                resp.send(Err(Status {
                                    code: Code::Internal.into(),
                                    message: format!("{e:#}"),
                                    details: vec![],
                                }));
                                return false;
                            }
                        },
                        Err(e) => {
                            tracing::error!(error = %e, "failed to resolve VM config");
                            resp.send(Err(Status {
                                code: Code::Internal.into(),
                                message: format!("{e:#}"),
                                details: vec![],
                            }));
                            return false;
                        }
                    }
                }

                match self.do_create_task(req).await {
                    Ok(r) => resp.send(Ok(r)),
                    Err(e) => {
                        tracing::error!(error = %e, "task.Create failed");
                        resp.send(Err(Status {
                            code: Code::Internal.into(),
                            message: format!("{e:#}"),
                            details: vec![],
                        }));
                    }
                }
                false
            }
            protos::Task::Start(req, resp) => {
                tracing::info!(id = %req.id, exec_id = %req.exec_id, "task.Start");
                if !req.exec_id.is_empty() {
                    match self.do_start_exec(&req.id, &req.exec_id).await {
                        Ok(r) => resp.send(Ok(r)),
                        Err(e) => {
                            tracing::error!(error = %e, "task.Start (exec) failed");
                            resp.send(Err(Status {
                                code: Code::Internal.into(),
                                message: format!("{e:#}"),
                                details: vec![],
                            }));
                        }
                    }
                } else {
                    match self.do_start_task(&req.id).await {
                        Ok(r) => resp.send(Ok(r)),
                        Err(e) => {
                            tracing::error!(error = %e, "task.Start failed");
                            resp.send(Err(Status {
                                code: Code::Internal.into(),
                                message: format!("{e:#}"),
                                details: vec![],
                            }));
                        }
                    }
                }
                false
            }
            protos::Task::Delete(req, resp) => {
                tracing::info!(id = %req.id, exec_id = %req.exec_id, "task.Delete");
                if !req.exec_id.is_empty() {
                    match self.do_delete_exec(&req.id, &req.exec_id).await {
                        Ok(r) => resp.send(Ok(r)),
                        Err(e) => {
                            tracing::error!(error = %e, "task.Delete (exec) failed");
                            resp.send(Err(Status {
                                code: Code::Internal.into(),
                                message: format!("{e:#}"),
                                details: vec![],
                            }));
                        }
                    }
                } else {
                    match self.do_delete_task(&req.id).await {
                        Ok(r) => resp.send(Ok(r)),
                        Err(e) => {
                            tracing::error!(error = %e, "task.Delete failed");
                            resp.send(Err(Status {
                                code: Code::Internal.into(),
                                message: format!("{e:#}"),
                                details: vec![],
                            }));
                        }
                    }
                }
                false
            }
            protos::Task::State(req, resp) => {
                tracing::info!(id = %req.id, exec_id = %req.exec_id, "task.State");
                match self.containers.get(&req.id) {
                    Some(container) => {
                        if !req.exec_id.is_empty() {
                            // Query exec state.
                            match container.execs.get(&req.exec_id) {
                                Some(exec) => {
                                    let cached = exec.exit_result.lock().unwrap().clone();
                                    let status = if cached.is_some() {
                                        protos::containerd::v1::types::Status::Stopped as i32
                                    } else if exec.pid > 0 {
                                        protos::containerd::v1::types::Status::Running as i32
                                    } else {
                                        protos::containerd::v1::types::Status::Created as i32
                                    };
                                    let (exit_code, exited_at) =
                                        cached.unwrap_or((0, prost_types::Timestamp::default()));
                                    resp.send(Ok(protos::containerd::task::v3::StateResponse {
                                        id: req.id,
                                        exec_id: req.exec_id,
                                        bundle: container.bundle.clone(),
                                        pid: exec.pid,
                                        status,
                                        stdin: exec.stdin_path.clone(),
                                        stdout: exec.stdout_path.clone(),
                                        stderr: exec.stderr_path.clone(),
                                        exit_status: exit_code as u32,
                                        exited_at: Some(exited_at),
                                        ..Default::default()
                                    }));
                                }
                                None => {
                                    resp.send(Err(Status {
                                        code: Code::NotFound.into(),
                                        message: format!("exec {} not found", req.exec_id),
                                        details: vec![],
                                    }));
                                }
                            }
                        } else {
                            resp.send(Ok(protos::containerd::task::v3::StateResponse {
                                id: req.id,
                                bundle: container.bundle.clone(),
                                pid: container.pid,
                                status: container.status,
                                stdin: container.stdin_path.clone(),
                                stdout: container.stdout_path.clone(),
                                stderr: container.stderr_path.clone(),
                                exit_status: container.exit_code.unwrap_or(0) as u32,
                                exited_at: container.exited_at.clone(),
                                ..Default::default()
                            }));
                        }
                    }
                    None => {
                        resp.send(Err(Status {
                            code: Code::NotFound.into(),
                            message: format!("container {} not found", req.id),
                            details: vec![],
                        }));
                    }
                }
                false
            }
            protos::Task::Wait(req, resp) => {
                tracing::info!(id = %req.id, exec_id = %req.exec_id, "task.Wait");
                if !req.exec_id.is_empty() {
                    // Exec wait: must not block the main loop because containerd
                    // sends Wait before Start. Spawn a background task.
                    let driver = self.driver.clone();
                    match self.prepare_wait_exec(&req.id, &req.exec_id) {
                        Ok(wait) => {
                            driver.spawn("exec-wait", async move {
                                let result = wait.await;
                                resp.send(Ok(result));
                            }).detach();
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "task.Wait (exec) failed");
                            resp.send(Err(Status {
                                code: Code::Internal.into(),
                                message: format!("{e:#}"),
                                details: vec![],
                            }));
                        }
                    }
                } else {
                    // Init wait: blocking is OK — containerd always sends
                    // Wait after Start for init processes.
                    match self.do_wait_task(&req.id).await {
                        Ok(r) => resp.send(Ok(r)),
                        Err(e) => {
                            tracing::error!(error = %e, "task.Wait failed");
                            resp.send(Err(Status {
                                code: Code::Internal.into(),
                                message: format!("{e:#}"),
                                details: vec![],
                            }));
                        }
                    }
                }
                false
            }
            protos::Task::Kill(req, resp) => {
                tracing::info!(id = %req.id, exec_id = %req.exec_id, signal = req.signal, "task.Kill");
                let exec_id = if req.exec_id.is_empty() {
                    None
                } else {
                    Some(req.exec_id)
                };
                match self
                    .do_kill_task(&req.id, req.signal, exec_id.as_deref())
                    .await
                {
                    Ok(()) => resp.send(Ok(())),
                    Err(e) => {
                        tracing::error!(error = %e, "task.Kill failed");
                        resp.send(Err(Status {
                            code: Code::Internal.into(),
                            message: format!("{e:#}"),
                            details: vec![],
                        }));
                    }
                }
                false
            }
            protos::Task::Connect(req, resp) => {
                let shim_pid = std::process::id();
                let task_pid = self.containers.get(&req.id).map(|c| c.pid).unwrap_or(0);
                tracing::info!(shim_pid, task_pid, "task.Connect");
                resp.send(Ok(protos::containerd::task::v3::ConnectResponse {
                    shim_pid,
                    task_pid,
                    version: String::from("v3"),
                }));
                false
            }
            protos::Task::Shutdown(_req, resp) => {
                tracing::info!("task.Shutdown");
                resp.send(Ok(()));
                if !self.sandbox_created() {
                    // Standalone mode — shut down VM.
                    if let VmState::Running(ref mut vm) = self.vm_state {
                        let _ = vm::shutdown_vm(&self.driver, vm).await;
                    }
                    self.vm_state = VmState::Stopped;
                    return true; // exit shim
                }
                false
            }
            protos::Task::CloseIo(req, resp) => {
                tracing::info!(id = %req.id, exec_id = %req.exec_id, "task.CloseIO");
                if let Some(container) = self.containers.get_mut(&req.id) {
                    if !req.exec_id.is_empty() {
                        // Close stdin for a specific exec.
                        if let Some(exec) = container.execs.get_mut(&req.exec_id) {
                            exec.stdin_pipe.take();
                        }
                    } else {
                        // Close stdin for the init process.
                        container.stdin_pipe.take();
                    }
                }
                resp.send(Ok(()));
                false
            }
            protos::Task::Exec(req, resp) => {
                tracing::info!(id = %req.id, exec_id = %req.exec_id, "task.Exec");
                match self.do_exec_create(&req).await {
                    Ok(()) => resp.send(Ok(())),
                    Err(e) => {
                        tracing::error!(error = %e, "task.Exec failed");
                        resp.send(Err(Status {
                            code: Code::Internal.into(),
                            message: format!("{e:#}"),
                            details: vec![],
                        }));
                    }
                }
                false
            }
            protos::Task::Pids(req, resp) => {
                tracing::info!(id = %req.id, "task.Pids");
                match self.do_pids(&req.id).await {
                    Ok(r) => resp.send(Ok(r)),
                    Err(e) => {
                        tracing::error!(error = %e, "task.Pids failed");
                        resp.send(Err(Status {
                            code: Code::Internal.into(),
                            message: format!("{e:#}"),
                            details: vec![],
                        }));
                    }
                }
                false
            }
            other => {
                tracing::warn!(method = other.method(), "unimplemented task method");
                other.fail(Status {
                    code: Code::Unimplemented.into(),
                    message: "not implemented".into(),
                    details: vec![],
                });
                false
            }
        }
    }

    // -----------------------------------------------------------------------
    // Task implementation methods
    // -----------------------------------------------------------------------

    async fn do_create_task(
        &mut self,
        req: protos::containerd::task::v3::CreateTaskRequest,
    ) -> anyhow::Result<protos::containerd::task::v3::CreateTaskResponse> {
        let vm = match &self.vm_state {
            VmState::Running(vm) => vm,
            _ => anyhow::bail!("VM not running"),
        };

        // Read OCI spec from bundle.
        let spec_path = PathBuf::from(&req.bundle).join("config.json");
        let spec_json =
            std::fs::read_to_string(&spec_path).context("failed to read config.json")?;

        // Get the containers staging directory (under the bundle used to create
        // the VM, which is the virtiofs root).
        let containers_dir = self.containers_dir();

        // Create staging directory for this container.
        let staging = containers_dir.join(&req.id);
        let rootfs_mount = staging.join("rootfs");
        std::fs::create_dir_all(&rootfs_mount).context("failed to create staging rootfs dir")?;

        // Apply overlay mount from containerd's rootfs mounts.
        if !req.rootfs.is_empty() {
            apply_rootfs_mounts(&req.rootfs, &rootfs_mount)?;
        }

        // Build mesh pipes for I/O bridging.
        let mut io_threads: Vec<std::thread::JoinHandle<()>> = Vec::new();
        let mut guest_stdin: Option<mesh::pipe::ReadPipe> = None;
        let mut guest_stdout: Option<mesh::pipe::WritePipe> = None;
        let mut guest_stderr: Option<mesh::pipe::WritePipe> = None;

        // stdout: guest → host FIFO
        if !req.stdout.is_empty() {
            let (read_pipe, write_pipe) = mesh::pipe::pipe();
            guest_stdout = Some(write_pipe);
            let stdout_path = req.stdout.clone();
            io_threads.push(std::thread::spawn(move || {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .open(&stdout_path)
                {
                    Ok(file) => {
                        let _ = block_on(futures::io::copy(read_pipe, &mut AllowStdIo::new(file)));
                    }
                    Err(e) => {
                        tracing::error!(path = %stdout_path, error = %e, "failed to open stdout FIFO");
                    }
                }
            }));
        }

        // stderr: guest → host FIFO
        if !req.stderr.is_empty() {
            let (read_pipe, write_pipe) = mesh::pipe::pipe();
            guest_stderr = Some(write_pipe);
            let stderr_path = req.stderr.clone();
            io_threads.push(std::thread::spawn(move || {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .open(&stderr_path)
                {
                    Ok(file) => {
                        let _ = block_on(futures::io::copy(read_pipe, &mut AllowStdIo::new(file)));
                    }
                    Err(e) => {
                        tracing::error!(path = %stderr_path, error = %e, "failed to open stderr FIFO");
                    }
                }
            }));
        }

        // stdin: host FIFO → guest
        if !req.stdin.is_empty() {
            let (read_pipe, mut write_pipe) = mesh::pipe::pipe();
            guest_stdin = Some(read_pipe);
            let stdin_path = req.stdin.clone();
            io_threads.push(std::thread::spawn(move || {
                match std::fs::OpenOptions::new()
                    .read(true)
                    .open(&stdin_path)
                {
                    Ok(file) => {
                        let _ = block_on(futures::io::copy(AllowStdIo::new(file), &mut write_pipe));
                    }
                    Err(e) => {
                        tracing::error!(path = %stdin_path, error = %e, "failed to open stdin FIFO");
                    }
                }
            }));
        }

        // Guest-side rootfs path.
        let guest_rootfs_path = format!("/run/containers/{}/rootfs", req.id);

        // Send CreateContainer RPC to agent.
        vm.agent_requests
            .call(
                AgentRequest::CreateContainer,
                CreateContainerRequest {
                    id: req.id.clone(),
                    spec_json,
                    rootfs_path: guest_rootfs_path,
                    stdin: guest_stdin,
                    stdout: guest_stdout,
                    stderr: guest_stderr,
                    terminal: req.terminal,
                },
            )
            .await
            .map_err(|e| anyhow::anyhow!("CreateContainer RPC failed: {e}"))?
            .map_err(|e| anyhow::anyhow!("CreateContainer failed: {e}"))?;

        self.containers.insert(
            req.id.clone(),
            ContainerState {
                bundle: req.bundle,
                status: protos::containerd::v1::types::Status::Created as i32,
                pid: 0,
                exit_recv: None,
                exit_code: None,
                exited_at: None,
                rootfs_mount_path: Some(rootfs_mount),
                stdin_path: req.stdin,
                stdout_path: req.stdout,
                stderr_path: req.stderr,
                stdin_pipe: None,
                _io_threads: io_threads,
                execs: HashMap::new(),
            },
        );

        Ok(protos::containerd::task::v3::CreateTaskResponse { pid: 0 })
    }

    async fn do_start_task(
        &mut self,
        id: &str,
    ) -> anyhow::Result<protos::containerd::task::v3::StartResponse> {
        let vm = match &self.vm_state {
            VmState::Running(vm) => vm,
            _ => anyhow::bail!("VM not running"),
        };

        let start_resp = vm
            .agent_requests
            .call(
                AgentRequest::StartContainer,
                StartContainerRequest { id: id.to_string() },
            )
            .await
            .map_err(|e| anyhow::anyhow!("StartContainer RPC failed: {e}"))?
            .map_err(|e| anyhow::anyhow!("StartContainer failed: {e}"))?;

        let container = self.containers.get_mut(id).context("container not found")?;

        container.pid = start_resp.pid;
        container.status = protos::containerd::v1::types::Status::Running as i32;
        container.exit_recv = Some(start_resp.exit_status);

        Ok(protos::containerd::task::v3::StartResponse {
            pid: start_resp.pid,
        })
    }

    async fn do_wait_task(
        &mut self,
        id: &str,
    ) -> anyhow::Result<protos::containerd::task::v3::WaitResponse> {
        let container = self.containers.get_mut(id).context("container not found")?;

        // If we already have cached exit info, return it.
        if let (Some(code), Some(exited_at)) = (container.exit_code, container.exited_at.clone()) {
            return Ok(protos::containerd::task::v3::WaitResponse {
                exit_status: code as u32,
                exited_at: Some(exited_at),
            });
        }

        // Await exit status from agent.
        let exit_recv = container
            .exit_recv
            .take()
            .context("no exit receiver (not started or already waited)")?;

        let exit_status = exit_recv
            .await
            .map_err(|_| anyhow::anyhow!("exit status channel broken"))?;

        let exited_at = prost_types::Timestamp {
            seconds: (exit_status.exited_at / 1_000_000_000) as i64,
            nanos: (exit_status.exited_at % 1_000_000_000) as i32,
        };

        container.status = protos::containerd::v1::types::Status::Stopped as i32;
        container.exit_code = Some(exit_status.code);
        container.exited_at = Some(exited_at.clone());

        Ok(protos::containerd::task::v3::WaitResponse {
            exit_status: exit_status.code as u32,
            exited_at: Some(exited_at),
        })
    }

    async fn do_kill_task(
        &mut self,
        id: &str,
        signal: u32,
        exec_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let vm = match &self.vm_state {
            VmState::Running(vm) => vm,
            _ => anyhow::bail!("VM not running"),
        };

        vm.agent_requests
            .call(
                AgentRequest::KillContainer,
                KillRequest {
                    id: id.to_string(),
                    signal,
                    exec_id: exec_id.map(|s| s.to_string()),
                },
            )
            .await
            .map_err(|e| anyhow::anyhow!("KillContainer RPC failed: {e}"))?
            .map_err(|e| anyhow::anyhow!("KillContainer failed: {e}"))?;

        Ok(())
    }

    async fn do_delete_task(
        &mut self,
        id: &str,
    ) -> anyhow::Result<protos::containerd::task::v3::DeleteResponse> {
        let vm = match &self.vm_state {
            VmState::Running(vm) => vm,
            _ => anyhow::bail!("VM not running"),
        };

        // Send DeleteContainer to agent.
        vm.agent_requests
            .call(
                AgentRequest::DeleteContainer,
                DeleteContainerRequest {
                    id: id.to_string(),
                    exec_id: None,
                },
            )
            .await
            .map_err(|e| anyhow::anyhow!("DeleteContainer RPC failed: {e}"))?
            .map_err(|e| anyhow::anyhow!("DeleteContainer failed: {e}"))?;

        // Clean up host-side state.
        let container = self.containers.remove(id).context("container not found")?;

        // Unmount overlay.
        if let Some(rootfs_mount) = &container.rootfs_mount_path {
            if let Ok(path_c) = std::ffi::CString::new(rootfs_mount.to_string_lossy().as_ref()) {
                // SAFETY: umount2 with a valid path.
                unsafe {
                    libc::umount2(path_c.as_ptr(), 0);
                }
            }
            // Remove staging directory.
            let staging = rootfs_mount.parent().unwrap_or(rootfs_mount);
            let _ = std::fs::remove_dir_all(staging);
        }

        let exit_status = container.exit_code.unwrap_or(0) as u32;
        let exited_at = container
            .exited_at
            .unwrap_or(prost_types::Timestamp::default());

        Ok(protos::containerd::task::v3::DeleteResponse {
            pid: container.pid,
            exit_status,
            exited_at: Some(exited_at),
        })
    }

    /// Handle Task.Exec — buffer the exec spec for later Start.
    async fn do_exec_create(
        &mut self,
        req: &protos::containerd::task::v3::ExecProcessRequest,
    ) -> anyhow::Result<()> {
        let container = self
            .containers
            .get_mut(&req.id)
            .context("container not found")?;

        if container.execs.contains_key(&req.exec_id) {
            anyhow::bail!("exec {} already exists", req.exec_id);
        }

        // Extract process spec JSON from the Any field.
        let spec_json = if let Some(spec_any) = &req.spec {
            // The spec is a protobuf Any wrapping a JSON-encoded OCI process spec.
            // containerd typically sends it as a google.protobuf.Any with the value
            // being the raw JSON bytes.
            String::from_utf8(spec_any.value.clone())
                .context("exec process spec is not valid UTF-8")?
        } else {
            anyhow::bail!("no process spec in exec request");
        };

        // Build mesh pipes for I/O bridging.
        let mut io_threads: Vec<std::thread::JoinHandle<()>> = Vec::new();
        let mut guest_stdin: Option<mesh::pipe::ReadPipe> = None;
        let mut guest_stdout: Option<mesh::pipe::WritePipe> = None;
        let mut guest_stderr: Option<mesh::pipe::WritePipe> = None;

        if !req.stdout.is_empty() {
            let (read_pipe, write_pipe) = mesh::pipe::pipe();
            guest_stdout = Some(write_pipe);
            let stdout_path = req.stdout.clone();
            io_threads.push(std::thread::spawn(move || {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .open(&stdout_path)
                {
                    Ok(file) => {
                        let _ = block_on(futures::io::copy(read_pipe, &mut AllowStdIo::new(file)));
                    }
                    Err(e) => {
                        tracing::error!(path = %stdout_path, error = %e, "failed to open exec stdout FIFO");
                    }
                }
            }));
        }

        if !req.stderr.is_empty() {
            let (read_pipe, write_pipe) = mesh::pipe::pipe();
            guest_stderr = Some(write_pipe);
            let stderr_path = req.stderr.clone();
            io_threads.push(std::thread::spawn(move || {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .open(&stderr_path)
                {
                    Ok(file) => {
                        let _ = block_on(futures::io::copy(read_pipe, &mut AllowStdIo::new(file)));
                    }
                    Err(e) => {
                        tracing::error!(path = %stderr_path, error = %e, "failed to open exec stderr FIFO");
                    }
                }
            }));
        }

        if !req.stdin.is_empty() {
            let (read_pipe, mut write_pipe) = mesh::pipe::pipe();
            guest_stdin = Some(read_pipe);
            let stdin_path = req.stdin.clone();
            io_threads.push(std::thread::spawn(move || {
                match std::fs::OpenOptions::new()
                    .read(true)
                    .open(&stdin_path)
                {
                    Ok(file) => {
                        let _ = block_on(futures::io::copy(
                            AllowStdIo::new(file),
                            &mut write_pipe,
                        ));
                    }
                    Err(e) => {
                        tracing::error!(path = %stdin_path, error = %e, "failed to open exec stdin FIFO");
                    }
                }
            }));
        }

        // Create the exit channel pair up front. Wait may arrive before Start
        // (containerd sends Wait in a goroutine before calling Start), so the
        // receiver must be available immediately.
        let (exit_send, exit_recv) = mesh::oneshot();

        container.execs.insert(
            req.exec_id.clone(),
            ExecState {
                container_id: req.id.clone(),
                spec_json,
                stdin: guest_stdin,
                stdout: guest_stdout,
                stderr: guest_stderr,
                terminal: req.terminal,
                pid: 0,
                exit_send: Some(exit_send),
                exit_recv: Some(exit_recv),
                exit_result: std::sync::Arc::new(std::sync::Mutex::new(None)),
                stdin_path: req.stdin.clone(),
                stdout_path: req.stdout.clone(),
                stderr_path: req.stderr.clone(),
                stdin_pipe: None,
                _io_threads: io_threads,
            },
        );

        Ok(())
    }

    /// Handle Task.Start for an exec — sends ExecProcess RPC to the agent.
    async fn do_start_exec(
        &mut self,
        container_id: &str,
        exec_id: &str,
    ) -> anyhow::Result<protos::containerd::task::v3::StartResponse> {
        let vm = match &self.vm_state {
            VmState::Running(vm) => vm,
            _ => anyhow::bail!("VM not running"),
        };

        let container = self
            .containers
            .get_mut(container_id)
            .context("container not found")?;

        let exec = container.execs.get_mut(exec_id).context("exec not found")?;

        let exec_resp = vm
            .agent_requests
            .call(
                AgentRequest::ExecProcess,
                ExecProcessRequest {
                    container_id: container_id.to_string(),
                    exec_id: exec_id.to_string(),
                    spec_json: exec.spec_json.clone(),
                    stdin: exec.stdin.take(),
                    stdout: exec.stdout.take(),
                    stderr: exec.stderr.take(),
                    terminal: exec.terminal,
                },
            )
            .await
            .map_err(|e| anyhow::anyhow!("ExecProcess RPC failed: {e}"))?
            .map_err(|e| anyhow::anyhow!("ExecProcess failed: {e}"))?;

        exec.pid = exec_resp.pid;

        // Bridge the agent's exit status into our pre-created exit channel.
        // This runs as a background task so the main loop isn't blocked.
        if let Some(exit_send) = exec.exit_send.take() {
            let agent_exit = exec_resp.exit_status;
            self.driver.spawn("exec-exit-watch", async move {
                match agent_exit.await {
                    Ok(status) => {
                        exit_send.send(status);
                    }
                    Err(_) => {
                        // Agent channel broken — send a synthetic exit status.
                        exit_send.send(containerd_shim_agent_protocol::ExitStatus {
                            code: -1,
                            exited_at: 0,
                        });
                    }
                }
            }).detach();
        }

        Ok(protos::containerd::task::v3::StartResponse { pid: exec_resp.pid })
    }

    /// Prepare a non-blocking Wait for an exec process.
    ///
    /// Returns a future that resolves to the WaitResponse. This must NOT
    /// be awaited in the main select loop because containerd sends Wait
    /// before Start for exec processes (Wait runs in a goroutine). Instead,
    /// the caller spawns the future as a background task.
    fn prepare_wait_exec(
        &mut self,
        container_id: &str,
        exec_id: &str,
    ) -> anyhow::Result<
        impl Future<Output = protos::containerd::task::v3::WaitResponse> + Send + use<>,
    > {
        let container = self
            .containers
            .get_mut(container_id)
            .context("container not found")?;

        let exec = container.execs.get_mut(exec_id).context("exec not found")?;

        // If we already have cached exit info, return it immediately.
        let cached = exec.exit_result.lock().unwrap().clone();
        if let Some((code, exited_at)) = cached {
            return Ok(futures::future::Either::Left(futures::future::ready(
                protos::containerd::task::v3::WaitResponse {
                    exit_status: code as u32,
                    exited_at: Some(exited_at),
                },
            )));
        }

        let exit_recv = exec
            .exit_recv
            .take()
            .context("no exit receiver (already waited)")?;

        let exit_result = exec.exit_result.clone();

        Ok(futures::future::Either::Right(async move {
            let exit_status = match exit_recv.await {
                Ok(status) => status,
                Err(_) => {
                    tracing::error!("exec exit status channel broken");
                    containerd_shim_agent_protocol::ExitStatus {
                        code: -1,
                        exited_at: 0,
                    }
                }
            };

            let exited_at = prost_types::Timestamp {
                seconds: (exit_status.exited_at / 1_000_000_000) as i64,
                nanos: (exit_status.exited_at % 1_000_000_000) as i32,
            };

            // Cache for Delete to read.
            *exit_result.lock().unwrap() = Some((exit_status.code, exited_at.clone()));

            protos::containerd::task::v3::WaitResponse {
                exit_status: exit_status.code as u32,
                exited_at: Some(exited_at),
            }
        }))
    }

    /// Handle Task.Delete for an exec.
    async fn do_delete_exec(
        &mut self,
        container_id: &str,
        exec_id: &str,
    ) -> anyhow::Result<protos::containerd::task::v3::DeleteResponse> {
        let vm = match &self.vm_state {
            VmState::Running(vm) => vm,
            _ => anyhow::bail!("VM not running"),
        };

        // Send DeleteContainer with exec_id to agent.
        vm.agent_requests
            .call(
                AgentRequest::DeleteContainer,
                DeleteContainerRequest {
                    id: container_id.to_string(),
                    exec_id: Some(exec_id.to_string()),
                },
            )
            .await
            .map_err(|e| anyhow::anyhow!("DeleteExec RPC failed: {e}"))?
            .map_err(|e| anyhow::anyhow!("DeleteExec failed: {e}"))?;

        let container = self
            .containers
            .get_mut(container_id)
            .context("container not found")?;

        let exec = container.execs.remove(exec_id).context("exec not found")?;

        let (exit_status, exited_at) = exec
            .exit_result
            .lock()
            .unwrap()
            .clone()
            .unwrap_or((0, prost_types::Timestamp::default()));

        Ok(protos::containerd::task::v3::DeleteResponse {
            pid: exec.pid,
            exit_status: exit_status as u32,
            exited_at: Some(exited_at),
        })
    }

    /// Handle Task.Pids — returns list of processes in a container.
    async fn do_pids(
        &mut self,
        id: &str,
    ) -> anyhow::Result<protos::containerd::task::v3::PidsResponse> {
        let vm = match &self.vm_state {
            VmState::Running(vm) => vm,
            _ => anyhow::bail!("VM not running"),
        };

        let resp = vm
            .agent_requests
            .call(
                AgentRequest::ListPids,
                ListPidsRequest {
                    container_id: id.to_string(),
                },
            )
            .await
            .map_err(|e| anyhow::anyhow!("ListPids RPC failed: {e}"))?
            .map_err(|e| anyhow::anyhow!("ListPids failed: {e}"))?;

        let processes = resp
            .pids
            .into_iter()
            .map(|p| protos::containerd::v1::types::ProcessInfo {
                pid: p.pid,
                info: None,
            })
            .collect();

        Ok(protos::containerd::task::v3::PidsResponse { processes })
    }

    /// Get the containers staging directory (virtiofs root).
    fn containers_dir(&self) -> PathBuf {
        PathBuf::from(&self.args.bundle).join("containers")
    }

    async fn handle_sandbox(&mut self, request: protos::Sandbox) {
        match request {
            protos::Sandbox::CreateSandbox(req, resp) => {
                tracing::info!(sandbox_id = %req.sandbox_id, "sandbox.CreateSandbox");
                let bundle_path = PathBuf::from(&self.args.bundle);
                match vm::resolve_config(&bundle_path, &req.annotations) {
                    Ok(config) => {
                        self.vm_state = VmState::Configured(config);
                        resp.send(Ok(
                            protos::containerd::runtime::sandbox::v1::CreateSandboxResponse {},
                        ));
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to resolve VM config");
                        resp.send(Err(Status {
                            code: Code::InvalidArgument.into(),
                            message: format!("{e:#}"),
                            details: vec![],
                        }));
                    }
                }
            }
            protos::Sandbox::StartSandbox(_req, resp) => {
                tracing::info!("sandbox.StartSandbox");
                match &self.vm_state {
                    VmState::Configured(_) => {
                        // Take the config out of the state.
                        let config = match std::mem::replace(&mut self.vm_state, VmState::Initial) {
                            VmState::Configured(c) => c,
                            _ => unreachable!(),
                        };
                        match vm::launch_vm(&self.driver, &config).await {
                            Ok(running) => {
                                self.vm_state = VmState::Running(running);
                                resp.send(Ok(
                                    protos::containerd::runtime::sandbox::v1::StartSandboxResponse {
                                        pid: std::process::id(),
                                        created_at: Some(prost_types::Timestamp::default()),
                                        spec: None,
                                    },
                                ));
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "failed to launch VM");
                                self.vm_state = VmState::Stopped;
                                resp.send(Err(Status {
                                    code: Code::Internal.into(),
                                    message: format!("{e:#}"),
                                    details: vec![],
                                }));
                            }
                        }
                    }
                    _ => {
                        resp.send(Err(Status {
                            code: Code::FailedPrecondition.into(),
                            message: "sandbox not in Configured state".into(),
                            details: vec![],
                        }));
                    }
                }
            }
            protos::Sandbox::Platform(_req, resp) => {
                tracing::info!("sandbox.Platform");
                resp.send(Ok(
                    protos::containerd::runtime::sandbox::v1::PlatformResponse {
                        platform: Some(protos::containerd::types::Platform {
                            os: "linux".into(),
                            architecture: std::env::consts::ARCH.into(),
                            variant: String::new(),
                            os_version: String::new(),
                        }),
                    },
                ));
            }
            protos::Sandbox::StopSandbox(_req, resp) => {
                tracing::info!("sandbox.StopSandbox");
                if let VmState::Running(ref mut vm) = self.vm_state {
                    if let Err(e) = vm::shutdown_vm(&self.driver, vm).await {
                        tracing::error!(error = %e, "VM shutdown error");
                    }
                }
                self.vm_state = VmState::Stopped;
                resp.send(Ok(
                    protos::containerd::runtime::sandbox::v1::StopSandboxResponse {},
                ));
            }
            protos::Sandbox::ShutdownSandbox(_req, resp) => {
                tracing::info!("sandbox.ShutdownSandbox");
                resp.send(Ok(
                    protos::containerd::runtime::sandbox::v1::ShutdownSandboxResponse {},
                ));
            }
            protos::Sandbox::WaitSandbox(_req, resp) => {
                tracing::info!("sandbox.WaitSandbox");
                match &mut self.vm_state {
                    VmState::Running(vm) => {
                        // Wait for VM halt.
                        match vm.halt_recv.next().await {
                            Some(reason) => {
                                tracing::info!(?reason, "VM halted (WaitSandbox)");
                                self.vm_state = VmState::Stopped;
                                resp.send(Ok(
                                    protos::containerd::runtime::sandbox::v1::WaitSandboxResponse {
                                        exit_status: 0,
                                        exited_at: Some(prost_types::Timestamp::default()),
                                    },
                                ));
                            }
                            None => {
                                tracing::info!("VM halt channel closed (WaitSandbox)");
                                self.vm_state = VmState::Stopped;
                                resp.send(Ok(
                                    protos::containerd::runtime::sandbox::v1::WaitSandboxResponse {
                                        exit_status: 1,
                                        exited_at: Some(prost_types::Timestamp::default()),
                                    },
                                ));
                            }
                        }
                    }
                    VmState::Stopped => {
                        // VM already stopped — return immediately.
                        resp.send(Ok(
                            protos::containerd::runtime::sandbox::v1::WaitSandboxResponse {
                                exit_status: 0,
                                exited_at: Some(prost_types::Timestamp::default()),
                            },
                        ));
                    }
                    _ => {
                        // No VM yet — shouldn't happen but respond with error.
                        resp.send(Err(Status {
                            code: Code::FailedPrecondition.into(),
                            message: "VM not running".into(),
                            details: vec![],
                        }));
                    }
                }
            }
            protos::Sandbox::PingSandbox(_req, resp) => {
                tracing::info!("sandbox.PingSandbox");
                if let VmState::Running(vm) = &self.vm_state {
                    match vm.agent_requests.call(AgentRequest::Ping, ()).await {
                        Ok(()) => {
                            resp.send(Ok(
                                protos::containerd::runtime::sandbox::v1::PingResponse {},
                            ));
                        }
                        Err(e) => {
                            resp.send(Err(Status {
                                code: Code::Unavailable.into(),
                                message: format!("ping failed: {e}"),
                                details: vec![],
                            }));
                        }
                    }
                } else {
                    resp.send(Ok(
                        protos::containerd::runtime::sandbox::v1::PingResponse {},
                    ));
                }
            }
            protos::Sandbox::SandboxStatus(_req, resp) => {
                tracing::info!("sandbox.SandboxStatus");
                resp.send(Ok(
                    protos::containerd::runtime::sandbox::v1::SandboxStatusResponse {
                        sandbox_id: self.args.id.clone(),
                        pid: std::process::id(),
                        state: "ready".into(),
                        info: HashMap::new(),
                        created_at: Some(prost_types::Timestamp::default()),
                        exited_at: None,
                        extra: None,
                    },
                ));
            }
            protos::Sandbox::SandboxMetrics(_req, resp) => {
                tracing::info!("sandbox.SandboxMetrics");
                resp.send(Ok(
                    protos::containerd::runtime::sandbox::v1::SandboxMetricsResponse {
                        metrics: None,
                    },
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// `delete` subcommand
// ---------------------------------------------------------------------------

fn cmd_delete(args: ShimArgs) -> anyhow::Result<()> {
    let socket_path = PathBuf::from(&args.bundle).join("shim.sock");

    // Clean up socket file.
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    // Write protobuf-encoded DeleteResponse to stdout.
    // containerd expects wire-format protobuf, not JSON.
    use prost::Message;
    let response = protos::containerd::task::v3::DeleteResponse {
        pid: 0,
        exit_status: 0,
        exited_at: Some(prost_types::Timestamp {
            seconds: 0,
            nanos: 0,
        }),
    };
    let mut buf = Vec::with_capacity(response.encoded_len());
    response
        .encode(&mut buf)
        .context("failed to encode DeleteResponse")?;
    std::io::stdout()
        .write_all(&buf)
        .context("failed to write DeleteResponse")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let cmd = match parse_args() {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    };

    let result = match cmd {
        Command::Start(args) => cmd_start(args),
        Command::Serve { args, pipe_fd } => cmd_serve(args, pipe_fd),
        Command::Delete(args) => cmd_delete(args),
    };

    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Bring FromRawFd into scope for the unsafe fd conversions.
// ---------------------------------------------------------------------------
use std::os::unix::io::FromRawFd;

// ---------------------------------------------------------------------------
// Overlay mount helpers
// ---------------------------------------------------------------------------

/// Apply containerd's rootfs mounts (typically overlay or bind) on the host.
fn apply_rootfs_mounts(
    mounts: &[protos::containerd::types::Mount],
    target: &std::path::Path,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(target)?;
    for mount in mounts {
        let mut flags: u64 = 0;
        let mut data_opts = Vec::new();

        // Parse mount options into flags vs. data.
        for opt in &mount.options {
            match opt.as_str() {
                "rbind" => flags |= libc::MS_BIND as u64 | libc::MS_REC as u64,
                "bind" => flags |= libc::MS_BIND as u64,
                "ro" => flags |= libc::MS_RDONLY as u64,
                "nosuid" => flags |= libc::MS_NOSUID as u64,
                "nodev" => flags |= libc::MS_NODEV as u64,
                "noexec" => flags |= libc::MS_NOEXEC as u64,
                "rw" => {} // default, no flag needed
                _ => data_opts.push(opt.as_str()),
            }
        }

        // If mount type is "bind", ensure MS_BIND is set.
        if mount.r#type == "bind" {
            flags |= libc::MS_BIND as u64;
        }

        let data = data_opts.join(",");
        let target_str = target.to_string_lossy();
        let source = if mount.source.is_empty() {
            &mount.r#type
        } else {
            &mount.source
        };
        c_mount(source, &target_str, &mount.r#type, flags, &data)
            .with_context(|| format!("failed to mount {} at {}", mount.r#type, target_str))?;
    }
    Ok(())
}

fn c_mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: u64,
    data: &str,
) -> std::io::Result<()> {
    let source = std::ffi::CString::new(source)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let target = std::ffi::CString::new(target)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let fstype = std::ffi::CString::new(fstype)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let data = std::ffi::CString::new(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
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
