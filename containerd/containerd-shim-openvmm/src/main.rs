// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! containerd shim v2 runtime for OpenVMM.
//!
//! Binary name: `containerd-shim-openvmm-v2`
//!
//! Implements the containerd shim v2 protocol with Task v3 and Sandbox v1 APIs.
//! Currently a stub — logs all requests, returns defaults, launches no VM.

#![allow(unsafe_code)]

use anyhow::Context as _;
use containerd_shim_protos as protos;
use futures::StreamExt;
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
                publish_binary =
                    Some(raw.get(i).context("missing -publish-binary value")?.clone());
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
            Ok(Command::Serve {
                args,
                pipe_fd: fd,
            })
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
        return Err(std::io::Error::last_os_error())
            .context("failed to create readiness pipe");
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
    let _n = read_file.read(&mut buf).context("failed to read readiness signal")?;

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
        let listener = unix_socket::UnixListener::bind(&socket_path)
            .context("failed to bind shim socket")?;

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

    let mut state = ShimState::new(args);

    loop {
        futures::select! {
            msg = task_recv.next() => match msg {
                Some((_ctx, request)) => {
                    if state.handle_task(request) {
                        break;
                    }
                }
                None => break,
            },
            msg = sandbox_recv.next() => match msg {
                Some((_ctx, request)) => {
                    state.handle_sandbox(request);
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
    sandbox_created: bool,
    containers: HashMap<String, ContainerState>,
}

struct ContainerState {
    #[allow(dead_code)]
    bundle: String,
    status: i32,
    pid: u32,
}

impl ShimState {
    fn new(args: ShimArgs) -> Self {
        Self {
            args,
            sandbox_created: false,
            containers: HashMap::new(),
        }
    }

    /// Handle a Task RPC. Returns `true` if the shim should shut down.
    fn handle_task(&mut self, request: protos::Task) -> bool {
        match request {
            protos::Task::Create(req, resp) => {
                tracing::info!(id = %req.id, bundle = %req.bundle, "task.Create");
                self.containers.insert(
                    req.id.clone(),
                    ContainerState {
                        bundle: req.bundle.clone(),
                        status: protos::containerd::v1::types::Status::Created as i32,
                        pid: 1,
                    },
                );
                resp.send(Ok(protos::containerd::task::v3::CreateTaskResponse {
                    pid: 1,
                }));
                false
            }
            protos::Task::Start(req, resp) => {
                tracing::info!(id = %req.id, "task.Start");
                if let Some(c) = self.containers.get_mut(&req.id) {
                    c.status = protos::containerd::v1::types::Status::Running as i32;
                }
                resp.send(Ok(protos::containerd::task::v3::StartResponse { pid: 1 }));
                false
            }
            protos::Task::Delete(req, resp) => {
                tracing::info!(id = %req.id, "task.Delete");
                self.containers.remove(&req.id);
                resp.send(Ok(protos::containerd::task::v3::DeleteResponse {
                    pid: 1,
                    exit_status: 0,
                    exited_at: Some(prost_types::Timestamp::default()),
                }));
                false
            }
            protos::Task::State(req, resp) => {
                tracing::info!(id = %req.id, "task.State");
                let (status, pid) = self
                    .containers
                    .get(&req.id)
                    .map(|c| (c.status, c.pid))
                    .unwrap_or((0, 0));
                resp.send(Ok(protos::containerd::task::v3::StateResponse {
                    id: req.id,
                    pid,
                    status,
                    ..Default::default()
                }));
                false
            }
            protos::Task::Wait(_req, _resp) => {
                tracing::info!("task.Wait — blocking forever (stub)");
                // Don't respond — keeps containerd waiting. The sender is
                // leaked intentionally; the task never exits in this stub.
                false
            }
            protos::Task::Kill(req, resp) => {
                tracing::info!(id = %req.id, signal = req.signal, "task.Kill");
                resp.send(Ok(()));
                false
            }
            protos::Task::Connect(_req, resp) => {
                let pid = std::process::id();
                tracing::info!(shim_pid = pid, "task.Connect");
                resp.send(Ok(protos::containerd::task::v3::ConnectResponse {
                    shim_pid: pid,
                    task_pid: 1,
                    version: String::from("v3"),
                }));
                false
            }
            protos::Task::Shutdown(_req, resp) => {
                tracing::info!("task.Shutdown");
                resp.send(Ok(()));
                // Only shut down if we are NOT in sandbox mode.
                !self.sandbox_created
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

    fn handle_sandbox(&mut self, request: protos::Sandbox) {
        match request {
            protos::Sandbox::CreateSandbox(req, resp) => {
                tracing::info!(sandbox_id = %req.sandbox_id, "sandbox.CreateSandbox");
                self.sandbox_created = true;
                resp.send(Ok(
                    protos::containerd::runtime::sandbox::v1::CreateSandboxResponse {},
                ));
            }
            protos::Sandbox::StartSandbox(_req, resp) => {
                let pid = std::process::id();
                tracing::info!(pid, "sandbox.StartSandbox");
                resp.send(Ok(
                    protos::containerd::runtime::sandbox::v1::StartSandboxResponse {
                        pid,
                        created_at: Some(prost_types::Timestamp::default()),
                        spec: None,
                    },
                ));
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
            protos::Sandbox::WaitSandbox(_req, _resp) => {
                tracing::info!("sandbox.WaitSandbox — blocking forever (stub)");
                // Don't respond — sandbox never exits in stub.
            }
            protos::Sandbox::PingSandbox(_req, resp) => {
                tracing::info!("sandbox.PingSandbox");
                resp.send(Ok(
                    protos::containerd::runtime::sandbox::v1::PingResponse {},
                ));
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

    // Print a DeleteResponse to stdout (containerd reads this).
    let response = serde_json::json!({
        "pid": 0,
        "exitStatus": 0,
        "exitedAt": "0001-01-01T00:00:00Z"
    });
    println!("{response}");
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
