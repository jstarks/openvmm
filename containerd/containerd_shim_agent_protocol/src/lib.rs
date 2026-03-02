// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Protocol types shared between the containerd shim host and the guest agent.
//!
//! Communication uses a mesh point-to-point connection over VMBus hvsocket
//! (AF_VSOCK), following the same pattern as petri/pipette and vmexec.

#![forbid(unsafe_code)]

use mesh::MeshPayload;
use mesh::pipe::ReadPipe;
use mesh::pipe::WritePipe;
use mesh::rpc::FailableRpc;
use mesh::rpc::Rpc;

/// The AF_VSOCK port used for the containerd shim guest agent connection.
pub const AGENT_VSOCK_PORT: u32 = 0xCE02;

/// Bootstrap message sent from the guest agent to the host shim after connection.
#[derive(MeshPayload)]
pub struct AgentBootstrap {
    /// Channel for host→guest RPCs.
    pub requests: mesh::Sender<AgentRequest>,
    /// Closed when the agent exits (crash or shutdown).
    pub watch: mesh::OneshotReceiver<()>,
}

/// An RPC request from the host shim to the guest agent.
#[derive(MeshPayload)]
pub enum AgentRequest {
    /// Health check.
    Ping(Rpc<(), ()>),
    /// Shut down the agent (powers off the VM).
    Shutdown(FailableRpc<(), ()>),
    /// Create a container (prepare rootfs, store spec). Does NOT start it.
    CreateContainer(FailableRpc<CreateContainerRequest, CreateContainerResponse>),
    /// Start a previously created container (fork+exec).
    StartContainer(FailableRpc<StartContainerRequest, StartContainerResponse>),
    /// Send a signal to a running container process.
    KillContainer(FailableRpc<KillRequest, ()>),
    /// Delete a container and clean up resources.
    DeleteContainer(FailableRpc<DeleteContainerRequest, ()>),
}

/// Request to create a container.
#[derive(MeshPayload)]
pub struct CreateContainerRequest {
    /// Container ID.
    pub id: String,
    /// JSON-serialized OCI runtime spec (from bundle's config.json).
    pub spec_json: String,
    /// Path inside the guest where rootfs is mounted via virtiofs,
    /// e.g., `/run/containers/{id}/rootfs`.
    pub rootfs_path: String,
    /// Stdin pipe (host→guest data flow). None if not requested.
    pub stdin: Option<ReadPipe>,
    /// Stdout pipe (guest→host data flow). None if not requested.
    pub stdout: Option<WritePipe>,
    /// Stderr pipe (guest→host data flow). None if not requested.
    pub stderr: Option<WritePipe>,
    /// Whether to allocate a PTY (terminal mode). Not implemented in M3.
    pub terminal: bool,
}

/// Response to CreateContainer.
#[derive(MeshPayload)]
pub struct CreateContainerResponse {}

/// Request to start a previously created container.
#[derive(MeshPayload)]
pub struct StartContainerRequest {
    /// Container ID.
    pub id: String,
}

/// Response to StartContainer.
#[derive(MeshPayload)]
pub struct StartContainerResponse {
    /// PID of the container process inside the guest.
    pub pid: u32,
    /// Receives exit status when the container process exits.
    pub exit_status: mesh::OneshotReceiver<ExitStatus>,
}

/// Request to send a signal to a container process.
#[derive(MeshPayload)]
pub struct KillRequest {
    /// Container ID.
    pub id: String,
    /// Signal number (e.g. SIGTERM=15, SIGKILL=9).
    pub signal: u32,
}

/// Request to delete a container.
#[derive(MeshPayload)]
pub struct DeleteContainerRequest {
    /// Container ID.
    pub id: String,
}

/// Exit status of a container process.
#[derive(MeshPayload, Clone, Debug)]
pub struct ExitStatus {
    /// Exit code. 0 = success, >0 = error, 128+N = killed by signal N.
    pub code: i32,
    /// When the process exited (Unix timestamp, nanoseconds).
    pub exited_at: u64,
}
