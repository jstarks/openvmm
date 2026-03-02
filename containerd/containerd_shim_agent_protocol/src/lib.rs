// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Protocol types shared between the containerd shim host and the guest agent.
//!
//! Communication uses a mesh point-to-point connection over VMBus hvsocket
//! (AF_VSOCK), following the same pattern as petri/pipette and vmexec.

#![forbid(unsafe_code)]

use mesh::MeshPayload;
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
    // M3 additions (not yet implemented):
    // CreateContainer(FailableRpc<CreateContainerRequest, CreateContainerResponse>),
    // StartContainer(FailableRpc<StartContainerRequest, StartContainerResponse>),
    // KillContainer(FailableRpc<KillRequest, ()>),
    // DeleteContainer(FailableRpc<DeleteContainerRequest, ()>),
    // ExecProcess(FailableRpc<ExecProcessRequest, ExecProcessResponse>),
    // ResizePty(FailableRpc<ResizePtyRequest, ()>),
    // ContainerStats(FailableRpc<StatsRequest, StatsResponse>),
}

/// Exit status of a container process.
#[derive(MeshPayload, Clone, Debug)]
pub struct ExitStatus {
    /// Exit code. 0 = success, >0 = error, 128+N = killed by signal N.
    pub code: i32,
    /// When the process exited (Unix timestamp, nanoseconds).
    pub exited_at: u64,
}
