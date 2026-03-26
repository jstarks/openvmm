// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Definitions for the mesh entrypoint.
//!
//! These are here instead of in `openvmm_entry` to support launching OpenVMM from
//! a foreign mesh host. The only supported use case is launching OpenVMM from
//! petri for testing.

use framebuffer::FramebufferAccess;
use mesh::MeshPayload;
use mesh_worker::WorkerHostRunner;

/// Parameters for the GUI child process.
#[derive(MeshPayload)]
pub struct GuiParameters {
    /// The framebuffer memory.
    pub framebuffer: FramebufferAccess,
    /// A channel to send input to.
    pub input_send: mesh::Sender<input_core::InputData>,
    /// Held by the child to indicate liveness. Dropped when the child exits.
    pub alive_send: mesh::Sender<()>,
}

/// The initial message to send when launching a mesh child process.
#[derive(MeshPayload)]
pub enum MeshHostParams {
    /// Run the worker host, dispatching to registered workers.
    WorkerHost(WorkerHostRunner),
    /// Run the GUI frontend directly.
    Gui(GuiParameters),
}
