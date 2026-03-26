// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Functions and types for running a mesh for OpenVMM and launching workers
//! within it.

use anyhow::Context;
use inspect::Inspect;
use mesh_process::Mesh;
use mesh_process::ProcessConfig;
use mesh_process::try_run_mesh_host;
use mesh_worker::RegisteredWorkers;
use mesh_worker::WorkerHost;
use openvmm_defs::entrypoint::MeshHostParams;
use pal_async::task::Spawn;
use pal_async::task::Task;
use std::path::PathBuf;

pub(crate) fn run_vmm_mesh_host() -> anyhow::Result<()> {
    try_run_mesh_host("openvmm", async |params: MeshHostParams| {
        match params {
            MeshHostParams::WorkerHost(runner) => {
                runner.run(RegisteredWorkers).await;
            }
            MeshHostParams::Gui(gui_params) => {
                #[cfg(feature = "gui")]
                openvmm_gui::run(gui_params.framebuffer, gui_params.input_send)?;
                #[cfg(not(feature = "gui"))]
                {
                    let _ = gui_params;
                    anyhow::bail!("GUI support not compiled in");
                }
            }
        }
        Ok(())
    })
}

#[derive(Inspect)]
pub(crate) struct VmmMesh {
    #[inspect(flatten)]
    mesh: Option<Mesh>,
    #[inspect(skip)]
    local_host: WorkerHost,
    #[inspect(skip)]
    _task: Task<()>,
}

impl VmmMesh {
    pub fn new(spawn: &impl Spawn, single_process: bool) -> anyhow::Result<Self> {
        let mesh = if single_process {
            None
        } else {
            Some(Mesh::new("openvmm".to_string())?)
        };
        let (local_host, runner) = mesh_worker::worker_host();
        let task = spawn.spawn("worker-host", runner.run(RegisteredWorkers));
        Ok(Self {
            mesh,
            local_host,
            _task: task,
        })
    }

    pub async fn make_host(
        &self,
        name: impl Into<String>,
        log_file: Option<PathBuf>,
    ) -> anyhow::Result<WorkerHost> {
        let log_file: Option<std::fs::File> = if let Some(file) = &log_file {
            Some(
                std::fs::File::create(file)
                    .with_context(|| format!("failed to create log file {}", file.display()))?,
            )
        } else {
            None
        };

        let host = if let Some(mesh) = &self.mesh {
            let (host, runner) = mesh_worker::worker_host();
            mesh.launch_host(
                ProcessConfig::new(name).stderr(log_file),
                MeshHostParams::WorkerHost(runner),
            )
            .await?;
            host
        } else {
            self.local_host.clone()
        };
        Ok(host)
    }

    /// Launch the GUI in a child process, sending parameters directly.
    #[cfg(feature = "gui")]
    pub async fn launch_gui(&self, params: openvmm_gui::GuiParameters) -> anyhow::Result<()> {
        let mesh = self
            .mesh
            .as_ref()
            .context("GUI requires multi-process mode (no --single-process)")?;
        mesh.launch_host(ProcessConfig::new("gui"), MeshHostParams::Gui(params))
            .await?;
        Ok(())
    }

    pub async fn shutdown(self) {
        if let Some(mesh) = self.mesh {
            mesh.shutdown().await;
        }
    }
}
