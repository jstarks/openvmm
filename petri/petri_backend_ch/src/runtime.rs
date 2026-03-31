// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cloud-hypervisor VM runtime implementation.

use anyhow::Context as _;
use async_trait::async_trait;
use pal_async::DefaultDriver;
use pal_async::socket::PolledSocket;
use petri::NoPetriVmFramebufferAccess;
use petri::NoPetriVmInspector;
use petri::OpenHclServicingFlags;
use petri::PetriHaltReason;
use petri::PetriVmProperties;
use petri::PetriVmRuntime;
use petri::ShutdownKind;
use petri_artifacts_core::ResolvedArtifact;
use pipette_client::PipetteClient;
use std::path::PathBuf;
use unix_socket::UnixListener;
use vtl2_settings_proto::Vtl2Settings;

/// A running cloud-hypervisor VM.
pub struct ChVmRuntime {
    child: Option<std::process::Child>,
    pipette_listener: PolledSocket<UnixListener>,
    _api_socket_path: PathBuf,
    driver: DefaultDriver,
    output_dir: PathBuf,
    // Keep the temp directory alive so socket files aren't cleaned up.
    _temp_dir: tempfile::TempDir,
    properties: PetriVmProperties,
    cidata_mounted: bool,
}

impl ChVmRuntime {
    pub(crate) fn new(
        child: std::process::Child,
        pipette_listener: PolledSocket<UnixListener>,
        api_socket_path: PathBuf,
        driver: DefaultDriver,
        output_dir: PathBuf,
        temp_dir: tempfile::TempDir,
        properties: PetriVmProperties,
    ) -> Self {
        Self {
            child: Some(child),
            pipette_listener,
            _api_socket_path: api_socket_path,
            driver,
            output_dir,
            _temp_dir: temp_dir,
            properties,
            cidata_mounted: false,
        }
    }
}

#[async_trait]
impl PetriVmRuntime for ChVmRuntime {
    type VmInspector = NoPetriVmInspector;
    type VmFramebufferAccess = NoPetriVmFramebufferAccess;

    async fn teardown(mut self) -> anyhow::Result<()> {
        if let Some(mut child) = self.child.take() {
            tracing::info!("killing cloud-hypervisor process");
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }

    async fn wait_for_halt(&mut self, _allow_reset: bool) -> anyhow::Result<PetriHaltReason> {
        let mut child = self
            .child
            .take()
            .context("cloud-hypervisor process already consumed")?;

        // Wait for the child process to exit on a background thread to
        // avoid blocking the async executor.
        let (tx, rx) = mesh::oneshot();
        std::thread::spawn(move || {
            let status = child.wait();
            tx.send((child, status));
        });

        let (child, status) = rx.await.context("wait thread dropped")?;
        let status = status.context("failed to wait for cloud-hypervisor process")?;
        // Put the child back so Drop doesn't try to kill a waited process.
        self.child = Some(child);

        tracing::info!(?status, "cloud-hypervisor exited");
        Ok(PetriHaltReason::PowerOff)
    }

    async fn wait_for_agent(&mut self, set_high_vtl: bool) -> anyhow::Result<PipetteClient> {
        if set_high_vtl {
            anyhow::bail!("cloud-hypervisor does not support VTL2 pipette");
        }

        tracing::info!("listening for pipette connection from cloud-hypervisor guest");
        let (conn, _) = self
            .pipette_listener
            .accept()
            .await
            .context("failed to accept pipette connection")?;

        tracing::info!("handshaking with pipette");
        let client = PipetteClient::new(
            &self.driver,
            PolledSocket::new(&self.driver, conn)?,
            &self.output_dir,
        )
        .await
        .context("failed to connect to pipette")?;
        tracing::info!("completed pipette handshake");

        // When pipette runs as PID 1 init and a CIDATA agent disk is
        // attached, mount it so test files are available at /cidata.
        if self.properties.uses_pipette_as_init
            && self.properties.has_agent_disk
            && !self.cidata_mounted
        {
            tracing::info!("mounting CIDATA agent disk via pipette");
            client
                .unix_shell()
                .cmd("mkdir")
                .arg("-p")
                .arg("/cidata")
                .run()
                .await
                .context("failed to create /cidata mount point")?;
            client
                .unix_shell()
                .cmd("mount")
                .arg("LABEL=cidata")
                .arg("/cidata")
                .run()
                .await
                .context("failed to mount CIDATA disk")?;
            self.cidata_mounted = true;
        }

        Ok(client)
    }

    fn openhcl_diag(&self) -> Option<petri::openhcl_diag::OpenHclDiagHandler> {
        None
    }

    async fn wait_for_boot_event(&mut self) -> anyhow::Result<get_resources::ged::FirmwareEvent> {
        anyhow::bail!("cloud-hypervisor does not emit firmware boot events")
    }

    async fn wait_for_enlightened_shutdown_ready(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("cloud-hypervisor does not support Hyper-V shutdown IC")
    }

    async fn send_enlightened_shutdown(&mut self, _kind: ShutdownKind) -> anyhow::Result<()> {
        anyhow::bail!("cloud-hypervisor does not support Hyper-V shutdown IC")
    }

    async fn restart_openhcl(
        &mut self,
        _new_openhcl: &ResolvedArtifact,
        _flags: OpenHclServicingFlags,
    ) -> anyhow::Result<()> {
        anyhow::bail!("cloud-hypervisor does not support OpenHCL")
    }

    async fn save_openhcl(
        &mut self,
        _new_openhcl: &ResolvedArtifact,
        _flags: OpenHclServicingFlags,
    ) -> anyhow::Result<()> {
        anyhow::bail!("cloud-hypervisor does not support OpenHCL")
    }

    async fn restore_openhcl(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("cloud-hypervisor does not support OpenHCL")
    }

    async fn update_command_line(&mut self, _command_line: &str) -> anyhow::Result<()> {
        anyhow::bail!("cloud-hypervisor does not support command line updates")
    }

    async fn reset(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("cloud-hypervisor reset not yet implemented")
    }

    async fn set_vtl2_settings(&mut self, _settings: &Vtl2Settings) -> anyhow::Result<()> {
        anyhow::bail!("cloud-hypervisor does not support VTL2 settings")
    }

    async fn set_vmbus_drive(
        &mut self,
        _disk: &petri::Drive,
        _controller_id: &guid::Guid,
        _controller_location: u32,
    ) -> anyhow::Result<()> {
        anyhow::bail!("cloud-hypervisor does not support VMBus drive hotplug")
    }
}

impl Drop for ChVmRuntime {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
