// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local process replacement for a direct-boot VM. The management RPCs
//! rendezvous two VMMs; live handles travel only on their private mesh.

use super::*;
use mesh::rpc::FailableRpc;
use openvmm_defs::rpc::ServicingResources;

#[derive(MeshPayload)]
struct Offer {
    resources: ServicingResources,
    prepared: mesh::OneshotSender<()>,
    state: mesh::OneshotReceiver<mesh::payload::message::ProtobufMessage>,
    ready: mesh::OneshotSender<()>,
    commit: mesh::OneshotReceiver<()>,
    resumed: mesh::OneshotSender<()>,
}

#[derive(Debug, Clone, PartialEq, mesh::payload::Protobuf)]
pub(super) struct TransferProfile {
    architecture: String,
    memory: vmservice::MemoryConfig,
    processors: Option<vmservice::ProcessorConfig>,
    cmdline: String,
    initrd: bool,
}

type Request = FailableRpc<TransferProfile, Offer>;

pub(super) fn profile(config: &vmservice::VmConfig) -> Option<TransferProfile> {
    let Some(vmservice::vm_config::BootConfig::DirectBoot(boot)) = &config.boot_config else {
        return None;
    };
    // Only admit the fixture whose devices can be reconstructed without
    // side effects on RAM before commit. New device classes opt in explicitly.
    let supported = vmservice::VmConfig {
        boot_config: config.boot_config.clone(),
        memory_config: config.memory_config.clone(),
        processor_config: config.processor_config.clone(),
        disable_vmbus: true,
        disable_hv: true,
        ..Default::default()
    };
    if &supported != config {
        return None;
    }
    let mut memory = supported.memory_config?;
    memory.backing_file_path = None;
    Some(TransferProfile {
        architecture: crate::GUEST_ARCH.to_owned(),
        memory,
        processors: supported.processor_config,
        cmdline: boot.kernel_cmdline.clone(),
        initrd: !boot.initrd_path.is_empty(),
    })
}

impl VmService {
    pub(super) async fn offer_servicing(
        &mut self,
        ctx: mesh::CancelContext,
        path: &Path,
    ) -> anyhow::Result<vmservice::OfferServicingVmResponse> {
        let mut ctx = ctx.with_timeout(Duration::from_secs(60));
        anyhow::ensure!(
            matches!(self.lifecycle, VmLifecycle::Running),
            "source VM must be running"
        );
        let vm = self.vm.as_ref().context("no VM")?;
        let profile = vm
            .servicing_profile
            .clone()
            .context("unsupported servicing configuration")?;
        let worker = vm.worker_rpc.clone();
        let resources = worker.call_failable(VmRpc::ServicingResources, ()).await?;
        let mesh = mesh_process::Mesh::new("servicing".into())?;
        let mut listener = mesh.listen::<Request>(path).await?;
        let request = ctx
            .until_cancelled(listener.next())
            .await?
            .context("servicing listener closed")?;
        let (candidate, response) = request.split();
        if candidate != profile {
            response.complete(Err(RemoteError::new(anyhow!(
                "destination configuration mismatch"
            ))));
            anyhow::bail!("destination configuration mismatch");
        }
        let (prepared, built) = mesh::oneshot();
        let (state, incoming) = mesh::oneshot();
        let (commit, committed) = mesh::oneshot();
        let (resumed, did_resume) = mesh::oneshot();
        let (ready, restored) = mesh::oneshot();
        response.complete(Ok(Offer {
            resources,
            prepared,
            state: incoming,
            ready,
            commit: committed,
            resumed,
        }));
        ctx.until_cancelled(built).await??;
        let blackout = std::time::Instant::now();
        self.pause_vm().await?;
        let prepared = async {
            state.send(worker.call_failable(VmRpc::Save, ()).await?);
            ctx.until_cancelled(restored).await??;
            anyhow::Ok(())
        }
        .await;
        if let Err(err) = prepared {
            drop(commit);
            self.resume_vm()
                .await
                .context("servicing rollback failed")?;
            return Err(err).context("destination did not prepare");
        }

        // This request owns the service loop. After sending commit, no error
        // (including lost acknowledgement) may let management resume source.
        commit.send(());
        let ack = ctx.until_cancelled(did_resume).await;
        let pause_to_resume_us = blackout.elapsed().as_micros().try_into()?;
        self.teardown_vm().await?;
        ack??;
        drop(listener);
        mesh.shutdown().await;
        Ok(vmservice::OfferServicingVmResponse { pause_to_resume_us })
    }

    pub(super) async fn accept_servicing(
        &mut self,
        ctx: mesh::CancelContext,
        request: vmservice::AcceptServicingVmRequest,
    ) -> anyhow::Result<()> {
        let mut ctx = ctx.with_timeout(Duration::from_secs(60));
        anyhow::ensure!(self.vm.is_none(), "destination already has a VM");
        let config = request
            .config
            .context("missing destination configuration")?;
        let candidate = profile(&config).context("unsupported servicing configuration")?;
        let (peer, connection) =
            mesh_process::connect::<Request>(self.driver.clone(), Path::new(&request.socket_path))
                .await?;
        let offer = ctx
            .until_cancelled(peer.call_failable(|r| r, candidate))
            .await??;
        self.create_vm_inner(
            config,
            Some(RestoreSource::Servicing(
                offer.resources,
                offer.prepared,
                offer.state,
            )),
        )
        .await?;
        offer.ready.send(());
        // Ready promises to wait for the source's decision. Cancelling the
        // management call now must not destroy the only VM after commit.
        if let Err(err) = offer.commit.await {
            self.teardown_vm().await?;
            return Err(err).context("source did not commit servicing");
        }
        self.resume_vm().await?;
        offer.resumed.send(());
        drop(peer);
        connection.shutdown().await;
        Ok(())
    }
}
