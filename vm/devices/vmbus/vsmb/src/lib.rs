// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A vSMB channel exposing the shared SMB engine with transport-owned guest memory.

#![forbid(unsafe_code)]

pub mod resolver;
#[cfg(test)]
mod tests;
mod transfer;
mod transport;

use guestmem::GuestMemory;
use guid::Guid;
use inspect::InspectMut;
use smb::{Server, memory::MemoryFs, provider::FileSystem, runtime::ConnectionTask};
use std::sync::Arc;
use task_control::{Cancelled, StopTask};
use vmbus_async::pipe::BytePipe;
use vmbus_channel::{
    RawAsyncChannel,
    bus::{ChannelType, OfferParams},
    gpadl_ring::GpadlRingMem,
    simple::{SaveRestoreSimpleVmbusDevice, SimpleVmbusDevice},
};
use vmbus_core::protocol::{PipeFlags, PipeUserDefinedData};
use vmcore::vm_task::VmTaskDriver;

const INTERFACE: Guid = guid::guid!("4d12e519-17a0-4ae4-8eaa-5270fc6abdb7");
const INSTANCE: Guid = guid::guid!("dcc079ae-60ba-4d07-847c-3493609c0870");

/// A share using a VM-independent filesystem provider. Serialization is unsupported.
pub struct VsmbDevice<B: FileSystem = MemoryFs> {
    server: Arc<Server<B>>,
    driver: VmTaskDriver,
    // Device ownership survives the simple wrapper dropping its runner on close.
    channel: Option<ConnectionTask<B, transport::Transport<BytePipe<GpadlRingMem>>>>,
    guest_data: Option<Arc<transfer::GuestData>>,
}

impl VsmbDevice {
    /// Configure a bounded synthetic share on the VM executor.
    pub fn new(share_name: String, driver: VmTaskDriver) -> Result<Self, smb::spec::Status> {
        let fs = MemoryFs::new(16 * 1024 * 1024, 4096)
            .with_oplocks()?
            .with_short_name_generation();
        Self::with_filesystem(share_name, driver, fs)
    }
}

impl<B: FileSystem> VsmbDevice<B> {
    /// Configure one share backed by the supplied provider.
    pub fn with_filesystem(
        share_name: String,
        driver: VmTaskDriver,
        filesystem: B,
    ) -> Result<Self, smb::spec::Status> {
        Ok(Self {
            server: Server::new(share_name, filesystem)?,
            driver,
            channel: None,
            guest_data: None,
        })
    }
}

#[async_trait::async_trait]
impl<B: FileSystem> SimpleVmbusDevice for VsmbDevice<B> {
    type SavedState = vmcore::save_restore::NoSavedState;
    type Runner = ();

    fn offer(&self) -> OfferParams {
        OfferParams {
            interface_name: "vsmb".into(),
            interface_id: INTERFACE,
            instance_id: INSTANCE,
            channel_type: ChannelType::Pipe {
                message_mode: false,
                user_defined: PipeUserDefinedData::from([0; 112]),
                pipe_flags: PipeFlags::new().with_gpa_direct(true),
            },
            ..Default::default()
        }
    }

    fn inspect(&mut self, req: inspect::Request<'_>, _: Option<&mut ()>) {
        let mut response = req.respond();
        response.field("server", &self.server);
        if let Some(channel) = &self.channel {
            response
                .field("channel", channel)
                .field("transport", channel.transport());
        }
        if let Some(data) = &self.guest_data {
            response.field("external_data", data);
        }
    }

    fn open(
        &mut self,
        channel: RawAsyncChannel<GpadlRingMem>,
        memory: GuestMemory,
    ) -> Result<(), vmbus_channel::channel::ChannelOpenError> {
        if self.channel.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "previous vSMB channel has not completed cleanup",
            )
            .into());
        }
        let stream = transport::Transport::new(BytePipe::new(channel)?);
        let data = Arc::new(transfer::GuestData::new(
            memory,
            stream.negotiated_capabilities(),
        ));
        let connection = self.server.connect_with_external_data(data.clone());
        self.channel = Some(ConnectionTask::new_with_driver(
            connection,
            stream,
            self.driver.clone(),
        ));
        self.guest_data = Some(data);
        Ok(())
    }

    async fn run(&mut self, stop: &mut StopTask<'_>, _: &mut ()) -> Result<(), Cancelled> {
        let result = if let Some(channel) = &mut self.channel {
            stop.until_stopped(channel.process()).await?
        } else {
            return Ok(());
        };
        if let Err(error) = result {
            tracelimit::warn_ratelimited!(?error, "vSMB channel failed");
        }
        Ok(())
    }

    async fn close(&mut self) {
        if let Some(channel) = &mut self.channel {
            if let Err(error) = channel.shutdown().await {
                tracelimit::warn_ratelimited!(?error, "vSMB shutdown reported an error");
                if !channel.cleanup_succeeded() {
                    return;
                }
            }
        }
        self.channel = None;
        self.guest_data = None;
    }

    fn supports_save_restore(
        &mut self,
    ) -> Option<&mut dyn SaveRestoreSimpleVmbusDevice<SavedState = Self::SavedState, Runner = ()>>
    {
        None
    }
}

impl<B: FileSystem> InspectMut for VsmbDevice<B> {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        SimpleVmbusDevice::inspect(self, req, None);
    }
}
