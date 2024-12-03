// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ChannelId;
use crate::ChannelInfo;
use crate::InterceptChannelRequest;
use crate::RelayChannelRequest;
use crate::RelayChannelTask;
use crate::RelayTask;
use anyhow::Result;
use mesh::payload::Protobuf;
use mesh::rpc::RpcSend;
use std::sync::atomic::Ordering;
use vmbus_core::VersionInfo;
use vmcore::save_restore::SavedStateBlob;
use vmcore::save_restore::SavedStateRoot;

impl RelayTask {
    pub async fn handle_save(&self) -> SavedState {
        assert!(!self.running);

        let client_saved_state = self.vmbus_client.save().await;
        let mut channels = futures::future::join_all(
            self.channels
                .iter()
                .map(|(id, channel)| self.save_channel_state(*id, channel)),
        )
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

        // Update the local event flag state for each channel for compatibility
        // with older versions.
        let mut local_event_flags = client_saved_state
            .channels
            .iter()
            .filter_map(|c| {
                Some((
                    c.id,
                    match c.state {
                        vmbus_client::saved_state::ChannelState::Offered => return None,
                        vmbus_client::saved_state::ChannelState::Opened { local_event_flag } => {
                            local_event_flag?
                        }
                    },
                ))
            })
            .collect::<Vec<_>>();

        local_event_flags.sort_by_key(|k| k.0);
        for channel in &mut channels {
            assert!(channel.event_flag.is_none());
            if let Ok(i) =
                local_event_flags.binary_search_by_key(&channel.channel_id, |&(id, _)| id)
            {
                channel.event_flag = Some(local_event_flags[i].1);
            }
        }

        SavedState {
            use_interrupt_relay: self.use_interrupt_relay.load(Ordering::SeqCst),
            relay_state: RelayState::save(&self.relay_state),
            client_saved_state,
            channels,
        }
    }

    pub async fn handle_restore(&mut self, state: SavedState) -> Result<()> {
        let SavedState {
            use_interrupt_relay,
            relay_state,
            mut client_saved_state,
            mut channels,
        } = state;

        // Update the local event flag state for each channel for compatibility
        // with older versions.
        channels.sort_by_key(|k| k.channel_id);
        for channel in &mut client_saved_state.channels {
            if let Ok(i) = channels.binary_search_by_key(&channel.id, |c| c.channel_id) {
                match channel.state {
                    vmbus_client::saved_state::ChannelState::Opened {
                        local_event_flag: Some(flag),
                    } => {
                        if channels[i].event_flag.is_some() && channels[i].event_flag != Some(flag)
                        {
                            anyhow::bail!("local event flag mismatch");
                        }
                        channels[i].event_flag = Some(flag);
                    }
                    vmbus_client::saved_state::ChannelState::Opened {
                        local_event_flag: None,
                    }
                    | vmbus_client::saved_state::ChannelState::Offered => {}
                }
            }
        }

        self.use_interrupt_relay
            .store(use_interrupt_relay, Ordering::SeqCst);
        let (version, offers) = self.vmbus_client.restore(client_saved_state).await?;
        self.relay_state = relay_state.restore(version);
        channels.sort_by_key(|k| k.channel_id);
        for offer in offers {
            let channel = channels
                .binary_search_by_key(&offer.offer.offer.channel_id.0, |k| k.channel_id)
                .ok()
                .and_then(|i| {
                    if offer.open.is_some() || channels[i].intercepted {
                        Some(&channels[i])
                    } else {
                        None
                    }
                });

            self.handle_offer(offer.offer, Some((offer.open, channel)))
                .await?;
        }
        Ok(())
    }

    async fn save_channel_state(
        &self,
        channel_id: ChannelId,
        channel: &ChannelInfo,
    ) -> Option<Channel> {
        match channel {
            ChannelInfo::Relay(relay) => {
                match relay
                    .relay_request_send
                    .call(RelayChannelRequest::Save, ())
                    .await
                {
                    Ok(result) => Some(result),
                    Err(err) => {
                        tracing::error!(
                            err = &err as &dyn std::error::Error,
                            "Failed to save relay channel state"
                        );
                        None
                    }
                }
            }
            ChannelInfo::Intercept(id) => {
                let intercepted_save_state = if let Some(intercepted_channel) =
                    self.intercept_channels.get(id)
                {
                    let result = intercepted_channel
                        .call(InterceptChannelRequest::Save, ())
                        .await;
                    match result {
                        Ok(save_state) => mesh_protobuf::encode(save_state),
                        Err(err) => {
                            tracing::error!(err = &err as &dyn std::error::Error, %id, "Failed to call device to save state");
                            Vec::new()
                        }
                    }
                } else {
                    tracing::error!(%id, "Intercepted device missing during save operation");
                    Vec::new()
                };
                Some(Channel {
                    channel_id: channel_id.0,
                    event_flag: None,
                    intercepted: true,
                    intercepted_save_state,
                })
            }
        }
    }
}

impl RelayChannelTask {
    /// Handle creating channel save state.
    pub(crate) fn handle_save(&self) -> Channel {
        Channel {
            channel_id: self.channel.channel_id.0,
            event_flag: None,
            intercepted: false,
            intercepted_save_state: Vec::new(),
        }
    }
}

#[derive(Clone, Protobuf, SavedStateRoot)]
#[mesh(package = "vmbus.relay")]
pub struct SavedState {
    #[mesh(1)]
    use_interrupt_relay: bool,
    #[mesh(2)]
    relay_state: RelayState,
    #[mesh(3)]
    client_saved_state: vmbus_client::SavedState,
    #[mesh(4)]
    channels: Vec<Channel>,
}

#[derive(Copy, Clone, Eq, PartialEq, Protobuf)]
#[mesh(package = "vmbus.relay")]
enum RelayState {
    #[mesh(1)]
    Disconnected,
    #[mesh(2)]
    Connected,
}

impl RelayState {
    fn save(value: &super::RelayState) -> Self {
        match value {
            super::RelayState::Disconnected => RelayState::Disconnected,
            // The version is not saved, but recovered from the client.
            super::RelayState::Connected(_) => RelayState::Connected,
        }
    }

    fn restore(self, version: Option<VersionInfo>) -> super::RelayState {
        match self {
            RelayState::Connected => {
                super::RelayState::Connected(version.expect("Relay connected but client is not."))
            }
            RelayState::Disconnected => super::RelayState::Disconnected,
        }
    }
}

#[derive(Clone, Protobuf)]
#[mesh(package = "vmbus.relay")]
pub struct Channel {
    #[mesh(1)]
    pub channel_id: u32,
    // Present for compatibility with old versions. This is ignored in this
    // crate but is populated from `vmbus_client` saved state on save and copied
    // over to `vmbus_client` saved state on restore.
    #[mesh(2)]
    pub event_flag: Option<u16>,
    #[mesh(3)]
    pub intercepted: bool,
    #[mesh(4)]
    pub intercepted_save_state: Vec<u8>,
}

impl Channel {
    pub fn try_get_intercept_save_state(&self) -> Option<SavedStateBlob> {
        if self.intercepted_save_state.is_empty() {
            return None;
        }
        match mesh_protobuf::decode(self.intercepted_save_state.as_slice()) {
            Ok(result) => Some(result),
            Err(err) => {
                tracing::error!(
                    err = &err as &dyn std::error::Error,
                    channel_id = self.channel_id,
                    "Failed to decode save state for intercepted device"
                );
                None
            }
        }
    }
}
