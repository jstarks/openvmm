// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! vhost-user frontend: a [`VirtioDevice`] implementation that forwards
//! device operations to an external vhost-user backend over a Unix socket.
//!
//! This is the counterpart to the `VhostUserDeviceServer` in the
//! `vhost_user_device` crate: the server hosts a device, while this
//! frontend connects to that server and presents it to the VMM as a
//! standard virtio device.

#![cfg(unix)]
#![expect(missing_docs)]

use anyhow::Context as _;
use guestmem::GuestMemory;
use inspect::InspectMut;
use pal_async::driver::SpawnDriver;
use pal_async::socket::PolledSocket;
use pal_event::Event;
use std::os::fd::AsFd;
use std::os::fd::OwnedFd;
use unix_socket::UnixStream;
use vhost_user_protocol::*;
use virtio::DeviceTraits;
use virtio::DeviceTraitsSharedMemory;
use virtio::QueueResources;
use virtio::VirtioDevice;
use virtio::queue::QueueState;
use virtio::spec::VirtioDeviceFeatures;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

/// A memory region exported for vhost-user `SET_MEM_TABLE`.
pub struct ExportedMemoryRegion {
    pub guest_phys_addr: u64,
    pub size: u64,
    pub fd: OwnedFd,
    pub mmap_offset: u64,
}

/// Per-queue tracking state.
struct FrontendQueueState {
    active: bool,
    /// Saved queue params for reading used ring index during stop.
    params: Option<virtio::queue::QueueParams>,
}

/// A `VirtioDevice` that proxies to a vhost-user backend.
#[derive(InspectMut)]
#[inspect(skip)]
pub struct VhostUserFrontend {
    device_traits: DeviceTraits,
    protocol_features: VhostUserProtocolFeatures,
    socket: VhostUserSocket,
    #[expect(dead_code)]
    negotiated_features: VirtioDeviceFeatures,
    config_cache: Vec<u8>,
    queues: Vec<FrontendQueueState>,
    guest_memory: GuestMemory,
}

impl VhostUserFrontend {
    /// Connect to a vhost-user backend, negotiate features, and send
    /// the memory table.
    ///
    /// `device_id` is the virtio device ID (e.g., 2 for block) —
    /// vhost-user has no GET_DEVICE_ID message so this must come from
    /// the resource configuration.
    pub async fn new(
        driver: &(impl SpawnDriver + ?Sized),
        socket_path: &std::path::Path,
        device_id: u16,
        guest_memory: &GuestMemory,
        exported_regions: Vec<ExportedMemoryRegion>,
    ) -> anyhow::Result<Self> {
        let stream = UnixStream::connect(socket_path)
            .with_context(|| format!("failed to connect to {}", socket_path.display()))?;
        let polled = PolledSocket::new(driver, stream)?;
        let socket = VhostUserSocket::new(polled);

        Self::from_socket(socket, device_id, guest_memory, exported_regions).await
    }

    /// Create from an already-connected socket (useful for testing with
    /// socketpairs).
    pub async fn from_socket(
        socket: VhostUserSocket,
        device_id: u16,
        guest_memory: &GuestMemory,
        exported_regions: Vec<ExportedMemoryRegion>,
    ) -> anyhow::Result<Self> {
        // 1. GET_FEATURES
        let device_features_raw = send_get_u64(&socket, VhostUserRequestCode::GET_FEATURES).await?;

        // 2. SET_FEATURES — include PROTOCOL_FEATURES bit
        send_set_u64(
            &socket,
            VhostUserRequestCode::SET_FEATURES,
            device_features_raw | VHOST_USER_F_PROTOCOL_FEATURES,
        )
        .await?;

        // 3. GET_PROTOCOL_FEATURES → SET_PROTOCOL_FEATURES
        let proto_features_raw =
            send_get_u64(&socket, VhostUserRequestCode::GET_PROTOCOL_FEATURES).await?;
        let wanted = VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::REPLY_ACK
            | VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::RESET_DEVICE;
        let negotiated_proto = VhostUserProtocolFeatures::from_bits(proto_features_raw & wanted);
        send_set_u64(
            &socket,
            VhostUserRequestCode::SET_PROTOCOL_FEATURES,
            negotiated_proto.bits(),
        )
        .await?;

        // 4. SET_OWNER
        send_simple(&socket, VhostUserRequestCode::SET_OWNER).await?;

        // 5. GET_QUEUE_NUM
        let max_queues = send_get_u64(&socket, VhostUserRequestCode::GET_QUEUE_NUM)
            .await
            .unwrap_or(1) as u16;

        // 6. SET_MEM_TABLE
        send_set_mem_table(&socket, &exported_regions).await?;

        // 7. GET_CONFIG (cache)
        let config_cache = if negotiated_proto.contains(VhostUserProtocolFeatures::CONFIG) {
            send_get_config(&socket, 0, 256).await.unwrap_or_default()
        } else {
            Vec::new()
        };

        // Build DeviceTraits from the wire features.
        let device_features =
            features_from_u64(device_features_raw & !(VHOST_USER_F_PROTOCOL_FEATURES));

        let device_traits = DeviceTraits {
            device_id,
            device_features,
            max_queues,
            device_register_length: config_cache.len() as u32,
            shared_memory: DeviceTraitsSharedMemory::default(),
        };

        let queues = (0..max_queues)
            .map(|_| FrontendQueueState {
                active: false,
                params: None,
            })
            .collect();

        Ok(Self {
            device_traits,
            protocol_features: negotiated_proto,
            socket,
            negotiated_features: features_from_u64(device_features_raw),
            config_cache,
            queues,
            guest_memory: guest_memory.clone(),
        })
    }
}

impl VirtioDevice for VhostUserFrontend {
    fn traits(&self) -> DeviceTraits {
        self.device_traits.clone()
    }

    async fn read_registers_u32(&mut self, offset: u16) -> u32 {
        let off = offset as usize;
        if off + 4 <= self.config_cache.len() {
            u32::from_le_bytes(self.config_cache[off..off + 4].try_into().unwrap())
        } else {
            0
        }
    }

    async fn write_registers_u32(&mut self, offset: u16, val: u32) {
        let _ = send_set_config(&self.socket, offset, &val.to_le_bytes()).await;
        let off = offset as usize;
        if off + 4 <= self.config_cache.len() {
            self.config_cache[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }
    }

    async fn start_queue(
        &mut self,
        idx: u16,
        resources: QueueResources,
        _features: &VirtioDeviceFeatures,
        initial_state: Option<QueueState>,
    ) -> anyhow::Result<()> {
        let base = initial_state.map(|s| s.avail_index).unwrap_or(0);

        // SET_VRING_NUM
        send_vring_state(
            &self.socket,
            VhostUserRequestCode::SET_VRING_NUM,
            idx,
            resources.params.size as u32,
        )
        .await?;

        // SET_VRING_ADDR
        send_vring_addr(
            &self.socket,
            idx,
            resources.params.desc_addr,
            resources.params.used_addr,
            resources.params.avail_addr,
        )
        .await?;

        // SET_VRING_BASE
        send_vring_state(
            &self.socket,
            VhostUserRequestCode::SET_VRING_BASE,
            idx,
            base as u32,
        )
        .await?;

        // SET_VRING_KICK — pass the kick eventfd to the backend
        send_vring_fd(
            &self.socket,
            VhostUserRequestCode::SET_VRING_KICK,
            idx,
            Some(&resources.event),
        )
        .await?;

        // SET_VRING_CALL — pass the interrupt eventfd to the backend
        if let Some(event) = resources.notify.event() {
            send_vring_fd(
                &self.socket,
                VhostUserRequestCode::SET_VRING_CALL,
                idx,
                Some(event),
            )
            .await?;
        } else {
            send_vring_fd(
                &self.socket,
                VhostUserRequestCode::SET_VRING_CALL,
                idx,
                None::<&Event>,
            )
            .await?;
        }

        // SET_VRING_ENABLE
        send_vring_state(&self.socket, VhostUserRequestCode::SET_VRING_ENABLE, idx, 1).await?;

        if let Some(q) = self.queues.get_mut(idx as usize) {
            q.active = true;
            q.params = Some(resources.params);
        }
        Ok(())
    }

    async fn stop_queue(&mut self, idx: u16) -> Option<QueueState> {
        let q = self.queues.get_mut(idx as usize)?;
        if !q.active {
            return None;
        }

        // GET_VRING_BASE implicitly stops the queue on the backend.
        let avail_index = send_get_vring_base(&self.socket, idx).await.ok()?;

        // Read used_index from the guest-visible used ring.
        let used_index = q
            .params
            .as_ref()
            .map(|params| read_used_index(&self.guest_memory, params))
            .unwrap_or(0);

        q.active = false;
        q.params = None;
        Some(QueueState {
            avail_index,
            used_index,
        })
    }

    async fn reset(&mut self) {
        // Stop all active queues.
        for idx in 0..self.queues.len() {
            if self.queues[idx].active {
                let _ = send_get_vring_base(&self.socket, idx as u16).await;
                self.queues[idx].active = false;
                self.queues[idx].params = None;
            }
        }
        // Send RESET_DEVICE if negotiated.
        if self
            .protocol_features
            .contains(VhostUserProtocolFeatures::RESET_DEVICE)
        {
            let _ = send_simple(&self.socket, VhostUserRequestCode::RESET_DEVICE).await;
        }
    }

    fn supports_save_restore(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Protocol helper functions
// ---------------------------------------------------------------------------

/// Send a request with no payload and receive a u64 reply.
async fn send_get_u64(socket: &VhostUserSocket, code: VhostUserRequestCode) -> anyhow::Result<u64> {
    let hdr = VhostUserMsgHeader {
        request: code.0,
        flags: VHOST_USER_FLAG_VERSION,
        size: 0,
    };
    socket.send_reply(&hdr, &[], &[] as &[OwnedFd]).await?;
    let (_reply_hdr, payload, _fds) = socket.recv_message().await?;
    let msg = VhostUserU64Msg::read_from_prefix(&payload)
        .map(|(val, _)| val)
        .map_err(|_| anyhow::anyhow!("reply payload too small for u64"))?;
    Ok(msg.value)
}

/// Send a SET request with a u64 payload.
async fn send_set_u64(
    socket: &VhostUserSocket,
    code: VhostUserRequestCode,
    value: u64,
) -> anyhow::Result<()> {
    let hdr = VhostUserMsgHeader {
        request: code.0,
        flags: VHOST_USER_FLAG_VERSION,
        size: size_of::<VhostUserU64Msg>() as u32,
    };
    let payload = VhostUserU64Msg { value };
    socket
        .send_reply(&hdr, payload.as_bytes(), &[] as &[OwnedFd])
        .await?;
    Ok(())
}

/// Send a request with no payload (e.g., SET_OWNER, RESET_DEVICE).
async fn send_simple(socket: &VhostUserSocket, code: VhostUserRequestCode) -> anyhow::Result<()> {
    let hdr = VhostUserMsgHeader {
        request: code.0,
        flags: VHOST_USER_FLAG_VERSION,
        size: 0,
    };
    socket.send_reply(&hdr, &[], &[] as &[OwnedFd]).await?;
    Ok(())
}

/// Send SET_MEM_TABLE with exported memory regions.
async fn send_set_mem_table(
    socket: &VhostUserSocket,
    regions: &[ExportedMemoryRegion],
) -> anyhow::Result<()> {
    // Payload: { nregions: u32, padding: u32, regions: [VhostUserMemoryRegion] }
    let nregions = regions.len() as u32;
    let mut payload = Vec::new();
    payload.extend_from_slice(&nregions.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes()); // padding

    let mut fds = Vec::new();
    for region in regions {
        let wire_region = VhostUserMemoryRegion {
            guest_phys_addr: region.guest_phys_addr,
            memory_size: region.size,
            userspace_addr: region.guest_phys_addr, // frontend uses GPA as VA placeholder
            mmap_offset: region.mmap_offset,
        };
        payload.extend_from_slice(wire_region.as_bytes());
        fds.push(&region.fd);
    }

    let hdr = VhostUserMsgHeader {
        request: VhostUserRequestCode::SET_MEM_TABLE.0,
        flags: VHOST_USER_FLAG_VERSION,
        size: payload.len() as u32,
    };
    socket.send_reply(&hdr, &payload, &fds).await?;
    Ok(())
}

/// Send a VringState message (SET_VRING_NUM, SET_VRING_BASE, SET_VRING_ENABLE).
async fn send_vring_state(
    socket: &VhostUserSocket,
    code: VhostUserRequestCode,
    index: u16,
    num: u32,
) -> anyhow::Result<()> {
    let hdr = VhostUserMsgHeader {
        request: code.0,
        flags: VHOST_USER_FLAG_VERSION,
        size: size_of::<VhostUserVringState>() as u32,
    };
    let payload = VhostUserVringState {
        index: index as u32,
        num,
    };
    socket
        .send_reply(&hdr, payload.as_bytes(), &[] as &[OwnedFd])
        .await?;
    Ok(())
}

/// Send SET_VRING_ADDR.
async fn send_vring_addr(
    socket: &VhostUserSocket,
    index: u16,
    desc_addr: u64,
    used_addr: u64,
    avail_addr: u64,
) -> anyhow::Result<()> {
    let hdr = VhostUserMsgHeader {
        request: VhostUserRequestCode::SET_VRING_ADDR.0,
        flags: VHOST_USER_FLAG_VERSION,
        size: size_of::<VhostUserVringAddr>() as u32,
    };
    let payload = VhostUserVringAddr {
        index: index as u32,
        flags: 0,
        desc_user_addr: desc_addr,
        used_user_addr: used_addr,
        avail_user_addr: avail_addr,
        log_guest_addr: 0,
    };
    socket
        .send_reply(&hdr, payload.as_bytes(), &[] as &[OwnedFd])
        .await?;
    Ok(())
}

/// Send SET_VRING_KICK or SET_VRING_CALL with an optional fd.
async fn send_vring_fd(
    socket: &VhostUserSocket,
    code: VhostUserRequestCode,
    index: u16,
    event: Option<&(impl AsFd + ?Sized)>,
) -> anyhow::Result<()> {
    let nofd = event.is_none();
    let value = (index as u64 & VHOST_USER_VRING_INDEX_MASK)
        | if nofd { VHOST_USER_VRING_NOFD_MASK } else { 0 };

    let hdr = VhostUserMsgHeader {
        request: code.0,
        flags: VHOST_USER_FLAG_VERSION,
        size: size_of::<VhostUserU64Msg>() as u32,
    };
    let payload = VhostUserU64Msg { value };

    if let Some(event) = event {
        socket
            .send_reply(&hdr, payload.as_bytes(), &[event.as_fd()])
            .await?;
    } else {
        socket
            .send_reply(&hdr, payload.as_bytes(), &[] as &[OwnedFd])
            .await?;
    }
    Ok(())
}

/// Send GET_VRING_BASE — this implicitly stops the queue on the backend
/// and returns the avail index.
async fn send_get_vring_base(socket: &VhostUserSocket, index: u16) -> anyhow::Result<u16> {
    let hdr = VhostUserMsgHeader {
        request: VhostUserRequestCode::GET_VRING_BASE.0,
        flags: VHOST_USER_FLAG_VERSION,
        size: size_of::<VhostUserVringState>() as u32,
    };
    let payload = VhostUserVringState {
        index: index as u32,
        num: 0,
    };
    socket
        .send_reply(&hdr, payload.as_bytes(), &[] as &[OwnedFd])
        .await?;
    let (_reply_hdr, reply_payload, _fds) = socket.recv_message().await?;
    let reply = VhostUserVringState::read_from_prefix(&reply_payload)
        .map(|(val, _)| val)
        .map_err(|_| anyhow::anyhow!("GET_VRING_BASE reply too small"))?;
    Ok(reply.num as u16)
}

/// Send GET_CONFIG and return the config bytes.
async fn send_get_config(
    socket: &VhostUserSocket,
    offset: u32,
    size: u32,
) -> anyhow::Result<Vec<u8>> {
    let config_hdr = VhostUserConfigHeader {
        offset,
        size,
        flags: 0,
    };
    let hdr = VhostUserMsgHeader {
        request: VhostUserRequestCode::GET_CONFIG.0,
        flags: VHOST_USER_FLAG_VERSION,
        size: size_of::<VhostUserConfigHeader>() as u32,
    };
    socket
        .send_reply(&hdr, config_hdr.as_bytes(), &[] as &[OwnedFd])
        .await?;
    let (_reply_hdr, reply_payload, _fds) = socket.recv_message().await?;
    // Reply: config header + config data.
    let hdr_size = size_of::<VhostUserConfigHeader>();
    if reply_payload.len() > hdr_size {
        Ok(reply_payload[hdr_size..].to_vec())
    } else {
        Ok(Vec::new())
    }
}

/// Send SET_CONFIG.
async fn send_set_config(socket: &VhostUserSocket, offset: u16, data: &[u8]) -> anyhow::Result<()> {
    let config_hdr = VhostUserConfigHeader {
        offset: offset as u32,
        size: data.len() as u32,
        flags: 0,
    };
    let mut payload = Vec::with_capacity(size_of::<VhostUserConfigHeader>() + data.len());
    payload.extend_from_slice(config_hdr.as_bytes());
    payload.extend_from_slice(data);

    let hdr = VhostUserMsgHeader {
        request: VhostUserRequestCode::SET_CONFIG.0,
        flags: VHOST_USER_FLAG_VERSION,
        size: payload.len() as u32,
    };
    socket.send_reply(&hdr, &payload, &[] as &[OwnedFd]).await?;
    Ok(())
}

/// Convert a u64 to VirtioDeviceFeatures.
fn features_from_u64(value: u64) -> VirtioDeviceFeatures {
    VirtioDeviceFeatures::new()
        .with_bank(0, value as u32)
        .with_bank(1, (value >> 32) as u32)
}

/// Read the used_index from the used ring in guest memory.
///
/// The used ring starts at `params.used_addr`. The `idx` field is at
/// offset 2 (after the flags field) and is a 16-bit LE value.
fn read_used_index(mem: &GuestMemory, params: &virtio::queue::QueueParams) -> u16 {
    let mut buf = [0u8; 2];
    // used ring layout: { flags: u16, idx: u16, ... }
    if mem.read_at(params.used_addr + 2, &mut buf).is_ok() {
        u16::from_le_bytes(buf)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use pal_async::socket::PolledSocket;
    use pal_async::task::Spawn;
    use test_with_tracing::test;
    use vhost_user_device::VhostUserDeviceServer;
    use virtio::DeviceTraits;
    use virtio::DeviceTraitsSharedMemory;
    use virtio::QueueResources;
    use virtio::VirtioDevice;

    use virtio::queue::QueueState;
    use virtio::spec::VirtioDeviceFeatures;

    /// A mock VirtioDevice for the backend side of the dog-food test.
    struct MockBackendDevice {
        traits: DeviceTraits,
        started_queues: Vec<u16>,
    }

    impl MockBackendDevice {
        fn new() -> Self {
            Self {
                traits: DeviceTraits {
                    device_id: 2,
                    device_features: VirtioDeviceFeatures::new(),
                    max_queues: 2,
                    device_register_length: 0,
                    shared_memory: DeviceTraitsSharedMemory::default(),
                },
                started_queues: Vec::new(),
            }
        }
    }

    impl InspectMut for MockBackendDevice {
        fn inspect_mut(&mut self, _req: inspect::Request<'_>) {}
    }

    impl VirtioDevice for MockBackendDevice {
        fn traits(&self) -> DeviceTraits {
            self.traits.clone()
        }

        async fn read_registers_u32(&mut self, _offset: u16) -> u32 {
            0
        }

        async fn write_registers_u32(&mut self, _offset: u16, _val: u32) {}

        async fn start_queue(
            &mut self,
            idx: u16,
            _resources: QueueResources,
            _features: &VirtioDeviceFeatures,
            _initial_state: Option<QueueState>,
        ) -> anyhow::Result<()> {
            self.started_queues.push(idx);
            Ok(())
        }

        async fn stop_queue(&mut self, idx: u16) -> Option<QueueState> {
            if self.started_queues.contains(&idx) {
                self.started_queues.retain(|&x| x != idx);
                Some(QueueState {
                    avail_index: 42,
                    used_index: 0,
                })
            } else {
                None
            }
        }

        async fn reset(&mut self) {
            self.started_queues.clear();
        }
    }

    fn socket_pair() -> (UnixStream, UnixStream) {
        let (a, b) = socket2::Socket::pair(socket2::Domain::UNIX, socket2::Type::STREAM, None)
            .expect("socketpair failed");
        (a.into(), b.into())
    }

    #[async_test]
    async fn frontend_backend_dogfood(driver: DefaultDriver) {
        let (frontend_stream, backend_stream) = socket_pair();

        let backend_polled = PolledSocket::new(&driver, backend_stream).unwrap();
        let backend_socket = VhostUserSocket::new(backend_polled);

        let server = VhostUserDeviceServer::new(|_mem| Box::new(MockBackendDevice::new()));

        let backend_task = driver.spawn("backend", async move {
            server.serve_connection(backend_socket).await.unwrap();
        });

        // Connect the frontend.
        let frontend_polled = PolledSocket::new(&driver, frontend_stream).unwrap();
        let frontend_socket = VhostUserSocket::new(frontend_polled);

        let guest_memory = GuestMemory::empty();

        let mut frontend =
            VhostUserFrontend::from_socket(frontend_socket, 2, &guest_memory, vec![])
                .await
                .expect("frontend handshake failed");

        // Verify traits.
        let traits = frontend.traits();
        assert_eq!(traits.device_id, 2);
        assert_eq!(traits.max_queues, 2);

        // Reset.
        frontend.reset().await;

        assert!(frontend.supports_save_restore());

        // Drop the frontend to close the socket so the backend task finishes.
        drop(frontend);
        backend_task.await;
    }
}
