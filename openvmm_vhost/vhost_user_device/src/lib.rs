// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! vhost-user backend device server.
//!
//! Implements the vhost-user backend protocol, driving a [`VirtioDevice`]
//! implementation. The server listens on a Unix domain socket, accepts one
//! connection at a time, and translates vhost-user protocol messages into
//! `VirtioDevice` trait calls.

#![cfg(unix)]
#![expect(missing_docs)]

pub mod memory;
pub mod queue_setup;

/// Re-export protocol types from the shared crate.
pub use vhost_user_protocol::protocol;
/// Re-export socket types from the shared crate.
pub use vhost_user_protocol::socket;

use crate::memory::VhostUserMemoryRegions;
use crate::memory::guest_memory_from_regions;
use crate::protocol::*;
use crate::queue_setup::QueueSetup;
use crate::socket::SocketError;
use crate::socket::VhostUserSocket;
use guestmem::GuestMemory;
use pal_async::driver::SpawnDriver;
use pal_async::socket::PolledSocket;
use pal_event::Event;
use std::os::fd::OwnedFd;
use std::path::Path;
use unix_socket::UnixListener;
use virtio::DeviceTraits;
use virtio::DynVirtioDevice;
use virtio::queue::QueueState;
use virtio::spec::VirtioDeviceFeatures;
use vmcore::interrupt::Interrupt;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

/// vhost-user backend device server.
///
/// Owns a `VirtioDevice` and serves the vhost-user protocol over a Unix
/// domain socket.
pub struct VhostUserDeviceServer {
    device: Box<dyn DynVirtioDevice>,
    /// Shared memory regions, also referenced by the GuestMemory given to
    /// the device.
    mem_regions: VhostUserMemoryRegions,
}

impl VhostUserDeviceServer {
    /// Create a new server wrapping the given device.
    ///
    /// The `device_factory` closure receives a `GuestMemory` that will be
    /// dynamically updated as the frontend sends `SET_MEM_TABLE`. The device
    /// should store this `GuestMemory` for use in its workers.
    pub fn new(device_factory: impl FnOnce(GuestMemory) -> Box<dyn DynVirtioDevice>) -> Self {
        let mem_regions = VhostUserMemoryRegions::new();
        let guest_memory = guest_memory_from_regions(&mem_regions);
        let device = device_factory(guest_memory);

        Self {
            device,
            mem_regions,
        }
    }

    /// Listen on `path` and serve one connection at a time.
    ///
    /// After a client disconnects, the server resets the device and waits
    /// for a new connection. This method runs indefinitely.
    pub async fn run(
        mut self,
        driver: &(impl SpawnDriver + ?Sized),
        path: &Path,
    ) -> anyhow::Result<()> {
        // Remove stale socket file if it exists.
        let _ = std::fs::remove_file(path);

        let std_listener = UnixListener::bind(path)?;
        let mut listener = PolledSocket::new(driver, std_listener)?;

        tracing::info!(path = %path.display(), "vhost-user server listening");

        loop {
            let (stream, _addr) = listener.accept().await?;
            let polled = PolledSocket::new(driver, stream)?;
            let socket = VhostUserSocket::new(polled);

            tracing::info!("vhost-user client connected");

            match self.handle_connection(&socket).await {
                Ok(()) => {
                    tracing::info!("vhost-user client disconnected");
                }
                Err(e) => {
                    tracing::warn!(
                        error = &*e as &dyn std::error::Error,
                        "vhost-user connection error"
                    );
                }
            }

            // Reset device state for the next connection.
            self.stop_all_queues().await;
            self.device.reset().await;
        }
    }

    /// Serve a single connection (used for testing with socketpairs).
    pub async fn serve_connection(mut self, socket: VhostUserSocket) -> anyhow::Result<()> {
        let result = self.handle_connection(&socket).await;
        self.stop_all_queues().await;
        self.device.reset().await;
        result
    }

    /// Handle a single client connection's message loop.
    async fn handle_connection(&mut self, socket: &VhostUserSocket) -> anyhow::Result<()> {
        let traits = self.device.traits();
        let mut state = ConnectionState::new(&traits);

        loop {
            let (hdr, payload, fds) = match socket.recv_message().await {
                Ok(msg) => msg,
                Err(SocketError::Closed) => return Ok(()),
                Err(e) => return Err(e.into()),
            };

            if !hdr.version_valid() {
                tracelimit::warn_ratelimited!("invalid vhost-user version flag");
                continue;
            }

            if let Err(e) = self
                .dispatch_message(socket, &mut state, &traits, &hdr, &payload, fds)
                .await
            {
                tracelimit::warn_ratelimited!(
                    error = &*e as &dyn std::error::Error,
                    request = ?hdr.code(),
                    "error handling vhost-user message"
                );
            }
        }
    }

    /// Dispatch a single protocol message.
    async fn dispatch_message(
        &mut self,
        socket: &VhostUserSocket,
        state: &mut ConnectionState,
        traits: &DeviceTraits,
        hdr: &VhostUserMsgHeader,
        payload: &[u8],
        fds: Vec<OwnedFd>,
    ) -> anyhow::Result<()> {
        let code = hdr.code();

        match code {
            VhostUserRequestCode::GET_FEATURES => {
                let mut features = features_to_u64(&traits.device_features);
                features |= VHOST_USER_F_PROTOCOL_FEATURES;
                let reply_payload = VhostUserU64Msg { value: features };
                send_reply(socket, hdr, reply_payload.as_bytes(), &[]).await?;
            }

            VhostUserRequestCode::SET_FEATURES => {
                let msg = parse_payload::<VhostUserU64Msg>(payload)?;
                // The frontend sends SET_FEATURES multiple times: once
                // during init (may include VHOST_USER_F_PROTOCOL_FEATURES)
                // and again with guest-negotiated features (which won't
                // include bit 30 since it's a vhost-user transport bit,
                // not a real virtio feature). Both are normal.
                state.negotiated_features = features_from_u64(msg.value);
                maybe_ack(socket, hdr, state).await?;
            }

            VhostUserRequestCode::GET_PROTOCOL_FEATURES => {
                let mut pf = VhostUserProtocolFeatures::default();
                pf.insert(VhostUserProtocolFeatures::MQ);
                pf.insert(VhostUserProtocolFeatures::REPLY_ACK);
                pf.insert(VhostUserProtocolFeatures::CONFIG);
                pf.insert(VhostUserProtocolFeatures::RESET_DEVICE);
                let reply_payload = VhostUserU64Msg { value: pf.bits() };
                send_reply(socket, hdr, reply_payload.as_bytes(), &[]).await?;
            }

            VhostUserRequestCode::SET_PROTOCOL_FEATURES => {
                let msg = parse_payload::<VhostUserU64Msg>(payload)?;
                state.protocol_features = VhostUserProtocolFeatures::from_bits(msg.value);
                maybe_ack(socket, hdr, state).await?;
            }

            VhostUserRequestCode::GET_QUEUE_NUM => {
                let reply_payload = VhostUserU64Msg {
                    value: traits.max_queues as u64,
                };
                send_reply(socket, hdr, reply_payload.as_bytes(), &[]).await?;
            }

            VhostUserRequestCode::SET_OWNER => {
                // No-op for single-user backend.
                maybe_ack(socket, hdr, state).await?;
            }

            VhostUserRequestCode::SET_MEM_TABLE => {
                self.handle_set_mem_table(state, payload, fds).await?;
                maybe_ack(socket, hdr, state).await?;
            }

            VhostUserRequestCode::GET_CONFIG => {
                let config_hdr = parse_payload::<VhostUserConfigHeader>(payload)?;
                let mut config_data = vec![0u8; config_hdr.size as usize];
                // Read device config registers 4 bytes at a time.
                let offset = config_hdr.offset;
                let size = config_hdr.size;
                let mut pos = 0u32;
                while pos < size {
                    let reg_offset = offset + pos;
                    let val = self.device.read_registers_u32(reg_offset as u16).await;
                    let remaining = (size - pos) as usize;
                    let bytes = val.to_le_bytes();
                    let copy_len = remaining.min(4);
                    config_data[pos as usize..pos as usize + copy_len]
                        .copy_from_slice(&bytes[..copy_len]);
                    pos += 4;
                }
                // Reply: config header + config data.
                let mut reply_body =
                    Vec::with_capacity(size_of::<VhostUserConfigHeader>() + config_data.len());
                reply_body.extend_from_slice(config_hdr.as_bytes());
                reply_body.extend_from_slice(&config_data);
                send_reply(socket, hdr, &reply_body, &[]).await?;
            }

            VhostUserRequestCode::SET_CONFIG => {
                let config_hdr = parse_payload::<VhostUserConfigHeader>(payload)?;
                let config_hdr_size = size_of::<VhostUserConfigHeader>();
                let config_data = payload.get(config_hdr_size..).unwrap_or(&[]);
                // Write device config registers 4 bytes at a time.
                let mut pos = 0u32;
                while pos < config_hdr.size {
                    let remaining = (config_hdr.size - pos) as usize;
                    let copy_len = remaining.min(4);
                    let mut bytes = [0u8; 4];
                    let data_start = pos as usize;
                    let data_end = data_start + copy_len;
                    if data_end <= config_data.len() {
                        bytes[..copy_len].copy_from_slice(&config_data[data_start..data_end]);
                    }
                    let val = u32::from_le_bytes(bytes);
                    self.device
                        .write_registers_u32((config_hdr.offset + pos) as u16, val)
                        .await;
                    pos += 4;
                }
                maybe_ack(socket, hdr, state).await?;
            }

            VhostUserRequestCode::SET_VRING_NUM => {
                let msg = parse_payload::<VhostUserVringState>(payload)?;
                let idx = msg.index as usize;
                if let Some(q) = state.queues.get_mut(idx) {
                    q.set_num(msg.num as u16);
                } else {
                    tracelimit::warn_ratelimited!(idx, "SET_VRING_NUM: invalid queue index");
                }
                maybe_ack(socket, hdr, state).await?;
            }

            VhostUserRequestCode::SET_VRING_ADDR => {
                let msg = parse_payload::<VhostUserVringAddr>(payload)?;
                let idx = msg.index as usize;
                if let Some(q) = state.queues.get_mut(idx) {
                    // Translate userspace VAs to GPAs.
                    let desc_gpa = self
                        .mem_regions
                        .va_to_gpa(msg.desc_user_addr)
                        .unwrap_or(msg.desc_user_addr);
                    let avail_gpa = self
                        .mem_regions
                        .va_to_gpa(msg.avail_user_addr)
                        .unwrap_or(msg.avail_user_addr);
                    let used_gpa = self
                        .mem_regions
                        .va_to_gpa(msg.used_user_addr)
                        .unwrap_or(msg.used_user_addr);
                    q.set_addr(desc_gpa, avail_gpa, used_gpa);
                } else {
                    tracelimit::warn_ratelimited!(idx, "SET_VRING_ADDR: invalid queue index");
                }
                maybe_ack(socket, hdr, state).await?;
            }

            VhostUserRequestCode::SET_VRING_BASE => {
                let msg = parse_payload::<VhostUserVringState>(payload)?;
                let idx = msg.index as usize;
                if let Some(q) = state.queues.get_mut(idx) {
                    q.set_base(msg.num as u16);
                } else {
                    tracelimit::warn_ratelimited!(idx, "SET_VRING_BASE: invalid queue index");
                }
                maybe_ack(socket, hdr, state).await?;
            }

            VhostUserRequestCode::GET_VRING_BASE => {
                let msg = parse_payload::<VhostUserVringState>(payload)?;
                let idx = msg.index as usize;
                // Stop the queue and get its state.
                let avail_index = if let Some(q) = state.queues.get_mut(idx) {
                    if q.is_active() {
                        let queue_state = stop_queue(&mut *self.device, idx as u16).await;
                        q.set_inactive();
                        queue_state.map(|s| s.avail_index).unwrap_or(0)
                    } else {
                        0
                    }
                } else {
                    0
                };
                let reply_payload = VhostUserVringState {
                    index: msg.index,
                    num: avail_index as u32,
                };
                send_reply(socket, hdr, reply_payload.as_bytes(), &[]).await?;
            }

            VhostUserRequestCode::SET_VRING_KICK => {
                let msg = parse_payload::<VhostUserU64Msg>(payload)?;
                let idx = (msg.value & VHOST_USER_VRING_INDEX_MASK) as usize;
                let nofd = msg.value & VHOST_USER_VRING_NOFD_MASK != 0;
                if !nofd
                    && let Some(fd) = fds.into_iter().next()
                    && let Some(q) = state.queues.get_mut(idx)
                {
                    q.set_kick(event_from_fd(fd));
                }
                maybe_ack(socket, hdr, state).await?;
            }

            VhostUserRequestCode::SET_VRING_CALL => {
                let msg = parse_payload::<VhostUserU64Msg>(payload)?;
                let idx = (msg.value & VHOST_USER_VRING_INDEX_MASK) as usize;
                let nofd = msg.value & VHOST_USER_VRING_NOFD_MASK != 0;
                if let Some(q) = state.queues.get_mut(idx) {
                    if nofd {
                        q.set_call(Interrupt::null());
                    } else if let Some(fd) = fds.into_iter().next() {
                        q.set_call(Interrupt::from_event(event_from_fd(fd)));
                    }
                }
                maybe_ack(socket, hdr, state).await?;
            }

            VhostUserRequestCode::SET_VRING_ERR => {
                // Low priority — store for error signaling but not critical for MVP.
                maybe_ack(socket, hdr, state).await?;
            }

            VhostUserRequestCode::SET_VRING_ENABLE => {
                let msg = parse_payload::<VhostUserVringState>(payload)?;
                let idx = msg.index as usize;
                let enable = msg.num != 0;
                if let Some(q) = state.queues.get_mut(idx) {
                    if enable {
                        if !q.is_active() {
                            if let Some((resources, queue_state)) = q.try_activate() {
                                self.device
                                    .start_queue(
                                        idx as u16,
                                        resources,
                                        &state.negotiated_features,
                                        Some(queue_state),
                                    )
                                    .await?;
                                q.set_active();
                            } else {
                                tracelimit::warn_ratelimited!(
                                    idx,
                                    "SET_VRING_ENABLE: queue not ready to activate"
                                );
                            }
                        }
                    } else if q.is_active() {
                        let _state = stop_queue(&mut *self.device, idx as u16).await;
                        q.set_inactive();
                    }
                } else {
                    tracelimit::warn_ratelimited!(idx, "SET_VRING_ENABLE: invalid queue index");
                }
                maybe_ack(socket, hdr, state).await?;
            }

            VhostUserRequestCode::RESET_DEVICE => {
                self.stop_all_queues().await;
                self.device.reset().await;
                state.reset(&self.device.traits());
                maybe_ack(socket, hdr, state).await?;
            }

            _ => {
                tracelimit::warn_ratelimited!(
                    code = ?code,
                    "unhandled vhost-user request"
                );
            }
        }

        Ok(())
    }

    /// Handle SET_MEM_TABLE: mmap fds and update the shared memory regions.
    async fn handle_set_mem_table(
        &mut self,
        state: &mut ConnectionState,
        payload: &[u8],
        fds: Vec<OwnedFd>,
    ) -> anyhow::Result<()> {
        // Payload starts with a u32 region count (within the padding of
        // VhostUserMemory struct), then an array of VhostUserMemoryRegion.
        //
        // The vhost-user spec packs: { u32 nregions, u32 padding, regions[] }.
        if payload.len() < 8 {
            anyhow::bail!("SET_MEM_TABLE payload too small");
        }
        let nregions = u32::from_le_bytes(payload[..4].try_into().unwrap()) as usize;
        let region_bytes = &payload[8..];
        let region_size = size_of::<VhostUserMemoryRegion>();

        if region_bytes.len() < nregions * region_size {
            anyhow::bail!(
                "SET_MEM_TABLE: expected {} region bytes, got {}",
                nregions * region_size,
                region_bytes.len()
            );
        }
        if fds.len() < nregions {
            anyhow::bail!(
                "SET_MEM_TABLE: expected {} fds, got {}",
                nregions,
                fds.len()
            );
        }

        // Stop all active queues before replacing memory.
        let active_queues = self.stop_active_queues(state).await;

        // Parse regions and pair with fds.
        let mut regions = Vec::with_capacity(nregions);
        let mut fd_iter = fds.into_iter();
        for i in 0..nregions {
            let offset = i * region_size;
            let region =
                VhostUserMemoryRegion::read_from_bytes(&region_bytes[offset..offset + region_size])
                    .expect("region_size matches struct size");

            let fd = fd_iter.next().unwrap();
            regions.push((
                region.guest_phys_addr,
                region.memory_size,
                region.userspace_addr,
                region.mmap_offset,
                fd,
            ));
        }

        // Update the shared memory regions (this mmaps the new fds).
        self.mem_regions.set_regions(regions)?;

        // Restart any queues that were active before the memory update.
        for (idx, resources, queue_state) in active_queues {
            self.device
                .start_queue(
                    idx,
                    resources,
                    &state.negotiated_features,
                    Some(queue_state),
                )
                .await?;
            if let Some(q) = state.queues.get_mut(idx as usize) {
                q.set_active();
            }
        }

        Ok(())
    }

    /// Stop all active queues, returning their indices and state for restart.
    async fn stop_active_queues(
        &mut self,
        state: &mut ConnectionState,
    ) -> Vec<(u16, virtio::QueueResources, QueueState)> {
        // For now, just stop and mark inactive. We don't have enough info to
        // rebuild QueueResources for restart (the kick/call fds were consumed).
        // A full implementation would stash the resources. For MVP, just stop
        // them — the frontend will re-enable after SET_MEM_TABLE.
        for (idx, q) in state.queues.iter_mut().enumerate() {
            if q.is_active() {
                let _queue_state = stop_queue(&mut *self.device, idx as u16).await;
                q.set_inactive();
            }
        }
        Vec::new()
    }

    /// Stop all active queues (cleanup).
    async fn stop_all_queues(&mut self) {
        // We don't have state.queues here, so ask the device to stop
        // all possible queues.
        let max_queues = self.device.traits().max_queues;
        for idx in 0..max_queues {
            // Try to stop; the device will return None if not active.
            let _ = stop_queue(&mut *self.device, idx).await;
        }
    }
}

/// Per-connection protocol state.
struct ConnectionState {
    negotiated_features: VirtioDeviceFeatures,
    protocol_features: VhostUserProtocolFeatures,
    queues: Vec<QueueSetup>,
}

impl ConnectionState {
    fn new(traits: &DeviceTraits) -> Self {
        let mut queues = Vec::with_capacity(traits.max_queues as usize);
        for _ in 0..traits.max_queues {
            queues.push(QueueSetup::new());
        }
        Self {
            negotiated_features: VirtioDeviceFeatures::new(),
            protocol_features: VhostUserProtocolFeatures::default(),
            queues,
        }
    }

    fn reset(&mut self, traits: &DeviceTraits) {
        *self = Self::new(traits);
    }
}

/// Stop a queue on the device and return its state.
async fn stop_queue(device: &mut dyn DynVirtioDevice, idx: u16) -> Option<QueueState> {
    device.stop_queue(idx).await
}

/// Send a reply for a GET_* message.
async fn send_reply(
    socket: &VhostUserSocket,
    request_hdr: &VhostUserMsgHeader,
    payload: &[u8],
    fds: &[OwnedFd],
) -> Result<(), SocketError> {
    let hdr = VhostUserMsgHeader::reply(request_hdr, payload.len() as u32);
    socket.send_reply(&hdr, payload, fds).await
}

/// Send an ACK reply if REPLY_ACK was negotiated and NEED_REPLY is set.
async fn maybe_ack(
    socket: &VhostUserSocket,
    hdr: &VhostUserMsgHeader,
    state: &ConnectionState,
) -> Result<(), SocketError> {
    if state
        .protocol_features
        .contains(VhostUserProtocolFeatures::REPLY_ACK)
        && hdr.need_reply()
    {
        let reply_payload = VhostUserU64Msg { value: 0 };
        send_reply(socket, hdr, reply_payload.as_bytes(), &[]).await?;
    }
    Ok(())
}

/// Parse a payload as a zerocopy type.
fn parse_payload<T: FromBytes>(payload: &[u8]) -> anyhow::Result<T> {
    T::read_from_prefix(payload)
        .map(|(val, _rest)| val)
        .map_err(|_| {
            anyhow::anyhow!(
                "payload too small: expected >= {} bytes, got {}",
                size_of::<T>(),
                payload.len()
            )
        })
}

/// Convert a u64 to VirtioDeviceFeatures (bank0 = low 32 bits, bank1 = high 32 bits).
fn features_from_u64(value: u64) -> VirtioDeviceFeatures {
    VirtioDeviceFeatures::new()
        .with_bank(0, value as u32)
        .with_bank(1, (value >> 32) as u32)
}

/// Convert VirtioDeviceFeatures to a u64 (bank0 = low 32 bits, bank1 = high 32 bits).
fn features_to_u64(features: &VirtioDeviceFeatures) -> u64 {
    features.bank(0) as u64 | ((features.bank(1) as u64) << 32)
}

/// Create a `pal_event::Event` from an `OwnedFd`.
///
/// The fd should be an eventfd. On Linux, `pal_event::Event` wraps an eventfd.
fn event_from_fd(fd: OwnedFd) -> Event {
    Event::from(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use inspect::InspectMut;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use pal_async::socket::PolledSocket;
    use std::os::fd::AsFd;

    use test_with_tracing::test;
    use unix_socket::UnixStream;
    use virtio::DeviceTraits;
    use virtio::DeviceTraitsSharedMemory;
    use virtio::QueueResources;
    use virtio::VirtioDevice;
    use virtio::queue::QueueState;
    use virtio::spec::VirtioDeviceFeatures;
    use zerocopy::IntoBytes;

    /// A mock VirtioDevice for testing the protocol adapter.
    struct MockDevice {
        traits: DeviceTraits,
        started_queues: Vec<u16>,
        stopped_queues: Vec<u16>,
    }

    impl MockDevice {
        fn new() -> Self {
            Self {
                traits: DeviceTraits {
                    device_id: 2, // block device
                    device_features: VirtioDeviceFeatures::new(),
                    max_queues: 2,
                    device_register_length: 0,
                    shared_memory: DeviceTraitsSharedMemory::default(),
                },
                started_queues: Vec::new(),
                stopped_queues: Vec::new(),
            }
        }
    }

    impl InspectMut for MockDevice {
        fn inspect_mut(&mut self, _req: inspect::Request<'_>) {}
    }

    impl VirtioDevice for MockDevice {
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
            self.stopped_queues.push(idx);
            Some(QueueState {
                avail_index: 0,
                used_index: 0,
            })
        }

        async fn reset(&mut self) {
            self.started_queues.clear();
            self.stopped_queues.clear();
        }
    }

    /// Helper: create a Unix socket pair for testing.
    fn socket_pair() -> (UnixStream, UnixStream) {
        let (a, b) = socket2::Socket::pair(socket2::Domain::UNIX, socket2::Type::STREAM, None)
            .expect("socketpair failed");
        let a: UnixStream = a.into();
        let b: UnixStream = b.into();
        (a, b)
    }

    /// Helper: send a vhost-user message on the frontend socket.
    async fn send_msg(
        socket: &VhostUserSocket,
        code: VhostUserRequestCode,
        payload: &[u8],
        fds: &[impl AsFd],
    ) {
        let hdr = VhostUserMsgHeader {
            request: code.0,
            flags: VHOST_USER_FLAG_VERSION,
            size: payload.len() as u32,
        };
        socket
            .send_reply(&hdr, payload, fds)
            .await
            .expect("send failed");
    }

    /// Helper: send a message and expect a reply, returning reply payload.
    async fn send_and_recv(
        socket: &VhostUserSocket,
        code: VhostUserRequestCode,
        payload: &[u8],
    ) -> Vec<u8> {
        send_msg(socket, code, payload, &[] as &[OwnedFd]).await;
        let (hdr, reply_payload, _fds) = socket.recv_message().await.expect("recv reply failed");
        assert!(hdr.is_reply(), "expected reply flag");
        reply_payload
    }

    #[async_test]
    async fn test_protocol_handshake(driver: DefaultDriver) {
        let (frontend_stream, backend_stream) = socket_pair();

        let backend_polled = PolledSocket::new(&driver, backend_stream).unwrap();
        let backend_socket = VhostUserSocket::new(backend_polled);

        let server = VhostUserDeviceServer::new(|_mem| Box::new(MockDevice::new()));

        // Frontend side: drive the handshake.
        let frontend_polled = PolledSocket::new(&driver, frontend_stream).unwrap();
        let frontend = VhostUserSocket::new(frontend_polled);

        let frontend_task = async {
            // GET_FEATURES
            let reply = send_and_recv(&frontend, VhostUserRequestCode::GET_FEATURES, &[]).await;
            let features_msg = VhostUserU64Msg::read_from_bytes(&reply).unwrap();
            assert!(
                features_msg.value & VHOST_USER_F_PROTOCOL_FEATURES != 0,
                "should advertise PROTOCOL_FEATURES"
            );

            // SET_FEATURES (must include PROTOCOL_FEATURES bit)
            let set_features = VhostUserU64Msg {
                value: VHOST_USER_F_PROTOCOL_FEATURES,
            };
            send_msg(
                &frontend,
                VhostUserRequestCode::SET_FEATURES,
                set_features.as_bytes(),
                &[] as &[OwnedFd],
            )
            .await;

            // GET_PROTOCOL_FEATURES
            let reply =
                send_and_recv(&frontend, VhostUserRequestCode::GET_PROTOCOL_FEATURES, &[]).await;
            let pf_msg = VhostUserU64Msg::read_from_bytes(&reply).unwrap();
            let pf = VhostUserProtocolFeatures::from_bits(pf_msg.value);
            assert!(pf.contains(VhostUserProtocolFeatures::MQ));
            assert!(pf.contains(VhostUserProtocolFeatures::CONFIG));

            // SET_PROTOCOL_FEATURES
            let set_pf = VhostUserU64Msg {
                value: VhostUserProtocolFeatures::MQ
                    | VhostUserProtocolFeatures::REPLY_ACK
                    | VhostUserProtocolFeatures::CONFIG,
            };
            send_msg(
                &frontend,
                VhostUserRequestCode::SET_PROTOCOL_FEATURES,
                set_pf.as_bytes(),
                &[] as &[OwnedFd],
            )
            .await;

            // GET_QUEUE_NUM
            let reply = send_and_recv(&frontend, VhostUserRequestCode::GET_QUEUE_NUM, &[]).await;
            let qn_msg = VhostUserU64Msg::read_from_bytes(&reply).unwrap();
            assert_eq!(qn_msg.value, 2); // MockDevice has 2 queues

            // SET_OWNER
            send_msg(
                &frontend,
                VhostUserRequestCode::SET_OWNER,
                &[],
                &[] as &[OwnedFd],
            )
            .await;

            // Disconnect by dropping the frontend socket.
            drop(frontend);
        };

        let (server_result, ()) =
            futures::join!(server.serve_connection(backend_socket), frontend_task,);
        server_result.expect("server should exit cleanly");
    }
}
