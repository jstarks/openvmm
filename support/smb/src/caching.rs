// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Oplock and SMB 2.1 lease wire lifecycle; coherence stays with the provider.

use super::*;
use crate::provider::{
    Caching, CachingBreak, CachingSnapshot, CachingState, LeaseIdentity, Oplock,
};
use futures::FutureExt;
use pal_async::{
    DefaultDriver,
    timer::{Instant, PolledTimer},
};
use std::time::Duration;

pub(super) const BREAK_TIMEOUT: Duration = Duration::from_secs(35);

pub(super) struct OpenCaching {
    lease: Option<LeaseIdentity>,
    members: AtomicUsize,
    control: Arc<dyn Caching>,
    state: Mutex<State>,
    pub(super) gate: futures::lock::Mutex<()>,
    changed: Event,
    pub(super) stop: RequestContext,
    started: AtomicBool,
}

struct State {
    level: OplockLevel,
    rights: CachingState,
    pending: Option<CachingBreak>,
}

impl OpenCaching {
    pub(super) fn from_grant(
        grant: CachingGrant,
        requested: OplockLevel,
        enabled: bool,
        stop: RequestContext,
    ) -> Result<Option<Self>, Status> {
        let (level, control) = match grant {
            CachingGrant::None => return Ok(None),
            CachingGrant::Oplock { level, control } if enabled => (level, control),
            _ => return Err(Status::INTERNAL_ERROR),
        };
        let valid = match requested {
            OplockLevel::EXCLUSIVE => matches!(level, Oplock::Exclusive | Oplock::LevelII),
            OplockLevel::BATCH => true,
            _ => false,
        };
        if !valid {
            return Err(Status::INTERNAL_ERROR);
        }
        let level = match level {
            Oplock::LevelII => OplockLevel::LEVEL_II,
            Oplock::Exclusive => OplockLevel::EXCLUSIVE,
            Oplock::Batch => OplockLevel::BATCH,
        };
        Ok(Some(Self {
            lease: None,
            members: AtomicUsize::new(1),
            control,
            state: Mutex::new(State {
                level,
                rights: match level {
                    OplockLevel::EXCLUSIVE => CachingState::ReadWrite,
                    OplockLevel::BATCH => CachingState::ReadWriteHandle,
                    _ => CachingState::Read,
                },
                pending: None,
            }),
            gate: futures::lock::Mutex::new(()),
            changed: Event::new(),
            stop,
            started: AtomicBool::new(false),
        }))
    }

    pub(super) fn level(&self) -> OplockLevel {
        self.state.lock().level
    }

    pub(super) fn lease(&self) -> Option<LeaseIdentity> {
        self.lease
    }

    pub(super) fn members(&self) -> usize {
        self.members.load(Ordering::Acquire)
    }

    pub(super) fn retire(&self) {
        if self.members.fetch_sub(1, Ordering::AcqRel) == 1 && self.lease.is_none() {
            self.stop.cancel();
        }
        self.changed.notify(usize::MAX);
    }

    pub(super) fn lease_snapshot(&self) -> CachingSnapshot {
        let state = self.state.lock();
        let provider = self.control.snapshot();
        CachingSnapshot {
            instance: provider.instance,
            state: state.rights,
            breaking: state.pending.is_some() || provider.breaking,
        }
    }

    async fn complete(
        &self,
        change: CachingBreak,
        rights: CachingState,
        request: &RequestContext,
    ) -> Result<(), Status> {
        // The caller holds gate, including across provider completion.
        if self.state.lock().pending != Some(change) {
            return Ok(());
        }
        let result = self.control.acknowledge(change.id, rights, request).await;
        match result {
            Err(Status::FILE_CLOSED)
                if self.stop.is_cancelled() || self.members.load(Ordering::Acquire) == 0 =>
            {
                let mut state = self.state.lock();
                state.level = OplockLevel::NONE;
                state.pending = None;
                state.rights = CachingState::None;
                self.changed.notify(usize::MAX);
                Ok(())
            }
            Ok(actual) if actual.bits() & rights.bits() == actual.bits() => {
                let mut state = self.state.lock();
                state.level = if self.lease.is_some() {
                    OplockLevel::LEASE
                } else {
                    match actual {
                        CachingState::None => OplockLevel::NONE,
                        CachingState::Read => OplockLevel::LEVEL_II,
                        _ => return Err(Status::INTERNAL_ERROR),
                    }
                };
                state.rights = actual;
                state.pending = None;
                self.changed.notify(usize::MAX);
                Ok(())
            }
            Ok(_) => {
                self.stop.cancel();
                Err(Status::INTERNAL_ERROR)
            }
            Err(error) => {
                self.stop.cancel();
                Err(error)
            }
        }
    }

    pub(super) async fn acknowledge(
        &self,
        level: OplockLevel,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let _gate = self.gate.lock().await;
        let (old, pending) = {
            let state = self.state.lock();
            (
                state.level,
                state.pending.ok_or(Status::INVALID_DEVICE_STATE)?,
            )
        };
        let valid = match old {
            OplockLevel::EXCLUSIVE => matches!(level, OplockLevel::LEVEL_II | OplockLevel::NONE),
            OplockLevel::BATCH => matches!(
                level,
                OplockLevel::EXCLUSIVE | OplockLevel::LEVEL_II | OplockLevel::NONE
            ),
            OplockLevel::LEVEL_II => level == OplockLevel::NONE,
            _ => false,
        };
        let rights = if level == OplockLevel::LEVEL_II {
            CachingState::Read
        } else {
            CachingState::None
        };
        if !valid || rights.bits() & pending.state.bits() != rights.bits() {
            let cleanup = RequestContext::new(self.stop.id());
            self.complete(pending, CachingState::None, &cleanup).await?;
            return Err(if level == OplockLevel::LEASE {
                Status::INVALID_PARAMETER
            } else {
                Status::INVALID_OPLOCK_PROTOCOL
            });
        }
        self.complete(pending, rights, request).await
    }

    pub(super) async fn acknowledge_lease(
        &self,
        bits: u32,
        request: &RequestContext,
    ) -> Result<CachingState, Status> {
        let _gate = self.gate.lock().await;
        let pending = self.state.lock().pending.ok_or(Status::UNSUCCESSFUL)?;
        if bits & pending.state.bits() != bits {
            return Err(Status::REQUEST_NOT_ACCEPTED);
        }
        let rights = CachingState::from_bits(bits).ok_or(Status::REQUEST_NOT_ACCEPTED)?;
        self.complete(pending, rights, request).await?;
        Ok(self.state.lock().rights)
    }
}

impl Inspect for OpenCaching {
    fn inspect(&self, req: inspect::Request<'_>) {
        let state = self.state.lock();
        req.respond()
            .field("level", inspect::AsDebug(state.level))
            .field("pending", inspect::AsDebug(state.pending))
            .field("lease", inspect::AsDebug(self.lease))
            .field("members", self.members.load(Ordering::Relaxed))
            .field("provider", self.control.as_ref());
    }
}

impl<B: FileSystem> Connection<B> {
    pub(crate) fn lease_identity(&self, key: [u8; 16]) -> Result<LeaseIdentity, Status> {
        Ok(LeaseIdentity {
            authority: self
                .server
                .guid
                .as_bytes()
                .try_into()
                .map_err(|_| Status::INTERNAL_ERROR)?,
            client_guid: self.state.lock().client_guid,
            key,
        })
    }

    pub(crate) async fn attach_caching(
        &self,
        grant: CachingGrant,
        requested_level: OplockLevel,
        request: CachingRequest,
        stop: RequestContext,
    ) -> Result<Option<Arc<OpenCaching>>, Status> {
        let enabled = self.state.lock().caching_enabled;
        let (identity, control) = match grant {
            CachingGrant::Lease {
                identity, control, ..
            } if enabled
                && matches!(request, CachingRequest::Lease { identity: requested, .. } if requested == identity) =>
            {
                (identity, control)
            }
            grant => {
                return OpenCaching::from_grant(grant, requested_level, enabled, stop)
                    .map(|caching| caching.map(Arc::new));
            }
        };
        let previous = {
            let mut leases = self.server.leases.lock();
            leases.retain(|_, lease| lease.strong_count() != 0);
            let snapshot = control.snapshot();
            let previous = leases.get(&identity).and_then(Weak::upgrade);
            if let Some(previous) = previous {
                if previous.control.snapshot().instance == snapshot.instance {
                    Some(previous)
                } else if previous.members.load(Ordering::Acquire) != 0 {
                    return Err(Status::INTERNAL_ERROR);
                } else {
                    None
                }
            } else {
                None
            }
            .or_else(|| {
                let caching = Arc::new(OpenCaching {
                    lease: Some(identity),
                    members: AtomicUsize::new(0),
                    control: control.clone(),
                    state: Mutex::new(State {
                        level: OplockLevel::LEASE,
                        rights: if snapshot.breaking {
                            CachingState::None
                        } else {
                            snapshot.state
                        },
                        pending: None,
                    }),
                    gate: futures::lock::Mutex::new(()),
                    changed: Event::new(),
                    stop,
                    started: AtomicBool::new(false),
                });
                leases.insert(identity, Arc::downgrade(&caching));
                Some(caching)
            })
        };
        if let Some(previous) = previous {
            let _gate = previous.gate.lock().await;
            let fresh = control.snapshot();
            if !fresh.breaking {
                previous.state.lock().rights = fresh.state;
            }
            previous.members.fetch_add(1, Ordering::AcqRel);
            previous.changed.notify(usize::MAX);
            return Ok(Some(previous.clone()));
        }
        Err(Status::INTERNAL_ERROR)
    }

    pub(crate) async fn serve_caching(
        self,
        driver: DefaultDriver,
        sender: async_channel::Sender<Vec<u8>>,
        timeout: Duration,
    ) -> Result<(), Error> {
        let mut watches = unicycle::FuturesUnordered::new();
        let mut failure = None;
        loop {
            let changed = self.caching_changed.listen();
            let disconnected = {
                let state = self.state.lock();
                for (&volatile, file) in state.files.iter().filter(|_| !state.disconnected) {
                    if let Some(caching) = &file.caching {
                        if !file.closing.load(Ordering::Acquire)
                            && !caching.started.swap(true, Ordering::AcqRel)
                        {
                            watches.push(
                                watch(
                                    file.clone(),
                                    FileId {
                                        persistent: file.identity.into(),
                                        volatile: volatile.into(),
                                    },
                                    state.session,
                                    driver.clone(),
                                    sender.clone(),
                                    timeout,
                                    self.caching_stop.clone(),
                                    self.caching_changed.clone(),
                                )
                                .boxed(),
                            );
                        }
                    }
                }
                state.disconnected
            };
            if disconnected && watches.is_empty() {
                return match failure {
                    Some(error) => Err(error),
                    None => Ok(()),
                };
            }
            let mut changed = std::pin::pin!(changed.fuse());
            let mut finished = std::pin::pin!(
                async {
                    if watches.is_empty() {
                        std::future::pending().await
                    } else {
                        watches.next().await
                    }
                }
                .fuse()
            );
            futures::select! {
                () = changed => {}
                result = finished => {
                    if let Some(Err(error)) = result {
                        if failure.is_none() { failure = Some(error); }
                        self.cancel_all();
                    }
                }
            }
        }
    }
}

async fn watch<F: Send + Sync>(
    file: Arc<OpenFile<F>>,
    file_id: FileId,
    session: u64,
    driver: DefaultDriver,
    sender: async_channel::Sender<Vec<u8>>,
    timeout: Duration,
    connection_stop: RequestContext,
    global_changed: Arc<Event>,
) -> Result<(), Error> {
    let caching = file
        .caching
        .as_ref()
        .ok_or(Error::Backend(Status::INTERNAL_ERROR))?;
    let _claim = WatchClaim {
        caching: caching.clone(),
        changed: global_changed,
    };
    if caching.lease.is_some() {
        return watch_lease(caching, driver, sender, timeout, connection_stop).await;
    }
    let cleanup = RequestContext::new(caching.stop.id());
    let mut timer = PolledTimer::new(&driver);
    loop {
        let change = match caching.control.wait_for_break(&caching.stop).await {
            Ok(change) => change,
            Err(Status::CANCELLED | Status::FILE_CLOSED)
                if caching.stop.is_cancelled() || file.closed.load(Ordering::Acquire) =>
            {
                return Ok(());
            }
            Err(error) => return Err(Error::Backend(error)),
        };
        let new_level = match change.state {
            CachingState::None => OplockLevel::NONE,
            CachingState::Read => OplockLevel::LEVEL_II,
            CachingState::ReadWrite => OplockLevel::EXCLUSIVE,
            _ => return Err(Error::Backend(Status::INTERNAL_ERROR)),
        };
        let old = {
            let mut state = caching.state.lock();
            let old = state.level;
            let valid = match old {
                OplockLevel::LEVEL_II => change.state == CachingState::None,
                OplockLevel::EXCLUSIVE => {
                    matches!(change.state, CachingState::Read | CachingState::None)
                }
                OplockLevel::BATCH => matches!(
                    change.state,
                    CachingState::ReadWrite | CachingState::Read | CachingState::None
                ),
                _ => false,
            };
            if !valid {
                return Err(Error::Backend(Status::INVALID_OPLOCK_PROTOCOL));
            }
            state.pending = Some(change);
            old
        };
        let mut header = Header::new_zeroed();
        header.protocol = SIGNATURE;
        header.structure_size = (HEADER_SIZE as u16).into();
        header.command = Command::OPLOCK_BREAK.0.into();
        header.flags = HeaderFlags::new().with_server_to_redir(true);
        header.message_id = u64::MAX.into();
        header.session_id = session.into();
        let body = OplockBreakAcknowledgement {
            structure_size: OplockBreakAcknowledgement::STRUCTURE_SIZE.into(),
            oplock_level: new_level,
            reserved: 0,
            reserved2: 0.into(),
            file_id,
        };
        if !caching.stop.is_cancelled() {
            let bytes = response_bytes(&header, None, body.as_bytes());
            let mut send = std::pin::pin!(sender.send(bytes).fuse());
            let mut stopped = std::pin::pin!(caching.stop.cancelled().fuse());
            futures::select! {
                result = send => result.map_err(|_| Error::ResponseChannelClosed)?,
                () = stopped => {}
            }
        }

        let deadline = Instant::now().saturating_add(timeout);
        loop {
            let changed = caching.changed.listen();
            if caching.state.lock().pending != Some(change) {
                break;
            }
            if old == OplockLevel::LEVEL_II || caching.stop.is_cancelled() {
                let _gate = caching.gate.lock().await;
                caching
                    .complete(change, CachingState::None, &cleanup)
                    .await
                    .map_err(Error::Backend)?;
                break;
            }
            let mut changed = std::pin::pin!(changed.fuse());
            let mut stopped = std::pin::pin!(caching.stop.cancelled().fuse());
            let mut expired = std::pin::pin!(timer.sleep_until(deadline).fuse());
            futures::select! {
                () = changed => {}
                () = stopped => {}
                _ = expired => {
                    let _gate = caching.gate.lock().await;
                    caching.complete(change, CachingState::None, &cleanup).await.map_err(Error::Backend)?;
                    break;
                }
            }
        }
        if caching.stop.is_cancelled() {
            return Ok(());
        }
    }
}

struct WatchClaim {
    caching: Arc<OpenCaching>,
    changed: Arc<Event>,
}

impl Drop for WatchClaim {
    fn drop(&mut self) {
        self.caching.started.store(false, Ordering::Release);
        self.changed.notify(usize::MAX);
    }
}

async fn watch_lease(
    caching: &Arc<OpenCaching>,
    driver: DefaultDriver,
    sender: async_channel::Sender<Vec<u8>>,
    timeout: Duration,
    connection_stop: RequestContext,
) -> Result<(), Error> {
    let identity = caching
        .lease
        .ok_or(Error::Backend(Status::INTERNAL_ERROR))?;
    let cleanup = RequestContext::new(caching.stop.id());
    let mut timer = PolledTimer::new(&driver);
    loop {
        if connection_stop.is_cancelled() {
            return Ok(());
        }
        let pending = caching.state.lock().pending;
        let mut change = if let Some(change) = pending {
            change
        } else {
            if caching.members.load(Ordering::Acquire) == 0 {
                return Ok(());
            }
            let request = RequestContext::new(caching.stop.id());
            let mut waiting = Box::pin(caching.control.wait_for_break(&request));
            let result = loop {
                let changed = caching.changed.listen();
                if caching.members.load(Ordering::Acquire) == 0 || connection_stop.is_cancelled() {
                    request.cancel();
                }
                let mut changed = std::pin::pin!(changed.fuse());
                let mut stopped = std::pin::pin!(connection_stop.cancelled().fuse());
                let mut next = std::pin::pin!(waiting.as_mut().fuse());
                futures::select! {
                    result = next => break result,
                    () = changed => {}
                    () = stopped => {
                        request.cancel();
                        break waiting.await;
                    }
                }
            };
            match result {
                Ok(change) => {
                    caching.state.lock().pending = Some(change);
                    change
                }
                Err(Status::CANCELLED | Status::FILE_CLOSED)
                    if caching.members.load(Ordering::Acquire) == 0
                        || connection_stop.is_cancelled() =>
                {
                    return Ok(());
                }
                Err(error) => return Err(Error::Backend(error)),
            }
        };
        if connection_stop.is_cancelled() {
            // Another live connection can resume this already delivered provider break.
            return Ok(());
        }
        if caching.members.load(Ordering::Acquire) == 0 {
            let _gate = caching.gate.lock().await;
            if caching.members.load(Ordering::Acquire) == 0 {
                caching
                    .complete(change, CachingState::None, &cleanup)
                    .await
                    .map_err(Error::Backend)?;
                return Ok(());
            }
        }
        let current = {
            let state = caching.state.lock();
            if state.pending != Some(change) {
                continue;
            }
            state.rights
        };
        let effective = CachingState::from_bits(change.state.bits() & current.bits())
            .ok_or(Error::Backend(Status::INVALID_OPLOCK_PROTOCOL))?;
        if effective != change.state {
            change.state = effective;
            caching.state.lock().pending = Some(change);
        }
        if effective == current {
            let _gate = caching.gate.lock().await;
            caching
                .complete(change, current, &cleanup)
                .await
                .map_err(Error::Backend)?;
            continue;
        }
        let ack_required = current != CachingState::Read;
        let mut header = Header::new_zeroed();
        header.protocol = SIGNATURE;
        header.structure_size = (HEADER_SIZE as u16).into();
        header.command = Command::OPLOCK_BREAK.0.into();
        header.flags = HeaderFlags::new().with_server_to_redir(true);
        header.message_id = u64::MAX.into();
        let body = LeaseBreakNotification {
            structure_size: LeaseBreakNotification::STRUCTURE_SIZE.into(),
            new_epoch: 0.into(),
            flags: u32::from(ack_required).into(),
            lease_key: identity.key,
            current_state: current.bits().into(),
            new_state: change.state.bits().into(),
            break_reason: 0.into(),
            access_hint: 0.into(),
            share_hint: 0.into(),
        };
        let bytes = response_bytes(&header, None, body.as_bytes());
        {
            let mut send = std::pin::pin!(sender.send(bytes).fuse());
            let mut stopped = std::pin::pin!(connection_stop.cancelled().fuse());
            futures::select! {
                result = send => result.map_err(|_| Error::ResponseChannelClosed)?,
                () = stopped => return Ok(()),
            }
        }
        let deadline = Instant::now().saturating_add(timeout);
        loop {
            let changed = caching.changed.listen();
            if caching.state.lock().pending != Some(change) {
                break;
            }
            if !ack_required || caching.members.load(Ordering::Acquire) == 0 {
                let _gate = caching.gate.lock().await;
                if !ack_required || caching.members.load(Ordering::Acquire) == 0 {
                    caching
                        .complete(change, CachingState::None, &cleanup)
                        .await
                        .map_err(Error::Backend)?;
                    break;
                }
            }
            let mut changed = std::pin::pin!(changed.fuse());
            let mut stopped = std::pin::pin!(connection_stop.cancelled().fuse());
            let mut expired = std::pin::pin!(timer.sleep_until(deadline).fuse());
            futures::select! {
                () = changed => {}
                () = stopped => return Ok(()),
                _ = expired => {
                    let _gate = caching.gate.lock().await;
                    caching.complete(change, CachingState::None, &cleanup).await.map_err(Error::Backend)?;
                    break;
                }
            }
        }
    }
}
