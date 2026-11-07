// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Classic oplock wire lifecycle; filesystem coherence stays with the provider.

use super::*;
use crate::provider::{Caching, CachingBreak, CachingState, Oplock};
use futures::FutureExt;
use pal_async::{
    DefaultDriver,
    timer::{Instant, PolledTimer},
};
use std::time::Duration;

pub(super) const BREAK_TIMEOUT: Duration = Duration::from_secs(35);

pub(super) struct OpenCaching {
    control: Arc<dyn Caching>,
    state: Mutex<State>,
    pub(super) gate: futures::lock::Mutex<()>,
    changed: Event,
    pub(super) stop: RequestContext,
    started: AtomicBool,
}

struct State {
    level: OplockLevel,
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
            control,
            state: Mutex::new(State {
                level,
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
            Err(Status::FILE_CLOSED) if self.stop.is_cancelled() => {
                let mut state = self.state.lock();
                state.level = OplockLevel::NONE;
                state.pending = None;
                self.changed.notify(usize::MAX);
                Ok(())
            }
            Ok(actual) if actual == CachingState::None || actual == rights => {
                let mut state = self.state.lock();
                state.level = match actual {
                    CachingState::None => OplockLevel::NONE,
                    CachingState::Read => OplockLevel::LEVEL_II,
                    _ => return Err(Status::INTERNAL_ERROR),
                };
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
        if !valid || (rights != CachingState::None && rights != pending.state) {
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
}

impl Inspect for OpenCaching {
    fn inspect(&self, req: inspect::Request<'_>) {
        let state = self.state.lock();
        req.respond()
            .field("level", inspect::AsDebug(state.level))
            .field("pending", inspect::AsDebug(state.pending))
            .field("provider", self.control.as_ref());
    }
}

impl<B: FileSystem> Connection<B> {
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
                for (&volatile, file) in &state.files {
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
) -> Result<(), Error> {
    let caching = file
        .caching
        .as_ref()
        .ok_or(Error::Backend(Status::INTERNAL_ERROR))?;
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
