// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Software oplocks for stores whose mutations are all mediated by the provider.
//!
//! Call admission and registration while holding the provider's object-store
//! lock. Release that lock before waiting, then resolve and validate again.
//! This ordering makes admission atomic with effects without awaiting under a
//! synchronous lock. All opens, including uncached opens, need a reservation.

use super::{
    Caching, CachingBreak, CachingBreakId, CachingGrant, CachingRequest, CachingState, Oplock,
};
use crate::provider::RequestContext;
use crate::spec::Status;
use async_trait::async_trait;
use event_listener::Event;
use futures::FutureExt;
use inspect::Inspect;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

const OPEN_LIMIT: usize = 4096;

/// Stable provider file/stream identity; never a pathname or protocol FileId.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachingKey {
    /// File identity, shared by hard links.
    pub file: u64,
    /// Stable stream identity, retained across binding renames.
    pub stream: u64,
}

/// Shared, bounded classic-oplock admission state.
#[derive(Clone, Default)]
pub struct SoftwareCaching(Arc<Mutex<Table>>);

#[derive(Default)]
struct Table {
    next: u64,
    opens: BTreeMap<u64, Entry>,
}

struct Entry {
    key: CachingKey,
    data_access: bool,
    control: Arc<Control>,
}

struct Control {
    state: Mutex<ControlState>,
    changed: Event,
}

struct ControlState {
    held: CachingState,
    pending: Option<CachingBreak>,
    desired: CachingState,
    delivered: bool,
    next: u64,
    closed: bool,
}

/// A pending admission. Cancellation does not undo an already issued break.
pub struct CachingWait(Vec<Arc<Control>>);

impl CachingWait {
    /// Wait without holding provider locks. Revalidate admission afterward.
    pub async fn wait(&self, request: &RequestContext) -> Result<(), Status> {
        for control in &self.0 {
            loop {
                let changed = control.changed.listen();
                if request.is_cancelled() {
                    return Err(Status::CANCELLED);
                }
                {
                    let state = control.state.lock();
                    if state.closed || state.pending.is_none() {
                        break;
                    }
                }
                let mut changed = std::pin::pin!(changed.fuse());
                let mut cancelled = std::pin::pin!(request.cancelled().fuse());
                futures::select! {
                    () = changed => {}
                    () = cancelled => return Err(Status::CANCELLED),
                }
            }
        }
        Ok(())
    }
}

/// One provider open's reservation; drop releases it and wakes break waiters.
pub struct SoftwareOpen {
    table: Weak<Mutex<Table>>,
    id: u64,
    control: Arc<Control>,
}

impl Drop for SoftwareOpen {
    fn drop(&mut self) {
        if let Some(table) = self.table.upgrade() {
            table.lock().opens.remove(&self.id);
        }
        let mut state = self.control.state.lock();
        state.closed = true;
        state.held = CachingState::None;
        state.pending = None;
        self.control.changed.notify(usize::MAX);
    }
}

impl SoftwareCaching {
    /// Check the reservation budget before publishing any open effects.
    pub fn check_capacity(&self) -> Result<(), Status> {
        let table = self.0.lock();
        if table.opens.len() >= OPEN_LIMIT || table.next == u64::MAX {
            return Err(Status::INSUFFICIENT_RESOURCES);
        }
        Ok(())
    }

    /// Break batch handle caching before ordinary open access/sharing checks
    /// (MS-FSA 2.1.5.1.2). Stat-only opens do not break classic oplocks.
    pub fn prepare_batch_open(
        &self,
        key: CachingKey,
        significant_access: bool,
        replacement: bool,
    ) -> Result<Option<CachingWait>, Status> {
        self.prepare(|_, entry| {
            if entry.key == key
                && significant_access
                && entry.control.state.lock().held == CachingState::ReadWriteHandle
            {
                Some(if replacement {
                    CachingState::None
                } else {
                    CachingState::Read
                })
            } else {
                None
            }
        })
    }

    /// Admit a data open or replacement after ordinary sharing/access validation.
    /// Replacement breaks every stream of the file before destructive effects.
    pub fn prepare_open(
        &self,
        key: CachingKey,
        data_access: bool,
        replacement: bool,
    ) -> Result<Option<CachingWait>, Status> {
        self.prepare(|_, entry| {
            if replacement && entry.key.file == key.file {
                Some(CachingState::None)
            } else if data_access && entry.key == key {
                match entry.control.state.lock().held {
                    CachingState::ReadWrite | CachingState::ReadWriteHandle => {
                        Some(CachingState::Read)
                    }
                    _ => None,
                }
            } else {
                None
            }
        })
    }

    /// Admit a file mutation, including shared metadata changes through streams.
    /// An exclusive owner's writes may flush dirty data during its break;
    /// level-II owners must invalidate their own read caching.
    pub fn prepare_mutation(
        &self,
        key: CachingKey,
        owner: &SoftwareOpen,
    ) -> Result<Option<CachingWait>, Status> {
        let owns_table = Weak::ptr_eq(&owner.table, &Arc::downgrade(&self.0));
        self.prepare(|id, entry| {
            if entry.key.file != key.file {
                return None;
            }
            let exclusive_owner = owns_table && id == owner.id;
            if exclusive_owner
                && matches!(
                    entry.control.state.lock().held,
                    CachingState::ReadWrite | CachingState::ReadWriteHandle
                )
            {
                None
            } else {
                Some(CachingState::None)
            }
        })
    }

    fn prepare(
        &self,
        target: impl Fn(u64, &Entry) -> Option<CachingState>,
    ) -> Result<Option<CachingWait>, Status> {
        let table = self.0.lock();
        let mut waits = Vec::new();
        for (&id, entry) in &table.opens {
            let Some(desired) = target(id, entry) else {
                continue;
            };
            let mut state = entry.control.state.lock();
            if state.held == CachingState::None {
                continue;
            }
            if state.pending.is_some() {
                if desired == CachingState::None {
                    state.desired = desired;
                }
            } else if state.held != desired {
                state.next = state
                    .next
                    .checked_add(1)
                    .ok_or(Status::INSUFFICIENT_RESOURCES)?;
                state.pending = Some(CachingBreak {
                    id: CachingBreakId(state.next),
                    state: desired,
                });
                state.desired = desired;
                state.delivered = false;
                entry.control.changed.notify(usize::MAX);
            }
            if state.pending.is_some() {
                waits.push(entry.control.clone());
            }
        }
        Ok((!waits.is_empty()).then_some(CachingWait(waits)))
    }

    /// Register the validated open while still holding the provider lock.
    /// Call check_capacity before committing effects and do not interleave opens.
    pub fn register(
        &self,
        key: CachingKey,
        data_access: bool,
        eligible: bool,
        requested: CachingRequest,
    ) -> Result<(SoftwareOpen, CachingGrant), Status> {
        let mut table = self.0.lock();
        if table.opens.len() >= OPEN_LIMIT || table.next == u64::MAX {
            return Err(Status::INSUFFICIENT_RESOURCES);
        }
        let another = table
            .opens
            .values()
            .any(|entry| entry.key == key && entry.data_access);
        let level = match requested {
            CachingRequest::Oplock(Oplock::Exclusive) if eligible => Some(if another {
                Oplock::LevelII
            } else {
                Oplock::Exclusive
            }),
            CachingRequest::Oplock(Oplock::Batch) if eligible => Some(if another {
                Oplock::LevelII
            } else {
                Oplock::Batch
            }),
            CachingRequest::Oplock(Oplock::LevelII) if eligible => Some(Oplock::LevelII),
            _ => None,
        };
        let control = Arc::new(Control {
            state: Mutex::new(ControlState {
                held: match level {
                    Some(Oplock::Exclusive) => CachingState::ReadWrite,
                    Some(Oplock::Batch) => CachingState::ReadWriteHandle,
                    Some(_) => CachingState::Read,
                    None => CachingState::None,
                },
                desired: CachingState::None,
                pending: None,
                delivered: false,
                next: 0,
                closed: false,
            }),
            changed: Event::new(),
        });
        table.next += 1;
        let id = table.next;
        table.opens.insert(
            id,
            Entry {
                key,
                data_access,
                control: control.clone(),
            },
        );
        let grant = match level {
            Some(level) => CachingGrant::Oplock {
                level,
                control: control.clone(),
            },
            None => CachingGrant::None,
        };
        Ok((
            SoftwareOpen {
                table: Arc::downgrade(&self.0),
                id,
                control,
            },
            grant,
        ))
    }
}

impl Inspect for SoftwareCaching {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("opens", self.0.lock().opens.len())
            .field("limit", OPEN_LIMIT);
    }
}

impl Inspect for Control {
    fn inspect(&self, req: inspect::Request<'_>) {
        let state = self.state.lock();
        req.respond()
            .field("held", inspect::AsDebug(state.held))
            .field("pending", inspect::AsDebug(state.pending))
            .field("closed", state.closed);
    }
}

#[async_trait]
impl Caching for Control {
    async fn wait_for_break(&self, request: &RequestContext) -> Result<CachingBreak, Status> {
        loop {
            let changed = self.changed.listen();
            {
                let mut state = self.state.lock();
                if state.closed {
                    return Err(Status::FILE_CLOSED);
                }
                if !state.delivered {
                    if let Some(change) = state.pending {
                        state.delivered = true;
                        return Ok(change);
                    }
                }
                if request.is_cancelled() {
                    return Err(Status::CANCELLED);
                }
            }
            let mut changed = std::pin::pin!(changed.fuse());
            let mut cancelled = std::pin::pin!(request.cancelled().fuse());
            futures::select! {
                () = changed => {}
                () = cancelled => return Err(Status::CANCELLED),
            }
        }
    }

    async fn acknowledge(
        &self,
        id: CachingBreakId,
        rights: CachingState,
        _request: &RequestContext,
    ) -> Result<CachingState, Status> {
        let mut state = self.state.lock();
        if state.closed {
            return Err(Status::FILE_CLOSED);
        }
        let pending = state.pending.ok_or(Status::INVALID_DEVICE_STATE)?;
        if pending.id != id || !state.delivered {
            return Err(Status::INVALID_DEVICE_STATE);
        }
        if rights != CachingState::None && rights != pending.state {
            return Err(Status::INVALID_PARAMETER);
        }
        if rights != CachingState::None && state.desired == CachingState::None {
            state.next = state
                .next
                .checked_add(1)
                .ok_or(Status::INSUFFICIENT_RESOURCES)?;
            state.pending = Some(CachingBreak {
                id: CachingBreakId(state.next),
                state: CachingState::None,
            });
            state.delivered = false;
        } else {
            state.pending = None;
        }
        state.held = rights;
        self.changed.notify(usize::MAX);
        Ok(rights)
    }
}
