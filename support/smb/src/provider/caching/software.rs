// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Software caching for stores whose mutations are all mediated by the provider.
//!
//! Call admission and registration while holding the provider's object-store
//! lock. Release that lock before waiting, then resolve and validate again.
//! This ordering makes admission atomic with effects without awaiting under a
//! synchronous lock. All opens, including uncached opens, need a reservation.

use super::{
    Caching, CachingBreak, CachingBreakId, CachingGrant, CachingRequest, CachingSnapshot,
    CachingState, LeaseIdentity, Oplock,
};
use crate::provider::RequestContext;
use crate::spec::{AccessMask, Status};
use async_trait::async_trait;
use event_listener::Event;
use futures::FutureExt;
use inspect::Inspect;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

const OPEN_LIMIT: usize = 4096;
const WRITE_CACHING: u32 = 0x4;
const HANDLE_CACHING: u32 = 0x2;

fn significant(access: u32, lease: bool) -> bool {
    let stat = AccessMask::new()
        .with_read_attributes(true)
        .with_write_attributes(true)
        .with_synchronize(true)
        .with_read_control(lease)
        .into_bits();
    access & !stat != 0
}

/// Stable provider file/stream identity; never a pathname or protocol FileId.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachingKey {
    /// File identity, shared by hard links.
    pub file: u64,
    /// Stable stream identity, retained across binding renames.
    pub stream: u64,
}

/// Shared, bounded oplock and lease admission state.
#[derive(Clone, Default)]
pub struct SoftwareCaching(Arc<Mutex<Table>>);

#[derive(Default)]
struct Table {
    next: u64,
    opens: BTreeMap<u64, Entry>,
}

struct Entry {
    lease: Option<LeaseIdentity>,
    key: CachingKey,
    access: u32,
    control: Arc<Control>,
}

struct Control {
    instance: u64,
    state: Mutex<ControlState>,
    changed: Event,
}

struct ControlState {
    owners: usize,
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
        state.owners -= 1;
        if state.owners != 0 {
            return;
        }
        state.closed = true;
        state.held = CachingState::None;
        state.pending = None;
        self.control.changed.notify(usize::MAX);
    }
}

impl SoftwareCaching {
    /// Reject reuse of a client lease identity for a different file or stream,
    /// before publishing any creation or replacement effects.
    pub fn validate_lease(&self, key: CachingKey, request: CachingRequest) -> Result<(), Status> {
        if let CachingRequest::Lease { identity, .. } = request {
            if self
                .0
                .lock()
                .opens
                .values()
                .any(|entry| entry.lease == Some(identity) && entry.key != key)
            {
                return Err(Status::INVALID_PARAMETER);
            }
        }
        Ok(())
    }

    /// Named streams do not share lease caching with the default stream.
    /// The older classic profile conservatively revokes its default-stream grants.
    pub fn prepare_named_open(&self, file: u64) -> Result<Option<CachingWait>, Status> {
        self.prepare(|_, entry| {
            (entry.key.file == file && entry.lease.is_none()).then_some(CachingState::None)
        })
    }

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
                && entry.lease.is_none()
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

    /// Admit an open or replacement after ordinary sharing/access validation.
    /// Replacement breaks every stream of the file before destructive effects.
    pub fn prepare_open(
        &self,
        key: CachingKey,
        access: u32,
        replacement: bool,
        delete: bool,
        request: CachingRequest,
    ) -> Result<Option<CachingWait>, Status> {
        let lease = match request {
            CachingRequest::Lease { identity, .. } => Some(identity),
            _ => None,
        };
        self.prepare(|_, entry| {
            if lease.is_some() && lease == entry.lease {
                return None;
            }
            if replacement && entry.key.file == key.file {
                Some(CachingState::None)
            } else if entry.key == key {
                if entry.lease.is_some() {
                    let state = entry.control.state.lock().held;
                    let remove = (if significant(access, true) {
                        WRITE_CACHING
                    } else {
                        0
                    }) | (if delete { HANDLE_CACHING } else { 0 });
                    return CachingState::from_bits(state.bits() & !remove);
                }
                if !significant(access, false) {
                    return None;
                }
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

    /// Admit a stream data mutation.
    /// An exclusive owner's writes may flush dirty data during its break;
    /// level-II owners must invalidate their own read caching.
    pub fn prepare_mutation(
        &self,
        key: CachingKey,
        owner: &SoftwareOpen,
    ) -> Result<Option<CachingWait>, Status> {
        self.prepare_change(key, owner, false, false)
    }

    /// Shared file metadata invalidates foreign caches across streams.
    pub fn prepare_metadata(
        &self,
        key: CachingKey,
        owner: &SoftwareOpen,
    ) -> Result<Option<CachingWait>, Status> {
        self.prepare_change(key, owner, true, false)
    }

    /// Namespace effects relinquish cached foreign handles before publication.
    pub fn prepare_namespace(
        &self,
        key: CachingKey,
        owner: &SoftwareOpen,
    ) -> Result<Option<CachingWait>, Status> {
        self.prepare_change(key, owner, true, true)
    }

    /// Handle caching may need a break even when sharing validation failed.
    pub fn prepare_sharing(
        &self,
        key: CachingKey,
        request: CachingRequest,
    ) -> Result<Option<CachingWait>, Status> {
        let lease = match request {
            CachingRequest::Lease { identity, .. } => Some(identity),
            _ => None,
        };
        self.prepare(|_, entry| {
            if entry.key != key || (lease.is_some() && entry.lease == lease) {
                return None;
            }
            let state = entry.control.state.lock().held;
            CachingState::from_bits(state.bits() & !HANDLE_CACHING)
        })
    }

    fn prepare_change(
        &self,
        key: CachingKey,
        owner: &SoftwareOpen,
        metadata: bool,
        namespace: bool,
    ) -> Result<Option<CachingWait>, Status> {
        let owns_table = Weak::ptr_eq(&owner.table, &Arc::downgrade(&self.0));
        let lease = self
            .0
            .lock()
            .opens
            .get(&owner.id)
            .and_then(|entry| entry.lease);
        self.prepare(|id, entry| {
            if entry.lease.is_some() {
                if (if metadata {
                    entry.key.file != key.file
                } else {
                    entry.key != key
                }) || (owns_table && entry.lease == lease)
                {
                    return None;
                }
                if namespace {
                    return CachingState::from_bits(
                        entry.control.state.lock().held.bits() & !HANDLE_CACHING,
                    );
                }
                return Some(CachingState::None);
            }
            if entry.key.file != key.file {
                return None;
            }
            let exclusive_owner = owns_table && id == owner.id;
            if namespace {
                if exclusive_owner {
                    return None;
                }
                return CachingState::from_bits(
                    entry.control.state.lock().held.bits() & !HANDLE_CACHING,
                );
            }
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
                state.desired = CachingState::from_bits(state.desired.bits() & desired.bits())
                    .ok_or(Status::INVALID_PARAMETER)?;
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
    /// `shared_eligible` indicates whether backing locks permit shared read caching.
    /// A declined lease grant still retains its identity and zero-state context.
    pub fn register(
        &self,
        key: CachingKey,
        access: u32,
        eligible: bool,
        shared_eligible: bool,
        requested: CachingRequest,
    ) -> Result<(SoftwareOpen, CachingGrant), Status> {
        let mut table = self.0.lock();
        if table.opens.len() >= OPEN_LIMIT || table.next == u64::MAX {
            return Err(Status::INSUFFICIENT_RESOURCES);
        }
        let another = table
            .opens
            .values()
            .any(|entry| entry.key == key && significant(entry.access, matches!(requested, CachingRequest::Lease { .. }))
                && !matches!(requested, CachingRequest::Lease { identity, .. } if entry.lease == Some(identity)));
        let lease = match requested {
            CachingRequest::Lease { identity, .. } if eligible => Some(identity),
            _ => None,
        };
        let shared = lease.and_then(|identity| {
            table
                .opens
                .values()
                .find(|entry| entry.lease == Some(identity) && entry.key == key)
                .map(|entry| entry.control.clone())
        });
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
        let control = if let Some(control) = shared {
            let mut state = control.state.lock();
            if let CachingRequest::Lease {
                state: requested, ..
            } = requested
            {
                if (!another || requested.bits() & WRITE_CACHING == 0)
                    && (shared_eligible || requested.bits() & WRITE_CACHING != 0)
                    && state.pending.is_none()
                    && state.held.bits() & requested.bits() == state.held.bits()
                {
                    state.held = requested;
                }
            }
            state.owners += 1;
            drop(state);
            control
        } else {
            let lease_state = match requested {
                CachingRequest::Lease { state, .. } if another => {
                    CachingState::from_bits(state.bits() & !WRITE_CACHING)
                        .ok_or(Status::INVALID_PARAMETER)?
                }
                CachingRequest::Lease { state, .. } => state,
                _ => CachingState::None,
            };
            Arc::new(Control {
                instance: table.next + 1,
                state: Mutex::new(ControlState {
                    owners: 1,
                    held: if lease.is_some() {
                        if shared_eligible || lease_state.bits() & WRITE_CACHING != 0 {
                            lease_state
                        } else {
                            CachingState::None
                        }
                    } else {
                        match level {
                            Some(Oplock::Exclusive) => CachingState::ReadWrite,
                            Some(Oplock::Batch) => CachingState::ReadWriteHandle,
                            Some(_) => CachingState::Read,
                            None => CachingState::None,
                        }
                    },
                    desired: CachingState::None,
                    pending: None,
                    delivered: false,
                    next: 0,
                    closed: false,
                }),
                changed: Event::new(),
            })
        };
        table.next += 1;
        let id = table.next;
        table.opens.insert(
            id,
            Entry {
                lease,
                key,
                access,
                control: control.clone(),
            },
        );
        let grant = if let Some(identity) = lease {
            let state = control.snapshot();
            CachingGrant::Lease {
                identity,
                state: state.state,
                breaking: state.breaking,
                control: control.clone(),
            }
        } else {
            match level {
                Some(level) => CachingGrant::Oplock {
                    level,
                    control: control.clone(),
                },
                None => CachingGrant::None,
            }
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
    fn snapshot(&self) -> CachingSnapshot {
        let state = self.state.lock();
        CachingSnapshot {
            instance: self.instance,
            state: state.held,
            breaking: state.pending.is_some(),
        }
    }

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
        if rights.bits() & pending.state.bits() != rights.bits() {
            return Err(Status::INVALID_PARAMETER);
        }
        let subsequent = CachingState::from_bits(rights.bits() & state.desired.bits())
            .ok_or(Status::INVALID_PARAMETER)?;
        if subsequent != rights {
            state.next = state
                .next
                .checked_add(1)
                .ok_or(Status::INSUFFICIENT_RESOURCES)?;
            state.pending = Some(CachingBreak {
                id: CachingBreakId(state.next),
                state: subsequent,
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
