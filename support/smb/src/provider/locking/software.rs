// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Synthetic byte-range locks and completion-lifetime I/O admission.
//!
//! Keys identify stable file/stream objects, not names. All cooperating access
//! paths must share this coordinator. It does not constrain external host I/O.

use super::super::{ByteRange, LockId, RequestContext};
use crate::spec::Status;
use event_listener::Event;
use futures::FutureExt;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

const OPEN_LIMIT: usize = 4096;
const LOCK_LIMIT: usize = 16384;

/// Shared software enforcement for stable provider-defined file/stream keys.
#[derive(Clone)]
pub struct SoftwareLocks<K>(Arc<Inner<K>>);

struct Inner<K> {
    state: Mutex<Table<K>>,
    changed: Event,
}

struct Table<K> {
    next: u64,
    owners: HashMap<u64, Open<K>>,
    locks: Vec<RangeLock<K>>,
    active: Vec<ActiveIo<K>>,
    waiters: HashMap<u64, u64>,
}

struct Open<K> {
    key: K,
    closing: bool,
}

struct RangeLock<K> {
    id: LockId,
    key: K,
    owner: u64,
    range: ByteRange,
    exclusive: bool,
}

struct ActiveIo<K> {
    id: u64,
    key: K,
    owner: u64,
    range: ByteRange,
    write: bool,
    eof: bool,
}

impl<K> Default for SoftwareLocks<K> {
    fn default() -> Self {
        Self(Arc::new(Inner {
            state: Mutex::new(Table {
                next: 0,
                owners: HashMap::new(),
                locks: Vec::new(),
                active: Vec::new(),
                waiters: HashMap::new(),
            }),
            changed: Event::new(),
        }))
    }
}

impl<K> SoftwareLocks<K> {
    /// Number of live logical acquisitions.
    pub fn lock_count(&self) -> usize {
        self.0.state.lock().locks.len()
    }

    /// Number of contended lock requests.
    pub fn waiter_count(&self) -> usize {
        self.0.state.lock().waiters.len()
    }

    /// Number of admitted operations whose completion guards remain owned.
    pub fn active_count(&self) -> usize {
        self.0.state.lock().active.len()
    }

    /// Observe natural provider contention without an artificial scheduling gate.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn wait_until_pending(&self, request: u64) {
        loop {
            let listener = self.0.changed.listen();
            if self
                .0
                .state
                .lock()
                .waiters
                .values()
                .any(|id| *id == request)
            {
                return;
            }
            listener.await;
        }
    }
}

impl<K: Clone + Eq> SoftwareLocks<K> {
    /// Register an independent open; aliases share a key but never an owner.
    pub fn open(&self, key: K) -> Result<SoftwareLockOwner<K>, Status> {
        let mut table = self.0.state.lock();
        if table.owners.len() == OPEN_LIMIT {
            return Err(Status::INSUFFICIENT_RESOURCES);
        }
        let id = table.next;
        table.next = id.checked_add(1).ok_or(Status::INSUFFICIENT_RESOURCES)?;
        table.owners.insert(
            id,
            Open {
                key,
                closing: false,
            },
        );
        Ok(SoftwareLockOwner(Arc::new(Owner {
            inner: self.0.clone(),
            id,
        })))
    }
}

struct Owner<K> {
    inner: Arc<Inner<K>>,
    id: u64,
}

impl<K> Owner<K> {
    fn close(&self) {
        let mut table = self.inner.state.lock();
        table.owners.remove(&self.id);
        table.locks.retain(|lock| lock.owner != self.id);
        drop(table);
        self.inner.changed.notify(usize::MAX);
    }
}

impl<K> Drop for Owner<K> {
    fn drop(&mut self) {
        self.close();
    }
}

/// Open-owned lock lifetime. Active I/O retains this owner through completion.
#[derive(Clone)]
pub struct SoftwareLockOwner<K>(Arc<Owner<K>>);

impl<K> SoftwareLockOwner<K> {
    /// Release all locks after the provider has drained this open's I/O.
    pub fn close(&self) {
        self.0.close();
    }

    /// Stop new admission before draining an explicit close.
    pub fn start_close(&self) -> Result<(), Status> {
        self.0
            .inner
            .state
            .lock()
            .owners
            .get_mut(&self.0.id)
            .ok_or(Status::FILE_CLOSED)?
            .closing = true;
        self.0.inner.changed.notify(usize::MAX);
        Ok(())
    }

    /// Undo a failed close's admission fence, without resurrecting a closed open.
    pub fn resume(&self) {
        if let Some(open) = self.0.inner.state.lock().owners.get_mut(&self.0.id) {
            open.closing = false;
        }
        self.0.inner.changed.notify(usize::MAX);
    }

    /// Drain admitted operations after `start_close`, independently of cancellation.
    pub async fn drain(&self) {
        loop {
            let listener = self.0.inner.changed.listen();
            if !self
                .0
                .inner
                .state
                .lock()
                .active
                .iter()
                .any(|io| io.owner == self.0.id)
            {
                return;
            }
            listener.await;
        }
    }

    /// Undo one acquisition, not an ordinary exact-range match. Idempotent.
    pub fn rollback(&self, id: LockId) {
        self.0
            .inner
            .state
            .lock()
            .locks
            .retain(|lock| lock.owner != self.0.id || lock.id != id);
        self.0.inner.changed.notify(usize::MAX);
    }
}

impl<K: Clone + Eq> SoftwareLockOwner<K> {
    /// Acquire a lock, or wait without blocking unlock, I/O or close.
    pub async fn lock(
        &self,
        range: ByteRange,
        exclusive: bool,
        immediate: bool,
        request: &RequestContext,
    ) -> Result<LockId, Status> {
        range.validate()?;
        let mut waiter = None;
        loop {
            let listener = self.0.inner.changed.listen();
            if request.is_cancelled() {
                return Err(Status::CANCELLED);
            }
            {
                let mut table = self.0.inner.state.lock();
                let open = table.owners.get(&self.0.id).ok_or(Status::FILE_CLOSED)?;
                if open.closing {
                    return Err(Status::FILE_CLOSED);
                }
                let key = open.key.clone();
                let conflict = table.locks.iter().any(|lock| {
                    lock.key == key
                        && lock.range.overlaps(range)
                        && (exclusive || lock.exclusive && lock.owner != self.0.id)
                }) || table.active.iter().any(|io| {
                    io.key == key
                        && io.owner != self.0.id
                        && io.range.overlaps(range)
                        && (exclusive || io.write)
                });
                if !conflict {
                    if table.locks.len() == LOCK_LIMIT {
                        return Err(Status::INSUFFICIENT_RESOURCES);
                    }
                    let id = LockId(table.next);
                    table.next = id.0.checked_add(1).ok_or(Status::INSUFFICIENT_RESOURCES)?;
                    table.locks.push(RangeLock {
                        id,
                        key,
                        owner: self.0.id,
                        range,
                        exclusive,
                    });
                    return Ok(id);
                }
                if immediate {
                    return Err(Status::LOCK_NOT_GRANTED);
                }
                if waiter.is_none() {
                    if table.waiters.len() == OPEN_LIMIT {
                        return Err(Status::INSUFFICIENT_RESOURCES);
                    }
                    let id = table.next;
                    table.next = id.checked_add(1).ok_or(Status::INSUFFICIENT_RESOURCES)?;
                    table.waiters.insert(id, request.id());
                    waiter = Some(Waiter {
                        inner: self.0.inner.clone(),
                        id,
                    });
                    self.0.inner.changed.notify(usize::MAX);
                }
            }
            let mut changed = std::pin::pin!(listener.fuse());
            let mut cancelled = std::pin::pin!(request.cancelled().fuse());
            futures::select! {
                () = changed => {},
                () = cancelled => return Err(Status::CANCELLED),
            }
        }
    }

    /// Remove one exact acquisition, preferring exclusive matches.
    pub fn unlock(&self, range: ByteRange) -> Result<(), Status> {
        range.validate()?;
        let mut table = self.0.inner.state.lock();
        if !table.owners.contains_key(&self.0.id) {
            return Err(Status::FILE_CLOSED);
        }
        let index = table
            .locks
            .iter()
            .enumerate()
            .filter(|(_, lock)| lock.owner == self.0.id && lock.range == range)
            .max_by_key(|(_, lock)| lock.exclusive)
            .map(|(index, _)| index)
            .ok_or(Status::RANGE_NOT_LOCKED)?;
        table.locks.remove(index);
        drop(table);
        self.0.inner.changed.notify(usize::MAX);
        Ok(())
    }

    /// Admit data I/O atomically with locks. EOF operations serialize cooperating
    /// writes; use `set_range` after learning the actual append destination.
    /// Move the returned guard into the actual native operation's owned state.
    pub async fn operation(
        &self,
        range: ByteRange,
        write: bool,
        eof: bool,
        request: &RequestContext,
    ) -> Result<SoftwareIo<K>, Status> {
        range.validate()?;
        loop {
            let listener = self.0.inner.changed.listen();
            if request.is_cancelled() {
                return Err(Status::CANCELLED);
            }
            {
                let mut table = self.0.inner.state.lock();
                let open = table.owners.get(&self.0.id).ok_or(Status::FILE_CLOSED)?;
                if open.closing {
                    return Err(Status::FILE_CLOSED);
                }
                let key = open.key.clone();
                let busy = table
                    .active
                    .iter()
                    .any(|io| io.key == key && (write && io.eof || eof && io.write));
                if !busy {
                    if !eof
                        && range.length != 0
                        && table.locks.iter().any(|lock| {
                            lock.key == key
                                && lock.range.overlaps(range)
                                && if write {
                                    !lock.exclusive || lock.owner != self.0.id
                                } else {
                                    lock.exclusive && lock.owner != self.0.id
                                }
                        })
                    {
                        return Err(Status::FILE_LOCK_CONFLICT);
                    }
                    let id = table.next;
                    table.next = id.checked_add(1).ok_or(Status::INSUFFICIENT_RESOURCES)?;
                    table.active.push(ActiveIo {
                        id,
                        key,
                        owner: self.0.id,
                        range,
                        write,
                        eof,
                    });
                    return Ok(SoftwareIo {
                        owner: self.clone(),
                        id,
                    });
                }
            }
            let mut changed = std::pin::pin!(listener.fuse());
            let mut cancelled = std::pin::pin!(request.cancelled().fuse());
            futures::select! {
                () = changed => {},
                () = cancelled => return Err(Status::CANCELLED),
            }
        }
    }
}

/// Admission retained by actual I/O, not merely by its caller's awaiting future.
pub struct SoftwareIo<K> {
    owner: SoftwareLockOwner<K>,
    id: u64,
}

impl<K: Eq> SoftwareIo<K> {
    /// Validate and record a resolved append/EOF range before issuing data effects.
    pub fn set_range(&self, range: ByteRange) -> Result<(), Status> {
        range.validate()?;
        let mut table = self.owner.0.inner.state.lock();
        let io = table
            .active
            .iter()
            .find(|io| io.id == self.id)
            .ok_or(Status::FILE_CLOSED)?;
        if table.locks.iter().any(|lock| {
            lock.key == io.key
                && lock.range.overlaps(range)
                && if io.write {
                    !lock.exclusive || lock.owner != io.owner
                } else {
                    lock.exclusive && lock.owner != io.owner
                }
        }) {
            return Err(Status::FILE_LOCK_CONFLICT);
        }
        table
            .active
            .iter_mut()
            .find(|io| io.id == self.id)
            .expect("operation remains registered")
            .range = range;
        Ok(())
    }
}

impl<K> Drop for SoftwareIo<K> {
    fn drop(&mut self) {
        self.owner
            .0
            .inner
            .state
            .lock()
            .active
            .retain(|io| io.id != self.id);
        self.owner.0.inner.changed.notify(usize::MAX);
    }
}

struct Waiter<K> {
    inner: Arc<Inner<K>>,
    id: u64,
}

impl<K> Drop for Waiter<K> {
    fn drop(&mut self) {
        self.inner.state.lock().waiters.remove(&self.id);
        self.inner.changed.notify(usize::MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use test_with_tracing::test;

    const RANGE: ByteRange = ByteRange {
        offset: 2,
        length: 4,
    };

    #[test]
    fn active_io_rejects_foreign_locks_and_retains_its_dropped_owner() {
        block_on(async {
            let locks = SoftwareLocks::default();
            let request = RequestContext::new(1);
            let owner = locks.open(7).unwrap();
            let peer = locks.open(7).unwrap();
            let other = locks.open(8).unwrap();
            let io = owner.operation(RANGE, true, false, &request).await.unwrap();
            assert_eq!(
                peer.lock(RANGE, false, true, &request).await,
                Err(Status::LOCK_NOT_GRANTED)
            );
            other.lock(RANGE, true, true, &request).await.unwrap();
            owner.lock(RANGE, true, true, &request).await.unwrap();
            drop(owner);
            assert_eq!(
                peer.lock(RANGE, false, true, &request).await,
                Err(Status::LOCK_NOT_GRANTED)
            );
            drop(io);
            peer.lock(RANGE, true, true, &request).await.unwrap();
        });
    }

    #[test]
    fn append_admission_serializes_writes_and_checks_the_resolved_range() {
        block_on(async {
            let locks = SoftwareLocks::default();
            let request = RequestContext::new(1);
            let owner = locks.open(7).unwrap();
            let peer = locks.open(7).unwrap();
            peer.lock(RANGE, false, true, &request).await.unwrap();
            let whole = ByteRange {
                offset: 0,
                length: u64::MAX,
            };
            let io = owner.operation(whole, true, true, &request).await.unwrap();
            assert_eq!(io.set_range(RANGE), Err(Status::FILE_LOCK_CONFLICT));
            let tail = ByteRange {
                offset: 8,
                length: 1,
            };
            io.set_range(tail).unwrap();
            let cancelled = RequestContext::new(2);
            {
                let mut write = std::pin::pin!(peer.operation(tail, true, false, &cancelled));
                assert!(futures::poll!(&mut write).is_pending());
                cancelled.cancel();
                assert_eq!(write.await.err(), Some(Status::CANCELLED));
            }
            drop(io);
            peer.operation(tail, true, false, &request).await.unwrap();
        });
    }

    #[test]
    fn closing_wakes_waiters_and_failed_close_can_resume_admission() {
        block_on(async {
            let locks = SoftwareLocks::default();
            let request = RequestContext::new(1);
            let owner = locks.open(7).unwrap();
            let peer = locks.open(7).unwrap();
            owner.lock(RANGE, true, true, &request).await.unwrap();
            {
                let mut waiting = std::pin::pin!(peer.lock(RANGE, true, false, &request));
                assert!(futures::poll!(&mut waiting).is_pending());
                peer.start_close().unwrap();
                assert_eq!(waiting.await, Err(Status::FILE_CLOSED));
            }
            peer.resume();
            owner.unlock(RANGE).unwrap();
            let acquired = peer.lock(RANGE, true, true, &request).await.unwrap();
            peer.rollback(acquired);
            peer.rollback(acquired);
            owner.lock(RANGE, true, true, &request).await.unwrap();
        });
    }

    #[test]
    fn close_drains_io_and_releases_locks_even_with_retained_owner_references() {
        block_on(async {
            let locks = SoftwareLocks::default();
            let request = RequestContext::new(1);
            let owner = locks.open(7).unwrap();
            let peer = locks.open(7).unwrap();
            owner.lock(RANGE, true, true, &request).await.unwrap();
            let io = owner.operation(RANGE, true, false, &request).await.unwrap();
            owner.start_close().unwrap();
            let mut drain = std::pin::pin!(owner.drain());
            assert!(futures::poll!(&mut drain).is_pending());
            assert_eq!(
                owner.operation(RANGE, true, false, &request).await.err(),
                Some(Status::FILE_CLOSED)
            );
            drop(io);
            drain.await;
            owner.close();
            peer.lock(RANGE, true, true, &request).await.unwrap();
            assert_eq!(
                owner.lock(RANGE, true, true, &request).await,
                Err(Status::FILE_CLOSED)
            );
        });
    }
}
