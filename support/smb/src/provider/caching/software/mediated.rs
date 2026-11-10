// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Admission for asynchronously backed stores with exclusively mediated mutations.
//!
//! Namespace admissions exclude other opens and namespace effects, not data I/O.
//! Drop an admission before waiting for a caching break. Bind admitted native work
//! to its request context, and retain each open until its native effects finish.

use super::{CachingKey, CachingWait, HANDLE_CACHING, OPEN_LIMIT, SoftwareCaching, SoftwareOpen};
use crate::provider::{
    ByteRange, CachingGrant, CachingRequest, CachingState, LockScope, LockSettlement,
    RequestContext,
};
use crate::spec::{AccessMask, Status};
use async_trait::async_trait;
use futures::FutureExt;
use futures::lock::{Mutex, OwnedMutexGuard};
use inspect::Inspect;
use parking_lot::Mutex as SyncMutex;
use std::collections::BTreeMap;
use std::sync::Arc;

const LOCK_LIMIT: usize = 16384;

/// Shared software policy for a store with no out-of-band mutations.
#[derive(Clone, Default)]
pub struct MediatedCaching(Arc<Store>);

#[derive(Default)]
struct Store {
    namespace: Arc<Mutex<()>>,
    caching: SoftwareCaching,
    activity: SyncMutex<Activity>,
}

#[derive(Default)]
struct Activity {
    namespaces: usize,
    next_lock: u64,
    locks: usize,
    files: BTreeMap<u64, FileActivity>,
}

#[derive(Default)]
struct FileActivity {
    opens: usize,
    active: usize,
    locks: usize,
    delete_modes: usize,
    delete_pending: bool,
}

impl FileActivity {
    fn deleting(&self) -> bool {
        self.delete_pending || self.delete_modes != 0
    }
}

impl Activity {
    fn reap(&mut self) {
        if self.namespaces == 0 {
            self.files
                .retain(|_, file| file.opens != 0 || file.active != 0);
        }
    }
}

/// Retain this admission through identity resolution, native effects and registration.
#[derive(Clone)]
pub struct NamespaceAdmission(Arc<NamespaceState>);

struct NamespaceState {
    store: Arc<Store>,
    _guard: OwnedMutexGuard<()>,
}

impl Drop for NamespaceState {
    fn drop(&mut self) {
        let mut state = self.store.activity.lock();
        state.namespaces -= 1;
        state.reap();
    }
}

/// Reservation attached to an actual provider open, not to an SMB connection.
pub struct MediatedOpen {
    store: Arc<Store>,
    key: CachingKey,
    reservation: SyncMutex<Option<SoftwareOpen>>,
    locks: SyncMutex<Vec<RangeLock>>,
    delete_mode: bool,
}

struct RangeLock {
    id: u64,
    range: ByteRange,
    exclusive: bool,
}

/// Kind of filesystem effect requiring cache invalidation.
#[derive(Clone, Copy)]
pub enum Change {
    /// Stream contents, allocation or byte-range locks.
    Data,
    /// Shared file metadata, including attributes and security.
    Metadata,
}

struct Effect(Arc<MediatedOpen>);

impl Drop for Effect {
    fn drop(&mut self) {
        let mut state = self.0.store.activity.lock();
        state
            .files
            .get_mut(&self.0.key.file)
            .expect("active file")
            .active -= 1;
        state.reap();
    }
}

impl MediatedCaching {
    /// Begin an interruptible namespace admission. Never hold it across break waits.
    pub async fn namespace(&self, request: &RequestContext) -> Result<NamespaceAdmission, Status> {
        let mut locked = std::pin::pin!(self.0.namespace.clone().lock_owned().fuse());
        let mut cancelled = std::pin::pin!(request.cancelled().fuse());
        let guard = futures::select_biased! {
            () = cancelled => return Err(Status::CANCELLED),
            guard = locked => guard,
        };
        if request.is_cancelled() {
            return Err(Status::CANCELLED);
        }
        self.0.activity.lock().namespaces += 1;
        Ok(NamespaceAdmission(Arc::new(NamespaceState {
            store: self.0.clone(),
            _guard: guard,
        })))
    }

    /// Admit a namespace mutation without holding exclusion during client flushes.
    ///
    /// Destination identity need not be probed: conservatively revoke foreign
    /// handle caching throughout the store before an unknown-target replacement.
    pub async fn namespace_request(
        &self,
        owner: &Arc<MediatedOpen>,
        request: &RequestContext,
    ) -> Result<RequestContext, Status> {
        if !Arc::ptr_eq(&self.0, &owner.store) {
            return Err(Status::FILE_CLOSED);
        }
        loop {
            let admission = self.namespace(request).await?;
            let wait = {
                let _state = self.0.activity.lock();
                let reservation = owner.reservation.lock();
                let reservation = reservation.as_ref().ok_or(Status::FILE_CLOSED)?;
                match self.0.prepare_handles(Some(reservation.control.instance))? {
                    Some(wait) => Some(wait),
                    None => self.0.caching.prepare_namespace(owner.key, reservation)?,
                }
            };
            if let Some(wait) = wait {
                drop(admission);
                wait.wait(request).await?;
                continue;
            }
            return Ok(owner.retain_effect(request)?.with_keepalive(admission));
        }
    }
}

impl Store {
    fn prepare_handles(&self, except: Option<u64>) -> Result<Option<CachingWait>, Status> {
        self.caching.prepare(|_, entry| {
            if Some(entry.control.instance) == except {
                return None;
            }
            let held = entry.control.state.lock().held;
            if entry.lease.is_none() && held == CachingState::ReadWriteHandle {
                Some(CachingState::Read)
            } else {
                CachingState::from_bits(held.bits() & !HANDLE_CACHING)
            }
        })
    }
}

impl NamespaceAdmission {
    /// Attach exclusion to work which may outlive its awaiting future.
    pub fn request(&self, request: &RequestContext) -> RequestContext {
        request.with_keepalive(self.clone())
    }

    /// Relinquish handle caching before an identity probe requiring data access.
    pub fn prepare_identity_probe(&self) -> Result<Option<CachingWait>, Status> {
        let _state = self.0.store.activity.lock();
        self.0.store.prepare_handles(None)
    }

    /// Retry a native sharing conflict only after foreign cached handles retire.
    pub fn prepare_sharing(
        &self,
        key: CachingKey,
        requested: CachingRequest,
    ) -> Result<Option<CachingWait>, Status> {
        let _state = self.0.store.activity.lock();
        self.0.store.caching.prepare_sharing(key, requested)
    }

    /// Validate lease identity and admit effects before the original native open.
    /// `None` requires a confirmed absent object or create-new-only disposition,
    /// never failed identity resolution for an operation that can replace data.
    pub fn prepare_open(
        &self,
        key: Option<CachingKey>,
        access: u32,
        replacement: bool,
        delete: bool,
        requested: CachingRequest,
    ) -> Result<Option<CachingWait>, Status> {
        let state = self.0.store.activity.lock();
        self.0.store.caching.check_capacity()?;
        if state.files.len() >= OPEN_LIMIT && key.is_none() {
            return Err(Status::INSUFFICIENT_RESOURCES);
        }
        let Some(key) = key else {
            if let CachingRequest::Lease { identity, .. } = requested {
                if self
                    .0
                    .store
                    .caching
                    .0
                    .lock()
                    .opens
                    .values()
                    .any(|entry| entry.lease == Some(identity))
                {
                    return Err(Status::INVALID_PARAMETER);
                }
            }
            return Ok(None);
        };
        self.0.store.caching.validate_lease(key, requested)?;
        if let Some(wait) = self.0.store.caching.prepare_batch_open(
            key,
            super::significant(access, false),
            replacement,
        )? {
            return Ok(Some(wait));
        }
        self.0
            .store
            .caching
            .prepare_open(key, access, replacement, delete, requested)
    }

    /// Register the actual opened identity and grants before releasing admission.
    /// Every open, including one requesting no caching, must be registered.
    pub fn register(
        &self,
        key: CachingKey,
        access: u32,
        eligible: bool,
        delete: bool,
        requested: CachingRequest,
    ) -> Result<(Arc<MediatedOpen>, CachingGrant), Status> {
        let mut state = self.0.store.activity.lock();
        let file = state.files.entry(key.file).or_default();
        let requested = match requested {
            CachingRequest::Lease { identity, state } => CachingRequest::Lease {
                identity,
                state: if file.active != 0 {
                    CachingState::None
                } else {
                    CachingState::from_bits(
                        state.bits()
                            & if file.deleting() {
                                !HANDLE_CACHING
                            } else {
                                u32::MAX
                            },
                    )
                    .ok_or(Status::INVALID_PARAMETER)?
                },
            },
            CachingRequest::Oplock(crate::provider::Oplock::Batch) if file.deleting() => {
                CachingRequest::Oplock(crate::provider::Oplock::Exclusive)
            }
            request => request,
        };
        let classic = matches!(requested, CachingRequest::Oplock(_));
        let rights = AccessMask::from_bits(access);
        let data_access =
            rights.read_data() || rights.write_data() || rights.append_data() || rights.execute();
        let (reservation, grant) = self.0.store.caching.register(
            key,
            access,
            eligible && (!classic || (data_access && file.active == 0 && file.locks == 0)),
            file.active == 0 && file.locks == 0,
            requested,
        )?;
        file.opens += 1;
        file.delete_modes += usize::from(delete);
        Ok((
            Arc::new(MediatedOpen {
                store: self.0.store.clone(),
                key,
                reservation: SyncMutex::new(Some(reservation)),
                locks: SyncMutex::new(Vec::new()),
                delete_mode: delete,
            }),
            grant,
        ))
    }
}

impl MediatedOpen {
    fn retain_effect(self: &Arc<Self>, request: &RequestContext) -> Result<RequestContext, Status> {
        let mut state = self.store.activity.lock();
        if self.reservation.lock().is_none() {
            return Err(Status::FILE_CLOSED);
        }
        state
            .files
            .get_mut(&self.key.file)
            .expect("registered file")
            .active += 1;
        Ok(request.with_keepalive(Effect(self.clone())))
    }

    /// Admit an effect, retaining its exclusion against new grants in native work.
    pub async fn request(
        self: &Arc<Self>,
        change: Change,
        request: &RequestContext,
    ) -> Result<RequestContext, Status> {
        loop {
            let wait = {
                let mut state = self.store.activity.lock();
                let reservation = self.reservation.lock();
                let reservation = reservation.as_ref().ok_or(Status::FILE_CLOSED)?;
                if request.is_cancelled() {
                    return Err(Status::CANCELLED);
                }
                let wait = match change {
                    Change::Data => self.store.caching.prepare_mutation(self.key, reservation)?,
                    Change::Metadata => {
                        self.store.caching.prepare_metadata(self.key, reservation)?
                    }
                };
                if wait.is_none() {
                    state
                        .files
                        .get_mut(&self.key.file)
                        .expect("registered file")
                        .active += 1;
                    return Ok(request.with_keepalive(Effect(self.clone())));
                }
                wait.expect("pending admission")
            };
            wait.wait(request).await?;
        }
    }

    /// Remember successful delete disposition before allowing further grants.
    pub fn set_deleting(&self, deleting: bool) -> Result<(), Status> {
        let mut state = self.store.activity.lock();
        if self.reservation.lock().is_none() {
            return Err(Status::FILE_CLOSED);
        }
        state
            .files
            .get_mut(&self.key.file)
            .expect("registered file")
            .delete_pending = deleting;
        Ok(())
    }

    /// Whether closing an open can have shared namespace effects.
    pub fn is_deleting(&self) -> bool {
        self.store
            .activity
            .lock()
            .files
            .get(&self.key.file)
            .is_some_and(FileActivity::deleting)
    }

    /// Release only after the backend has settled close and accepted native work.
    pub fn close(&self) {
        let mut state = self.store.activity.lock();
        if self.reservation.lock().take().is_some() {
            let mut locks = self.locks.lock();
            let file = state
                .files
                .get_mut(&self.key.file)
                .expect("registered file");
            file.opens -= 1;
            file.locks -= locks.len();
            file.delete_modes -= usize::from(self.delete_mode);
            file.delete_pending |= self.delete_mode;
            state.locks -= locks.len();
            locks.clear();
            state.reap();
        }
    }

    /// Preserve canonical backend lock semantics while coordinating cache admission.
    pub fn lock_scope<'a>(
        self: &Arc<Self>,
        inner: Box<dyn LockScope + 'a>,
    ) -> Box<dyn LockScope + 'a> {
        Box::new(MediatedLockScope {
            owner: self.clone(),
            inner,
            admission: None,
            acquired: Vec::new(),
        })
    }

    fn remove_locks(&self, ids: &[u64]) {
        let mut state = self.store.activity.lock();
        let mut locks = self.locks.lock();
        let before = locks.len();
        locks.retain(|lock| !ids.contains(&lock.id));
        state.locks -= before - locks.len();
        if let Some(file) = state.files.get_mut(&self.key.file) {
            file.locks -= before - locks.len();
        }
    }
}

impl Drop for MediatedOpen {
    fn drop(&mut self) {
        self.close();
    }
}

struct MediatedLockScope<'a> {
    owner: Arc<MediatedOpen>,
    inner: Box<dyn LockScope + 'a>,
    admission: Option<RequestContext>,
    acquired: Vec<u64>,
}

impl MediatedLockScope<'_> {
    async fn request(&mut self, request: &RequestContext) -> Result<RequestContext, Status> {
        if self.admission.is_none() {
            self.admission = Some(self.owner.request(Change::Data, request).await?);
        }
        Ok(request.with_keepalive(self.admission.clone()))
    }
}

#[async_trait]
impl LockScope for MediatedLockScope<'_> {
    async fn lock(
        &mut self,
        range: ByteRange,
        exclusive: bool,
        fail_immediately: bool,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let request = self.request(request).await?;
        let id = {
            let mut state = self.owner.store.activity.lock();
            if self.owner.reservation.lock().is_none() {
                return Err(Status::FILE_CLOSED);
            }
            if state.locks >= LOCK_LIMIT {
                return Err(Status::INSUFFICIENT_RESOURCES);
            }
            state.next_lock = state
                .next_lock
                .checked_add(1)
                .ok_or(Status::INSUFFICIENT_RESOURCES)?;
            let id = state.next_lock;
            self.owner.locks.lock().push(RangeLock {
                id,
                range,
                exclusive,
            });
            state
                .files
                .get_mut(&self.owner.key.file)
                .expect("registered file")
                .locks += 1;
            state.locks += 1;
            id
        };
        self.acquired.push(id);
        if let Err(status) = self
            .inner
            .lock(range, exclusive, fail_immediately, &request)
            .await
        {
            self.owner.remove_locks(&[id]);
            self.acquired.pop();
            return Err(status);
        }
        Ok(())
    }

    async fn unlock(&mut self, range: ByteRange, request: &RequestContext) -> Result<(), Status> {
        let request = self.request(request).await?;
        self.inner.unlock(range, &request).await?;
        let id = {
            let locks = self.owner.locks.lock();
            locks
                .iter()
                .find(|lock| lock.range == range && lock.exclusive)
                .or_else(|| locks.iter().find(|lock| lock.range == range))
                .map(|lock| lock.id)
        };
        if let Some(id) = id {
            self.owner.remove_locks(&[id]);
        }
        Ok(())
    }

    async fn settle(
        self: Box<Self>,
        settlement: LockSettlement,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let request = request.with_keepalive(self.admission);
        self.inner.settle(settlement, &request).await?;
        if settlement == LockSettlement::Rollback {
            self.owner.remove_locks(&self.acquired);
        }
        Ok(())
    }
}

impl Inspect for MediatedCaching {
    fn inspect(&self, req: inspect::Request<'_>) {
        let state = self.0.activity.lock();
        req.respond()
            .field("reservations", &self.0.caching)
            .field("files", state.files.len())
            .field("namespace_admissions", state.namespaces)
            .field(
                "active_effects",
                state.files.values().map(|file| file.active).sum::<usize>(),
            );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Caching, LeaseIdentity, Oplock};
    use pal_async::async_test;
    use test_with_tracing::test;

    fn key(file: u64) -> CachingKey {
        CachingKey { file, stream: 0 }
    }

    fn lease(id: u8, state: CachingState) -> CachingRequest {
        CachingRequest::Lease {
            identity: LeaseIdentity {
                authority: [1; 16],
                client_guid: [2; 16],
                key: [id; 16],
            },
            state,
        }
    }

    async fn open(
        cache: &MediatedCaching,
        file: u64,
        requested: CachingRequest,
    ) -> (Arc<MediatedOpen>, CachingGrant) {
        let context = RequestContext::new(file);
        let admission = cache.namespace(&context).await.unwrap();
        admission
            .register(
                key(file),
                AccessMask::FILE_GENERIC_READ.into_bits(),
                true,
                false,
                requested,
            )
            .unwrap()
    }

    fn control(grant: CachingGrant) -> Arc<dyn Caching> {
        match grant {
            CachingGrant::Lease { control, .. } | CachingGrant::Oplock { control, .. } => control,
            CachingGrant::None => panic!("missing caching control"),
        }
    }

    #[async_test]
    async fn namespace_break_allows_flush_and_keeps_native_admission() {
        let cache = MediatedCaching::default();
        let (source, _) = open(&cache, 1, CachingRequest::None).await;
        let (foreign, grant) = open(&cache, 2, lease(2, CachingState::ReadWriteHandle)).await;
        let control = control(grant);
        let context = RequestContext::new(3);
        let mut operation = Box::pin(cache.namespace_request(&source, &context));
        assert!(futures::poll!(&mut operation).is_pending());
        let change = control.wait_for_break(&context).await.unwrap();
        assert_eq!(change.state, CachingState::ReadWrite);

        let other_namespace = cache.namespace(&context).await.unwrap();
        drop(other_namespace);
        let flush = foreign.request(Change::Data, &context).await.unwrap();
        drop(flush);
        control
            .acknowledge(change.id, change.state, &context)
            .await
            .unwrap();
        let accepted = operation.await.unwrap();
        let owned_work = accepted.clone();
        drop(accepted);
        let mut later = Box::pin(cache.namespace(&context));
        assert!(futures::poll!(&mut later).is_pending());
        drop(owned_work);
        drop(later.await.unwrap());
    }

    #[async_test]
    async fn classic_namespace_break_uses_level_two_not_read_write() {
        let cache = MediatedCaching::default();
        let (source, _) = open(&cache, 1, CachingRequest::None).await;
        let (_foreign, grant) = open(&cache, 2, CachingRequest::Oplock(Oplock::Batch)).await;
        let control = control(grant);
        assert_eq!(control.snapshot().state, CachingState::ReadWriteHandle);
        let context = RequestContext::new(3);
        let mut operation = Box::pin(cache.namespace_request(&source, &context));
        assert!(futures::poll!(&mut operation).is_pending());
        let change = control.wait_for_break(&context).await.unwrap();
        assert_eq!(change.state, CachingState::Read);
        control
            .acknowledge(change.id, change.state, &context)
            .await
            .unwrap();
        drop(operation.await.unwrap());
    }

    #[async_test]
    async fn pending_native_effect_denies_new_read_grants_until_actual_completion() {
        let cache = MediatedCaching::default();
        let (writer, _) = open(&cache, 1, CachingRequest::None).await;
        let context = RequestContext::new(2);
        let accepted = writer.request(Change::Data, &context).await.unwrap();
        let owned_work = accepted.clone();
        drop(accepted);
        let (_reader, grant) = open(&cache, 1, lease(3, CachingState::Read)).await;
        let control = control(grant);
        assert_eq!(control.snapshot().state, CachingState::None);
        let (_reader2, _) = open(&cache, 1, lease(3, CachingState::Read)).await;
        assert_eq!(control.snapshot().state, CachingState::None);
        drop(owned_work);
        let (_reader3, _) = open(&cache, 1, lease(3, CachingState::Read)).await;
        assert_eq!(control.snapshot().state, CachingState::Read);
    }

    #[async_test]
    async fn replacement_waits_for_dirty_data_before_admitting_effects() {
        let cache = MediatedCaching::default();
        let (owner, grant) = open(&cache, 1, lease(1, CachingState::ReadWrite)).await;
        let control = control(grant);
        let context = RequestContext::new(2);
        let admission = cache.namespace(&context).await.unwrap();
        let wait = admission
            .prepare_open(
                Some(key(1)),
                AccessMask::FILE_GENERIC_WRITE.into_bits(),
                true,
                false,
                CachingRequest::None,
            )
            .unwrap()
            .unwrap();
        drop(admission);
        let mut waiting = Box::pin(wait.wait(&context));
        assert!(futures::poll!(&mut waiting).is_pending());
        let change = control.wait_for_break(&context).await.unwrap();
        assert_eq!(change.state, CachingState::None);
        let flush = owner.request(Change::Data, &context).await.unwrap();
        drop(flush);
        control
            .acknowledge(change.id, change.state, &context)
            .await
            .unwrap();
        waiting.await.unwrap();
        let admission = cache.namespace(&context).await.unwrap();
        assert!(
            admission
                .prepare_open(
                    Some(key(1)),
                    AccessMask::FILE_GENERIC_WRITE.into_bits(),
                    true,
                    false,
                    CachingRequest::None,
                )
                .unwrap()
                .is_none()
        );
    }

    #[async_test]
    async fn delete_intent_prevents_foreign_handle_cache_reacquisition() {
        let cache = MediatedCaching::default();
        let context = RequestContext::new(1);
        let admission = cache.namespace(&context).await.unwrap();
        let (_deleter, _) = admission
            .register(
                key(1),
                AccessMask::FILE_GENERIC_READ.into_bits(),
                true,
                true,
                CachingRequest::None,
            )
            .unwrap();
        drop(admission);
        let (_reader, grant) = open(&cache, 1, lease(2, CachingState::ReadHandle)).await;
        assert_eq!(control(grant).snapshot().state, CachingState::Read);
        let admission = cache.namespace(&context).await.unwrap();
        let (_classic, grant) = admission
            .register(
                key(1),
                AccessMask::FILE_GENERIC_READ.into_bits(),
                true,
                false,
                CachingRequest::Oplock(Oplock::Batch),
            )
            .unwrap();
        assert_ne!(
            control(grant).snapshot().state,
            CachingState::ReadWriteHandle
        );
    }

    #[async_test]
    async fn rollback_preserves_older_lock_admission_until_exact_unlock() {
        use crate::provider::locking::software::{self, SoftwareLocks};
        let cache = MediatedCaching::default();
        let locks = SoftwareLocks::default();
        let first = locks.open(1u64).unwrap();
        let second = locks.open(1u64).unwrap();
        let (owner, _) = open(&cache, 1, CachingRequest::None).await;
        let (other, _) = open(&cache, 1, CachingRequest::None).await;
        let context = RequestContext::new(1);
        let older = ByteRange {
            offset: 0,
            length: 16,
        };
        let conflict = ByteRange {
            offset: 32,
            length: 16,
        };
        let mut scope = owner.lock_scope(software::scope(Ok(first.clone())));
        scope.lock(older, true, true, &context).await.unwrap();
        scope
            .settle(LockSettlement::Preserve, &context)
            .await
            .unwrap();
        let mut scope = other.lock_scope(software::scope(Ok(second.clone())));
        scope.lock(conflict, true, true, &context).await.unwrap();
        scope
            .settle(LockSettlement::Preserve, &context)
            .await
            .unwrap();
        let mut scope = owner.lock_scope(software::scope(Ok(first.clone())));
        scope.lock(older, false, true, &context).await.unwrap();
        assert_eq!(
            scope.lock(conflict, true, true, &context).await,
            Err(Status::LOCK_NOT_GRANTED)
        );
        scope
            .settle(LockSettlement::Rollback, &context)
            .await
            .unwrap();
        second.close();
        other.close();
        let third = locks.open(1u64).unwrap();
        assert_eq!(
            third.operation(older, true, false, &context).await.err(),
            Some(Status::FILE_LOCK_CONFLICT)
        );
        let (_reader, grant) = open(&cache, 1, lease(4, CachingState::Read)).await;
        let control = control(grant);
        assert_eq!(control.snapshot().state, CachingState::None);
        let mut scope = owner.lock_scope(software::scope(Ok(first)));
        scope.unlock(older, &context).await.unwrap();
        scope
            .settle(LockSettlement::Preserve, &context)
            .await
            .unwrap();
        let (_upgraded, _) = open(&cache, 1, lease(4, CachingState::Read)).await;
        assert_eq!(control.snapshot().state, CachingState::Read);
    }
}
