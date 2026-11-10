// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deterministic scheduling and fault controls around a real filesystem provider.
//!
//! Held calls are announced to the controller. Ordinary passthrough calls only
//! enter bounded recent history, so an unattended TCP test server cannot fill
//! an announcement queue. No file contents are retained in diagnostic records.

pub mod contracts;

use crate::provider::{
    BasicInformation, ByteRange, Caching, CachingBreak, CachingBreakId, CachingGrant,
    CachingRequest, CachingSnapshot, CachingState, ExtendedAttribute, FileControl,
    FileControlResult, FileSystem, FileSystemInformation, LockId, LockScope, LockSettlement,
    Metadata, NotifyResult, OpenError, OpenOptions, Opened, RequestContext, StreamInformation,
};
use crate::security::SecurityDescriptor;
use crate::spec::SecurityInformation;
use crate::spec::{NotifyFilter, Status};
use async_trait::async_trait;
use event_listener::Event;
use futures::FutureExt;
use inspect::Inspect;
use parking_lot::Mutex;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use thiserror::Error;

const CAPACITY: usize = 256;

/// Filesystem operation being controlled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Operation {
    /// Open/create.
    Open,
    /// Open a stream-qualified path.
    OpenStream,
    /// Open with an atomic creation security descriptor.
    OpenSecurity,
    /// Open with an atomic creation EA list.
    OpenExtendedAttributes,
    /// Provider caching break delivery.
    CachingBreak,
    /// Provider caching break completion.
    CachingAck,
    /// Explicit close.
    Close,
    /// Metadata query.
    Metadata,
    /// Filesystem identity, capabilities and capacity query.
    FileSystemInformation,
    /// Selected filesystem control.
    FileControl,
    /// Selected security descriptor query.
    QuerySecurity,
    /// Selected security descriptor update.
    SetSecurity,
    /// Retained extended-attribute snapshot.
    QueryEas,
    /// Atomic extended-attribute mutation.
    SetEas,
    /// File data-stream snapshot.
    QueryStreams,
    /// Data read.
    Read,
    /// Data write.
    Write,
    /// Flush.
    Flush,
    /// Directory listing.
    List,
    /// Length change.
    SetLen,
    /// Allocation reservation or truncation.
    SetAllocationSize,
    /// Per-open I/O mode change.
    SetMode,
    /// Shared delete-disposition change.
    SetDeleteOnClose,
    /// Basic metadata change.
    SetBasic,
    /// Namespace rename or move.
    Rename,
    /// Hard-link creation or replacement.
    Link,
    /// Short-name assignment or removal.
    SetShortName,
    /// Volume identity and extension metadata update.
    SetVolumeObjectId,
    /// Query volume quota control state.
    QuotaControl,
    /// Update volume quota defaults.
    SetQuotaControl,
    /// Snapshot SID-based usage and policy.
    QueryQuotas,
    /// Atomically update SID quota policies.
    SetQuotas,
    /// Directory change notification.
    Notify,
    /// Byte-range lock.
    Lock,
    /// Byte-range unlock.
    Unlock,
    /// Exact acquisition rollback.
    RollbackLock,
    /// Preserve a processed lock-request prefix.
    CommitLocks,
}

/// A manually releasable scheduling point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Before invoking the underlying provider.
    Before,
    /// After obtaining its result but before returning that result.
    After,
}

/// Current execution phase; After means a result exists, not that it succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Waiting to invoke the provider.
    Before,
    /// Provider future is being driven.
    Executing,
    /// Provider result is retained pending completion delivery.
    After,
    /// Completion was returned.
    Completed,
    /// Caller dropped unfinished work.
    Abandoned,
}

/// How cancellation reaches the delegate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Cancellation {
    /// Cancel before invocation; let the delegate handle cancellation during I/O.
    #[default]
    Cooperative,
    /// Model an operation that cannot be cancelled.
    Ignore,
}

/// Controls for an operation. Faults occur before invoking the delegate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Plan {
    /// Hold before execution.
    pub hold_before: bool,
    /// Hold the actual result before delivery.
    pub hold_after: bool,
    /// Cancellation policy, never applied to an already obtained result.
    pub cancellation: Cancellation,
    /// Inject a failing NTSTATUS without filesystem effects.
    pub failure: Option<Status>,
    /// Limit a read/write's actual delegated length, not just its reported count.
    pub transfer_limit: Option<usize>,
}

/// Diagnostic record for one provider call.
#[derive(Debug, Clone)]
pub struct CallInfo {
    /// Controller-local call identity.
    pub id: u64,
    /// Correlation identity; several calls can share one request.
    pub request_id: u64,
    /// Operation.
    pub operation: Operation,
    /// Wrapper-owned open identity, when known.
    pub handle: Option<u64>,
    /// Share-relative name for open, not file contents.
    pub name: Option<String>,
    /// Transfer offset.
    pub offset: Option<u64>,
    /// Original requested transfer length or new file length.
    pub length: Option<u64>,
    /// Current phase.
    pub phase: Phase,
    /// Whether the delegate was invoked.
    pub delegated: bool,
    /// Observed cancellation request.
    pub cancel_requested: bool,
    /// Obtained status, if a result exists.
    pub status: Option<Status>,
    /// Obtained successful transfer length.
    pub transferred: Option<usize>,
}

impl Inspect for CallInfo {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("request_id", self.request_id)
            .field("operation", inspect::AsDebug(self.operation))
            .field("handle", self.handle)
            .field("name", &self.name)
            .field("offset", self.offset)
            .field("length", self.length)
            .field("phase", inspect::AsDebug(self.phase))
            .field("delegated", self.delegated)
            .field("cancel_requested", self.cancel_requested)
            .field("status", inspect::AsDebug(self.status))
            .field("transferred", self.transferred);
    }
}

/// Invalid controller input or expired diagnostic identity.
#[derive(Debug, Error)]
pub enum ControlError {
    /// The operation does not transfer file data.
    #[error("transfer limits only apply to reads and writes")]
    InvalidTransferLimit,
    /// Failure injection must not manufacture successful results.
    #[error("fault status must be an error: {0}")]
    InvalidFailure(Status),
    /// Bounded queued-plan storage is full.
    #[error("controlled provider plan queue is full")]
    QueueFull,
    /// The call is not active or present in recent history.
    #[error("unknown controlled provider call {0}")]
    UnknownCall(u64),
    /// The selected gate was not configured.
    #[error("gate {1:?} is not held for call {0}")]
    GateNotHeld(u64, Gate),
    /// An operation was dropped instead of completed.
    #[error("controlled provider call {0} was abandoned")]
    Abandoned(u64),
}

struct ActiveCall {
    info: CallInfo,
    request: RequestContext,
    plan: Plan,
    before_released: bool,
    after_released: bool,
}

impl ActiveCall {
    fn snapshot(&self) -> CallInfo {
        let mut info = self.info.clone();
        info.cancel_requested = self.request.is_cancelled();
        info
    }
}

struct State {
    next_id: u64,
    defaults: BTreeMap<Operation, Plan>,
    next: BTreeMap<Operation, VecDeque<Plan>>,
    active: BTreeMap<u64, ActiveCall>,
    announcements: VecDeque<CallInfo>,
    history: VecDeque<CallInfo>,
}

struct Shared {
    state: Mutex<State>,
    changed: Event,
}

/// Independent per-call release control and bounded inspectable diagnostics.
#[derive(Clone)]
pub struct Controller(Arc<Shared>);

impl Controller {
    fn new() -> Self {
        Self(Arc::new(Shared {
            state: Mutex::new(State {
                next_id: 1,
                defaults: BTreeMap::new(),
                next: BTreeMap::new(),
                active: BTreeMap::new(),
                announcements: VecDeque::new(),
                history: VecDeque::new(),
            }),
            changed: Event::new(),
        }))
    }

    fn validate(operation: Operation, plan: Plan) -> Result<(), ControlError> {
        if plan.transfer_limit.is_some() && !matches!(operation, Operation::Read | Operation::Write)
        {
            return Err(ControlError::InvalidTransferLimit);
        }
        if let Some(status) = plan.failure {
            if !status.is_error() {
                return Err(ControlError::InvalidFailure(status));
            }
        }
        Ok(())
    }

    /// Change defaults for future calls; already admitted calls keep their plans.
    pub fn set_plan(&self, operation: Operation, plan: Plan) -> Result<(), ControlError> {
        Self::validate(operation, plan)?;
        self.0.state.lock().defaults.insert(operation, plan);
        Ok(())
    }

    /// Override the next call of this operation, ahead of its default plan.
    pub fn plan_next(&self, operation: Operation, plan: Plan) -> Result<(), ControlError> {
        Self::validate(operation, plan)?;
        let mut state = self.0.state.lock();
        if state.next.values().map(VecDeque::len).sum::<usize>() >= CAPACITY {
            return Err(ControlError::QueueFull);
        }
        state.next.entry(operation).or_default().push_back(plan);
        Ok(())
    }

    /// Receive the next held-call announcement. Use snapshot for its current phase.
    pub async fn next_call(&self) -> CallInfo {
        loop {
            let listener = self.0.changed.listen();
            if let Some(call) = self.try_next_call() {
                return call;
            }
            listener.await;
        }
    }

    /// Poll held-call announcements without waiting.
    pub fn try_next_call(&self) -> Option<CallInfo> {
        self.0.state.lock().announcements.pop_front()
    }

    /// Release one configured gate; this never invokes the delegate itself.
    pub fn release(&self, id: u64, gate: Gate) -> Result<(), ControlError> {
        {
            let mut state = self.0.state.lock();
            let call = state
                .active
                .get_mut(&id)
                .ok_or(ControlError::UnknownCall(id))?;
            match gate {
                Gate::Before if call.plan.hold_before => call.before_released = true,
                Gate::After if call.plan.hold_after => call.after_released = true,
                _ => return Err(ControlError::GateNotHeld(id, gate)),
            }
        }
        self.0.changed.notify(usize::MAX);
        Ok(())
    }

    /// Snapshot an active or recently completed call.
    pub fn snapshot(&self, id: u64) -> Result<CallInfo, ControlError> {
        let state = self.0.state.lock();
        state
            .active
            .get(&id)
            .map(ActiveCall::snapshot)
            .or_else(|| state.history.iter().find(|call| call.id == id).cloned())
            .ok_or(ControlError::UnknownCall(id))
    }

    /// Wait for this phase or a later one, without wall-clock sleeps.
    pub async fn wait_for_phase(&self, id: u64, phase: Phase) -> Result<CallInfo, ControlError> {
        loop {
            let listener = self.0.changed.listen();
            let call = self.snapshot(id)?;
            if call.phase == Phase::Abandoned {
                return Err(ControlError::Abandoned(id));
            }
            if call.phase >= phase {
                return Ok(call);
            }
            listener.await;
        }
    }

    /// Active calls and the most recent 256 terminal calls, ordered by call ID.
    pub fn calls(&self) -> Vec<CallInfo> {
        let state = self.0.state.lock();
        let mut calls: Vec<_> = state
            .history
            .iter()
            .cloned()
            .chain(state.active.values().map(ActiveCall::snapshot))
            .collect();
        calls.sort_by_key(|call| call.id);
        calls
    }

    fn begin(
        &self,
        operation: Operation,
        handle: Option<u64>,
        name: Option<&str>,
        offset: Option<u64>,
        length: Option<u64>,
        request: &RequestContext,
    ) -> Result<Call, Status> {
        let mut state = self.0.state.lock();
        let plan = state
            .next
            .get(&operation)
            .and_then(|plans| plans.front())
            .copied()
            .or_else(|| state.defaults.get(&operation).copied())
            .unwrap_or_default();
        if state.active.len() >= CAPACITY
            || ((plan.hold_before || plan.hold_after) && state.announcements.len() >= CAPACITY)
        {
            return Err(Status::INSUFFICIENT_RESOURCES);
        }
        let id = state.next_id;
        state.next_id = id.checked_add(1).ok_or(Status::INSUFFICIENT_RESOURCES)?;
        if let Some(plans) = state.next.get_mut(&operation) {
            plans.pop_front();
        }
        let info = CallInfo {
            id,
            request_id: request.id(),
            operation,
            handle,
            name: name.map(str::to_owned),
            offset,
            length,
            phase: Phase::Before,
            delegated: false,
            cancel_requested: request.is_cancelled(),
            status: None,
            transferred: None,
        };
        if plan.hold_before || plan.hold_after {
            state.announcements.push_back(info.clone());
        }
        state.active.insert(
            id,
            ActiveCall {
                info,
                request: request.clone(),
                plan,
                before_released: !plan.hold_before,
                after_released: !plan.hold_after,
            },
        );
        drop(state);
        self.0.changed.notify(usize::MAX);
        Ok(Call {
            controller: self.clone(),
            id,
            request: request.clone(),
            plan,
            finished: false,
        })
    }
}

impl Inspect for Controller {
    fn inspect(&self, req: inspect::Request<'_>) {
        let calls = self.calls();
        let (active, announcements, plans) = {
            let state = self.0.state.lock();
            (
                state.active.len(),
                state.announcements.len(),
                state.next.values().map(VecDeque::len).sum::<usize>(),
            )
        };
        req.respond()
            .field("capacity", CAPACITY)
            .field("active_calls", active)
            .field("announcements", announcements)
            .field("queued_plans", plans)
            .field(
                "calls",
                inspect::iter_by_key(calls.iter().map(|call| (call.id, call))),
            );
    }
}

struct Call {
    controller: Controller,
    id: u64,
    request: RequestContext,
    plan: Plan,
    finished: bool,
}

impl Call {
    async fn gate(&self, gate: Gate) -> Result<(), Status> {
        loop {
            let listener = self.controller.0.changed.listen();
            let released = {
                let state = self.controller.0.state.lock();
                let call = &state.active[&self.id];
                match gate {
                    Gate::Before => call.before_released,
                    Gate::After => call.after_released,
                }
            };
            if released {
                return Ok(());
            }
            if gate == Gate::Before && self.plan.cancellation == Cancellation::Cooperative {
                let mut listener = std::pin::pin!(listener.fuse());
                let mut cancelled = std::pin::pin!(self.request.cancelled().fuse());
                futures::select! {
                    () = listener => {}
                    () = cancelled => return Err(Status::CANCELLED),
                }
            } else {
                listener.await;
            }
        }
    }

    fn update(&self, update: impl FnOnce(&mut CallInfo)) {
        update(
            &mut self
                .controller
                .0
                .state
                .lock()
                .active
                .get_mut(&self.id)
                .expect("active controlled call")
                .info,
        );
        self.controller.0.changed.notify(usize::MAX);
    }

    async fn prepare(&mut self) -> Result<RequestContext, Status> {
        self.prepare_inner(false).await
    }

    async fn prepare_inner(&mut self, register_on_cancel: bool) -> Result<RequestContext, Status> {
        let error = match self.gate(Gate::Before).await {
            Err(Status::CANCELLED) if register_on_cancel => self.plan.failure,
            Err(status) => Some(status),
            Ok(())
                if !register_on_cancel
                    && self.plan.cancellation == Cancellation::Cooperative
                    && self.request.is_cancelled() =>
            {
                Some(Status::CANCELLED)
            }
            Ok(()) => self.plan.failure,
        };
        if let Some(error) = error {
            self.update(|info| {
                info.phase = Phase::After;
                info.status = Some(error);
            });
            self.gate(Gate::After).await?;
            self.finish(Phase::Completed);
            return Err(error);
        }
        self.update(|info| {
            info.phase = Phase::Executing;
            info.delegated = true;
        });
        Ok(match self.plan.cancellation {
            Cancellation::Cooperative => self.request.clone(),
            Cancellation::Ignore => RequestContext::new(self.request.id()),
        })
    }

    async fn complete<T>(
        self,
        result: Result<T, Status>,
        transferred: Option<usize>,
    ) -> Result<T, Status> {
        let status = result.as_ref().err().copied().unwrap_or(Status::SUCCESS);
        self.complete_with_status(result, status, transferred).await
    }

    async fn complete_with_status<T, E: From<Status>>(
        mut self,
        result: Result<T, E>,
        status: Status,
        transferred: Option<usize>,
    ) -> Result<T, E> {
        self.update(|info| {
            info.phase = Phase::After;
            info.status = Some(status);
            info.transferred = transferred;
        });
        self.gate(Gate::After).await?;
        self.finish(Phase::Completed);
        result
    }

    fn finish(&mut self, phase: Phase) {
        let mut state = self.controller.0.state.lock();
        let mut info = state
            .active
            .remove(&self.id)
            .expect("active controlled call")
            .snapshot();
        info.phase = phase;
        if state.history.len() == CAPACITY {
            state.history.pop_front();
        }
        state.history.push_back(info);
        self.finished = true;
        drop(state);
        self.controller.0.changed.notify(usize::MAX);
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(Phase::Abandoned);
        }
    }
}

/// Provider-owned handle plus a diagnostic identity; no host handle is required.
pub struct ControlledFile<F> {
    inner: F,
    id: u64,
}

/// Real provider semantics with optional deterministic controls.
#[derive(Clone)]
pub struct ControlledFs<B> {
    backend: B,
    controller: Controller,
}

impl<B> ControlledFs<B> {
    /// Defaults to ordinary passthrough with bounded recent-call diagnostics.
    pub fn new(backend: B) -> (Self, Controller) {
        let controller = Controller::new();
        (
            Self {
                backend,
                controller: controller.clone(),
            },
            controller,
        )
    }
}

impl<B: Inspect> Inspect for ControlledFs<B> {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("backend", &self.backend)
            .field("control", &self.controller);
    }
}

struct ControlledCaching {
    inner: Arc<dyn Caching>,
    controller: Controller,
    handle: u64,
}

impl Inspect for ControlledCaching {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("backend", self.inner.as_ref())
            .field("handle", self.handle)
            .field("control", &self.controller);
    }
}

#[async_trait]
impl Caching for ControlledCaching {
    fn snapshot(&self) -> CachingSnapshot {
        self.inner.snapshot()
    }
    async fn wait_for_break(&self, r: &RequestContext) -> Result<CachingBreak, Status> {
        let mut call = self.controller.begin(
            Operation::CachingBreak,
            Some(self.handle),
            None,
            None,
            None,
            r,
        )?;
        let context = call.prepare().await?;
        let result = self.inner.wait_for_break(&context).await;
        call.complete(result, None).await
    }

    async fn acknowledge(
        &self,
        id: CachingBreakId,
        state: CachingState,
        r: &RequestContext,
    ) -> Result<CachingState, Status> {
        let mut call = self.controller.begin(
            Operation::CachingAck,
            Some(self.handle),
            None,
            None,
            None,
            r,
        )?;
        let context = call.prepare().await?;
        let result = self.inner.acknowledge(id, state, &context).await;
        call.complete(result, None).await
    }
}

struct ControlledLockScope<'a> {
    inner: Box<dyn LockScope + 'a>,
    controller: Controller,
    handle: u64,
}

#[async_trait]
impl LockScope for ControlledLockScope<'_> {
    async fn lock(
        &mut self,
        range: ByteRange,
        exclusive: bool,
        fail_immediately: bool,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let mut call = self.controller.begin(
            Operation::Lock,
            Some(self.handle),
            None,
            Some(range.offset),
            Some(range.length),
            request,
        )?;
        let context = call.prepare().await?;
        let result = self
            .inner
            .lock(range, exclusive, fail_immediately, &context)
            .await;
        call.complete(result, None).await
    }

    async fn unlock(&mut self, range: ByteRange, request: &RequestContext) -> Result<(), Status> {
        let mut call = self.controller.begin(
            Operation::Unlock,
            Some(self.handle),
            None,
            Some(range.offset),
            Some(range.length),
            request,
        )?;
        let context = call.prepare().await?;
        let result = self.inner.unlock(range, &context).await;
        call.complete(result, None).await
    }

    async fn settle(
        self: Box<Self>,
        settlement: LockSettlement,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let operation = match settlement {
            LockSettlement::Preserve => Operation::CommitLocks,
            LockSettlement::Rollback => Operation::RollbackLock,
        };
        let mut call =
            self.controller
                .begin(operation, Some(self.handle), None, None, None, request)?;
        let context = call.prepare().await?;
        let result = self.inner.settle(settlement, &context).await;
        call.complete(result, None).await
    }
}

#[async_trait]
impl<B: FileSystem> FileSystem for ControlledFs<B> {
    type File = ControlledFile<B::File>;

    fn lock_request<'a>(&'a self, file: &'a Self::File) -> Box<dyn LockScope + 'a> {
        Box::new(ControlledLockScope {
            inner: self.backend.lock_request(&file.inner),
            controller: self.controller.clone(),
            handle: file.id,
        })
    }

    fn supports_leases(&self) -> bool {
        self.backend.supports_leases()
    }

    async fn link(
        &self,
        file: &Self::File,
        name: &str,
        replace: bool,
        r: &RequestContext,
    ) -> Result<(), Status> {
        let mut call =
            self.controller
                .begin(Operation::Link, Some(file.id), Some(name), None, None, r)?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .link(&file.inner, name, replace, &context)
            .await;
        call.complete(result, None).await
    }

    async fn quota_control(
        &self,
        file: &Self::File,
        r: &RequestContext,
    ) -> Result<crate::provider::VolumeControlInformation, Status> {
        let mut call =
            self.controller
                .begin(Operation::QuotaControl, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self.backend.quota_control(&file.inner, &context).await;
        call.complete(result, None).await
    }
    async fn set_quota_control(
        &self,
        file: &Self::File,
        information: crate::provider::VolumeControlInformation,
        r: &RequestContext,
    ) -> Result<(), Status> {
        let mut call = self.controller.begin(
            Operation::SetQuotaControl,
            Some(file.id),
            None,
            None,
            None,
            r,
        )?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .set_quota_control(&file.inner, information, &context)
            .await;
        call.complete(result, None).await
    }
    async fn query_quotas(
        &self,
        file: &Self::File,
        r: &RequestContext,
    ) -> Result<Vec<crate::provider::QuotaInformation>, Status> {
        let mut call =
            self.controller
                .begin(Operation::QueryQuotas, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self.backend.query_quotas(&file.inner, &context).await;
        call.complete(result, None).await
    }
    async fn set_quotas(
        &self,
        file: &Self::File,
        information: &[crate::provider::QuotaInformation],
        r: &RequestContext,
    ) -> Result<(), Status> {
        let mut call =
            self.controller
                .begin(Operation::SetQuotas, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .set_quotas(&file.inner, information, &context)
            .await;
        call.complete(result, None).await
    }
    async fn set_volume_object_id(
        &self,
        file: &Self::File,
        information: crate::provider::VolumeObjectInformation,
        r: &RequestContext,
    ) -> Result<(), Status> {
        let mut call = self.controller.begin(
            Operation::SetVolumeObjectId,
            Some(file.id),
            None,
            None,
            None,
            r,
        )?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .set_volume_object_id(&file.inner, information, &context)
            .await;
        call.complete(result, None).await
    }
    async fn set_short_name(
        &self,
        file: &Self::File,
        name: &str,
        r: &RequestContext,
    ) -> Result<(), Status> {
        let mut call = self.controller.begin(
            Operation::SetShortName,
            Some(file.id),
            Some(name),
            None,
            None,
            r,
        )?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .set_short_name(&file.inner, name, &context)
            .await;
        call.complete(result, None).await
    }
    async fn rename(
        &self,
        file: &Self::File,
        name: &str,
        replace: bool,
        r: &RequestContext,
    ) -> Result<(), Status> {
        let mut call =
            self.controller
                .begin(Operation::Rename, Some(file.id), Some(name), None, None, r)?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .rename(&file.inner, name, replace, &context)
            .await;
        call.complete(result, None).await
    }
    async fn lock(
        &self,
        file: &Self::File,
        range: ByteRange,
        exclusive: bool,
        fail_immediately: bool,
        r: &RequestContext,
    ) -> Result<LockId, Status> {
        let mut call = self.controller.begin(
            Operation::Lock,
            Some(file.id),
            None,
            Some(range.offset),
            Some(range.length),
            r,
        )?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .lock(&file.inner, range, exclusive, fail_immediately, &context)
            .await;
        call.complete(result, None).await
    }

    async fn rollback_lock(
        &self,
        file: &Self::File,
        lock: LockId,
        r: &RequestContext,
    ) -> Result<(), Status> {
        let mut call =
            self.controller
                .begin(Operation::RollbackLock, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .rollback_lock(&file.inner, lock, &context)
            .await;
        call.complete(result, None).await
    }

    async fn unlock(
        &self,
        file: &Self::File,
        range: ByteRange,
        r: &RequestContext,
    ) -> Result<(), Status> {
        let mut call = self.controller.begin(
            Operation::Unlock,
            Some(file.id),
            None,
            Some(range.offset),
            Some(range.length),
            r,
        )?;
        let context = call.prepare().await?;
        let result = self.backend.unlock(&file.inner, range, &context).await;
        call.complete(result, None).await
    }

    async fn notify(
        &self,
        file: &Self::File,
        filter: NotifyFilter,
        tree: bool,
        output_length: usize,
        r: &RequestContext,
    ) -> Result<NotifyResult, Status> {
        let mut call = self.controller.begin(
            Operation::Notify,
            Some(file.id),
            None,
            None,
            Some(output_length as u64),
            r,
        )?;
        // Canceling the waiter must not prevent the open's first registration.
        let context = call.prepare_inner(true).await?;
        let result = self
            .backend
            .notify(&file.inner, filter, tree, output_length, &context)
            .await;
        call.complete(result, None).await
    }

    async fn open(
        &self,
        name: &str,
        options: OpenOptions<'_>,
        r: &RequestContext,
    ) -> Result<(Self::File, u32), Status> {
        self.open_with_reparse(name, options, r)
            .await
            .map_err(|error| error.status())
    }

    async fn open_with_reparse(
        &self,
        name: &str,
        options: OpenOptions<'_>,
        r: &RequestContext,
    ) -> Result<(Self::File, u32), OpenError> {
        let opened = self
            .open_with_caching(name, options, CachingRequest::None, r)
            .await?;
        Ok((opened.file, opened.action))
    }

    async fn open_with_caching(
        &self,
        name: &str,
        options: OpenOptions<'_>,
        caching: CachingRequest,
        r: &RequestContext,
    ) -> Result<Opened<Self::File>, OpenError> {
        let mut call = self.controller.begin(
            if options.security.is_some() {
                Operation::OpenSecurity
            } else if options.extended_attributes.is_some() {
                Operation::OpenExtendedAttributes
            } else if name.contains(':') {
                Operation::OpenStream
            } else {
                Operation::Open
            },
            None,
            Some(name),
            None,
            None,
            r,
        )?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .open_with_caching(name, options, caching, &context)
            .await
            .map(|opened| {
                let wrap = |inner| -> Arc<dyn Caching> {
                    Arc::new(ControlledCaching {
                        inner,
                        controller: self.controller.clone(),
                        handle: call.id,
                    })
                };
                let caching = match opened.caching {
                    CachingGrant::None => CachingGrant::None,
                    CachingGrant::Oplock { level, control } => CachingGrant::Oplock {
                        level,
                        control: wrap(control),
                    },
                    CachingGrant::Lease {
                        identity,
                        state,
                        breaking,
                        control,
                    } => CachingGrant::Lease {
                        identity,
                        state,
                        breaking,
                        control: wrap(control),
                    },
                };
                Opened {
                    file: ControlledFile {
                        inner: opened.file,
                        id: call.id,
                    },
                    action: opened.action,
                    caching,
                }
            });
        if result.is_ok() {
            call.update(|info| info.handle = Some(call.id));
        }
        let status = result
            .as_ref()
            .err()
            .map_or(Status::SUCCESS, OpenError::status);
        call.complete_with_status(result, status, None).await
    }

    async fn close(&self, file: &Self::File, r: &RequestContext) -> Result<(), Status> {
        let mut call =
            self.controller
                .begin(Operation::Close, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self.backend.close(&file.inner, &context).await;
        call.complete(result, None).await
    }

    async fn metadata(&self, file: &Self::File, r: &RequestContext) -> Result<Metadata, Status> {
        let mut call =
            self.controller
                .begin(Operation::Metadata, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self.backend.metadata(&file.inner, &context).await;
        call.complete(result, None).await
    }

    async fn filesystem_information(
        &self,
        file: &Self::File,
        r: &RequestContext,
    ) -> Result<FileSystemInformation, Status> {
        let mut call = self.controller.begin(
            Operation::FileSystemInformation,
            Some(file.id),
            None,
            None,
            None,
            r,
        )?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .filesystem_information(&file.inner, &context)
            .await;
        call.complete(result, None).await
    }

    async fn file_control(
        &self,
        file: &Self::File,
        control: FileControl<'_>,
        r: &RequestContext,
    ) -> Result<FileControlResult, Status> {
        let mut call =
            self.controller
                .begin(Operation::FileControl, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .file_control(&file.inner, control, &context)
            .await;
        call.complete(result, None).await
    }

    async fn query_eas(
        &self,
        file: &Self::File,
        r: &RequestContext,
    ) -> Result<Vec<ExtendedAttribute>, Status> {
        let mut call =
            self.controller
                .begin(Operation::QueryEas, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self.backend.query_eas(&file.inner, &context).await;
        call.complete(result, None).await
    }

    async fn set_eas(
        &self,
        file: &Self::File,
        attributes: &[ExtendedAttribute],
        r: &RequestContext,
    ) -> Result<(), Status> {
        let mut call =
            self.controller
                .begin(Operation::SetEas, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .set_eas(&file.inner, attributes, &context)
            .await;
        call.complete(result, None).await
    }

    async fn query_streams(
        &self,
        file: &Self::File,
        r: &RequestContext,
    ) -> Result<Vec<StreamInformation>, Status> {
        let mut call =
            self.controller
                .begin(Operation::QueryStreams, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self.backend.query_streams(&file.inner, &context).await;
        call.complete(result, None).await
    }

    async fn query_security(
        &self,
        file: &Self::File,
        information: SecurityInformation,
        r: &RequestContext,
    ) -> Result<SecurityDescriptor, Status> {
        let mut call =
            self.controller
                .begin(Operation::QuerySecurity, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .query_security(&file.inner, information, &context)
            .await;
        call.complete(result, None).await
    }

    async fn set_security(
        &self,
        file: &Self::File,
        information: SecurityInformation,
        descriptor: &SecurityDescriptor,
        r: &RequestContext,
    ) -> Result<(), Status> {
        let mut call =
            self.controller
                .begin(Operation::SetSecurity, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .set_security(&file.inner, information, descriptor, &context)
            .await;
        call.complete(result, None).await
    }

    async fn read(
        &self,
        file: &Self::File,
        offset: u64,
        length: usize,
        r: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let mut call = self.controller.begin(
            Operation::Read,
            Some(file.id),
            None,
            Some(offset),
            Some(length as u64),
            r,
        )?;
        let context = call.prepare().await?;
        let length = call.plan.transfer_limit.unwrap_or(length).min(length);
        let result = self
            .backend
            .read(&file.inner, offset, length, &context)
            .await;
        let transferred = result.as_ref().ok().map(Vec::len);
        call.complete(result, transferred).await
    }

    async fn write(
        &self,
        file: &Self::File,
        offset: u64,
        data: &[u8],
        r: &RequestContext,
    ) -> Result<usize, Status> {
        let mut call = self.controller.begin(
            Operation::Write,
            Some(file.id),
            None,
            Some(offset),
            Some(data.len() as u64),
            r,
        )?;
        let context = call.prepare().await?;
        let length = call
            .plan
            .transfer_limit
            .unwrap_or(data.len())
            .min(data.len());
        let result = self
            .backend
            .write(&file.inner, offset, &data[..length], &context)
            .await;
        let transferred = result.as_ref().ok().copied();
        call.complete(result, transferred).await
    }

    async fn flush(&self, file: &Self::File, r: &RequestContext) -> Result<(), Status> {
        let mut call =
            self.controller
                .begin(Operation::Flush, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self.backend.flush(&file.inner, &context).await;
        call.complete(result, None).await
    }

    async fn list(&self, file: &Self::File, r: &RequestContext) -> Result<Vec<Metadata>, Status> {
        let mut call =
            self.controller
                .begin(Operation::List, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self.backend.list(&file.inner, &context).await;
        call.complete(result, None).await
    }

    async fn set_len(
        &self,
        file: &Self::File,
        length: u64,
        r: &RequestContext,
    ) -> Result<(), Status> {
        let mut call = self.controller.begin(
            Operation::SetLen,
            Some(file.id),
            None,
            None,
            Some(length),
            r,
        )?;
        let context = call.prepare().await?;
        let result = self.backend.set_len(&file.inner, length, &context).await;
        call.complete(result, None).await
    }

    async fn set_allocation_size(
        &self,
        file: &Self::File,
        length: u64,
        r: &RequestContext,
    ) -> Result<(), Status> {
        let mut call = self.controller.begin(
            Operation::SetAllocationSize,
            Some(file.id),
            None,
            None,
            Some(length),
            r,
        )?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .set_allocation_size(&file.inner, length, &context)
            .await;
        call.complete(result, None).await
    }

    async fn set_mode(
        &self,
        file: &Self::File,
        mode: u32,
        r: &RequestContext,
    ) -> Result<u32, Status> {
        let mut call =
            self.controller
                .begin(Operation::SetMode, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self.backend.set_mode(&file.inner, mode, &context).await;
        call.complete(result, None).await
    }

    async fn set_delete_on_close(
        &self,
        file: &Self::File,
        delete: bool,
        r: &RequestContext,
    ) -> Result<(), Status> {
        let mut call = self.controller.begin(
            Operation::SetDeleteOnClose,
            Some(file.id),
            None,
            None,
            None,
            r,
        )?;
        let context = call.prepare().await?;
        let result = self
            .backend
            .set_delete_on_close(&file.inner, delete, &context)
            .await;
        call.complete(result, None).await
    }

    async fn set_basic(
        &self,
        file: &Self::File,
        info: BasicInformation,
        r: &RequestContext,
    ) -> Result<(), Status> {
        let mut call =
            self.controller
                .begin(Operation::SetBasic, Some(file.id), None, None, None, r)?;
        let context = call.prepare().await?;
        let result = self.backend.set_basic(&file.inner, info, &context).await;
        call.complete(result, None).await
    }
}
