// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::memory::MemoryFile;
use crate::provider::{
    Caching, CachingBreak, CachingBreakId, CachingGrant, CachingRequest, CachingSnapshot,
    CachingState, LeaseIdentity, Opened, Oplock,
};
use crate::test_support::{ControlledFs, Gate, Operation, Phase, Plan};
use async_trait::async_trait;
use futures::FutureExt;
use test_with_tracing::test;

#[derive(Default)]
struct BreakState {
    opens: usize,
    pending: Option<CachingBreak>,
    delivered: bool,
    next: u64,
    rights: CachingState,
    failure: Option<Status>,
}

#[derive(Default)]
struct BreakControl {
    state: Mutex<BreakState>,
    changed: Event,
}

impl BreakControl {
    fn indicate(&self, rights: CachingState) -> CachingBreak {
        let mut state = self.state.lock();
        assert!(state.pending.is_none());
        state.next += 1;
        let change = CachingBreak {
            id: CachingBreakId(state.next),
            state: rights,
        };
        state.pending = Some(change);
        state.delivered = false;
        self.changed.notify(usize::MAX);
        change
    }

    fn release(&self) {
        let mut state = self.state.lock();
        state.opens -= 1;
        if state.opens == 0 {
            state.pending = None;
            state.rights = CachingState::None;
        }
        self.changed.notify(usize::MAX);
    }
}

impl Inspect for BreakControl {
    fn inspect(&self, req: inspect::Request<'_>) {
        let state = self.state.lock();
        req.respond()
            .field("opens", state.opens)
            .field("rights", inspect::AsDebug(state.rights))
            .field("pending", inspect::AsDebug(state.pending));
    }
}

#[async_trait]
impl Caching for BreakControl {
    fn snapshot(&self) -> CachingSnapshot {
        let state = self.state.lock();
        CachingSnapshot {
            instance: 1,
            state: state.rights,
            breaking: state.pending.is_some(),
        }
    }

    async fn wait_for_break(&self, request: &RequestContext) -> Result<CachingBreak, Status> {
        loop {
            let listener = self.changed.listen();
            {
                let mut state = self.state.lock();
                if state.opens == 0 {
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
            let mut listener = std::pin::pin!(listener.fuse());
            let mut cancelled = std::pin::pin!(request.cancelled().fuse());
            futures::select! {
                () = listener => {}
                () = cancelled => {}
            }
        }
    }

    async fn acknowledge(
        &self,
        id: CachingBreakId,
        rights: CachingState,
        request: &RequestContext,
    ) -> Result<CachingState, Status> {
        let mut state = self.state.lock();
        if state.opens == 0 {
            return Err(Status::FILE_CLOSED);
        }
        let change = state.pending.ok_or(Status::INVALID_DEVICE_STATE)?;
        if change.id != id || !state.delivered {
            return Err(Status::INVALID_DEVICE_STATE);
        }
        if request.is_cancelled() {
            return Err(Status::CANCELLED);
        }
        if let Some(error) = state.failure.take() {
            return Err(error);
        }
        // The test provider only accepts the requested state or full revocation.
        if rights != change.state && rights != CachingState::None {
            return Err(Status::INVALID_PARAMETER);
        }
        state.rights = rights;
        state.pending = None;
        Ok(rights)
    }
}

struct CachedFile {
    inner: MemoryFile,
    control: Arc<BreakControl>,
    closed: AtomicBool,
}

impl CachedFile {
    fn release(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.control.release();
        }
    }
}

impl Drop for CachedFile {
    fn drop(&mut self) {
        self.release();
    }
}

/// A manually driven provider boundary, not a software coherence implementation.
struct CachingFs {
    memory: MemoryFs,
    control: Arc<BreakControl>,
    requests: Mutex<Vec<CachingRequest>>,
    grant_unrequested: bool,
}

impl CachingFs {
    fn new() -> Self {
        Self {
            memory: MemoryFs::new(1024, 16),
            control: Arc::default(),
            requests: Mutex::default(),
            grant_unrequested: false,
        }
    }
}

impl Inspect for CachingFs {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("memory", &self.memory)
            .field("caching", self.control.as_ref());
    }
}

#[async_trait]
impl FileSystem for CachingFs {
    type File = CachedFile;

    async fn open(
        &self,
        name: &str,
        options: OpenOptions<'_>,
        r: &RequestContext,
    ) -> Result<(Self::File, u32), Status> {
        let opened = self
            .open_with_caching(name, options, CachingRequest::None, r)
            .await
            .map_err(|error| error.status())?;
        Ok((opened.file, opened.action))
    }

    async fn open_with_caching(
        &self,
        name: &str,
        options: OpenOptions<'_>,
        caching: CachingRequest,
        r: &RequestContext,
    ) -> Result<Opened<Self::File>, OpenError> {
        self.requests.lock().push(caching);
        let (inner, action) = self.memory.open_with_reparse(name, options, r).await?;
        let (rights, grant) = match caching {
            CachingRequest::None if !self.grant_unrequested => {
                (CachingState::None, CachingGrant::None)
            }
            CachingRequest::None | CachingRequest::Oplock(_) => (
                CachingState::Read,
                CachingGrant::Oplock {
                    level: Oplock::LevelII,
                    control: self.control.clone(),
                },
            ),
            CachingRequest::Lease { identity, state } => (
                state,
                CachingGrant::Lease {
                    identity,
                    state,
                    breaking: self.control.state.lock().pending.is_some(),
                    control: self.control.clone(),
                },
            ),
        };
        {
            let mut state = self.control.state.lock();
            state.opens += 1;
            state.rights = rights;
        }
        Ok(Opened {
            file: CachedFile {
                inner,
                control: self.control.clone(),
                closed: AtomicBool::new(false),
            },
            action,
            caching: grant,
        })
    }

    async fn close(&self, file: &Self::File, r: &RequestContext) -> Result<(), Status> {
        self.memory.close(&file.inner, r).await?;
        file.release();
        Ok(())
    }

    async fn metadata(&self, file: &Self::File, r: &RequestContext) -> Result<Metadata, Status> {
        self.memory.metadata(&file.inner, r).await
    }

    async fn read(
        &self,
        file: &Self::File,
        offset: u64,
        length: usize,
        r: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        self.memory.read(&file.inner, offset, length, r).await
    }

    async fn write(
        &self,
        file: &Self::File,
        offset: u64,
        bytes: &[u8],
        r: &RequestContext,
    ) -> Result<usize, Status> {
        self.memory.write(&file.inner, offset, bytes, r).await
    }

    async fn flush(&self, file: &Self::File, r: &RequestContext) -> Result<(), Status> {
        self.memory.flush(&file.inner, r).await
    }

    async fn list(&self, file: &Self::File, r: &RequestContext) -> Result<Vec<Metadata>, Status> {
        self.memory.list(&file.inner, r).await
    }

    async fn set_len(
        &self,
        file: &Self::File,
        length: u64,
        r: &RequestContext,
    ) -> Result<(), Status> {
        self.memory.set_len(&file.inner, length, r).await
    }

    async fn set_delete_on_close(
        &self,
        file: &Self::File,
        delete: bool,
        r: &RequestContext,
    ) -> Result<(), Status> {
        self.memory
            .set_delete_on_close(&file.inner, delete, r)
            .await
    }

    async fn set_basic(
        &self,
        file: &Self::File,
        info: BasicInformation,
        r: &RequestContext,
    ) -> Result<(), Status> {
        self.memory.set_basic(&file.inner, info, r).await
    }
}

fn options() -> OpenOptions<'static> {
    OpenOptions {
        access: AccessMask::FILE_ALL_ACCESS.into_bits(),
        share_access: ShareAccess::ALL.into_bits(),
        disposition: CreateDisposition::OPEN_IF.0,
        options: 0,
        attributes: 0,
        allocation_size: 0,
        security: None,
        extended_attributes: None,
    }
}

fn lease() -> CachingRequest {
    CachingRequest::Lease {
        identity: LeaseIdentity {
            authority: [0x20; 16],
            client_guid: [0x31; 16],
            key: [0x42; 16],
        },
        state: CachingState::ReadWriteHandle,
    }
}

fn grant_control(grant: CachingGrant) -> Arc<dyn Caching> {
    match grant {
        CachingGrant::None => panic!("expected a caching grant"),
        CachingGrant::Oplock { control, .. } | CachingGrant::Lease { control, .. } => control,
    }
}

#[test]
fn ordinary_providers_decline_caching_without_changing_open_effects() {
    block_on(async {
        let memory = MemoryFs::new(1024, 16);
        let r = RequestContext::new(1);
        for caching in [
            CachingRequest::None,
            CachingRequest::Oplock(Oplock::Batch),
            lease(),
        ] {
            let opened = memory
                .open_with_caching("file", options(), caching, &r)
                .await
                .unwrap();
            assert!(matches!(opened.caching, CachingGrant::None));
            memory
                .write(&opened.file, 0, b"contents", &r)
                .await
                .unwrap();
            assert_eq!(
                memory.read(&opened.file, 0, 8, &r).await.unwrap(),
                b"contents"
            );
            memory.close(&opened.file, &r).await.unwrap();
        }
        assert!(matches!(
            memory
                .open_with_caching(
                    "missing",
                    OpenOptions {
                        disposition: CreateDisposition::OPEN.0,
                        ..options()
                    },
                    lease(),
                    &r,
                )
                .await,
            Err(OpenError::Status(Status::OBJECT_NAME_NOT_FOUND))
        ));
    });
}

#[test]
fn controlled_opens_retain_actual_grants_after_late_cancellation() {
    block_on(async {
        for caching in [CachingRequest::Oplock(Oplock::Batch), lease()] {
            let native = CachingFs::new();
            let observed = native.control.clone();
            let (fs, controller) = ControlledFs::new(native);
            controller
                .set_plan(
                    Operation::Open,
                    Plan {
                        hold_after: true,
                        ..Plan::default()
                    },
                )
                .unwrap();
            let r = RequestContext::new(1);
            let mut open = std::pin::pin!(fs.open_with_caching("file", options(), caching, &r));
            assert!(futures::poll!(&mut open).is_pending());
            let call = controller.next_call().await;
            assert_eq!(controller.snapshot(call.id).unwrap().phase, Phase::After);
            assert_eq!(observed.state.lock().opens, 1);
            r.cancel();
            assert!(futures::poll!(&mut open).is_pending());
            controller.release(call.id, Gate::After).unwrap();
            let opened = open.await.unwrap();
            match (&opened.caching, caching) {
                (CachingGrant::Oplock { level, .. }, CachingRequest::Oplock(_)) => {
                    assert_eq!(*level, Oplock::LevelII);
                }
                (
                    CachingGrant::Lease {
                        identity,
                        state,
                        breaking,
                        ..
                    },
                    CachingRequest::Lease {
                        identity: requested,
                        state: requested_state,
                    },
                ) => {
                    assert_eq!(*identity, requested);
                    assert_eq!(*state, requested_state);
                    assert!(!breaking);
                }
                _ => panic!("grant kind was not preserved"),
            }
            let control = grant_control(opened.caching);
            let cleanup = RequestContext::new(2);
            let change = observed.indicate(CachingState::None);
            assert_eq!(control.wait_for_break(&cleanup).await.unwrap(), change);
            assert_eq!(
                control
                    .acknowledge(change.id, CachingState::None, &cleanup)
                    .await,
                Ok(CachingState::None),
            );
            fs.close(&opened.file, &cleanup).await.unwrap();
            assert_eq!(observed.state.lock().opens, 0);
        }
    });
}

#[test]
fn break_wait_cancellation_and_acknowledgment_ids_preserve_pending_breaks() {
    block_on(async {
        let native = CachingFs::new();
        let observed = native.control.clone();
        let (fs, controller) = ControlledFs::new(native);
        let r = RequestContext::new(1);
        let opened = fs
            .open_with_caching("file", options(), lease(), &r)
            .await
            .unwrap();
        let control = grant_control(opened.caching);
        let waiting = RequestContext::new(2);
        let mut wait = std::pin::pin!(control.wait_for_break(&waiting));
        assert!(futures::poll!(&mut wait).is_pending());
        waiting.cancel();
        assert_eq!(wait.await, Err(Status::CANCELLED));
        let first = observed.indicate(CachingState::ReadHandle);
        assert_eq!(control.wait_for_break(&r).await.unwrap(), first);
        assert_eq!(
            control
                .acknowledge(first.id, CachingState::ReadWriteHandle, &r)
                .await,
            Err(Status::INVALID_PARAMETER),
        );
        observed.state.lock().failure = Some(Status::ACCESS_DENIED);
        assert_eq!(
            control
                .acknowledge(first.id, CachingState::ReadHandle, &r)
                .await,
            Err(Status::ACCESS_DENIED),
        );
        controller
            .plan_next(
                Operation::CachingAck,
                Plan {
                    hold_after: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let completing = RequestContext::new(3);
        let mut ack =
            std::pin::pin!(control.acknowledge(first.id, CachingState::ReadHandle, &completing));
        assert!(futures::poll!(&mut ack).is_pending());
        let call = controller.next_call().await;
        assert_eq!(call.operation, Operation::CachingAck);
        assert_eq!(observed.state.lock().rights, CachingState::ReadHandle);
        completing.cancel();
        controller.release(call.id, Gate::After).unwrap();
        assert_eq!(ack.await, Ok(CachingState::ReadHandle));
        let second = observed.indicate(CachingState::None);
        assert_eq!(control.wait_for_break(&r).await.unwrap(), second);
        assert_eq!(
            control.acknowledge(first.id, CachingState::None, &r).await,
            Err(Status::INVALID_DEVICE_STATE),
        );
        assert_eq!(observed.state.lock().pending, Some(second));
        assert_eq!(
            control.acknowledge(second.id, CachingState::None, &r).await,
            Ok(CachingState::None),
        );
        fs.close(&opened.file, &r).await.unwrap();
    });
}

#[test]
fn caching_gates_cancel_before_effect_without_consuming_grants_or_breaks() {
    block_on(async {
        let native = CachingFs::new();
        let observed = native.control.clone();
        let (fs, controller) = ControlledFs::new(native);
        controller
            .plan_next(
                Operation::Open,
                Plan {
                    hold_before: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let opening = RequestContext::new(1);
        let mut open = std::pin::pin!(fs.open_with_caching("file", options(), lease(), &opening));
        assert!(futures::poll!(&mut open).is_pending());
        let call = controller.next_call().await;
        opening.cancel();
        assert!(matches!(
            open.await,
            Err(OpenError::Status(Status::CANCELLED))
        ));
        assert!(!controller.snapshot(call.id).unwrap().delegated);
        assert_eq!(observed.state.lock().opens, 0);

        let r = RequestContext::new(2);
        let opened = fs
            .open_with_caching("file", options(), lease(), &r)
            .await
            .unwrap();
        assert_eq!(opened.action, CreateAction::CREATED.0);
        let control = grant_control(opened.caching);
        let change = observed.indicate(CachingState::Read);
        controller
            .plan_next(
                Operation::CachingBreak,
                Plan {
                    hold_before: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let waiting = RequestContext::new(3);
        let mut wait = std::pin::pin!(control.wait_for_break(&waiting));
        assert!(futures::poll!(&mut wait).is_pending());
        let call = controller.next_call().await;
        waiting.cancel();
        assert_eq!(wait.await, Err(Status::CANCELLED));
        assert!(!controller.snapshot(call.id).unwrap().delegated);
        assert_eq!(observed.state.lock().pending, Some(change));
        assert!(!observed.state.lock().delivered);

        controller
            .plan_next(
                Operation::CachingBreak,
                Plan {
                    hold_after: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let delivered = RequestContext::new(4);
        let mut wait = std::pin::pin!(control.wait_for_break(&delivered));
        assert!(futures::poll!(&mut wait).is_pending());
        let call = controller.next_call().await;
        assert!(observed.state.lock().delivered);
        delivered.cancel();
        controller.release(call.id, Gate::After).unwrap();
        assert_eq!(wait.await, Ok(change));

        controller
            .plan_next(
                Operation::CachingAck,
                Plan {
                    hold_before: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let completing = RequestContext::new(5);
        let mut ack =
            std::pin::pin!(control.acknowledge(change.id, CachingState::None, &completing));
        assert!(futures::poll!(&mut ack).is_pending());
        let call = controller.next_call().await;
        completing.cancel();
        assert_eq!(ack.await, Err(Status::CANCELLED));
        assert!(!controller.snapshot(call.id).unwrap().delegated);
        assert_eq!(observed.state.lock().pending, Some(change));
        assert_eq!(observed.state.lock().rights, CachingState::ReadWriteHandle);
        assert_eq!(
            control.acknowledge(change.id, CachingState::None, &r).await,
            Ok(CachingState::None)
        );
        fs.close(&opened.file, &r).await.unwrap();
    });
}

#[test]
fn shared_lease_controls_do_not_keep_closed_files_alive() {
    block_on(async {
        let fs = CachingFs::new();
        let r = RequestContext::new(1);
        let first = fs
            .open_with_caching("file", options(), lease(), &r)
            .await
            .unwrap();
        let change = fs.control.indicate(CachingState::Read);
        let second = fs
            .open_with_caching("file", options(), lease(), &r)
            .await
            .unwrap();
        assert!(matches!(
            second.caching,
            CachingGrant::Lease { breaking: true, .. }
        ));
        let control = grant_control(first.caching);
        fs.close(&first.file, &r).await.unwrap();
        fs.close(&first.file, &r).await.unwrap();
        assert_eq!(fs.control.state.lock().opens, 1);
        assert_eq!(control.wait_for_break(&r).await.unwrap(), change);
        assert_eq!(
            control.acknowledge(change.id, CachingState::Read, &r).await,
            Ok(CachingState::Read)
        );
        let mut wait = std::pin::pin!(control.wait_for_break(&r));
        assert!(futures::poll!(&mut wait).is_pending());
        drop(second);
        assert_eq!(wait.await, Err(Status::FILE_CLOSED));
        assert_eq!(
            control.acknowledge(change.id, CachingState::None, &r).await,
            Err(Status::FILE_CLOSED)
        );
    });
}

#[test]
fn uncached_frontend_uses_provider_caching_entry_and_rejects_unsolicited_grants() {
    block_on(async {
        let mut fs = CachingFs::new();
        fs.grant_unrequested = true;
        let observed = fs.control.clone();
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let body = create_body(
            "file",
            AccessMask::FILE_ALL_ACCESS.into_bits(),
            ShareAccess::ALL.into_bits(),
            CreateDisposition::OPEN_IF.0,
            0,
            &[],
        );
        let response = client.send(Command::CREATE, &body).await;
        assert_eq!(response_status(&response), Status::INTERNAL_ERROR);
        assert_eq!(*server.backend.requests.lock(), [CachingRequest::None]);
        assert_eq!(observed.state.lock().opens, 0);
    });
}
