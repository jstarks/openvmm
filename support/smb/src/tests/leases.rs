// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::provider::{CachingState, LeaseIdentity};
use crate::test_support::{ControlledFs, Gate, Operation, Plan};
use futures::FutureExt;
use pal_async::DefaultPool;
use std::time::Duration;
use test_with_tracing::test;

async fn client<B: FileSystem>(server: &Arc<Server<B>>, guid: u8) -> Client<B> {
    let mut client = Client {
        connection: server.connect(),
        session: 0,
        tree: 0,
        message: 0,
    };
    client.connection.state.lock().caching_enabled = true;
    let mut negotiate = negotiate_body();
    NegotiateRequest::mut_from_prefix(&mut negotiate[..])
        .unwrap()
        .0
        .client_guid = [guid; 16];
    let response = client.ok(Command::NEGOTIATE, &negotiate).await;
    assert!(
        read_body::<NegotiateResponse>(&response)
            .unwrap()
            .capabilities
            .leasing()
    );
    let mut setup = SessionSetupRequest::new_zeroed();
    setup.structure_size = SessionSetupRequest::STRUCTURE_SIZE.into();
    let response = client.ok(Command::SESSION_SETUP, setup.as_bytes()).await;
    client.session = Header::read_from_prefix(&response)
        .unwrap()
        .0
        .session_id
        .get();
    let response = client.ok(Command::TREE_CONNECT, &tree_body()).await;
    client.tree = Header::read_from_prefix(&response).unwrap().0.tree_id.get();
    client
}

fn body(name: &str, key: u8, rights: u32) -> Vec<u8> {
    let mut contexts = Vec::new();
    let mut previous = None;
    append_create_context(
        &mut contexts,
        &mut previous,
        CreateContextName::REQUEST_LEASE,
        LeaseContext {
            lease_key: [key; 16],
            lease_state: rights.into(),
            lease_flags: 0.into(),
            lease_duration: 0.into(),
        }
        .as_bytes(),
    );
    let mut bytes = create_body(
        name,
        AccessMask::FILE_ALL_ACCESS.into_bits(),
        ShareAccess::ALL.into_bits(),
        CreateDisposition::OPEN_IF.0,
        0,
        &contexts,
    );
    CreateRequest::mut_from_prefix(&mut bytes[..])
        .unwrap()
        .0
        .requested_oplock_level = OplockLevel::LEASE;
    bytes
}

fn created(response: &[u8], key: u8, rights: u32) -> FileId {
    assert_eq!(response_status(response), Status::SUCCESS);
    let result = read_body::<CreateResponse>(response).unwrap();
    assert_eq!(result.oplock_level, OplockLevel::LEASE);
    let data = variable::<CreateResponse>(
        response,
        result.contexts_offset.get() as usize,
        result.contexts_length.get() as usize,
    )
    .unwrap();
    let contexts = create_contexts(data).unwrap();
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].name(), Some(CreateContextName::REQUEST_LEASE));
    let lease = LeaseContext::read_from_bytes(contexts[0].data).unwrap();
    assert_eq!(lease.lease_key, [key; 16]);
    assert_eq!(lease.lease_state.get(), rights);
    assert_eq!(lease.lease_duration.get(), 0);
    result.file_id
}

fn change(bytes: &[u8], key: u8, old: u32, new: u32, flags: u32) -> LeaseBreakNotification {
    let header = Header::read_from_prefix(bytes).unwrap().0;
    assert_eq!(header.command(), Command::OPLOCK_BREAK);
    assert_eq!(header.message_id.get(), u64::MAX);
    assert_eq!(header.session_id.get(), 0);
    assert_eq!(header.tree_id.get(), 0);
    let result = read_body::<LeaseBreakNotification>(bytes).unwrap();
    assert_eq!(result.lease_key, [key; 16]);
    assert_eq!(result.current_state.get(), old);
    assert_eq!(result.new_state.get(), new);
    assert_eq!(result.flags.get(), flags);
    assert_eq!(result.new_epoch.get(), 0);
    result
}

fn ack(key: u8, rights: u32) -> LeaseBreakAcknowledgement {
    LeaseBreakAcknowledgement {
        structure_size: LeaseBreakAcknowledgement::STRUCTURE_SIZE.into(),
        reserved: 0.into(),
        flags: 0.into(),
        lease_key: [key; 16],
        lease_state: rights.into(),
        lease_duration: 0.into(),
    }
}

#[test]
fn stat_only_lease_owners_constrain_foreign_grants_and_same_key_upgrades() {
    DefaultPool::run_with(async |driver| {
        let server =
            Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
        let mut a = client(&server, 1).await;
        let mut b = client(&server, 2).await;
        let mut bytes = body("file", 1, 7);
        let request = CreateRequest::mut_from_prefix(&mut bytes).unwrap().0;
        request.desired_access = AccessMask::new().with_read_attributes(true);
        request.share_access = ShareAccess::new();
        let first = created(&a.ok(Command::CREATE, &bytes).await, 1, 7);
        let extra = created(&a.ok(Command::CREATE, &body("file", 1, 0)).await, 1, 7);
        a.close(extra).await;

        let (sender, receiver) = async_channel::bounded(4);
        let mut service = std::pin::pin!(a.connection.clone().serve_caching(
            driver,
            sender,
            Duration::from_secs(35)
        ));
        let bytes = body("file", 2, 7);
        let mut opening = Box::pin(b.send(Command::CREATE, &bytes));
        assert!(futures::poll!(&mut opening).is_pending());
        assert!(futures::poll!(&mut service).is_pending());
        change(&receiver.try_recv().unwrap(), 1, 7, 3, 1);
        a.ok(Command::OPLOCK_BREAK, ack(1, 3).as_bytes()).await;
        let second = created(&opening.await, 2, 3);

        let extra = created(&a.ok(Command::CREATE, &body("file", 1, 7)).await, 1, 3);
        a.close(extra).await;
        b.close(second).await;
        let extra = created(&a.ok(Command::CREATE, &body("file", 1, 7)).await, 1, 7);
        a.close(extra).await;
        a.close(first).await;
        a.connection.cancel_all();
        service.await.unwrap();
        a.connection.shutdown().await.unwrap();
        b.connection.shutdown().await.unwrap();
    });
}

#[test]
fn classic_shared_caching_coexists_with_read_but_not_handle_leases() {
    block_on(async {
        for rights in [1, 3] {
            let server =
                Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
            let mut a = client(&server, 1).await;
            let first = created(
                &a.ok(Command::CREATE, &body("file", 1, rights)).await,
                1,
                rights,
            );
            for level in [
                OplockLevel::LEVEL_II,
                OplockLevel::EXCLUSIVE,
                OplockLevel::BATCH,
            ] {
                let mut bytes = create_body(
                    "file",
                    AccessMask::FILE_ALL_ACCESS.into_bits(),
                    7,
                    CreateDisposition::OPEN_IF.0,
                    0,
                    &[],
                );
                CreateRequest::mut_from_prefix(&mut bytes[..])
                    .unwrap()
                    .0
                    .requested_oplock_level = level;
                let response = a.ok(Command::CREATE, &bytes).await;
                let open = read_body::<CreateResponse>(&response).unwrap();
                assert_eq!(
                    open.oplock_level,
                    if rights == 1 {
                        OplockLevel::LEVEL_II
                    } else {
                        OplockLevel::NONE
                    }
                );
                a.close(open.file_id).await;
            }
            a.close(first).await;
            let mut bytes = create_body(
                "file",
                AccessMask::FILE_ALL_ACCESS.into_bits(),
                7,
                CreateDisposition::OPEN_IF.0,
                0,
                &[],
            );
            CreateRequest::mut_from_prefix(&mut bytes[..])
                .unwrap()
                .0
                .requested_oplock_level = OplockLevel::LEVEL_II;
            let response = a.ok(Command::CREATE, &bytes).await;
            let classic = read_body::<CreateResponse>(&response).unwrap();
            assert_eq!(classic.oplock_level, OplockLevel::LEVEL_II);
            let leased = created(&a.ok(Command::CREATE, &body("file", 2, 7)).await, 2, 1);
            let extra = created(&a.ok(Command::CREATE, &body("file", 2, 3)).await, 2, 1);
            a.close(extra).await;
            a.close(classic.file_id).await;
            let extra = created(&a.ok(Command::CREATE, &body("file", 2, 3)).await, 2, 3);
            a.close(extra).await;
            a.close(leased).await;
            a.connection.shutdown().await.unwrap();
        }
    });
}

#[test]
fn a_tightened_pending_break_blocks_both_opens_until_final_ack() {
    DefaultPool::run_with(async |driver| {
        let server =
            Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
        let mut a = client(&server, 1).await;
        let mut b = client(&server, 2).await;
        let mut c = client(&server, 3).await;
        let first = created(&a.ok(Command::CREATE, &body("file", 1, 7)).await, 1, 7);
        a.ok(Command::WRITE, &Client::write_body(first, 0, b"keep"))
            .await;
        let (sender, receiver) = async_channel::bounded(4);
        let mut service = std::pin::pin!(a.connection.clone().serve_caching(
            driver,
            sender,
            Duration::from_secs(35)
        ));
        let bytes = body("file", 2, 7);
        let mut opening = Box::pin(b.send(Command::CREATE, &bytes));
        assert!(futures::poll!(&mut opening).is_pending());
        assert!(futures::poll!(&mut service).is_pending());
        change(&receiver.try_recv().unwrap(), 1, 7, 3, 1);
        let bytes = create_body(
            "file",
            AccessMask::FILE_ALL_ACCESS.into_bits(),
            7,
            CreateDisposition::OVERWRITE.0,
            0,
            &[],
        );
        let mut overwriting = Box::pin(c.send(Command::CREATE, &bytes));
        assert!(futures::poll!(&mut overwriting).is_pending());
        assert!(futures::poll!(&mut service).is_pending());
        assert!(receiver.try_recv().is_err());
        assert_eq!(&a.read(first, 0, 4).await[80..], b"keep");
        a.ok(Command::OPLOCK_BREAK, ack(1, 3).as_bytes()).await;
        assert!(futures::poll!(&mut opening).is_pending());
        assert!(futures::poll!(&mut overwriting).is_pending());
        assert!(futures::poll!(&mut service).is_pending());
        change(&receiver.try_recv().unwrap(), 1, 3, 0, 1);
        assert_eq!(&a.read(first, 0, 4).await[80..], b"keep");
        a.ok(Command::OPLOCK_BREAK, ack(1, 0).as_bytes()).await;
        let response = overwriting.await;
        let second = created(&opening.await, 2, 3);
        assert_eq!(response_status(&response), Status::SUCCESS);
        assert_eq!(
            response_status(&a.read(first, 0, 1).await),
            Status::END_OF_FILE
        );
        a.close(first).await;
        b.close(second).await;
        c.close(read_body::<CreateResponse>(&response).unwrap().file_id)
            .await;
        a.connection.cancel_all();
        service.await.unwrap();
        a.connection.shutdown().await.unwrap();
        b.connection.shutdown().await.unwrap();
        c.connection.shutdown().await.unwrap();
    });
}

#[test]
fn lease_contention_removes_write_not_handle_and_shared_opens_keep_the_grant() {
    DefaultPool::run_with(async |driver| {
        let server =
            Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
        let mut a = client(&server, 1).await;
        let mut b = client(&server, 1).await;
        let first = created(&a.ok(Command::CREATE, &body("file", 1, 7)).await, 1, 7);
        let (send_a, recv_a) = async_channel::bounded(4);
        let (send_b, recv_b) = async_channel::bounded(4);
        let mut service_a = std::pin::pin!(a.connection.clone().serve_caching(
            driver.clone(),
            send_a,
            Duration::from_secs(35)
        ));
        let mut service_b = std::pin::pin!(b.connection.clone().serve_caching(
            driver,
            send_b,
            Duration::from_secs(35)
        ));
        let request = body("file", 2, 7);
        let mut opening = Box::pin(b.send(Command::CREATE, &request));
        assert!(futures::poll!(&mut opening).is_pending());
        assert!(futures::poll!(&mut service_a).is_pending());
        change(&recv_a.try_recv().unwrap(), 1, 7, 3, 1);
        assert_eq!(
            response_status(&a.send(Command::OPLOCK_BREAK, ack(1, 7).as_bytes()).await),
            Status::REQUEST_NOT_ACCEPTED
        );
        assert!(futures::poll!(&mut opening).is_pending());
        let accepted = a.ok(Command::OPLOCK_BREAK, ack(1, 3).as_bytes()).await;
        assert_eq!(
            read_body::<LeaseBreakAcknowledgement>(&accepted)
                .unwrap()
                .lease_state
                .get(),
            3
        );
        let second = created(&opening.await, 2, 3);
        let extra = created(&a.ok(Command::CREATE, &body("file", 1, 7)).await, 1, 3);
        a.close(extra).await;
        assert!(futures::poll!(&mut service_a).is_pending());
        assert!(recv_a.try_recv().is_err());
        assert!(futures::poll!(&mut service_b).is_pending());
        let write = Client::write_body(first, 0, b"data");
        let mut writing = Box::pin(a.send(Command::WRITE, &write));
        assert!(futures::poll!(&mut writing).is_pending());
        assert!(futures::poll!(&mut service_b).is_pending());
        change(&recv_b.try_recv().unwrap(), 2, 3, 0, 1);
        b.ok(Command::OPLOCK_BREAK, ack(2, 0).as_bytes()).await;
        assert_eq!(response_status(&writing.await), Status::SUCCESS);
        assert!(futures::poll!(&mut service_a).is_pending());
        assert!(recv_a.try_recv().is_err());
        assert_eq!(
            response_status(&a.send(Command::OPLOCK_BREAK, ack(1, 3).as_bytes()).await),
            Status::UNSUCCESSFUL
        );
        a.close(first).await;
        b.close(second).await;
        a.connection.cancel_all();
        b.connection.cancel_all();
        service_a.await.unwrap();
        service_b.await.unwrap();
        a.connection.shutdown().await.unwrap();
        b.connection.shutdown().await.unwrap();
    });
}

#[test]
fn leases_remain_addressable_with_unbacked_locks_and_locking_breaks_foreign_caches() {
    DefaultPool::run_with(async |driver| {
        let server =
            Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
        let mut a = client(&server, 1).await;
        let mut b = client(&server, 2).await;
        let first = created(&a.ok(Command::CREATE, &body("file", 1, 7)).await, 1, 7);
        let exclusive = LockFlags::new()
            .with_exclusive_lock(true)
            .with_fail_immediately(true);
        a.ok(Command::LOCK, &locking::body(first, &[(0, 1, exclusive)]))
            .await;
        let (sender, receiver) = async_channel::bounded(4);
        let mut service = std::pin::pin!(a.connection.clone().serve_caching(
            driver,
            sender,
            Duration::from_secs(35)
        ));
        let bytes = body("file", 2, 7);
        let mut opening = Box::pin(b.send(Command::CREATE, &bytes));
        assert!(futures::poll!(&mut opening).is_pending());
        assert!(futures::poll!(&mut service).is_pending());
        change(&receiver.try_recv().unwrap(), 1, 7, 3, 1);
        a.ok(Command::OPLOCK_BREAK, ack(1, 3).as_bytes()).await;
        let second = created(&opening.await, 2, 3);
        let extra = created(&a.ok(Command::CREATE, &body("file", 1, 0)).await, 1, 3);
        a.close(extra).await;

        let bytes = locking::body(second, &[(100, 1, exclusive)]);
        let mut locking = Box::pin(b.send(Command::LOCK, &bytes));
        assert!(futures::poll!(&mut locking).is_pending());
        assert!(futures::poll!(&mut service).is_pending());
        change(&receiver.try_recv().unwrap(), 1, 3, 0, 1);
        assert!(futures::poll!(&mut locking).is_pending());
        a.ok(Command::OPLOCK_BREAK, ack(1, 0).as_bytes()).await;
        assert_eq!(response_status(&locking.await), Status::SUCCESS);
        let extra = created(&a.ok(Command::CREATE, &body("file", 1, 0)).await, 1, 0);
        a.close(extra).await;
        let extra = created(&b.ok(Command::CREATE, &body("file", 2, 0)).await, 2, 3);
        b.close(extra).await;
        a.close(first).await;
        b.close(second).await;
        a.connection.cancel_all();
        service.await.unwrap();
        a.connection.shutdown().await.unwrap();
        b.connection.shutdown().await.unwrap();
    });
}

#[test]
fn shared_lease_grants_respect_backing_and_readable_ranges_and_unlock_allows_upgrade() {
    block_on(async {
        for name in ["file", "file:stream"] {
            for (allocation, offset, storage) in [
                (0, 0, None),
                (16, 0, None),
                (16, 16, None),
                (0, 15, Some(FileControl::SetSparse { sparse: true })),
                (0, 15, Some(FileControl::SetCompression { format: 2 })),
            ] {
                let fs = MemoryFs::new(1024, 16).with_oplocks().unwrap();
                let context = RequestContext::new(1);
                let options = OpenOptions {
                    access: AccessMask::FILE_ALL_ACCESS.into_bits(),
                    share_access: ShareAccess::ALL.into_bits(),
                    disposition: CreateDisposition::OPEN_IF.0,
                    options: 0,
                    attributes: 0,
                    allocation_size: allocation,
                    security: None,
                    extended_attributes: None,
                };
                let lease = |key, state| CachingRequest::Lease {
                    identity: LeaseIdentity {
                        authority: [1; 16],
                        client_guid: [1; 16],
                        key: [key; 16],
                    },
                    state,
                };
                let first = fs
                    .open_with_caching(
                        name,
                        options,
                        lease(1, CachingState::ReadWriteHandle),
                        &context,
                    )
                    .await
                    .unwrap();
                let control = match first.caching {
                    CachingGrant::Lease { state, control, .. } => {
                        assert_eq!(state, CachingState::ReadWriteHandle);
                        control
                    }
                    _ => panic!("missing initial lease"),
                };
                let info = fs.metadata(&first.file, &context).await.unwrap();
                assert_eq!((info.size, info.allocation_size), (0, allocation));
                let size = if let Some(storage) = storage {
                    fs.file_control(&first.file, storage, &context)
                        .await
                        .unwrap();
                    fs.set_len(&first.file, 16, &context).await.unwrap();
                    let info = fs.metadata(&first.file, &context).await.unwrap();
                    assert_eq!((info.size, info.allocation_size), (16, 0));
                    16
                } else {
                    0
                };
                let range = ByteRange { offset, length: 1 };
                fs.lock(&first.file, range, true, true, &context)
                    .await
                    .unwrap();
                let request = lease(2, CachingState::ReadWriteHandle);
                let mut opening = Box::pin(fs.open_with_caching(
                    name,
                    OpenOptions {
                        allocation_size: 0,
                        ..options
                    },
                    request,
                    &context,
                ));
                assert!(futures::poll!(&mut opening).is_pending());
                let change = control.wait_for_break(&context).await.unwrap();
                assert_eq!(change.state, CachingState::ReadHandle);
                control
                    .acknowledge(change.id, change.state, &context)
                    .await
                    .unwrap();
                let second = opening.await.unwrap();
                let expected = if offset < allocation.max(size) {
                    CachingState::None
                } else {
                    CachingState::ReadHandle
                };
                if size != 0 {
                    assert_eq!(
                        fs.read(&second.file, offset, 1, &context)
                            .await
                            .unwrap_err(),
                        Status::FILE_LOCK_CONFLICT
                    );
                }
                let second_control = match second.caching {
                    CachingGrant::Lease {
                        identity,
                        state,
                        control,
                        ..
                    } => {
                        assert_eq!(
                            identity,
                            match request {
                                CachingRequest::Lease { identity, .. } => identity,
                                _ => unreachable!(),
                            }
                        );
                        assert_eq!(state, expected);
                        control
                    }
                    _ => panic!("a denied grant must retain its lease identity"),
                };
                let third = fs
                    .open_with_caching(
                        name,
                        OpenOptions {
                            allocation_size: 0,
                            ..options
                        },
                        lease(2, CachingState::ReadHandle),
                        &context,
                    )
                    .await
                    .unwrap();
                assert_eq!(second_control.snapshot().state, expected);
                fs.close(&third.file, &context).await.unwrap();
                fs.unlock(&first.file, range, &context).await.unwrap();
                let upgraded = fs
                    .open_with_caching(
                        name,
                        OpenOptions {
                            allocation_size: 0,
                            ..options
                        },
                        lease(2, CachingState::ReadHandle),
                        &context,
                    )
                    .await
                    .unwrap();
                assert_eq!(second_control.snapshot().state, CachingState::ReadHandle);
                fs.close(&upgraded.file, &context).await.unwrap();
                fs.close(&second.file, &context).await.unwrap();
                fs.close(&first.file, &context).await.unwrap();
            }
        }
    });
}

#[test]
fn a_shared_lease_migrates_to_a_live_connection_after_disconnect() {
    DefaultPool::run_with(async |driver| {
        let server =
            Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
        let mut a = client(&server, 4).await;
        let mut b = client(&server, 4).await;
        let first = created(&a.ok(Command::CREATE, &body("file", 1, 7)).await, 1, 7);
        let second = created(&b.ok(Command::CREATE, &body("file", 1, 7)).await, 1, 7);
        let (send_a, recv_a) = async_channel::bounded(4);
        let (send_b, recv_b) = async_channel::bounded(4);
        let mut service_a = std::pin::pin!(a.connection.clone().serve_caching(
            driver.clone(),
            send_a,
            Duration::from_secs(35)
        ));
        let mut service_b = std::pin::pin!(b.connection.clone().serve_caching(
            driver,
            send_b,
            Duration::from_secs(35)
        ));
        assert!(futures::poll!(&mut service_a).is_pending());
        assert!(futures::poll!(&mut service_b).is_pending());
        let packet = request(
            Command::CREATE,
            &body("file", 2, 7),
            b.session,
            b.tree,
            b.message,
        );
        b.message += 1;
        let mut opening = Box::pin(b.connection.request(packet).unwrap().execute());
        assert!(futures::poll!(&mut opening).is_pending());
        assert!(futures::poll!(&mut service_a).is_pending());
        change(&recv_a.try_recv().unwrap(), 1, 7, 3, 1);
        assert!(recv_b.try_recv().is_err());
        a.close(first).await;
        a.connection.shutdown().await.unwrap();
        service_a.await.unwrap();
        assert!(futures::poll!(&mut service_b).is_pending());
        assert!(futures::poll!(&mut opening).is_pending());
        assert!(futures::poll!(&mut service_b).is_pending());
        change(&recv_b.try_recv().unwrap(), 1, 7, 3, 1);
        assert!(recv_a.try_recv().is_err());
        b.ok(Command::OPLOCK_BREAK, ack(1, 3).as_bytes()).await;
        let third = created(&opening.await.unwrap(), 2, 3);
        b.close(second).await;
        b.close(third).await;
        b.connection.cancel_all();
        service_b.await.unwrap();
        b.connection.shutdown().await.unwrap();
    });
}

#[test]
fn identical_keys_are_isolated_by_client_and_service() {
    DefaultPool::run_with(async |driver| {
        for separate_services in [false, true] {
            let memory = MemoryFs::new(1024, 16).with_oplocks().unwrap();
            let server = Server::new("memory", memory.clone()).unwrap();
            let other = if separate_services {
                Server::new("memory", memory).unwrap()
            } else {
                server.clone()
            };
            let mut a = client(&server, 1).await;
            let mut b = client(&other, if separate_services { 1 } else { 2 }).await;
            created(&a.ok(Command::CREATE, &body("file", 1, 7)).await, 1, 7);
            let (sender, receiver) = async_channel::bounded(4);
            let mut service = std::pin::pin!(a.connection.clone().serve_caching(
                driver.clone(),
                sender,
                Duration::from_secs(35)
            ));
            let bytes = body("file", 1, 7);
            let packet = request(Command::CREATE, &bytes, b.session, b.tree, b.message);
            b.message += 1;
            let mut opening = Box::pin(b.connection.request(packet).unwrap().execute());
            assert!(futures::poll!(&mut opening).is_pending());
            assert!(futures::poll!(&mut service).is_pending());
            change(&receiver.try_recv().unwrap(), 1, 7, 3, 1);
            // A client cannot acknowledge another client's lease even when keys match.
            let response = b.send(Command::OPLOCK_BREAK, ack(1, 3).as_bytes()).await;
            assert_eq!(response_status(&response), Status::OBJECT_NAME_NOT_FOUND);
            a.ok(Command::OPLOCK_BREAK, ack(1, 3).as_bytes()).await;
            created(&opening.await.unwrap(), 1, 3);
            a.connection.cancel_all();
            service.await.unwrap();
            a.connection.shutdown().await.unwrap();
            b.connection.shutdown().await.unwrap();
        }
    });
}

#[test]
fn lease_timeout_releases_a_destructive_open_and_late_ack_is_unsuccessful() {
    DefaultPool::run_with(async |driver| {
        let server =
            Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
        let mut a = client(&server, 1).await;
        let mut b = client(&server, 1).await;
        let first = created(&a.ok(Command::CREATE, &body("file", 1, 7)).await, 1, 7);
        a.ok(Command::WRITE, &Client::write_body(first, 0, b"old"))
            .await;
        let mut overwrite = body("file", 2, 7);
        CreateRequest::mut_from_prefix(&mut overwrite[..])
            .unwrap()
            .0
            .create_disposition = CreateDisposition::OVERWRITE.0.into();
        let mut opening = Box::pin(b.send(Command::CREATE, &overwrite));
        assert!(futures::poll!(&mut opening).is_pending());
        let before = a.read(first, 0, 3).await;
        let read = read_body::<ReadResponse>(&before).unwrap();
        assert_eq!(&before[usize::from(read.data_offset)..], b"old");
        let (sender, receiver) = async_channel::bounded(4);
        let mut service = std::pin::pin!(a.connection.clone().serve_caching(
            driver,
            sender,
            Duration::ZERO
        ));
        let result = {
            let mut opening = std::pin::pin!(opening.fuse());
            let mut service = std::pin::pin!(service.as_mut().fuse());
            futures::select! {
                result = opening => result,
                result = service => panic!("lease service ended early: {result:?}"),
            }
        };
        created(&result, 2, 3);
        change(&receiver.try_recv().unwrap(), 1, 7, 0, 1);
        assert_eq!(
            response_status(&a.read(first, 0, 3).await),
            Status::END_OF_FILE
        );
        assert_eq!(
            response_status(&a.send(Command::OPLOCK_BREAK, ack(1, 0).as_bytes()).await),
            Status::UNSUCCESSFUL
        );
        a.connection.cancel_all();
        service.await.unwrap();
        a.connection.shutdown().await.unwrap();
        b.connection.shutdown().await.unwrap();
    });
}

#[test]
fn lease_key_reuse_gets_a_fresh_control_after_last_close() {
    DefaultPool::run_with(async |driver| {
        let server =
            Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
        let mut a = client(&server, 8).await;
        let first = created(&a.ok(Command::CREATE, &body("one", 9, 7)).await, 9, 7);
        assert_eq!(
            response_status(&a.send(Command::CREATE, &body("two", 9, 7)).await),
            Status::INVALID_PARAMETER
        );
        let (sender, receiver) = async_channel::bounded(4);
        let mut service = std::pin::pin!(a.connection.clone().serve_caching(
            driver,
            sender,
            Duration::from_secs(35)
        ));
        assert!(futures::poll!(&mut service).is_pending());
        a.close(first).await;
        let next = created(&a.ok(Command::CREATE, &body("two", 9, 7)).await, 9, 7);
        assert!(futures::poll!(&mut service).is_pending());
        assert!(receiver.try_recv().is_err());
        a.close(next).await;
        a.connection.cancel_all();
        service.await.unwrap();
        a.connection.shutdown().await.unwrap();
    });
}

#[test]
fn read_only_leases_break_without_ack_and_do_not_break_the_writer() {
    DefaultPool::run_with(async |driver| {
        let server =
            Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
        let mut a = client(&server, 6).await;
        let first = created(&a.ok(Command::CREATE, &body("file", 1, 1)).await, 1, 1);
        let second = created(&a.ok(Command::CREATE, &body("file", 2, 1)).await, 2, 1);
        let (sender, receiver) = async_channel::bounded(4);
        let mut service = std::pin::pin!(a.connection.clone().serve_caching(
            driver,
            sender,
            Duration::from_secs(35)
        ));
        assert!(futures::poll!(&mut service).is_pending());
        let bytes = Client::write_body(first, 0, b"new");
        let mut writing = Box::pin(a.send(Command::WRITE, &bytes));
        assert!(futures::poll!(&mut writing).is_pending());
        assert!(futures::poll!(&mut service).is_pending());
        assert_eq!(response_status(&writing.await), Status::SUCCESS);
        change(&receiver.try_recv().unwrap(), 2, 1, 0, 0);
        assert!(receiver.try_recv().is_err());
        let reopened = created(&a.ok(Command::CREATE, &body("file", 2, 1)).await, 2, 1);
        a.close(reopened).await;
        let bytes = Client::write_body(second, 0, b"old");
        let mut writing = Box::pin(a.send(Command::WRITE, &bytes));
        assert!(futures::poll!(&mut writing).is_pending());
        assert!(futures::poll!(&mut service).is_pending());
        assert_eq!(response_status(&writing.await), Status::SUCCESS);
        change(&receiver.try_recv().unwrap(), 1, 1, 0, 0);
        a.connection.cancel_all();
        service.await.unwrap();
        a.connection.shutdown().await.unwrap();
    });
}

#[test]
fn namespace_and_metadata_changes_wait_for_foreign_lease_invalidation() {
    block_on(async {
        let fs = MemoryFs::new(1024, 16).with_oplocks().unwrap();
        let context = RequestContext::new(1);
        let options = OpenOptions {
            access: AccessMask::FILE_ALL_ACCESS.into_bits(),
            share_access: ShareAccess::ALL.into_bits(),
            disposition: CreateDisposition::OPEN_IF.0,
            options: 0,
            attributes: 0,
            allocation_size: 0,
            security: None,
            extended_attributes: None,
        };
        let leased = fs
            .open_with_caching(
                "file",
                options,
                CachingRequest::Lease {
                    identity: LeaseIdentity {
                        authority: [1; 16],
                        client_guid: [1; 16],
                        key: [1; 16],
                    },
                    state: CachingState::ReadHandle,
                },
                &context,
            )
            .await
            .unwrap();
        let control = match leased.caching {
            CachingGrant::Lease { control, .. } => control,
            _ => panic!("missing lease"),
        };
        let (plain, _) = fs
            .open(
                "file",
                OpenOptions {
                    access: AccessMask::new()
                        .with_delete(true)
                        .with_write_attributes(true)
                        .into_bits(),
                    ..options
                },
                &context,
            )
            .await
            .unwrap();
        let mut rename = Box::pin(fs.rename(&plain, "moved", false, &context));
        assert!(futures::poll!(&mut rename).is_pending());
        assert_eq!(
            fs.metadata(&leased.file, &context).await.unwrap().name,
            "file"
        );
        let change = control.wait_for_break(&context).await.unwrap();
        assert_eq!(change.state, CachingState::Read);
        control
            .acknowledge(change.id, CachingState::Read, &context)
            .await
            .unwrap();
        rename.await.unwrap();
        assert_eq!(
            fs.metadata(&leased.file, &context).await.unwrap().name,
            "moved"
        );
        let before = fs.metadata(&leased.file, &context).await.unwrap().written;
        let mut update = Box::pin(fs.set_basic(
            &plain,
            BasicInformation {
                created: 0,
                accessed: 0,
                written: 123,
                changed: 0,
                attributes: 0,
            },
            &context,
        ));
        assert!(futures::poll!(&mut update).is_pending());
        assert_eq!(
            fs.metadata(&leased.file, &context).await.unwrap().written,
            before
        );
        let change = control.wait_for_break(&context).await.unwrap();
        assert_eq!(change.state, CachingState::None);
        control
            .acknowledge(change.id, CachingState::None, &context)
            .await
            .unwrap();
        update.await.unwrap();
        assert_eq!(
            fs.metadata(&leased.file, &context).await.unwrap().written,
            123
        );
        fs.close(&plain, &context).await.unwrap();
        fs.close(&leased.file, &context).await.unwrap();
    });
}

#[test]
fn a_delayed_shared_open_does_not_republish_rights_removed_by_a_break() {
    DefaultPool::run_with(async |driver| {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16).with_oplocks().unwrap());
        let server = Server::new("memory", fs).unwrap();
        let mut a = client(&server, 1).await;
        let mut b = client(&server, 1).await;
        created(&a.ok(Command::CREATE, &body("file", 1, 7)).await, 1, 7);
        control
            .plan_next(
                Operation::Metadata,
                Plan {
                    hold_after: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let packet = request(
            Command::CREATE,
            &body("file", 1, 7),
            a.session,
            a.tree,
            a.message,
        );
        a.message += 1;
        let mut delayed = Box::pin(a.connection.request(packet).unwrap().execute());
        assert!(futures::poll!(&mut delayed).is_pending());
        let call = control.next_call().await;
        assert_eq!(call.operation, Operation::Metadata);
        let packet = request(
            Command::CREATE,
            &body("file", 2, 7),
            b.session,
            b.tree,
            b.message,
        );
        b.message += 1;
        let mut contending = Box::pin(b.connection.request(packet).unwrap().execute());
        assert!(futures::poll!(&mut contending).is_pending());
        let (sender, receiver) = async_channel::bounded(4);
        let mut service = std::pin::pin!(a.connection.clone().serve_caching(
            driver,
            sender,
            Duration::from_secs(35)
        ));
        assert!(futures::poll!(&mut service).is_pending());
        change(&receiver.try_recv().unwrap(), 1, 7, 3, 1);
        b.ok(Command::OPLOCK_BREAK, ack(1, 3).as_bytes()).await;
        created(&contending.await.unwrap(), 2, 3);
        control.release(call.id, Gate::After).unwrap();
        created(&delayed.await.unwrap(), 1, 3);
        a.connection.cancel_all();
        service.await.unwrap();
        a.connection.shutdown().await.unwrap();
        b.connection.shutdown().await.unwrap();
    });
}
