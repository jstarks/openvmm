// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::provider::{CachingState, Oplock};
use futures::FutureExt;
use pal_async::DefaultPool;
use std::time::Duration;
use test_with_tracing::test;

fn exclusive_body(disposition: CreateDisposition, sharing: ShareAccess) -> Vec<u8> {
    let mut body = create_body(
        "file",
        AccessMask::FILE_ALL_ACCESS.into_bits(),
        sharing.into_bits(),
        disposition.0,
        0,
        &[],
    );
    CreateRequest::mut_from_prefix(&mut body[..])
        .unwrap()
        .0
        .requested_oplock_level = OplockLevel::EXCLUSIVE;
    body
}

async fn cached_client(server: &Arc<Server<MemoryFs>>) -> Client {
    let client = Client::new(server).await;
    client.connection.state.lock().caching_enabled = true;
    client
}

fn notification(
    bytes: &[u8],
    file: FileId,
    session: u64,
    level: OplockLevel,
) -> OplockBreakAcknowledgement {
    let header = Header::read_from_prefix(bytes).unwrap().0;
    assert_eq!(header.command(), Command::OPLOCK_BREAK);
    assert_eq!(header.message_id.get(), u64::MAX);
    assert_eq!(header.session_id.get(), session);
    assert_eq!(header.tree_id.get(), 0);
    assert_eq!(header.credits.get(), 0);
    let body = read_body::<OplockBreakAcknowledgement>(bytes).unwrap();
    assert_eq!(body.file_id.as_bytes(), file.as_bytes());
    assert_eq!(body.oplock_level, level);
    body
}

#[test]
fn software_oplocks_break_across_connections_and_invalidate_writes() {
    DefaultPool::run_with(async |driver| {
        let server =
            Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
        let mut a = cached_client(&server).await;
        let mut b = cached_client(&server).await;
        let body = exclusive_body(CreateDisposition::OPEN_IF, ShareAccess::ALL);
        let first = read_body::<CreateResponse>(&a.ok(Command::CREATE, &body).await).unwrap();
        assert_eq!(first.oplock_level, OplockLevel::EXCLUSIVE);
        let (send_a, receive_a) = async_channel::bounded(4);
        let (send_b, receive_b) = async_channel::bounded(4);
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
        let mut opening = Box::pin(b.send(Command::CREATE, &body));
        assert!(futures::poll!(&mut opening).is_pending());
        assert!(futures::poll!(&mut service_a).is_pending());
        let bytes = receive_a.try_recv().unwrap();
        let ack = notification(&bytes, first.file_id, a.session, OplockLevel::LEVEL_II);
        assert!(futures::poll!(&mut opening).is_pending());
        a.ok(
            Command::WRITE,
            &Client::write_body(first.file_id, 0, b"old"),
        )
        .await;
        assert!(futures::poll!(&mut opening).is_pending());
        let reply = a.ok(Command::OPLOCK_BREAK, ack.as_bytes()).await;
        assert_eq!(
            read_body::<OplockBreakAcknowledgement>(&reply)
                .unwrap()
                .oplock_level,
            OplockLevel::LEVEL_II
        );
        let response = opening.await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        let second = read_body::<CreateResponse>(&response).unwrap();
        assert_eq!(second.oplock_level, OplockLevel::LEVEL_II);
        assert!(futures::poll!(&mut service_b).is_pending());

        let write = Client::write_body(second.file_id, 0, b"new");
        let mut writing = Box::pin(b.send(Command::WRITE, &write));
        assert!(futures::poll!(&mut writing).is_pending());
        assert!(futures::poll!(&mut service_a).is_pending());
        assert!(futures::poll!(&mut service_b).is_pending());
        notification(
            &receive_a.try_recv().unwrap(),
            first.file_id,
            a.session,
            OplockLevel::NONE,
        );
        assert_eq!(response_status(&writing.await), Status::SUCCESS);
        notification(
            &receive_b.try_recv().unwrap(),
            second.file_id,
            b.session,
            OplockLevel::NONE,
        );
        let data = a.read(first.file_id, 0, 3).await;
        assert_eq!(response_status(&data), Status::SUCCESS);
        let read = read_body::<ReadResponse>(&data).unwrap();
        assert_eq!(&data[usize::from(read.data_offset)..], b"new");
        assert_eq!(
            response_status(&a.send(Command::OPLOCK_BREAK, ack.as_bytes()).await),
            Status::INVALID_DEVICE_STATE
        );
        a.connection.cancel_all();
        b.connection.cancel_all();
        service_a.await.unwrap();
        service_b.await.unwrap();
        a.connection.shutdown().await.unwrap();
        b.connection.shutdown().await.unwrap();
    });
}

#[test]
fn closing_without_ack_releases_the_reservation_and_waiting_open() {
    DefaultPool::run_with(async |driver| {
        let server =
            Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
        let mut a = cached_client(&server).await;
        let mut b = cached_client(&server).await;
        let body = exclusive_body(CreateDisposition::OPEN_IF, ShareAccess::ALL);
        let first = read_body::<CreateResponse>(&a.ok(Command::CREATE, &body).await).unwrap();
        let (sender, receiver) = async_channel::bounded(1);
        let mut service = std::pin::pin!(a.connection.clone().serve_caching(
            driver,
            sender,
            Duration::from_secs(35)
        ));
        let mut opening = Box::pin(b.send(Command::CREATE, &body));
        assert!(futures::poll!(&mut opening).is_pending());
        assert!(futures::poll!(&mut service).is_pending());
        notification(
            &receiver.try_recv().unwrap(),
            first.file_id,
            a.session,
            OplockLevel::LEVEL_II,
        );
        a.close(first.file_id).await;
        let response = opening.await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        let second = read_body::<CreateResponse>(&response).unwrap();
        assert_eq!(second.oplock_level, OplockLevel::EXCLUSIVE);
        assert!(futures::poll!(&mut service).is_pending());
        b.close(second.file_id).await;
        a.connection.cancel_all();
        service.await.unwrap();
        a.connection.shutdown().await.unwrap();
        b.connection.shutdown().await.unwrap();
    });
}

#[test]
fn timeout_revokes_rights_before_destructive_open_and_rejects_late_ack() {
    DefaultPool::run_with(async |driver| {
        let server =
            Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
        let mut a = cached_client(&server).await;
        let mut b = cached_client(&server).await;
        let first = read_body::<CreateResponse>(
            &a.ok(
                Command::CREATE,
                &exclusive_body(CreateDisposition::OPEN_IF, ShareAccess::ALL),
            )
            .await,
        )
        .unwrap();
        a.ok(
            Command::WRITE,
            &Client::write_body(first.file_id, 0, b"old"),
        )
        .await;
        let body = exclusive_body(CreateDisposition::OVERWRITE, ShareAccess::ALL);
        let mut opening = Box::pin(b.send(Command::CREATE, &body));
        assert!(futures::poll!(&mut opening).is_pending());
        let before = a.read(first.file_id, 0, 3).await;
        let read = read_body::<ReadResponse>(&before).unwrap();
        assert_eq!(&before[usize::from(read.data_offset)..], b"old");
        let (sender, receiver) = async_channel::bounded(1);
        let mut service = std::pin::pin!(a.connection.clone().serve_caching(
            driver,
            sender,
            Duration::ZERO
        ));
        let response = {
            let mut opening = std::pin::pin!(opening.fuse());
            let mut servicing = std::pin::pin!(service.as_mut().fuse());
            futures::select! {
                response = opening => response,
                result = servicing => panic!("cache service ended early: {result:?}"),
            }
        };
        assert_eq!(response_status(&response), Status::SUCCESS);
        let change = notification(
            &receiver.try_recv().unwrap(),
            first.file_id,
            a.session,
            OplockLevel::NONE,
        );
        assert_eq!(
            response_status(&a.read(first.file_id, 0, 3).await),
            Status::END_OF_FILE
        );
        assert_eq!(
            response_status(&a.send(Command::OPLOCK_BREAK, change.as_bytes()).await),
            Status::INVALID_DEVICE_STATE
        );
        a.connection.cancel_all();
        service.await.unwrap();
        a.connection.shutdown().await.unwrap();
        b.connection.shutdown().await.unwrap();
    });
}

#[test]
fn cancelling_a_waiting_open_keeps_the_break_but_does_not_leak_sharing() {
    DefaultPool::run_with(async |driver| {
        let server =
            Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
        let mut a = cached_client(&server).await;
        let mut b = cached_client(&server).await;
        let body = exclusive_body(CreateDisposition::OPEN_IF, ShareAccess::ALL);
        let first = read_body::<CreateResponse>(&a.ok(Command::CREATE, &body).await).unwrap();
        let connection = b.connection.clone();
        let cancel = request(
            Command::CANCEL,
            SimpleBody {
                structure_size: SimpleBody::STRUCTURE_SIZE.into(),
                reserved: 0.into(),
            }
            .as_bytes(),
            b.session,
            b.tree,
            b.message,
        );
        let (sender, receiver) = async_channel::bounded(1);
        let mut service = std::pin::pin!(a.connection.clone().serve_caching(
            driver,
            sender,
            Duration::from_secs(35)
        ));
        let mut opening = Box::pin(b.send(Command::CREATE, &body));
        assert!(futures::poll!(&mut opening).is_pending());
        assert!(futures::poll!(&mut service).is_pending());
        let change = notification(
            &receiver.try_recv().unwrap(),
            first.file_id,
            a.session,
            OplockLevel::LEVEL_II,
        );
        connection.cancel(&cancel).unwrap();
        assert_eq!(response_status(&opening.await), Status::CANCELLED);
        a.ok(Command::OPLOCK_BREAK, change.as_bytes()).await;
        a.close(first.file_id).await;
        let body = exclusive_body(CreateDisposition::OPEN, ShareAccess::new());
        let fresh = read_body::<CreateResponse>(&b.ok(Command::CREATE, &body).await).unwrap();
        assert_eq!(fresh.oplock_level, OplockLevel::EXCLUSIVE);
        b.close(fresh.file_id).await;
        a.connection.cancel_all();
        service.await.unwrap();
        a.connection.shutdown().await.unwrap();
        b.connection.shutdown().await.unwrap();
    });
}

#[test]
fn disconnect_revokes_a_break_without_waiting_for_outbound_capacity() {
    DefaultPool::run_with(async |driver| {
        let server =
            Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
        let mut a = cached_client(&server).await;
        let mut b = cached_client(&server).await;
        let body = exclusive_body(CreateDisposition::OPEN_IF, ShareAccess::ALL);
        a.ok(Command::CREATE, &body).await;
        let (sender, receiver) = async_channel::bounded(1);
        sender.try_send(vec![0]).unwrap();
        let mut service = std::pin::pin!(a.connection.clone().serve_caching(
            driver,
            sender,
            Duration::from_secs(35)
        ));
        let mut opening = Box::pin(b.send(Command::CREATE, &body));
        assert!(futures::poll!(&mut opening).is_pending());
        assert!(futures::poll!(&mut service).is_pending());
        assert!(futures::poll!(&mut opening).is_pending());
        a.connection.cancel_all();
        service.await.unwrap();
        a.connection.shutdown().await.unwrap();
        let response = opening.await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        assert_eq!(
            read_body::<CreateResponse>(&response).unwrap().oplock_level,
            OplockLevel::EXCLUSIVE
        );
        assert_eq!(receiver.try_recv().unwrap(), [0]);
        assert!(receiver.try_recv().is_err());
        b.connection.shutdown().await.unwrap();
    });
}

#[test]
fn invalid_ack_revokes_caching_and_unblocks_the_conflicting_open() {
    DefaultPool::run_with(async |driver| {
        let server =
            Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
        let mut a = cached_client(&server).await;
        let mut b = cached_client(&server).await;
        let body = exclusive_body(CreateDisposition::OPEN_IF, ShareAccess::ALL);
        let first = read_body::<CreateResponse>(&a.ok(Command::CREATE, &body).await).unwrap();
        let (sender, receiver) = async_channel::bounded(1);
        let mut service = std::pin::pin!(a.connection.clone().serve_caching(
            driver,
            sender,
            Duration::from_secs(35)
        ));
        let mut opening = Box::pin(b.send(Command::CREATE, &body));
        assert!(futures::poll!(&mut opening).is_pending());
        assert!(futures::poll!(&mut service).is_pending());
        let mut change = notification(
            &receiver.try_recv().unwrap(),
            first.file_id,
            a.session,
            OplockLevel::LEVEL_II,
        );
        change.oplock_level = OplockLevel::BATCH;
        assert_eq!(
            response_status(&a.send(Command::OPLOCK_BREAK, change.as_bytes()).await),
            Status::INVALID_OPLOCK_PROTOCOL
        );
        assert_eq!(response_status(&opening.await), Status::SUCCESS);
        change.oplock_level = OplockLevel::LEVEL_II;
        assert_eq!(
            response_status(&a.send(Command::OPLOCK_BREAK, change.as_bytes()).await),
            Status::INVALID_DEVICE_STATE
        );
        a.connection.cancel_all();
        service.await.unwrap();
        a.connection.shutdown().await.unwrap();
        b.connection.shutdown().await.unwrap();
    });
}

#[test]
fn named_stream_activity_revokes_and_suppresses_default_stream_caching() {
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
        let first = fs
            .open_with_caching(
                "file",
                options,
                CachingRequest::Oplock(Oplock::Exclusive),
                &context,
            )
            .await
            .unwrap();
        let control = match first.caching {
            CachingGrant::Oplock {
                level: Oplock::Exclusive,
                control,
            } => control,
            _ => panic!("missing exclusive grant"),
        };
        let mut opening = Box::pin(fs.open("file:side", options, &context));
        assert!(futures::poll!(&mut opening).is_pending());
        let change = control.wait_for_break(&context).await.unwrap();
        assert_eq!(change.state, CachingState::None);
        control
            .acknowledge(change.id, CachingState::None, &context)
            .await
            .unwrap();
        let (named, _) = opening.await.unwrap();
        let second = fs
            .open_with_caching(
                "file",
                options,
                CachingRequest::Oplock(Oplock::Exclusive),
                &context,
            )
            .await
            .unwrap();
        assert!(matches!(second.caching, CachingGrant::None));
        fs.close(&named, &context).await.unwrap();
        fs.close(&second.file, &context).await.unwrap();
        fs.close(&first.file, &context).await.unwrap();
        assert_eq!(
            control.wait_for_break(&context).await,
            Err(Status::FILE_CLOSED)
        );
    });
}
