// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::test_support::{Cancellation, ControlledFs, Controller, Gate, Operation, Phase, Plan};
use test_with_tracing::test;

async fn client(plan: Plan) -> (Client<ControlledFs<MemoryFs>>, Controller, FileId) {
    let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
    control.set_plan(Operation::Write, plan).unwrap();
    let server = Server::new("memory", fs).unwrap();
    let mut client = Client::new(&server).await;
    let file = client.open("pending", 2, 0).await;
    (client, control, file)
}

fn write(
    client: &mut Client<ControlledFs<MemoryFs>>,
    file: FileId,
) -> Request<ControlledFs<MemoryFs>> {
    let bytes = request(
        Command::WRITE,
        &Client::write_body(file, 0, b"abc"),
        client.session,
        client.tree,
        client.message,
    );
    client.message += 1;
    client.connection.request(bytes).unwrap()
}

pub(super) fn cancel<B: FileSystem>(client: &Client<B>, id: u64) {
    let header = AsyncHeader {
        protocol: SIGNATURE,
        structure_size: (HEADER_SIZE as u16).into(),
        credit_charge: 0.into(),
        status: 0.into(),
        command: Command::CANCEL.0.into(),
        credits: 0.into(),
        flags: HeaderFlags::new().with_async_command(true),
        next_command: 0.into(),
        message_id: u64::MAX.into(),
        async_id: id.into(),
        session_id: client.session.into(),
        signature: [0; 16],
    };
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(
        SimpleBody {
            structure_size: SimpleBody::STRUCTURE_SIZE.into(),
            reserved: 0.into(),
        }
        .as_bytes(),
    );
    client.connection.cancel(&bytes).unwrap();
}

fn pending(bytes: &[u8]) -> AsyncHeader {
    assert_eq!(&bytes[8..12], &[0x03, 0x01, 0, 0]);
    assert_eq!(&bytes[16..20], &[0x03, 0, 0, 0]);
    let header = AsyncHeader::read_from_prefix(bytes).unwrap().0;
    assert_eq!(Status(header.status.get()), Status::PENDING);
    assert!(header.flags.server_to_redir());
    assert!(header.flags.async_command());
    assert!(!header.flags.signed());
    assert_eq!(header.next_command.get(), 0);
    assert_ne!(header.async_id.get(), 0);
    assert!(header.credits.get() > 0);
    let error = read_body::<ErrorResponse>(bytes).unwrap();
    assert_eq!(error.byte_count.get(), 0);
    header
}

#[test]
fn async_cancel_selects_the_async_id_and_final_credits_are_zero() {
    block_on(async {
        let (mut client, control, file) = client(Plan {
            hold_before: true,
            ..Plan::default()
        })
        .await;
        let baseline = client.connection.state.lock().window.len();
        let (sender, receiver) = async_channel::bounded(8);
        let mut future = std::pin::pin!(write(&mut client, file).execute_with_interim(sender));
        assert!(futures::poll!(&mut future).is_pending());
        let call = control.next_call().await;
        let bytes = receiver.recv().await.unwrap();
        assert_eq!(&bytes[32..40], &[1, 0, 0, 0, 0, 0, 0, 0]);
        let interim = pending(&bytes);
        assert_eq!(client.connection.state.lock().window.len(), baseline);
        assert_eq!(client.connection.state.lock().credits_in_use, 0);
        cancel(&client, interim.async_id.get() + 1);
        assert!(!control.snapshot(call.id).unwrap().cancel_requested);
        cancel(&client, interim.async_id.get());
        future.await.unwrap();
        let bytes = receiver.recv().await.unwrap();
        let final_header = AsyncHeader::read_from_prefix(&bytes).unwrap().0;
        assert_eq!(Status(final_header.status.get()), Status::CANCELLED);
        assert_eq!(final_header.message_id, interim.message_id);
        assert_eq!(final_header.async_id, interim.async_id);
        assert_eq!(final_header.credits.get(), 0);
        assert_eq!(client.connection.state.lock().window.len(), baseline);
        assert!(!control.snapshot(call.id).unwrap().delegated);
        client.close(file).await;
    });
}

#[test]
fn async_late_cancel_preserves_a_committed_write() {
    block_on(async {
        let (mut client, control, file) = client(Plan {
            hold_after: true,
            ..Plan::default()
        })
        .await;
        let (sender, receiver) = async_channel::bounded(8);
        let mut future = std::pin::pin!(write(&mut client, file).execute_with_interim(sender));
        assert!(futures::poll!(&mut future).is_pending());
        let call = control.next_call().await;
        assert_eq!(control.snapshot(call.id).unwrap().phase, Phase::After);
        let interim = pending(&receiver.recv().await.unwrap());
        cancel(&client, interim.async_id.get());
        control.release(call.id, Gate::After).unwrap();
        future.await.unwrap();
        let bytes = receiver.recv().await.unwrap();
        let final_header = AsyncHeader::read_from_prefix(&bytes).unwrap().0;
        assert_eq!(Status(final_header.status.get()), Status::SUCCESS);
        assert_eq!(final_header.async_id, interim.async_id);
        assert_eq!(final_header.credits.get(), 0);
        assert_eq!(read_body::<WriteResponse>(&bytes).unwrap().count.get(), 3);
        assert_eq!(&client.read(file, 0, 3).await[80..], b"abc");
    });
}

#[test]
fn async_cancel_reaches_a_dependent_command_before_it_is_started() {
    block_on(async {
        let (mut client, control, file) = client(Plan {
            hold_before: true,
            ..Plan::default()
        })
        .await;
        let bytes = compound::packet(
            &mut client,
            vec![
                (Command::WRITE, Client::write_body(file, 0, b"one")),
                (
                    Command::WRITE,
                    Client::write_body(FileId::RELATED, 3, b"two"),
                ),
            ],
            true,
        );
        let (sender, receiver) = async_channel::bounded(8);
        let mut future = std::pin::pin!(
            client
                .connection
                .request(bytes)
                .unwrap()
                .execute_with_interim(sender)
        );
        assert!(futures::poll!(&mut future).is_pending());
        let first = pending(&receiver.recv().await.unwrap());
        let second = pending(&receiver.recv().await.unwrap());
        assert_ne!(first.async_id, second.async_id);
        cancel(&client, second.async_id.get());
        let held = control.next_call().await;
        control.release(held.id, Gate::Before).unwrap();
        future.await.unwrap();
        let first_final = receiver.recv().await.unwrap();
        let second_final = receiver.recv().await.unwrap();
        assert_eq!(response_status(&first_final), Status::SUCCESS);
        assert_eq!(response_status(&second_final), Status::CANCELLED);
        assert_eq!(
            AsyncHeader::read_from_prefix(&second_final)
                .unwrap()
                .0
                .async_id,
            second.async_id
        );
        assert_eq!(
            control
                .calls()
                .iter()
                .filter(|call| call.operation == Operation::Write)
                .count(),
            1
        );
        assert_eq!(&client.read(file, 0, 6).await[80..], b"one");
        client.close(file).await;
    });
}

#[test]
fn related_compound_flushes_its_prefix_then_sends_matching_async_completions() {
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        control
            .set_plan(
                Operation::Write,
                Plan {
                    hold_before: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let bytes = compound::packet(
            &mut client,
            vec![
                (
                    Command::CREATE,
                    create_body(
                        "async-chain",
                        AccessMask::FILE_ALL_ACCESS.into_bits(),
                        7,
                        2,
                        0,
                        &[],
                    ),
                ),
                (
                    Command::WRITE,
                    Client::write_body(FileId::RELATED, 0, b"abc"),
                ),
                (Command::READ, compound::read(FileId::RELATED, 3)),
                (Command::CLOSE, compound::close(FileId::RELATED)),
            ],
            true,
        );
        let baseline = client.connection.state.lock().window.len();
        let (sender, receiver) = async_channel::bounded(8);
        let mut future = std::pin::pin!(
            client
                .connection
                .request(bytes)
                .unwrap()
                .execute_with_interim(sender)
        );
        assert!(futures::poll!(&mut future).is_pending());
        let prefix = receiver.recv().await.unwrap();
        assert_eq!(response_status(&prefix), Status::SUCCESS);
        assert_eq!(
            Header::read_from_prefix(&prefix).unwrap().0.command(),
            Command::CREATE
        );
        let interims = [
            pending(&receiver.recv().await.unwrap()),
            pending(&receiver.recv().await.unwrap()),
            pending(&receiver.recv().await.unwrap()),
        ];
        let unique: BTreeSet<_> = interims
            .iter()
            .map(|header| header.async_id.get())
            .collect();
        assert_eq!(unique.len(), 3);
        assert_eq!(client.connection.state.lock().window.len(), baseline);
        let held = control.next_call().await;
        control.release(held.id, Gate::Before).unwrap();
        future.await.unwrap();
        for interim in interims {
            let bytes = receiver.recv().await.unwrap();
            let header = AsyncHeader::read_from_prefix(&bytes).unwrap().0;
            assert_eq!(header.async_id, interim.async_id);
            assert_eq!(header.message_id, interim.message_id);
            assert_eq!(Status(header.status.get()), Status::SUCCESS);
            assert_eq!(header.credits.get(), 0);
            assert_eq!(header.next_command.get(), 0);
            if header.command.get() == Command::READ.0 {
                assert_eq!(&bytes[80..], b"abc");
            }
        }
        assert!(client.connection.state.lock().requests.is_empty());
        assert_eq!(client.connection.state.lock().window.len(), baseline);
    });
}

#[test]
fn closed_response_receiver_does_not_abandon_an_uncancellable_backend() {
    block_on(async {
        let (mut client, control, file) = client(Plan {
            hold_before: true,
            cancellation: Cancellation::Ignore,
            ..Plan::default()
        })
        .await;
        let (sender, receiver) = async_channel::bounded(1);
        let mut future = std::pin::pin!(write(&mut client, file).execute_with_interim(sender));
        assert!(futures::poll!(&mut future).is_pending());
        let held = control.next_call().await;
        drop(receiver);
        assert!(futures::poll!(&mut future).is_pending());
        assert_ne!(control.snapshot(held.id).unwrap().phase, Phase::Abandoned);
        control.release(held.id, Gate::Before).unwrap();
        assert!(matches!(future.await, Err(Error::ResponseChannelClosed)));
        assert_eq!(
            control.snapshot(held.id).unwrap().status,
            Some(Status::SUCCESS)
        );
        assert!(client.connection.state.lock().disconnected);
        client.connection.shutdown().await.unwrap();
    });
}

#[test]
fn credit_replays_and_overlapping_compounds_fail_without_partial_consumption() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let body = SimpleBody {
            structure_size: SimpleBody::STRUCTURE_SIZE.into(),
            reserved: 0.into(),
        };
        let first = client.message;
        let high = request(
            Command::ECHO,
            body.as_bytes(),
            client.session,
            client.tree,
            first + 3,
        );
        client.connection.process(&high).await.unwrap();
        assert!(matches!(
            client.connection.request(high),
            Err(Error::InvalidCreditSequence(_))
        ));
        let mut bytes = compound::packet(
            &mut client,
            vec![
                (Command::ECHO, body.as_bytes().to_vec()),
                (Command::ECHO, body.as_bytes().to_vec()),
            ],
            false,
        );
        Header::mut_from_prefix(&mut bytes[..])
            .unwrap()
            .0
            .credit_charge = 2.into();
        assert!(matches!(
            client.connection.request(bytes),
            Err(Error::InvalidCreditSequence(_))
        ));
        for id in first..first + 2 {
            let bytes = request(
                Command::ECHO,
                body.as_bytes(),
                client.session,
                client.tree,
                id,
            );
            assert_eq!(
                response_status(&client.connection.process(&bytes).await.unwrap()),
                Status::SUCCESS
            );
        }
        let bytes = request(
            Command::ECHO,
            body.as_bytes(),
            client.session,
            client.tree,
            u64::MAX,
        );
        assert!(matches!(
            client.connection.request(bytes),
            Err(Error::InvalidCreditSequence(_))
        ));
    });
}
