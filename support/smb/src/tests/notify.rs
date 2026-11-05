// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::test_support::{ControlledFs, Gate, Operation, Phase, Plan};
use test_with_tracing::test;

pub(super) fn body(file: FileId, filter: NotifyFilter, tree: bool, length: u32) -> Vec<u8> {
    ChangeNotifyRequest {
        structure_size: ChangeNotifyRequest::STRUCTURE_SIZE.into(),
        flags: NotifyFlags::new().with_watch_tree(tree),
        output_buffer_length: length.into(),
        file_id: file,
        completion_filter: filter,
        reserved: u32::MAX.into(),
    }
    .as_bytes()
    .to_vec()
}

fn accept<B: FileSystem>(
    client: &mut Client<B>,
    file: FileId,
    filter: NotifyFilter,
    tree: bool,
    length: u32,
) -> Request<B> {
    let bytes = request(
        Command::CHANGE_NOTIFY,
        &body(file, filter, tree, length),
        client.session,
        client.tree,
        client.message,
    );
    client.message += u64::from(
        Header::read_from_prefix(&bytes)
            .unwrap()
            .0
            .credit_charge
            .get(),
    );
    client.connection.request(bytes).unwrap()
}

fn cancel<B: FileSystem>(client: &Client<B>, message: u64) {
    client
        .connection
        .cancel(&request(
            Command::CANCEL,
            SimpleBody {
                structure_size: SimpleBody::STRUCTURE_SIZE.into(),
                reserved: 0.into(),
            }
            .as_bytes(),
            client.session,
            client.tree,
            message,
        ))
        .unwrap();
}

pub(super) fn changes(bytes: &[u8]) -> Vec<(NotifyAction, String)> {
    assert_eq!(response_status(bytes), Status::SUCCESS);
    let response: BufferResponse = read_body(bytes).unwrap();
    let mut data = &bytes[response.output_buffer_offset.get() as usize..]
        [..response.output_buffer_length.get() as usize];
    let mut result = Vec::new();
    loop {
        let (entry, rest) = FileNotifyInformation::read_from_prefix(data).unwrap();
        result.push((
            NotifyAction(entry.action.get()),
            decode_name(&rest[..entry.file_name_length.get() as usize]).unwrap(),
        ));
        if entry.next_entry_offset.get() == 0 {
            break;
        }
        data = &data[entry.next_entry_offset.get() as usize..];
    }
    result
}

fn empty(bytes: &[u8], status: Status) {
    assert_eq!(response_status(bytes), status);
    let response: BufferResponse = read_body(bytes).unwrap();
    assert_eq!(response.output_buffer_length.get(), 0);
    assert_eq!(bytes.len(), HEADER_SIZE + size_of::<BufferResponse>());
}

#[test]
fn validation_and_multi_credit_checks_precede_watch_registration() {
    block_on(async {
        let fs = MemoryFs::new(1024, 16);
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("ordinary", 2, 0).await;
        let filter = NotifyFilter::new().with_file_name(true);
        assert_eq!(
            response_status(
                &client
                    .send(Command::CHANGE_NOTIFY, &body(file, filter, false, 32))
                    .await
            ),
            Status::INVALID_PARAMETER
        );
        let reply = client
            .open_result(
                "",
                AccessMask::new().with_write_attributes(true).into_bits(),
                7,
                1,
                1,
            )
            .await;
        let restricted = read_body::<CreateResponse>(&reply).unwrap().file_id;
        assert_eq!(
            response_status(
                &client
                    .send(Command::CHANGE_NOTIFY, &body(restricted, filter, false, 32))
                    .await
            ),
            Status::ACCESS_DENIED
        );
        let root = client.open("", 1, 1).await;
        let mut malformed = body(root, filter, false, 32);
        malformed[0] = 31;
        assert_eq!(
            response_status(&client.send(Command::CHANGE_NOTIFY, &malformed).await),
            Status::INVALID_PARAMETER
        );
        assert_eq!(
            response_status(
                &client
                    .send(
                        Command::CHANGE_NOTIFY,
                        &body(root, filter, false, MAX_TRANSFER_SIZE as u32 + 1)
                    )
                    .await
            ),
            Status::INVALID_PARAMETER
        );
        let mut bytes = request(
            Command::CHANGE_NOTIFY,
            &body(root, filter, false, CREDIT_PAYLOAD_SIZE + 1),
            client.session,
            client.tree,
            client.message,
        );
        Header::mut_from_prefix(&mut bytes).unwrap().0.credit_charge = 1.into();
        client.message += 1;
        assert_eq!(
            response_status(&client.connection.process(&bytes).await.unwrap()),
            Status::INVALID_PARAMETER
        );
        client.close(root).await;
        assert_eq!(
            response_status(
                &client
                    .send(Command::CHANGE_NOTIFY, &body(root, filter, false, 32))
                    .await
            ),
            Status::FILE_CLOSED
        );
    });
}

#[test]
fn notify_compound_tail_inherits_a_created_directory_and_non_tail_watches_fail_explicitly() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let filter = NotifyFilter::new().with_file_name(true);
        for related in [false, true] {
            let tail = if related {
                (Command::CLOSE, compound::close(FileId::RELATED))
            } else {
                (
                    Command::ECHO,
                    SimpleBody {
                        structure_size: SimpleBody::STRUCTURE_SIZE.into(),
                        reserved: 0.into(),
                    }
                    .as_bytes()
                    .to_vec(),
                )
            };
            let packet = compound::packet(
                &mut client,
                vec![
                    (Command::CHANGE_NOTIFY, body(root, filter, false, 1024)),
                    tail,
                ],
                related,
            );
            let bytes = client.connection.process(&packet).await.unwrap();
            let replies = compound::responses(&bytes);
            assert_eq!(response_status(replies[0]), Status::NOT_SUPPORTED);
            assert_eq!(
                response_status(replies[1]),
                if related {
                    Status::NOT_SUPPORTED
                } else {
                    Status::SUCCESS
                }
            );
        }
        client.close(root).await;
        let packet = compound::packet(
            &mut client,
            vec![
                (
                    Command::CREATE,
                    create_body(
                        "watched",
                        AccessMask::FILE_ALL_ACCESS.into_bits(),
                        7,
                        2,
                        1,
                        &[],
                    ),
                ),
                (
                    Command::CHANGE_NOTIFY,
                    body(FileId::RELATED, filter, false, 1024),
                ),
            ],
            true,
        );
        let (sender, receiver) = async_channel::bounded(4);
        let mut work = std::pin::pin!(
            client
                .connection
                .request(packet)
                .unwrap()
                .execute_with_interim(sender)
        );
        assert!(futures::poll!(&mut work).is_pending());
        let prefix = receiver.recv().await.unwrap();
        let directory = read_body::<CreateResponse>(&prefix).unwrap().file_id;
        let pending = AsyncHeader::read_from_prefix(&receiver.recv().await.unwrap())
            .unwrap()
            .0;
        assert_eq!(Status(pending.status.get()), Status::PENDING);
        let child = client.open("watched\\new", 2, 0).await;
        work.await.unwrap();
        let final_frame = receiver.recv().await.unwrap();
        assert_eq!(changes(&final_frame), [(NotifyAction::ADDED, "new".into())]);
        assert_eq!(
            AsyncHeader::read_from_prefix(&final_frame)
                .unwrap()
                .0
                .async_id,
            pending.async_id
        );
        client.close(child).await;
        client.close(directory).await;
    });
}

#[test]
fn first_filter_and_scope_persist_and_buffer_events_between_requests() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let filter = NotifyFilter::from_bits(0x80000001);
        let mut first = std::pin::pin!(accept(&mut client, root, filter, false, 1024).execute());
        assert!(futures::poll!(&mut first).is_pending());
        let sub = client.open("sub", 2, 1).await;
        let nested = client.open("sub\\ignored", 2, 0).await;
        assert!(futures::poll!(&mut first).is_pending());
        let child = client.open("\u{e9}", 2, 0).await;
        let bytes = first.await.unwrap();
        assert_eq!(
            changes(&bytes),
            [(NotifyAction::ADDED, "\u{e9}".to_owned())]
        );
        assert_eq!(&bytes[64..72], &[9, 0, 72, 0, 16, 0, 0, 0]);
        assert_eq!(
            &bytes[72..],
            &[0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0xe9, 0, 0, 0]
        );
        let buffered = client.open("buffered", 2, 0).await;
        let b = client.open("b", 2, 0).await;
        empty(
            &accept(&mut client, root, filter, false, 28)
                .execute()
                .await
                .unwrap(),
            Status::NOTIFY_ENUM_DIR,
        );
        let bytes = accept(
            &mut client,
            root,
            NotifyFilter::new().with_dir_name(true),
            true,
            1024,
        )
        .execute()
        .await
        .unwrap();
        assert_eq!(
            changes(&bytes),
            [
                (NotifyAction::ADDED, "buffered".to_owned()),
                (NotifyAction::ADDED, "b".to_owned())
            ]
        );
        assert_eq!(&bytes[72..76], &[28, 0, 0, 0]);
        assert_eq!(&bytes[100..104], &[0, 0, 0, 0]);
        for id in [child, buffered, b, nested, sub, root] {
            client.close(id).await;
        }
    });
}

#[test]
fn root_changes_do_not_notify_the_root_itself_or_block_metadata_mutations() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let filter = NotifyFilter::new().with_attributes(true);
        let mut work = std::pin::pin!(accept(&mut client, root, filter, true, 1024).execute());
        assert!(futures::poll!(&mut work).is_pending());
        let mut info = FileBasicInformation::new_zeroed();
        info.file_attributes = FileAttributes::new().with_archive(true).into_bits().into();
        assert_eq!(
            response_status(
                &client
                    .set(root, FileInformationClass::BASIC.0, info.as_bytes())
                    .await
            ),
            Status::SUCCESS
        );
        assert!(futures::poll!(&mut work).is_pending());
        let child = client.open("child", 2, 0).await;
        info.file_attributes = FileAttributes::new().with_hidden(true).into_bits().into();
        assert_eq!(
            response_status(
                &client
                    .set(child, FileInformationClass::BASIC.0, info.as_bytes())
                    .await
            ),
            Status::SUCCESS
        );
        assert_eq!(
            changes(&work.await.unwrap()),
            [(NotifyAction::MODIFIED, "child".into())]
        );
        client.close(child).await;
        client.close(root).await;
    });
}

#[test]
fn recursive_watches_are_independent_and_report_relative_names() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let sub = client.open("Sub", 2, 1).await;
        let filter = NotifyFilter::new().with_file_name(true);
        let mut outer = std::pin::pin!(accept(&mut client, root, filter, true, 1024).execute());
        let mut inner = std::pin::pin!(accept(&mut client, sub, filter, false, 1024).execute());
        assert!(futures::poll!(&mut outer).is_pending());
        assert!(futures::poll!(&mut inner).is_pending());
        let child = client.open("Sub\\Child", 2, 0).await;
        assert_eq!(
            changes(&outer.await.unwrap()),
            [(NotifyAction::ADDED, "Sub\\Child".into())]
        );
        assert_eq!(
            changes(&inner.await.unwrap()),
            [(NotifyAction::ADDED, "Child".into())]
        );
        client.close(child).await;
        client.close(sub).await;
        client.close(root).await;
    });
}

#[test]
fn notifications_complete_fifo_even_when_polled_backwards_and_middle_is_canceled() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let filter = NotifyFilter::new().with_file_name(true);
        let first = accept(&mut client, root, filter, false, 1024);
        let middle_id = client.message;
        let middle = accept(&mut client, root, filter, false, 1024);
        let last = accept(&mut client, root, filter, false, 1024);
        let mut first = std::pin::pin!(first.execute());
        let mut middle = std::pin::pin!(middle.execute());
        let mut last = std::pin::pin!(last.execute());
        assert!(futures::poll!(&mut last).is_pending());
        assert!(futures::poll!(&mut middle).is_pending());
        assert!(futures::poll!(&mut first).is_pending());
        let a = client.open("first", 2, 0).await;
        assert!(futures::poll!(&mut last).is_pending());
        assert_eq!(
            changes(&first.await.unwrap()),
            [(NotifyAction::ADDED, "first".into())]
        );
        cancel(&client, middle_id);
        assert_eq!(response_status(&middle.await.unwrap()), Status::CANCELLED);
        let b = client.open("second", 2, 0).await;
        assert_eq!(
            changes(&last.await.unwrap()),
            [(NotifyAction::ADDED, "second".into())]
        );
        for id in [a, b, root] {
            client.close(id).await;
        }
    });
}

#[test]
fn cancel_before_first_poll_still_establishes_the_persistent_watch() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let message = client.message;
        let filter = NotifyFilter::new().with_dir_name(true);
        let first = accept(&mut client, root, filter, false, 1024);
        cancel(&client, message);
        assert_eq!(
            response_status(&first.execute().await.unwrap()),
            Status::CANCELLED
        );
        let child = client.open("buffered", 2, 1).await;
        assert_eq!(
            changes(
                &accept(&mut client, root, NotifyFilter::new(), true, 1024)
                    .execute()
                    .await
                    .unwrap()
            ),
            [(NotifyAction::ADDED, "buffered".into())]
        );
        client.close(child).await;
        client.close(root).await;
    });
}

#[test]
fn zero_and_unknown_filters_wait_until_cancel_and_close_cleans_all_waiters() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let message = client.message;
        let filter = NotifyFilter::from_bits(0x80000000);
        let mut first = std::pin::pin!(accept(&mut client, root, filter, false, 1024).execute());
        assert!(futures::poll!(&mut first).is_pending());
        let child = client.open("ignored", 2, 0).await;
        assert!(futures::poll!(&mut first).is_pending());
        cancel(&client, message);
        assert_eq!(response_status(&first.await.unwrap()), Status::CANCELLED);
        let mut a = std::pin::pin!(
            accept(
                &mut client,
                root,
                NotifyFilter::new().with_file_name(true),
                true,
                1024
            )
            .execute()
        );
        let mut b = std::pin::pin!(accept(&mut client, root, filter, false, 1024).execute());
        assert!(futures::poll!(&mut a).is_pending());
        assert!(futures::poll!(&mut b).is_pending());
        let (a, b, ()) = futures::join!(a, b, client.close(root));
        empty(&a.unwrap(), Status::NOTIFY_CLEANUP);
        empty(&b.unwrap(), Status::NOTIFY_CLEANUP);
        client.close(child).await;
    });
}

#[test]
fn insufficient_output_retains_the_batch_and_bounded_overflow_recovers() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 256)).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let filter = NotifyFilter::new().with_file_name(true);
        let mut small = std::pin::pin!(accept(&mut client, root, filter, false, 0).execute());
        assert!(futures::poll!(&mut small).is_pending());
        let child = client.open("retained", 2, 0).await;
        empty(&small.await.unwrap(), Status::NOTIFY_ENUM_DIR);
        assert_eq!(
            changes(
                &accept(&mut client, root, filter, false, 1024)
                    .execute()
                    .await
                    .unwrap()
            ),
            [(NotifyAction::ADDED, "retained".into())]
        );
        client.close(child).await;
        let mut overflow = std::pin::pin!(accept(&mut client, root, filter, false, 1024).execute());
        assert!(futures::poll!(&mut overflow).is_pending());
        for i in 0..140 {
            let child = client
                .open(&format!("{i:03}{}", "x".repeat(247)), 2, 0)
                .await;
            client.close(child).await;
        }
        empty(&overflow.await.unwrap(), Status::NOTIFY_ENUM_DIR);
        let mut recovered =
            std::pin::pin!(accept(&mut client, root, filter, false, 1024).execute());
        assert!(futures::poll!(&mut recovered).is_pending());
        let child = client.open("recovered", 2, 0).await;
        assert_eq!(
            changes(&recovered.await.unwrap()),
            [(NotifyAction::ADDED, "recovered".into())]
        );
        client.close(child).await;
        client.close(root).await;
    });
}

#[test]
fn canceled_waiters_do_not_consume_already_queued_events() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let message = client.message;
        let filter = NotifyFilter::new().with_file_name(true);
        let mut first = std::pin::pin!(accept(&mut client, root, filter, false, 1024).execute());
        assert!(futures::poll!(&mut first).is_pending());
        cancel(&client, 0);
        assert!(futures::poll!(&mut first).is_pending());
        let child = client.open("retained-after-cancel", 2, 0).await;
        cancel(&client, message);
        assert_eq!(response_status(&first.await.unwrap()), Status::CANCELLED);
        assert_eq!(
            changes(
                &accept(&mut client, root, filter, false, 1024)
                    .execute()
                    .await
                    .unwrap()
            ),
            [(NotifyAction::ADDED, "retained-after-cancel".into())]
        );
        client.close(child).await;
        client.close(root).await;
    });
}

#[test]
fn controlled_registration_survives_cancel_at_the_before_gate_and_reports_real_errors() {
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        control
            .set_plan(
                Operation::Notify,
                Plan {
                    hold_before: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let message = client.message;
        let filter = NotifyFilter::new().with_file_name(true);
        let mut first = std::pin::pin!(accept(&mut client, root, filter, false, 1024).execute());
        assert!(futures::poll!(&mut first).is_pending());
        let call = control.next_call().await;
        assert!(!control.snapshot(call.id).unwrap().delegated);
        cancel(&client, message);
        assert_eq!(response_status(&first.await.unwrap()), Status::CANCELLED);
        assert!(control.snapshot(call.id).unwrap().delegated);
        let child = client.open("retained", 2, 0).await;
        control
            .set_plan(Operation::Notify, Plan::default())
            .unwrap();
        assert_eq!(
            changes(
                &accept(&mut client, root, NotifyFilter::new(), true, 1024)
                    .execute()
                    .await
                    .unwrap()
            ),
            [(NotifyAction::ADDED, "retained".into())]
        );
        control
            .set_plan(
                Operation::Notify,
                Plan {
                    failure: Some(Status::NOT_SUPPORTED),
                    ..Plan::default()
                },
            )
            .unwrap();
        assert_eq!(
            response_status(
                &accept(&mut client, root, filter, false, 1024)
                    .execute()
                    .await
                    .unwrap()
            ),
            Status::NOT_SUPPORTED
        );
        client.close(child).await;
        client.close(root).await;
    });
}

#[test]
fn mutation_filters_ignore_failed_effects_and_notify_actual_size_metadata_and_removal() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let child = client.open("data", 2, 0).await;
        let mut size = std::pin::pin!(
            accept(
                &mut client,
                root,
                NotifyFilter::new().with_size(true),
                false,
                1024
            )
            .execute()
        );
        assert!(futures::poll!(&mut size).is_pending());
        let failed = client
            .send(Command::WRITE, &Client::write_body(child, 0, &[1; 1025]))
            .await;
        assert_eq!(response_status(&failed), Status::DISK_FULL);
        assert!(futures::poll!(&mut size).is_pending());
        let basic = FileBasicInformation {
            creation_time: 11.into(),
            last_access_time: 12.into(),
            last_write_time: 13.into(),
            change_time: 0.into(),
            file_attributes: FileAttributes::new().with_hidden(true).into_bits().into(),
            reserved: 0.into(),
        };
        assert_eq!(
            response_status(
                &client
                    .set(root, FileInformationClass::BASIC.0, basic.as_bytes())
                    .await
            ),
            Status::SUCCESS
        );
        assert!(futures::poll!(&mut size).is_pending());
        client
            .ok(Command::WRITE, &Client::write_body(child, 0, b"abc"))
            .await;
        assert_eq!(
            changes(&size.await.unwrap()),
            [(NotifyAction::MODIFIED, "data".into())]
        );
        // A fresh open has an independent filter; the previous open remains size-only.
        let other = client.open("", 1, 1).await;
        let filter = NotifyFilter::new()
            .with_attributes(true)
            .with_creation(true)
            .with_last_access(true)
            .with_last_write(true);
        let mut metadata =
            std::pin::pin!(accept(&mut client, other, filter, false, 1024).execute());
        assert!(futures::poll!(&mut metadata).is_pending());
        assert_eq!(
            response_status(
                &client
                    .set(child, FileInformationClass::BASIC.0, basic.as_bytes())
                    .await
            ),
            Status::SUCCESS
        );
        assert_eq!(
            changes(&metadata.await.unwrap()),
            [(NotifyAction::MODIFIED, "data".into())]
        );
        let mut removed = std::pin::pin!(accept(&mut client, other, filter, false, 1024).execute());
        assert!(futures::poll!(&mut removed).is_pending());
        client.read(child, 0, 3).await;
        assert!(futures::poll!(&mut removed).is_pending());
        let mut restore = FileBasicInformation::new_zeroed();
        restore.last_access_time = TIME_RESTORE.into();
        assert_eq!(
            response_status(
                &client
                    .set(child, FileInformationClass::BASIC.0, restore.as_bytes())
                    .await
            ),
            Status::SUCCESS
        );
        client.read(child, 0, 3).await;
        assert_eq!(
            changes(&removed.await.unwrap()),
            [(NotifyAction::MODIFIED, "data".into())]
        );
        let deletion = client.open("", 1, 1).await;
        let mut removed = std::pin::pin!(
            accept(
                &mut client,
                deletion,
                NotifyFilter::new().with_file_name(true),
                false,
                1024
            )
            .execute()
        );
        assert!(futures::poll!(&mut removed).is_pending());
        assert_eq!(
            response_status(
                &client
                    .set(child, FileInformationClass::DISPOSITION.0, &[1])
                    .await
            ),
            Status::SUCCESS
        );
        assert!(futures::poll!(&mut removed).is_pending());
        client.close(child).await;
        assert_eq!(
            changes(&removed.await.unwrap()),
            [(NotifyAction::REMOVED, "data".into())]
        );
        for id in [other, deletion, root] {
            client.close(id).await;
        }
    });
}

#[test]
fn directory_deletion_completes_pending_notifies_without_closing_the_watched_handle() {
    block_on(async {
        for separate_connection in [false, true] {
            for initial_delete_on_close in [false, true] {
                let memory = MemoryFs::new(1024, 16);
                let server = Server::new("memory", memory.clone()).unwrap();
                let mut owner = Client::new(&server).await;
                let mut other = Client::new(&server).await;
                let directory = owner.open("deleted-directory", 2, 1).await;
                let watched = if separate_connection {
                    other.open("deleted-directory", 1, 1).await
                } else {
                    owner.open("deleted-directory", 1, 1).await
                };
                let request = accept(
                    if separate_connection {
                        &mut other
                    } else {
                        &mut owner
                    },
                    watched,
                    NotifyFilter::new().with_file_name(true),
                    false,
                    1024,
                );
                let mut notification = std::pin::pin!(request.execute());
                assert!(futures::poll!(&mut notification).is_pending());
                if initial_delete_on_close {
                    let deleting = owner
                        .open(
                            "deleted-directory",
                            1,
                            CreateOptions::new()
                                .with_directory_file(true)
                                .with_delete_on_close(true)
                                .into_bits(),
                        )
                        .await;
                    owner.close(deleting).await;
                } else {
                    assert_eq!(
                        response_status(
                            &owner
                                .set(directory, FileInformationClass::DISPOSITION.0, &[1])
                                .await
                        ),
                        Status::SUCCESS
                    );
                    // Clearing disposition before polling must not erase the completion.
                    assert_eq!(
                        response_status(
                            &owner
                                .set(directory, FileInformationClass::DISPOSITION.0, &[0])
                                .await
                        ),
                        Status::SUCCESS
                    );
                }
                let Poll::Ready(reply) = futures::poll!(&mut notification) else {
                    panic!("directory deletion left CHANGE_NOTIFY pending");
                };
                assert_eq!(response_status(&reply.unwrap()), Status::DELETE_PENDING);
                assert_eq!(runtime::inspect_text("watch_count", &memory).await, "0");
                assert_eq!(runtime::inspect_text("notify_waiters", &memory).await, "0");
                owner.close(directory).await;
                if separate_connection {
                    other.close(watched).await;
                } else {
                    owner.close(watched).await;
                }
                assert_eq!(runtime::inspect_text("opens", &memory).await, "0");
            }
        }
    });
}

#[test]
fn closing_the_receiver_after_interim_cancels_and_drains_a_waiting_notification() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let (sender, receiver) = async_channel::bounded(2);
        let mut work = std::pin::pin!(
            accept(
                &mut client,
                root,
                NotifyFilter::new().with_file_name(true),
                false,
                1024
            )
            .execute_with_interim(sender)
        );
        assert!(futures::poll!(&mut work).is_pending());
        assert_eq!(
            response_status(&receiver.recv().await.unwrap()),
            Status::PENDING
        );
        receiver.close();
        assert!(matches!(
            futures::poll!(&mut work),
            Poll::Ready(Err(Error::ResponseChannelClosed))
        ));
        assert!(client.connection.state.lock().requests.is_empty());
        assert!(client.connection.state.lock().disconnected);
        client.connection.shutdown().await.unwrap();
    });
}

#[test]
fn async_cancel_selects_the_queued_notification_without_stealing_events_or_credits() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let baseline = client.connection.state.lock().window.len();
        let filter = NotifyFilter::new().with_file_name(true);
        let first = accept(&mut client, root, filter, false, 1024);
        let second = accept(&mut client, root, filter, false, 1024);
        let (sender, receiver) = async_channel::bounded(4);
        let mut first = std::pin::pin!(first.execute_with_interim(sender.clone()));
        let mut second = std::pin::pin!(second.execute_with_interim(sender));
        assert!(futures::poll!(&mut first).is_pending());
        assert!(futures::poll!(&mut second).is_pending());
        let a = AsyncHeader::read_from_prefix(&receiver.recv().await.unwrap())
            .unwrap()
            .0;
        let b = AsyncHeader::read_from_prefix(&receiver.recv().await.unwrap())
            .unwrap()
            .0;
        assert_ne!(a.async_id, b.async_id);
        assert_eq!(Status(a.status.get()), Status::PENDING);
        assert_eq!(Status(b.status.get()), Status::PENDING);
        pending::cancel(&client, b.async_id.get());
        second.await.unwrap();
        let canceled = AsyncHeader::read_from_prefix(&receiver.recv().await.unwrap())
            .unwrap()
            .0;
        assert_eq!(Status(canceled.status.get()), Status::CANCELLED);
        assert_eq!(canceled.async_id, b.async_id);
        assert_eq!(canceled.credits.get(), 0);
        assert!(futures::poll!(&mut first).is_pending());
        let child = client.open("queued", 2, 0).await;
        pending::cancel(&client, a.async_id.get());
        first.await.unwrap();
        let canceled = AsyncHeader::read_from_prefix(&receiver.recv().await.unwrap())
            .unwrap()
            .0;
        assert_eq!(Status(canceled.status.get()), Status::CANCELLED);
        assert_eq!(canceled.async_id, a.async_id);
        assert_eq!(canceled.credits.get(), 0);
        assert_eq!(client.connection.state.lock().window.len(), baseline);
        assert_eq!(
            changes(
                &accept(&mut client, root, filter, false, 1024)
                    .execute()
                    .await
                    .unwrap()
            ),
            [(NotifyAction::ADDED, "queued".into())]
        );
        client.close(child).await;
        client.close(root).await;
    });
}

#[test]
fn obtained_event_survives_late_cancel_and_close_while_delivery_is_gated() {
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        control
            .set_plan(
                Operation::Notify,
                Plan {
                    hold_after: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let message = client.message;
        let mut pending = std::pin::pin!(
            accept(
                &mut client,
                root,
                NotifyFilter::new().with_file_name(true),
                false,
                1024
            )
            .execute()
        );
        assert!(futures::poll!(&mut pending).is_pending());
        let call = control.next_call().await;
        let child = client.open("committed", 2, 0).await;
        assert!(futures::poll!(&mut pending).is_pending());
        assert_eq!(control.snapshot(call.id).unwrap().phase, Phase::After);
        cancel(&client, message);
        {
            let mut close = std::pin::pin!(client.close(root));
            assert!(futures::poll!(&mut close).is_pending());
            control.release(call.id, Gate::After).unwrap();
            let (result, ()) = futures::join!(pending, close);
            assert_eq!(
                changes(&result.unwrap()),
                [(NotifyAction::ADDED, "committed".into())]
            );
        }
        assert!(
            !control
                .calls()
                .iter()
                .any(|call| call.phase == Phase::Abandoned)
        );
        client.close(child).await;
    });
}
