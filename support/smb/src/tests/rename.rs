// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::test_support::{ControlledFs, Gate, Operation, Phase, Plan};
use test_with_tracing::test;

pub(super) fn data(name: &str, replace: bool) -> Vec<u8> {
    let name = encode_name(name);
    let mut data = FileRenameInformation {
        replace_if_exists: u8::from(replace),
        reserved: [0; 7],
        root_directory: 0.into(),
        file_name_length: (name.len() as u32).into(),
    }
    .as_bytes()
    .to_vec();
    data.extend(name);
    data.resize(data.len().max(FILE_RENAME_INFORMATION_MIN_SIZE), 0);
    data
}

fn set_body(file: FileId, name: &str) -> Vec<u8> {
    let data = data(name, false);
    let mut body = SetInfoRequest::new_zeroed();
    body.structure_size = SetInfoRequest::STRUCTURE_SIZE.into();
    body.info_type = InformationType::FILE;
    body.info_class = FileInformationClass::RENAME.0;
    body.file_id = file;
    body.buffer_offset = (body_end::<SetInfoRequest>() as u16).into();
    body.buffer_length = (data.len() as u32).into();
    let mut bytes = body.as_bytes().to_vec();
    bytes.extend(data);
    bytes
}

fn accept<B: FileSystem>(client: &mut Client<B>, command: Command, body: &[u8]) -> Request<B> {
    let bytes = request(command, body, client.session, client.tree, client.message);
    client.message += 1;
    client.connection.request(bytes).unwrap()
}

#[test]
fn case_folded_replacement_buffers_the_complete_notification_batch() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("source", 2, 0).await;
        let target = client.open("target", 2, 0).await;
        client.close(target).await;
        let root = client.open("", 1, 1).await;
        let filter = NotifyFilter::new().with_file_name(true);
        let mut watch = std::pin::pin!(
            accept(
                &mut client,
                Command::CHANGE_NOTIFY,
                &notify::body(root, filter, false, 16)
            )
            .execute()
        );
        assert!(futures::poll!(&mut watch).is_pending());
        assert_eq!(
            response_status(
                &client
                    .set(file, FileInformationClass::RENAME.0, &data("TARGET", true))
                    .await
            ),
            Status::SUCCESS
        );
        assert_eq!(
            response_status(&watch.await.unwrap()),
            Status::NOTIFY_ENUM_DIR
        );
        let reply = client
            .ok(
                Command::CHANGE_NOTIFY,
                &notify::body(root, filter, false, 4096),
            )
            .await;
        assert_eq!(
            notify::changes(&reply),
            [
                (NotifyAction::REMOVED, "target".into()),
                (NotifyAction::RENAMED_OLD_NAME, "source".into()),
                (NotifyAction::RENAMED_NEW_NAME, "TARGET".into()),
            ]
        );
        client.close(file).await;
        client.close(root).await;
    });
}

#[test]
fn related_compound_create_rename_close_keeps_the_new_name() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let packet = compound::packet(
            &mut client,
            vec![
                (
                    Command::CREATE,
                    create_body(
                        "before",
                        AccessMask::FILE_ALL_ACCESS.into_bits(),
                        7,
                        2,
                        0,
                        &[],
                    ),
                ),
                (Command::SET_INFO, set_body(FileId::RELATED, "after")),
                (Command::CLOSE, compound::close(FileId::RELATED)),
            ],
            true,
        );
        let reply = client.connection.process(&packet).await.unwrap();
        assert!(
            compound::responses(&reply)
                .iter()
                .all(|reply| response_status(reply) == Status::SUCCESS)
        );
        let file = client.open("after", 1, 0).await;
        client.close(file).await;
    });
}

#[test]
fn invalid_names_do_not_change_the_source() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("source", 2, 0).await;
        for (name, status) in [
            ("trailing\\".into(), Status::OBJECT_NAME_INVALID),
            (".".into(), Status::OBJECT_NAME_INVALID),
            ("..".into(), Status::OBJECT_NAME_INVALID),
            ("wild*card".into(), Status::OBJECT_NAME_INVALID),
            ("control\u{1f}".into(), Status::OBJECT_NAME_INVALID),
            ("x".repeat(256), Status::NAME_TOO_LONG),
        ] {
            assert_eq!(
                response_status(
                    &client
                        .set(file, FileInformationClass::RENAME.0, &data(&name, false))
                        .await
                ),
                status
            );
            let unchanged = client.open("source", 1, 0).await;
            client.close(unchanged).await;
        }
        let response = client
            .set(
                file,
                FileInformationClass::RENAME.0,
                &data("..\\..\\inside", false),
            )
            .await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        let alias = client.open("inside", 1, 0).await;
        assert_eq!(alias.persistent, file.persistent);
        client.close(alias).await;
        client.close(file).await;
    });
}

#[test]
fn rename_preserves_handles_and_identity_across_connections() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut owner = Client::new(&server).await;
        let mut peer = Client::new(&server).await;
        let file = owner.open("before", 2, 0).await;
        let other = peer.open("before", 1, 0).await;
        owner
            .ok(Command::WRITE, &Client::write_body(file, 0, b"contents"))
            .await;
        let identity = owner.query(file, FileInformationClass::INTERNAL.0).await;
        assert_eq!(
            response_status(
                &owner
                    .set(file, FileInformationClass::RENAME.0, &data("after", false))
                    .await
            ),
            Status::SUCCESS
        );
        assert_eq!(&peer.read(other, 0, 8).await[80..], b"contents");
        assert_eq!(
            &peer.query(other, FileInformationClass::INTERNAL.0).await[72..],
            &identity[72..]
        );
        let reopened = peer.open("after", 1, 0).await;
        assert_eq!(&peer.read(reopened, 0, 8).await[80..], b"contents");
        assert_eq!(
            response_status(
                &peer
                    .open_result("before", AccessMask::FILE_ALL_ACCESS.into_bits(), 7, 1, 0)
                    .await
            ),
            Status::OBJECT_NAME_NOT_FOUND
        );
        owner.close(file).await;
        peer.close(other).await;
        peer.close(reopened).await;
    });
}

#[test]
fn rename_wire_validation_precedes_provider_effects() {
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("original", 2, 0).await;
        let valid = data("new", false);
        let mut cases = vec![(valid[..23].to_vec(), Status::INFO_LENGTH_MISMATCH)];
        for (offset, value) in [(8, 1u32), (16, 0), (16, 1), (16, 1000)] {
            let mut malformed = valid.clone();
            malformed[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            cases.push((malformed, Status::INVALID_PARAMETER));
        }

        cases.push((data("\\absolute", false), Status::INVALID_PARAMETER));
        let mut nul = valid.clone();
        nul[20..22].copy_from_slice(&0u16.to_le_bytes());
        cases.push((nul, Status::OBJECT_NAME_INVALID));
        let mut surrogate = valid.clone();
        surrogate[20..22].copy_from_slice(&0xd800u16.to_le_bytes());
        cases.push((surrogate, Status::OBJECT_NAME_INVALID));
        for (malformed, status) in cases {
            assert_eq!(
                response_status(
                    &client
                        .set(file, FileInformationClass::RENAME.0, &malformed)
                        .await
                ),
                status
            );
        }
        assert!(
            control
                .calls()
                .iter()
                .all(|call| call.operation != Operation::Rename)
        );
        let response = client
            .open_result(
                "original",
                AccessMask::FILE_GENERIC_READ.into_bits(),
                7,
                1,
                0,
            )
            .await;
        let restricted = read_body::<CreateResponse>(&response).unwrap().file_id;
        assert_eq!(
            response_status(
                &client
                    .set(restricted, FileInformationClass::RENAME.0, &valid)
                    .await
            ),
            Status::ACCESS_DENIED
        );
        assert!(
            control
                .calls()
                .iter()
                .all(|call| call.operation != Operation::Rename)
        );
        client.close(restricted).await;
        client.close(file).await;
    });
}

#[test]
fn literal_rename_ignores_reserved_padding_and_accepts_nonzero_boolean() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("source", 2, 0).await;
        let target = client.open("x", 2, 0).await;
        client.close(target).await;
        // MS-FSCC §2.4.42.2: 20-byte prefix, name length at 16, minimum 24.
        let mut literal = [0xff; 24];
        literal[0] = 0x80;
        literal[8..16].copy_from_slice(&0u64.to_le_bytes());
        literal[16..20].copy_from_slice(&2u32.to_le_bytes());
        literal[20..22].copy_from_slice(&[b'x', 0]);
        assert_eq!(
            response_status(&client.set(file, 10, &literal).await),
            Status::SUCCESS
        );
        let reopened = client.open("x", 1, 0).await;
        let actual = client.query(file, FileInformationClass::INTERNAL.0).await;
        let expected = client
            .query(reopened, FileInformationClass::INTERNAL.0)
            .await;
        assert_eq!(&actual[72..], &expected[72..]);
        client.close(reopened).await;
        client.close(file).await;
    });
}

#[test]
fn rename_barrier_and_close_preserve_actual_effects() {
    block_on(async {
        for after in [false, true] {
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
            control
                .set_plan(
                    Operation::Rename,
                    Plan {
                        hold_before: !after,
                        hold_after: after,
                        ..Plan::default()
                    },
                )
                .unwrap();
            let server = Server::new("memory", fs).unwrap();
            let mut client = Client::new(&server).await;
            let file = client.open("before", 2, 0).await;
            let mut write = std::pin::pin!(
                accept(
                    &mut client,
                    Command::WRITE,
                    &Client::write_body(file, 0, b"data")
                )
                .execute()
            );
            assert!(futures::poll!(&mut write).is_pending());
            let writing = control.next_call().await;
            assert_eq!(writing.operation, Operation::Write);
            let mut rename = std::pin::pin!(
                accept(&mut client, Command::SET_INFO, &set_body(file, "after")).execute()
            );
            assert!(futures::poll!(&mut rename).is_pending());
            assert!(control.try_next_call().is_none());
            control.release(writing.id, Gate::Before).unwrap();
            assert_eq!(response_status(&write.await.unwrap()), Status::SUCCESS);
            assert!(futures::poll!(&mut rename).is_pending());
            let renaming = control.next_call().await;
            assert_eq!(renaming.operation, Operation::Rename);
            assert_eq!(renaming.name.as_deref(), Some("after"));
            assert_eq!(control.snapshot(renaming.id).unwrap().delegated, after);
            let mut body = CloseRequest::new_zeroed();
            body.structure_size = CloseRequest::STRUCTURE_SIZE.into();
            body.file_id = file;
            let mut close =
                std::pin::pin!(accept(&mut client, Command::CLOSE, body.as_bytes()).execute());
            assert!(futures::poll!(&mut close).is_pending());
            if after {
                control.release(renaming.id, Gate::After).unwrap();
            }
            assert_eq!(
                response_status(&rename.await.unwrap()),
                if after {
                    Status::SUCCESS
                } else {
                    Status::CANCELLED
                }
            );
            assert_eq!(response_status(&close.await.unwrap()), Status::SUCCESS);
            let snapshot = control.snapshot(renaming.id).unwrap();
            assert_eq!(snapshot.phase, Phase::Completed);
            assert!(snapshot.cancel_requested);
            let reopened = client
                .open(if after { "after" } else { "before" }, 1, 0)
                .await;
            assert_eq!(&client.read(reopened, 0, 4).await[80..], b"data");
            client.close(reopened).await;
        }
    });
}

#[test]
fn directory_rename_keeps_its_own_watch_and_child_namespace() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let directory = client.open("before", 2, 1).await;
        let filter = NotifyFilter::new().with_file_name(true);
        let mut watch = std::pin::pin!(
            accept(
                &mut client,
                Command::CHANGE_NOTIFY,
                &notify::body(directory, filter, false, 4096)
            )
            .execute()
        );
        assert!(futures::poll!(&mut watch).is_pending());
        assert_eq!(
            response_status(
                &client
                    .set(
                        directory,
                        FileInformationClass::RENAME.0,
                        &data("after", false)
                    )
                    .await
            ),
            Status::SUCCESS
        );
        assert!(futures::poll!(&mut watch).is_pending());
        let child = client.open("after\\child", 2, 0).await;
        assert_eq!(
            notify::changes(&watch.await.unwrap()),
            [(NotifyAction::ADDED, "child".into())]
        );
        client.close(child).await;
        client.close(directory).await;
    });
}
