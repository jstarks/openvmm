// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

pub(super) fn packet<B: FileSystem>(
    client: &mut Client<B>,
    commands: Vec<(Command, Vec<u8>)>,
    related: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    let count = commands.len();
    for (index, (command, body)) in commands.into_iter().enumerate() {
        let mut bytes = request(command, &body, client.session, client.tree, client.message);
        let (header, _) = Header::mut_from_prefix(&mut bytes[..]).unwrap();
        client.message += u64::from(header.credit_charge.get().max(1));
        if related && index != 0 {
            header.flags.set_related_operations(true);
            // These values must be ignored, not merely accepted as a special sentinel.
            header.session_id = 42.into();
            header.tree_id = 43.into();
        }
        if index != count - 1 {
            let length = align_up(bytes.len(), COMPOUND_ALIGNMENT).unwrap();
            Header::mut_from_prefix(&mut bytes[..])
                .unwrap()
                .0
                .next_command = (length as u32).into();
            bytes.resize(length, 0);
        }
        out.extend(bytes);
    }
    out
}

pub(super) fn responses(mut packet: &[u8]) -> Vec<&[u8]> {
    let mut replies = Vec::new();
    loop {
        let header = Header::read_from_prefix(packet).unwrap().0;
        let next = header.next_command.get() as usize;
        if next == 0 {
            replies.push(packet);
            break;
        }
        assert!(next.is_multiple_of(COMPOUND_ALIGNMENT));
        replies.push(&packet[..next]);
        packet = &packet[next..];
    }
    replies
}

pub(super) fn refresh<B: FileSystem>(client: &mut Client<B>, packet: &mut [u8]) {
    let mut offset = 0;
    loop {
        let header = Header::mut_from_prefix(&mut packet[offset..]).unwrap().0;
        header.message_id = client.message.into();
        client.message += u64::from(header.credit_charge.get().max(1));
        let next = header.next_command.get() as usize;
        if next == 0 {
            break;
        }
        offset += next;
    }
}

pub(super) fn read(file: FileId, length: u32) -> Vec<u8> {
    let mut request = ReadRequest::new_zeroed();
    request.structure_size = ReadRequest::STRUCTURE_SIZE.into();
    request.file_id = file;
    request.length = length.into();
    request.as_bytes().to_vec()
}

pub(super) fn close(file: FileId) -> Vec<u8> {
    let mut request = CloseRequest::new_zeroed();
    request.structure_size = CloseRequest::STRUCTURE_SIZE.into();
    request.file_id = file;
    request.as_bytes().to_vec()
}

fn echo() -> Vec<u8> {
    SimpleBody {
        structure_size: SimpleBody::STRUCTURE_SIZE.into(),
        reserved: 0.into(),
    }
    .as_bytes()
    .to_vec()
}

#[test]
fn related_session_tree_and_file_creation_propagate_generated_identifiers() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client {
            connection: server.connect(),
            session: 0,
            tree: 0,
            message: 0,
        };
        client.ok(Command::NEGOTIATE, &negotiate_body()).await;
        let mut setup = SessionSetupRequest::new_zeroed();
        setup.structure_size = SessionSetupRequest::STRUCTURE_SIZE.into();
        let bytes = packet(
            &mut client,
            vec![
                (Command::SESSION_SETUP, setup.as_bytes().to_vec()),
                (Command::TREE_CONNECT, tree_body()),
                (Command::CREATE, create_body("generated", 1, 7, 2, 0, &[])),
                (Command::CLOSE, close(FileId::RELATED)),
            ],
            true,
        );
        let response = client.connection.process(&bytes).await.unwrap();
        let replies = responses(&response);
        assert!(
            replies
                .iter()
                .all(|reply| response_status(reply) == Status::SUCCESS)
        );
        let session = Header::read_from_prefix(replies[0])
            .unwrap()
            .0
            .session_id
            .get();
        let tree = Header::read_from_prefix(replies[1])
            .unwrap()
            .0
            .tree_id
            .get();
        assert_ne!(session, 0);
        assert_ne!(tree, 0);
        for reply in &replies[1..] {
            assert_eq!(
                Header::read_from_prefix(reply).unwrap().0.session_id.get(),
                session
            );
            assert_eq!(
                Header::read_from_prefix(reply).unwrap().0.tree_id.get(),
                tree
            );
        }
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client {
            connection: server.connect(),
            session: 0,
            tree: 0,
            message: 0,
        };
        client.ok(Command::NEGOTIATE, &negotiate_body()).await;
        setup.flags = SessionSetupFlags::new().with_binding(true);
        let bytes = packet(
            &mut client,
            vec![
                (Command::SESSION_SETUP, setup.as_bytes().to_vec()),
                (Command::TREE_CONNECT, tree_body()),
                (Command::ECHO, echo()),
            ],
            true,
        );
        let response = client.connection.process(&bytes).await.unwrap();
        let replies = responses(&response);
        assert_eq!(response_status(replies[0]), Status::NOT_SUPPORTED);
        assert_eq!(response_status(replies[1]), Status::INVALID_PARAMETER);
        assert_eq!(response_status(replies[2]), Status::INVALID_PARAMETER);
    });
}

#[test]
fn related_create_write_read_query_close_use_inherited_ids_and_local_offsets() {
    block_on(async {
        let memory = MemoryFs::new(1024, 16);
        let server = Server::new("memory", memory).unwrap();
        let mut client = Client::new(&server).await;
        let mut query = QueryInfoRequest::new_zeroed();
        query.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
        query.info_type = InformationType::FILE;
        query.info_class = FileInformationClass::ALL.0;
        query.file_id = FileId::new_zeroed();
        query.output_buffer_length = 1024.into();
        let bytes = packet(
            &mut client,
            vec![
                (
                    Command::CREATE,
                    create_body(
                        "chain",
                        AccessMask::FILE_ALL_ACCESS.into_bits(),
                        ShareAccess::ALL.into_bits(),
                        CreateDisposition::CREATE.0,
                        0,
                        &[],
                    ),
                ),
                (
                    Command::WRITE,
                    Client::write_body(FileId::RELATED, 0, b"abc"),
                ),
                (Command::READ, read(FileId::new_zeroed(), 3)),
                (Command::QUERY_INFO, query.as_bytes().to_vec()),
                (Command::CLOSE, close(FileId::RELATED)),
            ],
            true,
        );
        let response = client.connection.process(&bytes).await.unwrap();
        let replies = responses(&response);
        assert_eq!(replies.len(), 5);
        assert!(response.len().is_multiple_of(COMPOUND_ALIGNMENT));
        for (index, reply) in replies.iter().enumerate() {
            let header = Header::read_from_prefix(reply).unwrap().0;
            assert_eq!(header.status(), Status::SUCCESS);
            assert_eq!(header.session_id.get(), client.session);
            assert_eq!(header.tree_id.get(), client.tree);
            assert_eq!(header.flags.related_operations(), index != 0);
            assert!(header.credits.get() > 0);
        }
        let read = read_body::<ReadResponse>(replies[2]).unwrap();
        assert_eq!(
            variable::<ReadResponse>(
                replies[2],
                read.data_offset as usize,
                read.data_length.get() as usize
            )
            .unwrap(),
            b"abc"
        );
        let query = read_body::<BufferResponse>(replies[3]).unwrap();
        let data = variable::<BufferResponse>(
            replies[3],
            query.output_buffer_offset.get() as usize,
            query.output_buffer_length.get() as usize,
        )
        .unwrap();
        assert_eq!(
            FileAllInformation::read_from_prefix(data)
                .unwrap()
                .0
                .standard
                .end_of_file
                .get(),
            3
        );
        let file = read_body::<CreateResponse>(replies[0]).unwrap().file_id;
        assert_eq!(
            response_status(&client.read(file, 0, 3).await),
            Status::FILE_CLOSED
        );
        let reopened = client.open("chain", CreateDisposition::OPEN.0, 0).await;
        assert_eq!(&client.read(reopened, 0, 3).await[80..], b"abc");
    });
}

#[test]
fn related_failures_propagate_but_unrelated_operations_remain_independent() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let bytes = packet(
            &mut client,
            vec![
                (
                    Command::CREATE,
                    create_body("missing", 1, 7, CreateDisposition::OPEN.0, 0, &[]),
                ),
                (Command::READ, read(FileId::RELATED, 3)),
                (Command::CLOSE, close(FileId::RELATED)),
            ],
            true,
        );
        let response = client.connection.process(&bytes).await.unwrap();
        assert!(
            responses(&response)
                .iter()
                .all(|reply| response_status(reply) == Status::OBJECT_NAME_NOT_FOUND)
        );
        let mut unsupported = IoctlRequest::new_zeroed();
        unsupported.structure_size = IoctlRequest::STRUCTURE_SIZE.into();
        unsupported.file_id = FileId::RELATED;
        let bytes = packet(
            &mut client,
            vec![
                (
                    Command::CREATE,
                    create_body("missing", 1, 7, CreateDisposition::OPEN.0, 0, &[]),
                ),
                (Command::IOCTL, unsupported.as_bytes().to_vec()),
                (Command::CLOSE, close(FileId::RELATED)),
            ],
            true,
        );
        let response = client.connection.process(&bytes).await.unwrap();
        assert!(
            responses(&response)
                .iter()
                .all(|reply| response_status(reply) == Status::OBJECT_NAME_NOT_FOUND)
        );
        let bytes = packet(
            &mut client,
            vec![
                (Command::ECHO, echo()),
                (Command::READ, read(FileId::RELATED, 3)),
                (Command::ECHO, echo()),
            ],
            true,
        );
        let response = client.connection.process(&bytes).await.unwrap();
        let replies = responses(&response);
        assert_eq!(response_status(replies[0]), Status::SUCCESS);
        assert_eq!(response_status(replies[1]), Status::INVALID_HANDLE);
        assert_eq!(response_status(replies[2]), Status::INVALID_HANDLE);
        let file = client.open("failed-io", 2, 0).await;
        let bytes = packet(
            &mut client,
            vec![
                (Command::WRITE, Client::write_body(file, u64::MAX, b"x")),
                (Command::READ, read(FileId::RELATED, 1)),
                (Command::ECHO, echo()),
            ],
            true,
        );
        let response = client.connection.process(&bytes).await.unwrap();
        let replies = responses(&response);
        assert_eq!(response_status(replies[0]), Status::INVALID_PARAMETER);
        assert_eq!(response_status(replies[1]), Status::INVALID_PARAMETER);
        assert_eq!(response_status(replies[2]), Status::SUCCESS);
        let bytes = packet(
            &mut client,
            vec![
                (Command::READ, read(FileId::RELATED, 3)),
                (Command::ECHO, echo()),
                (
                    Command::CREATE,
                    create_body("independent", 1, 7, CreateDisposition::CREATE.0, 0, &[]),
                ),
            ],
            false,
        );
        let response = client.connection.process(&bytes).await.unwrap();
        let replies = responses(&response);
        assert_eq!(response_status(replies[0]), Status::FILE_CLOSED);
        assert_eq!(response_status(replies[1]), Status::SUCCESS);
        assert_eq!(response_status(replies[2]), Status::SUCCESS);
        assert!(replies.iter().all(|reply| {
            !Header::read_from_prefix(reply)
                .unwrap()
                .0
                .flags
                .related_operations()
        }));
    });
}

#[test]
fn malformed_chains_and_mixed_styles_are_rejected_before_filesystem_effects() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let bytes = packet(
            &mut client,
            vec![
                (Command::CREATE, create_body("invalid", 1, 7, 2, 0, &[])),
                (Command::ECHO, echo()),
                (Command::ECHO, echo()),
            ],
            true,
        );
        let first = Header::read_from_prefix(&bytes)
            .unwrap()
            .0
            .next_command
            .get() as usize;
        let second = first
            + Header::read_from_prefix(&bytes[first..])
                .unwrap()
                .0
                .next_command
                .get() as usize;
        for next in [1u32, 63, 65, bytes.len() as u32, u32::MAX] {
            let mut invalid = bytes.clone();
            Header::mut_from_prefix(&mut invalid[..])
                .unwrap()
                .0
                .next_command = next.into();
            assert!(client.connection.request(invalid).is_err());
        }
        let mut invalid = bytes.clone();
        Header::mut_from_prefix(&mut invalid[first..])
            .unwrap()
            .0
            .protocol = [0; 4];
        assert!(matches!(
            client.connection.request(invalid),
            Err(Error::InvalidHeader)
        ));
        let mut invalid = bytes.clone();
        Header::mut_from_prefix(&mut invalid[first..])
            .unwrap()
            .0
            .command = 0xff.into();
        assert!(matches!(
            client.connection.request(invalid),
            Err(Error::InvalidHeader)
        ));
        let mut duplicate = bytes.clone();
        let id = Header::read_from_prefix(&bytes).unwrap().0.message_id;
        Header::mut_from_prefix(&mut duplicate[first..])
            .unwrap()
            .0
            .message_id = id;
        assert!(matches!(
            client.connection.request(duplicate),
            Err(Error::DuplicateMessageId(_))
        ));
        let mut cross_command = bytes.clone();
        let create = CreateRequest::mut_from_prefix(&mut cross_command[HEADER_SIZE..])
            .unwrap()
            .0;
        create.name_offset = ((first + HEADER_SIZE) as u16).into();
        create.name_length = 2.into();
        let response = client.connection.process(&cross_command).await.unwrap();
        assert_eq!(
            response_status(responses(&response)[0]),
            Status::INVALID_PARAMETER
        );
        // The following ECHO body begins with UTF-16 U+0004. It is not CREATE data.
        assert_eq!(
            response_status(
                &client
                    .open_result("\u{4}", 1, 7, CreateDisposition::OPEN.0, 0)
                    .await
            ),
            Status::OBJECT_NAME_NOT_FOUND
        );
        let unused = client.message;
        let oversized = packet(
            &mut client,
            (0..=MAX_REQUESTS)
                .map(|_| (Command::ECHO, echo()))
                .collect(),
            false,
        );
        assert!(matches!(
            client.connection.request(oversized),
            Err(Error::InvalidCompound)
        ));
        client.message = unused;
        for offset in [0, second] {
            let mut mixed = bytes.clone();
            refresh(&mut client, &mut mixed);
            let header = Header::mut_from_prefix(&mut mixed[offset..]).unwrap().0;
            header.flags.set_related_operations(offset == 0);
            let response = client.connection.process(&mixed).await.unwrap();
            assert!(
                responses(&response)
                    .iter()
                    .all(|reply| response_status(reply) == Status::INVALID_PARAMETER)
            );
        }
        client.open("invalid", CreateDisposition::CREATE.0, 0).await;
        assert!(client.connection.state.lock().requests.is_empty());
    });
}

#[test]
fn per_command_credit_charge_and_close_before_later_io_are_enforced() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(128 * 1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("credits", 2, 0).await;
        let bytes = packet(
            &mut client,
            vec![
                (
                    Command::WRITE,
                    Client::write_body(file, 0, &vec![7; CREDIT_PAYLOAD_SIZE as usize + 1]),
                ),
                (Command::CLOSE, close(FileId::RELATED)),
                (Command::READ, read(FileId::RELATED, 1)),
            ],
            true,
        );
        let mut undercharged = bytes.clone();
        Header::mut_from_prefix(&mut undercharged[..])
            .unwrap()
            .0
            .credit_charge = 1.into();
        let response = client.connection.process(&undercharged).await.unwrap();
        assert!(
            responses(&response)
                .iter()
                .all(|reply| response_status(reply) == Status::INVALID_PARAMETER)
        );
        assert_eq!(
            response_status(&client.read(file, 0, 1).await),
            Status::END_OF_FILE
        );
        let mut bytes = bytes;
        refresh(&mut client, &mut bytes);
        let accepted = client.connection.request(bytes).unwrap();
        assert_eq!(client.connection.state.lock().credits_in_use, 4);
        let response = accepted.execute().await.unwrap();
        let replies = responses(&response);
        assert_eq!(response_status(replies[0]), Status::SUCCESS);
        assert_eq!(response_status(replies[1]), Status::SUCCESS);
        assert_eq!(response_status(replies[2]), Status::FILE_CLOSED);
        assert_eq!(
            read_body::<WriteResponse>(replies[0]).unwrap().count.get(),
            CREDIT_PAYLOAD_SIZE + 1
        );
        assert_eq!(client.connection.state.lock().credits_in_use, 0);
        assert!(client.connection.state.lock().requests.is_empty());
    });
}
