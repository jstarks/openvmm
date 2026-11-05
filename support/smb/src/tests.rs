// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::executor::block_on;
use memory::MemoryFs;
use std::pin::Pin;
use std::task::{Context, Poll};
use test_with_tracing::test;
use zerocopy::FromZeros;

struct Client<B: FileSystem = MemoryFs> {
    connection: Connection<B>,
    session: u64,
    tree: u32,
    message: u64,
}

fn request(command: Command, body: &[u8], session: u64, tree: u32, message: u64) -> Vec<u8> {
    let mut header = Header::new_zeroed();
    header.protocol = SIGNATURE;
    header.structure_size = (HEADER_SIZE as u16).into();
    header.command = command.0.into();
    header.credits = 1.into();
    header.message_id = message.into();
    header.session_id = session.into();
    header.tree_id = tree.into();
    let payload =
        match command {
            Command::READ => decode::<ReadRequest>(body).map(|request| request.length.get()),
            Command::WRITE => decode::<WriteRequest>(body).map(|request| request.length.get()),
            Command::QUERY_DIRECTORY => decode::<QueryDirectoryRequest>(body)
                .map(|request| request.output_buffer_length.get()),
            Command::QUERY_INFO => {
                decode::<QueryInfoRequest>(body).map(|request| request.output_buffer_length.get())
            }
            Command::CHANGE_NOTIFY => decode::<ChangeNotifyRequest>(body)
                .map(|request| request.output_buffer_length.get()),
            _ => Ok(0),
        }
        .unwrap_or(0);
    header.credit_charge = ((payload.saturating_sub(1) / CREDIT_PAYLOAD_SIZE + 1) as u16).into();
    let mut packet = header.as_bytes().to_vec();
    packet.extend_from_slice(body);
    packet
}

fn response_status(packet: &[u8]) -> Status {
    Header::read_from_prefix(packet).unwrap().0.status()
}

fn negotiate_body() -> Vec<u8> {
    let mut body = NegotiateRequest::new_zeroed();
    body.structure_size = NegotiateRequest::STRUCTURE_SIZE.into();
    body.dialect_count = 1.into();
    let mut out = body.as_bytes().to_vec();
    out.extend_from_slice(&DIALECT_210.to_le_bytes());
    out
}

fn tree_body() -> Vec<u8> {
    let path = encode_name("\\\\localhost\\memory");
    let mut tree = TreeConnectRequest::new_zeroed();
    tree.structure_size = TreeConnectRequest::STRUCTURE_SIZE.into();
    tree.path_offset = (body_end::<TreeConnectRequest>() as u16).into();
    tree.path_length = (path.len() as u16).into();
    let mut body = tree.as_bytes().to_vec();
    body.extend(path);
    body
}

fn create_body(
    name: &str,
    access: u32,
    sharing: u32,
    disposition: u32,
    options: u32,
    contexts: &[u8],
) -> Vec<u8> {
    let name = encode_name(name);
    let mut body = CreateRequest::new_zeroed();
    body.structure_size = CreateRequest::STRUCTURE_SIZE.into();
    body.desired_access = access.into();
    body.share_access = sharing.into();
    body.create_disposition = disposition.into();
    body.create_options = options.into();
    body.name_offset = (body_end::<CreateRequest>() as u16).into();
    body.name_length = (name.len() as u16).into();
    let mut bytes = body.as_bytes().to_vec();
    bytes.extend(name);
    if !contexts.is_empty() {
        bytes.resize(align_up(bytes.len(), CREATE_CONTEXT_ALIGNMENT).unwrap(), 0);
        body.contexts_offset = ((HEADER_SIZE + bytes.len()) as u32).into();
        body.contexts_length = (contexts.len() as u32).into();
        bytes[..size_of::<CreateRequest>()].copy_from_slice(body.as_bytes());
        bytes.extend_from_slice(contexts);
    }
    bytes
}

impl<B: FileSystem> Client<B> {
    async fn new(server: &Arc<Server<B>>) -> Self {
        let mut client = Self {
            connection: server.connect(),
            session: 0,
            tree: 0,
            message: 0,
        };
        client.ok(Command::NEGOTIATE, &negotiate_body()).await;
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

    async fn send(&mut self, command: Command, body: &[u8]) -> Vec<u8> {
        let mut packet = request(command, body, self.session, self.tree, self.message);
        Header::mut_from_prefix(&mut packet[..]).unwrap().0.credits = (MAX_REQUESTS as u16).into();
        self.message += u64::from(
            Header::read_from_prefix(&packet)
                .unwrap()
                .0
                .credit_charge
                .get()
                .max(1),
        );
        self.connection.process(&packet).await.unwrap()
    }

    async fn ok(&mut self, command: Command, body: &[u8]) -> Vec<u8> {
        let response = self.send(command, body).await;
        assert_eq!(response_status(&response), Status::SUCCESS, "{command:?}");
        response
    }

    async fn open_result(
        &mut self,
        name: &str,
        access: u32,
        sharing: u32,
        disposition: u32,
        options: u32,
    ) -> Vec<u8> {
        self.send(
            Command::CREATE,
            &create_body(name, access, sharing, disposition, options, &[]),
        )
        .await
    }

    async fn open(&mut self, name: &str, disposition: u32, options: u32) -> FileId {
        let response = self
            .open_result(
                name,
                AccessMask::FILE_ALL_ACCESS.into_bits(),
                ShareAccess::ALL.into_bits(),
                disposition,
                options,
            )
            .await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        read_body::<CreateResponse>(&response).unwrap().file_id
    }

    async fn close(&mut self, id: FileId) {
        let mut body = CloseRequest::new_zeroed();
        body.structure_size = CloseRequest::STRUCTURE_SIZE.into();
        body.file_id = id;
        let response = self.ok(Command::CLOSE, body.as_bytes()).await;
        assert!(response[66..].iter().all(|&b| b == 0));
    }

    async fn read(&mut self, id: FileId, offset: u64, length: u32) -> Vec<u8> {
        let mut body = ReadRequest::new_zeroed();
        body.structure_size = ReadRequest::STRUCTURE_SIZE.into();
        body.file_id = id;
        body.offset = offset.into();
        body.length = length.into();
        self.send(Command::READ, body.as_bytes()).await
    }

    async fn set(&mut self, id: FileId, class: u8, data: &[u8]) -> Vec<u8> {
        let mut body = SetInfoRequest::new_zeroed();
        body.structure_size = SetInfoRequest::STRUCTURE_SIZE.into();
        body.info_type = InformationType::FILE;
        body.info_class = class;
        body.file_id = id;
        body.buffer_offset = (body_end::<SetInfoRequest>() as u16).into();
        body.buffer_length = (data.len() as u32).into();
        let mut bytes = body.as_bytes().to_vec();
        bytes.extend_from_slice(data);
        self.send(Command::SET_INFO, &bytes).await
    }

    async fn query(&mut self, id: FileId, class: u8) -> Vec<u8> {
        let mut body = QueryInfoRequest::new_zeroed();
        body.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
        body.info_type = InformationType::FILE;
        body.info_class = class;
        body.output_buffer_length = (MAX_TRANSFER_SIZE as u32).into();
        body.file_id = id;
        self.send(Command::QUERY_INFO, body.as_bytes()).await
    }
}

impl Client<MemoryFs> {
    fn write_body(id: FileId, offset: u64, data: &[u8]) -> Vec<u8> {
        let mut body = WriteRequest::new_zeroed();
        body.structure_size = WriteRequest::STRUCTURE_SIZE.into();
        body.file_id = id;
        body.offset = offset.into();
        body.data_offset = (body_end::<WriteRequest>() as u16).into();
        body.length = (data.len() as u32).into();
        let mut bytes = body.as_bytes().to_vec();
        bytes.extend_from_slice(data);
        bytes
    }
}

mod compound;
mod create;
mod locking;
mod notify;
mod pending;
mod rename;
mod runtime;
mod wire;

#[test]
fn test_client_guest_handshake_does_not_activate_a_pending_session() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut connection = server.connect();
        connection
            .process(&request(Command::NEGOTIATE, &negotiate_body(), 0, 0, 0))
            .await
            .unwrap();
        let mut setup = SessionSetupRequest::new_zeroed();
        setup.structure_size = SessionSetupRequest::STRUCTURE_SIZE.into();
        setup.security_buffer_offset = (body_end::<SessionSetupRequest>() as u16).into();
        setup.security_buffer_length = 32.into();
        let mut body = setup.as_bytes().to_vec();
        body.extend_from_slice(b"NTLMSSP\0");
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&[0; 20]);
        let response = connection
            .process(&request(Command::SESSION_SETUP, &body, 0, 0, 1))
            .await
            .unwrap();
        assert_eq!(response_status(&response), Status::MORE_PROCESSING_REQUIRED);
        assert_eq!(&response[72..80], b"NTLMSSP\0");
        let session = u64::from_le_bytes(response[40..48].try_into().unwrap());
        let simple = SimpleBody {
            structure_size: SimpleBody::STRUCTURE_SIZE.into(),
            reserved: 0.into(),
        };
        let response = connection
            .process(&request(
                Command::TREE_DISCONNECT,
                simple.as_bytes(),
                session,
                1,
                2,
            ))
            .await
            .unwrap();
        assert_eq!(response_status(&response), Status::USER_SESSION_DELETED);
        setup.security_buffer_length = 64.into();
        let mut body = setup.as_bytes().to_vec();
        body.extend_from_slice(b"NTLMSSP\0");
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(&[0; 52]);
        let response = connection
            .process(&request(Command::SESSION_SETUP, &body, session + 1, 0, 3))
            .await
            .unwrap();
        assert_eq!(response_status(&response), Status::INVALID_PARAMETER);
        let response = connection
            .process(&request(Command::SESSION_SETUP, &body, session, 0, 4))
            .await
            .unwrap();
        assert_eq!(response_status(&response), Status::SUCCESS);
        assert_eq!(u16::from_le_bytes(response[66..68].try_into().unwrap()), 1);
    });
}

#[test]
fn create_write_read_truncate_and_reopen() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let id = client.open("file", 2, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(id, 3, b"hello"))
            .await;
        let read = client.read(id, 0, 100).await;
        assert_eq!(response_status(&read), Status::SUCCESS);
        assert_eq!(&read[80..], b"\0\0\0hello");
        assert_eq!(
            response_status(&client.read(id, 8, 1).await),
            Status::END_OF_FILE
        );
        assert_eq!(
            response_status(&client.set(id, 20, &5u64.to_le_bytes()).await),
            Status::SUCCESS
        );
        assert_eq!(&client.read(id, 0, 100).await[80..], b"\0\0\0he");
        client.close(id).await;
        let id = client.open("FILE", 1, 0).await;
        assert_eq!(&client.read(id, 0, 100).await[80..], b"\0\0\0he");
    });
}

#[test]
fn trees_scope_handles_and_disconnect_does_not_close_other_trees() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let first_tree = client.tree;
        let first = client.open("first", 2, 0).await;
        let response = client.ok(Command::TREE_CONNECT, &tree_body()).await;
        client.tree = u32::from_le_bytes(response[36..40].try_into().unwrap());
        let second_tree = client.tree;
        assert_ne!(first_tree, second_tree);
        assert_eq!(
            response_status(&client.read(first, 0, 0).await),
            Status::FILE_CLOSED
        );
        let second = client.open("second", 2, 0).await;
        client
            .ok(
                Command::WRITE,
                &Client::write_body(second, 0, b"still open"),
            )
            .await;
        client.tree = first_tree;
        let simple = SimpleBody {
            structure_size: SimpleBody::STRUCTURE_SIZE.into(),
            reserved: 0.into(),
        };
        client.ok(Command::TREE_DISCONNECT, simple.as_bytes()).await;
        assert_eq!(
            response_status(&client.read(first, 0, 0).await),
            Status::NETWORK_NAME_DELETED
        );
        let response = client.ok(Command::TREE_CONNECT, &tree_body()).await;
        let third_tree = u32::from_le_bytes(response[36..40].try_into().unwrap());
        assert_ne!(third_tree, first_tree);
        client.tree = second_tree;
        assert_eq!(&client.read(second, 0, 100).await[80..], b"still open");
    });
}

#[test]
fn sharing_is_bilateral_and_disconnect_releases_opens() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut first = Client::new(&server).await;
        let mut second = Client::new(&server).await;
        let response = first.open_result("shared", 1, 1, 2, 0).await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        assert_eq!(
            response_status(&second.open_result("shared", 2, 7, 1, 0).await),
            Status::SHARING_VIOLATION
        );
        assert_eq!(
            response_status(&second.open_result("shared", 1, 0, 1, 0).await),
            Status::SHARING_VIOLATION
        );
        drop(first);
        assert_eq!(
            response_status(&second.open_result("shared", 2, 0, 1, 0).await),
            Status::SUCCESS
        );
    });
}

#[test]
fn delete_waits_for_last_close() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut a = Client::new(&server).await;
        let mut b = Client::new(&server).await;
        let one = a.open("delete", 2, 0).await;
        let two = b.open("delete", 1, 0).await;
        assert_eq!(
            response_status(&a.set(one, 13, &[1]).await),
            Status::SUCCESS
        );
        a.close(one).await;
        assert_eq!(
            response_status(&a.open_result("delete", 1, 7, 1, 0).await),
            Status::DELETE_PENDING
        );
        b.close(two).await;
        assert_eq!(
            response_status(&a.open_result("delete", 1, 7, 1, 0).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
    });
}

#[test]
fn pending_directory_deletion_prevents_orphaned_children_and_can_be_cancelled() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let directory = client.open("pending", 2, 1).await;
        assert_eq!(
            response_status(&client.set(directory, 13, &[1]).await),
            Status::SUCCESS
        );
        assert_eq!(
            response_status(
                &client
                    .open_result("pending\\child", 0x1f01ff, 7, 2, 0)
                    .await
            ),
            Status::DELETE_PENDING
        );
        assert_eq!(
            response_status(&client.set(directory, 13, &[0]).await),
            Status::SUCCESS
        );
        let child = client.open("pending\\child", 2, 0).await;
        assert_eq!(
            response_status(&client.set(directory, 13, &[1]).await),
            Status::DIRECTORY_NOT_EMPTY
        );
        client.close(child).await;
        client.close(directory).await;
        let child = client.open("pending\\child", 1, 0).await;
        client.close(child).await;
    });
}

#[test]
fn quota_and_bad_offsets_leave_file_unchanged() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(8, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let id = client.open("limited", 2, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(id, 0, b"good"))
            .await;
        assert_eq!(
            response_status(
                &client
                    .send(Command::WRITE, &Client::write_body(id, 7, b"bad"))
                    .await
            ),
            Status::DISK_FULL
        );
        assert_eq!(
            response_status(
                &client
                    .send(Command::WRITE, &Client::write_body(id, u64::MAX, b"x"))
                    .await
            ),
            Status::INVALID_PARAMETER
        );
        let mut bad = Client::write_body(id, 0, b"bad");
        bad[2..4].copy_from_slice(&64u16.to_le_bytes());
        assert_eq!(
            response_status(&client.send(Command::WRITE, &bad).await),
            Status::INVALID_PARAMETER
        );
        assert_eq!(&client.read(id, 0, 100).await[80..], b"good");
    });
}

#[test]
fn large_io_and_windows_read_boundaries() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(2 * MAX_TRANSFER_SIZE, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let id = client.open("large", 2, 0).await;
        let bytes: Vec<_> = (0..100_000).map(|i| (i % 251) as u8).collect();
        client
            .ok(Command::WRITE, &Client::write_body(id, 0, &bytes))
            .await;
        assert_eq!(&client.read(id, 0, bytes.len() as u32).await[80..], bytes);
        assert_eq!(
            response_status(&client.read(id, i64::MAX as u64, 1).await),
            Status::INVALID_PARAMETER
        );
        assert_eq!(
            response_status(&client.read(id, i64::MAX as u64, 0).await),
            Status::SUCCESS
        );
        assert_eq!(
            response_status(&client.set(id, 13, &[1, 0, 0, 0, 0, 0, 0, 0]).await),
            Status::SUCCESS
        );
        let directory = client.open("directory", 2, 1).await;
        assert_eq!(
            response_status(&client.read(directory, 0, 1).await),
            Status::INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            response_status(&client.read(directory, 0, 0).await),
            Status::SUCCESS
        );
    });
}

#[test]
fn malformed_creates_and_traversal_are_rejected() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        for (name, status) in [
            ("..\\escape", Status::OBJECT_PATH_SYNTAX_BAD),
            ("\\rooted", Status::OBJECT_PATH_SYNTAX_BAD),
            ("a/../b", Status::OBJECT_NAME_INVALID),
            ("file:stream", Status::OBJECT_NAME_INVALID),
        ] {
            assert_eq!(
                response_status(&client.open_result(name, 1, 7, 2, 0).await),
                status
            );
        }
        assert_eq!(
            response_status(&client.open_result(&"x".repeat(256), 1, 7, 2, 0).await),
            Status::NAME_TOO_LONG,
        );
        let mut create = CreateRequest::new_zeroed();
        create.structure_size = CreateRequest::STRUCTURE_SIZE.into();
        create.name_offset = (body_end::<CreateRequest>() as u16).into();
        create.name_length = 4.into();
        let mut bytes = create.as_bytes().to_vec();
        bytes.extend(encode_name("ab"));
        for length in 0..bytes.len() {
            assert_ne!(
                response_status(&client.send(Command::CREATE, &bytes[..length]).await),
                Status::SUCCESS
            );
        }
        let valid = request(Command::CREATE, &bytes, client.session, client.tree, 100);
        for length in 0..HEADER_SIZE {
            assert!(matches!(
                client.connection.process(&valid[..length]).await,
                Err(Error::InvalidHeader)
            ));
        }
    });
}

#[test]
fn per_open_rights_and_stale_file_ids_are_enforced() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let response = client.open_result("readonly-handle", 1, 7, 2, 0).await;
        let id = FileId::read_from_bytes(&response[128..144]).unwrap();
        assert_eq!(
            response_status(
                &client
                    .send(Command::WRITE, &Client::write_body(id, 0, b"x"))
                    .await
            ),
            Status::ACCESS_DENIED
        );
        assert_eq!(
            response_status(&client.set(id, 13, &[1]).await),
            Status::ACCESS_DENIED
        );
        client.close(id).await;
        assert_eq!(
            response_status(&client.read(id, 0, 1).await),
            Status::FILE_CLOSED
        );
    });
}

#[test]
fn directory_pagination_and_small_buffer_do_not_lose_entries() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let dir = client.open("dir", 2, 1).await;
        let a = client.open("dir\\a", 2, 0).await;
        let b = client.open("dir\\b", 2, 0).await;
        client.close(a).await;
        client.close(b).await;
        let mut query = QueryDirectoryRequest::new_zeroed();
        query.structure_size = QueryDirectoryRequest::STRUCTURE_SIZE.into();
        query.info_class = FileInformationClass::NAMES.0;
        query.file_id = dir;
        query.output_buffer_length = 1.into();
        assert_eq!(
            response_status(
                &client
                    .send(Command::QUERY_DIRECTORY, query.as_bytes())
                    .await
            ),
            Status::BUFFER_TOO_SMALL
        );
        query.output_buffer_length = 16.into();
        let current = client.ok(Command::QUERY_DIRECTORY, query.as_bytes()).await;
        let parent = client.ok(Command::QUERY_DIRECTORY, query.as_bytes()).await;
        assert_eq!(&current[84..86], &encode_name("."));
        assert_eq!(&parent[84..88], &encode_name(".."));
        let first = client.ok(Command::QUERY_DIRECTORY, query.as_bytes()).await;
        let second = client.ok(Command::QUERY_DIRECTORY, query.as_bytes()).await;
        assert_eq!(&first[84..86], &encode_name("a"));
        assert_eq!(&second[84..86], &encode_name("b"));
        assert_eq!(
            response_status(
                &client
                    .send(Command::QUERY_DIRECTORY, query.as_bytes())
                    .await
            ),
            Status::NO_MORE_FILES
        );
        query.flags = QueryDirectoryFlags::new().with_restart_scans(true);
        assert_eq!(
            &client.ok(Command::QUERY_DIRECTORY, query.as_bytes()).await[84..86],
            &encode_name(".")
        );
    });
}

struct FragmentedStream {
    input: futures::io::Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl futures::AsyncRead for FragmentedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let len = buf.len().min(1);
        Pin::new(&mut self.input).poll_read(cx, &mut buf[..len])
    }
}

impl futures::AsyncWrite for FragmentedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let len = buf.len().min(3);
        self.output.extend_from_slice(&buf[..len]);
        Poll::Ready(Ok(len))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn tcp_handles_fragmentation_and_rejects_truncated_or_oversized_frames() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let packet = request(Command::NEGOTIATE, &negotiate_body(), 0, 0, 0);
        let mut frame = (packet.len() as u32).to_be_bytes().to_vec();
        frame.extend(packet);
        let mut stream = FragmentedStream {
            input: futures::io::Cursor::new(frame.clone()),
            output: Vec::new(),
        };
        tcp::serve(&mut server.connect(), &mut stream)
            .await
            .unwrap();
        let length = u32::from_be_bytes(stream.output[..4].try_into().unwrap()) as usize;
        assert_eq!(length + 4, stream.output.len());
        assert_eq!(response_status(&stream.output[4..]), Status::SUCCESS);
        assert_eq!(
            u16::from_le_bytes(stream.output[72..74].try_into().unwrap()),
            DIALECT_210
        );
        for data in [
            vec![0, 0],
            frame[..frame.len() - 1].to_vec(),
            vec![1, 0, 0, 0],
            (MAX_MESSAGE_SIZE as u32 + 1).to_be_bytes().to_vec(),
        ] {
            let mut stream = FragmentedStream {
                input: futures::io::Cursor::new(data),
                output: Vec::new(),
            };
            assert!(
                tcp::serve(&mut server.connect(), &mut stream)
                    .await
                    .is_err()
            );
            assert!(stream.output.is_empty());
        }
    });
}
