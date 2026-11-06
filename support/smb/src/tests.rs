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
            Command::IOCTL => decode::<IoctlRequest>(body).and_then(|request| {
                request
                    .input_count
                    .get()
                    .checked_add(request.output_count.get())
                    .zip(
                        request
                            .max_input_response
                            .get()
                            .checked_add(request.max_output_response.get()),
                    )
                    .map(|(input, output)| input.max(output))
                    .ok_or(Status::INVALID_PARAMETER)
            }),
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
mod security;
mod wire;

#[test]
fn allocation_reservation_and_mode_updates_preserve_their_distinct_state() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("reserved", 2, 0).await;
        assert_eq!(
            response_status(&client.set(file, 20, &4i64.to_le_bytes()).await),
            Status::SUCCESS
        );
        assert_eq!(
            response_status(&client.set(file, 19, &32i64.to_le_bytes()).await),
            Status::SUCCESS
        );
        let standard = client.query(file, 5).await;
        assert_eq!(&standard[72..80], &32u64.to_le_bytes());
        assert_eq!(&standard[80..88], &4u64.to_le_bytes());
        assert_eq!(
            response_status(&client.read(file, 4, 1).await),
            Status::END_OF_FILE
        );
        client
            .ok(Command::WRITE, &Client::write_body(file, 16, b"x"))
            .await;
        let standard = client.query(file, 5).await;
        assert_eq!(&standard[72..80], &32u64.to_le_bytes());
        assert_eq!(&standard[80..88], &17u64.to_le_bytes());
        let response = client.read(file, 4, 13).await;
        assert_eq!(&response[80..], b"\0\0\0\0\0\0\0\0\0\0\0\0x");
        assert_eq!(
            response_status(&client.set(file, 19, &0i64.to_le_bytes()).await),
            Status::SUCCESS
        );
        assert_eq!(&client.query(file, 5).await[72..88], &[0; 16]);
        assert_eq!(
            response_status(&client.set(file, 16, &6u32.to_le_bytes()).await),
            Status::SUCCESS
        );
        assert_eq!(&client.query(file, 16).await[72..], &6u32.to_le_bytes());
        for value in [8u32, 0x10, 0x20, 0x30, 0x1000, u32::MAX] {
            assert_eq!(
                response_status(&client.set(file, 16, &value.to_le_bytes()).await),
                Status::INVALID_PARAMETER
            );
        }
        assert_eq!(&client.query(file, 16).await[72..], &6u32.to_le_bytes());
        assert_eq!(
            response_status(&client.set(file, 19, &(-1i64).to_le_bytes()).await),
            Status::INVALID_PARAMETER
        );
        assert_eq!(
            response_status(&client.set(file, 19, &[0; 7]).await),
            Status::INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            response_status(&client.set(file, 16, &[0; 3]).await),
            Status::INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            response_status(&client.set(file, 14, &123i64.to_le_bytes()).await),
            Status::SUCCESS
        );
        assert_eq!(&client.query(file, 14).await[72..], &123i64.to_le_bytes());
        assert_eq!(
            &client.query(file, 18).await[152..160],
            &123i64.to_le_bytes()
        );
        assert_eq!(
            response_status(&client.set(file, 14, &(-1i64).to_le_bytes()).await),
            Status::INVALID_PARAMETER
        );
        assert_eq!(
            response_status(&client.set(file, 14, &[0; 7]).await),
            Status::INFO_LENGTH_MISMATCH
        );
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"data"))
            .await;
        assert_eq!(&client.query(file, 14).await[72..], &123i64.to_le_bytes());
        client.close(file).await;
    });
}

#[test]
fn allocation_reservations_consume_quota_and_failed_growth_is_atomic() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(32, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let first = client.open("first", 2, 0).await;
        let second = client.open("second", 2, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(first, 0, b"data"))
            .await;
        assert_eq!(
            response_status(&client.set(first, 19, &32i64.to_le_bytes()).await),
            Status::SUCCESS
        );
        assert_eq!(
            runtime::inspect_text(
                &format!("nodes/{}/size", first.persistent.get()),
                &server.backend
            )
            .await,
            "4"
        );
        assert_eq!(
            runtime::inspect_text(
                &format!("nodes/{}/allocation_size", first.persistent.get()),
                &server.backend
            )
            .await,
            "32"
        );
        assert_eq!(
            response_status(&client.set(first, 19, &64i64.to_le_bytes()).await),
            Status::DISK_FULL
        );
        assert_eq!(
            response_status(
                &client
                    .send(Command::WRITE, &Client::write_body(second, 0, b"x"))
                    .await
            ),
            Status::DISK_FULL
        );
        let response = client.query(first, 5).await;
        assert_eq!(&response[72..80], &32u64.to_le_bytes());
        assert_eq!(&response[80..88], &4u64.to_le_bytes());
        assert_eq!(&client.read(first, 0, 4).await[80..], b"data");
        assert_eq!(
            response_status(&client.set(first, 19, &2i64.to_le_bytes()).await),
            Status::SUCCESS
        );
        assert_eq!(&client.read(first, 0, 4).await[80..], b"da");
        client
            .ok(Command::WRITE, &Client::write_body(second, 0, b"now fits"))
            .await;
        let response = client
            .open_result(
                "read-only",
                AccessMask::FILE_GENERIC_READ.into_bits(),
                7,
                2,
                0,
            )
            .await;
        let read_only = read_body::<CreateResponse>(&response).unwrap().file_id;
        assert_eq!(
            response_status(&client.set(read_only, 19, &1i64.to_le_bytes()).await),
            Status::ACCESS_DENIED
        );
        let directory = client.open("directory", 2, 1).await;
        assert_eq!(
            response_status(&client.set(directory, 19, &0i64.to_le_bytes()).await),
            Status::INVALID_PARAMETER
        );
        client.close(directory).await;
        client.close(read_only).await;
        client.close(second).await;
        client.close(first).await;
    });
}

#[test]
fn file_metadata_queries_use_open_mode_and_complete_namespace_paths() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let directory = client.open("directory", 2, 1).await;
        let response = client
            .open_result(
                "directory\\file",
                AccessMask::FILE_ALL_ACCESS.into_bits(),
                ShareAccess::ALL.into_bits(),
                2,
                6,
            )
            .await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        let file = read_body::<CreateResponse>(&response).unwrap().file_id;
        for (class, value) in [
            (7, 0),
            (8, AccessMask::FILE_ALL_ACCESS.into_bits()),
            (16, 6),
            (17, 0),
        ] {
            let response = client.query(file, class).await;
            assert_eq!(response_status(&response), Status::SUCCESS);
            assert_eq!(&response[72..], &value.to_le_bytes());
        }
        let response = client.query(file, 18).await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        let data = &response[72..];
        assert_eq!(&data[88..92], &6u32.to_le_bytes());
        assert_eq!(&data[96..100], &30u32.to_le_bytes());
        assert_eq!(&data[100..], &encode_name("\\directory\\file"));
        assert_eq!(
            response_status(&client.query(file, 9).await),
            Status::NOT_SUPPORTED
        );
        client.close(file).await;
        client.close(directory).await;
    });
}

#[test]
fn file_metadata_buffer_errors_and_pending_link_counts_are_specified() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("long-name", 2, 0).await;
        let mut query = QueryInfoRequest::new_zeroed();
        query.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
        query.info_type = InformationType::FILE;
        query.file_id = file;
        for (class, minimum) in [
            (4, 40),
            (5, 24),
            (6, 8),
            (7, 4),
            (8, 4),
            (14, 8),
            (16, 4),
            (17, 4),
            (18, 104),
            (21, 8),
            (34, 56),
        ] {
            query.info_class = class;
            query.output_buffer_length = (minimum - 1).into();
            let response = client.send(Command::QUERY_INFO, query.as_bytes()).await;
            assert_eq!(
                response_status(&response),
                Status::INFO_LENGTH_MISMATCH,
                "class {class}"
            );
        }
        query.info_class = 18;
        query.output_buffer_length = 105.into();
        let response = client.send(Command::QUERY_INFO, query.as_bytes()).await;
        assert_eq!(response_status(&response), Status::BUFFER_OVERFLOW);
        assert_eq!(&response[68..72], &104u32.to_le_bytes());
        assert_eq!(&response[168..], &[20, 0, 0, 0, b'\\', 0, b'l', 0]);
        let response = client.set(file, 20, &9i64.to_le_bytes()).await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        let response = client.set(file, 13, &[1]).await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        let response = client.query(file, 5).await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        assert_eq!(&response[72..80], &9u64.to_le_bytes());
        assert_eq!(&response[80..88], &9u64.to_le_bytes());
        assert_eq!(&response[88..94], &[0, 0, 0, 0, 1, 0]);
        client.close(file).await;
    });
}

#[test]
fn file_mode_ignores_remote_sync_flags_and_unbuffered_access_excludes_append() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        for (name, options, mode, append) in [
            ("ignored", 0x800134, 4u32, true),
            ("unbuffered", 8, 8, false),
            ("delete", 0x1000, 0, true),
        ] {
            let response = client
                .open_result(name, AccessMask::FILE_ALL_ACCESS.into_bits(), 7, 2, options)
                .await;
            assert_eq!(response_status(&response), Status::SUCCESS);
            let file = read_body::<CreateResponse>(&response).unwrap().file_id;
            assert_eq!(&client.query(file, 16).await[72..], &mode.to_le_bytes());
            let expected = AccessMask::FILE_ALL_ACCESS
                .with_append_data(append)
                .into_bits();
            assert_eq!(&client.query(file, 8).await[72..], &expected.to_le_bytes());
            if options == 8 {
                assert_eq!(
                    response_status(&client.set(file, 14, &1i64.to_le_bytes()).await),
                    Status::SUCCESS
                );
                assert_eq!(&client.query(file, 14).await[72..], &1i64.to_le_bytes());
            }
            client.close(file).await;
        }
    });
}

#[test]
fn filesystem_queries_report_provider_identity_and_live_capacity() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let file = client.open("data", 2, 0).await;
        let mut query = QueryInfoRequest::new_zeroed();
        query.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
        query.info_type = InformationType::FILESYSTEM;
        query.file_id = root;
        query.output_buffer_length = 4096.into();
        query.info_class = 1;
        let response = client.ok(Command::QUERY_INFO, query.as_bytes()).await;
        let body: BufferResponse = read_body(&response).unwrap();
        let data = &response[body.output_buffer_offset.get() as usize..];
        assert_eq!(&data[8..12], &0u32.to_le_bytes());
        assert_eq!(&data[12..16], &12u32.to_le_bytes());
        assert_eq!(&data[16..18], &[1, 0]);
        assert_eq!(&data[18..], &encode_name("Memory"));
        let created = data[..8].to_vec();
        for (size, available) in [(0, 1024i64), (17, 1007), (0, 1024)] {
            let response = client.set(file, 20, &(size as i64).to_le_bytes()).await;
            assert_eq!(response_status(&response), Status::SUCCESS);
            for class in [3, 7] {
                query.info_class = class;
                let response = client.ok(Command::QUERY_INFO, query.as_bytes()).await;
                let body: BufferResponse = read_body(&response).unwrap();
                let data = &response[body.output_buffer_offset.get() as usize..];
                let mut expected = 1024i64.to_le_bytes().to_vec();
                expected.extend_from_slice(&available.to_le_bytes());
                if class == 7 {
                    expected.extend_from_slice(&available.to_le_bytes());
                }
                expected.extend_from_slice(&1u32.to_le_bytes());
                expected.extend_from_slice(&1u32.to_le_bytes());
                assert_eq!(data, expected);
            }
        }
        query.info_class = 1;
        query.output_buffer_length = 24.into();
        let response = client.send(Command::QUERY_INFO, query.as_bytes()).await;
        assert_eq!(response_status(&response), Status::BUFFER_OVERFLOW);
        let body: BufferResponse = read_body(&response).unwrap();
        let data = &response[body.output_buffer_offset.get() as usize..];
        assert_eq!(body.output_buffer_length.get(), 24);
        assert_eq!(&data[12..16], &12u32.to_le_bytes());
        assert_eq!(&data[18..], &encode_name("Mem"));
        query.info_class = 3;
        query.output_buffer_length = 23.into();
        let response = client.send(Command::QUERY_INFO, query.as_bytes()).await;
        assert_eq!(response_status(&response), Status::INFO_LENGTH_MISMATCH);
        query.output_buffer_length = 4096.into();
        query.info_class = 1;
        let response = client.ok(Command::QUERY_INFO, query.as_bytes()).await;
        let body: BufferResponse = read_body(&response).unwrap();
        assert_eq!(
            &response[body.output_buffer_offset.get() as usize..][..8],
            created
        );
        client.close(file).await;
        client.close(root).await;
    });
}

#[test]
fn filesystem_query_encoding_preserves_provider_fields_and_partial_records() {
    let mut info = FileSystemInformation {
        created: 123,
        serial: 0x12345678,
        label: "Other volume".into(),
        supports_objects: false,
        name: "OtherFS".into(),
        attributes: 0x80003,
        maximum_component_name_length: 128,
        device_type: 2,
        device_characteristics: 2,
        total_allocation_units: 100,
        caller_available_allocation_units: 20,
        actual_available_allocation_units: 30,
        sectors_per_allocation_unit: 8,
        bytes_per_sector: 512,
    };
    for (class, maximum, expected) in [
        (
            FileSystemInformationClass::DEVICE,
            8,
            vec![2, 0, 0, 0, 2, 0, 0, 0],
        ),
        (FileSystemInformationClass::ATTRIBUTE, 14, {
            let mut out = vec![3, 0, 8, 0, 128, 0, 0, 0, 14, 0, 0, 0];
            out.extend_from_slice(&[b'O', 0]);
            out
        }),
        (FileSystemInformationClass::SIZE, 24, {
            let mut out = 100i64.to_le_bytes().to_vec();
            out.extend_from_slice(&20i64.to_le_bytes());
            out.extend_from_slice(&8u32.to_le_bytes());
            out.extend_from_slice(&512u32.to_le_bytes());
            out
        }),
        (FileSystemInformationClass::FULL_SIZE, 32, {
            let mut out = 100i64.to_le_bytes().to_vec();
            out.extend_from_slice(&20i64.to_le_bytes());
            out.extend_from_slice(&30i64.to_le_bytes());
            out.extend_from_slice(&8u32.to_le_bytes());
            out.extend_from_slice(&512u32.to_le_bytes());
            out
        }),
    ] {
        let (status, body) = filesystem_response(&info, class, maximum).unwrap();
        assert_eq!(
            status,
            if class == FileSystemInformationClass::ATTRIBUTE {
                Status::BUFFER_OVERFLOW
            } else {
                Status::SUCCESS
            }
        );
        assert_eq!(&body[8..], expected);
        assert_eq!(
            filesystem_response(
                &info,
                class,
                if class == FileSystemInformationClass::ATTRIBUTE {
                    11
                } else {
                    maximum - 1
                }
            )
            .err(),
            Some(Status::INFO_LENGTH_MISMATCH),
        );
    }
    let (status, body) =
        filesystem_response(&info, FileSystemInformationClass::VOLUME, 25).unwrap();
    assert_eq!(status, Status::BUFFER_OVERFLOW);
    assert_eq!(&body[8..16], &123u64.to_le_bytes());
    assert_eq!(&body[16..20], &0x12345678u32.to_le_bytes());
    assert_eq!(&body[20..24], &24u32.to_le_bytes());
    assert_eq!(&body[24..26], &[0, 0]);
    assert_eq!(&body[26..], &encode_name("Other volume")[..7]);
    assert_eq!(
        filesystem_response(&info, FileSystemInformationClass::VOLUME, 23).err(),
        Some(Status::INFO_LENGTH_MISMATCH)
    );
    info.label = "a".repeat(40);
    let (status, body) =
        filesystem_response(&info, FileSystemInformationClass::VOLUME, 4096).unwrap();
    assert_eq!(status, Status::SUCCESS);
    assert_eq!(&body[20..24], &64u32.to_le_bytes());
    assert_eq!(&body[26..], &encode_name(&"a".repeat(32)));
    info.total_allocation_units = -1;
    assert_eq!(
        filesystem_response(&info, FileSystemInformationClass::SIZE, 24).err(),
        Some(Status::INTERNAL_ERROR)
    );
    info.total_allocation_units = 100;
    info.bytes_per_sector = 0;
    assert_eq!(
        filesystem_response(&info, FileSystemInformationClass::FULL_SIZE, 32).err(),
        Some(Status::INTERNAL_ERROR)
    );
}

#[test]
fn filesystem_queries_propagate_provider_rejection_without_memory_fallback() {
    use crate::test_support::{ControlledFs, Operation, Plan};
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        control
            .set_plan(
                Operation::FileSystemInformation,
                Plan {
                    failure: Some(Status::NOT_SUPPORTED),
                    ..Plan::default()
                },
            )
            .unwrap();
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let mut query = QueryInfoRequest::new_zeroed();
        query.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
        query.info_type = InformationType::FILESYSTEM;
        query.file_id = root;
        query.output_buffer_length = 4096.into();
        for class in [1, 3, 4, 5, 7] {
            query.info_class = class;
            let response = client.send(Command::QUERY_INFO, query.as_bytes()).await;
            assert_eq!(response_status(&response), Status::NOT_SUPPORTED);
        }
        assert_eq!(
            control
                .calls()
                .iter()
                .filter(|call| call.operation == Operation::FileSystemInformation)
                .count(),
            5
        );
        for (class, status) in [
            (2, Status::INVALID_INFO_CLASS),
            (11, Status::INVALID_PARAMETER),
            (255, Status::INVALID_PARAMETER),
        ] {
            query.info_class = class;
            let response = client.send(Command::QUERY_INFO, query.as_bytes()).await;
            assert_eq!(response_status(&response), status);
        }
        let unbuffered = client.open("unbuffered", 2, 8).await;
        assert_eq!(
            response_status(&client.set(unbuffered, 14, &1i64.to_le_bytes()).await),
            Status::NOT_SUPPORTED
        );
        assert_eq!(&client.query(unbuffered, 14).await[72..], &[0; 8]);
        client.close(unbuffered).await;
        client.close(root).await;
    });
}

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
            ("\\rooted", Status::INVALID_PARAMETER),
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
fn filename_wildcards_follow_dos_period_and_end_of_name_rules() {
    for (name, pattern, expected) in [
        ("", "", true),
        ("", "*", false),
        ("x", "", false),
        ("plain", "*.*", true),
        ("report.txt", "*.TXT", true),
        ("report.txt", "*.bin", false),
        ("report.txt", "**.txt", true),
        ("report.txt", "report?txt", true),
        ("a.b.c", "<.c", true),
        ("a.b.c", "<c", true),
        ("a.b.c", "<", false),
        ("a.", "<", true),
        ("file.ext", "file.<", true),
        ("file.a.ext", "file.<", false),
        ("a.txt", "a>>>.txt", true),
        ("ab.txt", "a>>>.txt", true),
        ("abcd.txt", "a>>>.txt", true),
        ("abcde.txt", "a>>>.txt", false),
        ("a", "a>", true),
        ("a.", "a>", false),
        ("a.", "a>\"", true),
        ("name", "name\"", true),
        ("name.", "name\"", true),
        ("name..", "name\"", false),
        ("\u{1f600}", "?", false),
        ("\u{1f600}", "??", true),
    ] {
        assert_eq!(
            name_matches(name, pattern),
            expected,
            "{name:?} {pattern:?}"
        );
    }
}

#[test]
fn directory_search_accepts_standard_and_dos_wildcards() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let directory = client.open("patterns", 2, 1).await;
        client.close(directory).await;
        for name in ["report.txt", "other.bin", "plain"] {
            let file = client.open(&format!("patterns\\{name}"), 2, 0).await;
            client.close(file).await;
        }
        for (pattern, expected) in [
            ("*.txt", Some("report.txt")),
            ("REPORT.?xt", Some("report.txt")),
            ("*PORT.TXT", Some("report.txt")),
            ("report>.txt", Some("report.txt")),
            ("<.txt", Some("report.txt")),
            ("report\"txt", Some("report.txt")),
            ("report.txt>>>", Some("report.txt")),
            ("plain\"", Some("plain")),
            ("plain>", Some("plain")),
            ("p????", Some("plain")),
            ("missing*", None),
            ("plain?", None),
        ] {
            let directory = client.open("patterns", 1, 1).await;
            let name = encode_name(pattern);
            let mut query = QueryDirectoryRequest::new_zeroed();
            query.structure_size = QueryDirectoryRequest::STRUCTURE_SIZE.into();
            query.file_id = directory;
            query.info_class = FileInformationClass::NAMES.0;
            query.flags = QueryDirectoryFlags::new().with_return_single_entry(true);
            query.output_buffer_length = 256.into();
            query.name_offset = (body_end::<QueryDirectoryRequest>() as u16).into();
            query.name_length = (name.len() as u16).into();
            let mut body = query.as_bytes().to_vec();
            body.extend_from_slice(&name);
            let response = client.send(Command::QUERY_DIRECTORY, &body).await;
            if let Some(expected) = expected {
                assert_eq!(response_status(&response), Status::SUCCESS, "{pattern}");
                let record = FileNamesInformation::read_from_prefix(&response[72..])
                    .unwrap()
                    .0;
                assert_eq!(
                    decode_name(&response[84..84 + record.file_name_length.get() as usize])
                        .unwrap(),
                    expected
                );
            } else {
                assert_eq!(
                    response_status(&response),
                    Status::NO_SUCH_FILE,
                    "{pattern}"
                );
            }
            assert_eq!(
                response_status(&client.send(Command::QUERY_DIRECTORY, &body).await),
                Status::NO_MORE_FILES,
                "{pattern}"
            );
            client.close(directory).await;
        }
        let directory = client.open("patterns", 1, 1).await;
        for (pattern, status) in [
            ("sub\\*".to_owned(), Status::OBJECT_NAME_INVALID),
            ("sub/*".to_owned(), Status::OBJECT_NAME_INVALID),
            ("stream:*".to_owned(), Status::OBJECT_NAME_INVALID),
            ("x".repeat(256), Status::NAME_TOO_LONG),
            ("x".repeat(255), Status::NO_SUCH_FILE),
        ] {
            let mut query = QueryDirectoryRequest::new_zeroed();
            query.structure_size = QueryDirectoryRequest::STRUCTURE_SIZE.into();
            query.file_id = directory;
            query.info_class = FileInformationClass::NAMES.0;
            query.flags = QueryDirectoryFlags::new().with_restart_scans(true);
            query.output_buffer_length = 256.into();
            query.name_offset = (body_end::<QueryDirectoryRequest>() as u16).into();
            let name = encode_name(&pattern);
            query.name_length = (name.len() as u16).into();
            let mut body = query.as_bytes().to_vec();
            body.extend_from_slice(&name);
            assert_eq!(
                response_status(&client.send(Command::QUERY_DIRECTORY, &body).await),
                status
            );
        }
        let source = client.open("patterns\\report.txt", 1, 0).await;
        let mut query = QueryDirectoryRequest::new_zeroed();
        query.structure_size = QueryDirectoryRequest::STRUCTURE_SIZE.into();
        query.file_id = directory;
        query.info_class = FileInformationClass::NAMES.0;
        query.flags = QueryDirectoryFlags::new().with_restart_scans(true);
        query.output_buffer_length = 256.into();
        query.name_offset = (body_end::<QueryDirectoryRequest>() as u16).into();
        query.name_length = 8.into();
        let mut body = query.as_bytes().to_vec();
        body.extend_from_slice(&encode_name("new*"));
        assert_eq!(
            response_status(&client.send(Command::QUERY_DIRECTORY, &body).await),
            Status::NO_MORE_FILES
        );
        let mut rename = FileRenameInformation::new_zeroed();
        let name = encode_name("patterns\\new-name");
        rename.file_name_length = (name.len() as u32).into();
        let mut input = rename.as_bytes().to_vec();
        input.extend_from_slice(&name);
        assert_eq!(
            response_status(&client.set(source, 10, &input).await),
            Status::SUCCESS
        );
        query.flags.set_restart_scans(false);
        body[..size_of::<QueryDirectoryRequest>()].copy_from_slice(query.as_bytes());
        assert_eq!(
            response_status(&client.send(Command::QUERY_DIRECTORY, &body).await),
            Status::NO_MORE_FILES
        );
        query.flags.set_restart_scans(true);
        body[..size_of::<QueryDirectoryRequest>()].copy_from_slice(query.as_bytes());
        let response = client.ok(Command::QUERY_DIRECTORY, &body).await;
        assert_eq!(&response[84..100], &encode_name("new-name"));
        client.close(source).await;
        client.close(directory).await;
    });
}

#[test]
fn directory_continuation_observes_live_entries_and_preserves_its_pattern() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let mut peer = Client::new(&server).await;
        let directory = client.open("live", 2, 1).await;
        let removed = peer.open("live\\removed", 2, 0).await;
        let changed = peer.open("live\\changed", 2, 0).await;
        let mut query = QueryDirectoryRequest::new_zeroed();
        query.structure_size = QueryDirectoryRequest::STRUCTURE_SIZE.into();
        query.info_class = FileInformationClass::DIRECTORY.0;
        query.file_id = directory;
        query.flags = QueryDirectoryFlags::new().with_return_single_entry(true);
        query.output_buffer_length = 512.into();
        let first = client.ok(Command::QUERY_DIRECTORY, query.as_bytes()).await;
        assert_eq!(&first[136..138], &encode_name("."));
        assert_eq!(
            response_status(&peer.set(removed, 13, &[1]).await),
            Status::SUCCESS
        );
        peer.close(removed).await;
        peer.ok(Command::WRITE, &Client::write_body(changed, 0, b"new"))
            .await;
        peer.close(changed).await;
        let added = peer.open("live\\added", 2, 0).await;
        peer.close(added).await;
        for (name, size) in [("..", None), ("changed", Some(3)), ("added", Some(0))] {
            let response = client.ok(Command::QUERY_DIRECTORY, query.as_bytes()).await;
            let record = FileDirectoryInformation::read_from_prefix(&response[72..])
                .unwrap()
                .0;
            assert_eq!(
                decode_name(&response[136..136 + record.file_name_length.get() as usize]).unwrap(),
                name
            );
            if let Some(size) = size {
                assert_eq!(record.end_of_file.get(), size);
            }
        }
        assert_eq!(
            response_status(
                &client
                    .send(Command::QUERY_DIRECTORY, query.as_bytes())
                    .await
            ),
            Status::NO_MORE_FILES
        );
        query.flags.set_restart_scans(true);
        query.name_offset = (body_end::<QueryDirectoryRequest>() as u16).into();
        query.name_length = 14.into();
        let mut body = query.as_bytes().to_vec();
        body.extend_from_slice(&encode_name("changed"));
        let response = client.ok(Command::QUERY_DIRECTORY, &body).await;
        assert_eq!(&response[136..150], &encode_name("changed"));
        query.flags.set_restart_scans(false);
        query.name_length = 10.into();
        let mut body = query.as_bytes().to_vec();
        body.extend_from_slice(&encode_name("added"));
        assert_eq!(
            response_status(&client.send(Command::QUERY_DIRECTORY, &body).await),
            Status::NO_MORE_FILES
        );
        query.flags.set_reopen(true);
        body[..size_of::<QueryDirectoryRequest>()].copy_from_slice(query.as_bytes());
        let response = client.ok(Command::QUERY_DIRECTORY, &body).await;
        assert_eq!(&response[136..146], &encode_name("added"));
        client.close(directory).await;
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
        query.flags.set_index_specified(true);
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
