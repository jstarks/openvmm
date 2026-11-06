// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

#[test]
fn execute_only_permits_reads_without_granting_directory_enumeration() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("execute", 2, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"code"))
            .await;
        client.close(file).await;
        let access = AccessMask::new()
            .with_execute(true)
            .with_read_attributes(true)
            .into_bits();
        let response = client.open_result("execute", access, 7, 1, 0).await;
        let file = read_body::<CreateResponse>(&response).unwrap().file_id;
        assert_eq!(&client.query(file, 8).await[72..], &access.to_le_bytes());
        assert_eq!(&client.read(file, 0, 4).await[80..], b"code");
        client.close(file).await;
        let directory = client.open("directory", 2, 1).await;
        client.close(directory).await;
        let response = client.open_result("directory", access, 7, 1, 1).await;
        let directory = read_body::<CreateResponse>(&response).unwrap().file_id;
        let mut query = QueryDirectoryRequest::new_zeroed();
        query.structure_size = QueryDirectoryRequest::STRUCTURE_SIZE.into();
        query.info_class = FileInformationClass::NAMES.0;
        query.file_id = directory;
        query.output_buffer_length = 4096.into();
        query.name_offset = (body_end::<QueryDirectoryRequest>() as u16).into();
        query.name_length = 2.into();
        let mut body = query.as_bytes().to_vec();
        body.extend_from_slice(&encode_name("*"));
        assert_eq!(
            response_status(&client.send(Command::QUERY_DIRECTORY, &body).await),
            Status::ACCESS_DENIED
        );
        assert_eq!(
            response_status(
                &client
                    .send(
                        Command::CHANGE_NOTIFY,
                        &notify::body(
                            directory,
                            NotifyFilter::new().with_file_name(true),
                            false,
                            4096
                        )
                    )
                    .await
            ),
            Status::ACCESS_DENIED
        );
        client.close(directory).await;
    });
}

fn contexts(values: &[(CreateContextName, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut previous = None;
    for (name, data) in values {
        append_create_context(&mut bytes, &mut previous, *name, data);
    }
    bytes
}

fn returned_contexts(packet: &[u8]) -> Vec<CreateContext<'_>> {
    let response = read_body::<CreateResponse>(packet).unwrap();
    let bytes = variable::<CreateResponse>(
        packet,
        response.contexts_offset.get() as usize,
        response.contexts_length.get() as usize,
    )
    .unwrap();
    create_contexts(bytes).unwrap()
}

#[test]
fn create_security_applies_before_visibility_and_ignores_existing_context_bytes() {
    use crate::security::{Acl, AclState, SecurityDescriptor};
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let mut descriptor = SecurityDescriptor::empty();
        descriptor.control.set_dacl_protected(true);
        descriptor.dacl = AclState::Present(Acl::access(&[]).unwrap());
        let encoded = descriptor.encode();
        let data = contexts(&[(CreateContextName::SECURITY_DESCRIPTOR, &encoded)]);
        let response = client
            .ok(
                Command::CREATE,
                &create_body(
                    "secured",
                    AccessMask::FILE_ALL_ACCESS.into_bits(),
                    7,
                    2,
                    0,
                    &data,
                ),
            )
            .await;
        let file = read_body::<CreateResponse>(&response).unwrap().file_id;
        client
            .ok(
                Command::WRITE,
                &Client::write_body(file, 0, b"creation grant"),
            )
            .await;
        assert_eq!(
            response_status(&client.open_result("secured", 1, 7, 1, 0).await),
            Status::ACCESS_DENIED
        );
        let malformed = contexts(&[(CreateContextName::SECURITY_DESCRIPTOR, &[0; 20])]);
        let response = client
            .ok(
                Command::CREATE,
                &create_body(
                    "secured",
                    AccessMask::new().with_read_control(true).into_bits(),
                    7,
                    3,
                    0,
                    &malformed,
                ),
            )
            .await;
        let existing = read_body::<CreateResponse>(&response).unwrap().file_id;
        client.close(existing).await;
        let response = client
            .send(
                Command::CREATE,
                &create_body("invalid", 1, 7, 2, 0, &malformed),
            )
            .await;
        assert_eq!(response_status(&response), Status::INVALID_SECURITY_DESCR);
        assert_eq!(
            response_status(&client.open_result("invalid", 1, 7, 1, 0).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        descriptor.control.set_dacl_protected(false);
        let encoded = descriptor.encode();
        let data = contexts(&[(CreateContextName::SECURITY_DESCRIPTOR, &encoded)]);
        let response = client
            .ok(
                Command::CREATE,
                &create_body("inherited", 1, 7, 2, 0, &data),
            )
            .await;
        let inherited = read_body::<CreateResponse>(&response).unwrap().file_id;
        client.close(inherited).await;
        let response = client.open_result("inherited", 1, 7, 1, 0).await;
        let reopened = read_body::<CreateResponse>(&response).unwrap().file_id;
        client.close(reopened).await;
        client.close(file).await;
    });
}

#[test]
fn create_context_queries_return_stable_ids_and_backend_maximal_access() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(8, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let data = contexts(&[
            (CreateContextName::QUERY_ON_DISK_ID, &[]),
            (CreateContextName::DURABLE_HANDLE_REQUEST, &[0; 16]),
            (CreateContextName::ALLOCATION_SIZE, &u64::MAX.to_le_bytes()),
            (CreateContextName::QUERY_MAXIMAL_ACCESS, &[]),
        ]);
        let packet = client
            .ok(Command::CREATE, &create_body("file", 0x81, 7, 2, 0, &data))
            .await;
        let id = FileId::read_from_bytes(&packet[128..144]).unwrap();
        let contexts = returned_contexts(&packet);
        assert_eq!(contexts.len(), 2);
        let maximal = MaximalAccessResponse::read_from_bytes(
            contexts
                .iter()
                .find(|c| c.name() == Some(CreateContextName::QUERY_MAXIMAL_ACCESS))
                .unwrap()
                .data,
        )
        .unwrap();
        assert_eq!(maximal.query_status.get(), Status::SUCCESS.0);
        assert_eq!(
            maximal.maximal_access.into_bits(),
            AccessMask::FILE_ALL_ACCESS.into_bits()
        );
        let disk = OnDiskIdResponse::read_from_bytes(
            contexts
                .iter()
                .find(|c| c.name() == Some(CreateContextName::QUERY_ON_DISK_ID))
                .unwrap()
                .data,
        )
        .unwrap();
        assert_eq!(disk.file_id.get(), id.persistent.get());
        assert!(disk.reserved.iter().all(|byte| *byte == 0));
        let internal = client.query(id, 6).await;
        assert_eq!(
            u64::from_le_bytes(internal[72..80].try_into().unwrap()),
            disk.file_id.get()
        );
        assert_eq!(u64::from_le_bytes(packet[112..120].try_into().unwrap()), 0);
        assert_eq!(
            response_status(&client.query(id, 21).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        client.close(id).await;
        let changed = u64::from_le_bytes(packet[96..104].try_into().unwrap());
        let data = self::contexts(&[
            (
                CreateContextName::QUERY_MAXIMAL_ACCESS,
                &changed.to_le_bytes(),
            ),
            (CreateContextName::QUERY_ON_DISK_ID, &[]),
        ]);
        let packet = client
            .ok(Command::CREATE, &create_body("file", 0x81, 7, 1, 0, &data))
            .await;
        let contexts = returned_contexts(&packet);
        let maximal = MaximalAccessResponse::read_from_bytes(
            contexts
                .iter()
                .find(|c| c.name() == Some(CreateContextName::QUERY_MAXIMAL_ACCESS))
                .unwrap()
                .data,
        )
        .unwrap();
        assert_eq!(maximal.query_status.get(), Status::NONE_MAPPED.0);
        assert_eq!(maximal.maximal_access.into_bits(), 0);
        let reopened = OnDiskIdResponse::read_from_bytes(
            contexts
                .iter()
                .find(|c| c.name() == Some(CreateContextName::QUERY_ON_DISK_ID))
                .unwrap()
                .data,
        )
        .unwrap();
        assert_eq!(reopened.file_id.get(), disk.file_id.get());
        assert_eq!(reopened.volume_id.get(), disk.volume_id.get());
    });
}

#[test]
fn maximum_allowed_uses_provider_grants_and_readonly_constraints() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("readonly", 2, 0).await;
        let mut basic = FileBasicInformation::new_zeroed();
        basic.file_attributes = FileAttributes::new().with_readonly(true);
        assert_eq!(
            response_status(&client.set(file, 4, basic.as_bytes()).await),
            Status::SUCCESS
        );
        client.close(file).await;
        let response = client
            .open_result(
                "readonly",
                AccessMask::new().with_maximum_allowed(true).into_bits(),
                7,
                1,
                0,
            )
            .await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        let file = read_body::<CreateResponse>(&response).unwrap().file_id;
        let access = client.query(file, 8).await;
        let access = AccessMask::from_bits(u32::from_le_bytes(access[72..76].try_into().unwrap()));
        assert!(access.read_data());
        assert!(!access.write_data());
        assert!(!access.append_data());
        assert!(!access.maximum_allowed());
        assert_eq!(
            response_status(
                &client
                    .send(Command::WRITE, &Client::write_body(file, 0, b"x"))
                    .await
            ),
            Status::ACCESS_DENIED
        );
        client.close(file).await;
        let response = client
            .open_result(
                "readonly",
                AccessMask::new()
                    .with_maximum_allowed(true)
                    .with_write_data(true)
                    .into_bits(),
                7,
                1,
                0,
            )
            .await;
        assert_eq!(response_status(&response), Status::ACCESS_DENIED);
    });
}

#[test]
fn malformed_create_context_chains_do_not_create_files() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 32)).unwrap();
        let mut client = Client::new(&server).await;
        let valid = contexts(&[(CreateContextName::QUERY_MAXIMAL_ACCESS, &1u64.to_le_bytes())]);
        let mut invalid = Vec::new();
        for (offset, value) in [
            (std::mem::offset_of!(CreateContextHeader, next), 26u32),
            (std::mem::offset_of!(CreateContextHeader, next), 16),
            (std::mem::offset_of!(CreateContextHeader, next), 32),
            (
                std::mem::offset_of!(CreateContextHeader, data_length),
                u32::MAX,
            ),
        ] {
            let mut bytes = valid.clone();
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            invalid.push(bytes);
        }
        for (offset, value) in [
            (std::mem::offset_of!(CreateContextHeader, name_offset), 8u16),
            (std::mem::offset_of!(CreateContextHeader, name_length), 3),
            (std::mem::offset_of!(CreateContextHeader, data_offset), 16),
            (std::mem::offset_of!(CreateContextHeader, data_offset), 25),
        ] {
            let mut bytes = valid.clone();
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            invalid.push(bytes);
        }
        let mut tail = contexts(&[
            (CreateContextName::QUERY_MAXIMAL_ACCESS, &[]),
            (CreateContextName::QUERY_ON_DISK_ID, &[]),
        ]);
        let next = CreateContextHeader::read_from_prefix(&tail)
            .unwrap()
            .0
            .next
            .get() as usize;
        CreateContextHeader::mut_from_prefix(&mut tail[next..])
            .unwrap()
            .0
            .name_length = 3.into();
        invalid.push(tail);
        for (index, bytes) in invalid.iter().enumerate() {
            let name = format!("invalid{index}");
            let response = client
                .send(Command::CREATE, &create_body(&name, 1, 7, 2, 0, bytes))
                .await;
            assert_eq!(response_status(&response), Status::INVALID_PARAMETER);
            client.open(&name, 2, 0).await;
        }
        let mut ignored = contexts(&[(CreateContextName::QUERY_MAXIMAL_ACCESS, &[])]);
        let header = CreateContextHeader::mut_from_prefix(&mut ignored[..])
            .unwrap()
            .0;
        header.reserved = u16::MAX.into();
        header.data_offset = u16::MAX.into();
        let response = client
            .ok(
                Command::CREATE,
                &create_body("reserved", 1, 7, 2, 0, &ignored),
            )
            .await;
        assert_eq!(returned_contexts(&response).len(), 1);
        let duplicates = contexts(&[
            (CreateContextName::QUERY_MAXIMAL_ACCESS, &[]),
            (CreateContextName::QUERY_MAXIMAL_ACCESS, &[]),
        ]);
        assert_eq!(
            response_status(
                &client
                    .send(
                        Command::CREATE,
                        &create_body("duplicate", 1, 7, 2, 0, &duplicates)
                    )
                    .await
            ),
            Status::INVALID_PARAMETER
        );
    });
}

#[test]
fn unsupported_eas_fail_before_creation_and_are_ignored_on_explicit_open() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let data = contexts(&[(CreateContextName::EA_BUFFER, &[0; 8])]);
        let response = client
            .send(Command::CREATE, &create_body("ea", 1, 7, 2, 0, &data))
            .await;
        assert_eq!(response_status(&response), Status::EAS_NOT_SUPPORTED);
        let id = client.open("ea", 2, 0).await;
        client.close(id).await;
        client
            .ok(Command::CREATE, &create_body("ea", 1, 7, 1, 0, &data))
            .await;
    });
}

#[test]
fn basic_information_times_and_attributes_are_atomic_and_handle_scoped() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let id = client.open("times", 2, 0).await;
        let mut info = FileBasicInformation::new_zeroed();
        info.creation_time = 100.into();
        info.last_access_time = 200.into();
        info.last_write_time = 300.into();
        info.change_time = 400.into();
        info.file_attributes = 0x80.into();
        info.reserved = u32::MAX.into();
        client
            .ok(Command::SET_INFO, &set_body(id, info.as_bytes()))
            .await;
        let frozen = FileBasicInformation {
            creation_time: 0.into(),
            last_access_time: (-1).into(),
            last_write_time: (-1).into(),
            change_time: (-1).into(),
            file_attributes: 0.into(),
            reserved: 0.into(),
        };
        assert_eq!(
            response_status(&client.set(id, 4, frozen.as_bytes()).await),
            Status::SUCCESS
        );
        client
            .ok(Command::WRITE, &Client::write_body(id, 0, b"data"))
            .await;
        client.read(id, 0, 4).await;
        let response = client.query(id, 4).await;
        let actual = FileBasicInformation::read_from_bytes(&response[72..112]).unwrap();
        assert_eq!(actual.creation_time.get(), 100);
        assert_eq!(actual.last_access_time.get(), 200);
        assert_eq!(actual.last_write_time.get(), 300);
        assert_eq!(actual.change_time.get(), 400);
        assert!(actual.file_attributes.normal());
        let mut invalid = info;
        invalid.creation_time = (-3).into();
        invalid.file_attributes = 2.into();
        assert_eq!(
            response_status(&client.set(id, 4, invalid.as_bytes()).await),
            Status::INVALID_PARAMETER
        );
        assert_eq!(&client.query(id, 4).await[72..112], actual.as_bytes());
        invalid = info;
        invalid.file_attributes = 0x10.into();
        assert_eq!(
            response_status(&client.set(id, 4, invalid.as_bytes()).await),
            Status::INVALID_PARAMETER
        );
        let restore = FileBasicInformation {
            creation_time: 0.into(),
            last_access_time: (-2).into(),
            last_write_time: (-2).into(),
            change_time: (-2).into(),
            file_attributes: 0.into(),
            reserved: 0.into(),
        };
        assert_eq!(
            response_status(&client.set(id, 4, restore.as_bytes()).await),
            Status::SUCCESS
        );
        client
            .ok(Command::WRITE, &Client::write_body(id, 0, b"more"))
            .await;
        let response = client.query(id, 4).await;
        let actual = FileBasicInformation::read_from_bytes(&response[72..112]).unwrap();
        assert!(actual.last_write_time.get() > 300);
        assert!(actual.change_time.get() > 400);
        let readonly = client.open_result("times", 0x81, 7, 1, 0).await;
        let readonly = FileId::read_from_bytes(&readonly[128..144]).unwrap();
        assert_eq!(
            response_status(&client.set(readonly, 4, info.as_bytes()).await),
            Status::ACCESS_DENIED
        );
        assert_eq!(
            response_status(&client.set(id, 4, &[]).await),
            Status::INFO_LENGTH_MISMATCH
        );
    });
}

fn set_body(id: FileId, data: &[u8]) -> Vec<u8> {
    let mut request = SetInfoRequest::new_zeroed();
    request.structure_size = SetInfoRequest::STRUCTURE_SIZE.into();
    request.info_type = InformationType::FILE;
    request.info_class = 4;
    request.buffer_offset = (body_end::<SetInfoRequest>() as u16).into();
    request.buffer_length = (data.len() as u32).into();
    request.file_id = id;
    let mut body = request.as_bytes().to_vec();
    body.extend_from_slice(data);
    body
}
