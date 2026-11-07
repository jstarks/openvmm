// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

#[test]
fn reserve_opfilter_is_rejected_before_open_or_replacement_effects() {
    use crate::test_support::ControlledFs;
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("existing", 2, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"keep"))
            .await;
        for (name, disposition, options) in [
            ("absent", 2, 0x00100000),
            ("existing", 1, 0x00100000),
            ("existing", 4, 0x00100000),
            ("", 1, 0x00100001),
        ] {
            let before = control.calls().len();
            let bytes = create_body(
                name,
                AccessMask::FILE_ALL_ACCESS.into_bits(),
                7,
                disposition,
                options,
                &[],
            );
            assert_eq!(
                response_status(&client.send(Command::CREATE, &bytes).await),
                Status::NOT_SUPPORTED
            );
            assert_eq!(control.calls().len(), before);
        }
        assert_eq!(&client.read(file, 0, 4).await[80..], b"keep");
        assert_eq!(
            response_status(&client.open_result("absent", 1, 7, 1, 0).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        client.close(file).await;
    });
}

#[test]
fn ignored_remote_and_oplock_create_options_do_not_change_open_behavior() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        for options in [0x400, 0x10000, 0x20000, 0x30400] {
            let response = client
                .open_result(
                    "ignored",
                    AccessMask::FILE_ALL_ACCESS.into_bits(),
                    7,
                    3,
                    options,
                )
                .await;
            assert_eq!(response_status(&response), Status::SUCCESS);
            let file = read_body::<CreateResponse>(&response).unwrap().file_id;
            client
                .ok(Command::WRITE, &Client::write_body(file, 0, b"data"))
                .await;
            assert_eq!(&client.read(file, 0, 4).await[80..], b"data");
            client.close(file).await;
        }
    });
}

#[test]
fn compression_information_reports_actual_memory_allocation_without_read_attributes() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(128, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("compression", 2, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"data"))
            .await;
        let limited = client
            .open_result(
                "compression",
                AccessMask::new().with_read_data(true).into_bits(),
                7,
                1,
                0,
            )
            .await;
        let limited = read_body::<CreateResponse>(&limited).unwrap().file_id;
        for allocation in [4u64, 32] {
            if allocation != 4 {
                assert_eq!(
                    response_status(
                        &client
                            .set(
                                file,
                                FileInformationClass::ALLOCATION.0,
                                &allocation.to_le_bytes()
                            )
                            .await
                    ),
                    Status::SUCCESS
                );
            }
            let response = client.query(limited, 28).await;
            assert_eq!(response_status(&response), Status::SUCCESS);
            assert_eq!(&response[72..80], &allocation.to_le_bytes());
            assert_eq!(&response[80..88], &[0; 8]);
        }
        let mut query = QueryInfoRequest::new_zeroed();
        query.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
        query.file_id = limited;
        query.info_type = InformationType::FILE;
        query.info_class = 28;
        query.output_buffer_length = 15.into();
        assert_eq!(
            response_status(&client.send(Command::QUERY_INFO, query.as_bytes()).await),
            Status::INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            response_status(&client.query(limited, 48).await),
            Status::NOT_SUPPORTED
        );
        client.close(limited).await;
        client.close(file).await;
        let directory = client.open("", 1, 1).await;
        let response = client.query(directory, 28).await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        assert_eq!(&response[72..], &[0; 16]);
        client.close(directory).await;
    });
}

#[test]
fn create_allocation_reserves_atomically_without_extending_eof() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(32, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let allocation =
            |size: u64| contexts(&[(CreateContextName::ALLOCATION_SIZE, &size.to_le_bytes())]);
        let body = create_body(
            "allocated",
            AccessMask::FILE_ALL_ACCESS.into_bits(),
            7,
            2,
            0,
            &allocation(16),
        );
        let response = client.ok(Command::CREATE, &body).await;
        let created = read_body::<CreateResponse>(&response).unwrap();
        assert_eq!(
            (created.end_of_file.get(), created.allocation_size.get()),
            (0, 16)
        );
        let file = created.file_id;
        assert_eq!(
            response_status(&client.read(file, 0, 1).await),
            Status::END_OF_FILE
        );
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"before"))
            .await;
        let body = create_body(
            "allocated",
            AccessMask::FILE_ALL_ACCESS.into_bits(),
            7,
            1,
            0,
            &allocation(64),
        );
        let response = client.ok(Command::CREATE, &body).await;
        let existing = read_body::<CreateResponse>(&response).unwrap();
        assert_eq!(
            (existing.end_of_file.get(), existing.allocation_size.get()),
            (6, 16)
        );
        client.close(existing.file_id).await;
        let body = create_body(
            "failed",
            AccessMask::FILE_ALL_ACCESS.into_bits(),
            7,
            2,
            0,
            &allocation(33),
        );
        assert_eq!(
            response_status(&client.send(Command::CREATE, &body).await),
            Status::DISK_FULL
        );
        assert_eq!(
            response_status(&client.open_result("failed", 1, 7, 1, 0).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        for disposition in [0, 4, 5] {
            let body = create_body(
                "allocated",
                AccessMask::FILE_ALL_ACCESS.into_bits(),
                7,
                disposition,
                0,
                &allocation(33),
            );
            assert_eq!(
                response_status(&client.send(Command::CREATE, &body).await),
                Status::DISK_FULL
            );
            assert_eq!(&client.read(file, 0, 6).await[80..], b"before");
            let standard = client.query(file, FileInformationClass::STANDARD.0).await;
            let standard = FileStandardInformation::read_from_bytes(&standard[72..]).unwrap();
            assert_eq!(
                (standard.end_of_file.get(), standard.allocation_size.get()),
                (6, 16)
            );
        }
        let body = create_body(
            "allocated",
            AccessMask::FILE_ALL_ACCESS.into_bits(),
            7,
            4,
            0,
            &allocation(24),
        );
        let response = client.ok(Command::CREATE, &body).await;
        let overwritten = read_body::<CreateResponse>(&response).unwrap();
        assert_eq!(
            (
                overwritten.end_of_file.get(),
                overwritten.allocation_size.get()
            ),
            (0, 24)
        );
        let response = client
            .set(
                file,
                FileInformationClass::END_OF_FILE.0,
                &6u64.to_le_bytes(),
            )
            .await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        assert_eq!(&client.read(file, 0, 6).await[80..], &[0; 6]);
        client.close(overwritten.file_id).await;
        client.close(file).await;
        let body = create_body(
            "directory",
            AccessMask::FILE_ALL_ACCESS.into_bits(),
            7,
            2,
            1,
            &allocation(1024),
        );
        let response = client.ok(Command::CREATE, &body).await;
        let directory = read_body::<CreateResponse>(&response).unwrap();
        assert_eq!(directory.allocation_size.get(), 0);
        client.close(directory.file_id).await;
    });
}

#[test]
fn create_file_id_and_no_ea_knowledge_options_fail_before_provider_calls() {
    use crate::test_support::ControlledFs;
    block_on(async {
        let (backend, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let server = Server::new("memory", backend).unwrap();
        let mut client = Client::new(&server).await;
        let existing = client.open("existing", 2, 0).await;
        client.close(existing).await;
        let calls = control.calls().len();
        let ea = contexts(&[(
            CreateContextName::EA_BUFFER,
            &[0, 0, 0, 0, 0, 1, 0, 0, b'A', 0],
        )]);
        for (name, disposition) in [("new", 2), ("existing", 1), ("existing", 4)] {
            for (options, contexts, expected) in [
                (0x2000, &[][..], Status::NOT_SUPPORTED),
                (0x200, ea.as_slice(), Status::ACCESS_DENIED),
            ] {
                let body = create_body(
                    name,
                    AccessMask::FILE_ALL_ACCESS.into_bits(),
                    7,
                    disposition,
                    options,
                    contexts,
                );
                assert_eq!(
                    response_status(&client.send(Command::CREATE, &body).await),
                    expected
                );
                assert_eq!(control.calls().len(), calls);
            }
        }
    });
}

#[test]
fn reserved_create_context_is_ignored_without_skipping_framing_or_known_contexts() {
    use crate::test_support::ControlledFs;
    block_on(async {
        let (backend, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let server = Server::new("memory", backend).unwrap();
        let mut client = Client::new(&server).await;
        let header = CreateContextHeader {
            name_offset: 16.into(),
            name_length: 16.into(),
            data_offset: 32.into(),
            ..CreateContextHeader::new_zeroed()
        };
        let mut reserved = header.as_bytes().to_vec();
        reserved.extend_from_slice(&[
            0x93, 0xad, 0x25, 0x50, 0x9c, 0xb4, 0x11, 0xe7, 0xb4, 0x23, 0x83, 0xde, 0x96, 0x8b,
            0xcd, 0x7c,
        ]);
        let mut malformed = reserved.clone();
        CreateContextHeader::mut_from_prefix(&mut malformed)
            .unwrap()
            .0
            .next = 1.into();
        let body = create_body(
            "reserved",
            AccessMask::FILE_ALL_ACCESS.into_bits(),
            7,
            2,
            0,
            &malformed,
        );
        assert_eq!(
            response_status(&client.send(Command::CREATE, &body).await),
            Status::INVALID_PARAMETER
        );
        assert!(control.calls().is_empty());
        for repetitions in [1, 2] {
            let mut data = reserved.repeat(repetitions);
            if repetitions == 2 {
                CreateContextHeader::mut_from_prefix(&mut data)
                    .unwrap()
                    .0
                    .next = 32.into();
            }
            let mut previous = Some((repetitions - 1) * 32);
            append_create_context(
                &mut data,
                &mut previous,
                CreateContextName::QUERY_MAXIMAL_ACCESS,
                &[],
            );
            let name = format!("reserved-{repetitions}");
            let body = create_body(
                &name,
                AccessMask::FILE_ALL_ACCESS.into_bits(),
                7,
                2,
                0,
                &data,
            );
            let response = client.ok(Command::CREATE, &body).await;
            let returned = returned_contexts(&response);
            assert_eq!(returned.len(), 1);
            assert_eq!(
                returned[0].name(),
                Some(CreateContextName::QUERY_MAXIMAL_ACCESS)
            );
            let file = read_body::<CreateResponse>(&response).unwrap().file_id;
            client.close(file).await;
        }
    });
}

#[test]
fn replacement_checks_attributes_before_truncation_and_applies_requested_attributes() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        for disposition in [
            CreateDisposition::SUPERSEDE,
            CreateDisposition::OVERWRITE,
            CreateDisposition::OVERWRITE_IF,
        ] {
            let name = format!("replacement-{}", disposition.0);
            let original_attributes = FileAttributes::new().with_hidden(true).with_system(true);
            let mut body =
                create_body(&name, AccessMask::FILE_ALL_ACCESS.into_bits(), 7, 2, 0, &[]);
            CreateRequest::mut_from_prefix(&mut body)
                .unwrap()
                .0
                .file_attributes = original_attributes;
            let original = read_body::<CreateResponse>(&client.ok(Command::CREATE, &body).await)
                .unwrap()
                .file_id;
            client
                .ok(Command::WRITE, &Client::write_body(original, 0, b"before"))
                .await;
            let root = client.open("", 1, 1).await;
            let mut watch = std::pin::pin!(
                notify::accept(
                    &mut client,
                    root,
                    NotifyFilter::new().with_attributes(true),
                    false,
                    1024
                )
                .execute()
            );
            assert!(futures::poll!(&mut watch).is_pending());
            for attributes in [
                FileAttributes::new().with_hidden(true),
                FileAttributes::new().with_system(true),
            ] {
                let mut body = create_body(
                    &name,
                    AccessMask::FILE_ALL_ACCESS.into_bits(),
                    7,
                    disposition.0,
                    0,
                    &[],
                );
                CreateRequest::mut_from_prefix(&mut body)
                    .unwrap()
                    .0
                    .file_attributes = attributes;
                assert_eq!(
                    response_status(&client.send(Command::CREATE, &body).await),
                    Status::ACCESS_DENIED
                );
                assert_eq!(&client.read(original, 0, 6).await[80..], b"before");
                assert!(futures::poll!(&mut watch).is_pending());
            }
            let mut body = create_body(
                &name,
                AccessMask::new().with_read_attributes(true).into_bits(),
                7,
                disposition.0,
                0,
                &[],
            );
            CreateRequest::mut_from_prefix(&mut body)
                .unwrap()
                .0
                .file_attributes = original_attributes
                .with_readonly(true)
                .with_compressed(true)
                .with_not_content_indexed(true);
            let response = client.ok(Command::CREATE, &body).await;
            let replacement = read_body::<CreateResponse>(&response).unwrap();
            assert_eq!(replacement.file_attributes.into_bits(), 0x27);
            assert_eq!(replacement.end_of_file.get(), 0);
            assert_eq!(
                replacement.create_action.get(),
                if disposition == CreateDisposition::SUPERSEDE {
                    CreateAction::SUPERSEDED.0
                } else {
                    CreateAction::OVERWRITTEN.0
                }
            );
            let metadata = client.query(original, FileInformationClass::BASIC.0).await;
            assert_eq!(
                FileBasicInformation::read_from_bytes(&metadata[72..])
                    .unwrap()
                    .file_attributes
                    .into_bits(),
                0x27
            );
            assert_eq!(
                notify::changes(&watch.await.unwrap()),
                vec![(NotifyAction::MODIFIED, name)]
            );
            client.close(replacement.file_id).await;
            client.close(original).await;
            client.close(root).await;
        }
    });
}

#[test]
fn memory_creation_preserves_dos_attributes_without_fabricating_storage_features() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let requested = FileAttributes::new()
            .with_readonly(true)
            .with_hidden(true)
            .with_system(true)
            .with_sparse_file(true)
            .with_compressed(true)
            .with_encrypted(true)
            .with_reparse_point(true)
            .with_integrity_stream(true)
            .with_pinned(true)
            .with_not_content_indexed(true);
        for (name, options, expected) in [
            ("attributes-file", 0, 0x27u32),
            ("attributes-directory", 1, 0x16),
        ] {
            let mut body = create_body(
                name,
                AccessMask::FILE_ALL_ACCESS.into_bits(),
                7,
                2,
                options,
                &[],
            );
            CreateRequest::mut_from_prefix(&mut body)
                .unwrap()
                .0
                .file_attributes = requested;
            let response = client.ok(Command::CREATE, &body).await;
            let created = read_body::<CreateResponse>(&response).unwrap();
            assert_eq!(created.file_attributes.into_bits(), expected);
            let basic = client
                .query(created.file_id, FileInformationClass::BASIC.0)
                .await;
            let basic = FileBasicInformation::read_from_bytes(&basic[72..]).unwrap();
            assert_eq!(basic.file_attributes.into_bits(), expected);
            client.close(created.file_id).await;
        }
        let mut body = create_body(
            "temporary-directory",
            AccessMask::FILE_ALL_ACCESS.into_bits(),
            7,
            2,
            1,
            &[],
        );
        CreateRequest::mut_from_prefix(&mut body)
            .unwrap()
            .0
            .file_attributes = FileAttributes::new().with_temporary(true);
        assert_eq!(
            response_status(&client.send(Command::CREATE, &body).await),
            Status::INVALID_PARAMETER
        );
        assert_eq!(
            response_status(&client.open_result("temporary-directory", 1, 7, 1, 1).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
    });
}

#[test]
fn create_rejects_invalid_attributes_paths_and_impersonation_before_provider_calls() {
    use crate::test_support::ControlledFs;
    block_on(async {
        let (backend, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let server = Server::new("memory", backend).unwrap();
        let mut client = Client::new(&server).await;
        for (name, attributes, impersonation, status) in [
            ("invalid", 0x08, 0, Status::INVALID_PARAMETER),
            ("invalid", 0x40, 0, Status::INVALID_PARAMETER),
            ("invalid", 0x80000000, 0, Status::INVALID_PARAMETER),
            ("invalid", 0, 4, Status::BAD_IMPERSONATION_LEVEL),
            ("invalid", 0, u32::MAX, Status::BAD_IMPERSONATION_LEVEL),
            ("\\invalid", 0, 0, Status::INVALID_PARAMETER),
            ("\\\\invalid", 0, 0, Status::INVALID_PARAMETER),
        ] {
            let mut body = create_body(name, AccessMask::FILE_ALL_ACCESS.into_bits(), 7, 2, 0, &[]);
            let (request, _) = CreateRequest::mut_from_prefix(&mut body).unwrap();
            request.file_attributes = FileAttributes::from_bits(attributes);
            request.impersonation_level = impersonation.into();
            let response = client.send(Command::CREATE, &body).await;
            assert_eq!(response_status(&response), status);
            assert!(control.calls().is_empty());
        }
        for impersonation in 0..=3u32 {
            let mut body = create_body(
                "invalid",
                AccessMask::FILE_ALL_ACCESS.into_bits(),
                7,
                3,
                0,
                &[],
            );
            let (request, _) = CreateRequest::mut_from_prefix(&mut body).unwrap();
            request.impersonation_level = impersonation.into();
            let response = client.ok(Command::CREATE, &body).await;
            let created = read_body::<CreateResponse>(&response).unwrap();
            assert_eq!(
                created.create_action.get(),
                if impersonation == 0 { 2 } else { 1 }
            );
            client.close(created.file_id).await;
        }
    });
}

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
        let data = contexts(&[
            (CreateContextName::SECURITY_DESCRIPTOR, &encoded),
            (CreateContextName::QUERY_MAXIMAL_ACCESS, &[]),
        ]);
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
        let returned = returned_contexts(&response);
        let maximal = MaximalAccessResponse::read_from_bytes(returned[0].data).unwrap();
        assert_eq!(
            maximal.maximal_access.into_bits(),
            AccessMask::new()
                .with_read_control(true)
                .with_write_dac(true)
                .into_bits()
        );
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
fn ea_validation_precedes_provider_rejection_and_existing_eas_are_ignored() {
    use crate::test_support::{ControlledFs, Operation, Plan};
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        for (operation, failure) in [
            (Operation::QueryEas, Status::INVALID_INFO_CLASS),
            (Operation::SetEas, Status::INVALID_DEVICE_REQUEST),
            (Operation::QueryStreams, Status::INVALID_INFO_CLASS),
        ] {
            control
                .set_plan(
                    operation,
                    Plan {
                        failure: Some(failure),
                        ..Plan::default()
                    },
                )
                .unwrap();
        }
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("eas", 2, 0).await;
        for class in [15, 22] {
            assert_eq!(
                response_status(&client.query(file, class).await),
                Status::INVALID_INFO_CLASS
            );
        }
        let ea = [0, 0, 0, 0, 0, 1, 1, 0, b'A', 0, b'v'];
        assert_eq!(
            response_status(&client.set(file, 15, &ea).await),
            Status::INVALID_DEVICE_REQUEST
        );
        let mut linked = ea.to_vec();
        linked[..4].copy_from_slice(&12u32.to_le_bytes());
        linked.push(0);
        linked.extend_from_slice(&ea);
        assert_eq!(
            response_status(&client.set(file, 15, &linked).await),
            Status::INVALID_DEVICE_REQUEST
        );
        for malformed in [&ea[..7], &ea[..10], &[1][..]] {
            assert_eq!(
                response_status(&client.set(file, 15, malformed).await),
                Status::EA_LIST_INCONSISTENT
            );
        }
        let mut malformed = ea;
        malformed[9] = b'x';
        assert_eq!(
            response_status(&client.set(file, 15, &malformed).await),
            Status::EA_LIST_INCONSISTENT
        );
        malformed = ea;
        malformed[..4].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            response_status(&client.set(file, 15, &malformed).await),
            Status::EA_LIST_INCONSISTENT
        );
        let response = client.open_result("eas", 1, 7, 1, 0).await;
        let limited = read_body::<CreateResponse>(&response).unwrap().file_id;
        assert_eq!(
            response_status(&client.query(limited, 15).await),
            Status::ACCESS_DENIED
        );
        assert_eq!(
            response_status(&client.set(limited, 15, &[1]).await),
            Status::ACCESS_DENIED
        );
        let data = contexts(&[(CreateContextName::EA_BUFFER, &[1])]);
        let response = client
            .ok(Command::CREATE, &create_body("eas", 1, 7, 3, 0, &data))
            .await;
        let existing = read_body::<CreateResponse>(&response).unwrap().file_id;
        client.close(existing).await;
        control
            .plan_next(
                Operation::OpenExtendedAttributes,
                Plan {
                    failure: Some(Status::EAS_NOT_SUPPORTED),
                    ..Plan::default()
                },
            )
            .unwrap();
        assert_eq!(
            response_status(
                &client
                    .send(Command::CREATE, &create_body("new-eas", 1, 7, 2, 0, &data))
                    .await
            ),
            Status::EAS_NOT_SUPPORTED
        );
        assert_eq!(
            response_status(&client.open_result("new-eas", 1, 7, 1, 0).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        let mut volume = QueryInfoRequest::new_zeroed();
        volume.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
        volume.info_type = InformationType::FILESYSTEM;
        volume.info_class = 5;
        volume.file_id = file;
        volume.output_buffer_length = 256.into();
        let response = client.ok(Command::QUERY_INFO, volume.as_bytes()).await;
        let flags = FileSystemAttributes::from_bits(u32::from_le_bytes(
            response[72..76].try_into().unwrap(),
        ));
        assert!(flags.named_streams());
        assert!(flags.extended_attributes());
        assert!(!flags.persistent_acls());
        client.close(limited).await;
        client.close(file).await;
    });
}

#[test]
fn retained_eas_create_query_update_and_require_knowledge_when_marked() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let ea = [0, 0, 0, 0, 128, 1, 1, 0, b'A', 0, b'v'];
        let extra = contexts(&[(CreateContextName::EA_BUFFER, &ea)]);
        let response = client
            .ok(
                Command::CREATE,
                &create_body("retained-eas", 0x001f01ff, 7, 2, 0, &extra),
            )
            .await;
        let file = read_body::<CreateResponse>(&response).unwrap().file_id;
        assert_eq!(&client.query(file, 7).await[72..], &15u32.to_le_bytes());
        assert_eq!(&client.query(file, 15).await[72..], &ea);
        assert_eq!(
            response_status(&client.query(file, 15).await),
            Status::NO_MORE_EAS,
        );
        assert_eq!(
            response_status(&client.open_result("retained-eas", 1, 7, 1, 0x200).await),
            Status::ACCESS_DENIED,
        );
        let second = [0, 0, 0, 0, 0, 1, 2, 0, b'b', 0, b'W', b'Q'];
        assert_eq!(
            response_status(&client.set(file, 15, &second).await),
            Status::SUCCESS
        );
        let mut query = QueryInfoRequest::new_zeroed();
        query.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
        query.info_type = InformationType::FILE;
        query.info_class = 15;
        query.file_id = file;
        query.output_buffer_length = 1024.into();
        query.flags = 3.into();
        assert_eq!(
            &client.ok(Command::QUERY_INFO, query.as_bytes()).await[72..],
            &ea
        );
        let mut expected = second;
        expected[8] = b'B';
        assert_eq!(&client.query(file, 15).await[72..], &expected);
        let update = [0, 0, 0, 0, 0, 1, 1, 0, b'a', 0, b'z'];
        assert_eq!(
            response_status(&client.set(file, 15, &update).await),
            Status::SUCCESS
        );
        let response = client.open_result("retained-eas", 1, 7, 1, 0x200).await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        client
            .close(read_body::<CreateResponse>(&response).unwrap().file_id)
            .await;
        query.flags = 1.into();
        let response = client.ok(Command::QUERY_INFO, query.as_bytes()).await;
        let mut expected = expected.to_vec();
        expected[..4].copy_from_slice(&12u32.to_le_bytes());
        let mut last = update;
        last[8] = b'A';
        expected.extend_from_slice(&last);
        assert_eq!(&response[72..], expected);
        client.close(file).await;
    });
}

#[test]
fn ea_queries_preserve_complete_records_cursor_and_named_index_precedence() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let a = [0, 0, 0, 0, 0, 1, 1, 0, b'A', 0, b'v'];
        let b = [0, 0, 0, 0, 0, 1, 2, 0, b'B', 0, b'W', b'Q'];
        let mut all = a.to_vec();
        all[..4].copy_from_slice(&12u32.to_le_bytes());
        all.push(0);
        all.extend_from_slice(&b);
        let extra = contexts(&[(CreateContextName::EA_BUFFER, &all)]);
        let response = client
            .ok(
                Command::CREATE,
                &create_body("ea-query", 0x1f01ff, 7, 2, 0, &extra),
            )
            .await;
        let file = read_body::<CreateResponse>(&response).unwrap().file_id;
        let mut query = QueryInfoRequest::new_zeroed();
        query.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
        query.info_type = InformationType::FILE;
        query.info_class = 15;
        query.file_id = file;
        query.flags = 1.into();
        for (maximum, status) in [
            (0u32, Status::INFO_LENGTH_MISMATCH),
            (7, Status::INFO_LENGTH_MISMATCH),
            (8, Status::BUFFER_TOO_SMALL),
            (10, Status::BUFFER_TOO_SMALL),
            (11, Status::BUFFER_OVERFLOW),
            (12, Status::BUFFER_OVERFLOW),
            (24, Status::SUCCESS),
        ] {
            query.output_buffer_length = maximum.into();
            let response = client.send(Command::QUERY_INFO, query.as_bytes()).await;
            assert_eq!(response_status(&response), status);
            if status == Status::BUFFER_OVERFLOW {
                assert_eq!(&response[72..], &a);
            }
            if status == Status::SUCCESS {
                assert_eq!(&response[72..], &all);
            }
        }
        query.output_buffer_length = (MAX_TRANSFER_SIZE as u32 + 1).into();
        assert_eq!(
            response_status(&client.send(Command::QUERY_INFO, query.as_bytes()).await),
            Status::INVALID_PARAMETER
        );
        query.flags = 5.into();
        query.additional_information = 2.into();
        query.output_buffer_length = 12.into();
        assert_eq!(
            &client.ok(Command::QUERY_INFO, query.as_bytes()).await[72..],
            &b
        );
        for index in [0u32, 3] {
            query.additional_information = index.into();
            assert_eq!(
                response_status(&client.send(Command::QUERY_INFO, query.as_bytes()).await),
                Status::NONEXISTENT_EA_ENTRY
            );
        }
        let names = [8, 0, 0, 0, 1, b'b', 0, 0, 0, 0, 0, 0, 1, b'a', 0];
        query.input_buffer_offset = (body_end::<QueryInfoRequest>() as u16).into();
        query.input_buffer_length = (names.len() as u32).into();
        query.output_buffer_length = 64.into();
        query.flags = 7.into();
        query.additional_information = 0.into();
        let mut body = query.as_bytes().to_vec();
        body.extend_from_slice(&names);
        assert_eq!(&client.ok(Command::QUERY_INFO, &body).await[72..], &b);
        query.flags = 5.into();
        body = query.as_bytes().to_vec();
        body.extend_from_slice(&names);
        let mut expected = b.to_vec();
        expected[..4].copy_from_slice(&12u32.to_le_bytes());
        expected.extend_from_slice(&a);
        assert_eq!(&client.ok(Command::QUERY_INFO, &body).await[72..], expected);
        let mut later_missing = names;
        later_missing[13] = b'X';
        query.flags = 7.into();
        body = query.as_bytes().to_vec();
        body.extend_from_slice(&later_missing);
        assert_eq!(&client.ok(Command::QUERY_INFO, &body).await[72..], &b);
        query.flags = 5.into();
        query.output_buffer_length = 12.into();
        body = query.as_bytes().to_vec();
        body.extend_from_slice(&later_missing);
        let response = client.send(Command::QUERY_INFO, &body).await;
        assert_eq!(response_status(&response), Status::BUFFER_OVERFLOW);
        assert_eq!(&response[72..], &b);
        query.output_buffer_length = 64.into();
        for (offset, value, status) in [
            (5usize, b'X', Status::NONEXISTENT_EA_ENTRY),
            (0, 4, Status::EA_LIST_INCONSISTENT),
            (5, b'/', Status::INVALID_EA_NAME),
        ] {
            let mut malformed = names;
            malformed[offset] = value;
            let mut body = query.as_bytes().to_vec();
            body.extend_from_slice(&malformed);
            assert_eq!(
                response_status(&client.send(Command::QUERY_INFO, &body).await),
                status
            );
        }
        query.flags = 0.into();
        query.input_buffer_length = 0.into();
        assert_eq!(
            response_status(&client.send(Command::QUERY_INFO, query.as_bytes()).await),
            Status::NO_MORE_EAS
        );
        let deletes = [
            12, 0, 0, 0, 0, 1, 0, 0, b'A', 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, b'B', 0,
        ];
        assert_eq!(
            response_status(&client.set(file, 15, &deletes).await),
            Status::SUCCESS
        );
        query.flags = 1.into();
        assert_eq!(
            response_status(&client.send(Command::QUERY_INFO, query.as_bytes()).await),
            Status::NO_EAS_ON_FILE
        );
        assert_eq!(
            response_status(&client.set(file, 15, &a).await),
            Status::SUCCESS
        );
        query.flags = 0.into();
        assert_eq!(
            &client.ok(Command::QUERY_INFO, query.as_bytes()).await[72..],
            &a
        );
        client.close(file).await;
    });
}

#[test]
fn ea_storage_limits_fail_atomically_and_deletion_releases_the_charge() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(32, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let ea = [0, 0, 0, 0, 0, 1, 1, 0, b'A', 0, b'v'];
        let extra = contexts(&[(CreateContextName::EA_BUFFER, &ea)]);
        let combined = contexts(&[
            (CreateContextName::EA_BUFFER, &ea),
            (CreateContextName::ALLOCATION_SIZE, &24u64.to_le_bytes()),
        ]);
        assert_eq!(
            response_status(
                &client
                    .send(
                        Command::CREATE,
                        &create_body("combined", 0x1f01ff, 7, 2, 0, &combined)
                    )
                    .await
            ),
            Status::DISK_FULL,
        );
        assert_eq!(
            response_status(&client.open_result("combined", 1, 7, 1, 0).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        let response = client
            .ok(
                Command::CREATE,
                &create_body("quota-ea", 0x1f01ff, 7, 2, 0, &extra),
            )
            .await;
        let file = read_body::<CreateResponse>(&response).unwrap().file_id;
        assert_eq!(
            response_status(&client.set(file, 19, &16i64.to_le_bytes()).await),
            Status::SUCCESS
        );
        let mut update = vec![0, 0, 0, 0, 0, 1, 9, 0, b'A', 0];
        update.extend_from_slice(&[b'x'; 9]);
        assert_eq!(
            response_status(&client.set(file, 15, &update).await),
            Status::DISK_FULL
        );
        for (byte, value) in [(4usize, 1u8), (8, b'/')] {
            let mut malformed = ea;
            malformed[byte] = value;
            assert_eq!(
                response_status(&client.set(file, 15, &malformed).await),
                Status::INVALID_EA_NAME
            );
        }
        let mut oversized = vec![0, 0, 0, 0, 0, 1, 255, 255, b'A', 0];
        oversized.resize(10 + u16::MAX as usize, b'x');
        assert_eq!(
            response_status(&client.set(file, 15, &oversized).await),
            Status::EA_TOO_LARGE
        );
        assert_eq!(&client.query(file, 15).await[72..], &ea);
        assert_eq!(
            response_status(
                &client
                    .send(Command::CREATE, &create_body("no-room", 1, 7, 2, 0, &extra))
                    .await
            ),
            Status::DISK_FULL
        );
        assert_eq!(
            response_status(&client.open_result("no-room", 1, 7, 1, 0).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(
            response_status(
                &client
                    .set(file, 15, &[0, 0, 0, 0, 0, 1, 0, 0, b'A', 0])
                    .await
            ),
            Status::SUCCESS
        );
        assert_eq!(
            response_status(&client.query(file, 15).await),
            Status::NO_EAS_ON_FILE
        );
        let response = client
            .ok(
                Command::CREATE,
                &create_body("now-room", 0x1f01ff, 7, 2, 0, &extra),
            )
            .await;
        let other = read_body::<CreateResponse>(&response).unwrap().file_id;
        assert_eq!(
            response_status(&client.set(other, 13, &[1]).await),
            Status::SUCCESS
        );
        client.close(other).await;
        assert_eq!(
            response_status(&client.set(file, 19, &32i64.to_le_bytes()).await),
            Status::SUCCESS
        );
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
            (CreateContextName::ALLOCATION_SIZE, &8u64.to_le_bytes()),
            (CreateContextName::QUERY_MAXIMAL_ACCESS, &[]),
        ]);
        let packet = client
            .ok(Command::CREATE, &create_body("file", 0x81, 7, 2, 0, &data))
            .await;
        let id = FileId::read_from_bytes(&packet[128..144]).unwrap();
        assert_eq!(
            read_body::<CreateResponse>(&packet)
                .unwrap()
                .allocation_size
                .get(),
            8
        );
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
        let data = contexts(&[(CreateContextName::QUERY_MAXIMAL_ACCESS, &[])]);
        let response = client
            .ok(
                Command::CREATE,
                &create_body(
                    "readonly",
                    AccessMask::new().with_maximum_allowed(true).into_bits(),
                    7,
                    1,
                    0,
                    &data,
                ),
            )
            .await;
        let returned = returned_contexts(&response);
        let maximal = MaximalAccessResponse::read_from_bytes(returned[0].data).unwrap();
        assert_eq!(
            maximal.maximal_access.into_bits(),
            AccessMask::FILE_ALL_ACCESS.into_bits()
        );
        let file = read_body::<CreateResponse>(&response).unwrap().file_id;
        let access = client.query(file, 8).await;
        let access = AccessMask::from_bits(u32::from_le_bytes(access[72..76].try_into().unwrap()));
        assert!(access.read_data());
        assert!(!access.write_data());
        assert!(!access.append_data());
        assert!(!access.delete_child());
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
    use crate::test_support::{ControlledFs, Operation, Plan};
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        control
            .plan_next(
                Operation::OpenExtendedAttributes,
                Plan {
                    failure: Some(Status::EAS_NOT_SUPPORTED),
                    ..Plan::default()
                },
            )
            .unwrap();
        let server = Server::new("memory", fs).unwrap();
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
