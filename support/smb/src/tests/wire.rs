// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

#[test]
fn embedded_bitfields_decode_unaligned_create_and_preserve_unknown_bits() {
    // Independent MS-SMB2 §2.2.13 fixture: access/attributes/options at 24/28/40.
    let mut bytes = [0; 1 + 56];
    let body = &mut bytes[1..];
    body[..2].copy_from_slice(&57u16.to_le_bytes());
    body[24..28].copy_from_slice(&0x8200_0281u32.to_le_bytes());
    body[28..32].copy_from_slice(&0x0004_0010u32.to_le_bytes());
    body[40..44].copy_from_slice(&0x0000_1001u32.to_le_bytes());
    let request = CreateRequest::ref_from_bytes(body).unwrap();
    assert!(request.desired_access.read_data());
    assert!(request.desired_access.read_attributes());
    assert!(request.desired_access.generic_read());
    assert!(request.desired_access.maximum_allowed());
    assert!(request.file_attributes.directory());
    assert!(request.file_attributes.recall_on_open());
    assert!(request.create_options.directory_file());
    assert!(request.create_options.delete_on_close());

    let request = CreateRequest::mut_from_bytes(body).unwrap();
    request.desired_access.set_write_data(true);
    request.create_options.set_directory_file(false);
    assert_eq!(&body[24..28], &[0x83, 0x02, 0x00, 0x82]);
    assert_eq!(&body[40..44], &[0x00, 0x10, 0x00, 0x00]);
    assert_eq!(&body[28..32], &[0x10, 0x00, 0x04, 0x00]);
    body[..2].copy_from_slice(&56u16.to_le_bytes());
    assert!(matches!(
        decode::<CreateRequest>(body),
        Err(Status::INVALID_PARAMETER)
    ));
}

#[test]
fn directory_formats_match_independent_byte_layouts() {
    let info = Metadata {
        id: 0x0807_0605_0403_0201,
        name: "a\u{100}".into(),
        path: "\\a\u{100}".into(),
        short_name: Some("S1".into()),
        attributes: FileAttributes::new().with_archive(true).into_bits(),
        created: 1,
        accessed: 2,
        written: 3,
        changed: 4,
        size: 5,
        allocation_size: 8,
        number_of_links: 2,
        extended_attributes_length: 8,
        alignment_requirement: 511,
        delete_pending: false,
        maximal_access: AccessMask::FILE_ALL_ACCESS.into_bits(),
        granted_access: AccessMask::FILE_ALL_ACCESS.into_bits(),
    };
    // Literal fixed lengths and offsets are independent of the encoder's types:
    // MS-FSCC §§2.4.8, 10, 15, 22, 24, 33.
    for (class, fixed, short_name, id_offset) in [
        (FileInformationClass::DIRECTORY, 64, false, None),
        (FileInformationClass::FULL_DIRECTORY, 68, false, None),
        (FileInformationClass::BOTH_DIRECTORY, 94, true, None),
        (FileInformationClass::NAMES, 12, false, None),
        (FileInformationClass::ID_BOTH_DIRECTORY, 104, true, Some(96)),
        (FileInformationClass::ID_FULL_DIRECTORY, 80, false, Some(72)),
    ] {
        let mut expected = vec![0; fixed];
        if class == FileInformationClass::NAMES {
            expected[8..12].copy_from_slice(&4u32.to_le_bytes());
        } else {
            for (offset, time) in [(8, 1u64), (16, 2), (24, 3), (32, 4)] {
                expected[offset..offset + 8].copy_from_slice(&time.to_le_bytes());
            }
            expected[40..48].copy_from_slice(&5u64.to_le_bytes());
            expected[48..56].copy_from_slice(&8u64.to_le_bytes());
            expected[56..60].copy_from_slice(&0x20u32.to_le_bytes());
            expected[60..64].copy_from_slice(&4u32.to_le_bytes());
            if class != FileInformationClass::DIRECTORY {
                expected[64..68].copy_from_slice(&8u32.to_le_bytes());
            }
            if short_name {
                expected[68] = 4;
                expected[70..74].copy_from_slice(&[b'S', 0, b'1', 0]);
            }
            if let Some(offset) = id_offset {
                expected[offset..offset + 8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
            }
        }
        expected.extend_from_slice(&[b'a', 0, 0, 1]);
        assert_eq!(
            directory_record(class, &info).unwrap(),
            expected,
            "{class:?}"
        );

        let mut no_alias = info.clone();
        no_alias.short_name = None;
        if short_name {
            expected[68..94].fill(0);
            assert_eq!(
                directory_record(class, &no_alias).unwrap(),
                expected,
                "{class:?}"
            );
        }
    }
    let mut invalid_alias = info;
    invalid_alias.short_name = Some("a".repeat(13));
    assert!(matches!(
        directory_record(FileInformationClass::BOTH_DIRECTORY, &invalid_alias),
        Err(Status::INTERNAL_ERROR)
    ));
    assert_eq!(ea_size(&invalid_alias).unwrap(), 12);
    let standard = standard_info(&invalid_alias);
    assert_eq!(standard.allocation_size.get(), 8);
    assert_eq!(standard.end_of_file.get(), 5);
    assert_eq!(standard.number_of_links.get(), 2);
}

#[test]
fn core_replies_match_literal_buffer_and_context_layouts() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let mut contexts = Vec::new();
        append_create_context(
            &mut contexts,
            &mut None,
            CreateContextName::QUERY_MAXIMAL_ACCESS,
            &[],
        );
        let response = client
            .ok(
                Command::CREATE,
                &create_body(
                    "A",
                    AccessMask::FILE_ALL_ACCESS.into_bits(),
                    ShareAccess::ALL.into_bits(),
                    CreateDisposition::CREATE.0,
                    0,
                    &contexts,
                ),
            )
            .await;
        // MS-SMB2 §§2.2.14, 2.2.14.2.5: context at 152, payload at context+24.
        assert_eq!(&response[144..152], &[152, 0, 0, 0, 32, 0, 0, 0]);
        assert_eq!(
            &response[152..],
            &[
                0, 0, 0, 0, 16, 0, 4, 0, 0, 0, 24, 0, 8, 0, 0, 0, b'M', b'x', b'A', b'c', 0, 0, 0,
                0, 0, 0, 0, 0, 0xff, 1, 0x1f, 0,
            ]
        );
        let file = read_body::<CreateResponse>(&response).unwrap().file_id;
        let created = read_body::<CreateResponse>(&response).unwrap();
        let response = client.query(file, FileInformationClass::ALL.0).await;
        // MS-SMB2 §2.2.38 and MS-FSCC §2.4.2: fixed ALL prefix 100, name 4 bytes.
        assert_eq!(&response[64..72], &[9, 0, 72, 0, 104, 0, 0, 0]);
        assert_eq!(&response[168..], &[4, 0, 0, 0, b'\\', 0, b'A', 0]);
        assert_eq!(
            response_status(&client.query(file, FileInformationClass::NAME.0).await),
            Status::NOT_SUPPORTED
        );
        let standard = client.query(file, FileInformationClass::STANDARD.0).await;
        assert_eq!(
            &standard[72..],
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(
            &client.query(file, FileInformationClass::POSITION.0).await[72..],
            &[0; 8]
        );
        // MS-FSCC §2.4.34 puts times before allocation/EOF, then attributes/padding.
        let mut network = Vec::new();
        for time in [
            created.creation_time,
            created.last_access_time,
            created.last_write_time,
            created.change_time,
        ] {
            network.extend_from_slice(&time.get().to_le_bytes());
        }
        network.extend_from_slice(&[0; 16]);
        network.extend_from_slice(&[0x20, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            &client
                .query(file, FileInformationClass::NETWORK_OPEN.0)
                .await[72..],
            &network
        );
        for (class, expected) in [
            (
                FileSystemInformationClass::DEVICE,
                vec![7, 0, 0, 0, 0, 0, 0, 0],
            ),
            (
                FileSystemInformationClass::ATTRIBUTE,
                vec![
                    6, 0, 0, 0, 255, 0, 0, 0, 12, 0, 0, 0, b'M', 0, b'E', 0, b'M', 0, b'O', 0,
                    b'R', 0, b'Y', 0,
                ],
            ),
        ] {
            // MS-FSCC §§2.5.1, 2.5.10: separate filesystem information-class namespace.
            let mut query = QueryInfoRequest::new_zeroed();
            query.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
            query.info_type = InformationType::FILESYSTEM;
            query.info_class = class.0;
            query.output_buffer_length = 1024.into();
            query.file_id = file;
            let response = client.ok(Command::QUERY_INFO, query.as_bytes()).await;
            assert_eq!(&response[72..], &expected);
        }
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"abc"))
            .await;
        let response = client.read(file, 0, 3).await;
        // MS-SMB2 §2.2.20: StructureSize 17, fixed prefix 16, data at packet+80.
        assert_eq!(
            &response[64..],
            &[
                17, 0, 80, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'a', b'b', b'c',
            ]
        );
        assert_eq!(&response[16..20], &[1, 0, 0, 0]);
    });
}
