// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

#[test]
fn ea_size_queries_do_not_require_ea_content_or_attribute_access() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        for (name, options) in [("file", 0), ("directory", 1)] {
            let response = client
                .open_result(
                    name,
                    AccessMask::new().with_synchronize(true).into_bits(),
                    7,
                    2,
                    options,
                )
                .await;
            assert_eq!(response_status(&response), Status::SUCCESS);
            let file = read_body::<CreateResponse>(&response).unwrap().file_id;
            let response = client.query(file, FileInformationClass::EA.0).await;
            assert_eq!(response_status(&response), Status::SUCCESS);
            assert_eq!(&response[72..], &[0; 4]);
            for class in [FileInformationClass::FULL_EA, FileInformationClass::BASIC] {
                assert_eq!(
                    response_status(&client.query(file, class.0).await),
                    Status::ACCESS_DENIED
                );
            }
            client.close(file).await;
        }
    });
}

#[test]
fn get_compression_control_reports_storage_state_without_attribute_access() {
    use crate::test_support::{ControlledFs, Operation, Plan};
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        for (name, options) in [("compressed-file", 0), ("compressed-directory", 1)] {
            let response = client.open_result(name, 0x00100000, 7, 2, options).await;
            assert_eq!(response_status(&response), Status::SUCCESS);
            let file = read_body::<CreateResponse>(&response).unwrap().file_id;
            let mut ioctl = IoctlRequest::new_zeroed();
            ioctl.structure_size = IoctlRequest::STRUCTURE_SIZE.into();
            ioctl.file_id = file;
            ioctl.control_code = 0x0009003cu32.into();
            ioctl.flags = IoctlFlags::new().with_fsctl(true);
            for maximum in [0u32, 1, 2, 4] {
                ioctl.max_output_response = maximum.into();
                let response = client.send(Command::IOCTL, ioctl.as_bytes()).await;
                if maximum < 2 {
                    assert_eq!(response_status(&response), Status::INVALID_PARAMETER);
                } else {
                    assert_eq!(response_status(&response), Status::SUCCESS);
                    let mut expected = vec![49, 0, 0, 0, 0x3c, 0, 9, 0];
                    expected.extend_from_slice(file.as_bytes());
                    for field in [112u32, 0, 112, 2, 0, 0] {
                        expected.extend_from_slice(&field.to_le_bytes());
                    }
                    expected.extend_from_slice(&[0, 0]);
                    assert_eq!(&response[64..], expected);
                }
            }
            for failure in [Status::INVALID_DEVICE_REQUEST, Status::ACCESS_DENIED] {
                control
                    .set_plan(
                        Operation::FileControl,
                        Plan {
                            failure: Some(failure),
                            ..Plan::default()
                        },
                    )
                    .unwrap();
                assert_eq!(
                    response_status(&client.send(Command::IOCTL, ioctl.as_bytes()).await),
                    failure,
                );
            }
            control
                .set_plan(Operation::FileControl, Plan::default())
                .unwrap();
            client.close(file).await;
            assert_eq!(
                response_status(&client.send(Command::IOCTL, ioctl.as_bytes()).await),
                Status::FILE_CLOSED
            );
        }
    });
}

#[test]
fn zero_data_control_preserves_eof_and_allocation_and_enforces_write_access() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("zero-data", 2, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"abcdefgh"))
            .await;
        assert_eq!(
            response_status(&client.set(file, 19, &32i64.to_le_bytes()).await),
            Status::SUCCESS
        );
        let before = client.query(file, 5).await;
        let mut ioctl = IoctlRequest::new_zeroed();
        ioctl.structure_size = IoctlRequest::STRUCTURE_SIZE.into();
        ioctl.file_id = file;
        ioctl.control_code = 0x000980c8u32.into();
        ioctl.flags = IoctlFlags::new().with_fsctl(true);
        ioctl.input_offset = 120.into();
        ioctl.input_count = 16.into();
        let make_body = |ioctl: &IoctlRequest, start: i64, end: i64| {
            let mut body = ioctl.as_bytes().to_vec();
            body.extend_from_slice(&start.to_le_bytes());
            body.extend_from_slice(&end.to_le_bytes());
            body
        };
        let response = client.ok(Command::IOCTL, &make_body(&ioctl, 2, 5)).await;
        assert_eq!(response.len(), 112);
        assert_eq!(&response[96..104], &[0; 8]);
        assert_eq!(&client.read(file, 0, 8).await[80..], b"ab\0\0\0fgh");
        let after = client.query(file, 5).await;
        assert_eq!(&after[72..88], &before[72..88]);
        for (start, end) in [(-1, 2), (0, -1), (6, 3)] {
            assert_eq!(
                response_status(
                    &client
                        .send(Command::IOCTL, &make_body(&ioctl, start, end))
                        .await
                ),
                Status::INVALID_PARAMETER,
            );
        }
        let no_write = client.open_result("zero-data", 4, 7, 1, 0).await;
        let no_write = read_body::<CreateResponse>(&no_write).unwrap().file_id;
        ioctl.file_id = no_write;
        assert_eq!(
            response_status(&client.send(Command::IOCTL, &make_body(&ioctl, 0, 8)).await),
            Status::ACCESS_DENIED,
        );
        client.close(no_write).await;
        ioctl.file_id = file;
        client
            .ok(Command::IOCTL, &make_body(&ioctl, 6, i64::MAX))
            .await;
        assert_eq!(&client.read(file, 0, 16).await[80..], b"ab\0\0\0f\0\0");
        let before = client.query(file, 4).await;
        for (start, end) in [(0, 0), (8, 8), (9, i64::MAX)] {
            client
                .ok(Command::IOCTL, &make_body(&ioctl, start, end))
                .await;
        }
        assert_eq!(&client.query(file, 4).await[72..], &before[72..]);
        ioctl.input_count = 15.into();
        let mut body = make_body(&ioctl, 0, 1);
        body.pop();
        assert_eq!(
            response_status(&client.send(Command::IOCTL, &body).await),
            Status::INVALID_PARAMETER,
        );
        let directory = client.open("zero-directory", 2, 1).await;
        ioctl.file_id = directory;
        ioctl.input_count = 16.into();
        assert_eq!(
            response_status(&client.send(Command::IOCTL, &make_body(&ioctl, 0, 1)).await),
            Status::INVALID_PARAMETER,
        );
        client.close(directory).await;
        client.close(file).await;
    });
}

#[test]
fn zero_data_control_obeys_cross_connection_and_owner_byte_range_locks() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut first = Client::new(&server).await;
        let mut second = Client::new(&server).await;
        let file = first.open("zero-locked", 2, 0).await;
        first
            .ok(Command::WRITE, &Client::write_body(file, 0, b"abcdef"))
            .await;
        let other = second.open("zero-locked", 1, 0).await;
        let mut ioctl = IoctlRequest::new_zeroed();
        ioctl.structure_size = IoctlRequest::STRUCTURE_SIZE.into();
        ioctl.file_id = file;
        ioctl.control_code = FsctlCode::SET_ZERO_DATA.0.into();
        ioctl.flags = IoctlFlags::new().with_fsctl(true);
        ioctl.input_count = 16.into();
        ioctl.input_offset = 120.into();
        let mut bytes = ioctl.as_bytes().to_vec();
        bytes.extend_from_slice(&2i64.to_le_bytes());
        bytes.extend_from_slice(&4i64.to_le_bytes());
        let unlock = LockFlags::new().with_unlock(true);
        for exclusive in [false, true] {
            let flags = LockFlags::new()
                .with_shared_lock(!exclusive)
                .with_exclusive_lock(exclusive)
                .with_fail_immediately(true);
            second
                .ok(Command::LOCK, &locking::body(other, &[(2, 2, flags)]))
                .await;
            assert_eq!(
                response_status(&first.send(Command::IOCTL, &bytes).await),
                Status::FILE_LOCK_CONFLICT,
            );
            second
                .ok(Command::LOCK, &locking::body(other, &[(2, 2, unlock)]))
                .await;
            assert_eq!(&first.read(file, 0, 6).await[80..], b"abcdef");
        }
        let flags = LockFlags::new()
            .with_exclusive_lock(true)
            .with_fail_immediately(true);
        first
            .ok(Command::LOCK, &locking::body(file, &[(2, 2, flags)]))
            .await;
        first.ok(Command::IOCTL, &bytes).await;
        first
            .ok(Command::LOCK, &locking::body(file, &[(2, 2, unlock)]))
            .await;
        assert_eq!(&first.read(file, 0, 6).await[80..], b"ab\0\0ef");
        second.close(other).await;
        first.close(file).await;
    });
}

#[test]
fn allocated_range_control_reports_dense_storage_and_validates_ranges_and_access() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("allocated-ranges", 2, 0).await;
        let mut ioctl = IoctlRequest::new_zeroed();
        ioctl.structure_size = IoctlRequest::STRUCTURE_SIZE.into();
        ioctl.file_id = file;
        ioctl.control_code = 0x000940cfu32.into();
        ioctl.flags = IoctlFlags::new().with_fsctl(true);
        ioctl.input_count = 16.into();
        ioctl.input_offset = 120.into();
        ioctl.max_output_response = 16.into();
        let make_body = |ioctl: &IoctlRequest, offset: i64, length: i64| {
            let mut body = ioctl.as_bytes().to_vec();
            body.extend_from_slice(&offset.to_le_bytes());
            body.extend_from_slice(&length.to_le_bytes());
            body
        };
        let empty = client.ok(Command::IOCTL, &make_body(&ioctl, 0, 8)).await;
        assert_eq!(empty.len(), 112);
        assert_eq!(&empty[96..104], &[0; 8]);
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, &[0; 8]))
            .await;
        for (offset, length) in [(0i64, 8i64), (2, 3), (16, 8)] {
            let response = client
                .ok(Command::IOCTL, &make_body(&ioctl, offset, length))
                .await;
            let mut expected = offset.to_le_bytes().to_vec();
            expected.extend_from_slice(&length.to_le_bytes());
            assert_eq!(&response[112..], expected);
        }
        for maximum in [0u32, 15, 16, 17] {
            ioctl.max_output_response = maximum.into();
            let response = client.send(Command::IOCTL, &make_body(&ioctl, 0, 8)).await;
            assert_eq!(
                response_status(&response),
                if maximum < 16 {
                    Status::BUFFER_TOO_SMALL
                } else {
                    Status::SUCCESS
                }
            );
            let response = client.ok(Command::IOCTL, &make_body(&ioctl, 0, 0)).await;
            assert_eq!(response.len(), 112);
        }
        for (offset, length) in [(-1, 0), (0, -1), (i64::MAX, 1)] {
            assert_eq!(
                response_status(
                    &client
                        .send(Command::IOCTL, &make_body(&ioctl, offset, length))
                        .await
                ),
                Status::INVALID_PARAMETER,
            );
        }
        let no_read = client.open_result("allocated-ranges", 0x20, 7, 1, 0).await;
        let no_read = read_body::<CreateResponse>(&no_read).unwrap().file_id;
        ioctl.file_id = no_read;
        assert_eq!(
            response_status(&client.send(Command::IOCTL, &make_body(&ioctl, 0, 8)).await),
            Status::ACCESS_DENIED,
        );
        client.close(no_read).await;
        let directory = client.open("ranges-directory", 2, 1).await;
        ioctl.file_id = directory;
        assert_eq!(
            response_status(&client.send(Command::IOCTL, &make_body(&ioctl, 0, 8)).await),
            Status::INVALID_PARAMETER,
        );
        client.close(directory).await;
        client.close(file).await;
    });
}

#[test]
fn allocated_range_output_preserves_partial_records_and_provider_bounds() {
    let control = FileControl::QueryAllocatedRanges {
        range: ByteRange {
            offset: 4,
            length: 12,
        },
        maximum_ranges: 1,
    };
    let (status, data) = file_control_output(
        control,
        FileControlResult::AllocatedRanges {
            ranges: vec![ByteRange {
                offset: 6,
                length: 2,
            }],
            overflow: true,
        },
    )
    .unwrap();
    assert_eq!(status, Status::BUFFER_OVERFLOW);
    let mut expected = 6i64.to_le_bytes().to_vec();
    expected.extend_from_slice(&2i64.to_le_bytes());
    assert_eq!(data, expected);
    for ranges in [
        vec![ByteRange {
            offset: 6,
            length: 0,
        }],
        vec![ByteRange {
            offset: 32,
            length: 2,
        }],
        vec![ByteRange {
            offset: u64::MAX,
            length: 2,
        }],
        vec![
            ByteRange {
                offset: 6,
                length: 2
            };
            2
        ],
    ] {
        assert_eq!(
            file_control_output(
                control,
                FileControlResult::AllocatedRanges {
                    ranges,
                    overflow: false
                }
            )
            .err(),
            Some(Status::INTERNAL_ERROR),
        );
    }
}

#[test]
fn stream_queries_report_actual_default_stream_without_attribute_access() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("stream-query", 2, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"data"))
            .await;
        assert_eq!(
            response_status(&client.set(file, 19, &16i64.to_le_bytes()).await),
            Status::SUCCESS
        );
        let response = client.open_result("stream-query", 0x100000, 7, 1, 0).await;
        let limited = read_body::<CreateResponse>(&response).unwrap().file_id;
        let mut query = QueryInfoRequest::new_zeroed();
        query.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
        query.info_type = InformationType::FILE;
        query.info_class = 22;
        query.file_id = limited;
        for maximum in [0u32, 23, 24, 37, 38, 40] {
            query.output_buffer_length = maximum.into();
            let response = client.send(Command::QUERY_INFO, query.as_bytes()).await;
            if maximum < 24 {
                assert_eq!(response_status(&response), Status::INFO_LENGTH_MISMATCH);
            } else if maximum < 38 {
                assert_eq!(response_status(&response), Status::BUFFER_OVERFLOW);
                assert_eq!(response.len(), 72);
            } else {
                assert_eq!(response_status(&response), Status::SUCCESS);
                let mut expected = vec![0, 0, 0, 0, 14, 0, 0, 0];
                expected.extend_from_slice(&4i64.to_le_bytes());
                expected.extend_from_slice(&16i64.to_le_bytes());
                expected.extend_from_slice(&[
                    b':', 0, b':', 0, b'$', 0, b'D', 0, b'A', 0, b'T', 0, b'A', 0,
                ]);
                assert_eq!(&response[72..], expected);
            }
        }
        assert_eq!(
            response_status(&client.query(limited, 4).await),
            Status::ACCESS_DENIED
        );
        let directory = client.open("streams-directory", 2, 1).await;
        query.file_id = directory;
        let response = client.ok(Command::QUERY_INFO, query.as_bytes()).await;
        assert_eq!(response.len(), 72);
        client.close(directory).await;
        client.close(limited).await;
        client.close(file).await;
    });
}

#[test]
fn stream_output_preserves_provider_sizes_unicode_and_record_boundaries() {
    let streams = [
        StreamInformation {
            name: String::new(),
            size: 4,
            allocation_size: 16,
        },
        StreamInformation {
            name: "\u{e9}".to_owned(),
            size: 1,
            allocation_size: 8,
        },
    ];
    let (status, body) = stream_response(&streams, 80).unwrap();
    assert_eq!(status, Status::SUCCESS);
    let mut expected = vec![40, 0, 0, 0, 14, 0, 0, 0];
    expected.extend_from_slice(&4i64.to_le_bytes());
    expected.extend_from_slice(&16i64.to_le_bytes());
    expected.extend_from_slice(&[
        b':', 0, b':', 0, b'$', 0, b'D', 0, b'A', 0, b'T', 0, b'A', 0, 0, 0,
    ]);
    expected.extend_from_slice(&[0, 0, 0, 0, 16, 0, 0, 0]);
    expected.extend_from_slice(&1i64.to_le_bytes());
    expected.extend_from_slice(&8i64.to_le_bytes());
    expected.extend_from_slice(&[
        b':', 0, 0xe9, 0, b':', 0, b'$', 0, b'D', 0, b'A', 0, b'T', 0, b'A', 0,
    ]);
    assert_eq!(&body[8..], expected);
    for maximum in [38u32, 40, 79] {
        let (status, body) = stream_response(&streams, maximum).unwrap();
        assert_eq!(status, Status::BUFFER_OVERFLOW);
        assert_eq!(body.len(), 46);
        assert_eq!(&body[8..12], &[0; 4]);
        assert_eq!(&body[12..], &expected[4..38]);
    }
}

#[test]
fn named_streams_keep_data_allocation_and_locks_separate_and_work_on_directories() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 32)).unwrap();
        let mut client = Client::new(&server).await;
        let base = client.open("streams", 2, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(base, 0, b"base"))
            .await;
        let named = client.open("streams:meta:$DATA", 3, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(named, 0, b"side"))
            .await;
        assert_eq!(&client.read(base, 0, 4).await[80..], b"base");
        assert_eq!(&client.read(named, 0, 4).await[80..], b"side");
        assert_eq!(
            response_status(&client.set(named, 20, &2i64.to_le_bytes()).await),
            Status::SUCCESS
        );
        assert_eq!(
            response_status(&client.set(named, 19, &8i64.to_le_bytes()).await),
            Status::SUCCESS
        );
        let info = client.query(named, 5).await;
        assert_eq!(&info[72..80], &8u64.to_le_bytes());
        assert_eq!(&info[80..88], &2u64.to_le_bytes());
        let alias = client.open("streams:MeTa", 1, 0).await;
        assert_eq!(&client.read(alias, 0, 4).await[80..], b"si");
        assert_eq!(
            &client.query(alias, 6).await[72..],
            &client.query(base, 6).await[72..]
        );
        let default = client.open("streams::$DATA", 1, 0).await;
        assert_eq!(&client.read(default, 0, 4).await[80..], b"base");
        let flags = LockFlags::new()
            .with_exclusive_lock(true)
            .with_fail_immediately(true);
        client
            .ok(Command::LOCK, &locking::body(named, &[(0, 2, flags)]))
            .await;
        client
            .ok(Command::WRITE, &Client::write_body(base, 0, b"B"))
            .await;
        assert_eq!(
            response_status(
                &client
                    .send(Command::WRITE, &Client::write_body(alias, 0, b"X"))
                    .await
            ),
            Status::FILE_LOCK_CONFLICT,
        );
        client
            .ok(
                Command::LOCK,
                &locking::body(named, &[(0, 2, LockFlags::new().with_unlock(true))]),
            )
            .await;
        let mut zero = IoctlRequest::new_zeroed();
        zero.structure_size = IoctlRequest::STRUCTURE_SIZE.into();
        zero.file_id = named;
        zero.control_code = FsctlCode::SET_ZERO_DATA.0.into();
        zero.flags = IoctlFlags::new().with_fsctl(true);
        zero.input_offset = 120.into();
        zero.input_count = 16.into();
        let mut bytes = zero.as_bytes().to_vec();
        bytes.extend_from_slice(&1i64.to_le_bytes());
        bytes.extend_from_slice(&2i64.to_le_bytes());
        client.ok(Command::IOCTL, &bytes).await;
        assert_eq!(&client.read(named, 0, 4).await[80..], b"s\0");
        assert_eq!(&client.read(base, 0, 4).await[80..], b"Base");
        let directory = client.open("folder", 2, 1).await;
        let data = client.open("folder:payload", 3, 0).await;
        client
            .ok(
                Command::WRITE,
                &Client::write_body(data, 0, b"directory-data"),
            )
            .await;
        assert_eq!(&client.read(data, 0, 32).await[80..], b"directory-data");
        assert_eq!(client.query(data, 5).await[93], 0);
        for file in [data, directory, alias, named, default, base] {
            client.close(file).await;
        }
    });
}

#[test]
fn data_stream_names_use_stream_rules_instead_of_filename_rules() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 32)).unwrap();
        let mut client = Client::new(&server).await;
        for name in ["wild*?<>\"|", " space.end. ", "\u{1}control", "é", ".."] {
            let path = format!("stream-grammar:{name}");
            let file = client.open(&path, 3, 0).await;
            client
                .ok(Command::WRITE, &Client::write_body(file, 0, b"data"))
                .await;
            let alias = client.open(&path, 1, 0).await;
            assert_eq!(&client.read(alias, 0, 4).await[80..], b"data");
            let new = format!(":{name}-renamed");
            let new = encode_name(&new);
            let mut rename = FileRenameInformation::new_zeroed();
            rename.file_name_length = (new.len() as u32).into();
            let mut bytes = rename.as_bytes().to_vec();
            bytes.extend(new);
            assert_eq!(
                response_status(&client.set(file, 10, &bytes).await),
                Status::SUCCESS
            );
            let renamed = client.open(&format!("{path}-renamed"), 1, 0).await;
            assert_eq!(&client.read(renamed, 0, 4).await[80..], b"data");
            for file in [alias, renamed, file] {
                client.close(file).await;
            }
        }
        assert_eq!(
            response_status(
                &client
                    .open_result(
                        &format!("stream-grammar:{}", "x".repeat(256)),
                        AccessMask::FILE_ALL_ACCESS.into_bits(),
                        7,
                        3,
                        0
                    )
                    .await
            ),
            Status::NAME_TOO_LONG
        );
        for name in ["stream-grammar:bad:", "stream-grammar:bad:$FOO"] {
            for disposition in [0, 1, 4, 5] {
                assert_eq!(
                    response_status(
                        &client
                            .open_result(
                                name,
                                AccessMask::FILE_ALL_ACCESS.into_bits(),
                                7,
                                disposition,
                                0
                            )
                            .await
                    ),
                    Status::OBJECT_NAME_INVALID
                );
            }
        }
    });
}

#[test]
fn supersede_of_a_new_named_stream_does_not_add_delete_access() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let write = AccessMask::new().with_write_data(true).into_bits();
        let first = client
            .open_result("stream-supersede:first", write, 0, 3, 0)
            .await;
        assert_eq!(response_status(&first), Status::SUCCESS);
        let first = read_body::<CreateResponse>(&first).unwrap().file_id;
        let second = client
            .open_result("stream-supersede:second", write, 0, 0, 0)
            .await;
        assert_eq!(response_status(&second), Status::SUCCESS);
        let second = read_body::<CreateResponse>(&second).unwrap().file_id;
        assert_eq!(&client.query(second, 8).await[72..], &write.to_le_bytes());
        assert_eq!(
            response_status(
                &client
                    .open_result(
                        "stream-supersede:third",
                        write | AccessMask::new().with_delete(true).into_bits(),
                        0,
                        0,
                        0
                    )
                    .await
            ),
            Status::SHARING_VIOLATION
        );
        assert_eq!(
            response_status(
                &client
                    .open_result("stream-supersede:second", write, 0, 0, 0)
                    .await
            ),
            Status::SHARING_VIOLATION
        );
        client.close(second).await;
        client.close(first).await;
    });
}

#[test]
fn named_stream_creation_is_atomic_under_byte_and_object_limits() {
    block_on(async {
        for (bytes, objects) in [(32usize, 32usize), (1024, 2)] {
            let server = Server::new("memory", MemoryFs::new(bytes, objects)).unwrap();
            let mut client = Client::new(&server).await;
            let base = client.open("base", 2, 0).await;
            client
                .ok(Command::WRITE, &Client::write_body(base, 0, b"base"))
                .await;
            let mut extra = Vec::new();
            let mut last = None;
            append_create_context(
                &mut extra,
                &mut last,
                CreateContextName::ALLOCATION_SIZE,
                &40u64.to_le_bytes(),
            );
            for name in ["base:side", "absent:side"] {
                let body = create_body(name, 0x1f01ff, 7, 2, 0, &extra);
                assert_eq!(
                    response_status(&client.send(Command::CREATE, &body).await),
                    Status::DISK_FULL
                );
                assert_eq!(
                    response_status(&client.open_result(name, 1, 7, 1, 0).await),
                    Status::OBJECT_NAME_NOT_FOUND
                );
            }
            assert_eq!(
                response_status(&client.open_result("absent", 1, 7, 1, 0).await),
                Status::OBJECT_NAME_NOT_FOUND
            );
            assert_eq!(&client.read(base, 0, 4).await[80..], b"base");
            client.close(base).await;
        }
    });
}

#[test]
fn named_stream_opens_do_not_require_the_base_files_ea_knowledge() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let mut extra = Vec::new();
        let mut last = None;
        append_create_context(
            &mut extra,
            &mut last,
            CreateContextName::EA_BUFFER,
            &[0, 0, 0, 0, 128, 1, 1, 0, b'A', 0, b'v'],
        );
        let response = client
            .ok(
                Command::CREATE,
                &create_body("knowledge", 0x1f01ff, 7, 2, 0, &extra),
            )
            .await;
        let base = read_body::<CreateResponse>(&response).unwrap().file_id;
        let response = client.open_result("knowledge:side", 1, 7, 3, 0x200).await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        let named = read_body::<CreateResponse>(&response).unwrap().file_id;
        client.close(named).await;
        assert_eq!(
            response_status(&client.open_result("knowledge", 1, 7, 1, 0x200).await),
            Status::ACCESS_DENIED
        );
        client.close(base).await;
    });
}

#[test]
fn readonly_files_reject_named_stream_delete_on_close() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let base = client.open("readonly-stream", 2, 0).await;
        let named = client.open("readonly-stream:side", 3, 0).await;
        client.close(named).await;
        let mut basic = [0; 40];
        basic[32] = 1;
        assert_eq!(
            response_status(&client.set(base, 4, &basic).await),
            Status::SUCCESS
        );
        assert_eq!(
            response_status(
                &client
                    .open_result("readonly-stream:side", 1, 7, 1, 0x1000)
                    .await
            ),
            Status::CANNOT_DELETE
        );
        let response = client.open_result("readonly-stream:side", 1, 7, 1, 0).await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        client
            .close(read_body::<CreateResponse>(&response).unwrap().file_id)
            .await;
        client.close(base).await;
    });
}

#[test]
fn stream_renames_preserve_open_data_and_move_default_stream_bindings() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 32)).unwrap();
        let mut client = Client::new(&server).await;
        let base = client.open("stream-renames", 2, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(base, 0, b"base"))
            .await;
        let named = client.open("stream-renames:old", 3, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(named, 0, b"named"))
            .await;
        let alias = client.open("stream-renames:old", 1, 0).await;
        client
            .ok(
                Command::LOCK,
                &locking::body(
                    named,
                    &[(
                        0,
                        5,
                        LockFlags::new()
                            .with_exclusive_lock(true)
                            .with_fail_immediately(true),
                    )],
                ),
            )
            .await;
        let rename = |name: &str, replace: bool| {
            let name = encode_name(name);
            let mut data = FileRenameInformation::new_zeroed();
            data.replace_if_exists = u8::from(replace);
            data.file_name_length = (name.len() as u32).into();
            let mut bytes = data.as_bytes().to_vec();
            bytes.extend(name);
            bytes
        };
        assert_eq!(
            response_status(&client.set(named, 10, &rename(":new", false)).await),
            Status::SUCCESS
        );
        assert_eq!(
            response_status(&client.read(alias, 0, 8).await),
            Status::FILE_LOCK_CONFLICT
        );
        assert_eq!(&client.read(named, 0, 8).await[80..], b"named");
        assert_eq!(
            response_status(&client.open_result("stream-renames:old", 1, 7, 1, 0).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(
            response_status(
                &client
                    .set(base, 10, &rename(":former-default:$DATA", false))
                    .await
            ),
            Status::SUCCESS
        );
        assert_eq!(&client.read(base, 0, 8).await[80..], b"base");
        let fresh = client.open("stream-renames", 1, 0).await;
        assert_eq!(
            response_status(&client.read(fresh, 0, 8).await),
            Status::END_OF_FILE
        );
        client.close(fresh).await;
        assert_eq!(
            response_status(&client.set(named, 10, &rename("::$DATA", true)).await),
            Status::SUCCESS
        );
        assert_eq!(
            response_status(&client.read(alias, 0, 8).await),
            Status::FILE_LOCK_CONFLICT
        );
        client
            .ok(
                Command::LOCK,
                &locking::body(named, &[(0, 5, LockFlags::new().with_unlock(true))]),
            )
            .await;
        assert_eq!(&client.read(alias, 0, 8).await[80..], b"named");
        let fresh = client.open("stream-renames", 1, 0).await;
        assert_eq!(&client.read(fresh, 0, 8).await[80..], b"named");
        for file in [fresh, alias, named, base] {
            client.close(file).await;
        }
    });
}

#[test]
fn stream_rename_validation_and_replacement_preserve_data_on_failure() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 32)).unwrap();
        let mut client = Client::new(&server).await;
        let source = client.open("rename-validation:source", 3, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(source, 0, b"payload"))
            .await;
        let target = client.open("rename-validation:target", 3, 0).await;
        let rename = |name: &str, replace: bool| {
            let name = encode_name(name);
            let mut data = FileRenameInformation::new_zeroed();
            data.replace_if_exists = u8::from(replace);
            data.file_name_length = (name.len() as u32).into();
            let mut bytes = data.as_bytes().to_vec();
            bytes.extend(name);
            bytes
        };
        for (name, replace, status) in [
            (":target", false, Status::OBJECT_NAME_COLLISION),
            (":target", true, Status::INVALID_PARAMETER),
            (":bad:", false, Status::INVALID_PARAMETER),
            (
                ":bad:$INDEX_ALLOCATION",
                false,
                Status::OBJECT_TYPE_MISMATCH,
            ),
            (":bad:$D?TA", false, Status::OBJECT_TYPE_MISMATCH),
        ] {
            assert_eq!(
                response_status(&client.set(source, 10, &rename(name, replace)).await),
                status
            );
            assert_eq!(&client.read(source, 0, 32).await[80..], b"payload");
        }
        client
            .ok(Command::WRITE, &Client::write_body(target, 0, b"x"))
            .await;
        client.close(target).await;
        assert_eq!(
            response_status(&client.set(source, 10, &rename(":target", true)).await),
            Status::INVALID_PARAMETER
        );
        let target = client.open("rename-validation:target", 1, 0).await;
        assert_eq!(
            response_status(&client.set(target, 20, &0i64.to_le_bytes()).await),
            Status::SUCCESS
        );
        assert_eq!(
            response_status(&client.set(target, 19, &16i64.to_le_bytes()).await),
            Status::SUCCESS
        );
        client.close(target).await;
        assert_eq!(
            response_status(&client.set(source, 10, &rename(":target", true)).await),
            Status::SUCCESS
        );
        assert_eq!(&client.read(source, 0, 32).await[80..], b"payload");
        let renamed = client.open("rename-validation:target", 1, 0).await;
        assert_eq!(&client.read(renamed, 0, 32).await[80..], b"payload");
        let directory = client.open("rename-directory", 2, 1).await;
        for (name, status) in [
            (":new", Status::INVALID_PARAMETER),
            (":new:$DATA", Status::OBJECT_TYPE_MISMATCH),
            (":new:$INDEX_ALLOCATION", Status::INVALID_PARAMETER),
        ] {
            assert_eq!(
                response_status(&client.set(directory, 10, &rename(name, false)).await),
                status
            );
        }
        let data = client.open("rename-directory:data", 3, 0).await;
        assert_eq!(
            response_status(&client.set(data, 10, &rename("::$DATA", true)).await),
            Status::INVALID_PARAMETER
        );
        assert_eq!(
            response_status(&client.set(data, 10, &rename(":new", false)).await),
            Status::SUCCESS
        );
        client.close(data).await;
        client.close(directory).await;
        client.close(renamed).await;
        client.close(source).await;
    });
}

#[test]
fn short_names_are_real_aliases_with_query_and_collision_semantics() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 32)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("long-file-name", 2, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"data"))
            .await;
        let root = client.open("", 1, 1).await;
        let filter = NotifyFilter::new().with_file_name(true);
        let mut watching =
            std::pin::pin!(notify::accept(&mut client, root, filter, false, 4096).execute());
        assert!(futures::poll!(&mut watching).is_pending());
        let short = |name: &str| {
            let name = encode_name(name);
            let mut bytes = (name.len() as u32).to_le_bytes().to_vec();
            bytes.extend(name);
            bytes.resize(bytes.len().max(8), 0);
            bytes
        };
        assert_eq!(
            response_status(&client.set(file, 40, &short("SHORT.TXT")).await),
            Status::SUCCESS
        );
        assert_eq!(
            notify::changes(&watching.await.unwrap()),
            [(NotifyAction::RENAMED_NEW_NAME, "SHORT.TXT".into())]
        );
        assert_eq!(
            &client.query(file, 21).await[76..],
            encode_name("SHORT.TXT")
        );
        let alias = client.open("short.txt", 1, 0).await;
        assert_eq!(&client.read(alias, 0, 4).await[80..], b"data");
        assert_eq!(
            response_status(
                &client
                    .open_result(
                        "SHORT.TXT",
                        AccessMask::FILE_ALL_ACCESS.into_bits(),
                        7,
                        2,
                        0
                    )
                    .await
            ),
            Status::OBJECT_NAME_COLLISION
        );
        let other = client.open("other-file", 2, 0).await;
        assert_eq!(
            response_status(&client.set(other, 40, &short("SHORT.TXT")).await),
            Status::OBJECT_NAME_COLLISION
        );
        assert_eq!(
            response_status(&client.set(file, 40, &short("NEW.TXT")).await),
            Status::SUCCESS
        );
        assert_eq!(
            response_status(&client.open_result("SHORT.TXT", 1, 7, 1, 0).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(&client.read(alias, 0, 4).await[80..], b"data");
        assert_eq!(
            response_status(&client.set(file, 40, &short("")).await),
            Status::SUCCESS
        );
        assert_eq!(
            response_status(&client.query(file, 21).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(
            response_status(&client.open_result("NEW.TXT", 1, 7, 1, 0).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(
            notify::changes(
                &client
                    .send(
                        Command::CHANGE_NOTIFY,
                        &notify::body(root, filter, false, 4096)
                    )
                    .await
            ),
            [
                (NotifyAction::ADDED, "other-file".into()),
                (NotifyAction::RENAMED_OLD_NAME, "SHORT.TXT".into()),
                (NotifyAction::RENAMED_NEW_NAME, "NEW.TXT".into()),
                (NotifyAction::REMOVED, "NEW.TXT".into()),
            ]
        );
        for file in [alias, other, file, root] {
            client.close(file).await;
        }
    });
}

#[test]
fn short_name_validation_preserves_existing_names() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 32)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("short-validation", 2, 0).await;
        for name in [
            "123456789",
            "A.LONG",
            "A.",
            ".TXT",
            "A B",
            "A.B.C",
            "é",
            "A?B",
        ] {
            let name = encode_name(name);
            let mut data = (name.len() as u32).to_le_bytes().to_vec();
            data.extend(name);
            data.resize(data.len().max(8), 0);
            assert_eq!(
                response_status(&client.set(file, 40, &data).await),
                Status::INVALID_PARAMETER
            );
        }
        for (data, status) in [
            (vec![0; 7], Status::INFO_LENGTH_MISMATCH),
            (vec![1, 0, 0, 0, 0, 0, 0, 0], Status::INVALID_PARAMETER),
            (vec![8, 0, 0, 0, 0, 0, 0, 0], Status::INVALID_PARAMETER),
        ] {
            assert_eq!(response_status(&client.set(file, 40, &data).await), status);
        }
        assert_eq!(
            response_status(&client.query(file, 21).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        let mut data = 10u32.to_le_bytes().to_vec();
        data.extend(encode_name("SHORT"));
        let root = client.open("", 1, 1).await;
        assert_eq!(
            response_status(&client.set(root, 40, &data).await),
            Status::INVALID_PARAMETER
        );
        let named = client.open("short-validation:side", 3, 0).await;
        assert_eq!(
            response_status(&client.set(named, 40, &data).await),
            Status::INVALID_PARAMETER
        );
        for access in [
            AccessMask::FILE_GENERIC_READ.into_bits(),
            AccessMask::new().with_delete(true).into_bits(),
        ] {
            let response = client
                .open_result("short-validation", access, 7, 1, 0)
                .await;
            assert_eq!(response_status(&response), Status::SUCCESS);
            let restricted = read_body::<CreateResponse>(&response).unwrap().file_id;
            assert_eq!(
                response_status(&client.set(restricted, 40, &data).await),
                Status::ACCESS_DENIED
            );
            client.close(restricted).await;
        }
        let directory = client.open("long-directory", 2, 1).await;
        let child = client.open("long-directory\\child", 2, 0).await;
        assert_eq!(
            response_status(&client.set(directory, 40, &data).await),
            Status::ACCESS_DENIED
        );
        client.close(child).await;
        assert_eq!(
            response_status(&client.set(directory, 40, &data).await),
            Status::SUCCESS
        );
        let alias = client.open("SHORT\\child", 1, 0).await;
        client.close(alias).await;
        let mut short = 16u32.to_le_bytes().to_vec();
        short.extend(encode_name("FILE.TXT"));
        assert_eq!(
            response_status(&client.set(file, 40, &short).await),
            Status::SUCCESS
        );
        let destination = client.open("destination", 2, 1).await;
        let target = client.open("destination\\FILE.TXT", 2, 0).await;
        let target_id = client.query(target, 6).await[72..].to_vec();
        let name = encode_name("destination\\moved");
        let mut rename = FileRenameInformation::new_zeroed();
        rename.file_name_length = (name.len() as u32).into();
        let mut bytes = rename.as_bytes().to_vec();
        bytes.extend(name);
        assert_eq!(
            response_status(&client.set(file, 10, &bytes).await),
            Status::SUCCESS
        );
        assert_eq!(
            response_status(&client.query(file, 21).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        let alias = client.open("destination\\FILE.TXT", 1, 0).await;
        assert_eq!(&client.query(alias, 6).await[72..], target_id);
        client.close(alias).await;
        client.close(target).await;
        client.close(destination).await;
        for file in [directory, named, root] {
            client.close(file).await;
        }
        client.close(file).await;
    });
}

#[test]
fn short_name_framing_and_delete_access_precede_provider_policy() {
    use crate::test_support::{ControlledFs, Operation, Plan};
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("provider-policy", 2, 0).await;
        let response = client
            .open_result(
                "provider-policy",
                AccessMask::FILE_GENERIC_READ.into_bits(),
                7,
                1,
                0,
            )
            .await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        let restricted = read_body::<CreateResponse>(&response).unwrap().file_id;
        let mut bytes = 10u32.to_le_bytes().to_vec();
        bytes.extend(encode_name("SHORT"));
        assert_eq!(
            response_status(&client.set(restricted, 40, &bytes).await),
            Status::ACCESS_DENIED
        );
        assert_eq!(
            response_status(&client.set(file, 40, &bytes[..7]).await),
            Status::INFO_LENGTH_MISMATCH
        );
        assert!(
            !control
                .calls()
                .iter()
                .any(|call| call.operation == Operation::SetShortName)
        );
        for status in [Status::NOT_SUPPORTED, Status::PRIVILEGE_NOT_HELD] {
            control
                .set_plan(
                    Operation::SetShortName,
                    Plan {
                        failure: Some(status),
                        ..Plan::default()
                    },
                )
                .unwrap();
            assert_eq!(response_status(&client.set(file, 40, &bytes).await), status);
        }
        assert_eq!(
            response_status(&client.query(file, 21).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        client.close(restricted).await;
        client.close(file).await;
    });
}

#[test]
fn volume_object_ids_are_shared_mutable_metadata_with_fixed_wire_bounds() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let file = client.open("volume-identity", 2, 0).await;
        let mut query = QueryInfoRequest::new_zeroed();
        query.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
        query.info_type = InformationType::FILESYSTEM;
        query.info_class = 8;
        query.file_id = root;
        for maximum in [0, 63, 64] {
            query.output_buffer_length = maximum.into();
            let response = client.send(Command::QUERY_INFO, query.as_bytes()).await;
            assert_eq!(
                response_status(&response),
                if maximum < 64 {
                    Status::INFO_LENGTH_MISMATCH
                } else {
                    Status::SUCCESS
                }
            );
            if maximum == 64 {
                assert_ne!(&response[72..88], &[0; 16]);
                assert_eq!(&response[88..], &[0; 48]);
            }
        }
        let mut set = SetInfoRequest::new_zeroed();
        set.structure_size = SetInfoRequest::STRUCTURE_SIZE.into();
        set.info_type = InformationType::FILESYSTEM;
        set.info_class = 8;
        set.file_id = file;
        set.buffer_offset = (body_end::<SetInfoRequest>() as u16).into();
        let expected: Vec<u8> = (1..=64).collect();
        for length in [0, 63, 64] {
            set.buffer_length = (length as u32).into();
            let mut bytes = set.as_bytes().to_vec();
            bytes.extend_from_slice(&expected[..length]);
            assert_eq!(
                response_status(&client.send(Command::SET_INFO, &bytes).await),
                if length < 64 {
                    Status::INVALID_INFO_CLASS
                } else {
                    Status::SUCCESS
                }
            );
        }
        for id in [root, file] {
            query.file_id = id;
            let response = client.ok(Command::QUERY_INFO, query.as_bytes()).await;
            assert_eq!(&response[72..], expected);
        }
        let mut bytes = set.as_bytes().to_vec();
        bytes.extend_from_slice(&[0; 64]);
        client.ok(Command::SET_INFO, &bytes).await;
        assert_eq!(
            response_status(&client.send(Command::QUERY_INFO, query.as_bytes()).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
        client.close(file).await;
        client.close(root).await;
    });
}

#[test]
fn volume_object_id_set_access_and_provider_errors_preserve_metadata() {
    use crate::test_support::{ControlledFs, Operation, Plan};
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("volume-policy", 2, 0).await;
        let response = client
            .open_result(
                "volume-policy",
                AccessMask::new().with_synchronize(true).into_bits(),
                7,
                1,
                0,
            )
            .await;
        assert_eq!(response_status(&response), Status::SUCCESS);
        let restricted = read_body::<CreateResponse>(&response).unwrap().file_id;
        let mut query = QueryInfoRequest::new_zeroed();
        query.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
        query.info_type = InformationType::FILESYSTEM;
        query.info_class = 8;
        query.file_id = restricted;
        query.output_buffer_length = 64.into();
        let before = client.ok(Command::QUERY_INFO, query.as_bytes()).await[72..].to_vec();
        let mut set = SetInfoRequest::new_zeroed();
        set.structure_size = SetInfoRequest::STRUCTURE_SIZE.into();
        set.info_type = InformationType::FILESYSTEM;
        set.info_class = 8;
        set.file_id = restricted;
        set.buffer_offset = (body_end::<SetInfoRequest>() as u16).into();
        set.buffer_length = 64.into();
        let mut bytes = set.as_bytes().to_vec();
        bytes.extend_from_slice(&[7; 64]);
        assert_eq!(
            response_status(&client.send(Command::SET_INFO, &bytes).await),
            Status::ACCESS_DENIED
        );
        assert!(
            !control
                .calls()
                .iter()
                .any(|call| call.operation == Operation::SetVolumeObjectId)
        );
        set.file_id = file;
        for status in [Status::INVALID_PARAMETER, Status::PRIVILEGE_NOT_HELD] {
            control
                .set_plan(
                    Operation::SetVolumeObjectId,
                    Plan {
                        failure: Some(status),
                        ..Plan::default()
                    },
                )
                .unwrap();
            let mut bytes = set.as_bytes().to_vec();
            bytes.extend_from_slice(&[7; 64]);
            assert_eq!(
                response_status(&client.send(Command::SET_INFO, &bytes).await),
                status
            );
        }
        assert_eq!(
            &client.ok(Command::QUERY_INFO, query.as_bytes()).await[72..],
            before
        );
        client.close(restricted).await;
        client.close(file).await;
    });
}

#[test]
fn ioctl_profile_validates_identity_bounds_flags_and_credits() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("ioctl", 2, 0).await;
        let mut ioctl = IoctlRequest::new_zeroed();
        ioctl.structure_size = IoctlRequest::STRUCTURE_SIZE.into();
        ioctl.file_id = file;
        ioctl.control_code = 0xdeadbeefu32.into();
        ioctl.flags = IoctlFlags::new().with_fsctl(true);
        assert_eq!(
            response_status(&client.send(Command::IOCTL, ioctl.as_bytes()).await),
            Status::NOT_SUPPORTED
        );
        ioctl.input_count = 1.into();
        ioctl.input_offset = (body_end::<IoctlRequest>() as u32).into();
        assert_eq!(
            response_status(&client.send(Command::IOCTL, ioctl.as_bytes()).await),
            Status::INVALID_PARAMETER
        );
        let mut body = ioctl.as_bytes().to_vec();
        body.push(0);
        assert_eq!(
            response_status(&client.send(Command::IOCTL, &body).await),
            Status::NOT_SUPPORTED
        );
        ioctl.input_offset = (body_end::<IoctlRequest>() as u32 + 1).into();
        body = ioctl.as_bytes().to_vec();
        body.extend_from_slice(&[0; 2]);
        assert_eq!(
            response_status(&client.send(Command::IOCTL, &body).await),
            Status::INVALID_PARAMETER
        );
        ioctl.input_count = 0.into();
        ioctl.input_offset = 0.into();
        ioctl.output_offset = u32::MAX.into();
        ioctl.output_count = 1.into();
        assert_eq!(
            response_status(&client.send(Command::IOCTL, ioctl.as_bytes()).await),
            Status::NOT_SUPPORTED
        );
        ioctl.output_count = 0.into();
        ioctl.max_output_response = (MAX_TRANSFER_SIZE as u32 + 1).into();
        assert_eq!(
            response_status(&client.send(Command::IOCTL, ioctl.as_bytes()).await),
            Status::INVALID_PARAMETER
        );
        ioctl.max_output_response = (CREDIT_PAYLOAD_SIZE + 1).into();
        assert_eq!(
            response_status(&client.send(Command::IOCTL, ioctl.as_bytes()).await),
            Status::NOT_SUPPORTED
        );
        let mut packet = request(
            Command::IOCTL,
            ioctl.as_bytes(),
            client.session,
            client.tree,
            client.message,
        );
        Header::mut_from_prefix(&mut packet)
            .unwrap()
            .0
            .credit_charge = 1.into();
        client.message += 2;
        assert_eq!(
            response_status(&client.connection.process(&packet).await.unwrap()),
            Status::INVALID_PARAMETER
        );
        ioctl.max_output_response = 0.into();
        ioctl.file_id = FileId::RELATED;
        assert_eq!(
            response_status(&client.send(Command::IOCTL, ioctl.as_bytes()).await),
            Status::FILE_CLOSED
        );
        ioctl.flags = IoctlFlags::new();
        assert_eq!(
            response_status(&client.send(Command::IOCTL, ioctl.as_bytes()).await),
            Status::NOT_SUPPORTED
        );
        ioctl.flags = IoctlFlags::new().with_fsctl(true);
        ioctl.control_code = FsctlCode::VALIDATE_NEGOTIATE_INFO.0.into();
        assert_eq!(
            response_status(&client.send(Command::IOCTL, ioctl.as_bytes()).await),
            Status::NOT_SUPPORTED
        );
        ioctl.file_id = file;
        assert_eq!(
            response_status(&client.send(Command::IOCTL, ioctl.as_bytes()).await),
            Status::INVALID_PARAMETER
        );
        ioctl.control_code = FsctlCode::QUERY_SHARED_VIRTUAL_DISK_SUPPORT.0.into();
        assert_eq!(
            response_status(&client.send(Command::IOCTL, ioctl.as_bytes()).await),
            Status::INVALID_DEVICE_REQUEST
        );
        client.close(file).await;
    });
}

#[test]
fn uncached_opens_decline_leases_and_reject_unsolicited_break_acknowledgements() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut connection = server.connect();
        let response = connection
            .process(&request(Command::NEGOTIATE, &negotiate_body(), 0, 0, 0))
            .await
            .unwrap();
        let capabilities = read_body::<NegotiateResponse>(&response)
            .unwrap()
            .capabilities;
        assert!(!capabilities.leasing());
        assert!(!capabilities.directory_leasing());
        let mut client = Client::new(&server).await;
        let mut extra = Vec::new();
        let mut last = None;
        append_create_context(
            &mut extra,
            &mut last,
            CreateContextName::REQUEST_LEASE,
            &[1],
        );
        for level in [
            OplockLevel::NONE,
            OplockLevel::LEVEL_II,
            OplockLevel::EXCLUSIVE,
            OplockLevel::BATCH,
            OplockLevel::LEASE,
        ] {
            let mut body = create_body("uncached", 1, 7, 3, 0, &extra);
            CreateRequest::mut_from_bytes(&mut body[..size_of::<CreateRequest>()])
                .unwrap()
                .requested_oplock_level = level;
            let response = client.ok(Command::CREATE, &body).await;
            let response = read_body::<CreateResponse>(&response).unwrap();
            assert_eq!(response.oplock_level, OplockLevel::NONE);
            assert_eq!(response.contexts_length.get(), 0);
            let file = response.file_id;
            let mut ack = OplockBreakAcknowledgement::new_zeroed();
            ack.structure_size = OplockBreakAcknowledgement::STRUCTURE_SIZE.into();
            ack.file_id = file;
            assert_eq!(
                response_status(&client.send(Command::OPLOCK_BREAK, ack.as_bytes()).await),
                Status::INVALID_DEVICE_STATE
            );
            client.close(file).await;
            assert_eq!(
                response_status(&client.send(Command::OPLOCK_BREAK, ack.as_bytes()).await),
                Status::FILE_CLOSED
            );
        }
        let mut lease = LeaseBreakAcknowledgement::new_zeroed();
        lease.structure_size = LeaseBreakAcknowledgement::STRUCTURE_SIZE.into();
        assert_eq!(
            response_status(&client.send(Command::OPLOCK_BREAK, lease.as_bytes()).await),
            Status::OBJECT_NAME_NOT_FOUND
        );
    });
}

#[test]
fn attribute_tag_queries_report_real_metadata_and_require_read_attributes() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let mut body = create_body("tag", AccessMask::FILE_ALL_ACCESS.into_bits(), 7, 2, 0, &[]);
        let create =
            CreateRequest::mut_from_bytes(&mut body[..size_of::<CreateRequest>()]).unwrap();
        create.file_attributes.set_reparse_point(true);
        let response = client.ok(Command::CREATE, &body).await;
        let file = read_body::<CreateResponse>(&response).unwrap().file_id;
        let response = client.query(file, 35).await;
        assert_eq!(&response[72..], &[0x20, 0, 0, 0, 0, 0, 0, 0]);
        let mut query = QueryInfoRequest::new_zeroed();
        query.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
        query.info_type = InformationType::FILE;
        query.info_class = 35;
        query.file_id = file;
        query.output_buffer_length = 7.into();
        assert_eq!(
            response_status(&client.send(Command::QUERY_INFO, query.as_bytes()).await),
            Status::INFO_LENGTH_MISMATCH
        );
        let response = client.open_result("tag", 1, 7, 1, 0).await;
        let limited = read_body::<CreateResponse>(&response).unwrap().file_id;
        assert_eq!(
            response_status(&client.query(limited, 35).await),
            Status::ACCESS_DENIED
        );
        client.close(limited).await;
        client.close(file).await;
    });
}

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
        stream_name: None,
        id: 0x0807_0605_0403_0201,
        id128: Some([0xA5; 16]),
        name: "a\u{100}".into(),
        path: "\\a\u{100}".into(),
        short_name: Some("S1".into()),
        attributes: FileAttributes::new().with_archive(true).into_bits(),
        reparse_tag: 0,
        created: 1,
        accessed: 2,
        written: 3,
        changed: 4,
        size: 5,
        allocation_size: 8,
        compression: None,
        number_of_links: 2,
        extended_attributes_length: 8,
        alignment_requirement: 511,
        delete_pending: false,
        maximal_access: AccessMask::FILE_ALL_ACCESS.into_bits(),
        granted_access: AccessMask::FILE_ALL_ACCESS.into_bits(),
    };
    // Literal fixed lengths and offsets are independent of the encoder's types:
    // MS-FSCC §§2.4.8, 10, 15, 18-24, 33.
    for (class, fixed, short_name, id_offset, id128_offset) in [
        (FileInformationClass::DIRECTORY, 64, None, None, None),
        (FileInformationClass::FULL_DIRECTORY, 68, None, None, None),
        (
            FileInformationClass::BOTH_DIRECTORY,
            94,
            Some(68),
            None,
            None,
        ),
        (FileInformationClass::NAMES, 12, None, None, None),
        (
            FileInformationClass::ID_BOTH_DIRECTORY,
            104,
            Some(68),
            Some(96),
            None,
        ),
        (
            FileInformationClass::ID_FULL_DIRECTORY,
            80,
            None,
            Some(72),
            None,
        ),
        (
            FileInformationClass::ID_EXTD_DIRECTORY,
            88,
            None,
            None,
            Some(72),
        ),
        (
            FileInformationClass::ID64_EXTD_DIRECTORY,
            80,
            None,
            Some(72),
            None,
        ),
        (
            FileInformationClass::ID64_EXTD_BOTH_DIRECTORY,
            106,
            Some(80),
            Some(72),
            None,
        ),
        (
            FileInformationClass::ID_ALL_EXTD_DIRECTORY,
            96,
            None,
            Some(72),
            Some(80),
        ),
        (
            FileInformationClass::ID_ALL_EXTD_BOTH_DIRECTORY,
            122,
            Some(96),
            Some(72),
            Some(80),
        ),
    ] {
        let extended = class.0 >= 60;
        let mut entry = info.clone();
        if extended {
            entry.attributes = 0x420;
            entry.reparse_tag = 0x8000001b;
        }
        let mut expected = vec![0; fixed];
        if class == FileInformationClass::NAMES {
            expected[8..12].copy_from_slice(&4u32.to_le_bytes());
        } else {
            for (offset, time) in [(8, 1u64), (16, 2), (24, 3), (32, 4)] {
                expected[offset..offset + 8].copy_from_slice(&time.to_le_bytes());
            }
            expected[40..48].copy_from_slice(&5u64.to_le_bytes());
            expected[48..56].copy_from_slice(&8u64.to_le_bytes());
            expected[56..60].copy_from_slice(&entry.attributes.to_le_bytes());
            expected[60..64].copy_from_slice(&4u32.to_le_bytes());
            if class != FileInformationClass::DIRECTORY {
                expected[64..68].copy_from_slice(&8u32.to_le_bytes());
            }
            if extended {
                expected[68..72].copy_from_slice(&0x8000001bu32.to_le_bytes());
            }
            if let Some(offset) = short_name {
                expected[offset] = 4;
                expected[offset + 2..offset + 6].copy_from_slice(&[b'S', 0, b'1', 0]);
            }
            if let Some(offset) = id_offset {
                expected[offset..offset + 8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
            }
            if let Some(offset) = id128_offset {
                expected[offset..offset + 16].fill(0xa5);
            }
        }
        expected.extend_from_slice(&[b'a', 0, 0, 1]);
        assert_eq!(
            directory_record(class, &entry).unwrap(),
            expected,
            "{class:?}"
        );

        let mut no_alias = entry;
        no_alias.short_name = None;
        if let Some(offset) = short_name {
            expected[offset..offset + 26].fill(0);
            assert_eq!(
                directory_record(class, &no_alias).unwrap(),
                expected,
                "{class:?}"
            );
        }
    }
    let mut missing_id128 = info.clone();
    missing_id128.id128 = None;
    assert!(matches!(
        directory_record(FileInformationClass::ID_EXTD_DIRECTORY, &missing_id128),
        Err(Status::NOT_SUPPORTED)
    ));
    assert!(directory_record(FileInformationClass::ID64_EXTD_DIRECTORY, &missing_id128).is_ok());
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
                    6, 0, 132, 0, 255, 0, 0, 0, 12, 0, 0, 0, b'M', 0, b'E', 0, b'M', 0, b'O', 0,
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
