// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

fn query(file: FileId, class: u8, capacity: u32) -> Vec<u8> {
    let mut request = QueryInfoRequest::new_zeroed();
    request.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
    request.info_type = InformationType::FILESYSTEM;
    request.info_class = class;
    request.output_buffer_length = capacity.into();
    request.file_id = file;
    request.as_bytes().to_vec()
}

#[test]
fn volume_control_dispatch_preserves_the_provider_quota_decline() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(128, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("", 1, 1).await;
        assert_eq!(
            response_status(&client.send(Command::QUERY_INFO, &query(file, 6, 48)).await),
            Status(0xc000029c)
        );
        for capacity in 12..16 {
            assert_eq!(
                response_status(
                    &client
                        .send(Command::QUERY_INFO, &query(file, 5, capacity))
                        .await
                ),
                Status::INFO_LENGTH_MISMATCH
            );
        }
        client.close(file).await;
    });
}

fn set(file: FileId, kind: InformationType, class: u8, data: &[u8]) -> Vec<u8> {
    let mut request = SetInfoRequest::new_zeroed();
    request.structure_size = SetInfoRequest::STRUCTURE_SIZE.into();
    request.info_type = kind;
    request.info_class = class;
    request.buffer_length = (data.len() as u32).into();
    request.buffer_offset = (body_end::<SetInfoRequest>() as u16).into();
    request.file_id = file;
    let mut bytes = request.as_bytes().to_vec();
    bytes.extend_from_slice(data);
    bytes
}

fn quota_query(file: FileId, capacity: u32, restart: bool, sids: Option<&[u8]>) -> Vec<u8> {
    let mut input = vec![0; 16];
    input[1] = u8::from(restart);
    if let Some(sid) = sids {
        input[4..8].copy_from_slice(&((8 + sid.len()) as u32).to_le_bytes());
        input[8..16].fill(0xff);
        input.extend_from_slice(&[0; 4]);
        input.extend_from_slice(&(sid.len() as u32).to_le_bytes());
        input.extend_from_slice(sid);
    }
    let mut request = QueryInfoRequest::new_zeroed();
    request.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
    request.info_type = InformationType::QUOTA;
    request.output_buffer_length = capacity.into();
    request.input_buffer_offset = (body_end::<QueryInfoRequest>() as u16).into();
    request.input_buffer_length = (input.len() as u32).into();
    request.file_id = file;
    let mut bytes = request.as_bytes().to_vec();
    bytes.extend_from_slice(&input);
    bytes
}

fn policy(sid: &[u8], threshold: i64, limit: i64) -> Vec<u8> {
    let mut bytes = vec![0; 4];
    bytes.extend_from_slice(&(sid.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(-1i64).to_le_bytes());
    bytes.extend_from_slice(&(-1i64).to_le_bytes());
    bytes.extend_from_slice(&threshold.to_le_bytes());
    bytes.extend_from_slice(&limit.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

#[test]
fn volume_defaults_enforce_real_allocation_and_report_distinct_free_space() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(128, 16).with_quotas().unwrap()).unwrap();
        let mut client = Client::new(&server).await;
        let volume = client.open("", 1, 1).await;
        let response = client.ok(Command::QUERY_INFO, &query(volume, 6, 48)).await;
        let mut defaults = response[72..].to_vec();
        assert_eq!(defaults.len(), 48);
        defaults[..24].fill(0xff);
        defaults[24..32].copy_from_slice(&4u64.to_le_bytes());
        defaults[32..40].copy_from_slice(&8u64.to_le_bytes());
        defaults[40..44].copy_from_slice(&0x8000030bu32.to_le_bytes());
        defaults[44..].fill(0xff);
        client
            .ok(
                Command::SET_INFO,
                &set(volume, InformationType::FILESYSTEM, 6, &defaults),
            )
            .await;
        let response = client.ok(Command::QUERY_INFO, &query(volume, 6, 48)).await;
        assert_eq!(&response[72..96], &[0; 24]);
        assert_eq!(&response[112..116], &10u32.to_le_bytes());
        let file = client.open("file", 2, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"12345678"))
            .await;
        assert_eq!(
            response_status(
                &client
                    .send(Command::WRITE, &Client::write_body(file, 8, b"x"))
                    .await
            ),
            Status::DISK_FULL
        );
        assert_eq!(&client.read(file, 0, 8).await[80..], b"12345678");
        let response = client.ok(Command::QUERY_INFO, &query(volume, 7, 32)).await;
        assert_eq!(&response[72..80], &8i64.to_le_bytes());
        assert_eq!(&response[80..88], &0i64.to_le_bytes());
        assert_eq!(&response[88..96], &120i64.to_le_bytes());
        defaults[32..40].copy_from_slice(&4u64.to_le_bytes());
        client
            .ok(
                Command::SET_INFO,
                &set(volume, InformationType::FILESYSTEM, 6, &defaults),
            )
            .await;
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"abcdefgh"))
            .await;
        assert_eq!(&client.read(file, 0, 8).await[80..], b"abcdefgh");
        client.close(file).await;
        client.close(volume).await;
    });
}

#[test]
fn sid_quotas_track_usage_page_without_loss_and_apply_policies_atomically() {
    use crate::security::Sid;
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(128, 16).with_quotas().unwrap()).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("quota", 2, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"data"))
            .await;
        let system = Sid::new([0, 0, 0, 0, 0, 5], &[18]).unwrap();
        let unknown = Sid::new([0, 0, 0, 0, 0, 5], &[19]).unwrap();
        assert_eq!(
            response_status(
                &client
                    .send(Command::QUERY_INFO, &quota_query(file, 51, true, None))
                    .await
            ),
            Status::BUFFER_TOO_SMALL
        );
        let response = client
            .ok(Command::QUERY_INFO, &quota_query(file, 52, false, None))
            .await;
        assert_eq!(&response[88..96], &4i64.to_le_bytes());
        assert_eq!(&response[112..], system.as_bytes());
        let response = client
            .send(Command::QUERY_INFO, &quota_query(file, 52, false, None))
            .await;
        assert_eq!(response_status(&response), Status(0x8000001a));
        assert_eq!(&response[64..], &[9, 0, 0, 0, 0, 0, 0, 0]);
        let response = client
            .ok(
                Command::QUERY_INFO,
                &quota_query(file, 52, true, Some(unknown.as_bytes())),
            )
            .await;
        assert_eq!(&response[80..112], &[0; 32]);
        assert_eq!(&response[112..], unknown.as_bytes());
        client
            .ok(
                Command::SET_INFO,
                &set(
                    file,
                    InformationType::QUOTA,
                    0,
                    &policy(system.as_bytes(), 2, 4),
                ),
            )
            .await;
        assert_eq!(
            response_status(
                &client
                    .send(Command::WRITE, &Client::write_body(file, 4, b"x"))
                    .await
            ),
            Status::DISK_FULL
        );
        let mut batch = policy(system.as_bytes(), -1, -1);
        batch.resize(56, 0);
        batch[..4].copy_from_slice(&56u32.to_le_bytes());
        batch.extend_from_slice(&policy(unknown.as_bytes(), -2, 1));
        assert_eq!(
            response_status(
                &client
                    .send(
                        Command::SET_INFO,
                        &set(file, InformationType::QUOTA, 0, &batch)
                    )
                    .await
            ),
            Status::INVALID_PARAMETER
        );
        assert_eq!(
            response_status(
                &client
                    .send(Command::WRITE, &Client::write_body(file, 4, b"x"))
                    .await
            ),
            Status::DISK_FULL
        );
        client
            .ok(
                Command::SET_INFO,
                &set(
                    file,
                    InformationType::QUOTA,
                    0,
                    &policy(system.as_bytes(), -1, -2),
                ),
            )
            .await;
        client
            .ok(Command::WRITE, &Client::write_body(file, 4, b"x"))
            .await;
        let response = client
            .ok(
                Command::QUERY_INFO,
                &quota_query(file, 52, true, Some(system.as_bytes())),
            )
            .await;
        assert_eq!(&response[88..96], &5i64.to_le_bytes());
        assert_eq!(&response[96..112], &[0xff; 16]);
        client.close(file).await;
    });
}

#[test]
fn malformed_or_read_only_quota_updates_have_no_provider_effects() {
    use crate::security::Sid;
    use crate::test_support::ControlledFs;
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(128, 16).with_quotas().unwrap());
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("quota", 2, 0).await;
        let response = client
            .open_result("quota", AccessMask::FILE_GENERIC_READ.into_bits(), 7, 1, 0)
            .await;
        let limited = read_body::<CreateResponse>(&response).unwrap().file_id;
        let sid = Sid::new([0, 0, 0, 0, 0, 5], &[18]).unwrap();
        let bytes = policy(sid.as_bytes(), 0, 0);
        let before = control.calls().len();
        assert_eq!(
            response_status(
                &client
                    .send(
                        Command::SET_INFO,
                        &set(limited, InformationType::QUOTA, 0, &bytes)
                    )
                    .await
            ),
            Status::ACCESS_DENIED
        );
        assert_eq!(
            response_status(
                &client
                    .send(
                        Command::SET_INFO,
                        &set(limited, InformationType::FILESYSTEM, 6, &[0; 48])
                    )
                    .await
            ),
            Status::ACCESS_DENIED
        );
        assert_eq!(control.calls().len(), before);
        for (offset, value) in [(0, 8u32), (0, 53), (4, u32::MAX)] {
            let mut bytes = bytes.clone();
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(
                response_status(
                    &client
                        .send(
                            Command::SET_INFO,
                            &set(file, InformationType::QUOTA, 0, &bytes)
                        )
                        .await
                ),
                Status::INVALID_PARAMETER
            );
            assert_eq!(control.calls().len(), before);
        }
        client.close(limited).await;
        client.close(file).await;
    });
}

#[test]
fn sparse_logical_growth_is_free_but_data_and_dense_conversion_obey_quotas() {
    use crate::provider::{FileControl, OpenOptions, QuotaInformation, RequestContext};
    use crate::security::Sid;
    block_on(async {
        let fs = MemoryFs::new(1024, 16).with_quotas().unwrap();
        let context = RequestContext::new(1);
        let (file, _) = fs
            .open(
                "sparse",
                OpenOptions {
                    access: AccessMask::FILE_ALL_ACCESS.into_bits(),
                    share_access: 7,
                    disposition: 2,
                    options: 0,
                    attributes: 0,
                    allocation_size: 0,
                    security: None,
                    extended_attributes: None,
                },
                &context,
            )
            .await
            .unwrap();
        fs.set_quotas(
            &file,
            &[QuotaInformation {
                sid: Sid::new([0, 0, 0, 0, 0, 5], &[18]).unwrap(),
                changed: 0,
                used: 0,
                threshold: -1,
                limit: 1,
            }],
            &context,
        )
        .await
        .unwrap();
        fs.file_control(&file, FileControl::SetSparse { sparse: true }, &context)
            .await
            .unwrap();
        fs.set_len(&file, 10000, &context).await.unwrap();
        assert_eq!(fs.query_quotas(&file, &context).await.unwrap()[0].used, 0);
        fs.write(&file, 9999, b"x", &context).await.unwrap();
        assert_eq!(
            fs.write(&file, 0, b"y", &context).await,
            Err(Status::DISK_FULL)
        );
        assert_eq!(
            fs.file_control(&file, FileControl::SetSparse { sparse: false }, &context)
                .await
                .err(),
            Some(Status::DISK_FULL)
        );
        let info = fs.metadata(&file, &context).await.unwrap();
        assert_eq!((info.size, info.allocation_size), (10000, 1));
        assert!(info.attributes().sparse_file());
        assert_eq!(fs.read(&file, 9999, 1, &context).await.unwrap(), b"x");
        assert_eq!(fs.query_quotas(&file, &context).await.unwrap()[0].used, 1);
        fs.close(&file, &context).await.unwrap();
    });
}

#[test]
fn quota_multi_entry_links_single_results_and_start_sid_use_the_same_order() {
    use crate::security::Sid;
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(128, 16).with_quotas().unwrap()).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("quota", 2, 0).await;
        let system = Sid::new([0, 0, 0, 0, 0, 5], &[18]).unwrap();
        let other = Sid::new([0, 0, 0, 0, 0, 5], &[19]).unwrap();
        client
            .ok(
                Command::SET_INFO,
                &set(
                    file,
                    InformationType::QUOTA,
                    0,
                    &policy(other.as_bytes(), 5, 16),
                ),
            )
            .await;
        let response = client
            .ok(Command::QUERY_INFO, &quota_query(file, 108, true, None))
            .await;
        assert_eq!(&response[72..76], &56u32.to_le_bytes());
        assert_eq!(&response[112..124], system.as_bytes());
        assert_eq!(&response[124..128], &[0; 4]);
        assert_eq!(&response[128..132], &[0; 4]);
        assert_eq!(&response[168..], other.as_bytes());
        let mut bytes = quota_query(file, 108, true, None);
        let input = bytes.len() - 16;
        bytes[input] = 7;
        let response = client.ok(Command::QUERY_INFO, &bytes).await;
        assert_eq!(response.len() - 72, 52);
        let response = client
            .ok(Command::QUERY_INFO, &quota_query(file, 52, false, None))
            .await;
        assert_eq!(&response[112..], other.as_bytes());
        let mut bytes = quota_query(file, 108, true, None);
        let input = bytes.len() - 16;
        bytes[input + 8..input + 12]
            .copy_from_slice(&(system.as_bytes().len() as u32).to_le_bytes());
        bytes.extend_from_slice(system.as_bytes());
        QueryInfoRequest::mut_from_prefix(&mut bytes[..])
            .unwrap()
            .0
            .input_buffer_length = 28.into();
        let response = client.ok(Command::QUERY_INFO, &bytes).await;
        assert_eq!(&response[112..], other.as_bytes());
        client.close(file).await;
    });
}
