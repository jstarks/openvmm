// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::security::{AclState, SecurityDescriptor};
use test_with_tracing::test;

fn query(file: FileId, information: u32, length: u32) -> Vec<u8> {
    let mut body = QueryInfoRequest::new_zeroed();
    body.structure_size = QueryInfoRequest::STRUCTURE_SIZE.into();
    body.info_type = InformationType::SECURITY;
    body.file_id = file;
    body.additional_information = information.into();
    body.output_buffer_length = length.into();
    body.as_bytes().to_vec()
}

fn set(file: FileId, information: u32, descriptor: &[u8]) -> Vec<u8> {
    let mut body = SetInfoRequest::new_zeroed();
    body.structure_size = SetInfoRequest::STRUCTURE_SIZE.into();
    body.info_type = InformationType::SECURITY;
    body.file_id = file;
    body.additional_information = information.into();
    body.buffer_offset = (body_end::<SetInfoRequest>() as u16).into();
    body.buffer_length = (descriptor.len() as u32).into();
    let mut bytes = body.as_bytes().to_vec();
    bytes.extend_from_slice(descriptor);
    bytes
}

#[test]
fn security_updates_check_rights_and_reject_unimplemented_stores() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("security", 2, 0).await;
        let descriptor = SecurityDescriptor::empty().encode();
        for information in [0, 1, 2, 4, 16, 32, 0x80000004] {
            assert_eq!(
                response_status(
                    &client
                        .send(Command::SET_INFO, &set(file, information, &descriptor))
                        .await
                ),
                Status::INVALID_DEVICE_REQUEST
            );
        }
        for information in [8, 64, 0x10000] {
            assert_eq!(
                response_status(
                    &client
                        .send(Command::SET_INFO, &set(file, information, &descriptor))
                        .await
                ),
                Status::ACCESS_DENIED
            );
        }
        let response = client
            .open_result(
                "security",
                AccessMask::new().with_read_attributes(true).into_bits(),
                7,
                1,
                0,
            )
            .await;
        let limited = read_body::<CreateResponse>(&response).unwrap().file_id;
        for information in [1, 2, 4, 8, 16, 32, 64, 0x10000] {
            assert_eq!(
                response_status(
                    &client
                        .send(Command::SET_INFO, &set(limited, information, &descriptor))
                        .await
                ),
                Status::ACCESS_DENIED
            );
        }
        assert_eq!(
            response_status(
                &client
                    .send(Command::SET_INFO, &set(file, 4, &[0; 20]))
                    .await
            )
            .0,
            0xc0000079
        );
        let mut bad_sid = descriptor.clone();
        bad_sid[4..8].copy_from_slice(&20u32.to_le_bytes());
        bad_sid.extend_from_slice(&[0; 8]);
        assert_eq!(
            response_status(
                &client
                    .send(Command::SET_INFO, &set(file, 1, &bad_sid))
                    .await
            )
            .0,
            0xc0000078
        );
        let mut bad_acl = descriptor;
        bad_acl[2] = 4;
        bad_acl[16..20].copy_from_slice(&20u32.to_le_bytes());
        bad_acl.extend_from_slice(&[0; 8]);
        assert_eq!(
            response_status(
                &client
                    .send(Command::SET_INFO, &set(file, 4, &bad_acl))
                    .await
            )
            .0,
            0xc0000077
        );
        client.close(limited).await;
        client.close(file).await;
    });
}

#[test]
fn security_queries_select_components_and_report_required_buffer_size() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("security", 2, 0).await;
        let mut required = 0;
        for information in [0u32, 1, 2, 4, 7, 0x80000001] {
            let response = client
                .ok(Command::QUERY_INFO, &query(file, information, 4096))
                .await;
            let descriptor = SecurityDescriptor::decode(&response[72..]).unwrap();
            assert_eq!(descriptor.owner.is_some(), information & 1 != 0);
            assert_eq!(descriptor.group.is_some(), information & 2 != 0);
            assert_eq!(
                matches!(descriptor.dacl, AclState::Present(_)),
                information & 4 != 0
            );
            assert_eq!(descriptor.sacl, AclState::Absent);
            if information == 7 {
                required = response.len() as u32 - 72;
            }
        }
        for length in [0, required - 1] {
            let response = client
                .send(Command::QUERY_INFO, &query(file, 7, length))
                .await;
            assert_eq!(response_status(&response), Status::BUFFER_TOO_SMALL);
            assert_eq!(&response[64..72], &[9, 0, 0, 0, 4, 0, 0, 0]);
            assert_eq!(&response[72..], &required.to_le_bytes());
        }
        let response = client
            .open_result(
                "security",
                AccessMask::new().with_read_attributes(true).into_bits(),
                7,
                1,
                0,
            )
            .await;
        let limited = read_body::<CreateResponse>(&response).unwrap().file_id;
        assert_eq!(
            response_status(
                &client
                    .send(Command::QUERY_INFO, &query(limited, 1, 4096))
                    .await
            ),
            Status::ACCESS_DENIED
        );
        assert_eq!(
            response_status(
                &client
                    .send(Command::QUERY_INFO, &query(file, 8, 4096))
                    .await
            ),
            Status::ACCESS_DENIED
        );
        assert_eq!(
            response_status(
                &client
                    .send(Command::QUERY_INFO, &query(file, 16, 4096))
                    .await
            ),
            Status::NOT_SUPPORTED
        );
        client.close(limited).await;
        client.close(file).await;
    });
}

#[test]
fn security_update_gates_preserve_cancellation_and_backend_rejection() {
    use crate::test_support::{ControlledFs, Gate, Operation, Phase, Plan};
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let context = RequestContext::new(100);
        let (file, _) = fs
            .open(
                "security",
                OpenOptions {
                    access: AccessMask::FILE_ALL_ACCESS.into_bits(),
                    share_access: 7,
                    disposition: 2,
                    options: 0,
                    attributes: 0,
                },
                &context,
            )
            .await
            .unwrap();
        let descriptor = SecurityDescriptor::empty();
        for delegated in [false, true] {
            control
                .set_plan(
                    Operation::SetSecurity,
                    Plan {
                        hold_before: true,
                        hold_after: true,
                        ..Plan::default()
                    },
                )
                .unwrap();
            let context = RequestContext::new(101 + u64::from(delegated));
            let mut future = std::pin::pin!(fs.set_security(
                &file,
                SecurityInformation::new().with_dacl(true),
                &descriptor,
                &context
            ));
            assert!(futures::poll!(&mut future).is_pending());
            let call = control.next_call().await;
            assert_eq!(call.operation, Operation::SetSecurity);
            if delegated {
                control.release(call.id, Gate::Before).unwrap();
                assert!(futures::poll!(&mut future).is_pending());
            }
            context.cancel();
            assert!(futures::poll!(&mut future).is_pending());
            let snapshot = control.snapshot(call.id).unwrap();
            let status = if delegated {
                Status::INVALID_DEVICE_REQUEST
            } else {
                Status::CANCELLED
            };
            assert_eq!(snapshot.phase, Phase::After);
            assert_eq!(snapshot.delegated, delegated);
            assert_eq!(snapshot.status, Some(status));
            control.release(call.id, Gate::After).unwrap();
            assert_eq!(future.await, Err(status));
        }
        fs.close(&file, &context).await.unwrap();
    });
}

#[test]
fn rejected_security_queries_have_no_default_descriptor_fallback() {
    use crate::test_support::{ControlledFs, Operation, Plan};
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        control
            .set_plan(
                Operation::QuerySecurity,
                Plan {
                    failure: Some(Status::INVALID_DEVICE_REQUEST),
                    ..Plan::default()
                },
            )
            .unwrap();
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("security", 2, 0).await;
        let response = client.send(Command::QUERY_INFO, &query(file, 7, 0)).await;
        assert_eq!(response_status(&response), Status::INVALID_DEVICE_REQUEST);
        assert_eq!(
            read_body::<ErrorResponse>(&response)
                .unwrap()
                .byte_count
                .get(),
            0
        );
        client.close(file).await;
    });
}
