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
