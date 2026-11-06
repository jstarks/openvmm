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
    use crate::test_support::{ControlledFs, Operation, Plan};
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        control
            .set_plan(
                Operation::SetSecurity,
                Plan {
                    failure: Some(Status::INVALID_DEVICE_REQUEST),
                    ..Plan::default()
                },
            )
            .unwrap();
        let server = Server::new("memory", fs).unwrap();
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
fn file_acl_changes_authorize_new_opens_without_revoking_existing_grants() {
    use crate::security::{AccessAce, Acl, Sid};
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("acl", 2, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"data"))
            .await;
        let world = Sid::new([0, 0, 0, 0, 0, 1], &[0]).unwrap();
        let ace = |deny, mask, sid: &Sid| AccessAce {
            deny,
            mask,
            flags: AceFlags::new(),
            sid: sid.clone(),
        };
        let mut descriptor = SecurityDescriptor::empty();
        descriptor.dacl = AclState::Present(
            Acl::access(&[
                ace(
                    true,
                    AccessMask::new().with_read_data(true).into_bits(),
                    &world,
                ),
                ace(false, AccessMask::FILE_ALL_ACCESS.into_bits(), &world),
            ])
            .unwrap(),
        );
        client
            .ok(Command::SET_INFO, &set(file, 4, &descriptor.encode()))
            .await;
        assert_eq!(&client.read(file, 0, 4).await[80..], b"data");
        let read = AccessMask::new().with_read_data(true).into_bits();
        let response = client.open_result("acl", read, 7, 1, 0).await;
        assert_eq!(response_status(&response), Status::ACCESS_DENIED);
        let maximum = AccessMask::new().with_maximum_allowed(true).into_bits();
        let response = client.open_result("acl", maximum, 7, 1, 0).await;
        let limited = read_body::<CreateResponse>(&response).unwrap().file_id;
        let expected = AccessMask::FILE_ALL_ACCESS
            .with_read_data(false)
            .into_bits();
        assert_eq!(
            &client.query(limited, 8).await[72..],
            &expected.to_le_bytes()
        );
        assert_eq!(&client.read(limited, 0, 4).await[80..], b"data");
        client.close(limited).await;
        let response = client.ok(Command::QUERY_INFO, &query(file, 7, 4096)).await;
        let actual = SecurityDescriptor::decode(&response[72..]).unwrap();
        assert_eq!(actual.dacl, descriptor.dacl);
        assert!(actual.owner.is_some());
        assert!(actual.group.is_some());

        descriptor.dacl = AclState::Present(Acl::access(&[]).unwrap());
        client
            .ok(Command::SET_INFO, &set(file, 4, &descriptor.encode()))
            .await;
        assert_eq!(
            response_status(&client.open_result("acl", read, 7, 1, 0).await),
            Status::ACCESS_DENIED
        );
        let owner_rights = Sid::new([0, 0, 0, 0, 0, 3], &[4]).unwrap();
        descriptor.dacl = AclState::Present(Acl::access(&[ace(false, 0, &owner_rights)]).unwrap());
        client
            .ok(Command::SET_INFO, &set(file, 4, &descriptor.encode()))
            .await;
        assert_eq!(
            response_status(
                &client
                    .open_result(
                        "acl",
                        AccessMask::new().with_write_dac(true).into_bits(),
                        7,
                        1,
                        0
                    )
                    .await
            ),
            Status::ACCESS_DENIED
        );
        descriptor.dacl = AclState::Null;
        client
            .ok(Command::SET_INFO, &set(file, 4, &descriptor.encode()))
            .await;
        let response = client.open_result("acl", read, 7, 1, 0).await;
        let readable = read_body::<CreateResponse>(&response).unwrap().file_id;
        assert_eq!(&client.read(readable, 0, 4).await[80..], b"data");
        client.close(readable).await;
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
                SecurityInformation::new().with_label(true),
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
                Status::NOT_SUPPORTED
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
fn rejected_file_security_updates_are_atomic_and_directory_policy_is_explicit() {
    use crate::security::{AccessAce, Acl, Sid};
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("acl", 2, 0).await;
        let before = client.ok(Command::QUERY_INFO, &query(file, 7, 4096)).await;
        let mut descriptor = SecurityDescriptor::decode(&before[72..]).unwrap();
        descriptor.owner = None;
        assert_eq!(
            response_status(
                &client
                    .send(Command::SET_INFO, &set(file, 1, &descriptor.encode()))
                    .await
            ),
            Status::INVALID_OWNER
        );
        descriptor.owner = Some(Sid::new([0, 0, 0, 0, 0, 1], &[0]).unwrap());
        descriptor.dacl = AclState::Null;
        assert_eq!(
            response_status(
                &client
                    .send(Command::SET_INFO, &set(file, 5, &descriptor.encode()))
                    .await
            ),
            Status::INVALID_OWNER
        );
        descriptor.group = None;
        assert_eq!(
            response_status(
                &client
                    .send(Command::SET_INFO, &set(file, 2, &descriptor.encode()))
                    .await
            ),
            Status::INVALID_PRIMARY_GROUP
        );
        descriptor.dacl =
            AclState::Present(Acl::decode(&[2, 0, 12, 0, 1, 0, 0, 0, 9, 0, 4, 0]).unwrap());
        assert_eq!(
            response_status(
                &client
                    .send(Command::SET_INFO, &set(file, 4, &descriptor.encode()))
                    .await
            ),
            Status::NOT_SUPPORTED
        );
        let after = client.ok(Command::QUERY_INFO, &query(file, 7, 4096)).await;
        assert_eq!(&after[72..], &before[72..]);
        let world = Sid::new([0, 0, 0, 0, 0, 1], &[0]).unwrap();
        let read = AccessMask::new().with_read_data(true).into_bits();
        descriptor.dacl = AclState::Present(
            Acl::access(&[
                AccessAce {
                    deny: false,
                    flags: AceFlags::new(),
                    mask: read,
                    sid: world.clone(),
                },
                AccessAce {
                    deny: true,
                    flags: AceFlags::new(),
                    mask: read,
                    sid: world.clone(),
                },
            ])
            .unwrap(),
        );
        client
            .ok(Command::SET_INFO, &set(file, 4, &descriptor.encode()))
            .await;
        let response = client.open_result("acl", read, 7, 1, 0).await;
        let allowed = read_body::<CreateResponse>(&response).unwrap().file_id;
        client.close(allowed).await;
        let response = client
            .open_result(
                "acl",
                AccessMask::new().with_maximum_allowed(true).into_bits(),
                7,
                1,
                0,
            )
            .await;
        let maximum = read_body::<CreateResponse>(&response).unwrap().file_id;
        let access = client.query(maximum, 8).await;
        assert!(
            AccessMask::from_bits(u32::from_le_bytes(access[72..76].try_into().unwrap()))
                .read_data()
        );
        client.close(maximum).await;
        descriptor.dacl = AclState::Present(
            Acl::access(&[AccessAce {
                deny: false,
                flags: AceFlags::new().with_inherit_only(true),
                mask: read,
                sid: world,
            }])
            .unwrap(),
        );
        client
            .ok(Command::SET_INFO, &set(file, 4, &descriptor.encode()))
            .await;
        assert_eq!(
            response_status(&client.open_result("acl", read, 7, 1, 0).await),
            Status::ACCESS_DENIED
        );
        let response = client
            .open_result(
                "acl",
                AccessMask::new().with_read_attributes(true).into_bits(),
                7,
                1,
                0,
            )
            .await;
        let attributes = read_body::<CreateResponse>(&response).unwrap().file_id;
        client.query(attributes, 4).await;
        client.close(attributes).await;
        let directory = client.open("directory", 2, 1).await;
        assert_eq!(
            response_status(
                &client
                    .send(Command::SET_INFO, &set(directory, 4, &descriptor.encode()))
                    .await
            ),
            Status::NOT_SUPPORTED
        );
        client.close(directory).await;
        client.close(file).await;
    });
}

#[test]
fn late_security_update_cancellation_retains_applied_policy() {
    use crate::security::Acl;
    use crate::test_support::{ControlledFs, Gate, Operation, Phase, Plan};
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let context = RequestContext::new(100);
        let options = OpenOptions {
            access: AccessMask::FILE_ALL_ACCESS.into_bits(),
            share_access: 7,
            disposition: 2,
            options: 0,
            attributes: 0,
        };
        let (file, _) = fs.open("acl", options, &context).await.unwrap();
        control
            .set_plan(
                Operation::SetSecurity,
                Plan {
                    hold_after: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let mut descriptor = SecurityDescriptor::empty();
        descriptor.dacl = AclState::Present(Acl::access(&[]).unwrap());
        let information = SecurityInformation::new().with_dacl(true);
        let mut future = std::pin::pin!(fs.set_security(&file, information, &descriptor, &context));
        assert!(futures::poll!(&mut future).is_pending());
        let call = control.next_call().await;
        assert_eq!(call.operation, Operation::SetSecurity);
        let snapshot = control.snapshot(call.id).unwrap();
        assert_eq!(snapshot.phase, Phase::After);
        assert_eq!(snapshot.status, Some(Status::SUCCESS));
        let read = OpenOptions {
            access: AccessMask::new().with_read_data(true).into_bits(),
            disposition: 1,
            ..options
        };
        assert_eq!(
            fs.open("acl", read, &RequestContext::new(101)).await.err(),
            Some(Status::ACCESS_DENIED)
        );
        context.cancel();
        control.release(call.id, Gate::After).unwrap();
        assert_eq!(future.await, Ok(()));
        assert_eq!(
            fs.query_security(&file, information, &RequestContext::new(102))
                .await
                .unwrap()
                .dacl,
            descriptor.dacl
        );
        fs.close(&file, &RequestContext::new(103)).await.unwrap();
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
