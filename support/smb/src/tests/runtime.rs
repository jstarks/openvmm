// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::test_support::{Cancellation, ControlledFs, Controller, Gate, Operation, Phase, Plan};
use futures::{AsyncRead, AsyncWrite};
use pal_async::DefaultPool;
use std::collections::VecDeque;
use task_control::TaskControl;
use test_with_tracing::test;

fn controlled(cancellable: bool) -> (ControlledFs<MemoryFs>, Controller) {
    let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
    control
        .set_plan(
            Operation::Write,
            Plan {
                hold_before: true,
                cancellation: if cancellable {
                    Cancellation::Cooperative
                } else {
                    Cancellation::Ignore
                },
                ..Plan::default()
            },
        )
        .unwrap();
    (fs, control)
}

fn successes(control: &Controller, operation: Operation) -> usize {
    control
        .calls()
        .iter()
        .filter(|call| {
            call.operation == operation
                && call.phase == Phase::Completed
                && call.status == Some(Status::SUCCESS)
        })
        .count()
}

async fn through_gates<T>(
    future: impl Future<Output = Result<T, Status>>,
    control: &Controller,
    operation: Operation,
) -> T {
    let mut future = std::pin::pin!(future);
    assert!(futures::poll!(&mut future).is_pending());
    let call = control.next_call().await;
    assert_eq!(call.operation, operation);
    assert!(!control.snapshot(call.id).unwrap().delegated);
    control.release(call.id, Gate::Before).unwrap();
    assert!(futures::poll!(&mut future).is_pending());
    let snapshot = control.snapshot(call.id).unwrap();
    assert_eq!(snapshot.phase, Phase::After);
    assert_eq!(snapshot.status, Some(Status::SUCCESS));
    control.release(call.id, Gate::After).unwrap();
    future.await.unwrap()
}

#[test]
fn every_provider_operation_can_be_gated_without_fabricating_filesystem_results() {
    block_on(async {
        let memory = MemoryFs::new(1024, 16);
        let (fs, control) = ControlledFs::new(memory.clone());
        let operations = [
            Operation::Open,
            Operation::Close,
            Operation::Metadata,
            Operation::FileSystemInformation,
            Operation::FileControl,
            Operation::QueryEas,
            Operation::SetEas,
            Operation::QueryStreams,
            Operation::QuerySecurity,
            Operation::Read,
            Operation::Write,
            Operation::Flush,
            Operation::List,
            Operation::SetLen,
            Operation::SetAllocationSize,
            Operation::SetMode,
            Operation::SetDeleteOnClose,
            Operation::SetBasic,
            Operation::Rename,
            Operation::Lock,
            Operation::Unlock,
            Operation::RollbackLock,
        ];
        for operation in operations {
            control
                .set_plan(
                    operation,
                    Plan {
                        hold_before: true,
                        hold_after: true,
                        ..Plan::default()
                    },
                )
                .unwrap();
        }
        let context = RequestContext::new(101);
        let options = OpenOptions {
            access: AccessMask::FILE_ALL_ACCESS.into_bits(),
            share_access: ShareAccess::ALL.into_bits(),
            disposition: CreateDisposition::CREATE.0,
            options: CreateOptions::new().with_directory_file(true).into_bits(),
            attributes: 0,
            security: None,
            extended_attributes: None,
            allocation_size: 0,
        };
        let (directory, _) = through_gates(
            fs.open("directory", options, &context),
            &control,
            Operation::Open,
        )
        .await;
        let (file, _) = through_gates(
            fs.open(
                "directory\\file",
                OpenOptions {
                    options: 0,
                    ..options
                },
                &context,
            ),
            &control,
            Operation::Open,
        )
        .await;
        assert_eq!(
            through_gates(
                fs.write(&file, 0, b"abcdef", &context),
                &control,
                Operation::Write
            )
            .await,
            6
        );
        through_gates(fs.set_len(&file, 3, &context), &control, Operation::SetLen).await;
        through_gates(
            fs.set_allocation_size(&file, 32, &context),
            &control,
            Operation::SetAllocationSize,
        )
        .await;
        assert_eq!(
            through_gates(
                fs.set_mode(&file, 6, &context),
                &control,
                Operation::SetMode
            )
            .await,
            6
        );
        through_gates(
            fs.set_allocation_size(&file, 3, &context),
            &control,
            Operation::SetAllocationSize,
        )
        .await;
        assert_eq!(
            through_gates(fs.read(&file, 0, 6, &context), &control, Operation::Read).await,
            b"abc"
        );
        let info = BasicInformation {
            created: 10,
            accessed: 20,
            written: 30,
            changed: 40,
            attributes: FileAttributes::new().with_normal(true).into_bits(),
        };
        through_gates(
            fs.set_basic(&file, info, &context),
            &control,
            Operation::SetBasic,
        )
        .await;
        through_gates(
            fs.rename(&file, "directory\\renamed", false, &context),
            &control,
            Operation::Rename,
        )
        .await;
        through_gates(
            fs.set_delete_on_close(&file, true, &context),
            &control,
            Operation::SetDeleteOnClose,
        )
        .await;
        let metadata =
            through_gates(fs.metadata(&file, &context), &control, Operation::Metadata).await;
        assert_eq!(metadata.size, 3);
        assert_eq!(metadata.name, "renamed");
        assert_eq!(metadata.written, 30);
        assert!(metadata.delete_pending);
        let descriptor = through_gates(
            fs.query_security(&file, SecurityInformation::new().with_owner(true), &context),
            &control,
            Operation::QuerySecurity,
        )
        .await;
        assert!(descriptor.owner.is_some());
        let volume = through_gates(
            fs.filesystem_information(&file, &context),
            &control,
            Operation::FileSystemInformation,
        )
        .await;
        assert_eq!(volume.caller_available_allocation_units, 1021);
        assert!(matches!(
            through_gates(
                fs.file_control(&file, FileControl::GetCompression, &context),
                &control,
                Operation::FileControl,
            )
            .await,
            FileControlResult::Compression(0),
        ));
        assert!(matches!(
            through_gates(
                fs.file_control(
                    &file,
                    FileControl::SetZeroData { offset: 1, end: 2 },
                    &context
                ),
                &control,
                Operation::FileControl,
            )
            .await,
            FileControlResult::Done,
        ));
        assert_eq!(
            through_gates(fs.read(&file, 0, 3, &context), &control, Operation::Read).await,
            b"a\0c",
        );
        let result = through_gates(
            fs.file_control(
                &file,
                FileControl::QueryAllocatedRanges {
                    range: ByteRange {
                        offset: 0,
                        length: 3,
                    },
                    maximum_ranges: 1,
                },
                &context,
            ),
            &control,
            Operation::FileControl,
        )
        .await;
        match result {
            FileControlResult::AllocatedRanges { ranges, overflow } => {
                assert_eq!(
                    ranges,
                    vec![ByteRange {
                        offset: 0,
                        length: 3
                    }]
                );
                assert!(!overflow);
            }
            other => panic!("unexpected allocation query result: {other:?}"),
        }
        let ea = provider::ExtendedAttribute {
            name: b"EA".to_vec(),
            value: b"value".to_vec(),
            need_ea: false,
        };
        through_gates(
            fs.set_eas(&file, std::slice::from_ref(&ea), &context),
            &control,
            Operation::SetEas,
        )
        .await;
        assert_eq!(
            through_gates(fs.query_eas(&file, &context), &control, Operation::QueryEas).await,
            vec![ea],
        );
        assert_eq!(
            through_gates(
                fs.query_streams(&file, &context),
                &control,
                Operation::QueryStreams
            )
            .await,
            vec![StreamInformation {
                name: String::new(),
                size: 3,
                allocation_size: 3
            }],
        );
        through_gates(fs.flush(&file, &context), &control, Operation::Flush).await;
        let range = ByteRange {
            offset: 0,
            length: 3,
        };
        let acquired = through_gates(
            fs.lock(&file, range, true, true, &context),
            &control,
            Operation::Lock,
        )
        .await;
        assert_eq!(inspect_text("lock_count", &memory).await, "1");
        through_gates(
            fs.rollback_lock(&file, acquired, &context),
            &control,
            Operation::RollbackLock,
        )
        .await;
        assert_eq!(inspect_text("lock_count", &memory).await, "0");
        through_gates(
            fs.lock(&file, range, false, true, &context),
            &control,
            Operation::Lock,
        )
        .await;
        through_gates(
            fs.unlock(&file, range, &context),
            &control,
            Operation::Unlock,
        )
        .await;
        assert_eq!(inspect_text("lock_count", &memory).await, "0");
        assert!(
            through_gates(fs.list(&directory, &context), &control, Operation::List)
                .await
                .iter()
                .any(|entry| entry.name == "renamed")
        );
        through_gates(fs.close(&file, &context), &control, Operation::Close).await;
        assert!(
            !through_gates(fs.list(&directory, &context), &control, Operation::List)
                .await
                .iter()
                .any(|entry| entry.name == "renamed")
        );
        through_gates(fs.close(&directory, &context), &control, Operation::Close).await;
        assert_eq!(inspect_text("opens", &memory).await, "0");
        let calls = control.calls();
        assert!(
            calls
                .iter()
                .all(|call| call.request_id == 101 && call.phase == Phase::Completed)
        );
        let ids: BTreeSet<_> = calls.iter().map(|call| call.id).collect();
        assert_eq!(ids.len(), calls.len());
        let kinds: BTreeSet<_> = calls.iter().map(|call| call.operation).collect();
        assert_eq!(kinds, operations.into_iter().collect());
    });
}

#[test]
fn pending_filesystem_controls_cancel_or_drain_before_close() {
    block_on(async {
        for (zero, after) in [(false, false), (false, true), (true, false), (true, true)] {
            let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
            control
                .set_plan(
                    Operation::FileControl,
                    Plan {
                        hold_before: !after,
                        hold_after: after,
                        ..Plan::default()
                    },
                )
                .unwrap();
            let server = Server::new("memory", fs).unwrap();
            let mut client = Client::new(&server).await;
            let file = client.open("controlled", 2, 0).await;
            client
                .ok(Command::WRITE, &Client::write_body(file, 0, b"abc"))
                .await;
            let observer = client.open("controlled", 1, 0).await;
            let mut body = IoctlRequest::new_zeroed();
            body.structure_size = IoctlRequest::STRUCTURE_SIZE.into();
            body.file_id = file;
            body.control_code = if zero {
                FsctlCode::SET_ZERO_DATA
            } else {
                FsctlCode::GET_COMPRESSION
            }
            .0
            .into();
            body.flags = IoctlFlags::new().with_fsctl(true);
            body.max_output_response = 2.into();
            let mut bytes;
            if zero {
                body.input_offset = 120.into();
                body.input_count = 16.into();
                bytes = body.as_bytes().to_vec();
                bytes.extend_from_slice(&1i64.to_le_bytes());
                bytes.extend_from_slice(&2i64.to_le_bytes());
            } else {
                bytes = body.as_bytes().to_vec();
            }
            let packet = request(
                Command::IOCTL,
                &bytes,
                client.session,
                client.tree,
                client.message,
            );
            client.message += 1;
            let mut querying = std::pin::pin!(client.connection.request(packet).unwrap().execute());
            assert!(futures::poll!(&mut querying).is_pending());
            let call = control.next_call().await;
            assert_eq!(call.operation, Operation::FileControl);
            assert_eq!(control.snapshot(call.id).unwrap().delegated, after);
            let mut body = CloseRequest::new_zeroed();
            body.structure_size = CloseRequest::STRUCTURE_SIZE.into();
            body.file_id = file;
            let packet = request(
                Command::CLOSE,
                body.as_bytes(),
                client.session,
                client.tree,
                client.message,
            );
            client.message += 1;
            let mut closing = std::pin::pin!(client.connection.request(packet).unwrap().execute());
            assert!(futures::poll!(&mut closing).is_pending());
            if after {
                control.release(call.id, Gate::After).unwrap();
            }
            let response = querying.await.unwrap();
            assert_eq!(
                response_status(&response),
                if after {
                    Status::SUCCESS
                } else {
                    Status::CANCELLED
                }
            );
            if after {
                assert_eq!(&response[112..], if zero { &[][..] } else { &[0, 0][..] });
            }
            assert_eq!(response_status(&closing.await.unwrap()), Status::SUCCESS);
            assert!(control.snapshot(call.id).unwrap().cancel_requested);
            assert_eq!(successes(&control, Operation::Close), 1);
            assert_eq!(
                &client.read(observer, 0, 3).await[80..],
                if zero && after { b"a\0c" } else { b"abc" },
            );
            client.close(observer).await;
        }
    });
}

#[test]
fn allocated_range_queries_observe_earlier_writes_on_the_same_open() {
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        control
            .set_plan(
                Operation::Write,
                Plan {
                    hold_before: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("ordered-control", 2, 0).await;
        let packet = request(
            Command::WRITE,
            &Client::write_body(file, 0, b"abc"),
            client.session,
            client.tree,
            client.message,
        );
        client.message += 1;
        let mut writing = std::pin::pin!(client.connection.request(packet).unwrap().execute());
        assert!(futures::poll!(&mut writing).is_pending());
        let call = control.next_call().await;
        assert_eq!(call.operation, Operation::Write);
        let mut ioctl = IoctlRequest::new_zeroed();
        ioctl.structure_size = IoctlRequest::STRUCTURE_SIZE.into();
        ioctl.file_id = file;
        ioctl.control_code = FsctlCode::QUERY_ALLOCATED_RANGES.0.into();
        ioctl.flags = IoctlFlags::new().with_fsctl(true);
        ioctl.input_count = 16.into();
        ioctl.input_offset = 120.into();
        ioctl.max_output_response = 16.into();
        let mut bytes = ioctl.as_bytes().to_vec();
        bytes.extend_from_slice(&0i64.to_le_bytes());
        bytes.extend_from_slice(&3i64.to_le_bytes());
        let packet = request(
            Command::IOCTL,
            &bytes,
            client.session,
            client.tree,
            client.message,
        );
        client.message += 1;
        let mut querying = std::pin::pin!(client.connection.request(packet).unwrap().execute());
        assert!(futures::poll!(&mut querying).is_pending());
        assert!(
            !control
                .calls()
                .iter()
                .any(|call| call.operation == Operation::FileControl)
        );
        control.release(call.id, Gate::Before).unwrap();
        assert_eq!(response_status(&writing.await.unwrap()), Status::SUCCESS);
        let response = querying.await.unwrap();
        assert_eq!(response_status(&response), Status::SUCCESS);
        assert_eq!(&response[112..], &bytes[size_of::<IoctlRequest>()..]);
        client.close(file).await;
    });
}

#[test]
fn metadata_updates_cancel_before_effect_and_close_drains_committed_results() {
    block_on(async {
        for operation in [
            Operation::SetAllocationSize,
            Operation::SetMode,
            Operation::SetEas,
        ] {
            for after in [false, true] {
                let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
                control
                    .set_plan(
                        operation,
                        Plan {
                            hold_before: !after,
                            hold_after: after,
                            ..Plan::default()
                        },
                    )
                    .unwrap();
                let server = Server::new("memory", fs).unwrap();
                let mut client = Client::new(&server).await;
                let file = client.open("update", 2, 0).await;
                let opened = client.connection.state.lock().files[&file.volatile.get()].clone();
                let data = if operation == Operation::SetMode {
                    6u32.to_le_bytes().to_vec()
                } else if operation == Operation::SetEas {
                    vec![0, 0, 0, 0, 0, 1, 1, 0, b'A', 0, b'v']
                } else {
                    32i64.to_le_bytes().to_vec()
                };
                let mut body = SetInfoRequest::new_zeroed();
                body.structure_size = SetInfoRequest::STRUCTURE_SIZE.into();
                body.info_type = InformationType::FILE;
                body.info_class = if operation == Operation::SetMode {
                    16
                } else if operation == Operation::SetEas {
                    15
                } else {
                    19
                };
                body.file_id = file;
                body.buffer_offset = (body_end::<SetInfoRequest>() as u16).into();
                body.buffer_length = (data.len() as u32).into();
                let mut bytes = body.as_bytes().to_vec();
                bytes.extend(data);
                let packet = request(
                    Command::SET_INFO,
                    &bytes,
                    client.session,
                    client.tree,
                    client.message,
                );
                client.message += 1;
                let mut updating =
                    std::pin::pin!(client.connection.request(packet).unwrap().execute());
                assert!(futures::poll!(&mut updating).is_pending());
                let call = control.next_call().await;
                assert_eq!(call.operation, operation);
                assert_eq!(control.snapshot(call.id).unwrap().delegated, after);
                let mut body = CloseRequest::new_zeroed();
                body.structure_size = CloseRequest::STRUCTURE_SIZE.into();
                body.file_id = file;
                let packet = request(
                    Command::CLOSE,
                    body.as_bytes(),
                    client.session,
                    client.tree,
                    client.message,
                );
                client.message += 1;
                let mut closing =
                    std::pin::pin!(client.connection.request(packet).unwrap().execute());
                assert!(futures::poll!(&mut closing).is_pending());
                if after {
                    control.release(call.id, Gate::After).unwrap();
                }
                assert_eq!(
                    response_status(&updating.await.unwrap()),
                    if after {
                        Status::SUCCESS
                    } else {
                        Status::CANCELLED
                    }
                );
                assert_eq!(response_status(&closing.await.unwrap()), Status::SUCCESS);
                assert!(control.snapshot(call.id).unwrap().cancel_requested);
                if operation == Operation::SetMode {
                    assert_eq!(
                        opened.mode.load(Ordering::Relaxed),
                        if after { 6 } else { 0 }
                    );
                } else {
                    let reopened = client.open("update", 1, 0).await;
                    if operation == Operation::SetEas {
                        let response = client.query(reopened, 15).await;
                        assert_eq!(
                            response_status(&response),
                            if after {
                                Status::SUCCESS
                            } else {
                                Status::NO_EAS_ON_FILE
                            }
                        );
                        if after {
                            assert_eq!(&response[72..], &[0, 0, 0, 0, 0, 1, 1, 0, b'A', 0, b'v']);
                        }
                    } else {
                        let response = client.query(reopened, 5).await;
                        assert_eq!(
                            &response[72..80],
                            &(if after { 32u64 } else { 0 }).to_le_bytes()
                        );
                    }
                    client.close(reopened).await;
                }
            }
        }
    });
}

#[test]
fn partial_transfers_and_injected_failure_match_actual_file_contents() {
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("partial", 2, 0).await;
        control
            .set_plan(
                Operation::Write,
                Plan {
                    transfer_limit: Some(2),
                    ..Plan::default()
                },
            )
            .unwrap();
        let response = client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"hello"))
            .await;
        assert_eq!(u32::from_le_bytes(response[68..72].try_into().unwrap()), 2);
        assert_eq!(&client.read(file, 0, 10).await[80..], b"he");
        control
            .set_plan(
                Operation::Read,
                Plan {
                    transfer_limit: Some(1),
                    ..Plan::default()
                },
            )
            .unwrap();
        assert_eq!(&client.read(file, 0, 10).await[80..], b"h");
        control
            .plan_next(
                Operation::Write,
                Plan {
                    failure: Some(Status::DISK_FULL),
                    ..Plan::default()
                },
            )
            .unwrap();
        assert_eq!(
            response_status(
                &client
                    .send(Command::WRITE, &Client::write_body(file, 0, b"changed"))
                    .await
            ),
            Status::DISK_FULL
        );
        control.set_plan(Operation::Read, Plan::default()).unwrap();
        assert_eq!(&client.read(file, 0, 10).await[80..], b"he");
        let calls = control.calls();
        let failed = calls
            .iter()
            .find(|call| {
                call.operation == Operation::Write && call.status == Some(Status::DISK_FULL)
            })
            .unwrap();
        assert!(!failed.delegated);
        assert_eq!(failed.phase, Phase::Completed);
        assert_eq!(
            calls
                .iter()
                .find(|call| call.operation == Operation::Write
                    && call.status == Some(Status::SUCCESS))
                .unwrap()
                .transferred,
            Some(2)
        );
    });
}

#[test]
fn selected_write_completion_order_and_late_close_cancellation_preserve_committed_data() {
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("reorder", 2, 0).await;
        let other = client.open("other", 2, 0).await;
        control
            .set_plan(
                Operation::Write,
                Plan {
                    hold_after: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let first_message = client.message;
        let first = admitted(
            &mut client,
            Command::WRITE,
            &Client::write_body(file, 0, b"one"),
        )
        .execute();
        let second_message = client.message;
        let second = admitted(
            &mut client,
            Command::WRITE,
            &Client::write_body(file, 3, b"two"),
        )
        .execute();
        let mut first = std::pin::pin!(first);
        let mut second = std::pin::pin!(second);
        assert!(futures::poll!(&mut first).is_pending());
        assert!(futures::poll!(&mut second).is_pending());
        let first_call = control.next_call().await;
        let second_call = control.next_call().await;
        assert_eq!(first_call.offset, Some(0));
        assert_eq!(second_call.offset, Some(3));
        assert_eq!(control.snapshot(first_call.id).unwrap().phase, Phase::After);
        assert_eq!(&client.read(file, 0, 6).await[80..], b"onetwo");
        control.release(second_call.id, Gate::After).unwrap();
        let response = second.await.unwrap();
        assert_eq!(
            Header::read_from_prefix(&response)
                .unwrap()
                .0
                .message_id
                .get(),
            second_message
        );
        assert!(futures::poll!(&mut first).is_pending());
        let close = admitted(&mut client, Command::CLOSE, close_body(file).as_bytes()).execute();
        let mut close = std::pin::pin!(close);
        assert!(futures::poll!(&mut close).is_pending());
        let snapshot = control.snapshot(first_call.id).unwrap();
        assert!(snapshot.cancel_requested);
        assert_eq!(snapshot.status, Some(Status::SUCCESS));
        assert_eq!(
            inspect_text(&format!("calls/{}/phase", first_call.id), &control).await,
            "\"After\""
        );
        assert_eq!(
            inspect_text(
                &format!("calls/{}/cancel_requested", first_call.id),
                &control
            )
            .await,
            "true"
        );
        assert_eq!(successes(&control, Operation::Close), 0);
        assert_eq!(
            response_status(&client.read(other, 0, 0).await),
            Status::SUCCESS
        );
        control.release(first_call.id, Gate::After).unwrap();
        let response = first.await.unwrap();
        assert_eq!(response_status(&response), Status::SUCCESS);
        assert_eq!(
            Header::read_from_prefix(&response)
                .unwrap()
                .0
                .message_id
                .get(),
            first_message
        );
        assert_eq!(response_status(&close.await.unwrap()), Status::SUCCESS);
        assert_eq!(successes(&control, Operation::Write), 2);
        assert_eq!(successes(&control, Operation::Close), 1);
        let file = client.open("reorder", 1, 0).await;
        assert_eq!(&client.read(file, 0, 6).await[80..], b"onetwo");
    });
}

#[test]
fn controlled_call_errors_and_abandonment_do_not_claim_completion() {
    block_on(async {
        use crate::test_support::ControlError;
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        assert!(matches!(
            control.set_plan(
                Operation::Open,
                Plan {
                    transfer_limit: Some(1),
                    ..Plan::default()
                }
            ),
            Err(ControlError::InvalidTransferLimit)
        ));
        assert!(matches!(
            control.plan_next(
                Operation::Write,
                Plan {
                    failure: Some(Status::SUCCESS),
                    ..Plan::default()
                }
            ),
            Err(ControlError::InvalidFailure(Status::SUCCESS))
        ));
        assert!(matches!(
            control.release(0, Gate::Before),
            Err(ControlError::UnknownCall(0))
        ));
        control
            .set_plan(
                Operation::Open,
                Plan {
                    hold_before: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let context = RequestContext::new(1);
        let options = OpenOptions {
            access: AccessMask::FILE_ALL_ACCESS.into_bits(),
            share_access: 7,
            disposition: 2,
            options: 0,
            attributes: 0,
            security: None,
            extended_attributes: None,
            allocation_size: 0,
        };
        let mut open = Box::pin(fs.open("abandoned", options, &context));
        assert!(futures::poll!(&mut open).is_pending());
        let call = control.next_call().await;
        assert!(matches!(
            control.release(call.id, Gate::After),
            Err(ControlError::GateNotHeld(_, Gate::After))
        ));
        drop(open);
        assert!(matches!(
            control.wait_for_phase(call.id, Phase::Completed).await,
            Err(ControlError::Abandoned(_))
        ));
        assert_eq!(control.snapshot(call.id).unwrap().status, None);
        control.set_plan(Operation::Open, Plan::default()).unwrap();
        let (_, action) = fs.open("abandoned", options, &context).await.unwrap();
        assert_eq!(action, 2);
    });
}

#[test]
fn cancellation_during_a_delegate_future_is_forwarded_or_suppressed_by_policy() {
    block_on(async {
        for policy in [Cancellation::Cooperative, Cancellation::Ignore] {
            let (inner, inner_control) = ControlledFs::new(MemoryFs::new(1024, 16));
            let (outer, outer_control) = ControlledFs::new(inner);
            let server = Server::new("memory", outer).unwrap();
            let mut client = Client::new(&server).await;
            let file = client.open("nested", 2, 0).await;
            inner_control
                .set_plan(
                    Operation::Write,
                    Plan {
                        hold_before: true,
                        ..Plan::default()
                    },
                )
                .unwrap();
            outer_control
                .set_plan(
                    Operation::Write,
                    Plan {
                        cancellation: policy,
                        ..Plan::default()
                    },
                )
                .unwrap();
            let message = client.message;
            let write = admitted(
                &mut client,
                Command::WRITE,
                &Client::write_body(file, 0, b"data"),
            )
            .execute();
            let mut write = std::pin::pin!(write);
            assert!(futures::poll!(&mut write).is_pending());
            let call = inner_control.next_call().await;
            let outer_call = outer_control
                .calls()
                .into_iter()
                .find(|call| call.operation == Operation::Write)
                .unwrap();
            assert_eq!(outer_call.phase, Phase::Executing);
            client
                .connection
                .cancel(&request(
                    Command::CANCEL,
                    SimpleBody {
                        structure_size: SimpleBody::STRUCTURE_SIZE.into(),
                        reserved: 0.into(),
                    }
                    .as_bytes(),
                    client.session,
                    client.tree,
                    message,
                ))
                .unwrap();
            if policy == Cancellation::Ignore {
                assert!(!inner_control.snapshot(call.id).unwrap().cancel_requested);
                inner_control.release(call.id, Gate::Before).unwrap();
            }
            let response = write.await.unwrap();
            assert_eq!(
                response_status(&response),
                if policy == Cancellation::Ignore {
                    Status::SUCCESS
                } else {
                    Status::CANCELLED
                }
            );
            let read = client.read(file, 0, 4).await;
            if policy == Cancellation::Ignore {
                assert_eq!(&read[80..], b"data");
            } else {
                assert_eq!(response_status(&read), Status::END_OF_FILE);
            }
        }
    });
}

fn close_body(file: FileId) -> CloseRequest {
    let mut body = CloseRequest::new_zeroed();
    body.structure_size = CloseRequest::STRUCTURE_SIZE.into();
    body.file_id = file;
    body
}

fn admitted<B: FileSystem>(client: &mut Client<B>, command: Command, body: &[u8]) -> Request<B> {
    let packet = request(command, body, client.session, client.tree, client.message);
    client.message += 1;
    client.connection.request(packet).unwrap()
}

#[test]
fn tcp_pause_retains_committed_reordered_writes_and_a_concurrent_close() {
    DefaultPool::run_with(async |driver| {
        let memory = MemoryFs::new(1024, 16);
        let (fs, control) = ControlledFs::new(memory.clone());
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("committed", 2, 0).await;
        control
            .set_plan(
                Operation::Write,
                Plan {
                    hold_after: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let first_message = client.message;
        let first_frame = frame(&request(
            Command::WRITE,
            &Client::write_body(file, 0, b"one"),
            client.session,
            client.tree,
            first_message,
        ));
        let second_frame = frame(&request(
            Command::WRITE,
            &Client::write_body(file, 3, b"two"),
            client.session,
            client.tree,
            first_message + 1,
        ));
        let close_frame = frame(&request(
            Command::CLOSE,
            close_body(file).as_bytes(),
            client.session,
            client.tree,
            first_message + 2,
        ));
        let stream = TestStream::new();
        stream.writable(usize::MAX);
        stream.input(&first_frame);
        stream.input(&second_frame);
        let mut task = TaskControl::new(tcp::ConnectionTask::new(
            client.connection.clone(),
            stream.clone(),
        ));
        task.insert(driver, "smb-committed-test", ());
        task.start();
        let first_call = control.next_call().await;
        let second_call = control.next_call().await;
        control
            .wait_for_phase(first_call.id, Phase::After)
            .await
            .unwrap();
        control
            .wait_for_phase(second_call.id, Phase::After)
            .await
            .unwrap();
        let context = RequestContext::new(1000);
        let (observer, _) = memory
            .open(
                "committed",
                OpenOptions {
                    access: 1,
                    share_access: 7,
                    disposition: 1,
                    options: 0,
                    attributes: 0,
                    security: None,
                    extended_attributes: None,
                    allocation_size: 0,
                },
                &context,
            )
            .await
            .unwrap();
        assert_eq!(
            memory.read(&observer, 0, 6, &context).await.unwrap(),
            b"onetwo"
        );
        memory.close(&observer, &context).await.unwrap();
        control.release(second_call.id, Gate::After).unwrap();
        stream.until(|s| final_frames(&s.output).len() == 1).await;
        task.stop().await;
        assert_eq!(control.snapshot(first_call.id).unwrap().phase, Phase::After);
        stream.input(&close_frame);
        task.start();
        stream
            .until(|s| s.read == first_frame.len() + second_frame.len() + close_frame.len())
            .await;
        assert_eq!(inspect_text("active_requests", &task).await, "2");
        task.stop().await;
        let snapshot = control.snapshot(first_call.id).unwrap();
        assert!(snapshot.cancel_requested);
        assert_eq!(snapshot.status, Some(Status::SUCCESS));
        assert_eq!(successes(&control, Operation::Close), 0);
        let before = stream.state.lock().output.clone();
        control.release(first_call.id, Gate::After).unwrap();
        assert_eq!(stream.state.lock().output, before);
        task.start();
        stream.until(|s| final_frames(&s.output).len() == 3).await;
        task.stop().await;
        let bytes = stream.state.lock().output.clone();
        let replies = final_frames(&bytes);
        let first_response = Header::read_from_prefix(replies[0]).unwrap().0;
        let second_response = Header::read_from_prefix(replies[1]).unwrap().0;
        let close_response = Header::read_from_prefix(replies[2]).unwrap().0;
        assert_eq!(first_response.message_id.get(), first_message + 1);
        assert_eq!(second_response.message_id.get(), first_message);
        assert_eq!(close_response.message_id.get(), first_message + 2);
        assert_eq!(first_response.status.get(), Status::SUCCESS.0);
        assert_eq!(second_response.status.get(), Status::SUCCESS.0);
        assert_eq!(close_response.status.get(), Status::SUCCESS.0);
        assert_eq!(successes(&control, Operation::Write), 2);
        assert_eq!(successes(&control, Operation::Close), 1);
        task.task_mut().shutdown().await.unwrap();
        assert_eq!(successes(&control, Operation::Close), 1);
        assert!(
            !control
                .calls()
                .iter()
                .any(|call| call.phase == Phase::Abandoned)
        );
    });
}

#[test]
fn compound_pause_retains_committed_io_and_queued_commands_during_external_close() {
    DefaultPool::run_with(async |driver| {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("compound-pause", 2, 0).await;
        control
            .set_plan(
                Operation::Write,
                Plan {
                    hold_after: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let bytes = compound::packet(
            &mut client,
            vec![
                (Command::WRITE, Client::write_body(file, 0, b"abc")),
                (Command::READ, compound::read(FileId::RELATED, 3)),
                (Command::CLOSE, compound::close(FileId::RELATED)),
            ],
            true,
        );
        let first_id = Header::read_from_prefix(&bytes).unwrap().0.message_id.get();
        let stream = TestStream::new();
        stream.writable(usize::MAX);
        stream.input(&frame(&bytes));
        let mut task = TaskControl::new(tcp::ConnectionTask::new(
            client.connection.clone(),
            stream.clone(),
        ));
        task.insert(driver, "smb-compound-pause", ());
        task.start();
        let write = control.next_call().await;
        control
            .wait_for_phase(write.id, Phase::After)
            .await
            .unwrap();
        assert_eq!(
            inspect_text("connection/requests", &task)
                .await
                .matches("activated")
                .count(),
            3
        );
        task.stop().await;
        assert!(final_frames(&stream.state.lock().output).is_empty());
        let close_id = client.message;
        let close = frame(&request(
            Command::CLOSE,
            close_body(file).as_bytes(),
            client.session,
            client.tree,
            close_id,
        ));
        stream.input(&close);
        task.start();
        stream
            .until(|state| state.read == bytes.len() + 4 + close.len())
            .await;
        task.stop().await;
        assert!(control.snapshot(write.id).unwrap().cancel_requested);
        assert_eq!(successes(&control, Operation::Close), 0);
        let paused = stream.state.lock().output.clone();
        control.release(write.id, Gate::After).unwrap();
        assert_eq!(stream.state.lock().output, paused);
        task.start();
        stream
            .until(|state| final_frames(&state.output).len() == 4)
            .await;
        task.stop().await;
        let output = stream.state.lock().output.clone();
        let mut saw_compound = false;
        let mut saw_close = false;
        let pending: BTreeMap<_, _> = complete_frames(&output)
            .into_iter()
            .filter(|frame| response_status(frame) == Status::PENDING)
            .map(|frame| {
                let header = AsyncHeader::read_from_prefix(frame).unwrap().0;
                (header.message_id.get(), header.async_id.get())
            })
            .collect();
        assert_eq!(pending.len(), 4);
        let replies = final_frames(&output);
        assert_eq!(replies.len(), 4);
        for reply in replies {
            let header = Header::read_from_prefix(reply).unwrap().0;
            let asynchronous = AsyncHeader::read_from_prefix(reply).unwrap().0;
            assert!(header.flags.async_command());
            assert_eq!(
                pending[&header.message_id.get()],
                asynchronous.async_id.get()
            );
            assert_eq!(header.credits.get(), 0);
            if header.message_id.get() == first_id {
                assert_eq!(header.status(), Status::SUCCESS);
                saw_compound = true;
            } else if header.message_id.get() == close_id {
                assert_eq!(header.status(), Status::SUCCESS);
                saw_close = true;
            } else {
                assert!(
                    matches!(header.message_id.get(), id if id == first_id + 1 || id == first_id + 2)
                );
                assert_eq!(header.status(), Status::FILE_CLOSED);
            }
        }
        assert!(saw_compound && saw_close);
        assert_eq!(successes(&control, Operation::Write), 1);
        assert_eq!(successes(&control, Operation::Read), 0);
        assert_eq!(successes(&control, Operation::Close), 1);
        task.task_mut().shutdown().await.unwrap();
        assert!(
            !control
                .calls()
                .iter()
                .any(|call| call.phase == Phase::Abandoned)
        );
    });
}

#[test]
fn queued_compound_writes_remain_ordered_before_a_later_flush() {
    block_on(async {
        let (fs, control) = controlled(false);
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("compound-order", 2, 0).await;
        let bytes = compound::packet(
            &mut client,
            vec![
                (Command::WRITE, Client::write_body(file, 0, b"one")),
                (
                    Command::WRITE,
                    Client::write_body(FileId::RELATED, 3, b"two"),
                ),
            ],
            true,
        );
        let mut group = std::pin::pin!(client.connection.request(bytes).unwrap().execute());
        assert!(futures::poll!(&mut group).is_pending());
        let first = control.next_call().await;
        let mut flush = FlushRequest::new_zeroed();
        flush.structure_size = FlushRequest::STRUCTURE_SIZE.into();
        flush.file_id = file;
        let mut flush =
            std::pin::pin!(admitted(&mut client, Command::FLUSH, flush.as_bytes()).execute());
        assert!(futures::poll!(&mut flush).is_pending());
        control.release(first.id, Gate::Before).unwrap();
        assert!(futures::poll!(&mut group).is_pending());
        let second = control.next_call().await;
        assert_eq!(successes(&control, Operation::Write), 1);
        assert!(futures::poll!(&mut flush).is_pending());
        assert_eq!(successes(&control, Operation::Flush), 0);
        control.release(second.id, Gate::Before).unwrap();
        let response = group.await.unwrap();
        assert!(
            compound::responses(&response)
                .iter()
                .all(|reply| response_status(reply) == Status::SUCCESS)
        );
        assert_eq!(response_status(&flush.await.unwrap()), Status::SUCCESS);
        assert_eq!(&client.read(file, 0, 6).await[80..], b"onetwo");
    });
}

#[test]
fn deferred_binding_orders_barriers_independently_of_operation_identity() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let id = client.open("binding-order", 2, 0).await;
        let file = client.connection.state.lock().files[&id.volatile.get()].clone();
        let barrier = RequestContext::new(30);
        let deferred = RequestContext::new(10);
        file.track(&barrier, Command::FLUSH);
        file.track(&deferred, Command::READ);
        let mut wait = std::pin::pin!(file.wait(&deferred, false));
        assert!(futures::poll!(&mut wait).is_pending());
        file.untrack(barrier.id());
        wait.await.unwrap();
        file.untrack(deferred.id());
        client.close(id).await;
    });
}

#[test]
fn cancel_reaches_queued_compound_io_and_discarded_work_does_not_reissue_ids() {
    block_on(async {
        let (fs, control) = controlled(false);
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("queued-cancel", 2, 0).await;
        let bytes = compound::packet(
            &mut client,
            vec![
                (Command::WRITE, Client::write_body(file, 0, b"one")),
                (
                    Command::WRITE,
                    Client::write_body(FileId::RELATED, 3, b"two"),
                ),
            ],
            true,
        );
        let baseline = client.connection.state.lock().window.len();
        drop(client.connection.request(bytes.clone()).unwrap());
        assert_eq!(client.connection.state.lock().window.len(), baseline - 2);
        assert!(client.connection.state.lock().disconnected);
        assert!(client.connection.state.lock().requests.is_empty());
        client.connection.shutdown().await.unwrap();
        client = Client::new(&server).await;
        let file = client.open("queued-cancel", 1, 0).await;
        let bytes = compound::packet(
            &mut client,
            vec![
                (Command::WRITE, Client::write_body(file, 0, b"one")),
                (
                    Command::WRITE,
                    Client::write_body(FileId::RELATED, 3, b"two"),
                ),
            ],
            true,
        );
        let next = Header::read_from_prefix(&bytes)
            .unwrap()
            .0
            .next_command
            .get() as usize;
        let message = Header::read_from_prefix(&bytes[next..])
            .unwrap()
            .0
            .message_id
            .get();
        let mut group = std::pin::pin!(client.connection.request(bytes).unwrap().execute());
        assert!(futures::poll!(&mut group).is_pending());
        let held = control.next_call().await;
        let cancel = SimpleBody {
            structure_size: SimpleBody::STRUCTURE_SIZE.into(),
            reserved: 0.into(),
        };
        client
            .connection
            .cancel(&request(
                Command::CANCEL,
                cancel.as_bytes(),
                client.session,
                client.tree,
                message,
            ))
            .unwrap();
        control.release(held.id, Gate::Before).unwrap();
        let response = group.await.unwrap();
        let replies = compound::responses(&response);
        assert_eq!(response_status(replies[0]), Status::SUCCESS);
        assert_eq!(response_status(replies[1]), Status::CANCELLED);
        assert_eq!(successes(&control, Operation::Write), 1);
        assert_eq!(&client.read(file, 0, 6).await[80..], b"one");
        client.close(file).await;
    });
}

#[test]
fn tcp_rejects_an_excess_compound_atomically_without_waiting_for_pending_io() {
    DefaultPool::run_with(async |driver| {
        let (fs, control) = controlled(false);
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("capacity", 2, 0).await;
        let write = request(
            Command::WRITE,
            &Client::write_body(file, 0, b"x"),
            client.session,
            client.tree,
            client.message,
        );
        client.message += 1;
        let echo = SimpleBody {
            structure_size: SimpleBody::STRUCTURE_SIZE.into(),
            reserved: 0.into(),
        };
        let bytes = compound::packet(
            &mut client,
            (0..MAX_REQUESTS)
                .map(|_| (Command::ECHO, echo.as_bytes().to_vec()))
                .collect(),
            false,
        );
        let stream = TestStream::new();
        stream.writable(usize::MAX);
        stream.input(&frame(&write));
        let mut task = TaskControl::new(tcp::ConnectionTask::new(
            client.connection.clone(),
            stream.clone(),
        ));
        task.insert(driver, "smb-compound-capacity", ());
        task.start();
        let held = control.next_call().await;
        stream.input(&frame(&bytes));
        stream
            .until(|state| final_frames(&state.output).len() == 1)
            .await;
        task.stop().await;
        assert_eq!(inspect_text("active_requests", &task).await, "1");
        control.release(held.id, Gate::Before).unwrap();
        task.start();
        stream
            .until(|state| final_frames(&state.output).len() == 2)
            .await;
        task.stop().await;
        let output = stream.state.lock().output.clone();
        let finals = final_frames(&output);
        let replies = compound::responses(finals[0]);
        assert_eq!(replies.len(), MAX_REQUESTS);
        assert!(
            replies
                .iter()
                .all(|reply| response_status(reply) == Status::INSUFFICIENT_RESOURCES)
        );
        assert_eq!(response_status(finals[1]), Status::SUCCESS);
        client.ok(Command::ECHO, echo.as_bytes()).await;
        task.task_mut().shutdown().await.unwrap();
    });
}

#[test]
fn close_drains_uncancellable_writes_without_blocking_other_opens() {
    block_on(async {
        let (fs, control) = controlled(false);
        let server = Server::new("memory", fs.clone()).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("target", 2, 0).await;
        let other = client.open("other", 2, 0).await;
        let first = admitted(
            &mut client,
            Command::WRITE,
            &Client::write_body(file, 0, b"one"),
        )
        .execute();
        let second = admitted(
            &mut client,
            Command::WRITE,
            &Client::write_body(file, 3, b"two"),
        )
        .execute();
        let mut first = std::pin::pin!(first);
        let mut second = std::pin::pin!(second);
        assert!(futures::poll!(&mut first).is_pending());
        assert!(futures::poll!(&mut second).is_pending());
        let first_call = control.next_call().await;
        let second_call = control.next_call().await;
        assert_ne!(first_call.id, second_call.id);
        let mut body = close_body(file);
        body.flags = CloseFlags::new().with_postquery_attrib(true);
        let close = admitted(&mut client, Command::CLOSE, body.as_bytes()).execute();
        let mut close = std::pin::pin!(close);
        assert!(futures::poll!(&mut close).is_pending());
        assert_eq!(successes(&control, Operation::Close), 0);
        assert_eq!(
            response_status(&client.read(file, 0, 1).await),
            Status::FILE_CLOSED
        );
        assert_eq!(
            response_status(&client.read(other, 0, 0).await),
            Status::SUCCESS
        );
        control.release(first_call.id, Gate::Before).unwrap();
        control.release(second_call.id, Gate::Before).unwrap();
        let (first, second, close) = futures::join!(first, second, close);
        assert_eq!(response_status(&first.unwrap()), Status::SUCCESS);
        assert_eq!(response_status(&second.unwrap()), Status::SUCCESS);
        let close = close.unwrap();
        assert_eq!(response_status(&close), Status::SUCCESS);
        assert_eq!(u64::from_le_bytes(close[112..120].try_into().unwrap()), 6);
        assert_eq!(successes(&control, Operation::Write), 2);
        assert_eq!(successes(&control, Operation::Close), 1);
        let reopened = client.open("target", 1, 0).await;
        assert_eq!(&client.read(reopened, 0, 6).await[80..], b"onetwo");
    });
}

#[test]
fn close_cancels_pending_io_and_cancel_races_are_harmless() {
    block_on(async {
        let (fs, control) = controlled(true);
        let server = Server::new("memory", fs.clone()).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("target", 2, 0).await;
        let message = client.message;
        let write = admitted(
            &mut client,
            Command::WRITE,
            &Client::write_body(file, 0, b"data"),
        )
        .execute();
        let mut write = std::pin::pin!(write);
        assert!(futures::poll!(&mut write).is_pending());
        control.next_call().await;
        let close = admitted(&mut client, Command::CLOSE, close_body(file).as_bytes()).execute();
        let (write, close) = futures::join!(write, close);
        assert_eq!(response_status(&write.unwrap()), Status::CANCELLED);
        assert_eq!(response_status(&close.unwrap()), Status::SUCCESS);
        let cancel = request(
            Command::CANCEL,
            SimpleBody {
                structure_size: SimpleBody::STRUCTURE_SIZE.into(),
                reserved: 0.into(),
            }
            .as_bytes(),
            client.session,
            client.tree,
            message,
        );
        client.connection.cancel(&cancel).unwrap();
        assert_eq!(successes(&control, Operation::Write), 0);
        assert_eq!(successes(&control, Operation::Close), 1);
    });
}

#[test]
fn flush_orders_earlier_and_later_writes_on_the_same_open() {
    block_on(async {
        let (fs, control) = controlled(false);
        let server = Server::new("memory", fs.clone()).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("target", 2, 0).await;
        let first = admitted(
            &mut client,
            Command::WRITE,
            &Client::write_body(file, 0, b"a"),
        )
        .execute();
        let flush = admitted(&mut client, Command::FLUSH, close_body(file).as_bytes()).execute();
        let second = admitted(
            &mut client,
            Command::WRITE,
            &Client::write_body(file, 1, b"b"),
        )
        .execute();
        let mut first = std::pin::pin!(first);
        let mut flush = std::pin::pin!(flush);
        let mut second = std::pin::pin!(second);
        assert!(futures::poll!(&mut first).is_pending());
        assert!(futures::poll!(&mut flush).is_pending());
        assert!(futures::poll!(&mut second).is_pending());
        let first_call = control.next_call().await;
        assert!(control.try_next_call().is_none());
        assert_eq!(successes(&control, Operation::Flush), 0);
        control.release(first_call.id, Gate::Before).unwrap();
        assert_eq!(response_status(&first.await.unwrap()), Status::SUCCESS);
        assert_eq!(response_status(&flush.await.unwrap()), Status::SUCCESS);
        assert_eq!(successes(&control, Operation::Flush), 1);
        assert!(futures::poll!(&mut second).is_pending());
        let second_call = control.next_call().await;
        control.release(second_call.id, Gate::Before).unwrap();
        assert_eq!(response_status(&second.await.unwrap()), Status::SUCCESS);
    });
}

#[derive(Default)]
struct StreamState {
    input: VecDeque<u8>,
    eof: bool,
    output: Vec<u8>,
    read: usize,
    write_limit: usize,
    repeat_echo: Option<(u64, u32, u64)>,
}

#[derive(Clone)]
struct TestStream {
    state: Arc<Mutex<StreamState>>,
    reader: Arc<futures::task::AtomicWaker>,
    writer: Arc<futures::task::AtomicWaker>,
    changed: Arc<Event>,
}

impl TestStream {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(StreamState::default())),
            reader: Arc::new(futures::task::AtomicWaker::new()),
            writer: Arc::new(futures::task::AtomicWaker::new()),
            changed: Arc::new(Event::new()),
        }
    }
    fn input(&self, bytes: &[u8]) {
        self.state.lock().input.extend(bytes);
        self.reader.wake();
    }
    fn writable(&self, length: usize) {
        self.state.lock().write_limit = length;
        self.writer.wake();
    }
    async fn until(&self, condition: impl Fn(&StreamState) -> bool) {
        loop {
            let listener = self.changed.listen();
            if condition(&self.state.lock()) {
                return;
            }
            listener.await;
        }
    }
}

impl AsyncRead for TestStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        self.reader.register(cx.waker());
        let mut state = self.state.lock();
        if state.input.is_empty() {
            if let Some((session, tree, message)) = state.repeat_echo {
                let body = SimpleBody {
                    structure_size: SimpleBody::STRUCTURE_SIZE.into(),
                    reserved: 0.into(),
                };
                state.input.extend(frame(&request(
                    Command::ECHO,
                    body.as_bytes(),
                    session,
                    tree,
                    message,
                )));
                state.repeat_echo = Some((session, tree, message + 1));
            }
        }
        if state.input.is_empty() {
            if state.eof {
                return Poll::Ready(Ok(0));
            }
            return Poll::Pending;
        }
        let length = out.len().min(state.input.len());
        for byte in &mut out[..length] {
            *byte = state.input.pop_front().unwrap();
        }
        state.read += length;
        self.changed.notify(usize::MAX);
        Poll::Ready(Ok(length))
    }
}

impl AsyncWrite for TestStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.writer.register(cx.waker());
        let mut state = self.state.lock();
        let length = state
            .write_limit
            .saturating_sub(state.output.len())
            .min(bytes.len())
            .min(3);
        if length == 0 {
            return Poll::Pending;
        }
        state.output.extend_from_slice(&bytes[..length]);
        self.changed.notify(usize::MAX);
        Poll::Ready(Ok(length))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn frame(packet: &[u8]) -> Vec<u8> {
    let mut frame = (packet.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(packet);
    frame
}

fn complete_frames(mut bytes: &[u8]) -> Vec<&[u8]> {
    let mut frames = Vec::new();
    while bytes.len() >= 4 {
        let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        if bytes.len() < 4 + length {
            break;
        }
        frames.push(&bytes[4..4 + length]);
        bytes = &bytes[4 + length..];
    }
    frames
}

fn final_frames(bytes: &[u8]) -> Vec<&[u8]> {
    complete_frames(bytes)
        .into_iter()
        .filter(|frame| response_status(frame) != Status::PENDING)
        .collect()
}

pub(super) async fn inspect_text(path: &str, object: impl inspect::InspectMut) -> String {
    let mut inspection = inspect::inspect(path, object);
    inspection.resolve().await;
    inspection.results().to_string()
}

#[test]
fn task_pause_and_inspection_preserve_partial_frames_pending_io_and_responses() {
    DefaultPool::run_with(async |driver| {
        let (fs, control) = controlled(false);
        let server = Server::new("memory", fs.clone()).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("target", 2, 0).await;
        let packet = request(
            Command::WRITE,
            &Client::write_body(file, 0, b"data"),
            client.session,
            client.tree,
            client.message,
        );
        let write_frame = frame(&packet);
        let stream = TestStream::new();
        let mut task = TaskControl::new(tcp::ConnectionTask::new(
            client.connection.clone(),
            stream.clone(),
        ));
        task.insert(driver, "smb-runtime-test", ());
        stream.input(&write_frame[..2]);
        task.start();
        stream.until(|s| s.read == 2).await;
        task.stop().await;
        assert_eq!(inspect_text("receive_prefix_bytes", &task).await, "2");
        task.start();
        stream.input(&write_frame[2..11]);
        stream.until(|s| s.read == 11).await;
        task.stop().await;
        assert_eq!(inspect_text("receive_body_bytes", &task).await, "7");
        task.start();
        stream.input(&write_frame[11..]);
        let call = control.next_call().await;
        let close = frame(&request(
            Command::CLOSE,
            close_body(file).as_bytes(),
            client.session,
            client.tree,
            client.message + 1,
        ));
        stream.input(&close);
        stream
            .until(|s| s.read == write_frame.len() + close.len())
            .await;
        assert_eq!(inspect_text("active_requests", &task).await, "2");
        assert_eq!(
            inspect_text(
                &format!("connection/opens/{}/closing", file.volatile.get()),
                &task
            )
            .await,
            "true"
        );
        task.stop().await;
        assert_eq!(successes(&control, Operation::Write), 0);
        control.release(call.id, Gate::Before).unwrap();
        assert_eq!(successes(&control, Operation::Write), 0);
        stream.writable(9);
        task.start();
        stream.until(|s| s.output.len() == 9).await;
        task.stop().await;
        assert_eq!(successes(&control, Operation::Write), 1);
        assert_eq!(inspect_text("transmit_offset", &task).await, "9");
        let queued: usize = inspect_text("queued_responses", &task)
            .await
            .parse()
            .unwrap();
        let channel: usize = inspect_text("response_channel_frames", &task)
            .await
            .parse()
            .unwrap();
        assert_eq!(queued + channel, 4);
        stream.writable(usize::MAX);
        task.start();
        stream.until(|s| final_frames(&s.output).len() == 2).await;
        assert_eq!(inspect_text("queued_responses", &task).await, "0");
        task.stop().await;
        let bytes = stream.state.lock().output.clone();
        let replies = final_frames(&bytes);
        assert_eq!(replies.len(), 2);
        assert_eq!(complete_frames(&bytes).len(), 4);
        assert_eq!(response_status(replies[0]), Status::SUCCESS);
        assert_eq!(response_status(replies[1]), Status::SUCCESS);
        assert_eq!(successes(&control, Operation::Write), 1);
        task.task_mut().shutdown().await.unwrap();
        assert_eq!(successes(&control, Operation::Close), 1);
    });
}

#[test]
fn excess_credited_requests_do_not_obstruct_cancel_when_every_slot_is_occupied() {
    DefaultPool::run_with(async |driver| {
        let (fs, control) = controlled(true);
        let server = Server::new("memory", fs.clone()).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("target", 2, 0).await;
        let stream = TestStream::new();
        stream.writable(usize::MAX);
        let mut task = TaskControl::new(tcp::ConnectionTask::new(
            client.connection.clone(),
            stream.clone(),
        ));
        task.insert(driver, "smb-full-test", ());
        let first_message = client.message;
        for _ in 0..MAX_REQUESTS {
            stream.input(&frame(&request(
                Command::WRITE,
                &Client::write_body(file, 0, b"x"),
                client.session,
                client.tree,
                client.message,
            )));
            client.message += 1;
        }

        task.start();
        for _ in 0..MAX_REQUESTS {
            control.next_call().await;
        }
        assert_eq!(
            inspect_text("active_requests", &task).await,
            MAX_REQUESTS.to_string()
        );
        let excess_message = client.message;
        stream.input(&frame(&request(
            Command::ECHO,
            SimpleBody {
                structure_size: SimpleBody::STRUCTURE_SIZE.into(),
                reserved: 0.into(),
            }
            .as_bytes(),
            client.session,
            client.tree,
            excess_message,
        )));
        client.message += 1;
        let cancel = request(
            Command::CANCEL,
            SimpleBody {
                structure_size: SimpleBody::STRUCTURE_SIZE.into(),
                reserved: 0.into(),
            }
            .as_bytes(),
            client.session,
            client.tree,
            first_message,
        );
        stream.input(&frame(&cancel));
        stream
            .until(|s| {
                final_frames(&s.output).iter().any(|frame| {
                    let header = Header::read_from_prefix(frame).unwrap().0;
                    header.message_id.get() == first_message && header.status() == Status::CANCELLED
                })
            })
            .await;
        assert!(
            final_frames(&stream.state.lock().output)
                .iter()
                .any(|frame| {
                    let header = Header::read_from_prefix(frame).unwrap().0;
                    header.message_id.get() == excess_message
                        && header.status() == Status::INSUFFICIENT_RESOURCES
                })
        );
        task.stop().await;
        assert_eq!(successes(&control, Operation::Write), 0);
        task.task_mut().shutdown().await.unwrap();
        assert_eq!(successes(&control, Operation::Close), 1);
    });
}

#[test]
fn notify_tcp_retains_events_async_ids_and_partial_output_across_pause() {
    DefaultPool::run_with(async |driver| {
        let memory = MemoryFs::new(1024, 16);
        let (fs, control) = ControlledFs::new(memory.clone());
        control
            .set_plan(
                Operation::Notify,
                Plan {
                    hold_after: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let stream = TestStream::new();
        stream.input(&frame(&request(
            Command::CHANGE_NOTIFY,
            &notify::body(root, NotifyFilter::new().with_file_name(true), false, 1024),
            client.session,
            client.tree,
            client.message,
        )));
        let mut task = TaskControl::new(tcp::ConnectionTask::new(
            client.connection.clone(),
            stream.clone(),
        ));
        task.insert(driver, "smb-notify-pause", ());
        task.start();
        let call = control.next_call().await;
        task.stop().await;
        assert_eq!(inspect_text("notify_waiters", &memory).await, "1");
        let mut writer = Client::new(&server).await;
        let child = writer.open("during-pause", 2, 0).await;
        assert_eq!(control.snapshot(call.id).unwrap().phase, Phase::Executing);
        task.start();
        control.wait_for_phase(call.id, Phase::After).await.unwrap();
        task.stop().await;
        assert_eq!(inspect_text("notify_waiters", &memory).await, "0");
        control.release(call.id, Gate::After).unwrap();
        task.start();
        control
            .wait_for_phase(call.id, Phase::Completed)
            .await
            .unwrap();
        task.stop().await;
        assert_eq!(inspect_text("watch_count", &memory).await, "1");
        stream.writable(5);
        task.start();
        stream.until(|state| state.output.len() == 5).await;
        task.stop().await;
        assert_eq!(inspect_text("transmit_offset", &task).await, "5");
        stream.writable(usize::MAX);
        task.start();
        stream
            .until(|state| complete_frames(&state.output).len() == 2)
            .await;
        task.stop().await;
        let bytes = stream.state.lock().output.clone();
        let frames = complete_frames(&bytes);
        let pending = AsyncHeader::read_from_prefix(frames[0]).unwrap().0;
        let completed = AsyncHeader::read_from_prefix(frames[1]).unwrap().0;
        assert_eq!(Status(pending.status.get()), Status::PENDING);
        assert_eq!(pending.async_id, completed.async_id);
        assert!(completed.flags.async_command());
        assert_eq!(completed.credits.get(), 0);
        assert_eq!(
            notify::changes(frames[1]),
            [(NotifyAction::ADDED, "during-pause".into())]
        );
        writer.close(child).await;
        task.task_mut().shutdown().await.unwrap();
        assert_eq!(inspect_text("watch_count", &memory).await, "0");
        assert_eq!(inspect_text("opens", &memory).await, "0");
        assert!(
            !control
                .calls()
                .iter()
                .any(|call| call.phase == Phase::Abandoned)
        );
    });
}

#[test]
fn tcp_pause_preserves_a_waiting_lock_and_its_partial_interim_response() {
    DefaultPool::run_with(async |driver| {
        let memory = MemoryFs::new(1024, 16);
        let (fs, control) = ControlledFs::new(memory.clone());
        let server = Server::new("memory", fs).unwrap();
        let mut owner = Client::new(&server).await;
        let a = owner.open("paused-lock", 2, 0).await;
        let exclusive = LockFlags::new()
            .with_exclusive_lock(true)
            .with_fail_immediately(true);
        owner
            .ok(Command::LOCK, &locking::body(a, &[(0, 1, exclusive)]))
            .await;
        let mut client = Client::new(&server).await;
        let b = client.open("paused-lock", 1, 0).await;
        control
            .set_plan(
                Operation::Lock,
                Plan {
                    hold_after: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let stream = TestStream::new();
        stream.writable(5);
        stream.input(&frame(&request(
            Command::LOCK,
            &locking::body(b, &[(0, 1, exclusive.with_fail_immediately(false))]),
            client.session,
            client.tree,
            client.message,
        )));
        let mut task = TaskControl::new(tcp::ConnectionTask::new(
            client.connection.clone(),
            stream.clone(),
        ));
        task.insert(driver, "smb-lock-pause", ());
        task.start();
        let call = control.next_call().await;
        stream.until(|state| state.output.len() == 5).await;
        task.stop().await;
        assert_eq!(inspect_text("lock_waiters", &memory).await, "1");
        assert_eq!(inspect_text("transmit_offset", &task).await, "5");
        owner
            .ok(
                Command::LOCK,
                &locking::body(a, &[(0, 1, LockFlags::new().with_unlock(true))]),
            )
            .await;
        assert_eq!(inspect_text("lock_count", &memory).await, "0");
        task.start();
        control.wait_for_phase(call.id, Phase::After).await.unwrap();
        task.stop().await;
        assert_eq!(inspect_text("lock_count", &memory).await, "1");
        control.release(call.id, Gate::After).unwrap();
        stream.writable(usize::MAX);
        task.start();
        stream
            .until(|state| complete_frames(&state.output).len() == 2)
            .await;
        task.stop().await;
        let bytes = stream.state.lock().output.clone();
        let frames = complete_frames(&bytes);
        let pending = AsyncHeader::read_from_prefix(frames[0]).unwrap().0;
        let completed = AsyncHeader::read_from_prefix(frames[1]).unwrap().0;
        assert_eq!(Status(pending.status.get()), Status::PENDING);
        assert_eq!(pending.async_id, completed.async_id);
        assert_eq!(Status(completed.status.get()), Status::SUCCESS);
        assert_eq!(completed.credits.get(), 0);
        assert_eq!(&frames[1][64..], &[4, 0, 0, 0]);
        task.task_mut().shutdown().await.unwrap();
        owner.close(a).await;
        assert_eq!(inspect_text("lock_count", &memory).await, "0");
        assert_eq!(inspect_text("lock_waiters", &memory).await, "0");
        assert_eq!(inspect_text("opens", &memory).await, "0");
        assert!(
            !control
                .calls()
                .iter()
                .any(|call| call.phase == Phase::Abandoned)
        );
    });
}

#[test]
fn peer_eof_cancels_pending_notify_and_releases_opens_without_output() {
    block_on(async {
        for partial_frame in [false, true] {
            let memory = MemoryFs::new(1024, 16);
            let (fs, control) = ControlledFs::new(memory.clone());
            control
                .set_plan(
                    Operation::Notify,
                    Plan {
                        hold_after: true,
                        ..Plan::default()
                    },
                )
                .unwrap();
            let server = Server::new("memory", fs).unwrap();
            let mut client = Client::new(&server).await;
            let root = client.open("", 1, 1).await;
            let stream = TestStream::new();
            stream.input(&frame(&request(
                Command::CHANGE_NOTIFY,
                &notify::body(root, NotifyFilter::new().with_file_name(true), false, 1024),
                client.session,
                client.tree,
                client.message,
            )));
            let mut connection = client.connection.clone();
            let mut socket = stream.clone();
            let mut serving = std::pin::pin!(tcp::serve(&mut connection, &mut socket));
            assert!(futures::poll!(&mut serving).is_pending());
            let call = control.next_call().await;
            assert_eq!(inspect_text("notify_waiters", &memory).await, "1");
            if partial_frame {
                stream.input(&[0, 0]);
            }
            stream.state.lock().eof = true;
            stream.reader.wake();
            for _ in 0..32 {
                assert!(futures::poll!(&mut serving).is_pending());
                if control.snapshot(call.id).unwrap().phase == Phase::After {
                    break;
                }
            }
            let snapshot = control.snapshot(call.id).unwrap();
            assert_eq!(snapshot.phase, Phase::After);
            assert_eq!(snapshot.status, Some(Status::CANCELLED));
            assert_eq!(inspect_text("notify_waiters", &memory).await, "0");
            // Even after EOF, an obtained provider result must be drained, not dropped.
            control.release(call.id, Gate::After).unwrap();
            if !partial_frame {
                for _ in 0..32 {
                    assert!(futures::poll!(&mut serving).is_pending());
                }
                assert_eq!(inspect_text("watch_count", &memory).await, "0");
                assert_eq!(inspect_text("opens", &memory).await, "0");
                assert!(stream.state.lock().output.is_empty());
                stream.writable(usize::MAX);
            }
            let result = serving.await;
            if partial_frame {
                assert!(matches!(result, Err(Error::Io(_))));
            } else {
                result.unwrap();
            }
            assert_eq!(inspect_text("watch_count", &memory).await, "0");
            assert_eq!(inspect_text("opens", &memory).await, "0");
            assert_eq!(successes(&control, Operation::Close), 1);
            if partial_frame {
                assert!(stream.state.lock().output.is_empty());
            } else {
                let bytes = stream.state.lock().output.clone();
                let frames = complete_frames(&bytes);
                assert_eq!(frames.len(), 2);
                assert_eq!(response_status(frames[1]), Status::CANCELLED);
            }
            assert!(
                !control
                    .calls()
                    .iter()
                    .any(|call| call.phase == Phase::Abandoned)
            );
        }
    });
}

#[test]
fn notify_shutdown_drains_a_saturated_connection_without_output_or_events() {
    DefaultPool::run_with(async |driver| {
        let memory = MemoryFs::new(1024, 16);
        let (fs, control) = ControlledFs::new(memory.clone());
        control
            .set_plan(
                Operation::Notify,
                Plan {
                    hold_after: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let root = client.open("", 1, 1).await;
        let stream = TestStream::new();
        for _ in 0..MAX_REQUESTS {
            stream.input(&frame(&request(
                Command::CHANGE_NOTIFY,
                &notify::body(root, NotifyFilter::new().with_file_name(true), false, 1024),
                client.session,
                client.tree,
                client.message,
            )));
            client.message += 1;
        }
        let mut task = TaskControl::new(tcp::ConnectionTask::new(
            client.connection.clone(),
            stream.clone(),
        ));
        task.insert(driver, "smb-notify-shutdown", ());
        task.start();
        let call = control.next_call().await;
        stream.until(|state| state.input.is_empty()).await;
        task.stop().await;
        assert_eq!(
            inspect_text("active_requests", &task).await,
            MAX_REQUESTS.to_string()
        );
        assert_eq!(inspect_text("notify_waiters", &memory).await, "1");
        // Already executing calls retain their plans; canceled successors need no gate.
        control
            .set_plan(Operation::Notify, Plan::default())
            .unwrap();
        control.release(call.id, Gate::After).unwrap();
        task.task_mut().shutdown().await.unwrap();
        assert!(stream.state.lock().output.is_empty());
        assert_eq!(inspect_text("notify_waiters", &memory).await, "0");
        assert_eq!(inspect_text("watch_count", &memory).await, "0");
        assert_eq!(inspect_text("opens", &memory).await, "0");
        assert!(
            !control
                .calls()
                .iter()
                .any(|call| call.phase == Phase::Abandoned)
        );
    });
}

#[test]
fn continuously_ready_traffic_still_allows_inspection_and_pause() {
    DefaultPool::run_with(async |driver| {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let client = Client::new(&server).await;
        let stream = TestStream::new();
        stream.writable(usize::MAX);
        stream.state.lock().repeat_echo = Some((client.session, client.tree, client.message));
        let mut task = TaskControl::new(tcp::ConnectionTask::new(
            client.connection.clone(),
            stream.clone(),
        ));
        task.insert(driver, "smb-ready-test", ());
        let (finished, done) = async_channel::bounded(1);
        let control = std::thread::spawn(move || {
            block_on(async {
                task.start();
                stream.until(|s| s.read >= 4).await;
                assert_eq!(
                    inspect_text("request_limit", &task).await,
                    MAX_REQUESTS.to_string()
                );
                assert!(task.stop().await);
                task.task_mut().shutdown().await.unwrap();
                finished.send(()).await.unwrap();
            })
        });
        done.recv().await.unwrap();
        control.join().unwrap();
    });
}

#[test]
fn tcp_service_pause_preserves_existing_connections() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    DefaultPool::run_with(async |driver| {
        use futures::{AsyncReadExt, AsyncWriteExt};
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = pal_async::socket::PolledSocket::new(&driver, client).unwrap();
        let mut service = tcp::Server::new(driver, listener, server).unwrap();
        assert_eq!(inspect_text("running", &service).await, "false");
        assert!(service.start());
        client
            .write_all(&frame(&request(
                Command::NEGOTIATE,
                &negotiate_body(),
                0,
                0,
                0,
            )))
            .await
            .unwrap();
        let mut prefix = [0; 4];
        client.read_exact(&mut prefix).await.unwrap();
        let mut response = vec![0; u32::from_be_bytes(prefix) as usize];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response_status(&response), Status::SUCCESS);
        assert!(service.stop().await);
        assert_eq!(inspect_text("running", &service).await, "false");
        let echo = SimpleBody {
            structure_size: SimpleBody::STRUCTURE_SIZE.into(),
            reserved: 0.into(),
        };
        client
            .write_all(&frame(&request(Command::ECHO, echo.as_bytes(), 0, 0, 1)))
            .await
            .unwrap();
        assert!(service.start());
        client.read_exact(&mut prefix).await.unwrap();
        response.resize(u32::from_be_bytes(prefix) as usize, 0);
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response_status(&response), Status::SUCCESS);
        service.shutdown().await.unwrap();
        assert!(!service.start());
    });
}

#[test]
fn shutdown_closes_other_opens_and_retains_failed_close_for_retry() {
    block_on(async {
        let (fs, control) = controlled(false);
        let server = Server::new("memory", fs.clone()).unwrap();
        let mut client = Client::new(&server).await;
        client.open("first", 2, 0).await;
        client.open("second", 2, 0).await;
        control
            .plan_next(
                Operation::Close,
                Plan {
                    failure: Some(Status::ACCESS_DENIED),
                    ..Plan::default()
                },
            )
            .unwrap();
        assert!(matches!(
            client.connection.shutdown().await,
            Err(Error::Backend(Status::ACCESS_DENIED))
        ));
        assert_eq!(inspect_text("backend/opens", &fs).await, "1");
        client.connection.shutdown().await.unwrap();
        assert_eq!(inspect_text("backend/opens", &fs).await, "0");
    });
}
