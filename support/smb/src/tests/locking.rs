// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::runtime::inspect_text;
use super::*;
use crate::test_support::{ControlledFs, Gate, Operation, Phase, Plan};
use test_with_tracing::test;

const SHARED: LockFlags = LockFlags::new()
    .with_shared_lock(true)
    .with_fail_immediately(true);
const EXCLUSIVE: LockFlags = LockFlags::new()
    .with_exclusive_lock(true)
    .with_fail_immediately(true);
const UNLOCK: LockFlags = LockFlags::new().with_unlock(true);

pub(super) fn body(file: FileId, locks: &[(u64, u64, LockFlags)]) -> Vec<u8> {
    let mut request = LockRequest::new_zeroed();
    request.structure_size = LockRequest::STRUCTURE_SIZE.into();
    request.lock_count = (locks.len() as u16).into();
    request.lock_sequence = u32::MAX.into();
    request.file_id = file;
    let mut bytes = request.as_bytes()[..std::mem::offset_of!(LockRequest, first_lock)].to_vec();
    for &(offset, length, flags) in locks {
        bytes.extend_from_slice(
            LockElement {
                offset: offset.into(),
                length: length.into(),
                flags,
                reserved: u32::MAX.into(),
            }
            .as_bytes(),
        );
    }
    bytes
}

fn accept<B: FileSystem>(
    client: &mut Client<B>,
    file: FileId,
    offset: u64,
    length: u64,
) -> Request<B> {
    let packet = request(
        Command::LOCK,
        &body(
            file,
            &[(offset, length, EXCLUSIVE.with_fail_immediately(false))],
        ),
        client.session,
        client.tree,
        client.message,
    );
    client.message += 1;
    client.connection.request(packet).unwrap()
}

async fn lock<B: FileSystem>(
    client: &mut Client<B>,
    file: FileId,
    locks: &[(u64, u64, LockFlags)],
    expected: Status,
) {
    let bytes = client.send(Command::LOCK, &body(file, locks)).await;
    assert_eq!(response_status(&bytes), expected);
    if expected == Status::SUCCESS {
        assert_eq!(&bytes[64..], &[4, 0, 0, 0]);
    }
}

#[test]
fn shared_and_exclusive_locks_enforce_stream_wide_conflicts_and_io() {
    block_on(async {
        for flags in [SHARED, EXCLUSIVE] {
            let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
            let mut first = Client::new(&server).await;
            let mut second = Client::new(&server).await;
            let a = first.open("ranges", 2, 0).await;
            first
                .ok(Command::WRITE, &Client::write_body(a, 0, b"abcdefghij"))
                .await;
            let b = first.open("ranges", 1, 0).await;
            let c = second.open("ranges", 1, 0).await;
            lock(&mut first, a, &[(2, 4, flags)], Status::SUCCESS).await;
            let write_status = if flags.exclusive_lock() {
                Status::SUCCESS
            } else {
                Status::FILE_LOCK_CONFLICT
            };
            assert_eq!(
                response_status(
                    &first
                        .send(Command::WRITE, &Client::write_body(a, 2, b"x"))
                        .await
                ),
                write_status
            );
            assert_eq!(response_status(&first.read(a, 2, 1).await), Status::SUCCESS);
            for (client, other) in [(&mut first, b), (&mut second, c)] {
                assert_eq!(
                    response_status(
                        &client
                            .send(Command::WRITE, &Client::write_body(other, 2, b"x"))
                            .await
                    ),
                    Status::FILE_LOCK_CONFLICT
                );
                assert_eq!(
                    response_status(&client.read(other, 2, 1).await),
                    if flags.exclusive_lock() {
                        Status::FILE_LOCK_CONFLICT
                    } else {
                        Status::SUCCESS
                    }
                );
                client
                    .ok(Command::WRITE, &Client::write_body(other, 6, b"x"))
                    .await;
                lock(
                    client,
                    other,
                    &[(3, 1, EXCLUSIVE)],
                    Status::LOCK_NOT_GRANTED,
                )
                .await;
                lock(client, other, &[(2, 4, UNLOCK)], Status::RANGE_NOT_LOCKED).await;
            }
            lock(&mut first, a, &[(2, 3, UNLOCK)], Status::RANGE_NOT_LOCKED).await;
            lock(&mut first, a, &[(2, 4, UNLOCK)], Status::SUCCESS).await;
            lock(&mut second, c, &[(2, 4, EXCLUSIVE)], Status::SUCCESS).await;
            second.close(c).await;
            assert_eq!(response_status(&first.read(b, 2, 1).await), Status::SUCCESS);
        }
    });
}

#[test]
fn literal_lock_packet_has_independent_offsets_flags_and_reserved_field_checks() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("literal-lock", 2, 0).await;
        let other = client.open("literal-lock", 1, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(file, 0, b"abcdefgh"))
            .await;
        let mut bytes = [0u8; 48];
        bytes[0] = 48;
        bytes[2] = 1;
        bytes[8..24].copy_from_slice(file.as_bytes());
        bytes[24] = 2;
        bytes[32] = 4;
        bytes[40] = 0x12;
        bytes[44..48].fill(0xff);
        let reply = client.ok(Command::LOCK, &bytes).await;
        assert_eq!(&reply[64..], &[4, 0, 0, 0]);
        assert_eq!(
            response_status(&client.read(other, 2, 1).await),
            Status::FILE_LOCK_CONFLICT
        );
        bytes[40] = 4;
        client.ok(Command::LOCK, &bytes).await;
        assert_eq!(&client.read(other, 2, 1).await[80..], b"c");
    });
}

#[test]
fn zero_length_maximum_offsets_and_stacked_locks_use_exact_unlocks() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let a = client.open("edges", 2, 0).await;
        let b = client.open("edges", 1, 0).await;
        for file in [a, b] {
            lock(&mut client, file, &[(0, 0, EXCLUSIVE)], Status::SUCCESS).await;
        }
        lock(&mut client, a, &[(u64::MAX, 1, EXCLUSIVE)], Status::SUCCESS).await;
        lock(
            &mut client,
            b,
            &[(u64::MAX, 1, SHARED)],
            Status::LOCK_NOT_GRANTED,
        )
        .await;
        lock(
            &mut client,
            a,
            &[(u64::MAX, 2, EXCLUSIVE)],
            Status::INVALID_LOCK_RANGE,
        )
        .await;
        lock(
            &mut client,
            a,
            &[(u64::MAX, 2, UNLOCK)],
            Status::INVALID_LOCK_RANGE,
        )
        .await;
        lock(&mut client, a, &[(u64::MAX, 1, UNLOCK)], Status::SUCCESS).await;
        lock(&mut client, a, &[(1, 4, EXCLUSIVE)], Status::SUCCESS).await;
        lock(
            &mut client,
            b,
            &[(3, 0, EXCLUSIVE)],
            Status::LOCK_NOT_GRANTED,
        )
        .await;
        lock(
            &mut client,
            a,
            &[(1, 4, SHARED), (1, 4, SHARED)],
            Status::SUCCESS,
        )
        .await;
        lock(
            &mut client,
            a,
            &[(1, 4, EXCLUSIVE)],
            Status::LOCK_NOT_GRANTED,
        )
        .await;
        lock(&mut client, a, &[(1, 4, UNLOCK)], Status::SUCCESS).await;
        // The exclusive match is removed first, so another open can now share.
        lock(&mut client, b, &[(1, 4, SHARED)], Status::SUCCESS).await;
        lock(
            &mut client,
            a,
            &[(1, 4, UNLOCK), (1, 4, UNLOCK)],
            Status::SUCCESS,
        )
        .await;
        lock(&mut client, a, &[(1, 4, UNLOCK)], Status::RANGE_NOT_LOCKED).await;
        client.close(b).await;
        lock(&mut client, a, &[(1, 4, EXCLUSIVE)], Status::SUCCESS).await;
    });
}

#[test]
fn arrays_roll_back_conflicts_but_preserve_partial_unlocks_and_invalid_flag_prefixes() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let a = client.open("arrays", 2, 0).await;
        let b = client.open("arrays", 1, 0).await;
        lock(&mut client, b, &[(10, 1, EXCLUSIVE)], Status::SUCCESS).await;
        lock(
            &mut client,
            a,
            &[(1, 1, EXCLUSIVE), (10, 1, EXCLUSIVE)],
            Status::LOCK_NOT_GRANTED,
        )
        .await;
        lock(&mut client, a, &[(1, 1, UNLOCK)], Status::RANGE_NOT_LOCKED).await;
        lock(&mut client, a, &[(30, 1, EXCLUSIVE)], Status::SUCCESS).await;
        lock(
            &mut client,
            a,
            &[(30, 1, SHARED), (10, 1, EXCLUSIVE)],
            Status::LOCK_NOT_GRANTED,
        )
        .await;
        lock(&mut client, b, &[(30, 1, SHARED)], Status::LOCK_NOT_GRANTED).await;
        lock(&mut client, a, &[(30, 1, UNLOCK)], Status::SUCCESS).await;
        lock(&mut client, a, &[(30, 1, UNLOCK)], Status::RANGE_NOT_LOCKED).await;
        lock(
            &mut client,
            a,
            &[(1, 1, EXCLUSIVE), (2, 1, SHARED.with_unlock(true))],
            Status::INVALID_PARAMETER,
        )
        .await;
        lock(
            &mut client,
            b,
            &[(1, 1, EXCLUSIVE)],
            Status::LOCK_NOT_GRANTED,
        )
        .await;
        lock(
            &mut client,
            a,
            &[(1, 1, UNLOCK), (2, 1, UNLOCK)],
            Status::RANGE_NOT_LOCKED,
        )
        .await;
        lock(&mut client, b, &[(1, 1, EXCLUSIVE)], Status::SUCCESS).await;
        lock(
            &mut client,
            a,
            &[
                (20, 1, EXCLUSIVE),
                (21, 1, EXCLUSIVE.with_fail_immediately(false)),
            ],
            Status::INVALID_PARAMETER,
        )
        .await;
        lock(&mut client, a, &[(20, 1, UNLOCK)], Status::RANGE_NOT_LOCKED).await;
        lock(
            &mut client,
            b,
            &[(1, 1, UNLOCK), (10, 1, UNLOCK.with_shared_lock(true))],
            Status::INVALID_PARAMETER,
        )
        .await;
        lock(&mut client, a, &[(1, 1, EXCLUSIVE)], Status::SUCCESS).await;
        lock(
            &mut client,
            a,
            &[(10, 1, EXCLUSIVE)],
            Status::LOCK_NOT_GRANTED,
        )
        .await;
        let mut truncated = body(a, &[(30, 1, EXCLUSIVE), (40, 1, EXCLUSIVE)]);
        truncated.pop();
        assert_eq!(
            response_status(&client.send(Command::LOCK, &truncated).await),
            Status::INVALID_PARAMETER
        );
        lock(&mut client, a, &[(30, 1, UNLOCK)], Status::RANGE_NOT_LOCKED).await;
        let mut zero = body(a, &[(30, 1, EXCLUSIVE)]);
        zero[2..4].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            response_status(&client.send(Command::LOCK, &zero).await),
            Status::INVALID_PARAMETER
        );
        lock(
            &mut client,
            a,
            &[(30, 1, LockFlags::from_bits(0x80000012))],
            Status::INVALID_PARAMETER,
        )
        .await;
        let root = client.open("", 1, 1).await;
        lock(
            &mut client,
            root,
            &[(0, 1, EXCLUSIVE)],
            Status::INVALID_PARAMETER,
        )
        .await;
    });
}

#[test]
fn pending_lock_cancel_uses_async_identity_and_does_not_obstruct_unlock_or_flush() {
    block_on(async {
        let memory = MemoryFs::new(1024, 16);
        let server = Server::new("memory", memory.clone()).unwrap();
        let mut client = Client::new(&server).await;
        let a = client.open("pending", 2, 0).await;
        let b = client.open("pending", 1, 0).await;
        lock(&mut client, a, &[(0, 1, EXCLUSIVE)], Status::SUCCESS).await;
        let pending = accept(&mut client, b, 0, 1);
        let (sender, receiver) = async_channel::bounded(4);
        let mut executing = std::pin::pin!(pending.execute_with_interim(sender));
        assert!(futures::poll!(&mut executing).is_pending());
        let interim = receiver.recv().await.unwrap();
        assert_eq!(response_status(&interim), Status::PENDING);
        let identity = AsyncHeader::read_from_prefix(&interim).unwrap().0;
        assert_eq!(inspect_text("lock_waiters", &memory).await, "1");
        client
            .ok(
                Command::FLUSH,
                FlushRequest {
                    structure_size: FlushRequest::STRUCTURE_SIZE.into(),
                    reserved1: 0.into(),
                    reserved2: 0.into(),
                    file_id: b,
                }
                .as_bytes(),
            )
            .await;
        let mut cancel = request(
            Command::CANCEL,
            SimpleBody {
                structure_size: SimpleBody::STRUCTURE_SIZE.into(),
                reserved: 0.into(),
            }
            .as_bytes(),
            client.session,
            client.tree,
            0,
        );
        Header::mut_from_prefix(&mut cancel)
            .unwrap()
            .0
            .flags
            .set_async_command(true);
        cancel[32..40].copy_from_slice(&(identity.async_id.get() + 1).to_le_bytes());
        client.connection.cancel(&cancel).unwrap();
        assert!(futures::poll!(&mut executing).is_pending());
        cancel[32..40].copy_from_slice(&identity.async_id.get().to_le_bytes());
        client.connection.cancel(&cancel).unwrap();
        executing.await.unwrap();
        let final_reply = receiver.recv().await.unwrap();
        assert_eq!(response_status(&final_reply), Status::CANCELLED);
        assert_eq!(
            AsyncHeader::read_from_prefix(&final_reply)
                .unwrap()
                .0
                .async_id,
            identity.async_id
        );
        assert_eq!(inspect_text("lock_waiters", &memory).await, "0");
        let mut pending = std::pin::pin!(accept(&mut client, b, 0, 1).execute());
        assert!(futures::poll!(&mut pending).is_pending());
        lock(&mut client, a, &[(0, 1, UNLOCK)], Status::SUCCESS).await;
        assert_eq!(response_status(&pending.await.unwrap()), Status::SUCCESS);
        client.close(b).await;
        lock(&mut client, a, &[(0, 1, EXCLUSIVE)], Status::SUCCESS).await;
    });
}

#[test]
fn rollback_failure_is_reported_without_hiding_retained_locks() {
    block_on(async {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 16));
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let owner = client.open("cleanup-error", 2, 0).await;
        let peer = client.open("cleanup-error", 1, 0).await;
        client
            .ok(Command::WRITE, &Client::write_body(owner, 0, &[b'a'; 16]))
            .await;
        lock(&mut client, owner, &[(2, 4, EXCLUSIVE)], Status::SUCCESS).await;
        lock(&mut client, peer, &[(10, 1, EXCLUSIVE)], Status::SUCCESS).await;
        control
            .set_plan(
                Operation::RollbackLock,
                Plan {
                    failure: Some(Status::ACCESS_DENIED),
                    ..Plan::default()
                },
            )
            .unwrap();
        lock(
            &mut client,
            owner,
            &[(2, 4, SHARED), (10, 1, EXCLUSIVE)],
            Status::ACCESS_DENIED,
        )
        .await;
        assert_eq!(
            response_status(&client.read(peer, 2, 1).await),
            Status::FILE_LOCK_CONFLICT
        );
        assert_eq!(
            response_status(
                &client
                    .send(Command::WRITE, &Client::write_body(owner, 2, b"x"))
                    .await
            ),
            Status::FILE_LOCK_CONFLICT
        );
        lock(&mut client, owner, &[(2, 4, UNLOCK)], Status::SUCCESS).await;
        assert_eq!(
            response_status(&client.read(peer, 2, 1).await),
            Status::SUCCESS
        );
        lock(&mut client, owner, &[(2, 4, UNLOCK)], Status::SUCCESS).await;
        client
            .ok(Command::WRITE, &Client::write_body(peer, 2, b"x"))
            .await;
    });
}

#[test]
fn close_cancels_own_waiters_and_releases_locks_for_other_connections() {
    block_on(async {
        let memory = MemoryFs::new(1024, 16);
        let server = Server::new("memory", memory.clone()).unwrap();
        let mut first = Client::new(&server).await;
        let mut second = Client::new(&server).await;
        let a = first.open("close", 2, 0).await;
        let b = second.open("close", 1, 0).await;
        lock(&mut first, a, &[(0, 1, EXCLUSIVE)], Status::SUCCESS).await;
        let mut self_waiter = std::pin::pin!(accept(&mut first, a, 0, 1).execute());
        let mut other_waiter = std::pin::pin!(accept(&mut second, b, 0, 1).execute());
        assert!(futures::poll!(&mut self_waiter).is_pending());
        assert!(futures::poll!(&mut other_waiter).is_pending());
        let ((), own) = futures::join!(first.close(a), &mut self_waiter);
        assert_eq!(response_status(&own.unwrap()), Status::CANCELLED);
        assert_eq!(
            response_status(&other_waiter.await.unwrap()),
            Status::SUCCESS
        );
        assert_eq!(inspect_text("lock_waiters", &memory).await, "0");
        assert_eq!(inspect_text("lock_count", &memory).await, "1");
        second.connection.shutdown().await.unwrap();
        assert_eq!(inspect_text("lock_count", &memory).await, "0");
        assert_eq!(inspect_text("opens", &memory).await, "0");
    });
}

#[test]
fn obtained_locks_survive_late_cancel_and_close_drains_delayed_results() {
    block_on(async {
        let memory = MemoryFs::new(1024, 16);
        let (fs, control) = ControlledFs::new(memory.clone());
        let server = Server::new("memory", fs).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("late", 2, 0).await;
        control
            .set_plan(
                Operation::Lock,
                Plan {
                    hold_after: true,
                    ..Plan::default()
                },
            )
            .unwrap();
        let message = client.message;
        let mut pending = std::pin::pin!(accept(&mut client, file, 0, 1).execute());
        assert!(futures::poll!(&mut pending).is_pending());
        let call = control.next_call().await;
        assert_eq!(control.snapshot(call.id).unwrap().phase, Phase::After);
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
        let mut close = std::pin::pin!(client.close(file));
        assert!(futures::poll!(&mut close).is_pending());
        assert_eq!(inspect_text("lock_count", &memory).await, "1");
        control.release(call.id, Gate::After).unwrap();
        assert_eq!(response_status(&pending.await.unwrap()), Status::SUCCESS);
        close.await;
        assert_eq!(inspect_text("lock_count", &memory).await, "0");
        assert!(
            !control
                .calls()
                .iter()
                .any(|call| call.phase == Phase::Abandoned)
        );
    });
}

#[test]
fn full_admission_does_not_obstruct_lock_cancellation_and_close() {
    block_on(async {
        let memory = MemoryFs::new(1024, 16);
        let server = Server::new("memory", memory.clone()).unwrap();
        let mut owner = Client::new(&server).await;
        let a = owner.open("full", 2, 0).await;
        lock(&mut owner, a, &[(0, 1, EXCLUSIVE)], Status::SUCCESS).await;
        let mut client = Client::new(&server).await;
        let b = client.open("full", 1, 0).await;
        let message = client.message;
        let mut cancelled_before_poll = std::pin::pin!(accept(&mut client, b, 0, 1).execute());
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
        assert_eq!(
            response_status(&cancelled_before_poll.as_mut().await.unwrap()),
            Status::CANCELLED
        );
        assert_eq!(inspect_text("lock_waiters", &memory).await, "0");
        let first = client.message;
        let mut waiters: Vec<_> = (0..MAX_REQUESTS)
            .map(|_| Box::pin(accept(&mut client, b, 0, 1).execute()))
            .collect();
        for waiter in &mut waiters {
            assert!(futures::poll!(waiter).is_pending());
        }
        assert_eq!(
            inspect_text("lock_waiters", &memory).await,
            MAX_REQUESTS.to_string()
        );
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
                first + MAX_REQUESTS as u64 - 1,
            ))
            .unwrap();
        assert_eq!(
            response_status(&waiters.pop().unwrap().await.unwrap()),
            Status::CANCELLED
        );
        let ((), replies) = futures::join!(client.close(b), futures::future::join_all(waiters));
        assert!(
            replies
                .iter()
                .all(|reply| response_status(reply.as_ref().unwrap()) == Status::CANCELLED)
        );
        assert_eq!(inspect_text("lock_waiters", &memory).await, "0");
        assert_eq!(inspect_text("lock_count", &memory).await, "1");
        owner.close(a).await;
        assert_eq!(inspect_text("lock_count", &memory).await, "0");
    });
}

#[test]
fn compound_locks_allow_immediate_operations_and_tail_waits_only() {
    block_on(async {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("compound", 2, 0).await;
        let packet = compound::packet(
            &mut client,
            vec![
                (Command::LOCK, body(file, &[(0, 1, EXCLUSIVE)])),
                (Command::LOCK, body(FileId::RELATED, &[(0, 1, UNLOCK)])),
                (Command::CLOSE, compound::close(FileId::RELATED)),
            ],
            true,
        );
        let reply = client.connection.process(&packet).await.unwrap();
        assert!(
            compound::responses(&reply)
                .iter()
                .all(|reply| response_status(reply) == Status::SUCCESS)
        );
        let file = client.open("compound", 1, 0).await;
        let packet = compound::packet(
            &mut client,
            vec![
                (
                    Command::LOCK,
                    body(file, &[(0, 1, EXCLUSIVE.with_fail_immediately(false))]),
                ),
                (Command::CLOSE, compound::close(FileId::RELATED)),
            ],
            true,
        );
        let reply = client.connection.process(&packet).await.unwrap();
        assert!(
            compound::responses(&reply)
                .iter()
                .all(|reply| response_status(reply) == Status::NOT_SUPPORTED)
        );
        client.close(file).await;
        let packet = compound::packet(
            &mut client,
            vec![
                (
                    Command::CREATE,
                    create_body(
                        "tail",
                        AccessMask::FILE_ALL_ACCESS.into_bits(),
                        7,
                        2,
                        0,
                        &[],
                    ),
                ),
                (
                    Command::LOCK,
                    body(
                        FileId::RELATED,
                        &[(0, 1, EXCLUSIVE.with_fail_immediately(false))],
                    ),
                ),
            ],
            true,
        );
        let reply = client.connection.process(&packet).await.unwrap();
        let replies = compound::responses(&reply);
        assert!(
            replies
                .iter()
                .all(|reply| response_status(reply) == Status::SUCCESS)
        );
        let file = read_body::<CreateResponse>(replies[0]).unwrap().file_id;
        lock(&mut client, file, &[(0, 1, UNLOCK)], Status::SUCCESS).await;
        client.close(file).await;
    });
}

#[test]
fn provider_lock_and_waiter_quotas_recover_after_cancellation_and_close() {
    block_on(async {
        let fs = MemoryFs::new(1024, 16);
        let context = RequestContext::new(1);
        let (file, _) = fs
            .open(
                "bounded",
                OpenOptions {
                    access: AccessMask::FILE_ALL_ACCESS.into_bits(),
                    share_access: 7,
                    disposition: 2,
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
        let range = ByteRange {
            offset: 0,
            length: 1,
        };
        for _ in 0..4096 {
            fs.lock(&file, range, false, true, &context).await.unwrap();
        }
        assert_eq!(
            fs.lock(
                &file,
                ByteRange {
                    offset: 1,
                    length: 1
                },
                false,
                true,
                &context
            )
            .await,
            Err(Status::INSUFFICIENT_RESOURCES)
        );
        let contexts: Vec<_> = (0..1024).map(|id| RequestContext::new(id + 2)).collect();
        let mut waiters: Vec<_> = contexts
            .iter()
            .map(|request| fs.lock(&file, range, true, false, request))
            .collect();
        for waiter in &mut waiters {
            assert!(futures::poll!(waiter).is_pending());
        }
        assert_eq!(inspect_text("lock_waiters", &fs).await, "1024");
        assert_eq!(
            fs.lock(&file, range, true, false, &context).await,
            Err(Status::INSUFFICIENT_RESOURCES)
        );
        for request in &contexts {
            request.cancel();
        }
        for waiter in waiters {
            assert_eq!(waiter.await, Err(Status::CANCELLED));
        }
        assert_eq!(inspect_text("lock_waiters", &fs).await, "0");
        fs.unlock(&file, range, &context).await.unwrap();
        let id = fs
            .lock(
                &file,
                ByteRange {
                    offset: 1,
                    length: 1,
                },
                true,
                true,
                &context,
            )
            .await
            .unwrap();
        fs.rollback_lock(&file, id, &context).await.unwrap();
        fs.close(&file, &context).await.unwrap();
        assert_eq!(inspect_text("lock_count", &fs).await, "0");
        assert_eq!(inspect_text("opens", &fs).await, "0");
        drop(file);
        let (file, _) = fs
            .open(
                "bounded",
                OpenOptions {
                    access: AccessMask::FILE_ALL_ACCESS.into_bits(),
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
        fs.lock(&file, range, true, true, &context).await.unwrap();
        drop(file);
        assert_eq!(inspect_text("lock_count", &fs).await, "0");
        assert_eq!(inspect_text("opens", &fs).await, "0");
    });
}
