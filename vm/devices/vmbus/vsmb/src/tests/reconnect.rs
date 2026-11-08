// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::FutureExt;
use vmbus_channel::gpadl::{GpadlId, GpadlMap};
use vmbus_channel::gpadl_ring::AlignedGpadlView;
use vmbus_ring::{IncomingRing, OutgoingRing, gparange::MultiPagedRangeBuf};
use vmcore::vm_task::{SingleDriverBackend, VmTaskDriverSource};

fn channels(memory: &GuestMemory) -> (RawAsyncChannel<GpadlRingMem>, BytePipe<GpadlRingMem>) {
    let map = GpadlMap::new();
    map.add(
        GpadlId(1),
        MultiPagedRangeBuf::from_range_buffer(1, vec![16384, 0, 1, 2, 3]).unwrap(),
    );
    map.add(
        GpadlId(2),
        MultiPagedRangeBuf::from_range_buffer(1, vec![16384, 4, 5, 6, 7]).unwrap(),
    );
    let view = map.view();
    let ring = |id| {
        GpadlRingMem::new(
            AlignedGpadlView::new(view.map(GpadlId(id)).unwrap()).unwrap(),
            memory,
        )
        .unwrap()
    };
    let (host_signal, guest_signal) = vmbus_channel::connected_async_channels(4096);
    let host = RawAsyncChannel {
        in_ring: IncomingRing::new(ring(1)).unwrap(),
        out_ring: OutgoingRing::new(ring(2)).unwrap(),
        signal: host_signal.signal,
    };
    let guest = RawAsyncChannel {
        in_ring: IncomingRing::new(ring(2)).unwrap(),
        out_ring: OutgoingRing::new(ring(1)).unwrap(),
        signal: guest_signal.signal,
    };
    (host, BytePipe::new(guest).unwrap())
}

async fn drive<T>(device: &mut VsmbDevice, operation: impl Future<Output = T>) -> T {
    match futures::future::select(
        std::pin::pin!(operation),
        std::pin::pin!(device.channel.as_mut().unwrap().process()),
    )
    .await
    {
        futures::future::Either::Left((result, _)) => result,
        futures::future::Either::Right((result, _)) => {
            panic!("device stopped unexpectedly: {result:?}")
        }
    }
}

pub(super) async fn connect<S: futures::AsyncRead + futures::AsyncWrite + Unpin>(
    guest: &mut S,
) -> (u64, u32) {
    guest
        .write_all(&[1, 0, 0, 8, 1, 0, 0, 0, 255, 255, 255, 255])
        .await
        .unwrap();
    let mut reply = [0; 12];
    guest.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [1, 0, 0, 8, 1, 0, 0, 0, 1, 0, 0, 0]);
    let mut negotiate = NegotiateRequest::new_zeroed();
    negotiate.structure_size = NegotiateRequest::STRUCTURE_SIZE.into();
    negotiate.dialect_count = 1.into();
    let body = [negotiate.as_bytes(), &0x0210u16.to_le_bytes()].concat();
    guest
        .write_all(&frame(Command::NEGOTIATE, 0, 0, 0, &body))
        .await
        .unwrap();
    let response = receive(guest).await;
    assert_eq!(
        Header::read_from_prefix(&response).unwrap().0.status.get(),
        0
    );
    let negotiated = NegotiateResponse::read_from_prefix(&response[64..])
        .unwrap()
        .0;
    assert_eq!(negotiated.dialect.get(), 0x0210);
    assert!(negotiated.capabilities.leasing());
    let setup = SessionSetupRequest {
        structure_size: SessionSetupRequest::STRUCTURE_SIZE.into(),
        ..SessionSetupRequest::new_zeroed()
    };
    guest
        .write_all(&frame(Command::SESSION_SETUP, 1, 0, 0, setup.as_bytes()))
        .await
        .unwrap();
    let response = receive(guest).await;
    let header = Header::read_from_prefix(&response).unwrap().0;
    assert_eq!(header.status.get(), 0);
    let session = header.session_id.get();
    let name: Vec<u8> = "\\\\VSMB\\memory"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let tree = TreeConnectRequest {
        structure_size: TreeConnectRequest::STRUCTURE_SIZE.into(),
        path_offset: 72.into(),
        path_length: (name.len() as u16).into(),
        ..TreeConnectRequest::new_zeroed()
    };
    guest
        .write_all(&frame(
            Command::TREE_CONNECT,
            2,
            session,
            0,
            &[tree.as_bytes(), &name].concat(),
        ))
        .await
        .unwrap();
    let response = receive(guest).await;
    let header = Header::read_from_prefix(&response).unwrap().0;
    assert_eq!(header.status.get(), 0);
    (session, header.tree_id.get())
}

async fn create(
    guest: &mut BytePipe<GpadlRingMem>,
    message: u64,
    session: u64,
    tree: u32,
    name: &str,
    directory: bool,
) -> FileId {
    let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let request = CreateRequest {
        structure_size: CreateRequest::STRUCTURE_SIZE.into(),
        desired_access: AccessMask::FILE_ALL_ACCESS,
        share_access: ShareAccess::ALL,
        create_disposition: if directory { 1 } else { 3 }.into(),
        create_options: CreateOptions::new().with_directory_file(directory),
        name_offset: if name.is_empty() {
            0
        } else {
            64 + size_of::<CreateRequest>() as u16
        }
        .into(),
        name_length: (name.len() as u16).into(),
        ..CreateRequest::new_zeroed()
    };
    guest
        .write_all(&frame(
            Command::CREATE,
            message,
            session,
            tree,
            &[request.as_bytes(), &name].concat(),
        ))
        .await
        .unwrap();
    let response = receive(guest).await;
    assert_eq!(
        Header::read_from_prefix(&response).unwrap().0.status.get(),
        0
    );
    CreateResponse::read_from_prefix(&response[64..])
        .unwrap()
        .0
        .file_id
}

fn clean(device: &mut VsmbDevice) {
    assert!(device.channel.is_none());
    assert!(device.guest_data.is_none());
    for field in [
        "opens",
        "watch_count",
        "lock_count",
        "lock_waiters",
        "notify_waiters",
    ] {
        assert_eq!(
            inspect::inspect(&format!("server/backend/{field}"), &mut *device)
                .results()
                .to_string(),
            "0",
            "{field}"
        );
    }
}

#[async_test]
async fn repeated_close_reopen_drains_pending_work_and_preserves_files(driver: DefaultDriver) {
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()));
    let mut device = VsmbDevice::new("memory".into(), source.simple()).unwrap();
    let mut old_file = None;
    for cycle in 0..3 {
        let memory = GuestMemory::allocate(8 * 4096);
        let (host, mut guest) = channels(&memory);
        device.open(host, memory).unwrap();
        let (session, tree) = drive(&mut device, connect(&mut guest)).await;
        let current = drive(&mut device, async {
            if let Some(file_id) = old_file {
                let request = ReadRequest {
                    structure_size: ReadRequest::STRUCTURE_SIZE.into(),
                    file_id,
                    length: 6.into(),
                    ..ReadRequest::new_zeroed()
                };
                guest
                    .write_all(&frame(Command::READ, 3, session, tree, request.as_bytes()))
                    .await
                    .unwrap();
                let response = receive(&mut guest).await;
                assert_eq!(
                    Header::read_from_prefix(&response).unwrap().0.status.get(),
                    Status::FILE_CLOSED.0
                );
            } else {
                guest
                    .write_all(&frame(Command::ECHO, 3, session, tree, &[4, 0, 0, 0]))
                    .await
                    .unwrap();
                assert_eq!(
                    Header::read_from_prefix(&receive(&mut guest).await)
                        .unwrap()
                        .0
                        .status
                        .get(),
                    0
                );
            }
            let file = create(&mut guest, 4, session, tree, "retained", false).await;
            let second = create(&mut guest, 5, session, tree, "retained", false).await;
            let directory = create(&mut guest, 6, session, tree, "", true).await;
            if cycle == 0 {
                let request = WriteRequest {
                    structure_size: WriteRequest::STRUCTURE_SIZE.into(),
                    file_id: file,
                    data_offset: (64 + size_of::<WriteRequest>() as u16).into(),
                    length: 6.into(),
                    ..WriteRequest::new_zeroed()
                };
                guest
                    .write_all(&frame(
                        Command::WRITE,
                        7,
                        session,
                        tree,
                        &[request.as_bytes(), b"seeded"].concat(),
                    ))
                    .await
                    .unwrap();
                let response = receive(&mut guest).await;
                assert_eq!(
                    Header::read_from_prefix(&response).unwrap().0.status.get(),
                    0
                );
                assert_eq!(
                    WriteResponse::read_from_prefix(&response[64..])
                        .unwrap()
                        .0
                        .count
                        .get(),
                    6
                );
            } else {
                let request = ReadRequest {
                    structure_size: ReadRequest::STRUCTURE_SIZE.into(),
                    file_id: file,
                    length: 6.into(),
                    ..ReadRequest::new_zeroed()
                };
                guest
                    .write_all(&frame(Command::READ, 7, session, tree, request.as_bytes()))
                    .await
                    .unwrap();
                let response = receive(&mut guest).await;
                assert_eq!(
                    Header::read_from_prefix(&response).unwrap().0.status.get(),
                    0
                );
                let read = ReadResponse::read_from_prefix(&response[64..]).unwrap().0;
                assert_eq!(&response[read.data_offset as usize..], b"seeded");
            }
            let lock = LockRequest {
                structure_size: LockRequest::STRUCTURE_SIZE.into(),
                lock_count: 1.into(),
                file_id: file,
                first_lock: LockElement {
                    offset: 0.into(),
                    length: 6.into(),
                    flags: LockFlags::new()
                        .with_exclusive_lock(true)
                        .with_fail_immediately(true),
                    reserved: 0.into(),
                },
                ..LockRequest::new_zeroed()
            };
            guest
                .write_all(&frame(Command::LOCK, 8, session, tree, lock.as_bytes()))
                .await
                .unwrap();
            assert_eq!(
                Header::read_from_prefix(&receive(&mut guest).await)
                    .unwrap()
                    .0
                    .status
                    .get(),
                0
            );
            let notify = ChangeNotifyRequest {
                structure_size: ChangeNotifyRequest::STRUCTURE_SIZE.into(),
                output_buffer_length: 1024.into(),
                file_id: directory,
                completion_filter: NotifyFilter::new().with_file_name(true),
                ..ChangeNotifyRequest::new_zeroed()
            };
            guest
                .write_all(&frame(
                    Command::CHANGE_NOTIFY,
                    9,
                    session,
                    tree,
                    notify.as_bytes(),
                ))
                .await
                .unwrap();
            assert_eq!(
                Header::read_from_prefix(&receive(&mut guest).await)
                    .unwrap()
                    .0
                    .status
                    .get(),
                Status::PENDING.0
            );
            let waiter = LockRequest {
                file_id: second,
                first_lock: LockElement {
                    flags: LockFlags::new().with_exclusive_lock(true),
                    ..lock.first_lock
                },
                ..lock
            };
            guest
                .write_all(&frame(Command::LOCK, 10, session, tree, waiter.as_bytes()))
                .await
                .unwrap();
            assert_eq!(
                Header::read_from_prefix(&receive(&mut guest).await)
                    .unwrap()
                    .0
                    .status
                    .get(),
                Status::PENDING.0
            );
            file
        })
        .await;
        for (field, count) in [
            ("watch_count", "1"),
            ("lock_count", "1"),
            ("lock_waiters", "1"),
        ] {
            assert_eq!(
                inspect::inspect(&format!("server/backend/{field}"), &mut device)
                    .results()
                    .to_string(),
                count
            );
        }
        drop(guest);
        if cycle == 1 {
            assert!(matches!(
                device.channel.as_mut().unwrap().process().now_or_never(),
                Some(Err(_))
            ));
        }
        vmbus_channel::test_helpers::with_timeout(&driver, device.close()).await;
        clean(&mut device);
        old_file = Some(current);
    }
}

#[async_test]
async fn close_after_protocol_failure_releases_drained_channel(driver: DefaultDriver) {
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()));
    let mut device = VsmbDevice::new("memory".into(), source.simple()).unwrap();
    let memory = GuestMemory::allocate(8 * 4096);
    let (host, mut guest) = channels(&memory);
    device.open(host, memory).unwrap();
    let (session, tree) = drive(&mut device, connect(&mut guest)).await;
    let file = drive(&mut device, async {
        let create = CreateRequest {
            structure_size: CreateRequest::STRUCTURE_SIZE.into(),
            desired_access: AccessMask::FILE_ALL_ACCESS,
            share_access: ShareAccess::ALL,
            create_disposition: 1.into(),
            create_options: CreateOptions::new().with_directory_file(true),
            ..CreateRequest::new_zeroed()
        };
        guest
            .write_all(&frame(Command::CREATE, 3, session, tree, create.as_bytes()))
            .await
            .unwrap();
        let response = receive(&mut guest).await;
        assert_eq!(
            Header::read_from_prefix(&response).unwrap().0.status.get(),
            0
        );
        CreateResponse::read_from_prefix(&response[64..])
            .unwrap()
            .0
            .file_id
    })
    .await;
    drive(&mut device, async {
        for message in 4..36 {
            let notify = ChangeNotifyRequest {
                structure_size: ChangeNotifyRequest::STRUCTURE_SIZE.into(),
                output_buffer_length: 1024.into(),
                file_id: file,
                completion_filter: NotifyFilter::new().with_file_name(true),
                ..ChangeNotifyRequest::new_zeroed()
            };
            guest
                .write_all(&frame(
                    Command::CHANGE_NOTIFY,
                    message,
                    session,
                    tree,
                    notify.as_bytes(),
                ))
                .await
                .unwrap();
            let response = receive(&mut guest).await;
            assert_eq!(
                Header::read_from_prefix(&response).unwrap().0.status.get(),
                Status::PENDING.0
            );
        }
    })
    .await;
    guest.write_all(&[1, 0, 0, 8]).await.unwrap();
    assert!(
        device
            .channel
            .as_mut()
            .unwrap()
            .process()
            .now_or_never()
            .is_none()
    );
    vmbus_channel::test_helpers::with_timeout(&driver, device.close()).await;
    assert!(
        device.channel.is_none(),
        "fully drained channel retained a protocol failure"
    );
    clean(&mut device);
    let memory = GuestMemory::allocate(8 * 4096);
    let (host, mut next) = channels(&memory);
    device.open(host, memory).unwrap();
    drive(&mut device, connect(&mut next)).await;
    vmbus_channel::test_helpers::with_timeout(&driver, device.close()).await;
}
