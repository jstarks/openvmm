// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::{AsyncReadExt, AsyncWriteExt};
use pal_async::{DefaultDriver, async_test};
use smb::{
    spec::*,
    transfer::{Direction, ExternalData},
};
use task_control::TaskControl;
use zerocopy::{FromBytes, FromZeros, IntoBytes};

fn frame(command: Command, message: u64, session: u64, tree: u32, body: &[u8]) -> Vec<u8> {
    let mut header = Header::new_zeroed();
    header.protocol = SIGNATURE;
    header.structure_size = 64.into();
    header.command = command.0.into();
    header.message_id = message.into();
    header.session_id = session.into();
    header.tree_id = tree.into();
    header.credit_charge = 1.into();
    header.credits = 1.into();
    let mut packet = (64u32 + body.len() as u32).to_be_bytes().to_vec();
    packet.extend_from_slice(header.as_bytes());
    packet.extend_from_slice(body);
    packet
}

async fn receive<S: futures::AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).await.unwrap();
    let mut packet = vec![0; u32::from_be_bytes(prefix) as usize];
    stream.read_exact(&mut packet).await.unwrap();
    packet
}

#[async_test]
async fn connected_channel_negotiates_and_services_real_smb(driver: DefaultDriver) {
    let (host, mut guest) = vmbus_async::pipe::connected_byte_pipes(16384);
    let server = Server::new("memory", MemoryFs::new(1024, 16).with_oplocks().unwrap()).unwrap();
    let memory = GuestMemory::allocate(4 * 4096);
    let stream = transport::Transport::new(host);
    let data = Arc::new(transfer::GuestData::new(
        memory.clone(),
        stream.negotiated_capabilities(),
    ));
    let channel = ConnectionTask::new_with_driver(
        server.connect_with_external_data(data),
        stream,
        driver.clone(),
    );
    let mut task = TaskControl::new(channel);
    task.insert(&driver, "vsmb-test", ());
    task.start();
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
    let mut body = negotiate.as_bytes().to_vec();
    body.extend_from_slice(&0x0210u16.to_le_bytes());
    guest
        .write_all(&frame(Command::NEGOTIATE, 0, 0, 0, &body))
        .await
        .unwrap();
    let response = receive(&mut guest).await;
    assert_eq!(
        Header::read_from_prefix(&response).unwrap().0.status.get(),
        0
    );
    let negotiate = NegotiateResponse::read_from_prefix(&response[64..])
        .unwrap()
        .0;
    assert_eq!(negotiate.dialect.get(), 0x0210);
    assert!(negotiate.capabilities.leasing());
    let setup = SessionSetupRequest {
        structure_size: SessionSetupRequest::STRUCTURE_SIZE.into(),
        ..SessionSetupRequest::new_zeroed()
    };
    guest
        .write_all(&frame(Command::SESSION_SETUP, 1, 0, 0, setup.as_bytes()))
        .await
        .unwrap();
    let response = receive(&mut guest).await;
    let header = Header::read_from_prefix(&response).unwrap().0;
    assert_eq!(header.status.get(), 0);
    assert_ne!(header.session_id.get(), 0);
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
    let body = [tree.as_bytes(), &name].concat();
    guest
        .write_all(&frame(Command::TREE_CONNECT, 2, session, 0, &body))
        .await
        .unwrap();
    let response = receive(&mut guest).await;
    let header = Header::read_from_prefix(&response).unwrap().0;
    assert_eq!(header.status.get(), 0);
    assert_ne!(header.tree_id.get(), 0);
    let tree = header.tree_id.get();
    let name: Vec<u8> = "wire".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut create = CreateRequest::new_zeroed();
    create.structure_size = CreateRequest::STRUCTURE_SIZE.into();
    create.desired_access = AccessMask::FILE_ALL_ACCESS;
    create.share_access = ShareAccess::ALL;
    create.create_disposition = 2.into();
    create.name_offset = (64 + size_of::<CreateRequest>() as u16).into();
    create.name_length = (name.len() as u16).into();
    let body = [create.as_bytes(), &name].concat();
    guest
        .write_all(&frame(Command::CREATE, 3, session, tree, &body))
        .await
        .unwrap();
    let response = receive(&mut guest).await;
    assert_eq!(
        Header::read_from_prefix(&response).unwrap().0.status.get(),
        0
    );
    let file = CreateResponse::read_from_prefix(&response[64..])
        .unwrap()
        .0
        .file_id;
    let descriptor = [
        2u16.to_le_bytes().as_slice(),
        &4093u16.to_le_bytes(),
        &6u32.to_le_bytes(),
        &1u64.to_le_bytes(),
        &3u64.to_le_bytes(),
    ]
    .concat();
    memory.write_at(4096 + 4093, b"abc").unwrap();
    memory.write_at(3 * 4096, b"def").unwrap();
    let mut write = WriteRequest::new_zeroed();
    write.structure_size = WriteRequest::STRUCTURE_SIZE.into();
    write.file_id = file;
    write.channel = 2.into();
    write.channel_info_offset = (64 + size_of::<WriteRequest>() as u16).into();
    write.channel_info_length = (descriptor.len() as u16).into();
    for (message, length, expected) in [(4, 7, Status::INVALID_PARAMETER), (6, 6, Status::SUCCESS)]
    {
        write.remaining_bytes = length.into();
        let body = [write.as_bytes(), &descriptor].concat();
        guest
            .write_all(&frame(Command::WRITE, message, session, tree, &body))
            .await
            .unwrap();
        let response = receive(&mut guest).await;
        assert_eq!(
            Header::read_from_prefix(&response).unwrap().0.status.get(),
            expected.0
        );
        if expected == Status::INVALID_PARAMETER {
            let mut read = ReadRequest::new_zeroed();
            read.structure_size = ReadRequest::STRUCTURE_SIZE.into();
            read.file_id = file;
            read.length = 1.into();
            guest
                .write_all(&frame(Command::READ, 5, session, tree, read.as_bytes()))
                .await
                .unwrap();
            let response = receive(&mut guest).await;
            assert_eq!(
                Header::read_from_prefix(&response).unwrap().0.status.get(),
                Status::END_OF_FILE.0
            );
        } else {
            assert_eq!(
                WriteResponse::read_from_prefix(&response[64..])
                    .unwrap()
                    .0
                    .count
                    .get(),
                6
            );
        }
    }
    let destination = [
        2u16.to_le_bytes().as_slice(),
        &4095u16.to_le_bytes(),
        &6u32.to_le_bytes(),
        &0u64.to_le_bytes(),
        &2u64.to_le_bytes(),
    ]
    .concat();
    let mut read = ReadRequest::new_zeroed();
    read.structure_size = ReadRequest::STRUCTURE_SIZE.into();
    read.file_id = file;
    read.length = 6.into();
    read.channel = 2.into();
    read.channel_info_offset = (64 + size_of::<ReadRequest>() as u16).into();
    read.channel_info_length = (destination.len() as u16).into();
    let body = [read.as_bytes(), &destination].concat();
    guest
        .write_all(&frame(Command::READ, 7, session, tree, &body))
        .await
        .unwrap();
    let response = receive(&mut guest).await;
    assert_eq!(
        Header::read_from_prefix(&response).unwrap().0.status.get(),
        0
    );
    let read = ReadResponse::read_from_prefix(&response[64..]).unwrap().0;
    assert_eq!((read.data_length.get(), read.data_remaining.get()), (0, 6));
    let mut copied = [0; 6];
    memory.read_at(4095, &mut copied[..1]).unwrap();
    memory.read_at(2 * 4096, &mut copied[1..]).unwrap();
    assert_eq!(&copied, b"abcdef");
    task.stop().await;
    task.task_mut().shutdown().await.unwrap();
}

#[async_test]
async fn pause_preserves_fragmented_transport_negotiation(driver: DefaultDriver) {
    let (_thread, worker_driver) = pal_async::DefaultPool::spawn_on_thread("vsmb-stop");
    let (host, guest, gate) = vmbus_channel::test_helpers::gated_channels(4096);
    let mut guest = BytePipe::new(guest).unwrap();
    let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
    let mut task = TaskControl::new(ConnectionTask::new(
        server.connect(),
        transport::Transport::new(BytePipe::new(host).unwrap()),
    ));
    task.insert(&worker_driver, "vsmb-stop", ());
    task.start();
    guest.write_all(&[1, 0]).await.unwrap();
    gate.stop(&mut task, &driver).await;
    assert_eq!(
        task.task()
            .transport()
            .negotiated_capabilities()
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    guest
        .write_all(&[0, 8, 1, 0, 0, 0, 1, 0, 0, 0])
        .await
        .unwrap();
    task.start();
    let mut response = [0; 12];
    vmbus_channel::test_helpers::with_timeout(&driver, guest.read_exact(&mut response))
        .await
        .unwrap();
    assert_eq!(response, [1, 0, 0, 8, 1, 0, 0, 0, 1, 0, 0, 0]);
    vmbus_channel::test_helpers::stop_with_timeout(&mut task, &driver).await;
    task.task_mut().shutdown().await.unwrap();
}

#[async_test]
async fn negotiation_rejects_unknown_version_then_accepts_supported_one(driver: DefaultDriver) {
    let (host, mut guest) = vmbus_async::pipe::connected_byte_pipes(4096);
    let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
    let mut task = TaskControl::new(ConnectionTask::new(
        server.connect(),
        transport::Transport::new(host),
    ));
    task.insert(&driver, "vsmb-version", ());
    task.start();
    for (version, expected) in [(99u32, u32::MAX), (1, 1)] {
        let packet = [
            &[1, 0, 0, 8][..],
            &version.to_le_bytes(),
            &0u32.to_le_bytes(),
        ]
        .concat();
        guest.write_all(&packet).await.unwrap();
        let mut response = [0; 12];
        guest.read_exact(&mut response).await.unwrap();
        assert_eq!(&response[..4], &[1, 0, 0, 8]);
        assert_eq!(&response[4..8], &expected.to_le_bytes());
        assert_eq!(&response[8..], &[0; 4]);
    }
    task.stop().await;
    task.task_mut().shutdown().await.unwrap();
}

#[test_with_tracing::test]
fn external_transfer_copies_cross_page_ranges_and_rejects_bad_descriptors() {
    let memory = GuestMemory::allocate(4 * 4096);
    let negotiated = Arc::new(std::sync::atomic::AtomicU32::new(1));
    let data = transfer::GuestData::new(memory.clone(), negotiated.clone());
    let descriptor = |offset: u16, size: u32, pages: &[u64]| {
        let mut bytes = (pages.len() as u16).to_le_bytes().to_vec();
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        for page in pages {
            bytes.extend_from_slice(&page.to_le_bytes());
        }
        bytes
    };
    let valid = descriptor(4093, 6, &[1, 3]);
    memory.write_at(4096 + 4093, b"abc").unwrap();
    memory.write_at(3 * 4096, b"def").unwrap();
    data.validate(2, &valid, 6, Direction::Read).unwrap();
    assert_eq!(
        futures::executor::block_on(data.read(2, &valid, 6)).unwrap(),
        b"abcdef"
    );
    data.validate(2, &valid, 6, Direction::Write).unwrap();
    futures::executor::block_on(data.write(2, &valid, b"UVWXYZ")).unwrap();
    let mut bytes = [0; 3];
    memory.read_at(4096 + 4093, &mut bytes).unwrap();
    assert_eq!(&bytes, b"UVW");
    memory.read_at(3 * 4096, &mut bytes).unwrap();
    assert_eq!(&bytes, b"XYZ");
    for invalid in [
        descriptor(4096, 1, &[1]),
        descriptor(0, 1, &[u64::MAX]),
        descriptor(4093, 6, &[1]),
        descriptor(0, 6, &[4]),
        descriptor(0, 5, &[1]),
        vec![0; 7],
    ] {
        assert_eq!(
            data.validate(2, &invalid, 6, Direction::Write),
            Err(Status::INVALID_PARAMETER)
        );
    }
    assert_eq!(
        data.validate(1, &valid, 6, Direction::Read),
        Err(Status::INVALID_PARAMETER)
    );
    for direction in [Direction::Read, Direction::Write] {
        let last_byte = descriptor(4095, 1, &[u64::MAX / 4096]);
        assert_eq!(
            data.validate(2, &last_byte, 1, direction),
            Err(Status::INVALID_PARAMETER)
        );
    }
    negotiated.store(0, std::sync::atomic::Ordering::Release);
    assert_eq!(
        data.validate(2, &valid, 6, Direction::Read),
        Err(Status::INVALID_PARAMETER)
    );
}
