// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::AsyncFileExt;
use crate::create::{self, CreateParams};
use crate::error::VhdxIoError;
use crate::error::VhdxIoErrorInner;
use crate::format;
use crate::format::BatEntryState;
use crate::format::MB1;
use crate::io::ReadRange;
use crate::io::WriteRange;
use crate::open::VhdxFile;
use crate::tests::support::InMemoryFile;
use crate::trim::{TrimMode, TrimRequest};
use pal_async::DefaultDriver;
use pal_async::async_test;

async fn create_and_write_block(
    disk_size: u64,
    block_number: u32,
    driver: &DefaultDriver,
) -> VhdxFile<InMemoryFile> {
    let (file, _) = InMemoryFile::create_test_vhdx(disk_size).await;
    let vhdx = VhdxFile::open(file).writable(driver).await.unwrap();
    let block_offset = block_number as u64 * vhdx.block_size() as u64;
    let block_size = vhdx.block_size();

    let mut ranges = Vec::new();
    let guard = vhdx
        .resolve_write(block_offset, block_size, &mut ranges)
        .await
        .unwrap();

    write_ranges(&vhdx, &ranges, 0xaa).await;
    guard.complete().await.unwrap();
    vhdx
}

fn assert_block_state(vhdx: &VhdxFile<InMemoryFile>, block_number: u32, expected: BatEntryState) {
    let mapping = vhdx.bat.get_block_mapping(block_number);
    let actual = mapping.bat_state();
    assert_eq!(
        actual, expected,
        "block {block_number}: expected {expected:?}, got {actual:?}"
    );
}

fn block_has_file_offset(vhdx: &VhdxFile<InMemoryFile>, block_number: u32) -> bool {
    vhdx.bat.get_block_mapping(block_number).file_megabyte() != 0
}

async fn write_ranges(vhdx: &VhdxFile<InMemoryFile>, ranges: &[WriteRange], pattern: u8) {
    for range in ranges {
        match range {
            WriteRange::Data {
                file_offset,
                length,
                ..
            } => {
                let buf = vec![pattern; *length as usize];
                vhdx.file.write_at(*file_offset, &buf).await.unwrap();
            }
            WriteRange::Zero {
                file_offset,
                length,
            } => {
                let buf = vec![0u8; *length as usize];
                vhdx.file.write_at(*file_offset, &buf).await.unwrap();
            }
        }
    }
}

#[async_test]
async fn trim_full_block_file_space(driver: DefaultDriver) {
    let vhdx = create_and_write_block(format::GB1, 0, &driver).await;
    assert_block_state(&vhdx, 0, BatEntryState::FullyPresent);
    assert!(block_has_file_offset(&vhdx, 0));

    vhdx.trim(TrimRequest::new(
        TrimMode::FileSpace,
        0,
        vhdx.block_size() as u64,
    ))
    .await
    .unwrap();

    assert_block_state(&vhdx, 0, BatEntryState::Unmapped);
    assert!(block_has_file_offset(&vhdx, 0));
}

#[async_test]
async fn trim_full_block_free_space(driver: DefaultDriver) {
    let vhdx = create_and_write_block(format::GB1, 0, &driver).await;

    vhdx.trim(TrimRequest::new(
        TrimMode::FreeSpace,
        0,
        vhdx.block_size() as u64,
    ))
    .await
    .unwrap();

    assert_block_state(&vhdx, 0, BatEntryState::Undefined);
    assert!(!block_has_file_offset(&vhdx, 0));
}

#[async_test]
async fn trim_full_block_zero(driver: DefaultDriver) {
    let vhdx = create_and_write_block(format::GB1, 0, &driver).await;

    vhdx.trim(TrimRequest::new(
        TrimMode::Zero,
        0,
        vhdx.block_size() as u64,
    ))
    .await
    .unwrap();

    assert_block_state(&vhdx, 0, BatEntryState::Zero);
    assert!(!block_has_file_offset(&vhdx, 0));
}

#[async_test]
async fn trim_full_block_make_transparent(driver: DefaultDriver) {
    let vhdx = create_and_write_block(format::GB1, 0, &driver).await;

    vhdx.trim(TrimRequest::new(
        TrimMode::MakeTransparent,
        0,
        vhdx.block_size() as u64,
    ))
    .await
    .unwrap();

    assert_block_state(&vhdx, 0, BatEntryState::NotPresent);
    assert!(!block_has_file_offset(&vhdx, 0));
}

#[async_test]
async fn trim_remove_soft_anchors(driver: DefaultDriver) {
    let vhdx = create_and_write_block(format::GB1, 0, &driver).await;

    vhdx.trim(TrimRequest::new(
        TrimMode::FileSpace,
        0,
        vhdx.block_size() as u64,
    ))
    .await
    .unwrap();
    assert_block_state(&vhdx, 0, BatEntryState::Unmapped);
    assert!(block_has_file_offset(&vhdx, 0));

    vhdx.trim(TrimRequest::new(
        TrimMode::RemoveSoftAnchors,
        0,
        vhdx.block_size() as u64,
    ))
    .await
    .unwrap();
    assert_block_state(&vhdx, 0, BatEntryState::Unmapped);
    assert!(!block_has_file_offset(&vhdx, 0));
}

#[async_test]
async fn trim_already_trimmed_idempotent(driver: DefaultDriver) {
    let vhdx = create_and_write_block(format::GB1, 0, &driver).await;

    vhdx.trim(TrimRequest::new(
        TrimMode::FileSpace,
        0,
        vhdx.block_size() as u64,
    ))
    .await
    .unwrap();
    assert_block_state(&vhdx, 0, BatEntryState::Unmapped);

    vhdx.trim(TrimRequest::new(
        TrimMode::FileSpace,
        0,
        vhdx.block_size() as u64,
    ))
    .await
    .unwrap();
    assert_block_state(&vhdx, 0, BatEntryState::Unmapped);
}

#[async_test]
async fn trim_undefined_block_file_space_noop(driver: DefaultDriver) {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

    assert_block_state(&vhdx, 0, BatEntryState::NotPresent);

    vhdx.trim(TrimRequest::new(
        TrimMode::FileSpace,
        0,
        vhdx.block_size() as u64,
    ))
    .await
    .unwrap();

    assert_block_state(&vhdx, 0, BatEntryState::NotPresent);
}

#[async_test]
async fn trim_zero_block_noop(driver: DefaultDriver) {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

    let block_size = vhdx.block_size();
    let mut ranges = Vec::new();
    let guard = vhdx
        .resolve_write(0, block_size, &mut ranges)
        .await
        .unwrap();
    write_ranges(&vhdx, &ranges, 0).await;
    guard.complete().await.unwrap();

    vhdx.trim(TrimRequest::new(TrimMode::Zero, 0, block_size as u64))
        .await
        .unwrap();
    assert_block_state(&vhdx, 0, BatEntryState::Zero);

    vhdx.trim(TrimRequest::new(TrimMode::Zero, 0, block_size as u64))
        .await
        .unwrap();
    assert_block_state(&vhdx, 0, BatEntryState::Zero);
}

#[async_test]
async fn trim_cross_block(driver: DefaultDriver) {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();
    let block_size = vhdx.block_size();

    for block in 0..3u32 {
        let offset = block as u64 * block_size as u64;
        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(offset, block_size, &mut ranges)
            .await
            .unwrap();
        write_ranges(&vhdx, &ranges, 0xbb).await;
        guard.complete().await.unwrap();
    }

    vhdx.trim(TrimRequest::new(
        TrimMode::FileSpace,
        0,
        3 * block_size as u64,
    ))
    .await
    .unwrap();

    for block in 0..3u32 {
        assert_block_state(&vhdx, block, BatEntryState::Unmapped);
        assert!(block_has_file_offset(&vhdx, block));
    }
}

#[async_test]
async fn trim_partial_range_skips_edges(driver: DefaultDriver) {
    let file = InMemoryFile::new(0);
    let block_size = MB1 as u32;
    let mut params = CreateParams {
        disk_size: 4 * MB1,
        block_size,
        ..Default::default()
    };
    create::create(&file, &mut params).await.unwrap();
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

    for block in 0..3u32 {
        let offset = block as u64 * block_size as u64;
        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(offset, block_size, &mut ranges)
            .await
            .unwrap();
        write_ranges(&vhdx, &ranges, 0xcc).await;
        guard.complete().await.unwrap();
    }

    vhdx.trim(TrimRequest::new(TrimMode::FileSpace, MB1 / 2, 2 * MB1))
        .await
        .unwrap();

    assert_block_state(&vhdx, 0, BatEntryState::FullyPresent);
    assert_block_state(&vhdx, 1, BatEntryState::Unmapped);
    assert_block_state(&vhdx, 2, BatEntryState::FullyPresent);
}

#[async_test]
async fn trim_entire_disk(driver: DefaultDriver) {
    let file = InMemoryFile::new(0);
    let block_size = MB1 as u32;
    let mut params = CreateParams {
        disk_size: 4 * MB1,
        block_size,
        ..Default::default()
    };
    create::create(&file, &mut params).await.unwrap();
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

    for block in 0..4u32 {
        let offset = block as u64 * block_size as u64;
        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(offset, block_size, &mut ranges)
            .await
            .unwrap();
        write_ranges(&vhdx, &ranges, 0xdd).await;
        guard.complete().await.unwrap();
    }

    vhdx.trim(TrimRequest::new(TrimMode::FileSpace, 0, 4 * MB1))
        .await
        .unwrap();

    for block in 0..4u32 {
        assert_block_state(&vhdx, block, BatEntryState::Unmapped);
    }
}

#[async_test]
async fn trim_at_disk_end_rounds_up(driver: DefaultDriver) {
    let file = InMemoryFile::new(0);
    let block_size = MB1 as u32;
    let disk_size = 3 * MB1 + MB1 / 2;
    let mut params = CreateParams {
        disk_size,
        block_size,
        ..Default::default()
    };
    create::create(&file, &mut params).await.unwrap();
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

    let block3_offset = 3 * MB1;
    let write_size = (MB1 / 2) as u32;
    let mut ranges = Vec::new();
    let guard = vhdx
        .resolve_write(block3_offset, write_size, &mut ranges)
        .await
        .unwrap();
    write_ranges(&vhdx, &ranges, 0xee).await;
    guard.complete().await.unwrap();

    vhdx.trim(TrimRequest::new(
        TrimMode::FileSpace,
        block3_offset,
        disk_size - block3_offset,
    ))
    .await
    .unwrap();

    assert_block_state(&vhdx, 3, BatEntryState::Unmapped);
}

#[async_test]
async fn read_after_trim_returns_zeros(driver: DefaultDriver) {
    let vhdx = create_and_write_block(format::GB1, 0, &driver).await;

    let mut ranges = Vec::new();
    let guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();
    assert!(matches!(ranges[0], ReadRange::Data { .. }));
    drop(guard);

    vhdx.trim(TrimRequest::new(
        TrimMode::FileSpace,
        0,
        vhdx.block_size() as u64,
    ))
    .await
    .unwrap();

    let mut ranges = Vec::new();
    let _guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();
    assert_eq!(ranges.len(), 1);
    assert!(
        matches!(ranges[0], ReadRange::Zero { .. }),
        "expected Zero range after trim, got {:?}",
        ranges[0]
    );
}

#[async_test]
async fn trim_then_write_reallocates(driver: DefaultDriver) {
    let vhdx = create_and_write_block(format::GB1, 0, &driver).await;

    vhdx.trim(TrimRequest::new(
        TrimMode::FileSpace,
        0,
        vhdx.block_size() as u64,
    ))
    .await
    .unwrap();
    assert_block_state(&vhdx, 0, BatEntryState::Unmapped);

    let block_size = vhdx.block_size();
    let mut ranges = Vec::new();
    let guard = vhdx
        .resolve_write(0, block_size, &mut ranges)
        .await
        .unwrap();
    write_ranges(&vhdx, &ranges, 0xff).await;
    guard.complete().await.unwrap();

    assert_block_state(&vhdx, 0, BatEntryState::FullyPresent);
}

#[async_test]
async fn trim_fixed_disk_file_space_noop(driver: DefaultDriver) {
    let file = InMemoryFile::new(0);
    let mut params = CreateParams {
        disk_size: 4 * MB1,
        block_size: MB1 as u32,
        is_fully_allocated: true,
        ..Default::default()
    };
    create::create(&file, &mut params).await.unwrap();
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

    vhdx.trim(TrimRequest::new(TrimMode::FileSpace, 0, 4 * MB1))
        .await
        .unwrap();

    let mapping = vhdx.bat.get_block_mapping(0);
    assert_ne!(mapping.bat_state(), BatEntryState::Unmapped);
}

#[async_test]
async fn trim_fixed_disk_make_transparent_allowed(driver: DefaultDriver) {
    let file = InMemoryFile::new(0);
    let mut params = CreateParams {
        disk_size: 4 * MB1,
        block_size: MB1 as u32,
        is_fully_allocated: true,
        ..Default::default()
    };
    create::create(&file, &mut params).await.unwrap();
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

    vhdx.trim(TrimRequest::new(TrimMode::MakeTransparent, 0, 4 * MB1))
        .await
        .unwrap();

    assert_block_state(&vhdx, 0, BatEntryState::NotPresent);
}

#[async_test]
async fn trim_waits_for_in_flight_read(driver: DefaultDriver) {
    let vhdx = create_and_write_block(format::GB1, 0, &driver).await;

    let mut ranges = Vec::new();
    let read_guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

    let trim_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let trim_done2 = trim_done.clone();

    let (trim_result, _) = futures::join!(
        async {
            let r = vhdx
                .trim(TrimRequest::new(
                    TrimMode::FileSpace,
                    0,
                    vhdx.block_size() as u64,
                ))
                .await;
            trim_done2.store(true, std::sync::atomic::Ordering::SeqCst);
            r
        },
        async {
            std::future::poll_fn(|cx| {
                cx.waker().wake_by_ref();
                std::task::Poll::Ready(())
            })
            .await;
            assert!(
                !trim_done.load(std::sync::atomic::Ordering::SeqCst),
                "trim should not complete while read guard is held"
            );
            drop(read_guard);
        }
    );

    trim_result.unwrap();
    assert_block_state(&vhdx, 0, BatEntryState::Unmapped);
}

#[async_test]
async fn trim_waits_for_in_flight_write(driver: DefaultDriver) {
    let vhdx = create_and_write_block(format::GB1, 0, &driver).await;

    let mut ranges = Vec::new();
    let write_guard = vhdx
        .resolve_write(0, vhdx.block_size(), &mut ranges)
        .await
        .unwrap();

    let trim_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let trim_done2 = trim_done.clone();

    let (trim_result, _) = futures::join!(
        async {
            let r = vhdx
                .trim(TrimRequest::new(
                    TrimMode::FileSpace,
                    0,
                    vhdx.block_size() as u64,
                ))
                .await;
            trim_done2.store(true, std::sync::atomic::Ordering::SeqCst);
            r
        },
        async {
            std::future::poll_fn(|cx| {
                cx.waker().wake_by_ref();
                std::task::Poll::Ready(())
            })
            .await;
            assert!(
                !trim_done.load(std::sync::atomic::Ordering::SeqCst),
                "trim should not complete while write guard is held"
            );
            write_guard.complete().await.unwrap();
        }
    );

    trim_result.unwrap();
    assert_block_state(&vhdx, 0, BatEntryState::Unmapped);
}

#[async_test]
async fn trim_concurrent_different_block(driver: DefaultDriver) {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();
    let block_size = vhdx.block_size();

    for block in 0..2u32 {
        let offset = block as u64 * block_size as u64;
        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(offset, block_size, &mut ranges)
            .await
            .unwrap();
        write_ranges(&vhdx, &ranges, 0xaa).await;
        guard.complete().await.unwrap();
    }

    let (trim_result, read_result) = futures::join!(
        vhdx.trim(TrimRequest::new(TrimMode::FileSpace, 0, block_size as u64,)),
        async {
            let mut ranges = Vec::new();
            let guard = vhdx
                .resolve_read(block_size as u64, 4096, &mut ranges)
                .await
                .unwrap();
            let result = ranges.clone();
            drop(guard);
            result
        }
    );

    trim_result.unwrap();
    assert_block_state(&vhdx, 0, BatEntryState::Unmapped);
    assert!(matches!(read_result[0], ReadRange::Data { .. }));
}

#[async_test]
async fn trim_read_only_fails() {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).read_only().await.unwrap();

    let result = vhdx
        .trim(TrimRequest::new(
            TrimMode::FileSpace,
            0,
            vhdx.block_size() as u64,
        ))
        .await;
    assert!(matches!(
        result,
        Err(VhdxIoError(VhdxIoErrorInner::ReadOnly))
    ));
}

#[async_test]
async fn trim_unaligned_offset_fails(driver: DefaultDriver) {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

    let result = vhdx
        .trim(TrimRequest::new(TrimMode::FileSpace, 1, 512))
        .await;
    assert!(matches!(
        result,
        Err(VhdxIoError(VhdxIoErrorInner::UnalignedIo))
    ));
}

#[async_test]
async fn trim_beyond_disk_fails(driver: DefaultDriver) {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

    let result = vhdx
        .trim(TrimRequest::new(
            TrimMode::FileSpace,
            format::GB1 - 512,
            1024,
        ))
        .await;
    assert!(matches!(
        result,
        Err(VhdxIoError(VhdxIoErrorInner::BeyondEndOfDisk))
    ));
}

#[async_test]
async fn trim_beyond_disk_ok_with_skip(driver: DefaultDriver) {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

    let result = vhdx
        .trim(
            TrimRequest::new(TrimMode::FileSpace, format::GB1 - 512, 1024)
                .skip_disk_size_check(true),
        )
        .await;
    assert!(result.is_ok());
}

#[async_test]
async fn trim_zero_length_noop(driver: DefaultDriver) {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

    let result = vhdx.trim(TrimRequest::new(TrimMode::FileSpace, 0, 0)).await;
    assert!(result.is_ok());
}
