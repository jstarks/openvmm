// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::AsyncFile;
use crate::AsyncFileExt;
use crate::create::{self, CreateParams};
use crate::error::VhdxIoError;
use crate::error::VhdxIoErrorInner;
use crate::format;
use crate::format::BatEntry;
use crate::format::BatEntryState;
use crate::format::MB1;
use crate::io::ReadRange;
use crate::io::WriteRange;
use crate::open::VhdxFile;
use crate::region;
use crate::tests::support::InMemoryFile;
use pal_async::DefaultDriver;
use pal_async::async_test;
use zerocopy::IntoBytes;

async fn write_resolved_ranges<F: AsyncFile>(
    vhdx: &VhdxFile<F>,
    ranges: &[WriteRange],
    pattern_byte: u8,
) {
    for range in ranges {
        match range {
            WriteRange::Data {
                file_offset,
                length,
                ..
            } => {
                let data = vec![pattern_byte; *length as usize];
                vhdx.file.write_at(*file_offset, &data).await.unwrap();
            }
            WriteRange::Zero {
                file_offset,
                length,
            } => {
                let zeros = vec![0; *length as usize];
                vhdx.file.write_at(*file_offset, &zeros).await.unwrap();
            }
        }
    }
}

async fn write_block<F: AsyncFile>(
    vhdx: &VhdxFile<F>,
    guest_offset: u64,
    length: u32,
    pattern_byte: u8,
) {
    let mut ranges = Vec::new();
    let guard = vhdx
        .resolve_write(guest_offset, length, &mut ranges)
        .await
        .unwrap();
    write_resolved_ranges(vhdx, &ranges, pattern_byte).await;
    guard.complete().await.unwrap();
}

#[async_test]
async fn read_empty_disk_returns_zero() {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).read_only().await.unwrap();

    let mut ranges = Vec::new();
    let _guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

    assert_eq!(
        ranges,
        vec![ReadRange::Zero {
            guest_offset: 0,
            length: 4096,
        }]
    );
}

#[async_test]
async fn read_fully_present_block() {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let regions = region::parse_region_tables(&file).await.unwrap();
    let entry = BatEntry::new()
        .with_state(BatEntryState::FullyPresent as u8)
        .with_file_offset_mb(4);
    file.write_at(regions.bat_offset, entry.as_bytes())
        .await
        .unwrap();
    file.set_file_size(4 * MB1 + u64::from(format::DEFAULT_BLOCK_SIZE))
        .await
        .unwrap();

    let vhdx = VhdxFile::open(file).read_only().await.unwrap();
    let mut ranges = Vec::new();
    let _guard = vhdx.resolve_read(5120, 512, &mut ranges).await.unwrap();

    assert_eq!(
        ranges,
        vec![ReadRange::Data {
            guest_offset: 5120,
            length: 512,
            file_offset: 4 * MB1 + 5120,
        }]
    );
}

#[async_test]
async fn read_differencing_not_present_is_unmapped() {
    let file = InMemoryFile::new(0);
    let mut params = CreateParams {
        disk_size: format::GB1,
        has_parent: true,
        ..Default::default()
    };
    create::create(&file, &mut params).await.unwrap();
    let vhdx = VhdxFile::open(file).read_only().await.unwrap();

    let mut ranges = Vec::new();
    let _guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

    assert_eq!(
        ranges,
        vec![ReadRange::Unmapped {
            guest_offset: 0,
            length: 4096,
        }]
    );
}

#[async_test]
async fn read_rejects_unaligned_and_beyond_end() {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).read_only().await.unwrap();

    let mut ranges = Vec::new();
    let result = vhdx.resolve_read(1, 512, &mut ranges).await;
    assert!(matches!(
        result,
        Err(VhdxIoError(VhdxIoErrorInner::UnalignedIo))
    ));

    let result = vhdx
        .resolve_read(format::GB1 - 512, 1024, &mut ranges)
        .await;
    assert!(matches!(
        result,
        Err(VhdxIoError(VhdxIoErrorInner::BeyondEndOfDisk))
    ));
}

#[async_test]
async fn write_to_empty_block_allocates_and_reads_back(driver: DefaultDriver) {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

    let mut write_ranges = Vec::new();
    let guard = vhdx.resolve_write(0, 512, &mut write_ranges).await.unwrap();
    assert!(
        write_ranges
            .iter()
            .any(|range| matches!(range, WriteRange::Data { .. }))
    );

    write_resolved_ranges(&vhdx, &write_ranges, 0x5a).await;
    guard.complete().await.unwrap();

    let mapping = vhdx.bat.get_block_mapping(0);
    assert_eq!(mapping.bat_state(), BatEntryState::FullyPresent);
    assert!(!mapping.transitioning_to_fully_present());

    let mut read_ranges = Vec::new();
    let _guard = vhdx.resolve_read(0, 512, &mut read_ranges).await.unwrap();
    assert_eq!(read_ranges.len(), 1);
    let ReadRange::Data {
        file_offset,
        length,
        ..
    } = read_ranges[0]
    else {
        panic!("expected data range");
    };
    assert_eq!(length, 512);

    let mut data = vec![0; 512];
    vhdx.file.read_at(file_offset, &mut data).await.unwrap();
    assert!(data.iter().all(|byte| *byte == 0x5a));
}

#[async_test]
async fn write_to_fully_present_block_does_not_allocate(driver: DefaultDriver) {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let regions = region::parse_region_tables(&file).await.unwrap();
    let entry = BatEntry::new()
        .with_state(BatEntryState::FullyPresent as u8)
        .with_file_offset_mb(100);
    file.write_at(regions.bat_offset, entry.as_bytes())
        .await
        .unwrap();
    file.set_file_size(100 * MB1 + u64::from(format::DEFAULT_BLOCK_SIZE))
        .await
        .unwrap();

    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();
    let eof_before = vhdx.allocation_lock.lock().await.file_length;
    let mut ranges = Vec::new();
    let _guard = vhdx.resolve_write(0, 4096, &mut ranges).await.unwrap();
    let eof_after = vhdx.allocation_lock.lock().await.file_length;

    assert_eq!(eof_before, eof_after);
    assert_eq!(
        ranges,
        vec![WriteRange::Data {
            guest_offset: 0,
            length: 4096,
            file_offset: 100 * MB1,
        }]
    );
}

#[async_test]
async fn full_block_write_sets_tfp_then_complete_clears_it(driver: DefaultDriver) {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();
    let block_size = vhdx.block_size();

    let mut ranges = Vec::new();
    let guard = vhdx
        .resolve_write(0, block_size, &mut ranges)
        .await
        .unwrap();

    assert!(
        vhdx.bat
            .get_block_mapping(0)
            .transitioning_to_fully_present()
    );
    write_resolved_ranges(&vhdx, &ranges, 0xa5).await;
    guard.complete().await.unwrap();

    let mapping = vhdx.bat.get_block_mapping(0);
    assert_eq!(mapping.bat_state(), BatEntryState::FullyPresent);
    assert!(!mapping.transitioning_to_fully_present());
}

#[async_test]
async fn dropping_write_guard_aborts_tfp(driver: DefaultDriver) {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();
    let block_size = vhdx.block_size();

    let mut ranges = Vec::new();
    let guard = vhdx
        .resolve_write(0, block_size, &mut ranges)
        .await
        .unwrap();
    assert_eq!(vhdx.bat.io_refcount(0), 1);
    drop(guard);

    let mapping = vhdx.bat.get_block_mapping(0);
    assert_eq!(vhdx.bat.io_refcount(0), 0);
    assert_eq!(mapping.bat_state(), BatEntryState::NotPresent);
    assert_eq!(mapping.file_offset(), 0);
}

#[async_test]
async fn flush_persists_completed_bat_update(driver: DefaultDriver) {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();
    let block_size = vhdx.block_size();

    write_block(&vhdx, 0, block_size, 0x11).await;
    let expected_mb = vhdx.bat.get_block_mapping(0).file_megabyte();
    vhdx.flush().await.unwrap();

    let snapshot = vhdx.file.snapshot();
    let recovered = InMemoryFile::from_snapshot(snapshot);
    let recovered = VhdxFile::open(recovered).writable(&driver).await.unwrap();
    let mapping = recovered.bat.get_block_mapping(0);
    assert_eq!(mapping.bat_state(), BatEntryState::FullyPresent);
    assert_eq!(mapping.file_megabyte(), expected_mb);
}

#[async_test]
async fn read_and_write_guards_track_refcounts(driver: DefaultDriver) {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();
    let block_size = vhdx.block_size();
    write_block(&vhdx, 0, block_size, 0xee).await;

    let mut read_ranges = Vec::new();
    let read_guard = vhdx
        .resolve_read(0, block_size, &mut read_ranges)
        .await
        .unwrap();
    assert_eq!(vhdx.bat.io_refcount(0), 1);
    drop(read_guard);
    assert_eq!(vhdx.bat.io_refcount(0), 0);

    let mut write_ranges = Vec::new();
    let write_guard = vhdx
        .resolve_write(0, block_size, &mut write_ranges)
        .await
        .unwrap();
    assert_eq!(vhdx.bat.io_refcount(0), 1);
    write_guard.complete().await.unwrap();
    assert_eq!(vhdx.bat.io_refcount(0), 0);
}

#[async_test]
async fn partial_differencing_write_updates_sector_bitmap(driver: DefaultDriver) {
    let file = InMemoryFile::new(0);
    let mut params = CreateParams {
        disk_size: format::GB1,
        has_parent: true,
        ..Default::default()
    };
    create::create(&file, &mut params).await.unwrap();
    let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

    let mut write_ranges = Vec::new();
    let guard = vhdx
        .resolve_write(0, 2048, &mut write_ranges)
        .await
        .unwrap();
    write_resolved_ranges(&vhdx, &write_ranges, 0x7c).await;
    guard.complete().await.unwrap();

    let mapping = vhdx.bat.get_block_mapping(0);
    assert_eq!(mapping.bat_state(), BatEntryState::PartiallyPresent);

    let mut read_ranges = Vec::new();
    let _guard = vhdx.resolve_read(0, 4096, &mut read_ranges).await.unwrap();
    assert_eq!(read_ranges.len(), 2);
    assert!(matches!(
        read_ranges[0],
        ReadRange::Data {
            guest_offset: 0,
            length: 2048,
            ..
        }
    ));
    assert_eq!(
        read_ranges[1],
        ReadRange::Unmapped {
            guest_offset: 2048,
            length: 2048,
        }
    );
}

#[async_test]
async fn write_read_only_is_rejected() {
    let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
    let vhdx = VhdxFile::open(file).read_only().await.unwrap();

    let mut ranges = Vec::new();
    let result = vhdx.resolve_write(0, 4096, &mut ranges).await;
    assert!(matches!(
        result,
        Err(VhdxIoError(VhdxIoErrorInner::ReadOnly))
    ));
}
