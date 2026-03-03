// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod support;

#[cfg(test)]
mod crash_tests;

#[cfg(test)]
mod integration {
    use crate::AsyncFile;
    use crate::create::{self, CreateParams};
    use crate::format;
    use crate::header;
    use crate::known_meta;
    use crate::metadata::MetadataTable;
    use crate::region;
    use crate::tests::support::InMemoryFile;
    use guid::Guid;
    use pal_async::async_test;

    #[async_test]
    async fn create_then_parse_full_roundtrip() {
        let disk_size = 2 * format::GB1;
        let mut params = CreateParams {
            disk_size,
            block_size: 2 * format::MB1 as u32,
            logical_sector_size: 512,
            physical_sector_size: 4096,
            ..CreateParams::default()
        };
        let file = InMemoryFile::new(0);
        create::create(&file, &mut params).await.unwrap();
        let file_length = file.file_size().await.unwrap();

        // 1. Parse headers.
        let parsed_header = header::parse_headers(&file, file_length).await.unwrap();
        assert_eq!(parsed_header.version, format::VERSION_1);
        assert_eq!(parsed_header.log_guid, Guid::ZERO);
        assert_ne!(parsed_header.file_write_guid, Guid::ZERO);
        assert_ne!(parsed_header.data_write_guid, Guid::ZERO);

        // 2. Parse region tables.
        let regions = region::parse_region_tables(&file).await.unwrap();
        assert!(!regions.needs_rewrite);
        assert!(regions.bat_offset > 0);
        assert!(regions.metadata_offset > 0);

        // 3. Read metadata table.
        let table = MetadataTable::read(&file, regions.metadata_offset, regions.metadata_length)
            .await
            .unwrap();

        // 4. Verify known metadata.
        known_meta::verify_known_metadata(&table, false).unwrap();

        // 5. Read known metadata.
        let meta = known_meta::read_known_metadata(&file, &table, regions.metadata_offset)
            .await
            .unwrap();

        assert_eq!(meta.disk_size, disk_size);
        assert_eq!(meta.block_size, 2 * format::MB1 as u32);
        assert_eq!(meta.logical_sector_size, 512);
        assert_eq!(meta.physical_sector_size, 4096);
        assert!(!meta.has_parent);
        assert!(!meta.leave_blocks_allocated);
        assert_ne!(meta.page_83_data, Guid::ZERO);
    }

    #[async_test]
    async fn create_differencing_then_parse() {
        let mut params = CreateParams {
            disk_size: format::GB1,
            has_parent: true,
            ..CreateParams::default()
        };
        let file = InMemoryFile::new(0);
        create::create(&file, &mut params).await.unwrap();
        let file_length = file.file_size().await.unwrap();

        let _header = header::parse_headers(&file, file_length).await.unwrap();
        let regions = region::parse_region_tables(&file).await.unwrap();
        let table = MetadataTable::read(&file, regions.metadata_offset, regions.metadata_length)
            .await
            .unwrap();

        known_meta::verify_known_metadata(&table, false).unwrap();
        let meta = known_meta::read_known_metadata(&file, &table, regions.metadata_offset)
            .await
            .unwrap();

        assert!(meta.has_parent);
    }
}

#[cfg(test)]
mod log_task_integration {
    use crate::AsyncFile;
    use crate::format;
    use crate::open::VhdxFile;
    use crate::tests::support::InMemoryFile;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use zerocopy::FromBytes;

    /// Helper: create a test VHDX file with default parameters.
    async fn create_test_vhdx_file(disk_size: u64) -> InMemoryFile {
        let (file, _) = InMemoryFile::create_test_vhdx(disk_size).await;
        file
    }

    /// Helper: write a data pattern via the write path.
    async fn write_pattern<F: AsyncFile>(vhdx: &VhdxFile<F>, offset: u64, len: usize, value: u8) {
        let write_buf = vec![value; len];
        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(offset, len as u32, &mut ranges)
            .await
            .unwrap();
        for range in &ranges {
            match range {
                crate::WriteRange::Data {
                    file_offset,
                    length,
                    ..
                } => {
                    vhdx.file
                        .write_at(*file_offset, &write_buf[..(*length as usize)])
                        .await
                        .unwrap();
                }
                crate::WriteRange::Zero {
                    file_offset,
                    length,
                } => {
                    let zeros = vec![0u8; *length as usize];
                    vhdx.file.write_at(*file_offset, &zeros).await.unwrap();
                }
            }
        }
        guard.complete().await.unwrap();
    }

    /// Helper: read data at a guest offset via the read path.
    async fn read_pattern<F: AsyncFile>(vhdx: &VhdxFile<F>, offset: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let mut ranges = Vec::new();
        let _guard = vhdx
            .resolve_read(offset, len as u32, &mut ranges)
            .await
            .unwrap();
        for range in &ranges {
            match range {
                crate::ReadRange::Data {
                    guest_offset,
                    file_offset,
                    length,
                } => {
                    let start = (*guest_offset - offset) as usize;
                    let end = start + *length as usize;
                    vhdx.file
                        .read_at(*file_offset, &mut buf[start..end])
                        .await
                        .unwrap();
                }
                crate::ReadRange::Zero {
                    guest_offset,
                    length,
                } => {
                    let start = (*guest_offset - offset) as usize;
                    let end = start + *length as usize;
                    buf[start..end].fill(0);
                }
                crate::ReadRange::Unmapped { .. } => {}
            }
        }
        buf
    }

    #[async_test]
    async fn open_with_log_and_close(driver: DefaultDriver) {
        let file = create_test_vhdx_file(format::GB1).await;
        let vhdx = VhdxFile::open_with_log(file, &driver).await.unwrap();

        // Verify the file is opened in writable mode with a log task.
        assert!(!vhdx.read_only);
        assert!(vhdx.flush_sequencer.is_some());

        // Close should succeed cleanly.
        vhdx.close().await.unwrap();
    }

    #[async_test]
    async fn open_with_log_sets_log_guid(driver: DefaultDriver) {
        let file = create_test_vhdx_file(format::GB1).await;
        let vhdx = VhdxFile::open_with_log(file, &driver).await.unwrap();

        // The file should have log_guid set (the header was written during open).
        // We verify by reading the header from the file.
        let mut buf = vec![0u8; format::HEADER_SIZE as usize];
        // Read both headers and check at least one has log_guid != 0.
        vhdx.file
            .read_at(format::HEADER_OFFSET_1, &mut buf)
            .await
            .unwrap();
        let h1 = format::Header::read_from_prefix(&buf).ok().map(|(h, _)| h);
        vhdx.file
            .read_at(format::HEADER_OFFSET_2, &mut buf)
            .await
            .unwrap();
        let h2 = format::Header::read_from_prefix(&buf).ok().map(|(h, _)| h);

        let has_log_guid = h1.as_ref().is_some_and(|h| h.log_guid != guid::Guid::ZERO)
            || h2.as_ref().is_some_and(|h| h.log_guid != guid::Guid::ZERO);
        assert!(has_log_guid, "log_guid should be set after open_with_log");

        vhdx.close().await.unwrap();
    }

    #[async_test]
    async fn close_clears_log_guid(driver: DefaultDriver) {
        let file = create_test_vhdx_file(format::GB1).await;
        let vhdx = VhdxFile::open_with_log(file, &driver).await.unwrap();
        let file_ref = vhdx.file.clone();

        // Close the file.
        vhdx.close().await.unwrap();

        // After close, both headers should have log_guid == ZERO
        // (at least the current one).
        let mut buf1 = vec![0u8; format::HEADER_SIZE as usize];
        file_ref
            .read_at(format::HEADER_OFFSET_1, &mut buf1)
            .await
            .unwrap();
        let mut buf2 = vec![0u8; format::HEADER_SIZE as usize];
        file_ref
            .read_at(format::HEADER_OFFSET_2, &mut buf2)
            .await
            .unwrap();

        use zerocopy::FromBytes as _;
        let h1 = format::Header::read_from_prefix(&buf1).ok().map(|(h, _)| h);
        let h2 = format::Header::read_from_prefix(&buf2).ok().map(|(h, _)| h);

        // The current header (highest sequence_number) should have ZERO log_guid.
        let current = match (&h1, &h2) {
            (Some(a), Some(b)) if b.sequence_number >= a.sequence_number => b,
            (Some(a), _) => a,
            (_, Some(b)) => b,
            _ => panic!("no valid headers"),
        };
        assert_eq!(current.log_guid, guid::Guid::ZERO);
    }

    #[async_test]
    async fn write_flush_close_reopen(driver: DefaultDriver) {
        let file = create_test_vhdx_file(format::GB1).await;

        // Open with log, write data, flush, close.
        let file_arc = {
            let vhdx = VhdxFile::open_with_log(file, &driver).await.unwrap();
            write_pattern(&vhdx, 0, 4096, 0xAB).await;
            vhdx.flush().await.unwrap();
            let file_arc = vhdx.file.clone();
            vhdx.close().await.unwrap();
            file_arc
        };

        // Reopen (no log needed since we closed cleanly) and verify data.
        {
            let vhdx = VhdxFile::open(InMemoryFile::from_snapshot(file_arc.snapshot()), false)
                .await
                .unwrap();
            let read_buf = read_pattern(&vhdx, 0, 4096).await;
            assert!(read_buf.iter().all(|&b| b == 0xAB));
        }
    }

    #[async_test]
    async fn close_then_reopen_is_clean(driver: DefaultDriver) {
        let file = create_test_vhdx_file(format::GB1).await;

        // Open with log, do nothing, close.
        let file_arc = {
            let vhdx = VhdxFile::open_with_log(file, &driver).await.unwrap();
            let file_arc = vhdx.file.clone();
            vhdx.close().await.unwrap();
            file_arc
        };

        // Reopen — should succeed without log replay.
        let vhdx = VhdxFile::open(InMemoryFile::from_snapshot(file_arc.snapshot()), false)
            .await
            .unwrap();
        assert!(!vhdx.read_only);
    }

    #[async_test]
    async fn open_read_only_no_spawner() {
        let file = create_test_vhdx_file(format::GB1).await;
        let vhdx = VhdxFile::open_read_only(file).await.unwrap();
        assert!(vhdx.read_only);
        assert!(vhdx.flush_sequencer.is_none());
    }

    #[async_test]
    async fn flush_returns_fsn(driver: DefaultDriver) {
        let file = create_test_vhdx_file(format::GB1).await;
        let vhdx = VhdxFile::open_with_log(file, &driver).await.unwrap();

        // Write data to dirty some cache pages.
        write_pattern(&vhdx, 0, 4096, 0xEE).await;

        // Flush should return a valid FSN via the cache.
        let _fsn = vhdx.cache.flush(vhdx.log_sender.as_ref().expect("log sender")).await.unwrap();
        // FSN can be 0 if no dirty pages (BAT may or may not be dirty depending
        // on cache state). Just verify no errors.

        vhdx.close().await.unwrap();
    }

    #[async_test]
    async fn multiple_writes_single_flush(driver: DefaultDriver) {
        let file = create_test_vhdx_file(format::GB1).await;
        let vhdx = VhdxFile::open_with_log(file, &driver).await.unwrap();

        // Multiple writes at different offsets.
        write_pattern(&vhdx, 0, 4096, 0x11).await;
        write_pattern(&vhdx, 4096, 4096, 0x22).await;
        write_pattern(&vhdx, 8192, 4096, 0x33).await;

        // Single flush should handle all dirty pages.
        vhdx.flush().await.unwrap();
        let file_arc = vhdx.file.clone();
        vhdx.close().await.unwrap();

        // Reopen and verify.
        let vhdx2 = VhdxFile::open(InMemoryFile::from_snapshot(file_arc.snapshot()), false)
            .await
            .unwrap();

        let buf0 = read_pattern(&vhdx2, 0, 4096).await;
        assert!(buf0.iter().all(|&b| b == 0x11), "first write mismatch");
        let buf1 = read_pattern(&vhdx2, 4096, 4096).await;
        assert!(buf1.iter().all(|&b| b == 0x22), "second write mismatch");
        let buf2 = read_pattern(&vhdx2, 8192, 4096).await;
        assert!(buf2.iter().all(|&b| b == 0x33), "third write mismatch");
    }
}
