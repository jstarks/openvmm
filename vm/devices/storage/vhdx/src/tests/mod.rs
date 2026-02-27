// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod support;

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
        let params = CreateParams {
            disk_size,
            block_size: 2 * format::MB1 as u32,
            logical_sector_size: 512,
            physical_sector_size: 4096,
            ..CreateParams::default()
        };
        let file = InMemoryFile::new(0);
        create::create(&file, params).await.unwrap();
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
        let params = CreateParams {
            disk_size: format::GB1,
            has_parent: true,
            ..CreateParams::default()
        };
        let file = InMemoryFile::new(0);
        create::create(&file, params).await.unwrap();
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
