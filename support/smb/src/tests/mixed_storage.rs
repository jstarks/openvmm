// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::provider::{
    ByteRange, FileControl, FileControlResult, OpenOptions, QuotaInformation, RequestContext,
};
use crate::security::Sid;
use test_with_tracing::test;

fn options() -> OpenOptions<'static> {
    OpenOptions {
        access: AccessMask::FILE_ALL_ACCESS.into_bits(),
        share_access: 7,
        disposition: 2,
        options: 0,
        attributes: 0,
        allocation_size: 0,
        security: None,
        extended_attributes: None,
    }
}

#[test]
fn mixed_attributes_holes_and_quota_failures_preserve_real_stream_data() {
    block_on(async {
        for name in ["file", "file:stream"] {
            for compressed_first in [false, true] {
                let fs = MemoryFs::new(32768, 16).with_quotas().unwrap();
                let context = RequestContext::new(1);
                let (file, _) = fs.open(name, options(), &context).await.unwrap();
                let sparse = FileControl::SetSparse { sparse: true };
                let compressed = FileControl::SetCompression { format: 2 };
                let controls = if compressed_first {
                    [compressed, sparse]
                } else {
                    [sparse, compressed]
                };
                for control in controls {
                    fs.file_control(&file, control, &context).await.unwrap();
                }
                fs.write(&file, 0, &[b'A'; 8192], &context).await.unwrap();
                let info = fs.metadata(&file, &context).await.unwrap();
                assert!(
                    info.attributes().sparse_file(),
                    "{name}, compressed first {compressed_first}"
                );
                assert_eq!(info.attributes().compressed(), name == "file");
                assert_eq!(info.size, 8192);
                assert!(info.allocation_size > 0 && info.allocation_size < 32);
                let queried = fs
                    .file_control(
                        &file,
                        FileControl::QueryAllocatedRanges {
                            range: ByteRange {
                                offset: 0,
                                length: 8192,
                            },
                            maximum_ranges: 8,
                        },
                        &context,
                    )
                    .await
                    .unwrap();
                let FileControlResult::AllocatedRanges { ranges, .. } = queried else {
                    panic!("missing ranges");
                };
                assert_eq!(
                    ranges,
                    [ByteRange {
                        offset: 0,
                        length: 8192
                    }]
                );
                fs.file_control(
                    &file,
                    FileControl::SetZeroData {
                        offset: 4096,
                        end: 8192,
                    },
                    &context,
                )
                .await
                .unwrap();
                assert_eq!(fs.read(&file, 0, 4, &context).await.unwrap(), b"AAAA");
                assert_eq!(fs.read(&file, 4096, 4, &context).await.unwrap(), [0; 4]);
                let before = fs.metadata(&file, &context).await.unwrap().allocation_size;
                assert!(before > 0 && before < info.allocation_size);
                fs.set_quotas(
                    &file,
                    &[QuotaInformation {
                        sid: Sid::new([0, 0, 0, 0, 0, 5], &[18]).unwrap(),
                        changed: 0,
                        used: 0,
                        threshold: -1,
                        limit: before as i64,
                    }],
                    &context,
                )
                .await
                .unwrap();
                assert_eq!(
                    fs.write(&file, 4096, b"x", &context).await,
                    Err(Status::DISK_FULL)
                );
                assert_eq!(
                    fs.file_control(&file, FileControl::SetCompression { format: 0 }, &context)
                        .await
                        .err(),
                    Some(Status::DISK_FULL)
                );
                assert_eq!(fs.read(&file, 4096, 4, &context).await.unwrap(), [0; 4]);
                let info = fs.metadata(&file, &context).await.unwrap();
                assert_eq!(info.allocation_size, before);
                assert!(info.attributes().sparse_file());
                assert_eq!(info.attributes().compressed(), name == "file");
                fs.set_quotas(
                    &file,
                    &[QuotaInformation {
                        sid: Sid::new([0, 0, 0, 0, 0, 5], &[18]).unwrap(),
                        changed: 0,
                        used: 0,
                        threshold: -1,
                        limit: -1,
                    }],
                    &context,
                )
                .await
                .unwrap();
                fs.file_control(&file, FileControl::SetCompression { format: 0 }, &context)
                    .await
                    .unwrap();
                let info = fs.metadata(&file, &context).await.unwrap();
                assert!(info.attributes().sparse_file() && !info.attributes().compressed());
                assert_eq!((info.size, info.allocation_size), (8192, 4096));
                fs.file_control(&file, FileControl::SetSparse { sparse: false }, &context)
                    .await
                    .unwrap();
                let info = fs.metadata(&file, &context).await.unwrap();
                assert!(!info.attributes().sparse_file() && !info.attributes().compressed());
                assert_eq!(info.allocation_size, 8192);
                fs.close(&file, &context).await.unwrap();
            }
        }
    });
}

#[test]
fn compressed_sparse_huge_holes_cost_only_live_chunks_and_survive_decompression() {
    block_on(async {
        let fs = MemoryFs::new(65536, 16);
        let context = RequestContext::new(1);
        let (file, _) = fs.open("huge", options(), &context).await.unwrap();
        let huge = 1u64 << 40;
        fs.file_control(&file, FileControl::SetSparse { sparse: true }, &context)
            .await
            .unwrap();
        fs.set_len(&file, huge, &context).await.unwrap();
        fs.write(&file, huge - 4, b"tail", &context).await.unwrap();
        fs.file_control(&file, FileControl::SetCompression { format: 2 }, &context)
            .await
            .unwrap();
        fs.set_len(&file, huge + 4096, &context).await.unwrap();
        fs.write(&file, 0, b"x", &context).await.unwrap();
        assert_eq!(
            fs.read(&file, huge - 4, 4, &context).await.unwrap(),
            b"tail"
        );
        assert_eq!(fs.read(&file, 8192, 4, &context).await.unwrap(), [0; 4]);
        let info = fs.metadata(&file, &context).await.unwrap();
        assert_eq!(info.size, huge + 4096);
        assert!(info.allocation_size > 0 && info.allocation_size < 64);
        let result = fs
            .file_control(
                &file,
                FileControl::QueryAllocatedRanges {
                    range: ByteRange {
                        offset: 0,
                        length: huge + 4096,
                    },
                    maximum_ranges: 8,
                },
                &context,
            )
            .await
            .unwrap();
        let FileControlResult::AllocatedRanges { ranges, .. } = result else {
            panic!("missing ranges");
        };
        assert_eq!(
            ranges,
            [
                ByteRange {
                    offset: 0,
                    length: 4096
                },
                ByteRange {
                    offset: huge - 4096,
                    length: 4096
                },
            ]
        );
        fs.file_control(&file, FileControl::SetCompression { format: 0 }, &context)
            .await
            .unwrap();
        assert_eq!(
            fs.metadata(&file, &context).await.unwrap().allocation_size,
            5
        );
        assert_eq!(
            fs.read(&file, huge - 4, 4, &context).await.unwrap(),
            b"tail"
        );
        assert_eq!(
            fs.file_control(&file, FileControl::SetSparse { sparse: false }, &context)
                .await
                .err(),
            Some(Status::DISK_FULL)
        );
        assert!(
            fs.metadata(&file, &context)
                .await
                .unwrap()
                .attributes()
                .sparse_file()
        );
        fs.close(&file, &context).await.unwrap();
    });
}
