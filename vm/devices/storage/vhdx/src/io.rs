// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Read I/O range resolution for VHDX files.
//!
//! Given a guest virtual disk offset and length, [`VhdxFile::resolve_read`]
//! walks the request block-by-block, looks up each block's state in the BAT,
//! and emits [`ReadRange`] entries describing where to find the data.

use crate::AsyncFile;
use crate::bat;
use crate::bat::BlockType;
use crate::bat::InternalBlockMapping;
use crate::error::CorruptionType;
use crate::error::VhdxError;
use crate::format;
use crate::format::BatEntryState;
use crate::format::MB1;
use crate::open::VhdxFile;
use crate::open::WriteMode;
use crate::sector_bitmap;

/// Resolved range from a read operation.
///
/// Each range describes a contiguous portion of the read request and its
/// data source. The caller iterates these ranges to perform the actual I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadRange {
    /// Data present at this file offset. Caller should read from the VHDX file.
    Data {
        /// Byte offset within the virtual disk.
        guest_offset: u64,
        /// Length in bytes.
        length: u32,
        /// Byte offset within the VHDX file where the data lives.
        file_offset: u64,
    },
    /// Range is zero-filled. Caller should return zeros.
    Zero {
        /// Byte offset within the virtual disk.
        guest_offset: u64,
        /// Length in bytes.
        length: u32,
    },
    /// Range is unmapped (transparent to parent). Caller should read from
    /// the parent disk in a differencing chain.
    Unmapped {
        /// Byte offset within the virtual disk.
        guest_offset: u64,
        /// Length in bytes.
        length: u32,
    },
}

/// Resolved range from a write operation.
///
/// Each range describes a contiguous portion of the write target and
/// what the caller needs to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteRange {
    /// Write caller's data at this file offset.
    Data {
        /// Byte offset within the virtual disk.
        guest_offset: u64,
        /// Length in bytes.
        length: u32,
        /// Byte offset within the VHDX file where data should be written.
        file_offset: u64,
    },
    /// Zero-fill this file range (e.g. newly allocated block padding).
    Zero {
        /// Byte offset within the VHDX file to zero-fill.
        file_offset: u64,
        /// Length in bytes.
        length: u32,
    },
}

impl<F: AsyncFile> VhdxFile<F> {
    /// Resolve a read request into file-level ranges.
    ///
    /// Walks the read request block-by-block, looking up each block's state
    /// in the BAT and appending one or more [`ReadRange`] entries to `ranges`.
    /// The caller performs actual file I/O based on the returned ranges.
    ///
    /// # Errors
    ///
    /// Returns an error if the read extends beyond the virtual disk size,
    /// if the offset or length is not aligned to the logical sector size,
    /// or if a BAT entry is corrupt.
    pub async fn resolve_read(
        &self,
        offset: u64,
        len: u32,
        ranges: &mut Vec<ReadRange>,
    ) -> Result<(), VhdxError> {
        // Zero-length reads succeed immediately.
        if len == 0 {
            return Ok(());
        }

        // Validate alignment to logical sector size.
        if !offset.is_multiple_of(self.logical_sector_size as u64)
            || !(len as u64).is_multiple_of(self.logical_sector_size as u64)
        {
            return Err(VhdxError::Corrupt(CorruptionType::UnalignedIo));
        }

        // Validate bounds.
        if offset
            .checked_add(len as u64)
            .is_none_or(|end| end > self.disk_size)
        {
            return Err(VhdxError::Corrupt(CorruptionType::ReadBeyondEndOfDisk));
        }

        let mut current_offset: u32 = 0;

        while current_offset < len {
            let virtual_offset = offset + current_offset as u64;
            let block_number = self.bat.offset_to_block(virtual_offset);
            let block_offset = self.bat.offset_within_block(virtual_offset);
            let block_length = std::cmp::min(
                self.block_size - block_offset,
                len - current_offset,
            );

            let mapping = self.get_block_mapping(block_number);

            match mapping.state {
                BatEntryState::FullyPresent => {
                    let file_offset = mapping.file_offset + block_offset as u64;
                    ranges.push(ReadRange::Data {
                        guest_offset: virtual_offset,
                        length: block_length,
                        file_offset,
                    });
                }
                BatEntryState::PartiallyPresent => {
                    sector_bitmap::resolve_partial_block_read(
                        &self.cache,
                        self,
                        mapping.file_offset,
                        self.block_size,
                        self.logical_sector_size,
                        virtual_offset,
                        block_length,
                        ranges,
                    )
                    .await?;
                }
                BatEntryState::NotPresent => {
                    if self.has_parent {
                        ranges.push(ReadRange::Unmapped {
                            guest_offset: virtual_offset,
                            length: block_length,
                        });
                    } else {
                        ranges.push(ReadRange::Zero {
                            guest_offset: virtual_offset,
                            length: block_length,
                        });
                    }
                }
                BatEntryState::Zero
                | BatEntryState::Unmapped
                | BatEntryState::Undefined => {
                    ranges.push(ReadRange::Zero {
                        guest_offset: virtual_offset,
                        length: block_length,
                    });
                }
            }

            current_offset += block_length;
        }

        Ok(())
    }

    /// Resolve a write request into file-level ranges.
    ///
    /// Walks the write request block-by-block, allocating blocks as needed.
    /// For each block, emits [`WriteRange::Data`] entries describing where
    /// the caller should write data, and [`WriteRange::Zero`] entries for
    /// any newly allocated regions that must be zero-filled.
    ///
    /// Blocks that are fully-covering writes use TFP (Transitioning to Fully
    /// Present) to defer BAT commit to [`complete_write()`]. Partial writes
    /// commit the BAT immediately via per-entry cache write.
    ///
    /// Before any ranges are returned, the header is updated with new GUIDs
    /// and flushed to disk (first-write gate).
    ///
    /// After the caller writes data at the returned offsets, it **must** call
    /// [`complete_write()`](Self::complete_write) to finalize the BAT and
    /// sector bitmaps — even if the data I/O failed (pass `success: false`).
    pub async fn resolve_write(
        &self,
        offset: u64,
        len: u32,
        ranges: &mut Vec<WriteRange>,
    ) -> Result<(), VhdxError> {
        // Check read-only.
        if self.read_only {
            return Err(VhdxError::ReadOnly);
        }

        // Zero-length writes succeed immediately.
        if len == 0 {
            return Ok(());
        }

        // Validate alignment to logical sector size.
        if !offset.is_multiple_of(self.logical_sector_size as u64)
            || !(len as u64).is_multiple_of(self.logical_sector_size as u64)
        {
            return Err(VhdxError::Corrupt(CorruptionType::UnalignedIo));
        }

        // Validate bounds.
        if offset
            .checked_add(len as u64)
            .is_none_or(|end| end > self.disk_size)
        {
            return Err(VhdxError::Corrupt(CorruptionType::ReadBeyondEndOfDisk));
        }

        // First-write gate: update header with new GUIDs before any data.
        self.enable_write_mode(WriteMode::DataWritable).await?;

        // Track which blocks we've resolved in the read phase.
        // Blocks needing allocation are collected for the allocation phase.
        struct BlockInfo {
            block_number: u32,
            block_offset: u32,
            block_length: u32,
            virtual_offset: u64,
        }

        let mut current_offset: u32 = 0;
        let mut blocks_needing_allocation = Vec::new();

        // --- Read phase: check BAT state for each block ---
        while current_offset < len {
            let virtual_offset = offset + current_offset as u64;
            let block_number = self.bat.offset_to_block(virtual_offset);
            let block_offset = self.bat.offset_within_block(virtual_offset);
            let block_length = std::cmp::min(
                self.block_size - block_offset,
                len - current_offset,
            );

            let is_full_block = block_offset == 0 && block_length >= self.block_size;

            // Read the in-memory BAT state.
            loop {
                let (state, file_offset, has_tfp) = {
                    let bat_state = self.bat_state.read();
                    let internal = bat_state.get_payload_mapping(block_number);
                    let mapping = self.bat.get_block_mapping_from_state(&bat_state, block_number);
                    (mapping.state, mapping.file_offset, internal.transitioning_to_fully_present())
                };

                if has_tfp {
                    // Block is being allocated by another task — wait and retry.
                    let listener = {
                        let _bat_state = self.bat_state.read();
                        // Re-check under lock to avoid wake-miss race.
                        let internal = _bat_state.get_payload_mapping(block_number);
                        if !internal.transitioning_to_fully_present() {
                            continue; // TFP cleared while we were setting up — retry
                        }
                        self.allocation_event.listen()
                    };
                    listener.await;
                    continue;
                }

                match state {
                    BatEntryState::FullyPresent => {
                        ranges.push(WriteRange::Data {
                            guest_offset: virtual_offset,
                            length: block_length,
                            file_offset: file_offset + block_offset as u64,
                        });
                        break;
                    }
                    BatEntryState::PartiallyPresent if !is_full_block => {
                        // Partial write to already-allocated block — write
                        // directly. complete_write() updates sector bitmaps.
                        ranges.push(WriteRange::Data {
                            guest_offset: virtual_offset,
                            length: block_length,
                            file_offset: file_offset + block_offset as u64,
                        });
                        break;
                    }
                    BatEntryState::PartiallyPresent => {
                        // Fully-covering write to PartiallyPresent block —
                        // needs TFP to promote to FullyPresent. Fall through
                        // to allocation phase.
                        blocks_needing_allocation.push(BlockInfo {
                            block_number,
                            block_offset,
                            block_length,
                            virtual_offset,
                        });
                        break;
                    }
                    BatEntryState::NotPresent
                    | BatEntryState::Zero
                    | BatEntryState::Unmapped
                    | BatEntryState::Undefined => {
                        // Unallocated — needs allocation.
                        blocks_needing_allocation.push(BlockInfo {
                            block_number,
                            block_offset,
                            block_length,
                            virtual_offset,
                        });
                        break;
                    }
                }
            }

            current_offset += block_length;
        }

        // If nothing needs allocation, we're done.
        if blocks_needing_allocation.is_empty() {
            return Ok(());
        }

        // --- Allocation phase: acquire BlockAllocationLock ---
        let _alloc_guard = self.allocation_lock.lock().await;

        // Track blocks that got TFP set (for error cleanup).
        struct TfpRecord {
            block_number: u32,
            original_mapping: InternalBlockMapping,
        }
        let mut tfp_records: Vec<TfpRecord> = Vec::new();

        // Re-check and allocate under the lock.
        let allocation_result = async {
            // Re-check all blocks under bat_state read lock for TFP set by
            // a concurrent allocator.
            {
                let bat_state = self.bat_state.read();
                for block_info in &blocks_needing_allocation {
                    let internal = bat_state.get_payload_mapping(block_info.block_number);
                    if internal.transitioning_to_fully_present() {
                        // Another allocator just claimed this block.
                        // We need to drop everything and restart.
                        // For simplicity in the sequential case, this
                        // should not happen. If it does, we'll get an
                        // error that the caller can retry.
                        return Err(VhdxError::Corrupt(CorruptionType::Other));
                    }
                }
            }

            for block_info in &blocks_needing_allocation {
                let is_full_block =
                    block_info.block_offset == 0 && block_info.block_length >= self.block_size;

                // Re-read mapping under lock (may have changed since read phase).
                let (internal, mapping) = {
                    let bat_state = self.bat_state.read();
                    let internal = bat_state.get_payload_mapping(block_info.block_number);
                    let mapping =
                        self.bat.get_block_mapping_from_state(&bat_state, block_info.block_number);
                    (internal, mapping)
                };

                match mapping.state {
                    BatEntryState::FullyPresent => {
                        // Already allocated by a concurrent writer — just emit range.
                        ranges.push(WriteRange::Data {
                            guest_offset: block_info.virtual_offset,
                            length: block_info.block_length,
                            file_offset: mapping.file_offset + block_info.block_offset as u64,
                        });
                    }
                    BatEntryState::PartiallyPresent if is_full_block => {
                        // Fully-covering write to PartiallyPresent — set TFP
                        // on existing mapping, no new space.
                        let original = internal;
                        let new_mapping = InternalBlockMapping::new()
                            .with_state(internal.state())
                            .with_transitioning_to_fully_present(true)
                            .with_file_megabyte(internal.file_megabyte());

                        {
                            let mut bat_state = self.bat_state.write();
                            bat_state.set_payload_mapping(
                                &self.bat,
                                block_info.block_number,
                                new_mapping,
                            );
                        }

                        tfp_records.push(TfpRecord {
                            block_number: block_info.block_number,
                            original_mapping: original,
                        });

                        ranges.push(WriteRange::Data {
                            guest_offset: block_info.virtual_offset,
                            length: block_info.block_length,
                            file_offset: mapping.file_offset + block_info.block_offset as u64,
                        });
                    }
                    _ => {
                        // Unallocated block — allocate space.
                        let new_offset = self.allocate_space(self.block_size);
                        let original = internal;

                        if is_full_block {
                            // Fully-covering: set TFP, defer BAT commit.
                            let new_mapping = InternalBlockMapping::new()
                                .with_state(internal.state())
                                .with_transitioning_to_fully_present(true)
                                .with_file_megabyte((new_offset / MB1) as u32);

                            {
                                let mut bat_state = self.bat_state.write();
                                bat_state.set_payload_mapping(
                                    &self.bat,
                                    block_info.block_number,
                                    new_mapping,
                                );
                            }

                            tfp_records.push(TfpRecord {
                                block_number: block_info.block_number,
                                original_mapping: original,
                            });

                            ranges.push(WriteRange::Data {
                                guest_offset: block_info.virtual_offset,
                                length: block_info.block_length,
                                file_offset: new_offset + block_info.block_offset as u64,
                            });
                        } else {
                            // Partial write — commit BAT immediately.
                            let new_mapping = InternalBlockMapping::new()
                                .with_state(BatEntryState::FullyPresent as u8)
                                .with_transitioning_to_fully_present(false)
                                .with_file_megabyte((new_offset / MB1) as u32);

                            {
                                let mut bat_state = self.bat_state.write();
                                bat_state.set_payload_mapping(
                                    &self.bat,
                                    block_info.block_number,
                                    new_mapping,
                                );
                            }

                            // Per-entry cache write (write-through to disk).
                            self.write_bat_entry_to_cache(
                                BlockType::Payload,
                                block_info.block_number,
                                new_mapping,
                            )
                            .await?;

                            // Emit zero + data + zero ranges.
                            if block_info.block_offset > 0 {
                                ranges.push(WriteRange::Zero {
                                    file_offset: new_offset,
                                    length: block_info.block_offset,
                                });
                            }

                            ranges.push(WriteRange::Data {
                                guest_offset: block_info.virtual_offset,
                                length: block_info.block_length,
                                file_offset: new_offset + block_info.block_offset as u64,
                            });

                            let end_offset = block_info.block_offset + block_info.block_length;
                            if end_offset < self.block_size {
                                ranges.push(WriteRange::Zero {
                                    file_offset: new_offset + end_offset as u64,
                                    length: self.block_size - end_offset,
                                });
                            }
                        }
                    }
                }
            }

            // Extend the file to cover new allocations (under allocation lock).
            let target_eof = *self.eof_offset.lock();
            self.file
                .set_file_size(target_eof)
                .await
                .map_err(VhdxError::Io)?;

            Ok(())
        }
        .await;

        // Error cleanup: revert TFP-marked blocks on failure.
        if let Err(e) = allocation_result {
            {
                let mut bat_state = self.bat_state.write();
                for record in &tfp_records {
                    bat_state.set_payload_mapping(
                        &self.bat,
                        record.block_number,
                        record.original_mapping,
                    );
                }
            }
            self.allocation_event.notify(usize::MAX);
            return Err(e);
        }

        // Allocation lock is released when _alloc_guard drops (after
        // returning ranges to caller).
        Ok(())
    }

    /// Finalize a write operation.
    ///
    /// Must be called after every successful [`resolve_write()`], regardless
    /// of whether the data I/O succeeded. Pass `success: false` if the data
    /// writes failed to revert TFP blocks and unblock concurrent writers.
    ///
    /// **Success path**: Clears TFP flags, sets state to FullyPresent, writes
    /// per-entry BAT to cache, notifies waiters. For PartiallyPresent blocks
    /// (non-TFP, i.e. partial writes to differencing disks), updates sector
    /// bitmaps.
    ///
    /// **Failure path**: Reverts TFP blocks to their original state and
    /// notifies waiters. Does not write BAT entries to cache.
    pub async fn complete_write(
        &self,
        offset: u64,
        len: u32,
        success: bool,
    ) -> Result<(), VhdxError> {
        // Zero-length — nothing to do.
        if len == 0 {
            return Ok(());
        }

        let mut had_tfp = false;
        let mut bat_write_error: Option<VhdxError> = None;

        let mut current_offset: u32 = 0;

        while current_offset < len {
            let virtual_offset = offset + current_offset as u64;
            let block_number = self.bat.offset_to_block(virtual_offset);
            let block_offset = self.bat.offset_within_block(virtual_offset);
            let block_length = std::cmp::min(
                self.block_size - block_offset,
                len - current_offset,
            );

            // Read the in-memory mapping to check for TFP.
            let internal = {
                let bat_state = self.bat_state.read();
                bat_state.get_payload_mapping(block_number)
            };

            if internal.transitioning_to_fully_present() {
                had_tfp = true;

                if success {
                    // Success: clear TFP, set FullyPresent.
                    let final_mapping = InternalBlockMapping::new()
                        .with_state(BatEntryState::FullyPresent as u8)
                        .with_transitioning_to_fully_present(false)
                        .with_file_megabyte(internal.file_megabyte());

                    {
                        let mut bat_state = self.bat_state.write();
                        bat_state.set_payload_mapping(
                            &self.bat,
                            block_number,
                            final_mapping,
                        );
                    }

                    // Write per-entry to cache. Errors are deferred so we
                    // can still notify waiters.
                    if bat_write_error.is_none() {
                        if let Err(e) = self
                            .write_bat_entry_to_cache(
                                BlockType::Payload,
                                block_number,
                                final_mapping,
                            )
                            .await
                        {
                            bat_write_error = Some(e);
                        }
                    }
                } else {
                    // Failure: revert to original state.
                    // If the original state was PartiallyPresent (block was
                    // already allocated), keep the file_megabyte.
                    // Otherwise, restore zero offset.
                    let original_state =
                        BatEntryState::from_raw(internal.state()).unwrap_or(BatEntryState::NotPresent);
                    let reverted = match original_state {
                        BatEntryState::PartiallyPresent => {
                            InternalBlockMapping::new()
                                .with_state(internal.state())
                                .with_transitioning_to_fully_present(false)
                                .with_file_megabyte(internal.file_megabyte())
                        }
                        _ => {
                            // Freshly allocated — revert to original state
                            // with zero offset. Space is leaked.
                            InternalBlockMapping::new()
                                .with_state(internal.state())
                                .with_transitioning_to_fully_present(false)
                                .with_file_megabyte(0)
                        }
                    };

                    {
                        let mut bat_state = self.bat_state.write();
                        bat_state.set_payload_mapping(
                            &self.bat,
                            block_number,
                            reverted,
                        );
                        bat_state.mark_bat_page_dirty(
                            &self.bat,
                            BlockType::Payload,
                            block_number,
                        );
                    }
                }
            } else if success && self.has_parent {
                // Non-TFP PartiallyPresent blocks: update sector bitmaps.
                let mapping = self.get_block_mapping(block_number);
                if mapping.state == BatEntryState::PartiallyPresent {
                    sector_bitmap::set_sector_bitmap_bits(
                        &self.cache,
                        self,
                        virtual_offset,
                        block_length,
                        self.logical_sector_size,
                        self.block_size,
                        true,
                    )
                    .await?;
                }
            }

            current_offset += block_length;
        }

        // Notify waiters ALWAYS, even on failure or cache write error.
        if had_tfp {
            self.allocation_event.notify(usize::MAX);
        }

        // Propagate any deferred BAT cache write error.
        if let Some(e) = bat_write_error {
            return Err(e);
        }

        Ok(())
    }

    /// Flush all writes to stable storage.
    ///
    /// Writes any dirty BAT pages to disk, then issues a file-level flush
    /// for durability.
    pub async fn flush(&self) -> Result<(), VhdxError> {
        self.flush_dirty_bat_pages().await?;
        self.file.flush().await.map_err(VhdxError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{self, CreateParams};
    use crate::format;
    use crate::format::BatEntry;
    use crate::open::VhdxFile;
    use crate::region;
    use crate::tests::support::InMemoryFile;
    use guid::Guid;
    use pal_async::async_test;
    use zerocopy::IntoBytes;

    #[async_test]
    async fn read_empty_disk_returns_zero() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: 0,
                length: 4096,
            }
        );
    }

    #[async_test]
    async fn read_zero_length() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        vhdx.resolve_read(0, 0, &mut ranges).await.unwrap();

        assert!(ranges.is_empty());
    }

    #[async_test]
    async fn read_beyond_end_of_disk() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        // Read 512 bytes past the end (both offset and length are sector-aligned).
        let result = vhdx
            .resolve_read(format::GB1 - 512, 1024, &mut ranges)
            .await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::ReadBeyondEndOfDisk))
        ));
    }

    #[async_test]
    async fn read_at_disk_end_exact() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        vhdx.resolve_read(format::GB1 - 4096, 4096, &mut ranges)
            .await
            .unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: format::GB1 - 4096,
                length: 4096,
            }
        );
    }

    #[async_test]
    async fn read_fully_present_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();
        let bat_offset = regions.bat_offset;

        // Write a FullyPresent BAT entry for block 0 at file_offset_mb = 100.
        let entry = BatEntry::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_offset_mb(100);
        file.write_at(bat_offset, entry.as_bytes()).await.unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let mut ranges = Vec::new();
        vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Data {
                guest_offset: 0,
                length: 4096,
                file_offset: 100 * format::MB1,
            }
        );
    }

    #[async_test]
    async fn read_spanning_two_blocks() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let block_size = vhdx.block_size() as u64;
        let mut ranges = Vec::new();
        // Read last 512 bytes of block 0 and first 512 bytes of block 1.
        vhdx.resolve_read((block_size - 512) as u64, 1024, &mut ranges)
            .await
            .unwrap();

        assert_eq!(ranges.len(), 2);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: block_size - 512,
                length: 512,
            }
        );
        assert_eq!(
            ranges[1],
            ReadRange::Zero {
                guest_offset: block_size,
                length: 512,
            }
        );
    }

    #[async_test]
    async fn read_spanning_multiple_blocks() {
        // Use a small disk with 1 MiB blocks so spans are easier to test.
        let file = InMemoryFile::new(0);
        let block_size = format::MB1 as u32;
        let mut params = CreateParams {
            disk_size: 4 * format::MB1,
            block_size,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        // Read across blocks 0, 1, 2: start at 512 KiB, length = 2 MiB.
        // Block 0: 512 KiB remaining. Block 1: full 1 MiB. Block 2: 512 KiB.
        let start = format::MB1 / 2; // middle of block 0
        let len = (2 * format::MB1) as u32; // spans 3 blocks
        vhdx.resolve_read(start, len, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 3);
        // Block 0: remaining half
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: start,
                length: (format::MB1 / 2) as u32,
            }
        );
        // Block 1: full block
        assert_eq!(
            ranges[1],
            ReadRange::Zero {
                guest_offset: format::MB1,
                length: block_size,
            }
        );
        // Block 2: first half
        assert_eq!(
            ranges[2],
            ReadRange::Zero {
                guest_offset: 2 * format::MB1,
                length: (format::MB1 / 2) as u32,
            }
        );
    }

    #[async_test]
    async fn read_unaligned_within_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        // Set block 0 to FullyPresent at file_offset_mb = 50.
        let entry = BatEntry::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_offset_mb(50);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let mut ranges = Vec::new();
        // Read 512 bytes starting at sector 10 (offset 5120).
        vhdx.resolve_read(5120, 512, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Data {
                guest_offset: 5120,
                length: 512,
                file_offset: 50 * format::MB1 + 5120,
            }
        );
    }

    #[async_test]
    async fn read_differencing_not_present() {
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            has_parent: true,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Unmapped {
                guest_offset: 0,
                length: 4096,
            }
        );
    }

    #[async_test]
    async fn read_zero_state_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        // Set block 0 to Zero state.
        let entry = BatEntry::new()
            .with_state(BatEntryState::Zero as u8)
            .with_file_offset_mb(0);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let mut ranges = Vec::new();
        vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: 0,
                length: 4096,
            }
        );
    }

    #[async_test]
    async fn read_unmapped_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        // Set block 0 to Unmapped (trimmed) state.
        let entry = BatEntry::new()
            .with_state(BatEntryState::Unmapped as u8)
            .with_file_offset_mb(0);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let mut ranges = Vec::new();
        vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: 0,
                length: 4096,
            }
        );
    }

    #[async_test]
    async fn read_undefined_state_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        // Set block 0 to Undefined state (value 1).
        let entry = BatEntry::new()
            .with_state(BatEntryState::Undefined as u8)
            .with_file_offset_mb(0);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let mut ranges = Vec::new();
        vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: 0,
                length: 4096,
            }
        );
    }

    #[async_test]
    async fn read_entire_disk() {
        // Small disk: 4 MiB with 2 MiB blocks = 2 blocks.
        let disk_size = 4 * format::MB1;
        let (file, _) = InMemoryFile::create_test_vhdx(disk_size).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        vhdx.resolve_read(0, disk_size as u32, &mut ranges)
            .await
            .unwrap();

        // 2 blocks, each produces one Zero range.
        assert_eq!(ranges.len(), 2);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: 0,
                length: format::DEFAULT_BLOCK_SIZE,
            }
        );
        assert_eq!(
            ranges[1],
            ReadRange::Zero {
                guest_offset: format::DEFAULT_BLOCK_SIZE as u64,
                length: format::DEFAULT_BLOCK_SIZE,
            }
        );
    }

    #[async_test]
    async fn read_4k_sector_disk() {
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            logical_sector_size: 4096,
            physical_sector_size: 4096,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        // Read one 4K sector.
        vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: 0,
                length: 4096,
            }
        );

        // Unaligned read should fail.
        let mut ranges2 = Vec::new();
        let result = vhdx.resolve_read(512, 4096, &mut ranges2).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::UnalignedIo))
        ));
    }

    // ---- Write tests ----

    #[async_test]
    async fn write_to_empty_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        vhdx.resolve_write(0, 4096, &mut ranges).await.unwrap();

        // Should allocate a new block: Zero padding before (none at offset 0),
        // Data for the write, Zero padding after.
        // At offset 0 within block: no leading padding.
        // block_size = 2 MiB, writing 4096 bytes at offset 0:
        //   Data(0, 4096, file_offset)
        //   Zero(file_offset+4096, block_size-4096)
        assert!(ranges.len() >= 2);
        // First should be Data
        match ranges[0] {
            WriteRange::Data {
                guest_offset,
                length,
                file_offset,
            } => {
                assert_eq!(guest_offset, 0);
                assert_eq!(length, 4096);
                // file_offset should be MB-aligned.
                assert!(file_offset > 0);
                assert_eq!(file_offset % format::MB1, 0);
            }
            _ => panic!("expected Data range, got {:?}", ranges[0]),
        }
        // Second should be Zero (trailing padding to fill the block).
        match ranges[1] {
            WriteRange::Zero {
                file_offset,
                length,
            } => {
                assert_eq!(length, format::DEFAULT_BLOCK_SIZE - 4096);
                assert!(file_offset > 0);
            }
            _ => panic!("expected Zero range, got {:?}", ranges[1]),
        }
    }

    #[async_test]
    async fn write_to_fully_present_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        // Write a FullyPresent BAT entry for block 0 at file_offset_mb = 100.
        let entry = BatEntry::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_offset_mb(100);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let mut ranges = Vec::new();
        vhdx.resolve_write(0, 4096, &mut ranges).await.unwrap();

        // Should write directly to the existing block — single Data range.
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            WriteRange::Data {
                guest_offset: 0,
                length: 4096,
                file_offset: 100 * format::MB1,
            }
        );
    }

    #[async_test]
    async fn write_spanning_two_blocks() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let block_size = vhdx.block_size() as u64;
        let mut ranges = Vec::new();
        // Write last 512 bytes of block 0 and first 512 bytes of block 1.
        vhdx.resolve_write((block_size - 512) as u64, 1024, &mut ranges)
            .await
            .unwrap();

        // Each block needs allocation. Filter out the data ranges.
        let data_ranges: Vec<_> = ranges
            .iter()
            .filter(|r| matches!(r, WriteRange::Data { .. }))
            .collect();
        assert_eq!(data_ranges.len(), 2, "expected 2 Data ranges for 2 blocks");

        // First Data: last 512 bytes of block 0.
        match data_ranges[0] {
            WriteRange::Data {
                guest_offset,
                length,
                ..
            } => {
                assert_eq!(*guest_offset, block_size - 512);
                assert_eq!(*length, 512);
            }
            _ => unreachable!(),
        }
        // Second Data: first 512 bytes of block 1.
        match data_ranges[1] {
            WriteRange::Data {
                guest_offset,
                length,
                ..
            } => {
                assert_eq!(*guest_offset, block_size);
                assert_eq!(*length, 512);
            }
            _ => unreachable!(),
        }
    }

    #[async_test]
    async fn write_then_read_roundtrip() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        // Step 1: resolve_write to get file offsets.
        let mut write_ranges = Vec::new();
        vhdx.resolve_write(0, 512, &mut write_ranges).await.unwrap();

        // Step 2: Write actual data at the returned Data offsets.
        let pattern: Vec<u8> = (0..512u16).map(|i| (i % 256) as u8).collect();
        for wr in &write_ranges {
            match wr {
                WriteRange::Data { file_offset, length, .. } => {
                    vhdx.file
                        .write_at(*file_offset, &pattern[..(*length as usize)])
                        .await
                        .unwrap();
                }
                WriteRange::Zero { file_offset, length } => {
                    let zeros = vec![0u8; *length as usize];
                    vhdx.file.write_at(*file_offset, &zeros).await.unwrap();
                }
            }
        }

        // Step 3: complete_write.
        vhdx.complete_write(0, 512, true).await.unwrap();

        // Step 4: resolve_read at the same offset.
        let mut read_ranges = Vec::new();
        vhdx.resolve_read(0, 512, &mut read_ranges).await.unwrap();

        // Should now be Data (block was allocated).
        assert_eq!(read_ranges.len(), 1);
        match &read_ranges[0] {
            ReadRange::Data {
                file_offset,
                length,
                ..
            } => {
                assert_eq!(*length, 512);
                let mut buf = vec![0u8; 512];
                vhdx.file.read_at(*file_offset, &mut buf).await.unwrap();
                assert_eq!(buf, pattern);
            }
            other => panic!("expected Data read range, got {:?}", other),
        }
    }

    #[async_test]
    async fn write_partial_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        // Write 512 bytes at offset 4096 within block 0.
        let mut ranges = Vec::new();
        vhdx.resolve_write(4096, 512, &mut ranges).await.unwrap();

        // Should have: Zero(leading 4096), Data(512), Zero(trailing).
        assert_eq!(ranges.len(), 3);
        match ranges[0] {
            WriteRange::Zero { length, .. } => assert_eq!(length, 4096),
            _ => panic!("expected leading Zero, got {:?}", ranges[0]),
        }
        match ranges[1] {
            WriteRange::Data {
                guest_offset,
                length,
                ..
            } => {
                assert_eq!(guest_offset, 4096);
                assert_eq!(length, 512);
            }
            _ => panic!("expected Data, got {:?}", ranges[1]),
        }
        match ranges[2] {
            WriteRange::Zero { length, .. } => {
                assert_eq!(
                    length,
                    format::DEFAULT_BLOCK_SIZE - 4096 - 512
                );
            }
            _ => panic!("expected trailing Zero, got {:?}", ranges[2]),
        }
    }

    #[async_test]
    async fn write_full_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        // Write exactly one full block (no padding needed).
        let mut ranges = Vec::new();
        vhdx.resolve_write(0, format::DEFAULT_BLOCK_SIZE, &mut ranges)
            .await
            .unwrap();

        // Should be exactly one Data range — no zero padding.
        assert_eq!(ranges.len(), 1);
        match ranges[0] {
            WriteRange::Data {
                guest_offset,
                length,
                file_offset,
            } => {
                assert_eq!(guest_offset, 0);
                assert_eq!(length, format::DEFAULT_BLOCK_SIZE);
                assert!(file_offset > 0);
                assert_eq!(file_offset % format::MB1, 0);
            }
            _ => panic!("expected Data range, got {:?}", ranges[0]),
        }
    }

    #[async_test]
    async fn write_zero_length() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        vhdx.resolve_write(0, 0, &mut ranges).await.unwrap();
        assert!(ranges.is_empty());
    }

    #[async_test]
    async fn write_beyond_end_of_disk() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let mut ranges = Vec::new();
        let result = vhdx
            .resolve_write(format::GB1 - 512, 1024, &mut ranges)
            .await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::ReadBeyondEndOfDisk))
        ));
    }

    #[async_test]
    async fn write_read_only() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, true).await.unwrap();

        let mut ranges = Vec::new();
        let result = vhdx.resolve_write(0, 4096, &mut ranges).await;
        assert!(matches!(result, Err(VhdxError::ReadOnly)));
    }

    #[async_test]
    async fn write_large_spanning_many_blocks() {
        // 4 MiB disk with 1 MiB blocks → 4 blocks.
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: 4 * format::MB1,
            block_size: format::MB1 as u32,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        // Write 3 MiB starting at offset 512 KiB (spans blocks 0,1,2,3).
        let start = format::MB1 / 2;
        let length = (3 * format::MB1) as u32;
        let mut ranges = Vec::new();
        vhdx.resolve_write(start, length, &mut ranges)
            .await
            .unwrap();

        let data_ranges: Vec<_> = ranges
            .iter()
            .filter(|r| matches!(r, WriteRange::Data { .. }))
            .collect();
        // Should span 4 blocks: partial block 0, full block 1, full block 2, partial block 3.
        assert_eq!(data_ranges.len(), 4);

        // Verify guest offsets and lengths.
        let block_size = format::MB1;
        match data_ranges[0] {
            WriteRange::Data {
                guest_offset,
                length,
                ..
            } => {
                assert_eq!(*guest_offset, start);
                assert_eq!(*length as u64, block_size - start);
            }
            _ => unreachable!(),
        }
        match data_ranges[1] {
            WriteRange::Data {
                guest_offset,
                length,
                ..
            } => {
                assert_eq!(*guest_offset, block_size);
                assert_eq!(*length as u64, block_size);
            }
            _ => unreachable!(),
        }
        match data_ranges[2] {
            WriteRange::Data {
                guest_offset,
                length,
                ..
            } => {
                assert_eq!(*guest_offset, 2 * block_size);
                assert_eq!(*length as u64, block_size);
            }
            _ => unreachable!(),
        }
        match data_ranges[3] {
            WriteRange::Data {
                guest_offset,
                length,
                ..
            } => {
                assert_eq!(*guest_offset, 3 * block_size);
                assert_eq!(*length as u64, start); // remaining half of last block
            }
            _ => unreachable!(),
        }
    }

    #[async_test]
    async fn first_write_updates_header() {
        let (file, params) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let original_data_guid = params.data_write_guid;
        assert_eq!(vhdx.data_write_guid(), original_data_guid);

        // Perform a write — this triggers enable_write_mode.
        let mut ranges = Vec::new();
        vhdx.resolve_write(0, 512, &mut ranges).await.unwrap();

        // data_write_guid should have changed.
        let new_data_guid = vhdx.data_write_guid();
        assert_ne!(new_data_guid, original_data_guid);
        assert_ne!(new_data_guid, Guid::ZERO);
    }

    #[async_test]
    async fn second_write_no_header_update() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        // First write — triggers header update.
        let mut ranges = Vec::new();
        vhdx.resolve_write(0, 512, &mut ranges).await.unwrap();
        let guid_after_first = vhdx.data_write_guid();

        // Second write — should NOT update header again.
        let mut ranges2 = Vec::new();
        vhdx.resolve_write(512, 512, &mut ranges2).await.unwrap();
        let guid_after_second = vhdx.data_write_guid();

        assert_eq!(guid_after_first, guid_after_second);
    }

    #[async_test]
    async fn file_writable_only_does_not_change_data_guid() {
        let (file, params) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let original_data_guid = params.data_write_guid;

        // Enable FileWritable mode (metadata-only modification).
        vhdx.enable_write_mode(WriteMode::FileWritable).await.unwrap();

        // data_write_guid should NOT have changed.
        assert_eq!(vhdx.data_write_guid(), original_data_guid);

        // But the write mode should be set (subsequent DataWritable will escalate).
        let state = vhdx.write_state.lock();
        assert_eq!(state.write_mode, Some(WriteMode::FileWritable));
    }
}
