// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Read I/O range resolution for VHDX files.
//!
//! Given a guest virtual disk offset and length, [`VhdxFile::resolve_read`]
//! walks the request block-by-block, looks up each block's state in the BAT,
//! and emits [`ReadRange`] entries describing where to find the data.

use crate::AsyncFile;
use crate::bat::BlockType;
use crate::bat::InternalBlockMapping;
use crate::error::CorruptionType;
use crate::error::VhdxError;
use crate::format::BatEntryState;
use crate::format::MB1;
use crate::io_guard::ReadIoGuard;
use crate::io_guard::WriteIoGuard;
use crate::open::VhdxFile;
use crate::open::WriteMode;
use crate::space::AllocateFlags;

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
    ) -> Result<ReadIoGuard<'_, F>, VhdxError> {
        // Zero-length reads succeed immediately.
        if len == 0 {
            return Ok(ReadIoGuard::new(self, 0, 0));
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
            let block_length = std::cmp::min(self.block_size - block_offset, len - current_offset);

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
                    self.resolve_partial_block_read(
                        mapping.file_offset,
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
                BatEntryState::Zero | BatEntryState::Unmapped | BatEntryState::Undefined => {
                    ranges.push(ReadRange::Zero {
                        guest_offset: virtual_offset,
                        length: block_length,
                    });
                }
            }

            current_offset += block_length;
        }

        // Compute the block range and increment refcounts.
        let start_block = self.bat.offset_to_block(offset);
        let end_block = self.bat.offset_to_block(offset + len as u64 - 1);
        let block_count = end_block - start_block + 1;

        {
            let mut bat_state = self.bat_state.write();
            for block in start_block..start_block + block_count {
                bat_state.increment_io_refcount(block);
            }
        }

        Ok(ReadIoGuard::new(self, start_block, block_count))
    }

    /// Resolve a write request into file-level ranges.
    ///
    /// Walks the write request block-by-block, allocating blocks as needed.
    /// For each block, emits [`WriteRange::Data`] entries describing where
    /// the caller should write data, and [`WriteRange::Zero`] entries for
    /// any newly allocated regions that must be zero-filled.
    ///
    /// Blocks that are fully-covering writes use TFP (Transitioning to Fully
    /// Present) to defer BAT commit to [`WriteIoGuard::complete()`]. Partial writes
    /// commit the BAT immediately via per-entry cache write.
    ///
    /// Before any ranges are returned, the header is updated with new GUIDs
    /// and flushed to disk (first-write gate).
    ///
    /// After the caller writes data at the returned offsets, it **must** call
    /// [`WriteIoGuard::complete()`] to finalize the BAT and sector bitmaps.
    /// Dropping the guard without calling `complete()` aborts the write.
    pub async fn resolve_write(
        &self,
        offset: u64,
        len: u32,
        ranges: &mut Vec<WriteRange>,
    ) -> Result<WriteIoGuard<'_, F>, VhdxError> {
        // Check read-only.
        if self.read_only {
            return Err(VhdxError::ReadOnly);
        }

        // Zero-length writes succeed immediately.
        if len == 0 {
            return Ok(WriteIoGuard::new_completed(self));
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
            let block_length = std::cmp::min(self.block_size - block_offset, len - current_offset);

            let is_full_block = block_offset == 0 && block_length >= self.block_size;

            // Read the in-memory BAT state.
            loop {
                let (state, file_offset, has_tfp) = {
                    let bat_state = self.bat_state.read();
                    let internal = bat_state.get_payload_mapping(block_number);
                    let mapping = self
                        .bat
                        .get_block_mapping_from_state(&bat_state, block_number);
                    (
                        mapping.state,
                        mapping.file_offset,
                        internal.transitioning_to_fully_present(),
                    )
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
                    // LOCK AUDIT: bat_state read-lock dropped above (end of block). Safe to await.
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
            // Compute block range and increment refcounts.
            let start_block = self.bat.offset_to_block(offset);
            let end_block = self.bat.offset_to_block(offset + len as u64 - 1);
            let block_count = end_block - start_block + 1;

            {
                let mut bat_state = self.bat_state.write();
                for block in start_block..start_block + block_count {
                    bat_state.increment_io_refcount(block);
                }
            }

            return Ok(WriteIoGuard::new(
                self,
                offset,
                len,
                start_block,
                block_count,
                false, // no allocation → no flush barrier needed
            ));
        }

        // --- Allocation phase: acquire BlockAllocationLock ---
        // Wait until no blocks in our allocation set have TFP set by
        // a concurrent allocator. This matches the C code's
        // OverlappingAllocations serialization: if another writer is
        // transitioning any of our blocks, we park and wait for that
        // writer's post-allocate to clear TFP before proceeding.
        // LOCK AUDIT: No synchronous locks held entering allocation loop.
        // allocation_lock (futures::Mutex) is acquired via .await — fine.
        let _alloc_guard = loop {
            let alloc_guard = self.allocation_lock.lock().await;

            // Check all blocks under BAT lock for TFP overlap.
            // Register listener before dropping locks to avoid missed wakes.
            let listener = {
                let bat_state = self.bat_state.read();
                let has_overlap = blocks_needing_allocation.iter().any(|block_info| {
                    bat_state
                        .get_payload_mapping(block_info.block_number)
                        .transitioning_to_fully_present()
                });
                if !has_overlap {
                    break alloc_guard;
                }
                // Register listener while holding bat_state lock to
                // avoid wake-miss race.
                self.allocation_event.listen()
            };

            // Drop the allocation lock before waiting so that the
            // concurrent writer can complete its post-allocate.
            drop(alloc_guard);
            // LOCK AUDIT: Both allocation_lock and bat_state dropped above. Safe to await.
            listener.await;
        };

        // Track blocks that got TFP set (for error cleanup).
        struct TfpRecord {
            block_number: u32,
            original_mapping: InternalBlockMapping,
            /// File offset of newly allocated space, if any (for release on error).
            allocated_offset: Option<u64>,
        }
        let mut tfp_records: Vec<TfpRecord> = Vec::new();

        // Track whether any TFP allocation used unsafe (non-safe-data) space.
        // When true, complete_write_inner() captures the current FSN and
        // attaches it to the BAT page(s) so the log task waits for the
        // data flush before logging the BAT update.
        let mut needs_flush_before_log = false;

        // Re-check and allocate under the lock.
        // No block in our set should have TFP at this point — we waited
        // for all concurrent allocators to finish above.
        let allocation_result = async {
            for block_info in &blocks_needing_allocation {
                let is_full_block =
                    block_info.block_offset == 0 && block_info.block_length >= self.block_size;

                // Re-read mapping under lock (may have changed since read phase).
                let (internal, mapping) = {
                    let bat_state = self.bat_state.read();
                    let internal = bat_state.get_payload_mapping(block_info.block_number);
                    let mapping = self
                        .bat
                        .get_block_mapping_from_state(&bat_state, block_info.block_number);
                    (internal, mapping)
                };

                // Assert no TFP — we serialized against concurrent
                // allocators in the loop above.
                debug_assert!(
                    !internal.transitioning_to_fully_present(),
                    "block {} has TFP after overlap wait",
                    block_info.block_number
                );

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
                        // This is always safe (space already has this block's
                        // data), so no change to needs_flush_before_log.
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
                            allocated_offset: None,
                        });

                        ranges.push(WriteRange::Data {
                            guest_offset: block_info.virtual_offset,
                            length: block_info.block_length,
                            file_offset: mapping.file_offset + block_info.block_offset as u64,
                        });
                    }
                    _ => {
                        // Unallocated block — allocate space.
                        //
                        // If the block is currently soft-anchored (trimmed
                        // with file space preserved), try to reclaim its own
                        // space first — matching `Vhd2iAllocateDataBlock` in
                        // the C code. This is `SpaceState::OwnStale` because
                        // the space still contains this block's own old
                        // data, so a power failure after BAT commit but
                        // before data write would only expose the block's
                        // own stale data — no cross-block leak.
                        let original = internal;
                        let (new_offset, space_state) = if crate::trim::is_soft_anchored(internal) {
                            let old_file_offset = internal.file_megabyte() as u64 * MB1;
                            if self
                                .free_space
                                .unmark_trimmed_block(
                                    block_info.block_number,
                                    old_file_offset,
                                    self.block_size,
                                )
                                .is_ok()
                            {
                                // Reusing the soft-anchored block's own space.
                                (old_file_offset, crate::space::SpaceState::OwnStale)
                            } else {
                                // Unmark failed (race) — fall through to
                                // normal allocation.
                                // LOCK AUDIT: bat_state read-lock dropped (end of prior block). allocation_lock held (async Mutex — OK across .await).
                                let r = self
                                    .allocate_space(self.block_size, AllocateFlags::new())
                                    .await?;
                                (r.file_offset, r.state)
                            }
                        } else {
                            // LOCK AUDIT: bat_state read-lock dropped (end of prior block). allocation_lock held (async Mutex — OK across .await).
                            let r = self
                                .allocate_space(self.block_size, AllocateFlags::new())
                                .await?;
                            (r.file_offset, r.state)
                        };

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
                                allocated_offset: Some(new_offset),
                            });

                            // Track unsafe allocations for flush barrier.
                            if !space_state.is_safe() {
                                needs_flush_before_log = true;
                            }

                            ranges.push(WriteRange::Data {
                                guest_offset: block_info.virtual_offset,
                                length: block_info.block_length,
                                file_offset: new_offset + block_info.block_offset as u64,
                            });
                        } else {
                            // Partial write — commit BAT immediately.
                            //
                            // For differencing disks: if the block was
                            // NotPresent (transparent to parent), allocate
                            // as PartiallyPresent so that unwritten sectors
                            // remain transparent. The sector bitmap will be
                            // updated in complete_write_inner() to mark
                            // only the written sectors as present.
                            //
                            // For non-diff disks or blocks in other states
                            // (Zero, Unmapped, Undefined): allocate as
                            // FullyPresent with zero-padding.
                            let is_partial_present =
                                self.has_parent && mapping.state == BatEntryState::NotPresent;

                            // --- SBM block allocation for PartiallyPresent ---
                            if is_partial_present {
                                let chunk_number = block_info.block_number / self.bat.chunk_ratio;
                                let sbm_mapping = self.get_sector_bitmap_mapping(chunk_number);

                                if sbm_mapping.state != BatEntryState::FullyPresent {
                                    // Allocate 1 MiB for the SBM block.
                                    // Zero flag ensures stale data is cleared
                                    // (near-EOF space is already zero).
                                    let sbm_alloc = self
                                        .allocate_space(
                                            crate::bat::SECTOR_BITMAP_BLOCK_SIZE,
                                            AllocateFlags::new().with_zero(true),
                                        )
                                        .await?;

                                    // Update in-memory SBM BAT entry.
                                    let new_sbm = InternalBlockMapping::new()
                                        .with_state(BatEntryState::FullyPresent as u8)
                                        .with_file_megabyte((sbm_alloc.file_offset / MB1) as u32);

                                    {
                                        let mut bat_state = self.bat_state.write();
                                        bat_state.set_sbm_mapping(&self.bat, chunk_number, new_sbm);
                                    }

                                    // Persist SBM BAT entry to disk.
                                    self.bat
                                        .write_block_mapping(
                                            &self.cache,
                                            &self.bat_state,
                                            BlockType::SectorBitmap,
                                            chunk_number,
                                            new_sbm,
                                        )
                                        .await?;
                                }
                            }

                            let new_state = if is_partial_present {
                                BatEntryState::PartiallyPresent
                            } else {
                                BatEntryState::FullyPresent
                            };

                            let new_mapping = InternalBlockMapping::new()
                                .with_state(new_state as u8)
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
                            // LOCK AUDIT: bat_state write-lock dropped (end of prior block). allocation_lock held (async Mutex — OK across .await).
                            self.bat
                                .write_block_mapping(
                                    &self.cache,
                                    &self.bat_state,
                                    BlockType::Payload,
                                    block_info.block_number,
                                    new_mapping,
                                )
                                .await?;

                            // For non-TFP path: set per-page FSN when
                            // !is_safe. The FSN is captured now (before
                            // the caller writes data), matching the C code's
                            // FreeSpace.RequiredFsn timing.
                            if !space_state.is_safe() {
                                if let Some(fs) = &self.flush_sequencer {
                                    let fsn = fs.current_fsn();
                                    let page_key =
                                        self.bat_page_key_for_block(block_info.block_number);
                                    self.cache.set_pre_log_fsn(page_key, fsn);
                                }
                            }

                            // Emit zero + data + zero ranges.
                            // For PartiallyPresent blocks, skip zero-fill —
                            // unwritten sectors are transparent to parent
                            // (the sector bitmap tracks presence).
                            // For FullyPresent blocks, zero-fill surround
                            // unless the space is already safe.
                            if !is_partial_present
                                && block_info.block_offset > 0
                                && !space_state.is_zero()
                            {
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
                            if !is_partial_present
                                && end_offset < self.block_size
                                && !space_state.is_zero()
                            {
                                ranges.push(WriteRange::Zero {
                                    file_offset: new_offset + end_offset as u64,
                                    length: self.block_size - end_offset,
                                });
                            }
                        }
                    }
                }
            }

            Ok(())
        }
        .await;

        // Error cleanup: revert TFP-marked blocks and release allocated space on failure.
        if let Err(e) = allocation_result {
            {
                let mut bat_state = self.bat_state.write();
                for record in &tfp_records {
                    bat_state.set_payload_mapping(
                        &self.bat,
                        record.block_number,
                        record.original_mapping,
                    );
                    // Release allocated space back to free pool.
                    if let Some(offset) = record.allocated_offset {
                        self.free_space.release(offset, self.block_size);
                    }
                }
            }
            self.allocation_event.notify(usize::MAX);
            return Err(e);
        }

        // Allocation lock is released when _alloc_guard drops (after
        // returning ranges to caller).

        // Compute block range and increment refcounts on success path.
        let start_block = self.bat.offset_to_block(offset);
        let end_block = self.bat.offset_to_block(offset + len as u64 - 1);
        let block_count = end_block - start_block + 1;

        {
            let mut bat_state = self.bat_state.write();
            for block in start_block..start_block + block_count {
                bat_state.increment_io_refcount(block);
            }
        }

        Ok(WriteIoGuard::new(
            self,
            offset,
            len,
            start_block,
            block_count,
            needs_flush_before_log,
        ))
    }

    /// Finalize a write operation (internal implementation).
    ///
    /// Called by [`WriteIoGuard::complete()`] after the caller has written
    /// data to the resolved ranges.
    ///
    /// Clears TFP flags, sets state to FullyPresent, writes per-entry BAT
    /// to cache, and notifies waiters. For PartiallyPresent blocks (non-TFP,
    /// i.e. partial writes to differencing disks), updates sector bitmaps.
    ///
    /// The abort path (write failure / guard dropped without `complete()`)
    /// is handled synchronously by [`abort_write_sync()`].
    pub(crate) async fn complete_write_inner(
        &self,
        offset: u64,
        len: u32,
        needs_flush_before_log: bool,
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
            let block_length = std::cmp::min(self.block_size - block_offset, len - current_offset);

            // Read the in-memory mapping to check for TFP.
            let internal = {
                let bat_state = self.bat_state.read();
                bat_state.get_payload_mapping(block_number)
            };

            if internal.transitioning_to_fully_present() {
                had_tfp = true;

                // Clear TFP, set FullyPresent.
                let final_mapping = InternalBlockMapping::new()
                    .with_state(BatEntryState::FullyPresent as u8)
                    .with_transitioning_to_fully_present(false)
                    .with_file_megabyte(internal.file_megabyte());

                {
                    let mut bat_state = self.bat_state.write();
                    bat_state.set_payload_mapping(&self.bat, block_number, final_mapping);
                }

                // Write per-entry to cache. Errors are deferred so we
                // can still notify waiters.
                // LOCK AUDIT: bat_state write-lock dropped (end of prior block). No sync locks held.
                if bat_write_error.is_none() {
                    if let Err(e) = self
                        .bat
                        .write_block_mapping(
                            &self.cache,
                            &self.bat_state,
                            BlockType::Payload,
                            block_number,
                            final_mapping,
                        )
                        .await
                    {
                        bat_write_error = Some(e);
                    } else if needs_flush_before_log {
                        // Capture FSN NOW (after caller's data writes,
                        // matching C's Vhd2iDereferenceReadWrite →
                        // Vhd2iGetCurrentFsn timing).
                        if let Some(fs) = &self.flush_sequencer {
                            let fsn = fs.current_fsn();
                            let page_key = self.bat_page_key_for_block(block_number);
                            self.cache.set_pre_log_fsn(page_key, fsn);
                        }
                    }
                }
            } else if self.has_parent {
                // Non-TFP PartiallyPresent blocks: update sector bitmaps.
                let mapping = self.get_block_mapping(block_number);
                if mapping.state == BatEntryState::PartiallyPresent {
                    self.set_sector_bitmap_bits(virtual_offset, block_length, true)
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

    /// Synchronous abort path for `WriteIoGuard::drop()`.
    ///
    /// Reverts TFP blocks to their original state, releases any newly
    /// allocated space back to the free pool, marks BAT pages dirty, and
    /// notifies allocation waiters. Does not perform any file I/O.
    pub(crate) fn abort_write_sync(&self, offset: u64, len: u32) {
        if len == 0 {
            return;
        }

        let mut had_tfp = false;
        let mut current_offset: u32 = 0;

        while current_offset < len {
            let virtual_offset = offset + current_offset as u64;
            let block_number = self.bat.offset_to_block(virtual_offset);
            let block_offset = self.bat.offset_within_block(virtual_offset);
            let block_length = std::cmp::min(self.block_size - block_offset, len - current_offset);

            let internal = {
                let bat_state = self.bat_state.read();
                bat_state.get_payload_mapping(block_number)
            };

            if internal.transitioning_to_fully_present() {
                had_tfp = true;
                let original_state =
                    BatEntryState::from_raw(internal.state()).unwrap_or(BatEntryState::NotPresent);
                let reverted = match original_state {
                    BatEntryState::PartiallyPresent => InternalBlockMapping::new()
                        .with_state(internal.state())
                        .with_transitioning_to_fully_present(false)
                        .with_file_megabyte(internal.file_megabyte()),
                    _ => {
                        let file_offset = internal.file_megabyte() as u64 * MB1;
                        if file_offset != 0 {
                            self.free_space.release(file_offset, self.block_size);
                        }
                        InternalBlockMapping::new()
                            .with_state(internal.state())
                            .with_transitioning_to_fully_present(false)
                            .with_file_megabyte(0)
                    }
                };

                let mut bat_state = self.bat_state.write();
                bat_state.set_payload_mapping(&self.bat, block_number, reverted);
            }

            current_offset += block_length;
        }

        if had_tfp {
            self.allocation_event.notify(usize::MAX);
        }
    }

    /// Flush all writes to stable storage.
    ///
    /// Commits dirty cache pages to the log task, waits for the WAL
    /// entry to be written, then flushes to make everything durable:
    /// user data writes, WAL entries, and apply-task writes.
    pub async fn flush(&self) -> Result<(), VhdxError> {
        if self.read_only {
            return Err(VhdxError::ReadOnly);
        }

        let lsn = self.cache.commit()?;

        // Wait for the log task to write WAL entries through this LSN.
        // Even if this commit had no dirty pages, we wait for the most
        // recent LSN to ensure a concurrent flush's WAL write completes.
        self.logged_lsn
            .as_ref()
            .expect("writable file has logged_lsn")
            .wait_for(lsn)
            .await?;

        // Flush everything: user data, WAL entries, applied pages.
        self.flush_sequencer
            .as_ref()
            .expect("writable file has flush_sequencer")
            .flush(self.file.as_ref())
            .await?;

        Ok(())
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
    use crate::tests::support::IoInterceptor;
    use guid::Guid;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use zerocopy::IntoBytes;

    #[async_test]
    async fn read_empty_disk_returns_zero() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();

        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

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
        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();

        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_read(0, 0, &mut ranges).await.unwrap();

        assert!(ranges.is_empty());
    }

    #[async_test]
    async fn read_beyond_end_of_disk() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();

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
        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();

        let mut ranges = Vec::new();
        let _guard = vhdx
            .resolve_read(format::GB1 - 4096, 4096, &mut ranges)
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

        // Write a FullyPresent BAT entry for block 0 at file_offset_mb = 4.
        let entry = BatEntry::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_offset_mb(4);
        file.write_at(bat_offset, entry.as_bytes()).await.unwrap();

        // Extend file to cover the allocated range.
        let needed = 4 * MB1 + format::DEFAULT_BLOCK_SIZE as u64;
        file.set_file_size(needed).await.unwrap();

        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();
        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Data {
                guest_offset: 0,
                length: 4096,
                file_offset: 4 * MB1,
            }
        );
    }

    #[async_test]
    async fn read_spanning_two_blocks() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();

        let block_size = vhdx.block_size() as u64;
        let mut ranges = Vec::new();
        // Read last 512 bytes of block 0 and first 512 bytes of block 1.
        let _guard = vhdx
            .resolve_read((block_size - 512) as u64, 1024, &mut ranges)
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
        let block_size = MB1 as u32;
        let mut params = CreateParams {
            disk_size: 4 * MB1,
            block_size,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();

        let mut ranges = Vec::new();
        // Read across blocks 0, 1, 2: start at 512 KiB, length = 2 MiB.
        // Block 0: 512 KiB remaining. Block 1: full 1 MiB. Block 2: 512 KiB.
        let start = MB1 / 2; // middle of block 0
        let len = (2 * MB1) as u32; // spans 3 blocks
        let _guard = vhdx.resolve_read(start, len, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 3);
        // Block 0: remaining half
        assert_eq!(
            ranges[0],
            ReadRange::Zero {
                guest_offset: start,
                length: (MB1 / 2) as u32,
            }
        );
        // Block 1: full block
        assert_eq!(
            ranges[1],
            ReadRange::Zero {
                guest_offset: MB1,
                length: block_size,
            }
        );
        // Block 2: first half
        assert_eq!(
            ranges[2],
            ReadRange::Zero {
                guest_offset: 2 * MB1,
                length: (MB1 / 2) as u32,
            }
        );
    }

    #[async_test]
    async fn read_unaligned_within_block() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        // Set block 0 to FullyPresent at file_offset_mb = 4.
        let entry = BatEntry::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_offset_mb(4);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        // Extend file to cover the allocated range.
        let needed = 4 * MB1 + format::DEFAULT_BLOCK_SIZE as u64;
        file.set_file_size(needed).await.unwrap();

        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();
        let mut ranges = Vec::new();
        // Read 512 bytes starting at sector 10 (offset 5120).
        let _guard = vhdx.resolve_read(5120, 512, &mut ranges).await.unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            ReadRange::Data {
                guest_offset: 5120,
                length: 512,
                file_offset: 4 * MB1 + 5120,
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
        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();

        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

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

        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();
        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

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

        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();
        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

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

        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();
        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

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
        let disk_size = 4 * MB1;
        let (file, _) = InMemoryFile::create_test_vhdx(disk_size).await;
        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();

        let mut ranges = Vec::new();
        let _guard = vhdx
            .resolve_read(0, disk_size as u32, &mut ranges)
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
        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();

        let mut ranges = Vec::new();
        // Read one 4K sector.
        let _guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();
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
    async fn write_to_empty_block(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_write(0, 4096, &mut ranges).await.unwrap();

        // Should allocate a new block. With SpaceState::Zero (near-EOF
        // extension space), zero padding is skipped — only Data emitted.
        // Writing 4096 bytes at offset 0 in block:
        //   Data(0, 4096, file_offset)
        assert!(!ranges.is_empty());
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
                assert_eq!(file_offset % MB1, 0);
            }
            _ => panic!("expected Data range, got {:?}", ranges[0]),
        }
        // With safe data, trailing zero padding is skipped.
        // If not safe, a trailing Zero range would follow.
        if ranges.len() > 1 {
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
    }

    #[async_test]
    async fn write_to_fully_present_block(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        // Write a FullyPresent BAT entry for block 0 at file_offset_mb = 4.
        let entry = BatEntry::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_offset_mb(4);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        // Extend file to cover the allocated range.
        let needed = 4 * MB1 + format::DEFAULT_BLOCK_SIZE as u64;
        file.set_file_size(needed).await.unwrap();

        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_write(0, 4096, &mut ranges).await.unwrap();

        // Should write directly to the existing block — single Data range.
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            WriteRange::Data {
                guest_offset: 0,
                length: 4096,
                file_offset: 4 * MB1,
            }
        );
    }

    #[async_test]
    async fn write_spanning_two_blocks(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        let block_size = vhdx.block_size() as u64;
        let mut ranges = Vec::new();
        // Write last 512 bytes of block 0 and first 512 bytes of block 1.
        let _guard = vhdx
            .resolve_write((block_size - 512) as u64, 1024, &mut ranges)
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
    async fn write_then_read_roundtrip(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        // Step 1: resolve_write to get file offsets.
        let mut write_ranges = Vec::new();
        let guard = vhdx.resolve_write(0, 512, &mut write_ranges).await.unwrap();

        // Step 2: Write actual data at the returned Data offsets.
        let pattern: Vec<u8> = (0..512u16).map(|i| (i % 256) as u8).collect();
        for wr in &write_ranges {
            match wr {
                WriteRange::Data {
                    file_offset,
                    length,
                    ..
                } => {
                    vhdx.file
                        .write_at(*file_offset, &pattern[..(*length as usize)])
                        .await
                        .unwrap();
                }
                WriteRange::Zero {
                    file_offset,
                    length,
                } => {
                    let zeros = vec![0u8; *length as usize];
                    vhdx.file.write_at(*file_offset, &zeros).await.unwrap();
                }
            }
        }

        // Step 3: complete via guard.
        guard.complete().await.unwrap();

        // Step 4: resolve_read at the same offset.
        let mut read_ranges = Vec::new();
        let _guard = vhdx.resolve_read(0, 512, &mut read_ranges).await.unwrap();

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
    async fn write_partial_block(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        // Write 512 bytes at offset 4096 within block 0.
        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_write(4096, 512, &mut ranges).await.unwrap();

        // With safe data (near-EOF or extension space), Zero padding is
        // skipped. Only expect the Data range.
        // Without safe data, we'd see: Zero(leading 4096), Data(512), Zero(trailing).
        assert!(!ranges.is_empty());
        // Find the Data range.
        let data_range = ranges
            .iter()
            .find(|r| matches!(r, WriteRange::Data { .. }))
            .expect("expected at least one Data range");
        match data_range {
            WriteRange::Data {
                guest_offset,
                length,
                ..
            } => {
                assert_eq!(*guest_offset, 4096);
                assert_eq!(*length, 512);
            }
            _ => unreachable!(),
        }
    }

    #[async_test]
    async fn write_full_block(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        // Write exactly one full block (no padding needed).
        let mut ranges = Vec::new();
        let _guard = vhdx
            .resolve_write(0, format::DEFAULT_BLOCK_SIZE, &mut ranges)
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
                assert_eq!(file_offset % MB1, 0);
            }
            _ => panic!("expected Data range, got {:?}", ranges[0]),
        }
    }

    #[async_test]
    async fn write_zero_length(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_write(0, 0, &mut ranges).await.unwrap();
        assert!(ranges.is_empty());
    }

    #[async_test]
    async fn write_beyond_end_of_disk(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

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
        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();

        let mut ranges = Vec::new();
        let result = vhdx.resolve_write(0, 4096, &mut ranges).await;
        assert!(matches!(result, Err(VhdxError::ReadOnly)));
    }

    #[async_test]
    async fn write_large_spanning_many_blocks(driver: DefaultDriver) {
        // 4 MiB disk with 1 MiB blocks → 4 blocks.
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: 4 * MB1,
            block_size: MB1 as u32,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        // Write 3 MiB starting at offset 512 KiB (spans blocks 0,1,2,3).
        let start = MB1 / 2;
        let length = (3 * MB1) as u32;
        let mut ranges = Vec::new();
        let _guard = vhdx
            .resolve_write(start, length, &mut ranges)
            .await
            .unwrap();

        let data_ranges: Vec<_> = ranges
            .iter()
            .filter(|r| matches!(r, WriteRange::Data { .. }))
            .collect();
        // Should span 4 blocks: partial block 0, full block 1, full block 2, partial block 3.
        assert_eq!(data_ranges.len(), 4);

        // Verify guest offsets and lengths.
        let block_size = MB1;
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
    async fn first_write_updates_header(driver: DefaultDriver) {
        let (file, params) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        let original_data_guid = params.data_write_guid;
        assert_eq!(vhdx.data_write_guid(), original_data_guid);

        // Perform a write — this triggers enable_write_mode.
        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_write(0, 512, &mut ranges).await.unwrap();

        // data_write_guid should have changed.
        let new_data_guid = vhdx.data_write_guid();
        assert_ne!(new_data_guid, original_data_guid);
        assert_ne!(new_data_guid, Guid::ZERO);
    }

    #[async_test]
    async fn second_write_no_header_update(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        // First write — triggers header update.
        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_write(0, 512, &mut ranges).await.unwrap();
        let guid_after_first = vhdx.data_write_guid();

        // Second write — should NOT update header again.
        let mut ranges2 = Vec::new();
        let _guard2 = vhdx.resolve_write(512, 512, &mut ranges2).await.unwrap();
        let guid_after_second = vhdx.data_write_guid();

        assert_eq!(guid_after_first, guid_after_second);
    }

    #[async_test]
    async fn file_writable_only_does_not_change_data_guid(driver: DefaultDriver) {
        let (file, params) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        let original_data_guid = params.data_write_guid;

        // Enable FileWritable mode (metadata-only modification).
        vhdx.enable_write_mode(WriteMode::FileWritable)
            .await
            .unwrap();

        // data_write_guid should NOT have changed.
        assert_eq!(vhdx.data_write_guid(), original_data_guid);

        // But the write mode should be set (subsequent DataWritable will escalate).
        let state = vhdx.write_state.lock();
        assert_eq!(state.write_mode, Some(WriteMode::FileWritable));
    }

    // --- Phase 9.5b: TFP mechanics, write integration, and error path tests ---

    /// Interceptor with toggleable failure for mid-test fault injection.
    struct ToggleableInterceptor {
        fail_writes: Arc<AtomicBool>,
        fail_set_file_size: Arc<AtomicBool>,
    }

    impl IoInterceptor for ToggleableInterceptor {
        fn before_write(&self, _offset: u64, _data: &[u8]) -> Result<(), std::io::Error> {
            if self.fail_writes.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("injected write failure"));
            }
            Ok(())
        }

        fn before_set_file_size(&self, _size: u64) -> Result<(), std::io::Error> {
            if self.fail_set_file_size.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("injected set_file_size failure"));
            }
            Ok(())
        }
    }

    #[async_test]
    async fn resolve_write_sets_tfp_on_full_block(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        let mut ranges = Vec::new();
        let _guard = vhdx
            .resolve_write(0, block_size, &mut ranges)
            .await
            .unwrap();

        // Full-block write should set TFP on block 0.
        let bat_state = vhdx.bat_state.read();
        let mapping = bat_state.get_payload_mapping(0);
        assert!(
            mapping.transitioning_to_fully_present(),
            "full-block resolve_write should set TFP"
        );
        assert!(
            mapping.file_megabyte() > 0,
            "allocated block should have non-zero file offset"
        );
    }

    #[async_test]
    async fn resolve_write_no_tfp_on_partial_block(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_write(0, 512, &mut ranges).await.unwrap();

        // Partial-block write should NOT set TFP — BAT committed immediately.
        let bat_state = vhdx.bat_state.read();
        let mapping = bat_state.get_payload_mapping(0);
        assert!(
            !mapping.transitioning_to_fully_present(),
            "partial-block resolve_write should not set TFP"
        );
        assert_eq!(
            mapping.state(),
            BatEntryState::FullyPresent as u8,
            "partial allocation should set FullyPresent immediately"
        );
    }

    #[async_test]
    async fn write_read_roundtrip_multi_block(driver: DefaultDriver) {
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: 4 * MB1,
            block_size: MB1 as u32,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        let block_size = vhdx.block_size() as u64;
        // Write 2 full blocks starting at offset 0.
        let length = (2 * block_size) as u32;
        let mut write_ranges = Vec::new();
        let guard = vhdx
            .resolve_write(0, length, &mut write_ranges)
            .await
            .unwrap();

        // Write recognizable pattern to each Data range.
        for wr in &write_ranges {
            match wr {
                WriteRange::Data {
                    guest_offset,
                    length,
                    file_offset,
                } => {
                    let pattern: Vec<u8> = (0..*length)
                        .map(|i| ((guest_offset + i as u64) % 251) as u8)
                        .collect();
                    vhdx.file.write_at(*file_offset, &pattern).await.unwrap();
                }
                WriteRange::Zero {
                    file_offset,
                    length,
                } => {
                    let zeros = vec![0u8; *length as usize];
                    vhdx.file.write_at(*file_offset, &zeros).await.unwrap();
                }
            }
        }
        guard.complete().await.unwrap();

        // Read back both blocks.
        let mut read_ranges = Vec::new();
        let _guard = vhdx
            .resolve_read(0, length, &mut read_ranges)
            .await
            .unwrap();

        for rr in &read_ranges {
            match rr {
                ReadRange::Data {
                    guest_offset,
                    length,
                    file_offset,
                } => {
                    let mut buf = vec![0u8; *length as usize];
                    vhdx.file.read_at(*file_offset, &mut buf).await.unwrap();
                    let expected: Vec<u8> = (0..*length)
                        .map(|i| ((guest_offset + i as u64) % 251) as u8)
                        .collect();
                    assert_eq!(
                        buf, expected,
                        "data mismatch at guest offset {guest_offset}"
                    );
                }
                ReadRange::Zero { .. } => {
                    panic!("expected Data range after write, got Zero");
                }
                ReadRange::Unmapped { .. } => {
                    panic!("expected Data range after write, got Unmapped");
                }
            }
        }
    }

    #[async_test]
    async fn write_to_already_allocated_no_growth(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = region::parse_region_tables(&file).await.unwrap();

        // Pre-allocate block 0 as FullyPresent at offset 100 MB.
        let entry = BatEntry::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_offset_mb(100);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        // Ensure file is big enough to cover that offset.
        let needed_size = 100 * MB1 + format::DEFAULT_BLOCK_SIZE as u64;
        file.set_file_size(needed_size).await.unwrap();

        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let eof_before = vhdx.free_space.file_length();

        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_write(0, 4096, &mut ranges).await.unwrap();

        // No new allocation should occur — verify file length unchanged.
        let eof_after = vhdx.free_space.file_length();
        assert_eq!(
            eof_before, eof_after,
            "eof should not change for existing block"
        );

        // Should point to the existing block.
        assert_eq!(ranges.len(), 1);
        match ranges[0] {
            WriteRange::Data { file_offset, .. } => {
                assert_eq!(file_offset, 100 * MB1);
            }
            _ => panic!("expected Data range"),
        }
    }

    #[async_test]
    async fn write_flush_persists_bat(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        // Write and complete a full block.
        let block_size = vhdx.block_size();
        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(0, block_size, &mut ranges)
            .await
            .unwrap();
        guard.complete().await.unwrap();
        vhdx.flush().await.unwrap();

        // Snapshot immediately after flush — proves flush persisted the BAT.
        // Log GUID is still set, so reopen will do log replay.
        let snapshot = vhdx.file.snapshot();

        // Reopen from snapshot (log replay recovers the state).
        let recovered = InMemoryFile::from_snapshot(snapshot);
        let vhdx2 = VhdxFile::open_writable(recovered, &driver).await.unwrap();
        let bat_state = vhdx2.bat_state.read();
        let mapping = bat_state.get_payload_mapping(0);
        assert_eq!(
            mapping.state(),
            BatEntryState::FullyPresent as u8,
            "BAT should show FullyPresent after flush + reopen"
        );
        assert!(
            mapping.file_megabyte() > 0,
            "BAT should have non-zero offset after flush + reopen"
        );
    }

    #[async_test]
    async fn complete_write_clears_tfp(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        // resolve_write should set TFP.
        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(0, block_size, &mut ranges)
            .await
            .unwrap();

        {
            let bat_state = vhdx.bat_state.read();
            let mapping = bat_state.get_payload_mapping(0);
            assert!(mapping.transitioning_to_fully_present());
        }

        // guard.complete() should clear TFP.
        guard.complete().await.unwrap();

        {
            let bat_state = vhdx.bat_state.read();
            let mapping = bat_state.get_payload_mapping(0);
            assert!(
                !mapping.transitioning_to_fully_present(),
                "TFP should be cleared after complete_write"
            );
            assert_eq!(
                mapping.state(),
                BatEntryState::FullyPresent as u8,
                "block should be FullyPresent after complete"
            );
        }
    }

    #[async_test]
    async fn complete_write_writes_bat_to_disk(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(0, block_size, &mut ranges)
            .await
            .unwrap();

        // Get the allocated offset from in-memory BAT.
        let expected_mb = {
            let bat_state = vhdx.bat_state.read();
            bat_state.get_payload_mapping(0).file_megabyte()
        };

        guard.complete().await.unwrap();
        vhdx.flush().await.unwrap();

        // Snapshot after flush — proves complete + flush persisted the BAT.
        let snapshot = vhdx.file.snapshot();

        // Reopen from snapshot (log replay recovers the state).
        let recovered = InMemoryFile::from_snapshot(snapshot);
        let vhdx2 = VhdxFile::open_writable(recovered, &driver).await.unwrap();
        let bat_state = vhdx2.bat_state.read();
        let mapping = bat_state.get_payload_mapping(0);
        assert_eq!(
            mapping.state(),
            BatEntryState::FullyPresent as u8,
            "BAT should be FullyPresent after flush + reopen"
        );
        assert_eq!(
            mapping.file_megabyte(),
            expected_mb,
            "BAT file offset should match after flush + reopen"
        );
    }

    #[async_test]
    async fn resolve_write_extends_file(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        let size_before = vhdx.file.file_size().await.unwrap();

        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_write(0, 512, &mut ranges).await.unwrap();

        let size_after = vhdx.file.file_size().await.unwrap();
        assert!(
            size_after > size_before,
            "file should grow after allocating a new block \
             (before={size_before}, after={size_after})"
        );
    }

    #[async_test]
    async fn abort_write_reverts_bat(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        // resolve_write for a full block → sets TFP.
        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(0, block_size, &mut ranges)
            .await
            .unwrap();

        // Abort (drop guard without complete) → reverts in-memory BAT.
        drop(guard);

        // Block should be back to NotPresent with zero offset.
        let mapping = vhdx.get_block_mapping(0);
        assert_eq!(mapping.state, BatEntryState::NotPresent);
        assert_eq!(mapping.file_offset, 0);

        vhdx.close().await.unwrap();
    }

    #[async_test]
    async fn abort_write_clears_tfp(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(0, block_size, &mut ranges)
            .await
            .unwrap();

        // TFP should be set.
        {
            let bat_state = vhdx.bat_state.read();
            assert!(
                bat_state
                    .get_payload_mapping(0)
                    .transitioning_to_fully_present()
            );
        }

        // Abort (drop guard without complete).
        drop(guard);

        // TFP should be cleared and state reverted to NotPresent.
        {
            let bat_state = vhdx.bat_state.read();
            let mapping = bat_state.get_payload_mapping(0);
            assert!(
                !mapping.transitioning_to_fully_present(),
                "TFP should be cleared after abort"
            );
            assert_eq!(
                mapping.state(),
                BatEntryState::NotPresent as u8,
                "should revert to original NotPresent state"
            );
            assert_eq!(
                mapping.file_megabyte(),
                0,
                "should revert file_megabyte to 0"
            );
        }
    }

    #[async_test]
    async fn abort_write_allows_subsequent_write(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        // First write: allocate and abort.
        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(0, block_size, &mut ranges)
            .await
            .unwrap();
        drop(guard);

        // Second write: should succeed (no TFP blocking).
        let mut ranges2 = Vec::new();
        let guard2 = vhdx
            .resolve_write(0, block_size, &mut ranges2)
            .await
            .unwrap();
        guard2.complete().await.unwrap();

        // Block should be FullyPresent now.
        let bat_state = vhdx.bat_state.read();
        let mapping = bat_state.get_payload_mapping(0);
        assert_eq!(mapping.state(), BatEntryState::FullyPresent as u8);
        assert!(!mapping.transitioning_to_fully_present());
    }

    #[async_test]
    async fn complete_write_notifies_on_cache_failure(driver: DefaultDriver) {
        // With write-back mode (no write-through), cache writes during
        // complete() only mark pages dirty in the cache. The actual disk
        // write happens on flush through the log task. So complete()
        // itself should succeed even with write failures enabled.
        let (orig_file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let data = orig_file.snapshot();

        let fail_writes = Arc::new(AtomicBool::new(false));
        let interceptor = Arc::new(ToggleableInterceptor {
            fail_writes: fail_writes.clone(),
            fail_set_file_size: Arc::new(AtomicBool::new(false)),
        });
        let file = InMemoryFile::with_interceptor(0, interceptor);
        file.write_at(0, &data).await.unwrap();

        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        // resolve_write succeeds (writes for header update, set_file_size).
        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(0, block_size, &mut ranges)
            .await
            .unwrap();

        // Enable write failure.
        fail_writes.store(true, Ordering::SeqCst);

        // complete() should succeed — commit() is a no-op in write-back mode,
        // and dirty pages are marked in cache without file I/O.
        let result = guard.complete().await;
        assert!(
            result.is_ok(),
            "complete() should succeed in write-back mode even with write failures"
        );

        // TFP should be cleared and state set to FullyPresent.
        {
            let bat_state = vhdx.bat_state.read();
            let mapping = bat_state.get_payload_mapping(0);
            assert!(
                !mapping.transitioning_to_fully_present(),
                "TFP should be cleared after complete"
            );
            assert_eq!(
                mapping.state(),
                BatEntryState::FullyPresent as u8,
                "state should be FullyPresent after complete"
            );
        }

        // Re-enable writes.
        fail_writes.store(false, Ordering::SeqCst);

        // A subsequent resolve_write should work (not hang on TFP).
        let mut ranges2 = Vec::new();
        let _guard2 = vhdx
            .resolve_write(0, block_size, &mut ranges2)
            .await
            .unwrap();
    }

    #[async_test]
    async fn resolve_write_error_reverts_tfp(driver: DefaultDriver) {
        // Create VHDX normally, then snapshot to new file with toggleable interceptor.
        let (orig_file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let data = orig_file.snapshot();

        let fail_set_file_size = Arc::new(AtomicBool::new(false));
        let interceptor = Arc::new(ToggleableInterceptor {
            fail_writes: Arc::new(AtomicBool::new(false)),
            fail_set_file_size: fail_set_file_size.clone(),
        });
        let file = InMemoryFile::with_interceptor(0, interceptor);
        file.write_at(0, &data).await.unwrap();

        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        // Enable set_file_size failure.
        fail_set_file_size.store(true, Ordering::SeqCst);

        // resolve_write should fail when set_file_size fails during allocation.
        let mut ranges = Vec::new();
        let result = vhdx.resolve_write(0, block_size, &mut ranges).await;
        assert!(
            result.is_err(),
            "resolve_write should fail when set_file_size fails"
        );

        // TFP should be reverted.
        {
            let bat_state = vhdx.bat_state.read();
            let mapping = bat_state.get_payload_mapping(0);
            assert!(
                !mapping.transitioning_to_fully_present(),
                "TFP should be reverted on resolve_write error"
            );
        }

        // Disable failure, retry should succeed.
        fail_set_file_size.store(false, Ordering::SeqCst);

        let mut ranges2 = Vec::new();
        let _guard = vhdx
            .resolve_write(0, block_size, &mut ranges2)
            .await
            .unwrap();
    }

    /// Verify that a new allocation from near-EOF (safe data) omits zero
    /// padding, while an allocation from the free pool does emit zero padding.
    #[async_test]
    async fn safe_data_skips_zero_padding(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size() as u64;

        // Step 1: Partial write to block 0 at guest_offset=0, len=512.
        // Allocation comes from near-EOF → SpaceState::Zero → no zero ranges.
        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_write(0, 512, &mut ranges).await.unwrap();

        let zero_ranges: Vec<_> = ranges
            .iter()
            .filter(|r| matches!(r, WriteRange::Zero { .. }))
            .collect();
        assert!(
            zero_ranges.is_empty(),
            "near-EOF allocation should skip zero padding, but got {} Zero ranges",
            zero_ranges.len(),
        );

        // Extract the block base offset (block_offset=0 since guest_offset=0).
        let allocated_offset = match ranges[0] {
            WriteRange::Data { file_offset, .. } => file_offset,
            _ => panic!("expected Data range"),
        };

        // Step 2: Release the allocated space back to pool.
        // (Intentionally creating an inconsistency for testing purposes.)
        vhdx.free_space
            .release(allocated_offset, vhdx.block_size() as u32);

        // Step 3: Partial write to block 1 at block-aligned guest offset.
        // Should allocate from pool (unsafe data) → zero ranges emitted.
        let mut ranges2 = Vec::new();
        let _guard2 = vhdx
            .resolve_write(block_size, 512, &mut ranges2)
            .await
            .unwrap();

        let zero_ranges2: Vec<_> = ranges2
            .iter()
            .filter(|r| matches!(r, WriteRange::Zero { .. }))
            .collect();
        assert!(
            !zero_ranges2.is_empty(),
            "pool allocation should emit zero padding, but got 0 Zero ranges",
        );
    }

    // ---- Concurrent I/O stress tests ----

    /// Wrapper around `InMemoryFile` that yields once on `set_file_size`.
    ///
    /// `InMemoryFile`'s async methods are synchronous (return Ready
    /// immediately), so `futures::join!` won't interleave two
    /// `resolve_write` calls. This wrapper inserts a
    /// `futures::pending!()` call inside `set_file_size`, creating a yield
    /// point during `allocate_space` while the `allocation_lock` is held.
    struct YieldingFile {
        inner: InMemoryFile,
    }

    impl AsyncFile for YieldingFile {
        async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), std::io::Error> {
            self.inner.read_at(offset, buf).await
        }
        async fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), std::io::Error> {
            self.inner.write_at(offset, buf).await
        }
        async fn flush(&self) -> Result<(), std::io::Error> {
            self.inner.flush().await
        }
        async fn file_size(&self) -> Result<u64, std::io::Error> {
            self.inner.file_size().await
        }
        async fn set_file_size(&self, size: u64) -> Result<(), std::io::Error> {
            // Yield once to allow other futures to run, then resume.
            // We must wake ourselves before returning Pending, otherwise
            // the executor won't re-poll us (deadlock).
            let mut yielded = false;
            std::future::poll_fn(|cx| {
                if !yielded {
                    yielded = true;
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(())
                }
            })
            .await;
            self.inner.set_file_size(size).await
        }
    }

    /// Helper: create a VHDX with custom block size on an `InMemoryFile`,
    /// returning the file and params.
    async fn create_vhdx_with_block_size(
        disk_size: u64,
        block_size: u32,
    ) -> (InMemoryFile, CreateParams) {
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size,
            block_size,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        (file, params)
    }

    /// Helper: perform a full write-complete cycle on a single block.
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

        // Write pattern data at each Data range, zero at each Zero range.
        for wr in &ranges {
            match wr {
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
                    let zeros = vec![0u8; *length as usize];
                    vhdx.file.write_at(*file_offset, &zeros).await.unwrap();
                }
            }
        }

        guard.complete().await.unwrap();
    }

    /// Helper: read a block and verify the pattern byte.
    async fn verify_block_pattern<F: AsyncFile>(
        vhdx: &VhdxFile<F>,
        guest_offset: u64,
        length: u32,
        expected_byte: u8,
    ) {
        let mut ranges = Vec::new();
        let _guard = vhdx
            .resolve_read(guest_offset, length, &mut ranges)
            .await
            .unwrap();

        for rr in &ranges {
            match rr {
                ReadRange::Data {
                    file_offset,
                    length,
                    ..
                } => {
                    let mut buf = vec![0u8; *length as usize];
                    vhdx.file.read_at(*file_offset, &mut buf).await.unwrap();
                    assert!(
                        buf.iter().all(|&b| b == expected_byte),
                        "expected all bytes to be 0x{:02x} at file_offset {}, \
                         but found mismatch",
                        expected_byte,
                        file_offset,
                    );
                }
                ReadRange::Zero { .. } => {
                    assert_eq!(expected_byte, 0, "expected data but got Zero range");
                }
                ReadRange::Unmapped { .. } => {
                    panic!("unexpected Unmapped range in non-differencing disk");
                }
            }
        }
    }

    #[async_test]
    async fn concurrent_reads_same_block(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = Arc::new(VhdxFile::open_writable(file, &driver).await.unwrap());
        let block_size = vhdx.block_size();

        // Pre-allocate block 0 with known data.
        write_block(&*vhdx, 0, block_size, 0xAA).await;

        // Spawn 10 concurrent reads to the same block.
        let futures: Vec<_> = (0..10)
            .map(|_| {
                let vhdx = vhdx.clone();
                async move {
                    let mut ranges = Vec::new();
                    let _guard = vhdx.resolve_read(0, block_size, &mut ranges).await.unwrap();
                    assert_eq!(ranges.len(), 1);
                    match &ranges[0] {
                        ReadRange::Data {
                            guest_offset,
                            length,
                            file_offset,
                        } => {
                            assert_eq!(*guest_offset, 0);
                            assert_eq!(*length, block_size);
                            assert!(*file_offset > 0);
                        }
                        other => panic!("expected Data range, got {:?}", other),
                    }
                    ranges
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        // All results should be identical.
        let first = &results[0];
        for result in &results[1..] {
            assert_eq!(first, result);
        }
    }

    #[async_test]
    async fn concurrent_reads_different_blocks(driver: DefaultDriver) {
        let (file, _) = create_vhdx_with_block_size(4 * MB1, MB1 as u32).await;
        let vhdx = Arc::new(VhdxFile::open_writable(file, &driver).await.unwrap());
        let block_size = vhdx.block_size();

        // Pre-allocate blocks 0, 1, 2.
        for i in 0..3u8 {
            write_block(&*vhdx, i as u64 * block_size as u64, block_size, 0x10 + i).await;
        }

        // Spawn 3 concurrent reads, one per block.
        let futures: Vec<_> = (0..3u32)
            .map(|i| {
                let vhdx = vhdx.clone();
                let bs = block_size;
                async move {
                    let mut ranges = Vec::new();
                    let _guard = vhdx
                        .resolve_read(i as u64 * bs as u64, bs, &mut ranges)
                        .await
                        .unwrap();
                    assert_eq!(ranges.len(), 1);
                    match &ranges[0] {
                        ReadRange::Data { file_offset, .. } => {
                            assert!(*file_offset > 0);
                        }
                        other => panic!("expected Data range for block {}, got {:?}", i, other),
                    }
                }
            })
            .collect();

        futures::future::join_all(futures).await;
    }

    #[async_test]
    async fn concurrent_writes_different_blocks(driver: DefaultDriver) {
        // 8 MiB disk with 1 MiB blocks → 8 blocks.
        let (file, _) = create_vhdx_with_block_size(8 * MB1, MB1 as u32).await;
        let vhdx = Arc::new(VhdxFile::open_writable(file, &driver).await.unwrap());
        let block_size = vhdx.block_size();

        // Spawn 4 concurrent tasks, each writing to a unique block.
        let futures: Vec<_> = (0..4u8)
            .map(|i| {
                let vhdx = vhdx.clone();
                let bs = block_size;
                async move {
                    let offset = i as u64 * bs as u64;
                    let pattern = 0x40 + i;
                    write_block(&*vhdx, offset, bs, pattern).await;
                }
            })
            .collect();

        futures::future::join_all(futures).await;

        // Verify each block reads back the correct pattern.
        for i in 0..4u8 {
            let offset = i as u64 * block_size as u64;
            verify_block_pattern(&*vhdx, offset, block_size, 0x40 + i).await;
        }
    }

    #[async_test]
    async fn concurrent_writes_same_block(driver: DefaultDriver) {
        // This test exercises concurrent writes to the same unallocated block.
        // The correct behavior (matching the C code) is serialization:
        //   1. task_a: resolve_write → acquires allocation lock → allocates
        //      → sets TFP → returns ranges
        //   2. task_a: complete_write → clears TFP → FullyPresent → notifies
        //   3. task_b: resolve_write → was waiting for TFP to clear (either
        //      in the read phase or after acquiring the lock). Once cleared,
        //      sees FullyPresent → emits Data range → returns.
        //
        // Uses YieldingFile to force a yield during set_file_size (inside
        // allocate_space), creating the interleaving where task_b's read
        // phase may see NotPresent before task_a sets TFP.

        let (inner_file, _) = create_vhdx_with_block_size(4 * MB1, MB1 as u32).await;
        let data = inner_file.snapshot();

        let yielding_file = YieldingFile {
            inner: InMemoryFile::new(0),
        };
        yielding_file.inner.write_at(0, &data).await.unwrap();

        let vhdx = Arc::new(
            VhdxFile::open_writable(yielding_file, &driver)
                .await
                .unwrap(),
        );
        let block_size = vhdx.block_size();

        // Both tasks write to block 0 (offset 0, full block).
        // task_a does resolve + complete as a unit so TFP clears and
        // task_b (serialized behind task_a) can proceed.
        let vhdx_a = vhdx.clone();
        let vhdx_b = vhdx.clone();

        let task_a = async {
            let mut ranges = Vec::new();
            let guard = vhdx_a
                .resolve_write(0, block_size, &mut ranges)
                .await
                .unwrap();
            guard.complete().await.unwrap();
            ranges
        };

        let task_b = async {
            let mut ranges = Vec::new();
            let _guard = vhdx_b
                .resolve_write(0, block_size, &mut ranges)
                .await
                .unwrap();
            ranges
        };

        let (ranges_a, ranges_b) = futures::join!(task_a, task_b);

        // Both should have produced data ranges.
        assert!(!ranges_a.is_empty(), "task_a produced no ranges");
        assert!(!ranges_b.is_empty(), "task_b produced no ranges");

        // Block should be FullyPresent.
        let bat_state = vhdx.bat_state.read();
        let mapping = bat_state.get_payload_mapping(0);
        assert_eq!(mapping.state(), BatEntryState::FullyPresent as u8);
        assert!(!mapping.transitioning_to_fully_present());
    }

    #[async_test]
    async fn concurrent_flush_requests(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = Arc::new(VhdxFile::open_writable(file, &driver).await.unwrap());
        let block_size = vhdx.block_size();

        // Write to a block, complete.
        write_block(&*vhdx, 0, block_size, 0xBB).await;

        // Spawn 5 concurrent flush calls.
        let futures: Vec<_> = (0..5)
            .map(|_| {
                let vhdx = vhdx.clone();
                async move {
                    vhdx.flush().await.unwrap();
                }
            })
            .collect();

        futures::future::join_all(futures).await;
    }

    #[async_test]
    async fn stress_random_writes_no_corruption(driver: DefaultDriver) {
        // 8 MiB disk with 1 MiB blocks → 8 blocks.
        let (file, _) = create_vhdx_with_block_size(8 * MB1, MB1 as u32).await;
        let vhdx = Arc::new(VhdxFile::open_writable(file, &driver).await.unwrap());
        let block_size = vhdx.block_size();

        // Spawn 8 tasks, each claiming a unique block.
        let futures: Vec<_> = (0..8u8)
            .map(|i| {
                let vhdx = vhdx.clone();
                let bs = block_size;
                async move {
                    let offset = i as u64 * bs as u64;
                    let pattern = 0x80 + i;
                    write_block(&*vhdx, offset, bs, pattern).await;
                    vhdx.flush().await.unwrap();
                }
            })
            .collect();

        futures::future::join_all(futures).await;

        // Verify all blocks.
        for i in 0..8u8 {
            let offset = i as u64 * block_size as u64;
            verify_block_pattern(&*vhdx, offset, block_size, 0x80 + i).await;
        }
    }

    #[async_test]
    async fn concurrent_read_and_write_same_block(driver: DefaultDriver) {
        let (file, _) = create_vhdx_with_block_size(4 * MB1, MB1 as u32).await;
        let vhdx = Arc::new(VhdxFile::open_writable(file, &driver).await.unwrap());
        let block_size = vhdx.block_size();

        // Pre-allocate block 0 with known data.
        write_block(&*vhdx, 0, block_size, 0xCC).await;

        // Concurrent: read block 0, write block 1.
        let vhdx_r = vhdx.clone();
        let vhdx_w = vhdx.clone();

        let read_task = async move {
            let mut ranges = Vec::new();
            let _guard = vhdx_r
                .resolve_read(0, block_size, &mut ranges)
                .await
                .unwrap();
            assert_eq!(ranges.len(), 1);
            match &ranges[0] {
                ReadRange::Data { .. } => {}
                other => panic!("expected Data range, got {:?}", other),
            }
        };

        let write_task = async move {
            let offset = block_size as u64;
            write_block(&*vhdx_w, offset, block_size, 0xDD).await;
        };

        futures::join!(read_task, write_task);

        // Verify block 0 still has original data.
        verify_block_pattern(&*vhdx, 0, block_size, 0xCC).await;
        // Verify block 1 has new data.
        verify_block_pattern(&*vhdx, block_size as u64, block_size, 0xDD).await;
    }

    // ---- IoGuard refcount tracking tests (Phase 10.5 Step 2) ----

    #[async_test]
    async fn read_guard_increments_refcount(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        // Pre-allocate block 0 so it's FullyPresent.
        write_block(&vhdx, 0, block_size, 0xAA).await;

        // Resolve a read — refcount should be 1 while guard is alive.
        let mut ranges = Vec::new();
        let guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        {
            let bat_state = vhdx.bat_state.read();
            assert_eq!(bat_state.io_refcount(0), 1);
        }

        // Drop the guard — refcount should go back to 0.
        drop(guard);

        {
            let bat_state = vhdx.bat_state.read();
            assert_eq!(bat_state.io_refcount(0), 0);
        }
    }

    #[async_test]
    async fn read_guard_drop_decrements_refcount(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        // Pre-allocate block 0.
        write_block(&vhdx, 0, block_size, 0xBB).await;

        let mut ranges = Vec::new();
        let guard = vhdx.resolve_read(0, block_size, &mut ranges).await.unwrap();

        // Refcount is 1 while guard is held.
        assert_eq!(vhdx.bat_state.read().io_refcount(0), 1);

        // Drop explicitly.
        drop(guard);

        // Refcount back to 0.
        assert_eq!(vhdx.bat_state.read().io_refcount(0), 0);
    }

    #[async_test]
    async fn read_guard_multiple_blocks(driver: DefaultDriver) {
        let (file, _) = create_vhdx_with_block_size(4 * MB1, MB1 as u32).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        // Write 3 blocks.
        write_block(&vhdx, 0, block_size, 0x11).await;
        write_block(&vhdx, block_size as u64, block_size, 0x22).await;
        write_block(&vhdx, 2 * block_size as u64, block_size, 0x33).await;

        // Read spanning all 3 blocks.
        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_read(0, 3 * block_size, &mut ranges)
            .await
            .unwrap();

        assert_eq!(guard.block_count(), 3);
        assert_eq!(guard.start_block(), 0);

        {
            let bat_state = vhdx.bat_state.read();
            assert_eq!(bat_state.io_refcount(0), 1);
            assert_eq!(bat_state.io_refcount(1), 1);
            assert_eq!(bat_state.io_refcount(2), 1);
        }

        drop(guard);

        {
            let bat_state = vhdx.bat_state.read();
            assert_eq!(bat_state.io_refcount(0), 0);
            assert_eq!(bat_state.io_refcount(1), 0);
            assert_eq!(bat_state.io_refcount(2), 0);
        }
    }

    #[async_test]
    async fn read_guard_zero_range_has_refcount() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_read_only(file, false).await.unwrap();

        // Read an unallocated (Zero) block — refcount is still incremented
        // (harmless, since trim won't touch unallocated blocks).
        let mut ranges = Vec::new();
        let guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        assert!(guard.block_count() > 0);
        assert_eq!(vhdx.bat_state.read().io_refcount(0), 1);

        drop(guard);

        assert_eq!(vhdx.bat_state.read().io_refcount(0), 0);
    }

    #[async_test]
    async fn write_guard_complete_drops_refcount(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(0, block_size, &mut ranges)
            .await
            .unwrap();

        // Refcount should be 1.
        assert_eq!(vhdx.bat_state.read().io_refcount(0), 1);

        // Write data and complete.
        for wr in &ranges {
            match wr {
                WriteRange::Data {
                    file_offset,
                    length,
                    ..
                } => {
                    let data = vec![0xEE; *length as usize];
                    vhdx.file.write_at(*file_offset, &data).await.unwrap();
                }
                WriteRange::Zero {
                    file_offset,
                    length,
                } => {
                    let zeros = vec![0u8; *length as usize];
                    vhdx.file.write_at(*file_offset, &zeros).await.unwrap();
                }
            }
        }

        guard.complete().await.unwrap();

        // After complete + drop, refcount should be 0 and block should be FullyPresent.
        assert_eq!(vhdx.bat_state.read().io_refcount(0), 0);
        let mapping = vhdx.get_block_mapping(0);
        assert_eq!(mapping.state, BatEntryState::FullyPresent);
    }

    #[async_test]
    async fn write_guard_drop_aborts_and_decrements_refcount(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(0, block_size, &mut ranges)
            .await
            .unwrap();

        // Refcount should be 1.
        assert_eq!(vhdx.bat_state.read().io_refcount(0), 1);

        // Drop without calling complete() — abort.
        drop(guard);

        // Refcount should be 0, block should be back to NotPresent.
        assert_eq!(vhdx.bat_state.read().io_refcount(0), 0);
        let mapping = vhdx.get_block_mapping(0);
        assert_eq!(mapping.state, BatEntryState::NotPresent);
    }

    #[async_test]
    async fn concurrent_read_guards_same_block(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        // Pre-allocate block 0.
        write_block(&vhdx, 0, block_size, 0xFF).await;

        // Two concurrent reads on the same block.
        let mut ranges1 = Vec::new();
        let mut ranges2 = Vec::new();
        let guard1 = vhdx.resolve_read(0, 4096, &mut ranges1).await.unwrap();
        let guard2 = vhdx.resolve_read(0, 4096, &mut ranges2).await.unwrap();

        // Refcount should be 2.
        assert_eq!(vhdx.bat_state.read().io_refcount(0), 2);

        // Drop first guard — refcount should be 1.
        drop(guard1);
        assert_eq!(vhdx.bat_state.read().io_refcount(0), 1);

        // Drop second guard — refcount should be 0.
        drop(guard2);
        assert_eq!(vhdx.bat_state.read().io_refcount(0), 0);
    }

    // ---- Phase 16b: Concurrent write+trim and mixed-workload stress tests ----

    use crate::trim::TrimMode;
    use crate::trim::TrimRequest;

    #[async_test]
    async fn concurrent_write_and_trim_same_block(driver: DefaultDriver) {
        // Setup: 8 MiB disk, 1 MiB blocks.
        let (file, _) = create_vhdx_with_block_size(8 * MB1, MB1 as u32).await;
        let vhdx = Arc::new(VhdxFile::open_writable(file, &driver).await.unwrap());
        let block_size = vhdx.block_size();

        // Write block 0 with pattern 0xAA, complete.
        write_block(&*vhdx, 0, block_size, 0xAA).await;

        // Concurrently: write block 0 with 0xEE + trim block 0 (FileSpace).
        let vhdx_w = vhdx.clone();
        let vhdx_t = vhdx.clone();

        let (write_result, trim_result) = futures::join!(
            async {
                write_block(&*vhdx_w, 0, block_size, 0xEE).await;
                Ok::<(), VhdxError>(())
            },
            async {
                vhdx_t
                    .trim(TrimRequest::new(TrimMode::FileSpace, 0, block_size as u64))
                    .await
            }
        );

        write_result.unwrap();
        trim_result.unwrap();

        // Check what actually happened by examining block state.
        let mapping = vhdx.get_block_mapping(0);
        match mapping.state {
            BatEntryState::Unmapped => {
                // Trim won — read should return zeros.
                verify_block_pattern(&*vhdx, 0, block_size, 0x00).await;
            }
            BatEntryState::FullyPresent => {
                // Write won — read should return 0xEE.
                verify_block_pattern(&*vhdx, 0, block_size, 0xEE).await;
            }
            other => panic!("unexpected state: {other:?}"),
        }
    }

    #[async_test]
    async fn concurrent_trim_then_rewrite(driver: DefaultDriver) {
        // Setup: 8 MiB disk, 1 MiB blocks.
        let (file, _) = create_vhdx_with_block_size(8 * MB1, MB1 as u32).await;
        let vhdx = Arc::new(VhdxFile::open_writable(file, &driver).await.unwrap());
        let block_size = vhdx.block_size();

        // Write block 0 with pattern 0xAA.
        write_block(&*vhdx, 0, block_size, 0xAA).await;

        // Sequential: trim → rewrite. Verify the trim→re-allocate path.
        vhdx.trim(TrimRequest::new(TrimMode::FileSpace, 0, block_size as u64))
            .await
            .unwrap();

        let mapping = vhdx.get_block_mapping(0);
        assert_eq!(
            mapping.state,
            BatEntryState::Unmapped,
            "block should be Unmapped after trim"
        );

        // Re-write with pattern 0xBB.
        write_block(&*vhdx, 0, block_size, 0xBB).await;

        let mapping = vhdx.get_block_mapping(0);
        assert_eq!(mapping.state, BatEntryState::FullyPresent);
        verify_block_pattern(&*vhdx, 0, block_size, 0xBB).await;

        // Now do trim + write concurrently.
        let vhdx_t = vhdx.clone();
        let vhdx_w = vhdx.clone();

        let (trim_result, write_result) = futures::join!(
            async {
                vhdx_t
                    .trim(TrimRequest::new(TrimMode::FileSpace, 0, block_size as u64))
                    .await
            },
            async {
                write_block(&*vhdx_w, 0, block_size, 0xCC).await;
                Ok::<(), VhdxError>(())
            }
        );

        trim_result.unwrap();
        write_result.unwrap();

        // Verify no panics and data is consistent.
        let mapping = vhdx.get_block_mapping(0);
        match mapping.state {
            BatEntryState::Unmapped => {
                verify_block_pattern(&*vhdx, 0, block_size, 0x00).await;
            }
            BatEntryState::FullyPresent => {
                verify_block_pattern(&*vhdx, 0, block_size, 0xCC).await;
            }
            other => panic!("unexpected state: {other:?}"),
        }
    }

    #[async_test]
    async fn mixed_workload_stress(driver: DefaultDriver) {
        // 8 MiB disk with 1 MiB blocks → 8 blocks.
        let (file, _) = create_vhdx_with_block_size(8 * MB1, MB1 as u32).await;
        let vhdx = Arc::new(VhdxFile::open_writable(file, &driver).await.unwrap());
        let block_size = vhdx.block_size();
        let num_blocks: u32 = 8;

        // Shadow state: None = unwritten/trimmed (expect zeros), Some(pattern) = last written pattern.
        let shadow: Arc<parking_lot::Mutex<Vec<Option<u8>>>> =
            Arc::new(parking_lot::Mutex::new(vec![None; num_blocks as usize]));

        let num_tasks: u32 = 8;
        let iters_per_task: u8 = 16;

        let tasks: Vec<_> = (0..num_tasks)
            .map(|task_id| {
                let vhdx = vhdx.clone();
                let shadow = shadow.clone();
                let bs = block_size;

                async move {
                    for iter in 0..iters_per_task {
                        let block =
                            (task_id.wrapping_mul(3).wrapping_add(iter as u32)) % num_blocks;
                        let pattern = ((task_id as u16 * 16 + iter as u16) as u8) | 0x01; // always nonzero
                        let block_offset = block as u64 * bs as u64;

                        let op = (task_id as u8).wrapping_add(iter) % 10;
                        match op {
                            0..=4 => {
                                // Write (50%)
                                write_block(&*vhdx, block_offset, bs, pattern).await;
                                shadow.lock()[block as usize] = Some(pattern);
                            }
                            5..=7 => {
                                // Read + verify (30%)
                                let expected = shadow.lock()[block as usize];
                                let mut ranges = Vec::new();
                                let guard = vhdx
                                    .resolve_read(block_offset, bs, &mut ranges)
                                    .await
                                    .unwrap();
                                for rr in &ranges {
                                    match rr {
                                        ReadRange::Data {
                                            file_offset,
                                            length,
                                            ..
                                        } => {
                                            let mut buf = vec![0u8; *length as usize];
                                            vhdx.file
                                                .read_at(*file_offset, &mut buf)
                                                .await
                                                .unwrap();
                                            let exp = expected.unwrap_or_else(|| {
                                                panic!(
                                                    "task {task_id} iter {iter}: shadow says \
                                                     None but got Data range"
                                                )
                                            });
                                            assert!(
                                                buf.iter().all(|&b| b == exp),
                                                "task {task_id} iter {iter}: expected \
                                                 0x{exp:02x}, got mismatch"
                                            );
                                        }
                                        ReadRange::Zero { .. } => {
                                            assert!(
                                                expected.is_none(),
                                                "task {task_id} iter {iter}: got Zero but \
                                                 expected Some({:02x})",
                                                expected.unwrap()
                                            );
                                        }
                                        ReadRange::Unmapped { .. } => {
                                            panic!("unexpected Unmapped on non-differencing disk");
                                        }
                                    }
                                }
                                drop(guard);
                            }
                            8 => {
                                // Trim (10%)
                                vhdx.trim(TrimRequest::new(
                                    TrimMode::FileSpace,
                                    block_offset,
                                    bs as u64,
                                ))
                                .await
                                .unwrap();
                                shadow.lock()[block as usize] = None;
                            }
                            9 => {
                                // Flush (10%)
                                vhdx.flush().await.unwrap();
                            }
                            _ => unreachable!(),
                        }
                    }
                }
            })
            .collect();

        futures::future::join_all(tasks).await;

        // Post-check: verify every block against final shadow state.
        let final_shadow = shadow.lock().clone();
        for block in 0..num_blocks {
            let block_offset = block as u64 * block_size as u64;
            let expected = final_shadow[block as usize];
            match expected {
                Some(pattern) => {
                    verify_block_pattern(&*vhdx, block_offset, block_size, pattern).await;
                }
                None => {
                    // Should be zeros.
                    let mut ranges = Vec::new();
                    let _guard = vhdx
                        .resolve_read(block_offset, block_size, &mut ranges)
                        .await
                        .unwrap();
                    for rr in &ranges {
                        match rr {
                            ReadRange::Zero { .. } => {}
                            ReadRange::Data {
                                file_offset,
                                length,
                                ..
                            } => {
                                let mut buf = vec![0u8; *length as usize];
                                vhdx.file.read_at(*file_offset, &mut buf).await.unwrap();
                                assert!(
                                    buf.iter().all(|&b| b == 0),
                                    "block {block}: shadow says None but data is non-zero"
                                );
                            }
                            ReadRange::Unmapped { .. } => {
                                panic!("unexpected Unmapped on non-differencing disk");
                            }
                        }
                    }
                }
            }
        }
    }

    #[async_test]
    async fn concurrent_partial_writes_same_block(driver: DefaultDriver) {
        // 8 MiB disk, 1 MiB blocks.
        let (file, _) = create_vhdx_with_block_size(8 * MB1, MB1 as u32).await;
        let vhdx = Arc::new(VhdxFile::open_writable(file, &driver).await.unwrap());
        let block_size = vhdx.block_size();

        // Pre-allocate block 0 with pattern 0xAA.
        write_block(&*vhdx, 0, block_size, 0xAA).await;

        let half = block_size / 2;
        let vhdx_a = vhdx.clone();
        let vhdx_b = vhdx.clone();

        // Concurrently write first half with 0xBB, second half with 0xCC.
        let ((), ()) = futures::join!(
            async {
                // Task A: write first half.
                let mut ranges = Vec::new();
                let guard = vhdx_a.resolve_write(0, half, &mut ranges).await.unwrap();
                for wr in &ranges {
                    match wr {
                        WriteRange::Data {
                            file_offset,
                            length,
                            ..
                        } => {
                            let data = vec![0xBB; *length as usize];
                            vhdx_a.file.write_at(*file_offset, &data).await.unwrap();
                        }
                        WriteRange::Zero {
                            file_offset,
                            length,
                        } => {
                            let zeros = vec![0u8; *length as usize];
                            vhdx_a.file.write_at(*file_offset, &zeros).await.unwrap();
                        }
                    }
                }
                guard.complete().await.unwrap();
            },
            async {
                // Task B: write second half.
                let mut ranges = Vec::new();
                let guard = vhdx_b
                    .resolve_write(half as u64, half, &mut ranges)
                    .await
                    .unwrap();
                for wr in &ranges {
                    match wr {
                        WriteRange::Data {
                            file_offset,
                            length,
                            ..
                        } => {
                            let data = vec![0xCC; *length as usize];
                            vhdx_b.file.write_at(*file_offset, &data).await.unwrap();
                        }
                        WriteRange::Zero {
                            file_offset,
                            length,
                        } => {
                            let zeros = vec![0u8; *length as usize];
                            vhdx_b.file.write_at(*file_offset, &zeros).await.unwrap();
                        }
                    }
                }
                guard.complete().await.unwrap();
            }
        );

        // Read back full block: first half should be 0xBB, second half 0xCC.
        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_read(0, block_size, &mut ranges).await.unwrap();

        for rr in &ranges {
            match rr {
                ReadRange::Data {
                    guest_offset,
                    length,
                    file_offset,
                } => {
                    let mut buf = vec![0u8; *length as usize];
                    vhdx.file.read_at(*file_offset, &mut buf).await.unwrap();

                    // Determine expected pattern based on position within block.
                    for (i, &byte) in buf.iter().enumerate() {
                        let pos = (*guest_offset as usize) + i;
                        let expected = if pos < half as usize { 0xBB } else { 0xCC };
                        assert_eq!(
                            byte, expected,
                            "byte at guest offset {pos}: expected 0x{expected:02x}, got 0x{byte:02x}"
                        );
                    }
                }
                other => panic!("expected Data range, got {other:?}"),
            }
        }
    }

    #[async_test]
    async fn concurrent_write_flush_trim_interleaved(driver: DefaultDriver) {
        // Setup: 8 MiB disk, 1 MiB blocks.
        let (file, _) = create_vhdx_with_block_size(8 * MB1, MB1 as u32).await;
        let vhdx = Arc::new(VhdxFile::open_writable(file, &driver).await.unwrap());
        let block_size = vhdx.block_size();

        // Write block 0 with 0xDD, complete.
        write_block(&*vhdx, 0, block_size, 0xDD).await;

        let vhdx_f = vhdx.clone();
        let vhdx_t = vhdx.clone();
        let vhdx_r = vhdx.clone();

        // Concurrently: flush + trim block 0 + read block 1 (unallocated → zeros).
        let (flush_result, trim_result, read_result) = futures::join!(
            async { vhdx_f.flush().await },
            async {
                vhdx_t
                    .trim(TrimRequest::new(TrimMode::FileSpace, 0, block_size as u64))
                    .await
            },
            async {
                let mut ranges = Vec::new();
                let _guard = vhdx_r
                    .resolve_read(block_size as u64, block_size, &mut ranges)
                    .await
                    .unwrap();
                // Block 1 is unallocated → should be Zero.
                for rr in &ranges {
                    assert!(
                        matches!(rr, ReadRange::Zero { .. }),
                        "block 1 should be Zero, got {rr:?}"
                    );
                }
                Ok::<(), VhdxError>(())
            }
        );

        flush_result.unwrap();
        trim_result.unwrap();
        read_result.unwrap();

        // Verify block 0 state is consistent.
        let mapping = vhdx.get_block_mapping(0);
        match mapping.state {
            BatEntryState::Unmapped => {
                // Trim completed — read should return zeros.
                verify_block_pattern(&*vhdx, 0, block_size, 0x00).await;
            }
            BatEntryState::FullyPresent => {
                // Flush completed before trim could run — data preserved.
                verify_block_pattern(&*vhdx, 0, block_size, 0xDD).await;
            }
            other => panic!("unexpected state: {other:?}"),
        }
    }

    #[async_test]
    async fn stress_write_trim_cycle(driver: DefaultDriver) {
        // 8 MiB disk with 1 MiB blocks → 8 blocks.
        let (file, _) = create_vhdx_with_block_size(8 * MB1, MB1 as u32).await;
        let vhdx = Arc::new(VhdxFile::open_writable(file, &driver).await.unwrap());
        let block_size = vhdx.block_size();

        let num_writer_tasks: u32 = 4;
        let num_reader_tasks: u32 = 2;
        let iters_per_writer: u8 = 8;

        // Shadow state: None = unwritten/trimmed (zeros), Some(pattern) = last written.
        let shadow: Arc<parking_lot::Mutex<Vec<Option<u8>>>> =
            Arc::new(parking_lot::Mutex::new(vec![None; 4]));

        // Writer tasks: write → trim → write again on block `task_id`.
        let writer_tasks: Vec<_> = (0..num_writer_tasks)
            .map(|task_id| {
                let vhdx = vhdx.clone();
                let shadow = shadow.clone();
                let bs = block_size;

                async move {
                    for iter in 0..iters_per_writer {
                        let block_offset = task_id as u64 * bs as u64;
                        let pattern_a = ((task_id as u16 * 32 + iter as u16 * 2) as u8) | 0x01;
                        let pattern_b = ((task_id as u16 * 32 + iter as u16 * 2 + 1) as u8) | 0x01;

                        // Write with pattern_a.
                        write_block(&*vhdx, block_offset, bs, pattern_a).await;
                        shadow.lock()[task_id as usize] = Some(pattern_a);

                        // Trim.
                        vhdx.trim(TrimRequest::new(
                            TrimMode::FileSpace,
                            block_offset,
                            bs as u64,
                        ))
                        .await
                        .unwrap();
                        shadow.lock()[task_id as usize] = None;

                        // Write with pattern_b.
                        write_block(&*vhdx, block_offset, bs, pattern_b).await;
                        shadow.lock()[task_id as usize] = Some(pattern_b);
                    }
                }
            })
            .collect();

        // Reader tasks: continuously read all 4 blocks, verify consistency.
        let reader_tasks: Vec<_> = (0..num_reader_tasks)
            .map(|_reader_id| {
                let vhdx = vhdx.clone();
                let shadow = shadow.clone();
                let bs = block_size;

                async move {
                    // Read all 4 blocks multiple times.
                    for _round in 0..16 {
                        for block in 0..4u32 {
                            let block_offset = block as u64 * bs as u64;
                            let expected = shadow.lock()[block as usize];

                            let mut ranges = Vec::new();
                            let guard = vhdx
                                .resolve_read(block_offset, bs, &mut ranges)
                                .await
                                .unwrap();
                            for rr in &ranges {
                                match rr {
                                    ReadRange::Data {
                                        file_offset,
                                        length,
                                        ..
                                    } => {
                                        let mut buf = vec![0u8; *length as usize];
                                        vhdx.file.read_at(*file_offset, &mut buf).await.unwrap();
                                        match expected {
                                            Some(exp) => {
                                                assert!(
                                                    buf.iter().all(|&b| b == exp),
                                                    "reader block {block}: expected \
                                                     0x{exp:02x}, got mismatch"
                                                );
                                            }
                                            None => {
                                                assert!(
                                                    buf.iter().all(|&b| b == 0),
                                                    "reader block {block}: expected zeros, \
                                                     got non-zero data"
                                                );
                                            }
                                        }
                                    }
                                    ReadRange::Zero { .. } => {
                                        assert!(
                                            expected.is_none(),
                                            "reader block {block}: got Zero but expected \
                                             Some({:02x})",
                                            expected.unwrap()
                                        );
                                    }
                                    ReadRange::Unmapped { .. } => {
                                        panic!("unexpected Unmapped on non-differencing disk");
                                    }
                                }
                            }
                            drop(guard);
                        }
                    }
                }
            })
            .collect();

        // Run all tasks concurrently.
        let all_tasks: Vec<_> = writer_tasks
            .into_iter()
            .map(|t| Box::pin(t) as std::pin::Pin<Box<dyn Future<Output = ()>>>)
            .chain(
                reader_tasks
                    .into_iter()
                    .map(|t| Box::pin(t) as std::pin::Pin<Box<dyn Future<Output = ()>>>),
            )
            .collect();

        futures::future::join_all(all_tasks).await;

        // Post-check: verify final state of all 4 blocks.
        let final_shadow = shadow.lock().clone();
        for block in 0..4u32 {
            let block_offset = block as u64 * block_size as u64;
            match final_shadow[block as usize] {
                Some(pattern) => {
                    verify_block_pattern(&*vhdx, block_offset, block_size, pattern).await;
                }
                None => {
                    verify_block_pattern(&*vhdx, block_offset, block_size, 0x00).await;
                }
            }
        }
    }

    // ---- SBM allocation tests ----

    #[async_test]
    async fn partial_write_diff_disk_allocates_sbm(driver: DefaultDriver) {
        // A sub-block write to a NotPresent block in a differencing disk
        // should allocate the SBM block and set the payload to PartiallyPresent.
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            has_parent: true,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        // Partial write: 4096 bytes at offset 0 (sub-block).
        write_block(&vhdx, 0, 4096, 0xAB).await;

        // Block 0 should be PartiallyPresent.
        let mapping = vhdx.get_block_mapping(0);
        assert_eq!(mapping.state, BatEntryState::PartiallyPresent);

        // SBM block for chunk 0 should be FullyPresent (allocated).
        let sbm_mapping = vhdx.get_sector_bitmap_mapping(0);
        assert_eq!(sbm_mapping.state, BatEntryState::FullyPresent);

        // Read the written range — should return Data.
        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();
        let has_data = ranges.iter().any(|r| matches!(r, ReadRange::Data { .. }));
        assert!(has_data, "written sectors should return Data");

        // Read an unwritten range in the same block — should return Unmapped.
        let mut ranges2 = Vec::new();
        let _guard2 = vhdx.resolve_read(4096, 512, &mut ranges2).await.unwrap();
        assert_eq!(ranges2.len(), 1);
        assert!(
            matches!(ranges2[0], ReadRange::Unmapped { .. }),
            "unwritten sectors in diff disk should return Unmapped"
        );
    }

    #[async_test]
    async fn partial_write_diff_disk_sbm_bits_set_correctly(driver: DefaultDriver) {
        // Write 4096 bytes (sectors 0-7 for 512-byte sectors) to a diff disk.
        // Verify that the written sectors read as Data and unwritten ones as Unmapped.
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            has_parent: true,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        write_block(&vhdx, 0, 4096, 0xCD).await;

        // Sectors 0-7 should be Data.
        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();
        assert_eq!(ranges.len(), 1);
        match &ranges[0] {
            ReadRange::Data {
                guest_offset,
                length,
                ..
            } => {
                assert_eq!(*guest_offset, 0);
                assert_eq!(*length, 4096);
            }
            other => panic!("expected Data, got {:?}", other),
        }

        // Sector 8 onward should be Unmapped (transparent to parent).
        let mut ranges2 = Vec::new();
        let _guard2 = vhdx.resolve_read(4096, 512, &mut ranges2).await.unwrap();
        assert_eq!(ranges2.len(), 1);
        assert_eq!(
            ranges2[0],
            ReadRange::Unmapped {
                guest_offset: 4096,
                length: 512,
            }
        );
    }

    #[async_test]
    async fn full_block_write_diff_disk_no_sbm(driver: DefaultDriver) {
        // A full-block write to a diff disk should set FullyPresent, not allocate SBM.
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            has_parent: true,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size();

        // Full-block write.
        write_block(&vhdx, 0, block_size, 0xEE).await;

        // Block 0 should be FullyPresent (TFP path).
        let mapping = vhdx.get_block_mapping(0);
        assert_eq!(mapping.state, BatEntryState::FullyPresent);

        // SBM block for chunk 0 should NOT be allocated.
        let sbm_mapping = vhdx.get_sector_bitmap_mapping(0);
        assert_ne!(
            sbm_mapping.state,
            BatEntryState::FullyPresent,
            "full-block write should not allocate SBM"
        );
    }

    #[async_test]
    async fn second_partial_write_same_chunk_reuses_sbm(driver: DefaultDriver) {
        // Two partial writes to different blocks in the same chunk should
        // reuse the same SBM block.
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            has_parent: true,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();
        let block_size = vhdx.block_size() as u64;

        // First partial write to block 0.
        write_block(&vhdx, 0, 4096, 0x11).await;

        let sbm_mapping_1 = vhdx.get_sector_bitmap_mapping(0);
        assert_eq!(sbm_mapping_1.state, BatEntryState::FullyPresent);
        let sbm_offset_1 = sbm_mapping_1.file_offset;

        // Second partial write to block 1 (same chunk).
        write_block(&vhdx, block_size, 4096, 0x22).await;

        let sbm_mapping_2 = vhdx.get_sector_bitmap_mapping(0);
        assert_eq!(sbm_mapping_2.state, BatEntryState::FullyPresent);
        let sbm_offset_2 = sbm_mapping_2.file_offset;

        // SBM should be reused (same file offset).
        assert_eq!(
            sbm_offset_1, sbm_offset_2,
            "SBM block should be reused, not reallocated"
        );

        // Both blocks should read back correctly.
        let mut ranges0 = Vec::new();
        let _g0 = vhdx.resolve_read(0, 4096, &mut ranges0).await.unwrap();
        assert!(matches!(ranges0[0], ReadRange::Data { .. }));

        let mut ranges1 = Vec::new();
        let _g1 = vhdx
            .resolve_read(block_size, 4096, &mut ranges1)
            .await
            .unwrap();
        assert!(matches!(ranges1[0], ReadRange::Data { .. }));
    }

    #[async_test]
    async fn partial_write_non_diff_disk_no_sbm(driver: DefaultDriver) {
        // A sub-block write to a non-differencing disk should set FullyPresent
        // and NOT allocate any SBM block.
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open_writable(file, &driver).await.unwrap();

        // Partial write: 4096 bytes at offset 0.
        write_block(&vhdx, 0, 4096, 0x77).await;

        // Block should be FullyPresent (not PartiallyPresent).
        let mapping = vhdx.get_block_mapping(0);
        assert_eq!(mapping.state, BatEntryState::FullyPresent);

        // SBM should NOT be allocated.
        // For non-diff disks, sector_bitmap_block_count may be 0,
        // so we check via bat_state directly.
        let sbm_count = vhdx.bat.sector_bitmap_block_count;
        if sbm_count > 0 {
            let sbm_mapping = vhdx.get_sector_bitmap_mapping(0);
            assert_ne!(
                sbm_mapping.state,
                BatEntryState::FullyPresent,
                "non-diff disk should not allocate SBM"
            );
        }

        // Unwritten sectors within the block should read as Zero (not Unmapped).
        let mut ranges = Vec::new();
        let _guard = vhdx.resolve_read(4096, 512, &mut ranges).await.unwrap();
        assert_eq!(ranges.len(), 1);
        match &ranges[0] {
            ReadRange::Data { .. } => {
                // Data range is fine — zero-padded data within an allocated block.
            }
            ReadRange::Zero { .. } => {
                // Zero range is also acceptable (block may be zero-padded).
            }
            ReadRange::Unmapped { .. } => {
                panic!("non-diff disk should never return Unmapped for allocated block");
            }
        }
    }
}
