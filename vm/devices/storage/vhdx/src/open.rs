// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VHDX file open orchestration.
//!
//! Ties together header, region, metadata, and BAT parsing into a single
//! [`VhdxFile::open()`] entry point. Produces an open file handle with
//! accessor methods for disk geometry and state.

use crate::AsyncFile;
use crate::bat::BAT_TAG;
use crate::bat::Bat;
use crate::bat::BatState;
use crate::bat::BlockMapping;
use crate::bat::BlockType;
use crate::bat::InternalBlockMapping;
use crate::bat::METADATA_TAG;
use crate::cache::PageCache;
use crate::cache::PageKey;
use crate::error::CorruptionType;
use crate::error::VhdxError;
use crate::flush::FlushSequencer;
use crate::format;
use crate::format::BatEntry;
use crate::format::BatEntryState;
use crate::format::CACHE_PAGE_SIZE;
use crate::format::ENTRIES_PER_BAT_PAGE;
use crate::format::FileIdentifier;
use crate::format::Header;
use crate::format::MB1;
use crate::header::parse_headers;
use crate::known_meta::read_known_metadata;
use crate::known_meta::verify_known_metadata;
use crate::log;
use crate::log::LogRegion;
use crate::log_task::LogRequest;
use crate::metadata::MetadataTable;
use crate::region::parse_region_tables;
use crate::sector_bitmap::SBM_TAG;
use crate::space::AllocateResult;
use crate::space::FreeSpaceTracker;
use guid::Guid;
use parking_lot::Mutex;
use parking_lot::RwLock;
use std::sync::Arc;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

/// Mutable header and write-mode state, protected by a mutex.
///
/// All fields here may change during write operations. The mutex must
/// be dropped before any `.await` point.
pub(crate) struct WriteState {
    /// Current write mode (None if no writes have occurred).
    pub write_mode: Option<WriteMode>,
    /// Current header sequence number.
    pub sequence_number: u64,
    /// GUID changed on every file-level write.
    pub file_write_guid: Guid,
    /// GUID changed on every virtual-disk data write.
    pub data_write_guid: Guid,
    /// Active log GUID. Zero when no log task is running.
    pub log_guid: Guid,
    /// True if header slot 1 (offset 64 KiB) is the current header.
    pub first_header_current: bool,
}

/// The kind of modification being made to the VHDX file. Controls which
/// GUIDs are updated in the header before the first write.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum WriteMode {
    /// The file is being modified (metadata only, e.g. resize/compact).
    /// Updates FileWriteGuid.
    FileWritable,
    /// User-visible virtual disk data is being modified.
    /// Updates both FileWriteGuid and DataWriteGuid.
    DataWritable,
}

/// An open VHDX file handle.
///
/// Created via [`VhdxFile::open()`], this provides read and write access
/// to the virtual disk's metadata and BAT (block allocation table).
//
// Lock ordering (must acquire in this order, never reverse):
//   1. allocation_lock    (futures::lock::Mutex — async, may be held across .await)
//   2. bat_state           (parking_lot::RwLock — synchronous, NEVER across .await)
//   3. write_state         (parking_lot::Mutex — synchronous, NEVER across .await)
//   4. free_space.inner    (parking_lot::Mutex — synchronous, NEVER across .await)
//   5. cache.pages/tags    (parking_lot::Mutex — brief, NEVER across .await)
//
// The allocation_lock serializes the entire allocation decision (check BAT, allocate
// space, mark TFP). It is released AFTER TFP is set but BEFORE data I/O begins.
// The bat_state RwLock is held for < 1μs per access (reading/writing in-memory entries).
// The write_state Mutex is held only in enable_write_mode() to check/update the mode.
pub struct VhdxFile<F: AsyncFile> {
    pub(crate) file: Arc<F>,
    pub(crate) cache: PageCache<F>,
    pub(crate) bat: Bat,

    // Parsed metadata
    pub(crate) disk_size: u64,
    pub(crate) block_size: u32,
    pub(crate) logical_sector_size: u32,
    physical_sector_size: u32,
    pub(crate) has_parent: bool,
    is_fully_allocated: bool,
    #[allow(dead_code)] // Phase 7+: used for disk_backend integration
    page_83_data: Guid,

    // Metadata table (kept for on-demand metadata reads).
    metadata_table: MetadataTable,

    // Mutable header / write-mode state.
    pub(crate) write_state: Mutex<WriteState>,

    // In-memory BAT state.
    pub(crate) bat_state: RwLock<BatState>,

    /// Serializes block allocation decisions. Only one allocation sequence
    /// runs at a time. Uses futures::lock::Mutex because it may be held
    /// across .await points.
    pub(crate) allocation_lock: futures::lock::Mutex<()>,

    /// Broadcast event notified when a TFP block completes post-allocation.
    /// Writers that encounter a TFP block listen on this event and retry.
    pub(crate) allocation_event: event_listener::Event,

    /// Broadcast event notified when any I/O guard is dropped and a block's
    /// refcount reaches zero. Trim (Phase 11) waits on this event when it
    /// finds a block with refcount > 0.
    pub(crate) trim_event: event_listener::Event,

    /// Free space tracker. Manages all space allocation within the file,
    /// replacing the simple EOF-bump allocator.
    pub(crate) free_space: FreeSpaceTracker,

    // Region offsets
    #[allow(dead_code)] // Phase 9+: used for space management
    bat_length: u32,
    #[allow(dead_code)] // Phase 9+: used for metadata writes
    metadata_offset: u64,
    #[allow(dead_code)] // Phase 9+: used for metadata writes
    metadata_length: u32,
    log_offset: u64,
    log_length: u32,

    // Mode
    pub(crate) read_only: bool,

    // Error state: once set, all operations fail.
    #[allow(dead_code)] // Phase 7+: used for error propagation on I/O path
    failed: Option<VhdxError>,

    // Log task state (set when opened with log task via open_with_log).
    /// Sender for log requests. `None` for read-only files or files opened
    /// without a log task.
    pub(crate) log_sender: Option<mesh::Sender<LogRequest>>,
    /// Handle to the spawned log task. `None` if no log task is running.
    log_task: Option<pal_async::task::Task<()>>,
    /// Flush sequencer for FSN-gated ordering. `None` for read-only files.
    pub(crate) flush_sequencer: Option<Arc<FlushSequencer>>,
}

impl<F: AsyncFile> VhdxFile<F> {
    /// Open an existing VHDX file.
    ///
    /// Validates the file identifier, headers, region tables, and metadata.
    /// If the log GUID is non-zero (indicating a dirty log), replays the
    /// log to recover the file. Read-only opens with a dirty log return
    /// [`CorruptionType::LogReplayRequired`].
    pub async fn open(file: F, read_only: bool) -> Result<Self, VhdxError> {
        // 1. Validate minimum file size.
        let file_length = file.file_size().await.map_err(VhdxError::Io)?;
        if file_length < format::HEADER_AREA_SIZE {
            return Err(VhdxError::Corrupt(CorruptionType::EmptyFile));
        }

        // 2. Validate the file identifier signature.
        validate_file_identifier(&file).await?;

        // 3. Parse dual headers.
        let mut header = parse_headers(&file, file_length).await?;

        // 4. If log_guid is non-zero, replay the log.
        if header.log_guid != Guid::ZERO {
            // A dirty log requires writing to the file to replay. If the caller
            // opened read-only, we cannot proceed — the metadata may be
            // inconsistent and we're not allowed to fix it.
            if read_only {
                return Err(VhdxError::Corrupt(CorruptionType::LogReplayRequired));
            }

            // The file handle hasn't been Arc-wrapped yet — pass &file directly.
            let log_region = LogRegion {
                file_offset: header.log_offset,
                length: header.log_length,
            };

            let replay_result = log::replay_log(&file, &log_region, header.log_guid).await?;

            if replay_result.replayed {
                // Write a clean header: clear log_guid, bump sequence number.
                // Write to the non-current header slot, then flush.
                let new_seq = header.sequence_number + 1;

                let mut clean_header = Header::new_zeroed();
                clean_header.signature = format::HEADER_SIGNATURE;
                clean_header.sequence_number = new_seq;
                clean_header.file_write_guid = header.file_write_guid;
                clean_header.data_write_guid = header.data_write_guid;
                clean_header.log_guid = Guid::ZERO;
                clean_header.log_version = format::LOG_VERSION;
                clean_header.version = format::VERSION_1;
                clean_header.log_length = header.log_length;
                clean_header.log_offset = header.log_offset;
                clean_header.checksum = 0;

                let mut buf = vec![0u8; format::HEADER_SIZE as usize];
                let hdr_bytes = clean_header.as_bytes();
                buf[..hdr_bytes.len()].copy_from_slice(hdr_bytes);
                let crc = format::compute_checksum(&buf, 4);
                buf[4..8].copy_from_slice(&crc.to_le_bytes());

                // Write to the non-current slot.
                let write_offset = if header.first_header_current {
                    format::HEADER_OFFSET_2
                } else {
                    format::HEADER_OFFSET_1
                };
                file.write_at(write_offset, &buf).await?;
                file.flush().await?;

                // Update the in-flight header state for the rest of the open path.
                header.sequence_number = new_seq;
                header.log_guid = Guid::ZERO;
                header.first_header_current = !header.first_header_current;
            }
        }

        // 5. Parse region tables.
        let regions = parse_region_tables(&file).await?;

        // 6. Read metadata table.
        let metadata_table =
            MetadataTable::read(&file, regions.metadata_offset, regions.metadata_length).await?;

        // 7. Verify known metadata (all required system items are recognized).
        verify_known_metadata(&metadata_table, false)?;

        // 8. Read known metadata values.
        let known = read_known_metadata(&file, &metadata_table, regions.metadata_offset).await?;

        // 9. Create BAT manager.
        let bat = Bat::new(
            known.disk_size,
            known.block_size,
            known.logical_sector_size,
            known.has_parent,
        )?;

        // 10. Validate BAT region size.
        bat.validate_bat_size(regions.bat_length)?;

        // 11. Wrap file in Arc for shared access.
        let file = Arc::new(file);

        // 12. Create PageCache and register tags.
        let mut cache = PageCache::new(file.clone());
        cache.register_tag(BAT_TAG, regions.bat_offset);
        cache.register_tag(METADATA_TAG, regions.metadata_offset);
        cache.register_tag(SBM_TAG, 0);

        // 13. Create FreeSpaceTracker.
        let free_space = FreeSpaceTracker::new(
            file_length,
            known.block_size,
            format::HEADER_AREA_SIZE,
            header.log_offset,
            header.log_length,
            regions.bat_offset,
            regions.bat_length,
            regions.metadata_offset,
            regions.metadata_length,
            bat.data_block_count,
        )?;

        // 14. Load in-memory BAT from disk.
        let bat_state = Self::load_bat_state(&cache, &bat, &free_space).await?;

        // 15. Finalize free space initialization after BAT parse.
        free_space.complete_initialization();

        // 16. Construct VhdxFile.
        Ok(VhdxFile {
            file,
            cache,
            bat,
            disk_size: known.disk_size,
            block_size: known.block_size,
            logical_sector_size: known.logical_sector_size,
            physical_sector_size: known.physical_sector_size,
            has_parent: known.has_parent,
            is_fully_allocated: known.leave_blocks_allocated,
            page_83_data: known.page_83_data,
            metadata_table,
            write_state: Mutex::new(WriteState {
                write_mode: None,
                sequence_number: header.sequence_number,
                file_write_guid: header.file_write_guid,
                data_write_guid: header.data_write_guid,
                log_guid: Guid::ZERO,
                first_header_current: header.first_header_current,
            }),
            bat_state: RwLock::new(bat_state),
            allocation_lock: futures::lock::Mutex::new(()),
            allocation_event: event_listener::Event::new(),
            trim_event: event_listener::Event::new(),
            free_space,

            bat_length: regions.bat_length,
            metadata_offset: regions.metadata_offset,
            metadata_length: regions.metadata_length,
            log_offset: header.log_offset,
            log_length: header.log_length,
            read_only,
            failed: None,

            log_sender: None,
            log_task: None,
            flush_sequencer: None,
        })
    }

    /// Open an existing VHDX file in read-only mode.
    ///
    /// Convenience wrapper for `open(file, true)`. No log task is spawned.
    pub async fn open_read_only(file: F) -> Result<Self, VhdxError> {
        Self::open(file, true).await
    }
}

impl<F: AsyncFile + 'static> VhdxFile<F> {
    /// Open an existing VHDX file in writable mode with a log task.
    ///
    /// Like [`open()`](Self::open) with `read_only = false`, but additionally
    /// spawns a log task for crash-consistent metadata writes. The log task
    /// receives dirty pages on `flush()` and writes them as WAL entries.
    ///
    /// The spawner must implement [`pal_async::task::Spawn`] to spawn the
    /// background log task.
    ///
    /// Call [`close()`](Self::close) for a clean shutdown. Dropping without
    /// close leaves the VHDX file dirty (log will be replayed on next open).
    pub async fn open_with_log(
        file: F,
        spawner: &impl pal_async::task::Spawn,
    ) -> Result<Self, VhdxError> {
        let mut vhdx = Self::open(file, false).await?;

        // Create mesh channel for log requests.
        let (tx, rx) = mesh::channel::<LogRequest>();

        // Create flush sequencer.
        let flush_sequencer = Arc::new(FlushSequencer::new());

        // Initialize the log writer.
        let log_guid = Guid::new_random();
        let log_region = LogRegion {
            file_offset: vhdx.log_offset,
            length: vhdx.log_length,
        };
        let file_length = vhdx.file.file_size().await.map_err(VhdxError::Io)?;
        let log_writer =
            log::LogWriter::initialize(vhdx.file.as_ref(), log_region, log_guid, file_length)
                .await?;

        // Write header with log_guid set (marks file as dirty).
        // This is done BEFORE spawning the log task so the file is marked
        // dirty before any log entries are written.
        {
            let mut state = vhdx.write_state.lock();
            state.sequence_number += 1;

            let mut header = Header::new_zeroed();
            header.signature = format::HEADER_SIGNATURE;
            header.sequence_number = state.sequence_number;
            header.file_write_guid = state.file_write_guid;
            header.data_write_guid = state.data_write_guid;
            header.log_guid = log_guid;
            header.log_version = format::LOG_VERSION;
            header.version = format::VERSION_1;
            header.log_length = vhdx.log_length;
            header.log_offset = vhdx.log_offset;
            header.checksum = 0;

            let mut buf = vec![0u8; format::HEADER_SIZE as usize];
            let hdr_bytes = header.as_bytes();
            buf[..hdr_bytes.len()].copy_from_slice(hdr_bytes);
            let crc = format::compute_checksum(&buf, 4);
            buf[4..8].copy_from_slice(&crc.to_le_bytes());

            let offset = if state.first_header_current {
                format::HEADER_OFFSET_2
            } else {
                format::HEADER_OFFSET_1
            };

            // Drop the lock before async I/O.
            drop(state);
            vhdx.file.write_at(offset, &buf).await?;
            vhdx.file.flush().await?;

            // Update state after flush.
            let mut state = vhdx.write_state.lock();
            state.first_header_current = !state.first_header_current;
            state.log_guid = log_guid;
        }

        // Enable write-back mode on the cache so dirty pages are deferred
        // to flush() rather than written directly on commit().
        vhdx.cache.enable_write_back();

        // Spawn the log task.
        let file_clone = vhdx.file.clone();
        let fsn_clone = flush_sequencer.clone();
        let log_offset = vhdx.log_offset;
        let log_length = vhdx.log_length;
        let task = spawner.spawn(
            "vhdx-log-task",
            crate::log_task::run_log_task(
                rx, file_clone, log_writer, fsn_clone, log_offset, log_length,
            ),
        );

        vhdx.log_sender = Some(tx);
        vhdx.log_task = Some(task);
        vhdx.flush_sequencer = Some(flush_sequencer);

        Ok(vhdx)
    }

    /// Gracefully close the VHDX file.
    ///
    /// Flushes all dirty pages through the log, applies all logged entries,
    /// clears the log GUID in the header, and waits for the log task to exit.
    ///
    /// After this returns, the file is in a clean state (no log replay needed
    /// on next open).
    ///
    /// If no log task is running (read-only or opened without log), this is
    /// a no-op.
    pub async fn close(mut self) -> Result<(), VhdxError> {
        use mesh::rpc::RpcSend;

        if let Some(sender) = self.log_sender.take() {
            // First flush any dirty pages from the cache through the log.
            self.cache.flush(Some(&sender)).await?;

            // Send Close request and await response.
            let result = sender
                .call(LogRequest::Close, ())
                .await
                .map_err(|_| VhdxError::Io(std::io::Error::other("log task closed")))?;
            result?;

            // Drop the sender to close the channel.
            drop(sender);

            // Await the log task to exit.
            if let Some(task) = self.log_task.take() {
                task.await;
            }
        }
        Ok(())
    }

    /// Abort the VHDX file without graceful close.
    ///
    /// Drops the log channel (causing the log task to exit on its next
    /// recv) and waits for the log task to finish. No pending batches are
    /// applied and the log GUID is NOT cleared — the file remains dirty,
    /// requiring log replay on the next open.
    ///
    /// This is the test-friendly equivalent of a crash: all state held by
    /// the log task (including its `Arc<F>`) is released, but no new I/O
    /// is issued.
    pub async fn abort(mut self) {
        // Drop the sender so the log task's recv() returns Err.
        self.log_sender.take();

        // Wait for the log task to notice the closed channel and exit.
        if let Some(task) = self.log_task.take() {
            task.await;
        }
    }
}

impl<F: AsyncFile> VhdxFile<F> {
    /// Load the in-memory BAT state from disk BAT pages.
    ///
    /// During parse, marks allocated blocks in the FreeSpaceTracker and
    /// records soft-anchored blocks.
    async fn load_bat_state(
        cache: &PageCache<F>,
        bat: &Bat,
        free_space: &FreeSpaceTracker,
    ) -> Result<BatState, VhdxError> {
        let mut payload_mappings = Vec::with_capacity(bat.data_block_count as usize);
        let mut sector_bitmap_mappings = Vec::with_capacity(bat.sector_bitmap_block_count as usize);
        let mut allocated_block_count: u32 = 0;

        // Read all payload entries.
        for block in 0..bat.data_block_count {
            let entry_index = bat.payload_entry_index(block);
            let entry = Self::read_bat_entry_raw(cache, entry_index).await?;
            // Validate the entry state.
            let raw_state = entry.state();
            if BatEntryState::from_raw(raw_state).is_none() {
                return Err(VhdxError::Corrupt(CorruptionType::InvalidBlockState));
            }
            let internal = InternalBlockMapping::from_bat_entry(entry);
            if raw_state == BatEntryState::FullyPresent as u8
                || raw_state == BatEntryState::PartiallyPresent as u8
            {
                allocated_block_count += 1;
                // Mark the block's file region as in-use in the space tracker.
                let file_offset = internal.file_megabyte() as u64 * MB1;
                if file_offset != 0 {
                    free_space.mark_range_in_use(file_offset, bat.block_size)?;
                }
            } else if (raw_state == BatEntryState::Unmapped as u8
                || raw_state == BatEntryState::Undefined as u8)
                && internal.file_megabyte() != 0
            {
                // Soft-anchored block: unmapped/undefined with non-zero file offset.
                let file_offset = internal.file_megabyte() as u64 * MB1;
                free_space.mark_trimmed_block(block, file_offset, bat.block_size)?;
            }
            payload_mappings.push(internal);
        }

        // Read all sector bitmap entries.
        for chunk in 0..bat.sector_bitmap_block_count {
            let entry_index = bat.sector_bitmap_entry_index(chunk);
            let entry = Self::read_bat_entry_raw(cache, entry_index).await?;
            let raw_state = entry.state();
            if BatEntryState::from_raw(raw_state).is_none() {
                return Err(VhdxError::Corrupt(CorruptionType::InvalidBlockState));
            }
            let internal = InternalBlockMapping::from_bat_entry(entry);
            // Mark sector bitmap block's file region as in-use if allocated.
            if raw_state == BatEntryState::FullyPresent as u8
                || raw_state == BatEntryState::PartiallyPresent as u8
            {
                let file_offset = internal.file_megabyte() as u64 * MB1;
                if file_offset != 0 {
                    free_space
                        .mark_range_in_use(file_offset, crate::bat::SECTOR_BITMAP_BLOCK_SIZE)?;
                }
            }
            sector_bitmap_mappings.push(internal);
        }

        let total_bat_pages = bat.total_bat_pages();
        let payload_count = payload_mappings.len();
        Ok(BatState {
            payload_mappings,
            sector_bitmap_mappings,
            allocated_block_count,
            dirty_bat_pages: vec![false; total_bat_pages],
            io_refcounts: vec![0u32; payload_count],
        })
    }

    /// Read a single raw BAT entry from disk through the cache.
    async fn read_bat_entry_raw(
        cache: &PageCache<F>,
        entry_index: u32,
    ) -> Result<BatEntry, VhdxError> {
        let page_offset = (entry_index as u64 / ENTRIES_PER_BAT_PAGE) * CACHE_PAGE_SIZE;
        let entry_within_page = entry_index as usize % ENTRIES_PER_BAT_PAGE as usize;

        let entry = {
            let guard = cache
                .acquire_read(PageKey {
                    tag: BAT_TAG,
                    offset: page_offset,
                })
                .await?;

            let byte_offset = entry_within_page * size_of::<BatEntry>();
            let entry_bytes = &guard[byte_offset..byte_offset + size_of::<BatEntry>()];
            BatEntry::read_from_bytes(entry_bytes)
                .map_err(|_| VhdxError::Corrupt(CorruptionType::InvalidBlockState))?
        };

        Ok(entry)
    }

    /// Virtual disk size in bytes.
    pub fn disk_size(&self) -> u64 {
        self.disk_size
    }

    /// Block size in bytes.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Logical sector size (512 or 4096).
    pub fn logical_sector_size(&self) -> u32 {
        self.logical_sector_size
    }

    /// Physical sector size (512 or 4096).
    pub fn physical_sector_size(&self) -> u32 {
        self.physical_sector_size
    }

    /// Whether this is a differencing disk (has a parent).
    pub fn has_parent(&self) -> bool {
        self.has_parent
    }

    /// Read and parse the parent locator from the metadata region.
    ///
    /// Returns `Ok(None)` for base (non-differencing) disks.
    /// Returns an error if the locator item is missing or corrupt.
    pub async fn parent_locator(&self) -> Result<Option<crate::locator::ParentLocator>, VhdxError> {
        if !self.has_parent {
            return Ok(None);
        }
        let locator_data = self
            .metadata_table
            .read_item(
                self.file.as_ref(),
                self.metadata_offset,
                false,
                &format::PARENT_LOCATOR_ITEM_GUID,
            )
            .await?;
        Ok(Some(crate::locator::ParentLocator::parse(&locator_data)?))
    }

    /// Whether the disk was created with all blocks pre-allocated (fixed VHD).
    pub fn is_fully_allocated(&self) -> bool {
        self.is_fully_allocated
    }

    /// GUID changed on every virtual-disk data write.
    pub fn data_write_guid(&self) -> Guid {
        self.write_state.lock().data_write_guid
    }

    /// Whether the file was opened in read-only mode.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Look up the block mapping for a given data block number.
    ///
    /// Synchronous — reads from the in-memory BAT, no I/O.
    pub(crate) fn get_block_mapping(&self, block_number: u32) -> BlockMapping {
        let bat_state = self.bat_state.read();
        self.bat
            .get_block_mapping_from_state(&bat_state, block_number)
    }

    /// Look up the sector bitmap block mapping for a given chunk number.
    ///
    /// Synchronous — reads from the in-memory BAT, no I/O.
    pub(crate) fn get_sector_bitmap_mapping(&self, chunk_number: u32) -> BlockMapping {
        let bat_state = self.bat_state.read();
        self.bat
            .get_sbm_mapping_from_state(&bat_state, chunk_number)
    }

    /// Allocate space for a new block. Async — may extend the file.
    ///
    /// Called under `allocation_lock` (the `FreeSpaceWorkerLock` equivalent).
    /// Tries pool → near-EOF → anchored, extends file and retries if needed.
    ///
    /// Corresponds to `Vhd2iContinueAllocateSpace`.
    pub(crate) async fn allocate_space(
        &self,
        size: u32,
        aligned: bool,
    ) -> Result<AllocateResult, VhdxError> {
        debug_assert!(
            (size as u64).is_multiple_of(MB1),
            "allocation size must be MB1-aligned"
        );

        loop {
            // Try priorities 1–3 (pool, near-EOF, anchored).
            // Pass BAT state for soft-anchor lookup.
            let result = {
                let bat_state = self.bat_state.read();
                self.free_space
                    .try_allocate_with_bat(size, aligned, &bat_state)
            };

            if let Some(alloc) = result {
                return Ok(alloc);
            }

            // Priority 4: extend EOF.
            let target = self.free_space.required_file_length(size, aligned);
            // LOCK AUDIT: bat_state read-lock dropped (end of block above). allocation_lock held (async Mutex — OK across .await).
            self.file
                .set_file_size(target)
                .await
                .map_err(VhdxError::Io)?;
            self.free_space.complete_file_extend(target);
            // Retry — will succeed from near-EOF space.
        }
    }

    /// Set block alignment for aligned allocations.
    ///
    /// Corresponds to `Vhd2SetBlockAlignment`.
    pub fn set_block_alignment(&self, alignment: u32) -> Result<(), VhdxError> {
        self.free_space.set_block_alignment(alignment)
    }

    /// Serialize a single BAT page from in-memory state into a raw byte buffer.
    ///
    /// For each of the 512 entries on the page, reverse-maps the flat entry
    /// number to (BlockType, block_number) and reads the in-memory mapping.
    /// Entries beyond the disk end are written as zero.
    ///
    /// The caller must hold a `BatState` lock (read or write) while calling
    /// this, passing in the locked state reference.
    fn produce_bat_page(
        &self,
        bat_state: &BatState,
        page_index: usize,
    ) -> [u8; CACHE_PAGE_SIZE as usize] {
        let mut buf = [0u8; CACHE_PAGE_SIZE as usize];
        let base_entry = page_index as u32 * ENTRIES_PER_BAT_PAGE as u32;
        for i in 0..ENTRIES_PER_BAT_PAGE as u32 {
            let entry_number = base_entry + i;
            let bat_entry = match self.bat.entry_number_to_block_id(entry_number) {
                Some((BlockType::Payload, block_number)) => {
                    let mapping = bat_state.get_payload_mapping(block_number);
                    BatEntry::new()
                        .with_state(mapping.state())
                        .with_file_offset_mb(mapping.file_megabyte() as u64)
                }
                Some((BlockType::SectorBitmap, chunk_number)) => {
                    let mapping = bat_state.get_sbm_mapping(chunk_number);
                    BatEntry::new()
                        .with_state(mapping.state())
                        .with_file_offset_mb(mapping.file_megabyte() as u64)
                }
                None => BatEntry::new(),
            };
            let offset = i as usize * size_of::<BatEntry>();
            buf[offset..offset + size_of::<BatEntry>()].copy_from_slice(bat_entry.as_bytes());
        }
        buf
    }

    /// Compute the cache [`PageKey`] for the BAT page containing the given
    /// payload block's entry.
    ///
    /// Used by the crash-consistency mechanism to attach per-page
    /// `pre_log_fsn` constraints to BAT pages during block allocation.
    pub(crate) fn bat_page_key_for_block(&self, block_number: u32) -> PageKey {
        let entry_index = self.bat.payload_entry_index(block_number);
        let page_offset = (entry_index as u64 * 8) & !(CACHE_PAGE_SIZE - 1);
        PageKey {
            tag: BAT_TAG,
            offset: page_offset,
        }
    }

    /// Write a single BAT entry to the cache page (write-through to disk).
    ///
    /// This is the primary BAT writeback mechanism, matching the C code's
    /// `UpdateBatAfterAcquire` pattern.
    ///
    /// The caller must have already updated the in-memory BAT via
    /// `BatState::set_payload_mapping()` or `set_sbm_mapping()`.
    pub(crate) async fn write_bat_entry_to_cache(
        &self,
        block_type: BlockType,
        block_number: u32,
        mapping: InternalBlockMapping,
    ) -> Result<(), VhdxError> {
        let entry_number = match block_type {
            BlockType::Payload => self.bat.payload_entry_index(block_number),
            BlockType::SectorBitmap => self.bat.sector_bitmap_entry_index(block_number),
        };
        let page_number = entry_number as u64 / ENTRIES_PER_BAT_PAGE;
        let page_offset = page_number * CACHE_PAGE_SIZE;

        // Check if the page is dirty under read lock.
        let is_dirty = {
            let state = self.bat_state.read();
            let page_idx = page_number as usize;
            page_idx < state.dirty_bat_pages.len() && state.dirty_bat_pages[page_idx]
        };

        if !is_dirty {
            // Fast path: page is NOT dirty — read existing page and update
            // just the single entry.
            let bat_entry = BatEntry::new()
                .with_state(mapping.state())
                .with_file_offset_mb(mapping.file_megabyte() as u64);

            self.bat
                .write_bat_entry(&self.cache, entry_number, bat_entry)
                .await?;
        } else {
            // Slow path: page IS dirty — rebuild the entire page from
            // in-memory state under write lock and clear dirty flag.
            let page_buf = {
                let mut state = self.bat_state.write();
                let buf = self.produce_bat_page(&state, page_number as usize);
                state.clear_dirty(page_number as usize);
                buf
            };

            let commit = {
                let mut guard = self
                    .cache
                    .acquire_write(
                        PageKey {
                            tag: BAT_TAG,
                            offset: page_offset,
                        },
                        crate::cache::WriteMode::Overwrite,
                    )
                    .await?;
                guard.copy_from_slice(&page_buf);
                guard.release()
            };
            commit.commit().await?;
        }

        Ok(())
    }

    /// Write all dirty in-memory BAT pages to disk via PageCache.
    ///
    /// Used for clean-close and batch operations. The normal write path
    /// uses per-entry cache writes instead.
    pub(crate) async fn flush_dirty_bat_pages(&self) -> Result<(), VhdxError> {
        // Under write lock: snapshot dirty pages and serialize them,
        // then clear dirty flags atomically.
        let pages_to_write: Vec<(usize, [u8; CACHE_PAGE_SIZE as usize])> = {
            let mut state = self.bat_state.write();
            let dirty_indices: Vec<usize> = state.dirty_page_indices().collect();
            let mut result = Vec::with_capacity(dirty_indices.len());
            for &page_index in &dirty_indices {
                let buf = self.produce_bat_page(&state, page_index);
                state.clear_dirty(page_index);
                result.push((page_index, buf));
            }
            result
        };

        // Write each serialized page to the cache (write-through to disk).
        // LOCK AUDIT: bat_state write-lock dropped (end of block above). No sync locks held.
        for (page_index, page_buf) in pages_to_write {
            let page_offset = page_index as u64 * CACHE_PAGE_SIZE;
            let commit = {
                let mut guard = self
                    .cache
                    .acquire_write(
                        PageKey {
                            tag: BAT_TAG,
                            offset: page_offset,
                        },
                        crate::cache::WriteMode::Overwrite,
                    )
                    .await?;
                guard.copy_from_slice(&page_buf);
                guard.release()
            };
            commit.commit().await?;
        }

        Ok(())
    }

    /// Ensures the requested write mode is enabled, updating the header
    /// and flushing if needed. If the current mode already satisfies the
    /// request, this is a no-op.
    ///
    /// The header is written to the non-current slot with new GUIDs and
    /// an incremented sequence number, then flushed to disk. Only after
    /// the flush completes is the mode committed in memory.
    pub(crate) async fn enable_write_mode(&self, mode: WriteMode) -> Result<(), VhdxError> {
        // Check if the mode is already enabled (fast path).
        let needs_update = {
            let state = self.write_state.lock();
            !matches!(state.write_mode, Some(current) if current >= mode)
        };

        if !needs_update {
            return Ok(());
        }

        // Prepare the header update under the lock, then release before I/O.
        let (header_buf, header_offset) = {
            let mut state = self.write_state.lock();

            // Double-check under lock (another caller may have raced).
            if let Some(current) = state.write_mode {
                if current >= mode {
                    return Ok(());
                }
            }

            // Always update file_write_guid (any write mode implies file modification).
            state.file_write_guid = Guid::new_random();

            // Update data_write_guid if escalating to DataWritable.
            if mode >= WriteMode::DataWritable {
                state.data_write_guid = Guid::new_random();
            }

            // Increment sequence number.
            state.sequence_number += 1;

            // Build the header.
            let mut header = Header::new_zeroed();
            header.signature = format::HEADER_SIGNATURE;
            header.sequence_number = state.sequence_number;
            header.file_write_guid = state.file_write_guid;
            header.data_write_guid = state.data_write_guid;
            header.log_guid = state.log_guid;
            header.log_version = format::LOG_VERSION;
            header.version = format::VERSION_1;
            header.log_length = self.log_length;
            header.log_offset = self.log_offset;
            header.checksum = 0;

            // Serialize to a 4 KiB buffer and compute CRC.
            let mut buf = vec![0u8; format::HEADER_SIZE as usize];
            let header_bytes = header.as_bytes();
            buf[..header_bytes.len()].copy_from_slice(header_bytes);
            let crc = format::compute_checksum(&buf, 4);
            buf[4..8].copy_from_slice(&crc.to_le_bytes());

            // Write to the non-current slot.
            let offset = if state.first_header_current {
                format::HEADER_OFFSET_2
            } else {
                format::HEADER_OFFSET_1
            };

            (buf, offset)
        };
        // LOCK AUDIT: write_state Mutex dropped here (end of block). Safe to do async I/O.

        // Write the header to disk.
        self.file.write_at(header_offset, &header_buf).await?;

        // Flush to ensure the header is on stable storage before any data writes.
        self.file.flush().await?;

        // Re-acquire lock to commit the state change.
        {
            let mut state = self.write_state.lock();
            state.first_header_current = !state.first_header_current;
            state.write_mode = Some(mode);
        }

        Ok(())
    }
}

/// Validate the file identifier signature at offset 0.
async fn validate_file_identifier(file: &impl AsyncFile) -> Result<(), VhdxError> {
    let mut buf = [0u8; size_of::<FileIdentifier>()];
    file.read_at(0, &mut buf).await?;

    let ident = FileIdentifier::read_from_bytes(&buf)
        .map_err(|_| VhdxError::Corrupt(CorruptionType::InvalidFileIdentifier))?;

    if ident.signature != format::FILE_IDENTIFIER_SIGNATURE {
        return Err(VhdxError::Corrupt(CorruptionType::InvalidFileIdentifier));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{self, CreateParams};
    use crate::format::BatEntryState;
    use crate::format::Header;
    use crate::tests::support::InMemoryFile;
    use pal_async::async_test;
    use zerocopy::IntoBytes;

    #[async_test]
    async fn open_default_vhdx() {
        let (file, params) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        assert_eq!(vhdx.disk_size(), format::GB1);
        assert_eq!(vhdx.block_size(), format::DEFAULT_BLOCK_SIZE);
        assert_eq!(vhdx.logical_sector_size(), 512);
        assert_eq!(vhdx.physical_sector_size(), 512);
        assert!(!vhdx.has_parent());
        assert!(!vhdx.is_fully_allocated());
        assert!(!vhdx.is_read_only());
        assert_ne!(vhdx.data_write_guid(), Guid::ZERO);
        assert_eq!(vhdx.data_write_guid(), params.data_write_guid);
    }

    #[async_test]
    async fn open_4k_sector_vhdx() {
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            logical_sector_size: 4096,
            physical_sector_size: 4096,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        assert_eq!(vhdx.logical_sector_size(), 4096);
        assert_eq!(vhdx.physical_sector_size(), 4096);
    }

    #[async_test]
    async fn open_512_sector_vhdx() {
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            logical_sector_size: 512,
            physical_sector_size: 512,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        assert_eq!(vhdx.logical_sector_size(), 512);
        assert_eq!(vhdx.physical_sector_size(), 512);
    }

    #[async_test]
    async fn open_various_block_sizes() {
        for &block_size in &[
            MB1 as u32,
            2 * MB1 as u32,
            32 * MB1 as u32,
            256 * MB1 as u32,
        ] {
            let file = InMemoryFile::new(0);
            let mut params = CreateParams {
                disk_size: format::GB1,
                block_size,
                ..Default::default()
            };
            create::create(&file, &mut params).await.unwrap();

            let vhdx = VhdxFile::open(file, false).await.unwrap();
            assert_eq!(vhdx.block_size(), block_size);
        }
    }

    #[async_test]
    async fn open_differencing_disk() {
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            has_parent: true,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        assert!(vhdx.has_parent());
    }

    #[async_test]
    async fn open_fully_allocated() {
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            is_fully_allocated: true,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        assert!(vhdx.is_fully_allocated());
    }

    #[async_test]
    async fn open_dirty_log_no_valid_entries() {
        // Setting log_guid to a random GUID without writing matching log
        // entries causes replay_log to return NoValidLogEntries.
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;

        // Overwrite header 2's log_guid with a non-zero GUID, then fix the CRC.
        let mut buf = vec![0u8; format::HEADER_SIZE as usize];
        file.read_at(format::HEADER_OFFSET_2, &mut buf)
            .await
            .unwrap();

        let mut header = Header::read_from_prefix(&buf).unwrap().0.clone();
        header.log_guid = Guid::new_random();
        header.checksum = 0;

        let header_bytes = header.as_bytes();
        buf[..header_bytes.len()].copy_from_slice(header_bytes);
        let crc = format::compute_checksum(&buf, 4);
        buf[4..8].copy_from_slice(&crc.to_le_bytes());
        file.write_at(format::HEADER_OFFSET_2, &buf).await.unwrap();

        let result = VhdxFile::open(file, false).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::NoValidLogEntries))
        ));
    }

    #[async_test]
    async fn open_invalid_file_identifier() {
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;

        // Corrupt the file identifier signature.
        file.write_at(0, b"BADMAGIC").await.unwrap();

        let result = VhdxFile::open(file, false).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::InvalidFileIdentifier))
        ));
    }

    #[async_test]
    async fn open_empty_file() {
        // File smaller than HEADER_AREA_SIZE (1 MiB).
        let file = InMemoryFile::new(512);
        let result = VhdxFile::open(file, false).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::EmptyFile))
        ));
    }

    #[async_test]
    async fn open_bat_block_lookup() {
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        // A newly created dynamic disk has all blocks as NotPresent.
        let mapping = vhdx.get_block_mapping(0);
        assert_eq!(mapping.state, BatEntryState::NotPresent);
        assert_eq!(mapping.file_offset, 0);
    }

    #[async_test]
    async fn open_bat_all_blocks_default() {
        let disk_size = 4 * MB1; // Small disk → 2 blocks.
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let block_count = (disk_size / vhdx.block_size() as u64) as u32;

        for block in 0..block_count {
            let mapping = vhdx.get_block_mapping(block);
            assert_eq!(mapping.state, BatEntryState::NotPresent);
            assert_eq!(mapping.file_offset, 0);
        }
    }

    #[async_test]
    async fn open_read_only_flag() {
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, true).await.unwrap();
        assert!(vhdx.is_read_only());
    }

    #[async_test]
    async fn open_populates_in_memory_bat() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();

        let bat_state = vhdx.bat_state.read();
        // All payload entries should be NotPresent.
        for (i, mapping) in bat_state.payload_mappings.iter().enumerate() {
            assert_eq!(
                mapping.state(),
                BatEntryState::NotPresent as u8,
                "block {i} should be NotPresent"
            );
        }
        assert_eq!(bat_state.allocated_block_count, 0);
        assert_eq!(
            bat_state.payload_mappings.len(),
            vhdx.bat.data_block_count as usize
        );
        assert_eq!(
            bat_state.sector_bitmap_mappings.len(),
            vhdx.bat.sector_bitmap_block_count as usize
        );
    }

    #[async_test]
    async fn open_with_allocated_blocks() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = parse_region_tables(&file).await.unwrap();

        // Manually write a FullyPresent BAT entry for block 0 at offset 4 MB
        // (just after the metadata region, within the file).
        // First extend the file to cover the block (4 MB offset + 2 MB block = 6 MB).
        file.set_file_size(6 * MB1).await.unwrap();

        let entry = BatEntry::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_offset_mb(4);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let bat_state = vhdx.bat_state.read();
        assert_eq!(
            bat_state.payload_mappings[0].state(),
            BatEntryState::FullyPresent as u8,
        );
        assert_eq!(bat_state.payload_mappings[0].file_megabyte(), 4);
        assert_eq!(bat_state.allocated_block_count, 1);
    }

    #[async_test]
    async fn bat_lookup_is_synchronous() {
        // Compile-time verification: get_block_mapping() is a regular fn,
        // not an async fn. We call it without .await.
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let mapping: BlockMapping = vhdx.get_block_mapping(0);
        assert_eq!(mapping.state, BatEntryState::NotPresent);
    }

    #[async_test]
    async fn eof_counter_no_overlap() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let a = vhdx.allocate_space(MB1 as u32, false).await.unwrap();
        let b = vhdx.allocate_space(MB1 as u32, false).await.unwrap();
        // Two allocations must not overlap.
        assert_ne!(a.file_offset, b.file_offset);
        assert!(b.file_offset >= a.file_offset + MB1);
    }

    #[async_test]
    async fn eof_counter_mb_aligned() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, false).await.unwrap();
        let result = vhdx.allocate_space(MB1 as u32, false).await.unwrap();
        assert_eq!(result.file_offset % MB1, 0, "offset must be MB1-aligned");
    }

    #[async_test]
    async fn open_with_allocated_blocks_inits_space() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let regions = parse_region_tables(&file).await.unwrap();

        // Extend file to 8 MB then write a FullyPresent BAT entry at offset 4 MB.
        file.set_file_size(8 * MB1).await.unwrap();

        let entry = BatEntry::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_offset_mb(4);
        file.write_at(regions.bat_offset, entry.as_bytes())
            .await
            .unwrap();

        let vhdx = VhdxFile::open(file, false).await.unwrap();

        // The free space tracker should have offset 4*MB marked as in-use.
        assert!(vhdx.free_space.is_range_in_use(4 * MB1, vhdx.block_size()));
    }

    #[async_test]
    async fn non_differencing_no_locator() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file, true).await.unwrap();
        assert!(!vhdx.has_parent());
        assert!(vhdx.parent_locator().await.unwrap().is_none());
    }

    /// Helper: inject a parent locator metadata entry and blob into a diff disk.
    ///
    /// Reads the existing metadata table, appends a new entry for the parent
    /// locator GUID, writes the locator blob at the entry's data offset, and
    /// updates the metadata table header's entry count.
    async fn inject_parent_locator(file: &InMemoryFile, locator_blob: &[u8]) {
        use crate::format::{MetadataTableEntry, MetadataTableEntryFlags, MetadataTableHeader};
        use zerocopy::{FromBytes, IntoBytes};

        let regions = parse_region_tables(file).await.unwrap();

        // Read the full metadata table (first 64 KiB of metadata region).
        let mut table_buf = vec![0u8; format::METADATA_TABLE_SIZE as usize];
        file.read_at(regions.metadata_offset, &mut table_buf)
            .await
            .unwrap();

        // Parse header to get current entry count.
        let mut header = MetadataTableHeader::read_from_prefix(&table_buf)
            .unwrap()
            .0
            .clone();
        let old_count = header.entry_count as usize;
        let entry_size = size_of::<MetadataTableEntry>();
        let header_size = size_of::<MetadataTableHeader>();

        // Find the max data offset used by existing entries to place our blob after them.
        let mut max_data_end: u32 = format::METADATA_TABLE_SIZE as u32;
        for i in 0..old_count {
            let off = header_size + i * entry_size;
            let entry = MetadataTableEntry::read_from_prefix(&table_buf[off..])
                .unwrap()
                .0
                .clone();
            if entry.length > 0 {
                let end = entry.offset + entry.length;
                if end > max_data_end {
                    max_data_end = end;
                }
            }
        }

        // Place the parent locator blob right after existing data.
        let locator_offset = max_data_end;

        // Write the new entry.
        let new_entry = MetadataTableEntry {
            item_id: format::PARENT_LOCATOR_ITEM_GUID,
            offset: locator_offset,
            length: locator_blob.len() as u32,
            flags: MetadataTableEntryFlags::new().with_is_required(true),
            reserved2: 0,
        };
        let new_entry_file_offset = header_size + old_count * entry_size;
        let e_bytes = new_entry.as_bytes();
        table_buf[new_entry_file_offset..new_entry_file_offset + e_bytes.len()]
            .copy_from_slice(e_bytes);

        // Update header entry count.
        header.entry_count = (old_count + 1) as u16;
        let h_bytes = header.as_bytes();
        table_buf[..h_bytes.len()].copy_from_slice(h_bytes);

        // Write back the metadata table.
        file.write_at(regions.metadata_offset, &table_buf)
            .await
            .unwrap();

        // Write the locator blob into the metadata region data area.
        file.write_at(
            regions.metadata_offset + locator_offset as u64,
            locator_blob,
        )
        .await
        .unwrap();
    }

    #[async_test]
    async fn differencing_has_locator() {
        use crate::locator;

        // Create a differencing disk.
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            has_parent: true,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();

        // Build a parent locator blob and inject it into the metadata region.
        let locator_blob = locator::build_locator(
            format::PARENT_LOCATOR_VHDX_TYPE_GUID,
            &[
                ("parent_linkage", "{some-guid}"),
                ("relative_path", ".\\parent.vhdx"),
                ("absolute_win32_path", "C:\\VMs\\parent.vhdx"),
            ],
        );
        inject_parent_locator(&file, &locator_blob).await;

        // Open and verify.
        let vhdx = VhdxFile::open(file, true).await.unwrap();
        assert!(vhdx.has_parent());

        let loc = vhdx
            .parent_locator()
            .await
            .unwrap()
            .expect("should have locator");
        assert_eq!(loc.locator_type, format::PARENT_LOCATOR_VHDX_TYPE_GUID);
        assert_eq!(loc.find("parent_linkage"), Some("{some-guid}"));
        assert_eq!(loc.find("relative_path"), Some(".\\parent.vhdx"));
        assert_eq!(
            loc.find("absolute_win32_path"),
            Some("C:\\VMs\\parent.vhdx")
        );
    }

    #[async_test]
    async fn parent_paths_extraction() {
        use crate::locator;

        // Create a differencing disk with a parent locator.
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            has_parent: true,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();

        let locator_blob = locator::build_locator(
            format::PARENT_LOCATOR_VHDX_TYPE_GUID,
            &[
                ("parent_linkage", "{some-guid}"),
                ("relative_path", ".\\parent.vhdx"),
                ("absolute_win32_path", "C:\\VMs\\parent.vhdx"),
            ],
        );
        inject_parent_locator(&file, &locator_blob).await;

        let vhdx = VhdxFile::open(file, true).await.unwrap();
        let loc = vhdx
            .parent_locator()
            .await
            .unwrap()
            .expect("should have locator");
        let paths = loc.parent_paths();
        assert_eq!(paths.parent_linkage.as_deref(), Some("{some-guid}"));
        assert_eq!(paths.relative_path.as_deref(), Some(".\\parent.vhdx"));
        assert_eq!(
            paths.absolute_win32_path.as_deref(),
            Some("C:\\VMs\\parent.vhdx")
        );
        assert!(paths.volume_path.is_none());
    }

    #[async_test]
    async fn differencing_missing_locator_errors() {
        // Create a diff disk but don't write any locator data.
        // create() doesn't add a parent locator entry, so read_item() will
        // return MissingRequiredMetadata.
        let file = InMemoryFile::new(0);
        let mut params = CreateParams {
            disk_size: format::GB1,
            has_parent: true,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();

        let vhdx = VhdxFile::open(file, true).await.unwrap();
        assert!(vhdx.has_parent());
        let result = vhdx.parent_locator().await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Log replay integration tests
    // -----------------------------------------------------------------------

    /// Inject a dirty log into a VHDX file:
    /// 1. Write log entries using LogWriter
    /// 2. Set the header's log_guid to match
    /// 3. Update header CRC
    ///
    /// Returns the log_guid used.
    async fn inject_dirty_log(
        file: &InMemoryFile,
        data_pages: &[log::DataPage<'_>],
        zero_ranges: &[log::ZeroRange],
    ) -> Guid {
        // Read the active header (header 2, sequence_number=1 after create).
        let mut hdr_buf = vec![0u8; format::HEADER_SIZE as usize];
        file.read_at(format::HEADER_OFFSET_2, &mut hdr_buf)
            .await
            .unwrap();
        let header = Header::read_from_prefix(&hdr_buf).unwrap().0.clone();

        let log_guid = Guid::new_random();
        let log_region = LogRegion {
            file_offset: header.log_offset,
            length: header.log_length,
        };

        // Initialize a LogWriter and write the entry.
        let file_size = file.file_size().await.unwrap();
        let mut writer = log::LogWriter::initialize(file, log_region, log_guid, file_size)
            .await
            .unwrap();

        if !data_pages.is_empty() || !zero_ranges.is_empty() {
            writer
                .write_entry(file, data_pages, zero_ranges)
                .await
                .unwrap();
        }

        // Set log_guid in a new header with bumped sequence number.
        // Write to header 1 (the non-current slot) with a higher sequence
        // number so it becomes the active header.
        let mut header_copy = header;
        header_copy.log_guid = log_guid;
        header_copy.sequence_number += 1;
        header_copy.checksum = 0;

        let mut buf = vec![0u8; format::HEADER_SIZE as usize];
        let hdr_bytes = header_copy.as_bytes();
        buf[..hdr_bytes.len()].copy_from_slice(hdr_bytes);
        let crc = format::compute_checksum(&buf, 4);
        buf[4..8].copy_from_slice(&crc.to_le_bytes());

        // Write to header 1 (which now has a higher seq, becoming active).
        file.write_at(format::HEADER_OFFSET_1, &buf).await.unwrap();

        log_guid
    }

    #[async_test]
    async fn open_replays_dirty_log_data() {
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;

        // Pick a target offset >= LOGABLE_OFFSET (192 KiB = region table offset).
        // Use 320 KiB (= 5 * 64 KiB) to be past both region tables.
        let target_offset: u64 = 5 * format::KB64;

        // Build a recognizable data pattern.
        let pattern = [0xABu8; 4096];
        let data_page = log::DataPage {
            file_offset: target_offset,
            data: &pattern,
        };

        inject_dirty_log(&file, &[data_page], &[]).await;

        // Open should replay the log and succeed.
        let vhdx = VhdxFile::open(file, false).await.unwrap();
        assert_eq!(vhdx.disk_size(), format::GB1);

        // Verify the data pattern was written at the target offset via the
        // Arc<InMemoryFile> inside the VhdxFile.
        let mut readback = [0u8; 4096];
        vhdx.file
            .read_at(target_offset, &mut readback)
            .await
            .unwrap();
        assert_eq!(readback, pattern);
    }

    #[async_test]
    async fn open_replays_dirty_log_zeros() {
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;

        // Write non-zero data at a target offset first.
        let target_offset: u64 = 5 * format::KB64;
        let non_zero = [0xFFu8; 4096];
        file.write_at(target_offset, &non_zero).await.unwrap();

        // Inject a dirty log with a zero descriptor targeting that offset.
        let zero_range = log::ZeroRange {
            file_offset: target_offset,
            length: 4096,
        };

        inject_dirty_log(&file, &[], &[zero_range]).await;

        // Open should replay the log and succeed.
        let vhdx = VhdxFile::open(file, false).await.unwrap();
        assert_eq!(vhdx.disk_size(), format::GB1);

        // Verify the range is now zeroed.
        let mut readback = [0u8; 4096];
        vhdx.file
            .read_at(target_offset, &mut readback)
            .await
            .unwrap();
        assert_eq!(readback, [0u8; 4096]);
    }

    #[async_test]
    async fn open_replay_then_reopen_clean() {
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;

        let target_offset: u64 = 5 * format::KB64;
        let pattern = [0xCDu8; 4096];
        let data_page = log::DataPage {
            file_offset: target_offset,
            data: &pattern,
        };

        inject_dirty_log(&file, &[data_page], &[]).await;

        // First open triggers replay.
        let vhdx = VhdxFile::open(file, false).await.unwrap();
        // The clean header was written to the file inside vhdx.
        // Make a snapshot of the replayed file for the second open.
        let snapshot = vhdx.file.snapshot();
        drop(vhdx);

        // Create a new InMemoryFile from the snapshot for the second open.
        let file3 = InMemoryFile::from_snapshot(snapshot);

        // Second open should succeed without replay (log_guid is now ZERO).
        let vhdx2 = VhdxFile::open(file3, false).await.unwrap();
        assert_eq!(vhdx2.disk_size(), format::GB1);
    }

    #[async_test]
    async fn open_replay_corrupt_log_entry() {
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;

        let target_offset: u64 = 5 * format::KB64;
        let pattern = [0xEEu8; 4096];
        let data_page = log::DataPage {
            file_offset: target_offset,
            data: &pattern,
        };

        let _log_guid = inject_dirty_log(&file, &[data_page], &[]).await;

        // Read the active header to find the log region offset.
        let mut hdr_buf = vec![0u8; format::HEADER_SIZE as usize];
        file.read_at(format::HEADER_OFFSET_1, &mut hdr_buf)
            .await
            .unwrap();
        let header = Header::read_from_prefix(&hdr_buf).unwrap().0.clone();

        // Corrupt the first byte of the log region (flip a byte in the CRC
        // of the log entry).
        let mut corrupt_buf = [0u8; 1];
        file.read_at(header.log_offset + 4, &mut corrupt_buf)
            .await
            .unwrap();
        corrupt_buf[0] ^= 0xFF;
        file.write_at(header.log_offset + 4, &corrupt_buf)
            .await
            .unwrap();

        // Open should fail because there are no valid log entries for this GUID.
        let result = VhdxFile::open(file, false).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::NoValidLogEntries))
        ));
    }

    #[async_test]
    async fn open_read_only_dirty_log_rejected() {
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;

        let target_offset: u64 = 5 * format::KB64;
        let pattern = [0xBBu8; 4096];
        let data_page = log::DataPage {
            file_offset: target_offset,
            data: &pattern,
        };

        inject_dirty_log(&file, &[data_page], &[]).await;

        // Read-only open with a dirty log should return LogReplayRequired.
        let result = VhdxFile::open(file, true).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::LogReplayRequired))
        ));
    }
}
