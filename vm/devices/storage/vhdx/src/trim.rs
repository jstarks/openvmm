// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VHDX block trim (unmap) support.
//!
//! Implements the `VhdxFile::trim()` method that transitions blocks to
//! unmapped states, releasing file space back to the free pool or
//! soft-anchoring it for later reuse. This module ports the C code's
//! `Vhd2iIssueBlockTrim` / `Vhd2iContinueBlockTrim` logic.

use crate::AsyncFile;
use crate::bat::BlockType;
use crate::bat::InternalBlockMapping;
use crate::error::CorruptionType;
use crate::error::VhdxError;
use crate::format::BatEntryState;
use crate::format::MB1;
use crate::open::VhdxFile;
use crate::open::WriteMode;

/// Trim mode determining the target block state.
///
/// Maps to `VHD2_TRIM_MODE` in vhd2.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrimMode {
    /// Move blocks to the Unmapped (trimmed) state, keeping file offset
    /// as a soft anchor for potential reuse. Maps to `Vhd2TrimModeFileSpace`.
    ///
    /// Denied for Undefined blocks: a block that was never written
    /// should stay Undefined (preserves backup semantics — backup tools
    /// skip Undefined blocks, but not Unmapped ones).
    FileSpace,

    /// Move blocks to the Undefined state. Soft anchor may be kept or
    /// cleared depending on the original state. Maps to `Vhd2TrimModeFreeSpace`.
    FreeSpace,

    /// Move blocks to the Zero state, clearing the file offset.
    /// Maps to `Vhd2TrimModeZero`.
    Zero,

    /// Move blocks to the NotPresent (transparent) state, clearing the
    /// file offset. For differencing disks, reads fall through to parent.
    /// Maps to `Vhd2TrimModeMakeTransparent`.
    ///
    /// Allowed on fully-allocated (fixed) disks.
    MakeTransparent,

    /// Remove soft anchors from trimmed/undefined blocks without changing
    /// their state. Clears file_megabyte if the block is soft-anchored.
    /// Maps to `Vhd2TrimModeRemoveSoftAnchors`.
    ///
    /// Allowed on fully-allocated (fixed) disks. Does not change data
    /// content, so DataWriteGuid is not updated.
    RemoveSoftAnchors,
}

/// Builder for a trim operation on a VHDX file.
///
/// Created via [`VhdxFile::trim`]. Required parameters (`mode`, `offset`,
/// `length`) are provided at construction; optional flags default to the
/// safe/common values and can be overridden with builder methods.
#[derive(Debug, Clone)]
pub struct TrimRequest {
    mode: TrimMode,
    offset: u64,
    length: u64,
    skip_disk_size_check: bool,
    skip_write_guid_change: bool,
}

impl TrimRequest {
    /// Create a new trim request.
    ///
    /// * `mode` - Determines the target block state.
    /// * `offset` - Virtual disk byte offset (must be sector-aligned).
    /// * `length` - Length in bytes (must be sector-aligned).
    pub fn new(mode: TrimMode, offset: u64, length: u64) -> Self {
        Self {
            mode,
            offset,
            length,
            skip_disk_size_check: false,
            skip_write_guid_change: false,
        }
    }

    /// Skip bounds checking against the virtual disk size.
    pub fn skip_disk_size_check(mut self, skip: bool) -> Self {
        self.skip_disk_size_check = skip;
        self
    }

    /// Don't update DataWriteGuid when trimming.
    pub fn skip_write_guid_change(mut self, skip: bool) -> Self {
        self.skip_write_guid_change = skip;
        self
    }
}

/// Returns true if the given trim mode is allowed on fully-allocated (fixed) disks.
fn mode_allowed_on_fixed(mode: TrimMode) -> bool {
    matches!(
        mode,
        TrimMode::MakeTransparent | TrimMode::RemoveSoftAnchors
    )
}

/// Returns true if this trim mode should skip the DataWriteGuid update.
fn mode_skips_write_guid(mode: TrimMode) -> bool {
    matches!(mode, TrimMode::RemoveSoftAnchors)
}

/// Check whether a block mapping is soft-anchored: unmapped/undefined
/// with a non-zero file offset.
pub(crate) fn is_soft_anchored(mapping: InternalBlockMapping) -> bool {
    let state = BatEntryState::from_raw(mapping.state());
    matches!(
        state,
        Some(BatEntryState::Unmapped) | Some(BatEntryState::Undefined)
    ) && mapping.file_megabyte() != 0
}

/// Convert a block mapping according to the trim mode.
///
/// Returns the new mapping, which may be identical to `old` (no-op).
fn convert_mapping(mode: TrimMode, old: InternalBlockMapping) -> InternalBlockMapping {
    let state = BatEntryState::from_raw(old.state());
    match mode {
        TrimMode::FileSpace => convert_file_space(state, old),
        TrimMode::FreeSpace => convert_free_space(state, old),
        TrimMode::Zero => convert_zero(state, old),
        TrimMode::MakeTransparent => convert_make_transparent(state, old),
        TrimMode::RemoveSoftAnchors => convert_remove_soft_anchors(old),
    }
}

/// FileSpace: FullyPresent/PartiallyPresent → Unmapped (keep soft anchor).
/// All other states are no-ops.
fn convert_file_space(
    state: Option<BatEntryState>,
    old: InternalBlockMapping,
) -> InternalBlockMapping {
    match state {
        Some(BatEntryState::FullyPresent) | Some(BatEntryState::PartiallyPresent) => {
            InternalBlockMapping::new()
                .with_state(BatEntryState::Unmapped as u8)
                .with_transitioning_to_fully_present(false)
                .with_file_megabyte(old.file_megabyte()) // keep as soft anchor
        }
        _ => old, // NotPresent, Undefined, Zero, Unmapped → no change
    }
}

/// FreeSpace: FullyPresent/PartiallyPresent → Undefined (clear offset, release space).
/// Zero → Undefined (clear offset).
/// Unmapped → Undefined (keep soft anchor).
/// Others → no change.
fn convert_free_space(
    state: Option<BatEntryState>,
    old: InternalBlockMapping,
) -> InternalBlockMapping {
    match state {
        Some(BatEntryState::FullyPresent) | Some(BatEntryState::PartiallyPresent) => {
            // Release space — clear file offset.
            InternalBlockMapping::new()
                .with_state(BatEntryState::Undefined as u8)
                .with_transitioning_to_fully_present(false)
                .with_file_megabyte(0)
        }
        Some(BatEntryState::Zero) => InternalBlockMapping::new()
            .with_state(BatEntryState::Undefined as u8)
            .with_transitioning_to_fully_present(false)
            .with_file_megabyte(0),
        Some(BatEntryState::Unmapped) => {
            // Keep soft anchor if present.
            InternalBlockMapping::new()
                .with_state(BatEntryState::Undefined as u8)
                .with_transitioning_to_fully_present(false)
                .with_file_megabyte(old.file_megabyte())
        }
        _ => old, // NotPresent, Undefined → no change
    }
}

/// Zero: any state → Zero (clear file offset).
fn convert_zero(state: Option<BatEntryState>, old: InternalBlockMapping) -> InternalBlockMapping {
    match state {
        Some(BatEntryState::Zero) if old.file_megabyte() == 0 => old, // already Zero with no offset
        _ => {
            debug_assert!(
                !old.transitioning_to_fully_present(),
                "cannot trim TFP block to Zero"
            );
            InternalBlockMapping::new()
                .with_state(BatEntryState::Zero as u8)
                .with_transitioning_to_fully_present(false)
                .with_file_megabyte(0)
        }
    }
}

/// MakeTransparent: any state → NotPresent (clear file offset).
fn convert_make_transparent(
    state: Option<BatEntryState>,
    old: InternalBlockMapping,
) -> InternalBlockMapping {
    match state {
        Some(BatEntryState::NotPresent) if old.file_megabyte() == 0 => old, // already NotPresent
        _ => InternalBlockMapping::new()
            .with_state(BatEntryState::NotPresent as u8)
            .with_transitioning_to_fully_present(false)
            .with_file_megabyte(0),
    }
}

/// RemoveSoftAnchors: clear file offset if soft-anchored, otherwise no-op.
fn convert_remove_soft_anchors(old: InternalBlockMapping) -> InternalBlockMapping {
    if is_soft_anchored(old) {
        InternalBlockMapping::new()
            .with_state(old.state())
            .with_transitioning_to_fully_present(false)
            .with_file_megabyte(0)
    } else {
        old
    }
}

/// Compute the block range fully included in a byte range.
///
/// Returns `(start_block, block_count)`. Only blocks whose entire extent
/// falls within `[offset..offset+length)` are included. Leading and
/// trailing partial blocks are skipped.
///
/// Maps to `Vhd2iIncludedBlocks` in block.c.
fn included_blocks(offset: u64, length: u64, block_size: u64) -> (u32, u32) {
    if length == 0 {
        return (0, 0);
    }
    // First fully-included block: round UP to next block boundary.
    let start = offset.div_ceil(block_size) as u32;
    // First block NOT included: round DOWN.
    let end = ((offset + length) / block_size) as u32;
    if end <= start {
        (start, 0)
    } else {
        (start, end - start)
    }
}

impl<F: AsyncFile> VhdxFile<F> {
    /// Trim (unmap) a range of virtual disk blocks.
    ///
    /// Transitions blocks to unmapped/zero/transparent state depending on
    /// the mode specified in `request`. Only blocks fully covered by the
    /// range are trimmed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file is read-only
    /// - Offset or length is not aligned to the logical sector size
    /// - The range extends beyond the disk size (unless `skip_disk_size_check`)
    /// - The file is in a permanently failed state
    pub async fn trim(&self, request: TrimRequest) -> Result<(), VhdxError> {
        self.failed.check()?;

        let TrimRequest {
            mode,
            offset,
            length,
            skip_disk_size_check,
            skip_write_guid_change,
        } = request;

        // 1. Check read-only.
        if self.read_only {
            return Err(VhdxError::ReadOnly);
        }

        // 2. Zero-length — immediate success.
        if length == 0 {
            return Ok(());
        }

        // 3. Validate alignment to logical sector size.
        if !offset.is_multiple_of(self.logical_sector_size as u64)
            || !length.is_multiple_of(self.logical_sector_size as u64)
        {
            return Err(VhdxError::Corrupt(CorruptionType::UnalignedIo));
        }

        // 4. Validate bounds (unless skipped).
        if !skip_disk_size_check {
            if offset
                .checked_add(length)
                .is_none_or(|end| end > self.disk_size)
            {
                return Err(VhdxError::Corrupt(CorruptionType::ReadBeyondEndOfDisk));
            }
        }

        // 5. If fully-allocated (fixed) disk and mode doesn't allow it: no-op.
        if self.is_fully_allocated() && !mode_allowed_on_fixed(mode) {
            return Ok(());
        }

        // 6. Enable write mode.
        // All trim modes modify the file (BAT entries), so FileWritable
        // is always needed. DataWritable is additionally needed when the
        // mode changes user-visible data (everything except
        // RemoveSoftAnchors) and the caller hasn't opted out.
        if !skip_write_guid_change && !mode_skips_write_guid(mode) {
            self.enable_write_mode(WriteMode::DataWritable).await?;
        } else {
            self.enable_write_mode(WriteMode::FileWritable).await?;
        }

        // 7. Compute effective length: if trim extends to exactly disk_size,
        //    round up to cover the full last block.
        let effective_length = if !skip_disk_size_check && offset + length == self.disk_size {
            let block_size = self.block_size as u64;
            let full_disk_size = crate::create::round_up(self.disk_size, block_size);
            full_disk_size - offset
        } else {
            length
        };

        // 8. Compute included blocks.
        let (start_block, block_count) =
            included_blocks(offset, effective_length, self.block_size as u64);
        if block_count == 0 {
            return Ok(());
        }
        let end_block = start_block + block_count;

        // 9. Main trim loop.
        //
        // For each block, we atomically claim it (CAS 0 → SENTINEL),
        // preventing any new I/O from reading stale mappings. Then we
        // read + convert the mapping, write the BAT, handle space
        // management, and release the claim.
        let mut current_block = start_block;
        loop {
            if current_block >= end_block {
                return Ok(());
            }

            // 9a. Claim the block: CAS refcount 0 → TRIM_SENTINEL.
            //     If I/O is active (refcount > 0), wait for it to drain.
            let claim = self.bat.claim_for_trim(current_block).await;

            // 9b. Block is claimed — no new I/O can start on it.
            //     Read the mapping and compute the trim conversion.
            let (old_mapping, new_mapping) = {
                let bat_state = self.bat.bat_state.read();
                let old = bat_state.get_payload_mapping(current_block);
                let new = convert_mapping(mode, old);
                (old, new)
            };

            if old_mapping == new_mapping {
                // No-op — release claim and advance.
                current_block += 1;
                continue;
            }

            // 9c. Update in-memory BAT under write lock.
            {
                let mut bat_state = self.bat.bat_state.write();
                bat_state.set_payload_mapping(&self.bat, current_block, new_mapping);
            }

            // 9d. Write BAT entry to cache (async).
            // LOCK AUDIT: bat_state write-lock dropped. Trim claim held (not a sync lock). Safe to await.
            self.bat
                .write_block_mapping(
                    &self.cache,
                    BlockType::Payload,
                    current_block,
                    new_mapping,
                    None,
                )
                .await?;

            // 9e. Handle space management based on old→new transition.
            //
            // Space releases are deferred until the BAT change is durable
            // on disk. Without deferral, a crash could teleport data from
            // a new block into the old block's offset.
            let old_anchored = is_soft_anchored(old_mapping);
            let new_anchored = is_soft_anchored(new_mapping);
            let old_file_mb = old_mapping.file_megabyte();
            let new_file_mb = new_mapping.file_megabyte();
            let old_file_offset = old_file_mb as u64 * MB1;
            let block_size = self.block_size;

            if old_anchored && new_anchored {
                // Same anchor — assert same file offset, no space management.
                debug_assert_eq!(old_file_mb, new_file_mb);
            } else if old_anchored && !new_anchored {
                // Was soft-anchored → no longer: unmark/cancel + defer release.
                let was_deferred = self.deferred_releases.cancel(current_block);
                if !was_deferred {
                    self.free_space.unmark_trimmed_block(
                        current_block,
                        old_file_offset,
                        block_size,
                    )?;
                }
                self.deferred_releases
                    .insert(current_block, old_file_offset, block_size, false);
            } else if !old_anchored && new_anchored {
                // Was not anchored → now soft-anchored: defer the anchor.
                self.deferred_releases
                    .insert(current_block, old_file_offset, block_size, true);
            } else {
                // Neither was nor becomes anchored.
                if old_file_mb != 0 {
                    self.deferred_releases.insert(
                        current_block,
                        old_file_offset,
                        block_size,
                        false,
                    );
                }
            }

            // 9f. Release the trim claim — I/O can resume on this block.
            drop(claim);

            // Quota check: force flush if too many deferred releases.
            if self.deferred_releases.needs_flush() {
                self.flush().await?;
            }

            current_block += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{self, CreateParams};
    use crate::format;
    use crate::io::ReadRange;
    use crate::open::VhdxFile;
    use crate::tests::support::InMemoryFile;
    use pal_async::DefaultDriver;
    use pal_async::async_test;

    /// Helper to create a disk and write a full block, returning the VhdxFile.
    async fn create_and_write_block(
        disk_size: u64,
        block_number: u32,
        driver: &DefaultDriver,
    ) -> VhdxFile<InMemoryFile> {
        let (file, _) = InMemoryFile::create_test_vhdx(disk_size).await;
        let vhdx = VhdxFile::open(file).writable(driver).await.unwrap();
        let block_offset = block_number as u64 * vhdx.block_size() as u64;
        let block_size = vhdx.block_size();

        // Write a full block of data.
        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(block_offset, block_size, &mut ranges)
            .await
            .unwrap();

        // Perform the writes (we don't actually need to write data for BAT testing).
        for range in &ranges {
            match range {
                crate::io::WriteRange::Data {
                    file_offset,
                    length,
                    ..
                } => {
                    let buf = vec![0xAA; *length as usize];
                    vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                }
                crate::io::WriteRange::Zero {
                    file_offset,
                    length,
                } => {
                    let buf = vec![0u8; *length as usize];
                    vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                }
            }
        }
        guard.complete().await.unwrap();
        vhdx
    }

    /// Helper to verify a block's BAT state.
    fn assert_block_state(
        vhdx: &VhdxFile<InMemoryFile>,
        block_number: u32,
        expected: BatEntryState,
    ) {
        let bat_state = vhdx.bat.bat_state.read();
        let mapping = bat_state.get_payload_mapping(block_number);
        let actual = BatEntryState::from_raw(mapping.state()).unwrap();
        assert_eq!(
            actual, expected,
            "block {block_number}: expected {expected:?}, got {actual:?}"
        );
    }

    /// Helper to check if a block has a non-zero file megabyte (soft anchor).
    fn block_has_file_offset(vhdx: &VhdxFile<InMemoryFile>, block_number: u32) -> bool {
        let bat_state = vhdx.bat.bat_state.read();
        let mapping = bat_state.get_payload_mapping(block_number);
        mapping.file_megabyte() != 0
    }

    // ---- included_blocks unit tests ----

    #[test]
    fn included_blocks_full_coverage() {
        // Range exactly covers blocks 0..3 (3 blocks).
        let block_size = 2 * MB1;
        let (start, count) = included_blocks(0, 3 * block_size, block_size);
        assert_eq!(start, 0);
        assert_eq!(count, 3);
    }

    #[test]
    fn included_blocks_partial_edges() {
        // Start mid-block-0, end mid-block-2 → only block 1 included.
        let block_size = 2 * MB1;
        let (start, count) = included_blocks(MB1, 2 * block_size, block_size);
        assert_eq!(start, 1); // block 0 is partial
        assert_eq!(count, 1); // only block 1 fully covered
    }

    #[test]
    fn included_blocks_zero_length() {
        let (start, count) = included_blocks(0, 0, 2 * MB1);
        assert_eq!(start, 0);
        assert_eq!(count, 0);
    }

    #[test]
    fn included_blocks_too_small() {
        // Range is less than one block → no blocks included.
        let block_size = 2 * MB1;
        let (_start, count) = included_blocks(MB1, MB1, block_size);
        assert_eq!(count, 0);
    }

    // ---- Basic Trim Tests ----

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
        // Soft anchor preserved.
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
        // FreeSpace on FullyPresent clears file offset (releases space).
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

        // First trim with FileSpace to create a soft anchor.
        vhdx.trim(TrimRequest::new(
            TrimMode::FileSpace,
            0,
            vhdx.block_size() as u64,
        ))
        .await
        .unwrap();
        assert_block_state(&vhdx, 0, BatEntryState::Unmapped);
        assert!(block_has_file_offset(&vhdx, 0));

        // Now remove the soft anchor.
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

        // Second trim with FileSpace → no-op.
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

        // Block 0 starts as NotPresent on a fresh non-differencing disk.
        assert_block_state(&vhdx, 0, BatEntryState::NotPresent);

        vhdx.trim(TrimRequest::new(
            TrimMode::FileSpace,
            0,
            vhdx.block_size() as u64,
        ))
        .await
        .unwrap();

        // FileSpace is a no-op for NotPresent → should still be NotPresent.
        assert_block_state(&vhdx, 0, BatEntryState::NotPresent);
    }

    #[async_test]
    async fn trim_zero_block_noop(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

        // First: write and trim to Zero to get a Zero block.
        let block_size = vhdx.block_size();
        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(0, block_size, &mut ranges)
            .await
            .unwrap();
        for range in &ranges {
            match range {
                crate::io::WriteRange::Data {
                    file_offset,
                    length,
                    ..
                } => {
                    let buf = vec![0u8; *length as usize];
                    vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                }
                crate::io::WriteRange::Zero {
                    file_offset,
                    length,
                } => {
                    let buf = vec![0u8; *length as usize];
                    vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                }
            }
        }
        guard.complete().await.unwrap();

        vhdx.trim(TrimRequest::new(TrimMode::Zero, 0, block_size as u64))
            .await
            .unwrap();
        assert_block_state(&vhdx, 0, BatEntryState::Zero);

        // Second Zero trim → no-op.
        vhdx.trim(TrimRequest::new(TrimMode::Zero, 0, block_size as u64))
            .await
            .unwrap();
        assert_block_state(&vhdx, 0, BatEntryState::Zero);
    }

    // ---- Range Tests ----

    #[async_test]
    async fn trim_cross_block(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();
        let bs = vhdx.block_size();

        // Write blocks 0, 1, 2.
        for block in 0..3u32 {
            let offset = block as u64 * bs as u64;
            let mut ranges = Vec::new();
            let guard = vhdx.resolve_write(offset, bs, &mut ranges).await.unwrap();
            for range in &ranges {
                match range {
                    crate::io::WriteRange::Data {
                        file_offset,
                        length,
                        ..
                    } => {
                        let buf = vec![0xBB; *length as usize];
                        vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                    }
                    crate::io::WriteRange::Zero {
                        file_offset,
                        length,
                    } => {
                        let buf = vec![0u8; *length as usize];
                        vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                    }
                }
            }
            guard.complete().await.unwrap();
        }

        // Trim all 3 blocks at once.
        vhdx.trim(TrimRequest::new(TrimMode::FileSpace, 0, 3 * bs as u64))
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
        let bs = MB1 as u32; // Use 1 MiB blocks for easier testing.
        let mut params = CreateParams {
            disk_size: 4 * MB1,
            block_size: bs,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

        // Write blocks 0, 1, 2.
        for block in 0..3u32 {
            let offset = block as u64 * bs as u64;
            let mut ranges = Vec::new();
            let guard = vhdx.resolve_write(offset, bs, &mut ranges).await.unwrap();
            for range in &ranges {
                match range {
                    crate::io::WriteRange::Data {
                        file_offset,
                        length,
                        ..
                    } => {
                        let buf = vec![0xCC; *length as usize];
                        vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                    }
                    crate::io::WriteRange::Zero {
                        file_offset,
                        length,
                    } => {
                        let buf = vec![0u8; *length as usize];
                        vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                    }
                }
            }
            guard.complete().await.unwrap();
        }

        // Trim from mid-block-0 through mid-block-2 → only block 1 is trimmed.
        let trim_offset = MB1 / 2; // mid-block-0
        let trim_length = 2 * MB1; // covers block 1 fully, partial block 0 and 2
        vhdx.trim(TrimRequest::new(
            TrimMode::FileSpace,
            trim_offset,
            trim_length,
        ))
        .await
        .unwrap();

        assert_block_state(&vhdx, 0, BatEntryState::FullyPresent); // partial → not trimmed
        assert_block_state(&vhdx, 1, BatEntryState::Unmapped); // fully covered → trimmed
        assert_block_state(&vhdx, 2, BatEntryState::FullyPresent); // partial → not trimmed
    }

    #[async_test]
    async fn trim_entire_disk(driver: DefaultDriver) {
        let file = InMemoryFile::new(0);
        let bs = MB1 as u32;
        let mut params = CreateParams {
            disk_size: 4 * MB1,
            block_size: bs,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

        // Write all 4 blocks.
        for block in 0..4u32 {
            let offset = block as u64 * bs as u64;
            let mut ranges = Vec::new();
            let guard = vhdx.resolve_write(offset, bs, &mut ranges).await.unwrap();
            for range in &ranges {
                match range {
                    crate::io::WriteRange::Data {
                        file_offset,
                        length,
                        ..
                    } => {
                        let buf = vec![0xDD; *length as usize];
                        vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                    }
                    crate::io::WriteRange::Zero {
                        file_offset,
                        length,
                    } => {
                        let buf = vec![0u8; *length as usize];
                        vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                    }
                }
            }
            guard.complete().await.unwrap();
        }

        // Trim the entire disk.
        vhdx.trim(TrimRequest::new(TrimMode::FileSpace, 0, 4 * MB1))
            .await
            .unwrap();

        for block in 0..4u32 {
            assert_block_state(&vhdx, block, BatEntryState::Unmapped);
        }
    }

    #[async_test]
    async fn trim_at_disk_end_rounds_up(driver: DefaultDriver) {
        // The disk size may not be an exact multiple of block size.
        // If trim range ends exactly at disk_size, we round up.
        let file = InMemoryFile::new(0);
        let bs = MB1 as u32;
        // 3.5 MiB disk with 1 MiB blocks → 4 blocks (last block is partial).
        let disk_size = 3 * MB1 + MB1 / 2;
        let mut params = CreateParams {
            disk_size,
            block_size: bs,
            ..Default::default()
        };
        create::create(&file, &mut params).await.unwrap();
        let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

        // Write block 3 (the last, partial block).
        let block3_offset = 3 * MB1;
        // Write less than a full block (only the valid portion).
        let write_size = (MB1 / 2) as u32;
        let mut ranges = Vec::new();
        let guard = vhdx
            .resolve_write(block3_offset, write_size, &mut ranges)
            .await
            .unwrap();
        for range in &ranges {
            match range {
                crate::io::WriteRange::Data {
                    file_offset,
                    length,
                    ..
                } => {
                    let buf = vec![0xEE; *length as usize];
                    vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                }
                crate::io::WriteRange::Zero {
                    file_offset,
                    length,
                } => {
                    let buf = vec![0u8; *length as usize];
                    vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                }
            }
        }
        guard.complete().await.unwrap();

        // Trim from block 3 to end of disk.
        vhdx.trim(TrimRequest::new(
            TrimMode::FileSpace,
            block3_offset,
            disk_size - block3_offset,
        ))
        .await
        .unwrap();

        // Block 3 should be trimmed (disk end rounding kicks in).
        assert_block_state(&vhdx, 3, BatEntryState::Unmapped);
    }

    // ---- Read-After-Trim Tests ----

    #[async_test]
    async fn read_after_trim_returns_zeros(driver: DefaultDriver) {
        let vhdx = create_and_write_block(format::GB1, 0, &driver).await;

        // Verify data is present.
        let mut ranges = Vec::new();
        let guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();
        assert!(matches!(ranges[0], ReadRange::Data { .. }));
        drop(guard);

        // Trim.
        vhdx.trim(TrimRequest::new(
            TrimMode::FileSpace,
            0,
            vhdx.block_size() as u64,
        ))
        .await
        .unwrap();

        // Read after trim → zeros.
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

        // Trim with FileSpace (soft anchor).
        vhdx.trim(TrimRequest::new(
            TrimMode::FileSpace,
            0,
            vhdx.block_size() as u64,
        ))
        .await
        .unwrap();
        assert_block_state(&vhdx, 0, BatEntryState::Unmapped);

        // Write again — should reallocate (possibly reusing soft anchor).
        let bs = vhdx.block_size();
        let mut ranges = Vec::new();
        let guard = vhdx.resolve_write(0, bs, &mut ranges).await.unwrap();
        for range in &ranges {
            match range {
                crate::io::WriteRange::Data {
                    file_offset,
                    length,
                    ..
                } => {
                    let buf = vec![0xFF; *length as usize];
                    vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                }
                crate::io::WriteRange::Zero {
                    file_offset,
                    length,
                } => {
                    let buf = vec![0u8; *length as usize];
                    vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                }
            }
        }
        guard.complete().await.unwrap();

        assert_block_state(&vhdx, 0, BatEntryState::FullyPresent);
    }

    // ---- Fully-Allocated Disk Tests ----

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

        // FileSpace trim on fixed → no-op.
        vhdx.trim(TrimRequest::new(TrimMode::FileSpace, 0, 4 * MB1))
            .await
            .unwrap();

        // Blocks should be unchanged.
        let bat_state = vhdx.bat.bat_state.read();
        let mapping = bat_state.get_payload_mapping(0);
        let state = BatEntryState::from_raw(mapping.state()).unwrap();
        // On a fully-allocated disk, blocks start as Undefined (not yet written).
        // The FileSpace mode is a no-op, so they stay the same.
        assert_ne!(state, BatEntryState::Unmapped);
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

        // MakeTransparent on fixed → allowed.
        vhdx.trim(TrimRequest::new(TrimMode::MakeTransparent, 0, 4 * MB1))
            .await
            .unwrap();

        // Blocks should be NotPresent (MakeTransparent succeeded).
        assert_block_state(&vhdx, 0, BatEntryState::NotPresent);
    }

    // ---- Concurrent Safety Tests ----

    #[async_test]
    async fn trim_waits_for_in_flight_read(driver: DefaultDriver) {
        let vhdx = create_and_write_block(format::GB1, 0, &driver).await;

        // Acquire a read guard on block 0 to hold its refcount.
        let mut ranges = Vec::new();
        let read_guard = vhdx.resolve_read(0, 4096, &mut ranges).await.unwrap();

        // Spawn trim concurrently. It should block until the guard is dropped.
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
                // After a yield, drop the read guard.
                // The trim should be able to see the refcount eventually.
                // Yield to let the trim task run.
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

        // Acquire a write guard on block 0.
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
                // Yield to let the trim task run.
                std::future::poll_fn(|cx| {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Ready(())
                })
                .await;
                assert!(
                    !trim_done.load(std::sync::atomic::Ordering::SeqCst),
                    "trim should not complete while write guard is held"
                );
                // Complete the write so the guard drops after.
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
        let bs = vhdx.block_size();

        // Write blocks 0 and 1.
        for block in 0..2u32 {
            let offset = block as u64 * bs as u64;
            let mut ranges = Vec::new();
            let guard = vhdx.resolve_write(offset, bs, &mut ranges).await.unwrap();
            for range in &ranges {
                match range {
                    crate::io::WriteRange::Data {
                        file_offset,
                        length,
                        ..
                    } => {
                        let buf = vec![0xAA; *length as usize];
                        vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                    }
                    crate::io::WriteRange::Zero {
                        file_offset,
                        length,
                    } => {
                        let buf = vec![0u8; *length as usize];
                        vhdx.file.write_at(*file_offset, &buf).await.unwrap();
                    }
                }
            }
            guard.complete().await.unwrap();
        }

        // Trim block 0, read block 1 concurrently.
        let (trim_result, read_result) = futures::join!(
            vhdx.trim(TrimRequest::new(TrimMode::FileSpace, 0, bs as u64)),
            async {
                let mut ranges = Vec::new();
                let guard = vhdx
                    .resolve_read(bs as u64, 4096, &mut ranges)
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

    // ---- Validation Tests ----

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
        assert!(matches!(result, Err(VhdxError::ReadOnly)));
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
            Err(VhdxError::Corrupt(CorruptionType::UnalignedIo))
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
            Err(VhdxError::Corrupt(CorruptionType::ReadBeyondEndOfDisk))
        ));
    }

    #[async_test]
    async fn trim_beyond_disk_ok_with_skip(driver: DefaultDriver) {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let vhdx = VhdxFile::open(file).writable(&driver).await.unwrap();

        // With skip_disk_size_check, goes beyond but computes no included blocks → ok.
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

    // ---- Conversion function unit tests ----

    #[test]
    fn convert_file_space_mappings() {
        // FullyPresent → Unmapped (keep offset)
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_megabyte(4);
        let r = convert_mapping(TrimMode::FileSpace, m);
        assert_eq!(
            BatEntryState::from_raw(r.state()),
            Some(BatEntryState::Unmapped)
        );
        assert_eq!(r.file_megabyte(), 4);

        // Undefined → Undefined (no change)
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::Undefined as u8)
            .with_file_megabyte(0);
        let r = convert_mapping(TrimMode::FileSpace, m);
        assert_eq!(r, m);

        // Unmapped → Unmapped (no change)
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::Unmapped as u8)
            .with_file_megabyte(5);
        let r = convert_mapping(TrimMode::FileSpace, m);
        assert_eq!(r, m);
    }

    #[test]
    fn convert_free_space_mappings() {
        // FullyPresent → Undefined (clear offset)
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_megabyte(4);
        let r = convert_mapping(TrimMode::FreeSpace, m);
        assert_eq!(
            BatEntryState::from_raw(r.state()),
            Some(BatEntryState::Undefined)
        );
        assert_eq!(r.file_megabyte(), 0);

        // Unmapped → Undefined (keep anchor)
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::Unmapped as u8)
            .with_file_megabyte(5);
        let r = convert_mapping(TrimMode::FreeSpace, m);
        assert_eq!(
            BatEntryState::from_raw(r.state()),
            Some(BatEntryState::Undefined)
        );
        assert_eq!(r.file_megabyte(), 5);
    }

    #[test]
    fn convert_zero_mappings() {
        // FullyPresent → Zero (clear offset)
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_megabyte(4);
        let r = convert_mapping(TrimMode::Zero, m);
        assert_eq!(
            BatEntryState::from_raw(r.state()),
            Some(BatEntryState::Zero)
        );
        assert_eq!(r.file_megabyte(), 0);

        // Zero (no offset) → Zero (no change)
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::Zero as u8)
            .with_file_megabyte(0);
        let r = convert_mapping(TrimMode::Zero, m);
        assert_eq!(r, m);
    }

    #[test]
    fn convert_make_transparent_mappings() {
        // FullyPresent → NotPresent
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_megabyte(4);
        let r = convert_mapping(TrimMode::MakeTransparent, m);
        assert_eq!(
            BatEntryState::from_raw(r.state()),
            Some(BatEntryState::NotPresent)
        );
        assert_eq!(r.file_megabyte(), 0);

        // NotPresent → NotPresent (no change)
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::NotPresent as u8)
            .with_file_megabyte(0);
        let r = convert_mapping(TrimMode::MakeTransparent, m);
        assert_eq!(r, m);
    }

    #[test]
    fn convert_remove_soft_anchors_mappings() {
        // Unmapped with offset → clear offset
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::Unmapped as u8)
            .with_file_megabyte(5);
        let r = convert_mapping(TrimMode::RemoveSoftAnchors, m);
        assert_eq!(
            BatEntryState::from_raw(r.state()),
            Some(BatEntryState::Unmapped)
        );
        assert_eq!(r.file_megabyte(), 0);

        // FullyPresent → no change (not soft-anchored)
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_megabyte(4);
        let r = convert_mapping(TrimMode::RemoveSoftAnchors, m);
        assert_eq!(r, m);
    }

    #[test]
    fn is_soft_anchored_checks() {
        // Unmapped with offset → anchored
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::Unmapped as u8)
            .with_file_megabyte(5);
        assert!(is_soft_anchored(m));

        // Undefined with offset → anchored
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::Undefined as u8)
            .with_file_megabyte(3);
        assert!(is_soft_anchored(m));

        // Unmapped with no offset → not anchored
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::Unmapped as u8)
            .with_file_megabyte(0);
        assert!(!is_soft_anchored(m));

        // FullyPresent with offset → not anchored (wrong state)
        let m = InternalBlockMapping::new()
            .with_state(BatEntryState::FullyPresent as u8)
            .with_file_megabyte(4);
        assert!(!is_soft_anchored(m));
    }
}
