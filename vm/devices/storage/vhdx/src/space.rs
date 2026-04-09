// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Free space management for VHDX files.
//!
//! Tracks which megabyte-granularity regions of the file are free, in-use,
//! or soft-anchored (from trimmed blocks). Implements a four-priority
//! allocation strategy matching the C code in space.c:
//!
//! 1. **Free space pool** — reuse interior free blocks
//! 2. **Near-EOF space** — allocate from zeroed space before file end
//! 3. **Soft-anchored blocks** — reclaim trimmed blocks (in-memory only)
//! 4. **Extend EOF** — grow the file
//!
//! The bitmap uses 1-bit-per-megabyte granularity with SET = free / anchored
//! and CLEAR = in-use, matching the C implementation's `RTL_BITMAP` semantics.

use crate::bat::BatState;
use crate::error::CorruptionType;
use crate::error::VhdxError;
use crate::format::BatEntryState;
use crate::format::MB1;
use bitfield_struct::bitfield;
use parking_lot::Mutex;

/// Default EOF extension length: 32 MiB.
/// Matches `VHD2_DEFAULT_EXTENSION_LENGTH = 32 * VHD2_1MB`.
const DEFAULT_EOF_EXTENSION_LENGTH: u32 = 32 * MB1 as u32;

// ---------------------------------------------------------------------------
// SpaceBitmap — RTL_BITMAP equivalent
// ---------------------------------------------------------------------------

/// Bitmap wrapper providing `RTL_BITMAP`-equivalent operations.
///
/// Uses a `Vec<u64>` internally with LSB-first bit ordering.
/// SET bits (1) denote the property tracked by the containing structure
/// (free, anchored, or trimmed); CLEAR bits (0) denote the opposite.
#[derive(Clone)]
struct SpaceBitmap {
    /// Packed 64-bit words; bit 0 of word 0 is bit index 0.
    words: Vec<u64>,
    /// Number of valid bits. Bits beyond this in the last word are always 0.
    bit_count: usize,
}

impl SpaceBitmap {
    /// Create a new bitmap with `bit_count` bits, all initially clear.
    fn new(bit_count: usize) -> Self {
        let word_count = bit_count.div_ceil(64);
        SpaceBitmap {
            words: vec![0u64; word_count],
            bit_count,
        }
    }

    /// Number of valid bits.
    fn len(&self) -> usize {
        self.bit_count
    }

    /// Set a single bit.
    fn set_bit(&mut self, index: usize) {
        debug_assert!(index < self.bit_count);
        self.words[index / 64] |= 1u64 << (index % 64);
    }

    /// Clear a single bit.
    fn clear_bit(&mut self, index: usize) {
        debug_assert!(index < self.bit_count);
        self.words[index / 64] &= !(1u64 << (index % 64));
    }

    /// Check whether a single bit is set.
    fn check_bit(&self, index: usize) -> bool {
        debug_assert!(index < self.bit_count);
        (self.words[index / 64] >> (index % 64)) & 1 != 0
    }

    /// Set a contiguous range of bits `[start..start+count)`.
    fn set_range(&mut self, start: usize, count: usize) {
        debug_assert!(start + count <= self.bit_count);
        for i in start..start + count {
            self.words[i / 64] |= 1u64 << (i % 64);
        }
    }

    /// Clear a contiguous range of bits `[start..start+count)`.
    fn clear_range(&mut self, start: usize, count: usize) {
        debug_assert!(start + count <= self.bit_count);
        for i in start..start + count {
            self.words[i / 64] &= !(1u64 << (i % 64));
        }
    }

    /// Check whether all bits in `[start..start+count)` are set.
    fn are_bits_set(&self, start: usize, count: usize) -> bool {
        if count == 0 {
            return true;
        }
        debug_assert!(start + count <= self.bit_count);
        for i in start..start + count {
            if (self.words[i / 64] >> (i % 64)) & 1 == 0 {
                return false;
            }
        }
        true
    }

    /// Check whether all bits in `[start..start+count)` are clear.
    fn are_bits_clear(&self, start: usize, count: usize) -> bool {
        if count == 0 {
            return true;
        }
        debug_assert!(start + count <= self.bit_count);
        for i in start..start + count {
            if (self.words[i / 64] >> (i % 64)) & 1 != 0 {
                return false;
            }
        }
        true
    }

    /// Find the first contiguous run of `count` SET bits, starting the
    /// scan at `hint`. Returns `None` if no such run exists.
    ///
    /// This is a direct port of the `RtlFindSetBits` linear scan.
    fn find_set_bits(&self, count: usize, hint: usize) -> Option<usize> {
        if count == 0 || count > self.bit_count {
            return None;
        }

        let total = self.bit_count;
        let mut scanned = 0usize;
        let mut pos = hint.min(total);
        let mut run_start = pos;
        let mut run_len = 0usize;

        while scanned < total {
            let idx = pos % total;
            if self.check_bit(idx) {
                if run_len == 0 {
                    run_start = idx;
                }
                run_len += 1;
                if run_len >= count {
                    // Verify the run doesn't wrap around the bitmap end.
                    if run_start + count <= total {
                        return Some(run_start);
                    }
                    // Wrapped — reset and continue.
                    run_len = 0;
                }
            } else {
                run_len = 0;
            }
            pos += 1;
            scanned += 1;
        }

        None
    }

    /// Set all valid bits.
    fn set_all(&mut self) {
        for w in &mut self.words {
            *w = u64::MAX;
        }
        // Mask off bits beyond bit_count.
        let tail = self.bit_count % 64;
        if tail != 0 {
            if let Some(last) = self.words.last_mut() {
                *last = (1u64 << tail) - 1;
            }
        }
    }

    /// Clear all bits.
    #[expect(dead_code)]
    fn clear_all(&mut self) {
        for w in &mut self.words {
            *w = 0;
        }
    }

    /// Resize the bitmap to `new_bit_count`. New bits are cleared.
    /// Preserves existing data up to `min(old_count, new_count)`.
    fn resize(&mut self, new_bit_count: usize) {
        let new_word_count = new_bit_count.div_ceil(64);
        self.words.resize(new_word_count, 0);
        // Clear bits beyond new_bit_count in the last word.
        let tail = new_bit_count % 64;
        if tail != 0 {
            if let Some(last) = self.words.last_mut() {
                *last &= (1u64 << tail) - 1;
            }
        }
        // If shrinking, clear any bits in the old tail region that are now
        // beyond the new bit_count but within existing words.
        if new_bit_count < self.bit_count {
            // Old bits in [new_bit_count..old_bit_count) need clearing.
            // The resize already handled this by masking the last word above.
            // Any words beyond new_word_count were removed by `resize()`.
        }
        self.bit_count = new_bit_count;
    }
}

// ---------------------------------------------------------------------------
// Sub-structures
// ---------------------------------------------------------------------------

/// Free space pool state. Tracks 1-bit-per-megabyte: SET = free.
struct FreeSpacePool {
    bitmap: SpaceBitmap,
    lowest_bit_hint: u32,
    /// Fast-path flag: if true, skip free-pool scan for block-sized allocations.
    no_free_blocks: bool,
}

/// Anchored space state. Tracks 1-bit-per-megabyte: SET = soft-anchored.
struct AnchoredSpacePool {
    bitmap: SpaceBitmap,
    lowest_bit_hint: u32,
}

/// Tracks which data blocks have been trimmed but still hold a
/// "soft anchor" to their file space.
///
/// When a block is trimmed with `TrimMode::FileSpace`, the BAT entry
/// transitions to Unmapped but the `file_megabyte` field is preserved.
/// The space is *not* released to the free pool. This avoids the cost
/// of zeroing + flushing the space before a future BAT commit, because
/// the space still contains only the block's own old data — no
/// cross-block data leak is possible on power failure.
///
/// Bitmap: 1-bit-per-block-number, SET = has soft-anchored file offset.
struct TrimmedBlockTracker {
    bitmap: SpaceBitmap,
    lowest_block_number_hint: u32,
    num_trimmed_blocks: u32,
}

/// Internal mutable state of the free space tracker.
#[expect(dead_code)] // fields used in later stages
struct FreeSpaceInner {
    free_space: FreeSpacePool,
    anchored_space: AnchoredSpacePool,
    trimmed_blocks: TrimmedBlockTracker,

    /// Current file length (always MB1-aligned).
    file_length: u64,
    /// Highest in-use file offset.
    last_file_offset: u64,
    /// Offset at which all data beyond is guaranteed zero.
    zero_offset: u64,
    /// Minimum chunk for EOF extension.
    eof_extension_length: u32,
    /// Block size in bytes.
    block_size: u32,
    /// Block alignment (0 or power of 2 ≤ block_size).
    block_alignment: u32,
    /// Number of data blocks.
    data_block_count: u32,

    /// In-memory soft-anchored block tracking for `find_and_unanchor`.
    soft_anchored_in_memory_bat_page_number: u32,
    soft_anchored_in_memory_block_count: u32,
}

// ---------------------------------------------------------------------------
// FreeSpaceTracker — public API
// ---------------------------------------------------------------------------

/// Free space tracker for VHDX files. All internal state is protected by
/// a synchronous `parking_lot::Mutex`.
///
/// This mutex must **never** be held across `.await` points. The outer
/// `allocation_lock` (an async mutex on `VhdxFile`) serializes the full
/// allocation sequence including any file I/O.
pub(crate) struct FreeSpaceTracker {
    inner: Mutex<FreeSpaceInner>,
}

/// Flags for [`VhdxFile::allocate_space()`].
#[bitfield(u8)]
#[derive(PartialEq, Eq)]
pub(crate) struct AllocateFlags {
    /// Align the allocation to `block_alignment`.
    #[bits(1)]
    pub aligned: bool,
    /// Zero the allocated region if not already zeroed on disk.
    #[bits(1)]
    pub zero: bool,
    #[bits(6)]
    _reserved: u8,
}

/// Describes the state of newly allocated space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpaceState {
    /// Fresh space from file extension — zeroed on disk. Safe to commit
    /// BAT before flushing the data write (no data leak possible).
    Zero,
    /// Recycled space containing the same block's own old data. Safe to
    /// commit BAT before flushing (a power failure only exposes the
    /// block's own stale data, not another block's). NOT zero.
    OwnStale,
    /// Recycled space that may contain another block's data. Must flush
    /// data writes before committing BAT to prevent cross-block data
    /// leaks on power failure. NOT zero.
    CrossStale,
}

impl SpaceState {
    /// Safe to commit BAT entry before data flush completes?
    pub fn is_safe(self) -> bool {
        matches!(self, Self::Zero | Self::OwnStale)
    }

    /// Guaranteed zeroed on disk?
    pub fn is_zero(self) -> bool {
        matches!(self, Self::Zero)
    }
}

/// Result from a successful space allocation.
pub(crate) struct AllocateResult {
    /// File byte offset of the allocated region.
    pub file_offset: u64,
    /// State of the allocated space.
    pub state: SpaceState,
}

impl FreeSpaceTracker {
    /// Create and initialize the free space tracker.
    ///
    /// Called during `VhdxFile::open_inner()`, before the BAT parse. Sets all file
    /// space as free, then marks the header area, log, BAT, and metadata
    /// regions as in-use.
    ///
    /// Corresponds to `Vhd2iInitializeSpace`.
    pub fn new(
        file_length: u64,
        block_size: u32,
        header_area_size: u64,
        log_offset: u64,
        log_length: u32,
        bat_offset: u64,
        bat_length: u32,
        metadata_offset: u64,
        metadata_length: u32,
        data_block_count: u32,
    ) -> Result<Self, VhdxError> {
        // File length must be MB1-aligned.
        let aligned_file_length = (file_length + MB1 - 1) & !(MB1 - 1);
        let bit_count = (aligned_file_length / MB1) as usize;

        // Create bitmaps.
        let mut free_space_bitmap = SpaceBitmap::new(bit_count);
        let anchored_space_bitmap = SpaceBitmap::new(bit_count);
        let trimmed_block_bitmap = SpaceBitmap::new(data_block_count as usize);

        // Mark entire file as free.
        free_space_bitmap.set_all();

        let mut inner = FreeSpaceInner {
            free_space: FreeSpacePool {
                bitmap: free_space_bitmap,
                lowest_bit_hint: 0,
                no_free_blocks: false,
            },
            anchored_space: AnchoredSpacePool {
                bitmap: anchored_space_bitmap,
                lowest_bit_hint: bit_count as u32,
            },
            trimmed_blocks: TrimmedBlockTracker {
                bitmap: trimmed_block_bitmap,
                lowest_block_number_hint: data_block_count,
                num_trimmed_blocks: 0,
            },
            file_length: aligned_file_length,
            last_file_offset: 0,
            zero_offset: 0,
            eof_extension_length: DEFAULT_EOF_EXTENSION_LENGTH,
            block_size,
            block_alignment: 0,
            data_block_count,
            soft_anchored_in_memory_bat_page_number: 0,
            soft_anchored_in_memory_block_count: 0,
        };

        // Mark header area as in-use.
        mark_range_in_use_inner(&mut inner, 0, header_area_size as u32)?;

        // Mark log as in-use.
        if log_length > 0 {
            mark_range_in_use_inner(&mut inner, log_offset, log_length)?;
        }

        // Mark BAT region as in-use.
        // BAT length is rounded up to MB1 for space tracking.
        let bat_length_aligned = round_up_mb1(bat_length as u64) as u32;
        mark_range_in_use_inner(&mut inner, bat_offset, bat_length_aligned)?;

        // Mark metadata region as in-use.
        let metadata_length_aligned = round_up_mb1(metadata_length as u64) as u32;
        mark_range_in_use_inner(&mut inner, metadata_offset, metadata_length_aligned)?;

        Ok(FreeSpaceTracker {
            inner: Mutex::new(inner),
        })
    }

    /// Set block alignment. Must be 0 or a power of 2.
    /// If alignment > block_size, it is ignored (set to 0).
    ///
    /// Corresponds to `Vhd2SetBlockAlignment`.
    pub fn set_block_alignment(&self, alignment: u32) -> Result<(), VhdxError> {
        if alignment != 0 && !alignment.is_power_of_two() {
            return Err(VhdxError::InvalidFormat(
                crate::error::InvalidFormatReason::BlockAlignmentNotPowerOfTwo,
            ));
        }
        let mut inner = self.inner.lock();
        inner.block_alignment = if inner.block_size < alignment {
            0
        } else {
            alignment
        };
        Ok(())
    }

    /// Mark a file range as in-use during BAT parse.
    ///
    /// Validates that the range doesn't overlap with an already-in-use range
    /// and doesn't extend past EOF. Corresponds to `Vhd2iMarkRangeInUseDuringParse`.
    pub fn mark_range_in_use(&self, offset: u64, length: u32) -> Result<(), VhdxError> {
        let mut inner = self.inner.lock();
        mark_range_in_use_inner(&mut inner, offset, length)
    }

    /// Mark a trimmed block as soft-anchored during BAT parse.
    ///
    /// Corresponds to `Vhd2iMarkTrimmedBlockLocked`.
    pub fn mark_trimmed_block(
        &self,
        block_number: u32,
        file_offset: u64,
        block_size: u32,
    ) -> Result<(), VhdxError> {
        let mut inner = self.inner.lock();
        mark_trimmed_block_inner(&mut inner, block_number, file_offset, block_size)
    }

    /// Finalize after BAT parse. Separates EOF free space from pool free space.
    ///
    /// Blocks from `ZeroOffset` to `FileLength` are "near-EOF free space"
    /// (tracked separately, not in the bitmap pool). Clear those bits from
    /// the FreeSpace bitmap.
    ///
    /// Corresponds to `Vhd2iCompleteSpaceInitialization`.
    pub fn complete_initialization(&self) {
        let mut inner = self.inner.lock();
        let bit_base = (inner.zero_offset / MB1) as usize;
        let bit_count = ((inner.file_length - inner.zero_offset) / MB1) as usize;
        if bit_count > 0 {
            debug_assert!(inner.free_space.bitmap.are_bits_set(bit_base, bit_count));
            inner.free_space.bitmap.clear_range(bit_base, bit_count);
        }
    }

    /// Try to allocate space using priorities 1–3 (pool, near-EOF, anchored).
    ///
    /// Returns `Some(result)` on success, `None` if EOF extension is needed.
    /// When `None`, the caller should call `required_file_length()`, extend
    /// the file, call `complete_file_extend()`, then retry.
    ///
    /// Corresponds to `Vhd2iContinueAllocateSpace`.
    pub fn try_allocate(&self, size: u32, aligned: bool) -> Option<AllocateResult> {
        let mut inner = self.inner.lock();
        try_allocate_inner(&mut inner, size, aligned, None)
    }

    /// Try to allocate using priorities 1–3, with access to the BAT state
    /// for soft-anchor lookup (priority 3).
    pub fn try_allocate_with_bat(
        &self,
        size: u32,
        aligned: bool,
        bat_state: &BatState,
    ) -> Option<AllocateResult> {
        let mut inner = self.inner.lock();
        try_allocate_inner(&mut inner, size, aligned, Some(bat_state))
    }

    /// Compute the target file size for EOF extension.
    ///
    /// Includes `eof_extension_length` minimum chunk.
    pub fn required_file_length(&self, size: u32, aligned: bool) -> u64 {
        let inner = self.inner.lock();
        let aligned_zero_offset = if aligned && inner.block_alignment != 0 {
            round_up(inner.zero_offset, inner.block_alignment as u64)
        } else {
            inner.zero_offset
        };
        let target = aligned_zero_offset + size as u64;
        let min_target = inner.file_length + inner.eof_extension_length as u64;
        target.max(min_target)
    }

    /// Update state after file extension completed.
    ///
    /// Resizes bitmaps if needed and updates `file_length`.
    pub fn complete_file_extend(&self, new_file_length: u64) {
        let mut inner = self.inner.lock();
        let aligned = (new_file_length + MB1 - 1) & !(MB1 - 1);
        let new_bit_count = (aligned / MB1) as usize;
        let old_bit_count = inner.free_space.bitmap.len();

        if new_bit_count > old_bit_count {
            // Grow by at least 125% to avoid O(n²) behavior.
            let target_bits = (old_bit_count + old_bit_count / 4).max(new_bit_count);
            inner.free_space.bitmap.resize(target_bits);
            inner.anchored_space.bitmap.resize(target_bits);
        }

        inner.file_length = aligned;
    }

    /// Release space back to the free pool.
    ///
    /// Corresponds to `Vhd2ReleaseFileSpaceNoResizeFreeSpaceBitmapLocked`.
    pub fn release(&self, offset: u64, size: u32) {
        let mut inner = self.inner.lock();
        release_inner(&mut inner, offset, size);
    }

    /// Unmark a trimmed block (when its space is reclaimed).
    ///
    /// Corresponds to `Vhd2iUnmarkTrimmedBlockLocked`.
    pub fn unmark_trimmed_block(
        &self,
        block_number: u32,
        file_offset: u64,
        block_size: u32,
    ) -> Result<(), VhdxError> {
        let mut inner = self.inner.lock();
        unmark_trimmed_block_inner(&mut inner, block_number, file_offset, block_size)
    }

    /// Find and unanchor a soft-anchored block (in-memory only anchors).
    ///
    /// Returns the file offset and block number if found.
    /// Corresponds to the in-memory path of `Vhd2iFindAndUnanchorSpaceLocked`.
    pub fn find_and_unanchor_in_memory(&self, bat_state: &BatState) -> Option<(u64, u32)> {
        let mut inner = self.inner.lock();
        find_and_unanchor_in_memory_inner(&mut inner, bat_state)
    }

    /// Compute truncation target size.
    #[expect(dead_code)] // used in later stages
    pub fn truncate_target(&self, is_fully_allocated: bool) -> u64 {
        let inner = self.inner.lock();
        let mut target = inner.last_file_offset;
        if is_fully_allocated {
            // Count unallocated blocks that still need space.
            // For simplicity, use the same approach as the C code:
            // add excess blocks * block_size without exceeding file_length.
            let excess = compute_excess_block_count(&inner, target);
            let extra = (excess as u64) * inner.block_size as u64;
            target = (target + extra).min(inner.file_length);
        }
        target
    }

    /// Update state after truncation.
    pub fn apply_truncate(&self, new_file_length: u64) {
        let mut inner = self.inner.lock();
        let aligned = (new_file_length + MB1 - 1) & !(MB1 - 1);
        let new_bit_count = (aligned / MB1) as usize;
        let old_bit_count = inner.free_space.bitmap.len();

        if new_bit_count < old_bit_count {
            inner.free_space.bitmap.resize(new_bit_count);
            inner.anchored_space.bitmap.resize(new_bit_count);
        }

        inner.file_length = aligned;
        inner.zero_offset = inner.zero_offset.min(aligned);
    }

    /// Check if a range is in use (for debug/validation).
    pub fn is_range_in_use(&self, offset: u64, length: u32) -> bool {
        let inner = self.inner.lock();
        debug_assert!(offset.is_multiple_of(MB1));
        debug_assert!((length as u64).is_multiple_of(MB1));

        if inner.file_length < offset || inner.file_length - offset < length as u64 {
            return true;
        }

        let bit_base = (offset / MB1) as usize;
        let bit_count = length as usize / MB1 as usize;
        !inner.free_space.bitmap.are_bits_set(bit_base, bit_count)
    }

    /// Current file length.
    #[cfg(test)]
    pub fn file_length(&self) -> u64 {
        self.inner.lock().file_length
    }

    /// Current zero offset.
    #[cfg(test)]
    pub fn zero_offset(&self) -> u64 {
        self.inner.lock().zero_offset
    }
}

// ---------------------------------------------------------------------------
// Internal helpers (operate on FreeSpaceInner, called under lock)
// ---------------------------------------------------------------------------

/// Round `value` up to the nearest multiple of `alignment`.
fn round_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

/// Round `value` up to the nearest MB1 boundary.
fn round_up_mb1(value: u64) -> u64 {
    round_up(value, MB1)
}

/// Mark a file range as in-use during parse (internal, no lock).
fn mark_range_in_use_inner(
    inner: &mut FreeSpaceInner,
    offset: u64,
    length: u32,
) -> Result<(), VhdxError> {
    debug_assert!(offset.is_multiple_of(MB1), "offset must be MB1-aligned");
    debug_assert!(
        (length as u64).is_multiple_of(MB1),
        "length must be MB1-aligned"
    );

    if length == 0 {
        return Ok(());
    }

    // Check range is within file.
    if inner.file_length < offset || inner.file_length - offset < length as u64 {
        return Err(VhdxError::Corrupt(CorruptionType::RangeBeyondEof));
    }

    let bit_base = (offset / MB1) as usize;
    let bit_count = length as usize / MB1 as usize;

    // Overlap check: all bits must currently be SET (free).
    if !inner.free_space.bitmap.are_bits_set(bit_base, bit_count) {
        return Err(VhdxError::Corrupt(CorruptionType::RangeCollision));
    }

    // Mark as in-use (clear the bits).
    inner.free_space.bitmap.clear_range(bit_base, bit_count);

    // Update last_file_offset and zero_offset.
    let range_end = offset + length as u64;
    if range_end > inner.last_file_offset {
        inner.last_file_offset = range_end;
        if inner.last_file_offset > inner.zero_offset {
            inner.zero_offset = inner.last_file_offset;
        }
    }

    Ok(())
}

/// Mark a trimmed block as soft-anchored (internal, no lock).
fn mark_trimmed_block_inner(
    inner: &mut FreeSpaceInner,
    block_number: u32,
    file_offset: u64,
    block_size: u32,
) -> Result<(), VhdxError> {
    debug_assert!(block_number < inner.data_block_count);
    debug_assert!(block_size.is_multiple_of(MB1 as u32));

    // Check: already marked as trimmed?
    if inner.trimmed_blocks.bitmap.check_bit(block_number as usize) {
        return Err(VhdxError::Corrupt(CorruptionType::TrimmedRangeCollision));
    }

    // Check: anchored space bits must be clear (no collision).
    let bit_base = (file_offset / MB1) as usize;
    let bit_count = block_size as usize / MB1 as usize;
    if !inner
        .anchored_space
        .bitmap
        .are_bits_clear(bit_base, bit_count)
    {
        return Err(VhdxError::Corrupt(CorruptionType::TrimmedRangeCollision));
    }

    // Mark in trimmed block tracker.
    inner.trimmed_blocks.bitmap.set_bit(block_number as usize);
    inner.trimmed_blocks.num_trimmed_blocks += 1;
    inner.trimmed_blocks.lowest_block_number_hint = inner
        .trimmed_blocks
        .lowest_block_number_hint
        .min(block_number);

    // Mark in anchored space bitmap.
    inner.anchored_space.bitmap.set_range(bit_base, bit_count);
    inner.anchored_space.lowest_bit_hint =
        inner.anchored_space.lowest_bit_hint.min(bit_base as u32);

    Ok(())
}

/// Unmark a trimmed block (internal, no lock).
fn unmark_trimmed_block_inner(
    inner: &mut FreeSpaceInner,
    block_number: u32,
    file_offset: u64,
    block_size: u32,
) -> Result<(), VhdxError> {
    debug_assert!(block_number < inner.data_block_count);
    debug_assert!(block_size.is_multiple_of(MB1 as u32));

    // If not marked, someone else already claimed it.
    if !inner.trimmed_blocks.bitmap.check_bit(block_number as usize) {
        return Err(VhdxError::Corrupt(CorruptionType::Other));
    }

    inner.trimmed_blocks.bitmap.clear_bit(block_number as usize);
    inner.trimmed_blocks.num_trimmed_blocks -= 1;

    let bit_base = (file_offset / MB1) as usize;
    let bit_count = block_size as usize / MB1 as usize;
    debug_assert!(
        inner
            .anchored_space
            .bitmap
            .are_bits_set(bit_base, bit_count)
    );
    inner.anchored_space.bitmap.clear_range(bit_base, bit_count);

    Ok(())
}

/// Release space to the free pool (internal, no lock).
fn release_inner(inner: &mut FreeSpaceInner, offset: u64, size: u32) {
    debug_assert!(offset.is_multiple_of(MB1));
    debug_assert!((size as u64).is_multiple_of(MB1));

    let bit_base = (offset / MB1) as usize;
    let bit_count = size as usize / MB1 as usize;

    if bit_base + bit_count > inner.free_space.bitmap.len() {
        // Defensive: can't release beyond bitmap size.
        return;
    }

    debug_assert!(inner.free_space.bitmap.are_bits_clear(bit_base, bit_count));
    inner.free_space.bitmap.set_range(bit_base, bit_count);
    inner.free_space.no_free_blocks = false;

    if (bit_base as u32) < inner.free_space.lowest_bit_hint {
        inner.free_space.lowest_bit_hint = bit_base as u32;
    }
}

/// Priority 1: free space pool allocation (internal, no lock).
fn free_space_pool_alloc(inner: &mut FreeSpaceInner, length: u32) -> Option<u64> {
    debug_assert!((length as u64).is_multiple_of(MB1));
    let bit_count = length as usize / MB1 as usize;

    // Fast-path skip for block-sized allocations.
    if length >= inner.block_size && inner.free_space.no_free_blocks {
        return None;
    }

    let result = inner
        .free_space
        .bitmap
        .find_set_bits(bit_count, inner.free_space.lowest_bit_hint as usize);

    match result {
        Some(bit_base) => {
            // Claim the space.
            inner.free_space.bitmap.clear_range(bit_base, bit_count);
            inner.free_space.lowest_bit_hint = (bit_base + bit_count) as u32;
            let max_offset = (bit_base + bit_count) as u64 * MB1;
            if inner.last_file_offset < max_offset {
                inner.last_file_offset = max_offset;
            }
            Some(bit_base as u64 * MB1)
        }
        None => {
            if length <= inner.block_size {
                inner.free_space.no_free_blocks = true;
            }
            None
        }
    }
}

/// Try all three in-memory allocation priorities (internal).
fn try_allocate_inner(
    inner: &mut FreeSpaceInner,
    size: u32,
    aligned: bool,
    bat_state: Option<&BatState>,
) -> Option<AllocateResult> {
    // Priority 1: free space pool.
    if let Some(offset) = free_space_pool_alloc(inner, size) {
        return Some(AllocateResult {
            file_offset: offset,
            state: SpaceState::CrossStale,
        });
    }

    // Priority 2: near-EOF space (between ZeroOffset and FileLength).
    let aligned_zero_offset = if aligned && inner.block_alignment != 0 {
        round_up(inner.zero_offset, inner.block_alignment as u64)
    } else {
        inner.zero_offset
    };

    if inner.file_length >= aligned_zero_offset + size as u64 {
        let offset = aligned_zero_offset;
        inner.zero_offset = aligned_zero_offset + size as u64;
        inner.last_file_offset = inner.zero_offset;
        return Some(AllocateResult {
            file_offset: offset,
            state: SpaceState::Zero,
        });
    }

    // Priority 3: soft-anchored space from trimmed blocks (in-memory only).
    //
    // Reclaim space held by a *different* trimmed block. This is
    // CrossStale because the space contains that other block's old
    // data — a flush is required before the BAT entry for the new
    // block can be committed, to prevent cross-block data leaks on
    // power failure.
    //
    // (When a block reclaims its *own* soft-anchored space, the io.rs
    // write path handles that directly and marks it OwnStale,
    // since leaking a block's old data back to itself is harmless.)
    if size <= inner.block_size {
        if let Some(bat_state) = bat_state {
            if let Some((file_offset, block_number)) =
                find_and_unanchor_in_memory_inner(inner, bat_state)
            {
                // If the allocated block is larger than needed, release excess.
                if size < inner.block_size {
                    let excess_offset = file_offset + size as u64;
                    let excess_size = inner.block_size - size;
                    release_inner(inner, excess_offset, excess_size);
                }
                let _ = block_number;
                return Some(AllocateResult {
                    file_offset,
                    state: SpaceState::CrossStale,
                });
            }
        }
    }

    // Priority 4: caller must extend EOF.
    None
}

/// Find and unanchor an in-memory-only soft-anchored block.
fn find_and_unanchor_in_memory_inner(
    inner: &mut FreeSpaceInner,
    bat_state: &BatState,
) -> Option<(u64, u32)> {
    if inner.trimmed_blocks.num_trimmed_blocks == 0 {
        return None;
    }

    let block_size = inner.block_size;

    // Try to find an in-memory-only soft-anchored block by scanning
    // the TrimmedBlock bitmap.
    let mut trimmed_found = 0u32;
    let total_trimmed = inner.trimmed_blocks.num_trimmed_blocks;
    let mut hint = inner.trimmed_blocks.lowest_block_number_hint as usize;

    while trimmed_found < total_trimmed {
        let block_number = match inner.trimmed_blocks.bitmap.find_set_bits(1, hint) {
            Some(n) => n,
            None => break,
        };

        trimmed_found += 1;
        let mapping = bat_state.get_payload_mapping(block_number as u32);

        // Block must be soft-anchored: unmapped/undefined state with non-zero file_megabyte.
        let state = mapping.state();
        let is_unmapped = state == BatEntryState::Unmapped as u8
            || state == BatEntryState::Undefined as u8
            || state == BatEntryState::Zero as u8
            || state == BatEntryState::NotPresent as u8;

        debug_assert!(
            is_unmapped && mapping.file_megabyte() != 0,
            "trimmed block {block_number} is not soft-anchored"
        );

        // Check if it's in-memory only (not on-disk anchored).
        // For Phase 10, we only handle in-memory-only anchors.
        // An in-memory-only anchor means the on-disk BAT already has
        // file_megabyte = 0, but we don't track on-disk state separately.
        // Instead, check if the state is NOT one of the on-disk anchor
        // states (Undefined/Trimmed). For now, accept any unmapped block.
        //
        // The on-disk states that indicate on-disk soft-anchoring are
        // BlockUndefined and BlockTrimmed (not InMemory variants).
        // In our Rust model, we don't distinguish on-disk vs in-memory
        // unmapped states. For Phase 10, we'll accept all soft-anchored
        // blocks and treat them as reclaimable (the caller handles
        // clearing the BAT entry in memory).
        let file_offset = mapping.file_megabyte() as u64 * MB1;

        // Unmark the trimmed block.
        if unmark_trimmed_block_inner(inner, block_number as u32, file_offset, block_size).is_ok() {
            return Some((file_offset, block_number as u32));
        }

        hint = block_number + 1;
    }

    None
}

/// Compute excess block count (blocks that won't fit given current space).
fn compute_excess_block_count(inner: &FreeSpaceInner, max_offset: u64) -> u32 {
    // Count unallocated blocks.
    let total = inner.data_block_count;
    // Available space: count of free bits in free space bitmap + anchored space
    // + space from zero_offset to file_length.
    let mut available_mb: u64 = 0;

    // Count free bits up to the bitmap.
    for i in 0..inner.free_space.bitmap.len() {
        if inner.free_space.bitmap.check_bit(i) {
            available_mb += 1;
        }
    }

    // Count anchored bits.
    for i in 0..inner.anchored_space.bitmap.len() {
        if inner.anchored_space.bitmap.check_bit(i) {
            available_mb += 1;
        }
    }

    // EOF space.
    let zero = inner.zero_offset.min(max_offset);
    if inner.file_length > zero {
        available_mb += (inner.file_length - zero) / MB1;
    }

    let block_mb = inner.block_size as u64 / MB1;
    let available_blocks = available_mb / block_mb;
    let needed = total as u64;
    if needed > available_blocks {
        (needed - available_blocks) as u32
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bat::InternalBlockMapping;
    use crate::format::BatEntryState;

    // -- Bitmap unit tests --

    #[test]
    fn bitmap_set_clear_range() {
        let mut bm = SpaceBitmap::new(128);
        assert!(bm.are_bits_clear(0, 128));

        bm.set_range(10, 20);
        assert!(bm.are_bits_set(10, 20));
        assert!(bm.are_bits_clear(0, 10));
        assert!(bm.are_bits_clear(30, 98));

        bm.clear_range(15, 5);
        assert!(bm.are_bits_set(10, 5));
        assert!(bm.are_bits_clear(15, 5));
        assert!(bm.are_bits_set(20, 10));
    }

    #[test]
    fn bitmap_find_set_bits() {
        let mut bm = SpaceBitmap::new(64);
        // Create a run of 8 set bits starting at index 20.
        bm.set_range(20, 8);

        assert_eq!(bm.find_set_bits(8, 0), Some(20));
        assert_eq!(bm.find_set_bits(8, 20), Some(20));
        assert_eq!(bm.find_set_bits(9, 0), None);
        assert_eq!(bm.find_set_bits(1, 25), Some(25));
    }

    #[test]
    fn bitmap_find_set_bits_wraps_hint() {
        let mut bm = SpaceBitmap::new(64);
        // Run at the beginning.
        bm.set_range(0, 4);

        // Hint past the run — should wrap and find it.
        assert_eq!(bm.find_set_bits(4, 50), Some(0));
    }

    #[test]
    fn bitmap_are_bits_set_clear() {
        let mut bm = SpaceBitmap::new(32);
        bm.set_all();
        assert!(bm.are_bits_set(0, 32));
        assert!(!bm.are_bits_clear(0, 32));

        bm.clear_bit(16);
        assert!(!bm.are_bits_set(0, 32));
        assert!(!bm.are_bits_set(16, 1));
        assert!(bm.are_bits_clear(16, 1));
    }

    #[test]
    fn bitmap_empty_and_full() {
        let bm_empty = SpaceBitmap::new(0);
        assert_eq!(bm_empty.len(), 0);
        assert_eq!(bm_empty.find_set_bits(1, 0), None);

        let mut bm = SpaceBitmap::new(1);
        assert!(bm.are_bits_clear(0, 1));
        bm.set_bit(0);
        assert!(bm.are_bits_set(0, 1));
    }

    // -- FreeSpaceTracker initialization tests --

    /// Helper: create a tracker for a small test file.
    fn make_test_tracker(file_mb: u64, block_size_mb: u32) -> FreeSpaceTracker {
        let file_length = file_mb * MB1;
        let block_size = block_size_mb * MB1 as u32;
        let data_block_count = 16; // arbitrary for testing

        FreeSpaceTracker::new(
            file_length,
            block_size,
            MB1,        // header_area_size = 1 MB
            MB1,        // log_offset = 1 MB
            MB1 as u32, // log_length = 1 MB
            2 * MB1,    // bat_offset = 2 MB
            MB1 as u32, // bat_length = 1 MB
            3 * MB1,    // metadata_offset = 3 MB
            MB1 as u32, // metadata_length = 1 MB
            data_block_count,
        )
        .unwrap()
    }

    #[test]
    fn init_marks_header_in_use() {
        let tracker = make_test_tracker(10, 2);
        // Header area (0..1MB) should be in-use.
        assert!(tracker.is_range_in_use(0, MB1 as u32));
    }

    #[test]
    fn init_marks_regions_in_use() {
        let tracker = make_test_tracker(10, 2);
        // Log (1..2MB), BAT (2..3MB), metadata (3..4MB) should be in-use.
        assert!(tracker.is_range_in_use(MB1, MB1 as u32));
        assert!(tracker.is_range_in_use(2 * MB1, MB1 as u32));
        assert!(tracker.is_range_in_use(3 * MB1, MB1 as u32));
    }

    #[test]
    fn overlap_detection() {
        let tracker = make_test_tracker(10, 2);
        // Try to mark the header area again — should fail with RangeCollision.
        let result = tracker.mark_range_in_use(0, MB1 as u32);
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::RangeCollision))
        ));
    }

    #[test]
    fn range_beyond_eof_detected() {
        let tracker = make_test_tracker(10, 2);
        // Try to mark a range that extends beyond file length.
        let result = tracker.mark_range_in_use(9 * MB1, 2 * MB1 as u32);
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::RangeBeyondEof))
        ));
    }

    // -- Allocation priority tests --

    #[test]
    fn allocate_from_free_pool() {
        let tracker = make_test_tracker(10, 2);
        // Mark offset 4MB in-use (simulating BAT parse finding a block there).
        tracker.mark_range_in_use(4 * MB1, MB1 as u32).unwrap();
        tracker.complete_initialization();
        // Now zero_offset = 5*MB. Near-EOF = 5..10 MB (5 MB).
        // Bit 4 is in-use (cleared). Release it back to pool.
        tracker.release(4 * MB1, MB1 as u32);

        // Priority 1: should find the released space.
        let result = tracker.try_allocate(MB1 as u32, false);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.file_offset, 4 * MB1);
        assert!(!r.state.is_safe());
    }

    #[test]
    fn allocate_from_eof_space() {
        let tracker = make_test_tracker(10, 2);
        tracker.complete_initialization();

        // After initialization, zero_offset = 4*MB, file_length = 10*MB.
        // Near-EOF space = 6 MB.
        let result = tracker.try_allocate(2 * MB1 as u32, false);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.file_offset, 4 * MB1);
        assert!(r.state.is_safe()); // Beyond old zero_offset.
    }

    #[test]
    fn allocate_extends_eof() {
        // Create a tracker with only 4MB (all in-use by regions).
        let tracker = make_test_tracker(4, 2);
        tracker.complete_initialization();

        // No free space, no near-EOF space.
        let result = tracker.try_allocate(MB1 as u32, false);
        assert!(result.is_none());

        // Compute required length and extend.
        let target = tracker.required_file_length(MB1 as u32, false);
        assert!(target > 4 * MB1);

        tracker.complete_file_extend(target);

        // Now retry — should succeed from near-EOF.
        let result = tracker.try_allocate(MB1 as u32, false);
        assert!(result.is_some());
        assert!(result.unwrap().state.is_safe());
    }

    #[test]
    fn allocate_alignment() {
        // 20MB file, 4MB block size, 4MB alignment.
        let tracker = make_test_tracker(20, 4);
        tracker.set_block_alignment(4 * MB1 as u32).unwrap();
        tracker.complete_initialization();

        // zero_offset = 4MB (after regions).
        // Aligned allocation from EOF: should be at 4MB (already aligned).
        let result = tracker.try_allocate(4 * MB1 as u32, true);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.file_offset % (4 * MB1), 0);
    }

    #[test]
    fn allocate_sets_no_free_blocks_flag() {
        let tracker = make_test_tracker(10, 2);
        tracker.complete_initialization();

        // Exhaust near-EOF space with pool allocations — first exhaust pool.
        // After init, pool is empty (regions fill 0..4MB, rest is EOF space).
        // Try pool-only: allocate 1MB from pool (should fail, and set flag).
        // But near-EOF will succeed before we get to that.
        //
        // Instead, fill up all space and verify the flag works.
        // Allocate all 6 MB of EOF space.
        for _ in 0..6 {
            tracker.try_allocate(MB1 as u32, false).unwrap();
        }
        // Now no space left.
        let result = tracker.try_allocate(MB1 as u32, false);
        assert!(result.is_none());
    }

    // -- Soft anchoring tests --

    fn make_bat_state_with_anchored_block(
        block_number: u32,
        file_megabyte: u32,
        data_block_count: u32,
    ) -> BatState {
        let mut payload_mappings = vec![
            InternalBlockMapping::new()
                .with_state(BatEntryState::NotPresent as u8);
            data_block_count as usize
        ];
        payload_mappings[block_number as usize] = InternalBlockMapping::new()
            .with_state(BatEntryState::Unmapped as u8)
            .with_file_megabyte(file_megabyte);

        BatState {
            payload_mappings,
            sector_bitmap_mappings: Vec::new(),
            allocated_block_count: 0,
            io_refcounts: vec![0u32; data_block_count as usize],
        }
    }

    #[test]
    fn mark_and_find_anchored_block() {
        let tracker = make_test_tracker(20, 2);
        // Mark block 3 as trimmed at file offset 6*MB.
        tracker
            .mark_trimmed_block(3, 6 * MB1, 2 * MB1 as u32)
            .unwrap();

        // Verify anchored space bits are set.
        let inner = tracker.inner.lock();
        assert!(inner.anchored_space.bitmap.are_bits_set(6, 2));
        assert!(inner.trimmed_blocks.bitmap.check_bit(3));
        assert_eq!(inner.trimmed_blocks.num_trimmed_blocks, 1);
    }

    #[test]
    fn unmark_trimmed_block() {
        let tracker = make_test_tracker(20, 2);
        tracker
            .mark_trimmed_block(3, 6 * MB1, 2 * MB1 as u32)
            .unwrap();
        tracker
            .unmark_trimmed_block(3, 6 * MB1, 2 * MB1 as u32)
            .unwrap();

        let inner = tracker.inner.lock();
        assert!(inner.anchored_space.bitmap.are_bits_clear(6, 2));
        assert!(!inner.trimmed_blocks.bitmap.check_bit(3));
        assert_eq!(inner.trimmed_blocks.num_trimmed_blocks, 0);
    }

    #[test]
    fn find_and_unanchor_in_memory() {
        let tracker = make_test_tracker(20, 2);
        // Mark block 5 as trimmed at file offset 8*MB.
        tracker
            .mark_trimmed_block(5, 8 * MB1, 2 * MB1 as u32)
            .unwrap();

        let bat_state = make_bat_state_with_anchored_block(5, 8, 16);

        let result = tracker.find_and_unanchor_in_memory(&bat_state);
        assert!(result.is_some());
        let (offset, block_num) = result.unwrap();
        assert_eq!(offset, 8 * MB1);
        assert_eq!(block_num, 5);

        // After unanchoring, the trimmed block should be unmarked.
        let inner = tracker.inner.lock();
        assert!(!inner.trimmed_blocks.bitmap.check_bit(5));
        assert_eq!(inner.trimmed_blocks.num_trimmed_blocks, 0);
    }

    #[test]
    fn anchored_space_before_eof_extend() {
        // Set up a full file with no free pool and no EOF space,
        // but with a soft-anchored block.
        let tracker = make_test_tracker(10, 2);

        // Mark block 2 as trimmed at offset 6*MB.
        tracker
            .mark_trimmed_block(2, 6 * MB1, 2 * MB1 as u32)
            .unwrap();
        // Mark remaining free space as in-use so pool is empty.
        tracker.mark_range_in_use(4 * MB1, MB1 as u32).unwrap();
        tracker.mark_range_in_use(5 * MB1, MB1 as u32).unwrap();
        tracker.mark_range_in_use(8 * MB1, 2 * MB1 as u32).unwrap();
        tracker.complete_initialization();

        let bat_state = make_bat_state_with_anchored_block(2, 6, 16);

        // Should find anchored space (priority 3) instead of extending EOF.
        let result = tracker.try_allocate_with_bat(2 * MB1 as u32, false, &bat_state);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.file_offset, 6 * MB1);
    }

    // -- Release tests --

    #[test]
    fn release_then_reallocate() {
        let tracker = make_test_tracker(10, 2);
        tracker.complete_initialization();

        // Allocate from EOF space.
        let r1 = tracker.try_allocate(MB1 as u32, false).unwrap();
        let offset = r1.file_offset;

        // Release it back to free pool.
        tracker.release(offset, MB1 as u32);

        // Allocate again — should reuse the released space.
        let r2 = tracker.try_allocate(MB1 as u32, false).unwrap();
        assert_eq!(r2.file_offset, offset);
    }

    // -- Truncation test --

    #[test]
    fn truncate_shrinks_bitmaps() {
        let tracker = make_test_tracker(10, 2);
        tracker.complete_initialization();

        let orig_len = tracker.file_length();
        assert_eq!(orig_len, 10 * MB1);

        tracker.apply_truncate(6 * MB1);
        assert_eq!(tracker.file_length(), 6 * MB1);
    }

    // -- Bitmap resize test --

    #[test]
    fn bitmap_resize_preserves_data() {
        let mut bm = SpaceBitmap::new(32);
        bm.set_range(10, 10);

        bm.resize(64);
        assert_eq!(bm.len(), 64);
        assert!(bm.are_bits_set(10, 10));
        assert!(bm.are_bits_clear(20, 44));

        bm.resize(16);
        assert_eq!(bm.len(), 16);
        assert!(bm.are_bits_set(10, 6)); // only 10..16 remains
    }

    // -- Priority cascade test --

    #[test]
    fn priority_cascade_pool_then_eof_then_anchor_then_extend() {
        // Walk through all 4 priorities in sequence.
        let tracker = make_test_tracker(10, 2);

        // Mark 4..5 MB in-use (a data block during BAT parse).
        tracker.mark_range_in_use(4 * MB1, MB1 as u32).unwrap();
        // Mark 5..7 MB in-use, then mark as soft-anchored (trimmed block 1).
        // The C code always marks in-use first, then marks as trimmed.
        tracker.mark_range_in_use(5 * MB1, 2 * MB1 as u32).unwrap();
        tracker
            .mark_trimmed_block(1, 5 * MB1, 2 * MB1 as u32)
            .unwrap();
        // Mark 7..8 MB in-use.
        tracker.mark_range_in_use(7 * MB1, MB1 as u32).unwrap();

        tracker.complete_initialization();
        // zero_offset = 8 MB, file_length = 10 MB.
        // Pool: empty (all bits 0..8 are cleared). Near-EOF: 8..10 (2 MB).

        // Release bit 4 back to pool.
        tracker.release(4 * MB1, MB1 as u32);

        // Create BAT state for soft-anchor lookup.
        let bat_state = make_bat_state_with_anchored_block(1, 5, 16);

        // Priority 1: pool (offset 4 MB).
        let r1 = tracker
            .try_allocate_with_bat(MB1 as u32, false, &bat_state)
            .unwrap();
        assert_eq!(r1.file_offset, 4 * MB1);
        assert!(!r1.state.is_safe());

        // Pool now empty. Priority 2: near-EOF (offset 8 MB).
        let r2 = tracker
            .try_allocate_with_bat(MB1 as u32, false, &bat_state)
            .unwrap();
        assert_eq!(r2.file_offset, 8 * MB1);
        assert!(r2.state.is_safe());

        // Take the second EOF MB too.
        let r3 = tracker
            .try_allocate_with_bat(MB1 as u32, false, &bat_state)
            .unwrap();
        assert_eq!(r3.file_offset, 9 * MB1);
        assert!(r3.state.is_safe());

        // Pool and EOF exhausted. Priority 3: soft-anchored (offset 5 MB).
        // The block is 2 MB but we only need 1 MB — excess goes to pool.
        let r4 = tracker
            .try_allocate_with_bat(MB1 as u32, false, &bat_state)
            .unwrap();
        assert_eq!(r4.file_offset, 5 * MB1);
        assert!(!r4.state.is_safe());

        // The excess 1 MB from the anchored block should now be in pool.
        let r5 = tracker
            .try_allocate_with_bat(MB1 as u32, false, &bat_state)
            .unwrap();
        assert_eq!(r5.file_offset, 6 * MB1);
        assert!(!r5.state.is_safe());

        // Everything exhausted. Priority 4: returns None.
        let r6 = tracker.try_allocate_with_bat(MB1 as u32, false, &bat_state);
        assert!(r6.is_none());

        // Extend EOF, then retry.
        let target = tracker.required_file_length(MB1 as u32, false);
        tracker.complete_file_extend(target);
        let r7 = tracker
            .try_allocate_with_bat(MB1 as u32, false, &bat_state)
            .unwrap();
        assert!(r7.state.is_safe());
        assert_eq!(r7.file_offset, 10 * MB1);
    }

    // -- Aligned allocation from pool test --

    #[test]
    fn aligned_alloc_from_pool() {
        // 20 MB file, 4 MB block size, 4 MB alignment.
        let tracker = make_test_tracker(20, 4);
        tracker.set_block_alignment(4 * MB1 as u32).unwrap();

        // Mark 4..8 MB in-use, then release to create a 4MB pool hole at an aligned offset.
        tracker.mark_range_in_use(4 * MB1, 4 * MB1 as u32).unwrap();
        tracker.complete_initialization();
        tracker.release(4 * MB1, 4 * MB1 as u32);

        // Pool allocation ignores alignment (alignment only applies to near-EOF).
        let result = tracker.try_allocate(4 * MB1 as u32, true).unwrap();
        assert_eq!(result.file_offset, 4 * MB1);
        assert!(!result.state.is_safe());
    }

    // -- Unaligned EOF skip test --

    #[test]
    fn aligned_alloc_skips_unaligned_eof_offset() {
        // 20 MB file, 4 MB block size, 4 MB alignment.
        let tracker = make_test_tracker(20, 4);
        tracker.set_block_alignment(4 * MB1 as u32).unwrap();

        // Mark 4..5 MB in-use. This pushes zero_offset to 5 MB (not 4MB-aligned).
        tracker.mark_range_in_use(4 * MB1, MB1 as u32).unwrap();
        tracker.complete_initialization();
        // zero_offset = 5 MB. Aligned to 4 MB → round up to 8 MB.
        // So the allocation should come from offset 8 MB (skipping 5..8).

        let result = tracker.try_allocate(4 * MB1 as u32, true).unwrap();
        assert_eq!(result.file_offset, 8 * MB1);
        assert!(result.state.is_safe());
    }

    // -- Bitmap resize on file extend --

    #[test]
    fn complete_file_extend_grows_bitmaps() {
        let tracker = make_test_tracker(4, 2);
        tracker.complete_initialization();

        // Bitmap should be 4 bits (4 MB / 1 MB).
        {
            let inner = tracker.inner.lock();
            assert!(inner.free_space.bitmap.len() >= 4);
        }

        // Extend to 100 MB.
        tracker.complete_file_extend(100 * MB1);
        assert_eq!(tracker.file_length(), 100 * MB1);

        {
            let inner = tracker.inner.lock();
            // Bitmap must have grown to at least 100 bits.
            assert!(inner.free_space.bitmap.len() >= 100);
            assert!(inner.anchored_space.bitmap.len() >= 100);
        }

        // Near-EOF space should now be available.
        let result = tracker.try_allocate(MB1 as u32, false).unwrap();
        assert!(result.state.is_safe());
    }

    // -- no_free_blocks flag reset on release --

    #[test]
    fn no_free_blocks_flag_resets_on_release() {
        let tracker = make_test_tracker(6, 2);
        tracker.complete_initialization();

        // Exhaust all space: 2 MB of near-EOF (6-4=2).
        tracker.try_allocate(MB1 as u32, false).unwrap();
        tracker.try_allocate(MB1 as u32, false).unwrap();
        assert!(tracker.try_allocate(MB1 as u32, false).is_none());

        // The no_free_blocks flag should be set now.
        {
            let inner = tracker.inner.lock();
            assert!(inner.free_space.no_free_blocks);
        }

        // Release 1 MB back.
        tracker.release(4 * MB1, MB1 as u32);

        // Flag should be cleared.
        {
            let inner = tracker.inner.lock();
            assert!(!inner.free_space.no_free_blocks);
        }

        // Should be able to allocate again.
        let result = tracker.try_allocate(MB1 as u32, false).unwrap();
        assert_eq!(result.file_offset, 4 * MB1);
        assert!(!result.state.is_safe());
    }

    // -- Fragmented pool test --

    #[test]
    fn fragmented_pool_allocates_from_lowest_hint() {
        let tracker = make_test_tracker(20, 2);
        // Mark a contiguous range 4..11 MB in-use during BAT parse.
        tracker.mark_range_in_use(4 * MB1, 7 * MB1 as u32).unwrap();
        tracker.complete_initialization();
        // zero_offset = 11 MB. Near-EOF = 11..20 (9 MB).
        // Pool: empty (bits 0..11 all cleared).

        // Release scattered 1MB blocks to create fragmentation.
        tracker.release(10 * MB1, MB1 as u32);
        tracker.release(8 * MB1, MB1 as u32);
        tracker.release(6 * MB1, MB1 as u32);
        tracker.release(4 * MB1, MB1 as u32);

        // Pool should find the lowest free bit first.
        let r1 = tracker.try_allocate(MB1 as u32, false).unwrap();
        assert_eq!(r1.file_offset, 4 * MB1);

        let r2 = tracker.try_allocate(MB1 as u32, false).unwrap();
        assert_eq!(r2.file_offset, 6 * MB1);

        let r3 = tracker.try_allocate(MB1 as u32, false).unwrap();
        assert_eq!(r3.file_offset, 8 * MB1);

        let r4 = tracker.try_allocate(MB1 as u32, false).unwrap();
        assert_eq!(r4.file_offset, 10 * MB1);

        // Pool exhausted — next allocation comes from near-EOF.
        let r5 = tracker.try_allocate(MB1 as u32, false).unwrap();
        assert_eq!(r5.file_offset, 11 * MB1);
        assert!(r5.state.is_safe());
    }

    // -- Multi-MB allocation from pool --

    #[test]
    fn pool_allocates_contiguous_multi_mb() {
        let tracker = make_test_tracker(20, 2);
        // Mark a contiguous 4 MB region (bits 4..8) in-use, then release.
        tracker.mark_range_in_use(4 * MB1, 4 * MB1 as u32).unwrap();
        tracker.complete_initialization();
        tracker.release(4 * MB1, 4 * MB1 as u32);

        // Now request a 3 MB allocation from pool — should find the 4MB hole.
        let result = tracker.try_allocate(3 * MB1 as u32, false).unwrap();
        assert_eq!(result.file_offset, 4 * MB1);
        assert!(!result.state.is_safe());

        // 1 MB of the hole (bit 7) is still in pool.
        let r2 = tracker.try_allocate(MB1 as u32, false).unwrap();
        assert_eq!(r2.file_offset, 7 * MB1);
    }

    // -- Truncation clamps zero_offset --

    #[test]
    fn truncate_clamps_zero_offset() {
        let tracker = make_test_tracker(10, 2);
        tracker.complete_initialization();
        // zero_offset = 4 MB, file_length = 10 MB.

        // Allocate some EOF space to advance zero_offset.
        tracker.try_allocate(3 * MB1 as u32, false).unwrap();
        assert_eq!(tracker.zero_offset(), 7 * MB1);

        // Truncate file to 5 MB.
        tracker.apply_truncate(5 * MB1);
        assert_eq!(tracker.file_length(), 5 * MB1);
        // zero_offset should be clamped to file_length.
        assert!(tracker.zero_offset() <= 5 * MB1);
    }

    // -- Multiple anchored blocks: only one reclaimed per allocate --

    #[test]
    fn multiple_anchored_blocks_reclaimed_one_at_a_time() {
        let tracker = make_test_tracker(20, 2);
        // Mark anchored regions in-use first (matching C code sequence),
        // then mark as trimmed.
        tracker.mark_range_in_use(6 * MB1, 2 * MB1 as u32).unwrap();
        tracker
            .mark_trimmed_block(2, 6 * MB1, 2 * MB1 as u32)
            .unwrap();
        tracker.mark_range_in_use(10 * MB1, 2 * MB1 as u32).unwrap();
        tracker
            .mark_trimmed_block(5, 10 * MB1, 2 * MB1 as u32)
            .unwrap();

        // Fill all remaining space so pool + EOF are empty.
        tracker.mark_range_in_use(4 * MB1, 2 * MB1 as u32).unwrap();
        tracker.mark_range_in_use(8 * MB1, 2 * MB1 as u32).unwrap();
        tracker.mark_range_in_use(12 * MB1, 8 * MB1 as u32).unwrap();
        tracker.complete_initialization();

        // BAT state with both blocks anchored.
        let mut payload_mappings =
            vec![InternalBlockMapping::new().with_state(BatEntryState::NotPresent as u8); 16];
        payload_mappings[2] = InternalBlockMapping::new()
            .with_state(BatEntryState::Unmapped as u8)
            .with_file_megabyte(6);
        payload_mappings[5] = InternalBlockMapping::new()
            .with_state(BatEntryState::Unmapped as u8)
            .with_file_megabyte(10);
        let bat_state = BatState {
            payload_mappings,
            sector_bitmap_mappings: Vec::new(),
            allocated_block_count: 0,
            io_refcounts: vec![0u32; 16],
        };

        // First allocate gets block 2 (lowest block number).
        let r1 = tracker
            .try_allocate_with_bat(2 * MB1 as u32, false, &bat_state)
            .unwrap();
        assert_eq!(r1.file_offset, 6 * MB1);
        assert!(!r1.state.is_safe());

        // Second allocate gets block 5.
        let r2 = tracker
            .try_allocate_with_bat(2 * MB1 as u32, false, &bat_state)
            .unwrap();
        assert_eq!(r2.file_offset, 10 * MB1);
        assert!(!r2.state.is_safe());

        // No more anchored blocks.
        assert!(
            tracker
                .try_allocate_with_bat(2 * MB1 as u32, false, &bat_state)
                .is_none()
        );
    }

    // -- Anchored block larger than requested: excess goes to pool --

    #[test]
    fn anchored_block_excess_released_to_pool() {
        let tracker = make_test_tracker(10, 2); // block_size = 2 MB
        // Anchor block 0 at offset 4..6 MB.
        tracker
            .mark_trimmed_block(0, 4 * MB1, 2 * MB1 as u32)
            .unwrap();
        // Fill the rest.
        tracker.mark_range_in_use(6 * MB1, 4 * MB1 as u32).unwrap();
        tracker.complete_initialization();

        let bat_state = make_bat_state_with_anchored_block(0, 4, 16);

        // Request only 1 MB from a 2 MB anchored block.
        let r = tracker
            .try_allocate_with_bat(MB1 as u32, false, &bat_state)
            .unwrap();
        assert_eq!(r.file_offset, 4 * MB1);

        // The excess 1 MB (at offset 5 MB) should now be in the free pool.
        let r2 = tracker.try_allocate(MB1 as u32, false).unwrap();
        assert_eq!(r2.file_offset, 5 * MB1);
        assert!(!r2.state.is_safe());
    }

    // -- required_file_length respects alignment --

    #[test]
    fn required_file_length_with_alignment() {
        let tracker = make_test_tracker(4, 4);
        tracker.set_block_alignment(4 * MB1 as u32).unwrap();
        tracker.complete_initialization();
        // zero_offset = 4 MB (already aligned).

        let target = tracker.required_file_length(4 * MB1 as u32, true);
        // Should be at least file_length + extension_length.
        assert!(target >= 4 * MB1 + DEFAULT_EOF_EXTENSION_LENGTH as u64);
        // And aligned target should fit the request.
        assert!(target >= 4 * MB1 + 4 * MB1);
    }

    // -- Zero-length mark is a no-op --

    #[test]
    fn mark_zero_length_is_noop() {
        let tracker = make_test_tracker(10, 2);
        assert!(tracker.mark_range_in_use(4 * MB1, 0).is_ok());
        // The range should still be free.
        assert!(!tracker.is_range_in_use(4 * MB1, MB1 as u32));
    }
}
