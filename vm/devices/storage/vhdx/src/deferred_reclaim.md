# Deferred Space Reclaim — Design Plan

## Problem

When a block is trimmed (state changes from FullyPresent to Unmapped/Undefined),
its file space must not be reused until the trim's BAT change is durable on disk.
Otherwise, a crash can "teleport" data: the new block's data appears at the old
block's offset, because the old block's BAT reverts to FullyPresent on replay.

Today the Rust code releases space to the free pool or marks soft anchors
immediately during trim, before flushing. This allows the allocator to hand out
space whose ownership change is not yet durable.

## Invariant

**A file offset X must not be written with new data until the BAT change that
released X is durable on disk.**

Same-block reclaim (block A reclaims its own soft-anchored offset) is exempt:
the worst case is A reads its own old data, which is harmless (OwnStale).

## Design

### Data Structure

A single `HashMap<u32, DeferredRelease>` keyed by block number, protected by a
`Mutex`. Lives on `VhdxFile`.

```rust
struct DeferredRelease {
    file_offset: u64,
    size: u32,
    /// true:  TrimMode::FileSpace — after durable, mark as soft-anchored
    ///        in FreeSpaceTracker (eligible for cross-block reclaim).
    /// false: TrimMode::FreeSpace/Zero/MakeTransparent — after durable,
    ///        release to free pool.
    anchor: bool,
}
```

### Operations

**Trim** (in `trim()`, step 9e — replacing current `free_space.release()` and
`free_space.mark_trimmed_block()` calls):

- When a block transitions away from allocated state and has a file offset:
  `deferred.insert(block_number, DeferredRelease { ... })`
- When a soft-anchored block has its anchor removed (e.g., RemoveSoftAnchors mode):
  update the existing entry to `anchor: false`, or insert a new one.
- If `deferred.len() >= DEFERRED_QUOTA` (e.g., 1024): call `flush().await`
  inline before continuing the trim loop.

**Flush** (in `flush()`, after WAL durability is confirmed):

- Drain the entire map.
- For each entry:
  - If `anchor == true`: call `free_space.mark_trimmed_block(block, offset, size)`
  - If `anchor == false`: call `free_space.release(offset, size)`

**Write — same-block reclaim** (in `io.rs`, the `is_soft_anchored` check):

- Before allocating, check `deferred.remove(block_number)`.
- If found: reuse `file_offset` directly as `OwnStale`. No flush needed.
- If not found: check `FreeSpaceTracker` for a durable soft anchor (existing
  `is_soft_anchored` + `unmark_trimmed_block` path, unchanged).

**Priority-3 cross-block reclaim** (in `space.rs`):

- Only considers blocks in `TrimmedBlockTracker` (populated by flush, so always
  durable).
- Clears old block's `file_megabyte` in `BatState`, writes old block's BAT page
  to cache. No extra flush needed — the old block's trim is already durable, so a
  crash just restores the old block as Unmapped(X) and B's allocation is lost.
  No teleportation.
- Returns space as `CrossStale`.

**Close** (in `close()`):

- `flush()` runs as part of close, which drains the deferred map.

**Abort** (in `abort()`, dirty shutdown):

- Deferred entries are simply dropped. On reopen, the in-memory BAT won't have
  the trims (they weren't durable), so blocks revert to their pre-trim state.
  Space is not leaked — it's still owned by the original blocks.

### Concurrency

The deferred map is accessed from:
- `trim()` — inserts entries (single trim at a time, no concurrent trims today)
- `flush()` — drains the map
- `resolve_write()` — removes same-block entries (under allocation_lock)

A `parking_lot::Mutex` is sufficient. No async lock needed — all operations
are brief. The mutex must NOT be held across `.await`.

### What This Does NOT Do

- No LSN/FSN tracking per entry. Flush drains everything; no partial promotion.
- No batch conversion of soft anchors (the C code's piggyback optimization).
- No DirtyBatBitmap side channel.
- No truncate-time unanchoring.
- No provenance tracking (in-memory vs on-disk anchor distinction).

These are all potential future optimizations. The current design is correct and
simple. The only cost is that trimmed space is unavailable between trim and
the next flush.

### Changes by File

**`open.rs`**:
- Add `deferred_releases: Mutex<HashMap<u32, DeferredRelease>>` to `VhdxFile`.
- In `flush()`: after WAL durability, drain deferred map into `FreeSpaceTracker`.
- In `close()`: no change (already calls `flush()`).

**`trim.rs`**:
- Replace `free_space.release()` and `free_space.mark_trimmed_block()` calls in
  step 9e with `deferred_releases.insert()`.
- Add quota check after each insert: if over quota, `flush().await`.

**`io.rs`**:
- In `resolve_write()`, before the `is_soft_anchored` check: try
  `deferred_releases.remove(block_number)`. If found, use offset as `OwnStale`.

**`space.rs`**:
- In `find_and_unanchor_in_memory_inner()`: add code to clear old block's
  `file_megabyte` in the returned block number. The caller (`allocate_space`)
  must write the old block's BAT page to cache.
- Remove `soft_anchored_in_memory_bat_page_number` and
  `soft_anchored_in_memory_block_count` fields (unused scaffolding).
- Remove stale comments about "accepting all soft-anchored blocks."

**`open.rs` (allocate_space)**:
- After `try_allocate_with_bat` returns a cross-block reclaim result (new return
  variant carrying old block number): clear old block's `file_megabyte` in
  `BatState`, write old block's BAT page to cache.

### Open-Time Validation

During BAT parse, after processing all blocks: verify that no allocated block
(FullyPresent/PartiallyPresent) shares a file offset with any soft-anchored
block. If overlap is found, treat as corruption or silently drop the anchor.

### Tests

1. **Trim-write-crash (same block)**: Trim A with FileSpace, write A again
   (same-block reclaim), crash before flush. Verify A has original data or is
   allocated — no corruption.

2. **Trim-write-crash (cross block)**: Trim A with FileSpace, exhaust pool+EOF,
   write B (forces priority-3 reclaim of A's space), crash before flush. Verify
   A still owns offset X on reopen — no teleportation.

3. **Trim-flush-write (cross block)**: Trim A with FileSpace, flush (makes trim
   durable), write B using A's reclaimed space, flush. Verify B owns X, A does
   not.

4. **Deferred quota triggers flush**: Trim 1025 blocks without flushing. Verify
   flush is triggered at the quota boundary and space becomes available.

5. **Open-time overlap rejection**: Construct image with two BAT entries pointing
   at same offset. Verify open fails or drops one.
