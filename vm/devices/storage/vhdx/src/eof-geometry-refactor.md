# Refactor: Split FreeSpaceInner EOF Geometry from Bitmap State

## Context

The `FreeSpaceTracker` in `space.rs` has a single `parking_lot::Mutex<FreeSpaceInner>`
protecting all state. But some fields are only ever mutated under the
`allocation_lock` (the async `futures::lock::Mutex<()>` on `VhdxFile` that
serializes the allocate→TFP→write sequence). The sync mutex is redundant for
those fields — they're already exclusively accessed.

## What to move

These fields should move out of `FreeSpaceInner` and onto `VhdxFile` (or into
a dedicated struct on `VhdxFile`), protected only by the `allocation_lock`:

- `file_length: u64` — current file length (MB1-aligned)
- `zero_offset: u64` — offset beyond which file contents are guaranteed zero
- `last_file_offset: u64` — highest in-use file offset
- `eof_extension_length: u32` — minimum chunk for EOF extension (constant after init)

These are "EOF geometry" — they describe where new space comes from.

## What stays in FreeSpaceInner

These fields remain in `FreeSpaceInner` behind the sync mutex because they're
accessed from `release()`, `mark_trimmed_block()`, and `unmark_trimmed_block()`,
which are called from `abort_write_sync()`, `flush()`, and `trim()` — none of
which hold the allocation lock:

- `free_space: FreeSpacePool` (bitmap + `lowest_bit_hint` + `no_free_blocks`)
- `anchored_space: AnchoredSpacePool` (bitmap + `lowest_bit_hint`)
- `trimmed_blocks: TrimmedBlockTracker` (bitmap + hint + count)
- `block_size: u32` (read-only after init, but needed by bitmap callers)
- `block_alignment: u32` (read-only after init)
- `data_block_count: u32` (read-only after init)

## How to do it

1. Create an `EofState` struct with the four fields above.
2. Add `eof_state: EofState` as a field on `VhdxFile` (no mutex — protected by
   `allocation_lock`). Or if you want it near the free space tracker, put it on
   `FreeSpaceTracker` as a non-mutex field with `&mut` access.
3. Change `try_allocate_inner` to take the EOF fields as parameters instead of
   reading them from `inner`. The function already takes `&mut FreeSpaceInner`
   — add `eof: &mut EofState`.
4. Change `allocate_space` (which holds `allocation_lock`) to pass `&mut eof_state`
   into the tracker methods.
5. `complete_file_extend` and `required_file_length` become methods on `EofState`
   (or take `&mut EofState`), not on `FreeSpaceTracker`.
6. `FreeSpaceTracker::new()` returns both the tracker and the initial `EofState`.
7. `complete_initialization` needs to move `zero_offset` — it touches both EOF
   geometry (sets `zero_offset`) and bitmaps (clears near-EOF bits). Split into
   two calls or pass both.
8. Update `apply_truncate` (currently unused in production) to take `&mut EofState`.
   Truncation should acquire `allocation_lock`.
9. The `#[cfg(test)]` accessors `file_length()` and `zero_offset()` move to
   `EofState`.

## Testing

All 387 existing tests should pass unchanged — this is a pure refactor with no
behavioral change. The sync mutex still protects bitmap operations; the async
lock still serializes allocation sequences. The only difference is that EOF
geometry reads/writes no longer acquire the sync mutex.

## Why bother

- Reduces sync mutex contention: `release()` from abort/flush doesn't need to
  wait for an allocation sequence that's reading `file_length`.
- Makes the locking design honest: the code documents `allocation_lock` as the
  serializer for allocation, but today the sync mutex is doing redundant work
  for fields that are already serialized by it.
- Simplifies reasoning: "EOF geometry is allocation-lock state" is a clearer
  invariant than "everything is behind one mutex but some fields are also
  behind another lock."
