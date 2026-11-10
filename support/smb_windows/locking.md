# Windows Host-Backed Lock Design

Status: proposed design; provider lock support is not implemented or enabled.
Native assumptions below were checked on ARM64 Windows `ge_release`,
build 26300.9818, on 2026-11-09.

## Required Semantics

Follow the specified lock and I/O conflict rules, including shared locks over
an exclusive lock owned by the same open/key:

- [MS-FSA 2.1.4.10: range conflicts](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/124bb289-eeef-4653-b9c6-4fb93dd07a21).
- [MS-FSA 2.1.5.8: acquisition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/369103ec-a8af-452b-8006-aff07b925b61).
- [MS-FSA 2.1.5.9: ordinary unlock](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/84e68de6-31a6-4cba-afd4-00b1bac6d1a2).
- [MS-SMB2 3.3.5.14.2: processing lock arrays](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/670c7eda-e683-4923-9477-414303959613).

Ordinary unlock prefers an exact exclusive match. That is different from
rolling back acquisitions made by the current request. A later immediate
conflict must not cause rollback to release a lock held before the request.

Lock arrays are not general all-or-nothing transactions. In particular, an
invalid later element preserves the successfully processed prefix. Keep
protocol validation and the decision to preserve or roll back that prefix
explicit; do not make a generic transaction destructor choose silently.

No common native-SMB/vSMB erratum has been established as justification for
weakening this contract. This design does not depend on one.

## Native Facts and Rejected Shortcuts

The [native tests](src/filesystem/tests.rs) establish:

- `native_lock_keys_and_overlapping_acquisitions`: an exclusive lock with key
  1 permits owner I/O with key 1, but not keys 0/2. An overlapping shared lock
  with key 2 fails; key 1 succeeds. Exact native unlock removes the exclusive
  lock first, leaving shared protection.
- `native_shared_backing_is_required_for_append_after_external_eof_change`:
  another open can move EOF into an exclusively locked range. Owner native
  append succeeds with only that exclusive lock, but fails once an overlapping
  native shared lock is present.
- `native_lock_boundaries_follow_unsigned_range_rules`: native acquisition,
  conflicts and unlock agree with the selected zero-length and unsigned
  64-bit boundary cases.

Consequently, do not implement acquisition rollback as ordinary range-unlock.
Unique acquisition keys do not solve the overlapping shared case. Do not
release and reacquire an older exclusive lock, reopen a hidden data handle,
or infer append safety from an earlier EOF query.

## Request Scope, Rather Than Unbounded Rollback Tokens

The proposed canonical provider operation owns a complete lock request scope.
It supports acquisition, ordinary unlock, preserving the processed prefix,
and rolling back only that scope's acquisitions.

The protocol engine still owns packet validation and settlement policy:

1. Validate the envelope and multi-lock fail-immediately requirement before
   effects, as today.
2. Process elements in order.
3. On the specified immediate-conflict path, roll back this request's prefix.
4. On an invalid later element, preserve the successful prefix and return the
   validation error. Unlock arrays likewise retain earlier successful unlocks.
5. Propagate other failures explicitly, retaining the existing error-class
   settlement policy unless a normative requirement establishes otherwise.

This boundary tells the backend when rollback of tentative acquisitions ends.
It is not a claim that the existing API cannot express correct behavior.
Rather, it supplies the lifecycle information required by this staging design.

Software providers can initially use a default scope adapter around their
existing acquisition IDs. Their ownership, I/O and rollback behavior must not
change. Native support overrides the scoped operation; do not pretend its
legacy per-acquisition rollback hook works for arbitrary committed locks.
No tentative native token escapes the scope after settlement.

## Logical Ledger and Native Backing

Maintain per-open logical acquisitions with unique IDs. Group exact ranges by
offset/length and track shared/exclusive logical counts and actual native
backing separately. Use the original native file object and one owner key for
its locks and I/O. Do not change access grants or sharing reservations.

Identical locks of one kind can share native backing: their protection is the
same, while the logical ledger retains individual acquisition identities.
Validate each acquisition against the logical conflict rules before reusing
backing; coalescing must never make an otherwise conflicting acquisition succeed.
Ordinary unlock removes one logical exact match, preferring exclusive matches,
and releases native backing only when that kind no longer has logical owners.
Use the specified range-overlap rules; zero-length locks must not be treated
as ordinary nonempty intervals or assumed to forbid duplicate exclusive locks.

For a new shared acquisition:

- If committed shared backing already exists, add only a logical acquisition.
- If an exact exclusive backing exists without shared backing, stage the new
  shared acquisition logically, without a native shared-lock call.
- Otherwise, acquire native shared backing normally and journal that effect.

The staged case is safe against other opens: the existing native exclusive
lock already provides protection at least as strong as shared backing would.
It is not yet safe for the owner's writes, so those writes must be excluded
until the request settles.

On rollback, remove only this scope's logical additions and undo its new native
effects in reverse order. A staged shared acquisition has no native effect to
undo. Removing a new physical shared backing is safe only when no exact
exclusive backing can be selected instead; old exclusive backing would have
selected the staging case, and later tentative exclusive effects are undone
first. These conditions must be checked by the ledger, not inferred from a
successful native unlock.

## Commit and Backing Realization

Preserving a prefix or completing a request commits its logical acquisitions.
A committed shared acquisition may still be covered by an exact native
exclusive lock without separate native shared backing.

Before admitting an owner data write, including append, realize the committed
shared backing using the same native key. Likewise, realize it before releasing
the last exact exclusive backing. Install shared backing before unlocking the
exclusive lock, so foreign I/O never sees an unprotected interval.

Backing realization can fail. Return that native error before the dependent
write or unlock has effects; retain the logical acquisitions and existing
exclusive protection. Partial realization of already committed groups is not
rolled back as if it were tentative request work. Never report success while
silently leaving a required write check unenforced.

This avoids the external-EOF race: owner append is checked by the filesystem
against actual native shared backing at its actual append offset, not against
a stale offset sampled by the provider.

## Admission and Waiting

An immediate lock-array scope must exclude concurrent owner I/O and lock-table
mutation while tentative acquisitions exist. Drain already admitted operations
and retain admission guards through actual native completion, not merely until
an awaiting future is dropped. Keep synchronous state locks short; never await
while holding them.

Do not hold such an exclusion gate across a contended native lock wait. That
could prevent a concurrent same-open unlock from releasing the lock needed for
progress.

The initial design instead implements a logical waiting request using bounded,
fail-immediately native attempts:

1. Enter admission, validate current state and issue one nonblocking attempt.
2. Retain its exact future and storage until the actual result settles, even
   if a filter makes the attempt asynchronous.
3. On contention, release admission and wait on provider changes, cancellation,
   or an asynchronous retry timer for external host unlocks.
4. Revalidate and retry. A successful native acquisition wins over late
   cancellation; do not claim cancellation undid it.

Only a single-element request may wait under the selected protocol rules, so
no tentative prefix needs to survive a contention wait. Use bounded waiter
storage and bounded/backed-off retry frequency, not spinning or one blocked
thread per waiter. This trades kernel-wait efficiency and immediate external
unlock notification for simpler, auditable ownership. It does not promise FIFO
lock acquisition, which is not the notification FIFO guarantee.

Pause retains the accepted logical future and any in-flight native attempt.
It must not cancel/replay work merely because the VM stopped. Destructive
shutdown cancels and drains; fallback file drop releases native locks.

If software caching is added later, complete required breaks before entering
an exclusion interval that could block a client's flush, then revalidate.
Byte-range admission must not deadlock cache-break acknowledgments.

## Safety Arguments

- **Rollback identity:** tentative additions have scope-local identities.
  Staged shared additions do not create an ambiguous native unlock.
- **Foreign I/O:** every committed logical restriction has native backing or
  is covered by a stronger existing native exclusive lock.
- **Owner I/O:** no write passes an unrealized shared restriction. Native
  append remains atomic and enforces the real destination range.
- **Unlock:** dropping exclusive protection installs required shared backing
  first. Duplicate logical acquisitions do not remove another acquisition's
  protection.
- **Waiting:** contended requests hold no exclusion gate needed by unlocks or
  unrelated requests, and cancellation waits for actual native outcomes.
- **Lifetime:** request settlement, I/O guards, buffers and handles remain
  owned through completion. Closing does not fabricate successful rollback.

Host-backed protection has the scope of native Windows byte-range locks. It
does not claim to prohibit external EOF changes or memory-mapped mutation
that the native filesystem itself permits.

## Implementation and Validation Gate

This is not yet a completed adapter. Before enabling it:

- Introduce the scoped provider operation and default software adapter;
  explicitly delegate it through instrumentation wrappers.
- Migrate direct provider contracts to test request outcomes, including failed
  arrays preserving an older exclusive lock.
- Implement the native ledger, realization and I/O admission together.
- Test repeated shared acquisitions, mixed exact groups, zero-length ranges,
  aliases, unsigned boundaries and exclusive-preferred ordinary unlock.
- Test rollback after every acquisition point, invalid later elements,
  resource/cleanup failures and commit-prefix outcomes.
- Test owner/foreign reads and writes, append with external EOF changes,
  and realization failure without data or unlock effects.
- Test same-open unlock and unrelated requests progressing while another lock
  waits; cancellation before admission, during an attempt and after grant.
- Test close/drop, waiter limits, transient stop retention and destructive
  cancel-and-drain. A batching API alone does not establish these properties.

Only after those checks pass should the shared synthetic coordinator be
extracted for Linux and Windows. That layer should reuse the admission and
identity concepts, while preserving the explicit distinction between native
host enforcement and the guest-exclusive mutation-ownership promise.
