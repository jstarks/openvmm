# Windows Host-Backed Lock Design

Status: implemented library adapter and Windows device/CLI wiring; both modes
pass Windows 11 Enterprise ARM64 guest lifecycle validation on an ARM64 Windows
host. This is not Server 2025 guest coverage. The native mode's legacy
acquisition-token API is unsupported;
use `FileSystem::lock_request` and explicit `LockScope::settle`.
Native assumptions below were checked on ARM64 Windows `ge_release`,
build 26300.9818, on 2026-11-09.

## Enforcement Modes

`WindowsFs::new` uses `LockMode::Native`. `new_with_lock_mode` can explicitly
select `LockMode::Synthetic`; errors never switch modes automatically.
Synthetic locking uses the
[shared coordinator](../smb/src/provider/locking/software.rs), also used by
Linux, rather than installing kernel locks. All guest access must share one
provider instance, and the host promises not to mutate the backing files
outside the SMB server. Independent providers and host readers bypass its
logical byte locks. Native sharing, access decisions and notifications remain
native. Neither mode grants guest caching.

Synthetic I/O retains its software admission guard in the actual native
operation's owned buffer/worker state. Append samples EOF only under cooperating
write/EOF exclusion. EOF/allocation changes join that exclusion without adding
byte-lock denials that their MS-FSA algorithms do not require:
[FileEndOfFileInformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/5555bcb6-bc29-4f8a-900c-e469b792faab)
and [FileAllocationInformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/3820daf2-e512-4730-8cce-2d0435ae6ad2).

A destructive native open can change EOF before its identity is returned.
Reserve bounded software-owner capacity first, then fence and drain admitted
writes across the store while the original `NtCreateFile` executes. Bind the
returned identity before publishing the open. This briefly defers writes to
other files during destructive opens, but ordinary writes remain concurrent.
It preserves native atomic access/sharing decisions without a speculative
pathname lookup or emulating supersede with extra write permissions.

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

The canonical provider operation owns a complete lock request scope.
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

Software providers use a default scope adapter around their
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

The implementation briefly takes the ledger gate to admit I/O and then retains
a completion-owned active-operation guard. Ordinary reads/writes may overlap.
A lock scope retains the gate and drains active operations before changing
locks. Native data buffers retain both that active guard and the native open.
Native lock/unlock attempts and ledger updates run together on bounded workers,
which retain the ledger gate even if an awaiting future is dropped.

Do not hold such an exclusion gate across a contended native lock wait. That
could prevent a concurrent same-open unlock from releasing the lock needed for
progress.

The adapter implements a logical waiting request using bounded,
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

## Implementation and Validation

The library adapter and default software adapter are implemented. Direct
contracts and focused native regressions cover:

- Instrumentation delegation without falling back to unsupported legacy hooks.
- Shared/exclusive ownership and exact exclusive-preferred unlock.
- Mixed rollback at every acquisition prefix, preserving older exclusive locks.
- Repeated shared locks, hard-link aliases, empty and unsigned boundary ranges.
- Shared backing realization before owner append and last-exclusive unlock.
- Owner/foreign reads and writes, including externally changed EOF.
- Same-open unlock and flush progress while a lock waits, and retries after a
  host unlock that does not signal the provider.
- Cancellation before admission and after grant, retained unpolled attempts,
  and completion-owned ledger updates after an awaiter is dropped.
- Acquisition-capacity failure preserving its prefix, close recovering capacity,
  foreign-provider handle rejection, and injected scope-settlement failure.

The shared engine's wire tests separately cover invalid-element prefix
preservation, immediate-conflict rollback, partial unlocks, cancellation and
CLOSE draining. They are not native SMB/vSMB wire certification.

Remaining limits: actual NT backing-installation/unlock failures have not been
fault-injected (the settlement failure is at the provider wrapper). Error paths
retain existing ledger/backing before reporting the dependent write/unlock
failure; partial realization remains committed. Waiter-cap exhaustion and
filter-induced pending NT calls are not forced by these tests. Windows
production line coverage is unavailable. Actual VM pause/disconnect validation
still requires the Windows device integration; a retained library future does
not establish VM lifecycle behavior.

Shared synthetic coordination preserves the explicit distinction between native
host enforcement and the guest-exclusive mutation-ownership promise. Tests
exercise both Windows modes, hard-link aliases, append-only grants without
extra query rights, destructive-open admission and cancellation, and the
different enforcement visible to an independent host reader.
