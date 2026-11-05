# Synthetic SMB Core

This crate implements an initial SMB 2.1 core with no VM or host-filesystem
dependencies. A provider interface separates protocol state from a bounded,
writable in-memory filesystem. It is not yet a complete SMB or vSMB server.

The TCP frontend is for testing only. Sessions are unsigned guests; a minimal
raw NTLM token exchange accommodates test clients without authenticating or
verifying credentials. This must not be used as a network authentication
service. The example binds only to loopback.

## Run

```bash
cargo run -p smb --example smb_server -- 127.0.0.1:1445
```

The share is named `memory`; all file data disappears when the process exits.
It has a 16 MiB data quota and a 4096-object limit.

## Tests

```bash
cargo nextest run --profile agent -p smb
cargo nextest run --profile agent -p smb --run-ignored only \
    -E 'test(samba_read_write_smoke)'
cargo nextest run --profile agent -p smb --features test-support --run-ignored only \
    -E 'test(samba_gated_async_compounds)'
cargo nextest run --profile agent -p smb --run-ignored only -E 'test(samba_notify)'
cargo nextest run --profile agent -p smb --run-ignored only -E 'test(samba_lock)'
cargo nextest run --profile agent -p smb --run-ignored only -E 'test(samba_rename)'
SMBTORTURE=/path/to/corrected/smbtorture \
    cargo nextest run --profile agent -p smb --run-ignored only \
    -E 'test(samba_notify_corrected_client)'
```

The ignored test requires `smbtorture` (Ubuntu package `samba-testsuite`),
starts its own server on an ephemeral loopback port, and shuts it down on
completion. It checks connection and tree isolation, multi-client read/write data integrity,
EOF/short reads, Windows-style position semantics, directory-read behavior,
per-open read rights, CREATE/open fixtures, and mkdir semantics. Unit tests drive the core directly and cover
sharing, deletion, quotas, malformed requests, and fragmented TCP frames.
The harness also checks compound CREATE/write/close, invalid inherited file
identity, and related/unrelated directory continuation.
The feature-enabled async harness gates real provider reads, writes, and
flushes on the server's poller. Its four async compound cases include READ/WRITE
checks requiring pending replies, rather than only allowing synchronous fallback.
The notify harness covers CLOSE, TREE_DISCONNECT, LOGOFF, ordinary-file rejection,
handle permissions, and excluding changes to the watched directory itself.
The lock harness runs seventeen cases covering shared/exclusive I/O enforcement,
conflicts, pending acquisition, exact unlocks, stacking, zero-length/64-bit
ranges, cross-connection ownership, arrays, and truncation.
The rename harness covers seven cases: simple, modification-time preservation,
missing DELETE access, source sharing, destination-directory sharing, and
rejecting directory renames with open descendants.
`SMBTORTURE` selects the executable for every harness; otherwise they use
`smbtorture` from PATH. The corrected-client harness requires that variable
explicitly and adds eleven notify cases: tcon, dir, tdis, double, tcp, overflow,
rmdir1-4, and rec. It uses ten operations because the directory fixture assumes that
count and has a fixed 1000-byte output buffer.

### Direct Provider Contracts

`test_support::contracts` exports generic async scenarios behind `test-support`
(also enabled for this crate's unit tests). MemoryFs runs each scenario as an
individually named `memory::tests::contract_*` test, without an SMB server:

```bash
cargo nextest run --profile agent -p smb -E 'test(contract_)'
cargo nextest run --profile agent -p smb --features test-support \
    --test provider_contracts
```

Provider crates should enable that feature as a dev-dependency, implement
`contracts::Fixture`, and register the same scenario functions as separate
tests on their own executor. Each invocation needs a fresh, empty, isolated,
writable filesystem; the fixture owns any native driver and temporary resources.
Declare basic-information, rename, locking, and notification expectations explicitly.
Unexpected unsupported errors fail; an unsupported profile exercises rejection
rather than silently skipping a test. These are test expectations, not runtime
SMB capability advertisement. Read-only providers will need separate scenarios
that do not assume successful creation or mutation.

The fixture's `wait_until_pending` hook must observe an actual registered watch
or contended lock wait. A first pending poll or worker-queue submission is not
sufficient for an asynchronously registering provider. The scenarios keep
driving the operation while awaiting that hook, then cancel or mutate the
filesystem deterministically. Cancellation is initiated inside the shared
scenarios; `RequestContext` does not expose a new production cancellation API.
See [the external-crate tests](tests/provider_contracts.rs) for API usage,
explicit rejection checks, short transfers, and delayed-registration scheduling.
Their controlled wrappers validate the test infrastructure, not native I/O.

The common cases check observable data and stable identity, directory listings,
zero extension/truncation, bilateral sharing and close/drop release, basic DOS
attributes, rename identity/replacement/sharing/notifications,
deferred delete modes versus shared disposition and nonempty-directory closes,
lock conflicts/I/O enforcement/waits/rollback, and watch policy,
buffering/FIFO/cancellation/subtrees/deletion generations. They permit genuine
short transfers and do not prescribe exact quotas, short names, or clock
precision. Keep provider-specific tests for those policies, native completion
ownership/cancellation, timestamp controls, resource bounds, and durability.
SMB access checks, per-open request barriers, CLOSE cancel/drain, transient
stop, and wire/transport behavior remain engine/runtime tests.

## Protocol Representation

`spec::{smb2, fscc, ntlm, tcp}` contains public-specification layouts and named
values, with section references at their declarations. It contains no server
policy or filesystem operations. Fixed layouts use zerocopy endian wrappers;
embedded bitfield types derive zerocopy and use alignment-one little-endian
storage, including inside directory records. Unknown enum values and flag bits
remain representable for explicit validation by the engine.

Each SMB body declares its specified `StructureSize` separately from its Rust
layout size, checked at compile time. The private `codec` module bounds-checks
header-relative fields against those layouts and validates linked CREATE
contexts. Handlers encode named response structures rather than individual
byte offsets. Implementation limits live outside `spec`.

Independent byte fixtures verify unaligned embedded bitfields, all six supported
directory layouts (with and without short names), and actual CREATE context,
QUERY_INFO, and READ replies. Literal offsets in these fixtures are deliberate
independent expectations, not production packet-access logic.

## Runtime and Backend Contract

`tcp::Server::new(driver, listener, share)` creates a stopped service on the
caller's executor. `start()` runs it; `stop().await` pauses without disconnecting
clients or draining backend I/O. A subsequent `start()` resumes the same
requests, partial frames, and response offsets. `shutdown().await` is destructive:
it requests cancellation, drives outstanding operations to completion, and
explicitly closes opens without waiting for clients to read responses. Drive
shutdown to completion before dropping a service with outstanding work.

Connections can have up to 32 outstanding command descriptors, 32 executing
transport frames, and two bounded 32-frame response queues (publication and
transmit), plus one
bounded receive frame for intake and cancellation. Frames and transfers are
size-limited. Ready processing is batched so stop and inspection can interrupt
continuous traffic. The service creates no executor or per-request threads.

Server/provider state, connections, opens, active requests, cancellation state,
transport progress, response queues, and quotas implement `inspect::Inspect`.
Inspection does not read file contents or wait for provider I/O.

All provider operations are async and receive a `RequestContext` carrying a
server-wide operation ID and cooperative cancellation notification. Operations
may overlap on one open. The provider reports whether cancellation actually
succeeded; a completed write is not relabeled as cancelled. Normal reads/writes
can overlap, while flush, supported mutations, and directory cursor operations
are ordered against earlier operations on the same open.

CLOSE prevents new use of its FileId, requests cancellation of earlier work,
and waits asynchronously for uncancellable work before provider close.
Explicit provider close releases sharing/delete-on-close state; `Drop` remains
fallback cleanup. A failed shutdown close stays inspectable and can be retried.

`Connection::request` admits an owned request synchronously; retain its
execution future until completion. `execute()` returns final replies only;
`execute_with_interim(sender)` publishes interim and final frames through a
caller-supplied channel that must be received concurrently. TCP uses the latter
with bounded publication. Closed receivers trigger cancellation while already
executing backend work is still drained. Discarding accepted work disconnects
the connection; consumed message IDs are never refunded or reissued.
`Connection::cancel` handles MessageId or AsyncId CANCEL without
a response or credit consumption. `tcp::ConnectionTask` provides persistent
framing/operation state for `TaskControl`; the direct `process`/`serve` convenience
futures are not pause-safe when dropped.

## Compound Requests

The core validates the complete bounded header chain before admitting any work.
It supports related and unrelated compounds, with at most 32 commands per frame
and 32 active command descriptors per connection. Every command has its own
message ID, cancellation context, credit charge, and inspectable queued/activated
state. Credit admission is atomic across the frame; payload/response credit
charges use the 64 KiB units in MS-SMB2 sections 3.1.5.2 and 3.3.5.2.5.

Commands within a frame run in order. Related commands inherit session/tree/file
identities from the previous operation or its response, ignoring replacement
IDs supplied in later requests. Missing dependencies and previous operation
failures follow section 3.3.5.2.7.2; unrelated commands have independent outcomes.
Variable-buffer offsets are bounded to each individual command, not the whole
transport frame. Synchronous replies form ordered, eight-byte-aligned chains.

Queued operations remain owned and cancellable across pause. Known-open queued
I/O participates in per-open barriers. Barrier order follows binding to the open,
not allocation of a deferred compound's operation IDs. CLOSE/teardown removes
later unstarted work in its own chain from the drain set without discarding its
reply descriptors, so it cannot wait on commands that depend on its completion.

In wire mode, the first pending command flushes the synchronous prefix and
receives STATUS_PENDING with a nonzero AsyncId. File-bearing related dependents
also receive early pending identities so they can be canceled before execution.
Final asynchronous replies carry matching AsyncIds and no further credits.
Logical session/tree identities remain available for inheritance even though
the async header replaces the TreeId fields.

The credit sequence window starts at message ID zero. Admission atomically
consumes all declared ranges, permits out-of-order use, and rejects ungranted,
replayed, overlapping, or overflowing IDs. Grants only extend the monotonically
increasing window; pending requests receive credits exactly once, in the interim.
TCP answers otherwise valid requests exceeding the active-descriptor limit
with STATUS_INSUFFICIENT_RESOURCES, consuming their IDs and returning credits
without provider effects. It does not leave them blocking subsequent CANCEL.
CHANGE_NOTIFY is supported as the last command of a compound, including inheritance
from CREATE. A non-tail CHANGE_NOTIFY returns STATUS_NOT_SUPPORTED rather than
stranding later commands behind an indefinite wait; MS-SMB2 section 3.3.5.2.7
allows rejecting asynchronous compound operations. Immediate LOCK operations
can precede other compound commands. Waiting LOCK operations are supported only
at the tail, using the same non-tail rejection policy. IOCTL remains unsupported.

The full Samba compound suite is not claimed to pass. The installed 4.19.5
`related1` probe crashed in client session-cloning setup. `related6` expects
continued I/O after an access failure; the core retains the specification's
recommended error propagation. Mixed-style `invalid3` and unknown-command
`invalid4` fixtures expect behavior different from the normative validation rules.
`compound_find_close` requests 128 credits and creates 5000 objects, outside this
test server's 32-credit/4096-object profile. None are counted as passing coverage.

## Directory Change Notifications

CHANGE_NOTIFY follows MS-SMB2 sections 3.3.1.3 and 3.3.5.19, MS-FSA sections
2.1.5.11/11.1, and MS-FSCC section 2.7.1. The first provider registration fixes
the filter and subtree policy while that registration exists, including when
its first waiter was already canceled. Unknown filter bits are ignored; an
empty filter waits for cancellation or close.

The memory provider registers and records actual filesystem changes under the
same lock, without an unmonitored gap. It retains changes between requests,
reports relative UTF-16 names and aligned linked records, and completes waiters
FIFO. Notifications have their own ordering queue, not a data/mutation barrier.
Normal I/O and metadata operations still progress; CLOSE cancels/drains watchers
and returns STATUS_NOTIFY_CLEANUP for canceled notifications.

Marking a directory for deletion completes its pending watches with
DELETE_PENDING and releases their registrations (MS-FSA 2.1.5.15.3).
Registration identities keep those completions distinct from any later watch
after disposition is cleared. The deleting open retains its own deletion marker;
closing a directory opened delete-on-close also completes other opens' watches.

Each watch retains up to 64 KiB of encoded events. The provider permits 1024
watches and 32 backend waiters per open; the core's existing request limit also
applies. These limits, watch policies, queued counts/bytes, overflow state, and
waiters are inspectable. A too-small output buffer gets STATUS_NOTIFY_ENUM_DIR
without partially consuming the batch. Actual storage overflow discards the
lost batch, reports re-enumeration, and resumes buffering afterward.

Canceling a waiter leaves the registration and unconsumed events intact.
Obtained results survive late cancellation, including controlled delayed delivery.
Pausing preserves watches, incoming changes, AsyncIds, and partial output. If a
response receiver closes after an interim, the executor cancels and drains its
still-waiting operation instead of leaking an indefinitely pending watch.

Deterministic regressions exercise registration/cancel/event ordering, backward
polling and FIFO, queued AsyncId cancellation, late results and close, subtree and
per-open policy, real mutation filters, overflow/recovery, resource release,
compound boundaries, paused delivery, full queues, and blocked-output shutdown.
Independent literal bytes check single and linked notification records. No sleeps
are used to arrange these interleavings.

Not all installed Samba 4.19.5 notify cases are applicable. Probes such as
`smb2.notify.double` send a synchronous CANCEL with MessageId zero before receiving
an interim, rather than the pending request's ID, and then wait indefinitely.
That unmatched CANCEL must be ignored, not treated as "cancel any request".
Its behavior is covered by a direct negative regression; those probes are not
counted as passes with the installed client.

The same mismatch was reproduced with unmodified Samba 4.25.1, including against
Samba's own server when pinned to SMB 2.1. SMB 3.1.1 defaults negotiate AES-GMAC
and pass; forcing AES-CMAC reproduces the failure. The legacy client path sets
MID zero too early, even when no AsyncId has been received. A corrected local
client keeps the real MID and applies the legacy zero convention only when
sending an asynchronous CANCEL. The ten-case harness above requires that fix;
our server does not weaken cancellation identity matching. Reference comparisons
with the corrected client pass in all three signing profiles.

The recursive (`rec`) fixture now passes. The mask-change probe gets past its
former deletion failure but still waits for separate attribute notifications;
it is not counted as passing coverage.
Tree uses dot-component paths rejected by the current namespace policy, and
valid-req assumes specific native event batching and notification-buffer policy.
The slow mask probe permits cancellation for many subcases and does not establish
complete notification compatibility.

## Rename and Move

SET_INFO FileRenameInformation follows MS-FSCC section 2.4.42.2 and MS-FSA
section 2.1.5.15.12. Its typed prefix is 20 bytes; the complete input must be
at least 24 bytes. Reserved bytes and padding are ignored, the UTF-16 name is
length-bounded, RootDirectory must be zero, and destinations are share-relative.
DELETE access is checked by the engine before calling the provider. Extended
rename flags, hard links and stream rename remain unsupported.

The provider atomically validates and updates the namespace, preserving the
source's data, identity, opens, and byte-range locks. Existing target names
require replacement permission; open targets, directory targets, readonly
targets, and directory sources with open descendants are denied. Destination
directory sharing is enforced, cycles are rejected, and an exact self-rename
is a no-op. The memory namespace keeps its existing ASCII-insensitive lookup
and dot-component rejection policy.

Same-directory changes report old/new name pairs; moves report removal/addition.
An exact-case replacement reports source removal and destination metadata change,
whereas a differently cased replacement also reports removal of the old target
name. Records are buffered under the namespace lock before waking observers,
including recursive watches and undersized-buffer retry. A watch on the renamed
directory itself stays registered. SET_INFO retains its ordinary I/O barrier;
CLOSE still cancels/drains pending operations and preserves already obtained
rename results rather than relabeling committed effects as cancelled.

The shared provider suite covers identity, moves, replacement failures, sharing,
closed subtrees and notification filtering. Wire tests additionally cover malformed
fields, independent literal layouts, related compounds, pending watches, and
before/after-effect cancellation. Provider-specific tests retain quota checks.
The selected Samba cases do not claim the entire rename or notify suite passes.

## Delete Mode and Disposition

MS-FSA sections 2.1.5.5 and 2.1.5.15.3 distinguish CREATE's per-open
FILE_DELETE_ON_CLOSE mode from the link's shared delete disposition.
Mode alone does not set Metadata.delete_pending or block other opens.
At close it marks a file deleted, or marks a directory deleted only if empty
at that time. Opening a nonempty directory with this mode is allowed; closing
it leaves that directory intact rather than returning DIRECTORY_NOT_EMPTY.
A directory may also gain children after a mode-bearing open.

Explicit disposition remains shared, reversible through another open, and
rejects nonempty directories. Pending child links still count as directory
entries until their last open closes. A retained handle can continue using
the object and clear its disposition; there is no separate irreversible
"committed delete" flag. Clearing disposition does not clear an open's mode.
Links, data, and quota are released only at actual final deletion.

A mode-bearing directory open has its own notify-deleted marker, but closing
it while nonempty must not invalidate watches on other opens. The inspector
reports delete_on_close_opens separately from node delete_pending state.
The frontend's CLOSE cancellation and draining behavior is unchanged.

## Byte-Range Locks

LOCK follows MS-SMB2 sections 2.2.26/27 and 3.3.5.14, and MS-FSA sections
2.1.4.10 and 2.1.5.8/9. Locks belong to provider opens, not connections or
client process IDs. Shared locks permit reads and shared acquisitions but block
all writes, including the owner's. Exclusive locks permit the owner's I/O but
block other opens and overlapping exclusive acquisitions by the same owner.
Ranges may extend beyond EOF, including zero-length ranges and offsets over
the complete unsigned 64-bit range. Overflowing nonempty ranges are rejected.

Contended immediate requests return LOCK_NOT_GRANTED; conflicting I/O returns
FILE_LOCK_CONFLICT. Waiting requests receive AsyncIds, honor CANCEL, survive
pause/resume, and do not block UNLOCK or I/O barriers. Unlock removes one exact
range, preferring an exclusive match when locks are stacked. A conflicting
immediate array rolls back only its own acquisitions, using provider-issued
identities rather than range-based unlocks that could remove older locks.
Successfully processed unlocks and prefixes preceding invalid flags are not
rolled back. LockSequence replay suppression is not active for this SMB 2.1
profile without resilient/durable/persistent handles or multichannel.

The memory provider bounds the share to 4096 acquired locks and 1024 waiting
provider operations, in addition to the core's 32-request connection limit.
Counts, limits, ownership and ranges are inspectable. Cancellation releases waiter
resources; close/drop releases all locks belonging to that open. CLOSE retains
its existing cancel-and-drain policy, and late acquired results remain successful.

The seventeen-case Samba harness excludes `smb2.lock.cancel`, `cancel-tdis`,
and `cancel-logoff`: the basic CANCEL portions work, but those fixtures require
RANGE_NOT_LOCKED (or success during tree/logoff close ordering) where this
server's cancellation policy returns CANCELLED. These are recorded mismatches,
not passing coverage or a reason to change CLOSE. Direct regressions cover
explicit MessageId/AsyncId cancellation, full admission, close/drain, rollback,
quotas, literal wire fields, compound boundaries, and paused TCP delivery.

Clean TCP EOF now requests cancellation and closes provider opens after accepted
work drains, independently of transmitting remaining replies. Existing replies
are still delivered to a half-closed peer; a malformed/truncated transport
discards them. The explicit cancel-and-drain teardown contract is unchanged;
uncancellable operations can delay cleanup, and saturated clean-EOF publication
remains a known limitation.

## Controlled Provider Tests

The optional `test-support` feature exposes `test_support::ControlledFs<B>`.
It wraps any real provider; it does not add timing branches or fabricated
filesystem results to `MemoryFs`. Unit tests have this support available
automatically, and integration tests can enable the feature.

Its `Controller` configures operation defaults or one-shot plans. Each call
gets a unique token distinct from its request context ID. A plan can hold the
call before invoking the provider, or retain its actual result after invocation
until the controller releases that particular gate. Gates use events, not sleeps.
Held calls are announced by `next_call`; `snapshot` and `wait_for_phase` expose
their progress. Pending calls, cancellation observations, queues, and recent
history are inspectable without retaining file contents.

Cancellation can be cooperative or suppressed to model uncancellable I/O.
Obtained results are never relabeled when cancellation arrives late. Fault
injection fails before delegation. Transfer limits shorten the actual delegated
read/write, so file contents and reported counts agree.
Notify cancellation still establishes the open's persistent registration, even
when it interrupts a before gate; it cancels the waiter, not the watch.

Active calls, announcements, and queued plans are bounded at 256 each. Recent
terminal history retains 256 calls; ordinary passthrough calls need no controller
consumer. Dropping an unfinished call records `Abandoned`, not successful
completion or acknowledged cancellation.

The tests cover all provider operations, independent completion ordering,
committed writes with concurrent close/pause, partial transfers, real failure
effects, cancellation during nested delegate execution, and controller errors.
With the feature enabled, the ordinary Samba harness uses the controlled wrapper
in passthrough mode; a second harness releases individual before-execution gates
for async compound interoperability.

## Current Limits

Supported commands are NEGOTIATE, SESSION_SETUP, LOGOFF, TREE_CONNECT,
TREE_DISCONNECT, CREATE, CLOSE, FLUSH, READ, WRITE, LOCK, QUERY_DIRECTORY, CHANGE_NOTIFY, and a
subset of QUERY_INFO/SET_INFO, plus ECHO. CREATE validates linked context
containers and returns maximal-access (`MxAc`) and on-disk-ID (`QFid`) responses.
Unsupported preallocation, durable-handle requests, and leases are explicitly
declined without response contexts. EA creation returns `STATUS_EAS_NOT_SUPPORTED`;
security descriptors and snapshots remain unsupported.

Basic-information updates support DOS attributes and per-open timestamp
controls, including zero/no-change and -1/-2 automatic-update suppression/reset.
Alternate-name queries use optional provider short names; the memory provider
does not generate 8.3 aliases.

Non-default streams, Unicode
case-folding, rename, ACL updates, leases, and IOCTLs
remain future work. Unsupported requests receive explicit status errors.
Memory is allocated for file holes; this is not a sparse-filesystem model.

Full filesystem- and dialect-specific torture suites are not expected to
pass yet. For example, `smb2.rw.invalid` includes a particular filesystem
maximum-file-size expectation, whereas this provider reports quota
exhaustion without emulating that filesystem's limit.

Protocol layouts and behavior are independently implemented from the public
MS-SMB2, MS-FSCC, and MS-ERREF specifications. VMBus and host-backed providers
are intentionally deferred.
