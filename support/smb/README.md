# Synthetic SMB Core

This crate implements an initial SMB 2.1 core with no VM or host-filesystem
dependencies. A provider interface separates protocol state from a bounded,
writable in-memory filesystem. It is not yet a complete SMB or vSMB server.

The TCP frontend is for testing only. Sessions are unsigned guests; a minimal
raw NTLM token exchange accommodates test clients without authenticating or
verifying credentials. This must not be used as a network authentication
service. The example binds only to loopback.

## Compatibility Checklist

This is the current SMB 2.1, writable MemoryFs test profile, not a claim of
Windows guest compatibility. "Implemented" means the listed behavior has direct
tests; selected Samba cases provide additional independent evidence, not proof
that an entire suite passes. Provider-optional features must be rejected honestly
when unavailable. Their absence does not establish that a future vSMB guest
will not need them.

| Area | Required behavior in this profile | Evidence and remaining checks |
|------|-----------------------------------|-------------------------------|
| Sessions and trees | Guest setup, scoped trees, disconnect/logoff and cleanup | Implemented; `smb2.connect`, `smb2.tcon`, lifecycle regressions |
| CREATE and data I/O | Sharing, access grants, dispositions, EOF, short I/O, flush and close | Implemented; selected CREATE/read/write/mkdir cases and provider contracts |
| Compounds and credits | Bounded admission, inherited identities, error propagation, pending replies and cancellation | Implemented; selected compound/async cases; retain committed CLOSE and compound-tail policies |
| File metadata | Supported query classes, attributes/timestamps, allocation, EOF, mode and position | Implemented subset; broaden applicable getinfo/setinfo cases and classify unsupported-class dependencies |
| Volume metadata | Provider-owned identity, capacity and capability flags | Classes 1/3/4/5/7 implemented; broader fixtures may require quota/object-ID/sector classes outside this profile |
| Namespace and enumeration | Directory continuation, rename/move, sharing, replacement and deletion | Implemented subset; broaden directory/rename cases; no generated short names or hard links |
| Byte-range locks | Shared/exclusive conflicts, waiting, cancellation, unlock and release | Seventeen selected Samba cases and deterministic cross-open/connection tests; cancellation-status fixture differences remain documented |
| Change notifications | Persistent registration, filters, subtree events, buffering and cleanup | Seventeen selected Samba cases and deterministic contracts; `rec` has conflicting fixed-count expectations |
| Security | Basic descriptors, faithful grants, atomic updates, parent checks and creation inheritance | Four selected ACL cases plus direct contracts; advanced ACEs/SACLs/reinheritance unsupported, persistent-ACL flag clear |
| EAs and named streams | Explicit unsupported storage profile, validation and access checks | Neither capability advertised; no fabricated empty-success replies; fixtures requiring storage are not passes |
| Caching and IOCTLs | Explicit uncached profile and validated unsupported controls | No oplock/lease grants; ACK/error/identity/bounds/credit regressions; no successful FSCTL operations |
| Naming | Share-relative namespace and canonical paths | ASCII-insensitive lookup; full Unicode folding, dot-component normalization and short-name generation remain limitations |
| Transport integration | Exercise the shared engine without VM dependencies | Loopback TCP only; VMBus, guest tests and host-backed providers remain deferred |

Compatibility work proceeds by selecting applicable Samba cases, checking any
mismatch against public specifications, and adding small deterministic Rust
regressions before fixing the behavior. Stateful fuzzing and a broader hardening
harness are deferred; they are not represented as completed validation.

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
cargo nextest run --profile agent -p smb --run-ignored only -E 'test(samba_directory)'
cargo nextest run --profile agent -p smb --run-ignored only -E 'test(samba_create_and_sharing)'
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
The CREATE/sharing harness adds thirteen cases covering locked-file opens,
multiple connections, readonly deletion, leading-backslash rejection, invalid
impersonation, concurrent/visible directory creation, directory allocation,
temporary attributes, the no-stream profile and bilateral share modes.
The feature-enabled async harness gates real provider reads, writes, and
flushes on the server's poller. Its four async compound cases include READ/WRITE
checks requiring pending replies, rather than only allowing synchronous fallback.
The notify harness covers CLOSE, TREE_DISCONNECT, LOGOFF, ordinary-file rejection,
handle permissions, and excluding changes to the watched directory itself.
The lock harness runs seventeen cases covering shared/exclusive I/O enforcement,
conflicts, pending acquisition, exact unlocks, stacking, zero-length/64-bit
ranges, cross-connection ownership, arrays, and truncation.
The rename harness covers eleven cases: simple, modification-time preservation,
missing DELETE access, source sharing, destination-directory sharing, and
rejecting directory renames with open descendants, plus metadata-only parent
opens, no-delete-sharing parent opens, close-time metadata and concurrent opens.
`SMBTORTURE` selects the executable for every harness; otherwise they use
`smbtorture` from PATH. The corrected-client harness requires that variable
explicitly and adds eleven notify cases: tcon, dir, tdis, double, tcp, overflow,
rmdir1-4, and mask-change. It uses ten operations because the directory fixture assumes that
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
Declare filesystem-information, allocation, file-mode, basic-information,
rename, locking, and notification expectations explicitly.
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
provider-owned volume identity/capacity and explicit unsupported-volume profiles,
zero extension/truncation, bilateral sharing and close/drop release, basic DOS
attributes, allocation reservation/truncation, per-open modes,
rename identity/replacement/sharing/notifications,
deferred delete modes versus shared disposition and nonempty-directory closes,
lock conflicts/I/O enforcement/waits/rollback, and watch policy,
buffering/FIFO/cancellation/subtrees/deletion generations. They permit genuine
short transfers and do not prescribe exact quotas, short names, or clock
precision. Keep provider-specific tests for those policies, native completion
ownership/cancellation, timestamp controls, resource bounds, and durability.
SMB access checks, per-open request barriers, CLOSE cancel/drain, transient
stop, and wire/transport behavior remain engine/runtime tests.

Metadata-only opens do not participate in data/execute/delete sharing conflicts
(MS-FSA 2.1.5.1.2.2). This exemption works in both open orders, even when either
handle requests exclusive sharing. Rename's temporary destination-directory open
uses the same check, so a metadata-only parent handle cannot obstruct a rename.

## Protocol Representation

`spec::{smb2, fscc, security, ntlm, tcp}` contains public-specification layouts and named
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

The portable `security` module bounds-checks self-relative descriptor offsets,
SID counts, ACL lengths and ACE extents without native handles. It distinguishes
absent/null/empty ACLs and preserves opaque ACE bodies for native providers.
Structural decoding is not an access check: interpreting or rejecting unsupported
ACE kinds remains a provider obligation. These primitives alone do not enable
security descriptor requests or advertise ACL support.

Security queries use the optional provider operation and enforce READ_CONTROL
or ACCESS_SYSTEM_SECURITY as appropriate. Unknown selector bits are ignored.
Undersized replies return BUFFER_TOO_SMALL with the required length, never a
partial descriptor. Unsupported providers have no default descriptor fallback.
MemoryFs uses a fixed synthetic SYSTEM share identity with World membership,
no privilege bypass, and an allow-everyone default DACL, not a network client's
identity. File OWNER/GROUP/DACL updates are atomic and affect future opens,
not existing grants. Basic ordered allow/deny ACEs, generic masks, OWNER_RIGHTS,
inherit-only ACEs and distinct null/empty DACLs are supported. Owner assignment
is restricted to SYSTEM; group metadata may contain any valid SID.
Directory DACL updates also govern traversal, child creation and rename
destinations. Parent DELETE_CHILD / LIST_DIRECTORY rights independently authorize
child DELETE / READ_ATTRIBUTES and are checked against the actual parent ACL.
New objects inherit basic file/container ACEs, preserving generic SID/right
templates for later generations and honoring no-propagate. Effective ACEs map
CREATOR_OWNER / CREATOR_GROUP to the fixed share identity. When no ACE applies,
the synthetic token's default DACL is used. Creation retains the requested grant
even when the newly assigned ACL denies subsequent opens (MS-FSA 2.1.5.1.1).
The effective/template split follows the public
[ACE inheritance rules](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules).
CREATE security descriptors travel in borrowed OpenOptions input and are decoded
only for new objects under the provider's namespace lock. Explicit/protected and
parent-inherited basic ACLs are assembled before publication, never by opening
then setting security. Existing objects ignore the bytes even for OPEN_IF.
Malformed/unsupported new descriptors fail without creating an object.
Automatic reinheritance requests, SACLs, advanced ACEs and security selectors
are still unsupported.
Maximum grants check each individual right with
the same ordered DACL policy as explicit requests (MS-FSA 2.1.5.1.2.1).
The persistent-ACL capability remains off pending broader security interoperability.
SET_SECURITY is routed through an optional provider operation after open-right
checks and bounded descriptor decoding. The default rejects INVALID_DEVICE_REQUEST.
Providers must apply selected components atomically and enforce their policy on
future opens and namespace operations; merely storing an ACL is not success.
ControlledFs gates both the call and delivery of its settled result.

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

## Directory Enumeration

Each continuation queries the provider's current listing rather than retaining
a whole-directory metadata snapshot. Per-open state contains only the search
pattern, last identity/link-name key and returned-entry count. Deleted entries
disappear, changed metadata is refreshed, and new entries after the resume key
can appear without a restart. Ordering is implementation-specific; entries
before the key require restarting the scan.

An unflagged continuation retains its original pattern. RESTART_SCANS and REOPEN
reset the cursor and pattern. FileIndex resumption is optional in MS-SMB2
3.3.5.18; this profile returns zero indices and ignores INDEX_SPECIFIED while
continuing normally. It does not advertise fabricated native index positions.

Seven selected Samba directory cases cover ordinary and deleted-entry scans,
700-file continuation/restart/reopen paths, changed attributes, unspecified
ordering, 2000 long filenames, and enumeration across repeated renames.
The short-name-dependent `one` and index-dependent `file-index` cases are not
counted as passing coverage.

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

The mask-change fixture passes, including fixed attributes-only registration
across later filter changes and file renames. The recursive (`rec`) fixture
expects nine name records despite requesting attribute/creation changes too.
It now gets eleven records, including two file-rename metadata records; the
checkout-built Samba 4.25.1 server also fails that fixture (fourteen records).
The earlier nine-record pass omitted these metadata events and is not retained
as passing coverage. Shared provider tests cover recursive rename delivery.
Tree uses dot-component paths rejected by the current namespace policy, and
valid-req assumes specific native event batching and notification-buffer policy.
The slow mask probe permits cancellation for many subcases and does not establish
complete notification compatibility.

## Filesystem Information

QUERY_INFO obtains volume identity, capabilities, device information and capacity
from the provider's optional filesystem_information operation. The engine does
not label arbitrary providers MEMORY or assume their component limits or device
characteristics. Supported classes are volume (1), size (3), device (4),
attributes (5), and full size (7); other classes are rejected explicitly.
Variable name/label replies retain their full length fields when returning a
partial buffer with BUFFER_OVERFLOW. Undersized fixed prefixes return
INFO_LENGTH_MISMATCH.

The filesystem-attribute fixed prefix is 12 bytes, as specified by MS-FSA
2.1.5.13.5. Samba's `qfs_buffercheck` expects 16 and is not a passing case;
the implementation retains the specified prefix. That fixture and `fsinfo`
also require volume classes outside this provider profile.

MemoryFs uses one-byte logical allocation units: total capacity is its configured
data quota and available capacity follows retained data bytes, including truncation
and final deletion. These are synthetic byte units, not invented host disk
geometry. Volume creation time is independent of root file timestamps; serial
zero is a valid provider-assigned opaque value. Unsupported providers return
NOT_SUPPORTED rather than receiving a successful memory-volume fallback.

## File Metadata Queries

Provider metadata distinguishes stream allocation from logical length, supplies
link counts, EA lengths, alignment and canonical paths within the share's virtual
volume. Directory records, CREATE/CLOSE attributes and file queries use those
values rather than assuming allocation equals EOF or every object has one link.
MemoryFs uses byte-granular allocation and derives paths from current parent links.

File access (8), EA size (7), mode (16) and alignment (17) queries complement the
basic/standard/internal/all/network-open classes. Modes reflect normalized CREATE
options; SMB-mandated ignored synchronous/completion/free-space flags are cleared,
and unbuffered opens exclude append access. FileAllInformation reports the complete
backslash-prefixed path, not only its final component. Direct FileNameInformation
is local-only and returns NOT_SUPPORTED remotely.

File queries validate their fixed minimum buffers with INFO_LENGTH_MISMATCH.
Variable name replies retain the full name length and return partial complete
UTF-16 code units with BUFFER_OVERFLOW. EA-size queries do not require READ_EA;
only queries for EA contents require that right. Providers report actual EA
lengths, with no EAs in the current MemoryFs profile.

The provider resolves MAXIMUM_ALLOWED and reports actual per-open grants
separately from maximal access for the established identity. The engine does not
expand that request to blanket FILE_ALL_ACCESS. Existing opens retain their grants
when attributes or security change; new opens are checked against current state.
MemoryFs maximum access on readonly objects excludes data write/append rights.
FILE_EXECUTE authorizes SMB READ without adding FILE_READ_DATA to the reported
grant. On directories it means traversal, not enumeration or change-notify access.

Allocation updates (19) reserve space without extending EOF and can truncate
data when reduced. MemoryFs charges reservations to its quota, hides bytes beyond
EOF, preserves zero-filled gaps and retains reservations during EOF growth.
Failed reservation growth has no data or quota effects. EOF truncation and
deletion release storage.

Mode updates (16) delegate to the provider and cache the applied per-open flags
only after completion. Buffering and synchronous status cannot be changed through
this operation; write-through is retained on unbuffered opens. Explicit position
updates (14) are per-open, validate nonnegative/sector-aligned offsets and do not
affect the explicit offsets of SMB reads/writes. Reads/writes do not advance
that position. Mode and position are inspectable. Controlled before/after gates
verify that CLOSE cancels uncommitted updates and drains committed results.

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

File renames additionally report MODIFIED at the destination for attribute and
creation watches, even when those metadata values are unchanged. Directories
do not produce this extra record, and exact-case replacement already reports
metadata, so it is not duplicated. This is a compatibility behavior exercised
by the public Samba mask-change fixture and implemented by Samba's notify_rename;
MS-FSA's ordinary name-notification algorithm does not explicitly require it.
It does not introduce general deferred close-time metadata notification.

The shared provider suite covers identity, moves, replacement failures, sharing,
closed subtrees and notification filtering. Wire tests additionally cover malformed
fields, independent literal layouts, related compounds, pending watches, and
before/after-effect cancellation. Provider-specific tests retain quota checks.
The selected Samba cases do not claim the entire rename or notify suite passes.
`share_delete_and_delete_access` expects rename to reject a parent DELETE
handle even when it shares writes. MS-FSA 2.1.5.15.12 uses all three sharing
flags for the temporary destination-directory open; Appendix A note 185
documents the older Windows behavior that omits FILE_SHARE_DELETE. This
implementation retains the main algorithm rather than adding that legacy
restriction to make the fixture pass.

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
snapshots remain unsupported; security descriptors are applied atomically on creation.

Basic-information updates support DOS attributes and per-open timestamp
controls, including zero/no-change and -1/-2 automatic-update suppression/reset.
Alternate-name queries use optional provider short names; the memory provider
does not generate 8.3 aliases.

FileAttributeTagInformation reports provider attributes and reparse tags with
READ_ATTRIBUTES and fixed-buffer checks. MemoryFs has no reparse objects and
ignores CREATE's non-settable REPARSE_POINT attribute.
CREATE rejects undefined attribute bits and leading-backslash names with
INVALID_PARAMETER before invoking the provider. Invalid impersonation values
return BAD_IMPERSONATION_LEVEL; all four defined levels remain accepted.

MemoryFs deliberately has no EAs or named streams and advertises neither.
Full-EA/stream queries return INVALID_INFO_CLASS; EA-content queries/sets check
READ_EA / WRITE_EA. EA-size queries are unrestricted. Structurally invalid EA
SET lists return EA_LIST_INCONSISTENT, while
valid unsupported sets return INVALID_DEVICE_REQUEST. Creation EAs fail
EAS_NOT_SUPPORTED before publication, but existing objects ignore EA bytes,
including OPEN_IF. Borrowed OpenOptions input preserves atomic native-provider
creation rather than requiring an open-then-set sequence.

Full Unicode case-folding, advanced/reinherited ACLs, leases and IOCTLs remain
future work. Basic rename/move and ACL updates are implemented.
Unsupported requests receive explicit status errors.
Memory is allocated for file holes; this is not a sparse-filesystem model.

The current profile grants no oplocks or leases and advertises no leasing
capability. Lease contexts are ignored as required for that profile. Unsolicited
oplock acknowledgments validate the open then return INVALID_DEVICE_STATE;
lease acknowledgments return OBJECT_NAME_NOT_FOUND because no lease table exists.
IOCTL validates FSCTL flags, file/server-wide identity, input bounds/alignment,
transaction limits and multi-credit sizes before declining unsupported controls.
Server-wide controls preserve their all-ones no-file sentinel in compounds.
The profile allows no filesystem controls; shared-VHD controls explicitly return
INVALID_DEVICE_REQUEST. No snapshots, server-side copy, reparse mutation,
resiliency or interface-discovery success is fabricated.

Full filesystem- and dialect-specific torture suites are not expected to
pass yet. For example, `smb2.rw.invalid` includes a particular filesystem
maximum-file-size expectation, whereas this provider reports quota
exhaustion without emulating that filesystem's limit.

Protocol layouts and behavior are independently implemented from the public
MS-SMB2, MS-FSCC, and MS-ERREF specifications. VMBus and host-backed providers
are intentionally deferred.
