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
complete Windows guest compatibility. "Implemented" means the listed behavior has direct
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
| Volume metadata | Provider-owned identity, capacity and capability flags | Classes 1/3/4/5/7/8/11 implemented; optional class 6 volume controls and SID quota queries/sets supported; object-ID metadata can be set |
| Namespace and enumeration | Directory continuation, rename/move, hard links, short names, sharing, replacement and deletion | Link-scoped names/deletion and shared-file identity implemented; automatic short names can be enabled in MemoryFs |
| Byte-range locks | Shared/exclusive conflicts, waiting, cancellation, unlock and release | Seventeen selected Samba cases and deterministic cross-open/connection tests; cancellation-status fixture differences remain documented |
| Change notifications | Persistent registration, filters, subtree events, buffering and cleanup | Eighteen selected Samba cases and deterministic contracts; `rec` has conflicting fixed-count expectations |
| Security | Basic descriptors, faithful grants, atomic updates, parent checks and creation inheritance | Descriptor-read/buffer/grant cases, four selected ACL cases and direct contracts; advanced ACEs/SACLs/reinheritance unsupported, persistent-ACL flag clear |
| EAs and named streams | Retained EAs and real named-stream storage, enumeration, rename and lifetime | Both advertised; thirteen selected naming/directory/I/O/sharing/deletion/rename/attribute/permission/disposition stream cases pass |
| Caching and IOCTLs | Uncached default, opt-in oplocks/SMB 2.1 leases and provider-backed controls | Real grants, shared lifetime, routed breaks/ACKs and lock-aware admission have direct tests plus selected Samba classic, lease request/break/no-self-break, upgrades, locks, sharing failures, mixed caching and pending-break cases; lease-v2 and directory leasing remain unsupported |
| Naming | Share-relative namespace and canonical paths | Dot components/aliases resolve within the virtual root; Unicode BMP simple uppercase is shared by lookup, streams and wildcard matching |
| Transport integration | Exercise the shared engine without VM dependencies | Shared runtime serves loopback TCP and the separate `vsmb` VMBus device; Server 2025 file operations and copied external I/O tested; native providers remain deferred |

Compatibility work proceeds by selecting applicable Samba cases, checking any
mismatch against public specifications, and adding small deterministic Rust
regressions before fixing the behavior. Stateful fuzzing and a broader hardening
harness are deferred; they are not represented as completed validation.

CREATE rejects FILE_OPEN_BY_FILE_ID and FILE_RESERVE_OPFILTER before provider
effects, and rejects undefined option bits with INVALID_PARAMETER.
Remote-instance, requiring-oplock and disallow-exclusive options are
ignored as required by SMB 2.1, rather than forwarded as native open requirements.

Directory buffers smaller than the selected record's fixed prefix return
INFO_LENGTH_MISMATCH. A first filename that does not fit returns BUFFER_OVERFLOW
as an SMB2 ERROR response, retaining that entry for retry (MS-FSA 2.1.5.6.3;
MS-SMB2 3.3.4.4). Successful records are aligned between entries, not padded
after the final entry, so exact-fit buffers do not lose records.
Extended directory classes 60 and 78-81 include provider reparse tags and
64-bit/128-bit identities, plus short names where specified. Providers may
decline formats needing an unsupported 128-bit identity. MemoryFs exposes a
stable volume-scoped 128-bit identity by extending its own node identity.

Selected FSCTLs use a semantic async provider operation, not arbitrary native
passthrough. GET_COMPRESSION returns the provider's format for files and
directories. SET_COMPRESSION validates NONE/DEFAULT/LZNT1 and requires
write-data access. MemoryFs stores real LZNT1 chunk bodies, using
distance-one run matches and literal fallback rather than claiming an optimal
encoder. Zero units have no payload. Queries report actual stored allocation
and compression geometry. Directory compression is inherited by future
children, and named streams retain independent state. Decompression and
rewrites fail atomically when quota is insufficient. Sparse and compressed
states can coexist: nonzero LZNT1 chunks are indexed by logical position, with
holes implicit rather than allocating metadata for each skipped unit.
Both control orders preserve data and per-stream state. Hole punching releases
encoded chunks; explicit allocation reservations remain actual reserved bytes.
Sparse decompression materializes live ranges only, and clearing sparse state
after decompression allocates logical holes atomically or fails without effects.
The shared 4096-entry budget bounds candidate/live chunks and sparse extents,
not the logical size of an otherwise empty sparse/compressed stream.
Controlled providers can gate, cancel or reject these calls, and CLOSE drains
their actual results before releasing the open.
SET_ZERO_DATA requires WRITE_DATA and zeroes only the requested bytes below EOF,
without allocating or extending the stream. MemoryFs enforces byte-range locks,
updates automatic modification times and emits last-write notifications.
QUERY_ALLOCATED_RANGES requires READ_DATA and bounds provider results to the
requested record capacity. Dense streams report the queried range, not holes
inferred from zero bytes; streams with no allocation return no ranges.
SET_SPARSE enables real byte-granular sparse backing for each data stream.
Logical EOF growth does not allocate holes; writes allocate their actual ranges,
zeroing punches holes and releases quota, and queries return bounded contiguous
allocated ranges. Disabling sparse storage allocates holes before changing the
flag, with atomic quota failure. Sparse storage is advertised and shared file
attributes reflect all surviving streams. Backing storage, not logical EOF,
consumes the shared byte quota; the volume also bounds allocated sparse extents
to 4096 shared sparse extents/compression chunks. This is synthetic byte
geometry, not native cluster emulation.

MemoryFs retains case-insensitive ASCII EAs with required-knowledge flags.
Creation applies them atomically; existing opens ignore CREATE EA input.
SET_INFO replaces named values or deletes empty ones, enforces the combined
64 KiB minus five limit and charges EA storage against the shared byte quota.
QUERY_INFO returns complete aligned records with per-open continuation,
restart/single-entry/indexed queries and explicit name lists. EA mutations
preserve open grants, update metadata and notify EA/attribute watchers.
Stream-information queries use provider-owned names, lengths and allocation.
MemoryFs reports default and named data streams, excluding directory/index
streams. Named streams have independent data, EOF, allocation and locks, and
stream-local sharing with file-wide delete-sharing checks. They work on files
and directories, charge shared storage/object quotas atomically, and retain
existing opens through stream-scoped deletion. File metadata/times and identity
are shared. Colon-prefixed stream renames preserve open data and locks, including
moves between default and named streams. Replacing an existing stream requires
an empty, unopened target; its reserved allocation is released.
Data-stream names follow MS-FSCC 2.1.5.3 rather than filename restrictions:
wildcards, punctuation and non-NUL controls can be literal stream-name characters;
separators, NUL and names longer than 255 UTF-16 units are rejected.
Stream rename targets begin with `:` (MS-FSA 2.1.5.15.12). A fully qualified
`base:stream` target follows file-name validation and returns OBJECT_NAME_INVALID;
it is not an alternate spelling of stream-only rename.
Default-stream replacement removes closed named streams and uses their released
allocation in the same atomic reservation. Live named opens must share deletion:
their data/locks and quota charges remain until final close, with new opens
receiving DELETE_PENDING. Failed replacement leaves data and notifications intact.

SET_INFO FileShortNameInformation delegates explicit 8.3 alias assignment/removal
to the provider after framing and DELETE-access validation. Providers own restore
privilege and filesystem eligibility; their errors are preserved. MemoryFs treats
its fixed synthetic system identity as having restore access. It validates write
rights, stream/directory eligibility and namespace-wide uniqueness, preserves
existing opens, and publishes ordered alias notifications. Alias opens, directory
matching and alternate-name queries use real stored names. MemoryFs defaults to
explicit aliases; `with_short_name_generation()` enables future automatic
assignment and rename regeneration. Compliant names alias themselves; other
names receive deterministic unique ASCII `prefix~number` aliases with bounded
extensions, checking both long names and aliases. The selected generation
algorithm is implementation-specific, not an NTFS/OEM-codepage emulation.
Only one link per file carries an alias. This is not a native privilege model.

The synthetic namespace uses ordinal UTF-16 simple uppercase for case-insensitive
lookup, stream identity, alias collisions and directory expressions. It does not
normalize Unicode or expand one character into several; supplementary UTF-16
pairs retain their identity. The Unicode version follows Rust's
`char::UNICODE_VERSION`, not a particular native filesystem's upcase table.
ASCII-only protocol tokens and EA names retain their separate grammar.

FileFsObjectIdInformation queries and sets use optional provider-owned volume
identity and 48-byte extension metadata, separate from per-file object IDs.
MemoryFs assigns an initial synthetic volume ID and retains atomic updates
visible through every open. An all-zero ID represents no assigned identity and
queries return OBJECT_NAME_NOT_FOUND. Unsupported snapshots/updates are explicit
errors. SET requires WRITE_DATA and participates in cancellation/CLOSE draining.
Volume metadata alone does not establish per-file controls, quotas or persistent identity.

Quota support is provider-optional. `MemoryFs::with_quotas()` enables real
accounting for the synthetic SYSTEM share identity before opens; descriptor
ownership does not change the identity charged for mutations. Defaults and
SID-specific policies are retained separately, with atomic bounded updates,
deletion back to defaults, and actual allocation-based hard limits. Sparse
logical growth is not charged, but sparse writes, allocation, conversion and
compressed backing use the quota-aware storage budget. Reducing a quota below
current usage permits non-growing writes but prevents additional allocation.
Caller capacity/free space is quota-limited while actual volume free space
remains physical. Control queries/sets use class 6; enforcement/tracking flags
are host configuration and ignored on set. Content-index enabling and quota
event logging are unsupported, not reported as successful effects.
SID queries support explicit lists, required zero records for unknown requested
SIDs, start-SID selection and per-open continuation without losing entries on
small buffers. Quota change-time and usage fields are ignored on set.
This is synthetic-identity accounting, not native per-owner quota emulation.

Per-file GET_OBJECT_ID, CREATE_OR_GET_OBJECT_ID, SET_OBJECT_ID,
SET_OBJECT_ID_EXTENDED and DELETE_OBJECT_ID also use semantic provider controls.
MemoryFs stores volume-unique identities shared by all file streams, preserves
birth metadata on deletion, and enforces assignment collisions. Creation is
atomic and repeated queries return the same identity. Extension updates require
WRITE_DATA or WRITE_ATTRIBUTES; restore access for assignment belongs to the
provider (the synthetic system identity has it). The actual object-ID capability
is advertised. This does not provide a USN journal, an NTFS object-ID index
namespace or persistent/native GUID generation.

GET_REPARSE_POINT, SET_REPARSE_POINT and DELETE_REPARSE_POINT use retained
provider-owned tag/GUID/data, with validated Microsoft and GUID framing and
symbolic-link/mount-point payloads. MemoryFs enforces ownership, eligibility,
write rights and atomic shared-quota accounting, updates actual attributes/tags,
and releases stored bytes on deletion. Its synthetic system identity has
symbolic-link creation access. Partial GET replies preserve the full data length
and return BUFFER_OVERFLOW as specified by MS-FSCC 2.3.28. Reparse capability is
advertised for these controls. Symbolic-link CREATE failures return semantic
provider target/print names, flags and the original unparsed suffix as an SMB2
STOPPED_ON_SYMLINK error. Clients evaluate targets and retry; the server does
not access host paths or silently open underlying data. Final-component
FILE_OPEN_REPARSE_POINT opens access the reparse object itself, but do not
bypass intermediate links. Other name-surrogate tags, including mount points,
remain explicit IO_REPARSE_TAG_NOT_HANDLED failures.

Hard-link SET_INFO requests use typed FileLinkInformation and provider-owned
destination validation. MemoryFs stores namespace links separately from shared
file data: handles retain the opened link, while file IDs, streams, locks,
security and object IDs remain shared. Rename and deletion affect the selected
link, and storage is released only with the last link. Live link counts are
maintained without scanning the volume during enumeration. Namespace links and
streams count toward the object limit; data is charged once. At most one link
per file has a short name. Open replacement targets remain denied in the
uncached profile. Hard links are advertised; direct/provider/wire/cancellation
tests cover them, not the lease-dependent independent hard-link fixture.

Security queries project actual owner/group/DACL components and the absence of
stored audit, integrity-label, resource-attribute and central-policy ACEs.
Backup queries return the complete supported descriptor. The synthetic SYSTEM
identity can explicitly request ACCESS_SYSTEM_SECURITY; MAXIMUM_ALLOWED does
not implicitly grant that privilege. Query authorization still applies, and
unsupported SACL/security mutation policies remain explicit errors. Empty
queried components do not establish native audit or mandatory-label enforcement.

## Provider Caching Boundary

`FileSystem::open_with_caching` accepts semantic oplock or client-scoped lease
requests and returns an `Opened` object containing the actual grant. Its default
delegates to `open_with_reparse` and grants nothing, so existing providers need
no changes. Supporting providers coordinate conflicting effects before opening
or truncating objects and acquire rights before returning. No frontend
pathname lookup or separate speculative open is required.

Grants retain a provider-owned `Caching` control for queued break delivery and
acknowledgment. Each break has a provider identity so late completions cannot
acknowledge a newer break. Controls do not keep closed files alive; shared
leases survive until their last associated open closes. The engine is responsible
for wire routing, acknowledgment validation and timers; providers own coherence
with filesystem effects, including external mutations when permitted.
`ControlledFs` forwards these requests and retains actual grants, breaks and
acknowledgment results across deterministic scheduling and late cancellation.

The driver-aware connection runtime forwards oplock and lease requests, routes
unsolicited break notifications and validates acknowledgments. Unacknowledged
breaks revoke caching after 35 seconds. Close and disconnect release reservations
without waiting for a client to read notifications or send an acknowledgment.
Retained notification/provider futures and partial transport progress survive pause.
`ConnectionTask::new_with_driver` supplies notification service and timers; the
ordinary constructor and direct `tcp::serve` helper remain uncached.

MemoryFs defaults to no caching. `MemoryFs::with_oplocks()` opts into the shared
`provider::caching::software::SoftwareCaching` infrastructure before any opens
exist. The table uses stable file/stream identities, tracks uncached opens too,
bounds reservations to 4096, and coordinates conflicting opens, data writes,
length/allocation changes, byte-range locks and storage controls before effects.
Exclusive owners can flush dirty data while their break awaits acknowledgment;
level-II writes invalidate read caching, including the writer's. Ordinary sharing
validation precedes exclusive-oplock breaks, and destructive opens revalidate
after waits. The helper is independent of MemoryFs storage, but providers must
call admission and registration under their own store lock and wait outside it.
This first implementation is shared provider infrastructure, not a transparent
wrapper around arbitrary providers.

Classic grants cover exclusive/level-II and batch caching on default file streams
only, not directories. Batch open breaks precede ordinary
sharing checks; stat-only opens retain the grant. After a batch downgrade, a
write self-invalidates level-II caching. Named-stream opens conservatively revoke
default-stream classic caching and suppress new classic grants while they remain
open. Unsupported caching requests may be
declined without failing the open. Host providers with external mutations must
coordinate those mutators rather than use this software-only guarantee.

SMB 2.1 leases support read, read/handle, read/write and read/write/handle caching,
including independent named-stream leases. The provider scopes keys by service
authority and negotiated client GUID, rejects a key reused for another object
before creation effects, and shares one control across the lease's opens.
Closing one handle does not release other handles' grants. A current provider
snapshot and non-reused control identity prevent delayed open results from
republishing revoked rights or resurrecting a closed lease instance.
The engine routes one lease watcher per control and transfers an outstanding
break to a surviving connection after disconnect. Read-only lease breaks need
no client ACK; other breaks require one. Writes do not break the writer's own
lease. Foreign writes, metadata and namespace effects are admitted before
publication, including relinquishing handle caching when sharing checks fail.
Lease acquisition/upgrade is constrained by other significant opens. The lease
identity/context remains valid when backing locks prevent new shared rights.
MemoryFs permits shared grants for locks outside both allocation and logical EOF,
retains existing grants for the same lease, and admits new shared rights after
unlock. Locks inside allocation or readable sparse/compressed ranges block new
shared caching, without changing reported physical allocation or logical EOF.
Lock acquisition invalidates foreign leases before publishing the reservation.
The lease
capability is advertised only when provider configuration and runtime support it.
Explicit level-II requests are supported. Classic level-II grants can share
read leases but cannot coexist with handle-caching leases. A contended lease
therefore falls back to read-only rights while a classic grant remains held;
an upgrade to handle caching is possible after that classic open closes.
Overlapping operations can tighten an outstanding break. The provider queues
the additional invalidation after the first ACK, and waiting effects remain
blocked until the final required rights are released.
Directory leases, lease-v2 epochs/parent keys and native external-mutator
coordination remain outside this profile.

## Run

```bash
cargo run -p smb --example smb_server -- 127.0.0.1:1445
```

The share is named `memory`; all file data disappears when the process exits.
It has a 16 MiB data quota and a 4096-object limit.

## VMBus Integration

The separate `vsmb` device exposes one volatile MemoryFs share through
OpenVMM's `--vsmb-memory <SHARE>` option. The common `runtime::ConnectionTask`
owns admission, pending operations, responses, caching and disconnect cleanup;
`tcp::ConnectionTask` remains a compatibility re-export. The device owns VMBus
negotiation, guest-memory access and VM lifecycle. `transfer::ExternalData`
validates transport-owned descriptors and copies data into owned buffers without
adding guest addresses or VM types to the core API.

The initial target is Windows Server 2025 with vSMB transport version 1 and
negotiated v2 page descriptors. A real guest test verifies create, ordinary
read/write, uncached external read, rename, enumeration, deletion and clean
teardown. The stock image needs explicit virtual-redirector activation and
transport binding; offering the device alone does not map a drive.

This is not a complete vSMB implementation. Registered-buffer/older transfer
profiles, boot-file service, serialized save/restore, multiple-share management
and native filesystem providers are separate work. See the
[vSMB Guide](../../Guide/src/reference/devices/vmbus/vsmb.md) for usage and tests.

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
cargo nextest run --profile agent -p smb --run-ignored only -E 'test(samba_sparse)'
cargo nextest run --profile agent -p smb --run-ignored only -E 'test(samba_compression)'
cargo nextest run --profile agent -p smb --run-ignored only -E 'test(samba_oplock_exclusive)'
cargo nextest run --profile agent -p smb --run-ignored only -E 'test(samba_oplock_batch)'
cargo nextest run --profile agent -p smb --run-ignored only -E 'test(samba_lease_request) | test(samba_lease_breaks) | test(samba_lease_nobreakself)'
cargo nextest run --profile agent -p smb --run-ignored only -E 'test(samba_lease_upgrades) | test(samba_lease_locks) | test(samba_lease_sharing_violation)'
cargo nextest run --profile agent -p smb --run-ignored only -E 'test(samba_lease_oplock_mixing) | test(samba_lease_multiple_breaks)'
cargo nextest run --profile agent -p smb --run-ignored only -E 'test(samba_volume_quotas)'
cargo nextest run --profile agent -p smb --run-ignored only -E 'test(samba_sparse_compressed)'
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
The harness also checks descriptor component selection/read rights,
compound CREATE/write/close, invalid inherited file
identity, and related/unrelated directory continuation.
The CREATE/sharing harness adds eighteen cases covering locked-file opens,
multiple connections, readonly deletion, leading-backslash rejection, invalid
impersonation, concurrent/visible directory creation, directory allocation,
temporary attributes, bilateral share modes and readonly
file/directory maximum-access reporting, readonly delete modes/dispositions,
and basic DOS attributes/unchanged attributes on existing-object opens,
plus attribute checks on truncating replacement.
The feature-enabled async harness gates real provider reads, writes, and
flushes on the server's poller. Its four async compound cases include READ/WRITE
checks requiring pending replies, rather than only allowing synchronous fallback.
The notify harness covers CLOSE, TREE_DISCONNECT, LOGOFF, ordinary-file rejection,
handle permissions, and excluding changes to the watched directory itself.
The lock harness runs seventeen cases covering shared/exclusive I/O enforcement,
conflicts, pending acquisition, exact unlocks, stacking, zero-length/64-bit
ranges, cross-connection ownership, arrays, and truncation.
The sparse harness covers nine cases for flags, absent/oversized input,
allocation queries and partial output, hole punching and locks.
The broader malformed-range fixture expects an empty-file nonzero query with
zero output capacity to succeed, unlike MS-FSA 2.1.5.10.22's buffer check.
The broader permission fixture expects append-only SET_SPARSE to succeed,
unlike the write-data/write-attributes requirement in MS-FSA 2.1.5.10.38.
Those two fixtures are not counted as passing; direct tests retain the public
rules instead of weakening validation or access grants.
The compression harness covers eight cases for state, inheritance, malformed
inputs, attributes and write-data access. The broader inherit-disable fixture
expects FILE_NO_COMPRESSION to disable directory inheritance; MS-SMB2 2.2.13
requires that bit to be ignored when FILE_DIRECTORY_FILE is set. It is not
counted as passing; direct tests preserve the public directory rule.
The opt-in oplock harness adds `smb2.oplock.exclusive1` and `exclusive2`: real
grants, sharing failures without spurious breaks, and cross-connection downgrade
notifications acknowledged by Samba. Both failed before implementation.
The batch harness adds `smb2.oplock.batch1`, also failing first: a break before
a sharing-violation result, no duplicate break on a second failure, and a
write-triggered self-break to none. These are three selected cases, not lease
or full oplock-suite coverage.
The three lease harnesses cover `smb2.lease.request`, `smb2.lease.break` and
`smb2.lease.nobreakself`. Each fixture requires the lease capability rather than
skipping an uncached server. Request and contention runs exposed real failures
before passing; the contention matrix checks READ/HANDLE/WRITE bits independently
and caught an initially swapped HANDLE/WRITE mapping. This is selected SMB 2.1
coverage, not the entire lease suite.
The rename harness covers eleven cases: simple, modification-time preservation,
missing DELETE access, source sharing, destination-directory sharing, and
rejecting directory renames with open descendants, plus metadata-only parent
opens, no-delete-sharing parent opens, close-time metadata and concurrent opens.
`SMBTORTURE` selects the executable for every harness; otherwise they use
`smbtorture` from PATH. The corrected-client harness requires that variable
explicitly and adds twelve notify cases: tcon, dir, tdis, double, tcp, overflow,
rmdir1-4, mask-change, and tree. It uses ten operations because the directory fixture assumes that
count and has a fixed 1000-byte output buffer.

### Broader SMB 2.1 Sampling

The `samba_smb21_*` tests retain eighteen additional independently passing
cases, bringing selected coverage to 164 cases, not the entire Samba suite.
Each case uses a fresh MemoryFs/server, automatic short names and real oplocks,
SMB 2.1 negotiation, and a 20-second child-process limit. Run them with:

```bash
SMBTORTURE=/path/to/corrected/smbtorture \
    cargo nextest run --profile agent -p smb --run-ignored only \
    -E 'test(samba_smb21_)' -j 2
```

A bounded 32-case expansion initially returned nineteen process successes,
but four were Samba skips, not passes. After configuring actual short-name
generation and fixing stat-only lease contention and the 32-byte native minimum
stream-query buffer, eighteen cases genuinely pass. They cover file identity,
metadata/stream buffers, SET_INFO, classic contention and stat-only lease opens.
Undefined CREATE options also exposed a validation bug; a literal-wire
regression now verifies rejection before creation or truncation. The generated
CREATE fixture proceeds farther but is not counted as passing.

The fourteen remaining sampled cases are classified explicitly:

| Cases | Classification | Observed limitation or expectation |
|-------|----------------|------------------------------------|
| create.case-insensitive-bypass, create.path-length, dir.file-index, read.bug14607 | Four Samba skips | Case-sensitive/interactive/native file-index profiles or a Samba-only padding control; exit success is not evidence of a passing case |
| getinfo.getinfo_access | Dialect expectation | Requires normalized-name success, which MS-SMB2 3.3.5.20.1 forbids on SMB 2.1 |
| ea.acl_xattr | Fixture dependency | Requires Samba's configured private NTACL xattr, not ordinary EA functionality |
| create.blob | Unsupported context | Requires accepting unknown vendor tag FooO; unknown contexts currently return NOT_SUPPORTED |
| create.aclfile, create.acldir | Descriptor-policy difference | Expects the input ACE order to survive CREATE; MemoryFs places explicit ACEs before regenerated inherited ACEs |
| create.nulldacl | Descriptor-policy difference | Final assertion expects absent-DACL SET to normalize to a present null DACL; MemoryFs retains the absent/present distinction |
| dir.one | Metadata expectation | Requires directory EA size to equal FileEaInformation; MS-FSA directory records omit the additional four-byte query header |
| oplock.exclusive6, rename.share_delete_and_delete_access | Historical rename profile | Requires a DELETE-access parent to block rename; MS-FSA 2.1.5.15.12 now uses all sharing flags, with the older behavior documented in product note 185 |
| create.gentest | Native matrix/error-ordering expectation | After the reserved-option fix, combines invalid attributes and access and expects access denial first; also asserts historical native flag bitmaps |

These differences are not silently skipped, changed to success, or included
in the passing total. Descriptor normalization, vendor-context handling and
native error-ordering expectations remain explicit compatibility-policy
questions, not proof that the whole frontend is complete.

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
Declare filesystem-information, allocation, file-mode, basic-information, short-name,
rename, locking, and notification expectations explicitly.
Creation-allocation expectations are independent from SET_ALLOCATION support;
declare explicitly whether the provider honors or ignores creation hints.
Unexpected unsupported errors fail; an unsupported profile exercises rejection
rather than silently skipping a test. These are test expectations, not runtime
SMB capability advertisement. Read-only providers will need separate scenarios
that do not assume successful creation or mutation.

MemoryFs coverage is not a minimum feature requirement for other providers.
For example, a provider without compression leaves `file_compression` clear,
can decline optional compression metadata, and rejects compression controls.
The default `FileSystem::file_control` already returns INVALID_DEVICE_REQUEST;
providers implementing other controls can retain that fallback for compression.
Contract expectations mark the feature unsupported and verify the rejection.

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

Dot-directory components resolve within the virtual share (MS-FSCC 2.1.5.1).
The parent of the root is that root, so repeated `..` cannot escape it. Resolution
retains directory traversal/type checks rather than blindly deleting path text.
Opening dot aliases preserves identity and canonical metadata paths. Literal
dot names cannot be published by CREATE or rename. Pathnames are bounded at
32,760 UTF-16 units.

MemoryFs creation preserves supported DOS attributes on files and directories,
inherits the parent's not-content-indexed flag, forces ARCHIVE for files and
DIRECTORY for directories, and rejects temporary-directory creation before
publication (MS-FSA 2.1.5.1.1). Readonly directory creation remains ignored in
this profile. Unsupported compression, encryption, sparse, reparse and other
storage flags are not fabricated. Basic attribute updates use the same settable
mask; opening an existing object does not apply creation attributes.
After a directory's READONLY bit is set through basic metadata, it remains
observable but does not prohibit explicitly requested directory write/append
rights (MS-FSA 2.1.5.1.2.1). Readonly data-file restrictions are unchanged.

OVERWRITE/OVERWRITE_IF/SUPERSEDE preserve existing HIDDEN/SYSTEM requirements
before truncation, check their implied data/delete/metadata rights, and apply
requested supported attributes with ARCHIVE set and not-content-indexed cleared
(MS-FSA 2.1.5.1.2). Attribute changes notify registered attribute watches.

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
Parent policy changes affect future creation, not the ACLs of existing
descendants. Explicit automatic-reinheritance requests return NOT_SUPPORTED
without changing the stored descriptor. The persistent-ACL capability remains
off: basic synthetic enforcement and selected passing ACL cases do not establish
complete persistent filesystem ACL semantics. Native identity/privilege policy,
advanced ACEs, SACLs and descendant reinheritance require a separate supported
provider profile, not successful no-ops or broader advertisement.
SET_SECURITY is routed through an optional provider operation after open-right
checks and bounded descriptor decoding. The default rejects INVALID_DEVICE_REQUEST.
Providers enforcing security apply selected components atomically and enforce
their policy on future opens and namespace operations; merely storing an ACL
does not establish enforcement support.
Frontend framing, descriptor decoding and access checks do not depend on
provider effects. A provider returning success produces a SET_INFO response
without frontend read-back or simulated mutation; MemoryFs applies real policy
changes for semantic testing.
ControlledFs gates both the call and delivery of its settled result.

Independent byte fixtures verify unaligned embedded bitfields, all eleven supported
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

Patterns follow MS-FSA 2.1.4.4: `*`, `?`, DOS_STAR (`<`), DOS_QM (`>`) and
DOS_DOT (`"`), including `*.*` matching extensionless names. Matching operates
on UTF-16 units and retains the current ASCII-only case-insensitive policy.
Provider-supplied short names are matched too; none are fabricated. A first
search with no matching entries returns NO_SUCH_FILE; continuation returns
NO_MORE_FILES. Empty patterns select all names.

Search patterns are limited to one 255-UTF-16-unit component in this core
profile. Longer patterns return NAME_TOO_LONG; separators, streams and control
characters are invalid. The matcher uses bounded prefix states, not recursive
backtracking. Direct tests cover ordinary and DOS operators, periods/end of
name, surrogate pairs, validation and continuation.

Seven selected Samba directory cases cover ordinary and deleted-entry scans,
700-file continuation/restart/reopen paths, changed attributes, unspecified
ordering, 2000 long filenames, and enumeration across repeated renames.
The short-name-dependent `one` and index-dependent `file-index` cases are not
counted as passing coverage.
The checkout-built source3 `smbclient` probe was blocked at session setup,
before any wildcard request: it does not accept this raw unsigned-guest test
exchange. That is a harness limitation, not passing wildcard interoperability
evidence or a reason to add network authentication.

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
sending an asynchronous CANCEL. The extended notify harness requires that fix;
our server does not weaken cancellation identity matching. Reference comparisons
with the corrected client pass in all three signing profiles.

The mask-change fixture passes, including fixed attributes-only registration
across later filter changes and file renames. The recursive (`rec`) fixture
expects nine name records despite requesting attribute/creation changes too.
It now gets eleven records, including two file-rename metadata records; the
checkout-built Samba 4.25.1 server also fails that fixture (fourteen records).
The earlier nine-record pass omitted these metadata events and is not retained
as passing coverage. Shared provider tests cover recursive rename delivery.
Tree now passes with share-root-clamped dot-directory resolution.
Valid-req assumes specific native event batching and notification-buffer policy.
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
MxAc reports descriptor-derived maximum rights, independently of readonly
attributes and parent-directory fallback grants (MS-SMB2 3.3.5.9.5, note 334).
Actual MAXIMUM_ALLOWED grants on readonly objects exclude data write/append and
DELETE_CHILD rights (MS-FSA 2.1.5.1.2.1); the readonly restriction does not alter
the reported descriptor maximum or revoke existing handles.
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
rename flags remain unsupported. Colon-prefixed destinations
select data-stream rename, including default/named moves (MS-FSA 2.1.5.15.12.1).

The provider atomically validates and updates the namespace, preserving the
source's data, identity, opens, and byte-range locks. Existing target names
require replacement permission; open targets, directory targets, readonly
targets, and directory sources with open descendants are denied. Destination
directory sharing is enforced, cycles are rejected, and an exact self-rename
is a no-op. The memory namespace keeps its ASCII-insensitive lookup and resolves
dot-directory components within the share.

CREATE and rename share filename-component validation (MS-FSCC 2.1.5.2).
Wildcard characters, quotes, vertical bars and ASCII controls are rejected
before namespace publication. Query-directory patterns deliberately permit
their standard/DOS wildcard characters; those are not valid created filenames.

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
Readonly objects reject both delete-on-close opens and explicit true disposition
with CANNOT_DELETE, without changing namespace or pending state. Clearing
disposition remains allowed; clearing readonly permits a later delete retry.
Creating a readonly object with delete-on-close fails before publication.

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
CREATE allocation (`AlSi`) reaches the provider open. MemoryFs reserves space
without extending EOF, including replacement opens, and fails quota checks
before publication or truncation. Ordinary existing-object opens and directory
creation ignore the hint. Durable-handle requests and leases are accepted
without granting those features or returning response contexts.
EA creation returns `STATUS_EAS_NOT_SUPPORTED`;
snapshots remain unsupported; security descriptors are applied atomically on creation.

Basic-information updates support DOS attributes and per-open timestamp
controls, including zero/no-change and -1/-2 automatic-update suppression/reset.
FileCompressionInformation returns provider-owned compression metadata.
MemoryFs reports its actual allocated bytes with COMPRESSION_FORMAT_NONE; this
query does not claim compression storage or require READ_ATTRIBUTES.
FileNormalizedNameInformation remains NOT_SUPPORTED as required for SMB 2.1.
Alternate-name queries use provider short names. MemoryFs retains explicitly
assigned 8.3 aliases but does not generate them automatically.

FileAttributeTagInformation reports provider attributes and reparse tags with
READ_ATTRIBUTES and fixed-buffer checks. MemoryFs has no reparse objects and
ignores CREATE's non-settable REPARSE_POINT attribute.
CREATE rejects undefined attribute bits and leading-backslash names with
INVALID_PARAMETER before invoking the provider. Invalid impersonation values
return BAD_IMPERSONATION_LEVEL; all four defined levels remain accepted.
FILE_OPEN_BY_FILE_ID returns NOT_SUPPORTED, and FILE_NO_EA_KNOWLEDGE combined
with an EA-buffer context returns ACCESS_DENIED, before provider calls.
The specifically reserved CREATE context is ignored after framing validation;
it does not prevent processing other contexts.

MemoryFs supports and advertises EAs and named streams. Providers can explicitly
decline either feature: unsupported snapshots return INVALID_INFO_CLASS, sets
return INVALID_DEVICE_REQUEST, and creation EAs return EAS_NOT_SUPPORTED before
publication. EA-content queries/sets check READ_EA / WRITE_EA; EA-size queries
are unrestricted. Invalid EA SET lists return EA_LIST_INCONSISTENT. Existing
objects ignore creation EA bytes, including OPEN_IF. Borrowed OpenOptions input
preserves atomic provider creation rather than requiring an open-then-set sequence.

Full Unicode case-folding, advanced/reinherited ACLs, leases and broader IOCTLs remain
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
