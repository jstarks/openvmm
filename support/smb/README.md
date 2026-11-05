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
```

The ignored test requires `smbtorture` (Ubuntu package `samba-testsuite`),
starts its own server on an ephemeral loopback port, and shuts it down on
completion. It checks connection and tree isolation, multi-client read/write data integrity,
EOF/short reads, Windows-style position semantics, directory-read behavior,
per-open read rights, CREATE/open fixtures, and mkdir semantics. Unit tests drive the core directly and cover
sharing, deletion, quotas, malformed requests, and fragmented TCP frames.

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

Connections can have up to 32 outstanding request/response slots, plus one
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
`execute()` future until completion. `Connection::cancel` handles CANCEL without
a response or credit consumption. `tcp::ConnectionTask` provides persistent
framing/operation state for `TaskControl`; the direct `process`/`serve` convenience
futures are not pause-safe when dropped.

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

Active calls, announcements, and queued plans are bounded at 256 each. Recent
terminal history retains 256 calls; ordinary passthrough calls need no controller
consumer. Dropping an unfinished call records `Abandoned`, not successful
completion or acknowledged cancellation.

The tests cover all provider operations, independent completion ordering,
committed writes with concurrent close/pause, partial transfers, real failure
effects, cancellation during nested delegate execution, and controller errors.
With the feature enabled, the Samba harness also uses the controlled wrapper
in its ordinary passthrough configuration.

## Current Limits

Supported commands are NEGOTIATE, SESSION_SETUP, LOGOFF, TREE_CONNECT,
TREE_DISCONNECT, CREATE, CLOSE, FLUSH, READ, WRITE, QUERY_DIRECTORY, and a
subset of QUERY_INFO/SET_INFO, plus ECHO. CREATE validates linked context
containers and returns maximal-access (`MxAc`) and on-disk-ID (`QFid`) responses.
Unsupported preallocation, durable-handle requests, and leases are explicitly
declined without response contexts. EA creation returns `STATUS_EAS_NOT_SUPPORTED`;
security descriptors and snapshots remain unsupported.

Basic-information updates support DOS attributes and per-open timestamp
controls, including zero/no-change and -1/-2 automatic-update suppression/reset.
Alternate-name queries use optional provider short names; the memory provider
does not generate 8.3 aliases.

Compounding, complete credit-window enforcement, non-default streams, Unicode
case-folding, rename, ACL updates, locks, leases, notifications, and IOCTLs
remain future work. Unsupported requests receive explicit status errors.
Cancellation currently uses MessageId; interim STATUS_PENDING/AsyncId responses
and full credit sequence-window validation remain future work.
Memory is allocated for file holes; this is not a sparse-filesystem model.

Full filesystem- and dialect-specific torture suites are not expected to
pass yet. For example, `smb2.rw.invalid` includes a particular filesystem
maximum-file-size expectation, whereas this provider reports quota
exhaustion without emulating that filesystem's limit.

Protocol layouts and behavior are independently implemented from the public
MS-SMB2, MS-FSCC, and MS-ERREF specifications. VMBus and host-backed providers
are intentionally deferred.
