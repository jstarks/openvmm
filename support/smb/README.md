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
and per-open read rights. Unit tests drive the core directly and cover
sharing, deletion, quotas, malformed requests, and fragmented TCP frames.

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

## Current Limits

Supported commands are NEGOTIATE, SESSION_SETUP, LOGOFF, TREE_CONNECT,
TREE_DISCONNECT, CREATE, CLOSE, FLUSH, READ, WRITE, QUERY_DIRECTORY, and a
subset of QUERY_INFO/SET_INFO, plus ECHO. CREATE contexts, compounding,
complete credit-window enforcement, non-default streams, Unicode
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
