# SMB Specification Errata Candidates

Observed discrepancies between published specifications and native behavior.
These are **candidates**, not publisher-confirmed errata. A difference may
reflect a specification defect, a product deviation, or an incomplete model.
Keep those possibilities distinct until the evidence establishes otherwise.

Record public specification references, reproducible observations, affected
versions, regression tests and the implementation decision. Do not include
proprietary source excerpts or references. Native API observations do not, by
themselves, establish on-wire SMB server behavior.

| ID | Specification | Candidate | Status |
|----|---------------|-----------|--------|
| FSA-001 | MS-FSA 2.1.5.1.2.1 | Readonly maximum access with explicit DELETE_CHILD | Unconfirmed |
| FSA-002 | MS-FSA 2.1.5.15.3 and 2.1.5.11 | Notification deletion state belongs to registrations, not the deleting open | Unconfirmed |

Both entries were observed on 2026-11-09 using local NTFS on ARM64 Windows
`ge_release`, build 26300.9818. Neither entry has a recorded publisher
acknowledgment or a direct Windows SMB wire reproduction.

## FSA-001: Readonly Maximum Access with Explicit DELETE_CHILD

**Specification:** [MS-FSA 2.1.5.1.2.1, Algorithm to Check Access to an Existing File](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/82b364ce-6d7b-422f-8d88-4db32eea809a).

**Reproduction:** Open an existing readonly regular data file, with permissive
ACLs and sharing, requesting `MAXIMUM_ALLOWED | FILE_DELETE_CHILD`. Do not
request delete-on-close or explicit data-write/append access.

**Published algorithm:** Compute maximum grants, remove readonly-disallowed
rights including `FILE_DELETE_CHILD`, then reject any remaining explicit
requested rights. This implies `STATUS_ACCESS_DENIED`.

**Native observation:** `NtCreateFile` accepts the open. This records the
success status, not a claim that DELETE_CHILD has meaningful effects on a
regular file. The provider regression also checks that the mixed request
does not acquire data-write or append grants.

**Implementation decision:** The Windows provider preserves the native open's
access decision. A post-open readonly query would combine different snapshots
under external mutation and require attribute-query permissions that the
native grant need not include. MemoryFs retains the literal-rule rejection.

**Regression:** `maximum_allowed_access` in the
[Windows provider tests](../smb_windows/src/filesystem/tests.rs), using the
[shared maximum-access scenario](src/test_support/contracts.rs) with an
explicit Windows expected status.

## FSA-002: Notification Deletion State and Open Identity

**Specification:**
[MS-FSA 2.1.5.15.3, FileDispositionInformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/386d9ec5-e0f6-4853-b175-c05be01419e0)
and
[MS-FSA 2.1.5.11, Server Requests Change Notifications for a Directory](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/e9e427f6-16b6-49ff-8782-6b564bef7726).

**Reproduction:**

1. Open an empty directory as A and establish a change-notification registration.
2. Open the same directory as B, without registering notifications on B.
3. Use B to set delete disposition to true, then clear it without closing either
   open.
4. Request notifications again through A and start a first registration through B.

**Published algorithm:** Setting disposition marks
`B.ChangeNotifyDirectoryMarkedDeleted` and removes all affected registrations,
including A's. Clearing disposition does not clear B's notification flag.
A later notification request recreates a missing registration and checks only
the requesting open's flag.

| After disposition reset | Literal published model | Native observation |
|-------------------------|-------------------------|--------------------|
| A registers again | A may recreate its registration | `STATUS_DELETE_PENDING` |
| B registers for the first time | `STATUS_DELETE_PENDING` | Registration succeeds and delivers changes |

**Interpretation:** Native terminal deletion state follows existing
notification registrations. The published model instead attaches its sticky
flag to the open requesting deletion. Simply changing the flag on the deleting
open does not describe the observed cross-open lifetime.

**Implementation decision:** Preserve native registration lifetime. An
invalidated Windows registration requires a fresh directory open; clearing
disposition does not revive it. An otherwise unregistered deleting open can
start watching after disposition reset. Do not reopen handles implicitly:
that would introduce different sharing, authorization and identity concerns.
MemoryFs and Linux retain their existing notification model.

**Regression:** `notification_delete_state_belongs_to_existing_registrations`
in the [Windows provider tests](../smb_windows/src/filesystem/tests.rs) checks
provider A's terminal state and actual raw-native B event delivery.
`notify_deletion_generations` in the
[shared scenarios](src/test_support/contracts.rs) declares the Windows
registration-lifetime expectation separately from the other providers.
