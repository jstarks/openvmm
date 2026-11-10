# vSMB

The `vsmb` device exposes one SMB share over VMBus, backed by memory or a Linux
or Windows host directory.

## Configuration

Add `--vsmb-memory <SHARE>` to an OpenVMM command with Hyper-V enlightenments
and VMBus enabled, for example a normal UEFI Windows VM. The device offers one
writable share with a 16 MiB storage quota and a 4096-object limit. Files survive
channel reconnects but disappear when the device is destroyed. The option
cannot be combined with `--no-vmbus`.

On Linux, use `--vsmb-linux <ROOT>` instead to expose the host directory as the
share `linux`. The declared minimum kernel is Linux 6.6. File reads, writes and
flushes use io_uring; metadata operations without usable SQEs use bounded workers.

On Windows, use `--vsmb-windows <ROOT>` to expose a local NTFS directory as the
share `windows`. The initial Windows baseline is `ge_release`. Reparse traversal,
case-sensitive directories and remote filesystems are rejected. Guest names
must round-trip through native UTF-16 without lossy conversion.

Host root configuration paths must be UTF-8. All share options require Hyper-V
enlightenments and VMBus; select only one.

Windows uses native byte-range locks by default, coordinating with independent
host opens. Select `--vsmb-windows-locks synthetic` only when the host promises
not to mutate the backing files outside the SMB server. All cooperating SMB
access must use the same provider instance; independently constructed providers
do not share synthetic coordination. Errors never switch modes automatically.
Native sharing and access checks apply in either mode. Selecting a byte-range
lock mode does not itself grant oplocks or leases.

On either Linux or Windows, add `--vsmb-software-caching` only when the host
promises not to mutate the backing files outside this SMB service. This opts
into software-managed oplocks and SMB 2.1 leases using the shared caching layer;
it does not acquire host-kernel oplocks. All cooperating SMB paths must share
one provider instance. Caching is disabled by default for host-directory exports
and is independent of the Windows byte-range lock mode. Do not expect host
readers to see dirty data still cached by the guest.

The shared layer orders cache breaks and acknowledgments before conflicting
effects, including destructive opens through hard-link aliases. Namespace
replacements conservatively revoke foreign handle caching store-wide when the
destination identity is unknown. Ordinary data I/O can still overlap.

```admonish warning
Host-directory exports are writable with the OpenVMM process's credentials. Choose an
export directory accordingly: guest changes affect real host files.
This is an initial compatibility profile, not a complete vSMB implementation.
Serialized VM save/restore is unsupported.
```

The Linux v1 profile uses native case lookup and WSL-style character projection.
It does not guarantee unambiguous access to every possible Linux filename.
Existing relative symlinks are exposed for guest evaluation; absolute-target
traversal is rejected. Nested mounts within the export are allowed. Safe target
inspection supplies directory-link hints; dangling links are file-like.

By default, external host changes are allowed and no caching rights are granted.
Notifications observe native changes; recursive membership changes can report
overflow and require enumeration. SMB locks and sharing coordinate SMB clients,
not uncooperative host processes. Guest security queries describe simple
share-level policy, not POSIX ACLs; guest ACL changes are rejected.
Windows-only metadata storage, guest EAs and named streams are not implemented.
Ordinary writes are buffered; FLUSH and write-through are honored, while an
ordinary CLOSE does not implicitly flush.

The Windows profile uses process-identity native access checks, sharing,
metadata/security queries, rename/deletion and persistent native notifications.
Backup intent uses the process token's existing privileges; the provider never
enables privileges. Ordinary opens with `FILE_OPEN_REPARSE_POINT` are accepted,
but actual reparse objects remain unsupported and are not traversed.
Unbuffered opens use native unbuffered I/O, including native offset and length
alignment requirements.
Guest ACL changes, creation security descriptors, EAs and named streams are
rejected. Native byte locks have NTFS's enforcement scope: they do not prevent
every host metadata or memory-mapped change. Synthetic locking instead relies
on the exclusive-mutation ownership promise above. Software caching is a
separate opt-in under that same promise, not a consequence of synthetic locks.

The initial compatibility target is Windows Server 2025. The tested transport
uses version 1 negotiation and v2 page descriptors, copying data between guest
memory and owned server buffers. Older registered-buffer transfer profiles and
boot-file service are not implemented.

Offering the channel does not automatically activate the Windows virtual
redirector or map a drive. The guest test explicitly creates an isolated
redirector instance, binds it to the offered VMBus transport and maps the share.
The mapping includes a persistent tree connection, not just a drive-letter
alias, so closing application files does not tear down the idle transport.
Its activation fixture targets the tested Server 2025 and Windows 11 ARM64
images; it is not a general guest provisioning interface.

## Validation

Run connected-ring and guest-memory tests with:

```bash
cargo nextest run --profile agent -p vsmb
```

Run the MemoryFs Windows guest fixture with:

```bash
cargo xflowey vmm-tests-run \
  --filter 'test(vsmb_memory_file_operations)' --skip-vhd-prompt
```

The fixture verifies directory creation, patterned file read/write, rename,
enumeration, deletion and clean shutdown. An aligned uncached read and device
transfer counters verify actual external reads and writes, rather than relying
on client-cached readback.
It also checks that the mapped share remains connected during an idle interval
and that file contents can be read afterward. An orderly guest reboot must
release the old connection's resources and preserve data in the same device.

Native Windows cases exercise notification delivery/cancellation, shared and
exclusive byte-range locks, waiting/cancelled locks and release on handle close.
Locking opens use hard-link aliases, and a waiting LOCK must be observed in the
server request table rather than inferred from Windows-local lock caching.
A server-observed pending watch and waiting LOCK must survive VM pause/resume.
A cached reader holds verified server-granted lease rights; a write through a hard-link alias
must revoke those rights before cached and uncached reads see the updated data.
The break must finish before the server's forced-revocation timeout.

On a Linux host, run the native-backed Windows guest fixture with:

```bash
cargo xflowey vmm-tests-run \
  --filter 'test(vsmb_linux_file_operations)' --skip-vhd-prompt
```

It verifies real host bytes, host updates and notifications, filename projection,
uncached external transfers, pending watch/lock pause-resume and reboot cleanup.
Host-seeded hard-link aliases force server-side locking; guest hard-link creation
is not part of this native v1 profile.

On an ARM64 Windows host, run the Windows-backed fixtures. From WSL, first
configure [Windows cross-compilation](../../../dev_guide/getting_started/cross_compile.md)
and put the output on a Windows filesystem:

```bash
cargo xflowey vmm-tests-run --target windows-aarch64 \
  --dir /mnt/c/path/to/vmm_tests \
  --filter 'test(vsmb_windows_)' --skip-vhd-prompt
```

Both lock modes, with and without software caching, have passed Windows 11
Enterprise ARM64 guest lifecycle tests on an ARM64 Windows host. The fixtures
verify real NTFS bytes, hard-link lock ownership, uncached external transfers,
pending watch/lock pause-resume and reboot cleanup. Cached cases additionally
verify actual server grants, retained rights across pause, acknowledged alias
breaks and released caching reservations after reboot. Only uncached native mode
tests external host mutations; the other cases preserve their exclusive-mutation
promise. This is not Windows Server 2025 guest compatibility evidence for the
Windows provider.

The VM-independent [`smb` engine](https://openvmm.dev/rustdoc/linux/smb/index.html)
is also exercised by selected Samba suites over its loopback TCP test frontend.
Those tests complement, but do not replace, VMBus guest coverage.
