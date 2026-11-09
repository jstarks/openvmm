# vSMB

The `vsmb` device exposes one SMB share over VMBus, backed by memory or a Linux
host directory.

## Configuration

Add `--vsmb-memory <SHARE>` to an OpenVMM command with Hyper-V enlightenments
and VMBus enabled, for example a normal UEFI Windows VM. The device offers one
writable share with a 16 MiB storage quota and a 4096-object limit. Files survive
channel reconnects but disappear when the device is destroyed. The option
cannot be combined with `--no-vmbus`.

On Linux, use `--vsmb-linux <ROOT>` instead to expose the host directory as the
share `linux`. The declared minimum kernel is Linux 6.6. File reads, writes and
flushes use io_uring; metadata operations without usable SQEs use bounded workers.
The root configuration path must be UTF-8. Both options require Hyper-V
enlightenments and VMBus and are mutually exclusive.

```admonish warning
Linux exports are writable with the OpenVMM process's credentials. Choose an
export directory accordingly: guest changes affect real host files.
This is an initial compatibility profile, not a complete vSMB implementation.
Serialized VM save/restore is unsupported.
```

The Linux v1 profile uses native case lookup and WSL-style character projection.
It does not guarantee unambiguous access to every possible Linux filename.
Existing relative symlinks are exposed for guest evaluation; absolute-target
traversal is rejected. Nested mounts within the export are allowed. Safe target
inspection supplies directory-link hints; dangling links are file-like.

External host changes are allowed, so the provider grants no oplocks or leases.
Notifications observe native changes; recursive membership changes can report
overflow and require enumeration. SMB locks and sharing coordinate SMB clients,
not uncooperative host processes. Guest security queries describe simple
share-level policy, not POSIX ACLs; guest ACL changes are rejected.
Windows-only metadata storage, guest EAs and named streams are not implemented.
Ordinary writes are buffered; FLUSH and write-through are honored, while an
ordinary CLOSE does not implicitly flush.

The initial compatibility target is Windows Server 2025. The tested transport
uses version 1 negotiation and v2 page descriptors, copying data between guest
memory and owned server buffers. Older registered-buffer transfer profiles and
boot-file service are not implemented.

Offering the channel does not automatically activate the Windows virtual
redirector or map a drive. The guest test explicitly creates an isolated
redirector instance, binds it to the offered VMBus transport and maps the share.
The mapping includes a persistent tree connection, not just a drive-letter
alias, so closing application files does not tear down the idle transport.
Its activation fixture is pinned to the Server 2025 test image; it is not a
general guest provisioning interface.

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

The VM-independent [`smb` engine](https://openvmm.dev/rustdoc/linux/smb/index.html)
is also exercised by selected Samba suites over its loopback TCP test frontend.
Those tests complement, but do not replace, VMBus guest coverage.
