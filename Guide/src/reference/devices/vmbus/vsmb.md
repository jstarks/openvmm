# vSMB

The `vsmb` device exposes a volatile in-memory SMB filesystem over VMBus.

## Configuration

Add `--vsmb-memory <SHARE>` to an OpenVMM command with Hyper-V enlightenments
and VMBus enabled, for example a normal UEFI Windows VM. The device offers one
writable share with a 16 MiB storage quota and a 4096-object limit. Files survive
channel reconnects but disappear when the device is destroyed. The option
cannot be combined with `--no-vmbus`.

```admonish warning
This is an initial integration profile, not a host filesystem export or a
complete vSMB implementation. Serialized VM save/restore is unsupported.
```

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

Run the real Windows guest fixture with:

```bash
cargo xflowey vmm-tests-run \
  --filter 'test(vsmb_memory_file_operations)' --skip-vhd-prompt
```

The fixture verifies directory creation, patterned file read/write, rename,
enumeration, deletion and clean shutdown. An aligned uncached read and device
transfer counters verify actual external reads and writes, rather than relying
on client-cached readback.
It also checks that the mapped share remains connected during an idle interval
and that file contents can be read afterward.

Native Windows cases exercise notification delivery/cancellation, shared and
exclusive byte-range locks, waiting/cancelled locks and release on handle close.
Locking opens use hard-link aliases, and a waiting LOCK must be observed in the
server request table rather than inferred from Windows-local lock caching.
A server-observed pending watch must survive VM pause/resume. A cached reader
holds verified server-granted lease rights; a write through a hard-link alias
must revoke those rights before cached and uncached reads see the updated data.
The break must finish before the server's forced-revocation timeout.

The VM-independent [`smb` engine](https://openvmm.dev/rustdoc/linux/smb/index.html)
is also exercised by selected Samba suites over its loopback TCP test frontend.
Those tests complement, but do not replace, VMBus guest coverage.
