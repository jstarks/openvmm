# Minimal mshv boot image

The experimental `incubator-mshv-image` binary constructs an x86-64 raw GPT disk
with a FAT32 EFI System Partition from supplied boot artifacts. Construction is
entirely in Rust using the workspace's `gptman`, `fatfs`, and `fscommon` crates:
no host mounts, RPM installation, filesystem utilities, or GRUB tools are used.

Artifact acquisition, image composition, and execution are separate steps.
The experimental [Incubator mshv profile](incubator.md#direct-invocation)
uses this composer to cold-boot a root partition and run existing child-VM tests
through Pipette. Public-artifact boot and a Linux-direct mshv child boot have
been demonstrated.

## Inputs

- An x64 shim binary configured to load `grubx64.efi` from its own directory.
- A compatible prebuilt x64 GRUB binary with prefix `/boot/grub2` and embedded
  FAT, GPT, normal, search, chain, boot, Linux, and halt support. Azure Linux 3's
  regular `grub2-efi-binary` recipe provides this layout; do not use its
  `noprefix` variant. The binary must enter Linux through its EFI stub.
- An extracted payload directory containing `HvLoader.efi`, `lxhvloader.dll`,
  and the complete matching `Windows/System32` hypervisor runtime. Both
  `hvix64.exe` and `hvax64.exe` must be present. Retain the complete runtime
  rather than inferring DLL dependencies from these prerequisites.
- An x64 Linux kernel with the mshv EFI launch patches, `CONFIG_EFI_STUB=y`,
  `CONFIG_MSHV_ROOT=y`, initramfs support, and drivers for the outer VM's devices.
- An initramfs providing `/init` and the desired runtime. This tool does not
  construct the initramfs or supply a Linux root filesystem.

Use version-pinned artifacts from authorized sources. Keep proprietary binaries
and generated images outside the repository. The composer does not verify
artifact provenance, binary architecture, signatures, or version compatibility;
those are responsibilities of artifact provisioning.

## Acquire public boot artifacts

`incubator-mshv-artifacts` downloads version-pinned Azure Linux 3 x86-64 RPMs
using `curl`, verifies their pinned SHA-256 hashes, and extracts their contents
in Rust. It does not install packages or run package scripts. `curl` must be
on `PATH`; no host RPM, archive, filesystem, or GRUB utilities are needed.

```bash
cargo run -p incubator --bin incubator-mshv-artifacts -- \
  --cache /path/to/cache/rpms \
  --output /path/to/artifacts
```

The output directory must not exist, and its parent must exist. The cache is
created if necessary. `--offline` requires all RPMs to be cached and still
checks their hashes. A corrupt cache entry is reported, not silently reused
or replaced. Output contains `boot/`, packaged `licenses/`, and `SHA256SUMS`
recording source URLs and hashes. An output write failure may leave a partial
directory; use a new output path after resolving the error.

The recipe pins shim 15.8-6, GRUB 2.06-27, edk2-hvloader
20240524git3e722403cd16-20, and matching `mshv` / `mshv-bootloader-lx`
26100.9444.2609032029.1-1 RPMs. The hypervisor packages come from the public
`ms-non-oss` repository. Public availability does not change their licensing.
Hashes pin the HTTPS-acquired bytes; the tool does not verify RPM signatures
or enable Secure Boot. Private payloads can still be supplied directly to the
image composer.

Use these extracted paths for the composer:

| Input | Path beneath the artifact output |
|-------|----------------------------------|
| `--shim` | `boot/EFI/BOOT/bootx64.efi` |
| `--grub` | `boot/EFI/BOOT/grubx64.efi` |
| `--payload` | `boot` |

## Kernel and initrd

The first demonstrated boot uses the public
[6.18.34.mshv2 kernel tag](https://github.com/microsoft/CBL-Mariner-Linux-Kernel/tree/rolling-lts/kata/6.18.34.mshv2)
at commit `54d1300808c3a77b5772c7837393dfb9e60fac59`.
Start from `pkg/linux/6.18/x86_64.config` in `microsoft/openvmm-deps`,
enable `CONFIG_MSHV_ROOT=y`, retain `CONFIG_EFI_STUB=y`, and keep
`CONFIG_MODULES` disabled. Build `bzImage` out of tree. Disabling kernel debug
information is optional and reduces build size.

Reuse the x64 OpenVMM test initrd unchanged. Its `/init` mounts devtmpfs,
sysfs, and procfs and drops to a shell when no root disk is specified. No
custom initramfs or module installation is required for this milestone.

The unmodified kernel tag is sufficient for the `/init` milestone but needs
two corrections for the Incubator runtime:

* Release root I/O-APIC hypervisor mappings on IRQ-domain **deactivation**,
  before the parent recycles the vector, not only when freeing the domain.
  Otherwise probing can leave stale mappings and subsequent virtio MSI
  allocations fail with `HV_STATUS_INVALID_PARAMETER`.
* Preserve the two-bank `CreatePartition` wire layout for build 26100.
  Kernel commit `0ac2dd628657` expanded the processor-feature array to three
  banks, shifting the XSAVE and isolation fields. Sending that layout to the
  pinned payload causes `InitializePartition` to fail with
  `HV_STATUS_PROPERTY_VALUE_OUT_OF_RANGE`. The development compatibility fix
  is explicitly scoped to build 26100; other hypervisor versions need their
  own compatibility validation.

The demonstrated development kernel applies
[the IRQ deactivation fix](https://github.com/jstarks/OHCL-Linux-Kernel/commit/bf859fc5bde6)
and [the build-26100 ABI fix](https://github.com/jstarks/OHCL-Linux-Kernel/commit/910205359002)
on top of the public tag above. These are development patches, not a claim that
the unmodified public tag or other hypervisor versions support this runtime.

Use built-in PCIe, virtio-blk, virtio-net, virtio-9p, and devtmpfs drivers.
Incubator injects a bootstrap script into a temporary copy of the base initrd;
it does not modify the original file.

## Compose

```bash
cargo run -p incubator --bin incubator-mshv-image -- \
  --shim /artifacts/shimx64.efi \
  --grub /artifacts/grubx64.efi \
  --payload /artifacts/mshv-boot \
  --kernel /build/linux/arch/x86/boot/bzImage \
  --initrd /build/initramfs.cpio.gz \
  --kernel-cmdline 'console=ttyS0,115200 rdinit=/init' \
  --output /build/mshv.img
```

The output parent directory must exist. Existing output files are never
overwritten. Payload files must be regular files (no symlinks); the `Windows`
tree must use ASCII FAT-compatible names. Space-separated command-line options
are individually single-quoted for GRUB, so multiple options reach Linux as
separate arguments rather than one quoted string. Quotes and control characters
are rejected; option values containing spaces are not supported.
Image size is derived from input lengths with space reserved for filesystem
metadata. File contents are streamed rather than buffering the entire image.
File and directory timestamps are fixed at the valid FAT epoch,
1980-01-01 00:00:00. Zero-valued FAT dates encode an invalid month and day;
GRUB 2.06 rejects them during directory probing and reports an unknown
filesystem even when firmware can read the ESP.

The generated layout is:

```text
EFI/BOOT/BOOTX64.EFI       shim
EFI/BOOT/grubx64.efi       GRUB
boot/grub2/grub.cfg       generated boot configuration
HvLoader.efi
lxhvloader.dll
Windows/System32/...     supplied runtime
bzImage
initramfs.cpio            supplied initramfs, unchanged (may be compressed)
```

GRUB invokes HvLoader with root scheduling and forced nested launch enabled,
then loads Linux and its initramfs if the loader returns success. The patched
Linux EFI stub reserves hypervisor memory and launches the hypervisor after
exiting EFI boot services. There is no `linuxloader.conf` or disk BCD store.

Keep Secure Boot disabled for the initial development environment. Shim is
still needed because the existing HvLoader requires its `SHIM_LOCK` protocol.
The recipe does not enable CVM features or hypervisor debugging.

## First boot

Build the launcher for the host architecture rather than reusing a potentially
cross-compiled VMM-test artifact:

```bash
cargo build -p openvmm
```

For x86-64 KVM, attach the disk explicitly through emulated PCIe. Plain
`--virtio-blk` uses VPCI, which requires VMBus; it is not an appropriate
attachment when using `--no-vmbus`.

```bash
target/debug/openvmm --single-process --hypervisor kvm --nested-virt \
  --uefi --uefi-firmware /path/to/MSVM.fd \
  --no-vmbus --memory 4G --processors 2 \
  --pcie-root-complex rc0,segment=1 --pcie-root-port rc0:boot \
  --virtio-blk memdiff:file:/path/to/mshv.img,pcie_port=boot \
  --com1 console --uefi-console-mode com1 \
  --guest-shutdown-action exit --guest-crash-action exit:1
```

Run this interactive example from a terminal, or add `--headless` for an
automated harness. Incubator supplies timeouts and captures logs outside the
guest. The nonzero segment avoids the nested hypervisor's legacy CF8/CFC
emulation: Linux must use ECAM to enumerate OpenVMM's PCIe devices.

Verify the expected kernel identity, the kernel message
`Hyper-V: running as root partition`, and `test -c /dev/mshv` in the initrd
shell. This proves the first boot milestone, not child-partition execution.
Loader errors reported to GRUB halt the boot. The first successful boot also
reported an unresolved kernel W+X mapping warning; reaching the shell does
not imply a warning-free or production-ready environment.

## Limits

The proof uses the existing `multiarch::openvmm_linux_x64_boot` test, with a
Pipette connection to the child followed by clean poweroff. It does not establish
compatibility with the entire Dom0 suite. Boot still reports W+X mapping and
managed-MSI placeholder warnings; the child may log transient SINT delivery
warnings. These are not suppressed or claimed resolved.

Private artifact acquisition remains deferred. Snapshotting a running nested
hypervisor needs separate correctness validation and is not assumed here.
