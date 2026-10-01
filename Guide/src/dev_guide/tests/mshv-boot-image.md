# Minimal mshv boot image

The experimental `incubator-mshv-image` binary constructs an x86-64 raw GPT disk
with a FAT32 EFI System Partition from supplied boot artifacts. Construction is
entirely in Rust using the workspace's `gptman`, `fatfs`, and `fscommon` crates:
no host mounts, RPM installation, filesystem utilities, or GRUB tools are used.

This is an image composer, **not yet an Incubator execution backend**. Artifact
acquisition and booting the resulting image are separate steps. Nested boot on
OpenVMM/KVM has not yet been validated.

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
tree must use ASCII FAT-compatible names. Command lines are passed literally
through GRUB single quotes; single quotes and control characters are rejected.
Image size is derived from input lengths with space reserved for filesystem
metadata. File contents are streamed rather than buffering the entire image.

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

A boot reaching Linux is not sufficient evidence of success: the eventual
runtime harness must verify the expected kernel and successfully create/run
an mshv partition. Loader errors reported to GRUB halt the boot; missing mshv
initialization must also be caught by that runtime check.

## Remaining integration

1. Pin and acquire compatible prebuilt boot artifacts without host package tools.
2. Supply a minimal initramfs and prove a nested OpenVMM/KVM boot and mshv smoke test.
3. Add an OpenVMM launcher/profile to Incubator, preserving current QEMU behavior.
4. Connect Pipette, test artifacts, nextest, and externally captured boot logs.

Start with cold boots. Snapshotting a running nested hypervisor needs separate
correctness validation and is not assumed by this design.
