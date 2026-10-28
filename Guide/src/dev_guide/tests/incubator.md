# Incubator

Incubator runs commands and interactive shells in disposable Linux VMs using
Petri, keeping builds, caches, and logs on the host.

## Launcher and boot selection

`[incubator]` selects the launcher and VM resources; `[boot]` selects the guest
environment and defaults to `linux-direct`. Standalone QEMU uses a native
`qemu-system-aarch64` executable on Linux; OpenVMM requires x64 Linux with KVM.

| Launcher | Boot environment | Current support |
|----------|------------------|-----------------|
| `qemu-tcg` | `linux-direct` | AArch64 guest on Linux |
| `openvmm` | `linux-direct` | x64 Linux guest on x64 Linux |
| `openvmm` | `mshv` | x64 mshv root partition on x64 Linux |
| `qemu-tcg` | `mshv` | AArch64 guest on Linux x64 or ARM64; local runtime required |

Registered VMM tests use [Petri nested tests](vmm.md#nested-tests), not an
Incubator Flowey target runner. Each Incubator invocation cold-boots a VM.

## QEMU commands

```bash
cargo run -p incubator -- \
  --profile petri/incubator/profiles/aarch64-tcg-pcie.toml \
  --kernel path/to/Image --initrd path/to/initrd \
  --share path/to/shared-root \
  --guest-pipette /share/pipette \
  --map-command-path path/to/shared-root/test-binary
```

The kernel and static Pipette binary must match the guest architecture. Place
Pipette and the command binary beneath the shared directory.
Profile devices are provisioned for VFIO before the command runs.

### Provision an ARM64 mshv environment

The standalone ARM64 mshv path boots a GPT/FAT32 disk through QEMU `sbsa-ref`
firmware, then runs HvLoader and the root kernel's EFI stub. Hypervisor launch,
root Linux discovery, `/dev/mshv`, Pipette commands, an OpenVMM L2 Linux
boot/poweroff, and clean outer shutdown have been validated with a single CPU.
This path remains experimental. Select `--backend qemu-tcg` explicitly;
omitting it preserves the x64/OpenVMM default. Neither KVM nor native ARM64
virtualization is required.

Hyper-V and `lxhvloader.dll` must be supplied locally as a matching ARM64 set:

```text
path/to/arm64-runtime/
  boot/lxhvloader.dll
  boot/Windows/System32/hvaa64.exe
  boot/Windows/...                 other matching runtime files
```

Flowey checks the required PE architectures, preserves the Windows tree, and
stages a content-addressed copy with the public HvLoader. It does not modify
your directory or use a supplied `HvLoader.efi` in preference to the public
one. Architecture validation does not establish version compatibility.

Until the ARM64 dependency packages are published and pinned, supply the root
kernel and extracted public CI packages explicitly:

```bash
cargo xflowey incubator --backend qemu-tcg \
  --boot-artifacts path/to/arm64-runtime \
  --kernel path/to/mshv/Image \
  --mshv-sbsa-firmware path/to/extracted-sbsa-package \
  --mshv-hvloader path/to/extracted-hvloader-package \
  --timeout 600 -- /bin/sh -c 'test -c /dev/mshv && uname -a'
```

This builds native Incubator, ARM64 musl Pipette, and ARM64
`mshv_host_boot.efi`, and resolves native-host `qemu-system-aarch64` and the
ARM64 initrd. It never downloads the private runtime or falls back to x64 RPMs.
`--rpm-cache` and `--offline` apply only to the OpenVMM/x64 backend.
Use `--prepare-only` instead of a command to generate
`target/incubator/profile.toml` and print a reusable interactive command.
Logs are under `target/incubator/results/incubator-*`.
The shared-directory and containment rules below apply to both backends.

To override the paired firmware directly, provide both
`--firmware path/to/SBSA_FLASH0.fd` and
`--firmware-vars path/to/SBSA_FLASH1.fd`. The latter is a template, never the
per-run writable copy. Do not mix firmware from different builds.
For the registered ignored nested smoke, see
[ARM64 QEMU-TCG MSHV](vmm.md#arm64-qemu-tcg-mshv).

### ARM64 firmware and manual bring-up

Supply compatible ARM64 HvLoader, `lxhvloader.dll`, and the complete hypervisor
runtime, an ARM64 mshv EFI-launch kernel with 4 KiB pages, a test initrd, and
matching TF-A/UEFI SBSA firmware. MSVM and QEMU `virt` firmware are not
interchangeable with SBSA firmware. The pinned x64 RPMs and x64 `mshv-test`
kernel cannot be reused for ARM64.

The `openvmm-deps` `sbsa-mshv` package builds the paired firmware from pinned
TF-A, EDK2, and edk2-platforms sources. Its ARM64 archive is
`openvmm-test-sbsa-mshv.aarch64.<release>.tar.gz`, containing both flash images
and a build manifest. It includes the virtio drivers and temporary loader
workaround described below; loader and hypervisor payloads remain separate.

The separate `hvloader` package builds the public ARM64 EFI application from
pinned HvLoader and EDK2 sources. Flowey stages `HvLoader.efi` from
`openvmm-test-hvloader.aarch64.<release>.tar.gz` separately from your runtime.
For manual provisioning, copy it into the boot-artifact directory's `boot/`
subdirectory. The archive includes licenses and a build
manifest. It is unsigned and does not include `lxhvloader.dll` or the
hypervisor runtime; supply those separately.

Use TF-A's `qemu_sbsa` platform and EDK2's
`Platform/Qemu/SbsaQemu/SbsaQemu.dsc`. Set `boot.firmware` to `SBSA_FLASH0.fd`
(TF-A) and `boot.firmware-vars` to `SBSA_FLASH1.fd` (UEFI code and variables).
Size both images for QEMU's flash banks; the validated configuration uses
256 MiB images. Incubator copies flash1 for each run, preserving your template.
The UEFI build must include PCI virtio transport and virtio block drivers so
it can read the boot disk. These drivers are not present in every SBSA build.
Secure Boot must be disabled.

```admonish warning title="Development loader compatibility"
Some loader versions apply read-only PE section protections before writing
their import tables. These versions require a development firmware workaround
that uninstalls `EFI_MEMORY_ATTRIBUTE_PROTOCOL` before launching HvLoader.
SBSA's Arm platform boot manager does not provide the QEMU `virt` firmware's
`UninstallMemAttrProtocol` fw_cfg switch. Use a corrected loader or explicitly
prepared development firmware; do not assume an unmodified SBSA image works.
```

Build the host tools, ARM64 agent, and development EFI application:

```bash
rustup target add aarch64-unknown-uefi aarch64-unknown-linux-musl
cargo build -p incubator --profile light
cargo build -p pipette --target aarch64-unknown-linux-musl
cargo build -p mshv_host_boot --target aarch64-unknown-uefi
```

Copy `petri/incubator/profiles/aarch64-tcg-mshv.toml` outside the checkout,
set its local executable/artifact paths, and point `host-boot` at
`target/aarch64-unknown-uefi/debug/mshv_host_boot.efi`. Start with the supplied
single-CPU profile and no assignment devices:

```bash
target/light/incubator \
  --profile path/to/aarch64-mshv.toml \
  --kernel path/to/mshv/Image --initrd path/to/aarch64/initrd \
  --share "$PWD" \
  --guest-pipette /share/target/aarch64-unknown-linux-musl/debug/pipette \
  --output-dir target/aarch64-mshv-logs --timeout 600 \
  --no-pty /bin/sh -c 'test -c /dev/mshv && uname -a'
```

QEMU runs explicitly with TCG. `sbsa-ref` provides EL2 and EL3 without
`virtualization=on` or `secure=on` machine properties; do not add those
`virt`-specific properties to the SBSA profile. TF-A implements PSCI at EL3,
and SBSA's ACPI FADT advertises its SMC conduit. This lets root Linux perform
normal SMCCC hypervisor discovery without overriding the FADT identity.
Use `[boot]` command-line overrides; leave `[incubator].cmdline` empty.
ARM64 defaults select the PL011 Linux console and omit x86 APIC policy.
Pipette uses TCP/user networking and the writable 9p share, not OpenVMM's
virtio-vsock setup. Missing `/dev/mshv` fails bootstrap before starting Pipette.

Firmware must preserve an EL2 handoff; the hypervisor must also accept QEMU's
GIC, timers, PSCI, and ACPI descriptions. CPU emulation alone does not establish
this compatibility. Inspect `guest.log` and `qemu.log` when bringing up a new
firmware/payload combination. OpenVMM queries the host's processor-feature banks
and supplies explicit masks when creating ARM64 child partitions, rather than
relying on the kernel's legacy defaults.
SMP, device assignment, and CCA/TF-RMM remain separate follow-up work. The
ordinary mshv profile does not enable RME or load an RMM.

## OpenVMM commands

### Provision an mshv environment

On an x64 Linux host with KVM and nested virtualization enabled:

```bash
cargo xflowey incubator -- \
  /bin/sh -c 'test -c /dev/mshv && uname -a'
```

This builds the native OpenVMM/Incubator pair, static x64 Pipette, and EFI host
boot application; downloads the pinned mshv root kernel, firmware, shared
test initrd, and verified hypervisor/loader RPMs; then boots and executes the
command non-interactively. Incubator uses the `light` build profile by default.
`--release` selects release builds for all components; the normal VMM/agent
build profile remains independent of the optimized launcher. It never checks
out, configures, patches, or builds a kernel. `--kernel /path/to/mshv/bzImage`
overrides the published `mshv-test` kernel. It selects only the root kernel,
not a child VM's kernel.

The writable share defaults to this checkout. `--share` selects a different
workspace; `--dir` defaults to `target/incubator` within that share and must
remain beneath it so Incubator can read the staged Pipette. Preparation updates
`profile.toml` and retains compatible binaries for direct reuse after other
Flowey jobs. Unchanged binaries are reused across kernel edits. Per-run logs
remain in `results/incubator-*`; do not use the same directory concurrently.

Use `--prepare-only` without a guest command to prepare everything and print
a direct Incubator command for `/bin/sh`. Run that printed command for an
interactive shell without going through Flowey again. Copy the generated
profile before customizing it. `--kernel-cmdline` and `--hypervisor-cmdline`
override the checked-in profile's boot options without rebuilding EFI code.

`--initrd`, `--firmware`, and `--boot-artifacts` accept explicit local inputs.
`--rpm-cache` reuses an existing RPM cache; `--offline` prohibits only mshv RPM
downloads, not Rust or other dependency downloads. Cached RPMs and extracted
payloads are checked on reuse; corrupt caches fail rather than being trusted.
Packaged licenses and source URLs/hashes are retained with the extracted
payloads. No RPM is installed and no package script runs.

### Supply artifacts manually

Build the native launcher and Incubator from the same checkout for protocol
compatibility, and build a static guest agent:

```bash
cargo build -p openvmm
cargo build -p incubator --profile light
cargo build -p pipette --target x86_64-unknown-linux-musl
cargo build -p mshv_host_boot --target x86_64-unknown-uefi
```

Copy `petri/incubator/profiles/x86_64-mshv.toml` outside the checkout and set
absolute paths for `binary`, `host-boot`, `firmware`, and `boot-artifacts`. Set
`host-boot` to the built `target/x86_64-unknown-uefi/debug/mshv_host_boot.efi`.
This environment requires `nested-virt = true`, a compatible mshv root kernel,
and the [boot artifacts below](#mshv-boot-artifacts-and-kernel).

```bash
target/light/incubator \
  --profile path/to/mshv-profile.toml \
  --kernel path/to/mshv/bzImage \
  --initrd path/to/test/initrd \
  --share "$PWD" \
  --guest-pipette /share/target/x86_64-unknown-linux-musl/debug/pipette \
  --output-dir target/mshv-logs \
  --no-pty /bin/sh -c 'test -c /dev/mshv && uname -a'
```

Omit `--no-pty` and run `/bin/sh` for an interactive session. Pipette must be
inside the shared directory. Keep the mshv root kernel separate from any
child VM's kernel, and the native outer OpenVMM separate from guest binaries.

To expose virtual SMT explicitly, set `enable-smt = true` alongside
`processors` in `[incubator]`. Omission preserves the launcher's default.
This controls the outer topology, not the child VM's vCPU count. Verify the
effective hypervisor scheduler in its boot log when comparing ROOT and CORE;
requesting CORE without SMT can select a classic scheduler instead.

Incubator supplies Petri with a `UefiGuest::Mshv` boot recipe: resolved kernel
and payload paths plus an owned, prepared initrd. Petri composes and owns the
temporary boot disk during VM preparation; the separate mshv platform preset
configures nested virtualization and the required devices.

OpenVMM guests use virtio-console (`console=hvc0`) for Linux output and
guest-initiated virtio-vsock for Pipette. The host listener exists before boot;
agent connection does not poll TCP readiness. The network remains available for
guest workloads. UEFI/host-boot/HvLoader output stays on the 16550 UART. The
mshv default disables Linux UART initialization with `8250.nr_uarts=0`; this
does not affect firmware output. For early Linux UART diagnostics, select
`console=ttyS0` and replace that option with `8250.nr_uarts=2` in the mshv
kernel options. Selecting both consoles duplicates Linux output. QEMU keeps its
existing TCP agent transport.

For OpenVMM **without mshv**, use
`petri/incubator/profiles/x86_64-openvmm.toml` with a native executable path,
an ordinary x64 Linux kernel, and the test initrd. No firmware or hypervisor
payloads are needed. Set `nested-virt = true` to create child KVM VMs, and replace
the example's `/dev/mshv` check with your command.

## mshv boot artifacts and kernel

The standalone Incubator executable does not download payloads; Flowey resolves
the public support packages and, for x64, pinned RPMs. ARM64 Hyper-V and
`lxhvloader.dll` always remain user-provided. Keep authorized binaries, their
packaged licenses, and generated images outside Git; public availability does
not change licensing terms.

The artifact directory must contain:

```text
boot/
  HvLoader.efi
  lxhvloader.dll
  Windows/System32/...   complete matching runtime
```

For x64, both `hvix64.exe` and `hvax64.exe` must be present under
`Windows/System32`; ARM64 media requires `hvaa64.exe` instead. Shim and GRUB
are not used. The validated x64 Azure Linux 3 payload recipe uses
edk2-hvloader 20240524git3e722403cd16-20 and matching `mshv` /
`mshv-bootloader-lx` 26100.9444.2609032029.1-1 payloads. The composer does not
verify provenance, signatures, architecture, or compatibility.

The root kernel needs the mshv EFI-launch patches, `CONFIG_EFI_STUB=y`,
`CONFIG_MSHV_ROOT=y`, and built-in PCIe, virtio-blk, virtio-net, virtio-9p,
devtmpfs, and initramfs support. Disable modules and reuse the OpenVMM test
initrd. A stock upstream test kernel cannot launch this environment.
Build virtio-console and virtio-vsock into the root kernel as well. Petri
selects the matching vsock initcall blacklist for both Linux-direct and mshv
UEFI boot, preventing the competing Hyper-V socket driver from claiming it.

The `mshv-test` dependency recipe targets released
`rolling-lts/kata/6.18.34.mshv4` plus the root
[IO-APIC IRQ-lifecycle fix](https://github.com/jstarks/OHCL-Linux-Kernel/commit/4178badb4e34).
That release already restores the two-bank partition-feature ABI; the older
mshv2 development kernel needed a separate compatibility patch. Kernel build
and source selection remain independent of OpenVMM provisioning.

To compose an image without launching it:

```bash
cargo run -p incubator --bin incubator-mshv-image -- \
  --host-boot target/x86_64-unknown-uefi/debug/mshv_host_boot.efi \
  --payload path/to/artifacts/boot \
  --kernel path/to/bzImage --initrd path/to/initrd \
  --kernel-cmdline 'console=ttyS0 rdinit=/init' \
  --output path/to/new-mshv.img
```

The output parent must exist; existing output is never overwritten. Payload
files must be regular files with ASCII FAT-compatible names.
For ARM64, pass `--arch aarch64` and matching ARM64 inputs. The image contains
`EFI/BOOT/BOOTAA64.EFI` and `Image`; x64 remains the default, using
`EFI/BOOT/BOOTX64.EFI` and `bzImage`.

### Boot command lines

The host boot application uses the EFI Simple File System protocol to read two
UTF-8 files at the ESP root. They contain literal load options, not shell or
GRUB code:

| File | Contents |
|------|----------|
| `linux.cmdline` | `initrd=\initramfs.cpio` followed by Linux options |
| `hvloader.cmdline` | `\lxhvloader.dll` followed by hypervisor options |

For Incubator, set `kernel-cmdline` and `hypervisor-cmdline` in `[boot]`; Petri
appends the prepared initrd's required `rdinit` and vsock driver selection. The
standalone image composer exposes `--kernel-cmdline` and `--hypervisor-cmdline`.
Both paths write these files when composing media. You can also edit the files
on an existing ESP without rebuilding the host boot application, kernel, or
hypervisor.

Each file is limited to 16 KiB and a single UCS-2-compatible line, with an
optional final LF or CRLF. Quotes, spaces, backslashes, and shell metacharacters
are passed literally. Missing or malformed configuration fails the boot rather
than selecting hidden defaults. The host boot application initializes HvLoader,
then enters Linux's EFI stub; the modified kernel retains responsibility for
launching the hypervisor.

## Sharing and guest trust

```admonish warning
The host share is writable. Incubator is a trusted development environment,
not a sandbox for untrusted guest programs.
```

The mshv host boot is development-only and refuses Secure Boot mode. Its
`SHIM_LOCK` verification callback deliberately accepts every image; it does not
authenticate signatures or implement shim's measurements.

All environments copy the host CA bundle into the temporary initrd and export
`SSL_CERT_FILE=/incubator-ca-certificates.crt` for guest TLS clients. A nonempty
host `SSL_CERT_FILE` selects the bundle; otherwise a conventional Linux system
bundle is required. An invalid or unreadable bundle fails the run. The guest
inherits that trust, including enterprise CAs, without copying private keys or
disabling verification. Its clock is initialized from the host.

## Output and failures

Each invocation creates an `incubator-*` directory beneath `--output-dir`, with
console logs (`hvc0.log` for OpenVMM Linux, `uefi.log` for firmware/early UART,
or `guest.log` for QEMU), VMM logs (`openvmm.log` or `qemu.log`),
and `petri.jsonl`. Direct Incubator keeps guest stdout/stderr separate from
runner diagnostics; xflowey also prints provisioning logs. Use the prepared
direct command when stdout must contain only guest output. Use `--guest-env`
or `INCUBATOR_ENV` for guest environment overrides.

`--timeout` / `INCUBATOR_TIMEOUT` bounds boot for Linux-direct and boot plus
command execution for mshv. Graceful shutdown and teardown each have a
ten-second deadline. OpenVMM cleanup is best-effort: startup cancellation or
an unresponsive VMM can leave a host process requiring manual termination.
Direct Incubator invocations preserve the guest exit code. Through xflowey,
a nonzero guest exit fails the pipeline with Flowey's failure status instead.
Unexpected VM exit/reset and timeouts fail.
SIGINT/SIGTERM attempt cleanup; SIGKILL cannot. Temporary boot files are removed
on normal teardown and handled errors; logs remain on the host.
