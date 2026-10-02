# Incubator

Incubator runs test executables inside a disposable Linux environment through
Pipette. QEMU TCG provides emulated hardware; the experimental OpenVMM/KVM
backend provides an x86-64 mshv root partition using
[public boot artifacts](mshv-boot-image.md).

## When to use Incubator

Use Incubator for tests that need hardware behavior outside the normal OpenVMM
host test environment.

Ordinary VMM tests should continue to use `cargo xflowey vmm-tests-run`
without `--incubator`. QEMU TCG is significantly slower than native execution,
so the QEMU profile is reserved for tests that need its emulated platform.
The mshv profile instead uses hardware-assisted nested virtualization.

## Execution model

Incubator introduces an outer VM around the normal Petri test process:

```text
x64 Linux host
  `- Incubator process
       `- QEMU TCG AArch64 Linux VM (L1)
            |- Pipette agent
            `- VMM test executable
                 `- OpenVMM using KVM
                      `- test VM (L2)
```

The VMM test executable is cross-compiled for
`*-unknown-linux-musl`. It runs inside the QEMU VM and starts OpenVMM
there. OpenVMM then uses the emulated KVM interface to create the test VM.

Incubator is therefore not an OpenVMM backend. It is a Cargo target runner that
places the existing test executable in a machine capable of running it.

## Running the current Incubator tests

Run the AArch64 TCG test set from a Linux host:

```bash
cargo xflowey vmm-tests-run \
  --incubator \
  --target linux-aarch64-musl \
  --filter "test(aarch64_tcg)"
```

`--target` is required with `--incubator`.

To select a profile explicitly, pass either its short name or a path:

```bash
cargo xflowey vmm-tests-run \
  --incubator aarch64-tcg-pcie \
  --target linux-aarch64-musl \
  --filter "test(aarch64_tcg)"
```

## Direct invocation

For the mshv backend, copy
`petri/incubator/profiles/x86_64-mshv.toml` outside the checkout and replace its
placeholder paths with a **native host** OpenVMM executable, x64 MSVM firmware,
and the extracted public boot-artifact directory. Keep the host executable
separate from the musl OpenVMM binary built for the child tests.

The root kernel must have mshv EFI launch support and the kernel fixes
described in [Minimal mshv boot image](mshv-boot-image.md). Then run the existing
Linux-direct boot test:

```bash
INCUBATOR_KERNEL=/path/to/mshv/bzImage \
INCUBATOR_INITRD=/path/to/test/initrd \
cargo xflowey vmm-tests-run --target linux-x64-musl \
  --incubator /path/to/mshv-profile.toml \
  --filter 'test(=multiarch::openvmm_linux_x64_boot)'
```

Flowey builds the same static musl test/guest artifacts used by the Dom0 test
configuration. Nextest stays on the host, including discovery; each target-runner
invocation cold-boots the root partition. `INCUBATOR_KERNEL` and
`INCUBATOR_INITRD` override Flowey's boot inputs, not the child test's kernel.
Missing mshv kernels fail explicitly instead of selecting a stock test kernel.

The outer mshv VM uses **no VMBus**. PCIe segment 1 supplies the boot disk,
virtio-9p share, and virtio-net NIC; loopback TCP forwarding reaches Pipette.
The share is writable, so this is a trusted development environment, not a
sandbox for untrusted guest programs.

The binary also has a direct CLI for debugging the runner itself:

```bash
cargo run -p incubator -- \
  --profile petri/incubator/profiles/aarch64-tcg-pcie.toml \
  --share path/to/shared-root \
  --map-command-path \
  path/to/shared-root/test-binary
```

Direct use requires a suitable kernel, initrd, Pipette binary, QEMU, and shared
test artifacts. Running through `cargo xflowey vmm-tests-run` is preferred
because Flowey resolves and connects those inputs automatically.

## Output and failures

Incubator writes per-process `incubator-serial.<PID>.log` and
`incubator-vmm.<PID>.log` files under the test output directory. Guest command
stdout and stderr flow through Pipette to nextest; the guest exit code is
preserved.

When a run fails, check the serial log first. It distinguishes a guest boot or
Pipette startup failure from a failure in the nested VMM test itself. VMM
stderr is streamed directly to the VMM log rather than held in memory.

For mshv, `--timeout` / `INCUBATOR_TIMEOUT` bounds VM boot and command execution
(default 300 seconds). Shutdown gets another 10 seconds before the runner
kills and reaps the VMM. QEMU retains its boot-only timeout. Each new invocation
starts fresh; temporary boot images and patched initrds are removed on normal
completion and handled errors. Snapshots and private artifact acquisition are
not part of this path.
