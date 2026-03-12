---
applyTo: "vmm_tests/**,petri/**"
---

# VMM Tests (Petri Framework)

VMM tests are end-to-end integration tests that boot real VMs. They live in
`vmm_tests/vmm_tests/tests/tests/` and use the **petri** framework (`petri/`).

Full documentation: `Guide/src/dev_guide/tests/vmm.md`

## Building & Running

The easiest way to build all artifacts and run VMM tests is `cargo xflowey`:

```bash
# Build everything + run a specific test
cargo xflowey vmm-tests --dir /tmp/vmm-test-out --filter 'test(my_test_name)'

# Build only (no test execution)
cargo xflowey vmm-tests --dir /tmp/vmm-test-out --build-only

# Auto-install missing system dependencies
cargo xflowey vmm-tests --dir /tmp/vmm-test-out --install-missing-deps --filter 'test(my_test)'
```

`--dir` is required — it's the output directory for a self-contained test
artifacts folder. `--filter` uses
[nextest filter syntax](https://nexte.st/docs/filtersets/).

Other useful flags: `--release`, `--target`, `--flags` (e.g., `+openvmm,-hyperv`).

## Test Macros

- `#[vmm_test(...)]` — runs on multiple backends (openvmm, Hyper-V, OpenHCL).
  The test function is generic over `T: PetriVmmBackend`.
- `#[openvmm_test(...)]` — openvmm-only. Takes `PetriVmBuilder<OpenVmmPetriBackend>`.
- `#[vmm_test_no_agent]` / `#[openvmm_test_no_agent]` — tests that don't
  need a guest agent (pipette).

Config names go inside the macro attribute parentheses, e.g.:

```rust
#[openvmm_test(linux_direct_x64)]
#[openvmm_test(uefi_x64(vhd(ubuntu_2504_server_x64)))]
#[vmm_test(
    openvmm_linux_direct_x64,
    openvmm_uefi_x64(vhd(ubuntu_2504_server_x64)),
    hyperv_uefi_x64(vhd(ubuntu_2504_server_x64))
)]
```

Note: `#[openvmm_test()]` auto-prefixes `openvmm_` to the test name, so
`linux_direct_x64` inside the macro becomes test name
`openvmm_linux_direct_x64_<fn_name>`.

## Test Naming

Full test name: `{backend}_{firmware}_{arch}_{fn_name}`, e.g.,
`openvmm_linux_direct_x64_boot_private_memory`.

## Test Pattern

```rust
#[openvmm_test(linux_direct_x64)]
async fn my_test(config: PetriVmBuilder<OpenVmmPetriBackend>) -> anyhow::Result<()> {
    let (vm, agent) = config
        .modify_backend(|b| b.with_custom_config(|c| { /* modify config */ }))
        .run()
        .await?;

    let sh = agent.unix_shell();
    cmd!(sh, "echo hello").run().await?;

    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}
```

## Petri Architecture

| Layer | Location | Visibility | Purpose |
|---|---|---|---|
| Worker | `petri/src/worker.rs` | `pub(crate)` | Wraps mesh WorkerHandle + VmRpc. NOT test-visible |
| Config | `petri/src/vm/openvmm/mod.rs`, `construct.rs`, `modify.rs` | `pub` | Config builder with `with_*()` methods |
| Runtime | `petri/src/vm/openvmm/runtime.rs` | `pub` | Running VM handle |
| Start | `petri/src/vm/openvmm/start.rs` | `pub(super)` | Bridges config → runtime via Worker::launch() |

Tests interact with `PetriVmBuilder` (config) and `PetriVm` (runtime). To add
new VM configuration options, add `with_*()` methods to
`PetriVmConfigOpenVmm` in `modify.rs` and wire them through `start.rs`.

## Key Files

- `vmm_tests/vmm_tests/tests/tests/multiarch.rs` — cross-architecture tests
- `vmm_tests/vmm_tests/tests/tests/x86_64.rs` — x86_64-specific tests
- `petri/src/vm/openvmm/modify.rs` — `with_*()` config methods
- `petri/src/vm/openvmm/start.rs` — VM launch orchestration
- `petri/src/worker.rs` — worker process management (internal)

## Debugging

```bash
# Full openvmm logs during test
OPENVMM_LOG=trace cargo nextest run -p vmm_tests -- my_test --no-capture

# List tests matching a pattern
cargo nextest list -p vmm_tests | grep my_test
```
