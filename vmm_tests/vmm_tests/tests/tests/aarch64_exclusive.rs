// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for aarch64 guests.

use anyhow::Context;
use petri::PetriVmBuilder;
use petri::PetriVmmBackend;
use petri::openvmm::OpenVmmPetriBackend;
use petri::pipette::cmd;
use vm_resource::IntoResource;
use vmm_test_macros::openvmm_test;
use vmm_test_macros::vmm_test;

/// Boot Linux and verify the PMU interrupt is available.
///
/// TODO: This is only supported on WHP and Hyper-V.
///
#[vmm_test(
    // TODO: requires aarch64 serial emulator changes, or petri changes to use
    // something other than serial. GH issue 1790.
    //
    // openvmm_linux_direct_aarch64,
    openvmm_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    hyperv_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    hyperv_openhcl_uefi_aarch64(vhd(ubuntu_2404_server_aarch64))
)]
async fn pmu_gsiv<T: PetriVmmBackend>(config: PetriVmBuilder<T>) -> Result<(), anyhow::Error> {
    let (vm, agent) = config.run().await?;

    // Check dmesg for logs about the PMU.
    let shell = agent.unix_shell();
    let dmesg = cmd!(shell, "dmesg").read().await?;

    // There should be no lines that look like the following:
    //  "No ACPI PMU IRQ for CPU0"
    dmesg.lines().try_for_each(|line| {
        if line.contains("No ACPI PMU IRQ for CPU") {
            Err(anyhow::anyhow!("PMU IRQ not found in dmesg: {}", line))
        } else {
            Ok(())
        }
    })?;

    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;

    Ok(())
}

/// Boot ARM64 Linux in device-tree mode (full DT, no ACPI).
// TODO: disabled until we get a kernel that supports DT boot with the
// current device configuration.
// #[openvmm_test(linux_direct_aarch64)]
#[expect(dead_code)]
async fn boot_dt(config: PetriVmBuilder<OpenVmmPetriBackend>) -> Result<(), anyhow::Error> {
    let (vm, agent) = config
        .modify_backend(|c| {
            c.with_custom_config(|c| {
                if let openvmm_defs::config::LoadMode::Linux { boot_mode, .. } = &mut c.load_mode {
                    *boot_mode = openvmm_defs::config::LinuxDirectBootMode::DeviceTree;
                }
            })
        })
        .run()
        .await?;

    // Verify we're in DT mode — no ACPI tables directory.
    let shell = agent.unix_shell();
    let output = cmd!(shell, "test -d /sys/firmware/acpi/tables")
        .ignore_status()
        .output()
        .await?;
    assert!(
        !output.status.success(),
        "ACPI tables should not exist in DT-only mode"
    );

    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Boot an aarch64 guest with no VMBus via linux direct boot.
///
/// This test is intended to run inside a QEMU TCG hosting VM with KVM,
/// validating that the basic aarch64 KVM boot path works.
///
/// Assigned to the `aarch64-tcg` nextest test group.
#[openvmm_test(linux_direct_aarch64)]
async fn boot_no_vmbus_pcie_aarch64_tcg(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
) -> anyhow::Result<()> {
    let (vm, agent) = config
        .with_no_vmbus()
        .with_memory(petri::MemoryConfig {
            startup_bytes: 1024 * 1024 * 1024,
            ..Default::default()
        })
        .modify_backend(|b| {
            b.with_pcie_root_topology(1, 1, 3).with_custom_config(|c| {
                // KVM/aarch64 does not support the synthetic hypervisor
                // interface (--hv).
                c.hypervisor.with_hv = false;
            })
        })
        .run()
        .await?;

    let sh = agent.unix_shell();
    let uname = cmd!(sh, "uname -r").read().await?;
    tracing::info!(uname = %uname, "guest booted successfully");

    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}
