// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests that run on more than one architecture.

use anyhow::Context;
use futures::StreamExt;
use petri::ApicMode;
use petri::EfiDiagnosticsLogLevel;
use petri::MemoryConfig;
use petri::PetriHaltReason;
use petri::PetriVmBuilder;
use petri::PetriVmInspector;
use petri::PetriVmRuntime;
use petri::PetriVmmBackend;
use petri::ProcessorTopology;
use petri::SIZE_1_GB;
use petri::ShutdownKind;
use petri::openvmm::OpenVmmPetriBackend;
use petri::pipette::cmd;
use petri_artifacts_common::tags::MachineArch;
use petri_artifacts_common::tags::OsFlavor;
#[cfg(target_os = "linux")]
use petri_artifacts_vmm_test::artifacts::OPENVMM_VHOST_NATIVE;
use vmm_test_macros::openvmm_test;
use vmm_test_macros::vmm_test;
use vmm_test_macros::vmm_test_with;

/// Test for the Windows DirectIO (`-net dio`) network backend.
mod dio_nic;
/// Tests for Hyper-V integration components.
mod ic;
// Memory Validation tests.
mod memstat;
/// NUMA topology tests.
mod numa;
/// Servicing tests.
mod openhcl_servicing;
/// PCIe emulation tests.
mod pcie;
/// Tests involving TPM functionality
mod tpm;
/// Tests for VLAN (802.1Q) support on virtual NICs.
mod vlan;
/// Tests of vmbus relay functionality.
mod vmbus_relay;
/// Tests involving VMGS functionality
mod vmgs;

/// Boot through the UEFI firmware, it will shut itself down after booting.
#[vmm_test_with(noagent(
    openvmm_uefi_x64(none),
    openvmm_openhcl_uefi_x64(none),
    openvmm_uefi_aarch64(none),
    hyperv_openhcl_uefi_aarch64(none),
    hyperv_openhcl_uefi_x64(none)
))]
async fn frontpage<T: PetriVmmBackend>(config: PetriVmBuilder<T>) -> anyhow::Result<()> {
    let vm = config.run_without_agent().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Basic boot test.
#[vmm_test(
    openvmm_linux_direct_x64,
    openvmm_linux_direct_aarch64,
    openvmm_openhcl_linux_direct_x64,
    openvmm_pcat_x64(vhd(windows_datacenter_core_2022_x64)),
    openvmm_pcat_x64(vhd(ubuntu_2404_server_x64)),
    openvmm_pcat_x64(vhd(ubuntu_2504_server_x64)),
    openvmm_uefi_aarch64(vhd(windows_11_enterprise_aarch64)),
    openvmm_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    openvmm_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    openvmm_uefi_x64(vhd(ubuntu_2404_server_x64)),
    openvmm_uefi_x64(vhd(ubuntu_2504_server_x64)),
    openvmm_openhcl_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    openvmm_openhcl_uefi_x64(vhd(ubuntu_2404_server_x64)),
    openvmm_openhcl_uefi_x64(vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_pcat_x64(vhd(windows_datacenter_core_2022_x64)),
    hyperv_openhcl_pcat_x64(vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_aarch64(vhd(windows_11_enterprise_aarch64)),
    hyperv_openhcl_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    hyperv_openhcl_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    hyperv_openhcl_uefi_x64(vhd(ubuntu_2404_server_x64)),
    hyperv_openhcl_uefi_x64(vhd(ubuntu_2504_server_x64)),
    unstable_openvmm_openhcl_uefi_x64[vbs](vhd(windows_datacenter_core_2025_x64_prepped)),
    // openvmm_openhcl_uefi_x64[vbs](vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_x64[vbs](vhd(windows_datacenter_core_2025_x64_prepped)),
    hyperv_openhcl_uefi_x64[vbs](vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_x64[snp](vhd(windows_datacenter_core_2025_x64_prepped)),
    hyperv_openhcl_uefi_x64[snp](vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_x64[tdx](vhd(windows_datacenter_core_2025_x64_prepped)),
    hyperv_openhcl_uefi_x64[tdx](vhd(ubuntu_2504_server_x64))
)]
async fn boot<T: PetriVmmBackend>(config: PetriVmBuilder<T>) -> anyhow::Result<()> {
    let (vm, agent) = config.run().await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Boot a Windows guest with x2APIC mode enabled at reset and an Intel VT-d
/// IOMMU advertising EIM=1 (Extended Interrupt Mode). The APIC starts in
/// x2APIC mode, so there is no dynamic xAPIC→x2APIC transition.
///
/// This is a regression test for a KVM synic SIMP overlay bug. When the guest
/// enabled the synic message page, OpenVMM did not zero it (KVM with
/// `KVM_CAP_HYPERV_SYNIC2` leaves the page in guest RAM), so a stale message
/// type in the SINT 3 slot caused KVM's in-kernel synic to treat the slot as
/// occupied and never deliver the Hyper-V synic timer interrupt. Windows then
/// hung in `HalpTimerInitializeClock` (`TimerProblemInterruptsNotFiring`).
#[openvmm_test(uefi_x64(vhd(windows_datacenter_core_2022_x64)))]
async fn boot_x2apic(config: PetriVmBuilder<OpenVmmPetriBackend>) -> Result<(), anyhow::Error> {
    let (mut vm, agent) = config
        .with_processor_topology(ProcessorTopology {
            vp_count: 4,
            apic_mode: Some(ApicMode::X2apicEnabled),
            ..Default::default()
        })
        .with_boot_device_type(petri::BootDeviceType::PcieNvme)
        .modify_backend(|b| {
            b.with_pcie_root_topology(1, 1, 2)
                .with_intel_vtd(&["s0rc0"])
        })
        .run()
        .await?;

    // Verify x2APIC is active by inspecting the APIC base MSR from the VMM.
    // Bit 10 of IA32_APIC_BASE is the x2APIC enable bit.
    let node = vm
        .backend()
        .inspector()
        .context("no inspector")?
        .inspect_path("partition/vp/0")
        .await?;
    let apic_base =
        find_inspect_value(&node, "apic_base").context("apic_base not found in inspect tree")?;
    assert!(
        apic_base & (1 << 10) != 0,
        "x2APIC not enabled: apic_base = {apic_base:#x} (bit 10 not set)",
    );

    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Recursively search an inspect node tree for a value with the given name.
fn find_inspect_value(node: &inspect::Node, name: &str) -> Option<u64> {
    match node {
        inspect::Node::Dir(entries) => {
            for entry in entries {
                if entry.name == name {
                    if let inspect::Node::Value(v) = &entry.node {
                        return match &v.kind {
                            inspect::ValueKind::Unsigned(x) => Some(*x),
                            inspect::ValueKind::Signed(x) => Some(*x as u64),
                            _ => None,
                        };
                    }
                }
                if let Some(v) = find_inspect_value(&entry.node, name) {
                    return Some(v);
                }
            }
            None
        }
        _ => None,
    }
}

/// Basic boot test using virtio vsock instead of vmbus hvsocket.
/// N.B. Because this requires kernel support, it's only done for Linux direct boot since the test
///      kernel is guaranteed to include it.
#[vmm_test(openvmm_linux_direct_x64, openvmm_linux_direct_aarch64)]
async fn boot_virtio_vsock(config: PetriVmBuilder<OpenVmmPetriBackend>) -> anyhow::Result<()> {
    let (vm, agent) = config
        .with_virtio_vsock()
        .modify_backend(|b| b.with_pcie_root_topology(1, 1, 1))
        .run()
        .await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Boot Linux direct with VMBus entirely disabled.
///
/// Virtio-vsock provides the pipette transport. No VMBus server, no VMBus
/// storage controllers, and no VMBus MMIO gaps in the memory layout.
#[vmm_test(openvmm_linux_direct_x64, openvmm_linux_direct_aarch64)]
async fn boot_no_vmbus(config: PetriVmBuilder<OpenVmmPetriBackend>) -> anyhow::Result<()> {
    let (vm, agent) = config
        .with_no_vmbus()
        .modify_backend(|b| b.with_pcie_root_topology(1, 1, 1))
        .run()
        .await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Boot with private anonymous memory instead of shared memory sections.
#[openvmm_test(
    linux_direct_x64,
    // TODO: add linux_direct_aarch64 (GH #1798)
)]
async fn boot_private_memory(config: PetriVmBuilder<OpenVmmPetriBackend>) -> anyhow::Result<()> {
    let (vm, agent) = config
        .modify_backend(|b| {
            b.with_custom_config(|c| {
                for node in &mut c.numa.nodes {
                    if let Some(mem) = &mut node.mem {
                        mem.private_memory = true;
                    }
                }
            })
        })
        .run()
        .await?;

    agent.ping().await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;

    Ok(())
}

/// Boot Linux with guest memory backed by explicit 2 MiB hugetlb pages.
#[cfg(target_os = "linux")]
#[openvmm_test(linux_direct_x64)]
#[openvmm_test(linux_direct_aarch64)]
async fn hugetlb_memory_boot(config: PetriVmBuilder<OpenVmmPetriBackend>) -> anyhow::Result<()> {
    const RAM_BYTES: u64 = 1024 * 1024 * 1024;

    let required_pages = RAM_BYTES / petri::openvmm::HUGETLB_2MB_PAGE_SIZE;
    if !petri::openvmm::ensure_2mb_hugetlb_pages(required_pages)? {
        return Ok(());
    }

    let (vm, agent) = config
        .with_memory(MemoryConfig {
            startup_bytes: RAM_BYTES,
            ..Default::default()
        })
        .modify_backend(|b| b.with_hugepages(Some(petri::openvmm::HUGETLB_2MB_PAGE_SIZE)))
        .run()
        .await?;

    agent.ping().await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;

    Ok(())
}

/// Basic boot test for images that require small amounts of ram, like alpine.
#[vmm_test(
    openvmm_uefi_x64(vhd(alpine_3_23_x64)),
    openvmm_openhcl_uefi_x64(vhd(alpine_3_23_x64)),
    hyperv_openhcl_uefi_x64(vhd(alpine_3_23_x64)),
    openvmm_uefi_aarch64(vhd(alpine_3_23_aarch64)),
    openvmm_openhcl_uefi_aarch64(vhd(alpine_3_23_aarch64)),
    hyperv_openhcl_uefi_aarch64(vhd(alpine_3_23_aarch64))
)]
async fn boot_small<T: PetriVmmBackend>(config: PetriVmBuilder<T>) -> anyhow::Result<()> {
    let (vm, agent) = config
        .with_memory(MemoryConfig {
            startup_bytes: SIZE_1_GB,
            ..Default::default()
        })
        .run()
        .await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Basic boot test without agent
#[vmm_test_with(noagent(
    openvmm_pcat_x64(vhd(freebsd_13_2_x64)),
    openvmm_pcat_x64(iso(freebsd_13_2_x64))
))]
async fn boot_no_agent<T: PetriVmmBackend>(config: PetriVmBuilder<T>) -> anyhow::Result<()> {
    let mut vm = config.run_without_agent().await?;
    vm.send_enlightened_shutdown(ShutdownKind::Shutdown).await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

// Basic vp "heavy" boot test with 16 VPs and 2 NUMA nodes.
#[vmm_test(
    openvmm_linux_direct_x64,
    openvmm_openhcl_linux_direct_x64,
    openvmm_pcat_x64(vhd(windows_datacenter_core_2022_x64)),
    openvmm_pcat_x64(vhd(ubuntu_2504_server_x64)),
    openvmm_uefi_aarch64(vhd(windows_11_enterprise_aarch64)),
    openvmm_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    openvmm_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    openvmm_uefi_x64(vhd(ubuntu_2504_server_x64)),
    openvmm_openhcl_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    openvmm_openhcl_uefi_x64(vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_pcat_x64(vhd(windows_datacenter_core_2022_x64)),
    hyperv_openhcl_pcat_x64(vhd(ubuntu_2504_server_x64)),
    unstable_hyperv_openhcl_uefi_aarch64(vhd(windows_11_enterprise_aarch64)),
    hyperv_openhcl_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    hyperv_openhcl_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    hyperv_openhcl_uefi_x64(vhd(ubuntu_2504_server_x64)),
    unstable_openvmm_openhcl_uefi_x64[vbs](vhd(windows_datacenter_core_2025_x64_prepped)),
    // openvmm_openhcl_uefi_x64[vbs](vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_x64[vbs](vhd(windows_datacenter_core_2025_x64_prepped)),
    hyperv_openhcl_uefi_x64[vbs](vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_x64[snp](vhd(windows_datacenter_core_2025_x64_prepped)),
    hyperv_openhcl_uefi_x64[snp](vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_x64[tdx](vhd(windows_datacenter_core_2025_x64_prepped)),
    hyperv_openhcl_uefi_x64[tdx](vhd(ubuntu_2504_server_x64))
)]
async fn boot_heavy<T: PetriVmmBackend>(config: PetriVmBuilder<T>) -> anyhow::Result<()> {
    let (vm, agent) = config
        .with_processor_topology(ProcessorTopology::heavy())
        .run()
        .await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Basic boot test with a single VP.
#[vmm_test(
    unstable_openvmm_openhcl_uefi_x64[vbs](vhd(windows_datacenter_core_2025_x64_prepped)),
    // openvmm_openhcl_uefi_x64[vbs](vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_x64[vbs](vhd(windows_datacenter_core_2025_x64_prepped)),
    hyperv_openhcl_uefi_x64[vbs](vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_x64[snp](vhd(windows_datacenter_core_2025_x64_prepped)),
    hyperv_openhcl_uefi_x64[snp](vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_x64[tdx](vhd(windows_datacenter_core_2025_x64_prepped)),
    hyperv_openhcl_uefi_x64[tdx](vhd(ubuntu_2504_server_x64))
)]
async fn boot_single_proc<T: PetriVmmBackend>(config: PetriVmBuilder<T>) -> anyhow::Result<()> {
    let (vm, agent) = config
        .with_processor_topology(ProcessorTopology {
            vp_count: 1,
            ..Default::default()
        })
        .run()
        .await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

#[vmm_test_with(vpci(
    // TODO: virt_whp is missing VPCI LPI interrupt support, used by Windows (but not Linux)
    // openvmm_uefi_aarch64(vhd(windows_11_enterprise_aarch64)),
    openvmm_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    // TODO: Linux image is missing VPCI driver in its initrd
    // openvmm_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    // openvmm_uefi_x64(vhd(ubuntu_2504_server_x64))
))]
async fn boot_nvme<T: PetriVmmBackend>(config: PetriVmBuilder<T>) -> anyhow::Result<()> {
    let (vm, agent) = config
        .with_boot_device_type(petri::BootDeviceType::Nvme)
        .run()
        .await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Tests NVMe boot with OpenHCL VPCI relaying enabled.
#[vmm_test_with(vpci(
    // TODO: aarch64 support (WHP missing ARM64 VTL2 support)
    // openvmm_openhcl_uefi_aarch64(vhd(windows_11_enterprise_aarch64)),
    // openvmm_openhcl_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    openvmm_openhcl_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    // TODO: Linux image is missing VPCI driver in its initrd
    // openvmm_openhcl_uefi_x64(vhd(ubuntu_2504_server_x64))
))]
async fn boot_nvme_vpci_relay<T: PetriVmmBackend>(config: PetriVmBuilder<T>) -> anyhow::Result<()> {
    let (vm, agent) = config
        .with_boot_device_type(petri::BootDeviceType::Nvme)
        .with_openhcl_command_line("OPENHCL_ENABLE_VPCI_RELAY=1")
        .with_vmbus_redirect(true)
        .run()
        .await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Validate we can reboot a VM and reconnect to pipette.
// TODO: Reenable openvmm guests that use the framebuffer once #74 is fixed.
#[vmm_test(
    openvmm_linux_direct_x64,
    openvmm_openhcl_linux_direct_x64,
    // openvmm_pcat_x64(vhd(windows_datacenter_core_2022_x64)),
    // openvmm_pcat_x64(vhd(ubuntu_2504_server_x64)),
    // openvmm_uefi_aarch64(vhd(windows_11_enterprise_aarch64)),
    // openvmm_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    // openvmm_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    // openvmm_uefi_x64(vhd(ubuntu_2504_server_x64)),
    // openvmm_openhcl_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    // openvmm_openhcl_uefi_x64(vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_pcat_x64(vhd(windows_datacenter_core_2022_x64)),
    hyperv_openhcl_pcat_x64(vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_aarch64(vhd(windows_11_enterprise_aarch64)),
    hyperv_openhcl_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    hyperv_openhcl_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    hyperv_openhcl_uefi_x64(vhd(ubuntu_2504_server_x64)),
    unstable_openvmm_openhcl_uefi_x64[vbs](vhd(windows_datacenter_core_2025_x64_prepped)),
    // openvmm_openhcl_uefi_x64[vbs](vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_x64[vbs](vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_x64[tdx](vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_x64[snp](vhd(ubuntu_2504_server_x64))
)]
async fn reboot<T: PetriVmmBackend>(config: PetriVmBuilder<T>) -> Result<(), anyhow::Error> {
    let (mut vm, agent) = config.run().await?;
    agent.ping().await?;
    agent.reboot().await?;
    let agent = vm.wait_for_reset().await?;
    agent.ping().await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Configure Guest VSM and reboot the VM to verify it works.
#[vmm_test(
    hyperv_openhcl_uefi_x64[vbs](vhd(windows_datacenter_core_2025_x64_prepped)),
    hyperv_openhcl_uefi_x64[snp](vhd(windows_datacenter_core_2025_x64_prepped)),
    hyperv_openhcl_uefi_x64[tdx](vhd(windows_datacenter_core_2025_x64_prepped)),
)]
#[cfg_attr(not(windows), expect(dead_code))]
async fn reboot_into_guest_vsm<T: PetriVmmBackend>(
    config: PetriVmBuilder<T>,
) -> Result<(), anyhow::Error> {
    let (mut vm, agent) = config.run().await?;
    let shell = agent.windows_shell();

    // VBS should be off by default
    let output = cmd!(shell, "systeminfo").output().await?;
    let output_str = String::from_utf8_lossy(&output.stdout);
    assert!(!output_str.contains("Virtualization-based security: Status: Running"));

    // Enable VBS
    cmd!(shell, "reg")
        .args([
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            "/v",
            "EnableVirtualizationBasedSecurity",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ])
        .run()
        .await?;
    // Enable Credential Guard
    cmd!(shell, "reg")
        .args([
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            "/v",
            "LsaCfgFlags",
            "/t",
            "REG_DWORD",
            "/d",
            "2",
            "/f",
        ])
        .run()
        .await?;
    // Enable HVCI
    cmd!(shell, "reg")
        .args([
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
            "/v",
            "Enabled",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ])
        .run()
        .await?;

    agent.reboot().await?;
    let agent = vm.wait_for_reset().await?;
    let shell = agent.windows_shell();

    // Verify VBS is running
    let output = cmd!(shell, "systeminfo").output().await?;
    let output_str = String::from_utf8_lossy(&output.stdout);
    assert!(output_str.contains("Virtualization-based security: Status: Running"));
    let output_running = &output_str[output_str.find("Services Running:").unwrap()..];
    assert!(output_running.contains("Credential Guard"));
    assert!(output_running.contains("Hypervisor enforced Code Integrity"));

    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Enable the Hyper-V role in a Windows guest, verify the hypervisor
/// management service is running after reboot, and start a small L2 VM
/// to confirm nested virtualization works.
#[openvmm_test(uefi_x64(vhd(windows_datacenter_core_2022_x64_no_vmbus_prepped)))]
async fn boot_hyperv_role(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
    (): (),
    driver: pal_async::DefaultDriver,
) -> Result<(), anyhow::Error> {
    let mut vm = config
        .with_no_vmbus()
        .with_boot_device_type(petri::BootDeviceType::PcieNvme)
        .with_default_boot_always_attempt(true)
        .modify_backend(|b| {
            // Root ports:
            //   s0rc0rp0 — boot NVMe (auto)
            //   s0rc0rp1 — cidata NVMe (auto)
            //   s0rc0rp2 — TCP pipette NIC
            //   s0rc0rp3 — extra NVMe for DDA to L2
            b.with_nested_virt()
                .with_pcie_root_topology(1, 1, 4)
                .with_intel_vtd(&["s0rc0"])
                .with_pcie_nvme(
                    "s0rc0rp3",
                    guid::guid!("a1b2c3d4-e5f6-7890-abcd-ef0123456789"),
                )
                .with_tcp_pipette_nic("s0rc0rp2")
                .with_custom_config(|c| {
                    // Set ACS capability bits on root ports for proper IOMMU
                    // group isolation (SV + RR + CR + UF).
                    for rc in &mut c.pcie_root_complexes {
                        for port in &mut rc.ports {
                            port.acs_capabilities_supported = Some(0x5D);
                        }
                    }
                })
        })
        .run_without_agent()
        .await?;

    // Wait for the guest to initialize VT-d and potentially hang, then dump.
    pal_async::timer::PolledTimer::new(&driver)
        .sleep(std::time::Duration::from_secs(10))
        .await;
    let dump_path = std::path::Path::new("/tmp/vtd-hang.vmrs");
    tracing::info!("Dumping VM state to {}", dump_path.display());
    vm.backend().dump_state(dump_path).await?;
    anyhow::bail!("dumped state to {}", dump_path.display());

    let agent = vm.wait_for_agent().await?;
    let shell = agent.windows_shell();

    // Check guest CPU virtualization capabilities.
    let cpu_info = cmd!(shell, "powershell.exe")
        .args(["-Command", r#"
            $p = Get-CimInstance Win32_Processor | Select-Object -First 1
            Write-Host "VMMonitorModeExtensions: $($p.VMMonitorModeExtensions)"
            Write-Host "VirtualizationFirmwareEnabled: $($p.VirtualizationFirmwareEnabled)"
            Write-Host "HypervisorPresent: $((Get-CimInstance Win32_ComputerSystem).HypervisorPresent)"
            Write-Host "Processor: $($p.Name)"
        "#])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("Guest CPU info:\n{cpu_info}");

    // Install the Hyper-V role and management tools. DISM returns exit code
    // 3010 when a restart is required, which is expected.
    for feature in [
        "Microsoft-Hyper-V",
        "Microsoft-Hyper-V-Management-PowerShell",
    ] {
        let output = cmd!(shell, "dism.exe")
            .args([
                "/online",
                "/enable-feature",
                &format!("/featurename:{feature}"),
                "/all",
                "/norestart",
            ])
            .ignore_status()
            .output()
            .await?;
        let exit_code = output.status.code().context("dism terminated by signal")?;
        anyhow::ensure!(
            exit_code == 0 || exit_code == 3010,
            "dism /enable-feature {feature} failed with exit code {exit_code}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Ensure the hypervisor launches on next boot.
    cmd!(shell, "bcdedit.exe")
        .args(["/set", "hypervisorlaunchtype", "auto"])
        .run()
        .await?;

    // Reboot to start the hypervisor.
    agent.reboot().await?;
    let agent = vm.wait_for_reset().await?;
    let shell = agent.windows_shell();

    // Verify the Hyper-V Virtual Machine Management service is running.
    let output = cmd!(shell, "sc.exe").args(["query", "vmms"]).read().await?;
    assert!(
        output.contains("RUNNING"),
        "vmms service is not running: {output}"
    );

    // Diagnostic: check hypervisor status, BCD config, and installed features.
    let systeminfo = cmd!(shell, "systeminfo").read().await?;
    tracing::info!("systeminfo (hypervisor section):");
    for line in systeminfo.lines() {
        if line.contains("Hyper-V")
            || line.contains("hypervisor")
            || line.contains("Virtualization")
        {
            tracing::info!("  {line}");
        }
    }
    let bcd = cmd!(shell, "bcdedit.exe").ignore_status().read().await?;
    tracing::info!("bcdedit output:\n{bcd}");
    let features = cmd!(shell, "dism.exe")
        .args(["/online", "/get-features", "/format:table"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("Hyper-V features:");
    for line in features.lines() {
        if line.contains("Hyper-V") {
            tracing::info!("  {line}");
        }
    }
    let wmi = cmd!(shell, "powershell.exe")
        .args(["-Command", "Get-WmiObject -Namespace root\\virtualization\\v2 -Class Msvm_VirtualSystemManagementService -ErrorAction SilentlyContinue | Select-Object Name,Started"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("WMI virtualization namespace query: {wmi}");

    // Check if the Windows hypervisor actually loaded.
    let hvlog = cmd!(shell, "powershell.exe")
        .args(["-Command", "Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-Hypervisor-Admin' -MaxEvents 20 -ErrorAction SilentlyContinue | Format-List TimeCreated,Id,LevelDisplayName,Message"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("Hyper-V Hypervisor event log:\n{hvlog}");
    let hvstatus = cmd!(shell, "powershell.exe")
        .args(["-Command", "Get-WinEvent -LogName System -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -match 'Hyper-V' -or $_.Message -match 'hypervisor' } | Format-List TimeCreated,Id,ProviderName,LevelDisplayName,Message"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("System log Hyper-V entries:\n{hvstatus}");

    // Check VID driver and VMMS service details.
    let vid = cmd!(shell, "sc.exe")
        .args(["query", "vid"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("vid driver status: {vid}");
    let vmms_detail = cmd!(shell, "sc.exe")
        .args(["qc", "vmms"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("vmms service config: {vmms_detail}");
    let vmcompute = cmd!(shell, "sc.exe")
        .args(["query", "vmcompute"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("vmcompute service status: {vmcompute}");
    let wmi_ns = cmd!(shell, "powershell.exe")
        .args(["-Command", "Get-WmiObject -Namespace root\\virtualization\\v2 -List -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Msvm' } | Select-Object -First 10 Name"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("WMI v2 namespace Msvm classes:\n{wmi_ns}");

    // Deep diagnostics: check hypervisor driver load, VMMS logs, and VM worker logs.
    let hv_drivers = cmd!(shell, "driverquery.exe")
        .args(["/v"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("Hyper-V related drivers:");
    for line in hv_drivers.lines() {
        let lower = line.to_lowercase();
        if lower.contains("hv")
            || lower.contains("vid")
            || lower.contains("vmbus")
            || lower.contains("hypervisor")
            || lower.contains("virt")
        {
            tracing::info!("  {line}");
        }
    }

    let vmms_log = cmd!(shell, "powershell.exe")
        .args(["-Command", "Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-VMMS-Admin' -MaxEvents 20 -ErrorAction SilentlyContinue | Format-List TimeCreated,Id,LevelDisplayName,Message"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("VMMS event log:\n{vmms_log}");

    // Check why vmbusr is not running.
    let vmbusr_status = cmd!(shell, "sc.exe")
        .args(["query", "vmbusr"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("vmbusr service status: {vmbusr_status}");
    let vmbusr_start = cmd!(shell, "sc.exe")
        .args(["start", "vmbusr"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("vmbusr manual start attempt: {vmbusr_start}");
    let vmbusr_deps = cmd!(shell, "sc.exe")
        .args(["qc", "vmbusr"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("vmbusr config: {vmbusr_deps}");
    let system_errors = cmd!(shell, "powershell.exe")
        .args(["-Command", "Get-WinEvent -LogName System -MaxEvents 200 -ErrorAction SilentlyContinue | Where-Object { $_.LevelDisplayName -eq 'Error' -or $_.LevelDisplayName -eq 'Warning' } | Format-List TimeCreated,Id,ProviderName,LevelDisplayName,Message"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("System log errors/warnings:\n{system_errors}");

    let worker_log = cmd!(shell, "powershell.exe")
        .args(["-Command", "Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-Worker-Admin' -MaxEvents 20 -ErrorAction SilentlyContinue | Format-List TimeCreated,Id,LevelDisplayName,Message"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("Hyper-V Worker event log:\n{worker_log}");

    let compute_log = cmd!(shell, "powershell.exe")
        .args(["-Command", "Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-Compute-Admin' -MaxEvents 20 -ErrorAction SilentlyContinue | Format-List TimeCreated,Id,LevelDisplayName,Message"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("Hyper-V Compute event log:\n{compute_log}");

    // List all Hyper-V event logs that have events.
    let all_hv_logs = cmd!(shell, "powershell.exe")
        .args(["-Command", "Get-WinEvent -ListLog *Hyper-V* -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 } | Format-Table LogName,RecordCount -AutoSize"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("All Hyper-V event logs with entries:\n{all_hv_logs}");

    // Check if the hypervisor is actually running via CPUID/firmware.
    let firmware_type = cmd!(shell, "powershell.exe")
        .args(["-Command", "[System.Environment]::Is64BitOperatingSystem; (Get-CimInstance Win32_ComputerSystem).HypervisorPresent; (Get-CimInstance Win32_OperatingSystem).Caption"])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("System info: {firmware_type}");

    // Create and start a small L2 VM to verify nested virtualization works.
    // VMMS may still be initializing its WMI provider after the first boot
    // with Hyper-V enabled, so retry New-VM a few times.
    cmd!(shell, "powershell.exe")
        .args([
            "-Command",
            "$attempt = 0; while ($attempt -lt 10) { try { New-VM -Name TestL2 -MemoryStartupBytes 64MB -Generation 2 -NoVHD -ErrorAction Stop; break } catch { $attempt++; if ($attempt -ge 10) { throw }; Start-Sleep -Seconds 5 } }",
        ])
        .run()
        .await?;
    cmd!(shell, "powershell.exe")
        .args(["-Command", "Start-VM -Name TestL2"])
        .run()
        .await?;
    let state = cmd!(shell, "powershell.exe")
        .args(["-Command", "(Get-VM -Name TestL2).State"])
        .read()
        .await?;
    assert!(state.contains("Running"), "L2 VM is not running: {state}");
    cmd!(shell, "powershell.exe")
        .args([
            "-Command",
            "Stop-VM -Name TestL2 -TurnOff -Force; Remove-VM -Name TestL2 -Force",
        ])
        .run()
        .await?;

    // --- DDA (Discrete Device Assignment) test ---
    //
    // Find the extra NVMe controller on root port s0rc0rp3, dismount it
    // from the L1 host, assign it to a new L2 VM, and verify the L2 starts.

    // Diagnostic: check if the L1 hypervisor exposes DDA / IOMMU support.
    let dda_diag = cmd!(shell, "powershell.exe")
        .args(["-Command", r#"
            Write-Host "=== DDA / IOMMU Diagnostics ==="

            # Check VMHost DDA support
            $vmHost = Get-VMHost -ErrorAction SilentlyContinue
            Write-Host "IovSupport: $($vmHost.IovSupport)"
            Write-Host "IovSupportReasons: $($vmHost.IovSupportReasons)"

            # Check pcip.sys driver status
            $pcip = Get-PnpDevice -FriendlyName '*pcip*' -ErrorAction SilentlyContinue
            if (-not $pcip) { $pcip = sc.exe query pcip 2>&1 }
            Write-Host "pcip driver: $pcip"

            # Check if pcip.sys file exists
            $pcipPath = "$env:SystemRoot\System32\drivers\pcip.sys"
            Write-Host "pcip.sys exists: $(Test-Path $pcipPath)"

            # Try loading pcip manually
            $loadResult = sc.exe start pcip 2>&1
            Write-Host "pcip start attempt: $loadResult"

            # Check ACPI DMAR table visibility from the hypervisor
            $dmar = Test-Path "/sys/firmware/acpi/tables/DMAR" -ErrorAction SilentlyContinue
            Write-Host "DMAR table check: $dmar"

            # Check IOMMU-related registry keys
            $iommuReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\HAL" -ErrorAction SilentlyContinue
            Write-Host "HAL reg: $($iommuReg | Format-List | Out-String)"

            # Check hypervisor features via WMI
            $hvInfo = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemManagementServiceSettingData -ErrorAction SilentlyContinue
            Write-Host "VMMS settings: $($hvInfo | Select-Object * | Format-List | Out-String)"

            # List system devices related to IOMMU/DMA remapping
            $iommuDevs = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
                $_.FriendlyName -match 'IOMMU|DMA|DMAR|Remap|Intel.*VT' -or
                $_.InstanceId -match 'IOMMU|DMAR|ACPI\\INTL'
            }
            Write-Host "IOMMU-related devices:"
            $iommuDevs | Format-List InstanceId,FriendlyName,Class,Status | Out-Host

            # Check hypervisor CPUID for IOMMU support (leaf 0x40000006)
            # This isn't directly queryable from PowerShell, but the event
            # log may have clues.
            $hvEvents = Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-Hypervisor-Admin' -MaxEvents 50 -ErrorAction SilentlyContinue
            foreach ($e in $hvEvents) {
                if ($e.Message -match 'IOMMU|DMA|remap|assign|partition') {
                    Write-Host "HV event: $($e.TimeCreated) $($e.Id) $($e.Message)"
                }
            }

            # Check system event log for pcip errors
            $pcipEvents = Get-WinEvent -LogName System -MaxEvents 200 -ErrorAction SilentlyContinue |
                Where-Object { $_.ProviderName -match 'pcip|pci' -or $_.Message -match 'pcip' }
            foreach ($e in $pcipEvents) {
                Write-Host "PCI event: $($e.TimeCreated) $($e.Id) [$($e.ProviderName)] $($e.LevelDisplayName): $($e.Message)"
            }
        "#])
        .ignore_status()
        .read()
        .await?;
    tracing::info!("DDA diagnostics:\n{dda_diag}");

    //
    // The OpenVMM NVMe emulator has PCI vendor 1414 (Microsoft), device
    // c03e. We find all matching controllers, pick the one on the
    // highest-numbered root port (our DDA target), and capture both its
    // PnP instance ID (for Disable-PnpDevice) and PCI location path
    // (for the DDA cmdlets).
    let dda_info = cmd!(shell, "powershell.exe")
        .args(["-Command", r#"
            $devs = Get-PnpDevice -InstanceId 'PCI\VEN_1414&DEV_C03E*' -ErrorAction SilentlyContinue |
                Where-Object { $_.Status -eq 'OK' }
            if (-not $devs -or @($devs).Count -lt 2) {
                # Diagnostic: show all PCI devices
                Get-PnpDevice -ErrorAction SilentlyContinue |
                    Where-Object { $_.InstanceId -match '^PCI\\' } |
                    Format-List InstanceId,Class,FriendlyName,Status | Out-Host
                Write-Error "Expected at least 2 NVMe controllers (VEN_1414&DEV_C03E), found $(@($devs).Count)"
                exit 1
            }
            # Pick the controller on the highest-numbered root port.
            $best = $null
            $bestPath = $null
            foreach ($d in @($devs)) {
                $paths = (Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName DEVPKEY_Device_LocationPaths -ErrorAction SilentlyContinue).Data
                foreach ($p in $paths) {
                    if ($p -match 'PCIROOT' -and ($bestPath -eq $null -or $p -gt $bestPath)) {
                        $best = $d
                        $bestPath = $p
                    }
                }
            }
            if (-not $best) {
                Write-Error "Could not find PCI location path for any NVMe controller"
                exit 1
            }
            # Output instance ID on line 1, location path on line 2.
            Write-Output $best.InstanceId
            Write-Output $bestPath
        "#])
        .read()
        .await?;
    let mut lines = dda_info.lines().filter(|l| !l.trim().is_empty());
    let dda_instance_id = lines
        .next()
        .context("missing instance ID in DDA discovery output")?
        .trim();
    let dda_location_path = lines
        .next()
        .context("missing location path in DDA discovery output")?
        .trim();
    tracing::info!("DDA target: instance={dda_instance_id} location={dda_location_path}");

    // Disable the device before dismounting.
    cmd!(shell, "powershell.exe")
        .args([
            "-Command",
            &format!(
                "Disable-PnpDevice -InstanceId '{}' -Confirm:$false",
                dda_instance_id
            ),
        ])
        .run()
        .await?;

    // Dismount the device from the host so it can be assigned to a VM.
    cmd!(shell, "powershell.exe")
        .args([
            "-Command",
            &format!(
                "Dismount-VMHostAssignableDevice -LocationPath '{}' -Force",
                dda_location_path
            ),
        ])
        .run()
        .await?;

    // Create a Gen2 VM and assign the device to it.
    cmd!(shell, "powershell.exe")
        .args([
            "-Command",
            "$attempt = 0; while ($attempt -lt 10) { try { New-VM -Name TestL2DDA -MemoryStartupBytes 512MB -Generation 2 -NoVHD -ErrorAction Stop; break } catch { $attempt++; if ($attempt -ge 10) { throw }; Start-Sleep -Seconds 5 } }",
        ])
        .run()
        .await?;

    // Set the automatic stop action to TurnOff to avoid save-state issues
    // with assigned devices.
    cmd!(shell, "powershell.exe")
        .args([
            "-Command",
            "Set-VM -Name TestL2DDA -AutomaticStopAction TurnOff",
        ])
        .run()
        .await?;

    // Assign the device to the VM.
    cmd!(shell, "powershell.exe")
        .args([
            "-Command",
            &format!(
                "Add-VMAssignableDevice -VMName TestL2DDA -LocationPath '{}'",
                dda_location_path
            ),
        ])
        .run()
        .await?;

    // Verify the device is listed as assigned.
    let assigned_devs = cmd!(shell, "powershell.exe")
        .args([
            "-Command",
            "Get-VMAssignableDevice -VMName TestL2DDA | Format-List",
        ])
        .read()
        .await?;
    tracing::info!("Assigned devices on TestL2DDA:\n{assigned_devs}");
    assert!(
        !assigned_devs.trim().is_empty(),
        "No devices assigned to TestL2DDA"
    );

    // Start the L2 VM with the assigned device.
    cmd!(shell, "powershell.exe")
        .args(["-Command", "Start-VM -Name TestL2DDA"])
        .run()
        .await?;
    let state = cmd!(shell, "powershell.exe")
        .args(["-Command", "(Get-VM -Name TestL2DDA).State"])
        .read()
        .await?;
    assert!(
        state.contains("Running"),
        "L2 DDA VM is not running: {state}"
    );

    // Clean up.
    cmd!(shell, "powershell.exe")
        .args([
            "-Command",
            "Stop-VM -Name TestL2DDA -TurnOff -Force; Remove-VM -Name TestL2DDA -Force",
        ])
        .run()
        .await?;

    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Basic boot test with secure boot enabled and a valid template.
#[vmm_test(
    openvmm_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    openvmm_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    openvmm_uefi_x64(vhd(ubuntu_2504_server_x64)),
    openvmm_openhcl_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    openvmm_openhcl_uefi_x64(vhd(ubuntu_2504_server_x64)),
    hyperv_uefi_aarch64(vhd(windows_11_enterprise_aarch64)),
    hyperv_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    hyperv_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    hyperv_uefi_x64(vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_aarch64(vhd(windows_11_enterprise_aarch64)),
    hyperv_openhcl_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    hyperv_openhcl_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    hyperv_openhcl_uefi_x64(vhd(ubuntu_2504_server_x64))
)]
async fn secure_boot<T: PetriVmmBackend>(config: PetriVmBuilder<T>) -> anyhow::Result<()> {
    let (vm, agent) = config.with_secure_boot().run().await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Verify that secure boot fails with a mismatched template.
/// TODO: Allow Hyper-V VMs to load a UEFI firmware per VM, not system wide.
#[vmm_test_with(noagent(
    openvmm_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    openvmm_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    openvmm_uefi_x64(vhd(ubuntu_2504_server_x64)),
    openvmm_openhcl_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    openvmm_openhcl_uefi_x64(vhd(ubuntu_2504_server_x64)),
    // hyperv_uefi_aarch64(vhd(windows_11_enterprise_aarch64)),
    // hyperv_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    // hyperv_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    // hyperv_uefi_x64(vhd(ubuntu_2504_server_x64)),
    hyperv_openhcl_uefi_aarch64(vhd(windows_11_enterprise_aarch64)),
    hyperv_openhcl_uefi_aarch64(vhd(ubuntu_2404_server_aarch64)),
    hyperv_openhcl_uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    hyperv_openhcl_uefi_x64(vhd(ubuntu_2504_server_x64))
))]
async fn secure_boot_mismatched_template<T: PetriVmmBackend>(
    config: PetriVmBuilder<T>,
) -> anyhow::Result<()> {
    let config = config
        .with_expect_boot_failure()
        .with_secure_boot()
        .with_uefi_frontpage(false);
    let config = match config.os_flavor() {
        OsFlavor::Windows => config.with_uefi_ca_secure_boot_template(),
        OsFlavor::Linux => config.with_windows_secure_boot_template(),
        _ => anyhow::bail!("Unsupported OS flavor for test: {:?}", config.os_flavor()),
    };
    let vm = config.run_without_agent().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Test EFI diagnostics with no boot devices.
/// TODO:
///   - uefi_x64 + uefi_aarch64 trace searching support
#[vmm_test_with(noagent(
    hyperv_openhcl_uefi_x64(none),
    hyperv_openhcl_uefi_aarch64(none),
    openvmm_openhcl_uefi_x64(none)
))]
async fn efi_diagnostics_no_boot<T: PetriVmmBackend>(
    config: PetriVmBuilder<T>,
) -> anyhow::Result<()> {
    let vm = config.with_uefi_frontpage(true).run_without_agent().await?;

    // Expected no-boot message.
    const NO_BOOT_MSG: &str = "[Bds] Unable to boot!";

    // Get kmsg stream
    let mut kmsg = vm.kmsg().await?;

    // Search for the message
    while let Some(data) = kmsg.next().await {
        let data = data.context("reading kmsg")?;
        let msg = kmsg::KmsgParsedEntry::new(&data).unwrap();
        let raw = msg.message.as_raw();
        if raw.contains(NO_BOOT_MSG) {
            return Ok(());
        }
    }

    anyhow::bail!("Did not find expected message in kmsg");
}

/// Test EFI diagnostics with INFO-level logging enabled
/// TODO:
///  - change hyperv tests to use WMI instead of env_cfg once
///    CI runners support it
#[vmm_test_with(noagent(
    openvmm_openhcl_uefi_x64(none),
    hyperv_openhcl_uefi_x64(none),
    hyperv_openhcl_uefi_aarch64(none)
))]
async fn efi_diagnostics_info_level<T: PetriVmmBackend>(
    config: PetriVmBuilder<T>,
) -> anyhow::Result<()> {
    let vm = config
        .with_uefi_frontpage(true)
        .with_efi_diagnostics_log_level(EfiDiagnosticsLogLevel::Info)
        .run_without_agent()
        .await?;

    // Marker emitted by `firmware_uefi::service::diagnostics` for every
    // UEFI log entry tagged with `DEBUG_INFO`.
    //
    // Presence of this marker in the kmsg output validates that.
    const INFO_MARKER: &str = "debug_level=INFO";

    let mut kmsg = vm.kmsg().await?;

    while let Some(data) = kmsg.next().await {
        let data = data.context("reading kmsg")?;
        let msg = kmsg::KmsgParsedEntry::new(&data).unwrap();
        let raw = msg.message.as_raw();
        if raw.contains(INFO_MARKER) {
            return Ok(());
        }
    }

    anyhow::bail!("Did not find any INFO-level UEFI diagnostics entry ({INFO_MARKER:?}) in kmsg");
}

/// Boot our guest-test UEFI image, which will run some tests,
/// and then purposefully triple fault itself via an expiring
/// watchdog timer.
#[vmm_test_with(noagent(
    openvmm_uefi_x64(guest_test_uefi_x64),
    openvmm_uefi_aarch64(guest_test_uefi_aarch64),
    openvmm_openhcl_uefi_x64(guest_test_uefi_x64)
))]
async fn guest_test_uefi<T: PetriVmmBackend>(config: PetriVmBuilder<T>) -> anyhow::Result<()> {
    let vm = config
        .with_windows_secure_boot_template()
        .run_without_agent()
        .await?;
    let arch = vm.arch();
    // No boot event check, UEFI watchdog gets fired before ExitBootServices
    let halt_reason = vm.wait_for_teardown().await?;
    tracing::debug!("vm halt reason: {halt_reason:?}");
    let check_reason = |expected| {
        if halt_reason.reason != expected {
            anyhow::bail!("Expected {expected:?}, got {halt_reason:?}");
        }
        Ok(())
    };
    match arch {
        MachineArch::X86_64 => check_reason(PetriHaltReason::TripleFault),
        MachineArch::Aarch64 => check_reason(PetriHaltReason::Reset),
    }
}

/// Test that unauthenticated deletion of PK and KEK is rejected by the firmware.
/// With secure boot enabled, PK and KEK are authenticated variables. An unsigned
/// delete (e.g. `rm` via efivarfs) must fail, leaving the variables intact and
/// SetupMode unchanged.
#[vmm_test(
    openvmm_openhcl_uefi_x64(vhd(ubuntu_2404_server_x64)),
    openvmm_openhcl_uefi_x64(vhd(ubuntu_2504_server_x64)),
    openvmm_openhcl_uefi_aarch64(vhd(ubuntu_2404_server_aarch64))
)]
async fn secure_boot_pk_kek_unauthenticated_delete_rejected<T: PetriVmmBackend>(
    config: PetriVmBuilder<T>,
) -> anyhow::Result<()> {
    let (vm, agent) = config.with_secure_boot().run().await?;
    let shell = agent.unix_shell();

    const EFI_GLOBAL_VARIABLE_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";

    let pk_path = format!("/sys/firmware/efi/efivars/PK-{}", EFI_GLOBAL_VARIABLE_GUID);
    let kek_path = format!("/sys/firmware/efi/efivars/KEK-{}", EFI_GLOBAL_VARIABLE_GUID);
    let setup_mode_path = format!(
        "/sys/firmware/efi/efivars/SetupMode-{}",
        EFI_GLOBAL_VARIABLE_GUID
    );

    // Verify initial state: PK and KEK exist, SetupMode is 0
    let pk_exists = cmd!(shell, "sudo")
        .args(["test", "-f", &pk_path])
        .output()
        .await?;
    assert!(pk_exists.status.success(), "PK should exist initially");

    let kek_exists = cmd!(shell, "sudo")
        .args(["test", "-f", &kek_path])
        .output()
        .await?;
    assert!(kek_exists.status.success(), "KEK should exist initially");

    let setup_mode = cmd!(shell, "sudo")
        .args([
            "sh",
            "-c",
            &format!("od -An -t u1 {} | tail -c 2", setup_mode_path),
        ])
        .output()
        .await?;
    let sm = String::from_utf8_lossy(&setup_mode.stdout)
        .trim()
        .to_string();
    assert_eq!(sm, "0", "SetupMode should be 0 (secure boot active)");

    // Attempt to delete PK without authentication — should fail
    cmd!(shell, "sudo")
        .args([
            "sh",
            "-c",
            &format!("chattr -i {} 2>/dev/null || true", pk_path),
        ])
        .run()
        .await?;
    let pk_delete = cmd!(shell, "sudo")
        .args(["rm", "-f", &pk_path])
        .output()
        .await?;

    // Verify PK still exists after failed delete attempt
    let pk_still_exists = cmd!(shell, "sudo")
        .args(["test", "-f", &pk_path])
        .output()
        .await?;
    assert!(
        pk_still_exists.status.success(),
        "PK should still exist after unauthenticated delete attempt (rm exit status: {})",
        pk_delete.status,
    );

    // Attempt to delete KEK without authentication — should fail
    cmd!(shell, "sudo")
        .args([
            "sh",
            "-c",
            &format!("chattr -i {} 2>/dev/null || true", kek_path),
        ])
        .run()
        .await?;
    let kek_delete = cmd!(shell, "sudo")
        .args(["rm", "-f", &kek_path])
        .output()
        .await?;

    // Verify KEK still exists after failed delete attempt
    let kek_still_exists = cmd!(shell, "sudo")
        .args(["test", "-f", &kek_path])
        .output()
        .await?;
    assert!(
        kek_still_exists.status.success(),
        "KEK should still exist after unauthenticated delete attempt (rm exit status: {})",
        kek_delete.status,
    );

    // Verify SetupMode is still 0 — the failed deletes should not change it
    let setup_mode_after = cmd!(shell, "sudo")
        .args([
            "sh",
            "-c",
            &format!("od -An -t u1 {} | tail -c 2", setup_mode_path),
        ])
        .output()
        .await?;
    let sm_after = String::from_utf8_lossy(&setup_mode_after.stdout)
        .trim()
        .to_string();
    assert_eq!(
        sm_after, "0",
        "SetupMode should still be 0 after failed delete attempts"
    );

    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Boot with a virtio-blk device served by the openvmm_vhost binary over
/// a vhost-user Unix socket.  Verifies the full stack: guest driver →
/// virtio transport → frontend protocol → socket → backend protocol →
/// virtio-blk device → disk file.
#[cfg(target_os = "linux")]
#[openvmm_test(
    linux_direct_x64[OPENVMM_VHOST_NATIVE],
    linux_direct_aarch64[OPENVMM_VHOST_NATIVE],
)]
async fn vhost_user_blk_device<T>(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
    extra_deps: (petri::ResolvedArtifact<T>,),
    driver: pal_async::DefaultDriver,
) -> anyhow::Result<()> {
    use openvmm_defs::config::VirtioBus;
    use pal_async::pipe::PolledPipe;
    use pal_async::task::Spawn;
    use virtio_resources::vhost_user::VhostUserBlkHandle;
    use vm_resource::IntoResource;

    let (openvmm_vhost_artifact,) = extra_deps;
    let openvmm_vhost_path = openvmm_vhost_artifact.get();

    let log_file = config.log_source().log_file("openvmm_vhost")?;

    // Create a temporary directory for the socket and disk file.
    let tmp_dir = tempfile::tempdir().context("create temp dir")?;
    let socket_path = tmp_dir.path().join("vhost.sock");
    let disk_path = tmp_dir.path().join("test.raw");

    // Create a small raw disk file (8 MiB).
    let disk_size: u64 = 8 * 1024 * 1024;
    {
        let f = std::fs::File::create(&disk_path).context("create disk file")?;
        f.set_len(disk_size).context("set disk length")?;
    }

    // Spawn the openvmm_vhost backend process. Pipe stderr so we can
    // forward it to the petri log system.
    let (stderr_read, stderr_write) = pal::pipe_pair()?;
    let backend_child = std::process::Command::new(openvmm_vhost_path)
        .arg("--socket")
        .arg(&socket_path)
        .arg("blk")
        .arg("--disk")
        .arg(&disk_path)
        .env("RUST_LOG", "debug")
        .stdout(stderr_write.try_clone()?)
        .stderr(stderr_write)
        .spawn()
        .context("spawn openvmm_vhost")?;

    // Guard that kills the backend if the test exits early.
    struct ChildGuard(Option<std::process::Child>);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let mut backend_guard = ChildGuard(Some(backend_child));

    // Forward backend stderr to a petri log file.
    let _log_task = driver.spawn(
        "openvmm_vhost stderr",
        petri::log_task(
            log_file,
            PolledPipe::new(&driver, stderr_read)?,
            "openvmm_vhost",
        ),
    );

    // Wait for the socket to appear (the server creates it on listen).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !socket_path.exists() {
        if std::time::Instant::now() > deadline {
            if let Some(status) = backend_guard.0.as_mut().unwrap().try_wait()? {
                anyhow::bail!("openvmm_vhost exited early with status: {status}");
            }
            anyhow::bail!(
                "timed out waiting for vhost-user socket at {}",
                socket_path.display()
            );
        }
        pal_async::timer::PolledTimer::new(&driver)
            .sleep(std::time::Duration::from_millis(50))
            .await;
    }

    // Connect to the backend and build the VM config.
    let stream =
        unix_socket::UnixStream::connect(&socket_path).context("connect to vhost-user socket")?;

    let vhost_resource = VhostUserBlkHandle {
        socket: stream.into(),
        num_queues: None,
        queue_size: None,
    }
    .into_resource();

    let (vm, agent) = config
        .modify_backend(move |b| {
            b.with_custom_config(|c| {
                c.virtio_devices.push((VirtioBus::Mmio, vhost_resource));
            })
        })
        .run()
        .await?;

    let sh = agent.unix_shell();

    // Verify the virtio-blk device appears as /dev/vda.
    let vda_size = cmd!(sh, "cat /sys/block/vda/size")
        .read()
        .await
        .context("virtio-blk device /dev/vda not found")?;
    let vda_sectors: u64 = vda_size.trim().parse().context("parse vda size")?;
    let expected_sectors = disk_size / 512;
    assert_eq!(
        vda_sectors, expected_sectors,
        "unexpected disk size in sectors"
    );

    // Write data and read it back.
    cmd!(
        sh,
        "sh -c 'echo hello_vhost_user | dd of=/dev/vda bs=512 count=1 conv=notrunc 2>/dev/null'"
    )
    .read()
    .await
    .context("write to vhost-user-blk device")?;
    let readback = cmd!(
        sh,
        "sh -c 'dd if=/dev/vda bs=512 count=1 2>/dev/null | head -c 16'"
    )
    .read()
    .await
    .context("read from vhost-user-blk device")?;
    assert!(
        readback.starts_with("hello_vhost_user"),
        "read back data mismatch: {readback}"
    );

    // Clean shutdown.
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;

    // The backend serves one connection and exits. Take the child out
    // of the guard so we can wait for clean exit.
    let mut backend_child = backend_guard.0.take().unwrap();
    let status = backend_child.wait().context("wait for openvmm_vhost")?;
    assert!(
        status.success(),
        "openvmm_vhost exited with non-zero status: {status}"
    );

    Ok(())
}
