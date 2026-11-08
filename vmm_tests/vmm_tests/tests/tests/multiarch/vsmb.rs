// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use openvmm_defs::config::DeviceVtl;
use petri::{PetriVmBuilder, openvmm::OpenVmmPetriBackend, pipette::cmd};
use vm_resource::IntoResource;
use vmm_test_macros::openvmm_test;
use vsmb_resources::VsmbMemoryDeviceHandle;

#[openvmm_test(uefi_x64(vhd(windows_datacenter_core_2025_x64)))]
async fn vsmb_memory_file_operations(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
) -> anyhow::Result<()> {
    let (vm, agent) = config
        .modify_backend(|b| {
            b.without_save_restore().with_custom_config(|c| {
                c.vmbus_devices.push((
                    DeviceVtl::Vtl0,
                    VsmbMemoryDeviceHandle {
                        share_name: "memory".into(),
                    }
                    .into_resource(),
                ));
            })
        })
        .run()
        .await?;
    let script = include_str!("../../../test_data/vsmb_file_operations.ps1");
    let shell = agent.windows_shell();
    cmd!(shell, "powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .run()
        .await?;
    for operation in ["reads", "writes"] {
        let path = format!("vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/external_data/{operation}");
        let value = vm.inspect_vmm(&path).await?.to_string();
        anyhow::ensure!(
            value.parse::<u64>()? > 0,
            "no actual external {operation} observed"
        );
    }
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}
