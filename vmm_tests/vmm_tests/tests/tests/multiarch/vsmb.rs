// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use openvmm_defs::config::DeviceVtl;
use pal_async::{DefaultDriver, timer::PolledTimer};
use petri::{PetriVmBuilder, openvmm::OpenVmmPetriBackend, pipette::cmd};
use vm_resource::IntoResource;
use vmm_test_macros::openvmm_test;
use vsmb_resources::VsmbMemoryDeviceHandle;

#[openvmm_test(uefi_x64(vhd(windows_datacenter_core_2025_x64)))]
async fn vsmb_memory_file_operations(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
    _extra_deps: (),
    driver: DefaultDriver,
) -> anyhow::Result<()> {
    let (mut vm, agent) = config
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
    agent
        .write_file("C:\\vsmb-cache-ready", b"waiting".as_slice())
        .await?;
    agent
        .write_file("C:\\vsmb-lock-ready", b"waiting".as_slice())
        .await?;
    agent
        .write_file("C:\\vsmb-idle-ready", b"waiting".as_slice())
        .await?;
    let command =
        cmd!(shell, "powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", script]);
    let checkpoint = async {
        let path = "vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/channel/connection/requests";
        let mut timer = PolledTimer::new(&driver);
        let mut pending = false;
        for _ in 0..400 {
            if vm
                .inspect_vmm(path)
                .await?
                .to_string()
                .contains("CHANGE_NOTIFY")
            {
                pending = true;
                break;
            }
            timer.sleep(std::time::Duration::from_millis(25)).await;
        }
        anyhow::ensure!(pending, "no server-side pending notification observed");
        vm.backend().pause().await?;
        anyhow::ensure!(
            vm.inspect_vmm(path)
                .await?
                .to_string()
                .contains("CHANGE_NOTIFY"),
            "pause discarded pending notification"
        );
        vm.backend().resume().await?;
        cmd!(shell, "powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[System.IO.File]::WriteAllText('C:\\vsmb-resume', 'go')",
            ])
            .run()
            .await?;
        let mut lock_ready = false;
        for _ in 0..400 {
            if agent.read_file("C:\\vsmb-lock-ready").await? == b"ready" {
                lock_ready = true;
                break;
            }
            timer.sleep(std::time::Duration::from_millis(25)).await;
        }
        anyhow::ensure!(lock_ready, "guest did not reach pending-lock checkpoint");
        let inspect::Node::Dir(requests) = vm.inspect_vmm(path).await? else {
            anyhow::bail!("request table is not inspectable");
        };
        let lock = requests
            .iter()
            .find(|entry| match &entry.node {
                inspect::Node::Dir(fields) => fields
                    .iter()
                    .any(|field| field.name == "command" && field.node.to_string() == "\"LOCK\""),
                _ => false,
            })
            .ok_or_else(|| anyhow::anyhow!("lock wait was not observed on the server"))?;
        let lock_path = format!("{path}/{}", lock.name);
        let waiting = lock.node.to_string();
        vm.backend().pause().await?;
        anyhow::ensure!(
            vm.inspect_vmm(&lock_path).await?.to_string() == waiting,
            "pause discarded or changed the pending lock"
        );
        vm.backend().resume().await?;
        anyhow::ensure!(
            vm.inspect_vmm(&lock_path).await?.to_string() == waiting,
            "resume completed or changed the lock before unlock"
        );
        agent
            .write_file("C:\\vsmb-lock-go", b"go".as_slice())
            .await?;
        let mut ready = false;
        for _ in 0..400 {
            if agent.read_file("C:\\vsmb-cache-ready").await? == b"ready" {
                ready = true;
                break;
            }
            timer.sleep(std::time::Duration::from_millis(25)).await;
        }
        anyhow::ensure!(ready, "guest did not reach cached-read checkpoint");
        let path = "vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/channel/connection/opens";
        let inspect::Node::Dir(opens) = vm.inspect_vmm(path).await? else {
            anyhow::bail!("open table is not inspectable");
        };
        let open = opens
            .iter()
            .find(|entry| match &entry.node {
                inspect::Node::Dir(fields) => fields.iter().any(|field| field.name == "caching"),
                _ => false,
            })
            .ok_or_else(|| anyhow::anyhow!("guest has no server-granted caching control"))?;
        let held_path = format!("{path}/{}/caching/provider/held", open.name);
        let held = vm.inspect_vmm(&held_path).await?.to_string();
        anyhow::ensure!(
            held.contains("Read"),
            "guest has no actual read caching rights: {held}"
        );
        let break_started = std::time::Instant::now();
        agent
            .write_file("C:\\vsmb-cache-go", b"go".as_slice())
            .await?;
        let mut written = false;
        for _ in 0..400 {
            if agent.read_file("C:\\vsmb-cache-ready").await? == b"written" {
                written = true;
                break;
            }
            timer.sleep(std::time::Duration::from_millis(25)).await;
        }
        anyhow::ensure!(written, "alias writer did not complete after lease break");
        anyhow::ensure!(
            break_started.elapsed() < std::time::Duration::from_secs(10),
            "lease break did not complete before the forced-revocation timeout"
        );
        let held = vm.inspect_vmm(&held_path).await?.to_string();
        anyhow::ensure!(
            held == "\"None\"",
            "foreign alias write did not revoke cached rights: {held}"
        );
        agent
            .write_file("C:\\vsmb-cache-read-go", b"go".as_slice())
            .await?;
        let mut idle = false;
        for _ in 0..400 {
            if agent.read_file("C:\\vsmb-idle-ready").await? == b"ready" {
                idle = true;
                break;
            }
            timer.sleep(std::time::Duration::from_millis(25)).await;
        }
        anyhow::ensure!(idle, "guest did not reach idle-share checkpoint");
        for _ in 0..50 {
            timer.sleep(std::time::Duration::from_millis(500)).await;
            let eof = vm
                .inspect_vmm("vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/channel/eof")
                .await?
                .to_string();
            anyhow::ensure!(eof == "false", "idle share disconnected: {eof}");
        }
        agent
            .write_file("C:\\vsmb-idle-go", b"go".as_slice())
            .await?;
        Ok::<_, anyhow::Error>(())
    };
    futures::try_join!(command.run(), checkpoint)?;
    for operation in ["reads", "writes"] {
        let path = format!("vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/external_data/{operation}");
        let value = vm.inspect_vmm(&path).await?.to_string();
        anyhow::ensure!(
            value.parse::<u64>()? > 0,
            "no actual external {operation} observed"
        );
    }
    cmd!(shell, "powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[System.IO.File]::WriteAllText('V:\\reboot.txt', 'retained')",
        ])
        .run()
        .await?;
    agent.reboot().await?;
    let agent = vm.wait_for_reset().await?;
    for resource in [
        "opens",
        "watch_count",
        "lock_count",
        "lock_waiters",
        "caching/opens",
    ] {
        let path = format!("vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/server/backend/{resource}");
        let value = vm.inspect_vmm(&path).await?.to_string();
        anyhow::ensure!(value == "0", "guest reboot retained {resource}: {value}");
    }
    let (bootstrap, _) = script
        .split_once("\n[VsmbGuest]::Activate()")
        .ok_or_else(|| anyhow::anyhow!("guest bootstrap boundary missing"))?;
    let probe = format!(
        "{bootstrap}\n[VsmbGuest]::Activate()\n\
         if ([System.IO.File]::ReadAllText('V:\\reboot.txt') -ne 'retained') {{ throw 'Wrong file contents after reboot' }}\n\
         [System.IO.File]::Delete('V:\\reboot.txt')"
    );
    let shell = agent.windows_shell();
    cmd!(shell, "powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &probe])
        .run()
        .await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}
