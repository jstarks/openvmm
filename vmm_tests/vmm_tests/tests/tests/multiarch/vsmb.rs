// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use openvmm_defs::config::DeviceVtl;
use pal_async::{DefaultDriver, timer::PolledTimer};
use petri::{PetriVmBuilder, openvmm::OpenVmmPetriBackend, pipette::cmd};
use vm_resource::IntoResource;
use vmm_test_macros::openvmm_test;
use vsmb_resources::VsmbMemoryDeviceHandle;

#[cfg(target_os = "linux")]
#[openvmm_test(uefi_x64(vhd(windows_datacenter_core_2025_x64)))]
async fn vsmb_linux_file_operations(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
    _extra_deps: (),
    driver: DefaultDriver,
) -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("locked.bin"), [0; 4096])?;
    std::fs::hard_link(
        root.path().join("locked.bin"),
        root.path().join("locked.bin.alias"),
    )?;
    std::fs::write(root.path().join("host-update.bin"), [0x11; 4096])?;
    std::fs::write(root.path().join("colon:name"), b"projected")?;
    let root_path = root
        .path()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 test root"))?
        .to_owned();
    let (mut vm, agent) = config
        .modify_backend(|b| {
            b.without_save_restore().with_custom_config(|c| {
                c.vmbus_devices.push((
                    DeviceVtl::Vtl0,
                    vsmb_resources::VsmbLinuxDeviceHandle {
                        share_name: "linux".into(),
                        root_path,
                        software_caching: false,
                    }
                    .into_resource(),
                ));
            })
        })
        .run()
        .await?;
    let common = include_str!("../../../test_data/vsmb_file_operations.ps1");
    let (bootstrap, _) = common
        .split_once("\n[VsmbGuest]::Activate()")
        .ok_or_else(|| anyhow::anyhow!("guest bootstrap boundary missing"))?;
    let script = format!(
        "{bootstrap}\n{}",
        include_str!("../../../test_data/vsmb_linux_file_operations.ps1")
    );
    for signal in [
        "vsmb-lock-ready",
        "vsmb-native-ready",
        "vsmb-native-watch-ready",
    ] {
        agent
            .write_file(format!("C:\\{signal}"), b"waiting".as_slice())
            .await?;
    }
    let shell = agent.windows_shell();
    let command =
        cmd!(shell, "powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", &script]);
    let checkpoint = async {
        let requests = "vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/channel/connection/requests";
        let backend = "vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/server/backend";
        let mut timer = PolledTimer::new(&driver);
        let mut registered = false;
        for _ in 0..400 {
            if vm
                .inspect_vmm(&format!("{backend}/notify_waiters"))
                .await?
                .to_string()
                .parse::<usize>()?
                > 0
            {
                registered = true;
                break;
            }
            timer.sleep(std::time::Duration::from_millis(25)).await;
        }
        anyhow::ensure!(registered, "native notification was not registered");
        vm.backend().pause().await?;
        anyhow::ensure!(
            vm.inspect_vmm(requests)
                .await?
                .to_string()
                .contains("CHANGE_NOTIFY"),
            "pause lost the native notification"
        );
        vm.backend().resume().await?;
        agent
            .write_file("C:\\vsmb-resume", b"go".as_slice())
            .await?;
        let mut ready = false;
        for _ in 0..400 {
            if agent.read_file("C:\\vsmb-lock-ready").await? == b"ready" {
                ready = true;
                break;
            }
            timer.sleep(std::time::Duration::from_millis(25)).await;
        }
        anyhow::ensure!(ready, "native lock checkpoint was not reached");
        let inspect::Node::Dir(entries) = vm.inspect_vmm(requests).await? else {
            anyhow::bail!("request table is not inspectable");
        };
        let waiting = entries
            .iter()
            .find(|entry| match &entry.node {
                inspect::Node::Dir(fields) => fields
                    .iter()
                    .any(|field| field.name == "command" && field.node.to_string() == "\"LOCK\""),
                _ => false,
            })
            .ok_or_else(|| anyhow::anyhow!("no actual native pending LOCK"))?;
        let waiting_path = format!("{requests}/{}", waiting.name);
        let waiting = waiting.node.to_string();
        vm.backend().pause().await?;
        anyhow::ensure!(
            vm.inspect_vmm(&waiting_path).await?.to_string() == waiting,
            "pause changed the native pending LOCK"
        );
        vm.backend().resume().await?;
        anyhow::ensure!(
            vm.inspect_vmm(&waiting_path).await?.to_string() == waiting,
            "resume changed the native pending LOCK"
        );
        agent
            .write_file("C:\\vsmb-lock-go", b"go".as_slice())
            .await?;
        let mut ready = false;
        for _ in 0..400 {
            if agent.read_file("C:\\vsmb-native-ready").await? == b"ready" {
                ready = true;
                break;
            }
            timer.sleep(std::time::Duration::from_millis(25)).await;
        }
        anyhow::ensure!(ready, "native backing checkpoint was not reached");
        let actual = std::fs::read(root.path().join("guest-test").join("renamed.bin"))?;
        anyhow::ensure!(
            actual.len() == 131077
                && actual
                    .iter()
                    .enumerate()
                    .all(|(i, byte)| *byte == (i % 251) as u8),
            "guest data was not stored in the host filesystem"
        );
        std::fs::write(root.path().join("host-update.bin"), [0x5a; 4096])?;
        agent
            .write_file("C:\\vsmb-native-go", b"go".as_slice())
            .await?;
        let mut ready = false;
        for _ in 0..400 {
            if agent.read_file("C:\\vsmb-native-watch-ready").await? == b"ready" {
                ready = true;
                break;
            }
            timer.sleep(std::time::Duration::from_millis(25)).await;
        }
        anyhow::ensure!(ready, "guest did not register the host-change notification");
        std::fs::write(
            root.path().join("guest-test").join("from-host.bin"),
            b"host",
        )?;
        Ok::<_, anyhow::Error>(())
    };
    futures::try_join!(command.run(), checkpoint)?;
    for operation in ["reads", "writes"] {
        let path = format!("vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/external_data/{operation}");
        anyhow::ensure!(
            vm.inspect_vmm(&path).await?.to_string().parse::<u64>()? > 0,
            "no native external {operation}"
        );
    }
    anyhow::ensure!(
        std::fs::read(root.path().join("retained.txt"))? == b"retained",
        "missing retained host data"
    );
    anyhow::ensure!(
        !root.path().join("guest-test").exists(),
        "guest directory deletion did not reach the host"
    );
    agent.reboot().await?;
    let agent = vm.wait_for_reset().await?;
    for resource in [
        "opens",
        "watch_count",
        "notify_waiters",
        "lock_count",
        "lock_waiters",
        "active_io",
    ] {
        let path = format!("vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/server/backend/{resource}");
        let value = vm.inspect_vmm(&path).await?.to_string();
        anyhow::ensure!(value == "0", "native reboot retained {resource}: {value}");
    }
    let probe = format!(
        "{bootstrap}\n[VsmbGuest]::Activate('linux')\n\
        if ([System.IO.File]::ReadAllText('V:\\retained.txt') -ne 'retained') {{ throw 'Wrong retained native data' }}"
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

#[cfg(windows)]
#[openvmm_test(uefi_aarch64(vhd(windows_11_enterprise_aarch64)))]
async fn vsmb_windows_native_file_operations(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
    _extra_deps: (),
    driver: DefaultDriver,
) -> anyhow::Result<()> {
    windows_file_operations(
        config,
        driver,
        vsmb_resources::VsmbWindowsLockMode::Native,
        false,
    )
    .await
}

#[cfg(windows)]
#[openvmm_test(uefi_aarch64(vhd(windows_11_enterprise_aarch64)))]
async fn vsmb_windows_synthetic_file_operations(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
    _extra_deps: (),
    driver: DefaultDriver,
) -> anyhow::Result<()> {
    windows_file_operations(
        config,
        driver,
        vsmb_resources::VsmbWindowsLockMode::Synthetic,
        false,
    )
    .await
}

#[cfg(windows)]
#[openvmm_test(uefi_aarch64(vhd(windows_11_enterprise_aarch64)))]
async fn vsmb_windows_native_software_caching(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
    _extra_deps: (),
    driver: DefaultDriver,
) -> anyhow::Result<()> {
    windows_file_operations(
        config,
        driver,
        vsmb_resources::VsmbWindowsLockMode::Native,
        true,
    )
    .await
}

#[cfg(windows)]
#[openvmm_test(uefi_aarch64(vhd(windows_11_enterprise_aarch64)))]
async fn vsmb_windows_synthetic_software_caching(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
    _extra_deps: (),
    driver: DefaultDriver,
) -> anyhow::Result<()> {
    windows_file_operations(
        config,
        driver,
        vsmb_resources::VsmbWindowsLockMode::Synthetic,
        true,
    )
    .await
}

#[cfg(windows)]
async fn windows_file_operations(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
    driver: DefaultDriver,
    lock_mode: vsmb_resources::VsmbWindowsLockMode,
    software_caching: bool,
) -> anyhow::Result<()> {
    let host_changes =
        !software_caching && matches!(&lock_mode, vsmb_resources::VsmbWindowsLockMode::Native);
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("locked.bin"), [0; 4096])?;
    std::fs::hard_link(
        root.path().join("locked.bin"),
        root.path().join("locked.bin.alias"),
    )?;
    std::fs::write(root.path().join("host-update.bin"), [0x11; 4096])?;
    if software_caching {
        std::fs::write(root.path().join("cached.bin"), [0; 4096])?;
        std::fs::hard_link(
            root.path().join("cached.bin"),
            root.path().join("cached.bin.alias"),
        )?;
    }
    let root_path = root
        .path()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 test root"))?
        .to_owned();
    let (mut vm, agent) = config
        .modify_backend(move |b| {
            b.without_save_restore().with_custom_config(move |c| {
                c.vmbus_devices.push((
                    DeviceVtl::Vtl0,
                    vsmb_resources::VsmbWindowsDeviceHandle {
                        share_name: "windows".into(),
                        root_path,
                        lock_mode,
                        software_caching,
                    }
                    .into_resource(),
                ));
            })
        })
        .run()
        .await?;
    let common = include_str!("../../../test_data/vsmb_file_operations.ps1");
    let (bootstrap, _) = common
        .split_once("\n[VsmbGuest]::Activate()")
        .ok_or_else(|| anyhow::anyhow!("guest bootstrap boundary missing"))?;
    let script = format!(
        "{bootstrap}\n$VsmbHostChanges = ${host_changes}\n$VsmbSoftwareCaching = ${software_caching}\n{}",
        include_str!("../../../test_data/vsmb_windows_file_operations.ps1")
    );
    for signal in [
        "vsmb-lock-ready",
        "vsmb-native-ready",
        "vsmb-native-watch-ready",
        "vsmb-cache-ready",
    ] {
        agent
            .write_file(format!("C:\\{signal}"), b"waiting".as_slice())
            .await?;
    }
    let shell = agent.windows_shell();
    let command =
        cmd!(shell, "powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", &script]);
    let checkpoint = async {
        let requests = "vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/channel/connection/requests";
        let backend = "vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/server/backend";
        let mut timer = PolledTimer::new(&driver);
        let mut registered = false;
        for _ in 0..400 {
            if vm
                .inspect_vmm(&format!("{backend}/notify_waiters"))
                .await?
                .to_string()
                .parse::<usize>()?
                > 0
            {
                registered = true;
                break;
            }
            timer.sleep(std::time::Duration::from_millis(25)).await;
        }
        anyhow::ensure!(registered, "Windows-backed notification was not registered");
        vm.backend().pause().await?;
        anyhow::ensure!(
            vm.inspect_vmm(requests)
                .await?
                .to_string()
                .contains("CHANGE_NOTIFY"),
            "pause lost the Windows-backed notification"
        );
        vm.backend().resume().await?;
        agent
            .write_file("C:\\vsmb-resume", b"go".as_slice())
            .await?;
        let mut ready = false;
        for _ in 0..400 {
            if agent.read_file("C:\\vsmb-lock-ready").await? == b"ready" {
                ready = true;
                break;
            }
            timer.sleep(std::time::Duration::from_millis(25)).await;
        }
        anyhow::ensure!(ready, "Windows-backed lock checkpoint was not reached");
        let inspect::Node::Dir(entries) = vm.inspect_vmm(requests).await? else {
            anyhow::bail!("request table is not inspectable");
        };
        let waiting = entries
            .iter()
            .find(|entry| match &entry.node {
                inspect::Node::Dir(fields) => fields
                    .iter()
                    .any(|field| field.name == "command" && field.node.to_string() == "\"LOCK\""),
                _ => false,
            })
            .ok_or_else(|| anyhow::anyhow!("no actual Windows-backed pending LOCK"))?;
        let waiting_path = format!("{requests}/{}", waiting.name);
        let waiting = waiting.node.to_string();
        vm.backend().pause().await?;
        anyhow::ensure!(
            vm.inspect_vmm(&waiting_path).await?.to_string() == waiting,
            "pause changed the Windows-backed LOCK"
        );
        vm.backend().resume().await?;
        anyhow::ensure!(
            vm.inspect_vmm(&waiting_path).await?.to_string() == waiting,
            "resume changed the Windows-backed LOCK"
        );
        agent
            .write_file("C:\\vsmb-lock-go", b"go".as_slice())
            .await?;
        if software_caching {
            let mut ready = false;
            for _ in 0..400 {
                if agent.read_file("C:\\vsmb-cache-ready").await? == b"ready" {
                    ready = true;
                    break;
                }
                timer.sleep(std::time::Duration::from_millis(25)).await;
            }
            anyhow::ensure!(ready, "guest did not reach Windows cached-read checkpoint");
            let opens_path = "vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/channel/connection/opens";
            let inspect::Node::Dir(opens) = vm.inspect_vmm(opens_path).await? else {
                anyhow::bail!("open table is not inspectable");
            };
            let mut held_path = None;
            for open in &opens {
                let inspect::Node::Dir(fields) = &open.node else {
                    continue;
                };
                if !fields.iter().any(|field| field.name == "caching") {
                    continue;
                }
                let path = format!("{opens_path}/{}/caching/provider/held", open.name);
                let held = vm.inspect_vmm(&path).await?.to_string();
                if held.contains("Read") {
                    held_path = Some(path);
                    break;
                }
            }
            let held_path = held_path
                .ok_or_else(|| anyhow::anyhow!("no server-granted Windows read caching"))?;
            let held = vm.inspect_vmm(&held_path).await?.to_string();
            vm.backend().pause().await?;
            anyhow::ensure!(
                vm.inspect_vmm(&held_path).await?.to_string() == held,
                "pause changed Windows caching rights"
            );
            vm.backend().resume().await?;
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
            anyhow::ensure!(
                written,
                "Windows alias writer did not complete after caching break"
            );
            anyhow::ensure!(
                break_started.elapsed() < std::time::Duration::from_secs(10),
                "Windows caching break used forced timeout"
            );
            anyhow::ensure!(
                vm.inspect_vmm(&held_path).await?.to_string() == "\"None\"",
                "Windows alias write retained stale cache rights"
            );
            agent
                .write_file("C:\\vsmb-cache-read-go", b"go".as_slice())
                .await?;
        }
        let mut ready = false;
        for _ in 0..400 {
            if agent.read_file("C:\\vsmb-native-ready").await? == b"ready" {
                ready = true;
                break;
            }
            timer.sleep(std::time::Duration::from_millis(25)).await;
        }
        anyhow::ensure!(ready, "Windows backing checkpoint was not reached");
        let actual = std::fs::read(root.path().join("guest-test").join("renamed.bin"))?;
        anyhow::ensure!(
            actual.len() == 131077
                && actual
                    .iter()
                    .enumerate()
                    .all(|(i, byte)| *byte == (i % 251) as u8),
            "guest data did not reach NTFS"
        );
        if host_changes {
            std::fs::write(root.path().join("host-update.bin"), [0x5a; 4096])?;
        }
        agent
            .write_file("C:\\vsmb-native-go", b"go".as_slice())
            .await?;
        if host_changes {
            let mut ready = false;
            for _ in 0..400 {
                if agent.read_file("C:\\vsmb-native-watch-ready").await? == b"ready" {
                    ready = true;
                    break;
                }
                timer.sleep(std::time::Duration::from_millis(25)).await;
            }
            anyhow::ensure!(
                ready,
                "guest did not register the Windows host-change watch"
            );
            std::fs::write(
                root.path().join("guest-test").join("from-host.bin"),
                b"host",
            )?;
        }
        Ok::<_, anyhow::Error>(())
    };
    futures::try_join!(command.run(), checkpoint)?;
    for operation in ["reads", "writes"] {
        let path = format!("vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/external_data/{operation}");
        anyhow::ensure!(
            vm.inspect_vmm(&path).await?.to_string().parse::<u64>()? > 0,
            "no Windows-backed external {operation}"
        );
    }
    anyhow::ensure!(
        std::fs::read(root.path().join("retained.txt"))? == b"retained",
        "missing retained NTFS data"
    );
    anyhow::ensure!(
        !root.path().join("guest-test").exists(),
        "guest directory deletion did not reach NTFS"
    );
    agent.reboot().await?;
    let agent = vm.wait_for_reset().await?;
    for resource in [
        "opens",
        "watch_count",
        "notify_waiters",
        "lock_count",
        "lock_waiters",
        "active_io",
    ] {
        let path = format!("vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/server/backend/{resource}");
        let value = vm.inspect_vmm(&path).await?.to_string();
        anyhow::ensure!(value == "0", "Windows reboot retained {resource}: {value}");
    }
    if software_caching {
        for resource in [
            "reservations/opens",
            "files",
            "namespace_admissions",
            "active_effects",
        ] {
            let value = vm.inspect_vmm(&format!(
                "vsmb:dcc079ae-60ba-4d07-847c-3493609c0870/server/backend/software_caching/{resource}"
            )).await?.to_string();
            anyhow::ensure!(
                value == "0",
                "Windows reboot retained caching {resource}: {value}"
            );
        }
    }
    let probe = format!(
        "{bootstrap}\n[VsmbGuest]::Activate('windows')\nif ([System.IO.File]::ReadAllText('V:\\retained.txt') -ne 'retained') {{ throw 'Wrong retained Windows data' }}"
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
