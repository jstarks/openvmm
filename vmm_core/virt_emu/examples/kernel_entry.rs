// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bounded unchanged-loader witness for the content-pinned Linux entry.

// xtask-fmt allow-target-arch cpu-intrinsic -- Uses the native x86 WB provider.
#[cfg(all(guest_arch = "x86_64", target_arch = "x86_64"))]
mod native {
    use anyhow::{Context, bail, ensure};
    use futures::future::{Either, select};
    use futures::task::AtomicWaker;
    use guestmem::GuestMemory;
    use hvdef::Vtl;
    use loader::linux::{AcpiTables, InitrdAddressType, InitrdConfig};

    use pal_async::{DefaultDriver, DefaultPool};
    use parking_lot::Mutex;
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::CString;
    use std::fs::File;
    use std::task::Poll;
    use std::time::Instant;
    use virt::io::CpuIo;
    use virt::vp::AccessVpState;
    use virt::{
        BindProcessor, Hypervisor, Partition, PartitionConfig, Processor, ProtoPartition,
        ProtoPartitionConfig, ProtoPartitionIsolation, StopVpSource, VpHaltReason, VpIndex,
    };
    use virt_emu::backend::{EmuHypervisor, Error};
    use vm_topology::memory::MemoryLayout;
    use vm_topology::processor::TopologyBuilder;
    use vm_topology::processor::x86::X2ApicState;
    use vmcore::vmtime::{VmTime, VmTimeKeeper};
    use vmm_core::acpi_builder::{AcpiArchConfig, AcpiTablesBuilder};

    const RAM: u64 = 512 * 1024 * 1024;
    const ENTRY: u64 = 0x2d98100;
    const CHECKPOINT: u64 = 0xffff_ffff_82d9_8940;
    const TARGET: u64 = 0xffff_ffff_82d9_8890;
    const ROOT: u64 = 0x2e32000;
    const STACK: u64 = 0xffff_ffff_8260_3f30;
    const RETURN: u64 = 0xffff_ffff_812f_3dad;
    const CMDLINE: &str =
        "console=ttyS0,115200n8 earlycon=uart8250,io,0x3f8,115200n8 nokaslr maxcpus=1 rdinit=/init";
    type Failure = Box<dyn std::error::Error + Send + Sync>;

    #[derive(Default)]
    struct NoIo {
        error: Mutex<Option<Failure>>,
        wake: AtomicWaker,
    }

    impl NoIo {
        fn unexpected(&self, operation: &str) {
            self.fatal_error(Box::new(std::io::Error::other(format!(
                "unexpected {operation} before the declared entry frontier"
            ))));
        }

        async fn failed(&self) {
            std::future::poll_fn(|cx| {
                self.wake.register(cx.waker());
                if self.error.lock().is_some() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await
        }
    }

    impl CpuIo for NoIo {
        fn is_mmio(&self, _address: u64) -> bool {
            false
        }
        fn acknowledge_pic_interrupt(&self) -> Option<u8> {
            self.unexpected("PIC acknowledgement");
            None
        }
        fn handle_eoi(&self, _irq: u32) {
            self.unexpected("EOI");
        }
        async fn read_mmio(&self, _vp: VpIndex, _address: u64, _data: &mut [u8]) {
            self.unexpected("MMIO read");
            std::future::pending().await
        }
        async fn write_mmio(&self, _vp: VpIndex, _address: u64, _data: &[u8]) {
            self.unexpected("MMIO write");
            std::future::pending().await
        }
        async fn read_io(&self, _vp: VpIndex, _port: u16, _data: &mut [u8]) {
            self.unexpected("PIO read");
            std::future::pending().await
        }
        async fn write_io(&self, _vp: VpIndex, _port: u16, _data: &[u8]) {
            self.unexpected("PIO write");
            std::future::pending().await
        }
        fn fatal_error(&self, error: Failure) -> VpHaltReason {
            *self.error.lock() = Some(error);
            self.wake.wake();
            VpHaltReason::PowerOff
        }
    }

    fn expected_walk(
        memory: &GuestMemory,
        root: u64,
        va: u64,
        physical: u64,
        write: bool,
        changes: &mut BTreeMap<u64, (u64, u64)>,
    ) -> anyhow::Result<()> {
        let mut table = root;
        for (level, shift) in [39, 30, 21].into_iter().enumerate() {
            let address = table + ((va >> shift) & 511) * 8;
            let before = memory.read_plain::<u64>(address)?;
            let word = changes.get(&address).map_or(before, |pair| pair.1);
            ensure!(
                word & 1 != 0 && (!write || word & 2 != 0),
                "oracle encountered an absent or read-only page-table entry"
            );
            let bits = 0x20 | if write && level == 2 { 0x40 } else { 0 };
            changes
                .entry(address)
                .and_modify(|pair| pair.1 |= bits)
                .or_insert((before, word | bits));
            if level == 2 {
                ensure!(word & 0x80 != 0, "loader did not use a 2-MiB leaf");
                ensure!(
                    (word & 0x0000_ffff_ffe0_0000) | (va & 0x1f_ffff) == physical,
                    "incorrect projected mapping"
                );
            } else {
                ensure!(word & 0x80 == 0, "unexpected earlier huge leaf");
                table = word & 0x0000_ffff_ffff_f000;
            }
        }
        Ok(())
    }

    fn memory_digest(
        memory: &GuestMemory,
        restore: &BTreeMap<u64, (u64, u64)>,
    ) -> anyhow::Result<Vec<u8>> {
        let mut hash = Sha256::new();
        let mut bytes = vec![0; 65536];
        for address in (0..RAM).step_by(bytes.len()) {
            memory.read_at(address, &mut bytes)?;
            for (&word, &(before, _)) in restore.range(address..address + bytes.len() as u64) {
                let offset = usize::try_from(word - address)?;
                bytes[offset..offset + 8].copy_from_slice(&before.to_le_bytes());
            }

            hash.update(&bytes);
        }
        Ok(hash.finalize().to_vec())
    }

    fn expected_store(
        memory: &GuestMemory,
        changes: &mut BTreeMap<u64, (u64, u64)>,
        address: u64,
        bytes: &[u8],
    ) -> anyhow::Result<()> {
        for (offset, &byte) in bytes.iter().enumerate() {
            let address = address + u64::try_from(offset)?;
            let aligned = address & !7;
            let before = memory.read_plain::<u64>(aligned)?;
            let pair = changes.entry(aligned).or_insert((before, before));
            let shift = (address & 7) * 8;
            pair.1 = (pair.1 & !(0xff << shift)) | (u64::from(byte) << shift);
        }
        Ok(())
    }

    fn apply_projection(
        memory: &GuestMemory,
        changes: &mut BTreeMap<u64, (u64, u64)>,
        projection: &serde_json::Value,
    ) -> anyhow::Result<usize> {
        let words = projection["words"]
            .as_array()
            .context("missing projected words")?;
        ensure!(!words.is_empty(), "empty page-table projection");
        let mut seen = BTreeSet::new();
        for word in words {
            let address = word["address"]
                .as_u64()
                .context("missing projected address")?;
            let before = word["before"]
                .as_u64()
                .context("missing projected preimage")?;
            let after = word["after"]
                .as_u64()
                .context("missing projected postimage")?;
            ensure!(
                address % 8 == 0 && address < RAM,
                "invalid projected address"
            );
            ensure!(
                memory.read_plain::<u64>(address)? == before,
                "loader differs from the independent ELF preimage at {address:#x}"
            );
            ensure!(seen.insert(address), "duplicate projected address");
            changes.insert(address, (before, after));
        }
        Ok(words.len())
    }

    fn check_zero_ranges(
        memory: &GuestMemory,
        projection: &serde_json::Value,
    ) -> anyhow::Result<u64> {
        let ranges = projection["zero_ranges"]
            .as_array()
            .context("missing exact zero ranges")?;
        ensure!(ranges.len() == 2, "expected BSS and brk ranges");
        let mut total = 0;
        let mut buffer = vec![0; 65536];
        for range in ranges {
            let start = range["start"]
                .as_u64()
                .context("missing zero-range start")?;
            let end = range["end"].as_u64().context("missing zero-range end")?;
            ensure!(
                start < end && end <= RAM && range["loader_preimage_zero"].as_bool() == Some(true),
                "invalid zero-range profile"
            );
            let mut address = start;
            while address < end {
                let count = usize::try_from((end - address).min(buffer.len() as u64))?;
                memory.read_at(address, &mut buffer[..count])?;
                if let Some(offset) = buffer[..count].iter().position(|&byte| byte != 0) {
                    bail!(
                        "nonzero byte in exact clearing range at {:#x}",
                        address + offset as u64
                    );
                }
                address += count as u64;
            }
            total += end - start;
        }
        Ok(total)
    }

    async fn witness(driver: DefaultDriver) -> anyhow::Result<()> {
        let mut args = std::env::args_os().skip(1);
        let kernel_path = args.next().context("missing vmlinux")?;
        let initrd_path = args.next().context("missing initrd")?;
        let oracle_path = args.next().context("missing mapping projection")?;
        let initial_mapping_path = args
            .next()
            .context("missing pre-reset mapping projection")?;
        ensure!(
            args.next().is_none(),
            "expected vmlinux, initrd and both mapping projections"
        );
        let topology = TopologyBuilder::new_x86()
            .x2apic(X2ApicState::Unsupported)
            .build(1)?;
        let layout = MemoryLayout::new(RAM, &[], &[], &[], None)?;
        let memory = GuestMemory::allocate(usize::try_from(RAM)?);
        let keeper = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
        let time = keeper.builder().build(&driver).await?;
        let mut hypervisor = EmuHypervisor;
        let proto = hypervisor.new_partition(ProtoPartitionConfig {
            processor_topology: &topology,
            hv_config: None,
            vmtime: &time,
            isolation: ProtoPartitionIsolation::None,
            nested_virt: false,
        })?;
        let (partition, mut binders) = proto.build(PartitionConfig {
            mem_layout: &layout,
            guest_memory: &memory,
            cpuid: &[],
            vtl0_alias_map: None,
            fault_resolver: None,
        })?;
        let mut kernel = File::open(kernel_path)?;
        let mut initrd = File::open(initrd_path)?;
        let initrd_size = initrd.metadata()?.len();
        let mut importer = vm_loader::Loader::new(memory.clone(), &layout, Vtl::Vtl0);
        let bridges = Vec::new();
        let acpi = AcpiTablesBuilder {
            processor_topology: &topology,
            mem_layout: &layout,
            cache_topology: None,
            pcie_host_bridges: &bridges,
            slit_info: None,
            generic_initiators: &[],
            arch: AcpiArchConfig::X86 {
                with_ioapic: false,
                with_pic: false,
                with_pit: false,
                with_psp: false,
                pm_base: 0x400,
                acpi_irq: 9,
                iommu: None,
            },
        };
        loader::linux::load_x86(
            &mut importer,
            &mut kernel,
            Some(InitrdConfig {
                initrd_address: InitrdAddressType::AfterKernel,
                initrd: &mut initrd,
                size: initrd_size,
            }),
            &CString::new(CMDLINE)?,
            &layout,
            |gpa| {
                let built = acpi.build_acpi_tables(gpa, |dsdt| {
                    dsdt.add_uart(b"\\_SB.UAR1", b"COM1", 1, 0x3f8, 4)
                });
                AcpiTables {
                    rsdp: built.rsdp,
                    tables: built.tables,
                }
            },
            None,
            None,
        )?;
        let imports = importer.initial_regs_and_page_imports();
        let initial = vm_loader::initial_regs::x86_initial_regs(
            &imports.regs,
            partition.caps(),
            &topology.vps_arch().next().context("missing BSP")?,
        );
        ensure!(
            initial.registers.rip == ENTRY
                && initial.registers.rsi == 0x2000
                && initial.registers.cr3 == 0x4000,
            "unexpected pinned loader handoff"
        );
        let mut changes = BTreeMap::new();
        let projection: serde_json::Value = serde_json::from_reader(File::open(oracle_path)?)?;
        ensure!(
            projection["root"].as_u64() == Some(ROOT)
                && projection["target"].as_u64() == Some(TARGET)
                && projection["checkpoint"].as_u64() == Some(CHECKPOINT),
            "wrong mapping projection profile"
        );
        let initial_mapping: serde_json::Value =
            serde_json::from_reader(File::open(initial_mapping_path)?)?;
        ensure!(
            initial_mapping["root"].as_u64() == Some(ROOT)
                && initial_mapping["target"].as_u64() == Some(0xffff_ffff_812f_3c6f),
            "wrong pre-reset mapping profile"
        );
        apply_projection(&memory, &mut changes, &initial_mapping)?;
        expected_walk(
            &memory,
            initial.registers.cr3,
            ENTRY,
            ENTRY,
            false,
            &mut changes,
        )?;
        for address in [
            0x2d8af5a, 0x1201f8b, 0x1edc370, 0x2d98163, 0x30ae018, 0x2000, 0x28b94f2,
        ] {
            expected_walk(
                &memory,
                initial.registers.cr3,
                address,
                address,
                false,
                &mut changes,
            )?;
        }
        for address in [0x2603ed8, 0x26041d0, ROOT] {
            expected_walk(
                &memory,
                initial.registers.cr3,
                address,
                address,
                true,
                &mut changes,
            )?;
        }
        for (address, physical) in [
            (0x2d9815e, 0x2d9815e),
            (0x2f574dc, 0x2f574dc),
            (0xffff_ffff_812f_3c6f, 0x12f3c6f),
            (0xffff_ffff_812f_3c80, 0x12f3c80),
        ] {
            expected_walk(&memory, ROOT, address, physical, false, &mut changes)?;
        }
        let projected_words = apply_projection(&memory, &mut changes, &projection)?;
        for physical in [
            0x12f3c6f, 0x1201f8b, 0x1ec83f0, 0x1ed0260, 0x2d98890, 0x2d98940, 0x2500000, 0x30ae000,
        ] {
            expected_walk(
                &memory,
                ROOT,
                0xffff_ffff_8000_0000u64 + physical,
                physical,
                false,
                &mut changes,
            )?;
        }
        for physical in [0x2603f00, 0x26041d0, ROOT, 0x264e018, 0x30d0a58] {
            expected_walk(
                &memory,
                ROOT,
                0xffff_ffff_8000_0000u64 + physical,
                physical,
                true,
                &mut changes,
            )?;
        }
        for physical in (0x3000000..0x3630000).step_by(0x200000) {
            expected_walk(
                &memory,
                ROOT,
                0xffff_ffff_8000_0000u64 + physical,
                physical,
                true,
                &mut changes,
            )?;
        }
        let zero_bytes = check_zero_ranges(&memory, &projection)?;
        ensure!(
            memory.read_plain::<u32>(0x213c)? == 0 && memory.read_plain::<u64>(0x2250)? == 0,
            "unexpected confidential-computing/setup-data boot parameters"
        );
        // Include surviving physical-stack history and the later high-VA aliases.
        for (address, value) in [
            (0x2603f40, RETURN),
            (0x2603f38, initial.registers.r12),
            (0x2603f30, 0),
            (0x2603f28, CHECKPOINT),
            (0x2603f20, 0xffff_ffff_82d9_885c),
            (0x2603f18, 0x100000001d),
            (0x2603f10, 0xffff_ffff_8260_4000),
            (0x2603f08, 0x01ff_0000_02d8_b226),
            (0x2603f00, 27),
            (0x2603ef8, 0x2e35000),
            (0x2603ef0, 0x264a000),
            (0x2603ee8, 0x2000),
            (0x2603ee0, 512),
            (0x2603ed8, 0x80000000),
        ] {
            expected_store(&memory, &mut changes, address, &value.to_le_bytes())?;
        }
        let before = memory_digest(&memory, &BTreeMap::new())?;
        let mut binder = binders.pop().context("missing VP binder")?;
        ensure!(binders.is_empty(), "unexpected additional VP");
        let mut vp = binder.bind()?;
        vp.set_execution_checkpoint(Some(CHECKPOINT))?;
        {
            let mut state = vp.access_state(Vtl::Vtl0);
            state.set_mtrrs(&initial.mtrrs)?;
            state.set_registers(&initial.registers)?;
            state.set_pat(&initial.pat)?;
            state.commit()?;
        }
        let devices = NoIo::default();
        let stop = StopVpSource::new();
        let started = Instant::now();
        let run = Box::pin(vp.run_vp(stop.checker(), &devices));
        match select(run, Box::pin(devices.failed())).await {
            Either::Left((Err(VpHaltReason::PowerOff), _)) => {}
            Either::Left((other, _)) => bail!("unexpected VP outcome: {other:?}"),
            Either::Right(_) => {
                let failure = devices
                    .error
                    .lock()
                    .take()
                    .context("missing device diagnostic")?;
                bail!("device operation before entry frontier: {failure}");
            }
        }
        let seconds = started.elapsed().as_secs_f64();
        let failure = devices
            .error
            .lock()
            .take()
            .context("missing frontier diagnostic")?;
        let stopped_rip = vp.access_state(Vtl::Vtl0).registers()?.rip;
        ensure!(
            matches!(
                failure.downcast_ref::<Error>(),
                Some(Error::Checkpoint {rip}) if *rip==CHECKPOINT
            ),
            "did not reach the host checkpoint: stopped at {stopped_rip:#x}: {failure}"
        );
        let progress = vp.completed_batch_progress();
        ensure!(
            progress.retired > 3700 && progress.retired < 2_000_000 && progress.delivered == 0,
            "wrong progress: {progress:?}"
        );
        let mut expected = initial.registers;
        expected.cr0 = 0x80050033;
        expected.cr4 = 0xb0;
        expected.efer = 0xd01;
        expected.rax = 0xffff_ffff_8360_0000;
        expected.rbx = 0;
        expected.rdx = 0;
        expected.rcx = 0;
        expected.rsi = 0;
        expected.rdi = 0xffff_ffff_8363_0000;
        expected.rbp = 0x2000;
        expected.r8 = 20;
        expected.r9 = 0;
        expected.r10 = 0xffff_ffff_8360_0000;
        expected.r11 = 20;
        expected.cr3 = ROOT;
        expected.r15 = initial.registers.rsi;
        expected.rsp = STACK;
        expected.rip = CHECKPOINT;
        expected.rflags = 0x46;
        expected.gdtr.base = 0xffff_ffff_830a_e000;
        expected.gdtr.limit = 0x7f;
        expected.idtr.base = 0xffff_ffff_8260_4000;
        expected.idtr.limit = 0x1ff;
        expected.ds = Default::default();
        expected.ss = Default::default();
        expected.es = Default::default();
        expected.fs = Default::default();
        expected.gs = Default::default();
        expected.cs.selector = 0x10;
        let mut state = vp.access_state(Vtl::Vtl0);
        let actual = state.registers()?;
        ensure!(
            actual == expected,
            "complete register image mismatch:\nactual {actual:?}\nexpected {expected:?}"
        );
        ensure!(
            state.pat()? == initial.pat && state.mtrrs()? == initial.mtrrs,
            "PAT/MTRR image changed"
        );
        for (&address, &(_, expected)) in &changes {
            ensure!(
                memory.read_plain::<u64>(address)? == expected,
                "incorrect memory effect at {address:#x}"
            );
        }
        ensure!(
            check_zero_ranges(&memory, &projection)? == zero_bytes,
            "changed clearing bounds"
        );
        ensure!(
            memory_digest(&memory, &changes)? == before,
            "RAM changed outside the projected tables/data, A/D, stack and #VC gate effects"
        );
        let mut bytes = [0; 7];
        memory.read_at(0x2d98940, &mut bytes)?;
        ensure!(
            bytes == [0x48, 0xc7, 0xc7, 0, 0x40, 0x64, 0x82],
            "wrong checkpoint bytes"
        );
        let functions = [0, 1, 0x8000_0000, 0x8000_0001, 0x8000_0008];
        let cpuid: Vec<_> = functions
            .into_iter()
            .map(|function| {
                serde_json::json!({
                    "function": function, "subleaf": 0,
                    "registers": x86_system::memory_core::cpu_core::profile::cpuid(function, 0),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "retired": progress.retired, "delivered": progress.delivered,
                "entry": ENTRY, "checkpoint": actual.rip, "checkpoint_hex": "48c7c700406482",
                "stop_kind":"host_checkpoint","initial_memory_cleared":true,
                "kernel_c_entry":true,"identity_mappings_removed":true,"zero_bytes":zero_bytes,
                "r15": actual.r15, "rsp": actual.rsp, "return_address": RETURN,
                "rflags": actual.rflags, "seconds": seconds,
                "complete_register_image_checked": true, "whole_ram_checked": true,
                "descriptor_setup_returned": true,
                "verify_cpu_returned_success": true,
                "kernel_page_tables_constructed": true,"high_virtual_fetch": true,
                "root":actual.cr3,"target":TARGET,"mapping_oracle_words":projected_words,
                "cr0":actual.cr0,"cr4":actual.cr4,"efer":actual.efer,
                "cpuid_target": cpuid, "cpuid_instruction_implemented": true,
                "linux_boot": false, "snp": false,
            })
        );
        Ok(())
    }

    pub fn run() -> anyhow::Result<()> {
        DefaultPool::run_with(witness)
    }
}

fn main() -> anyhow::Result<()> {
    // xtask-fmt allow-target-arch cpu-intrinsic -- Matches the native WB provider.
    #[cfg(all(guest_arch = "x86_64", target_arch = "x86_64"))]
    return native::run();
    // xtask-fmt allow-target-arch cpu-intrinsic -- Reject unsupported host providers.
    #[cfg(not(all(guest_arch = "x86_64", target_arch = "x86_64")))]
    anyhow::bail!("kernel-entry witness requires the native x86-64 WB provider");
}
