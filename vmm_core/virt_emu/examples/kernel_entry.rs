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
    use std::collections::BTreeMap;
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
    use x86_system::{EventDiagnostic, PagedDiagnostic};

    const RAM: u64 = 512 * 1024 * 1024;
    const ENTRY: u64 = 0x2d98100;
    const FRONTIER: u64 = 0x2d98124;
    const STACK: u64 = 0x2603f38;
    const RETURN: u64 = 0x2d9811a;
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
        write: bool,
        changes: &mut BTreeMap<u64, (u64, u64)>,
    ) -> anyhow::Result<()> {
        let mut table = root;
        for (level, shift) in [39, 30, 21].into_iter().enumerate() {
            let address = table + ((va >> shift) & 511) * 8;
            let word = memory.read_plain::<u64>(address)?;
            ensure!(word & 1 != 0, "oracle encountered an absent loader entry");
            let bits = 0x20 | if write && level == 2 { 0x40 } else { 0 };
            changes
                .entry(address)
                .and_modify(|pair| pair.1 |= bits)
                .or_insert((word, word | bits));
            if level == 2 {
                ensure!(word & 0x80 != 0, "loader did not use a 2-MiB leaf");
                ensure!(
                    (word & 0x0000_ffff_ffe0_0000) | (va & 0x1f_ffff) == va,
                    "loader mapping is not identity"
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

    async fn witness(driver: DefaultDriver) -> anyhow::Result<()> {
        let mut args = std::env::args_os().skip(1);
        let kernel_path = args.next().context("missing vmlinux")?;
        let initrd_path = args.next().context("missing initrd")?;
        ensure!(args.next().is_none(), "expected vmlinux and initrd paths");
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
        expected_walk(&memory, initial.registers.cr3, ENTRY, false, &mut changes)?;
        for address in [0x2d8af5a, 0x1201f8b, 0x1edc370, FRONTIER, 0x30ae018] {
            expected_walk(&memory, initial.registers.cr3, address, false, &mut changes)?;
        }
        for address in [0x2603ef0, 0x26041d0] {
            expected_walk(&memory, initial.registers.cr3, address, true, &mut changes)?;
        }
        // Independent expected bytes of both ten-byte table operands and the #VC gate.
        // Later pushes overwrite the original GDTR base and first CALL return slot.
        for (address, value) in [
            (0x2603f40, 0x10u64),
            (0x2603f38, 0x2d98126),
            (0x2603f28, 0x2d8af8d),
            (0x2603f20, initial.registers.rbp),
            (0x2603f00, 0x2604000),
            (0x2603f08, 0x100000001d),
            (0x2603f10, 0x8e00),
            (0x2603f18, 0x2d982ca),
            (0x26041d0, 0x02d98e00001082ca),
            (0x26041d8, 0),
        ] {
            expected_store(&memory, &mut changes, address, &value.to_le_bytes())?;
        }
        expected_store(&memory, &mut changes, 0x2603f36, &0x7fu16.to_le_bytes())?;
        expected_store(&memory, &mut changes, 0x2603efe, &0x1ffu16.to_le_bytes())?;
        let before = memory_digest(&memory, &BTreeMap::new())?;
        let mut binder = binders.pop().context("missing VP binder")?;
        ensure!(binders.is_empty(), "unexpected additional VP");
        let mut vp = binder.bind()?;
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
        ensure!(
            matches!(
                failure.downcast_ref::<Error>(),
                Some(Error::Cpu(EventDiagnostic::Instruction(
                    PagedDiagnostic::Unsupported
                )))
            ),
            "wrong execution frontier: {failure}"
        );
        let progress = vp.completed_batch_progress();
        ensure!(
            progress.retired == 54 && progress.delivered == 0,
            "wrong progress: {progress:?}"
        );
        let mut expected = initial.registers;
        expected.cr0 |= 0x10;
        expected.rax = 0x2d98126;
        expected.rdx = 0x2604000;
        expected.rcx = 0x02d9000000000000;
        expected.rsi = 0x00008e0000000000;
        expected.rdi = 0;
        expected.r15 = initial.registers.rsi;
        expected.rsp = STACK;
        expected.rip = FRONTIER;
        expected.rflags &= !0x108d5;
        expected.gs.base = 0;
        expected.gdtr.base = 0x30ae000;
        expected.gdtr.limit = 0x7f;
        expected.idtr.base = 0x2604000;
        expected.idtr.limit = 0x1ff;
        expected.ds.selector = 0x18;
        expected.ss.selector = 0x18;
        expected.es.selector = 0x18;
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
            memory_digest(&memory, &changes)? == before,
            "RAM changed outside the declared A/D, stack and #VC gate effects"
        );
        let mut bytes = [0; 2];
        memory.read_at(FRONTIER, &mut bytes)?;
        ensure!(bytes == [0x48, 0xcb], "wrong frontier bytes");
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
                "entry": ENTRY, "frontier": actual.rip, "frontier_hex": "48cb",
                "r15": actual.r15, "rsp": actual.rsp, "return_address": RETURN,
                "rflags": actual.rflags, "seconds": seconds,
                "complete_register_image_checked": true, "whole_ram_checked": true,
                "descriptor_setup_returned": true,
                "cpuid_target": cpuid, "cpuid_instruction_implemented": false,
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
