// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bounded unchanged-loader witness for the content-pinned Linux entry.

#![recursion_limit = "256"]

// xtask-fmt allow-target-arch cpu-intrinsic -- Uses the native x86 WB provider.
#[cfg(all(guest_arch = "x86_64", target_arch = "x86_64"))]
mod native {
    use anyhow::{Context, bail, ensure};
    use futures::future::{Either, select};
    use futures::task::AtomicWaker;
    use guestmem::{GuestMemory, GuestMemoryAccess, WriteTracker};
    use hvdef::Vtl;
    use loader::linux::{AcpiTables, InitrdAddressType, InitrdConfig};

    use chipset_device_resources::IRQ_LINE_SET;
    use pal_async::{DefaultDriver, DefaultPool};
    use parking_lot::Mutex;
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::ffi::CString;
    use std::fs::File;
    use std::pin::Pin;
    use std::ptr::NonNull;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context as TaskContext, Poll};
    use std::time::Instant;
    use virt::io::CpuIo;
    use virt::vp::AccessVpState;
    use virt::{
        BindProcessor, Hypervisor, Partition, PartitionConfig, PartitionMemoryMap, Processor,
        ProtoPartition, ProtoPartitionConfig, ProtoPartitionIsolation, StopVpSource, VpHaltReason,
        VpIndex,
    };
    use virt_emu::backend::{EmuHypervisor, EmuPartition, Error};
    use vm_topology::memory::MemoryLayout;
    use vm_topology::processor::TopologyBuilder;
    use vm_topology::processor::x86::X2ApicState;
    use vmcore::vm_task::{VmTaskDriverSource, thread::ThreadDriverBackend};
    use vmcore::vmtime::{VmTime, VmTimeKeeper};
    use vmm_core::acpi_builder::{AcpiArchConfig, AcpiTablesBuilder};

    const RAM: u64 = 512 * 1024 * 1024;

    fn execution_json(d: x86_system::execute::compiled::ExecutionDiagnostics) -> serde_json::Value {
        serde_json::json!({
            "single_entries":d.single_entries,"single_retired":d.single_retired,
            "resumes":d.resumes,"block_entries":d.block_entries,
            "block_retired":d.block_retired,"completed_lengths":d.completed_lengths,
            "complete_exits":d.complete_exits,"budget_exits":d.budget_exits,
            "revocation_exits":d.revocation_exits,"code_write_exits":d.code_write_exits,
            "host_stop_exits":d.host_stop_exits,
            "suspended_exits":d.suspended_exits,"transition_exits":d.transition_exits,
            "stopped_exits":d.stopped_exits,
            "svm_page_faults":d.svm_page_faults,"svm_fault_samples":d.svm_fault_samples,
            "svm_ud_exits":d.svm_ud_exits,"svm_invlpg_exits":d.svm_invlpg_exits,
            "svm_exits":d.svm_exits,"svm_exit_samples":d.svm_exit_samples,
            "svm_breakpoint":d.svm_breakpoint,
        })
    }

    struct DeviceBacking {
        mapping: Arc<sparse_mmap::SparseMapping>,
        tracker: WriteTracker,
    }

    // SAFETY: the owned reservation remains stable throughout this view's lifetime.
    // UNSAFETY: Provides mapped, observed loader/device access to harness RAM.
    #[expect(unsafe_code)]
    unsafe impl GuestMemoryAccess for DeviceBacking {
        fn mapping(&self) -> Option<NonNull<u8>> {
            NonNull::new(self.mapping.as_ptr().cast())
        }

        fn max_address(&self) -> u64 {
            self.mapping.len() as u64
        }

        fn write_tracker(&self) -> Option<WriteTracker> {
            Some(self.tracker.clone())
        }
    }

    const ENTRY: u64 = 0x2d98100;
    const CHECKPOINT: u64 = 0xffff_ffff_81ed_6589;
    const PROBE_TARGET: u64 = 0xffff_ffff_82d9_8800;
    const TARGET: u64 = 0xffff_ffff_82d9_8890;
    const ROOT: u64 = 0x2e32000;
    const STACK: u64 = 0xffff_ffff_8260_3e98;
    const RETURN: u64 = 0xffff_ffff_812f_3dad;
    const PM_BASE: u16 = 0x400;
    const CMDLINE: &str =
        "console=ttyS0,115200n8 earlycon=uart8250,io,0x3f8,115200n8 nokaslr maxcpus=1 rdinit=/init";
    type Failure = Box<dyn std::error::Error + Send + Sync>;

    #[derive(Debug, thiserror::Error)]
    #[error("unconfigured {operation} port {port:#x}/{size}")]
    struct UnconfiguredPort {
        operation: &'static str,
        port: u16,
        size: usize,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("unsupported asserted chipset IRQ {0}")]
    struct UnsupportedIrq(u32);

    struct IoApicRoutes {
        partition: Arc<EmuPartition>,
        routes: Mutex<[Option<virt::irqcon::MsiRequest>; 24]>,
        events: Arc<DeviceEvents>,
    }
    impl chipset_resources::ioapic::IoApicRouting for IoApicRoutes {
        fn set_route(&self, irq: u8, request: Option<(u64, u32)>) {
            self.routes.lock()[usize::from(irq)] =
                request.map(|(address, data)| virt::irqcon::MsiRequest { address, data });
        }
        fn assert(&self, irq: u8) {
            let request = self.routes.lock()[usize::from(irq)];
            match request {
                Some(request) => self.partition.request_msi(Vtl::Vtl0, request),
                None => {
                    self.events.fail(Box::new(std::io::Error::other(
                        "IOAPIC asserted an unconfigured route",
                    )));
                }
            }
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("bounded kernel probe reached its {0}-second deadline")]
    struct ProbeDeadline(u32);

    #[derive(Debug, thiserror::Error)]
    #[error("serial command returned to the shell prompt")]
    struct CommandReturned;

    #[derive(Default)]
    struct ConsoleState {
        output: Vec<u8>,
        command: Option<Vec<u8>>,
        input: VecDeque<u8>,
        reader: Option<std::task::Waker>,
        command_sent: bool,
        consumed: usize,
        command_returned: bool,
        return_waiter: Option<std::task::Waker>,
    }

    impl ConsoleState {
        fn new(command: Option<String>) -> Self {
            Self {
                command: command.map(|command| {
                    let mut bytes = command.into_bytes();
                    if !bytes.ends_with(b"\n") {
                        bytes.push(b'\n');
                    }
                    bytes
                }),
                ..Self::default()
            }
        }
    }

    struct ConsoleCapture(Arc<Mutex<ConsoleState>>);
    impl futures::AsyncRead for ConsoleCapture {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            data: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            if data.is_empty() {
                Poll::Ready(Ok(0))
            } else {
                let mut state = self.0.lock();
                let count = data.len().min(state.input.len());
                if count != 0 {
                    for byte in &mut data[..count] {
                        *byte = state.input.pop_front().unwrap();
                    }
                    state.consumed += count;
                    Poll::Ready(Ok(count))
                } else {
                    if state.command.is_some() {
                        state.reader = Some(cx.waker().clone());
                    }
                    Poll::Pending
                }
            }
        }
    }
    impl futures::AsyncWrite for ConsoleCapture {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut state = self.0.lock();
            state.output.extend_from_slice(data);
            let wake = if state.command.is_some() && state.output.ends_with(b"~ # ") {
                let command = state.command.take().unwrap();
                state.input.extend(command);
                state.command_sent = true;
                state.reader.take()
            } else {
                None
            };
            let returned = if state.command_sent
                && state.consumed != 0
                && state.input.is_empty()
                && state.output.ends_with(b"~ # ")
            {
                state.command_returned = true;
                state.return_waiter.take()
            } else {
                None
            };
            drop(state);
            if let Some(wake) = wake {
                wake.wake();
            }
            if let Some(wake) = returned {
                wake.wake();
            }
            Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct DeviceEvents {
        error: Mutex<Option<Failure>>,
        wake: AtomicWaker,
    }

    impl DeviceEvents {
        fn fail(&self, error: Failure) -> VpHaltReason {
            let mut first = self.error.lock();
            if first.is_none() {
                *first = Some(error);
            }
            drop(first);
            self.wake.wake();
            VpHaltReason::PowerOff
        }
    }

    impl vmotherboard::PowerEventHandler for DeviceEvents {
        fn on_power_event(&self, _event: vmotherboard::PowerEvent) {
            self.fail(Box::new(std::io::Error::other(
                "unexpected chipset power event",
            )));
        }
    }
    impl vmotherboard::DebugEventHandler for DeviceEvents {
        fn on_debug_break(&self, _vp: Option<u32>) {
            self.fail(Box::new(std::io::Error::other(
                "unexpected chipset debug event",
            )));
        }
    }
    impl vmcore::line_interrupt::LineSetTarget for DeviceEvents {
        fn set_irq(&self, vector: u32, high: bool) {
            if high {
                self.fail(Box::new(UnsupportedIrq(vector)));
            }
        }
    }

    #[derive(Default)]
    struct WitnessIo {
        with_ioapic: bool,
        events: Arc<DeviceEvents>,
        chipset: Option<Arc<vmotherboard::Chipset>>,
        pm_reads: AtomicU64,
        pm_stalls: bool,
        pm_stalls_injected: AtomicU64,
    }

    impl WitnessIo {
        fn unexpected(&self, operation: &str) {
            self.fatal_error(Box::new(std::io::Error::other(format!(
                "unexpected {operation} before the declared entry frontier"
            ))));
        }

        async fn failed(&self) {
            std::future::poll_fn(|cx| {
                self.events.wake.register(cx.waker());
                if self.events.error.lock().is_some() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await
        }
    }

    impl CpuIo for WitnessIo {
        fn is_mmio(&self, address: u64) -> bool {
            self.with_ioapic && (0xfec0_0000..0xfec0_0020).contains(&address)
        }
        fn acknowledge_pic_interrupt(&self) -> Option<u8> {
            self.unexpected("PIC acknowledgement");
            None
        }
        fn handle_eoi(&self, irq: u32) {
            if self.with_ioapic {
                if let Some(chipset) = &self.chipset {
                    chipset.handle_eoi(irq);
                    return;
                }
            }
            self.unexpected("EOI");
        }
        async fn read_mmio(&self, vp: VpIndex, address: u64, data: &mut [u8]) {
            if let Some(chipset) = &self.chipset {
                chipset.mmio_read(vp.index(), address, data).await;
                return;
            }
            self.unexpected("MMIO read");
            std::future::pending().await
        }
        async fn write_mmio(&self, vp: VpIndex, address: u64, data: &[u8]) {
            if let Some(chipset) = &self.chipset {
                chipset.mmio_write(vp.index(), address, data).await;
                return;
            }
            self.unexpected("MMIO write");
            std::future::pending().await
        }
        async fn read_io(&self, vp: VpIndex, port: u16, data: &mut [u8]) {
            if let Some(chipset) = &self.chipset {
                if port == PM_BASE + 8 {
                    let read = self.pm_reads.fetch_add(1, Ordering::Relaxed) + 1;
                    if self.pm_stalls && read.is_multiple_of(7) {
                        // Deschedule the VP's host thread without pausing guest time.
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        self.pm_stalls_injected.fetch_add(1, Ordering::Relaxed);
                    }
                }
                chipset.io_read(vp.index(), port, data).await;
                return;
            }
            self.fatal_error(Box::new(UnconfiguredPort {
                operation: "input",
                port,
                size: data.len(),
            }));
            std::future::pending().await
        }
        async fn write_io(&self, vp: VpIndex, port: u16, data: &[u8]) {
            if let Some(chipset) = &self.chipset {
                chipset.io_write(vp.index(), port, data).await;
                return;
            }
            self.fatal_error(Box::new(UnconfiguredPort {
                operation: "output",
                port,
                size: data.len(),
            }));
            std::future::pending().await
        }
        fn fatal_error(&self, error: Failure) -> VpHaltReason {
            self.events.fail(error)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn console_command_waits_for_fragmented_prompt_and_wakes_one_reader_once() {
            use futures::{AsyncRead, AsyncWrite};
            use std::sync::atomic::AtomicUsize;

            struct WakeCount(AtomicUsize);
            impl std::task::Wake for WakeCount {
                fn wake(self: Arc<Self>) {
                    self.0.fetch_add(1, Ordering::SeqCst);
                }
            }
            let count = Arc::new(WakeCount(AtomicUsize::new(0)));
            let waker = std::task::Waker::from(count.clone());
            let mut cx = TaskContext::from_waker(&waker);
            let state = Arc::new(Mutex::new(ConsoleState::new(Some("echo one".to_owned()))));
            let mut console = ConsoleCapture(state.clone());
            let mut data = [0; 3];
            assert!(
                Pin::new(&mut console)
                    .poll_read(&mut cx, &mut data)
                    .is_pending()
            );
            assert!(matches!(
                Pin::new(&mut console).poll_write(&mut cx, b"boot\n~ "),
                Poll::Ready(Ok(7))
            ));
            assert_eq!(count.0.load(Ordering::SeqCst), 0);
            assert!(
                Pin::new(&mut console)
                    .poll_read(&mut cx, &mut data)
                    .is_pending()
            );
            assert!(matches!(
                Pin::new(&mut console).poll_write(&mut cx, b"# "),
                Poll::Ready(Ok(2))
            ));
            assert_eq!(count.0.load(Ordering::SeqCst), 1);
            let mut received = Vec::new();
            while let Poll::Ready(Ok(n)) = Pin::new(&mut console).poll_read(&mut cx, &mut data) {
                assert_ne!(n, 0);
                received.extend_from_slice(&data[..n]);
            }
            assert_eq!(received, b"echo one\n");
            assert_eq!(state.lock().consumed, received.len());
            assert!(state.lock().command_sent);
            assert!(!state.lock().command_returned);
            state.lock().return_waiter = Some(waker.clone());
            assert_eq!(state.lock().output, b"boot\n~ # ");
            assert!(matches!(
                Pin::new(&mut console).poll_write(&mut cx, b"~ # "),
                Poll::Ready(Ok(4))
            ));
            assert!(
                Pin::new(&mut console)
                    .poll_read(&mut cx, &mut data)
                    .is_pending()
            );
            assert_eq!(count.0.load(Ordering::SeqCst), 2);
            assert!(state.lock().command_returned);
        }

        #[test]
        fn console_without_command_keeps_reads_pending_and_captures_output_verbatim() {
            use futures::{AsyncRead, AsyncWrite};
            let state = Arc::new(Mutex::new(ConsoleState::new(None)));
            let mut console = ConsoleCapture(state.clone());
            let waker = futures::task::noop_waker();
            let mut cx = TaskContext::from_waker(&waker);
            assert!(matches!(
                Pin::new(&mut console).poll_read(&mut cx, &mut []),
                Poll::Ready(Ok(0))
            ));
            assert!(matches!(
                Pin::new(&mut console).poll_write(&mut cx, b"~ # "),
                Poll::Ready(Ok(4))
            ));
            assert!(
                Pin::new(&mut console)
                    .poll_read(&mut cx, &mut [0])
                    .is_pending()
            );
            let state = state.lock();
            assert_eq!(state.output, b"~ # ");
            assert!(!state.command_sent);
            assert!(state.input.is_empty());
            assert!(state.reader.is_none());
        }

        #[pal_async::async_test]
        async fn unclaimed_ports_rowi_while_claimed_ports_reach_the_chipset(driver: DefaultDriver) {
            async fn complete(io: &WitnessIo, operation: impl Future<Output = ()>) {
                match select(Box::pin(operation), Box::pin(io.failed())).await {
                    Either::Left(((), _)) => {}
                    Either::Right(_) => panic!("harness rejected chipset I/O"),
                }
            }

            let mut io = WitnessIo::default();
            let memory = GuestMemory::allocate(4096);
            let keeper = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
            let time = keeper.builder().build(&driver).await.unwrap();
            let units = state_unit::StateUnits::new();
            let time_unit = units
                .add("vmtime")
                .spawn(driver.clone(), move |recv| async move {
                    let mut keeper = keeper;
                    vmm_core::vmtime_unit::run_vmtime(&mut keeper, recv).await;
                    keeper
                })
                .unwrap();
            let drivers = VmTaskDriverSource::new(ThreadDriverBackend::new(driver));
            let mut config = vmotherboard::options::BaseChipsetDevices::empty();
            config.deps_generic_pci_bus = Some(vmotherboard::options::dev::GenericPciBusDeps {
                bus_id: vmotherboard::BusIdPci::new("pci"),
                pio_addr: 0xcf8,
                pio_data: 0xcfc,
                amd_extended_config: false,
            });
            let output = vmotherboard::BaseChipsetBuilder::new(
                vmotherboard::options::BaseChipsetFoundation {
                    is_restoring: false,
                    untrusted_dma_memory: memory.clone(),
                    trusted_vtl0_dma_memory: memory,
                    power_event_handler: io.events.clone(),
                    debug_event_handler: io.events.clone(),
                    vmtime: &time,
                    vmtime_unit: time_unit.handle(),
                    doorbell_registration: None,
                },
                config,
            )
            .build(&drivers, &units, &vm_resource::ResourceResolver::new())
            .await
            .unwrap();
            let (chipset, _devices) = output.chipset_builder.build().unwrap();
            io.chipset = Some(chipset);
            let vp = VpIndex::new(0);
            for port in [0x87, 0x2f9, 0x4321] {
                for size in [1, 2, 4] {
                    let mut bytes = [0x5a; 6];
                    complete(&io, io.read_io(vp, port, &mut bytes[1..size + 1])).await;
                    assert_eq!(&bytes[1..size + 1], &[0xff; 4][..size]);
                    assert_eq!((bytes[0], bytes[size + 1]), (0x5a, 0x5a));
                    complete(&io, io.write_io(vp, port, &[0; 4][..size])).await;
                    complete(&io, io.read_io(vp, port, &mut bytes[1..size + 1])).await;
                    assert_eq!(&bytes[1..size + 1], &[0xff; 4][..size]);
                }
            }
            let address = 0x8000_0800u32.to_le_bytes();
            for address in [0xfed8_03c0, 0xdead_0000] {
                assert!(!io.is_mmio(address));
                let mut bytes = [0; 4];
                complete(&io, io.read_mmio(vp, address, &mut bytes)).await;
                assert_eq!(bytes, [0xff; 4]);
                complete(&io, io.write_mmio(vp, address, &[0; 4])).await;
            }
            complete(&io, io.write_io(vp, 0xcf8, &address)).await;
            let mut actual = [0; 4];
            complete(&io, io.read_io(vp, 0xcf8, &mut actual)).await;
            assert_eq!(actual, address);
            assert!(io.events.error.lock().is_none());
        }

        #[test]
        fn asserted_unimplemented_irq_is_explicit_and_preserves_the_first_stop() {
            for existing in [false, true] {
                let events = Arc::new(DeviceEvents::default());
                let line = vmcore::line_interrupt::LineInterrupt::new_with_target(
                    "com1",
                    events.clone(),
                    4,
                );
                line.set_level(false);
                assert!(events.error.lock().is_none());
                if existing {
                    events.fail(Box::new(UnconfiguredPort {
                        operation: "input",
                        port: 0x61,
                        size: 1,
                    }));
                }
                line.set_level(true);
                let error = events.error.lock().take().unwrap();
                if existing {
                    assert!(error.is::<UnconfiguredPort>());
                } else {
                    assert!(matches!(
                        error.downcast_ref::<UnsupportedIrq>(),
                        Some(UnsupportedIrq(4))
                    ));
                }
            }
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

    struct MemoryDigest {
        whole: Vec<u8>,
        chunks: Vec<Vec<u8>>,
    }

    fn memory_digest(
        memory: &GuestMemory,
        restore: &BTreeMap<u64, (u64, u64)>,
    ) -> anyhow::Result<MemoryDigest> {
        let mut hash = Sha256::new();
        let mut chunks = Vec::new();
        let mut bytes = vec![0; 65536];
        for address in (0..RAM).step_by(bytes.len()) {
            memory.read_at(address, &mut bytes)?;
            for (&word, &(before, _)) in restore.range(address..address + bytes.len() as u64) {
                let offset = usize::try_from(word - address)?;
                bytes[offset..offset + 8].copy_from_slice(&before.to_le_bytes());
            }

            hash.update(&bytes);
            chunks.push(Sha256::digest(&bytes).to_vec());
        }
        Ok(MemoryDigest {
            whole: hash.finalize().to_vec(),
            chunks,
        })
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

    fn bootdata_stack(
        memory: &GuestMemory,
        changes: &mut BTreeMap<u64, (u64, u64)>,
        initrd: u64,
        initrd_size: u64,
    ) -> anyhow::Result<()> {
        let direct = 0xffff_8880_0000_0000;
        let boot_params = direct + 0x2000;
        let image = direct + initrd;
        let stack = 0xffff_ffff_8260_0000u64;
        let mut word = |offset: u64, value: u64| {
            expected_store(memory, changes, 0x2600000 + offset, &value.to_le_bytes())
        };

        // First #PF: copy_bootdata's original registers, then the early handler's
        // pt_regs, do_early_exception and __early_make_pgtable prologues.
        for (offset, value) in [
            (0x3f18, 0),
            (0x3f10, stack + 0x3f20),
            (0x3f08, 0x10046),
            (0x3f00, 16),
            (0x3ef8, 0xffff_ffff_82d9_8349),
            (0x3ef0, 0),
            (0x3ee8, 1),
            (0x3ee0, 0xffff_ffff),
            (0x3ed8, 0xffff_ffff_82d9_8290),
            (0x3ed0, 0xffff_ffff_830e_2200),
            (0x3ec8, 0),
            (0x3ec0, 0xffff_0000_ffff_ffff),
            (0x3eb8, 0xffff_ffff_0000_ffff),
            (0x3eb0, 0xffff_ffff_82d9_8290),
            (0x3ea8, 20),
            (0x3ea0, 0),
            (0x3e98, boot_params),
            (0x3e90, 0xb0),
            (0x3e88, 0),
            (0x3e80, 0),
            (0x3e78, 0x2000),
            (0x3e70, 0xffff_ffff_82d9_82bf),
            (0x3e68, 0xb0),
            (0x3e60, boot_params),
            (0x3e58, 0xffff_ffff_82d9_87d0),
            (0x3e50, 0x2000),
            (0x3e48, 0),
            (0x3e40, 0),
            (0x3e38, stack + 0x3e78),
            (0x3e30, 14),
            (0x3e28, 0),
            (0x3e20, 0x8000_0000_0000_00e3),
        ] {
            word(offset, value)?;
        }

        // The wrapper clears its option buffer, restores its registers and
        // tail-calls the AMD loader. Its x86_family return survives a dword store.
        for offset in (0x3ec8..=0x3f08).step_by(8) {
            word(offset, 0)?;
        }
        word(0x3eb8, 0xffff_ffff_82da_7a7f)?;
        word(0x3f20, 0x2000)?;
        word(0x3f18, 0)?;
        word(0x3f10, 0)?;
        for offset in (0x3ec0..=0x3f00).step_by(8) {
            word(offset, 0)?;
        }
        word(0x3eb0, 0xffff_ffff_82da_82b4)?;
        word(0x3ea8, 0x00a0_0f11)?;
        word(0x3ea0, 0)?;

        // snprintf/vsnprintf's saved registers and surviving locals. The final
        // literal memcpy overwrites only the low byte of a saved format pointer.
        for (offset, value) in [
            (0x3dc8, stack + 0x3e28),
            (0x3dc0, 0x2000),
            (0x3db8, 0),
            (0x3db0, 0),
            (0x3da8, 0xb0),
            (0x3da0, stack + 0x3ee0),
            (0x3dd0, 0xffff_ffff_81eb_f9c8),
            (0x3d78, 36),
            (0x3d70, 0xffff_ffff_8243_2e01),
            (0x3d68, 0xffff_ffff_8243_2e5e),
            (0x3d60, 0xffff_ffff_81eb_f6d4),
            (0x3d58, stack + 0x3dc8),
        ] {
            word(offset, value)?;
        }

        // find_microcode_in_initrd and find_cpio_data. The gzip byte is not a
        // hexadecimal CPIO digit, so the initialized empty result is returned.
        for (offset, value) in [
            (0x3e30, 0xffff_ffff_82da_7f98),
            (0x3e28, 0xb0),
            (0x3e20, 0),
            (0x3e18, 0xffff_ffff_82da_7b5f),
            (0x3e10, 0x2000),
            (0x3e08, 0),
            (0x3e00, 0),
            (0x3df8, stack + 0x3e50),
            (0x3df0, 0xffff_ffff_830f_36a0),
            (0x3de8, stack + 0x3ee0),
            (0x3de0, 0),
            (0x3d50, 0),
            (0x3d80, 0),
            (0x3d88, 0),
            (0x3d90, 0),
            (0x3d98, 0),
            (0x3e50, 0),
            (0x3e58, 0),
            (0x3e60, 0),
            (0x3e68, 0),
            (0x3e70, (stack + 0x3ee0) & !0xffff),
        ] {
            word(offset, value)?;
        }

        // Second #PF: the first initrd byte, before CPIO parsing can alter its
        // arguments. CMP initrd_size,0x6e supplies the saved arithmetic flags.
        ensure!(
            initrd_size > 0x6e && initrd_size < RAM,
            "unexpected initrd comparison profile"
        );
        let difference = initrd_size - 0x6e;
        let flags =
            2 | if (difference as u8).count_ones().is_multiple_of(2) {
                4
            } else {
                0
            } | if (initrd_size ^ 0x6e ^ difference) & 0x10 != 0 {
                0x10
            } else {
                0
            };
        for (offset, value) in [
            (0x3d48, 0),
            (0x3d40, stack + 0x3d50),
            (0x3d38, flags | 0x10000),
            (0x3d30, 16),
            (0x3d28, 0xffff_ffff_81e9_ecfa),
            (0x3d20, 0),
            (0x3d18, 0xffff_ffff_8202_2d00),
            (0x3d10, 0xffff_ffff_8202_2d00),
            (0x3d08, image),
            (0x3d00, 37),
            (0x3cf8, 37),
            (0x3cf0, stack + 0x3ddc),
            (0x3ce8, 0xffff_ffff_8243_2e5e),
            (0x3ce0, 1),
            (0x3cd8, 1),
            (0x3cd0, image),
            (0x3cc8, initrd_size),
            (0x3cc0, stack + 0x3e50),
            (0x3cb8, 0),
            (0x3cb0, image),
            (0x3ca8, 0xffff_ffff_8202_2d00),
            (0x3ca0, 0xffff_ffff_82d9_82bf),
            (0x3c98, stack + 0x3e50),
            (0x3c90, initrd_size),
            (0x3c88, 0xffff_ffff_82d9_87d0),
            (0x3c80, 0xffff_ffff_8202_2d00),
            (0x3c78, image),
            (0x3c70, 0),
            (0x3c68, stack + 0x3ca8),
            (0x3c60, 14),
            (0x3c58, image),
            (0x3c50, (initrd & !0x1f_ffff) | 0x8000_0000_0000_00e3),
            (0x3f28, 0xffff_ffff_82d9_899c),
        ] {
            word(offset, value)?;
        }
        expected_store(memory, changes, 0x2603ebc, &0u32.to_le_bytes())?;
        expected_store(memory, changes, 0x2603dd8, &32u32.to_le_bytes())?;
        expected_store(memory, changes, 0x2603da0, &0u16.to_le_bytes())?;
        expected_store(memory, changes, 0x2603e9c, &0u32.to_le_bytes())?;
        expected_store(
            memory,
            changes,
            0x2603e7c,
            b"amd-ucode/microcode_amd_fam19h.bin\0",
        )?;
        Ok(())
    }

    fn main_kernel_stack(
        memory: &GuestMemory,
        changes: &mut BTreeMap<u64, (u64, u64)>,
    ) -> anyhow::Result<()> {
        let stack = 0xffff_ffff_8260_0000u64;
        // Reservations repeats copy_bootdata because the loader header version
        // is zero; SME-disabled calls still leave their ordinary return slots.
        for (offset, value) in [
            (0, 0x57ac6e9d),
            (0x3f00, 0xffff_ffff_82db_8d8e),
            (0x3f08, 0xffff_ffff_82db_8e2f),
            (0x3f18, 0x2000),
            (0x3f20, 0xffff_ffff_82d9_8814),
            // start_kernel, build_id_parse_buf and parse_build_id prologues.
            (0x3f18, 0),
            (0x3f10, 0),
            (0x3f08, 0xb0),
            (0x3f00, 0x2000),
            (0x3ef8, 0),
            (0x3ee0, 0),
            (0x3ed8, 0),
            (0x3ed0, 0),
            (0x3ec8, 0),
            (0x3ec0, 0x88),
            (0x3eb8, 0xffff_ffff_8256_fa2c),
            (0x3eb0, 0),
            (0x3ea8, 0),
            (0x3e90, 0x2000),
            (0x3e88, 0),
            (0x3e80, 0),
            (0x3e78, 0xb0),
            (0x3e70, 0x2000),
            (0x3e68, 0),
            (0x3e60, 20u64 << 32),
            // freader_fetch's second GNU-note fetch: offset 16, length 20.
            (0x3e58, 0xffff_ffff_81e9_de0e),
            (0x3e50, 0x88),
            (0x3e48, stack + 0x3ea8),
            (0x3e40, 0x88),
            (0x3e38, 20),
            (0x3e30, 16),
            // cgroup_init_early, first cpuset initialization and mutex_lock.
            (0x3ee8, 0xffff_ffff_82d8_7b07),
            (0x3ee0, 0),
            (0x3ed8, 0xb0),
            (0x3ed0, 0x2000),
            (0x3ec8, 0),
            (0x3ec0, 0xffff_ffff_82dc_696a),
            (0x3eb8, 0xffff_ffff_8245_6242),
            (0x3eb0, 0xffff_ffff_827b_95a0),
            (0x3ea8, 0),
            (0x3ea0, 0xffff_ffff_82dc_66d6),
            (0x3e98, 0xffff_ffff_827b_95a0),
            (0x3e90, 0xffff_ffff_81ed_6579),
        ] {
            expected_store(memory, changes, 0x2600000 + offset, &value.to_le_bytes())?;
        }
        Ok(())
    }

    fn check_zero_ranges(
        memory: &GuestMemory,
        projection: &serde_json::Value,
    ) -> anyhow::Result<u64> {
        let ranges = projection["zero_ranges"]
            .as_array()
            .context("missing exact zero ranges")?;
        ensure!(!ranges.is_empty(), "missing residual BSS/brk zero ranges");
        let mut total = 0;
        let mut previous_end = 0x30e1000;
        let mut buffer = vec![0; 65536];
        for range in ranges {
            let start = range["start"]
                .as_u64()
                .context("missing zero-range start")?;
            let end = range["end"].as_u64().context("missing zero-range end")?;
            ensure!(
                previous_end <= start
                    && start < end
                    && end <= 0x3630000
                    && range["loader_preimage_zero"].as_bool() == Some(true),
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
            previous_end = end;
        }
        Ok(total)
    }

    fn walk_trace(
        memory: &GuestMemory,
        root: u64,
        va: u64,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let mut table = root;
        let mut trace = Vec::new();
        for shift in [39, 30, 21, 12] {
            let address = table + ((va >> shift) & 511) * 8;
            if address >= RAM {
                trace.push(serde_json::json!({"shift":shift,"address":address,"outside_ram":true}));
                break;
            }
            let word = memory.read_plain::<u64>(address)?;
            trace.push(serde_json::json!({"shift":shift,"address":address,"word":word}));
            if word & 1 == 0 || shift == 12 || ((shift == 30 || shift == 21) && word & 0x80 != 0) {
                break;
            }
            table = word & 0x0000_ffff_ffff_f000;
        }
        Ok(trace)
    }

    fn virtual_words(
        memory: &GuestMemory,
        root: u64,
        linear: u64,
        count: u64,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let trace = walk_trace(memory, root, linear)?;
        let mut words = Vec::new();
        if let Some(leaf) = trace.last() {
            if let (Some(word), Some(shift)) = (leaf["word"].as_u64(), leaf["shift"].as_u64()) {
                if word & 1 != 0
                    && (shift == 12 || ((shift == 21 || shift == 30) && word & 0x80 != 0))
                {
                    let mask = (1u64 << shift) - 1;
                    let physical = (word & 0x0000_ffff_ffff_f000 & !mask) | (linear & mask);
                    let bytes = (0x1000 - (linear & 0xfff)).min(count * 8);
                    for offset in (0..bytes.saturating_sub(7)).step_by(8) {
                        words.push(serde_json::json!({
                            "address":linear+offset, "value":memory.read_plain::<u64>(physical+offset)?,
                        }));
                    }
                }
            }
        }
        Ok(words)
    }

    async fn witness(driver: DefaultDriver) -> anyhow::Result<()> {
        let mut args = std::env::args_os().skip(1);
        let kernel_path = args.next().context("missing vmlinux")?;
        let initrd_path = args.next().context("missing initrd")?;
        let oracle_path = args.next().context("missing mapping projection")?;
        let initial_mapping_path = args
            .next()
            .context("missing pre-reset mapping projection")?;
        let option = args.next();
        let slow_time = option.as_deref() == Some(std::ffi::OsStr::new("--probe-apic-slow"));
        let probe_apic =
            slow_time || option.as_deref() == Some(std::ffi::OsStr::new("--probe-apic"));
        let clock_slowdown = std::num::NonZeroU16::new(if slow_time { 10 } else { 1 }).unwrap();
        let pm_stalls = option.as_deref() == Some(std::ffi::OsStr::new("--probe-pm-stalls"));
        let loader_inputs = option.as_deref() == Some(std::ffi::OsStr::new("--loader-inputs"));
        let probe = match option {
            None => false,
            Some(argument) => {
                ensure!(
                    argument == "--probe" || probe_apic || pm_stalls || loader_inputs,
                    "unknown witness option"
                );
                !loader_inputs
            }
        };
        let probe_target = if probe {
            match args.next() {
                None => PROBE_TARGET,
                Some(value) => {
                    let value = value.to_str().context("non-UTF8 probe checkpoint")?;
                    u64::from_str_radix(
                        value
                            .strip_prefix("0x")
                            .context("probe checkpoint needs 0x prefix")?,
                        16,
                    )
                    .context("invalid probe checkpoint")?
                }
            }
        } else {
            PROBE_TARGET
        };
        let probe_seconds = if probe {
            match args.next() {
                None => 120,
                Some(value) => value
                    .to_str()
                    .context("non-UTF8 probe deadline")?
                    .parse::<u32>()
                    .context("invalid probe deadline in seconds")?,
            }
        } else {
            120
        };
        ensure!(probe_seconds > 0, "probe deadline must be positive");
        let mut shell_command = None;
        let mut stop_after_command = false;
        let mut guest_checkpoint = None;
        let mut svm_enabled = false;
        let mut profile_enabled = false;
        #[cfg(feature = "perf")]
        let mut perf_control = None;
        while let Some(flag) = args.next() {
            if flag == "--guest-checkpoint" {
                ensure!(guest_checkpoint.is_none(), "duplicate guest checkpoint");
                let value = args
                    .next()
                    .context("missing guest checkpoint")?
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("non-UTF8 guest checkpoint"))?;
                guest_checkpoint = Some(u64::from_str_radix(
                    value
                        .strip_prefix("0x")
                        .context("guest checkpoint needs 0x prefix")?,
                    16,
                )?);
            } else if flag == "--stop-after-command" {
                ensure!(!stop_after_command, "duplicate command-stop flag");
                stop_after_command = true;
            } else if flag == "--svm" {
                ensure!(probe_apic, "SVM requires the APIC/chipset probe");
                ensure!(!svm_enabled, "duplicate SVM flag");
                svm_enabled = true;
            } else if flag == "--shell-command" {
                ensure!(probe_apic, "shell command requires the APIC/chipset probe");
                ensure!(shell_command.is_none(), "duplicate shell command");
                shell_command = Some(
                    args.next()
                        .context("missing shell command")?
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("non-UTF8 shell command"))?,
                );
            } else if flag == "--profile" {
                ensure!(probe, "profiling requires a diagnostic probe");
                ensure!(cfg!(feature = "perf"), "profiling requires --features perf");
                ensure!(!profile_enabled, "duplicate profiling flag");
                profile_enabled = true;
            } else if flag == "--perf-control" {
                #[cfg(not(feature = "perf"))]
                bail!("counter control requires --features perf");
                #[cfg(feature = "perf")]
                {
                    ensure!(perf_control.is_none(), "duplicate counter control");
                    perf_control = Some(strudel::perf::CounterControl::open(
                        args.next().context("missing perf control FIFO")?,
                        args.next().context("missing perf acknowledgement FIFO")?,
                    )?);
                }
            } else {
                bail!("unexpected witness argument: {flag:?}");
            }
        }
        let command_configured = shell_command.is_some();
        ensure!(
            guest_checkpoint.is_none() || (probe && svm_enabled),
            "guest checkpoint requires an SVM probe"
        );
        ensure!(
            !stop_after_command || (probe_apic && command_configured),
            "command-stop requires the APIC probe and a shell command"
        );
        ensure!(args.next().is_none(), "unexpected witness arguments");
        let topology = TopologyBuilder::new_x86()
            .x2apic(if probe_apic {
                X2ApicState::Supported
            } else {
                X2ApicState::Unsupported
            })
            .build(1)?;
        let layout = MemoryLayout::new(RAM, &[], &[], &[], None)?;
        let backing = Arc::new(sparse_mmap::SparseMapping::new(usize::try_from(RAM)?)?);
        backing.alloc(0, usize::try_from(RAM)?)?;
        let keeper =
            VmTimeKeeper::new_with_slowdown(&driver, VmTime::from_100ns(0), clock_slowdown);
        let time = keeper.builder().build(&driver).await?;
        let mut hypervisor = EmuHypervisor;
        let config = ProtoPartitionConfig {
            processor_topology: &topology,
            hv_config: None,
            vmtime: &time,
            isolation: ProtoPartitionIsolation::None,
            nested_virt: svm_enabled,
        };
        let proto = if probe_apic {
            hypervisor.new_partition(config)?
        } else {
            hypervisor.new_legacy_fixture(config)?
        };
        let memory = GuestMemory::new(
            "kernel-device-view",
            DeviceBacking {
                mapping: backing.clone(),
                tracker: proto
                    .memory_write_tracker()
                    .context("missing emulator write tracker")?,
            },
        );
        let (partition, mut binders) = proto.build(PartitionConfig {
            mem_layout: &layout,
            guest_memory: &memory,
            cpuid: &[],
            vtl0_alias_map: None,
            fault_resolver: None,
        })?;
        // SAFETY: backing outlives both the partition and its VP binders.
        // UNSAFETY: Installs the owned harness backing just as membacking would.
        #[expect(unsafe_code)]
        unsafe {
            partition.map_range(
                backing.as_ptr().cast(),
                usize::try_from(RAM)?,
                0,
                true,
                true,
            )?;
        }
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
                with_ioapic: probe_apic,
                with_pic: false,
                with_pit: false,
                with_psp: false,
                pm_base: PM_BASE,
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
        if loader_inputs {
            let mut boot_params = vec![0; 4096];
            memory.read_at(initial.registers.rsi, &mut boot_params)?;
            let command_line_address =
                u64::from(u32::from_le_bytes(boot_params[0x228..0x22c].try_into()?))
                    | (u64::from(u32::from_le_bytes(boot_params[0xc8..0xcc].try_into()?)) << 32);
            ensure!(
                command_line_address < RAM - 2048,
                "invalid loader command-line pointer"
            );
            let mut command_line = vec![0; 2048];
            memory.read_at(command_line_address, &mut command_line)?;
            println!(
                "{}",
                serde_json::json!({
                    "loader_inputs":true,"guest_executed":false,
                    "boot_params_address":initial.registers.rsi,
                    "command_line_address":command_line_address,
                    "boot_params_hex":boot_params.iter().map(|byte|format!("{byte:02x}")).collect::<String>(),
                    "command_line_hex":command_line.iter().map(|byte|format!("{byte:02x}")).collect::<String>(),
                })
            );
            return Ok(());
        }
        let mut changes = BTreeMap::new();
        let projection: serde_json::Value = serde_json::from_reader(File::open(oracle_path)?)?;
        for (address, size, name) in [
            (0x2000, 4096, "boot_params"),
            (0x3000, 2048, "command_line"),
        ] {
            let mut input = vec![0; size];
            memory.read_at(address, &mut input)?;
            let actual = Sha256::digest(&input)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            ensure!(
                projection["loader_input_sha256"][name].as_str() == Some(actual.as_str()),
                "loader input differs from its pre-execution projection: {name}"
            );
        }
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
            (0x2603f28, 0xffff_ffff_82d9_8940),
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
        let initrd_address = u64::from(memory.read_plain::<u32>(0x2218)?)
            | (u64::from(memory.read_plain::<u32>(0x20c0)?) << 32);
        ensure!(
            initrd_address == 0x3c00000,
            "unexpected pinned initrd address"
        );
        ensure!(
            memory.read_plain::<u8>(initrd_address)? == 0x1f,
            "unexpected early CPIO input"
        );
        bootdata_stack(&memory, &mut changes, initrd_address, initrd_size)?;
        main_kernel_stack(&memory, &mut changes)?;
        let current_task = memory.read_plain::<u64>(0x30bc018)?;
        let first_subsystem = memory.read_plain::<u64>(0x27b6ac0)?;
        ensure!(
            current_task == 0xffff_ffff_8260_d380 && first_subsystem == 0xffff_ffff_827b_95a0,
            "unexpected first cgroup/task inputs"
        );
        let first_css_alloc = memory.read_plain::<u64>(first_subsystem - 0xffff_ffff_8000_0000)?;
        let first_css_free =
            memory.read_plain::<u64>(first_subsystem - 0xffff_ffff_8000_0000 + 0x20)?;
        // Diagnostic probes return before the post-run digest comparison.
        let before = if probe {
            None
        } else {
            Some(memory_digest(&memory, &BTreeMap::new())?)
        };
        let mut initial_stack_task = vec![0; 65536];
        memory.read_at(0x2600000, &mut initial_stack_task)?;
        let mut binder = binders.pop().context("missing VP binder")?;
        ensure!(binders.is_empty(), "unexpected additional VP");
        let mut vp = binder.bind()?;
        #[cfg(feature = "perf")]
        if profile_enabled {
            vp.enable_execution_profile()?;
        }
        if let Some(target) = guest_checkpoint {
            vp.set_guest_execution_checkpoint(Some(target))?;
        } else {
            vp.set_execution_checkpoint(Some(if probe { probe_target } else { CHECKPOINT }))?;
        }
        {
            let mut state = vp.access_state(Vtl::Vtl0);
            state.set_mtrrs(&initial.mtrrs)?;
            state.set_registers(&initial.registers)?;
            state.set_pat(&initial.pat)?;
            state.commit()?;
        }
        let mut devices = WitnessIo {
            with_ioapic: probe_apic,
            pm_stalls,
            ..WitnessIo::default()
        };
        let console = Arc::new(Mutex::new(ConsoleState::new(shell_command)));
        let mut units = state_unit::StateUnits::new();
        let time_unit = units
            .add("vmtime")
            .spawn(driver.clone(), move |recv| async move {
                let mut keeper = keeper;
                vmm_core::vmtime_unit::run_vmtime(&mut keeper, recv).await;
                keeper
            })?;
        let driver_source = VmTaskDriverSource::new(ThreadDriverBackend::new(driver.clone()));
        let _chipset_devices = if probe {
            let mut config = vmotherboard::options::BaseChipsetDevices::empty();
            config.deps_generic_pci_bus = Some(vmotherboard::options::dev::GenericPciBusDeps {
                bus_id: vmotherboard::BusIdPci::new("pci"),
                pio_addr: 0xcf8,
                pio_data: 0xcfc,
                amd_extended_config: x86_system::arch::profile::NB_CFG & (1 << 46) != 0,
            });
            let foundation = vmotherboard::options::BaseChipsetFoundation {
                is_restoring: false,
                untrusted_dma_memory: memory.clone(),
                trusted_vtl0_dma_memory: memory.clone(),
                power_event_handler: devices.events.clone(),
                debug_event_handler: devices.events.clone(),
                vmtime: &time,
                vmtime_unit: time_unit.handle(),
                doorbell_registration: None,
            };
            let output = vmotherboard::BaseChipsetBuilder::new(foundation, config)
                .build(
                    &driver_source,
                    &units,
                    &vm_resource::ResourceResolver::new(),
                )
                .await?;
            if probe_apic {
                let partition = Arc::new(partition);
                output
                    .chipset_builder
                    .arc_mutex_device("ioapic")
                    .add(|services| {
                        services.add_line_target(IRQ_LINE_SET, 0..=23, 0);
                        chipset::ioapic::IoApicDevice::new(
                            24,
                            Box::new(IoApicRoutes {
                                partition,
                                routes: Mutex::new([None; 24]),
                                events: devices.events.clone(),
                            }),
                        )
                    })?;
            }
            output
                .chipset_builder
                .arc_mutex_device("absent-pcat")
                .omit_saved_state()
                .add(|services| {
                    missing_dev::MissingDev::from_manifest(
                        missing_dev::MissingDevManifest::new()
                            .claim_pio("primary-pic", 0x20..=0x21)
                            .claim_pio("secondary-pic", 0xa0..=0xa1)
                            .claim_pio("pic-elcr", 0x4d0..=0x4d1)
                            .claim_pio("pit", 0x40..=0x43)
                            .claim_pio("speaker", 0x61..=0x61)
                            .claim_pio("post-delay", 0x80..=0x80)
                            .claim_pio("absent-pci-config-type2", 0xc000..=0xcfff),
                        &mut services.register_mmio(),
                        &mut services.register_pio(),
                    )
                })?;
            output
                .chipset_builder
                .arc_mutex_device("pm")
                .add(|services| {
                    let events = devices.events.clone();
                    let mut pm = chipset::pm::PowerManagementDevice::new(
                        Box::new(move |action| {
                            events.fail(Box::new(std::io::Error::other(format!(
                                "unexpected PM action {action:?}"
                            ))));
                        }),
                        if probe_apic {
                            services.new_line(IRQ_LINE_SET, "pm", 9)
                        } else {
                            vmcore::line_interrupt::LineInterrupt::new_with_target(
                                "pm",
                                devices.events.clone(),
                                9,
                            )
                        },
                        &mut services.register_pio(),
                        services.register_vmtime().access("pm"),
                        None,
                        None,
                        None,
                    );
                    pm.update_dynamic_pio_mappings(Some(PM_BASE));
                    pm
                })?;
            output
                .chipset_builder
                .arc_mutex_device("rtc")
                .add(|services| {
                    chipset::cmos_rtc::Rtc::new(
                        Box::new(local_clock::SystemTimeClock::new(
                            local_clock::LocalClockDelta::ZERO,
                        )),
                        if probe_apic {
                            services.new_line(IRQ_LINE_SET, "rtc", 8)
                        } else {
                            vmcore::line_interrupt::LineInterrupt::new_with_target(
                                "rtc",
                                devices.events.clone(),
                                8,
                            )
                        },
                        services.register_vmtime(),
                        0x32,
                        None,
                        false,
                    )
                })?;
            output
                .chipset_builder
                .arc_mutex_device("com1")
                .try_add(|services| {
                    serial_16550::Serial16550::new(
                        "com1".to_owned(),
                        serial_16550_resources::MmioOrIoPort::IoPort(0x3f8),
                        1,
                        if probe_apic {
                            services.new_line(IRQ_LINE_SET, "com1", 4)
                        } else {
                            vmcore::line_interrupt::LineInterrupt::new_with_target(
                                "com1",
                                devices.events.clone(),
                                4,
                            )
                        },
                        Box::new(serial_core::serial_io::Connected::new(ConsoleCapture(
                            console.clone(),
                        ))),
                        false,
                        None,
                    )
                })?;
            let (chipset, registered) = output.chipset_builder.build()?;
            devices.chipset = Some(chipset);
            units.start().await;
            Some(registered)
        } else {
            None
        };
        let stop = StopVpSource::new();
        let initial_jiffies = memory.read_plain::<u64>(0x2609980)?;
        #[cfg(feature = "perf")]
        let counters_gated = perf_control.is_some();
        #[cfg(not(feature = "perf"))]
        let counters_gated = false;
        #[cfg(feature = "perf")]
        if let Some(control) = &mut perf_control {
            control.set(true)?;
        }
        let started = Instant::now();
        let run = Box::pin(vp.run_vp(stop.checker(), &devices));
        let diagnostic = async {
            let deadline = async {
                if !probe {
                    std::future::pending::<()>().await;
                }
                pal_async::timer::PolledTimer::new(&driver)
                    .sleep(std::time::Duration::from_secs(u64::from(probe_seconds)))
                    .await;
                devices.events.fail(Box::new(ProbeDeadline(probe_seconds)));
            };
            let command_end = async {
                if !stop_after_command {
                    std::future::pending::<()>().await;
                }
                futures::future::poll_fn(|cx| {
                    let mut state = console.lock();
                    if state.command_returned {
                        Poll::Ready(())
                    } else {
                        state.return_waiter = Some(cx.waker().clone());
                        Poll::Pending
                    }
                })
                .await;
                devices.events.fail(Box::new(CommandReturned));
            };
            let terminal = async {
                select(Box::pin(deadline), Box::pin(command_end)).await;
            };
            select(Box::pin(devices.failed()), Box::pin(terminal)).await;
        };
        match select(run, Box::pin(diagnostic)).await {
            Either::Left((Err(VpHaltReason::PowerOff), _)) => {}
            Either::Left((other, _)) => bail!("unexpected VP outcome: {other:?}"),
            Either::Right(_) if probe => {}
            Either::Right(_) => {
                let failure = devices
                    .events
                    .error
                    .lock()
                    .take()
                    .context("missing device diagnostic")?;
                bail!("device operation before entry frontier: {failure}");
            }
        }
        let seconds = started.elapsed().as_secs_f64();
        #[cfg(feature = "perf")]
        if let Some(control) = &mut perf_control {
            control.set(false)?;
        }
        if probe {
            units.stop().await;
        }
        let failure = devices
            .events
            .error
            .lock()
            .take()
            .context("missing frontier diagnostic")?;
        let stopped_rip = vp.access_state(Vtl::Vtl0).registers()?.rip;
        if probe {
            ensure!(
                matches!(
                    failure.downcast_ref::<Error>(),
                    Some(
                        Error::Cpu(_)
                            | Error::Checkpoint { .. }
                            | Error::Apic(_)
                            | Error::ApicIngress(_)
                            | Error::UnsupportedInterrupt
                            | Error::Memory(_)
                    )
                ) || failure.is::<UnconfiguredPort>()
                    || failure.is::<UnsupportedIrq>()
                    || failure.is::<ProbeDeadline>()
                    || failure.is::<CommandReturned>(),
                "unexpected probe transport/device failure: {failure}"
            );
            let registers = vp.access_state(Vtl::Vtl0).registers()?;
            let progress = vp.completed_batch_progress();
            #[cfg(feature = "perf")]
            let execution_profile = vp.take_execution_profile().map(|profile| {
                serde_json::json!({
                    "sample_every_batches":profile.sample_every_batches,
                    "truncated":profile.truncated,
                    "samples":profile.samples.into_iter().map(|sample| serde_json::json!({
                        "seconds":sample.seconds,"retired":sample.retired,
                        "delivered":sample.delivered,"rip":sample.rip,
                    })).collect::<Vec<_>>(),
                })
            });
            #[cfg(not(feature = "perf"))]
            let execution_profile: Option<serde_json::Value> = None;
            let final_jiffies = memory.read_plain::<u64>(0x2609980)?;
            let (decode, first_decode) = vp.decode_diagnostics()?;
            let decode_json = |d: virt_emu::backend::DecodeDiagnostics| {
                serde_json::json!({
                    "entries":d.entries,"bytes":d.bytes,
                    "windows":d.windows,"hits":d.hits,"empty":d.empty,"collisions":d.collisions,
                    "changed":d.changed,"admissions":d.admissions,
                    "fetch_lookups":d.fetch_lookups,"fetch_hits":d.fetch_hits,
                    "fetch_misses":d.fetch_misses,
                    "execution_lookups":d.execution_lookups,
                    "execution_hits":d.execution_hits,"execution_misses":d.execution_misses,
                    "chain_lookups":d.chain_lookups,"chain_hits":d.chain_hits,
                    "chain_links":d.chain_links,
                    "block_lookups":d.block_lookups,"block_hits":d.block_hits,
                    "block_builds":d.block_builds,
                })
            };
            let preparation = vp.code_preparation_diagnostics();
            let execution = vp.execution_diagnostics()?;
            ensure!(
                execution
                    .single_retired
                    .wrapping_add(execution.block_retired)
                    == progress.retired,
                "execution diagnostics disagree with retired instruction progress"
            );
            let translations = vp.translation_diagnostics()?;
            let apic=vp.apic_diagnostics().map(|snapshot| {
                let apic=snapshot.registers;
                serde_json::json!({
                    "base":apic.base,"svr":apic.svr,"tpr":apic.tpr,"lvt":apic.lvt,
                    "irr":apic.interrupts.irr.words,"isr":apic.interrupts.isr.words,
                    "timer_initial":apic.timer.initial,"timer_current":apic.timer.current,
                    "timer_divisor":apic.timer.divisor,"timer_periodic":apic.timer.periodic,
                    "timer_last":apic.timer.last,"vm_time_100ns":snapshot.vm_time_100ns,
                    "delivered":snapshot.delivered,"first_interrupt_retired":snapshot.first_interrupt_retired,
                    "first_interrupt_time_100ns":snapshot.first_interrupt_time_100ns,
                    "decode":decode_json(decode),"decode_at_first_interrupt":first_decode.map(decode_json),
                    "execution":execution_json(execution),
                    "code_pages_prepared":preparation.prepared,
                    "code_pages_unavailable":preparation.unavailable,
                    "translations":{
                        "hits":translations.hits,"misses":translations.misses,
                        "invalidations":translations.invalidations,"fallbacks":translations.fallbacks,
                    },
                    "layout":{
                        "event_phase":size_of::<x86_system::execute::Phase>(),
                        "decode_decision":size_of::<x86_system::execute::decode::DecodeOutcome>(),
                        "request":size_of::<x86_system::mmu::translate::Request>(),
                        "reply":size_of::<x86_system::mmu::translate::Reply>(),
                        "effect_result":size_of::<Result<x86_system::mmu::translate::Reply,x86_system::mmu::translate::RunError<virt_emu::native_memory::RamError>>>(),
                    },
                    "jiffies_initial":initial_jiffies,"jiffies_final":final_jiffies,
                    "jiffies_delta":final_jiffies.wrapping_sub(initial_jiffies),
                })
            });
            let current_stack_walk = walk_trace(&memory, registers.cr3, registers.rsp)?;
            let current_stack_words = virtual_words(&memory, registers.cr3, registers.rsp, 128)?;
            let current_code_words = virtual_words(&memory, registers.cr3, registers.rip & !7, 4)?;
            let callback_args = if guest_checkpoint.is_some() {
                virtual_words(&memory, registers.cr3, registers.rdx, 4)?
            } else {
                Vec::new()
            };
            let callback_regs = if let Some(address) = callback_args
                .first()
                .and_then(|word| word["value"].as_u64())
            {
                virtual_words(&memory, registers.cr3, address, 21)?
            } else {
                Vec::new()
            };
            let checkpoint_rdi_words = if guest_checkpoint.is_some() {
                virtual_words(&memory, registers.cr3, registers.rdi, 21)?
            } else {
                Vec::new()
            };
            let breakpoint_gate = if guest_checkpoint.is_some() {
                virtual_words(&memory, registers.cr3, registers.idtr.base + 3 * 16, 2)?
            } else {
                Vec::new()
            };
            // v6.18.33's soft-exception skip return, with its pinned vcpu_svm offsets.
            let kvm_soft_rip = if probe_target == 0xffff_ffff_812e_42d6
                && guest_checkpoint.is_none()
            {
                let rip = virtual_words(&memory, registers.cr3, registers.rbx + 0x1b0, 4)?;
                let exception = virtual_words(&memory, registers.cr3, registers.rbx + 0x868, 4)?;
                let pointer = virtual_words(&memory, registers.cr3, registers.rbx + 0x1740, 1)?;
                serde_json::json!({
                    "rip":rip,"exception":exception,"vmcb_pointer":pointer,
                    "vcpu_address":registers.rbx,
                    "vcpu_rip_mapped":!rip.is_empty(),"vmcb_pointer_mapped":!pointer.is_empty(),
                })
            } else {
                serde_json::Value::Null
            };
            let mut stack_words = Vec::new();
            for address in (0x2603c00..0x2603f48).step_by(8) {
                let value = memory.read_plain::<u64>(address)?;
                if value != 0 {
                    stack_words.push(serde_json::json!({"address":address,"value":value}));
                }
            }
            let mut encoding = None;
            if stopped_rip >= 0xffff_ffff_8000_0000
                && stopped_rip - 0xffff_ffff_8000_0000 < RAM - 16
            {
                let mut bytes = [0; 16];
                memory.read_at(stopped_rip - 0xffff_ffff_8000_0000, &mut bytes)?;
                encoding = Some(bytes);
            }
            let (serial_bytes, serial_input) = {
                let console = console.lock();
                (
                    console.output.clone(),
                    serde_json::json!({
                        "configured":command_configured,
                        "queued_after_prompt":console.command_sent,
                        "consumed":console.consumed,
                        "remaining":console.input.len(),
                    }),
                )
            };
            let serial_output = String::from_utf8_lossy(&serial_bytes).into_owned();
            println!(
                "{}",
                serde_json::json!({
                    "probe":true,"acceptance":false,"stop":failure.to_string(),"target":probe_target,
                    "stop_debug":format!("{failure:?}"),
                    "stop_after_command":stop_after_command,
                    "transport_error":matches!(failure.downcast_ref::<Error>(),Some(Error::Memory(_))),
                    "retired":progress.retired,"delivered":progress.delivered,"seconds":seconds,
                    "counters_gated":counters_gated,
                    "execution_profile":execution_profile,
                    "clock_slowdown":clock_slowdown.get(),"svm_enabled":svm_enabled,
                    "rip":registers.rip,"cr2":registers.cr2,"registers":format!("{registers:?}"),
                    "kernel_image_bytes":encoding,
                    "instruction_walk":walk_trace(&memory,registers.cr3,registers.rip)?,
                    "cr2_walk":walk_trace(&memory,registers.cr3,registers.cr2)?,
                    "stack_words":stack_words,
                    "current_stack_walk":current_stack_walk,
                    "current_stack_words":current_stack_words,
                    "current_code_words":current_code_words,
                    "guest_checkpoint":guest_checkpoint,"callback_args":callback_args,"callback_regs":callback_regs,
                    "checkpoint_rdi_words":checkpoint_rdi_words,
                    "breakpoint_gate":breakpoint_gate,
                    "kvm_soft_rip":kvm_soft_rip,
                    "serial_bytes":serial_bytes,
                    "serial_output":serial_output,
                    "serial_input":serial_input,
                    "calibration":{
                        "cpu_khz":memory.read_plain::<u32>(0x28b95f8)?,
                        "tsc_khz":memory.read_plain::<u32>(0x28b95f4)?,
                        "pm_reads":devices.pm_reads.load(Ordering::Relaxed),
                        "pm_stalls":devices.pm_stalls,
                        "pm_stalls_injected":devices.pm_stalls_injected.load(Ordering::Relaxed),
                        "tsc_hz":x86_system::arch::profile::TSC_HZ,
                    },
                    "apic":apic,
                })
            );
            return Ok(());
        }
        ensure!(
            matches!(
                failure.downcast_ref::<Error>(),
                Some(Error::Checkpoint {rip}) if *rip==CHECKPOINT
            ),
            "did not reach the host checkpoint: stopped at {stopped_rip:#x}: {failure}"
        );
        let progress = vp.completed_batch_progress();
        ensure!(
            progress.retired > 960613 && progress.retired < 2_000_000 && progress.delivered == 2,
            "wrong progress: {progress:?}"
        );
        let mut expected = initial.registers;
        expected.cr0 = 0x80050033;
        expected.cr4 = 0xb0;
        expected.efer = 0xd01;
        expected.rax = 0;
        expected.rbx = first_subsystem;
        expected.rdx = current_task;
        expected.rcx = first_css_alloc;
        expected.rsi = 1;
        expected.rdi = 0xffff_ffff_827b_6be0;
        expected.rbp = expected.rdi;
        expected.r8 = first_css_free;
        expected.r9 = 0;
        expected.r10 = 0xffff_ffff_8256_fa2c;
        expected.r11 = 1;
        expected.r12 = 1;
        expected.cr3 = ROOT;
        expected.r15 = initial.registers.rsi;
        expected.rsp = STACK;
        expected.rip = CHECKPOINT;
        expected.rflags = 0x46;
        expected.cr2 = 0xffff_8880_0000_0000 + initrd_address;
        expected.gdtr.base = 0xffff_ffff_830a_e000;
        expected.gdtr.limit = 0x7f;
        expected.idtr.base = 0xffff_ffff_830e_2000;
        expected.idtr.limit = 0xfff;
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
        let after = memory_digest(&memory, &changes)?;
        let before = before.context("missing strict whole-RAM baseline")?;
        let mismatched_chunks: Vec<_> = before
            .chunks
            .iter()
            .zip(&after.chunks)
            .enumerate()
            .filter(|(_, pair)| pair.0 != pair.1)
            .map(|(index, _)| format!("{:#x}", index * 65536))
            .collect();
        if after.whole != before.whole {
            let mut unknown = Vec::new();
            let mut count = 0usize;
            for (index, bytes) in initial_stack_task.chunks_exact(8).enumerate() {
                let address = 0x2600000 + index as u64 * 8;
                let original = u64::from_le_bytes(bytes.try_into()?);
                let actual = memory.read_plain::<u64>(address)?;
                if !changes.contains_key(&address) && original != actual {
                    count += 1;
                    if unknown.len() < 16 {
                        unknown.push(format!("{address:#x}: {original:#x}->{actual:#x}"));
                    }
                }
            }
            bail!(
                "RAM changed outside projected effects; chunks {mismatched_chunks:?}; unprojected stack/task words {count}: {unknown:?}"
            );
        }
        ensure!(
            after.whole == before.whole,
            "RAM changed outside projected effects; mismatched 64-KiB chunks: {mismatched_chunks:?}"
        );
        let mut bytes = [0; 7];
        memory.read_at(CHECKPOINT - 0xffff_ffff_8000_0000, &mut bytes)?;
        ensure!(
            bytes == [0x75, 0x06, 0x5d, 0xe9, 0xdf, 0x5d, 0],
            "wrong checkpoint bytes"
        );
        let functions = [0, 1, 0x8000_0000, 0x8000_0001, 0x8000_0008];
        let cpuid: Vec<_> = functions
            .into_iter()
            .map(|function| {
                serde_json::json!({
                    "function": function, "subleaf": 0,
                    "registers": x86_system::arch::profile::cpuid(function, 0),
                })
            })
            .collect();
        let decode = vp.decode_diagnostics()?.0;
        let execution = vp.execution_diagnostics()?;
        let translations = vp.translation_diagnostics()?;
        ensure!(
            translations.hits > 0,
            "host-bound TLB path was not exercised"
        );
        let no_refetch_hits = decode.fetch_hits.wrapping_add(decode.execution_hits);
        ensure!(
            no_refetch_hits > 0,
            "watched instruction-cache path was not exercised"
        );
        ensure!(
            decode.execution_hits > 0,
            "VA execution-cache path was not exercised"
        );
        ensure!(
            decode.chain_hits > 0,
            "intra-page successor path was not exercised"
        );
        let preparation = vp.code_preparation_diagnostics();
        println!(
            "{}",
            serde_json::json!({
                "retired": progress.retired, "delivered": progress.delivered,
                "no_refetch_hits":no_refetch_hits,
                "execution_cache_hits":decode.execution_hits,
                "chain_hits":decode.chain_hits,
                "execution":execution_json(execution),
                "translations":{
                    "hits":translations.hits,"misses":translations.misses,
                    "invalidations":translations.invalidations,"fallbacks":translations.fallbacks,
                },
                "code_pages_prepared":preparation.prepared,
                "code_pages_unavailable":preparation.unavailable,
                "entry": ENTRY, "checkpoint": actual.rip, "checkpoint_hex": "75065de9df5d00",
                "stop_kind":"host_checkpoint","initial_memory_cleared":true,
                "kernel_c_entry":true,"identity_mappings_removed":true,"zero_bytes":zero_bytes,
                "boot_parameters_copied":true,"command_line_copied":true,
                "guest_page_faults_repaired":true,"reservations_entry":true,
                "main_kernel_entry":true,"first_mutex_acquired":true,
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
