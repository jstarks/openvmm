// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::backend::{EmuHypervisor, EmuPartition, EmuProcessorBinder, long_mode_registers};
use super::shared_event_tests::fixture;
use futures::task::{ArcWake, AtomicWaker, waker};
use guestmem::GuestMemory;
use hvdef::Vtl;
use memory_range::MemoryRange;
use pal_async::{DefaultDriver, async_test};
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use test_with_tracing::test;
use virt::io::CpuIo;
use virt::vp::AccessVpState;
use virt::{
    BindProcessor, Hypervisor, Partition, PartitionConfig, Processor, ProtoPartition,
    ProtoPartitionConfig, ProtoPartitionIsolation, StopVpSource, VpHaltReason, VpIndex,
};
use vm_topology::memory::MemoryLayout;
use vm_topology::processor::TopologyBuilder;
use vm_topology::processor::x86::X2ApicState;
use vmcore::vmtime::{VmTime, VmTimeKeeper};

const CODE: u64 = 0x10000;
const DEVICE: u64 = 0x20000;
const VALUE: u64 = 0xfedc_ba98_7654_3210;

struct Devices {
    released: AtomicBool,
    wait: AtomicWaker,
    writes: AtomicUsize,
    writes_done: AtomicUsize,
    reads: AtomicUsize,
    value: AtomicU64,
    faults: Mutex<Vec<String>>,
}

impl Devices {
    fn new() -> Self {
        Self {
            released: AtomicBool::new(false),
            wait: AtomicWaker::new(),
            writes: AtomicUsize::new(0),
            writes_done: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            value: AtomicU64::new(0),
            faults: Mutex::new(Vec::new()),
        }
    }
    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.wait.wake();
    }
}

impl CpuIo for Devices {
    fn is_mmio(&self, address: u64) -> bool {
        (DEVICE..DEVICE + 8).contains(&address)
    }
    fn acknowledge_pic_interrupt(&self) -> Option<u8> {
        panic!("no PIC in this profile")
    }
    fn handle_eoi(&self, _irq: u32) {
        panic!("no EOI instruction in this profile")
    }
    async fn read_mmio(&self, _vp: VpIndex, address: u64, data: &mut [u8]) {
        assert_eq!(address, DEVICE);
        self.reads.fetch_add(1, Ordering::SeqCst);
        data.copy_from_slice(&VALUE.to_le_bytes());
    }
    async fn write_mmio(&self, _vp: VpIndex, address: u64, data: &[u8]) {
        assert_eq!(address, DEVICE);
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.value.store(
            u64::from_le_bytes(data.try_into().unwrap()),
            Ordering::SeqCst,
        );
        std::future::poll_fn(|cx| {
            self.wait.register(cx.waker());
            if self.released.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        self.writes_done.fetch_add(1, Ordering::SeqCst);
    }
    async fn read_io(&self, _vp: VpIndex, _port: u16, _data: &mut [u8]) {
        panic!("unexpected PIO")
    }
    async fn write_io(&self, _vp: VpIndex, _port: u16, _data: &[u8]) {
        panic!("unexpected PIO")
    }
    fn fatal_error(&self, error: Box<dyn std::error::Error + Send + Sync>) -> VpHaltReason {
        self.faults.lock().push(error.to_string());
        VpHaltReason::PowerOff
    }
}

#[derive(Default)]
struct Wakes(AtomicUsize);
impl ArcWake for Wakes {
    fn wake_by_ref(this: &Arc<Self>) {
        this.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn park<F: Future>(mut future: Pin<&mut F>) {
    let wakes = Arc::new(Wakes::default());
    let wake = waker(wakes.clone());
    let mut cx = Context::from_waker(&wake);
    for _ in 0..4096 {
        let before = wakes.0.load(Ordering::SeqCst);
        assert!(future.as_mut().poll(&mut cx).is_pending());
        if wakes.0.load(Ordering::SeqCst) == before {
            return;
        }
    }
    panic!("VP never reached a non-spinning asynchronous wait");
}

fn ready<F: Future>(future: Pin<&mut F>) -> F::Output {
    let wake = waker(Arc::new(Wakes::default()));
    match future.poll(&mut Context::from_waker(&wake)) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("VP did not stop at the required safe boundary"),
    }
}

fn ready_after_yields<F: Future>(mut future: Pin<&mut F>) -> F::Output {
    let wake = waker(Arc::new(Wakes::default()));
    let mut context = Context::from_waker(&wake);
    for _ in 0..4096 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
    }
    panic!("RAM-only execution did not reach its host checkpoint");
}

async fn build(
    driver: &DefaultDriver,
    bytes: &[u8],
) -> (EmuPartition, EmuProcessorBinder, GuestMemory, VmTimeKeeper) {
    let topology = TopologyBuilder::new_x86()
        .x2apic(X2ApicState::Unsupported)
        .build(1)
        .unwrap();
    let memory_layout = MemoryLayout::new(
        bytes.len() as u64,
        &[MemoryRange::new(DEVICE..DEVICE + 4096)],
        &[],
        &[],
        None,
    )
    .unwrap();
    let memory = GuestMemory::allocate(bytes.len());
    memory.write_at(0, bytes).unwrap();
    let keeper = VmTimeKeeper::new(driver, VmTime::from_100ns(0));
    let time = keeper.builder().build(driver).await.unwrap();
    let mut hv = EmuHypervisor;
    let proto = hv
        .new_partition(ProtoPartitionConfig {
            processor_topology: &topology,
            hv_config: None,
            vmtime: &time,
            isolation: ProtoPartitionIsolation::None,
            nested_virt: false,
        })
        .unwrap();
    assert_eq!(proto.max_physical_address_size(), 48);
    let (partition, mut binders) = proto
        .build(PartitionConfig {
            mem_layout: &memory_layout,
            guest_memory: &memory,
            cpuid: &[],
            vtl0_alias_map: None,
            fault_resolver: None,
        })
        .unwrap();
    assert_eq!(binders.len(), 1);
    (partition, binders.pop().unwrap(), memory, keeper)
}

#[async_test]
async fn descriptor_entry_updates_real_vp_state_and_preserves_store_neighbors(
    driver: DefaultDriver,
) {
    let (mut bytes, owned) = fixture();
    let program = [
        0x48, 0x83, 0xec, 0x10, 0x66, 0xc7, 0x44, 0x24, 6, 0x1f, 0, 0x48, 0x89, 0x44, 0x24, 8,
        0x0f, 0x01, 0x54, 0x24, 6, 0xb8, 0x18, 0, 0, 0, 0x8e, 0xd8, 0x8e, 0xd0, 0x8e, 0xc0, 0x48,
        0x83, 0xc4, 0x10, 0xf4,
    ];
    bytes[CODE as usize..CODE as usize + program.len()].copy_from_slice(&program);
    bytes[0x9018..0x9020].copy_from_slice(&0x00cf93000000ffffu64.to_le_bytes());
    bytes[0x18008..0x18010].copy_from_slice(&0x1122334455667788u64.to_le_bytes());
    let (_, mut binder, memory, _keeper) = build(&driver, &bytes).await;
    let mut vp = binder.bind().unwrap();
    let mut initial = long_mode_registers(
        owned.core.cpu,
        super::shared_mmu_tests::config(),
        owned.tables,
        77,
    );
    initial.rax = 0x9000;
    initial.rsp = 0x18018;
    vp.access_state(Vtl::Vtl0).set_registers(&initial).unwrap();
    let devices = Devices::new();
    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    park(run.as_mut());
    stop.stop();
    assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
    drop(run);
    let mut expected = initial;
    expected.rax = 0x18;
    expected.gdtr.limit = 0x1f;
    expected.ds.selector = 0x18;
    expected.ss.selector = 0x18;
    expected.es.selector = 0x18;
    expected.rip = CODE + program.len() as u64;
    expected.rflags = (initial.rflags & !0x108d5) | 4;
    assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
    assert_eq!(
        memory.read_plain::<u64>(0x18008).unwrap(),
        0x001f334455667788
    );
    assert_eq!(memory.read_plain::<u64>(0x18010).unwrap(), 0x9000);
    let progress = vp.completed_batch_progress();
    assert_eq!((progress.retired, progress.delivered), (10, 0));
    assert!(devices.faults.lock().is_empty());
}

#[async_test]
async fn loaded_nondefault_ss_iret_restores_the_actual_frame_and_segment_state(
    driver: DefaultDriver,
) {
    let (mut bytes, mut owned) = fixture();
    let program = [0xb8, 0x18, 0, 0, 0, 0x8e, 0xd0, 0x48, 0xcf, 0xf4];
    bytes[CODE as usize..CODE as usize + program.len()].copy_from_slice(&program);
    bytes[0x9018..0x9020].copy_from_slice(&0x00cf93000000ffffu64.to_le_bytes());
    owned.tables.gdt_limit = 31;
    let (_, mut binder, memory, _keeper) = build(&driver, &bytes).await;
    let mut vp = binder.bind().unwrap();
    let initial = long_mode_registers(
        owned.core.cpu,
        super::shared_mmu_tests::config(),
        owned.tables,
        77,
    );
    for (index, value) in [CODE + 9, 8, initial.rflags, 0x18040, 0x18]
        .into_iter()
        .enumerate()
    {
        memory
            .write_plain(initial.rsp + index as u64 * 8, &value)
            .unwrap();
    }
    vp.access_state(Vtl::Vtl0).set_registers(&initial).unwrap();
    let devices = Devices::new();
    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    park(run.as_mut());
    stop.stop();
    assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
    drop(run);
    let mut expected = initial;
    expected.rax = 0x18;
    expected.ss.selector = 0x18;
    expected.rip = CODE + 10;
    expected.rsp = 0x18040;
    expected.rflags &= !0x10000;
    assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
    let progress = vp.completed_batch_progress();
    assert_eq!((progress.retired, progress.delivered), (4, 0));
    assert!(devices.faults.lock().is_empty());
}

#[async_test]
async fn bootdata_string_and_conditional_families_use_actual_vp_state(driver: DefaultDriver) {
    for supported_msr in [true, false] {
        let (mut bytes, owned) = fixture();
        let data = 0x16000u64;
        let mut program = vec![0xfc, 0xb9, 3, 0, 0, 0, 0x48, 0xbe];
        program.extend(data.to_le_bytes());
        program.extend([0x48, 0xbf]);
        program.extend((data + 8).to_le_bytes());
        program.extend([0xf3, 0x48, 0xa5, 0x31, 0xc0, 0x0f, 0x45, 0xda]);
        program.extend([0x0f, 0x45, 0x1c, 0x25]);
        program.extend((data as u32).to_le_bytes());
        program.extend([0x0f, 0x95, 0x04, 0x25]);
        program.extend(((data + 0x40) as u32).to_le_bytes());
        program.extend([0x41, 0x0f, 0x20, 0xd0, 0xb9]);
        program.extend((if supported_msr { 0x8bu32 } else { 0x8c }).to_le_bytes());
        let msr_rip = CODE + program.len() as u64;
        program.extend([0x0f, 0x32, 0xf4]);
        bytes[CODE as usize..CODE as usize + program.len()].copy_from_slice(&program);
        bytes[data as usize..data as usize + 8]
            .copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        bytes[data as usize + 0x40..data as usize + 0x48].fill(0xff);
        let (_, mut binder, memory, _keeper) = build(&driver, &bytes).await;
        let mut vp = binder.bind().unwrap();
        let mut initial = long_mode_registers(
            owned.core.cpu,
            super::shared_mmu_tests::config(),
            owned.tables,
            77,
        );
        initial.rflags = (initial.rflags & !0x200) | 0x400;
        initial.rbx = 0xaaaa_bbbb_cccc_dddd;
        initial.rdx = 0x1234_5678;
        vp.access_state(Vtl::Vtl0).set_registers(&initial).unwrap();
        let devices = Devices::new();
        let stop = StopVpSource::new();
        if supported_msr {
            let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
            park(run.as_mut());
            stop.stop();
            assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
            drop(run);
            assert!(devices.faults.lock().is_empty());
        } else {
            assert!(matches!(
                vp.run_vp(stop.checker(), &devices).await,
                Err(VpHaltReason::PowerOff)
            ));
            assert_eq!(devices.faults.lock().len(), 1);
            assert!(devices.faults.lock()[0].contains("Unsupported"));
        }
        let mut expected = initial;
        expected.rax = 0;
        expected.rbx = 0xcccc_dddd;
        expected.rcx = if supported_msr { 0x8b } else { 0x8c };
        expected.rdx = if supported_msr { 0 } else { initial.rdx };
        expected.rsi = data + 24;
        expected.rdi = data + 32;
        expected.r8 = 77;
        expected.rflags = (initial.rflags & !0x10cd5) | 0x44;
        expected.rip = if supported_msr {
            CODE + program.len() as u64
        } else {
            msr_rip
        };
        assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
        for offset in [0, 8, 16, 24] {
            assert_eq!(
                memory.read_plain::<u64>(data + offset).unwrap(),
                0x1122_3344_5566_7788
            );
        }
        assert_eq!(
            memory.read_plain::<u64>(data + 0x40).unwrap(),
            0xffff_ffff_ffff_ff00
        );
        let progress = vp.completed_batch_progress();
        assert_eq!(
            (progress.retired, progress.delivered),
            (if supported_msr { 13 } else { 11 }, 0)
        );
    }
}

#[async_test]
async fn locked_compare_exchange_uses_actual_vp_state_and_atomic_ram(driver: DefaultDriver) {
    for (matched, flags) in [(true, 0x46), (false, 0x97)] {
        let (mut bytes, owned) = fixture();
        let program = [0xf0, 0x48, 0x0f, 0xb1, 0x55, 0, 0xf4];
        bytes[CODE as usize..CODE as usize + program.len()].copy_from_slice(&program);
        bytes[0x16000..0x16008]
            .copy_from_slice(&(if matched { 0x11u64 } else { 0x33 }).to_le_bytes());
        let (_, mut binder, memory, _keeper) = build(&driver, &bytes).await;
        let mut vp = binder.bind().unwrap();
        let mut initial = long_mode_registers(
            owned.core.cpu,
            super::shared_mmu_tests::config(),
            owned.tables,
            77,
        );
        initial.rax = 0x11;
        initial.rdx = 0x22;
        initial.rbp = 0x16000;
        vp.access_state(Vtl::Vtl0).set_registers(&initial).unwrap();
        vp.set_execution_checkpoint(Some(CODE + 6)).unwrap();
        let devices = Devices::new();
        let stop = StopVpSource::new();
        assert!(matches!(
            vp.run_vp(stop.checker(), &devices).await,
            Err(VpHaltReason::PowerOff)
        ));
        assert_eq!(devices.faults.lock().len(), 1);
        assert!(devices.faults.lock()[0].contains("checkpoint"));
        let mut expected = initial;
        expected.rip = CODE + 6;
        expected.rflags = (initial.rflags & !0x108d5) | flags;
        if !matched {
            expected.rax = 0x33;
        }
        assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
        assert_eq!(
            memory.read_plain::<u64>(0x16000).unwrap(),
            if matched { 0x22 } else { 0x33 }
        );
        let progress = vp.completed_batch_progress();
        assert_eq!((progress.retired, progress.delivered), (1, 0));
    }
}

#[async_test]
async fn locked_integer_modify_preserves_neighbor_bits_and_carry_through_the_real_vp(
    driver: DefaultDriver,
) {
    let (mut bytes, owned) = fixture();
    let program = [0xf0, 0xff, 0x43, 0x58, 0xf4];
    bytes[CODE as usize..CODE as usize + program.len()].copy_from_slice(&program);
    bytes[0x16000..0x16008].copy_from_slice(&0xaabb_ccdd_ffff_ffffu64.to_le_bytes());
    let (_, mut binder, memory, _keeper) = build(&driver, &bytes).await;
    let mut vp = binder.bind().unwrap();
    let mut initial = long_mode_registers(
        owned.core.cpu,
        super::shared_mmu_tests::config(),
        owned.tables,
        77,
    );
    initial.rbx = 0x16000 - 0x58;
    initial.rflags |= 1;
    vp.access_state(Vtl::Vtl0).set_registers(&initial).unwrap();
    vp.set_execution_checkpoint(Some(CODE + 4)).unwrap();
    let devices = Devices::new();
    let stop = StopVpSource::new();
    assert!(matches!(
        vp.run_vp(stop.checker(), &devices).await,
        Err(VpHaltReason::PowerOff)
    ));
    assert_eq!(devices.faults.lock().len(), 1);
    assert!(devices.faults.lock()[0].contains("checkpoint"));
    let mut expected = initial;
    expected.rip = CODE + 4;
    expected.rflags = (initial.rflags & !0x108d5) | 0x57;
    assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
    assert_eq!(
        memory.read_plain::<u64>(0x16000).unwrap(),
        0xaabb_ccdd_0000_0000
    );
    let progress = vp.completed_batch_progress();
    assert_eq!((progress.retired, progress.delivered), (1, 0));
}

#[async_test]
async fn locked_bit_strings_use_signed_word_addresses_through_the_real_vp(driver: DefaultDriver) {
    for (opcode, operation) in [(0xab, 0), (0xb3, 1), (0xbb, 2)] {
        for index in [-65i64, -1, 0, 63, 64, 127] {
            let (mut bytes, owned) = fixture();
            let program = [0xf0, 0x48, 0x0f, opcode, 0x0b, 0xf4];
            bytes[CODE as usize..CODE as usize + program.len()].copy_from_slice(&program);
            let original = 0xa5a5_a5a5_a5a5_a5a5u64;
            bytes[0x16020..0x16060].fill(0xa5);
            let (_, mut binder, memory, _keeper) = build(&driver, &bytes).await;
            let mut vp = binder.bind().unwrap();
            let mut initial = long_mode_registers(
                owned.core.cpu,
                super::shared_mmu_tests::config(),
                owned.tables,
                77,
            );
            initial.rbx = 0x16040;
            initial.rcx = index as u64;
            vp.access_state(Vtl::Vtl0).set_registers(&initial).unwrap();
            vp.set_execution_checkpoint(Some(CODE + 5)).unwrap();
            let devices = Devices::new();
            let stop = StopVpSource::new();
            assert!(matches!(
                vp.run_vp(stop.checker(), &devices).await,
                Err(VpHaltReason::PowerOff)
            ));
            assert_eq!(devices.faults.lock().len(), 1);
            assert!(devices.faults.lock()[0].contains("checkpoint"));
            let target = (0x16040i64 + index.div_euclid(64) * 8) as u64;
            let bit = 1u64 << index.rem_euclid(64);
            let mut expected = initial;
            expected.rip = CODE + 5;
            expected.rflags = (initial.rflags & !0x10001) | u64::from(original & bit != 0);
            assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
            for address in (0x16020..0x16060).step_by(8) {
                let expected = if address != target {
                    original
                } else {
                    match operation {
                        0 => original | bit,
                        1 => original & !bit,
                        _ => original ^ bit,
                    }
                };
                assert_eq!(memory.read_plain::<u64>(address).unwrap(), expected);
            }
            let progress = vp.completed_batch_progress();
            assert_eq!((progress.retired, progress.delivered), (1, 0));
        }
    }
}

#[async_test]
async fn cpu_check_far_return_cpuid_and_flag_stack_use_actual_vp_state(driver: DefaultDriver) {
    for iret in [false, true] {
        let (mut bytes, owned) = fixture();
        let mut program = vec![
            0x6a, 0x10, 0x48, 0x8d, 0x05, 3, 0, 0, 0, 0x50, 0x48, 0xcb, 0x9c, 0x6a, 0, 0x9d, 0xb8,
            1, 0, 0, 0, 0x0f, 0xa2, 0x9d,
        ];
        if iret {
            program.extend([0x48, 0xcf]);
        } else {
            program.push(0xf4);
        }
        bytes[CODE as usize..CODE as usize + program.len()].copy_from_slice(&program);
        bytes[0x9010..0x9018].copy_from_slice(&0x00af9b000000ffffu64.to_le_bytes());
        let (_, mut binder, memory, _keeper) = build(&driver, &bytes).await;
        let mut vp = binder.bind().unwrap();
        let mut initial = long_mode_registers(
            owned.core.cpu,
            super::shared_mmu_tests::config(),
            owned.tables,
            77,
        );
        initial.rsp = 0x18018;
        vp.access_state(Vtl::Vtl0).set_registers(&initial).unwrap();
        let devices = Devices::new();
        let stop = StopVpSource::new();
        if iret {
            assert!(matches!(
                vp.run_vp(stop.checker(), &devices).await,
                Err(VpHaltReason::PowerOff)
            ));
            assert_eq!(devices.faults.lock().len(), 1);
            assert!(devices.faults.lock()[0].contains("ReturnImage"));
        } else {
            let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
            park(run.as_mut());
            stop.stop();
            assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
            drop(run);
            assert!(devices.faults.lock().is_empty());
        }
        let mut expected = initial;
        expected.rax = 0x00a00f11;
        expected.rbx = 0x10000;
        expected.rcx = 0;
        expected.rdx = 0x0780a179;
        expected.cs.selector = 16;
        expected.rip = CODE + if iret { 24 } else { 25 };
        expected.rflags &= !0x10000;
        assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
        assert_eq!(
            memory.read_plain::<u64>(0x18010).unwrap(),
            initial.rflags & !0x30000
        );
        assert_eq!(memory.read_plain::<u64>(0x18008).unwrap(), 0);
        let progress = vp.completed_batch_progress();
        assert_eq!(
            (progress.retired, progress.delivered),
            (if iret { 10 } else { 11 }, 0)
        );
    }
}

#[async_test]
async fn entry_forms_retire_through_real_vp_and_preserve_the_call_push(driver: DefaultDriver) {
    let (mut bytes, owned) = fixture();
    bytes[CODE as usize..CODE as usize + 11]
        .copy_from_slice(&[0x31, 0xc0, 0x31, 0xd2, 0x0f, 0x30, 0xe8, 5, 0, 0, 0]);
    bytes[CODE as usize + 16] = 0xf4;
    let (_, mut binder, memory, _keeper) = build(&driver, &bytes).await;
    let mut vp = binder.bind().unwrap();
    let mut initial = long_mode_registers(
        owned.core.cpu,
        super::shared_mmu_tests::config(),
        owned.tables,
        77,
    );
    initial.rcx = 0xc0000101;
    initial.rsp = 0x18008;
    initial.gs.base = 0x1234;
    vp.access_state(Vtl::Vtl0).set_registers(&initial).unwrap();
    let devices = Devices::new();
    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    park(run.as_mut());
    stop.stop();
    assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
    drop(run);
    let mut expected = initial;
    expected.rax = 0;
    expected.rdx = 0;
    expected.rsp = 0x18000;
    expected.rip = CODE + 17;
    expected.rflags = (initial.rflags & !0x108d5) | 0x44;
    expected.gs.base = 0;
    assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
    assert_eq!(memory.read_plain::<u64>(0x18000).unwrap(), CODE + 11);
    let progress = vp.completed_batch_progress();
    assert_eq!((progress.retired, progress.delivered), (5, 0));
    assert!(devices.faults.lock().is_empty());
}

#[async_test]
async fn loader_system_import_orders_roundtrip_and_lock_after_run(driver: DefaultDriver) {
    use virt::vp::{Mtrrs, Pat};
    use x86_system::memory_core::cpu_core::system::{DEFAULT_PAT, FIXED_WB};

    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let (mut bytes, owned) = fixture();
        bytes[CODE as usize] = 0xf4;
        let (_, mut binder, _memory, _keeper) = build(&driver, &bytes).await;
        let mut vp = binder.bind().unwrap();
        let mut regs = long_mode_registers(
            owned.core.cpu,
            super::shared_mmu_tests::config(),
            owned.tables,
            77,
        );
        regs.fs = regs.ds;
        regs.gs = regs.ds;
        regs.fs.base = 0xffff_8000_0000_1234;
        regs.gs.base = 0x1234;
        regs.tr = virt::x86::SegmentRegister {
            base: 0,
            limit: 0xffff,
            selector: 0,
            attributes: 0x8b,
        };
        regs.ldtr = virt::x86::SegmentRegister {
            attributes: 0x82,
            ..regs.tr
        };
        regs.efer |= 1;
        regs.cr0 &= !0x10;
        let pat = Pat { value: DEFAULT_PAT };
        let mut mtrrs = Mtrrs {
            msr_mtrr_def_type: 0xc00,
            ..Default::default()
        };
        mtrrs.fixed[..2].fill(FIXED_WB);
        for operation in order {
            let mut access = vp.access_state(Vtl::Vtl0);
            match operation {
                0 => access.set_registers(&regs).unwrap(),
                1 => access.set_pat(&pat).unwrap(),
                2 => access.set_mtrrs(&mtrrs).unwrap(),
                _ => unreachable!(),
            }
        }
        let mut expected = regs;
        expected.cr0 |= 0x10;
        assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
        assert_eq!(vp.access_state(Vtl::Vtl0).pat().unwrap(), pat);
        assert_eq!(vp.access_state(Vtl::Vtl0).mtrrs().unwrap(), mtrrs);
        assert!(vp.access_state(Vtl::Vtl2).set_mtrrs(&mtrrs).is_err());
        assert!(vp.access_state(Vtl::Vtl2).pat().is_err());
        assert!(
            vp.access_state(Vtl::Vtl0)
                .set_pat(&Pat { value: 0 })
                .is_err()
        );
        let mut bad_mtrrs = Mtrrs::default();
        bad_mtrrs.variable[15] = 1;
        assert!(vp.access_state(Vtl::Vtl0).set_mtrrs(&bad_mtrrs).is_err());
        assert_eq!(vp.access_state(Vtl::Vtl0).mtrrs().unwrap(), mtrrs);

        let devices = Devices::new();
        let stop = StopVpSource::new();
        let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
        park(run.as_mut());
        stop.stop();
        assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
        drop(run);
        expected.rip += 1;
        expected.rflags &= !0x10000;
        assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
        assert_eq!(vp.access_state(Vtl::Vtl0).mtrrs().unwrap(), mtrrs);
        assert_eq!(vp.access_state(Vtl::Vtl0).pat().unwrap(), pat);
        assert!(vp.access_state(Vtl::Vtl0).set_pat(&pat).is_err());
        assert!(vp.access_state(Vtl::Vtl0).set_mtrrs(&mtrrs).is_err());
        assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
        assert!(devices.faults.lock().is_empty());
    }
}

#[async_test]
async fn rejected_initial_system_import_keeps_staging_and_allows_corrected_image(
    driver: DefaultDriver,
) {
    use virt::vp::Mtrrs;
    use x86_system::memory_core::cpu_core::system::FIXED_WB;

    let (bytes, owned) = fixture();
    let (_, mut binder, _memory, _keeper) = build(&driver, &bytes).await;
    let mut vp = binder.bind().unwrap();
    let mut mtrrs = Mtrrs {
        msr_mtrr_def_type: 0xc00,
        ..Default::default()
    };
    mtrrs.fixed[..2].fill(FIXED_WB);
    vp.access_state(Vtl::Vtl0).set_mtrrs(&mtrrs).unwrap();
    let mut regs = long_mode_registers(
        owned.core.cpu,
        super::shared_mmu_tests::config(),
        owned.tables,
        77,
    );
    regs.gs.base = 0x8000_0000_0000;
    assert!(vp.access_state(Vtl::Vtl0).set_registers(&regs).is_err());
    assert!(vp.access_state(Vtl::Vtl0).registers().is_err());
    assert_eq!(vp.access_state(Vtl::Vtl0).mtrrs().unwrap(), mtrrs);
    regs.gs.base = 0xffff_8000_0000_0000;
    vp.access_state(Vtl::Vtl0).set_registers(&regs).unwrap();
    assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), regs);
    assert_eq!(vp.access_state(Vtl::Vtl0).mtrrs().unwrap(), mtrrs);
}

#[async_test]
async fn real_backend_guest_recovery_delayed_mmio_hlt_and_irq(driver: DefaultDriver) {
    let (mut bytes, mut oracle) = fixture();
    bytes[CODE as usize..CODE as usize + 11].copy_from_slice(&[
        0x48, 0x8b, 0x07, 0x48, 0x89, 0x03, 0x48, 0x8b, 0x13, 0xf4, 0xf4,
    ]);
    oracle.core.cpu.gpr[3] = DEVICE;
    let initial = long_mode_registers(
        oracle.core.cpu,
        super::shared_mmu_tests::config(),
        oracle.tables,
        oracle.core.mmu.cr2(),
    );
    let (partition, mut binder, memory, _keeper) = build(&driver, &bytes).await;
    let mut vp = binder.bind().unwrap();
    vp.access_state(Vtl::Vtl0).set_registers(&initial).unwrap();
    let devices = Devices::new();
    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    park(run.as_mut());
    assert_eq!(devices.writes.load(Ordering::SeqCst), 1);
    assert_eq!(devices.reads.load(Ordering::SeqCst), 0);
    assert_eq!(devices.writes_done.load(Ordering::SeqCst), 0);
    assert_eq!(
        memory.read_plain::<u64>(0x40d0).unwrap() & 1,
        1,
        "guest repaired its own PTE"
    );
    devices.release();
    park(run.as_mut());
    assert_eq!(devices.reads.load(Ordering::SeqCst), 1);
    partition.inject_selected(64).unwrap();
    park(run.as_mut());
    stop.stop();
    assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
    drop(run);

    let mut expected = bytes;
    expected.resize(0x21000, 0);
    let report = oracle.run(&mut expected, 0, 7);
    assert_eq!((report.retired, report.delivered), (6, 1));
    expected[DEVICE as usize..DEVICE as usize + 8].copy_from_slice(&VALUE.to_le_bytes());
    assert_eq!(oracle.run(&mut expected, 0, 2).retired, 2);
    assert_eq!(oracle.inject(64), x86_system::Injection::Queued);
    let report = oracle.run(&mut expected, 0, 4);
    assert_eq!((report.retired, report.delivered), (3, 1));
    let actual = vp.access_state(Vtl::Vtl0).registers().unwrap();
    assert_eq!(
        actual,
        long_mode_registers(
            oracle.core.cpu,
            super::shared_mmu_tests::config(),
            oracle.tables,
            oracle.core.mmu.cr2()
        )
    );
    assert_eq!(
        (actual.rip, actual.rsp, actual.r10, actual.rdx),
        (CODE + 11, initial.rsp, 1, VALUE)
    );
    let mut actual_bytes = vec![0; 0x20000];
    memory.read_at(0, &mut actual_bytes).unwrap();
    assert_eq!(actual_bytes, expected[..0x20000]);
    assert_eq!(devices.writes.load(Ordering::SeqCst), 1);
    assert_eq!(devices.writes_done.load(Ordering::SeqCst), 1);
    assert_eq!(devices.value.load(Ordering::SeqCst), 0x1234_5678_89ab_cdef);
    assert!(devices.faults.lock().is_empty());
}

#[async_test]
async fn backend_stop_during_device_completion_resumes_without_reissue(driver: DefaultDriver) {
    let (mut bytes, owned) = fixture();
    bytes[CODE as usize..CODE as usize + 4].copy_from_slice(&[0x48, 0x89, 0x07, 0xf4]);
    let mut cpu = owned.core.cpu;
    cpu.gpr[7] = DEVICE;
    cpu.gpr[0] = 0xabcdef;
    let (_, mut binder, _memory, _keeper) = build(&driver, &bytes).await;
    let mut vp = binder.bind().unwrap();
    let regs = long_mode_registers(cpu, super::shared_mmu_tests::config(), owned.tables, 77);
    vp.access_state(Vtl::Vtl0).set_registers(&regs).unwrap();
    let devices = Devices::new();
    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    park(run.as_mut());
    stop.stop();
    park(run.as_mut());
    assert_eq!(devices.writes_done.load(Ordering::SeqCst), 0);
    devices.release();
    assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
    drop(run);
    assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), regs);

    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    park(run.as_mut());
    stop.stop();
    assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
    drop(run);
    assert_eq!(
        vp.access_state(Vtl::Vtl0).registers().unwrap().rip,
        CODE + 4
    );
    assert_eq!(devices.writes.load(Ordering::SeqCst), 1);
    assert_eq!(devices.writes_done.load(Ordering::SeqCst), 1);
    assert!(devices.faults.lock().is_empty());
}

#[async_test]
async fn decoded_backend_scalar_widths_recovery_mmio_and_irq_match_full_oracle(
    driver: DefaultDriver,
) {
    let (mut bytes, mut oracle) = fixture();
    let prefix = [
        0x49, 0x89, 0xf7, 0x4c, 0x8d, 0x35, 0, 0, 0, 0, 0xba, 0x01, 0x01, 0, 0xc0, 0x41, 0xb4,
        0x56, 0x66, 0x41, 0xbd, 0x9a, 0x78,
    ];
    let ordinary = [
        0x48, 0x8b, 0x07, 0x48, 0x89, 0x03, 0x48, 0x8b, 0x13, 0xf4, 0xf4,
    ];
    bytes[CODE as usize..CODE as usize + prefix.len()].copy_from_slice(&prefix);
    bytes[CODE as usize + prefix.len()..CODE as usize + prefix.len() + ordinary.len()]
        .copy_from_slice(&ordinary);
    oracle.core.cpu.gpr[3] = DEVICE;
    oracle.core.cpu.gpr[2] = u64::MAX;
    oracle.core.cpu.gpr[12] = 0x1122334455667788;
    oracle.core.cpu.gpr[13] = 0x99aabbccddeeff00;
    oracle.core.cpu.flags |= 0x10000;
    let initial = long_mode_registers(
        oracle.core.cpu,
        super::shared_mmu_tests::config(),
        oracle.tables,
        oracle.core.mmu.cr2(),
    );
    let (partition, mut binder, memory, _keeper) = build(&driver, &bytes).await;
    let mut vp = binder.bind().unwrap();
    vp.access_state(Vtl::Vtl0).set_registers(&initial).unwrap();
    let devices = Devices::new();
    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    park(run.as_mut());
    assert_eq!(devices.writes.load(Ordering::SeqCst), 1);
    assert_eq!(devices.reads.load(Ordering::SeqCst), 0);
    stop.stop();
    devices.release();
    assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
    drop(run);
    let suspended = vp.access_state(Vtl::Vtl0).registers().unwrap();
    assert_eq!(suspended.rdx, 0xc0000101);
    assert_eq!(suspended.r12, 0x1122334455667756);
    assert_eq!(suspended.r13, 0x99aabbccddee789a);
    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    park(run.as_mut());
    partition.inject_selected(64).unwrap();
    park(run.as_mut());
    stop.stop();
    assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
    drop(run);

    oracle.core.cpu.gpr[15] = initial.rsi;
    oracle.core.cpu.gpr[14] = CODE + 10;
    oracle.core.cpu.gpr[2] = 0xc0000101;
    oracle.core.cpu.gpr[12] = 0x1122334455667756;
    oracle.core.cpu.gpr[13] = 0x99aabbccddee789a;
    oracle.core.cpu.rip += prefix.len() as u64;
    oracle.core.cpu.flags &= !0x10000;
    let mut expected = bytes;
    expected.resize(0x21000, 0);
    let report = oracle.run(&mut expected, 0, 7);
    assert_eq!((report.retired, report.delivered), (6, 1));
    expected[DEVICE as usize..DEVICE as usize + 8].copy_from_slice(&VALUE.to_le_bytes());
    assert_eq!(oracle.run(&mut expected, 0, 2).retired, 2);
    assert_eq!(oracle.inject(64), x86_system::Injection::Queued);
    let report = oracle.run(&mut expected, 0, 4);
    assert_eq!((report.retired, report.delivered), (3, 1));
    let actual = vp.access_state(Vtl::Vtl0).registers().unwrap();
    assert_eq!(
        actual,
        long_mode_registers(
            oracle.core.cpu,
            super::shared_mmu_tests::config(),
            oracle.tables,
            oracle.core.mmu.cr2()
        )
    );
    assert_eq!(actual.r12, 0x1122334455667756);
    assert_eq!(actual.r13, 0x99aabbccddee789a);
    let mut actual_bytes = vec![0; 0x20000];
    memory.read_at(0, &mut actual_bytes).unwrap();
    assert_eq!(actual_bytes, expected[..0x20000]);
    assert_eq!(devices.writes.load(Ordering::SeqCst), 1);
    assert_eq!(devices.writes_done.load(Ordering::SeqCst), 1);
    assert_eq!(devices.reads.load(Ordering::SeqCst), 1);
    assert!(devices.faults.lock().is_empty());
}

#[async_test]
async fn mapping_families_reload_cr3_and_fetch_high_va_through_the_real_vp(driver: DefaultDriver) {
    let (mut bytes, owned) = fixture();
    let tables = bytes[0x1000..0x5000].to_vec();
    bytes[0x5000..0x9000].copy_from_slice(&tables);
    for (address, value) in [
        (0x5000, 0x6007u64),
        (0x6000, 0x7007),
        (0x7000, 0x8007),
        (0x5800, 0x6007),
        (0x80b0, 0x17007),
        (0x16000, 0x1122_3344_ffff_ffff),
        (0x17000, 0x5566_7788_ffff_fff9),
    ] {
        bytes[address..address + 8].copy_from_slice(&value.to_le_bytes());
    }
    let prefix = [
        0x83, 0x07, 0x01, 0x9c, 0x41, 0x58, 0x8b, 0x07, 0x0f, 0x22, 0xde, 0x8b, 0x07, 0x99, 0xb9,
        0x03, 0, 0, 0, 0xf7, 0xf9, 0xff, 0xe3,
    ];
    let suffix = [0xd3, 0xfa, 0xf4];
    bytes[CODE as usize..CODE as usize + prefix.len()].copy_from_slice(&prefix);
    bytes[CODE as usize + prefix.len()..CODE as usize + prefix.len() + suffix.len()]
        .copy_from_slice(&suffix);
    let target = 0xffff_8000_0000_0000 | (CODE + prefix.len() as u64);
    let mut cpu = owned.core.cpu;
    cpu.flags = 2;
    cpu.gpr[4] = 0x18000;
    cpu.gpr[6] = 0x5000;
    cpu.gpr[7] = 0x16000;
    cpu.gpr[3] = target;
    let config = super::shared_mmu_tests::config();
    let initial = long_mode_registers(cpu, config, owned.tables, owned.core.mmu.cr2());
    let (_, mut binder, memory, _keeper) = build(&driver, &bytes).await;
    let mut vp = binder.bind().unwrap();
    vp.access_state(Vtl::Vtl0).set_registers(&initial).unwrap();
    let devices = Devices::new();
    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    park(run.as_mut());
    stop.stop();
    assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
    drop(run);
    let mut expected = initial;
    expected.rax = 0xffff_fffe;
    expected.rdx = 0xffff_ffff;
    expected.rcx = 3;
    expected.r8 = 0x57;
    expected.rip = target + suffix.len() as u64;
    expected.rflags = 0x87;
    expected.cr3 = 0x5000;
    assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
    let progress = vp.completed_batch_progress();
    assert_eq!((progress.retired, progress.delivered), (12, 0));
    assert!(devices.faults.lock().is_empty());
    for (address, bits) in [
        (0x1000, 0x20u64),
        (0x2000, 0x20),
        (0x3000, 0x20),
        (0x4080, 0x20),
        (0x40b0, 0x60),
        (0x40b8, 0x60),
        (0x5000, 0x20),
        (0x5800, 0x20),
        (0x6000, 0x20),
        (0x7000, 0x20),
        (0x8080, 0x20),
        (0x80b0, 0x20),
    ] {
        let word = u64::from_le_bytes(bytes[address..address + 8].try_into().unwrap()) | bits;
        bytes[address..address + 8].copy_from_slice(&word.to_le_bytes());
    }
    bytes[0x16000..0x16008].copy_from_slice(&0x1122_3344_0000_0000u64.to_le_bytes());
    bytes[0x17ff8..0x18000].copy_from_slice(&0x57u64.to_le_bytes());
    let mut actual = vec![0; bytes.len()];
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(
        actual, bytes,
        "complete RAM image, including old and new A/D effects"
    );
}

#[async_test]
async fn bootstrap_control_and_null_segments_use_the_actual_vp_image(driver: DefaultDriver) {
    let (mut bytes, owned) = fixture();
    let program = [
        0xb8, 0x01, 0x0d, 0, 0, 0x31, 0xd2, 0xb9, 0x80, 0, 0, 0xc0, 0x0f, 0x30, 0x0f, 0x32, 0xb8,
        0xb0, 0, 0, 0, 0x0f, 0x22, 0xe0, 0xb8, 0x33, 0, 0x05, 0x80, 0x0f, 0x22, 0xc0, 0x31, 0xc0,
        0x8e, 0xd8, 0x8e, 0xd0, 0x8e, 0xc0, 0x8e, 0xe0, 0x8e, 0xe8, 0xf4,
    ];
    bytes[CODE as usize..CODE as usize + program.len()].copy_from_slice(&program);
    let mut cpu = owned.core.cpu;
    cpu.flags = 2;
    cpu.gpr[4] = 0x18000;
    let mut config = super::shared_mmu_tests::config();
    config.nxe = false;
    let initial = long_mode_registers(cpu, config, owned.tables, owned.core.mmu.cr2());
    let (_, mut binder, memory, _keeper) = build(&driver, &bytes).await;
    let mut vp = binder.bind().unwrap();
    vp.access_state(Vtl::Vtl0).set_registers(&initial).unwrap();
    let devices = Devices::new();
    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    park(run.as_mut());
    stop.stop();
    assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
    drop(run);
    let mut expected = initial;
    expected.rax = 0;
    expected.rdx = 0;
    expected.rcx = 0xc0000080;
    expected.rflags = 0x46;
    expected.cr0 = 0x80050033;
    expected.cr4 = 0xb0;
    expected.efer = 0xd01;
    expected.rip = CODE + program.len() as u64;
    expected.ds = Default::default();
    expected.ss = Default::default();
    expected.es = Default::default();
    expected.fs = Default::default();
    expected.gs = Default::default();
    assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
    assert_eq!(vp.completed_batch_progress().retired, 16);
    assert!(devices.faults.lock().is_empty());
    for address in [0x1000, 0x2000, 0x3000, 0x4080] {
        let word = u64::from_le_bytes(bytes[address..address + 8].try_into().unwrap()) | 0x20;
        bytes[address..address + 8].copy_from_slice(&word.to_le_bytes());
    }
    let mut actual = vec![0; bytes.len()];
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, bytes);
}

#[async_test]
async fn host_checkpoint_stops_after_complete_rep_and_can_resume_without_guest_changes(
    driver: DefaultDriver,
) {
    let (mut bytes, owned) = fixture();
    let program = [0xb9, 3, 0, 0, 0, 0xf3, 0x48, 0xab, 0xb8, 1, 0, 0, 0, 0xf4];
    bytes[CODE as usize..CODE as usize + program.len()].copy_from_slice(&program);
    for index in 0..4 {
        bytes[0x16000 + index * 8..0x16008 + index * 8]
            .copy_from_slice(&(index as u64 + 1).to_le_bytes());
    }
    let mut cpu = owned.core.cpu;
    cpu.flags = 2;
    cpu.gpr[0] = 0;
    cpu.gpr[7] = 0x16000;
    cpu.gpr[4] = 0x18000;
    let initial = long_mode_registers(
        cpu,
        super::shared_mmu_tests::config(),
        owned.tables,
        owned.core.mmu.cr2(),
    );
    let (_, mut binder, memory, _keeper) = build(&driver, &bytes).await;
    let mut vp = binder.bind().unwrap();
    vp.access_state(Vtl::Vtl0).set_registers(&initial).unwrap();
    let checkpoint = CODE + 8;
    vp.set_execution_checkpoint(Some(checkpoint)).unwrap();
    assert!(vp.set_execution_checkpoint(Some(0x8000_0000_0000)).is_err());
    let devices = Devices::new();
    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    assert!(matches!(
        ready_after_yields(run.as_mut()),
        Err(VpHaltReason::PowerOff)
    ));
    drop(run);
    assert_eq!(
        &*devices.faults.lock(),
        &[format!("host execution checkpoint at {checkpoint:#x}")]
    );
    let mut expected = initial;
    expected.rcx = 0;
    expected.rdi = 0x16018;
    expected.rip = checkpoint;
    assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
    assert_eq!(
        vp.completed_batch_progress().retired,
        2,
        "REP is one retired instruction, not three"
    );
    for address in [0x16000, 0x16008, 0x16010] {
        assert_eq!(memory.read_plain::<u64>(address).unwrap(), 0);
    }
    assert_eq!(memory.read_plain::<u64>(0x16018).unwrap(), 4);
    let mut before_resume = vec![0; bytes.len()];
    memory.read_at(0, &mut before_resume).unwrap();
    vp.set_execution_checkpoint(None).unwrap();
    devices.faults.lock().clear();
    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    park(run.as_mut());
    stop.stop();
    assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
    drop(run);
    expected.rax = 1;
    expected.rip = CODE + program.len() as u64;
    assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), expected);
    assert_eq!(vp.completed_batch_progress().retired, 4);
    let mut after = vec![0; bytes.len()];
    memory.read_at(0, &mut after).unwrap();
    assert_eq!(
        after, before_resume,
        "checkpoint or resume changed RAM beyond the guest's stores"
    );
    assert!(devices.faults.lock().is_empty());
}

#[async_test]
async fn backend_cancelled_device_future_is_explicitly_fatal_not_replayed(driver: DefaultDriver) {
    let (mut bytes, owned) = fixture();
    bytes[CODE as usize..CODE as usize + 3].copy_from_slice(&[0x48, 0x89, 0x07]);
    let mut cpu = owned.core.cpu;
    cpu.gpr[7] = DEVICE;
    let (_, mut binder, _memory, _keeper) = build(&driver, &bytes).await;
    let mut vp = binder.bind().unwrap();
    vp.access_state(Vtl::Vtl0)
        .set_registers(&long_mode_registers(
            cpu,
            super::shared_mmu_tests::config(),
            owned.tables,
            77,
        ))
        .unwrap();
    let devices = Devices::new();
    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    park(run.as_mut());
    drop(run);
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    let wake = waker(Arc::new(Wakes::default()));
    assert!(matches!(
        run.as_mut().poll(&mut Context::from_waker(&wake)),
        Poll::Ready(Err(VpHaltReason::PowerOff))
    ));
    drop(run);
    assert_eq!(devices.writes.load(Ordering::SeqCst), 1);
    assert_eq!(devices.writes_done.load(Ordering::SeqCst), 0);
    assert!(devices.faults.lock()[0].contains("replay is unsafe"));
    assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap().rip, CODE);
}

#[async_test]
async fn backend_state_profile_and_requested_yield_preserve_cpu(driver: DefaultDriver) {
    let (mut bytes, owned) = fixture();
    bytes[CODE as usize] = 0xf4;
    let (partition, mut binder, _memory, _keeper) = build(&driver, &bytes).await;
    let mut vp = binder.bind().unwrap();
    let regs = long_mode_registers(
        owned.core.cpu,
        super::shared_mmu_tests::config(),
        owned.tables,
        77,
    );
    let mut invalid = regs;
    invalid.cr4 = 0;
    assert!(vp.access_state(Vtl::Vtl0).set_registers(&invalid).is_err());
    assert!(vp.access_state(Vtl::Vtl0).registers().is_err());
    vp.access_state(Vtl::Vtl0).set_registers(&regs).unwrap();
    assert!(vp.access_state(Vtl::Vtl0).set_registers(&regs).is_err());
    assert!(vp.access_state(Vtl::Vtl2).registers().is_err());
    assert!(vp.access_state(Vtl::Vtl0).apic().is_err());
    assert!(vp.reset().is_err());
    assert!(vp.scrub(Vtl::Vtl0).is_err());
    assert!(partition.inject_selected(31).is_err());
    partition.request_yield(VpIndex::new(0));
    let devices = Devices::new();
    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    let wake = waker(Arc::new(Wakes::default()));
    assert!(
        run.as_mut()
            .poll(&mut Context::from_waker(&wake))
            .is_pending()
    );
    stop.stop();
    assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
    drop(run);
    assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), regs);
    assert!(devices.faults.lock().is_empty());

    let (mut bytes, owned) = fixture();
    let code = [0xba, 0x01, 0x01, 0, 0xc0].repeat(128);
    bytes[CODE as usize..CODE as usize + code.len()].copy_from_slice(&code);
    bytes[CODE as usize + code.len()] = 0xf4;
    let (_, mut binder, _memory, _keeper) = build(&driver, &bytes).await;
    let mut vp = binder.bind().unwrap();
    vp.access_state(Vtl::Vtl0)
        .set_registers(&long_mode_registers(
            owned.core.cpu,
            super::shared_mmu_tests::config(),
            owned.tables,
            77,
        ))
        .unwrap();
    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    assert!(
        run.as_mut()
            .poll(&mut Context::from_waker(&wake))
            .is_pending()
    );
    stop.stop();
    assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
    drop(run);
    let partial = vp.access_state(Vtl::Vtl0).registers().unwrap();
    assert_eq!(
        partial.rip,
        CODE + 12 * 5,
        "decode work must yield before HLT"
    );
    assert_eq!(partial.rdx, 0xc0000101);

    let stop = StopVpSource::new();
    let mut run = Box::pin(vp.run_vp(stop.checker(), &devices));
    park(run.as_mut());
    stop.stop();
    assert!(matches!(ready(run.as_mut()), Err(VpHaltReason::Stop(_))));
    drop(run);
    assert_eq!(
        vp.access_state(Vtl::Vtl0).registers().unwrap().rip,
        CODE + code.len() as u64 + 1
    );
    assert!(devices.faults.lock().is_empty());
}
