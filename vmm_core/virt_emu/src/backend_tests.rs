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
