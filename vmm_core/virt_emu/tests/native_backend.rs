// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Real-VP direct mappings are independent of GuestMemory access permissions.

// xtask-fmt allow-target-arch cpu-intrinsic -- Exercises the host x86 RAM provider.
#![cfg(all(guest_arch = "x86_64", target_arch = "x86_64"))]

use guestmem::{
    AlignedHeapMemory, BitmapInfo, GuestMemory, GuestMemoryAccess, PageFaultAction, PageFaultError,
};
use hvdef::Vtl;
use memory_range::MemoryRange;
use pal_async::{DefaultDriver, async_test};
use parking_lot::Mutex;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use virt::io::CpuIo;
use virt::vp::AccessVpState;
use virt::{
    BindProcessor, PartitionConfig, PartitionMemoryMap, Processor, ProtoPartition,
    ProtoPartitionConfig, ProtoPartitionIsolation, StopVpSource, VpHaltReason, VpIndex,
};
use virt_emu::backend::{EmuHypervisor, EmuPartition, long_mode_registers};
use vm_topology::memory::MemoryLayout;
use vm_topology::processor::TopologyBuilder;
use vm_topology::processor::x86::X2ApicState;
use vmcore::vmtime::{VmTime, VmTimeKeeper};
use x86_system::{Config, State, Tables};

const SIZE: usize = 0x10000;
const CODE: u64 = 0x6000;
const DATA: u64 = 0x8000;

struct CpuOnlyBacking {
    memory: AlignedHeapMemory,
    read_bitmap: [u8; 2],
    write_bitmap: [u8; 2],
    guest_memory_faults: AtomicUsize,
}

// SAFETY: the aligned allocation and both bitmaps remain valid and stable for
// the backing's lifetime. All mapped pages are committed. The immutable bitmap
// denies GuestMemory reads and writes independently of the CPU mapping.
// UNSAFETY: Exposes stable mapping pointers for this transport regression.
#[expect(unsafe_code)]
unsafe impl GuestMemoryAccess for CpuOnlyBacking {
    fn mapping(&self) -> Option<NonNull<u8>> {
        self.memory.mapping()
    }

    fn max_address(&self) -> u64 {
        SIZE as u64
    }

    fn access_bitmap(&self) -> Option<BitmapInfo> {
        Some(BitmapInfo {
            read_bitmap: NonNull::from(&self.read_bitmap[0]),
            write_bitmap: NonNull::from(&self.write_bitmap[0]),
            bit_offset: 0,
        })
    }

    fn page_fault(
        &self,
        _address: u64,
        _len: usize,
        _write: bool,
        bitmap_failure: bool,
    ) -> PageFaultAction {
        assert!(bitmap_failure);
        self.guest_memory_faults.fetch_add(1, Ordering::SeqCst);
        PageFaultAction::Fail(PageFaultError::other(std::io::Error::other(
            "GuestMemory transport is forbidden",
        )))
    }
}

struct CpuMapping<'a> {
    partition: &'a EmuPartition,
    _backing: Arc<CpuOnlyBacking>,
}

impl<'a> CpuMapping<'a> {
    fn new(partition: &'a EmuPartition, backing: Arc<CpuOnlyBacking>) -> Self {
        // SAFETY: this guard retains the shared allocation until synchronous
        // unmap has drained all CPU leases.
        // UNSAFETY: Installs the guard-owned backing in the CPU partition view.
        #[expect(unsafe_code)]
        unsafe {
            partition
                .map_range(
                    backing.memory.mapping().unwrap().as_ptr(),
                    SIZE,
                    0,
                    true,
                    true,
                )
                .unwrap();
        }
        Self {
            partition,
            _backing: backing,
        }
    }
}

impl Drop for CpuMapping<'_> {
    fn drop(&mut self) {
        self.partition.unmap_range(0, SIZE as u64).unwrap();
    }
}

#[derive(Default)]
struct NoDevices(Mutex<Vec<String>>);

impl CpuIo for NoDevices {
    fn is_mmio(&self, _address: u64) -> bool {
        false
    }
    fn acknowledge_pic_interrupt(&self) -> Option<u8> {
        None
    }
    fn handle_eoi(&self, _irq: u32) {
        panic!("no APIC access expected");
    }
    async fn read_mmio(&self, _vp: VpIndex, _address: u64, _data: &mut [u8]) {
        panic!("RAM must not be classified as MMIO");
    }
    async fn write_mmio(&self, _vp: VpIndex, _address: u64, _data: &[u8]) {
        panic!("RAM must not be classified as MMIO");
    }
    async fn read_io(&self, _vp: VpIndex, _port: u16, _data: &mut [u8]) {
        panic!("no port I/O expected");
    }
    async fn write_io(&self, _vp: VpIndex, _port: u16, _data: &[u8]) {
        panic!("no port I/O expected");
    }
    fn fatal_error(&self, error: Box<dyn std::error::Error + Send + Sync>) -> VpHaltReason {
        let mut message = error.to_string();
        let mut source = error.source();
        while let Some(error) = source {
            message.push_str(": ");
            message.push_str(&error.to_string());
            source = error.source();
        }
        self.0.lock().push(message);
        VpHaltReason::PowerOff
    }
}

#[async_test]
async fn real_backend_stores_and_atomics_use_direct_mappings_not_guest_memory(
    driver: DefaultDriver,
) {
    run_transport_fixture(&driver, true, true).await;
    run_transport_fixture(&driver, true, false).await;
}

#[async_test]
async fn guest_memory_without_partition_mapping_does_not_back_cpu_ram(driver: DefaultDriver) {
    run_transport_fixture(&driver, false, true).await;
    run_transport_fixture(&driver, false, false).await;
}

async fn run_transport_fixture(driver: &DefaultDriver, mapped: bool, counted: bool) {
    let program = [
        0xc6, 0x47, 0x01, 0x11, // mov byte [rdi+1],11h
        0x66, 0xc7, 0x47, 0x02, 0x33, 0x22, // mov word [rdi+2],2233h
        0xc7, 0x47, 0x04, 0x77, 0x66, 0x55, 0x44, // mov dword [rdi+4],44556677h
        0x86, 0x57, 0x01, // xchg [rdi+1],dl
        0x66, 0xf0, 0x0f, 0xc1, 0x4f, 0x02, // lock xadd [rdi+2],cx
        0xb8, 0x99, 0, 0, 0, // mov eax,99h
        0xba, 0x77, 0, 0, 0, // mov edx,77h
        0xf0, 0x0f, 0xb0, 0x57, 0x01, // lock cmpxchg [rdi+1],dl
        0xf0, 0x80, 0x47, 0x01, 0x01, // lock add byte [rdi+1],1
    ];
    let mut allocation = AlignedHeapMemory::new(SIZE);
    let bytes = allocation.as_mut_bytes();
    for (address, value) in [(0x1000, 0x2067u64), (0x2000, 0x3067), (0x3000, 0x4067)] {
        bytes[address..address + 8].copy_from_slice(&value.to_le_bytes());
    }
    for page in 0..SIZE / 4096 {
        let address = 0x4000 + page * 8;
        bytes[address..address + 8].copy_from_slice(&((page * 4096) as u64 | 0x67).to_le_bytes());
    }
    bytes[0x5008..0x5010].copy_from_slice(&0x00af9b000000ffffu64.to_le_bytes());
    bytes[0x5010..0x5018].copy_from_slice(&0x00cf93000000ffffu64.to_le_bytes());
    bytes[CODE as usize..CODE as usize + program.len()].copy_from_slice(&program);
    bytes[DATA as usize..DATA as usize + 16].fill(0xa5);
    let backing = Arc::new(CpuOnlyBacking {
        memory: allocation,
        read_bitmap: [0; 2],
        write_bitmap: [0; 2],
        guest_memory_faults: AtomicUsize::new(0),
    });
    let memory = GuestMemory::new("no-guest-memory-cpu-transport", backing.clone());
    assert!(memory.read_plain::<u8>(DATA).is_err());
    assert!(memory.write_plain(DATA, &0u8).is_err());
    let layout = MemoryLayout::new(SIZE as u64, &[] as &[MemoryRange], &[], &[], None).unwrap();
    let topology = TopologyBuilder::new_x86()
        .x2apic(X2ApicState::Unsupported)
        .build(1)
        .unwrap();
    let keeper = VmTimeKeeper::new(driver, VmTime::from_100ns(0));
    let time = keeper.builder().build(driver).await.unwrap();
    let proto = EmuHypervisor
        .new_legacy_fixture(ProtoPartitionConfig {
            processor_topology: &topology,
            hv_config: None,
            vmtime: &time,
            isolation: ProtoPartitionIsolation::None,
            nested_virt: false,
        })
        .unwrap();
    let (partition, mut binders) = proto
        .build(PartitionConfig {
            mem_layout: &layout,
            guest_memory: &memory,
            cpuid: &[],
            vtl0_alias_map: None,
            fault_resolver: None,
        })
        .unwrap();
    let _mapping = mapped.then(|| CpuMapping::new(&partition, backing.clone()));
    let mut vp = binders[0].bind().unwrap();
    let mut state = State {
        gpr: [0; 16],
        flags: 2,
        rip: CODE,
    };
    state.gpr[1] = 5;
    state.gpr[2] = 0x99;
    state.gpr[4] = 0xf000;
    state.gpr[7] = DATA;
    let initial = long_mode_registers(
        state,
        Config {
            root: 0x1000,
            wp: true,
            nxe: true,
        },
        Tables {
            idt_base: 0,
            idt_limit: 0,
            gdt_base: 0x5000,
            gdt_limit: 23,
        },
        0,
    );
    vp.access_state(Vtl::Vtl0).set_registers(&initial).unwrap();
    vp.set_execution_checkpoint(Some(CODE + program.len() as u64))
        .unwrap();
    let devices = NoDevices::default();
    let stop = StopVpSource::new();
    let result = if counted {
        vp.run_vp_counted(stop.checker(), &devices).await
    } else {
        vp.run_vp(stop.checker(), &devices).await
    };
    assert!(matches!(result, Err(VpHaltReason::PowerOff)));
    assert_eq!(devices.0.lock().len(), 1);
    assert_eq!(backing.guest_memory_faults.load(Ordering::SeqCst), 2);
    if !mapped {
        assert!(
            devices.0.lock()[0].contains("unmapped"),
            "{:?}",
            devices.0.lock()
        );
        assert_eq!(vp.access_state(Vtl::Vtl0).registers().unwrap(), initial);
        assert_eq!(
            vp.completed_batch_progress().map(|p| p.retired),
            counted.then_some(0)
        );
        assert!(
            backing.memory[DATA as usize..DATA as usize + 16]
                .iter()
                .all(|byte| byte.load(Ordering::SeqCst) == 0xa5)
        );
        return;
    }
    assert!(
        devices.0.lock()[0].contains("checkpoint"),
        "{:?}",
        devices.0.lock()
    );
    let mut expected = [0xa5; 16];
    expected[1..8].copy_from_slice(&[0x78, 0x38, 0x22, 0x77, 0x66, 0x55, 0x44]);
    let actual: Vec<_> = backing.memory[DATA as usize..DATA as usize + 16]
        .iter()
        .map(|byte| byte.load(Ordering::SeqCst))
        .collect();
    assert_eq!(actual, expected);
    let mut expected_registers = initial;
    expected_registers.rax = 0x99;
    expected_registers.rcx = 0x2233;
    expected_registers.rdx = 0x77;
    expected_registers.rflags = 6;
    expected_registers.rip = CODE + program.len() as u64;
    assert_eq!(
        vp.access_state(Vtl::Vtl0).registers().unwrap(),
        expected_registers
    );
    assert_eq!(
        vp.completed_batch_progress().map(|p| p.retired),
        counted.then_some(9)
    );
}
