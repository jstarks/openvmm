// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::native_memory::NativeRam;
use guestmem::GuestMemory;
use memory_range::MemoryRange;
use std::sync::{Arc, Barrier};
use std::thread;
use test_with_tracing::test;
use x86_system::memory_core::shared::{Exchange, PhysicalRam};
use x86_system::mmu_core::shared::{Progress, Request, RunError, SharedMmu};
use x86_system::mmu_core::{Access, Config, Mmu, MmuResult, Report};

const SIZE: usize = 0x8000;

pub(super) fn config() -> Config {
    Config {
        root: 0x1000,
        wp: true,
        nxe: true,
    }
}

pub(super) fn bytes() -> Vec<u8> {
    let mut ram = vec![0; SIZE];
    for (address, value) in [
        (0x1000, 0x2007u64),
        (0x2000, 0x3007),
        (0x3000, 0x4007),
        (0x4000, 0x5007),
    ] {
        ram[address..address + 8].copy_from_slice(&value.to_le_bytes());
    }
    ram[0x5000] = 0xa1;
    ram[0x6000] = 0xb2;
    ram
}

pub(super) fn fixture(data: &[u8]) -> (GuestMemory, NativeRam) {
    let memory = GuestMemory::allocate(data.len());
    memory.write_at(0, data).unwrap();
    let ram = NativeRam::new(memory.clone(), MemoryRange::new(0..SIZE as u64)).unwrap();
    (memory, ram)
}

fn finish(mmu: &mut SharedMmu, ram: &NativeRam) -> Report {
    for _ in 0..128 {
        if let Progress::Complete(report) = mmu.run(ram, 1).unwrap() {
            return report;
        }
    }
    panic!("MMU did not finish its bounded test schedule");
}

fn compare(mut data: Vec<u8>, c: Config, va: u64, access: Access, user: bool) {
    let (memory, ram) = fixture(&data);
    let mut owned = Mmu::new(c, 0x77);
    let expected = owned.access(&mut data, 0, va, access, user);
    let mut shared = SharedMmu::new(c, 0x77);
    assert!(shared.begin(va, access, user));
    assert_eq!(finish(&mut shared, &ram), expected);
    assert_eq!(shared.cr2(), owned.cr2());
    assert_eq!(shared.cache_count(), owned.cache_count());
    let mut actual = vec![0; SIZE];
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, data);
}

#[test]
fn shared_huge_leaf_geometry_word_cache_and_pde_replacement() {
    let mut data = vec![0; 0x400000];
    for (address, value) in [(0x1000, 0x2007u64), (0x2000, 0x3007), (0x3008, 0x201087)] {
        data[address..address + 8].copy_from_slice(&value.to_le_bytes());
    }
    data[0x200000] = 0x71;
    data[0x20f123] = 0x72;
    data[0x3fffff] = 0x73;
    let memory = GuestMemory::allocate(data.len());
    memory.write_at(0, &data).unwrap();
    let ram = NativeRam::new(memory.clone(), MemoryRange::new(0..data.len() as u64)).unwrap();
    let mut owned = Mmu::new(config(), 77);
    let mut shared = SharedMmu::new(config(), 77);
    for va in [0x200000, 0x20f123, 0x3fffff] {
        let expected = owned.access(&mut data, 0, va, Access::Read, false);
        assert!(shared.begin(va, Access::Read, false));
        assert_eq!(finish(&mut shared, &ram), expected);
    }
    let expected = owned.access_word(&mut data, 0, 0x20f121, x86_system::WordAccess::Read, false);
    assert!(shared.begin_word(0x20f121, x86_system::WordAccess::Read, false));
    let Progress::CompleteWord(report) = shared.run(&ram, 64).unwrap() else {
        panic!("qword did not complete")
    };
    assert_eq!(report, expected);
    assert_eq!(report.result, x86_system::WordResult::Success(0x720000));
    assert!(shared.invalidate(0x3ff000));
    owned.invalidate(0x3ff000);
    assert_eq!((shared.cache_count(), owned.cache_count()), (0, 0));
    let mut actual = vec![0; data.len()];
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, data);
    for mask in [32, 64] {
        memory.write_plain(0x3008, &(0x201087u64)).unwrap();
        let mut shared = SharedMmu::new(config(), 77);
        assert!(shared.begin(0x20f123, Access::Write(0x93), false));
        let mut raced = false;
        let mut result = None;
        for _ in 0..128 {
            if let Request::Compare {
                address: 0x3008,
                expected,
                replacement,
            } = shared.request()
            {
                if !raced && expected & mask == 0 && replacement & mask != 0 {
                    memory.write_plain(0x3008, &(expected & !2)).unwrap();
                    raced = true;
                }
            }
            if let Progress::Complete(report) = shared.run(&ram, 1).unwrap() {
                result = Some(report.result);
                break;
            }
        }
        assert!(raced);
        assert_eq!(result, Some(MmuResult::PageFault(3)));
        assert_eq!(shared.cr2(), 0x20f123);
        assert_eq!(memory.read_plain::<u8>(0x20f123).unwrap(), 0x72);
        assert_eq!(memory.read_plain::<u64>(0x3008).unwrap() & 64, 0);
    }
}

#[test]
fn shared_mmu_matches_owned_full_ram_permission_matrix() {
    for pattern in 0..4096u64 {
        let mut data = bytes();
        for level in 0..4 {
            let word = ((level + 2) << 12)
                | 1
                | ((pattern >> (level * 3) & 1) << 1)
                | ((pattern >> (level * 3 + 1) & 1) << 2)
                | ((pattern >> (level * 3 + 2) & 1) << 63);
            let address = (level as usize + 1) * 4096;
            data[address..address + 8].copy_from_slice(&word.to_le_bytes());
        }
        for user in [false, true] {
            for access in [Access::Read, Access::Fetch, Access::Write(0xc3)] {
                compare(data.clone(), config(), 0, access, user);
            }
        }
    }
}

#[test]
fn shared_mmu_fault_profiles_preserve_exact_partial_effects() {
    for level in 0..4 {
        for flags in [0u64, 1 << 48, 1 << 63, 1 << 7, 1 << 8] {
            let mut data = bytes();
            let address = (level + 1) * 4096;
            let original = u64::from_le_bytes(data[address..address + 8].try_into().unwrap());
            let word = if flags == 0 {
                original & !1
            } else {
                original | flags
            };
            data[address..address + 8].copy_from_slice(&word.to_le_bytes());
            for nxe in [false, true] {
                for wp in [false, true] {
                    for access in [Access::Read, Access::Fetch, Access::Write(0xc3)] {
                        compare(
                            data.clone(),
                            Config {
                                wp,
                                nxe,
                                ..config()
                            },
                            0,
                            access,
                            false,
                        );
                    }
                }
            }
        }
    }
    for va in [0x8000_0000_0000, u64::MAX, 7, 4095] {
        compare(bytes(), config(), va, Access::Read, false);
    }
    compare(
        bytes(),
        Config {
            root: 3,
            ..config()
        },
        0,
        Access::Read,
        false,
    );
}

#[test]
fn shared_mmu_revalidates_replaced_and_revoked_ptes() {
    for (access, expected_word, replacement, expected) in [
        (Access::Read, 0x5007, 0x6007u64, MmuResult::Success(0xb2)),
        (Access::Read, 0x5007, 0x6006, MmuResult::PageFault(0)),
        (Access::Write(0xcc), 0x5027, 0x5025, MmuResult::PageFault(3)),
    ] {
        let (memory, ram) = fixture(&bytes());
        let mut mmu = SharedMmu::new(config(), 0x77);
        assert!(mmu.begin(0, access, false));
        let mut reached = false;
        for _ in 0..32 {
            if matches!(mmu.request(), Request::Compare { address: 0x4000, expected, .. }
                if expected == expected_word)
            {
                reached = true;
                break;
            }
            assert_eq!(mmu.run(&ram, 1).unwrap(), Progress::Yield);
        }
        assert!(reached, "target PTE CAS was never requested");
        let changed = Arc::new(Barrier::new(2));
        thread::scope(|scope| {
            let changed_dma = changed.clone();
            let memory = &memory;
            scope.spawn(move || {
                memory.write_plain(0x4000, &replacement).unwrap();
                changed_dma.wait();
            });
            changed.wait();
            assert_eq!(finish(&mut mmu, &ram).result, expected);
        });
        assert_eq!(memory.read_plain::<u8>(0x5000).unwrap(), 0xa1);
        assert_eq!(memory.read_plain::<u8>(0x6000).unwrap(), 0xb2);
        assert_eq!(memory.read_plain::<u64>(0x4000).unwrap() & 64, 0);
    }
}

#[test]
fn shared_mmu_retains_pending_effect_on_yield_and_memory_error() {
    struct FailOnce {
        ram: NativeRam,
        fail: std::sync::atomic::AtomicBool,
    }
    impl PhysicalRam for FailOnce {
        type Error = std::io::Error;
        fn read_word(&self, address: u64) -> Result<u64, Self::Error> {
            if self.fail.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(std::io::Error::other("scheduled backing failure"));
            }
            self.ram.read_word(address).map_err(std::io::Error::other)
        }
        fn write_word(&self, address: u64, value: u64) -> Result<(), Self::Error> {
            self.ram
                .write_word(address, value)
                .map_err(std::io::Error::other)
        }
        fn compare_exchange_word(
            &self,
            address: u64,
            old: u64,
            new: u64,
        ) -> Result<Exchange, Self::Error> {
            self.ram
                .compare_exchange_word(address, old, new)
                .map_err(std::io::Error::other)
        }
        fn barrier(&self) {
            self.ram.barrier();
        }
    }
    let (memory, ram) = fixture(&bytes());
    let mut mmu = SharedMmu::new(config(), 0x77);
    assert!(mmu.begin(0, Access::Read, false));
    let request = mmu.request();
    assert_eq!(mmu.run(&ram, 0).unwrap(), Progress::Yield);
    assert!(!mmu.begin(1, Access::Write(0), false));
    assert!(!mmu.reload(config()));
    assert!(!mmu.invalidate(0));
    assert!(!mmu.exchanged());
    assert_eq!(mmu.request(), request);
    let fail = FailOnce {
        ram: ram.clone(),
        fail: true.into(),
    };
    assert!(matches!(mmu.run(&fail, 1), Err(RunError::Memory { .. })));
    assert_eq!(mmu.request(), request);
    assert_eq!(mmu.cr2(), 0x77);
    assert_eq!(memory.read_plain::<u64>(0x1000).unwrap(), 0x2007);
    assert_eq!(finish(&mut mmu, &ram).result, MmuResult::Success(0xa1));
}

#[test]
fn shared_mmu_parallel_cpu_contexts_and_direct_dma_preserve_neighbors() {
    let (memory, ram) = fixture(&bytes());
    memory.write_plain(0x5000, &0u64).unwrap();
    let start = Arc::new(Barrier::new(3));
    thread::scope(|scope| {
        for lane in 0..2 {
            let ram = &ram;
            let start = start.clone();
            scope.spawn(move || {
                let mut mmu = SharedMmu::new(config(), 0);
                start.wait();
                for value in 0..1000 {
                    assert!(mmu.begin(lane, Access::Write((value + lane) as u8), false));
                    loop {
                        match mmu.run(ram, 8).unwrap() {
                            Progress::Complete(report) => {
                                assert_eq!(report.result, MmuResult::Success((value + lane) as u8));
                                break;
                            }
                            Progress::Yield => thread::yield_now(),
                            Progress::CompleteWord(_) => panic!("word completion for byte access"),
                        }
                    }
                }
            });
        }
        start.wait();
        for value in 0..1000 {
            memory.write_plain(0x5002, &((value + 2) as u8)).unwrap();
        }
    });
    assert_eq!(memory.read_plain::<u64>(0x5000).unwrap(), 0xe9e8e7);
    assert_eq!(memory.read_plain::<u64>(0x4000).unwrap(), 0x5067);
}

#[test]
fn shared_mmu_tlbs_are_per_cpu_stale_until_explicit_invalidation() {
    let (memory, ram) = fixture(&bytes());
    let mut first = SharedMmu::new(config(), 0);
    let mut second = SharedMmu::new(config(), 0);
    assert!(first.begin(0, Access::Read, false));
    assert_eq!(finish(&mut first, &ram).result, MmuResult::Success(0xa1));
    memory.write_plain(0x4000, &0x6007u64).unwrap();
    assert!(first.begin(0, Access::Read, false));
    let stale = finish(&mut first, &ram);
    assert_eq!(stale.result, MmuResult::Success(0xa1));
    assert_eq!(stale.table_reads, 0);
    assert!(second.begin(0, Access::Read, false));
    assert_eq!(finish(&mut second, &ram).result, MmuResult::Success(0xb2));
    assert!(first.invalidate(0));
    assert!(first.begin(0, Access::Read, false));
    assert_eq!(finish(&mut first, &ram).result, MmuResult::Success(0xb2));
    memory.write_plain(0x4000, &0x6003u64).unwrap();
    assert!(first.reload(config()));
    assert!(first.begin(0, Access::Read, false));
    finish(&mut first, &ram);
    assert!(first.begin(0, Access::Read, true));
    assert_eq!(finish(&mut first, &ram).result, MmuResult::PageFault(5));
    memory.write_plain(0x4000, &0x6007u64).unwrap();
    assert!(first.begin(0, Access::Read, true));
    assert_eq!(finish(&mut first, &ram).result, MmuResult::Success(0xb2));
}

#[test]
fn shared_mmu_self_pte_alias_and_backing_error_order() {
    let mut data = bytes();
    data[0x4000..0x4008].copy_from_slice(&0x4007u64.to_le_bytes());
    compare(data, config(), 0, Access::Write(1), false);
    let (memory, ram) = fixture(&bytes()[..0x5000]);
    let mut mmu = SharedMmu::new(config(), 0x77);
    assert!(mmu.begin(0, Access::Write(0xcc), false));
    assert!(matches!(mmu.run(&ram, 32), Err(RunError::Memory { .. })));
    assert_eq!(mmu.cr2(), 0x77);
    assert_eq!(memory.read_plain::<u64>(0x4000).unwrap(), 0x5027);
    assert!(matches!(mmu.request(), Request::Read(0x5000)));
}

fn finish_word(mmu: &mut SharedMmu, ram: &NativeRam) -> x86_system::mmu_core::word::WordReport {
    for _ in 0..128 {
        match mmu.run(ram, 1).unwrap() {
            Progress::CompleteWord(report) => return report,
            Progress::Yield => {}
            Progress::Complete(_) => panic!("byte completion for qword access"),
        }
    }
    panic!("qword MMU exceeded finite test schedule");
}

#[test]
fn shared_qwords_match_owned_ram_at_every_supported_offset() {
    use x86_system::mmu_core::word::WordAccess;
    for offset in 0..=4088 {
        for access in [WordAccess::Read, WordAccess::Write(0x1122334455667788)] {
            let mut expected = bytes();
            for (i, byte) in expected[0x5000..0x6000].iter_mut().enumerate() {
                *byte = i as u8;
            }
            let (memory, ram) = fixture(&expected);
            let mut owned = Mmu::new(config(), 0x77);
            let report = owned.access_word(&mut expected, 0, offset, access, false);
            let mut shared = SharedMmu::new(config(), 0x77);
            assert!(shared.begin_word(offset, access, false));
            assert_eq!(finish_word(&mut shared, &ram), report);
            assert_eq!(shared.cr2(), owned.cr2());
            let mut actual = vec![0; SIZE];
            memory.read_at(0, &mut actual).unwrap();
            assert_eq!(actual, expected);
        }
    }
    for va in [4089, 4095, u64::MAX, u64::MAX - 7, 0x8000_0000_0000] {
        let mut data = bytes();
        let (_, ram) = fixture(&data);
        let mut owned = Mmu::new(config(), 0x77);
        let mut shared = SharedMmu::new(config(), 0x77);
        assert!(shared.begin_word(va, WordAccess::Read, false));
        assert_eq!(
            finish_word(&mut shared, &ram),
            owned.access_word(&mut data, 0, va, WordAccess::Read, false)
        );
    }
}

#[test]
fn shared_aligned_qword_stores_are_native_and_do_not_tear() {
    use x86_system::mmu_core::word::WordAccess;
    let (memory, ram) = fixture(&bytes());
    memory.write_plain(0x5000, &0u64).unwrap();
    let values = [0x5555aaaa5555aaaa, 0xaaaa5555aaaa5555];
    let start = Arc::new(Barrier::new(3));
    thread::scope(|scope| {
        for value in values {
            let start = start.clone();
            let ram = &ram;
            scope.spawn(move || {
                let mut mmu = SharedMmu::new(config(), 0);
                start.wait();
                for _ in 0..2000 {
                    assert!(mmu.begin_word(0, WordAccess::Write(value), false));
                    loop {
                        if let Request::WriteWord {
                            address,
                            word_value,
                        } = mmu.request()
                        {
                            assert_eq!((address, word_value), (0x5000, value));
                        }
                        if let Progress::CompleteWord(_) = mmu.run(ram, 1).unwrap() {
                            break;
                        }
                    }
                }
            });
        }
        start.wait();
        for _ in 0..50_000 {
            let value = memory.read_plain::<u64>(0x5000).unwrap();
            assert!(value == 0 || values.contains(&value));
        }
    });
}

#[test]
fn split_qword_yield_and_error_never_replay_committed_head() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use x86_system::mmu_core::word::{WordAccess, WordResult};
    struct TailFault {
        ram: NativeRam,
        fail: AtomicBool,
    }
    impl PhysicalRam for TailFault {
        type Error = std::io::Error;
        fn read_word(&self, a: u64) -> Result<u64, Self::Error> {
            self.ram.read_word(a).map_err(std::io::Error::other)
        }
        fn write_word(&self, a: u64, v: u64) -> Result<(), Self::Error> {
            self.ram.write_word(a, v).map_err(std::io::Error::other)
        }
        fn compare_exchange_word(
            &self,
            a: u64,
            old: u64,
            new: u64,
        ) -> Result<Exchange, Self::Error> {
            if a == 0x5008 && self.fail.swap(false, Ordering::SeqCst) {
                return Err(std::io::Error::other("scheduled tail failure"));
            }
            self.ram
                .compare_exchange_word(a, old, new)
                .map_err(std::io::Error::other)
        }
        fn barrier(&self) {
            self.ram.barrier();
        }
    }
    let (memory, ram) = fixture(&bytes());
    let value = 0x1122334455667788;
    let mut mmu = SharedMmu::new(config(), 0);
    assert!(mmu.begin_word(1, WordAccess::Write(value), false));
    let mut reached = false;
    for _ in 0..64 {
        if matches!(
            mmu.request(),
            Request::DataCompare {
                address: 0x5008,
                ..
            }
        ) {
            reached = true;
            break;
        }
        assert_eq!(mmu.run(&ram, 1).unwrap(), Progress::Yield);
    }
    assert!(reached);
    memory.write_plain(0x5000, &0xefu8).unwrap();
    memory.write_plain(0x5002, &0xddu8).unwrap();
    memory.write_plain(0x5009, &0xeeu8).unwrap();
    let fault = TailFault {
        ram: ram.clone(),
        fail: true.into(),
    };
    let pending = mmu.request();
    assert!(matches!(mmu.run(&fault, 1), Err(RunError::Memory { .. })));
    assert_eq!(mmu.request(), pending);
    assert_eq!(
        finish_word(&mut mmu, &ram).result,
        WordResult::Success(value)
    );
    assert_eq!(
        memory.read_plain::<u64>(0x5000).unwrap(),
        0x2233445566dd88ef
    );
    assert_eq!(memory.read_plain::<u16>(0x5008).unwrap(), 0xee11);
}

#[test]
fn qword_aliases_and_revocation_keep_dirty_order_precise() {
    use x86_system::mmu_core::word::{WordAccess, WordResult};
    for offset in 0..8 {
        let mut data = bytes();
        data[0x4000..0x4008].copy_from_slice(&0x4007u64.to_le_bytes());
        let (memory, ram) = fixture(&data);
        let mut owned = Mmu::new(config(), 0);
        let access = WordAccess::Write(0x1122334455667788);
        let expected = owned.access_word(&mut data, 0, offset, access, false);
        let mut shared = SharedMmu::new(config(), 0);
        assert!(shared.begin_word(offset, access, false));
        assert_eq!(finish_word(&mut shared, &ram), expected);
        let mut actual = vec![0; SIZE];
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, data);
    }
    let (memory, ram) = fixture(&bytes());
    let mut mmu = SharedMmu::new(config(), 0);
    assert!(mmu.begin_word(1, WordAccess::Write(u64::MAX), false));
    let mut reached = false;
    for _ in 0..64 {
        if matches!(
            mmu.request(),
            Request::Compare {
                address: 0x4000,
                expected: 0x5027,
                ..
            }
        ) {
            reached = true;
            break;
        }
        assert_eq!(mmu.run(&ram, 1).unwrap(), Progress::Yield);
    }
    assert!(reached);
    memory.write_plain(0x4000, &0x5025u64).unwrap();
    assert_eq!(finish_word(&mut mmu, &ram).result, WordResult::PageFault(3));
    assert_eq!(memory.read_plain::<u64>(0x5000).unwrap(), 0xa1);
    assert_eq!(memory.read_plain::<u64>(0x5008).unwrap(), 0);
    assert_eq!(memory.read_plain::<u64>(0x4000).unwrap(), 0x5025);
}
