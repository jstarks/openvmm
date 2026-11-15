// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::native_memory::NativeRam;
use guestmem::GuestMemory;
use memory_range::MemoryRange;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use test_with_tracing::test;
use x86_system::events::EventOutcome;
use x86_system::execute::{Batch, BatchStop, Machine};
use x86_system::memory::physical::{Exchange, PhysicalRam};
use x86_system::mmu::translate::{Request, RunError};
use x86_system::reference::{ReferenceCpu, ReferenceMachine, ReferenceMmu};
use x86_system::{EventDiagnostic, Injection, State, Tables};

const CODE: u64 = 0x10000;
const HANDLER: u64 = 0x11000;
const IRQ: u64 = 0x12000;
const DATA: u64 = 0x1a000;
const INITIAL: u64 = 0x1234_5678_89ab_cdef;
const RF: u64 = 1 << 16;
const IF: u64 = 1 << 9;

fn put(ram: &mut [u8], address: u64, value: u64) {
    ram[address as usize..address as usize + 8].copy_from_slice(&value.to_le_bytes());
}

fn pte(page: u64) -> u64 {
    0x4000 + page / 4096 * 8
}

fn gate(ram: &mut [u8], vector: u8, target: u64, attr: u8) {
    put(
        ram,
        0xa000 + vector as u64 * 16,
        (target & 0xffff) | (8 << 16) | ((attr as u64) << 40) | ((target >> 16) << 48),
    );
    put(ram, 0xa008 + vector as u64 * 16, target >> 32);
}

pub(super) fn fixture() -> (Vec<u8>, ReferenceMachine) {
    let mut ram = vec![0; 0x20000];
    for (table, next) in [(0x1000, 0x2000), (0x2000, 0x3000), (0x3000, 0x4000)] {
        put(&mut ram, table, next | 7);
    }
    for page in 0..512 {
        put(&mut ram, 0x4000 + page * 8, (page * 4096) | 7);
    }
    put(&mut ram, pte(DATA), DATA);
    put(&mut ram, DATA, INITIAL);
    put(&mut ram, 0x9008, 0x00af9b000000ffff);
    put(&mut ram, 0x9010, 0x00cf93000000ffff);
    gate(&mut ram, 13, HANDLER, 0x8e);
    gate(&mut ram, 14, HANDLER, 0x8e);
    gate(&mut ram, 64, IRQ, 0x8e);
    ram[CODE as usize..CODE as usize + 5].copy_from_slice(&[0x48, 0x8b, 0x07, 0xf4, 0xf4]);
    ram[HANDLER as usize..HANDLER as usize + 11].copy_from_slice(&[
        0x48, 0x89, 0x0e, 0x0f, 0x01, 0x3f, 0x4c, 0x01, 0xc4, 0x48, 0xcf,
    ]);
    ram[IRQ as usize..IRQ as usize + 5].copy_from_slice(&[0x4d, 0x01, 0xda, 0x48, 0xcf]);
    let mut gpr = [0; 16];
    gpr[1] = DATA | 7;
    gpr[4] = 0x1800b;
    gpr[6] = pte(DATA);
    gpr[7] = DATA;
    gpr[8] = 8;
    gpr[11] = 1;
    let owned = ReferenceMachine {
        core: ReferenceCpu {
            cpu: State {
                gpr,
                flags: 0x20_0603,
                rip: CODE,
            },
            mmu: ReferenceMmu::new(super::shared_mmu_tests::config(), 0xdead_beef),
        },
        tables: Tables {
            idt_base: 0xa000,
            idt_limit: 4095,
            gdt_base: 0x9000,
            gdt_limit: 23,
        },
        stopped: None,
        handler_pending: false,
        pending: None,
        shadow: false,
        halted: false,
    };
    (ram, owned)
}

pub(super) fn backing(bytes: &[u8]) -> (GuestMemory, NativeRam) {
    let memory = GuestMemory::allocate(bytes.len());
    memory.write_at(0, bytes).unwrap();
    let ram = NativeRam::new(memory.clone(), MemoryRange::new(0..bytes.len() as u64)).unwrap();
    (memory, ram)
}

fn shared(owned: &ReferenceMachine) -> Machine {
    x86_system::reference::machine(
        owned.core.cpu,
        super::shared_mmu_tests::config(),
        owned.core.mmu.cr2(),
        owned.tables,
    )
}

fn decoded_one(cpu: &mut Machine, ram: &NativeRam) -> Batch {
    let before = cpu.cpu();
    for _ in 0..4096 {
        let batch = cpu.run(ram, 1, 1).unwrap();
        match batch.stop {
            BatchStop::Decode(input) => {
                assert_eq!(cpu.cpu(), before, "decode must expose the unretired CPU");
                assert!(cpu.complete_decode(input.sequence, x86_decode::admit(input)));
            }
            BatchStop::Yield => assert_eq!(cpu.cpu(), before),
            _ => return batch,
        }
    }
    panic!("decoded instruction exceeded finite schedule");
}

#[test]
fn decoded_page_edge_retires_without_touching_the_missing_next_page() {
    let (mut bytes, mut owned) = fixture();
    let start = 0x10ffdusize;
    bytes[start..start + 3].copy_from_slice(&[0x49, 0x89, 0xf7]);
    put(&mut bytes, pte(0x11000), 0x11000);
    owned.core.cpu.rip = start as u64;
    owned.core.cpu.flags |= RF;
    let (memory, ram) = backing(&bytes);
    let mut cpu = shared(&owned);
    assert!(cpu.enable_decode());
    let batch = decoded_one(&mut cpu, &ram);
    assert_eq!(
        (batch.retired, batch.delivered, batch.stop),
        (1, 0, BatchStop::Budget)
    );
    let mut expected = owned.core.cpu;
    expected.gpr[15] = expected.gpr[6];
    expected.rip += 3;
    expected.flags &= !RF;
    assert_eq!(cpu.cpu(), expected);
    assert_eq!(cpu.cr2(), owned.core.mmu.cr2());
    assert_eq!(memory.read_plain::<u64>(pte(0x11000)).unwrap(), 0x11000);
}

#[test]
fn decoded_faults_frame_ud_and_gp_without_fetching_past_the_page() {
    for (code, vector, count) in [
        (&[0x0f, 0x0b][..], 6u8, 5u64),
        (&[0x66; 15][..], 13u8, 6u64),
    ] {
        let (mut bytes, mut owned) = fixture();
        let start = 0x11000 - code.len();
        bytes[start..0x11000].copy_from_slice(code);
        put(&mut bytes, pte(0x11000), 0x11000);
        gate(&mut bytes, vector, IRQ, 0x8e);
        owned.core.cpu.rip = start as u64;
        let initial = owned.core.cpu;
        let (memory, ram) = backing(&bytes);
        let mut cpu = shared(&owned);
        assert!(cpu.enable_decode());
        let stack = initial.gpr[4] & !15;
        let mut stores = Vec::new();
        let mut completed = None;
        for _ in 0..4096 {
            if let Request::WriteBytes {
                address,
                bytes,
                end: 8,
                ..
            } = cpu.request()
            {
                stores.push((address, u64::from_le_bytes(bytes[..8].try_into().unwrap())));
            }
            let batch = cpu.run(&ram, 1, 1).unwrap();
            match batch.stop {
                BatchStop::Decode(input) => {
                    assert!(cpu.complete_decode(input.sequence, x86_decode::admit(input)));
                }
                BatchStop::Yield => assert_eq!(cpu.cpu(), initial),
                _ => {
                    completed = Some(batch);
                    break;
                }
            }
        }
        let batch = completed.expect("fault delivery exceeded finite schedule");
        let mut words = vec![16, initial.gpr[4], initial.flags | RF, 8, initial.rip];
        if vector == 13 {
            words.push(0);
        }
        let expected: Vec<_> = words
            .into_iter()
            .enumerate()
            .map(|(index, value)| (stack - 8 * (index as u64 + 1), value))
            .collect();
        assert_eq!(
            stores, expected,
            "frame prefix writes must be ordered and never replayed"
        );
        assert_eq!(
            (batch.retired, batch.delivered, batch.stop),
            (0, 1, BatchStop::Budget)
        );
        assert_eq!(cpu.cr2(), owned.core.mmu.cr2());
        assert_eq!(memory.read_plain::<u64>(pte(0x11000)).unwrap(), 0x11000);
        let bottom = stack - count * 8;
        assert_eq!(cpu.cpu().rip, IRQ);
        assert_eq!(cpu.cpu().gpr[4], bottom);
        let ip = bottom + if vector == 13 { 8 } else { 0 };
        assert_eq!(memory.read_plain::<u64>(ip).unwrap(), initial.rip);
        assert_eq!(
            memory.read_plain::<u64>(stack - 24).unwrap(),
            initial.flags | RF
        );
        if vector == 13 {
            assert_eq!(memory.read_plain::<u64>(bottom).unwrap(), 0);
        }
    }
}

#[test]
fn truncated_decode_fetch_fault_wins_before_opcode_classification() {
    let (mut bytes, mut owned) = fixture();
    bytes[0x10fff] = 0x0f;
    put(&mut bytes, pte(0x11000), 0x11000);
    gate(&mut bytes, 14, IRQ, 0x8e);
    owned.core.cpu.rip = 0x10fff;
    let initial = owned.core.cpu;
    let (memory, ram) = backing(&bytes);
    let mut cpu = shared(&owned);
    assert!(cpu.enable_decode());
    let batch = decoded_one(&mut cpu, &ram);
    assert_eq!((batch.retired, batch.delivered), (0, 1));
    assert_eq!(cpu.cr2(), 0x11000);
    let stack = (initial.gpr[4] & !15) - 48;
    assert_eq!(memory.read_plain::<u64>(stack).unwrap(), 16);
    assert_eq!(memory.read_plain::<u64>(stack + 8).unwrap(), initial.rip);
    assert_eq!(cpu.cpu().rip, IRQ);
}

#[test]
fn decoded_scalar_and_legacy_keep_retained_bytes_after_direct_dma_changes_code() {
    for (code, expected, length) in [
        (&[0xb8, 0x78, 0x56, 0x34, 0x12][..], 0x12345678, 5),
        (&[0x48, 0x8b, 0x07][..], 0xabcdef0123456789, 3),
    ] {
        let (mut bytes, mut owned) = fixture();
        bytes[CODE as usize..CODE as usize + code.len()].copy_from_slice(code);
        owned.core.cpu.gpr[7] = 0x8000;
        put(&mut bytes, 0x8000, 0xabcdef0123456789);
        let (memory, ram) = backing(&bytes);
        let mut cpu = shared(&owned);
        assert!(cpu.enable_decode());
        loop {
            let batch = cpu.run(&ram, 1024, 1).unwrap();
            let BatchStop::Decode(input) = batch.stop else {
                panic!("{batch:?}")
            };
            let decision = x86_decode::admit(input);
            assert!(cpu.complete_decode(input.sequence, decision));
            if !matches!(decision, x86_system::execute::decode::DecodeOutcome::More) {
                break;
            }
        }
        memory.write_at(CODE, &[0xff; 8]).unwrap();
        let done = decoded_one(&mut cpu, &ram);
        assert_eq!(
            (done.retired, done.delivered, done.stop),
            (1, 0, BatchStop::Budget)
        );
        assert_eq!(cpu.cpu().gpr[0], expected);
        assert_eq!(cpu.cpu().rip, CODE + length);
    }
}

#[test]
fn decoded_fetch_fault_discards_prefix_and_rejects_reply_after_guest_repair() {
    use x86_system::execute::decode::DecodeOutcome;
    let (mut bytes, mut owned) = fixture();
    let start = 0x15ffeusize;
    bytes[start..start + 5].copy_from_slice(&[0xb8, 0x11, 0x22, 0x33, 0x44]);
    put(&mut bytes, pte(0x16000), 0x16000);
    owned.core.cpu.rip = start as u64;
    owned.core.cpu.flags |= RF;
    owned.core.cpu.gpr[0] = 0xfeedface;
    owned.core.cpu.gpr[1] = 0x16007;
    owned.core.cpu.gpr[6] = pte(0x16000);
    owned.core.cpu.gpr[7] = 0x16000;
    let (memory, ram) = backing(&bytes);
    let mut cpu = shared(&owned);
    assert!(cpu.enable_decode());
    let stale = loop {
        let batch = cpu.run(&ram, 1024, 1).unwrap();
        let BatchStop::Decode(input) = batch.stop else {
            panic!("{batch:?}")
        };
        assert!(cpu.complete_decode(input.sequence, x86_decode::admit(input)));
        if input.length == 2 {
            break input;
        }
    };
    let fault = cpu.run(&ram, 1024, 1).unwrap();
    assert_eq!(
        (fault.retired, fault.delivered, fault.stop),
        (0, 1, BatchStop::Budget)
    );
    assert_eq!(cpu.cr2(), 0x16000);
    assert!(!cpu.complete_decode(stale.sequence, DecodeOutcome::Rejected));
    memory
        .write_at(start as u64, &[0xb9, 0x78, 0x56, 0x34, 0x12])
        .unwrap();
    for _ in 0..4 {
        assert_eq!(decoded_one(&mut cpu, &ram).retired, 1);
    }
    assert_eq!(cpu.cpu().rip, start as u64);
    assert_ne!(cpu.cpu().flags & RF, 0);
    let batch = cpu.run(&ram, 1024, 1).unwrap();
    let BatchStop::Decode(current) = batch.stop else {
        panic!("{batch:?}")
    };
    assert!(current.sequence > stale.sequence);
    assert_eq!(
        current.bytes[0], 0xb9,
        "restart must refetch the changed opcode"
    );
    assert!(!cpu.complete_decode(stale.sequence, x86_decode::admit(stale)));
    assert!(cpu.complete_decode(current.sequence, x86_decode::admit(current)));
    let done = decoded_one(&mut cpu, &ram);
    assert_eq!(
        (done.retired, done.delivered, done.stop),
        (1, 0, BatchStop::Budget)
    );
    assert_eq!(cpu.cpu().gpr[0], 0xfeedface);
    assert_eq!(cpu.cpu().gpr[1], 0x12345678);
    assert_eq!(cpu.cpu().rip, start as u64 + 5);
    assert_eq!(cpu.cpu().flags & RF, 0);
}

#[test]
fn decoded_instruction_keeps_sti_shadow_until_retirement_then_delivers_irq() {
    let (mut bytes, mut owned) = fixture();
    bytes[CODE as usize..CODE as usize + 7]
        .copy_from_slice(&[0xfb, 0xb8, 0x78, 0x56, 0x34, 0x12, 0xf4]);
    owned.core.cpu.flags &= !IF;
    let (memory, ram) = backing(&bytes);
    let mut cpu = shared(&owned);
    assert!(cpu.enable_decode());
    assert_eq!(decoded_one(&mut cpu, &ram).retired, 1);
    assert!(cpu.shadow());
    assert_eq!(cpu.inject(64), Injection::Queued);
    loop {
        let batch = cpu.run(&ram, 1, 1).unwrap();
        match batch.stop {
            BatchStop::Decode(input) => {
                assert!(cpu.shadow());
                assert_eq!(cpu.pending(), Some(64));
                assert_eq!((batch.retired, batch.delivered), (0, 0));
                assert!(cpu.complete_decode(input.sequence, x86_decode::admit(input)));
            }
            BatchStop::Yield => {}
            BatchStop::Budget => {
                assert_eq!((batch.retired, batch.delivered), (1, 0));
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(!cpu.shadow());
    assert_eq!(cpu.cpu().rip, CODE + 6);
    assert_eq!(cpu.cpu().gpr[0], 0x12345678);
    let entered = decoded_one(&mut cpu, &ram);
    assert_eq!((entered.retired, entered.delivered), (0, 1));
    let stack = owned.core.cpu.gpr[4] / 16 * 16;
    assert_eq!(memory.read_plain::<u64>(stack - 40).unwrap(), CODE + 6);
    assert_eq!(cpu.pending(), None);
}

fn one<R: PhysicalRam>(cpu: &mut Machine, ram: &R) -> Batch
where
    R::Error: std::fmt::Debug,
{
    let before = cpu.cpu();
    for _ in 0..1024 {
        let batch = cpu.run(ram, 1, 1).unwrap();
        if batch.stop != BatchStop::Yield {
            return batch;
        }
        assert_eq!((batch.retired, batch.delivered), (0, 0));
        assert_eq!(
            cpu.cpu(),
            before,
            "yield must expose the unretired CPU image"
        );
    }
    panic!("shared event exceeded finite test schedule");
}

fn compare_one(
    bytes: &mut Vec<u8>,
    owned: &mut ReferenceMachine,
    cpu: &mut Machine,
    memory: &GuestMemory,
    ram: &NativeRam,
) -> Batch {
    let expected = owned.run(bytes, 0, 1);
    let actual = one(cpu, ram);
    assert_eq!(
        (actual.retired, actual.delivered),
        (expected.retired, expected.delivered)
    );
    assert_eq!(
        actual.stop,
        match expected.outcome {
            EventOutcome::Budget => BatchStop::Budget,
            EventOutcome::Waiting => BatchStop::Waiting,
            EventOutcome::Stopped(reason) => BatchStop::Stopped(reason),
            other => panic!("unexpected one-step oracle outcome: {other:?}"),
        }
    );
    assert_eq!(cpu.cpu(), owned.core.cpu);
    assert_eq!(cpu.cr2(), owned.core.mmu.cr2());
    assert_eq!(cpu.pending(), owned.pending);
    assert_eq!(cpu.shadow(), owned.shadow);
    assert_eq!(cpu.halted(), owned.halted);
    assert_eq!(cpu.handler_pending(), owned.handler_pending);
    let mut actual_bytes = vec![0; bytes.len()];
    memory.read_at(0, &mut actual_bytes).unwrap();
    assert_eq!(actual_bytes, *bytes, "complete RAM oracle");
    actual
}

#[test]
fn shared_guest_repairs_fault_retries_and_wakes_from_hlt() {
    let (mut bytes, mut owned) = fixture();
    let initial = owned.core.cpu;
    let (memory, ram) = backing(&bytes);
    let mut cpu = shared(&owned);
    let (mut retired, mut delivered) = (0, 0);
    for _ in 0..6 {
        let batch = compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram);
        retired += batch.retired;
        delivered += batch.delivered;
    }
    assert_eq!((retired, delivered), (5, 1));
    assert_eq!(cpu.cpu().gpr[0], INITIAL);
    assert_eq!(cpu.cpu().gpr[4], initial.gpr[4]);
    assert_eq!((cpu.cpu().rip, cpu.cpu().flags & RF), (CODE + 3, 0));
    retired += compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram).retired;
    assert_eq!(
        compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram).stop,
        BatchStop::Waiting
    );
    assert_eq!(owned.inject(64), Injection::Queued);
    assert_eq!(cpu.inject(64), Injection::Queued);
    for _ in 0..4 {
        let batch = compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram);
        retired += batch.retired;
        delivered += batch.delivered;
    }
    assert_eq!((retired, delivered), (9, 2));
    assert_eq!(cpu.cpu().gpr[10], 1);
    assert_eq!(cpu.cpu().rip, CODE + 5);
    assert!(cpu.halted());
}

#[test]
fn shared_event_entry_matches_owned_full_ram_matrix() {
    for attr in [0x8e, 0x8f] {
        for residue in [0, 1, 7, 15] {
            for rf in [0, RF] {
                for kind in 0..4 {
                    let (mut bytes, mut owned) = fixture();
                    owned.core.cpu.gpr[4] = 0x18000 + residue;
                    owned.core.cpu.flags |= rf;
                    for (vector, target) in [(13, HANDLER), (14, HANDLER), (64, IRQ)] {
                        gate(&mut bytes, vector, target, attr);
                    }
                    match kind {
                        0 => assert_eq!(owned.inject(64), Injection::Queued),
                        1 => {}
                        2 => owned.core.cpu.gpr[7] = 0x8000_0000_0000,
                        _ => put(&mut bytes, pte(CODE), CODE | 7 | (1 << 63)),
                    }
                    let (memory, ram) = backing(&bytes);
                    let mut cpu = shared(&owned);
                    if kind == 0 {
                        assert_eq!(cpu.inject(64), Injection::Queued);
                    }
                    assert_eq!(
                        compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram).delivered,
                        1
                    );
                }
            }
        }
    }
}

#[test]
fn shared_event_partial_frames_preserve_cpu_pending_and_prefix() {
    for rsp in [0x18008, 0x18018, 0x18028] {
        let (mut bytes, mut owned) = fixture();
        owned.core.cpu.gpr[4] = rsp;
        put(&mut bytes, pte(0x17000), 0x17000);
        assert_eq!(owned.inject(64), Injection::Queued);
        let initial = owned.core.cpu;
        let (memory, ram) = backing(&bytes);
        let mut cpu = shared(&owned);
        assert_eq!(cpu.inject(64), Injection::Queued);
        let batch = compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram);
        assert!(matches!(
            batch.stop,
            BatchStop::Stopped(EventDiagnostic::Memory { .. })
        ));
        assert_eq!(cpu.cpu(), initial);
        assert_eq!(cpu.pending(), Some(64));
        assert_eq!(cpu.inject(65), Injection::Stopped(owned.stopped.unwrap()));
        compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram);
    }
}

struct FailOnce {
    ram: NativeRam,
    address: u64,
    fail: AtomicBool,
}

impl PhysicalRam for FailOnce {
    type Error = io::Error;
    fn read_word(&self, address: u64) -> io::Result<u64> {
        self.ram.read_word(address).map_err(io::Error::other)
    }
    fn write_word(&self, address: u64, value: u64) -> io::Result<()> {
        if address == self.address && self.fail.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("scheduled frame transport error"));
        }
        self.ram
            .write_word(address, value)
            .map_err(io::Error::other)
    }
    fn compare_exchange_word(&self, address: u64, old: u64, new: u64) -> io::Result<Exchange> {
        self.ram
            .compare_exchange_word(address, old, new)
            .map_err(io::Error::other)
    }
    fn barrier(&self) {
        self.ram.barrier();
    }
}

#[test]
fn shared_frame_host_error_and_dma_never_replay_committed_prefix() {
    let (bytes, owned) = fixture();
    let initial = owned.core.cpu;
    let (memory, ram) = backing(&bytes);
    let ram = FailOnce {
        ram,
        address: 0x17ff0,
        fail: AtomicBool::new(true),
    };
    let mut cpu = shared(&owned);
    assert_eq!(cpu.inject(64), Injection::Queued);
    let error = cpu.run(&ram, 256, 1).unwrap_err();
    assert!(matches!(
        error,
        RunError::Copy {
            request: Request::WriteBytes {
                address: 0x17ff0,
                ..
            },
            ..
        }
    ));
    let request = cpu.request();
    assert_eq!(cpu.cpu(), initial);
    assert_eq!(cpu.pending(), Some(64));
    assert_eq!(memory.read_plain::<u64>(0x17ff8).unwrap(), 16);
    memory.write_plain(0x17ff8, &0xfaceu64).unwrap();
    let yielded = cpu.run(&ram, 0, 1).unwrap();
    assert_eq!(
        (yielded.retired, yielded.delivered, yielded.stop),
        (0, 0, BatchStop::Yield)
    );
    assert_eq!(cpu.request(), request);
    let result = one(&mut cpu, &ram);
    assert_eq!((result.retired, result.delivered), (0, 1));
    assert_eq!(memory.read_plain::<u64>(0x17ff8).unwrap(), 0xface);
    assert_eq!(cpu.pending(), None);
    assert_eq!(cpu.cpu().rip, IRQ);
}

#[test]
fn shared_iret_rejects_bad_images_without_early_cpu_commit() {
    for kind in 0..9 {
        let (mut bytes, mut owned) = fixture();
        bytes[CODE as usize..CODE as usize + 2].copy_from_slice(&[0x48, 0xcf]);
        let stack = owned.core.cpu.gpr[4];
        for (index, word) in [CODE + 3, 8, 0x20_0603 | RF, 0x1b007, 16]
            .into_iter()
            .enumerate()
        {
            put(&mut bytes, stack + index as u64 * 8, word);
        }
        match kind {
            0 => {}
            1 => put(&mut bytes, stack + 8, 16),
            2 => put(&mut bytes, stack + 32, 8),
            3 => put(&mut bytes, stack + 16, 0),
            4 => put(&mut bytes, stack, 0x8000_0000_0000),
            5 => put(&mut bytes, stack + 24, 0x8000_0000_0000),
            6 => put(&mut bytes, 0x9008, 0),
            7 => put(&mut bytes, 0x9010, 0),
            _ => put(&mut bytes, pte(0x18000), 0x18000),
        }
        let initial = owned.core.cpu;
        let (memory, ram) = backing(&bytes);
        let mut cpu = shared(&owned);
        let batch = compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram);
        if kind == 0 {
            assert_eq!(batch.retired, 1);
            assert_eq!(cpu.cpu().gpr[4], 0x1b007);
        } else {
            assert!(matches!(batch.stop, BatchStop::Stopped(_)));
            assert_eq!(cpu.cpu(), initial);
        }
    }
}

#[test]
fn shared_sti_shadow_rf_and_first_handler_boundaries_match_oracle() {
    let (mut bytes, mut owned) = fixture();
    owned.core.cpu.flags &= !IF;
    bytes[CODE as usize..CODE as usize + 5].copy_from_slice(&[0xfb, 0xfb, 0xfa, 0xf4, 0xf4]);
    let (memory, ram) = backing(&bytes);
    let mut cpu = shared(&owned);
    assert_eq!(cpu.inject(31), Injection::InvalidVector);
    assert_eq!(owned.inject(64), Injection::Queued);
    assert_eq!(cpu.inject(64), Injection::Queued);
    assert_eq!(cpu.inject(65), Injection::Busy);
    for _ in 0..7 {
        compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram);
    }
    assert!(cpu.halted());
    assert_eq!(owned.inject(65), Injection::Queued);
    assert_eq!(cpu.inject(65), Injection::Queued);
    assert_eq!(
        compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram).stop,
        BatchStop::Waiting
    );

    let (mut bytes, mut owned) = fixture();
    let (memory, ram) = backing(&bytes);
    let mut cpu = shared(&owned);
    for _ in 0..5 {
        compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram);
    }
    assert_ne!(cpu.cpu().flags & RF, 0);
    assert_eq!(owned.inject(64), Injection::Queued);
    assert_eq!(cpu.inject(64), Injection::Queued);
    compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram);
    assert_ne!(
        memory.read_plain::<u64>(cpu.cpu().gpr[4] + 16).unwrap() & RF,
        0
    );
    for _ in 0..3 {
        compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram);
    }
    assert_eq!(cpu.cpu().gpr[0], INITIAL);
    assert_eq!(cpu.cpu().flags & RF, 0);

    let (mut bytes, mut owned) = fixture();
    owned.core.cpu.flags &= !IF;
    bytes[CODE as usize..CODE as usize + 4].copy_from_slice(&[0xfb, 0x48, 0x8b, 0x07]);
    gate(&mut bytes, 14, HANDLER, 0x8f);
    assert_eq!(owned.inject(64), Injection::Queued);
    let (memory, ram) = backing(&bytes);
    let mut cpu = shared(&owned);
    assert_eq!(cpu.inject(64), Injection::Queued);
    for _ in 0..2 {
        compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram);
    }
    assert_eq!(
        compare_one(&mut bytes, &mut owned, &mut cpu, &memory, &ram).stop,
        BatchStop::Stopped(EventDiagnostic::HandlerFault {
            vector: 64,
            code: 0
        }),
    );
}
