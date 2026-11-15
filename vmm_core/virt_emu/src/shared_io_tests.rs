// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::shared_event_tests::{backing, fixture};
use super::test_support::RunDecoded;
use test_with_tracing::test;
use x86_system::WordAccess;
use x86_system::execute::{BatchStop, Machine, Tick};
use x86_system::mmu::translate::io::{IoReply, IoRoute};
use x86_system::mmu::translate::{Reply, RunError, perform};

const CODE: u64 = 0x10000;
const DEVICE: u64 = 0x20000;
const PTE: u64 = 0x4100;

#[test]
fn shared_mmio_typed_completion_never_reads_a_store_target_or_replays() {
    let (mut bytes, owned) = fixture();
    bytes[CODE as usize..CODE as usize + 7]
        .copy_from_slice(&[0x48, 0x89, 0x07, 0x48, 0x8b, 0x07, 0xf4]);
    let (memory, ram) = backing(&bytes);
    let mut initial = owned.core.cpu;
    initial.gpr[7] = DEVICE;
    initial.gpr[0] = 0xabcdef;
    let mut cpu = Machine::new(initial, super::shared_mmu_tests::config(), 77, owned.tables);
    let batch = cpu
        .run_mmio_decoded(&ram, 256, 1, |address, _| address == DEVICE)
        .unwrap();
    let BatchStop::Io(write) = batch.stop else {
        panic!("no MMIO write: {batch:?}")
    };
    assert_eq!((batch.retired, batch.delivered), (0, 0));
    assert_eq!(write.access, WordAccess::Write(0xabcdef));
    assert_eq!(cpu.cpu(), initial);
    assert_ne!(memory.read_plain::<u64>(PTE).unwrap() & 64, 0);
    assert!(!cpu.complete_io(write.sequence, IoReply::Read(0)));
    assert!(!cpu.complete_io(write.sequence - 1, IoReply::Written));
    assert!(!cpu.respond(Reply::Committed));
    assert!(!cpu.respond(Reply::Read(0)));
    assert!(cpu.complete_io(write.sequence, IoReply::Written));
    assert!(!cpu.complete_io(write.sequence, IoReply::Written));
    assert_eq!(cpu.run_decoded(&ram, 1, 1).unwrap().retired, 1);
    let batch = cpu
        .run_mmio_decoded(&ram, 256, 1, |address, _| address == DEVICE)
        .unwrap();
    let BatchStop::Io(read) = batch.stop else {
        panic!("no MMIO read: {batch:?}")
    };
    assert!(read.sequence > write.sequence);
    assert_eq!(read.access, WordAccess::Read);
    assert!(!cpu.complete_io(write.sequence, IoReply::Read(0xbad)));
    assert!(!cpu.complete_io(read.sequence, IoReply::Written));
    assert!(cpu.complete_io(read.sequence, IoReply::Read(0x1234_5678)));
    assert_eq!(cpu.cpu().gpr[0], 0xabcdef, "completion is not retirement");
    assert_eq!(cpu.run_decoded(&ram, 1, 1).unwrap().retired, 1);
    assert_eq!(cpu.cpu().gpr[0], 0x1234_5678);
}

#[test]
fn shared_mmio_store_revalidates_revoked_pte_before_offering_device_io() {
    let (mut bytes, owned) = fixture();
    bytes[CODE as usize..CODE as usize + 3].copy_from_slice(&[0x48, 0x89, 0x07]);
    let (memory, ram) = backing(&bytes);
    let mut initial = owned.core.cpu;
    initial.gpr[7] = DEVICE;
    let mut cpu = Machine::new(initial, super::shared_mmu_tests::config(), 77, owned.tables);
    let mut ready = false;
    for _ in 0..256 {
        if cpu.io_operand().is_some() {
            ready = true;
            break;
        }
        match cpu.advance() {
            Tick::Decode(input) => {
                assert!(cpu.complete_decode(input.sequence, x86_decode::admit(input)));
            }
            Tick::Pending => {}
            Tick::Waiting => {
                if cpu.io_operand().is_none() {
                    assert!(cpu.respond(perform(&ram, cpu.request()).unwrap()));
                }
            }
            other => panic!("unexpected instruction progress: {other:?}"),
        }
    }
    assert!(ready);
    assert_eq!(cpu.route_io(), IoRoute::Accepted);
    memory.write_plain(PTE, &DEVICE).unwrap();
    assert!(cpu.respond(perform(&ram, cpu.request()).unwrap()));
    let batch = cpu
        .run_mmio_decoded(&ram, 256, 1, |address, _| address == DEVICE)
        .unwrap();
    assert_eq!(
        (batch.retired, batch.delivered, batch.stop),
        (0, 1, BatchStop::Budget)
    );
    assert_eq!(cpu.cr2(), DEVICE);
    assert_eq!(memory.read_plain::<u64>(PTE).unwrap(), DEVICE);
}

#[test]
fn shared_mmio_alignment_permissions_and_fetch_are_explicit_boundaries() {
    let (bytes, owned) = fixture();
    let (_, ram) = backing(&bytes);
    let mut initial = owned.core.cpu;
    initial.gpr[7] = DEVICE + 1;
    let mut cpu = Machine::new(initial, super::shared_mmu_tests::config(), 77, owned.tables);
    assert!(matches!(
        cpu.run_mmio_decoded(&ram, 256, 1, |_, _| true),
        Err(RunError::IoProfile(IoRoute::Unaligned))
    ));
    assert_eq!(cpu.cpu(), initial);

    let (mut bytes, owned) = fixture();
    bytes[CODE as usize..CODE as usize + 3].copy_from_slice(&[0x48, 0x89, 0x07]);
    bytes[PTE as usize..PTE as usize + 8].copy_from_slice(&(DEVICE | 5).to_le_bytes());
    let (memory, ram) = backing(&bytes);
    initial.gpr[7] = DEVICE;
    let mut cpu = Machine::new(initial, super::shared_mmu_tests::config(), 77, owned.tables);
    let mut classifications = 0;
    let batch = cpu
        .run_mmio_decoded(&ram, 256, 1, |_, _| {
            classifications += 1;
            true
        })
        .unwrap();
    assert_eq!((batch.retired, batch.delivered), (0, 1));
    assert_eq!(classifications, 0);
    assert_eq!(memory.read_plain::<u64>(PTE).unwrap() & 64, 0);

    initial.rip = DEVICE;
    let mut cpu = Machine::new(initial, super::shared_mmu_tests::config(), 77, owned.tables);
    assert!(matches!(
        cpu.run_mmio_decoded(&ram, 256, 1, |_, _| panic!("fetch is not an MMIO operand")),
        Err(RunError::Memory { .. })
    ));
    assert_eq!(cpu.cpu(), initial);
}
