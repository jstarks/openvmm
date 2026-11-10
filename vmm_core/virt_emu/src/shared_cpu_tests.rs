// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::shared_mmu_tests::{bytes, config, fixture};
use std::sync::{Arc, Barrier};
use std::thread;
use test_with_tracing::test;
use x86_system::paged_core::shared::{BatchStop, SharedMachine};
use x86_system::paged_core::{Machine, PagedDiagnostic, StepOutcome};
use x86_system::{Mmu, State};

fn state() -> State {
    State {
        gpr: std::array::from_fn(|i| 0x1000 + (i * 8) as u64),
        rip: 0,
        flags: 2,
    }
}
fn program(code: &[u8]) -> Vec<u8> {
    let mut data = bytes();
    data[0x4008..0x4010].copy_from_slice(&0x6007u64.to_le_bytes());
    data[0x5000..0x5000 + code.len()].copy_from_slice(code);
    data
}

#[test]
fn shared_cpu_matches_owned_registers_and_full_ram() {
    for rex in 0x48..=0x4f {
        for opcode in [0x01, 0x11, 0x8b, 0x89] {
            for modrm in 0..=255 {
                let mut expected = program(&[rex, opcode, modrm]);
                let (memory, ram) = fixture(&expected);
                let initial = state();
                let mut owned = Machine {
                    cpu: initial,
                    mmu: Mmu::new(config(), 0x77),
                };
                let report = owned.run(&mut expected, 0, false, 1);
                let mut shared = SharedMachine::new(initial, config(), 0x77, false);
                let mut retired = 0;
                let mut final_stop = None;
                for _ in 0..128 {
                    let batch = shared.run(&ram, 1, 1 - retired).unwrap();
                    retired += batch.retired;
                    if batch.stop != BatchStop::Yield {
                        final_stop = Some(batch.stop);
                        break;
                    }
                }
                assert_eq!(retired, report.retired);
                assert_eq!(
                    final_stop,
                    Some(match report.outcome {
                        StepOutcome::Budget => BatchStop::Budget,
                        other => BatchStop::Stopped(other),
                    })
                );
                assert_eq!(shared.cpu(), owned.cpu);
                assert_eq!(shared.cr2(), owned.mmu.cr2());
                let mut actual = vec![0; expected.len()];
                memory.read_at(0, &mut actual).unwrap();
                assert_eq!(actual, expected);
            }
        }
    }
}

#[test]
fn shared_cpu_fault_retry_and_incremental_fetch_keep_precise_state() {
    let code = [0x48, 0x8b, 0x07, 0x48, 0x01, 0xc8, 0x48, 0x89, 0x07];
    let mut data = program(&code);
    data[0x4008..0x4010].copy_from_slice(&0u64.to_le_bytes());
    let (memory, ram) = fixture(&data);
    let mut initial = state();
    initial.gpr[7] = 0x1000;
    initial.gpr[1] = 1;
    let mut machine = SharedMachine::new(initial, config(), 0x77, false);
    let failed = machine.run(&ram, 64, 3).unwrap();
    assert_eq!(failed.retired, 0);
    assert_eq!(
        failed.stop,
        BatchStop::Stopped(StepOutcome::PageFault {
            code: 0,
            address: 0x1000
        })
    );
    assert_eq!(machine.cpu(), initial);
    assert_eq!(machine.cr2(), 0x1000);
    memory.write_plain(0x4008, &0x6007u64).unwrap();
    assert!(machine.invalidate(0x1000));
    assert!(machine.resume());
    let retried = machine.run(&ram, 128, 3).unwrap();
    assert_eq!((retried.retired, retried.stop), (3, BatchStop::Budget));
    assert_eq!(machine.cpu().gpr[0], 0xb3);
    assert_eq!(memory.read_plain::<u64>(0x6000).unwrap(), 0xb3);
    for first in [0x90u8, 0x48] {
        let mut data = bytes();
        data[0x5fff] = first;
        let (_, ram) = fixture(&data);
        let initial = State {
            rip: 4095,
            ..state()
        };
        let mut machine = SharedMachine::new(initial, config(), 0, false);
        let stop = machine.run(&ram, 64, 1).unwrap();
        let expected = if first == 0x90 {
            StepOutcome::Diagnostic(PagedDiagnostic::Unsupported)
        } else {
            StepOutcome::PageFault {
                code: 16,
                address: 4096,
            }
        };
        assert_eq!(stop.stop, BatchStop::Stopped(expected));
        assert_eq!(machine.cpu(), initial);
    }
}

#[test]
fn two_instruction_streams_and_direct_dma_share_existing_backing() {
    const LOOPS: usize = 128;
    let code = [0x48, 0x8b, 0x07, 0x48, 0x01, 0xc8, 0x48, 0x89, 0x07].repeat(LOOPS);
    let data = program(&code);
    let code_len = code.len();
    let (memory, ram) = fixture(&data);
    memory.write_plain(0x6000, &0u64).unwrap();
    memory.write_plain(0x6008, &100u64).unwrap();
    let start = Arc::new(Barrier::new(3));
    thread::scope(|scope| {
        for lane in 0..2 {
            let start = start.clone();
            let ram = &ram;
            scope.spawn(move || {
                let mut initial = state();
                initial.gpr[7] = 0x1000 + lane * 8;
                initial.gpr[1] = 1;
                let mut cpu = SharedMachine::new(initial, config(), 0, false);
                let mut retired = 0;
                start.wait();
                while retired < (LOOPS * 3) as u64 {
                    let batch = cpu.run(ram, 1, (LOOPS * 3) as u64 - retired).unwrap();
                    retired += batch.retired;
                    assert!(matches!(batch.stop, BatchStop::Yield | BatchStop::Budget));
                    if batch.stop == BatchStop::Yield {
                        thread::yield_now();
                    }
                }
                assert_eq!(cpu.cpu().rip, code_len as u64);
                assert_eq!(cpu.cpu().gpr[0], LOOPS as u64 + lane * 100);
            });
        }
        start.wait();
        for value in 0..10_000u64 {
            memory.write_plain(0x6010, &value).unwrap();
        }
    });
    assert_eq!(memory.read_plain::<u64>(0x6000).unwrap(), 128);
    assert_eq!(memory.read_plain::<u64>(0x6008).unwrap(), 228);
    assert_eq!(memory.read_plain::<u64>(0x6010).unwrap(), 9999);
}
