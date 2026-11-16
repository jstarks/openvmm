// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::shared_mmu_tests::{bytes, config, fixture};
use super::test_support::{EventFixture, RunDecoded, long64_system, run_fixture};
use std::sync::{Arc, Barrier};
use std::thread;
use test_with_tracing::test;
use x86_system::execute::{BatchStop, Machine};
use x86_system::reference::{ReferenceCpu, ReferenceMachine, ReferenceMmu};
use x86_system::{CpuState, State, Tables};

fn machine(initial: State, cr2: u64) -> Machine {
    Machine::new(CpuState {
        registers: initial,
        config: config(),
        cr2,
        tables: Tables {
            idt_base: 0,
            idt_limit: 0,
            gdt_base: 0,
            gdt_limit: 0,
        },
        system: long64_system(),
    })
    .unwrap()
}

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
fn shared_cpu_native_and_vector_transports_agree_on_registers_and_full_ram() {
    for rex in 0x48..=0x4f {
        for opcode in [0x01, 0x11, 0x8b, 0x89] {
            for modrm in 0..=255 {
                let mut expected = program(&[rex, opcode, modrm]);
                let (memory, ram) = fixture(&expected);
                let initial = state();
                let mut owned = EventFixture {
                    system: long64_system(),
                    snapshot: ReferenceMachine {
                        core: ReferenceCpu {
                            cpu: initial,
                            mmu: ReferenceMmu::new(config(), 0x77),
                        },
                        tables: Tables {
                            idt_base: 0,
                            idt_limit: 0,
                            gdt_base: 0,
                            gdt_limit: 0,
                        },
                        stopped: None,
                        handler_pending: false,
                        pending: None,
                        shadow: false,
                        halted: false,
                    },
                };
                let report = run_fixture(&mut owned, &mut expected, 1);
                let mut shared = machine(initial, 0x77);
                let mut retired = 0;
                let mut final_stop = None;
                for _ in 0..128 {
                    let batch = shared.run_decoded(&ram, 1, 1 - retired).unwrap();
                    retired += batch.retired;
                    if batch.stop != BatchStop::Yield {
                        final_stop = Some(batch.stop);
                        break;
                    }
                }
                assert_eq!(retired, report.retired);
                assert_eq!(final_stop, Some(report.stop));
                assert_eq!(shared.cpu(), owned.core.cpu);
                assert_eq!(shared.cr2(), owned.core.mmu.cr2());
                let mut actual = vec![0; expected.len()];
                memory.read_at(0, &mut actual).unwrap();
                assert_eq!(actual, expected);
            }
        }
    }
}

#[test]
fn shared_cpu_incremental_execution_matches_explicit_load_add_store_state() {
    let code = [0x48, 0x8b, 0x07, 0x48, 0x01, 0xc8, 0x48, 0x89, 0x07];
    let data = program(&code);
    let (memory, ram) = fixture(&data);
    let mut initial = state();
    initial.gpr[7] = 0x1000;
    initial.gpr[1] = 1;
    let mut machine = machine(initial, 0x77);
    let mut retired = 0;
    for _ in 0..256 {
        let batch = machine.run_decoded(&ram, 1, 3 - retired).unwrap();
        retired += batch.retired;
        if retired == 3 {
            break;
        }
        assert_eq!(batch.stop, BatchStop::Yield);
    }
    assert_eq!(retired, 3);
    let mut expected = initial;
    expected.gpr[0] = 0xb3;
    expected.rip += 9;
    assert_eq!(machine.cpu(), expected);
    assert_eq!(machine.cpu().gpr[0], 0xb3);
    assert_eq!(memory.read_plain::<u64>(0x6000).unwrap(), 0xb3);
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
                let mut cpu = machine(initial, 0);
                let mut retired = 0;
                start.wait();
                while retired < (LOOPS * 3) as u64 {
                    let batch = cpu
                        .run_decoded(ram, 1, (LOOPS * 3) as u64 - retired)
                        .unwrap();
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
