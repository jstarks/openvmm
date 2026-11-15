// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Single-thread release costs for the native shared-RAM adapter and its backing.

// xtask-fmt allow-target-arch cpu-intrinsic -- Measures the native x86 WB lowering.
#[cfg(all(guest_arch = "x86_64", target_arch = "x86_64"))]
mod native {
    use guestmem::GuestMemory;
    use memory_range::MemoryRange;
    use std::hint::black_box;
    use std::time::Instant;
    use virt_emu::native_memory::{AdUpdate, NativeRam};
    use x86_system::State;
    use x86_system::mmu::translate::{Progress, Translator};
    use x86_system::mmu::word::WordAccess;
    use x86_system::mmu::{Access, Config};
    use x86_system::paging::runtime::{BatchStop, ExecutionState};

    fn measure(name: &str, mut operation: impl FnMut(u64)) {
        const ITERATIONS: u64 = 200_000;
        let mut samples = [0.0; 5];
        for sample in &mut samples {
            let start = Instant::now();
            for i in 0..ITERATIONS {
                operation(black_box(i));
            }
            *sample = start.elapsed().as_nanos() as f64 / ITERATIONS as f64;
        }
        let raw = samples;
        samples.sort_by(f64::total_cmp);
        println!(
            "{{\"name\":\"{name}\",\"median_ns\":{},\"samples_ns\":{raw:?}}}",
            samples[2]
        );
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let memory = GuestMemory::allocate(4096);
        let ram = NativeRam::new(memory.clone(), MemoryRange::new(0..4096))?;
        measure("guest-memory-read64", |_| {
            black_box(memory.read_plain::<u64>(0).unwrap());
        });
        measure("native-ram-read64", |_| {
            black_box(ram.read(0, 8).unwrap());
        });
        measure("guest-memory-write64", |i| {
            memory.write_plain(0, &i).unwrap();
        });
        measure("native-ram-write64", |i| {
            ram.write(0, 8, i).unwrap();
        });
        measure("native-ram-masked-byte", |i| {
            ram.write(1, 1, i).unwrap();
        });
        ram.write(0, 8, 0x2007)?;
        measure("native-ram-ad-cas", |_| {
            let observed = ram.read(0, 8).unwrap();
            assert_eq!(
                ram.try_mark_ad(0, observed, true).unwrap(),
                AdUpdate::Marked
            );
        });
        assert_eq!(ram.read(0, 8)?, 0x2067);
        let memory = GuestMemory::allocate(0x8000);
        for (address, value) in [
            (0x1000, 0x2007u64),
            (0x2000, 0x3007),
            (0x3000, 0x4007),
            (0x4000, 0x5007),
        ] {
            memory.write_plain(address, &value)?;
        }
        let ram = NativeRam::new(memory.clone(), MemoryRange::new(0..0x8000))?;
        let mut mmu = Translator::new(
            Config {
                root: 0x1000,
                wp: true,
                nxe: true,
            },
            0,
        );
        assert!(mmu.begin(0, Access::Read, false));
        assert!(matches!(mmu.run(&ram, 16)?, Progress::Complete(_)));
        measure("shared-mmu-warm-read8", |_| {
            assert!(mmu.begin(0, Access::Read, false));
            let result = mmu.run(&ram, 16).unwrap();
            assert!(matches!(result, Progress::Complete(_)));
            black_box(result);
        });
        measure("shared-mmu-cold-write8", |i| {
            assert!(mmu.begin(0, Access::Write(i as u8), false));
            let result = mmu.run(&ram, 16).unwrap();
            assert!(matches!(result, Progress::Complete(_)));
            black_box(result);
        });
        assert!(mmu.begin_word(0, WordAccess::Read, false));
        assert!(matches!(mmu.run(&ram, 16)?, Progress::CompleteWord(_)));
        measure("shared-mmu-warm-read64", |_| {
            assert!(mmu.begin_word(0, WordAccess::Read, false));
            let result = mmu.run(&ram, 16).unwrap();
            assert!(matches!(result, Progress::CompleteWord(_)));
            black_box(result);
        });
        measure("shared-mmu-cold-write64", |i| {
            assert!(mmu.begin_word(0, WordAccess::Write(i), false));
            let result = mmu.run(&ram, 16).unwrap();
            assert!(matches!(result, Progress::CompleteWord(_)));
            black_box(result);
        });
        memory.write_plain(0x4008, &0x6007u64)?;
        memory.write_at(
            0x5000,
            &[0x48, 0x8b, 0x07, 0x48, 0x01, 0xc8, 0x48, 0x89, 0x07],
        )?;
        let mut initial = State {
            gpr: [0; 16],
            rip: 0,
            flags: 2,
        };
        initial.gpr[7] = 0x1000;
        initial.gpr[1] = 1;
        measure("shared-cpu-fresh-load-add-store", |_| {
            let mut cpu = ExecutionState::new(
                initial,
                Config {
                    root: 0x1000,
                    wp: true,
                    nxe: true,
                },
                0,
                false,
            );
            let result = cpu.run(&ram, 64, 3).unwrap();
            assert_eq!(result.retired, 3);
            assert_eq!(result.stop, BatchStop::Budget);
            black_box(cpu.cpu());
        });
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // xtask-fmt allow-target-arch cpu-intrinsic -- The measured lowering is host-specific.
    #[cfg(all(guest_arch = "x86_64", target_arch = "x86_64"))]
    return native::run();

    // xtask-fmt allow-target-arch cpu-intrinsic -- No other host lowering is measured.
    #[cfg(not(all(guest_arch = "x86_64", target_arch = "x86_64")))]
    Err("native RAM benchmark requires an x86-64 host and guest".into())
}
