// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Two interpreted, paged CPU contexts and a direct DMA writer on existing RAM.

// xtask-fmt allow-target-arch cpu-intrinsic -- Uses the native x86 WB provider.
#[cfg(all(guest_arch = "x86_64", target_arch = "x86_64"))]
mod native {
    use guestmem::GuestMemory;
    use memory_range::MemoryRange;
    use std::io;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use virt_emu::native_memory::NativeRam;
    use x86_system::paged_core::shared::{BatchStop, SharedMachine};
    use x86_system::{Config, State, StepOutcome};

    type Error = Box<dyn std::error::Error + Send + Sync>;
    const LOOPS: usize = 128;
    const INSTRUCTIONS: u64 = (LOOPS * 3) as u64;

    fn initial(lane: u64) -> State {
        let mut cpu = State {
            gpr: [0; 16],
            flags: 2,
            rip: 0,
        };
        cpu.gpr[7] = 0x1000 + lane * 8;
        cpu.gpr[1] = 1;
        cpu
    }
    fn config() -> Config {
        Config {
            root: 0x1000,
            wp: true,
            nxe: true,
        }
    }

    pub fn run() -> Result<(), Error> {
        let memory = GuestMemory::allocate(0x8000);
        for (address, value) in [
            (0x1000, 0x2007u64),
            (0x2000, 0x3007),
            (0x3000, 0x4007),
            (0x4000, 0x5007),
        ] {
            memory.write_plain(address, &value)?;
        }
        let instruction = [0x48, 0x8b, 0x07, 0x48, 0x01, 0xc8, 0x48, 0x89, 0x07];
        memory.write_at(0x5000, &instruction.repeat(LOOPS))?;
        let ram = NativeRam::new(memory.clone(), MemoryRange::new(0..0x8000))?;
        let mut retry = SharedMachine::new(initial(0), config(), 0, false);
        let fault = retry.run(&ram, 64, 3)?;
        if fault.retired != 0
            || fault.stop
                != BatchStop::Stopped(StepOutcome::PageFault {
                    code: 0,
                    address: 0x1000,
                })
            || retry.cpu() != initial(0)
        {
            return Err(io::Error::other("fault did not preserve the instruction state").into());
        }
        memory.write_plain(0x4008, &0x6007u64)?;
        if !retry.invalidate(0x1000) || !retry.resume() {
            return Err(io::Error::other("faulted CPU did not accept repair").into());
        }
        let repaired = retry.run(&ram, 128, 3)?;
        if repaired.retired != 3
            || repaired.stop != BatchStop::Budget
            || memory.read_plain::<u64>(0x6000)? != 1
        {
            return Err(io::Error::other("fault retry did not execute load/add/store").into());
        }
        memory.write_plain(0x6000, &0u64)?;
        memory.write_plain(0x6008, &100u64)?;
        let start = Arc::new(Barrier::new(3));
        let retired = thread::scope(|scope| -> Result<u64, Error> {
            let mut workers = Vec::new();
            for lane in 0..2 {
                let start = start.clone();
                let ram = &ram;
                workers.push(scope.spawn(move || -> Result<u64, Error> {
                    let mut cpu = SharedMachine::new(initial(lane), config(), 0, false);
                    let mut retired = 0;
                    start.wait();
                    while retired < INSTRUCTIONS {
                        let batch = cpu.run(ram, 8, INSTRUCTIONS - retired)?;
                        retired += batch.retired;
                        match batch.stop {
                            BatchStop::Yield => thread::yield_now(),
                            BatchStop::Budget => {}
                            BatchStop::Stopped(outcome) => {
                                return Err(
                                    io::Error::other(format!("CPU stopped: {outcome:?}")).into()
                                );
                            }
                        }
                    }
                    if cpu.cpu().gpr[0] != LOOPS as u64 + lane * 100
                        || cpu.cpu().rip != (LOOPS * instruction.len()) as u64
                    {
                        return Err(io::Error::other("incorrect final CPU state").into());
                    }
                    Ok(retired)
                }));
            }
            start.wait();
            for value in 0..10_000u64 {
                memory.write_plain(0x6010, &value)?;
            }
            let mut total = 0;
            for worker in workers {
                total += worker
                    .join()
                    .map_err(|_| io::Error::other("CPU worker panicked"))??;
            }
            Ok(total)
        })?;
        let values = [
            memory.read_plain::<u64>(0x6000)?,
            memory.read_plain(0x6008)?,
            memory.read_plain(0x6010)?,
        ];
        if retired != INSTRUCTIONS * 2 || values != [128, 228, 9999] {
            return Err(io::Error::other("shared backing result mismatch").into());
        }
        println!(
            "{{\"cpu_contexts\":2,\"retired_instructions\":{retired},\"dma_writes\":10000,\"ram\":{values:?},\"fault_retry_instructions\":3}}"
        );
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // xtask-fmt allow-target-arch cpu-intrinsic -- This demo uses the native x86 WB provider.
    #[cfg(all(guest_arch = "x86_64", target_arch = "x86_64"))]
    return native::run();

    // xtask-fmt allow-target-arch cpu-intrinsic -- Other host lowerings are not implemented.
    #[cfg(not(all(guest_arch = "x86_64", target_arch = "x86_64")))]
    Err("shared CPU demo requires an x86-64 host and guest".into())
}
