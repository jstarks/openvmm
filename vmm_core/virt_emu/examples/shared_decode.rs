// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Decoder, shared event/MMU execution and existing native WB backing cost.

// xtask-fmt allow-target-arch cpu-intrinsic -- Uses the native x86 WB provider.
#[cfg(all(guest_arch = "x86_64", target_arch = "x86_64"))]
mod native {
    use guestmem::GuestMemory;
    use memory_range::MemoryRange;
    use std::io;
    use std::time::Instant;
    use virt_emu::native_memory::NativeRam;
    use x86_system::shared::{BatchStop, SharedEventMachine};
    use x86_system::{Config, State, Tables};

    type Error = Box<dyn std::error::Error + Send + Sync>;
    const CODE: u64 = 0x10000;
    const LOOPS: usize = 20_000;

    pub fn run() -> Result<(), Error> {
        let memory = GuestMemory::allocate(0x80000);
        let instructions = [
            0x49, 0x89, 0xf7, 0x4c, 0x8d, 0x35, 0, 0, 0, 0, 0xba, 0x01, 0x01, 0, 0xc0,
        ];
        memory.write_at(CODE, &instructions.repeat(LOOPS))?;
        let ram = NativeRam::new(memory.clone(), MemoryRange::new(0..0x80000))?;
        for trial in 0..3 {
            for (address, value) in [(0x1000, 0x2007u64), (0x2000, 0x3007), (0x3000, 0x4007)] {
                memory.write_plain(address, &value)?;
            }
            for page in 0..512u64 {
                memory.write_plain(0x4000 + page * 8, &((page * 4096) | 7))?;
            }
            let mut initial = State {
                gpr: [0; 16],
                flags: 2,
                rip: CODE,
            };
            initial.gpr[6] = 0x40d0;
            initial.gpr[4] = 0x70000;
            let mut cpu = SharedEventMachine::new(
                initial,
                Config {
                    root: 0x1000,
                    wp: true,
                    nxe: true,
                },
                0,
                Tables {
                    gdt_base: 0x9000,
                    gdt_limit: 23,
                    idt_base: 0xa000,
                    idt_limit: 4095,
                },
            );
            if !cpu.enable_decode() {
                return Err(io::Error::other("decoder initialization rejected").into());
            }
            let (mut retired, mut requests) = (0, 0u64);
            let target = LOOPS as u64 * 3;
            let start = Instant::now();
            while retired < target {
                let batch = cpu.run(&ram, 64, target - retired)?;
                retired += batch.retired;
                match batch.stop {
                    BatchStop::Decode(input) => {
                        requests += 1;
                        if !cpu.complete_decode(input.sequence, x86_decode::admit(input)) {
                            return Err(io::Error::other("decoder completion rejected").into());
                        }
                    }
                    BatchStop::Budget | BatchStop::Yield => {}
                    other => {
                        return Err(
                            io::Error::other(format!("execution stopped: {other:?}")).into()
                        );
                    }
                }
            }
            let seconds = start.elapsed().as_secs_f64();
            let end = CODE + (LOOPS * instructions.len()) as u64;
            let actual = cpu.cpu();
            if actual.rip != end
                || actual.gpr[15] != 0x40d0
                || actual.gpr[14] != end - 5
                || actual.gpr[2] != 0xc0000101
                || requests != (LOOPS * instructions.len()) as u64
            {
                return Err(io::Error::other("decoded stream final state mismatch").into());
            }
            println!(
                "{{\"mode\":\"shared_decode\",\"trial\":{trial},\"instructions\":{retired},\"decode_requests\":{requests},\"seconds\":{seconds},\"instructions_per_second\":{}}}",
                retired as f64 / seconds
            );
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // xtask-fmt allow-target-arch cpu-intrinsic -- Uses the native x86 WB provider.
    #[cfg(all(guest_arch = "x86_64", target_arch = "x86_64"))]
    return native::run();

    // xtask-fmt allow-target-arch cpu-intrinsic -- Other host lowerings are not implemented.
    #[cfg(not(all(guest_arch = "x86_64", target_arch = "x86_64")))]
    Err("shared decode benchmark requires an x86-64 host and guest".into())
}
