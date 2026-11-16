// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Opt-in measurement of production fast paths, with no hooks in default builds.

use crate::native_memory::NativeRam;
use anyhow::{Result, bail, ensure};
use guestmem::GuestMemory;
use std::hint::black_box;
use std::time::Instant;
use x86_system::WordAccess;
use x86_system::mmu::translate::{Progress, Translator};
use x86_system::mmu::{Access, Config};

const SAMPLE_BATCHES: u64 = 4093;
const MAX_SAMPLES: usize = 65_536;

/// One coarse, host-only observation of the executing guest.
#[derive(Debug)]
pub struct ExecutionSample {
    /// Seconds since the first observation.
    pub seconds: f64,
    /// Completed guest retirements.
    pub retired: u64,
    /// Completed event deliveries.
    pub delivered: u64,
    /// Current guest instruction pointer, including a pending instruction.
    pub rip: u64,
}

/// Bounded sampling output; not saved architectural state.
#[derive(Debug)]
pub struct ExecutionProfile {
    /// Returned batches between observations.
    pub sample_every_batches: u64,
    /// Whether the sample limit was reached.
    pub truncated: bool,
    /// Recorded observations.
    pub samples: Vec<ExecutionSample>,
}

pub(super) struct Sampler {
    start: Option<Instant>,
    batches: u64,
    output: ExecutionProfile,
}

impl Sampler {
    pub(super) fn new() -> Self {
        Self {
            start: None,
            batches: 0,
            output: ExecutionProfile {
                sample_every_batches: SAMPLE_BATCHES,
                truncated: false,
                samples: Vec::new(),
            },
        }
    }

    pub(super) fn record(&mut self, retired: u64, delivered: u64, rip: impl FnOnce() -> u64) {
        let due = self.batches.is_multiple_of(SAMPLE_BATCHES);
        self.batches = self.batches.wrapping_add(1);
        if !due {
            return;
        }
        if self.output.samples.len() == MAX_SAMPLES {
            self.output.truncated = true;
            return;
        }
        self.output.samples.push(ExecutionSample {
            seconds: self
                .start
                .get_or_insert_with(Instant::now)
                .elapsed()
                .as_secs_f64(),
            retired,
            delivered,
            rip: rip(),
        });
    }

    pub(super) fn finish(self) -> ExecutionProfile {
        self.output
    }
}

/// One measured operation count and elapsed interval; setup/warm-up are excluded.
pub struct FastPathResult {
    /// Number of production-path calls in the measured interval.
    pub operations: u64,
    /// Elapsed seconds in the measured interval.
    pub seconds: f64,
}

fn completed_hit(progress: Progress) -> Result<()> {
    match progress {
        Progress::Complete(report) => ensure!(report.table_reads == 0, "fetch TLB miss"),
        Progress::CompleteWord(report) => ensure!(report.table_reads == 0, "data TLB miss"),
        Progress::Yield => bail!("warm access did not complete in one physical operation"),
    }
    Ok(())
}

fn access<const KIND: u8>(mmu: &mut Translator) -> bool {
    match KIND {
        0 => mmu.begin(black_box(0x10000), Access::Fetch, false),
        1 => mmu.begin_word(black_box(0x10000), WordAccess::Read, false),
        2 => mmu.begin_word(black_box(0x10000), WordAccess::Write(0x5a), false),
        _ => false,
    }
}

/// Measures warm decoder hits or warm MMU hits including native qword transport.
///
/// `control(true/false)` gates external hardware counters around only the hot
/// loop. MMU iterations permit only their warm data effects, not a table walk.
pub fn fast_path(
    case: &str,
    operations: u64,
    control: impl FnMut(bool) -> Result<()>,
) -> Result<FastPathResult> {
    ensure!(operations > 0, "operation count must be positive");
    if case == "decode" {
        let seconds = strudel::perf::decode_hits(operations, control)?;
        return Ok(FastPathResult {
            operations,
            seconds,
        });
    }
    match case {
        "fetch" => tlb::<0>(operations, control),
        "read" => tlb::<1>(operations, control),
        "write" => tlb::<2>(operations, control),
        _ => bail!("unknown fast path: {case}"),
    }
}

fn tlb<const KIND: u8>(
    operations: u64,
    mut control: impl FnMut(bool) -> Result<()>,
) -> Result<FastPathResult> {
    let memory = GuestMemory::allocate(0x20000);
    for (address, value) in [
        (0x1000, 0x2067u64),
        (0x2000, 0x3067),
        (0x3000, 0x4067),
        (0x4080, 0x10067),
        (0x10000, 0x5a),
    ] {
        memory.write_plain(address, &value)?;
    }
    let ram = NativeRam::new(memory.clone());
    let mut mmu = Translator::new(
        Config {
            root: 0x1000,
            wp: true,
            nxe: true,
        },
        0,
    );
    ensure!(access::<KIND>(&mut mmu), "initial access rejected");
    black_box(mmu.run(&ram, 32)?);
    for _ in 0..1024 {
        ensure!(access::<KIND>(&mut mmu), "warm-up access rejected");
        completed_hit(mmu.run(&ram, 1)?)?;
    }
    control(true)?;
    let start = Instant::now();
    let mut last = Progress::Yield;
    for _ in 0..operations {
        ensure!(
            access::<KIND>(black_box(&mut mmu)),
            "measured access rejected"
        );
        last = black_box(mmu.run(&ram, 1)?);
    }
    let seconds = start.elapsed().as_secs_f64();
    control(false)?;
    completed_hit(last)?;
    ensure!(
        memory.read_plain::<u64>(0x10000)? == 0x5a,
        "RAM result mismatch"
    );
    Ok(FastPathResult {
        operations,
        seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_paths_gate_only_after_warmup_and_verify_hits() {
        for case in ["decode", "fetch", "read", "write"] {
            let mut gates = Vec::new();
            let result = fast_path(case, 16, |enabled| {
                gates.push(enabled);
                Ok(())
            })
            .unwrap();
            assert_eq!(gates, [true, false]);
            assert_eq!(result.operations, 16);
        }
        assert!(fast_path("other", 1, |_| Ok(())).is_err());
        assert!(fast_path("decode", 0, |_| Ok(())).is_err());
    }

    #[test]
    fn sampler_is_bounded_and_does_not_read_guest_state_between_samples() {
        let mut sampler = Sampler::new();
        sampler.record(64, 0, || 0x10000);
        sampler.record(128, 0, || panic!("not a sample boundary"));
        sampler.batches = SAMPLE_BATCHES;
        sampler.record(256, 1, || 0x10004);
        let result = sampler.finish();
        assert_eq!(result.samples.len(), 2);
        assert_eq!(result.samples[1].rip, 0x10004);
        let mut sampler = Sampler::new();
        sampler.output.samples = (0..MAX_SAMPLES)
            .map(|_| ExecutionSample {
                seconds: 0.0,
                retired: 0,
                delivered: 0,
                rip: 0,
            })
            .collect();
        sampler.record(0, 0, || panic!("sample limit must not read guest state"));
        assert!(sampler.finish().truncated);
    }
}
