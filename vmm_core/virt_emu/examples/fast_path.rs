// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Warm production fast paths with externally gated hardware counters.

// xtask-fmt allow-target-arch cpu-intrinsic -- Measures the native x86 WB provider.
#[cfg(all(guest_arch = "x86_64", target_arch = "x86_64"))]
mod native {
    use anyhow::{Context, Result, ensure};
    use std::fs::{File, OpenOptions};
    use std::io::{BufRead, BufReader, Write};

    struct Control {
        command: File,
        ack: BufReader<File>,
    }

    impl Control {
        fn set(&mut self, enabled: bool) -> Result<()> {
            self.command
                .write_all(if enabled { b"enable\n" } else { b"disable\n" })?;
            self.command.flush()?;
            let mut ack = String::new();
            self.ack.read_line(&mut ack)?;
            // perf versions may NUL-terminate the preceding acknowledgement.
            ensure!(
                ack.trim_start_matches('\0') == "ack\n",
                "unexpected perf control response: {ack:?}"
            );
            Ok(())
        }
    }

    pub fn run() -> Result<()> {
        let mut args = std::env::args_os().skip(1);
        let case = args
            .next()
            .context("missing decode/fetch/read/write case")?
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 case"))?;
        let operations = args
            .next()
            .context("missing operation count")?
            .to_str()
            .context("non-UTF8 count")?
            .parse::<u64>()?;
        let mut control = match args.next() {
            Some(command) => {
                let ack = args.next().context("missing perf acknowledgement FIFO")?;
                Some(Control {
                    command: OpenOptions::new().write(true).open(command)?,
                    ack: BufReader::new(File::open(ack)?),
                })
            }
            None => None,
        };
        ensure!(args.next().is_none(), "unexpected arguments");
        let result = virt_emu::backend::perf::fast_path(&case, operations, |enabled| {
            if let Some(control) = &mut control {
                control.set(enabled)?;
            }
            Ok(())
        })?;
        println!(
            "{}",
            serde_json::json!({
                "case":case,"operations":result.operations,"seconds":result.seconds,
                "ns_per_operation":result.seconds * 1e9 / result.operations as f64,
                "warm":true,"setup_included":false,
                "scope":if case=="decode" {"cached decoder lookup"} else {"TLB hit plus native qword transport"},
                "physical_effects_per_operation":match case.as_str() {"decode"=>0,"write"=>2,_=>1},
            })
        );
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    // xtask-fmt allow-target-arch cpu-intrinsic -- Measures the native x86 WB provider.
    #[cfg(all(guest_arch = "x86_64", target_arch = "x86_64"))]
    return native::run();
    // xtask-fmt allow-target-arch cpu-intrinsic -- Other host lowerings are not available.
    #[cfg(not(all(guest_arch = "x86_64", target_arch = "x86_64")))]
    anyhow::bail!("fast-path measurement requires an x86-64 host and guest")
}
