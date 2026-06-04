// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Standalone CLI for testing the hosting VM launcher.
//!
//! Usage:
//!   cargo run -p hosting_vm -- --profile <profile.toml> \
//!       --kernel <Image> --initrd <initrd> --share <dir> \
//!       -- <command>

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let mut profile_path = None;
    let mut kernel = None;
    let mut initrd = None;
    let mut share_dir = None;
    let mut timeout_secs: u64 = 1800;
    let mut guest_cmd_parts = Vec::new();
    let mut after_dashdash = false;

    let mut i = 1;
    while i < args.len() {
        if after_dashdash {
            guest_cmd_parts.push(args[i].clone());
            i += 1;
            continue;
        }
        match args[i].as_str() {
            "--" => {
                after_dashdash = true;
                i += 1;
            }
            "--profile" => {
                profile_path = Some(args.get(i + 1).expect("--profile requires a value").clone());
                i += 2;
            }
            "--kernel" => {
                kernel = Some(args.get(i + 1).expect("--kernel requires a value").clone());
                i += 2;
            }
            "--initrd" => {
                initrd = Some(args.get(i + 1).expect("--initrd requires a value").clone());
                i += 2;
            }
            "--share" => {
                share_dir = Some(args.get(i + 1).expect("--share requires a value").clone());
                i += 2;
            }
            "--timeout" => {
                timeout_secs = args
                    .get(i + 1)
                    .expect("--timeout requires a value")
                    .parse()
                    .expect("--timeout must be a number");
                i += 2;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                print_usage();
                std::process::exit(1);
            }
        }
    }

    let profile_path = profile_path.unwrap_or_else(|| {
        print_usage();
        std::process::exit(1);
    });
    let share_dir = share_dir.unwrap_or_else(|| {
        print_usage();
        std::process::exit(1);
    });

    if guest_cmd_parts.is_empty() {
        eprintln!("Error: command required after --");
        print_usage();
        std::process::exit(1);
    }

    let profile = hosting_vm::HostingVmProfile::from_file(std::path::Path::new(&profile_path))?;

    let kernel = kernel
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| find_aarch64_kernel().expect("could not find aarch64 kernel"));
    let initrd = initrd
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| find_aarch64_initrd().expect("could not find aarch64 initrd"));

    let guest_command = guest_cmd_parts.join(" ");

    eprintln!("Profile: {profile_path}");
    eprintln!("Kernel:  {}", kernel.display());
    eprintln!("Initrd:  {}", initrd.display());
    eprintln!("Share:   {share_dir}");
    eprintln!("Command: {guest_command}");
    eprintln!();

    let output = hosting_vm::run_in_hosting_vm(hosting_vm::HostingVmConfig {
        profile,
        kernel,
        initrd,
        share_dir: std::path::PathBuf::from(share_dir),
        guest_command,
        timeout: std::time::Duration::from_secs(timeout_secs),
    })?;

    eprintln!();
    eprintln!(
        "Completed in {:.1}s, exit code: {:?}",
        output.elapsed.as_secs_f64(),
        output.exit_code
    );

    std::process::exit(output.exit_code.unwrap_or(1));
}

fn print_usage() {
    eprintln!(
        "Usage: hosting-vm --profile <profile.toml> --share <dir> [--kernel <Image>] [--initrd <initrd>] [--timeout <secs>] -- <command...>"
    );
}

/// Search for an aarch64 kernel in the openvmm deps directory.
fn find_aarch64_kernel() -> Option<std::path::PathBuf> {
    find_in_deps("Image", "aarch64")
}

/// Search for an aarch64 initrd in the openvmm deps directory.
fn find_aarch64_initrd() -> Option<std::path::PathBuf> {
    find_in_deps("initrd", "aarch64")
}

fn find_in_deps(filename: &str, arch_filter: &str) -> Option<std::path::PathBuf> {
    // Walk up to find the repo root (look for Cargo.toml with [workspace])
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(contents) = std::fs::read_to_string(&cargo_toml) {
                if contents.contains("[workspace]") {
                    break;
                }
            }
        }
        if !dir.pop() {
            return None;
        }
    }

    // Search flowey-persist for the file
    let persist_dir = dir.join("flowey-persist");
    if !persist_dir.exists() {
        return None;
    }

    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    collect_files(&persist_dir, filename, arch_filter, &mut candidates);
    candidates.sort();
    candidates.pop() // latest by lexicographic order
}

fn collect_files(
    dir: &std::path::Path,
    filename: &str,
    arch_filter: &str,
    results: &mut Vec<std::path::PathBuf>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, filename, arch_filter, results);
        } else if path.file_name().is_some_and(|n| n == filename) {
            if path.to_string_lossy().contains(arch_filter) {
                results.push(path);
            }
        }
    }
}
