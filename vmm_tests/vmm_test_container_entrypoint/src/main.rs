// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Container entrypoint for running OpenVMM VMM tests.
//!
//! This binary is designed to run inside the `ghcr.io/microsoft/openvmm/vmm-tests`
//! container image. It sets up the test environment, downloads any missing VHD
//! disk images, and execs `cargo-nextest` to run the test archive.

#![forbid(unsafe_code)]

use anyhow::Context;
use clap::Parser;
use std::path::Path;
use std::path::PathBuf;
use vmm_test_images::KnownTestArtifacts;

/// Well-known paths inside the container image (set by the Dockerfile).
mod paths {
    pub const CONTENT_DIR: &str = "/opt/openvmm/bin";
    pub const NEXTEST_ARCHIVE: &str = "/opt/openvmm/vmm_tests.tar.zst";
    pub const NEXTEST_CONFIG: &str = "/opt/openvmm/nextest.toml";
    pub const CACHE_DIR: &str = "/cache";
    pub const RESULTS_DIR: &str = "/results";
    pub const IMAGES_DIR: &str = "/images";
}

const BLOB_STORE_BASE_URL: &str = "https://hvlitetestvhds.blob.core.windows.net/vhds";

#[derive(Parser)]
#[clap(
    name = "run-vmm-tests",
    about = "Run OpenVMM VMM tests inside a container"
)]
struct Args {
    /// Nextest profile to use.
    #[clap(long, default_value = "default")]
    profile: String,

    /// Nextest filter expression.
    #[clap(long)]
    filter: Option<String>,

    /// List available tests without running them.
    #[clap(long)]
    list: bool,

    /// Skip VHD download (assume images are already mounted).
    #[clap(long)]
    skip_download: bool,

    /// Extra arguments passed through directly to nextest.
    #[clap(last = true)]
    nextest_args: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    check_kvm();
    setup_directories()?;

    if !args.skip_download {
        download_vhds()?;
    }

    let env = setup_env()?;
    exec_nextest(&args, &env)
}

/// Warn if /dev/kvm is not accessible.
fn check_kvm() {
    let kvm = Path::new("/dev/kvm");
    if !kvm.exists() {
        eprintln!(
            "warning: /dev/kvm not found. Most tests require KVM.\n\
             Hint: run the container with --device=/dev/kvm"
        );
    }
}

/// Create output directories if they don't exist.
fn setup_directories() -> anyhow::Result<()> {
    fs_err::create_dir_all(paths::RESULTS_DIR).context("failed to create results directory")?;

    // Use /images if it's mounted, otherwise use /cache/images.
    let images_dir = images_dir();
    fs_err::create_dir_all(&images_dir).context("failed to create images directory")?;

    Ok(())
}

/// Determine where VHD images should be stored.
fn images_dir() -> PathBuf {
    let mounted = Path::new(paths::IMAGES_DIR);
    if mounted.exists() {
        mounted.to_path_buf()
    } else {
        PathBuf::from(paths::CACHE_DIR).join("images")
    }
}

/// Download missing VHDs from Azure Blob Storage.
fn download_vhds() -> anyhow::Result<()> {
    let dir = images_dir();

    let all_artifacts = [
        KnownTestArtifacts::Alpine323X64Vhd,
        KnownTestArtifacts::Alpine323Aarch64Vhd,
        KnownTestArtifacts::Gen1WindowsDataCenterCore2022X64Vhd,
        KnownTestArtifacts::Gen2WindowsDataCenterCore2022X64Vhd,
        KnownTestArtifacts::Gen2WindowsDataCenterCore2025X64Vhd,
        KnownTestArtifacts::FreeBsd13_2X64Vhd,
        KnownTestArtifacts::FreeBsd13_2X64Iso,
        KnownTestArtifacts::Ubuntu2404ServerX64Vhd,
        KnownTestArtifacts::Ubuntu2504ServerX64Vhd,
        KnownTestArtifacts::Ubuntu2404ServerAarch64Vhd,
        KnownTestArtifacts::Windows11EnterpriseAarch64Vhdx,
        KnownTestArtifacts::VmgsWithBootEntry,
        KnownTestArtifacts::VmgsWith16kTpm,
    ];

    for artifact in all_artifacts {
        let filename = artifact.filename();
        let expected_size = artifact.file_size();
        let dest = dir.join(filename);

        // Skip if already cached with correct size.
        if dest.exists() {
            let actual_size = fs_err::metadata(&dest)
                .with_context(|| format!("failed to stat {}", dest.display()))?
                .len();
            if actual_size == expected_size {
                eprintln!("[cached] {filename}");
                continue;
            }
            eprintln!(
                "[size mismatch] {filename}: expected {expected_size}, got {actual_size} — re-downloading"
            );
        }

        let url = format!("{BLOB_STORE_BASE_URL}/{filename}");
        eprintln!(
            "[downloading] {filename} ({} MB)",
            expected_size / 1_000_000
        );

        let status = std::process::Command::new("curl")
            .args(["-fSL", "--progress-bar", "-o"])
            .arg(&dest)
            .arg(&url)
            .status()
            .context("failed to execute curl")?;

        if !status.success() {
            // Clean up partial download.
            let _ = std::fs::remove_file(&dest);
            anyhow::bail!("failed to download {url}");
        }

        // Validate downloaded size.
        let actual_size = fs_err::metadata(&dest)
            .with_context(|| format!("failed to stat downloaded {}", dest.display()))?
            .len();
        if actual_size != expected_size {
            let _ = std::fs::remove_file(&dest);
            anyhow::bail!(
                "downloaded {filename} has wrong size: expected {expected_size}, got {actual_size}"
            );
        }
    }

    Ok(())
}

/// Set up environment variables for the test harness.
fn setup_env() -> anyhow::Result<Vec<(String, String)>> {
    let content_dir = paths::CONTENT_DIR;
    let images_dir = images_dir();
    let results_dir = paths::RESULTS_DIR;

    let env = vec![
        ("VMM_TESTS_CONTENT_DIR".into(), content_dir.into()),
        ("VMM_TEST_IMAGES".into(), images_dir.display().to_string()),
        ("TEST_OUTPUT_PATH".into(), results_dir.into()),
    ];

    // Log the environment for debugging.
    eprintln!("--- VMM test environment ---");
    for (key, value) in &env {
        eprintln!("  {key}={value}");
    }
    eprintln!("---");

    Ok(env)
}

/// Exec nextest with the test archive.
fn exec_nextest(args: &Args, env: &[(String, String)]) -> anyhow::Result<()> {
    let mut cmd = std::process::Command::new("cargo-nextest");
    cmd.arg("nextest");

    if args.list {
        cmd.arg("list");
    } else {
        cmd.arg("run");
    }

    cmd.args(["--archive-file", paths::NEXTEST_ARCHIVE]);
    cmd.args(["--config-file", paths::NEXTEST_CONFIG]);
    cmd.args(["--workspace-remap", "/opt/openvmm/workspace"]);
    cmd.args(["--profile", &args.profile]);

    if let Some(filter) = &args.filter {
        cmd.args(["--filter-expr", filter]);
    }

    // Passthrough args.
    for arg in &args.nextest_args {
        cmd.arg(arg);
    }

    // Set environment variables.
    for (key, value) in env {
        cmd.env(key, value);
    }

    let status = cmd.status().context("failed to execute cargo-nextest")?;
    std::process::exit(status.code().unwrap_or(1));
}
