// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local standalone Incubator provisioning, independent of VMM test discovery.

use anyhow::Context as _;
use flowey::node::prelude::ReadVar;
use flowey::pipeline::prelude::*;
use flowey_lib_hvlite::common::CommonArch;
use flowey_lib_hvlite::common::CommonProfile;
use flowey_lib_hvlite::common::CommonTriple;
use std::path::Path;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct IncubatorCli {
    /// Source OpenVMM Linux-direct/mshv or ARM64 QEMU mshv profile.
    #[arg(long)]
    profile: PathBuf,

    /// Native runner target. Windows targets require WSL; defaults to Linux.
    #[arg(long, value_enum)]
    target: Option<IncubatorTargetCli>,

    /// Override the pinned guest kernel (the root kernel for mshv boot).
    #[arg(long)]
    kernel: Option<PathBuf>,

    /// Override the pinned test initrd for the guest architecture.
    #[arg(long)]
    initrd: Option<PathBuf>,

    /// Override MSVM.fd (OpenVMM) or SBSA_FLASH0.fd (QEMU).
    #[arg(long)]
    firmware: Option<PathBuf>,

    /// Override SBSA_FLASH1.fd alongside --firmware for QEMU.
    #[arg(long, requires = "firmware")]
    firmware_vars: Option<PathBuf>,

    /// Use authorized local payloads containing boot/ (required for ARM64).
    #[arg(long)]
    boot_artifacts: Option<PathBuf>,

    /// Writable host share (defaults to the OpenVMM checkout).
    #[arg(long)]
    share: Option<PathBuf>,

    /// Provisioning/output directory beneath the share (default: target/incubator).
    #[arg(long)]
    dir: Option<PathBuf>,

    /// Override Linux options, excluding the required initrd entry point.
    #[arg(long)]
    kernel_cmdline: Option<String>,

    /// Override hypervisor options, excluding the loader DLL path.
    #[arg(long)]
    hypervisor_cmdline: Option<String>,

    /// Prepare dependencies/profile and print a direct command without booting.
    #[arg(long, conflicts_with = "incubator_args")]
    prepare_only: bool,

    /// Release VMM, agent, and EFI builds (Incubator otherwise uses light).
    #[arg(long)]
    release: bool,

    /// Automatically install missing build dependencies.
    #[arg(long)]
    install_missing_deps: bool,

    /// Enable verbose Flowey output.
    #[arg(long)]
    verbose: bool,

    /// Incubator options and guest command, after `--`.
    #[arg(last = true, required_unless_present = "prepare_only")]
    incubator_args: Vec<String>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum IncubatorTargetCli {
    LinuxX64,
    LinuxAarch64,
    WindowsX64,
    WindowsAarch64,
}

impl IncubatorTargetCli {
    fn triple(self) -> CommonTriple {
        match self {
            Self::LinuxX64 => CommonTriple::X86_64_LINUX_GNU,
            Self::LinuxAarch64 => CommonTriple::AARCH64_LINUX_GNU,
            Self::WindowsX64 => CommonTriple::X86_64_WINDOWS_MSVC,
            Self::WindowsAarch64 => CommonTriple::AARCH64_WINDOWS_MSVC,
        }
    }
}

impl IntoPipeline for IncubatorCli {
    fn into_pipeline(self, backend_hint: PipelineBackendHint) -> anyhow::Result<Pipeline> {
        let working_dir = std::env::current_dir().context("getting Incubator working directory")?;
        let source_profile = read_source_profile(&self.profile)?;
        let source =
            flowey_lib_hvlite::_jobs::local_run_incubator::parse_source_profile(&source_profile)?;
        let qemu_tcg = source["incubator"]["type"].as_str() == Some("qemu-tcg");
        let mshv = source["boot"]["type"].as_str() == Some("mshv");
        anyhow::ensure!(
            matches!(backend_hint, PipelineBackendHint::Local)
                && matches!(FlowPlatform::host(backend_hint), FlowPlatform::Linux(_)),
            "incubator provisioning requires a local Linux or WSL host"
        );
        let host_arch: CommonArch = FlowArch::host(backend_hint).try_into()?;
        let target = self
            .target
            .unwrap_or(match host_arch {
                CommonArch::X86_64 => IncubatorTargetCli::LinuxX64,
                CommonArch::Aarch64 => IncubatorTargetCli::LinuxAarch64,
            })
            .triple();
        let windows = matches!(
            target.as_triple().operating_system,
            target_lexicon::OperatingSystem::Windows
        );
        anyhow::ensure!(
            !windows || flowey_cli::running_in_wsl(),
            "Windows Incubator targets require provisioning from WSL"
        );
        anyhow::ensure!(
            !windows || !qemu_tcg,
            "QEMU TCG Incubator provisioning requires a Linux target"
        );
        anyhow::ensure!(
            target.common_arch()? == host_arch,
            "the Incubator target must match the native host architecture"
        );
        let guest_arch = match source["incubator"]["arch"].as_str() {
            Some("x86-64") => CommonArch::X86_64,
            Some("aarch64") => CommonArch::Aarch64,
            _ => unreachable!("source profile architecture was validated"),
        };
        anyhow::ensure!(
            qemu_tcg || target.common_arch()? == guest_arch,
            "the OpenVMM target must match the profile's guest architecture"
        );
        anyhow::ensure!(
            mshv || (self.firmware.is_none()
                && self.firmware_vars.is_none()
                && self.boot_artifacts.is_none()
                && self.kernel_cmdline.is_none()
                && self.hypervisor_cmdline.is_none()),
            "firmware, boot-artifact and boot command-line overrides require mshv boot"
        );
        anyhow::ensure!(
            if qemu_tcg {
                self.firmware.is_some() == self.firmware_vars.is_some()
            } else {
                self.firmware_vars.is_none()
            },
            "QEMU firmware overrides require both --firmware and --firmware-vars; OpenVMM does not use --firmware-vars"
        );
        if qemu_tcg {
            anyhow::ensure!(
                self.boot_artifacts.is_some(),
                "ARM64 MSHV requires --boot-artifacts with authorized Hyper-V and lxhvloader.dll"
            );
        }
        let kernel = self.kernel.as_deref().map(existing_file).transpose()?;
        let initrd = self.initrd.as_deref().map(existing_file).transpose()?;
        let firmware = self.firmware.as_deref().map(existing_file).transpose()?;
        let firmware_vars = self
            .firmware_vars
            .as_deref()
            .map(existing_file)
            .transpose()?;
        let boot_artifacts = self
            .boot_artifacts
            .map(|path| {
                anyhow::ensure!(path.is_dir(), "not a payload directory: {}", path.display());
                fs_canonicalize(&path)
            })
            .transpose()?;
        let share = fs_canonicalize(&self.share.unwrap_or_else(crate::repo_root))?;
        anyhow::ensure!(
            share.is_dir(),
            "share is not a directory: {}",
            share.display()
        );
        let dir = self.dir.unwrap_or_else(|| share.join("target/incubator"));
        std::fs::create_dir_all(&dir)?;
        let dir = fs_canonicalize(&dir)?;
        anyhow::ensure!(
            dir.starts_with(&share),
            "--dir must be beneath --share so the guest Pipette source is accessible"
        );

        let mut pipeline = Pipeline::new();
        pipeline
            .new_job(
                FlowPlatform::host(backend_hint),
                FlowArch::host(backend_hint),
                "provision and run standalone Incubator",
            )
            .dep_on(|_| flowey_lib_hvlite::_jobs::cfg_versions::Request::Init)
            .dep_on(
                |_| flowey_lib_hvlite::_jobs::cfg_hvlite_reposource::Params {
                    hvlite_repo_source: flowey_lib_common::git_checkout::RepoSource::ExistingClone(
                        ReadVar::from_static(crate::repo_root()),
                    ),
                },
            )
            .dep_on(|_| flowey_lib_hvlite::_jobs::cfg_common::Params {
                local_only: Some(flowey_lib_hvlite::_jobs::cfg_common::LocalOnlyParams {
                    interactive: true,
                    auto_install: self.install_missing_deps,
                    ignore_rust_version: true,
                }),
                verbose: ReadVar::from_static(self.verbose),
                locked: false,
                deny_warnings: false,
                no_incremental: false,
            })
            .dep_on(
                |ctx| flowey_lib_hvlite::_jobs::local_run_incubator::Params {
                    target,
                    profile: CommonProfile::from_release(self.release),
                    source_profile,
                    working_dir,
                    kernel,
                    initrd,
                    firmware,
                    firmware_vars,
                    boot_artifacts,
                    share,
                    dir,
                    kernel_cmdline: self.kernel_cmdline,
                    hypervisor_cmdline: self.hypervisor_cmdline,
                    prepare_only: self.prepare_only,
                    incubator_args: self.incubator_args,
                    done: ctx.new_done_handle(),
                },
            )
            .finish();
        Ok(pipeline)
    }
}

fn read_source_profile(path: &Path) -> anyhow::Result<String> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading Incubator profile {}", path.display()))?;
    flowey_lib_hvlite::_jobs::local_run_incubator::parse_source_profile(&contents)
        .with_context(|| format!("validating Incubator profile {}", path.display()))?;
    Ok(contents)
}

#[expect(
    clippy::disallowed_methods,
    reason = "resolve symlinks before enforcing containment within the host share"
)]
fn fs_canonicalize(path: &Path) -> anyhow::Result<PathBuf> {
    std::fs::canonicalize(path).with_context(|| format!("resolving {}", path.display()))
}

fn existing_file(path: &Path) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(path.is_file(), "not an input file: {}", path.display());
    fs_canonicalize(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use test_with_tracing::test;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        incubator: IncubatorCli,
    }

    #[test]
    fn preparation_needs_neither_a_kernel_override_nor_a_command() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["incubator", "--profile", "source.toml", "--prepare-only"])?;
        assert!(cli.incubator.prepare_only);
        assert!(cli.incubator.kernel.is_none());
        assert!(cli.incubator.incubator_args.is_empty());
        Ok(())
    }

    #[test]
    fn windows_target_is_separate_from_guest_arguments() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "incubator",
            "--profile",
            "source.toml",
            "--target",
            "windows-aarch64",
            "--",
            "--guest-env",
            "MESSAGE=hello world",
            "--",
            "/bin/sh",
            "-c",
            "printf '%s' \"$MESSAGE\"",
        ])?;
        assert!(matches!(
            cli.incubator.target,
            Some(IncubatorTargetCli::WindowsAarch64)
        ));
        assert_eq!(
            cli.incubator.incubator_args,
            [
                "--guest-env",
                "MESSAGE=hello world",
                "--",
                "/bin/sh",
                "-c",
                "printf '%s' \"$MESSAGE\"",
            ]
        );
        Ok(())
    }

    #[test]
    fn commands_preserve_shell_arguments_and_conflicting_modes_are_rejected() -> anyhow::Result<()>
    {
        let cli = Cli::try_parse_from([
            "incubator",
            "--profile",
            "source.toml",
            "--",
            "--timeout",
            "600",
            "--guest-env",
            "TEST=hello world",
            "--no-pty",
            "--",
            "/bin/sh",
            "-c",
            "exit 17",
        ])?;
        assert_eq!(
            cli.incubator.incubator_args,
            [
                "--timeout",
                "600",
                "--guest-env",
                "TEST=hello world",
                "--no-pty",
                "--",
                "/bin/sh",
                "-c",
                "exit 17"
            ]
        );
        for args in [
            vec!["incubator"],
            vec!["incubator", "--prepare-only"],
            vec!["incubator", "--profile", "source.toml", "--timeout", "600"],
            vec![
                "incubator",
                "--profile",
                "source.toml",
                "--prepare-only",
                "--",
                "/bin/sh",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        Ok(())
    }
}
