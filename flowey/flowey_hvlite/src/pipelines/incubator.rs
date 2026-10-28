// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local standalone mshv provisioning, independent of VMM test discovery.

use anyhow::Context as _;
use flowey::node::prelude::ReadVar;
use flowey::pipeline::prelude::*;
use flowey_lib_hvlite::common::CommonProfile;
use std::path::Path;
use std::path::PathBuf;

#[derive(Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
enum Backend {
    #[default]
    Openvmm,
    QemuTcg,
}

/// Local overrides for public packages pending the ARM64 dependency release.
#[derive(clap::Args)]
pub(crate) struct MshvSupportArgs {
    /// Extracted public SBSA paired-flash package from openvmm-deps CI.
    #[arg(long)]
    mshv_sbsa_firmware: Option<PathBuf>,
    /// Extracted public ARM64 HvLoader package from openvmm-deps CI.
    #[arg(long)]
    mshv_hvloader: Option<PathBuf>,
}

impl MshvSupportArgs {
    pub(crate) fn requests(
        self,
    ) -> anyhow::Result<Vec<flowey_lib_hvlite::_jobs::cfg_versions::Request>> {
        use flowey_lib_hvlite::resolve_mshv_support::MshvSupport;
        [
            (MshvSupport::Sbsa, self.mshv_sbsa_firmware),
            (MshvSupport::Hvloader, self.mshv_hvloader),
        ]
        .into_iter()
        .filter_map(|(package, path)| path.map(|path| (package, path)))
        .map(|(package, path)| {
            anyhow::ensure!(
                path.is_dir(),
                "not an extracted support directory: {}",
                path.display()
            );
            Ok(
                flowey_lib_hvlite::_jobs::cfg_versions::Request::LocalMshvSupport(
                    package,
                    ReadVar::from_static(fs_canonicalize(&path)?),
                ),
            )
        })
        .collect()
    }
}

#[derive(clap::Args)]
pub struct IncubatorCli {
    /// Backend: OpenVMM/x64 with KVM, or QEMU-TCG/ARM64.
    #[arg(long, value_enum, default_value = "openvmm")]
    backend: Backend,

    #[command(flatten)]
    mshv_support: MshvSupportArgs,

    /// Override the mshv root kernel (x64 bzImage or ARM64 Image).
    #[arg(long)]
    kernel: Option<PathBuf>,

    /// Override the shared test initrd for the guest architecture.
    #[arg(long)]
    initrd: Option<PathBuf>,

    /// Override MSVM.fd (OpenVMM) or SBSA_FLASH0.fd (QEMU).
    #[arg(long)]
    firmware: Option<PathBuf>,

    /// Override the writable SBSA_FLASH1.fd template for QEMU.
    #[arg(long, requires = "firmware")]
    firmware_vars: Option<PathBuf>,

    /// Use authorized local payloads containing boot/ instead of pinned RPMs.
    #[arg(long, conflicts_with_all = ["rpm_cache", "offline"])]
    boot_artifacts: Option<PathBuf>,

    /// Override the persistent cache for the pinned hypervisor/loader RPMs.
    #[arg(long)]
    rpm_cache: Option<PathBuf>,

    /// Only use cached mshv RPMs; other build/dependency nodes are unaffected.
    #[arg(long)]
    offline: bool,

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
    #[arg(long, conflicts_with = "command")]
    prepare_only: bool,

    /// Release VMM, agent, and EFI builds (Incubator otherwise uses light).
    #[arg(long)]
    release: bool,

    /// Automatically install missing build dependencies.
    #[arg(long)]
    install_missing_deps: bool,

    /// Boot and guest-command deadline in seconds.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,

    /// Enable verbose Flowey output.
    #[arg(long)]
    verbose: bool,

    /// Non-interactive guest command and arguments, after `--`.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required_unless_present = "prepare_only"
    )]
    command: Vec<String>,
}

impl IntoPipeline for IncubatorCli {
    fn into_pipeline(self, backend_hint: PipelineBackendHint) -> anyhow::Result<Pipeline> {
        anyhow::ensure!(
            matches!(backend_hint, PipelineBackendHint::Local)
                && matches!(FlowPlatform::host(backend_hint), FlowPlatform::Linux(_)),
            "incubator provisioning requires a local Linux host"
        );
        let qemu_tcg = self.backend == Backend::QemuTcg;
        let host_arch = match FlowArch::host(backend_hint) {
            FlowArch::X86_64 => flowey_lib_hvlite::common::CommonArch::X86_64,
            FlowArch::Aarch64 => flowey_lib_hvlite::common::CommonArch::Aarch64,
            arch => anyhow::bail!("unsupported Incubator host architecture: {arch:?}"),
        };
        anyhow::ensure!(
            qemu_tcg || matches!(FlowArch::host(backend_hint), FlowArch::X86_64),
            "OpenVMM Incubator requires an x64 Linux host with KVM"
        );
        anyhow::ensure!(
            qemu_tcg || self.firmware_vars.is_none(),
            "--firmware-vars requires --backend qemu-tcg"
        );
        anyhow::ensure!(
            !qemu_tcg || (self.rpm_cache.is_none() && !self.offline),
            "RPM options are not valid for QEMU-TCG; ARM64 runtime inputs are local-only"
        );
        anyhow::ensure!(
            !qemu_tcg || self.firmware.is_some() == self.firmware_vars.is_some(),
            "QEMU firmware overrides require both --firmware and --firmware-vars"
        );
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
        if qemu_tcg {
            flowey_lib_hvlite::resolve_mshv_boot_artifacts::validate_arm64_inputs(
                boot_artifacts.as_deref().context("--backend qemu-tcg requires --boot-artifacts with user-provided ARM64 Hyper-V and lxhvloader.dll")?
            )?;
        }
        let support_requests = self.mshv_support.requests()?;
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
        let rpm_cache = self.rpm_cache.map(std::path::absolute).transpose()?;

        let mut pipeline = Pipeline::new();
        let mut job = pipeline
            .new_job(
                FlowPlatform::host(backend_hint),
                FlowArch::host(backend_hint),
                "provision and run standalone mshv Incubator",
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
                    qemu_tcg,
                    host_arch,
                    profile: CommonProfile::from_release(self.release),
                    kernel,
                    initrd,
                    firmware,
                    firmware_vars,
                    boot_artifacts,
                    rpm_cache,
                    offline: self.offline,
                    share,
                    dir,
                    kernel_cmdline: self.kernel_cmdline,
                    hypervisor_cmdline: self.hypervisor_cmdline,
                    prepare_only: self.prepare_only,
                    timeout: self.timeout,
                    command: self.command,
                    done: ctx.new_done_handle(),
                },
            );
        for request in support_requests {
            job = job.dep_on(move |_| request);
        }
        job.finish();
        Ok(pipeline)
    }
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
