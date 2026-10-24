// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local standalone mshv provisioning, independent of VMM test discovery.

use anyhow::Context as _;
use flowey::node::prelude::ReadVar;
use flowey::pipeline::prelude::*;
use flowey_lib_hvlite::common::CommonProfile;
use std::path::Path;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct IncubatorCli {
    /// Root bzImage with mshv EFI-launch support, not the child VM's kernel.
    ///
    /// Required until the minimal mshv-test openvmm-deps kernel is published.
    #[arg(long)]
    kernel: PathBuf,

    /// Override the pinned shared x64 test initrd.
    #[arg(long)]
    initrd: Option<PathBuf>,

    /// Override the pinned x64 MSVM.fd firmware.
    #[arg(long)]
    firmware: Option<PathBuf>,

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
                && matches!(FlowPlatform::host(backend_hint), FlowPlatform::Linux(_))
                && matches!(FlowArch::host(backend_hint), FlowArch::X86_64),
            "incubator provisioning currently requires a local x64 Linux host with KVM"
        );
        let kernel = existing_file(&self.kernel)?;
        let initrd = self.initrd.as_deref().map(existing_file).transpose()?;
        let firmware = self.firmware.as_deref().map(existing_file).transpose()?;
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
        let rpm_cache = self.rpm_cache.map(std::path::absolute).transpose()?;

        let mut pipeline = Pipeline::new();
        pipeline
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
                    profile: CommonProfile::from_release(self.release),
                    kernel,
                    initrd,
                    firmware,
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
            )
            .finish();
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
