// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared logic to set cfg_common params across various backends

use flowey::node::prelude::*;
use flowey::pipeline::prelude::*;
use flowey_lib_hvlite::run_cargo_build::common::CommonArch;

#[derive(Clone, Default, clap::Args)]
#[clap(next_help_heading = "Local Only")]
pub struct LocalRunArgs {
    /// Emit verbose output when possible
    #[clap(long)]
    pub verbose: bool,

    /// Run builds with --locked
    #[clap(long)]
    pub locked: bool,

    /// Automatically install all required dependencies
    #[clap(long)]
    pub auto_install_deps: bool,

    /// Don't prompt user when running certain interactive commands.
    #[clap(long)]
    pub non_interactive: bool,

    /// (WSL2 only) Force the use of `mono` to download nuget packages.
    #[clap(long)]
    pub force_nuget_mono: bool,

    /// Claim that nuget is using an external auth mechanism.
    ///
    /// This will skip the check to make sure Azure Credential Provider is
    /// installed.
    #[clap(long)]
    pub external_nuget_auth: bool,
}

pub type FulfillCommonRequestsParamsResolver = Box<dyn for<'a> Fn(&mut ConfigCtx<'a>)>;

fn get_params_local(
    local_run_args: Option<LocalRunArgs>,
) -> anyhow::Result<FulfillCommonRequestsParamsResolver> {
    Ok(Box::new(move |ctx| {
        let LocalRunArgs {
            verbose,
            locked,
            auto_install_deps,
            non_interactive,
            force_nuget_mono,
            external_nuget_auth,
        } = local_run_args.clone().unwrap_or_default();

        ctx.set_once(flowey_lib_common::_config::Interactive(!non_interactive));
        ctx.set_once(flowey_lib_common::_config::AutoInstall(auto_install_deps));
        ctx.set_once(flowey_lib_common::_config::Verbose(ReadVar::from_static(
            verbose,
        )));
        ctx.set_once(flowey_lib_common::_config::PackagesLocked(locked));

        ctx.set_once(flowey_lib_common::install_rust::IgnoreVersion(true));

        ctx.set_once(
            flowey_lib_common::install_nuget_azure_credential_provider::LocalOnlySkipAuthCheck(
                external_nuget_auth,
            ),
        );
        ctx.set_once(
            flowey_lib_common::download_nuget_exe::LocalOnlyForceWsl2MonoNugetExe(force_nuget_mono),
        );
        ctx.set_once(flowey_lib_common::git_checkout::LocalOnlyRequireExistingClones(true));

        ctx.set_once(
            flowey_lib_hvlite::init_openvmm_cargo_config_deny_warnings::DenyWarnings(false),
        );

        flowey_lib_hvlite::_jobs::cfg_versions::configure_versions(ctx);
    }))
}

fn get_params_cloud(
    pipeline: &mut Pipeline,
) -> anyhow::Result<FulfillCommonRequestsParamsResolver> {
    let param_verbose = pipeline.new_parameter_bool(
        "verbose",
        "Run with verbose output",
        ParameterKind::Stable,
        Some(false),
    );

    Ok(Box::new(move |ctx| {
        ctx.set_once(flowey_lib_common::_config::Interactive(false));
        ctx.set_once(flowey_lib_common::_config::AutoInstall(true));
        let verbose = ctx.use_parameter(param_verbose.clone());
        ctx.set_once(flowey_lib_common::_config::Verbose(verbose));
        ctx.set_once(flowey_lib_common::_config::PackagesLocked(true));
        ctx.set_once(flowey_lib_common::install_rust::IgnoreVersion(false));

        ctx.set_once(
            flowey_lib_hvlite::init_openvmm_cargo_config_deny_warnings::DenyWarnings(true),
        );

        flowey_lib_hvlite::_jobs::cfg_versions::configure_versions(ctx);
    }))
}

pub fn get_cfg_common_params(
    pipeline: &mut Pipeline,
    local_run_args: Option<LocalRunArgs>,
) -> anyhow::Result<FulfillCommonRequestsParamsResolver> {
    match pipeline.backend_hint() {
        PipelineBackendHint::Local => get_params_local(local_run_args),
        PipelineBackendHint::Ado | PipelineBackendHint::Github => {
            if local_run_args.is_some() {
                anyhow::bail!("cannot set local only params when emitting as non-local pipeline")
            }
            get_params_cloud(pipeline)
        }
    }
}

#[derive(clap::ValueEnum, Clone, Copy)]
pub enum CommonArchCli {
    X86_64,
    Aarch64,
}

impl From<CommonArchCli> for CommonArch {
    fn from(value: CommonArchCli) -> Self {
        match value {
            CommonArchCli::X86_64 => CommonArch::X86_64,
            CommonArchCli::Aarch64 => CommonArch::Aarch64,
        }
    }
}

impl TryFrom<FlowArch> for CommonArchCli {
    type Error = anyhow::Error;

    fn try_from(arch: FlowArch) -> anyhow::Result<Self> {
        Ok(match arch {
            FlowArch::X86_64 => CommonArchCli::X86_64,
            FlowArch::Aarch64 => CommonArchCli::Aarch64,
            arch => anyhow::bail!("unsupported arch {arch}"),
        })
    }
}
