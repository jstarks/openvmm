// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! An amalgamated configuration node that streamlines the process of resolving
//! the most common subset of shared configuration requests required by OpenVMM
//! pipelines.

use flowey::node::prelude::*;

flowey_config! {
    #[derive(Clone)]
    pub struct LocalOnlyParams {
        /// Prompt the user before certain interesting operations (e.g:
        /// installing packages from apt)
        pub interactive: bool,
        /// Automatically install any necessary system dependencies / tools.
        pub auto_install: bool,
        /// (WSL2 only) Use `mono` to run `nuget.exe`, instead of using native
        /// WSL2 interop.
        pub force_nuget_mono: bool,
        /// Claim that nuget is using an external auth mechanism, and Azure
        /// Credential Provider doesn't need to be present to pull down required
        /// packages.
        pub external_nuget_auth: bool,
        /// Ignore the Rust version requirement, and use whatever toolchain the user
        /// currently has installed.
        pub ignore_rust_version: bool,
    }
}

flowey_request! {
    #[derive(Clone)]
    pub struct Params {
        pub deny_warnings: bool,
    }
}

new_simple_flow_node!(struct Node);

impl SimpleFlowNode for Node {
    type Request = Params;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<crate::download_lxutil::Node>();
        ctx.import::<crate::download_openhcl_kernel_package::Node>();
        ctx.import::<crate::download_openvmm_deps::Node>();
        ctx.import::<crate::download_uefi_mu_msvm::Node>();
        ctx.import::<crate::git_checkout_openvmm_repo::Node>();
        ctx.import::<crate::init_openvmm_cargo_config_deny_warnings::Node>();
        ctx.import::<crate::install_git_credential_manager::Node>();
        ctx.import::<crate::install_openvmm_rust_build_essential::Node>();
        ctx.import::<flowey_lib_common::download_azcopy::Node>();
        ctx.import::<flowey_lib_common::download_cargo_nextest::Node>();
        ctx.import::<flowey_lib_common::download_nuget_exe::Node>();
        ctx.import::<flowey_lib_common::download_protoc::Node>();
        ctx.import::<flowey_lib_common::git_checkout::Node>();
        ctx.import::<flowey_lib_common::install_dist_pkg::Node>();
        ctx.import::<flowey_lib_common::install_azure_cli::Node>();
        ctx.import::<flowey_lib_common::install_git::Node>();
        ctx.import::<flowey_lib_common::install_nodejs::Node>();
        ctx.import::<flowey_lib_common::install_nuget_azure_credential_provider::Node>();
        ctx.import::<flowey_lib_common::install_rust::Node>();
        ctx.import::<flowey_lib_common::nuget_install_package::Node>();
        ctx.import::<flowey_lib_common::run_cargo_nextest_run::Node>();
        ctx.import::<flowey_lib_common::use_gh_cli::Node>();
    }

    fn process_request(request: Self::Request, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let Params { deny_warnings } = request;

        if matches!(ctx.backend(), FlowBackend::Github) {
        } else if matches!(ctx.backend(), FlowBackend::Ado) {
        } else if matches!(ctx.backend(), FlowBackend::Local) {
            let local_only = ctx
                .try_config::<LocalOnlyParams>()
                .ok_or(anyhow::anyhow!("missing essential config: LocalOnlyParams"))?;

            let LocalOnlyParams {
                interactive: _,
                auto_install,
                force_nuget_mono,
                external_nuget_auth,
                ignore_rust_version: _,
            } = *local_only;

            // wire up `interactive`
            {}

            //
            // wire up misc.
            //

            // FUTURE: if we ever spin up a openvmm setup utility - it might be
            // interesting to distribute a flowey-based tool that also clones
            // the repo.
        } else {
            anyhow::bail!("unsupported backend")
        }

        ctx.req(
            crate::init_openvmm_cargo_config_deny_warnings::Request::DenyWarnings(deny_warnings),
        );

        Ok(())
    }
}
