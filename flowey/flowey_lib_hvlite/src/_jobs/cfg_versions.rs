// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! An amalgamated configuration node that streamlines the process of resolving
//! version configuration requests required by various dependencies in OpenVMM
//! pipelines.

use flowey::node::prelude::*;
use flowey::pipeline::prelude::PipelineBackendHint;

// FUTURE: instead of hard-coding these values in-code, we might want to make
// our own nuget-esque `packages.config` file, that we can read at runtime to
// resolve all Version requests.
//
// This would require nodes that currently accept a `Version(String)` to accept
// a `Version(ReadVar<String>)`, but that shouldn't be a serious blocker.
pub const AZCOPY: &str = "10.27.1-20241113";
pub const AZURE_CLI: &str = "2.56.0";
pub const FUZZ: &str = "0.12.0";
pub const GH_CLI: &str = "2.52.0";
pub const LXUTIL: &str = "10.0.26100.1-240331-1435.ge-release";
pub const MDBOOK: &str = "0.4.40";
pub const MDBOOK_ADMONISH: &str = "1.18.0";
pub const MDBOOK_MERMAID: &str = "0.14.0";
pub const RUSTUP_TOOLCHAIN: &str = "1.86.0";
pub const MU_MSVM: &str = "24.0.4";
pub const NEXTEST: &str = "0.9.74";
pub const NODEJS: &str = "18.x";
// N.B. Kernel version numbers for dev and stable branches are not directly
//      comparable. They originate from separate branches, and the fourth digit
//      increases with each release from the respective branch.
pub const OPENHCL_KERNEL_DEV_VERSION: &str = "6.12.9.2";
pub const OPENHCL_KERNEL_STABLE_VERSION: &str = "6.12.9.2";
pub const OPENVMM_DEPS: &str = "0.1.0-20250403.3";
pub const PROTOC: &str = "27.1";

pub fn configure_versions(ctx: &mut ConfigCtx<'_>) {
    ctx.set_once(flowey_lib_common::download_protoc::Version(PROTOC.into()));

    ctx.set_once(crate::download_openhcl_kernel_package::Versions {
        dev: OPENHCL_KERNEL_DEV_VERSION.into(),
        main: OPENHCL_KERNEL_STABLE_VERSION.into(),
        cvm: OPENHCL_KERNEL_STABLE_VERSION.into(),
        cvm_dev: OPENHCL_KERNEL_DEV_VERSION.into(),
    });

    ctx.set_once(crate::download_lxutil::Version(LXUTIL.into()));
    ctx.set_once(crate::download_openvmm_deps::Version(OPENVMM_DEPS.into()));
    ctx.set_once(crate::download_uefi_mu_msvm::Version(MU_MSVM.into()));
    ctx.set_once(flowey_lib_common::download_azcopy::Version(AZCOPY.into()));
    ctx.set_once(flowey_lib_common::download_cargo_fuzz::Version(FUZZ.into()));
    ctx.set_once(flowey_lib_common::download_cargo_nextest::Version(
        NEXTEST.into(),
    ));
    ctx.set_once(flowey_lib_common::download_gh_cli::Version(GH_CLI.into()));
    ctx.set_once(flowey_lib_common::download_mdbook::Version(MDBOOK.into()));
    ctx.set_once(flowey_lib_common::download_mdbook_admonish::Version(
        MDBOOK_ADMONISH.into(),
    ));
    ctx.set_once(flowey_lib_common::download_mdbook_mermaid::Version(
        MDBOOK_MERMAID.into(),
    ));
    ctx.set_once(flowey_lib_common::install_azure_cli::Version(
        AZURE_CLI.into(),
    ));
    ctx.set_once(flowey_lib_common::install_nodejs::Version(NODEJS.into()));

    if !matches!(ctx.backend_hint(), PipelineBackendHint::Ado) {
        ctx.set_once(flowey_lib_common::install_rust::Version(
            RUSTUP_TOOLCHAIN.into(),
        ));
    }
}
