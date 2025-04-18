// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build and run the `cargo test` based doc tests.
//!
//! `cargo-nextest` does not currently support running doctests, hence the need
//! for this separate job.

use crate::run_cargo_build::common::CommonProfile;
use flowey::node::prelude::*;

flowey_request! {
    pub struct Params {
        /// Build and run doc tests for the specified target
        pub target: target_lexicon::Triple,
        /// Build and run doc tests with the specified cargo profile
        pub profile: CommonProfile,
        pub done: WriteVar<SideEffect>,
    }
}

new_simple_flow_node!(struct Node);

impl SimpleFlowNode for Node {
    type Request = Params;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<crate::git_checkout_openvmm_repo::Node>();
        ctx.import::<crate::install_openvmm_rust_build_essential::Node>();
    }

    fn process_request(request: Self::Request, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let Params {
            target,
            profile,
            done,
        } = request;

        let rust_installed = ctx.reqv(crate::install_openvmm_rust_build_essential::Request);
        let openvmm_repo_path = ctx.reqv(crate::git_checkout_openvmm_repo::req::GetRepoDir);

        ctx.emit_rust_step_into(
            [done.discard_result()],
            format!("run doctests for {target}"),
            |ctx| {
                ctx.run_with(
                    (rust_installed, openvmm_repo_path),
                    move |_rt, (_rust_installed, openvmm_repo_path)| {
                        let sh = xshell::Shell::new()?;

                        let target = target.to_string();
                        let profile = match profile {
                            CommonProfile::Release => "release",
                            CommonProfile::Debug => "dev",
                        };

                        sh.change_dir(openvmm_repo_path);
                        xshell::cmd!(
                            sh,
                            "cargo test
                            --locked
                            --doc
                            --workspace
                            --no-fail-fast
                            --target {target}
                            --profile {profile}"
                        )
                        .run()?;

                        Ok(())
                    },
                )
            },
        );

        Ok(())
    }
}
