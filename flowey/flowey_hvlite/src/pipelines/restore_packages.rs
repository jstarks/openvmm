// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::pipelines_shared::cfg_common_params::CommonArchCli;
use crate::pipelines_shared::cfg_common_params::LocalRunArgs;
use flowey::node::prelude::ReadVar;
use flowey::pipeline::prelude::*;

/// Download and restore packages needed for building the specified architectures.
#[derive(clap::Args)]
pub struct RestorePackagesCli {
    /// Specify what architectures to restore packages for.
    ///
    /// If none are specified, defaults to just the current host architecture.
    arch: Vec<CommonArchCli>,
}

impl BuildPipeline for RestorePackagesCli {
    fn build_pipeline(self, pipeline: &mut Pipeline) -> anyhow::Result<()> {
        let openvmm_repo = flowey_lib_common::git_checkout::RepoSource::ExistingClone(
            ReadVar::from_static(crate::repo_root()),
        );

        let cfg_common_params = crate::pipelines_shared::cfg_common_params::get_cfg_common_params(
            pipeline,
            Some(LocalRunArgs {
                verbose: true,
                locked: false,
                auto_install_deps: true,
                non_interactive: false,
                force_nuget_mono: false,
                external_nuget_auth: false,
            }),
        )?;

        let backend_hint = pipeline.backend_hint();
        let mut job = pipeline
            .new_job(
                FlowPlatform::host(backend_hint),
                FlowArch::host(backend_hint),
                "restore packages",
            )
            .configure(cfg_common_params)
            .dep_on(
                |_| flowey_lib_hvlite::_jobs::cfg_hvlite_reposource::Params {
                    hvlite_repo_source: openvmm_repo,
                },
            );

        let arches = {
            if self.arch.is_empty() {
                vec![FlowArch::host(backend_hint).try_into()?]
            } else {
                self.arch
            }
        };

        for arch in arches {
            job = job.dep_on(
                |ctx| flowey_lib_hvlite::_jobs::local_restore_packages::Request {
                    arch: arch.into(),
                    done: ctx.new_done_handle(),
                },
            );
        }
        job.finish();
        Ok(())
    }
}
