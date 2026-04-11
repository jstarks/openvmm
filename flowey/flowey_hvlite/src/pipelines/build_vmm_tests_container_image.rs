// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! See [`BuildVmmTestsContainerImageCli`]

use flowey::node::prelude::ReadVar;
use flowey::pipeline::prelude::*;
use flowey_lib_hvlite::run_cargo_build::common::CommonArch;
use flowey_lib_hvlite::run_cargo_build::common::CommonPlatform;
use flowey_lib_hvlite::run_cargo_build::common::CommonProfile;
use flowey_lib_hvlite::run_cargo_build::common::CommonTriple;

/// Build the VMM tests container image locally. DO NOT USE IN CI.
#[derive(clap::Args)]
pub struct BuildVmmTestsContainerImageCli {
    /// Build in release mode.
    #[clap(long)]
    release: bool,

    /// Target architecture (defaults to host).
    #[clap(long, value_enum, default_value_t = ContainerArch::X86_64)]
    arch: ContainerArch,

    /// Automatically install missing build dependencies.
    #[clap(long)]
    install_missing_deps: bool,
}

#[derive(clap::ValueEnum, Copy, Clone)]
enum ContainerArch {
    X86_64,
    Aarch64,
}

impl IntoPipeline for BuildVmmTestsContainerImageCli {
    fn into_pipeline(self, backend_hint: PipelineBackendHint) -> anyhow::Result<Pipeline> {
        if !matches!(backend_hint, PipelineBackendHint::Local) {
            anyhow::bail!("build-vmm-tests-container-image is for local use only")
        }

        let Self {
            release,
            arch,
            install_missing_deps,
        } = self;

        let arch = match arch {
            ContainerArch::X86_64 => CommonArch::X86_64,
            ContainerArch::Aarch64 => CommonArch::Aarch64,
        };

        let _openvmm_repo = flowey_lib_common::git_checkout::RepoSource::ExistingClone(
            ReadVar::from_static(crate::repo_root()),
        );

        let mut pipeline = Pipeline::new();

        let linux_target = CommonTriple::Common {
            arch,
            platform: CommonPlatform::LinuxGnu,
        };
        let musl_target = CommonTriple::Common {
            arch,
            platform: CommonPlatform::LinuxMusl,
        };
        let profile = CommonProfile::from_release(release);

        // Create all typed artifacts upfront (pipeline borrows prevent
        // interleaving new_typed_artifact with dep_on).
        let (pub_openvmm, use_openvmm) = pipeline.new_typed_artifact("openvmm");
        let (pub_openvmm_vhost, use_openvmm_vhost) = pipeline.new_typed_artifact("openvmm_vhost");
        let (pub_pipette, use_pipette) = pipeline.new_typed_artifact("pipette");
        let (pub_pipette_windows, use_pipette_windows) =
            pipeline.new_typed_artifact("pipette_windows");
        let (pub_tmk_vmm, use_tmk_vmm) = pipeline.new_typed_artifact("tmk_vmm");
        let (pub_tmks, use_tmks) = pipeline.new_typed_artifact("tmks");
        let (pub_vmgstool, use_vmgstool) = pipeline.new_typed_artifact("vmgstool");
        let (pub_guest_test_uefi, use_guest_test_uefi) =
            pipeline.new_typed_artifact("guest_test_uefi");
        let (pub_nextest_archive, use_nextest_archive) =
            pipeline.new_typed_artifact("nextest_archive");
        let (pub_entrypoint, use_entrypoint) = pipeline.new_typed_artifact("entrypoint");

        let _openvmm_repo = flowey_lib_common::git_checkout::RepoSource::ExistingClone(
            ReadVar::from_static(crate::repo_root()),
        );

        // Build job: compile everything
        pipeline
            .new_job(
                FlowPlatform::host(backend_hint),
                FlowArch::host(backend_hint),
                "build artifacts",
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
                    auto_install: install_missing_deps,
                    ignore_rust_version: true,
                }),
                verbose: ReadVar::from_static(false),
                locked: false,
                deny_warnings: false,
                no_incremental: false,
            })
            .dep_on(|ctx| flowey_lib_hvlite::build_openvmm::Request {
                params: flowey_lib_hvlite::build_openvmm::OpenvmmBuildParams {
                    target: linux_target.clone(),
                    profile,
                    features: [flowey_lib_hvlite::build_openvmm::OpenvmmFeature::Tpm].into(),
                },
                openvmm: ctx.publish_typed_artifact(pub_openvmm),
            })
            .dep_on(|ctx| flowey_lib_hvlite::build_openvmm_vhost::Request {
                params: flowey_lib_hvlite::build_openvmm_vhost::OpenvmmVhostBuildParams {
                    target: linux_target.clone(),
                    profile,
                },
                openvmm_vhost: ctx.publish_typed_artifact(pub_openvmm_vhost),
            })
            .dep_on(|ctx| flowey_lib_hvlite::build_pipette::Request {
                target: musl_target.clone(),
                profile,
                pipette: ctx.publish_typed_artifact(pub_pipette),
            })
            .dep_on(|ctx| flowey_lib_hvlite::build_pipette::Request {
                target: CommonTriple::Common {
                    arch,
                    platform: CommonPlatform::WindowsMsvc,
                },
                profile,
                pipette: ctx.publish_typed_artifact(pub_pipette_windows),
            })
            .dep_on(|ctx| flowey_lib_hvlite::build_tmk_vmm::Request {
                target: musl_target.clone(),
                profile,
                unstable_whp: false,
                tmk_vmm: ctx.publish_typed_artifact(pub_tmk_vmm),
            })
            .dep_on(|ctx| flowey_lib_hvlite::build_tmks::Request {
                arch,
                profile,
                tmks: ctx.publish_typed_artifact(pub_tmks),
            })
            .dep_on(|ctx| flowey_lib_hvlite::build_vmgstool::Request {
                target: linux_target.clone(),
                profile,
                with_crypto: true,
                with_test_helpers: true,
                vmgstool: ctx.publish_typed_artifact(pub_vmgstool),
            })
            .dep_on(|ctx| flowey_lib_hvlite::build_guest_test_uefi::Request {
                arch,
                profile,
                guest_test_uefi: ctx.publish_typed_artifact(pub_guest_test_uefi),
            })
            .dep_on(|ctx| flowey_lib_hvlite::build_nextest_vmm_tests::Request {
                target: linux_target.clone().as_triple(),
                profile,
                build_mode:
                    flowey_lib_hvlite::build_nextest_vmm_tests::BuildNextestVmmTestsMode::Archive(
                        ctx.publish_typed_artifact(pub_nextest_archive),
                    ),
            })
            .dep_on(
                |ctx| flowey_lib_hvlite::build_vmm_test_container_entrypoint::Request {
                    target: linux_target.clone(),
                    profile,
                    entrypoint: ctx.publish_typed_artifact(pub_entrypoint),
                },
            )
            .finish();

        // Container image job: assemble and build
        pipeline
            .new_job(
                FlowPlatform::host(backend_hint),
                FlowArch::host(backend_hint),
                "build container image",
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
                    auto_install: install_missing_deps,
                    ignore_rust_version: true,
                }),
                verbose: ReadVar::from_static(false),
                locked: false,
                deny_warnings: false,
                no_incremental: false,
            })
            .dep_on(|ctx| {
                flowey_lib_hvlite::_jobs::build_and_publish_vmm_tests_container_image::Params {
                    push: false,
                    arch,
                    nextest_archive: ctx.use_typed_artifact(&use_nextest_archive),
                    openvmm: ctx.use_typed_artifact(&use_openvmm),
                    openvmm_vhost: Some(ctx.use_typed_artifact(&use_openvmm_vhost)),
                    pipette_linux: ctx.use_typed_artifact(&use_pipette),
                    pipette_windows: Some(ctx.use_typed_artifact(&use_pipette_windows)),
                    tmk_vmm: Some(ctx.use_typed_artifact(&use_tmk_vmm)),
                    tmks: Some(ctx.use_typed_artifact(&use_tmks)),
                    vmgstool: Some(ctx.use_typed_artifact(&use_vmgstool)),
                    guest_test_uefi: Some(ctx.use_typed_artifact(&use_guest_test_uefi)),
                    openhcl_igvm_files: None,
                    entrypoint_bin: ctx.use_typed_artifact(&use_entrypoint),
                    done: ctx.new_done_handle(),
                }
            })
            .finish();

        Ok(pipeline)
    }
}
