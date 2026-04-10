// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build and optionally publish the VMM tests container image.
//!
//! This job assembles a Docker build context from pre-built artifacts, then
//! invokes `docker buildx build` to produce a container image for running
//! VMM tests on arbitrary Linux hosts.
//!
//! The Dockerfile is embedded from
//! `flowey_lib_hvlite/src/build_vmm_tests_container_image/Dockerfile`.

use crate::build_nextest_vmm_tests::NextestVmmTestsArchive;
use crate::build_openvmm::OpenvmmOutput;
use crate::build_openvmm_vhost::OpenvmmVhostOutput;
use crate::build_pipette::PipetteOutput;
use crate::build_tmk_vmm::TmkVmmOutput;
use crate::build_tmks::TmksOutput;
use crate::build_vmgstool::VmgstoolOutput;
use crate::build_vmm_test_container_entrypoint::VmmTestContainerEntrypointOutput;
use crate::run_cargo_build::common::CommonArch;
use flowey::node::prelude::*;

const DOCKERFILE: &str = include_str!("../build_vmm_tests_container_image/Dockerfile");

flowey_request! {
    pub struct Params {
        /// Whether to push the image to the registry after building.
        pub push: bool,

        /// Target architecture for the container image.
        pub arch: CommonArch,

        /// The nextest VMM tests archive.
        pub nextest_archive: ReadVar<NextestVmmTestsArchive>,

        /// The openvmm binary (Linux).
        pub openvmm: ReadVar<OpenvmmOutput>,

        /// The openvmm_vhost binary (Linux).
        pub openvmm_vhost: Option<ReadVar<OpenvmmVhostOutput>>,

        /// The pipette binary (Linux musl).
        pub pipette_linux: ReadVar<PipetteOutput>,

        /// The TMK VMM binary (Linux).
        pub tmk_vmm: Option<ReadVar<TmkVmmOutput>>,

        /// The TMK binaries.
        pub tmks: Option<ReadVar<TmksOutput>>,

        /// The vmgstool binary (Linux).
        pub vmgstool: Option<ReadVar<VmgstoolOutput>>,

        /// The guest_test_uefi image.
        pub guest_test_uefi: Option<ReadVar<crate::build_guest_test_uefi::GuestTestUefiOutput>>,

        /// OpenHCL IGVM files.
        pub openhcl_igvm_files: Option<
            ReadVar<
                Vec<(
                    crate::build_openhcl_igvm_from_recipe::OpenhclIgvmRecipe,
                    crate::run_igvmfilegen::IgvmOutput,
                )>,
            >,
        >,

        /// The entrypoint binary (vmm_test_container_entrypoint), pre-built.
        pub entrypoint_bin: ReadVar<VmmTestContainerEntrypointOutput>,

        /// Completion signal.
        pub done: WriteVar<SideEffect>,
    }
}

new_simple_flow_node!(struct Node);

impl SimpleFlowNode for Node {
    type Request = Params;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<crate::git_checkout_openvmm_repo::Node>();
    }

    fn process_request(request: Self::Request, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let Params {
            push,
            arch,
            nextest_archive,
            openvmm,
            openvmm_vhost,
            pipette_linux,
            tmk_vmm,
            tmks,
            vmgstool,
            guest_test_uefi,
            openhcl_igvm_files,
            entrypoint_bin,
            done,
        } = request;

        // Get the nextest config from the repo checkout.
        let repo_dir = ctx.reqv(crate::git_checkout_openvmm_repo::req::GetRepoDir);

        // Read branch name from GH context (only available on GitHub backend).
        let branch_name = matches!(ctx.backend(), FlowBackend::Github)
            .then(|| ctx.get_gh_context_var().global().ref_name());

        // Only push on GitHub — local builds just --load.
        let push = push && matches!(ctx.backend(), FlowBackend::Github);

        ctx.emit_rust_step("build vmm-tests container image", |ctx| {
            done.claim(ctx);
            let nextest_archive = nextest_archive.claim(ctx);
            let branch_name = branch_name.claim(ctx);
            let openvmm = openvmm.claim(ctx);
            let openvmm_vhost = openvmm_vhost.claim(ctx);
            let pipette_linux = pipette_linux.claim(ctx);
            let tmk_vmm = tmk_vmm.claim(ctx);
            let tmks = tmks.claim(ctx);
            let vmgstool = vmgstool.claim(ctx);
            let guest_test_uefi = guest_test_uefi.claim(ctx);
            let openhcl_igvm_files = openhcl_igvm_files.claim(ctx);
            let entrypoint_bin = entrypoint_bin.claim(ctx);
            let repo_dir = repo_dir.claim(ctx);
            move |rt| {
                // --- Set up build context directory ---
                let context_dir = rt.sh.current_dir().absolute()?.join("docker-context");
                let bin_dir = context_dir.join("artifacts").join("bin");
                let artifacts_dir = context_dir.join("artifacts");
                fs_err::create_dir_all(&bin_dir)?;

                // Write the Dockerfile
                fs_err::write(context_dir.join("Dockerfile"), DOCKERFILE)?;

                // Copy nextest archive
                let archive = rt.read(nextest_archive);
                fs_err::copy(
                    &archive.archive_file,
                    artifacts_dir.join("vmm_tests.tar.zst"),
                )?;

                // Copy nextest config from repo
                let repo_dir: PathBuf = rt.read(repo_dir);
                fs_err::copy(
                    repo_dir.join(".config").join("nextest.toml"),
                    artifacts_dir.join("nextest.toml"),
                )?;

                // Copy entrypoint binary
                let entrypoint = rt.read(entrypoint_bin);
                let entrypoint_dst = context_dir.join("run-vmm-tests");
                fs_err::copy(&entrypoint.bin, &entrypoint_dst)?;
                entrypoint_dst.make_executable()?;

                // Copy openvmm binary
                match rt.read(openvmm) {
                    OpenvmmOutput::LinuxBin { bin, dbg: _ } => {
                        fs_err::copy(bin, bin_dir.join("openvmm"))?;
                    }
                    OpenvmmOutput::WindowsBin { .. } => {
                        anyhow::bail!("container image requires Linux openvmm binary");
                    }
                }

                // Copy openvmm_vhost
                if let Some(openvmm_vhost) = openvmm_vhost {
                    let OpenvmmVhostOutput { bin, dbg: _ } = rt.read(openvmm_vhost);
                    fs_err::copy(bin, bin_dir.join("openvmm_vhost"))?;
                }

                // Copy pipette
                match rt.read(pipette_linux) {
                    PipetteOutput::LinuxBin { bin, dbg: _ } => {
                        fs_err::copy(bin, bin_dir.join("pipette"))?;
                    }
                    _ => {
                        anyhow::bail!("container image requires Linux pipette binary");
                    }
                }

                // Copy tmk_vmm
                if let Some(tmk_vmm) = tmk_vmm {
                    match rt.read(tmk_vmm) {
                        TmkVmmOutput::LinuxBin { bin, dbg: _ } => {
                            fs_err::copy(bin, bin_dir.join("tmk_vmm"))?;
                        }
                        TmkVmmOutput::WindowsBin { .. } => {
                            anyhow::bail!("container image requires Linux tmk_vmm binary");
                        }
                    }
                }

                // Copy tmks
                if let Some(tmks) = tmks {
                    let TmksOutput { bin, dbg: _ } = rt.read(tmks);
                    fs_err::copy(bin, bin_dir.join("simple_tmk"))?;
                }

                // Copy vmgstool
                if let Some(vmgstool) = vmgstool {
                    match rt.read(vmgstool) {
                        VmgstoolOutput::LinuxBin { bin, dbg: _ } => {
                            fs_err::copy(bin, bin_dir.join("vmgstool"))?;
                        }
                        VmgstoolOutput::WindowsBin { .. } => {
                            anyhow::bail!("container image requires Linux vmgstool binary");
                        }
                    }
                }

                // Copy guest_test_uefi
                if let Some(guest_test_uefi) = guest_test_uefi {
                    let output = rt.read(guest_test_uefi);
                    fs_err::copy(output.img, bin_dir.join("guest_test_uefi.img"))?;
                }

                // Copy OpenHCL IGVM files
                if let Some(openhcl_igvm_files) = openhcl_igvm_files {
                    for (recipe, igvm) in rt.read(openhcl_igvm_files) {
                        use crate::build_openhcl_igvm_from_recipe::OpenhclIgvmRecipe;
                        let filename = match recipe {
                            OpenhclIgvmRecipe::X64 => "openhcl-x64.bin",
                            OpenhclIgvmRecipe::X64Devkern => "openhcl-x64-devkern.bin",
                            OpenhclIgvmRecipe::X64Cvm => "openhcl-x64-cvm.bin",
                            OpenhclIgvmRecipe::X64TestLinuxDirect => {
                                "openhcl-x64-test-linux-direct.bin"
                            }
                            OpenhclIgvmRecipe::Aarch64 => "openhcl-aarch64.bin",
                            OpenhclIgvmRecipe::Aarch64Devkern => "openhcl-aarch64-devkern.bin",
                            _ => continue,
                        };
                        fs_err::copy(igvm.igvm_bin, bin_dir.join(filename))?;
                    }
                }

                // --- Build the container image ---
                let nextest_version = crate::_jobs::cfg_versions::NEXTEST;
                let openvmm_deps_version = crate::_jobs::cfg_versions::OPENVMM_DEPS;
                let mu_msvm_version = crate::_jobs::cfg_versions::MU_MSVM;

                let (rust_arch, uefi_arch) = match arch {
                    CommonArch::X86_64 => ("x86_64", "X64"),
                    CommonArch::Aarch64 => ("aarch64", "AARCH64"),
                };

                let arch_tag = match arch {
                    CommonArch::X86_64 => "x64",
                    CommonArch::Aarch64 => "aarch64",
                };

                // Generate image tag.
                // On GitHub: use branch name + commit date + SHA for a
                // meaningful, immutable tag.
                // Locally: use a simple local tag (not pushed).
                let short_sha = flowey::shell_cmd!(rt, "git rev-parse --short HEAD").read()?;
                let tag = if let Some(branch_name) = branch_name {
                    let branch: String = rt.read(branch_name);
                    let branch_tag = branch.replace('/', "-");
                    let date = flowey::shell_cmd!(
                        rt,
                        "git log -1 --format=%cd --date=format:%Y%m%d"
                    )
                    .read()?;
                    format!(
                        "ghcr.io/microsoft/openvmm/vmm-tests:{arch_tag}-{branch_tag}-{date}-{short_sha}"
                    )
                } else {
                    format!("openvmm/vmm-tests:{arch_tag}-local-{short_sha}")
                };

                let nextest_arg = format!("NEXTEST_VERSION={nextest_version}");
                let deps_arg = format!("OPENVMM_DEPS_VERSION={openvmm_deps_version}");
                let msvm_arg = format!("MU_MSVM_VERSION={mu_msvm_version}");
                let rust_arg = format!("RUST_ARCH={rust_arch}");
                let uefi_arg = format!("UEFI_ARCH={uefi_arch}");

                let push_or_load: &str = if push { "--push" } else { "--load" };

                flowey::shell_cmd!(
                    rt,
                    "docker buildx build
                        --build-arg {nextest_arg}
                        --build-arg {deps_arg}
                        --build-arg {msvm_arg}
                        --build-arg {rust_arg}
                        --build-arg {uefi_arg}
                        --tag {tag}
                        {push_or_load}
                        {context_dir}"
                )
                .run()?;

                Ok(())
            }
        });

        Ok(())
    }
}
