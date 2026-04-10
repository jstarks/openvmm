// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build the `vmm_test_container_entrypoint` binary

use crate::run_cargo_build::common::CommonProfile;
use crate::run_cargo_build::common::CommonTriple;
use flowey::node::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct VmmTestContainerEntrypointOutput {
    #[serde(rename = "vmm_test_container_entrypoint")]
    pub bin: PathBuf,
}

impl Artifact for VmmTestContainerEntrypointOutput {}

flowey_request! {
    pub struct Request {
        pub target: CommonTriple,
        pub profile: CommonProfile,
        pub entrypoint: WriteVar<VmmTestContainerEntrypointOutput>,
    }
}

new_simple_flow_node!(struct Node);

impl SimpleFlowNode for Node {
    type Request = Request;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<crate::run_cargo_build::Node>();
    }

    fn process_request(request: Self::Request, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let Request {
            target,
            profile,
            entrypoint,
        } = request;

        let output = ctx.reqv(|v| crate::run_cargo_build::Request {
            crate_name: "vmm_test_container_entrypoint".into(),
            out_name: "vmm_test_container_entrypoint".into(),
            crate_type: flowey_lib_common::run_cargo_build::CargoCrateType::Bin,
            profile: profile.into(),
            features: Default::default(),
            target: target.as_triple(),
            no_split_dbg_info: true,
            extra_env: None,
            pre_build_deps: Vec::new(),
            output: v,
        });

        ctx.emit_minor_rust_step("report built vmm_test_container_entrypoint", |ctx| {
            let entrypoint = entrypoint.claim(ctx);
            let output = output.claim(ctx);
            move |rt| {
                let bin = match rt.read(output) {
                    crate::run_cargo_build::CargoBuildOutput::ElfBin { bin, dbg: _ } => bin,
                    _ => unreachable!("entrypoint is Linux-only"),
                };
                rt.write(entrypoint, &VmmTestContainerEntrypointOutput { bin });
            }
        });

        Ok(())
    }
}
