// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build the `hosting_vm` binary

use crate::common::CommonProfile;
use crate::common::CommonTriple;
use flowey::node::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct HostingVmOutput {
    #[serde(rename = "hosting_vm")]
    pub bin: PathBuf,
    #[serde(rename = "hosting_vm.dbg")]
    pub dbg: PathBuf,
}

impl Artifact for HostingVmOutput {}

flowey_request! {
    pub struct Request {
        pub target: CommonTriple,
        pub profile: CommonProfile,
        pub hosting_vm: WriteVar<HostingVmOutput>,
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
            hosting_vm,
        } = request;

        let output = ctx.reqv(|v| crate::run_cargo_build::Request {
            crate_name: "hosting_vm".into(),
            out_name: "hosting_vm".into(),
            crate_type: flowey_lib_common::run_cargo_build::CargoCrateType::Bin,
            profile: profile.into(),
            features: Default::default(),
            target: target.as_triple(),
            no_split_dbg_info: false,
            extra_env: None,
            pre_build_deps: Vec::new(),
            output: v,
        });

        ctx.emit_minor_rust_step("report built hosting_vm", |ctx| {
            let hosting_vm = hosting_vm.claim(ctx);
            let output = output.claim(ctx);
            move |rt| {
                let output = match rt.read(output) {
                    crate::run_cargo_build::CargoBuildOutput::ElfBin { bin, dbg } => {
                        HostingVmOutput {
                            bin,
                            dbg: dbg.unwrap(),
                        }
                    }
                    _ => unreachable!(),
                };

                rt.write(hosting_vm, &output);
            }
        });

        Ok(())
    }
}
