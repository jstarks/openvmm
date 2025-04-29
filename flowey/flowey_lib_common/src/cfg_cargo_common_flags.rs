// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Centralized configuration for setting "global" cargo command flags, such as
//! `--locked`, `--verbose`, etc...
//!
//! This node can then be depended on by nodes which do fine-grained ops with
//! cargo (e.g: `cargo build`, `cargo doc`, `cargo test`, etc...) to avoid
//! duping the same flag config all over the place.

use flowey::node::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct Flags {
    pub locked: bool,
    pub verbose: bool,
}

flowey_config! {
    pub struct Locked(pub bool);

    /// Write verbose output.
    #[derive(Default)]
    pub struct Verbose(pub ReadVar<bool>);
}

flowey_request! {
    pub enum Request {
        SetLocked(bool),
        GetFlags(WriteVar<Flags>),
    }
}

new_flow_node!(struct Node);

impl FlowNode for Node {
    type Request = Request;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<crate::install_rust::Node>();
    }

    fn emit(requests: Vec<Self::Request>, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let mut set_locked = None;
        let mut get_flags = Vec::new();

        for req in requests {
            match req {
                Request::SetLocked(v) => same_across_all_reqs("SetLocked", &mut set_locked, v)?,
                Request::GetFlags(v) => get_flags.push(v),
            }
        }

        let set_locked =
            set_locked.ok_or(anyhow::anyhow!("Missing essential request: SetLocked"))?;
        let set_verbose = ctx.config_or_default::<crate::_config::Verbose>().0.clone();
        let get_flags = get_flags;

        // -- end of req processing -- //

        if get_flags.is_empty() {
            return Ok(());
        }

        ctx.emit_minor_rust_step("report common cargo flags", |ctx| {
            let get_flags = get_flags.claim(ctx);
            let set_verbose = set_verbose.claim(ctx);

            move |rt| {
                let set_verbose = rt.read(set_verbose);
                for var in get_flags {
                    rt.write(
                        var,
                        &Flags {
                            locked: set_locked,
                            verbose: set_verbose,
                        },
                    );
                }
            }
        });

        Ok(())
    }
}
