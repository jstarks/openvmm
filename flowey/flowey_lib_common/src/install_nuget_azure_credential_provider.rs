// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Globally install the azure credential provider nuget plugin

use crate::download_nuget_exe::NugetInstallPlatform;
use flowey::node::prelude::*;

flowey_config! {
    pub struct LocalOnlySkipAuthCheck(pub bool);
}

flowey_request! {
    pub enum Request {
        EnsureAuth(WriteVar<SideEffect>),
    }
}

new_flow_node!(struct Node);

impl FlowNode for Node {
    type Request = Request;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<crate::ado_task_nuget_authenticate::Node>();
        ctx.import::<super::download_nuget_exe::Node>();
    }

    fn emit(requests: Vec<Self::Request>, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let mut ensure_auth = Vec::new();
        let auto_install = ctx.config::<crate::_config::AutoInstall>().0;
        let skip_auth_check = ctx.config::<LocalOnlySkipAuthCheck>().0;

        for req in requests {
            match req {
                Request::EnsureAuth(v) => ensure_auth.push(v),
            }
        }

        if ensure_auth.is_empty() {
            return Ok(());
        }

        if matches!(ctx.backend(), FlowBackend::Ado) {
            // -- end of req processing -- //

            // defer auth to the built-in task
            for v in ensure_auth {
                ctx.req(crate::ado_task_nuget_authenticate::Request::EnsureAuth(v));
            }
        } else if matches!(ctx.backend(), FlowBackend::Local) {
            // -- end of req processing -- //

            let nuget_config_platform =
                ctx.reqv(super::download_nuget_exe::Request::NugetInstallPlatform);

            if auto_install {
                ctx.emit_rust_step(
                    "Install Azure Artifacts Credential Provider",
                    move |ctx|{
                        let nuget_config_platform = nuget_config_platform.claim(ctx);
                        ensure_auth.claim(ctx);

                        move |rt| {
                            let nuget_config_platform = rt.read(nuget_config_platform);
                            if check_if_aacp_installed(rt, &nuget_config_platform).is_ok() {
                                return Ok(())
                            }

                            let sh = xshell::Shell::new()?;

                            if matches!(nuget_config_platform, NugetInstallPlatform::Windows) {
                                let install_aacp_cmd = r#""& { $(irm https://aka.ms/install-artifacts-credprovider.ps1) } -AddNetfx""#;
                                xshell::cmd!(sh, "powershell.exe iex {install_aacp_cmd}").run()?;
                            } else {
                                log::warn!("automatic Azure Artifacts Credential Provider installation is not supported yet for this platform!");
                                log::warn!("follow the guide, and press <enter> to continue");
                                let _ = std::io::stdin().read_line(&mut String::new());
                            }

                            check_if_aacp_installed(rt, &nuget_config_platform)?;

                            Ok(())
                        }
                    }
                );
            } else {
                ctx.emit_rust_step(
                    "Check if Azure Artifacts Credential Provider is installed",
                    move |ctx| {
                        let nuget_config_platform = nuget_config_platform.claim(ctx);
                        ensure_auth.claim(ctx);

                        move |rt| {
                            let nuget_config_platform = rt.read(nuget_config_platform);
                            if let Err(e) = check_if_aacp_installed(rt, &nuget_config_platform) {
                                if skip_auth_check {
                                    log::warn!("{}", e);
                                    log::warn!("user passed --skip-auth-check, so assuming they know what they're doing...");
                                } else {
                                    return Err(e)
                                }
                            }

                            Ok(())
                        }
                    },
                );
            }
        } else {
            anyhow::bail!("unsupported backend")
        }

        Ok(())
    }
}

fn check_if_aacp_installed(
    rt: &mut RustRuntimeServices<'_>,
    nuget_config_platform: &NugetInstallPlatform,
) -> anyhow::Result<()> {
    let sh = xshell::Shell::new()?;

    let profile: PathBuf = if matches!(nuget_config_platform, NugetInstallPlatform::Windows) {
        let path = xshell::cmd!(sh, "cmd.exe /c echo %UserProfile%")
            .ignore_status()
            .read()?;

        if crate::_util::running_in_wsl(rt) {
            crate::_util::wslpath::win_to_linux(path)
        } else {
            path.into()
        }
    } else {
        dirs::home_dir().unwrap_or_default()
    };

    for kind in ["netfx", "netcore"] {
        let path = profile
            .join(".nuget")
            .join("plugins")
            .join(kind)
            .join("CredentialProvider.Microsoft");
        if path.exists() {
            log::info!("found it!");
            return Ok(());
        }
    }

    anyhow::bail!("Azure Artifacts Credential Provider was not detected!")
}
