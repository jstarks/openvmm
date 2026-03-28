// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![expect(missing_docs)]

fn main() {
    // Prevent this build script from rerunning unnecessarily.
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        println!("cargo:rustc-link-lib=onecore_apiset");
        println!("cargo:rustc-link-lib=onecoreuap_apiset");

        // Delayload DLLs introduced by the GUI feature so that non-GUI
        // invocations of openvmm.exe don't pay the startup cost of loading
        // GDI, shell, DWM, etc.
        if std::env::var_os("CARGO_FEATURE_GUI").is_some() {
            for dll in [
                "dwmapi.dll",
                "gdi32.dll",
                "imm32.dll",
                "ole32.dll",
                "shell32.dll",
                "shlwapi.dll",
                "uxtheme.dll",
            ] {
                println!("cargo:rustc-link-arg=/DELAYLOAD:{dll}");
            }
            println!("cargo:rustc-link-lib=delayimp");
        }
    }
}
