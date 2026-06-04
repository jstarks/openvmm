// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hosting VM launcher for running tests inside emulated environments.
//!
//! Provides the runtime machinery to boot an emulated VM (e.g., QEMU TCG)
//! with a given hardware profile, share artifacts into the VM via virtio-fs,
//! and run a command inside it. Console output streams to the host in real
//! time.
//!
//! This crate is emulator-agnostic: profiles define the platform
//! requirements, and emulator backends (currently QEMU TCG) satisfy them.

mod profile;
mod qemu;
mod run;

pub use profile::HostingVmProfile;
pub use run::HostingVmConfig;
pub use run::HostingVmOutput;
pub use run::run_in_hosting_vm;
