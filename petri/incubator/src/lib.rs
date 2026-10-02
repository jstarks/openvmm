// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Incubator: launches a controlled environment in which to run petri test
//! commands.
//!
//! An incubator boots a hardware profile, shares artifacts via virtio-9p,
//! and runs a command through Pipette. QEMU TCG supplies emulated hardware;
//! OpenVMM/KVM can host an experimental x86-64 mshv root partition.
//!
//! This crate is backend-agnostic: profiles define the platform requirements,
//! and incubator backends satisfy them.
//!
//! # Why QEMU rather than OpenVMM?
//!
//! The incubator is fundamentally about providing a *stable host* for running
//! tests against obscure or emulated hardware (unusual IOMMUs, PCIe topologies,
//! device-assignment paths, etc.). QEMU TCG is better at faithfully emulating
//! that breadth of hardware than OpenVMM is, and is likely to remain so. The
//! OpenVMM backend uses a separately supplied, stable host executable to run
//! mshv tests inside the root partition. It is not a replacement for QEMU's
//! hardware models, nor a test of the outer VMM's snapshot support.

#![forbid(unsafe_code)]

pub mod mshv_image;
mod openvmm;
mod path_mapping;
mod profile;
mod qemu;
mod run;

/// Guest path where the host share is mounted.
pub const GUEST_SHARE_ROOT: &str = "/share";

pub use path_mapping::HostPathMapper;
pub use path_mapping::guest_env_from_incubator_env;
pub use profile::Arch;
pub use profile::IncubatorBackend;
pub use profile::IncubatorProfile;
pub use run::IncubatorConfig;
pub use run::IncubatorOutput;
pub use run::run_in_incubator;
