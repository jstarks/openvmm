// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Flowey node for building and publishing the VMM tests container image.
//!
//! This node assembles the Docker build context from pre-built artifacts,
//! then invokes `docker buildx build` with version args from `cfg_versions.rs`.
//!
//! The Dockerfile lives alongside this module at `Dockerfile`.
//!
//! # Container Image
//!
//! Published to `ghcr.io/microsoft/openvmm/vmm-tests`.
//!
//! # Build Context Layout
//!
//! ```text
//! context/
//! ├── Dockerfile
//! ├── run-vmm-tests           # entrypoint binary (vmm_test_container_entrypoint)
//! └── artifacts/
//!     ├── bin/                 # openvmm, pipette, tmk_vmm, etc.
//!     ├── vmm_tests.tar.zst   # nextest archive
//!     └── nextest.toml        # nextest config
//! ```

// TODO: implement flowey node for Milestone 2
