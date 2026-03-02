// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rust bindings to the containerd Task v3 and Sandbox v1 ttrpc APIs.
//!
//! Proto files vendored from <https://github.com/containerd/containerd>

#![expect(missing_docs)]
#![forbid(unsafe_code)]
#![expect(clippy::enum_variant_names, clippy::large_enum_variant)]

// Crates used by generated code. Reference them explicitly to ensure that
// automated tools do not remove them.
use mesh_rpc as _;
use prost as _;
use prost_types as _;

// Generated code is organized into a module hierarchy matching the protobuf
// package names, so that `super::` references between packages resolve correctly.
pub mod containerd {
    pub mod types {
        include!(concat!(env!("OUT_DIR"), "/containerd.types.rs"));
    }

    pub mod v1 {
        pub mod types {
            include!(concat!(env!("OUT_DIR"), "/containerd.v1.types.rs"));
        }
    }

    pub mod task {
        pub mod v3 {
            include!(concat!(env!("OUT_DIR"), "/containerd.task.v3.rs"));
        }
    }

    pub mod runtime {
        pub mod sandbox {
            pub mod v1 {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/containerd.runtime.sandbox.v1.rs"
                ));
            }
        }
    }
}

// Re-export the service enums at the crate root for ergonomic access.
pub use containerd::runtime::sandbox::v1::Sandbox;
pub use containerd::task::v3::Task;
