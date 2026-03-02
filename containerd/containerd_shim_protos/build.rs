// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![expect(missing_docs)]

fn main() {
    // Compile containerd Task v3 and Sandbox v1 proto files.
    // Proto files vendored from https://github.com/containerd/containerd
    prost_build::Config::new()
        .extern_path(".google.protobuf.Timestamp", "::prost_types::Timestamp")
        .extern_path(".google.protobuf.Any", "::prost_types::Any")
        .type_attribute(".", "#[derive(mesh::MeshPayload)]")
        .type_attribute(".", "#[mesh(prost)]")
        .service_generator(Box::new(mesh_build::MeshServiceGenerator::new()))
        .compile_protos(
            &["src/protos/shim.proto", "src/protos/sandbox.proto"],
            &["src/protos"],
        )
        .unwrap();

    // Rerun if any proto file changes.
    println!("cargo:rerun-if-changed=src/protos");
}
