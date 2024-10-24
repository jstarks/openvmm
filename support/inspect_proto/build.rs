// Copyright (C) Microsoft Corporation. All rights reserved.

use std::path::Path;

fn main() {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();

    // Generate .proto files from the inspect types.
    mesh_protobuf::protofile::DescriptorWriter::new(&[
        mesh_protobuf::protofile::message_description::<inspect::Node>(),
    ])
    .write_to_path(&out_dir)
    .unwrap();

    prost_build::Config::new()
        .type_attribute(".", "#[derive(mesh::MeshPayload)]")
        .type_attribute(".", "#[mesh(prost)]")
        .service_generator(Box::new(mesh_build::MeshServiceGenerator))
        .compile_protos(
            &["src/inspect_service.proto"],
            &[Path::new("src"), out_dir.as_ref()],
        )
        .unwrap();
}
