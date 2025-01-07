use mesh_node::common::Address;
use mesh_node::common::NodeId;
use mesh_node::local_node::RemoteNodeHandle;
use mesh_protobuf::Protobuf;

#[derive(Debug)]
pub struct NullConnector;

impl mesh_node::local_node::Connect for NullConnector {
    fn connect(&self, _node_id: NodeId, _handle: RemoteNodeHandle) {
        todo!()
    }
}

#[derive(Protobuf)]
pub struct StartParams {
    pub local: Address,
    pub remote: Address,
}
