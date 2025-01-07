#![no_std]

extern crate alloc;

use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use mesh_channel_core::OneshotSender;
use mesh_channel_core::Receiver;
use mesh_channel_core::Sender;
use mesh_node::common::Address;
use mesh_node::common::NodeId;
use mesh_node::local_node::RemoteNodeHandle;
use mesh_node::resource::Resource;
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

#[derive(Protobuf)]
#[mesh(resource = "Resource")]
pub struct InitialMessage {
    pub logger: Sender<String>,
    pub dictionary: BTreeMap<char, char>,
    pub requests: Receiver<Request>,
}

#[derive(Protobuf)]
#[mesh(resource = "Resource")]
pub struct Request {
    pub request: String,
    pub response: OneshotSender<String>,
}
