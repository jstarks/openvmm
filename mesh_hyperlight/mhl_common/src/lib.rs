#![no_std]

extern crate alloc;

pub mod infra;

use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use mesh_channel_core::OneshotSender;
use mesh_channel_core::Receiver;
use mesh_channel_core::Sender;
use mesh_node::resource::Resource;
use mesh_protobuf::Protobuf;

#[derive(Protobuf)]
#[mesh(resource = "Resource")]
pub struct InitialMessage {
    pub logger: Sender<String>,
    pub dictionary: BTreeMap<char, char>,
    pub requests: Receiver<Request>,
}

#[derive(Protobuf)]
#[mesh(resource = "Resource")]
pub enum Request {
    TranslateString {
        request: String,
        response: OneshotSender<String>,
    },
    Ping {
        response: OneshotSender<()>,
    },
}

#[derive(Protobuf)]
pub struct Add {
    pub a: i32,
    pub b: i32,
    pub log_annotation: String,
}
