use mesh::rpc::Rpc;
use mesh::MeshPayload;

#[derive(MeshPayload)]
pub struct RemotePciDeviceHandle {}

pub enum RemotePciRequest {
    MmioRead(Rpc<u64, u64>),
    MmioWrite(Rpc<(u64, u64), ()>),
    ConfigRead(Rpc<u16, u32>),
    ConfigWrite(Rpc<(u16, u32), ()>),
}
