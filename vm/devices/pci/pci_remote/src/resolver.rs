use crate::pci_remote_resources::RemotePciDeviceHandle;
use pci_resources::ResolvePciDeviceHandleParams;
use pci_resources::ResolvedPciDevice;
use vm_resource::kind::PciDeviceHandleKind;
use vm_resource::ResolveResource;

pub struct RemotePciDeviceResolver;

impl ResolveResource<PciDeviceHandleKind, RemotePciDeviceHandle> for RemotePciDeviceResolver {
    type Output = ResolvedPciDevice;
    type Error = anyhow::Error;

    fn resolve(
        &self,
        resource: RemotePciDeviceHandle,
        input: ResolvePciDeviceHandleParams<'_>,
    ) -> Result<Self::Output, Self::Error> {
        todo!()
    }
}
