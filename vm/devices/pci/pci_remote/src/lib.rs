use chipset_device::io::deferred::DeferredRead;
use chipset_device::io::deferred::DeferredWrite;
use chipset_device::io::IoResult;
use chipset_device::mmio::MmioIntercept;
use chipset_device::pci::PciConfigSpace;
use chipset_device::poll_device::PollDevice;
use chipset_device::ChipsetDevice;
use futures::stream::Stream;
use mesh::rpc::RpcSend;
use mesh::OneshotReceiver;
use pci_remote_resources::RemotePciRequest;
use std::future::Future;
use std::pin::Pin;
use std::task::ready;
use std::task::Poll;
use unicycle::FuturesUnordered;

pub mod pci_remote_resources;
pub mod resolver;

pub struct RemotePciDevice {
    send: mesh::Sender<RemotePciRequest>,
    ios: FuturesUnordered<PendingIo>,
}

impl ChipsetDevice for RemotePciDevice {
    fn supports_mmio(&mut self) -> Option<&mut dyn MmioIntercept> {
        Some(self)
    }

    fn supports_pci(&mut self) -> Option<&mut dyn PciConfigSpace> {
        Some(self)
    }

    fn supports_poll_device(&mut self) -> Option<&mut dyn PollDevice> {
        Some(self)
    }
}

impl MmioIntercept for RemotePciDevice {
    fn mmio_read(&mut self, addr: u64, data: &mut [u8]) -> IoResult {
        let (read, token) = chipset_device::io::deferred::defer_read();
        let recv = self.send.call(RemotePciRequest::MmioRead, addr);
        self.ios
            .push(PendingIo::MmioRead(Some(read), recv, data.len()));
        IoResult::Defer(token)
    }

    fn mmio_write(&mut self, addr: u64, data: &[u8]) -> IoResult {
        let (write, token) = chipset_device::io::deferred::defer_write();
        let data = match data.len() {
            1 => data[0] as u64,
            2 => u16::from_ne_bytes(data[..2].try_into().unwrap()) as u64,
            4 => u32::from_ne_bytes(data[..4].try_into().unwrap()) as u64,
            8 => u64::from_ne_bytes(data[..8].try_into().unwrap()),
            _ => panic!("Invalid data length"),
        };
        let recv = self.send.call(RemotePciRequest::MmioWrite, (addr, data));
        self.ios.push(PendingIo::MmioWrite(Some(write), recv));
        IoResult::Defer(token)
    }
}

impl PciConfigSpace for RemotePciDevice {
    fn pci_cfg_read(&mut self, offset: u16, _value: &mut u32) -> IoResult {
        let (read, token) = chipset_device::io::deferred::defer_read();
        let recv = self.send.call(RemotePciRequest::ConfigRead, offset);
        self.ios.push(PendingIo::ConfigRead(Some(read), recv));
        IoResult::Defer(token)
    }

    fn pci_cfg_write(&mut self, offset: u16, value: u32) -> IoResult {
        let (write, token) = chipset_device::io::deferred::defer_write();
        let recv = self
            .send
            .call(RemotePciRequest::ConfigWrite, (offset, value));
        self.ios.push(PendingIo::ConfigWrite(Some(write), recv));
        IoResult::Defer(token)
    }
}

impl PollDevice for RemotePciDevice {
    fn poll_device(&mut self, cx: &mut std::task::Context<'_>) {
        while let Poll::Ready(Some(())) = Pin::new(&mut self.ios).poll_next(cx) {}
    }
}

enum PendingIo {
    MmioRead(Option<DeferredRead>, OneshotReceiver<u64>, usize),
    MmioWrite(Option<DeferredWrite>, OneshotReceiver<()>),
    ConfigRead(Option<DeferredRead>, OneshotReceiver<u32>),
    ConfigWrite(Option<DeferredWrite>, OneshotReceiver<()>),
}

impl Future for PendingIo {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            PendingIo::MmioRead(deferred_read, recv, len) => {
                let v = ready!(Pin::new(recv).poll(cx)).unwrap_or_else(|err| {
                    tracelimit::error_ratelimited!(
                        error = &err as &dyn std::error::Error,
                        "failed to read from remote PCI device"
                    );
                    !0
                });
                deferred_read
                    .take()
                    .unwrap()
                    .complete(&v.to_ne_bytes()[..*len]);
            }
            PendingIo::MmioWrite(deferred_write, recv) => {
                if let Err(err) = ready!(Pin::new(recv).poll(cx)) {
                    tracelimit::error_ratelimited!(
                        error = &err as &dyn std::error::Error,
                        "failed to write to remote PCI device"
                    );
                }
                deferred_write.take().unwrap().complete();
            }
            PendingIo::ConfigRead(deferred_read, recv) => {
                let v = ready!(Pin::new(recv).poll(cx)).unwrap_or_else(|err| {
                    tracelimit::error_ratelimited!(
                        error = &err as &dyn std::error::Error,
                        "failed to read from remote PCI device"
                    );
                    !0
                });
                deferred_read.take().unwrap().complete(&v.to_ne_bytes());
            }
            PendingIo::ConfigWrite(deferred_write, recv) => {
                if let Err(err) = ready!(Pin::new(recv).poll(cx)) {
                    tracelimit::error_ratelimited!(
                        error = &err as &dyn std::error::Error,
                        "failed to write to remote PCI device"
                    );
                }
                deferred_write.take().unwrap().complete();
            }
        }
        Poll::Ready(())
    }
}
