use anyhow::Context as _;
use chipset_device::ChipsetDevice;
use chipset_device::io::IoResult;
use chipset_device::pci::PciConfigSpace;
use futures::FutureExt as _;
use futures::StreamExt as _;
use hcl::ioctl::MshvHvcall;
use inspect::Inspect;
use inspect::InspectMut;
use memory_range::MemoryRange;
use openhcl_dma_manager::OpenhclDmaClient;
use state_unit::StateUnits;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::Poll;
use vmbus_client::driver::OpenParams;
use vmcore::device_state::ChangeDeviceState;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveError;
use vmcore::save_restore::SaveRestore;
use vmcore::save_restore::SavedStateNotSupported;
use vmcore::vm_task::VmTaskDriverSource;
use vmcore::vpci_msi::VpciInterruptMapper;
use vmotherboard::ChipsetDevices;
use vmotherboard::DynamicDeviceUnit;
use vpci_client::MemoryAccess;
use vpci_client::VpciClient;
use vpci_client::VpciDevice;
use vpci_client::VpciDeviceRemoved;

const TEMP_GPA: u64 = 0x1000000000 - 0x2000;

struct HypercallMmio(MshvHvcall);

struct DirectMmio(sparse_mmap::SparseMapping);

impl MemoryAccess for DirectMmio {
    fn gpa(&mut self) -> u64 {
        TEMP_GPA
    }

    fn read(&mut self, addr: u64) -> u32 {
        let offset = addr
            .checked_sub(self.gpa())
            .and_then(|o| o.try_into().ok())
            .unwrap_or(!0);
        match self.0.read_volatile(offset) {
            Ok(v) => v,
            Err(err) => {
                tracelimit::error_ratelimited!(
                    addr,
                    error = &err as &dyn std::error::Error,
                    "vpci mmio read failure"
                );
                !0
            }
        }
    }

    fn write(&mut self, addr: u64, value: u32) {
        let offset = addr
            .checked_sub(self.gpa())
            .and_then(|o| o.try_into().ok())
            .unwrap_or(!0);
        if let Err(err) = self.0.write_volatile(offset, &value) {
            tracelimit::error_ratelimited!(
                addr,
                value,
                error = &err as &dyn std::error::Error,
                "vpci mmio write failure"
            );
        }
    }
}

impl MemoryAccess for HypercallMmio {
    fn gpa(&mut self) -> u64 {
        TEMP_GPA
    }

    fn read(&mut self, addr: u64) -> u32 {
        let mut data = [0; 4];
        match self.0.mmio_read(addr, &mut data) {
            Ok(()) => u32::from_ne_bytes(data),
            Err(err) => {
                tracelimit::error_ratelimited!(
                    addr,
                    error = &err as &dyn std::error::Error,
                    "vpci mmio read failure"
                );
                !0
            }
        }
    }

    fn write(&mut self, addr: u64, value: u32) {
        let data = value.to_ne_bytes();
        if let Err(err) = self.0.mmio_write(addr, &data) {
            tracelimit::error_ratelimited!(
                addr,
                value,
                error = &err as &dyn std::error::Error,
                "vpci mmio write failure"
            );
        }
    }
}

#[derive(Inspect)]
pub struct VpciRelay {
    #[inspect(skip)]
    driver_source: VmTaskDriverSource,
    dma_client: Arc<OpenhclDmaClient>,
    #[inspect(skip)]
    new_buses: Vec<vmbus_client::OfferInfo>,
    #[inspect(skip)]
    bus_recv: mesh::Receiver<vmbus_client::OfferInfo>,
    #[inspect(skip)]
    vmbus: Arc<vmbus_server::VmbusServerControl>,
    #[inspect(iter_by_index)]
    devices: slab::Slab<RelayedDevice>,
}

#[derive(Inspect)]
struct RelayedDevice {
    bus_client: VpciClient,
    #[inspect(skip)]
    removed: VpciDeviceRemoved,
    #[inspect(skip)]
    bus_unit: DynamicDeviceUnit,
    #[inspect(skip)]
    device_unit: DynamicDeviceUnit,
    ready_to_remove: bool,
}

impl RelayedDevice {
    async fn remove(self) {
        self.bus_unit.remove().await;
        self.device_unit.remove().await;
        self.bus_client.shutdown().await;
    }
}

impl VpciRelay {
    pub fn new(
        driver_source: VmTaskDriverSource,
        offers: vmbus_client::ConnectResult,
        vmbus: Arc<vmbus_server::VmbusServerControl>,
        dma_client: Arc<OpenhclDmaClient>,
        mmio_range: MemoryRange,
        use_hypercall_for_mmio: bool,
    ) -> Self {
        Self {
            driver_source,
            dma_client,
            new_buses: offers.offers,
            bus_recv: offers.offer_recv,
            vmbus,
            devices: Vec::new(),
        }
    }

    pub async fn wait_ready(&mut self) {
        poll_fn(|cx| {
            if !self.new_buses.is_empty() {
                return Poll::Ready(());
            }
            if self.devices.iter_mut().any(|dev| {
                let p = dev.ready_to_remove || dev.removed.poll_unpin(cx).is_ready();
                if p {
                    dev.ready_to_remove = true;
                }
                p
            }) {
                return Poll::Ready(());
            }
            if let Poll::Ready(Some(bus)) = self.bus_recv.poll_next_unpin(cx) {
                self.new_buses.push(bus);
                return Poll::Ready(());
            }
            Poll::Pending
        })
        .await
    }

    pub async fn process(
        &mut self,
        chipset: &ChipsetDevices,
        units: &mut StateUnits,
    ) -> anyhow::Result<()> {
        let mut i = 0;
        while i < self.devices.len() {
            if self.devices[i].ready_to_remove {
                let dev = self.devices.remove(i);
                dev.remove().await;
            } else {
                i += 1;
            }
        }
        while let Some(bus) = self.new_buses.pop() {
            self.relay_vpci_bus(chipset, units, bus).await?;
        }
        Ok(())
    }

    pub async fn relay_vpci_bus(
        &mut self,
        chipset: &ChipsetDevices,
        state_units: &mut StateUnits,
        offer_info: vmbus_client::OfferInfo,
    ) -> anyhow::Result<()> {
        let instance_id = offer_info.offer.instance_id;

        let mmio = if false {
            let mshv_hvcall = MshvHvcall::new().context("failed to open mshv_hvcall device")?;
            mshv_hvcall.set_allowed_hypercalls(&[
                hvdef::HypercallCode::HvCallMemoryMappedIoRead,
                hvdef::HypercallCode::HvCallMemoryMappedIoWrite,
            ]);
            Box::new(HypercallMmio(mshv_hvcall)) as _
        } else {
            let mapping = sparse_mmap::SparseMapping::new(0x2000)
                .context("failed to create sparse mapping for vpci mmio")?;
            let dev_mem = fs_err::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/mem")
                .context("failed to open /dev/mem")?;
            mapping
                .map_file(0, 0x2000, &dev_mem, TEMP_GPA, true)
                .context("failed to map /dev/mem for vpci mmio")?;

            Box::new(DirectMmio(mapping)) as _
        };

        let channel = vmbus_client::driver::open_channel(
            self.driver_source.simple(),
            offer_info,
            OpenParams {
                ring_pages: 20,
                ring_offset_in_pages: 10,
            },
            self.dma_client.as_ref(),
        )
        .await?;
        let (devices, _devices_recv) = mesh::channel();
        let (vpci_client, devices) =
            VpciClient::connect(self.driver_source.simple(), channel, mmio, devices).await?;
        let vpci_device = devices.into_iter().next().context("no device")?;
        let (vpci_device, removed) = vpci_device
            .init()
            .await
            .context("failed to initialize vpci device")?;
        let vpci_device = Arc::new(vpci_device);

        let device_name = format!("assigned_device:vpci-{instance_id}");
        let (device_unit, device) = chipset
            .add_dyn_device(&self.driver_source, state_units, device_name, async |_| {
                Ok(RelayedVpciDevice(vpci_device.clone()))
            })
            .await?;

        let interrupt_mapper = VpciInterruptMapper::new(vpci_device);

        let (bus_unit, _) = {
            let vpci_bus_name = format!("vpci:{instance_id}");
            chipset
                .add_dyn_device(
                    &self.driver_source,
                    state_units,
                    vpci_bus_name,
                    async |mmio| {
                        let bus = vpci::bus::VpciBus::new(
                            &self.driver_source,
                            instance_id,
                            device,
                            mmio,
                            self.vmbus.as_ref(),
                            interrupt_mapper,
                        )
                        .await?;

                        anyhow::Ok(bus)
                    },
                )
                .await?
        };

        self.devices.push(RelayedDevice {
            bus_client: vpci_client,
            removed,
            bus_unit,
            device_unit,
            ready_to_remove: false,
        });

        state_units.start_stopped_units().await;
        Ok(())
    }
}

#[derive(InspectMut)]
#[inspect(transparent)]
pub struct RelayedVpciDevice(Arc<VpciDevice>);

impl ChipsetDevice for RelayedVpciDevice {
    fn supports_pci(&mut self) -> Option<&mut dyn PciConfigSpace> {
        Some(self)
    }
}

impl PciConfigSpace for RelayedVpciDevice {
    fn pci_cfg_read(&mut self, offset: u16, value: &mut u32) -> IoResult {
        *value = self.0.read_cfg(offset);
        IoResult::Ok
    }

    fn pci_cfg_write(&mut self, offset: u16, value: u32) -> IoResult {
        self.0.write_cfg(offset, value);
        IoResult::Ok
    }
}

impl ChangeDeviceState for RelayedVpciDevice {
    fn start(&mut self) {}

    async fn stop(&mut self) {}

    async fn reset(&mut self) {}
}

impl SaveRestore for RelayedVpciDevice {
    type SavedState = SavedStateNotSupported;

    fn save(&mut self) -> Result<Self::SavedState, SaveError> {
        Err(SaveError::NotSupported)
    }

    fn restore(&mut self, state: Self::SavedState) -> Result<(), RestoreError> {
        match state {}
    }
}
