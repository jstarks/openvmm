// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(guest_arch = "aarch64")]

//! GICv3 ITS and GICv2m MSI-controller device wiring for aarch64 VMs.
//!
//! Mirrors the SMMU wiring mechanism: MMIO bases come from the memory-layout
//! allocator, and the MSI controllers are registered as chipset devices. In
//! ITS mode one `GicItsDevice` (headless, no MMIO — the in-kernel vITS owns
//! its register block) is created per PCI segment. In v2m mode the single
//! VM-wide `GicV2mDevice` (a full MMIO chipset device) is created.

use crate::partition::HvlitePartition;
use chipset_device::ChipsetDevice;
use chipset_device::mmio::MmioIntercept;
use hvdef::Vtl;
use inspect::InspectMut;
use memory_range::MemoryRange;
use std::collections::BTreeMap;
use std::sync::Arc;
use virt::aarch64::gic_its::GicItsBackend;
use vmcore::device_state::ChangeDeviceState;
use vmcore::save_restore::NoSavedState;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveError;
use vmcore::save_restore::SaveRestore;
use vmotherboard::ChipsetBuilder;

/// A headless chipset device representing one GICv3 ITS instance.
///
/// On KVM the in-kernel vITS owns its MMIO register block, so this device
/// registers no MMIO (`supports_mmio` returns `None`). It exists to give the
/// ITS a save/restore identity in the device model; the routing surface is
/// consumed directly from the [`GicItsBackend`].
#[derive(InspectMut)]
pub(super) struct GicItsDevice {
    segment: u16,
    its_id: u32,
    #[inspect(hex)]
    base: u64,
    #[inspect(skip)]
    backend: Arc<dyn GicItsBackend>,
}

impl GicItsDevice {
    fn new(segment: u16, its_id: u32, base: u64, backend: Arc<dyn GicItsBackend>) -> Self {
        Self {
            segment,
            its_id,
            base,
            backend,
        }
    }
}

impl ChangeDeviceState for GicItsDevice {
    fn start(&mut self) {}

    async fn stop(&mut self) {}

    async fn reset(&mut self) {}
}

impl ChipsetDevice for GicItsDevice {
    fn supports_mmio(&mut self) -> Option<&mut dyn MmioIntercept> {
        // The in-kernel vITS owns its MMIO block; no userspace interception.
        None
    }
}

impl SaveRestore for GicItsDevice {
    // TODO: delegate to `backend.save()`/`backend.restore()` once the KVM
    // vITS state marshaling (KVM_DEV_ARM_ITS_SAVE_TABLES + the ITS register
    // block) is implemented. KVM aarch64 save/restore is greenfield today.
    type SavedState = NoSavedState;

    fn save(&mut self) -> Result<Self::SavedState, SaveError> {
        let _ = &self.backend;
        Ok(NoSavedState)
    }

    fn restore(&mut self, NoSavedState: Self::SavedState) -> Result<(), RestoreError> {
        Ok(())
    }
}

/// Result of [`setup_its`].
pub(super) struct ItsDevicesResult {
    /// Per-segment ITS backends, keyed by PCI segment, for PCIe MSI wiring.
    pub backends: BTreeMap<u16, Arc<dyn GicItsBackend>>,
    /// ACPI IORT/MADT configuration for each ITS instance.
    pub configs: Vec<vmm_core::acpi_builder::AcpiItsConfig>,
}

/// Instantiate one GICv3 ITS per PCI segment (ITS mode).
///
/// `its_ranges` are the allocator-assigned MMIO bases, ordered to match
/// `its_segments` (sorted distinct segments). Returns the per-segment backends
/// for PCIe wiring and the ACPI configs.
pub(super) fn setup_its(
    its_segments: &[u16],
    its_ranges: &[MemoryRange],
    chipset_builder: &ChipsetBuilder<'_>,
    partition: &dyn HvlitePartition,
) -> anyhow::Result<ItsDevicesResult> {
    assert_eq!(its_segments.len(), its_ranges.len());

    let mut backends = BTreeMap::new();
    let mut configs = Vec::new();

    for (&segment, range) in its_segments.iter().zip(its_ranges) {
        let base = range.start();
        let its_id = segment as u32;
        let backend = partition.new_its(base)?;

        let device_backend = backend.clone();
        chipset_builder
            .arc_mutex_device(format!("its:seg{segment}"))
            .add(|_services| GicItsDevice::new(segment, its_id, base, device_backend))?;

        backends.insert(segment, backend);
        configs.push(vmm_core::acpi_builder::AcpiItsConfig {
            segment,
            its_id,
            its_base: base,
        });
    }

    Ok(ItsDevicesResult { backends, configs })
}

/// Result of [`setup_v2m`].
pub(super) struct V2mDeviceResult {
    /// MSI target for emulated-device delivery through the v2m frame.
    pub signal_msi: Arc<dyn pci_core::msi::SignalMsi>,
    /// irqfd for passthrough-device delivery through the v2m frame, if the
    /// backend supports SPI irqfd routing.
    pub irqfd: Option<Arc<dyn vmcore::irqfd::IrqFd>>,
    /// ACPI MADT configuration for the v2m frame.
    pub config: vmm_core::acpi_builder::AcpiV2mConfig,
}

/// Instantiate the single VM-wide GICv2m MSI frame device (v2m mode).
pub(super) fn setup_v2m(
    frame_base: u64,
    spi_base: u32,
    spi_count: u32,
    chipset_builder: &ChipsetBuilder<'_>,
    partition: &dyn HvlitePartition,
) -> anyhow::Result<V2mDeviceResult> {
    let irqcon = partition.control_gic(Vtl::Vtl0);
    let spi_irqfd = partition.spi_irqfd();

    let device = chipset_builder
        .arc_mutex_device("gic_v2m")
        .add(|_services| {
            gic_v2m::GicV2mDevice::new(frame_base, spi_base, spi_count, irqcon, spi_irqfd)
        })?;

    let (signal_msi, irqfd) = {
        let dev = device.lock();
        (dev.signal_msi(), dev.irqfd())
    };

    Ok(V2mDeviceResult {
        signal_msi,
        irqfd,
        config: vmm_core::acpi_builder::AcpiV2mConfig {
            frame_base,
            spi_base,
            spi_count,
        },
    })
}
