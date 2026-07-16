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
use gic_its::GicItsDevice;
use hvdef::Vtl;
use memory_range::MemoryRange;
use std::collections::BTreeMap;
use std::sync::Arc;
use virt::aarch64::gic_its::GicItsBackend;
use vmotherboard::ChipsetBuilder;

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
    /// irqfd for passthrough-device delivery through the v2m frame, if the
    /// backend supports SPI irqfd routing.
    pub irqfd: Option<Arc<dyn vmcore::irqfd::IrqFd>>,
    /// ACPI MADT configuration for the v2m frame.
    pub config: vmm_core::acpi_builder::AcpiV2mConfig,
}

/// Instantiate the single VM-wide GICv2m MSI frame device (v2m mode).
///
/// The device registers its MMIO frame and layers its `SETSPI_NS` doorbell into
/// the chipset MSI map, so emulated-device MSIs are decoded by the map router;
/// only the passthrough irqfd is surfaced here.
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
        .add(|services| {
            gic_v2m::GicV2mDevice::new(
                &mut services.register_mmio(),
                frame_base,
                spi_base,
                spi_count,
                irqcon,
                spi_irqfd,
            )
        })?;

    let irqfd = device.lock().irqfd();

    Ok(V2mDeviceResult {
        irqfd,
        config: vmm_core::acpi_builder::AcpiV2mConfig {
            frame_base,
            spi_base,
            spi_count,
        },
    })
}
