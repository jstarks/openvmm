// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! PCIe MSI routing and DMA wiring helpers.
//!
//! This module provides layered MSI routing and DMA translation for PCIe
//! entities (root complexes, switches, and devices).
//!
//! [`PcieMsiPlatform`] captures platform-specific context (ITS on aarch64,
//! IOMMU interrupt remapping on x86_64) and wraps `SignalMsi`/`IrqFd` via
//! [`PcieMsiPlatform::wrap_msi`] → [`PcieMsiRouting`].
//!
//! [`build_device_wiring`] extends this with IOMMU DMA translation
//! (SMMU on aarch64, AMD/Intel IOMMU on x86_64) → [`PcieDeviceWiring`].

use crate::partition::HvlitePartition;
use guestmem::GuestMemory;
#[cfg(guest_arch = "x86_64")]
use hvdef::Vtl;
use pci_core::dma::DmaTarget;
use std::sync::Arc;

/// Platform-specific MSI wrapping context for PCIe entities.
///
/// Encapsulates ITS device ID composition (aarch64) and IOMMU interrupt
/// remapping (x86_64). Construct one of these and call [`wrap_msi`] to
/// get correctly-wrapped `SignalMsi` and `IrqFd` for any PCIe entity —
/// root complexes, switches, and devices alike.
///
/// [`wrap_msi`]: PcieMsiPlatform::wrap_msi
pub(super) struct PcieMsiPlatform<'a> {
    /// The partition providing base `SignalMsi` and `IrqFd` (x86).
    #[cfg_attr(guest_arch = "aarch64", expect(dead_code))]
    pub partition: &'a dyn HvlitePartition,
    /// The chipset's arch-neutral MSI-sink map router — the generic downstream
    /// decode a device's outbound MSI falls through to.
    ///
    /// On x86 it is the fallback of the root-complex `0xFEE` decode (see
    /// [`X86RootComplexMsi`]); the map holds no MSI sinks there today. On
    /// aarch64 the ITS/v2m path is still selected via `msi_source` (Phase 3
    /// moves ITS/v2m onto this router), so it is currently unused.
    #[cfg_attr(guest_arch = "aarch64", expect(dead_code))]
    pub msi_router: Arc<dyn pci_core::msi::SignalMsi>,
    /// aarch64 GIC MSI source for this entity (per-segment ITS or the VM-wide
    /// v2m frame).
    #[cfg(guest_arch = "aarch64")]
    pub msi_source: Aarch64MsiSource<'a>,
    /// x86 IOMMU shared state for interrupt remapping, or `None` if this
    /// entity is not behind an IOMMU.
    #[cfg(guest_arch = "x86_64")]
    pub iommu: Option<X86IommuSharedState<'a>>,
}

/// The aarch64 GIC MSI routing source for a PCIe entity.
///
/// In ITS mode this is the ITS backend for the entity's PCI segment; in v2m
/// mode it is the shared v2m frame's routing surface.
#[cfg(guest_arch = "aarch64")]
pub(super) enum Aarch64MsiSource<'a> {
    /// No MSI controller (no routing).
    None,
    /// GICv3 ITS for this entity's PCI segment. MSIs use plain 16-bit RID
    /// device IDs; the ITS is selected by its doorbell address.
    Its(&'a Arc<dyn virt::aarch64::gic_its::GicItsBackend>),
    /// The VM-wide GICv2m frame's routing surface.
    V2m {
        signal_msi: &'a Arc<dyn pci_core::msi::SignalMsi>,
        irqfd: Option<&'a Arc<dyn vmcore::irqfd::IrqFd>>,
    },
}

/// Enum dispatching between AMD IOMMU and Intel VT-d shared state on x86_64.
#[cfg(guest_arch = "x86_64")]
pub(super) enum X86IommuSharedState<'a> {
    AmdVi(&'a Arc<amd_iommu::IommuSharedState>),
    IntelVtd(&'a Arc<intel_vtd::VtdSharedState>),
}

/// The x86 PCIe root complex's outbound MSI decode.
///
/// Models how the root complex recognizes writes to the `0xFEE` interrupt-
/// message window on a device's outbound path and converts them into
/// interrupt messages to the LAPIC — here, via the partition `injector`, with
/// IOMMU interrupt remapping already applied when the device is behind an
/// IOMMU. Every other address falls through to the `generic` downstream MMIO
/// decode (the chipset MSI-sink map router).
///
/// On x86 that map holds no MSI sinks, so the fallback drops today; since every
/// device MSI targets `0xFEE`, the injector branch is taken in practice. The
/// fallback is the seam for the deferred peer-to-peer DMA path.
#[cfg(guest_arch = "x86_64")]
struct X86RootComplexMsi {
    /// Receives writes to the `0xFEE` interrupt-message window (the partition
    /// injector, IOMMU-remapped when applicable).
    injector: Arc<dyn pci_core::msi::SignalMsi>,
    /// The generic downstream decode: the chipset MSI-sink map router.
    generic: Arc<dyn pci_core::msi::SignalMsi>,
}

#[cfg(guest_arch = "x86_64")]
impl pci_core::msi::SignalMsi for X86RootComplexMsi {
    fn signal_msi(&self, devid: Option<u32>, address: u64, data: u32) {
        // The interrupt-message window is `0xFEE0_0000..=0xFEEF_FFFF`
        // (address bits [31:20] == 0xFEE).
        if address >> 20 == 0xFEE {
            self.injector.signal_msi(devid, address, data);
        } else {
            self.generic.signal_msi(devid, address, data);
        }
    }
}

/// Wrapped `SignalMsi` and `IrqFd` for a PCIe entity.
///
/// Produced by [`PcieMsiPlatform::wrap_msi`]. Use [`connect_to`] to
/// wire these into an [`MsiConnection`].
///
/// [`connect_to`]: PcieMsiRouting::connect_to
/// [`MsiConnection`]: pci_core::msi::MsiConnection
pub(super) struct PcieMsiRouting {
    /// MSI signaling target with platform wrapping applied. `None` if
    /// the partition does not provide MSI support.
    pub signal_msi: Option<Arc<dyn pci_core::msi::SignalMsi>>,
    /// IrqFd for kernel-accelerated MSI delivery with platform wrapping
    /// applied. `None` if the partition does not provide irqfd support,
    /// or if IOMMU interrupt remapping is active (irqfd is not yet
    /// supported through the emulated IOMMU).
    pub irqfd: Option<Arc<dyn vmcore::irqfd::IrqFd>>,
}

impl PcieMsiRouting {
    /// Connect the signal_msi and irqfd to an [`MsiConnection`].
    pub fn connect_to(self, msi_conn: &pci_core::msi::MsiConnection) {
        if let Some(target) = self.signal_msi {
            msi_conn.connect(target);
        }
        if let Some(fd) = self.irqfd {
            msi_conn.connect_irqfd(fd);
        }
    }
}

impl PcieMsiPlatform<'_> {
    /// Wrap the partition's base `SignalMsi` and `IrqFd` with platform-
    /// specific MSI controller translation and IOMMU interrupt remapping.
    ///
    /// On aarch64 with ITS: wraps with segment-based device ID composition.
    /// On x86_64 with AMD IOMMU: wraps with interrupt remapping; irqfd
    /// is disabled because kernel-mediated MSI routes bypass emulated
    /// interrupt remapping.
    pub fn wrap_msi(&self) -> PcieMsiRouting {
        // aarch64: the MSI source is the GIC MSI controller device (per-segment
        // ITS with plain-RID device IDs, or the VM-wide v2m frame), not the
        // partition.
        #[cfg(guest_arch = "aarch64")]
        let (signal_msi, irqfd): (
            Option<Arc<dyn pci_core::msi::SignalMsi>>,
            Option<Arc<dyn vmcore::irqfd::IrqFd>>,
        ) = match &self.msi_source {
            Aarch64MsiSource::None => (None, None),
            Aarch64MsiSource::Its(backend) => (Some(backend.as_signal_msi()), backend.irqfd()),
            Aarch64MsiSource::V2m { signal_msi, irqfd } => {
                (Some((*signal_msi).clone()), irqfd.cloned())
            }
        };

        #[cfg(guest_arch = "x86_64")]
        let mut signal_msi: Option<Arc<dyn pci_core::msi::SignalMsi>> =
            self.partition.as_signal_msi(Vtl::Vtl0);
        #[cfg(guest_arch = "x86_64")]
        let mut irqfd: Option<Arc<dyn vmcore::irqfd::IrqFd>> = self.partition.irqfd();

        // x86_64 IOMMU: wrap with interrupt remapping.
        //
        // TODO: irqfd is disabled because kernel-mediated MSI routes
        // bypass our emulated interrupt remapping. We could support
        // irqfd by wrapping IrqFdRoute::enable() to do the IRTE lookup
        // and push the remapped address/data to the kernel, then
        // re-pushing on INVALIDATE_INTERRUPT_TABLE commands.
        #[cfg(guest_arch = "x86_64")]
        if let Some(iommu_state) = &self.iommu {
            match iommu_state {
                X86IommuSharedState::AmdVi(shared) => {
                    signal_msi = signal_msi.map(|s| shared.wrap_signal_msi(s) as _);
                }
                X86IommuSharedState::IntelVtd(shared) => {
                    signal_msi = signal_msi.map(|s| shared.wrap_signal_msi(s) as _);
                }
            }
            irqfd = None;
        }

        // x86: model the PCIe root complex's outbound MSI decode. The
        // (IOMMU-remapped) partition injector receives writes to the `0xFEE`
        // interrupt-message window; everything else falls through to the
        // generic downstream MMIO decode (the chipset MSI-sink map router).
        // Behaviorally identical to routing straight to the injector today,
        // since every x86 device MSI targets `0xFEE`.
        #[cfg(guest_arch = "x86_64")]
        let signal_msi = signal_msi.map(|injector| {
            Arc::new(X86RootComplexMsi {
                injector,
                generic: self.msi_router.clone(),
            }) as Arc<dyn pci_core::msi::SignalMsi>
        });

        PcieMsiRouting { signal_msi, irqfd }
    }
}

/// Input parameters for [`build_device_wiring`].
pub(super) struct PcieDeviceWiringParams<'a> {
    /// Platform MSI context (ITS, IOMMU interrupt remapping).
    pub msi_platform: PcieMsiPlatform<'a>,
    /// Raw guest memory (wrapped with IOMMU DMA translation when applicable).
    pub guest_memory: &'a GuestMemory,
    /// The device's assigned bus range (for IOMMU stream/device ID and the
    /// MSI/DMA requester identity).
    pub bus_range: &'a pci_core::bus_range::AssignedBusRange,
    /// The device's MSI connection, providing the late-bound MSI backend.
    pub msi: &'a pci_core::msi::MsiConnection,
    /// SMMU shared state if this device is behind an SMMU, or `None`.
    #[cfg(guest_arch = "aarch64")]
    pub smmu: Option<&'a Arc<smmu::SmmuSharedState>>,
}

/// The layered DMA target and MSI routing for a PCIe device.
///
/// Produced by [`build_device_wiring`]. Pairs a [`DmaTarget`] (guest memory
/// + MSI identity + optional IOMMU) with the wrapped [`PcieMsiRouting`].
pub(super) struct PcieDeviceWiring {
    /// DMA and MSI target for the device, including any IOMMU translation.
    pub dma_target: DmaTarget,
    /// Wrapped MSI routing for the device.
    pub msi: PcieMsiRouting,
}

impl PcieDeviceWiring {
    /// Connect the MSI routing to an [`MsiConnection`].
    pub fn connect_to(self, msi_conn: &pci_core::msi::MsiConnection) {
        self.msi.connect_to(msi_conn);
    }
}

/// Build the layered DMA target and MSI routing for a PCIe device.
///
/// Calls [`PcieMsiPlatform::wrap_msi`] for MSI/IrqFd wrapping, then
/// adds IOMMU DMA translation (SMMU on aarch64, AMD/Intel IOMMU on x86_64)
/// to produce the device's [`DmaTarget`].
pub(super) fn build_device_wiring(params: PcieDeviceWiringParams<'_>) -> PcieDeviceWiring {
    let msi = params.msi_platform.wrap_msi();

    // aarch64 SMMU: wrap GuestMemory and SignalMsi/IrqFd with SMMU
    // translation. stream_id_base is 0 because each SMMU is 1:1 with
    // its root complex — stream IDs are plain BDFs.
    //
    // The translating GuestMemory is created unconditionally when an
    // SMMU is present — DMA translation must not depend on MSI
    // availability.
    #[cfg(guest_arch = "aarch64")]
    if let Some(shared) = params.smmu {
        let dma_target = iommu_common::new_dma_target(
            "smmu",
            shared.translator(0),
            params.bus_range.clone(),
            0,
            params.guest_memory.clone(),
            params.msi,
        );
        let smmu_msi = msi.signal_msi.map(|inner_msi| {
            Arc::new(smmu::SmmuSignalMsi::new(shared.clone(), 0, inner_msi))
                as Arc<dyn pci_core::msi::SignalMsi>
        });
        let irqfd = msi
            .irqfd
            .map(|fd| shared.wrap_irqfd(0, fd) as Arc<dyn vmcore::irqfd::IrqFd>);
        return PcieDeviceWiring {
            dma_target,
            msi: PcieMsiRouting {
                signal_msi: smmu_msi,
                irqfd,
            },
        };
    }

    // x86_64 IOMMU: wrap GuestMemory with DMA translation.
    // MSI interrupt remapping was already applied by wrap_msi().
    #[cfg(guest_arch = "x86_64")]
    if let Some(iommu_state) = &params.msi_platform.iommu {
        let dma_target = match iommu_state {
            X86IommuSharedState::AmdVi(shared) => iommu_common::new_dma_target(
                "amd-iommu",
                shared.translator(),
                params.bus_range.clone(),
                0,
                params.guest_memory.clone(),
                params.msi,
            ),
            X86IommuSharedState::IntelVtd(shared) => iommu_common::new_dma_target(
                "intel-vtd",
                shared.translator(),
                params.bus_range.clone(),
                0,
                params.guest_memory.clone(),
                params.msi,
            ),
        };
        return PcieDeviceWiring { dma_target, msi };
    }

    PcieDeviceWiring {
        dma_target: DmaTarget::new(
            params.bus_range.clone(),
            0,
            params.guest_memory.clone(),
            params.msi,
        ),
        msi,
    }
}
