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
use pal_async::driver::SpawnDriver;
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
    /// aarch64 it is the device's outbound MSI path for both delivery forms: a
    /// device's write is decoded there ([`SignalMsi::signal_msi`]) and a
    /// passthrough fd is bound there ([`SignalMsi::bind_msi`]) — the v2m frame
    /// and each ITS registered their doorbell (with its kernel route) into the
    /// map, so a guest reprogramming the MSI address re-decodes to the right
    /// sink automatically.
    pub msi_router: Arc<dyn pci_core::msi::SignalMsi>,
    /// Driver for the usermode fallback of kernel-mediated MSI routes: when a
    /// passthrough device's guest-programmed MSI address does not decode to a
    /// kernel-serviceable sink, the route polls its fd on this driver and
    /// dispatches through [`msi_router`](Self::msi_router).
    pub driver: Arc<dyn SpawnDriver>,
    /// aarch64: whether the platform's GIC MSI controller supports
    /// kernel-mediated (passthrough) routes (v2m SPI irqfd or ITS irqfd
    /// present). Emulated-device MSIs always work through the map router; this
    /// gates whether passthrough routes are enabled.
    #[cfg(guest_arch = "aarch64")]
    pub supports_routes: bool,
    /// x86 IOMMU shared state for interrupt remapping, or `None` if this
    /// entity is not behind an IOMMU.
    #[cfg(guest_arch = "x86_64")]
    pub iommu: Option<X86IommuSharedState<'a>>,
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
/// interrupt messages to the LAPIC — here, via the partition `injector`
/// ([`signal_msi`](pci_core::msi::SignalMsi::signal_msi)) or, for passthrough,
/// by binding the fd to the partition's kernel irqfd
/// ([`bind_msi`](pci_core::msi::SignalMsi::bind_msi)). IOMMU interrupt
/// remapping, when present, is applied to the usermode `signal_msi` path;
/// kernel routes are disabled under an emulated IOMMU (`irqfd` is `None`),
/// since they would bypass remapping. Every other address falls through to the
/// `generic` downstream MMIO decode (the chipset MSI-sink map router).
///
/// On x86 that map holds no MSI sinks, so the fallback drops today; since every
/// device MSI targets `0xFEE`, the injector branch is taken in practice.
#[cfg(guest_arch = "x86_64")]
struct X86RootComplexMsi {
    /// Receives usermode writes to the `0xFEE` interrupt-message window (the
    /// partition injector, IOMMU-remapped when applicable).
    injector: Arc<dyn pci_core::msi::SignalMsi>,
    /// The partition's kernel irqfd used to bind passthrough fds targeting the
    /// `0xFEE` window. `None` when kernel routes are unavailable (WHP) or
    /// disabled (behind an emulated IOMMU).
    irqfd: Option<Arc<dyn vmcore::irqfd::IrqFd>>,
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

    fn bind_msi(
        &self,
        fd: &pal_event::Event,
        devid: Option<u32>,
        address: u64,
        data: u32,
    ) -> Option<Box<dyn vmcore::irqfd::KernelMsiBinding>> {
        if address >> 20 == 0xFEE {
            // Bind the fd to the partition's kernel irqfd for the LAPIC. `None`
            // (no kernel irqfd, or disabled under an emulated IOMMU) falls back
            // to the usermode `signal_msi` leg.
            let route = self.irqfd.as_ref()?.new_irqfd_route(fd.clone()).ok()?;
            if !route.enable(address, data, devid) {
                return None;
            }
            Some(Box::new(vmcore::irqfd::IrqFdBinding(route)))
        } else {
            self.generic.bind_msi(fd, devid, address, data)
        }
    }
}

/// Wrapped `SignalMsi` for a PCIe entity, plus whether passthrough routes are
/// supported.
///
/// Produced by [`PcieMsiPlatform::wrap_msi`]. Use [`connect_to`] to
/// wire these into an [`MsiConnection`].
///
/// [`connect_to`]: PcieMsiRouting::connect_to
/// [`MsiConnection`]: pci_core::msi::MsiConnection
pub(super) struct PcieMsiRouting {
    /// MSI signaling/binding target with platform wrapping applied. `None` if
    /// the partition does not provide MSI support.
    pub signal_msi: Option<Arc<dyn pci_core::msi::SignalMsi>>,
    /// Whether kernel-mediated (passthrough) MSI routes are supported on this
    /// entity. When true, [`connect_to`](Self::connect_to) enables routes on
    /// the connection (supplying `driver`).
    pub supports_routes: bool,
    /// Driver used to run kernel-mediated MSI routes (see
    /// [`PcieMsiPlatform::driver`]).
    pub driver: Arc<dyn SpawnDriver>,
}

impl PcieMsiRouting {
    /// Connect the routing to an [`MsiConnection`].
    pub fn connect_to(self, msi_conn: &pci_core::msi::MsiConnection) {
        if let Some(target) = self.signal_msi {
            msi_conn.connect(target);
        }
        if self.supports_routes {
            // The connected router binds passthrough fds (its `bind_msi`), and
            // falls back to a usermode poll on this driver when the guest
            // points the MSI address at a sink the kernel can't service.
            msi_conn.enable_msi_routes(self.driver);
        }
    }
}

impl PcieMsiPlatform<'_> {
    /// Wrap the partition's base `SignalMsi` (and, on x86, kernel irqfd) with
    /// platform-specific MSI controller translation and IOMMU interrupt
    /// remapping.
    ///
    /// On aarch64: the connected target is the chipset map router, which
    /// decodes both usermode signals and passthrough binds to the per-segment
    /// ITS / v2m doorbell sinks.
    /// On x86_64: models the root complex's `0xFEE` decode; with an emulated
    /// IOMMU, interrupt remapping is applied and kernel routes are disabled.
    pub fn wrap_msi(&self) -> PcieMsiRouting {
        // aarch64: the connected target is the chipset MSI map router for both
        // delivery forms; the per-segment ITS / v2m sinks (which hold their own
        // kernel routes) are reached by address decode. No wire-time backend
        // selection — a reprogram re-decodes at the map.
        #[cfg(guest_arch = "aarch64")]
        let (signal_msi, supports_routes): (
            Option<Arc<dyn pci_core::msi::SignalMsi>>,
            bool,
        ) = (Some(self.msi_router.clone()), self.supports_routes);

        #[cfg(guest_arch = "x86_64")]
        let mut signal_msi: Option<Arc<dyn pci_core::msi::SignalMsi>> =
            self.partition.as_signal_msi(Vtl::Vtl0);
        #[cfg(guest_arch = "x86_64")]
        let mut irqfd: Option<Arc<dyn vmcore::irqfd::IrqFd>> = self.partition.irqfd();

        // x86_64 IOMMU: wrap with interrupt remapping, and disable kernel
        // routes (they would bypass emulated remapping).
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
        // interrupt-message window (usermode), and the partition kernel irqfd
        // binds passthrough fds there; everything else falls through to the
        // generic downstream decode (the chipset MSI-sink map router).
        #[cfg(guest_arch = "x86_64")]
        let supports_routes = irqfd.is_some();
        #[cfg(guest_arch = "x86_64")]
        let signal_msi = signal_msi.map(|injector| {
            Arc::new(X86RootComplexMsi {
                injector,
                irqfd,
                generic: self.msi_router.clone(),
            }) as Arc<dyn pci_core::msi::SignalMsi>
        });

        PcieMsiRouting {
            signal_msi,
            supports_routes,
            driver: self.driver.clone(),
        }
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
        return PcieDeviceWiring {
            dma_target,
            msi: PcieMsiRouting {
                signal_msi: smmu_msi,
                supports_routes: msi.supports_routes,
                driver: msi.driver,
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
