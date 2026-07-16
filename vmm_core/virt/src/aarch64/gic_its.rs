// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GICv3 ITS backend seam.
//!
//! The ITS (Interrupt Translation Service) is modeled as a device object
//! owned in device-land (see the `GicItsDevice` chipset device), parameterized
//! over a narrow backend seam so that ITS ownership and save/restore are
//! decoupled from the virt backend. On KVM the backend is a thin proxy over
//! the in-kernel vITS; a future userspace emulator would be a peer
//! implementation.
//!
//! One backend instance exists per PCI segment; the guest selects the target
//! ITS by the doorbell (`GITS_TRANSLATER`) address, so device IDs are plain
//! 16-bit RIDs with no segment prefix.

use crate::irqfd::IrqFd;
use mesh_protobuf::Protobuf;
use pci_core::msi::SignalMsi;
use std::sync::Arc;

/// Marshaled ITS state for save/restore.
///
/// For the KVM backend this carries the `GITS_*` register block; the ITS
/// device and collection tables are flushed to guest RAM (which rides along
/// with the memory snapshot) via `KVM_DEV_ARM_ITS_SAVE_TABLES`.
#[derive(Debug, Clone, Default, Protobuf)]
#[mesh(package = "virt.aarch64.its")]
pub struct ItsSavedState {
    /// `GITS_CTLR`.
    #[mesh(1)]
    pub gits_ctlr: u32,
    /// `GITS_CBASER`.
    #[mesh(2)]
    pub gits_cbaser: u64,
    /// `GITS_CREADR`.
    #[mesh(3)]
    pub gits_creadr: u64,
    /// `GITS_CWRITER`.
    #[mesh(4)]
    pub gits_cwriter: u64,
    /// `GITS_BASER<n>`.
    #[mesh(5)]
    pub gits_baser: Vec<u64>,
}

/// A narrow backend seam for a single GICv3 ITS instance.
///
/// Implementations expose the routing surface (`SignalMsi` for emulated-device
/// MSIs, an irqfd route for passthrough) and save/restore, all bound to this
/// ITS's doorbell address.
pub trait GicItsBackend: Send + Sync {
    /// Returns a [`SignalMsi`] that injects emulated-device MSIs through this
    /// ITS. The returned target validates that MSI writes target this ITS's
    /// `GITS_TRANSLATER` and forwards them with the device's RID as the ITS
    /// device ID.
    fn as_signal_msi(&self) -> Arc<dyn SignalMsi>;

    /// Returns an irqfd routing interface that delivers passthrough-device
    /// MSIs through this ITS, or `None` if the backend does not support irqfd
    /// routing.
    fn irqfd(&self) -> Option<Arc<dyn IrqFd>>;

    /// Returns this ITS's `GITS_TRANSLATER` physical address, used by ACPI/DT
    /// description and MSI-address validation.
    fn translater_addr(&self) -> u64;

    /// Adds backend-specific ITS state to an inspection request.
    ///
    /// The default surfaces nothing; backends override to expose their
    /// implementation kind and any cheaply-readable identity/configuration.
    /// Implementations must not perform operations that disturb a running VM
    /// (e.g. reads that quiesce all VPs).
    fn inspect(&self, _req: inspect::Request<'_>) {}

    /// Marshals this ITS's state for save.
    fn save(&self) -> anyhow::Result<ItsSavedState>;

    /// Restores this ITS's state.
    fn restore(&self, state: ItsSavedState) -> anyhow::Result<()>;
}
