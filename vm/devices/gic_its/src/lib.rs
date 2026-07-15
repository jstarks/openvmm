// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GICv3 ITS instance as a headless emulated chipset device.
//!
//! Unlike GICv2m, the ITS has a hypervisor-backend-specific component: on KVM
//! the in-kernel vITS owns its MMIO register block. This device therefore
//! registers no MMIO (`supports_mmio` returns `None`) and instead exists to
//! give each ITS a save/restore identity in the device model. Its routing
//! surface (`SignalMsi`/irqfd) is consumed directly from the [`GicItsBackend`]
//! seam by the PCIe MSI wiring.

#![forbid(unsafe_code)]

use chipset_device::ChipsetDevice;
use chipset_device::mmio::MmioIntercept;
use inspect::InspectMut;
use std::sync::Arc;
use virt::aarch64::gic_its::GicItsBackend;
use vmcore::device_state::ChangeDeviceState;
use vmcore::save_restore::NoSavedState;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveError;
use vmcore::save_restore::SaveRestore;

/// A headless chipset device representing one GICv3 ITS instance.
///
/// On KVM the in-kernel vITS owns its MMIO register block, so this device
/// registers no MMIO (`supports_mmio` returns `None`). It exists to give the
/// ITS a save/restore identity in the device model; the routing surface is
/// consumed directly from the [`GicItsBackend`].
#[derive(InspectMut)]
pub struct GicItsDevice {
    segment: u16,
    its_id: u32,
    #[inspect(hex)]
    base: u64,
    #[inspect(skip)]
    backend: Arc<dyn GicItsBackend>,
}

impl GicItsDevice {
    /// Creates a new headless ITS device for `segment`, with in-kernel MMIO
    /// register block at `base`, delegating save/restore to `backend`.
    pub fn new(segment: u16, its_id: u32, base: u64, backend: Arc<dyn GicItsBackend>) -> Self {
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
