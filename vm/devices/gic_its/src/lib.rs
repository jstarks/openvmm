// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GICv3 ITS instance as an emulated chipset device.
//!
//! Unlike GICv2m, the ITS has a hypervisor-backend-specific component: on KVM
//! the in-kernel vITS owns and services its MMIO register block. This device
//! still registers the ITS's MMIO frame so it can layer its `GITS_TRANSLATER`
//! register on as an MSI doorbell (via [`ControlMmioIntercept::add_doorbell`]),
//! so a device's outbound MSI write is recognized on the platform fabric's
//! downstream decode (the chipset MSI map) and delivered without locking this
//! device. Because the in-kernel vITS services actual register accesses, the
//! device's MMIO intercept only ever warns — registering the frame exists to
//! give the doorbell a covering entry in the map (the MMIO-first invariant)
//! and to give each ITS a save/restore identity in the device model.

#![forbid(unsafe_code)]

use chipset_device::ChipsetDevice;
use chipset_device::io::IoResult;
use chipset_device::mmio::ControlMmioIntercept;
use chipset_device::mmio::MmioIntercept;
use chipset_device::mmio::RegisterMmioIntercept;
use chipset_device::msi::DoorbellTarget;
use chipset_device::msi::SignalMsi;
use inspect::InspectMut;
use pal_event::Event;
use std::sync::Arc;
use virt::aarch64::gic_its::GicItsBackend;
use vmcore::device_state::ChangeDeviceState;
use vmcore::irqfd::IrqFd;
use vmcore::irqfd::IrqFdBinding;
use vmcore::irqfd::KernelMsiBinding;
use vmcore::save_restore::NoSavedState;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveError;
use vmcore::save_restore::SaveRestore;

/// Size of a GICv3 ITS MMIO frame: two 64 KiB pages (the control page and the
/// translation page holding `GITS_TRANSLATER`). Architecturally fixed.
const GIC_ITS_SIZE: u64 = 0x2_0000;

/// Length of the `GITS_TRANSLATER` doorbell register.
const GITS_TRANSLATER_LEN: u64 = 4;

/// A chipset device representing one GICv3 ITS instance.
///
/// On KVM the in-kernel vITS owns and services its MMIO register block, so the
/// device's MMIO intercept only ever warns. The device registers the ITS's
/// MMIO frame purely so it can layer its `GITS_TRANSLATER` register on as an
/// MSI doorbell (giving the doorbell a covering entry in the chipset MSI map),
/// and to give the ITS a save/restore identity in the device model. The
/// routing surface is provided by the [`GicItsBackend`].
#[derive(InspectMut)]
pub struct GicItsDevice {
    segment: u16,
    its_id: u32,
    #[inspect(hex)]
    base: u64,
    /// Keeps the ITS's MMIO frame (and its nested `GITS_TRANSLATER` doorbell)
    /// registered for the lifetime of the device.
    #[inspect(skip)]
    _control: Box<dyn ControlMmioIntercept>,
    #[inspect(with = "|b| inspect::adhoc(|req| b.inspect(req))")]
    backend: Arc<dyn GicItsBackend>,
}

impl GicItsDevice {
    /// Creates a new ITS device for `segment`, with its in-kernel MMIO register
    /// block at `base`, delegating routing and save/restore to `backend`.
    ///
    /// The ITS's MMIO frame is registered through `register_mmio` and its
    /// `GITS_TRANSLATER` register is layered on as an MSI doorbell, so a
    /// device's outbound MSI write is decoded by the chipset MSI map and
    /// delivered without locking this device.
    pub fn new(
        register_mmio: &mut dyn RegisterMmioIntercept,
        segment: u16,
        its_id: u32,
        base: u64,
        backend: Arc<dyn GicItsBackend>,
    ) -> Self {
        // Build the doorbell sink from the backend's routing surface: the
        // ioctl-backed `SignalMsi` fast path plus, for backends that support
        // it, the pre-registered irqfd route for passthrough devices.
        let sink: Arc<dyn SignalMsi> = Arc::new(GicItsSink {
            signal: backend.as_signal_msi(),
            irqfd: backend.irqfd(),
            translater_addr: backend.translater_addr(),
        });

        // Register the ITS's MMIO frame and layer its `GITS_TRANSLATER`
        // doorbell onto it (offset-relative, so it follows the frame).
        // MMIO-first is structural: the frame is inserted immediately before
        // its doorbell.
        let translater_offset = backend.translater_addr() - base;
        let mut control = register_mmio.new_io_region("its", GIC_ITS_SIZE);
        control.add_doorbell(
            translater_offset,
            GITS_TRANSLATER_LEN,
            DoorbellTarget::Msi(sink),
        );
        control.map(base);

        Self {
            segment,
            its_id,
            base,
            _control: control,
            backend,
        }
    }
}

/// The ITS doorbell sink: a [`SignalMsi`] that delivers emulated-device MSIs
/// through the backend's ioctl fast path, and binds passthrough-device fds
/// through the backend's irqfd route.
struct GicItsSink {
    signal: Arc<dyn SignalMsi>,
    irqfd: Option<Arc<dyn IrqFd>>,
    translater_addr: u64,
}

impl SignalMsi for GicItsSink {
    fn signal_msi(&self, devid: Option<u32>, address: u64, data: u32) {
        self.signal.signal_msi(devid, address, data);
    }

    fn bind_msi(
        &self,
        fd: &Event,
        devid: Option<u32>,
        address: u64,
        data: u32,
    ) -> Option<Box<dyn KernelMsiBinding>> {
        // Only writes to this ITS's `GITS_TRANSLATER` are kernel-serviceable
        // here; a mismatch means the address resolves to a different sink, so
        // fall back to the usermode `signal_msi` leg.
        if address != self.translater_addr {
            return None;
        }
        let route = self.irqfd.as_ref()?.new_irqfd_route(fd.clone()).ok()?;
        if !route.enable(address, data, devid) {
            return None;
        }
        Some(Box::new(IrqFdBinding(route)))
    }
}

impl ChangeDeviceState for GicItsDevice {
    fn start(&mut self) {}

    async fn stop(&mut self) {}

    async fn reset(&mut self) {}
}

impl ChipsetDevice for GicItsDevice {
    fn supports_mmio(&mut self) -> Option<&mut dyn MmioIntercept> {
        Some(self)
    }
}

impl MmioIntercept for GicItsDevice {
    fn mmio_read(&mut self, addr: u64, data: &mut [u8]) -> IoResult {
        // The in-kernel vITS services its register block; a trap here means an
        // access slipped past the kernel. Return all-ones and warn.
        tracelimit::warn_ratelimited!(addr, "unexpected read of in-kernel ITS register block");
        data.fill(0xff);
        IoResult::Ok
    }

    fn mmio_write(&mut self, addr: u64, _data: &[u8]) -> IoResult {
        // Writes to `GITS_TRANSLATER` are handled by the doorbell fast path;
        // any other trapped write means an access slipped past the in-kernel
        // vITS.
        tracelimit::warn_ratelimited!(addr, "unexpected write to in-kernel ITS register block");
        IoResult::Ok
    }
}

impl SaveRestore for GicItsDevice {
    // TODO: delegate to `backend.save()`/`backend.restore()` once the KVM
    // vITS state marshaling (KVM_DEV_ARM_ITS_SAVE_TABLES + the ITS register
    // block) is implemented. KVM aarch64 save/restore is greenfield today.
    type SavedState = NoSavedState;

    fn save(&mut self) -> Result<Self::SavedState, SaveError> {
        Ok(NoSavedState)
    }

    fn restore(&mut self, NoSavedState: Self::SavedState) -> Result<(), RestoreError> {
        Ok(())
    }
}
