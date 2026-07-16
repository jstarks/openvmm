// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GICv3 GICv2m MSI frame as a self-contained emulated chipset device.
//!
//! GICv2m has no in-kernel or hypervisor component: an MSI write to the
//! frame's `SETSPI_NS` register simply asserts a GIC SPI. This device
//! therefore depends only on generic aarch64 partition capabilities —
//! [`ControlGic`] for asserting the SPI (both from the doorbell fast path and
//! from direct guest MMIO writes to the frame), and a generic SPI irqfd route
//! for passthrough devices — and carries no v2m knowledge in any virt backend.
//!
//! The frame's `SETSPI_NS` register is the MSI doorbell: the device layers it
//! onto the MMIO region it already owns via
//! [`ControlMmioIntercept::add_doorbell`], so a device's outbound MSI write is
//! recognized on the platform fabric's downstream decode (the chipset MSI map)
//! and delivered without locking this device. Reads of the frame's control
//! registers (`TYPER`/`IIDR`) still go through the device's MMIO intercept.

#![forbid(unsafe_code)]

use aarch64defs::gic::GicV2mRegister;
use chipset_device::ChipsetDevice;
use chipset_device::io::IoError;
use chipset_device::io::IoResult;
use chipset_device::mmio::ControlMmioIntercept;
use chipset_device::mmio::MmioIntercept;
use chipset_device::mmio::RegisterMmioIntercept;
use chipset_device::msi::DoorbellTarget;
use chipset_device::msi::MsiSink;
use inspect::InspectMut;
use pal_event::Event;
use pci_core::msi::SignalMsi;
use std::ops::Range;
use std::sync::Arc;
use virt::irqcon::ControlGic;
use vmcore::device_state::ChangeDeviceState;
use vmcore::irqfd::IrqFd;
use vmcore::irqfd::IrqFdRoute;
use vmcore::save_restore::NoSavedState;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveError;
use vmcore::save_restore::SaveRestore;

/// GICv2m MSI frame chipset device.
///
/// Owns the 4 KiB MSI frame MMIO region. MSIs are delivered as GIC SPI
/// assertions: emulated-device and direct-guest writes to `SETSPI_NS` are
/// recognized by the frame's doorbell (layered onto the MMIO region at
/// construction) and dispatched via [`ControlGic`], while passthrough devices
/// use the irqfd returned by [`GicV2mDevice::irqfd`].
#[derive(InspectMut)]
pub struct GicV2mDevice {
    /// Keeps the frame's MMIO region (and its nested `SETSPI_NS` doorbell)
    /// registered for the lifetime of the device.
    #[inspect(skip)]
    _control: Box<dyn ControlMmioIntercept>,
    #[inspect(hex)]
    frame_base: u64,
    #[inspect(hex)]
    setspi_addr: u64,
    spi_base: u32,
    spi_count: u32,
    #[inspect(skip)]
    irqcon: Arc<dyn ControlGic>,
    /// Wrapped SPI irqfd used for passthrough-device MSI delivery, if the
    /// backend supports it.
    #[inspect(skip)]
    passthrough_irqfd: Option<Arc<dyn IrqFd>>,
}

impl GicV2mDevice {
    /// Creates a new GICv2m MSI frame device.
    ///
    /// The frame's MMIO region is registered through `register_mmio` and its
    /// `SETSPI_NS` register is layered on as an MSI doorbell, so a device's
    /// outbound MSI write is decoded by the chipset MSI map and delivered
    /// without locking this device. `frame_base` is the guest-visible frame
    /// base address (one 4 KiB page), `spi_base`/`spi_count` describe the SPI
    /// range the frame owns, `irqcon` asserts the SPIs, and `spi_irqfd` (if
    /// any) delivers passthrough MSIs.
    pub fn new(
        register_mmio: &mut dyn RegisterMmioIntercept,
        frame_base: u64,
        spi_base: u32,
        spi_count: u32,
        irqcon: Arc<dyn ControlGic>,
        spi_irqfd: Option<Arc<dyn IrqFd>>,
    ) -> Self {
        let setspi_addr = frame_base + GicV2mRegister::SETSPI_NS.0 as u64;
        let spi_range = spi_base..spi_base + spi_count;

        // Build the doorbell sink: the userspace `SignalMsi` fast path (always
        // present) plus, for backends that support it, a pre-registered SPI
        // irqfd route for passthrough devices.
        let signal: Arc<dyn SignalMsi> = Arc::new(GicV2mSignalMsi {
            setspi_addr,
            spi_range: spi_range.clone(),
            irqcon: irqcon.clone(),
        });
        let passthrough_irqfd = spi_irqfd.map(|inner| {
            Arc::new(GicV2mIrqFd {
                inner,
                setspi_addr,
                spi_range: spi_range.clone(),
            }) as Arc<dyn IrqFd>
        });
        let sink = MsiSink {
            signal,
            irqfd: passthrough_irqfd.clone(),
        };

        // Register the frame's MMIO region and layer the `SETSPI_NS` doorbell
        // onto it (offset-relative, so it follows the region). MMIO-first is
        // structural: the frame is inserted immediately before its doorbell.
        let mut control = register_mmio.new_io_region("gic_v2m", FRAME_SIZE);
        control.add_doorbell(
            GicV2mRegister::SETSPI_NS.0 as u64,
            SETSPI_LEN,
            DoorbellTarget::Msi(sink),
        );
        control.map(frame_base);

        Self {
            _control: control,
            frame_base,
            setspi_addr,
            spi_base,
            spi_count,
            irqcon,
            passthrough_irqfd,
        }
    }

    fn spi_range(&self) -> Range<u32> {
        self.spi_base..self.spi_base + self.spi_count
    }

    /// Returns an [`IrqFd`] for passthrough-device MSI delivery through this
    /// frame, or `None` if the backend does not support SPI irqfd routing.
    pub fn irqfd(&self) -> Option<Arc<dyn IrqFd>> {
        self.passthrough_irqfd.clone()
    }
}

/// Size of the v2m MSI frame (one 4 KiB page is the architectural minimum).
const FRAME_SIZE: u64 = 0x1000;

/// Size of the `SETSPI_NS` doorbell register.
const SETSPI_LEN: u64 = 4;

impl ChangeDeviceState for GicV2mDevice {
    fn start(&mut self) {}

    async fn stop(&mut self) {}

    async fn reset(&mut self) {}
}

impl ChipsetDevice for GicV2mDevice {
    fn supports_mmio(&mut self) -> Option<&mut dyn MmioIntercept> {
        Some(self)
    }
}

impl SaveRestore for GicV2mDevice {
    // The v2m frame is stateless: TYPER is read-only, SETSPI_NS is write-only.
    type SavedState = NoSavedState;

    fn save(&mut self) -> Result<Self::SavedState, SaveError> {
        Ok(NoSavedState)
    }

    fn restore(&mut self, NoSavedState: Self::SavedState) -> Result<(), RestoreError> {
        Ok(())
    }
}

impl MmioIntercept for GicV2mDevice {
    fn mmio_read(&mut self, addr: u64, data: &mut [u8]) -> IoResult {
        if data.len() != 4 {
            return IoResult::Err(IoError::InvalidAccessSize);
        }
        let offset = (addr - self.frame_base) as u16;
        let value: u32 = match GicV2mRegister(offset) {
            // MSI_TYPER: bits[25:16] = base SPI, bits[9:0] = number of SPIs.
            GicV2mRegister::TYPER => ((self.spi_base & 0x3ff) << 16) | (self.spi_count & 0x3ff),
            // Implementation identification — report nothing specific.
            GicV2mRegister::IIDR => 0,
            // PIDR2: architecture revision in bits[7:4]. GICv2m frames report
            // the GIC architecture revision; leave 0 (unimplemented) here.
            GicV2mRegister::PIDR2 => 0,
            _ => 0,
        };
        data.copy_from_slice(&value.to_le_bytes());
        IoResult::Ok
    }

    fn mmio_write(&mut self, addr: u64, data: &[u8]) -> IoResult {
        if data.len() != 4 {
            return IoResult::Err(IoError::InvalidAccessSize);
        }
        let offset = (addr - self.frame_base) as u16;
        let value = u32::from_le_bytes(data.try_into().unwrap());
        // `SETSPI_NS` writes are normally intercepted by the layered doorbell
        // (tier 2) and never reach here; deliver defensively if one does.
        if GicV2mRegister(offset) == GicV2mRegister::SETSPI_NS {
            deliver_spi(&*self.irqcon, &self.spi_range(), value);
        } else {
            tracelimit::warn_ratelimited!(offset, value, "unexpected v2m frame register write");
        }
        IoResult::Ok
    }
}

/// Validates and delivers a v2m SETSPI assertion via [`ControlGic`].
fn deliver_spi(irqcon: &dyn ControlGic, spi_range: &Range<u32>, spi: u32) {
    if !spi_range.contains(&spi) {
        tracelimit::warn_ratelimited!(spi, "MSI data (SPI ID) outside v2m SPI range");
        return;
    }
    irqcon.set_spi_irq(spi, true);
}

/// A [`SignalMsi`] that decodes GICv2m-style MSIs and delivers them as SPI
/// assertions via [`ControlGic`].
///
/// When a device fires an MSI it writes the assigned GIC interrupt ID to the
/// SETSPI_NS register inside the v2m frame (`frame_base + 0x0040`). The host
/// intercepts that write (or, for software devices, synthesizes it) and calls
/// [`signal_msi`](SignalMsi::signal_msi) with `address = frame_base + 0x0040`
/// and `data = interrupt_id`.
struct GicV2mSignalMsi {
    setspi_addr: u64,
    spi_range: Range<u32>,
    irqcon: Arc<dyn ControlGic>,
}

impl SignalMsi for GicV2mSignalMsi {
    fn signal_msi(&self, _devid: Option<u32>, address: u64, data: u32) {
        if address != self.setspi_addr {
            tracelimit::warn_ratelimited!(
                address,
                data,
                "unexpected MSI address (expected v2m SETSPI_NS)"
            );
            return;
        }
        deliver_spi(&*self.irqcon, &self.spi_range, data);
    }
}

/// An [`IrqFd`] wrapper that validates the v2m SETSPI address and delivers the
/// route through the backend's generic SPI irqfd.
struct GicV2mIrqFd {
    inner: Arc<dyn IrqFd>,
    setspi_addr: u64,
    spi_range: Range<u32>,
}

impl IrqFd for GicV2mIrqFd {
    fn new_irqfd_route(&self, event: Event) -> anyhow::Result<Box<dyn IrqFdRoute>> {
        Ok(Box::new(GicV2mIrqFdRoute {
            inner: self.inner.new_irqfd_route(event)?,
            setspi_addr: self.setspi_addr,
            spi_range: self.spi_range.clone(),
        }))
    }
}

/// An [`IrqFdRoute`] that validates the v2m SETSPI address on `enable` and
/// programs the underlying generic SPI route with the SPI interrupt ID.
struct GicV2mIrqFdRoute {
    inner: Box<dyn IrqFdRoute>,
    setspi_addr: u64,
    spi_range: Range<u32>,
}

impl IrqFdRoute for GicV2mIrqFdRoute {
    fn event(&self) -> &Event {
        self.inner.event()
    }

    fn enable(&self, address: u64, data: u32, _devid: Option<u32>) {
        if address != self.setspi_addr {
            tracelimit::warn_ratelimited!(
                address,
                data,
                "unexpected v2m irqfd MSI address (expected SETSPI_NS)"
            );
            return;
        }
        if !self.spi_range.contains(&data) {
            tracelimit::warn_ratelimited!(data, "v2m irqfd SPI ID outside frame range");
            return;
        }
        // The generic SPI route interprets `data` as the SPI interrupt ID.
        self.inner.enable(address, data, None);
    }

    fn disable(&self) {
        self.inner.disable();
    }
}
