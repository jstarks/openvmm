// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Traits for signaling MSI interrupts.
//!
//! An MSI is, in hardware, a bus-mastered memory write a device performs to a
//! platform-defined doorbell address. The platform fabric decodes that write
//! and delivers an interrupt. [`SignalMsi`] is the seam that models that
//! decode: it is the outbound MSI path a device (or an intermediate fabric
//! component) writes to.
//!
//! On ARM the doorbell is a real downstream MMIO block (the GICv3 ITS or a
//! GICv2m frame); those blocks layer their doorbell onto the MMIO region they
//! already own, via
//! [`ControlMmioIntercept::add_doorbell`](crate::mmio::ControlMmioIntercept::add_doorbell),
//! which delivers matching writes to an [`MsiSink`] wrapped in a
//! [`DoorbellTarget`]. On x86 there is no MSI "device": the root complex
//! recognizes the `0xFEE` window on a device's outbound path and converts it in
//! place, so the map holds no sinks. Either way the fabric decodes an address to
//! a downstream target.

use inspect::Inspect;
use std::sync::Arc;
use vmcore::irqfd::IrqFd;

/// An object that can signal MSI interrupts.
pub trait SignalMsi: Send + Sync {
    /// Signals a message-signaled interrupt at the specified address with the specified data.
    ///
    /// `devid` is an optional device identity. Its meaning is layer-dependent:
    /// at the device layer it is a BDF for multi-function devices (`None` for
    /// single-function); at the ITS wrapper layer it is the fully composed ITS
    /// device ID; backends that don't need it ignore it.
    fn signal_msi(&self, devid: Option<u32>, address: u64, data: u32);
}

/// A registered MSI sink: the downstream doorbell target that a device's
/// outbound MSI write decodes to.
///
/// This bundles the two existing delivery traits with a shared identity: the
/// [`SignalMsi`] fast path (always present) and, for backends that support
/// kernel-mediated routes, an [`IrqFd`] for pre-registered delivery
/// (e.g. VFIO passthrough). Doorbells are static, so a sink is registered once
/// at resolve time and looked up by address on the MSI hot path.
#[derive(Clone)]
pub struct MsiSink {
    /// The signal path used for userspace-mediated MSI delivery.
    pub signal: Arc<dyn SignalMsi>,
    /// The optional kernel-mediated route path, when the backend supports it.
    pub irqfd: Option<Arc<dyn IrqFd>>,
}

impl std::fmt::Debug for MsiSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsiSink")
            .field("has_irqfd", &self.irqfd.is_some())
            .finish()
    }
}

/// What a doorbell write is delivered to.
///
/// A doorbell is a sub-range of an MMIO region whose writes are recognized and
/// delivered directly to a downstream target instead of falling through to the
/// owning device's MMIO intercept. A device layers one onto its MMIO region via
/// [`ControlMmioIntercept::add_doorbell`](crate::mmio::ControlMmioIntercept::add_doorbell).
/// Today the only flavor is [`Msi`](DoorbellTarget::Msi).
#[derive(Inspect, Clone)]
#[inspect(tag = "kind")]
pub enum DoorbellTarget {
    /// A message-carrying MSI doorbell (RID + data). Bundles the pre-registered
    /// route (irqfd) form.
    Msi(#[inspect(rename = "has_irqfd", with = "|x| x.irqfd.is_some()")] MsiSink),
}

impl DoorbellTarget {
    /// Delivers a write that landed on this doorbell.
    ///
    /// `devid` is the requester ID (`DeviceID`) when the write is a bus-master
    /// MSI on the outbound path, or `None` for a CPU access.
    pub fn signal(&self, devid: Option<u32>, address: u64, data: u32) {
        match self {
            DoorbellTarget::Msi(sink) => sink.signal.signal_msi(devid, address, data),
        }
    }
}
