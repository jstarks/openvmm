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
//! GICv2m frame); those blocks register their doorbell range as an [`MsiSink`]
//! in the platform's arch-neutral MSI-sink map via [`RegisterMsiSink`]. On x86
//! there is no MSI "device": the root complex recognizes the `0xFEE` window on
//! a device's outbound path and converts it in place, so the map holds no
//! sinks. Either way the fabric decodes an address to a downstream target.

use std::ops::RangeInclusive;
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

/// A trait to register device MSI doorbell ranges (sinks) with the platform's
/// arch-neutral MSI-sink map.
///
/// This mirrors [`RegisterMmioIntercept`](crate::mmio::RegisterMmioIntercept):
/// a device claims a downstream address range at resolve time. Unlike MMIO —
/// where dispatch calls back into the device under lock — the sink handler is
/// stored directly, so the MSI hot path never re-enters the device.
pub trait RegisterMsiSink: Send {
    /// Claims an MSI doorbell address range, routing MSI writes whose address
    /// falls within `range` to `sink`.
    fn claim(&mut self, region_name: &str, range: RangeInclusive<u64>, sink: MsiSink);
}
