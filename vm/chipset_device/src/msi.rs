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
//! which delivers matching writes to a [`SignalMsi`] wrapped in a
//! [`DoorbellTarget`]. On x86 there is no MSI "device": the root complex
//! recognizes the `0xFEE` window on a device's outbound path and converts it in
//! place, so the map holds no sinks. Either way the fabric decodes an address to
//! a downstream target.

use inspect::Inspect;
use pal_event::Event;
use std::sync::Arc;
use vmcore::irqfd::KernelMsiBinding;

/// An object that can signal MSI interrupts.
///
/// This is the fabric's outbound-MSI decode seam. It has two forms of the same
/// operation, distinguished only by *when* the target is resolved:
///
/// - [`signal_msi`](Self::signal_msi) delivers a message *now*, in usermode.
/// - [`bind_msi`](Self::bind_msi) pre-registers a caller-owned fd so the
///   *kernel* injects the same message when the fd is later signaled, with no
///   usermode transition (device passthrough, e.g. VFIO).
///
/// Both decode the address the same way; `bind_msi` is just the
/// kernel-accelerated binding time of `signal_msi`. Emulated sinks implement
/// only `signal_msi` and inherit the default `bind_msi` (which returns `None`,
/// so callers fall back to `signal_msi`).
pub trait SignalMsi: Send + Sync {
    /// Signals a message-signaled interrupt at the specified address with the specified data.
    ///
    /// `devid` is an optional device identity. Its meaning is layer-dependent:
    /// at the device layer it is a BDF for multi-function devices (`None` for
    /// single-function); at the ITS wrapper layer it is the fully composed ITS
    /// device ID; backends that don't need it ignore it.
    fn signal_msi(&self, devid: Option<u32>, address: u64, data: u32);

    /// Pre-registers `fd` so that the hypervisor injects this MSI directly when
    /// the fd is signaled, without a usermode transition.
    ///
    /// Returns `Some(binding)` if the address decodes to a kernel-serviceable
    /// sink (the returned [`KernelMsiBinding`] owns the kernel registration and
    /// unbinds on drop), or `None` if it does not — in which case the caller
    /// should deliver via [`signal_msi`](Self::signal_msi) in usermode instead.
    ///
    /// The default returns `None`: emulated sinks are not kernel-serviceable.
    fn bind_msi(
        &self,
        fd: &Event,
        devid: Option<u32>,
        address: u64,
        data: u32,
    ) -> Option<Box<dyn KernelMsiBinding>> {
        let _ = (fd, devid, address, data);
        None
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
    /// A message-carrying MSI doorbell (RID + data). The [`SignalMsi`] both
    /// delivers in usermode ([`signal_msi`](SignalMsi::signal_msi)) and, for
    /// kernel-serviceable sinks, pre-registers passthrough fds
    /// ([`bind_msi`](SignalMsi::bind_msi)).
    Msi(#[inspect(skip)] Arc<dyn SignalMsi>),
}

impl DoorbellTarget {
    /// Delivers a write that landed on this doorbell.
    ///
    /// `devid` is the requester ID (`DeviceID`) when the write is a bus-master
    /// MSI on the outbound path, or `None` for a CPU access.
    pub fn signal(&self, devid: Option<u32>, address: u64, data: u32) {
        match self {
            DoorbellTarget::Msi(sink) => sink.signal_msi(devid, address, data),
        }
    }

    /// Pre-registers `fd` for kernel-mediated delivery of writes that land on
    /// this doorbell, if the target is kernel-serviceable. See
    /// [`SignalMsi::bind_msi`].
    pub fn bind(
        &self,
        fd: &Event,
        devid: Option<u32>,
        address: u64,
        data: u32,
    ) -> Option<Box<dyn KernelMsiBinding>> {
        match self {
            DoorbellTarget::Msi(sink) => sink.bind_msi(fd, devid, address, data),
        }
    }
}
