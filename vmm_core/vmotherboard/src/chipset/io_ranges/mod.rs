// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Exports [`IoRanges`], which models a linear address-space with certain
//! regions "claimed" by [`ChipsetDevice`]s.
//!
//! - e.g: `IoRanges<u64>` can be used to model 64-bit MMIO.
//! - e.g: `IoRanges<u16>` can be used to model 16-bit x86 port IO.

use address_filter::AddressFilter;
use address_filter::RangeKey;
use chipset_device::ChipsetDevice;
use chipset_device::msi::MsiSink;
use chipset_device::msi::SignalMsi;
use closeable_mutex::CloseableMutex;
use inspect::Inspect;
use inspect_counters::SharedCounter;
use parking_lot::RwLock;
use range_map_vec::RangeMap;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::Weak;

struct IoRangesInner<T> {
    map: RangeMap<T, RangeEntry>,
    trace_on: AddressFilter<T>,
    break_on: AddressFilter<T>,
    // Starts off a `Some(Vec::new())`, and then set to `None` as part of
    // Chipset finalization
    static_registration_conflicts: Option<Vec<IoRangeConflict<T>>>,
    fallback_device: Option<Arc<CloseableMutex<dyn ChipsetDevice>>>,
}

#[derive(Debug, Clone)]
pub struct IoRangeConflict<T> {
    existing_dev_region: (Arc<str>, Arc<str>, RangeInclusive<T>),
    conflict_dev_region: (Arc<str>, Arc<str>, RangeInclusive<T>),
}

impl<T> std::error::Error for IoRangeConflict<T> where T: std::fmt::LowerHex + core::fmt::Debug {}
impl<T> std::fmt::Display for IoRangeConflict<T>
where
    T: std::fmt::LowerHex + core::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}:{:#x?} conflicts with existing {}/{}:{:#x?}",
            self.conflict_dev_region.0,
            self.conflict_dev_region.1,
            self.conflict_dev_region.2,
            self.existing_dev_region.0,
            self.existing_dev_region.1,
            self.existing_dev_region.2,
        )
    }
}

/// The target of a registered address range in the generalized map.
///
/// MMIO device intercepts and MSI doorbell sinks share one address space, so
/// they share one map. CPU MMIO/PIO dispatch handles the [`MmioDevice`] arm
/// (lock + intercept); the device outbound MSI router handles the [`MsiSink`]
/// arm (lock-free `signal_msi`). Each consumer treats the other arm as a miss.
///
/// [`MmioDevice`]: RangeTarget::MmioDevice
/// [`MsiSink`]: RangeTarget::MsiSink
#[derive(Inspect)]
#[inspect(tag = "kind")]
enum RangeTarget {
    /// An MMIO/PIO device that intercepts CPU accesses in this range.
    MmioDevice(
        #[inspect(rename = "device_is_init", with = "|x| x.upgrade().is_some()")]
        Weak<CloseableMutex<dyn ChipsetDevice>>,
    ),
    /// An MSI doorbell sink: device MSI writes whose address falls in this
    /// range are dispatched lock-free to the sink. Only ever present in the
    /// `u64` (MMIO) map; the `u16` (PIO) map never accepts sinks.
    MsiSink(#[inspect(rename = "has_irqfd", with = "|x| x.irqfd.is_some()")] MsiSink),
}

#[derive(Inspect)]
struct RangeEntry {
    region_name: Arc<str>,
    dev_name: Arc<str>,
    target: RangeTarget,
    read_count: SharedCounter,
    write_count: SharedCounter,
}

/// Local newtype wrapping the lock-guarded state, so the shared `Arc` can be
/// coerced directly to `Arc<dyn SignalMsi>` for the `u64` map without a second
/// `Arc` layer (the orphan rules forbid implementing `SignalMsi` on the
/// foreign `RwLock` directly). Derefs to the lock so callers use it as before.
struct LockedRanges<T>(RwLock<IoRangesInner<T>>);

impl<T> std::ops::Deref for LockedRanges<T> {
    type Target = RwLock<IoRangesInner<T>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone)]
pub struct IoRanges<T> {
    inner: Arc<LockedRanges<T>>,
}

impl<T: RangeKey> IoRanges<T> {
    pub fn new(
        trace_on_unknown: bool,
        fallback_device: Option<Arc<CloseableMutex<dyn ChipsetDevice>>>,
    ) -> Self {
        Self {
            inner: Arc::new(LockedRanges(RwLock::new(IoRangesInner {
                map: RangeMap::new(),
                trace_on: AddressFilter::new(trace_on_unknown),
                break_on: AddressFilter::new(false),
                static_registration_conflicts: Some(Vec::new()),
                fallback_device,
            }))),
        }
    }

    pub fn register(
        &self,
        start: T,
        end: T,
        region_name: Arc<str>,
        dev: Weak<CloseableMutex<dyn ChipsetDevice>>,
        dev_name: Arc<str>,
    ) -> Result<(), IoRangeConflict<T>> {
        self.register_target(
            start,
            end,
            region_name,
            dev_name,
            RangeTarget::MmioDevice(dev),
        )
    }

    fn register_target(
        &self,
        start: T,
        end: T,
        region_name: Arc<str>,
        dev_name: Arc<str>,
        target: RangeTarget,
    ) -> Result<(), IoRangeConflict<T>> {
        let mut inner = self.inner.write();
        match inner.map.entry(start..=end) {
            range_map_vec::Entry::Vacant(entry) => {
                entry.insert(RangeEntry {
                    region_name,
                    dev_name,
                    target,
                    read_count: Default::default(),
                    write_count: Default::default(),
                });
                Ok(())
            }
            range_map_vec::Entry::Overlapping(entry) => {
                let existing_dev_region = {
                    let (start, end, entry) = entry.get();
                    (
                        entry.dev_name.clone(),
                        entry.region_name.clone(),
                        *start..=*end,
                    )
                };
                let conflict = IoRangeConflict {
                    existing_dev_region,
                    conflict_dev_region: (dev_name, region_name, start..=end),
                };

                if let Some(v) = inner.static_registration_conflicts.as_mut() {
                    v.push(conflict.clone())
                }

                Err(conflict)
            }
        }
    }

    pub fn revoke(&self, start: T) {
        let mut inner = self.inner.write();
        inner.map.remove(&start);
    }

    pub fn lookup(&self, addr: T, is_read: bool) -> LookupResult {
        static UNKNOWN_DEVICE: OnceLock<Arc<CloseableMutex<dyn ChipsetDevice>>> = OnceLock::new();
        static UNKNOWN_DEVICE_NAME: OnceLock<Arc<str>> = OnceLock::new();
        static UNKNOWN_RANGE: OnceLock<Arc<str>> = OnceLock::new();

        let inner = self.inner.read();
        let entry = inner.map.get(&addr);
        if let Some(entry) = entry {
            if is_read {
                entry.read_count.increment()
            } else {
                entry.write_count.increment()
            }
        }

        let unknown = || {
            (
                inner.fallback_device.clone().unwrap_or_else(|| {
                    UNKNOWN_DEVICE
                        .get_or_init(|| {
                            Arc::new(CloseableMutex::new(missing_dev::MissingDev::from_manifest(
                                missing_dev::MissingDevManifest::new(),
                                &mut chipset_device::mmio::ExternallyManagedMmioIntercepts,
                                &mut chipset_device::pio::ExternallyManagedPortIoIntercepts,
                            )))
                        })
                        .clone()
                }),
                UNKNOWN_DEVICE_NAME
                    .get_or_init(|| "<unknown>".into())
                    .clone(),
            )
        };

        let (target, dev_name) = match entry {
            Some(e) => match &e.target {
                RangeTarget::MmioDevice(dev) => match dev.upgrade() {
                    Some(d) => (LookupTarget::Device(d), e.dev_name.clone()),
                    None => {
                        let (d, n) = unknown();
                        (LookupTarget::Device(d), n)
                    }
                },
                // A CPU access landing on an MSI doorbell is itself an MSI:
                // the dispatch path signals the sink (see `Chipset::mmio_*`).
                RangeTarget::MsiSink(sink) => {
                    (LookupTarget::MsiSink(sink.clone()), e.dev_name.clone())
                }
            },
            None => {
                let (d, n) = unknown();
                (LookupTarget::Device(d), n)
            }
        };

        let trace = inner.trace_on.filtered(&addr, entry.is_some());
        let trace = trace.then(|| {
            entry.map_or_else(
                || UNKNOWN_RANGE.get_or_init(|| "<unknown>".into()).clone(),
                |e| e.region_name.clone(),
            )
        });
        let debug_break = inner.break_on.filtered(&addr, entry.is_some());
        LookupResult {
            target,
            dev_name,
            trace,
            debug_break,
        }
    }

    pub fn take_static_registration_conflicts(&mut self) -> Vec<IoRangeConflict<T>> {
        self.inner
            .write()
            .static_registration_conflicts
            .take()
            .expect("must only be called once")
    }

    pub fn is_occupied(&self, addr: T) -> bool {
        self.inner.read().map.contains(&addr)
    }
}

/// MSI-doorbell-sink API, specific to the `u64` (MMIO) address space. MSI
/// doorbells share the MMIO address space with device BARs and RAM, so they
/// live in the same generalized map; the `u16` (PIO) map never carries sinks.
impl IoRanges<u64> {
    /// Registers an MSI doorbell range, routing device MSI writes whose
    /// address falls within `start..=end` to `sink`. Overlaps with any
    /// existing entry (MMIO device or sink) are recorded as static conflicts,
    /// surfaced during chipset finalization.
    pub fn register_msi_sink(
        &self,
        start: u64,
        end: u64,
        region_name: Arc<str>,
        dev_name: Arc<str>,
        sink: MsiSink,
    ) -> Result<(), IoRangeConflict<u64>> {
        self.register_target(
            start,
            end,
            region_name,
            dev_name,
            RangeTarget::MsiSink(sink),
        )
    }

    /// Returns this map as an MSI router, reusing the existing inner `Arc`
    /// (coerced to `dyn SignalMsi`) rather than wrapping it in a second `Arc`.
    ///
    /// The router resolves a device's outbound MSI by looking its address up
    /// in the doorbell sinks and dispatching to the matched sink.
    pub fn as_msi_router(&self) -> Arc<dyn SignalMsi> {
        self.inner.clone()
    }
}

impl IoRangesInner<u64> {
    /// Looks up the MSI sink whose doorbell range contains `address`, if the
    /// covering entry is a sink (rather than an MMIO device).
    fn lookup_msi_sink(&self, address: u64) -> Option<MsiSink> {
        match self.map.get(&address) {
            Some(RangeEntry {
                target: RangeTarget::MsiSink(sink),
                ..
            }) => Some(sink.clone()),
            _ => None,
        }
    }
}

/// The generalized `u64` map doubles as the platform's MSI router: a device's
/// outbound MSI is an address lookup into the doorbell sinks, then dispatch to
/// the matched sink. Implemented on the inner locked state so the map's
/// existing `Arc` can be coerced directly to `Arc<dyn SignalMsi>` (see
/// [`as_msi_router`](IoRanges::as_msi_router)) without a second `Arc` layer.
impl SignalMsi for LockedRanges<u64> {
    fn signal_msi(&self, devid: Option<u32>, address: u64, data: u32) {
        // Clone the sink out under the read lock, then release the lock before
        // dispatching so the MSI isn't delivered while the map is locked.
        let sink = self.read().lookup_msi_sink(address);
        match sink {
            Some(sink) => sink.signal.signal_msi(devid, address, data),
            None => {
                // A miss (no entry, or the entry is an MMIO device rather than
                // a doorbell) means the MSI-X entry was misprogrammed: it
                // targeted an address with no downstream doorbell. Drop it.
                // (The generic memory / peer-to-peer fallback is deferred.)
                tracelimit::warn_ratelimited!(
                    address,
                    data,
                    "dropped MSI: no doorbell sink for address"
                );
            }
        }
    }
}

/// A handle a device uses at resolve time to claim MSI doorbell ranges in the
/// generalized `u64` map.
///
/// This is the [`RegisterMsiSink`](chipset_device::msi::RegisterMsiSink)
/// implementation offered to devices, mirroring the MMIO `DeviceRangeMapper`.
/// It writes claims straight into the shared MMIO map; overlaps are surfaced
/// as finalization conflicts.
pub struct MsiSinkRegistrar {
    dev_name: Arc<str>,
    ranges: IoRanges<u64>,
}

impl MsiSinkRegistrar {
    pub(crate) fn new(dev_name: Arc<str>, ranges: IoRanges<u64>) -> Self {
        Self { dev_name, ranges }
    }
}

impl chipset_device::msi::RegisterMsiSink for MsiSinkRegistrar {
    fn claim(&mut self, region_name: &str, range: RangeInclusive<u64>, sink: MsiSink) {
        // Conflicts are recorded and surfaced during finalization; a failure
        // here just means the entry was not inserted.
        let _ = self.ranges.register_msi_sink(
            *range.start(),
            *range.end(),
            region_name.into(),
            self.dev_name.clone(),
            sink,
        );
    }
}

/// What a [`LookupResult`] resolves an address to.
pub enum LookupTarget {
    /// A device that intercepts CPU accesses to this range.
    Device(Arc<CloseableMutex<dyn ChipsetDevice>>),
    /// An MSI doorbell sink. A CPU access to this range is itself an MSI, so
    /// the dispatch path signals the sink lock-free rather than locking a
    /// device. (Only the `u64` MMIO map ever yields this.)
    MsiSink(MsiSink),
}

pub struct LookupResult {
    pub target: LookupTarget,
    pub dev_name: Arc<str>,
    pub trace: Option<Arc<str>>,
    pub debug_break: bool,
}

impl<T: RangeKey> Inspect for IoRanges<T> {
    fn inspect(&self, req: inspect::Request<'_>) {
        let mut resp = req.respond();
        let mut inner = self.inner.write();
        resp.field_mut("trace_on", &mut inner.trace_on)
            .field_mut("break_on", &mut inner.break_on);
        for (range, entry) in inner.map.iter() {
            resp.field(&format!("{:#x}-{:#x}", range.start(), range.end()), entry);
        }
    }
}
