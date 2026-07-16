// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Exports [`IoRanges`], which models a linear address-space with certain
//! regions "claimed" by [`ChipsetDevice`]s.
//!
//! - e.g: `IoRanges<u64>` can be used to model 64-bit MMIO.
//! - e.g: `IoRanges<u16>` can be used to model 16-bit x86 port IO.
//!
//! # Doorbell delivery tiers
//!
//! A write to a doorbell offset within a page (an MSI `GITS_TRANSLATER`/`SETSPI`
//! today; a virtio/NVMe queue notification in the future) can be delivered in
//! one of three ways, each a strict acceleration of the one below it. Comments
//! throughout this module refer to these as tiers 1-3:
//!
//! - **Tier 1 — hypervisor.** The doorbell is registered with the partition
//!   (`DoorbellRegistration` → KVM ioeventfd / WHP doorbell). The page stays
//!   **mapped**: the write lands in RAM *and* fires an eventfd, so it never
//!   reaches usermode. Cheapest, but not every backend supports it. Not modeled
//!   in this map (it lives partition-side); listed for context.
//! - **Tier 2 — usermode fast path.** The page **traps**, and the offset is
//!   recognized here in [`IoRanges`] and dispatched (fire `signal_msi` / an
//!   eventfd) **without taking the owning device's lock**. A [`Doorbell`] is a
//!   tier-2 recognizer. "Lock-free" is a property of the target: a stateless
//!   forwarder stays lock-free, while a stateful emulated doorbell may share the
//!   device lock (degrading to tier 3 by choice).
//! - **Tier 3 — device slow path.** The page **traps** and the access is
//!   serviced by the owning device's [`MmioIntercept`], which takes its
//!   `CloseableMutex`. A [`RangeEntry`]'s `device` is the tier-3 backstop.
//!
//! An entry can carry both: an emulated ITS/v2m frame services its control
//! registers at tier 3 and its `TRANSLATER`/`SETSPI` doorbell at tier 2.
//!
//! [`MmioIntercept`]: chipset_device::mmio::MmioIntercept

use address_filter::AddressFilter;
use address_filter::RangeKey;
use chipset_device::ChipsetDevice;
use chipset_device::msi::DoorbellTarget;
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
    map: RangeMap<T, RangeEntry<T>>,
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

/// A registered address range in the generalized map.
///
/// MMIO device intercepts, MSI doorbells, and RAM share one address space, so
/// they share one map. Every entry has an owning **MMIO device** (the tier-3
/// backstop that intercepts CPU accesses across the whole range) plus a
/// possibly-empty set of **layered doorbells** (tier-2 sub-range recognizers):
///
/// - A plain MMIO device (BAR, fixed register block) has a `device` and no
///   `doorbells`.
/// - An emulated ITS/v2m frame — or a KVM in-kernel ITS registered as a
///   full-frame device — has **both**: a `device` for the control registers
///   (for the in-kernel case the device only ever warns, since the kernel
///   services the frame) plus a `doorbell` nested at the `TRANSLATER`/`SETSPI`
///   offset.
///
/// This models the fabric decode the way hardware does it: a bus-master write
/// to the doorbell offset carries a requester ID and is recognized on the
/// outbound path (tier 2 / `signal_msi`), while everything else in the frame is
/// an ordinary trapping MMIO access serviced by the owning device (tier 3).
///
/// See the doc comment on [`DoorbellTarget`] for the RID / lock-free nuances.
#[derive(Inspect)]
#[inspect(bound = "T: RangeKey")]
struct RangeEntry<T> {
    region_name: Arc<str>,
    dev_name: Arc<str>,
    /// The tier-3 MMIO device backing this range. For a KVM in-kernel ITS this
    /// device only ever warns, since the kernel services the frame.
    #[inspect(rename = "device_is_init", with = "|x| x.upgrade().is_some()")]
    device: Weak<CloseableMutex<dyn ChipsetDevice>>,
    /// Tier-2 doorbell recognizers nested within (or equal to) this range.
    #[inspect(with = "|x| inspect::iter_by_index(x.iter())")]
    doorbells: Vec<Doorbell<T>>,
    read_count: SharedCounter,
    write_count: SharedCounter,
}

/// A tier-2 doorbell: a sub-range of an entry whose writes are recognized and
/// accelerated (fired without taking the owning device's lock) instead of
/// falling through to the device's MMIO intercept.
#[derive(Inspect)]
#[inspect(bound = "T: RangeKey")]
struct Doorbell<T> {
    region_name: Arc<str>,
    #[inspect(with = "|r| format!(\"{:#x}-{:#x}\", r.start(), r.end())")]
    range: RangeInclusive<T>,
    target: DoorbellTarget,
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
        let mut inner = self.inner.write();
        inner.insert_entry(
            start,
            end,
            RangeEntry {
                region_name,
                dev_name,
                device: dev,
                doorbells: Vec::new(),
                read_count: Default::default(),
                write_count: Default::default(),
            },
        )
    }

    pub fn revoke(&self, start: T) {
        let mut inner = self.inner.write();
        inner.map.remove(&start);
    }

    /// Nests a tier-2 doorbell over `start..=end` into the covering MMIO frame,
    /// routing writes whose address falls in that range to `target`. Panics if
    /// no covering frame exists (the owning device must register its MMIO range
    /// first). See [`IoRangesInner::register_doorbell`].
    pub(crate) fn register_doorbell(
        &self,
        start: T,
        end: T,
        region_name: Arc<str>,
        dev_name: Arc<str>,
        target: DoorbellTarget,
    ) {
        self.inner
            .write()
            .register_doorbell(start, end, region_name, dev_name, target);
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
            Some(e) => {
                // Only writes can land on a doorbell (doorbells are write-only):
                // a write to a nested doorbell sub-range is a tier-2 access,
                // recognized and signaled without locking the owning device
                // (see `Chipset::mmio_write`). Reads, and writes outside any
                // doorbell, go to the owning device (tier 3).
                let doorbell = (!is_read)
                    .then(|| e.doorbells.iter().find(|d| d.range.contains(&addr)))
                    .flatten();
                match (doorbell, e.device.upgrade()) {
                    (Some(d), _) => (LookupTarget::Doorbell(d.target.clone()), e.dev_name.clone()),
                    (None, Some(dev)) => (LookupTarget::Device(dev), e.dev_name.clone()),
                    (None, None) => {
                        let (d, n) = unknown();
                        (LookupTarget::Device(d), n)
                    }
                }
            }
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

/// Generic helpers shared by the MMIO (`u64`) and PIO (`u16`) maps.
impl<T: RangeKey> IoRangesInner<T> {
    /// Inserts a fresh entry, recording any overlap as a static conflict
    /// (surfaced during chipset finalization).
    fn insert_entry(
        &mut self,
        start: T,
        end: T,
        entry: RangeEntry<T>,
    ) -> Result<(), IoRangeConflict<T>> {
        let region_name = entry.region_name.clone();
        let dev_name = entry.dev_name.clone();
        match self.map.entry(start..=end) {
            range_map_vec::Entry::Vacant(vacant) => {
                vacant.insert(entry);
                Ok(())
            }
            range_map_vec::Entry::Overlapping(existing) => {
                let existing_dev_region = {
                    let (s, e, ent) = existing.get();
                    (ent.dev_name.clone(), ent.region_name.clone(), *s..=*e)
                };
                let conflict = IoRangeConflict {
                    existing_dev_region,
                    conflict_dev_region: (dev_name, region_name, start..=end),
                };
                if let Some(v) = self.static_registration_conflicts.as_mut() {
                    v.push(conflict.clone());
                }
                Err(conflict)
            }
        }
    }

    /// Registers a tier-2 doorbell over `start..=end` by nesting it into the
    /// already-registered MMIO frame that fully covers it (an emulated ITS/v2m
    /// frame, or a KVM in-kernel ITS registered as a full-frame device).
    ///
    /// A doorbell has no standalone existence: the owning device must register
    /// its MMIO frame first, so a doorbell with no covering frame is a host
    /// wiring bug and panics.
    ///
    /// Nesting couples the doorbell's lifetime to the covering entry: revoking
    /// the entry (e.g. a BAR remap) drops its doorbells. Re-attaching doorbells
    /// across a remap is deferred virtio/NVMe work; today's MSI frames are at
    /// fixed platform addresses, so they are registered MMIO-first and never
    /// remap.
    fn register_doorbell(
        &mut self,
        start: T,
        end: T,
        region_name: Arc<str>,
        dev_name: Arc<str>,
        target: DoorbellTarget,
    ) {
        let (es, _ee) = self
            .map
            .get_entry(&start)
            .map(|(s, e, _)| (*s, *e))
            .filter(|&(es, ee)| es <= start && end <= ee)
            .unwrap_or_else(|| {
                panic!(
                    "MSI doorbell '{region_name}' (device '{dev_name}') has no covering \
                     MMIO frame; register the owning device's MMIO range before its doorbell"
                )
            });
        let (es, ee, mut entry) = self.map.remove(&es).expect("entry just found");
        entry.doorbells.push(Doorbell {
            region_name,
            range: start..=end,
            target,
        });
        let reinserted = self.map.insert(es..=ee, entry);
        assert!(
            reinserted,
            "reinserting a just-removed entry cannot overlap"
        );
    }

    /// Resolves the doorbell (if any) whose nested sub-range contains `address`.
    fn lookup_doorbell(&self, address: T) -> Option<DoorbellTarget> {
        self.map.get(&address).and_then(|e| {
            e.doorbells
                .iter()
                .find(|d| d.range.contains(&address))
                .map(|d| d.target.clone())
        })
    }
}

/// MSI-doorbell API, specific to the `u64` (MMIO) address space. MSI doorbells
/// share the MMIO address space with device BARs and RAM, so they live in the
/// same generalized map; the `u16` (PIO) map never carries doorbells.
impl IoRanges<u64> {
    /// Returns this map as an MSI router, reusing the existing inner `Arc`
    /// (coerced to `dyn SignalMsi`) rather than wrapping it in a second `Arc`.
    ///
    /// The router resolves a device's outbound MSI by looking its address up
    /// in the doorbells and dispatching to the matched doorbell target.
    pub fn as_msi_router(&self) -> Arc<dyn SignalMsi> {
        self.inner.clone()
    }
}

/// The generalized `u64` map doubles as the platform's MSI router: a device's
/// outbound MSI is an address lookup into the doorbells, then dispatch to the
/// matched doorbell target. Implemented on the inner locked state so the map's
/// existing `Arc` can be coerced directly to `Arc<dyn SignalMsi>` (see
/// [`as_msi_router`](IoRanges::as_msi_router)) without a second `Arc` layer.
impl SignalMsi for LockedRanges<u64> {
    fn signal_msi(&self, devid: Option<u32>, address: u64, data: u32) {
        // Clone the target out under the read lock, then release the lock
        // before dispatching so the MSI isn't delivered while the map is
        // locked.
        let target = self.read().lookup_doorbell(address);
        match target {
            Some(target) => target.signal(devid, address, data),
            None => {
                // A miss (no entry, or the entry has no doorbell covering the
                // address) means the MSI-X entry was misprogrammed: it targeted
                // an address with no downstream doorbell. Drop it. (The generic
                // memory / peer-to-peer fallback is deferred.)
                tracelimit::warn_ratelimited!(
                    address,
                    data,
                    "dropped MSI: no doorbell for address"
                );
            }
        }
    }
}

/// What a [`LookupResult`] resolves an address to.
pub enum LookupTarget {
    /// A device that intercepts CPU accesses to this range (tier 3).
    Device(Arc<CloseableMutex<dyn ChipsetDevice>>),
    /// A tier-2 doorbell whose nested sub-range covers the address of a write. A
    /// CPU write to it is itself a doorbell access, so the dispatch path
    /// delivers it (lock-free for a stateless target) rather than locking the
    /// owning device. Reads never resolve here — they go to the owning device.
    /// (Only the `u64` MMIO map ever yields this.)
    Doorbell(DoorbellTarget),
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
