// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A very incomplete implementation of ARM GICv3.

// TODO: Remove when all the matches actually handle things.
#![allow(clippy::match_single_binding)]
#![forbid(unsafe_code)]

pub use gicd::Distributor;
pub use gicr::Redistributor;

mod gicd {
    use super::gicr::SharedState;
    use super::Redistributor;
    use aarch64defs::gic::GicdCtlr;
    use aarch64defs::gic::GicdRegister;
    use aarch64defs::gic::GicdTyper;
    use aarch64defs::gic::GicdTyper2;
    use aarch64defs::gic::GicrSgi;
    use aarch64defs::MpidrEl1;
    use aarch64defs::SystemReg;
    use inspect::Inspect;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use vm_topology::processor::VpIndex;

    #[derive(Debug, Inspect)]
    pub struct Distributor {
        state: Mutex<DistributorState>,
        max_spi_intid: u32,
        #[inspect(skip)]
        gicr: Vec<Arc<SharedState>>,
    }

    #[derive(Debug, Inspect)]
    struct DistributorState {
        #[inspect(iter_by_index)]
        pending: Vec<u32>,
        #[inspect(iter_by_index)]
        active: Vec<u32>,
        #[inspect(iter_by_index)]
        group: Vec<u32>,
        #[inspect(iter_by_index)]
        enable: Vec<u32>,
        #[inspect(iter_by_index)]
        cfg: Vec<u32>,
        #[inspect(iter_by_index)]
        priority: Vec<u32>,
        #[inspect(iter_by_index)]
        route: Vec<u64>,
        enable_grp0: bool,
        enable_grp1: bool,
    }

    impl Distributor {
        pub fn new(max_spis: u32) -> Self {
            let n = (max_spis as usize + 1) / 32;
            Self {
                state: Mutex::new(DistributorState {
                    pending: vec![0; n],
                    active: vec![0; n],
                    group: vec![0; n],
                    enable: vec![0; n],
                    cfg: vec![0; n * 2],
                    priority: vec![0; n * 8],
                    route: vec![0; n * 64],
                    enable_grp0: false,
                    enable_grp1: false,
                }),
                max_spi_intid: 32 + max_spis - 1,
                gicr: Default::default(),
            }
        }

        pub fn add_redistributor(&mut self, mpidr: u64, last: bool) -> Redistributor {
            let mpidr = mpidr & u64::from(MpidrEl1::AFFINITY_MASK);
            let state = Arc::new(SharedState {
                pending: 0.into(),
                mpidr: mpidr.into(),
            });
            let gicr = Redistributor::new(self.gicr.len(), last, state.clone());
            self.gicr.push(state);
            gicr
        }

        pub fn raise_ppi(&self, vp: VpIndex, intid: u32) -> bool {
            if let Some(gicr) = self.gicr.get(vp.index() as usize) {
                gicr.raise(intid)
            } else {
                false
            }
        }

        pub fn set_pending(&self, intid: u32, pending: bool) -> Option<u32> {
            let v = &mut self.state.lock().pending[intid as usize / 32];
            let mask = 1 << (intid & 31);
            if (*v & mask != 0) != pending {
                tracing::debug!(intid, pending, "set pending");
            }
            if pending {
                *v |= mask;
                Some(0)
            } else {
                *v &= !mask;
                None
            }
        }

        pub fn irq_pending(&self, gicr: &Redistributor) -> bool {
            if gicr.irq_pending() {
                return true;
            }
            if gicr.index != 0 {
                return false;
            }
            let state = self.state.lock();
            state
                .pending
                .iter()
                .zip(&state.active)
                .zip(&state.enable)
                .any(|((&p, &a), e)| p & !a & e != 0)
        }

        pub fn ack(&self, gicr: &mut Redistributor, group1: bool) -> u32 {
            if let Some(intid) = gicr.ack(group1) {
                return intid;
            }
            if gicr.index != 0 {
                return 1023;
            }
            let mut state = self.state.lock();
            let state = &mut *state;
            if let Some((i, (p, a))) = state
                .pending
                .iter_mut()
                .zip(&mut state.active)
                .enumerate()
                .find(|(_, (&mut p, &mut a))| p & !a != 0)
            {
                let v = 31 - (*p & !*a).leading_zeros();
                *p &= !(1 << v);
                *a |= 1 << v;
                let intid = i as u32 * 32 + v;
                tracing::debug!(intid, "gicd ack");
                intid
            } else {
                1023
            }
        }

        pub fn write_sysreg(
            &self,
            gicr: &mut Redistributor,
            reg: SystemReg,
            value: u64,
            wake: impl FnMut(usize),
        ) -> bool {
            match reg {
                SystemReg::ICC_EOIR0_EL1 => self.eoi(gicr, false, value as u32),
                SystemReg::ICC_EOIR1_EL1 => self.eoi(gicr, true, value as u32),
                SystemReg::ICC_SGI0R_EL1 => self.sgi(gicr, false, value, wake),
                SystemReg::ICC_SGI1R_EL1 => self.sgi(gicr, true, value, wake),
                _ => return false,
            }
            true
        }

        fn sgi(
            &self,
            this: &mut Redistributor,
            group1: bool,
            value: u64,
            mut wake: impl FnMut(usize),
        ) {
            let value = GicrSgi::from(value);
            for (index, gicr) in self.gicr.iter().enumerate() {
                if (value.irm() && !Arc::ptr_eq(&this.shared, gicr))
                    || (!value.irm()
                        && gicr.mpidr.aff3() == value.aff3()
                        && gicr.mpidr.aff2() == value.aff2()
                        && gicr.mpidr.aff1() == value.aff1()
                        && (1 << gicr.mpidr.aff0()) & value.target_list() != 0)
                {
                    if gicr.raise(value.intid()) {
                        wake(index);
                    }
                }
            }
        }

        pub fn read_sysreg(&self, gicr: &mut Redistributor, reg: SystemReg) -> Option<u64> {
            let v = match reg {
                SystemReg::ICC_IAR0_EL1 => self.ack(gicr, false).into(),
                SystemReg::ICC_IAR1_EL1 => self.ack(gicr, true).into(),
                _ => return None,
            };
            Some(v)
        }

        fn eoi(&self, gicr: &mut Redistributor, group1: bool, intid: u32) {
            if intid < 32 {
                gicr.eoi(group1, intid);
                return;
            }
            if gicr.index != 0 {
                return;
            }
            tracing::debug!(intid, "gicd eoi");
            let v = &mut self.state.lock().active[intid as usize / 32];
            *v &= !(1 << (intid & 31));
        }

        fn write32(&self, address: GicdRegister, value: u32) -> bool {
            assert!(address.0 & 3 == 0);
            match address {
                GicdRegister::CTLR => {
                    let ctlr = GicdCtlr::from(value);
                    let mut state = self.state.lock();
                    let state = &mut *state;
                    state.enable_grp0 = ctlr.enable_grp0();
                    state.enable_grp1 = ctlr.enable_grp1();
                }
                r if GicdRegister::IGROUPR.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    if n != 0 {
                        if let Some(group) = self.state.lock().group.get_mut(n as usize) {
                            *group = value;
                        }
                    }
                }
                r if GicdRegister::ISENABLER.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    if n != 0 {
                        if let Some(enable) = self.state.lock().enable.get_mut(n as usize) {
                            *enable |= value;
                        }
                    }
                }
                r if GicdRegister::ICENABLER.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    if n != 0 {
                        if let Some(enable) = self.state.lock().enable.get_mut(n as usize) {
                            *enable &= !value;
                        }
                    }
                }
                r if GicdRegister::ICFGR.contains(&r.0) => {
                    let n = (r.0 & 0xff) / 4;
                    if n >= 2 {
                        if let Some(cfg) = self.state.lock().cfg.get_mut(n as usize) {
                            // The low bit of each bit pair is res0.
                            *cfg = value & 0xaaaaaaaa;
                        }
                    }
                }
                r if GicdRegister::IPRIORITYR.contains(&r.0) => {
                    let n = (r.0 & 0x3ff) / 4;
                    if n >= 8 {
                        if let Some(cfg) = self.state.lock().cfg.get_mut(n as usize) {
                            *cfg = value;
                        }
                    }
                }
                r if GicdRegister::ISACTIVER.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    if n != 0 {
                        if let Some(active) = self.state.lock().active.get_mut(n as usize) {
                            *active |= value;
                        }
                    }
                }
                r if GicdRegister::ICACTIVER.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    if n != 0 {
                        if let Some(active) = self.state.lock().active.get_mut(n as usize) {
                            *active &= !value;
                        }
                    }
                }
                _ => return false,
            }
            true
        }

        fn read32(&self, address: GicdRegister) -> Option<u32> {
            assert!(address.0 & 3 == 0);
            let v = match address {
                GicdRegister::PIDR2 => {
                    // GICv3
                    3 << 4
                }
                GicdRegister::TYPER => GicdTyper::new()
                    .with_it_lines_number(31)
                    .with_id_bits(5)
                    .into(),
                GicdRegister::IIDR => 0,
                GicdRegister::TYPER2 => GicdTyper2::new().into(),
                GicdRegister::CTLR => {
                    let state = self.state.lock();
                    GicdCtlr::new()
                        .with_enable_grp0(state.enable_grp0)
                        .with_enable_grp1(state.enable_grp1)
                        .with_ds(true)
                        .with_are(true)
                        .into()
                }
                r if GicdRegister::IGROUPR.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    self.state
                        .lock()
                        .group
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                r if GicdRegister::ICENABLER.contains(&r.0)
                    || GicdRegister::ISENABLER.contains(&r.0) =>
                {
                    let n = (r.0 & 0x7f) / 4;
                    self.state
                        .lock()
                        .enable
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                r if GicdRegister::ICFGR.contains(&r.0) => {
                    let n = (r.0 & 0xff) / 4;
                    self.state.lock().cfg.get(n as usize).copied().unwrap_or(0)
                }
                r if GicdRegister::IPRIORITYR.contains(&r.0) => {
                    let n = (r.0 & 0x3ff) / 4;
                    self.state
                        .lock()
                        .priority
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                r if GicdRegister::ICACTIVER.contains(&r.0)
                    || GicdRegister::ISACTIVER.contains(&r.0) =>
                {
                    let n = (r.0 & 0x7f) / 4;
                    self.state
                        .lock()
                        .active
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                r if GicdRegister::ICPENDR.contains(&r.0)
                    || GicdRegister::ISPENDR.contains(&r.0) =>
                {
                    let n = (r.0 & 0x7f) / 4;
                    self.state
                        .lock()
                        .pending
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                _ => return None,
            };
            Some(v)
        }

        fn write64(&self, address: GicdRegister, value: u64) -> bool {
            assert!(address.0 & 7 == 0);
            match address {
                r if GicdRegister::IROUTER.contains(&r.0) => {
                    let n = (r.0 & 0x1fff) / 8;
                    if n >= 32 {
                        if let Some(route) = self.state.lock().route.get_mut(n as usize) {
                            *route = value;
                        }
                    }
                }
                _ => return false,
            }
            true
        }

        fn read64(&self, address: GicdRegister) -> Option<u64> {
            assert!(address.0 & 7 == 0);
            let v = match address {
                r if GicdRegister::IROUTER.contains(&r.0) => {
                    let n = (r.0 & 0x1fff) / 8;
                    self.state
                        .lock()
                        .route
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                _ => return None,
            };
            Some(v)
        }

        pub fn read(&self, address: u64, data: &mut [u8]) {
            if address & (data.len() as u64 - 1) != 0 {
                data.fill(!0);
                tracing::warn!(address, ?data, "gicd read unaligned access");
                return;
            }
            let address = GicdRegister(address as u16);
            let handled = match data.len() {
                4 => {
                    if let Some(v) = self.read32(address) {
                        data.copy_from_slice(&v.to_ne_bytes());
                        true
                    } else {
                        false
                    }
                }
                8 => {
                    if let Some(v) = self.read64(address) {
                        data.copy_from_slice(&v.to_ne_bytes());
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            };
            if !handled {
                data.fill(0);
                tracing::warn!(?address, ?data, "unsupported gicd register read");
            }
        }

        pub fn write(&self, address: u64, data: &[u8]) {
            if address & (data.len() as u64 - 1) != 0 {
                tracing::warn!(address, ?data, "gicd write unaligned access");
                return;
            }
            let address = GicdRegister(address as u16);
            let handled = match data.len() {
                4 => self.write32(address, u32::from_ne_bytes(data.try_into().unwrap())),
                8 => self.write64(address, u64::from_ne_bytes(data.try_into().unwrap())),
                _ => false,
            };
            if !handled {
                tracelimit::warn_ratelimited!(?address, ?data, "unsupported gicd register write");
            }
        }
    }
}

mod gicr {
    use aarch64defs::gic::GicrCtlr;
    use aarch64defs::gic::GicrRdRegister;
    use aarch64defs::gic::GicrSgiRegister;
    use aarch64defs::gic::GicrTyper;
    use aarch64defs::gic::GicrWaker;
    use aarch64defs::MpidrEl1;
    use inspect::Inspect;
    use std::sync::atomic::AtomicU32;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    #[derive(Debug, Inspect)]
    pub struct Redistributor {
        #[inspect(flatten)]
        pub(super) shared: Arc<SharedState>,
        pub(super) index: usize,
        active: u32,
        group: u32,
        enable: u32,
        ppi_cfg: u32,
        #[inspect(iter_by_index)]
        priority: [u32; 8],
        sleep: bool,
        last: bool,
    }

    #[derive(Debug, Inspect)]
    pub(crate) struct SharedState {
        pub(super) pending: AtomicU32,
        #[inspect(with = "|&x| u64::from(x)")]
        pub(super) mpidr: MpidrEl1,
    }

    impl SharedState {
        pub fn raise(&self, intid: u32) -> bool {
            let mask = 1 << intid;
            self.pending.fetch_or(mask, Ordering::Relaxed) & mask == 0
        }
    }

    impl Redistributor {
        pub(crate) fn new(index: usize, last: bool, shared: Arc<SharedState>) -> Self {
            Self {
                index,
                shared,
                active: 0,
                group: 0,
                enable: 0,
                ppi_cfg: 0,
                priority: [0; 8],
                sleep: true,
                last,
            }
        }

        pub fn read(&mut self, address: u64, data: &mut [u8]) {
            if address & (data.len() as u64 - 1) != 0 {
                data.fill(!0);
                tracing::warn!(address, ?data, "gicr read unaligned access");
                return;
            }

            if address & 0x10000 == 0 {
                let address = GicrRdRegister(address as u16);
                let handled = match data.len() {
                    4 => {
                        if let Some(v) = self.rd_read32(address) {
                            data.copy_from_slice(&v.to_ne_bytes());
                            true
                        } else {
                            false
                        }
                    }
                    8 => {
                        if let Some(v) = self.rd_read64(address) {
                            data.copy_from_slice(&v.to_ne_bytes());
                            true
                        } else {
                            false
                        }
                    }
                    _ => false,
                };
                if !handled {
                    data.fill(0);
                    tracelimit::warn_ratelimited!(?address, "unsupported gicr rd register read");
                }
            } else {
                let address = GicrSgiRegister(address as u16);
                let handled = match data.len() {
                    4 => {
                        if let Some(v) = self.sgi_read32(address) {
                            data.copy_from_slice(&v.to_ne_bytes());
                            true
                        } else {
                            false
                        }
                    }
                    _ => false,
                };
                if !handled {
                    data.fill(0);
                    tracelimit::warn_ratelimited!(
                        ?address,
                        ?data,
                        "unsupported gicr sgi register read"
                    );
                }
            }
        }

        pub fn write(&mut self, address: u64, data: &[u8]) {
            if address & (data.len() as u64 - 1) != 0 {
                tracing::warn!(address, ?data, "gicr write unaligned access");
                return;
            }

            if address & 0x10000 == 0 {
                let address = GicrRdRegister(address as u16);
                let handled = match data.len() {
                    4 => {
                        let data = u32::from_ne_bytes(data.try_into().unwrap());
                        self.rd_write32(address, data)
                    }
                    8 => {
                        let data = u64::from_ne_bytes(data.try_into().unwrap());
                        self.rd_write64(address, data)
                    }
                    _ => false,
                };
                if !handled {
                    tracelimit::warn_ratelimited!(
                        ?address,
                        ?data,
                        "unsupported gicr rd register write"
                    );
                }
            } else {
                let address = GicrSgiRegister(address as u16);
                let handled = match data.len() {
                    4 => {
                        let data = u32::from_ne_bytes(data.try_into().unwrap());
                        self.sgi_write32(address, data)
                    }
                    _ => false,
                };
                if !handled {
                    tracelimit::warn_ratelimited!(
                        ?address,
                        ?data,
                        "unsupported gicr sgi register write"
                    );
                }
            }
        }

        fn rd_read32(&mut self, address: GicrRdRegister) -> Option<u32> {
            let v = match address {
                GicrRdRegister::PIDR2 => {
                    // GICv3
                    3 << 4
                }
                GicrRdRegister::CTLR => GicrCtlr::new().into(),
                GicrRdRegister::WAKER => GicrWaker::new()
                    .with_processor_sleep(self.sleep)
                    .with_children_asleep(self.sleep)
                    .into(),
                _ => return None,
            };
            tracing::debug!(?address, v, "gicr rd read32");
            Some(v)
        }

        fn rd_write32(&mut self, address: GicrRdRegister, data: u32) -> bool {
            match address {
                GicrRdRegister::CTLR => {}
                GicrRdRegister::WAKER => {
                    let v = GicrWaker::from(data);
                    self.sleep = v.processor_sleep();
                }
                _ => return false,
            }
            tracing::debug!(?address, data, "gicr rd write32");
            true
        }

        fn rd_read64(&mut self, address: GicrRdRegister) -> Option<u64> {
            let mpidr = MpidrEl1::from(self.shared.mpidr);
            let v = match address {
                GicrRdRegister::TYPER => GicrTyper::new()
                    .with_aff0(mpidr.aff0())
                    .with_aff1(mpidr.aff1())
                    .with_aff2(mpidr.aff2())
                    .with_aff3(mpidr.aff3())
                    .with_last(self.last)
                    .into(),
                _ => return None,
            };
            Some(v)
        }

        fn rd_write64(&mut self, _address: GicrRdRegister, _data: u64) -> bool {
            false
        }

        fn sgi_read32(&mut self, address: GicrSgiRegister) -> Option<u32> {
            let v = match address {
                GicrSgiRegister::IGROUPR0 => self.group,
                GicrSgiRegister::ICACTIVER0 | GicrSgiRegister::ISACTIVER0 => self.active,
                GicrSgiRegister::ICENABLER0 | GicrSgiRegister::ISENABLER0 => self.enable,
                GicrSgiRegister::ICPENDR0 | GicrSgiRegister::ISPENDR0 => {
                    self.shared.pending.load(Ordering::Relaxed)
                }
                GicrSgiRegister::ICFGR0 => {
                    // SGIs are always edge triggered.
                    0xaaaaaaaa
                }
                GicrSgiRegister::ICFGR1 => self.ppi_cfg,
                r if GicrSgiRegister::IPRIORITYR.contains(&r.0) => {
                    let n = (r.0 & 0x1f) / 4;
                    self.priority[n as usize]
                }
                _ => return None,
            };
            tracing::debug!(?address, v, "gicr sgi read32");
            Some(v)
        }

        fn sgi_write32(&mut self, address: GicrSgiRegister, data: u32) -> bool {
            match address {
                GicrSgiRegister::IGROUPR0 => self.group = data,
                GicrSgiRegister::ISACTIVER0 => self.active |= data,
                GicrSgiRegister::ICACTIVER0 => self.active &= !data,
                GicrSgiRegister::ISENABLER0 => self.enable |= data,
                GicrSgiRegister::ICENABLER0 => self.enable &= !data,
                GicrSgiRegister::ICFGR0 => {
                    // Cannot change trigger mode for SGIs.
                }
                GicrSgiRegister::ICFGR1 => self.ppi_cfg = data,
                r if GicrSgiRegister::IPRIORITYR.contains(&r.0) => {
                    let n = (r.0 & 0x1f) / 4;
                    self.priority[n as usize] = data;
                }
                _ => return false,
            }
            tracing::debug!(?address, data, "gicr sgi write32");
            true
        }

        pub fn raise(&mut self, intid: u32) {
            self.shared.pending.fetch_or(1 << intid, Ordering::Relaxed);
        }

        pub(crate) fn irq_pending(&self) -> bool {
            (self.shared.pending.load(Ordering::Relaxed) & !self.active & self.enable & self.group)
                != 0
        }

        pub fn is_pending_or_active(&self, intid: u32) -> bool {
            (self.shared.pending.load(Ordering::Relaxed) | self.active) & (1 << intid) != 0
        }

        pub(crate) fn ack(&mut self, group1: bool) -> Option<u32> {
            let pending = self.shared.pending.load(Ordering::Relaxed);
            if pending == 0 {
                None
            } else {
                let intid = 31 - (pending & !self.active).leading_zeros();
                tracing::trace!(intid, "ack");
                self.shared
                    .pending
                    .fetch_and(!(1 << intid), Ordering::Relaxed);
                self.active |= 1 << intid;
                Some(intid)
            }
        }

        pub(crate) fn eoi(&mut self, _group1: bool, intid: u32) {
            assert!(intid < 32);
            tracing::trace!(intid, "eoi");
            self.active &= !(1 << intid);
        }
    }
}
