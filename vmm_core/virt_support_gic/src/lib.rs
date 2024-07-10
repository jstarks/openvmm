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
    use bitfield_struct::bitfield;
    use inspect::Inspect;
    use open_enum::open_enum;
    use parking_lot::Mutex;
    use std::ops::Range;
    use std::sync::Arc;
    use vm_topology::processor::VpIndex;

    open_enum! {
        enum Register: u16 {
            CTLR = 0x0000,
            TYPER = 0x0004,
            IIDR = 0x0008,
            TYPER2 = 0x000c,
            STATUSR = 0x0010,
            SETSPI_NSR = 0x0040,
            CLRSPI_NSR = 0x0048,
            SETSPI_SR = 0x0050,
            CLRSPI_SR = 0x0058,
            IGROUPR0 = 0x0080,       // 0x80
            ISENABLER0 = 0x0100,     // 0x80
            ICENABLER0 = 0x0180,     // 0x80
            ISPENDR0 = 0x0200,       // 0x80
            ICPENDR0 = 0x0280,       // 0x80
            ISACTIVER0 = 0x0300,     // 0x80
            ICACTIVER0 = 0x0380,     // 0x80
            IPRIORITYR0 = 0x0400,    // 0x400
            ITARGETSR0 = 0x0800,     // 0x400
            ICFGR0 = 0x0c00,         // 0x100
            IGRPMODR0 = 0x0d00,      // 0x100
            NSACR0 = 0x0e00,         // 0x100
            SGIR = 0x0f00,
            CPENDSGIR0 = 0x0f10,     // 0x10
            SPENDSGIR0 = 0x0f20,     // 0x10
            INMIR0 = 0x0f80,         // 0x80
            IROUTER0 = 0x6000,       // 0x2000, skip first 0x100,
            PIDR2 = 0xffe8,
        }
    }

    impl Register {
        const IGROUPR: Range<u16> = Self::IGROUPR0.0..Self::IGROUPR0.0 + 0x80;
        const ISENABLER: Range<u16> = Self::ISENABLER0.0..Self::ISENABLER0.0 + 0x80;
        const ICENABLER: Range<u16> = Self::ICENABLER0.0..Self::ICENABLER0.0 + 0x80;
        const ISPENDR: Range<u16> = Self::ISPENDR0.0..Self::ISPENDR0.0 + 0x80;
        const ICPENDR: Range<u16> = Self::ICPENDR0.0..Self::ICPENDR0.0 + 0x80;
        const ISACTIVER: Range<u16> = Self::ISACTIVER0.0..Self::ISACTIVER0.0 + 0x80;
        const ICACTIVER: Range<u16> = Self::ICACTIVER0.0..Self::ICACTIVER0.0 + 0x80;
        const ICFGR: Range<u16> = Self::ICFGR0.0..Self::ICFGR0.0 + 0x100;
        const IPRIORITYR: Range<u16> = Self::IPRIORITYR0.0..Self::IPRIORITYR0.0 + 0x400;
        const IROUTER: Range<u16> = Self::IROUTER0.0..Self::IROUTER0.0 + 0x2000;
    }

    #[bitfield(u32)]
    pub struct GicdTyper {
        #[bits(5)]
        pub it_lines_number: u8,
        #[bits(3)]
        pub cpu_number: u8,
        pub espi: bool,
        pub nmi: bool,
        pub security_extn: bool,
        #[bits(5)]
        pub num_lpis: u8,
        pub mbis: bool,
        pub lpis: bool,
        pub dvis: bool,
        #[bits(5)]
        pub id_bits: u8,
        pub a3v: bool,
        pub no1n: bool,
        pub rss: bool,
        #[bits(5)]
        pub espi_range: u8,
    }

    #[bitfield(u32)]
    pub struct GicdTyper2 {
        #[bits(5)]
        pub vid: u8,
        #[bits(2)]
        _res5_6: u8,
        pub vil: bool,
        pub n_assgi_cap: bool,
        #[bits(23)]
        _res9_31: u32,
    }

    #[bitfield(u32)]
    pub struct GicdCtlr {
        pub enable_grp0: bool,
        pub enable_grp1: bool,
        #[bits(2)]
        _res_2_3: u8,
        pub are: bool,
        _res_5: bool,
        pub ds: bool,
        pub e1nwf: bool,
        pub n_assgi_req: bool,
        #[bits(22)]
        _res_9_30: u32,
        pub rwp: bool,
    }

    #[derive(Debug, Inspect)]
    pub struct Distributor {
        state: Mutex<DistributorState>,
        max_spi_intid: u32,
        #[inspect(skip)]
        gicr: Arc<SharedState>,
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

        pub fn add_redistributor(&mut self) -> Redistributor {
            Redistributor::new(self.gicr.clone())
        }

        pub fn raise_ppi(&self, _vp: VpIndex, intid: u32) -> bool {
            self.gicr.raise(intid)
        }

        pub fn set_pending(&self, intid: u32, pending: bool) -> Option<u32> {
            let v = &mut self.state.lock().pending[intid as usize / 32 - 1];
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

        pub fn irq_pending(&self) -> bool {
            let state = self.state.lock();
            state
                .pending
                .iter()
                .zip(&state.active)
                .any(|(&p, &a)| p & !a != 0)
        }

        pub fn ack(&self) -> u32 {
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
                let intid = (i as u32 + 1) * 32 + v;
                tracing::debug!(intid, "gicd ack");
                intid
            } else {
                1023
            }
        }

        pub fn eoi(&self, intid: u32) {
            tracing::debug!(intid, "gicd eoi");
            let v = &mut self.state.lock().active[intid as usize / 32 - 1];
            *v &= !(1 << (intid & 31));
        }

        fn write32(&self, address: Register, value: u32) -> bool {
            assert!(address.0 & 3 == 0);
            match address {
                Register::CTLR => {
                    let ctlr = GicdCtlr::from(value);
                    let mut state = self.state.lock();
                    let state = &mut *state;
                    state.enable_grp0 = ctlr.enable_grp0();
                    state.enable_grp1 = ctlr.enable_grp1();
                }
                r if Register::IGROUPR.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    if n != 0 {
                        if let Some(group) = self.state.lock().group.get_mut(n as usize) {
                            *group = value;
                        }
                    }
                }
                r if Register::ISENABLER.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    if n != 0 {
                        if let Some(enable) = self.state.lock().enable.get_mut(n as usize) {
                            *enable |= value;
                        }
                    }
                }
                r if Register::ICENABLER.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    if n != 0 {
                        if let Some(enable) = self.state.lock().enable.get_mut(n as usize) {
                            *enable &= !value;
                        }
                    }
                }
                r if Register::ICFGR.contains(&r.0) => {
                    let n = (r.0 & 0xff) / 4;
                    if n >= 2 {
                        if let Some(cfg) = self.state.lock().cfg.get_mut(n as usize) {
                            // The low bit of each bit pair is res0.
                            *cfg = value & 0xaaaaaaaa;
                        }
                    }
                }
                r if Register::IPRIORITYR.contains(&r.0) => {
                    let n = (r.0 & 0x3ff) / 4;
                    if n >= 8 {
                        if let Some(cfg) = self.state.lock().cfg.get_mut(n as usize) {
                            *cfg = value;
                        }
                    }
                }
                r if Register::ISACTIVER.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    if n != 0 {
                        if let Some(active) = self.state.lock().active.get_mut(n as usize) {
                            *active |= value;
                        }
                    }
                }
                r if Register::ICACTIVER.contains(&r.0) => {
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

        fn read32(&self, address: Register) -> Option<u32> {
            assert!(address.0 & 3 == 0);
            let v = match address {
                Register::PIDR2 => {
                    // GICv3
                    3 << 4
                }
                Register::TYPER => GicdTyper::new()
                    .with_it_lines_number(31)
                    .with_id_bits(5)
                    .into(),
                Register::IIDR => 0,
                Register::TYPER2 => GicdTyper2::new().into(),
                Register::CTLR => {
                    let state = self.state.lock();
                    GicdCtlr::new()
                        .with_enable_grp0(state.enable_grp0)
                        .with_enable_grp1(state.enable_grp1)
                        .with_ds(true)
                        .with_are(true)
                        .into()
                }
                r if Register::IGROUPR.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    self.state
                        .lock()
                        .group
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                r if Register::ICENABLER.contains(&r.0) || Register::ISENABLER.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    self.state
                        .lock()
                        .enable
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                r if Register::ICFGR.contains(&r.0) => {
                    let n = (r.0 & 0xff) / 4;
                    self.state.lock().cfg.get(n as usize).copied().unwrap_or(0)
                }
                r if Register::IPRIORITYR.contains(&r.0) => {
                    let n = (r.0 & 0x3ff) / 4;
                    self.state
                        .lock()
                        .priority
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                r if Register::ICACTIVER.contains(&r.0) || Register::ISACTIVER.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    self.state
                        .lock()
                        .active
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                _ => return None,
            };
            Some(v)
        }

        fn write64(&self, address: Register, value: u64) -> bool {
            assert!(address.0 & 7 == 0);
            match address {
                r if Register::IROUTER.contains(&r.0) => {
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

        fn read64(&self, address: Register) -> Option<u64> {
            assert!(address.0 & 7 == 0);
            let v = match address {
                r if Register::IROUTER.contains(&r.0) => {
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
            let address = Register(address as u16);
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
            let address = Register(address as u16);
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
    use bitfield_struct::bitfield;
    use inspect::Inspect;
    use open_enum::open_enum;
    use std::sync::atomic::AtomicU32;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    open_enum! {
        enum RdRegister: u16 {
            CTLR = 0x0000,
            IIDR = 0x0004,
            TYPER = 0x0008,     // 64 bit
            STATUSR = 0x0010,
            WAKER = 0x0014,
            MPAMIDR = 0x0018,
            PARTIDR = 0x001c,
            SETLPIR = 0x0040,   // 64 bit
            CLRLPIR = 0x0048,   // 64 bit
            PROPBASER = 0x0070, // 64 bit
            PENDBASER = 0x0078, // 64 bit
            INVLPIR = 0x00A0,   // 64 bit
            SYNCR = 0x00C0,     // 64 bit
            PIDR2 = 0xffe8,
        }
    }

    open_enum! {
        enum SgiRegister: u16 {
            IGROUPR0 = 0x0080,
            ISENABLER0 = 0x0100,
            ICENABLER0 = 0x0180,
            ISPENDR0 = 0x0200,
            ICPENDR0 = 0x0280,
            ISACTIVER0 = 0x0300,
            ICACTIVER0 = 0x0380,
            IPRIORITYR = 0x0400, // 0x20
            ICFGR0 = 0x0c00,
            ICFGR1 = 0x0c04,
            IGRPMODR0 = 0x0d00,
        }
    }

    #[bitfield(u64)]
    pub struct GicrTyper {
        pub plpis: bool,
        pub vlpis: bool,
        pub dirty: bool,
        pub direct_lpi: bool,
        pub last: bool,
        pub dpgs: bool,
        pub mpam: bool,
        pub rvpeid: bool,
        pub processor_number: u16,
        #[bits(2)]
        pub common_lpi_aff: u8,
        pub vsgi: bool,
        #[bits(5)]
        pub ppi_num: u8,
        pub affinity_value: u32,
    }

    #[bitfield(u32)]
    pub struct GicrCtlr {
        pub enable_lpis: bool,
        pub ces: bool,
        pub ir: bool,
        pub rwp: bool,
        #[bits(20)]
        _res_4_23: u32,
        pub dpg0: bool,
        pub dpg1ns: bool,
        pub dpg1s: bool,
        #[bits(4)]
        _res_27_30: u32,
        pub uwp: bool,
    }

    #[derive(Debug, Inspect)]
    pub struct Redistributor {
        shared: Arc<SharedState>,
        active: u32,
    }

    #[derive(Default, Debug, Inspect)]
    pub struct SharedState {
        pending: AtomicU32,
    }

    impl SharedState {
        pub fn raise(&self, intid: u32) -> bool {
            let mask = 1 << intid;
            self.pending.fetch_or(mask, Ordering::Relaxed) & mask == 0
        }
    }

    impl Redistributor {
        pub(crate) fn new(shared: Arc<SharedState>) -> Self {
            Self { shared, active: 0 }
        }

        pub fn read(&mut self, address: u64, data: &mut [u8]) {
            if address & (data.len() as u64 - 1) != 0 {
                data.fill(!0);
                tracing::warn!(address, ?data, "gicr read unaligned access");
                return;
            }

            if address & 0x10000 == 0 {
                let address = RdRegister(address as u16);
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
                let address = SgiRegister(address as u16);
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
                let address = RdRegister(address as u16);
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
                let address = SgiRegister(address as u16);
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

        fn rd_read32(&mut self, address: RdRegister) -> Option<u32> {
            let v = match address {
                RdRegister::PIDR2 => {
                    // GICv3
                    3 << 4
                }
                RdRegister::CTLR => GicrCtlr::new().into(),
                _ => return None,
            };
            Some(v)
        }

        fn rd_write32(&mut self, address: RdRegister, _data: u32) -> bool {
            match address {
                RdRegister::CTLR => {}
                _ => return false,
            }
            true
        }

        fn rd_read64(&mut self, address: RdRegister) -> Option<u64> {
            let v = match address {
                RdRegister::TYPER => GicrTyper::new().with_last(true).into(),
                _ => return None,
            };
            Some(v)
        }

        fn rd_write64(&mut self, address: RdRegister, data: u64) -> bool {
            false
        }

        fn sgi_read32(&mut self, address: SgiRegister) -> Option<u32> {
            None
        }

        fn sgi_write32(&mut self, address: SgiRegister, data: u32) -> bool {
            false
        }

        pub fn raise(&mut self, intid: u32) {
            self.shared.pending.fetch_or(1 << intid, Ordering::Relaxed);
        }

        pub fn irq_pending(&self) -> bool {
            (self.shared.pending.load(Ordering::Relaxed) & !self.active) != 0
        }

        pub fn fiq_pending(&self) -> bool {
            false
        }

        pub fn is_pending_or_active(&self, intid: u32) -> bool {
            (self.shared.pending.load(Ordering::Relaxed) | self.active) & (1 << intid) != 0
        }

        pub fn ack_group1(&mut self) -> u32 {
            let pending = self.shared.pending.load(Ordering::Relaxed);
            if pending == 0 {
                1023
            } else {
                let intid = 31 - (pending & !self.active).leading_zeros();
                tracing::trace!(intid, "ack");
                self.shared
                    .pending
                    .fetch_and(!(1 << intid), Ordering::Relaxed);
                self.active |= 1 << intid;
                intid
            }
        }

        pub fn eoi_group1(&mut self, intid: u32) {
            if intid < 32 {
                tracing::trace!(intid, "eoi");
                self.active &= !(1 << intid);
            }
        }
    }
}
