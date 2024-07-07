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
            IGROUPR = 0x0080,       // 0x80
            ISENABLER = 0x0100,     // 0x80
            ICENABLER = 0x0180,     // 0x80
            ISPENDR = 0x0200,       // 0x80
            ICPENDR = 0x0280,       // 0x80
            ISACTIVER = 0x0300,     // 0x80
            ICACTIVER = 0x0380,     // 0x80
            IPRIORITYR = 0x0400,    // 0x400
            ITARGETSR = 0x0800,     // 0x400
            ICFGR = 0x0c00,         // 0x100
            IGRPMODR = 0x0d00,      // 0x100
            NSACR = 0x0e00,         // 0x100
            SGIR = 0x0f00,
            CPENDSGIR = 0x0f10,     // 0x10
            SPENDSGIR = 0x0f20,     // 0x10
            INMIR = 0x0f80,         // 0x80
            IROUTER = 0x6000,       // 0x2000, skip first 0x100,
            PIDR2 = 0xffe8,
        }
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

    #[derive(Debug, Inspect)]
    pub struct Distributor {
        #[inspect(skip)]
        state: Mutex<DistributorState>,
        max_spi_intid: u32,
        #[inspect(skip)]
        gicr: Arc<SharedState>,
    }

    #[derive(Debug)]
    struct DistributorState {
        pending: Vec<u32>,
        active: Vec<u32>,
    }

    impl Distributor {
        pub fn new(max_spis: u32) -> Self {
            let n = (max_spis as usize + 1) / 32;
            Self {
                state: Mutex::new(DistributorState {
                    pending: vec![0; n],
                    active: vec![0; n],
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

        fn write32(&self, address: u16, value: u32) {
            assert!(address & 3 == 0);
            match Register(address) {
                address => {
                    tracing::warn!(?address, value, "unsupported 4-byte gicd register write");
                }
            }
        }

        fn read32(&self, address: u16) -> u32 {
            assert!(address & 3 == 0);
            match Register(address) {
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
                address => {
                    tracing::warn!(?address, "unsupported 4-byte gicd register read");
                    0
                }
            }
        }

        pub fn read(&self, address: u64, data: &mut [u8]) {
            if address & (data.len() as u64 - 1) != 0 {
                data.fill(!0);
                tracing::warn!(address, ?data, "gicd read unaligned access");
                return;
            }
            match data.len() {
                4 => data.copy_from_slice(&self.read32(address as u16).to_ne_bytes()),
                _ => {
                    data.fill(0);
                    tracing::warn!(address, ?data, "unsupported n-byte gicd register read");
                }
            }
        }

        pub fn write(&self, address: u64, data: &[u8]) {
            if address & (data.len() as u64 - 1) != 0 {
                tracing::warn!(address, ?data, "gicd write unaligned access");
                return;
            }

            match data.len() {
                4 => {
                    self.write32(address as u16, u32::from_ne_bytes(data.try_into().unwrap()));
                }
                _ => {
                    tracing::warn!(address, ?data, "unsupported n-byte gicd register write");
                }
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

            let rd = address & 0x10000 == 0;

            match data.len() {
                4 => {
                    let v = if rd {
                        self.rd_read32(address as u16)
                    } else {
                        self.sgi_read32(address as u16)
                    };
                    data.copy_from_slice(&v.to_ne_bytes())
                }
                8 if rd => {
                    let v = self.rd_read64(address as u16);
                    data.copy_from_slice(&v.to_ne_bytes())
                }
                _ => {
                    data.fill(0);
                    tracing::warn!(?address, ?data, "unsupported n-byte gicr register read");
                }
            }
        }

        pub fn write(&mut self, address: u64, data: &[u8]) {
            if address & (data.len() as u64 - 1) != 0 {
                tracing::warn!(address, ?data, "gicr write unaligned access");
                return;
            }

            let rd = address & 0x10000 == 0;

            match data.len() {
                4 => {
                    let data = u32::from_ne_bytes(data.try_into().unwrap());
                    if rd {
                        self.rd_write32(address as u16, data);
                    } else {
                        self.sgi_write32(address as u16, data);
                    }
                }
                8 if rd => {
                    let data = u64::from_ne_bytes(data.try_into().unwrap());
                    self.rd_write64(address as u16, data);
                }
                address => {
                    tracing::warn!(?address, ?data, "unsupported n-byte gicr register write");
                }
            }
        }

        fn rd_read32(&mut self, address: u16) -> u32 {
            match RdRegister(address) {
                RdRegister::PIDR2 => {
                    // GICv3
                    3 << 4
                }
                address => {
                    tracing::warn!(?address, "unsupported 4-byte gicr rd register read");
                    0
                }
            }
        }

        fn rd_write32(&mut self, address: u16, data: u32) {
            match RdRegister(address) {
                address => {
                    tracing::warn!(?address, data, "unsupported 4-byte gicr rd register write");
                }
            }
        }

        fn rd_read64(&mut self, address: u16) -> u64 {
            match RdRegister(address) {
                RdRegister::TYPER => GicrTyper::new().with_last(true).into(),
                address => {
                    tracing::warn!(?address, "unsupported 8-byte gicr rd register read");
                    0
                }
            }
        }

        fn rd_write64(&mut self, address: u16, data: u64) {
            match RdRegister(address) {
                address => {
                    tracing::warn!(?address, data, "unsupported 8-byte gicr rd register write");
                }
            }
        }

        fn sgi_read32(&mut self, address: u16) -> u32 {
            match SgiRegister(address) {
                address => {
                    tracing::warn!(?address, "unsupported 4-byte gicr sgi register read");
                    0
                }
            }
        }

        fn sgi_write32(&mut self, address: u16, data: u32) {
            match SgiRegister(address) {
                address => {
                    tracing::warn!(?address, data, "unsupported 4-byte gicr sgi register write");
                }
            }
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
