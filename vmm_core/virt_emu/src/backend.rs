// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Restricted single-VP long-mode backend, not a Linux-capable machine backend.
//!
//! Initial register import is supported; reset, migration, APIC/MSI, other VTLs
//! and subsequent register writes are rejected. Stop is deferred until an
//! already-started device operation completes. Cancelling its run future poisons
//! that VP rather than reissuing a possibly side-effecting operation.

use crate::native_memory::{NativeRam, RamError};
use crate::{state_from_registers, update_registers};
use futures::task::AtomicWaker;
use hvdef::Vtl;
use memory_range::MemoryRange;
use std::convert::Infallible;
use std::future::poll_fn;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::task::Poll;
use virt::io::CpuIo;
use virt::vp::{self, AccessVpState};
use virt::x86::{SegmentRegister, TableRegister};
use virt::{
    BindProcessor, Hypervisor, InitialVpStateSource, NeedsYield, Partition, PartitionCapabilities,
    PartitionConfig, PlatformInfo, Processor, ProtoPartition, ProtoPartitionConfig,
    ProtoPartitionIsolation, StopVp, VpHaltReason, VpIndex,
};
use x86_system::memory_core::cpu_core::system::{self, SegmentState, SystemState};
use x86_system::memory_core::shared::{Exchange, PhysicalRam};
use x86_system::mmu_core::shared::RunError;
use x86_system::mmu_core::shared::io::IoReply;
use x86_system::shared::{BatchStop, SharedEventMachine};
use x86_system::{Config, EventDiagnostic, Injection, State, Tables, WordAccess};

/// Unsupported profile, invalid lifecycle operation, or execution failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A requested state or feature is outside the restricted profile.
    #[error("unsupported emulator profile: {0}")]
    Profile(&'static str),
    /// Execution/state access requires initial register import.
    #[error("VP registers have not been initialized")]
    Uninitialized,
    /// Reimport would discard instruction, event or interrupt progress.
    #[error("register writes after initialization are not supported")]
    AlreadyInitialized,
    /// The bounded external input has not been consumed.
    #[error("selected interrupt input is occupied")]
    InterruptBusy,
    /// Exception vectors cannot enter the selected IRQ port.
    #[error("invalid selected interrupt vector")]
    InterruptVector,
    /// The private interrupt input protocol was inconsistent.
    #[error("invalid interrupt ingress state")]
    InterruptIngress,
    /// An unsupported controller request was latched for the VP.
    #[error("APIC/MSI or an invalid VP target was requested")]
    UnsupportedInterrupt,
    /// The core rejected an external input.
    #[error("selected interrupt rejected: {0:?}")]
    Injection(Injection),
    /// Completion identity or kind did not match.
    #[error("device completion did not match the outstanding request")]
    Completion,
    /// Decoder input was stale or no longer outstanding.
    #[error("decoder completion did not match the outstanding request")]
    DecodeCompletion,
    /// Dropping an in-flight run future prevents safe continuation.
    #[error("run future was cancelled during a device operation; replay is unsafe")]
    CancelledIo,
    /// The core explicitly stopped outside its execution profile.
    #[error("emulated CPU stopped: {0:?}")]
    Cpu(EventDiagnostic),
    /// A physical operation failed without inventing a guest exception.
    #[error("physical memory operation failed")]
    Memory(#[from] RunError<RamError>),
    /// Declared RAM could not be adapted.
    #[error("invalid native RAM backing")]
    Ram(#[from] RamError),
    /// Topology and capability metadata were incompatible.
    #[error("partition capabilities")]
    Capabilities(#[from] virt::PartitionCapabilitiesError),
}

struct Control {
    pending: AtomicU16,
    unsupported: AtomicBool,
    waker: AtomicWaker,
    yield_requested: NeedsYield,
}

impl Control {
    fn new() -> Self {
        Self {
            pending: AtomicU16::new(0),
            unsupported: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            yield_requested: NeedsYield::new(),
        }
    }

    fn flush(&self, core: &mut SharedEventMachine) -> Result<(), Error> {
        if self.unsupported.load(Ordering::Acquire) {
            return Err(Error::UnsupportedInterrupt);
        }
        if core.pending().is_some() {
            return Ok(());
        }
        let current = self.pending.load(Ordering::Acquire);
        if current == 0 {
            return Ok(());
        }
        let vector = u8::try_from(current - 1).map_err(|_| Error::InterruptIngress)?;
        match core.inject(vector) {
            Injection::Queued => {
                self.pending
                    .compare_exchange(current, 0, Ordering::AcqRel, Ordering::Acquire)
                    .map_err(|_| Error::InterruptIngress)?;
                Ok(())
            }
            other => Err(Error::Injection(other)),
        }
    }
}

struct RamBank {
    range: MemoryRange,
    ram: NativeRam,
}

struct Ram {
    banks: Vec<RamBank>,
}

impl Ram {
    fn bank(&self, address: u64) -> Result<&NativeRam, RamError> {
        self.banks
            .iter()
            .find(|bank| {
                address >= bank.range.start()
                    && address < bank.range.end()
                    && bank.range.end() - address >= 8
            })
            .map(|bank| &bank.ram)
            .ok_or(RamError::OutsideBank { address })
    }

    fn is_ram(&self, address: u64) -> bool {
        self.banks
            .iter()
            .any(|bank| address >= bank.range.start() && address < bank.range.end())
    }
}

impl PhysicalRam for Ram {
    type Error = RamError;
    fn read_word(&self, address: u64) -> Result<u64, RamError> {
        self.bank(address)?.read_word(address)
    }
    fn write_word(&self, address: u64, value: u64) -> Result<(), RamError> {
        self.bank(address)?.write_word(address, value)
    }
    fn compare_exchange_word(
        &self,
        address: u64,
        old: u64,
        new: u64,
    ) -> Result<Exchange, RamError> {
        self.bank(address)?.compare_exchange_word(address, old, new)
    }
    fn barrier(&self) {
        std::sync::atomic::fence(Ordering::SeqCst);
    }
}

/// Long-mode component backend with no native-hypervisor execution dependency.
#[derive(Default)]
pub struct EmuHypervisor;

/// Validated profile awaiting existing backing.
pub struct EmuProtoPartition {
    caps: Arc<PartitionCapabilities>,
}

/// Partition control and bounded external event ingress.
pub struct EmuPartition {
    caps: Arc<PartitionCapabilities>,
    control: Arc<Control>,
}

struct VpState {
    core: Option<SharedEventMachine>,
    initial_system: Option<SystemState>,
    started: bool,
    io_active: bool,
    fault: Option<Error>,
}

/// Owns the sole CPU context across bindings.
pub struct EmuProcessorBinder {
    state: VpState,
    ram: Arc<Ram>,
    caps: Arc<PartitionCapabilities>,
    control: Arc<Control>,
}

/// Bound access to that CPU context and the real VP run loop.
pub struct EmuProcessor<'a> {
    state: &'a mut VpState,
    ram: Arc<Ram>,
    caps: Arc<PartitionCapabilities>,
    control: Arc<Control>,
}

impl Hypervisor for EmuHypervisor {
    type ProtoPartition<'a> = EmuProtoPartition;
    type Partition = EmuPartition;
    type Error = Error;

    fn platform_info(&self) -> PlatformInfo {
        PlatformInfo::default()
    }

    fn new_partition<'a>(
        &'a mut self,
        config: ProtoPartitionConfig<'a>,
    ) -> Result<EmuProtoPartition, Error> {
        if config.processor_topology.vps().count() != 1
            || config.hv_config.is_some()
            || config.nested_virt
            || !matches!(config.isolation, ProtoPartitionIsolation::None)
        {
            return Err(Error::Profile(
                "one VP, no isolation/HV1/nested virtualization",
            ));
        }
        let caps =
            PartitionCapabilities::from_cpuid(config.processor_topology, &mut |function, _| {
                match function {
                    0 => [
                        0,
                        u32::from_le_bytes(*b"Auth"),
                        u32::from_le_bytes(*b"cAMD"),
                        u32::from_le_bytes(*b"enti"),
                    ],
                    0x8000_0000 => [0x8000_0008, 0, 0, 0],
                    0x8000_0008 => [48, 0, 0, 0],
                    _ => [0; 4],
                }
            })?;
        Ok(EmuProtoPartition {
            caps: Arc::new(caps),
        })
    }
}

impl ProtoPartition for EmuProtoPartition {
    type Partition = EmuPartition;
    type ProcessorBinder = EmuProcessorBinder;
    type Error = Error;
    fn max_physical_address_size(&self) -> u8 {
        48
    }

    fn build(
        self,
        config: PartitionConfig<'_>,
    ) -> Result<(EmuPartition, Vec<EmuProcessorBinder>), Error> {
        if !config.cpuid.is_empty()
            || config.vtl0_alias_map.is_some()
            || config.fault_resolver.is_some()
            || config.mem_layout.vtl2_range().is_some()
        {
            return Err(Error::Profile(
                "CPUID override, alias, fault resolver or VTL2",
            ));
        }
        let mut banks = Vec::new();
        for region in config.mem_layout.ram() {
            if region.range.end() > (1u64 << 48) {
                return Err(Error::Profile("RAM exceeds MAXPHYADDR"));
            }
            banks.push(RamBank {
                range: region.range,
                ram: NativeRam::new(config.guest_memory.clone(), region.range)?,
            });
        }
        if banks.is_empty() {
            return Err(Error::Profile("no RAM"));
        }
        let control = Arc::new(Control::new());
        let partition = EmuPartition {
            caps: self.caps.clone(),
            control: control.clone(),
        };
        let binder = EmuProcessorBinder {
            state: VpState {
                core: None,
                initial_system: Some(SystemState::empty()),
                started: false,
                io_active: false,
                fault: None,
            },
            ram: Arc::new(Ram { banks }),
            caps: self.caps,
            control,
        };
        Ok((partition, vec![binder]))
    }
}

impl EmuPartition {
    /// Offers an already-selected vector, not an APIC/PIC arbitration interface.
    pub fn inject_selected(&self, vector: u8) -> Result<(), Error> {
        if vector < 32 {
            return Err(Error::InterruptVector);
        }
        self.control
            .pending
            .compare_exchange(
                0,
                u16::from(vector) + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| Error::InterruptBusy)?;
        self.control.waker.wake();
        Ok(())
    }
}

impl inspect::Inspect for EmuPartition {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond().field("restricted_long_mode", true);
    }
}

impl virt::Hv1 for EmuPartition {
    type Error = Error;
    type Device = virt::UnimplementedDevice;
    fn reference_time_source(&self) -> Option<vmcore::reference_time::ReferenceTimeSource> {
        None
    }
    fn new_virtual_device(
        &self,
    ) -> Option<&dyn virt::DeviceBuilder<Device = Self::Device, Error = Error>> {
        None
    }
    fn synic(&self) -> anyhow::Result<Arc<dyn vmcore::synic::SynicPortAccess>> {
        Err(anyhow::anyhow!("emulator profile has no SynIC"))
    }
}

impl Partition for EmuPartition {
    fn initial_vp_state_source(&self) -> InitialVpStateSource {
        InitialVpStateSource::Registers
    }
    fn supports_reset(&self) -> Option<&dyn virt::ResetPartition<Error = Error>> {
        None
    }
    fn request_msi(&self, _vtl: Vtl, _request: virt::irqcon::MsiRequest) {
        self.control.unsupported.store(true, Ordering::Release);
        self.control.waker.wake();
    }
    fn caps(&self) -> &PartitionCapabilities {
        &self.caps
    }
    fn request_yield(&self, vp_index: VpIndex) {
        if vp_index.index() != 0 {
            self.control.unsupported.store(true, Ordering::Release);
        }
        self.control.yield_requested.request_yield();
        self.control.waker.wake();
    }
}

impl BindProcessor for EmuProcessorBinder {
    type Processor<'a> = EmuProcessor<'a>;
    type Error = Error;
    fn bind(&mut self) -> Result<EmuProcessor<'_>, Error> {
        Ok(EmuProcessor {
            state: &mut self.state,
            ram: self.ram.clone(),
            caps: self.caps.clone(),
            control: self.control.clone(),
        })
    }
}

impl inspect::InspectMut for EmuProcessor<'_> {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond()
            .field("initialized", self.state.core.is_some())
            .field("io_active", self.state.io_active);
    }
}

impl Processor for EmuProcessor<'_> {
    type StateAccess<'a>
        = EmuStateAccess<'a>
    where
        Self: 'a;

    fn set_debug_state(
        &mut self,
        vtl: Vtl,
        state: Option<&virt::x86::DebugState>,
    ) -> Result<(), Error> {
        if vtl != Vtl::Vtl0 || state.is_some() {
            return Err(Error::Profile("debug state/VTL"));
        }
        Ok(())
    }

    async fn run_vp(
        &mut self,
        mut stop: StopVp<'_>,
        dev: &impl CpuIo,
    ) -> Result<Infallible, VpHaltReason> {
        if self.state.io_active {
            return Err(dev.fatal_error(Box::new(Error::CancelledIo)));
        }
        self.state.started = true;
        let mut decode_work = 0u8;
        loop {
            stop.check()?;
            if let Some(error) = self.state.fault.take() {
                return Err(dev.fatal_error(Box::new(error)));
            }
            let Some(core) = self.state.core.as_mut() else {
                return Err(dev.fatal_error(Box::new(Error::Uninitialized)));
            };
            if let Err(error) = self.control.flush(core) {
                return Err(dev.fatal_error(Box::new(error)));
            }
            self.control.yield_requested.maybe_yield().await;
            stop.check()?;
            let batch = match core.run_with_mmio(&*self.ram, 64, 64, |address, width| {
                (0..u64::from(width)).all(|offset| {
                    !self.ram.is_ram(address + offset) && dev.is_mmio(address + offset)
                })
            }) {
                Ok(batch) => batch,
                Err(error) => return Err(dev.fatal_error(Box::new(Error::Memory(error)))),
            };
            match batch.stop {
                BatchStop::Decode(input) => {
                    if !core.complete_decode(input.sequence, x86_decode::admit(input)) {
                        return Err(dev.fatal_error(Box::new(Error::DecodeCompletion)));
                    }
                    decode_work += 1;
                    if decode_work == 64 {
                        self.control.yield_requested.request_yield();
                        decode_work = 0;
                    }
                }
                BatchStop::Io(request) => {
                    self.state.io_active = true;
                    self.ram.barrier();
                    let reply = match request.access {
                        WordAccess::Read => {
                            let mut bytes = [0; 8];
                            dev.read_mmio(VpIndex::new(0), request.address, &mut bytes)
                                .await;
                            IoReply::Read(u64::from_le_bytes(bytes))
                        }
                        WordAccess::Write(value) => {
                            dev.write_mmio(VpIndex::new(0), request.address, &value.to_le_bytes())
                                .await;
                            IoReply::Written
                        }
                    };
                    self.ram.barrier();
                    if !core.complete_io(request.sequence, reply) {
                        return Err(dev.fatal_error(Box::new(Error::Completion)));
                    }
                    self.state.io_active = false;
                }
                BatchStop::Budget | BatchStop::Yield => {
                    self.control.yield_requested.request_yield();
                }
                BatchStop::Waiting => {
                    let can_accept = core.pending().is_none();
                    stop.until_stop(poll_fn(|cx| {
                        self.control.waker.register(cx.waker());
                        if self.control.unsupported.load(Ordering::Acquire)
                            || (can_accept && self.control.pending.load(Ordering::Acquire) != 0)
                        {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    }))
                    .await?;
                }
                BatchStop::Stopped(reason) => {
                    return Err(dev.fatal_error(Box::new(Error::Cpu(reason))));
                }
            }
        }
    }

    fn flush_async_requests(&mut self) {
        if let Some(core) = self.state.core.as_mut() {
            if let Err(error) = self.control.flush(core) {
                self.state.fault = Some(error);
            }
        }
    }

    fn access_state(&mut self, vtl: Vtl) -> EmuStateAccess<'_> {
        EmuStateAccess {
            state: self.state,
            caps: &self.caps,
            vtl,
        }
    }

    fn reset(&mut self) -> Result<(), impl std::error::Error + Send + Sync + 'static> {
        Err::<(), Error>(Error::Profile("reset"))
    }

    fn scrub(&mut self, _vtl: Vtl) -> Result<(), impl std::error::Error + Send + Sync + 'static> {
        Err::<(), Error>(Error::Profile("scrub"))
    }
}

/// Snapshot access and initialization-only register import.
pub struct EmuStateAccess<'a> {
    state: &'a mut VpState,
    caps: &'a PartitionCapabilities,
    vtl: Vtl,
}

impl EmuStateAccess<'_> {
    fn core(&self) -> Result<&SharedEventMachine, Error> {
        if self.vtl != Vtl::Vtl0 {
            return Err(Error::Profile("VTL"));
        }
        self.state.core.as_ref().ok_or(Error::Uninitialized)
    }

    fn system(&self) -> Result<SystemState, Error> {
        if self.vtl != Vtl::Vtl0 {
            return Err(Error::Profile("VTL"));
        }
        if let Some(core) = &self.state.core {
            core.system()
                .ok_or(Error::Profile("missing core system state"))
        } else {
            self.state.initial_system.ok_or(Error::Uninitialized)
        }
    }

    fn set_system(&mut self, system: SystemState) -> Result<(), Error> {
        if self.vtl != Vtl::Vtl0 {
            return Err(Error::Profile("VTL"));
        }
        if self.state.started {
            return Err(Error::AlreadyInitialized);
        }
        if let Some(core) = &mut self.state.core {
            if !core.configure_system(system) {
                return Err(Error::Profile("initial system state"));
            }
        } else {
            self.state.initial_system = Some(system);
        }
        Ok(())
    }
}

fn segment_state(segment: SegmentRegister) -> SegmentState {
    SegmentState {
        base: segment.base,
        limit: segment.limit,
        selector: segment.selector,
        attributes: segment.attributes,
    }
}

fn segment_register(segment: SegmentState) -> SegmentRegister {
    SegmentRegister {
        base: segment.base,
        limit: segment.limit,
        selector: segment.selector,
        attributes: segment.attributes,
    }
}

fn with_system(mut regs: vp::Registers, system: SystemState) -> vp::Registers {
    regs.cs = segment_register(system.cs);
    regs.ss = segment_register(system.ss);
    regs.ds = segment_register(system.ds);
    regs.es = segment_register(system.es);
    regs.fs = segment_register(system.fs);
    regs.gs = segment_register(system.gs);
    regs.tr = segment_register(system.tr);
    regs.ldtr = segment_register(system.ldtr);
    regs.efer |= u64::from(system.efer_sce);
    regs
}

/// Constructs the one fixed flat-segment profile accepted by initial import.
pub fn long_mode_registers(cpu: State, config: Config, tables: Tables, cr2: u64) -> vp::Registers {
    let data = SegmentRegister {
        base: 0,
        limit: u32::MAX,
        selector: 16,
        attributes: 0xc093,
    };
    let mut regs = vp::Registers {
        cs: SegmentRegister {
            base: 0,
            limit: u32::MAX,
            selector: 8,
            attributes: 0xa09b,
        },
        ss: data,
        ds: data,
        es: data,
        gdtr: TableRegister {
            base: tables.gdt_base,
            limit: tables.gdt_limit,
        },
        idtr: TableRegister {
            base: tables.idt_base,
            limit: tables.idt_limit,
        },
        cr0: 0x8000_0011 | if config.wp { 1 << 16 } else { 0 },
        cr2,
        cr3: config.root,
        cr4: 0x20,
        efer: 0x500 | if config.nxe { 1 << 11 } else { 0 },
        ..Default::default()
    };
    update_registers(&mut regs, cpu);
    regs
}

macro_rules! unsupported_state {
    ($(($get:ident, $set:ident, $ty:ty)),* $(,)?) => {$(
        fn $get(&mut self) -> Result<$ty, Error> { Err(Error::Profile(stringify!($get))) }
        fn $set(&mut self, _value: &$ty) -> Result<(), Error> { Err(Error::Profile(stringify!($set))) }
    )*};
}

impl AccessVpState for EmuStateAccess<'_> {
    type Error = Error;
    fn caps(&self) -> &PartitionCapabilities {
        self.caps
    }
    fn commit(&mut self) -> Result<(), Error> {
        self.core().map(|_| ())
    }
    fn registers(&mut self) -> Result<vp::Registers, Error> {
        let core = self.core()?;
        Ok(with_system(
            long_mode_registers(core.cpu(), core.config(), core.tables(), core.cr2()),
            self.system()?,
        ))
    }
    fn set_registers(&mut self, regs: &vp::Registers) -> Result<(), Error> {
        if self.vtl != Vtl::Vtl0 {
            return Err(Error::Profile("VTL"));
        }
        if self.state.core.is_some() || self.state.started {
            return Err(Error::AlreadyInitialized);
        }
        let config = Config {
            root: regs.cr3,
            wp: regs.cr0 & (1 << 16) != 0,
            nxe: regs.efer & (1 << 11) != 0,
        };
        let tables = Tables {
            gdt_base: regs.gdtr.base,
            gdt_limit: regs.gdtr.limit,
            idt_base: regs.idtr.base,
            idt_limit: regs.idtr.limit,
        };
        let cpu = state_from_registers(regs);
        let system = SystemState {
            cs: segment_state(regs.cs),
            ss: segment_state(regs.ss),
            ds: segment_state(regs.ds),
            es: segment_state(regs.es),
            fs: segment_state(regs.fs),
            gs: segment_state(regs.gs),
            tr: segment_state(regs.tr),
            ldtr: segment_state(regs.ldtr),
            efer_sce: regs.efer & 1 != 0,
            ..self.system()?
        };
        let mut normalized = *regs;
        normalized.cr0 |= 0x10;
        if !system.is_supported()
            || normalized != with_system(long_mode_registers(cpu, config, tables, regs.cr2), system)
            || config.root >= 1u64 << 48
            || !config.root.is_multiple_of(4096)
            || cpu.flags & !0x0021_0ed7 != 0
            || cpu.flags & 2 == 0
            || !tables.gdt_base.is_multiple_of(8)
            || tables.gdt_limit < 23
            || !tables.idt_base.is_multiple_of(16)
        {
            return Err(Error::Profile("initial long-mode register image"));
        }
        let mut core = SharedEventMachine::new(cpu, config, regs.cr2, tables);
        if !core.configure_system(system) || !core.enable_decode() {
            return Err(Error::Profile("initial system/decoder state"));
        }
        self.state.core = Some(core);
        self.state.initial_system = None;
        Ok(())
    }
    fn pat(&mut self) -> Result<vp::Pat, Error> {
        Ok(vp::Pat {
            value: self.system()?.pat,
        })
    }
    fn set_pat(&mut self, value: &vp::Pat) -> Result<(), Error> {
        if value.value != system::DEFAULT_PAT {
            return Err(Error::Profile("initial PAT image"));
        }
        let mut system = self.system()?;
        system.pat = value.value;
        self.set_system(system)
    }
    fn mtrrs(&mut self) -> Result<vp::Mtrrs, Error> {
        let system = self.system()?;
        Ok(vp::Mtrrs {
            msr_mtrr_def_type: system.mtrr_def,
            fixed: system.mtrr_fixed,
            variable: system.mtrr_variable,
        })
    }
    fn set_mtrrs(&mut self, value: &vp::Mtrrs) -> Result<(), Error> {
        if !system::mtrrs_supported(value.msr_mtrr_def_type, &value.fixed, &value.variable) {
            return Err(Error::Profile("initial MTRR image"));
        }
        let mut system = self.system()?;
        system.mtrr_def = value.msr_mtrr_def_type;
        system.mtrr_fixed = value.fixed;
        system.mtrr_variable = value.variable;
        self.set_system(system)
    }
    fn activity(&mut self) -> Result<vp::Activity, Error> {
        let core = self.core()?;
        Ok(vp::Activity {
            mp_state: if core.halted() {
                vp::MpState::Halted
            } else {
                vp::MpState::Running
            },
            interrupt_shadow: core.shadow(),
            pending_interruption: core
                .pending()
                .map(|vector| vp::PendingInterruption::Interrupt { vector }),
            ..Default::default()
        })
    }
    fn set_activity(&mut self, value: &vp::Activity) -> Result<(), Error> {
        if value != &self.activity()? {
            return Err(Error::Profile("activity mutation"));
        }
        Ok(())
    }
    unsupported_state! {
        (xsave, set_xsave, vp::Xsave), (apic, set_apic, vp::Apic),
        (xcr, set_xcr, vp::Xcr0), (xss, set_xss, vp::Xss),
        (virtual_msrs, set_virtual_msrs, vp::VirtualMsrs),
        (debug_regs, set_debug_regs, vp::DebugRegisters),
        (tsc, set_tsc, vp::Tsc), (cet, set_cet, vp::Cet),
        (cet_ss, set_cet_ss, vp::CetSs), (tsc_aux, set_tsc_aux, vp::TscAux),
        (tsc_deadline, set_tsc_deadline, vp::TscDeadline),
        (synic_msrs, set_synic_msrs, vp::SyntheticMsrs),
        (synic_message_page, set_synic_message_page, vp::SynicMessagePage),
        (synic_event_flags_page, set_synic_event_flags_page, vp::SynicEventFlagsPage),
        (synic_message_queues, set_synic_message_queues, vp::SynicMessageQueues),
        (synic_timers, set_synic_timers, vp::SynicTimers),
        (nested_state, set_nested_state, vp::NestedState),
    }
}
