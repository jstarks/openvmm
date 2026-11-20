// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Restricted single-VP long-mode backend, not a Linux-capable machine backend.
//!
//! Initial register import and owned APIC/MSI are supported; reset, migration, other VTLs
//! and subsequent register writes are rejected. Stop is deferred until an
//! already-started device operation completes. Cancelling its run future poisons
//! that VP rather than reissuing a possibly side-effecting operation.

use crate::native_memory::{PartitionMemory, RamError};
use crate::write_watch::{CaptureError, CodeCaptureError, Watched, WriteWatch};
use crate::{state_from_registers, update_registers};
use futures::task::AtomicWaker;
use hvdef::Vtl;
use memory_range::MemoryRange;
use std::convert::Infallible;
use std::future::poll_fn;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64, Ordering};
use std::task::Poll;
pub use strudel::DecodeDiagnostics;
use strudel::{CpuState, Machine, RunBudget, Stop as BatchStop};
use virt::io::CpuIo;
use virt::vp::{self, AccessVpState};
use virt::x86::{SegmentRegister, TableRegister};
use virt::{
    BindProcessor, Hypervisor, InitialVpStateSource, NeedsYield, Partition, PartitionCapabilities,
    PartitionConfig, PartitionMemoryMap, PlatformInfo, Processor, ProtoPartition,
    ProtoPartitionConfig, ProtoPartitionIsolation, StopVp, VpHaltReason, VpIndex,
};
use vmcore::vmtime::{VmTimeAccess, VmTimeSource};
use x86_system::arch::apic::registers::LocalApic;
use x86_system::arch::system::{self, SegmentState, SystemState};
use x86_system::memory::physical::PhysicalRam;
use x86_system::mmu::translate::RunError;
use x86_system::mmu::translate::io::IoReply;
use x86_system::{Config, EventDiagnostic, Injection, State, Tables, WordAccess};

#[path = "backend_apic.rs"]
mod apic;
#[cfg(feature = "perf")]
#[path = "backend_perf.rs"]
pub mod perf;

/// Unsupported profile, invalid lifecycle operation, or execution failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A requested state or feature is outside the restricted profile.
    #[error("unsupported emulator profile: {0}")]
    Profile(&'static str),
    /// The complete architectural image was rejected before CPU publication.
    #[error("unsupported initial CPU state")]
    State(#[from] strudel::StateError),
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
    #[error("unsupported interrupt message or an invalid VP target was requested")]
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
    /// Completed-batch telemetry cannot wrap.
    #[error("completed-batch progress counter exhausted")]
    ProgressExhausted,
    /// An explicitly configured host checkpoint was reached before its fetch.
    #[error("host execution checkpoint at {rip:#x}")]
    Checkpoint {
        /// The unexecuted instruction at the stopped architectural boundary.
        rip: u64,
    },
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
    /// The owned controller rejected an unimplemented device profile.
    #[error("owned APIC stopped: {0:?}")]
    Apic(x86_system::arch::apic::registers::Error),
    /// A controller message could not enter its architectural image.
    #[error("owned APIC ingress rejected: {0:?}")]
    ApicIngress(x86_system::arch::apic::Rejection),
}

struct Control {
    has_apic: bool,
    routing: AtomicU64,
    incoming: [AtomicU64; 8],
    incoming_banks: AtomicU8,
    pending: AtomicU16,
    unsupported: AtomicBool,
    waker: AtomicWaker,
    yield_requested: NeedsYield,
}

impl Control {
    fn new(has_apic: bool) -> Self {
        Self {
            has_apic,
            routing: AtomicU64::new(0),
            incoming: std::array::from_fn(|_| AtomicU64::new(0)),
            incoming_banks: AtomicU8::new(0),
            pending: AtomicU16::new(0),
            unsupported: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            yield_requested: NeedsYield::new(),
        }
    }

    fn flush(&self, core: &mut Machine) -> Result<(), Error> {
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

/// Long-mode component backend with no native-hypervisor execution dependency.
#[derive(Default)]
pub struct EmuHypervisor;

/// Validated profile awaiting existing backing.
pub struct EmuProtoPartition {
    caps: Arc<PartitionCapabilities>,
    clock: VmTimeSource,
    architectural_apic: bool,
    apic_id: u32,
    writes: WriteWatch,
}

/// Partition control and bounded external event ingress.
pub struct EmuPartition {
    caps: Arc<PartitionCapabilities>,
    control: Arc<Control>,
    ram: Arc<PartitionMemory>,
    writes: WriteWatch,
}

enum CpuLifecycle {
    Importing(Box<SystemState>),
    Ready(Box<Machine>),
}

struct VpState {
    #[cfg(test)]
    decode_cache_enabled: bool,
    #[cfg(test)]
    boundary_in_batch: bool,
    lapic: Option<LocalApic>,
    apic_offer: Option<u8>,
    apic_delivered: [u64; 256],
    first_apic_retired: Option<u64>,
    first_apic_time: Option<u64>,
    first_apic_decode: Option<DecodeDiagnostics>,
    cpu: CpuLifecycle,
    started: bool,
    progress: CompletedBatchProgress,
    code_preparation: CodePreparationDiagnostics,
    checkpoint: Option<u64>,
    io_active: bool,
    fault: Option<Error>,
    #[cfg(feature = "perf")]
    profile: Option<perf::Sampler>,
}

/// Owns the sole CPU context across bindings.
pub struct EmuProcessorBinder {
    state: VpState,
    ram: Arc<PartitionMemory>,
    writes: WriteWatch,
    ram_ranges: Arc<[MemoryRange]>,
    caps: Arc<PartitionCapabilities>,
    control: Arc<Control>,
    clock: VmTimeAccess,
}

/// Bound access to that CPU context and the real VP run loop.
pub struct EmuProcessor<'a> {
    state: &'a mut VpState,
    ram: Arc<PartitionMemory>,
    writes: WriteWatch,
    ram_ranges: Arc<[MemoryRange]>,
    caps: Arc<PartitionCapabilities>,
    control: Arc<Control>,
    clock: &'a mut VmTimeAccess,
}

/// Progress from successfully returned core batches, not transport-error totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompletedBatchProgress {
    /// Instructions retired in completed batches.
    pub retired: u64,
    /// Events delivered in completed batches.
    pub delivered: u64,
}

/// Cold code-page registration, never permission to bypass guest fetch checks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CodePreparationDiagnostics {
    /// Cold page requests satisfied with a current watched identity.
    pub prepared: u64,
    /// Requests whose backing was unavailable by the preparation point.
    pub unavailable: u64,
}

/// Read-only interrupt telemetry, not a restartable migration snapshot.
#[derive(Debug)]
pub struct ApicDiagnostics {
    /// The single owned register image.
    pub registers: LocalApic,
    /// Successfully delivered vectors and counts.
    pub delivered: Vec<(u8, u64)>,
    /// Retirements at the first successful APIC delivery.
    pub first_interrupt_retired: Option<u64>,
    /// Shared VM time at the first successful APIC delivery.
    pub first_interrupt_time_100ns: Option<u64>,
    /// Current time in the shared VM clock domain.
    pub vm_time_100ns: u64,
}

impl EmuProcessor<'_> {
    /// Enables bounded guest-PC sampling before execution, without changing guest state.
    #[cfg(feature = "perf")]
    pub fn enable_execution_profile(&mut self) -> Result<(), Error> {
        if self.state.started {
            return Err(Error::Profile("profiling must be enabled before execution"));
        }
        self.state.profile = Some(perf::Sampler::new());
        Ok(())
    }

    /// Takes the optional host-only samples after execution has stopped.
    #[cfg(feature = "perf")]
    pub fn take_execution_profile(&mut self) -> Option<perf::ExecutionProfile> {
        self.state.profile.take().map(|sampler| sampler.finish())
    }

    /// Returns current decoder counters and their first-interrupt baseline.
    pub fn decode_diagnostics(
        &self,
    ) -> Result<(DecodeDiagnostics, Option<DecodeDiagnostics>), Error> {
        let CpuLifecycle::Ready(core) = &self.state.cpu else {
            return Err(Error::Uninitialized);
        };
        Ok((core.decode_diagnostics(), self.state.first_apic_decode))
    }

    /// Returns aggregate IR entry lengths, retirements and precise exit reasons.
    pub fn execution_diagnostics(
        &self,
    ) -> Result<x86_system::execute::block::ExecutionDiagnostics, Error> {
        let CpuLifecycle::Ready(core) = &self.state.cpu else {
            return Err(Error::Uninitialized);
        };
        Ok(core.execution_diagnostics())
    }

    /// Reports host payload reuse separately from guest translation state.
    pub fn translation_diagnostics(
        &self,
    ) -> Result<x86_system::memory::physical::TranslationDiagnostics, Error> {
        let CpuLifecycle::Ready(core) = &self.state.cpu else {
            return Err(Error::Uninitialized);
        };
        Ok(core.translation_diagnostics())
    }

    /// Reports cold registration separately from guest execution progress.
    pub fn code_preparation_diagnostics(&self) -> CodePreparationDiagnostics {
        self.state.code_preparation
    }

    #[cfg(test)]
    pub(crate) fn bypass_decode_cache(&mut self) {
        self.state.decode_cache_enabled = false;
    }
    #[cfg(test)]
    pub(crate) fn bypass_boundary_batch(&mut self) {
        self.state.boundary_in_batch = false;
    }
    /// Captures the owned controller and delivery counters without changing them.
    pub fn apic_diagnostics(&self) -> Option<ApicDiagnostics> {
        self.state.lapic.map(|registers| ApicDiagnostics {
            registers,
            delivered: self
                .state
                .apic_delivered
                .iter()
                .enumerate()
                .filter_map(|(vector, &count)| (count != 0).then_some((vector as u8, count)))
                .collect(),
            first_interrupt_retired: self.state.first_apic_retired,
            first_interrupt_time_100ns: self.state.first_apic_time,
            vm_time_100ns: self.clock.now().as_100ns(),
        })
    }
    /// Configure an out-of-band instruction-boundary stop without changing guest state.
    pub fn set_execution_checkpoint(&mut self, address: Option<u64>) -> Result<(), Error> {
        if address
            .is_some_and(|address| (0x8000_0000_0000..0xffff_8000_0000_0000).contains(&address))
        {
            return Err(Error::Profile("noncanonical execution checkpoint"));
        }
        self.state.checkpoint = address;
        Ok(())
    }

    /// Transport failures can leave additional, unreported partial progress.
    pub fn completed_batch_progress(&self) -> CompletedBatchProgress {
        self.state.progress
    }
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
        self.partition(config, true)
    }
}

impl EmuHypervisor {
    /// Constructs the frozen pre-APIC regression fixture, not a production option.
    pub fn new_legacy_fixture<'a>(
        &'a mut self,
        config: ProtoPartitionConfig<'a>,
    ) -> Result<EmuProtoPartition, Error> {
        self.partition(config, false)
    }

    fn partition(
        &mut self,
        config: ProtoPartitionConfig<'_>,
        architectural_apic: bool,
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
        let apic_id = config.processor_topology.max_apic_id();
        if architectural_apic
            && (apic_id > 255
                || config.processor_topology.apic_mode()
                    != vm_topology::processor::x86::ApicMode::X2ApicSupported)
        {
            return Err(Error::Profile(
                "initial APIC profile requires an 8-bit boot ID and x2APIC-capable legacy mode",
            ));
        }
        let caps = PartitionCapabilities::from_cpuid(
            config.processor_topology,
            &mut |function, subleaf| {
                let mut values = x86_system::arch::profile::cpuid(function, subleaf);
                if architectural_apic && function == 1 {
                    values[1] = (values[1] & 0x00ff_ffff) | (apic_id << 24);
                    values[2] |= 1 << 21;
                    values[3] |= 1 << 9;
                }
                values
            },
        )?;
        Ok(EmuProtoPartition {
            caps: Arc::new(caps),
            clock: config.vmtime.clone(),
            architectural_apic,
            apic_id,
            writes: WriteWatch::default(),
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

    fn memory_write_tracker(&self) -> Option<guestmem::WriteTracker> {
        Some(self.writes.tracker())
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
        let mut ram_ranges = Vec::new();
        for region in config.mem_layout.ram() {
            if region.range.end() > (1u64 << 48) {
                return Err(Error::Profile("RAM exceeds MAXPHYADDR"));
            }
            ram_ranges.push(region.range);
        }
        if ram_ranges.is_empty() {
            return Err(Error::Profile("no RAM"));
        }
        let control = Arc::new(Control::new(self.architectural_apic));
        let ram = Arc::new(PartitionMemory::with_write_tracker(self.writes.tracker()));
        let partition = EmuPartition {
            caps: self.caps.clone(),
            control: control.clone(),
            ram: ram.clone(),
            writes: self.writes.clone(),
        };
        let binder = EmuProcessorBinder {
            clock: self.clock.access("emu-tsc"),
            state: VpState {
                #[cfg(test)]
                decode_cache_enabled: true,
                #[cfg(test)]
                boundary_in_batch: true,
                lapic: if self.architectural_apic {
                    Some(LocalApic::new(self.apic_id, true, 0))
                } else {
                    None
                },
                apic_offer: None,
                apic_delivered: [0; 256],
                first_apic_retired: None,
                first_apic_time: None,
                first_apic_decode: None,
                cpu: CpuLifecycle::Importing(Box::new(SystemState::empty())),
                started: false,
                progress: CompletedBatchProgress::default(),
                code_preparation: CodePreparationDiagnostics::default(),
                #[cfg(feature = "perf")]
                profile: None,
                checkpoint: None,
                io_active: false,
                fault: None,
            },
            ram,
            writes: self.writes,
            ram_ranges: ram_ranges.into(),
            caps: self.caps,
            control,
        };
        Ok((partition, vec![binder]))
    }
}

impl EmuPartition {
    #[cfg(test)]
    pub(crate) fn write_tracker(&self) -> guestmem::WriteTracker {
        self.writes.tracker()
    }

    /// Captures physical code after revoking CPU writes and excluding DMA writes.
    ///
    /// Every external writer must use this prototype's observed memory backing.
    /// The result is a backing observation, not guest execute authorization;
    /// instruction fetch permissions and current translation remain separate.
    /// This may wait for bounded CPU batches. Do not call from inside such a
    /// batch or while holding the external write-registration gate.
    pub fn capture_code<const N: usize>(
        &self,
        address: u64,
    ) -> Result<Watched<[u8; N]>, CodeCaptureError> {
        let end = address
            .checked_add(N as u64)
            .filter(|&end| address < end)
            .ok_or(CaptureError::InvalidRange)?;
        self.ram
            .with_code_watch(address..end, |ram| {
                self.writes.capture(address..end, || {
                    let mut bytes = [0; N];
                    ram.read_bytes(address, &mut bytes)?;
                    Ok(bytes)
                })
            })?
            .map_err(CodeCaptureError::Capture)
    }

    /// Offers an already-selected vector, not an APIC/PIC arbitration interface.
    pub fn inject_selected(&self, vector: u8) -> Result<(), Error> {
        if self.control.has_apic {
            return Err(Error::Profile(
                "selected-vector ingress bypasses the owned LAPIC",
            ));
        }
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
    fn request_msi(&self, vtl: Vtl, request: virt::irqcon::MsiRequest) {
        if vtl == Vtl::Vtl0 {
            self.control.request_apic_msi(request);
        } else {
            self.control.unsupported.store(true, Ordering::Release);
            self.control.waker.wake();
        }
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

// UNSAFETY: Forwards the caller's mapping lifetime contract to the owned map.
#[expect(unsafe_code)]
impl PartitionMemoryMap for EmuPartition {
    unsafe fn map_range(
        &self,
        data: *mut u8,
        size: usize,
        addr: u64,
        writable: bool,
        exec: bool,
    ) -> anyhow::Result<()> {
        // SAFETY: the caller keeps the backing valid until unmap completes.
        unsafe { self.ram.map_range(data, size, addr, writable, exec) }?;
        self.writes.tracker().notify_write(addr, size)?;
        Ok(())
    }

    fn unmap_range(&self, addr: u64, size: u64) -> anyhow::Result<()> {
        self.ram.unmap_range(addr, size)?;
        self.writes.tracker().notify_write(addr, size as usize)?;
        Ok(())
    }

    #[cfg(windows)]
    unsafe fn map_remote_range(
        &self,
        _process: std::os::windows::io::BorrowedHandle<'_>,
        _data: *mut u8,
        _size: usize,
        _addr: u64,
        _writable: bool,
        _exec: bool,
    ) -> anyhow::Result<()> {
        anyhow::bail!("emulator requires local process memory mappings")
    }
}

impl BindProcessor for EmuProcessorBinder {
    type Processor<'a> = EmuProcessor<'a>;
    type Error = Error;
    fn bind(&mut self) -> Result<EmuProcessor<'_>, Error> {
        Ok(EmuProcessor {
            clock: &mut self.clock,
            state: &mut self.state,
            ram: self.ram.clone(),
            writes: self.writes.clone(),
            ram_ranges: self.ram_ranges.clone(),
            caps: self.caps.clone(),
            control: self.control.clone(),
        })
    }
}

impl inspect::InspectMut for EmuProcessor<'_> {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond()
            .field(
                "initialized",
                matches!(self.state.cpu, CpuLifecycle::Ready(_)),
            )
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
        let mut batch_work = 0u8;
        loop {
            stop.check()?;
            if let Err(error) = apic::poll(self.state, &self.control, self.clock) {
                return Err(dev.fatal_error(Box::new(error)));
            }
            let local_window = self.state.lapic.as_ref().and_then(|apic| {
                (apic.base & 0x800 != 0 && !apic.x2apic()).then_some(apic.base & !0xfff)
            });
            let checkpoint = self.state.checkpoint;
            if let Some(error) = self.state.fault.take() {
                return Err(dev.fatal_error(Box::new(error)));
            }
            let CpuLifecycle::Ready(core) = &mut self.state.cpu else {
                return Err(dev.fatal_error(Box::new(Error::Uninitialized)));
            };
            if let Err(error) = self.control.flush(core) {
                return Err(dev.fatal_error(Box::new(error)));
            }
            self.control.yield_requested.maybe_yield().await;
            stop.check()?;
            if core.at_instruction_boundary() && checkpoint == Some(core.cpu().rip) {
                return Err(dev.fatal_error(Box::new(Error::Checkpoint {
                    rip: core.cpu().rip,
                })));
            }
            let candidate = self.state.lapic.as_ref().and_then(|apic| apic.candidate());
            let deadline = self
                .state
                .lapic
                .as_ref()
                .filter(|apic| apic.enabled() && apic.lvt[0] & 0x10000 == 0)
                .map(|apic| apic.timer.deadline());
            let offer = self.state.apic_offer;
            #[cfg(test)]
            let boundary_in_batch = self.state.boundary_in_batch;
            let result = {
                let access = self.ram.access();
                let ram = access.ram();
                core.run(
                    &ram,
                    RunBudget {
                        memory_effects: 64,
                        steps: 64,
                    },
                    |address, width| {
                        (0..u64::from(width)).all(|offset| {
                            !self.ram_ranges.iter().any(|range| {
                                address + offset >= range.start() && address + offset < range.end()
                            })
                        })
                    },
                    |core| {
                        #[cfg(test)]
                        if !boundary_in_batch {
                            return true;
                        }
                        if core.halted() {
                            // Arm the timer timeout before registering the halt wait.
                            return true;
                        }
                        if core.at_instruction_boundary() && checkpoint == Some(core.cpu().rip) {
                            return true;
                        }
                        if self.control.unsupported.load(Ordering::Acquire)
                            || self.control.apic_work_pending()
                            || self.control.pending.load(Ordering::Acquire) != 0
                        {
                            return true;
                        }
                        if core.pending().is_some() {
                            return false;
                        }
                        if offer.is_some() {
                            return true;
                        }
                        if core.cpu().flags & 0x200 == 0 || core.shadow() {
                            return false;
                        }
                        candidate.is_some()
                            || match deadline {
                                Some(x86_system::arch::apic::timer::Deadline::At(value)) => {
                                    self.clock.now().as_100ns()
                                        >= apic::deadline_time(value).as_100ns()
                                }
                                Some(x86_system::arch::apic::timer::Deadline::BeyondClock) => true,
                                _ => false,
                            }
                    },
                )
            };
            let batch = match result {
                Ok(batch) => batch,
                Err(RunError::DecodeCompletion(_)) => {
                    return Err(dev.fatal_error(Box::new(Error::DecodeCompletion)));
                }
                Err(error) => return Err(dev.fatal_error(Box::new(Error::Memory(error)))),
            };
            let Some(retired) = self.state.progress.retired.checked_add(batch.retired) else {
                return Err(dev.fatal_error(Box::new(Error::ProgressExhausted)));
            };
            let Some(delivered) = self.state.progress.delivered.checked_add(batch.delivered) else {
                return Err(dev.fatal_error(Box::new(Error::ProgressExhausted)));
            };
            self.state.progress = CompletedBatchProgress { retired, delivered };
            let preparation = match self.ram.prepare_code_pages(&self.writes) {
                Ok(preparation) => preparation,
                Err(error) => return Err(dev.fatal_error(Box::new(Error::Ram(error)))),
            };
            let Some(prepared) = self
                .state
                .code_preparation
                .prepared
                .checked_add(preparation.prepared as u64)
            else {
                return Err(dev.fatal_error(Box::new(Error::ProgressExhausted)));
            };
            let Some(unavailable) = self
                .state
                .code_preparation
                .unavailable
                .checked_add(preparation.unavailable as u64)
            else {
                return Err(dev.fatal_error(Box::new(Error::ProgressExhausted)));
            };
            self.state.code_preparation = CodePreparationDiagnostics {
                prepared,
                unavailable,
            };
            #[cfg(feature = "perf")]
            if let Some(profile) = &mut self.state.profile {
                profile.record(retired, delivered, || core.cpu().rip);
            }
            // Frequent controller/checkpoint returns are not executor-yield requests.
            batch_work += 1;
            if batch_work == 64 {
                self.control.yield_requested.request_yield();
                batch_work = 0;
            }
            match apic::acknowledge(&mut self.state.lapic, &mut self.state.apic_offer, core) {
                Ok(Some(vector)) => {
                    let slot = &mut self.state.apic_delivered[usize::from(vector)];
                    let Some(count) = slot.checked_add(1) else {
                        return Err(dev.fatal_error(Box::new(Error::ProgressExhausted)));
                    };
                    *slot = count;
                    self.state.first_apic_retired.get_or_insert(retired);
                    if self.state.first_apic_time.is_none() {
                        self.state.first_apic_time = Some(self.clock.now().as_100ns());
                        self.state.first_apic_decode = Some(core.decode_diagnostics());
                    }
                }
                Ok(None) => {}
                Err(error) => return Err(dev.fatal_error(Box::new(error))),
            }
            match batch.stop {
                BatchStop::ControlIo { sequence, access } => {
                    let Some(lapic) = self.state.lapic.as_mut() else {
                        return Err(
                            dev.fatal_error(Box::new(Error::Profile("missing owned LAPIC")))
                        );
                    };
                    let reply = match apic::ticks(self.clock.now())
                        .and_then(|now| apic::control(lapic, access, now, &self.control, dev))
                    {
                        Ok(reply) => reply,
                        Err(error) => return Err(dev.fatal_error(Box::new(error))),
                    };
                    if !core.complete_control(sequence, reply) {
                        return Err(dev.fatal_error(Box::new(Error::Completion)));
                    }
                }
                BatchStop::Timestamp { sequence } => {
                    let ticks = self
                        .clock
                        .now()
                        .as_100ns()
                        .wrapping_mul(x86_system::arch::profile::TSC_HZ / 10_000_000);
                    if !core.complete_timestamp(sequence, ticks) {
                        return Err(dev.fatal_error(Box::new(Error::Completion)));
                    }
                }
                BatchStop::PortIo(request) => {
                    self.state.io_active = true;
                    self.ram.barrier();
                    let size = (request.width.bits() / 8) as usize;
                    let reply = match request.access {
                        WordAccess::Read => {
                            let mut bytes = [0; 8];
                            dev.read_io(VpIndex::new(0), request.port, &mut bytes[..size])
                                .await;
                            IoReply::Read(u64::from_le_bytes(bytes))
                        }
                        WordAccess::Write(value) => {
                            dev.write_io(
                                VpIndex::new(0),
                                request.port,
                                &value.to_le_bytes()[..size],
                            )
                            .await;
                            IoReply::Written
                        }
                    };
                    self.ram.barrier();
                    if !core.complete_port_io(request.sequence, reply) {
                        return Err(dev.fatal_error(Box::new(Error::Completion)));
                    }
                    self.state.io_active = false;
                }
                BatchStop::Io(request) => {
                    self.state.io_active = true;
                    self.ram.barrier();
                    let size = usize::from(request.size);
                    if let Some(base) = local_window
                        .filter(|&base| request.address >= base && request.address - base < 4096)
                    {
                        let Some(lapic) = self.state.lapic.as_mut() else {
                            return Err(dev.fatal_error(Box::new(Error::Profile(
                                "missing local APIC window owner",
                            ))));
                        };
                        let now = match apic::ticks(self.clock.now()) {
                            Ok(now) => now,
                            Err(error) => return Err(dev.fatal_error(Box::new(error))),
                        };
                        let offset = (request.address - base) as u16;
                        let reply = match request.access {
                            WordAccess::Read => match lapic.mmio_read(offset, request.size, now) {
                                Ok((next, value)) => {
                                    *lapic = next;
                                    IoReply::Read(u64::from(value))
                                }
                                Err(error) => {
                                    return Err(dev.fatal_error(Box::new(Error::Apic(error))));
                                }
                            },
                            WordAccess::Write(value) => {
                                match lapic.mmio_write(offset, request.size, value as u32, now) {
                                    Ok((next, effects)) => {
                                        *lapic = next;
                                        if let Err(error) =
                                            apic::effect(lapic, &self.control, effects, dev)
                                        {
                                            return Err(dev.fatal_error(Box::new(error)));
                                        }
                                        IoReply::Written
                                    }
                                    Err(error) => {
                                        return Err(dev.fatal_error(Box::new(Error::Apic(error))));
                                    }
                                }
                            }
                        };
                        self.ram.barrier();
                        if !core.complete_io(request.sequence, reply) {
                            return Err(dev.fatal_error(Box::new(Error::Completion)));
                        }
                        self.state.io_active = false;
                        continue;
                    }
                    let reply = match request.access {
                        WordAccess::Read => {
                            let mut bytes = [0; 8];
                            dev.read_mmio(VpIndex::new(0), request.address, &mut bytes[..size])
                                .await;
                            IoReply::Read(u64::from_le_bytes(bytes))
                        }
                        WordAccess::Write(value) => {
                            dev.write_mmio(
                                VpIndex::new(0),
                                request.address,
                                &value.to_le_bytes()[..size],
                            )
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
                BatchStop::Budget | BatchStop::Yield => {}
                BatchStop::Waiting => {
                    let can_accept = core.pending().is_none();
                    stop.until_stop(poll_fn(|cx| {
                        self.control.waker.register(cx.waker());
                        if self.control.unsupported.load(Ordering::Acquire)
                            || (can_accept && self.control.pending.load(Ordering::Acquire) != 0)
                            || self.control.apic_work_pending()
                            || self.clock.poll_timeout(cx).is_ready()
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
        if let CpuLifecycle::Ready(core) = &mut self.state.cpu {
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
    fn core(&self) -> Result<&Machine, Error> {
        if self.vtl != Vtl::Vtl0 {
            return Err(Error::Profile("VTL"));
        }
        match &self.state.cpu {
            CpuLifecycle::Ready(core) => Ok(core),
            CpuLifecycle::Importing(_) => Err(Error::Uninitialized),
        }
    }

    fn system(&self) -> Result<SystemState, Error> {
        if self.vtl != Vtl::Vtl0 {
            return Err(Error::Profile("VTL"));
        }
        Ok(match &self.state.cpu {
            CpuLifecycle::Ready(core) => core.system(),
            CpuLifecycle::Importing(system) => **system,
        })
    }

    fn set_system(&mut self, system: SystemState) -> Result<(), Error> {
        if self.vtl != Vtl::Vtl0 {
            return Err(Error::Profile("VTL"));
        }
        if self.state.started {
            return Err(Error::AlreadyInitialized);
        }
        match &mut self.state.cpu {
            CpuLifecycle::Ready(core) => {
                if !core.set_system(system) {
                    return Err(Error::Profile("initial system state"));
                }
            }
            CpuLifecycle::Importing(initial) => **initial = system,
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
    regs.cr0 |= system.cr0_extra;
    regs.cr4 |= system.cr4_extra;
    regs
}

/// Constructs the component fixture's flat-segment initial profile.
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
        let state = self.core()?.state();
        let mut registers = with_system(
            long_mode_registers(state.registers, state.config, state.tables, state.cr2),
            state.system,
        );
        if let Some(apic) = &self.state.lapic {
            registers.cr8 = u64::from(apic.tpr >> 4);
        }
        Ok(registers)
    }
    fn set_registers(&mut self, regs: &vp::Registers) -> Result<(), Error> {
        if self.vtl != Vtl::Vtl0 {
            return Err(Error::Profile("VTL"));
        }
        if matches!(self.state.cpu, CpuLifecycle::Ready(_)) || self.state.started {
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
            cr0_extra: regs.cr0 & 0x40022,
            cr4_extra: regs.cr4 & 0x90,
            ..self.system()?
        };
        let mut normalized = *regs;
        normalized.cr0 |= 0x10;
        if self.state.lapic.is_some() {
            if regs.cr8 > 15 {
                return Err(Error::Profile("initial CR8"));
            }
            normalized.cr8 = 0;
        }
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
        let mut core = Machine::new(CpuState {
            registers: cpu,
            config,
            cr2: regs.cr2,
            tables,
            system,
        })?;
        #[cfg(test)]
        core.set_test_options(strudel::TestOptions {
            cache: self.state.decode_cache_enabled,
        });
        if let Some(apic) = &mut self.state.lapic {
            if !core.configure_apic(apic.id) {
                return Err(Error::Profile("initial APIC metadata"));
            }
            *apic = apic.write_cr8(regs.cr8).map_err(Error::Apic)?;
        }
        self.state.cpu = CpuLifecycle::Ready(Box::new(core));
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
