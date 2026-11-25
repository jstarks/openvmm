// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Restricted single-VP long-mode backend for Linux direct boot.
//!
//! Initial register import and owned APIC/MSI are supported; reset, migration, other VTLs
//! and subsequent register writes are rejected. Stop is deferred until an
//! already-started device operation completes. Cancelling its run future poisons
//! that VP rather than reissuing a possibly side-effecting operation.
//!
//! Run on a dedicated VP thread through `block_on_vp`: a poll can execute
//! indefinitely or block in guest HLT until another thread posts work. VM
//! time and devices need a driver independent of that thread. HLT releases
//! the mapping lease, and a host yield does not unhalt the guest.

use crate::native_memory::{PartitionMemory, RamError};
use crate::write_watch::{CodeCaptureError, Watched, WriteWatch};
use crate::{state_from_registers, update_registers};
use hvdef::Vtl;
use memory_range::MemoryRange;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Wake, Waker};
pub use strudel::DecodeDiagnostics;
use strudel::{CpuState, Machine, Stop as BatchStop, VpControl};
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
use x86_system::mmu::translate::RunError;
use x86_system::mmu::translate::io::IoReply;
use x86_system::{Config, EventDiagnostic, Injection, State, Tables, WordAccess};

#[cfg(feature = "perf")]
#[path = "backend_perf.rs"]
pub mod perf;
#[path = "backend_timer.rs"]
mod timer;

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
    /// The selected executor cannot compile this entry; no guest exception was injected.
    #[error("native compilation at guest RIP {rip:#x}: {instruction}: {reason}")]
    NativeCompilation {
        /// Best available guest instruction text.
        instruction: String,
        /// Unexecuted guest instruction.
        rip: u64,
        /// Unsupported operation or compilation failure.
        reason: &'static str,
    },
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
    #[error("emulated CPU stopped at guest RIP {rip:#x}: {instruction}: {reason:?}")]
    Cpu {
        /// Architectural instruction pointer at the stop.
        rip: u64,
        /// Guest instruction and encoding, or an explicit unavailable marker.
        instruction: String,
        /// Original stop reason.
        reason: EventDiagnostic,
    },
    /// A physical operation failed without inventing a guest exception.
    #[error("physical memory operation failed")]
    Memory(#[from] RunError<x86_system::ram_ranges::RangeError>),
    /// Declared RAM could not be adapted.
    #[error("invalid native RAM backing")]
    Ram(#[from] RamError),
    /// Topology and capability metadata were incompatible.
    #[error("partition capabilities")]
    Capabilities(#[from] virt::PartitionCapabilitiesError),
    /// The owned controller rejected an unimplemented device profile.
    #[error("Strudel local APIC stopped: {0:?}")]
    Apic(x86_system::arch::apic::registers::Error),
    /// Failure in an owned VP-local device.
    #[error("Strudel VP-local device at guest RIP {rip:#x}: {reason:#x?}")]
    LocalDevice {
        /// RIP of the unretired instruction.
        rip: u64,
        /// Access and rejection from Strudel.
        reason: strudel::LocalError,
    },
    /// A controller message could not enter its architectural image.
    #[error("owned APIC ingress rejected: {0:?}")]
    ApicIngress(x86_system::arch::apic::Rejection),
}

struct Control {
    irq_routes: virt::irqcon::IrqRoutes,
    #[cfg(test)]
    waiting: AtomicBool,
    has_apic: bool,
    routing: Arc<strudel::LocalRouting>,
    unsupported: AtomicBool,
    remote: VpControl,
    yield_requested: NeedsYield,
}

impl Control {
    fn new(has_apic: bool) -> Self {
        Self {
            irq_routes: Default::default(),
            #[cfg(test)]
            waiting: AtomicBool::new(false),
            has_apic,
            routing: Default::default(),
            unsupported: AtomicBool::new(false),
            remote: VpControl::default(),
            yield_requested: NeedsYield::new(),
        }
    }

    fn unsupported(&self) {
        self.unsupported.store(true, Ordering::Release);
        self.remote.request_attention();
    }

    fn request_apic_msi(&self, request: virt::irqcon::MsiRequest) {
        let (address, data) = request.as_x86();
        if !self.has_apic
            || request.address >> 20 != 0xfee
            || data.delivery_mode() > 1
            || self
                .routing
                .post_msi(
                    &self.remote,
                    address.virt_destination().into(),
                    address.destination_mode_logical(),
                    data.vector(),
                    data.trigger_mode_level(),
                )
                .is_err()
        {
            self.unsupported();
        }
    }
}

struct TimerWake {
    fired: AtomicBool,
    remote: VpControl,
}

impl Wake for TimerWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.fired.store(true, Ordering::Release);
        self.remote.request_attention();
    }
}

/// Long-mode component backend with no native-hypervisor execution dependency.
#[derive(Default)]
pub struct EmuHypervisor;

/// Validated profile awaiting existing backing.
pub struct EmuProtoPartition {
    backend: strudel::Backend,
    caps: Arc<PartitionCapabilities>,
    clock: VmTimeSource,
    architectural_apic: bool,
    svm: x86_system::arch::svm::State,
    apic_id: u32,
    writes: WriteWatch,
}

/// Partition control and bounded external event ingress.
#[derive(Clone)]
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
    timer: Arc<TimerWake>,
    clock_source: VmTimeSource,
    backend: strudel::Backend,
    #[cfg(test)]
    decode_cache_enabled: bool,
    #[cfg(test)]
    boundary_in_batch: bool,
    #[cfg(test)]
    observed: bool,
    apic_id: Option<u32>,
    apic_delivered: [u64; 256],
    first_apic_retired: Option<u64>,
    first_apic_time: Option<u64>,
    first_apic_decode: Option<DecodeDiagnostics>,
    cpu: CpuLifecycle,
    started: bool,
    progress: Option<CompletedBatchProgress>,
    code_preparation: CodePreparationDiagnostics,
    checkpoint: Option<u64>,
    checkpoint_guest: bool,
    svm_exit_checkpoint: Option<(u64, u8)>,
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
    /// Successful returns from the core to the platform (not guest entries).
    pub core_returns: u64,
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
    /// Enables bounded guest-PC sampling for `run_vp_counted`, without changing guest state.
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

    /// Select the strict native executor before the CPU is constructed.
    // xtask-fmt allow-target-arch dependency - the native backend emits host x86-64 code.
    #[cfg(all(feature = "native-jit", target_os = "linux", target_arch = "x86_64"))]
    pub fn enable_native_jit(&mut self) -> Result<(), Error> {
        if !matches!(self.state.cpu, CpuLifecycle::Importing(_)) || self.state.started {
            return Err(Error::AlreadyInitialized);
        }
        self.state.backend = strudel::Backend::Native;
        Ok(())
    }

    /// Native instrumentation counters, not total guest progress after uncounted execution.
    // xtask-fmt allow-target-arch dependency - these counters belong to the host JIT.
    #[cfg(all(feature = "native-jit", target_os = "linux", target_arch = "x86_64"))]
    pub fn native_diagnostics(&self) -> Result<x86_system::execute::native::Diagnostics, Error> {
        let CpuLifecycle::Ready(core) = &self.state.cpu else {
            return Err(Error::Uninitialized);
        };
        Ok(core.native_diagnostics())
    }

    /// IR instrumentation counters. Uncounted fast entries do not contribute
    /// to the normal entry/retirement totals.
    pub fn execution_diagnostics(
        &self,
    ) -> Result<x86_system::execute::compiled::ExecutionDiagnostics, Error> {
        let CpuLifecycle::Ready(core) = &self.state.cpu else {
            return Err(Error::Uninitialized);
        };
        Ok(core.execution_diagnostics())
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
        let registers = match &self.state.cpu {
            CpuLifecycle::Ready(core) => *core.lapic()?,
            CpuLifecycle::Importing(_) => LocalApic::new(self.state.apic_id?, true, 0),
        };
        Some(ApicDiagnostics {
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
        self.state.checkpoint_guest = false;
        Ok(())
    }

    /// Stops at a guest instruction boundary without also stopping the SVM host.
    pub fn set_guest_execution_checkpoint(&mut self, address: Option<u64>) -> Result<(), Error> {
        self.set_execution_checkpoint(address)?;
        self.state.checkpoint_guest = true;
        Ok(())
    }

    /// Pause after VMEXIT for an exit code and in-flight event vector, before host execution.
    pub fn set_svm_exit_checkpoint(&mut self, selector: Option<(u64, u8)>) {
        self.state.svm_exit_checkpoint = selector;
        if let CpuLifecycle::Ready(core) = &mut self.state.cpu {
            core.set_svm_exit_stop(selector);
        }
    }

    /// Whether the requested exit checkpoint, rather than an instruction stop, was reached.
    pub fn svm_exit_checkpoint_reached(&self) -> Result<bool, Error> {
        let CpuLifecycle::Ready(core) = &self.state.cpu else {
            return Err(Error::Uninitialized);
        };
        Ok(core.svm_exit_stopped())
    }

    /// Exact totals are unavailable once the VP has run uncounted. Transport
    /// failures can leave additional, unreported partial progress.
    pub fn completed_batch_progress(&self) -> Option<CompletedBatchProgress> {
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
        self.partition(config, true, true, true)
    }
}

/// The strict native executor used by full OpenVMM on Linux/x86-64.
#[cfg(all(feature = "native-jit", target_os = "linux"))]
pub struct NativeHypervisor;

#[cfg(all(feature = "native-jit", target_os = "linux"))]
impl Hypervisor for NativeHypervisor {
    type ProtoPartition<'a> = EmuProtoPartition;
    type Partition = EmuPartition;
    type Error = Error;

    fn platform_info(&self) -> PlatformInfo {
        PlatformInfo::default()
    }
    fn recognizes_nested_virt(&self) -> bool {
        true
    }
    fn new_partition(
        &mut self,
        config: ProtoPartitionConfig<'_>,
    ) -> Result<EmuProtoPartition, Error> {
        let mut proto = EmuHypervisor.new_partition(config)?;
        proto.backend = strudel::Backend::Native;
        Ok(proto)
    }
}

impl EmuHypervisor {
    /// Constructs the frozen pre-APIC regression fixture, not a production option.
    pub fn new_legacy_fixture<'a>(
        &'a mut self,
        config: ProtoPartitionConfig<'a>,
    ) -> Result<EmuProtoPartition, Error> {
        self.partition(config, false, false, false)
    }

    /// Diagnostic SVM profile without nested paging, optionally also without NRIPS.
    pub fn new_shadow_fixture(
        &mut self,
        config: ProtoPartitionConfig<'_>,
        nrips: bool,
    ) -> Result<EmuProtoPartition, Error> {
        self.partition(config, true, nrips, false)
    }

    fn partition(
        &mut self,
        config: ProtoPartitionConfig<'_>,
        architectural_apic: bool,
        nrips: bool,
        npt: bool,
    ) -> Result<EmuProtoPartition, Error> {
        if config.processor_topology.vps().count() != 1
            || config.hv_config.is_some()
            || (config.nested_virt && !architectural_apic)
            || !matches!(config.isolation, ProtoPartitionIsolation::None)
        {
            return Err(Error::Profile(
                "one VP, no isolation/HV1; basic SVM requires the architectural APIC profile",
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
        let svm = if config.nested_virt {
            x86_system::arch::svm::State {
                nrips,
                npt,
                ..x86_system::arch::svm::BASIC
            }
        } else {
            x86_system::arch::svm::RESET
        };
        let mut caps = PartitionCapabilities::from_cpuid(
            config.processor_topology,
            &mut |function, subleaf| {
                let mut values = x86_system::arch::svm::cpuid(svm, function, subleaf);
                if architectural_apic && function == 1 {
                    values[1] = (values[1] & 0x00ff_ffff) | (apic_id << 24);
                    values[2] |= 1 << 21;
                    values[3] |= 1 << 9;
                }
                values
            },
        )?;
        caps.nested_virt = config.nested_virt;
        Ok(EmuProtoPartition {
            backend: strudel::Backend::Interpreter,
            caps: Arc::new(caps),
            clock: config.vmtime.clone(),
            architectural_apic,
            svm,
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
        let ram = Arc::new(PartitionMemory::for_vp(
            self.writes.tracker(),
            control.remote.clone(),
        ));
        let partition = EmuPartition {
            caps: self.caps.clone(),
            control: control.clone(),
            ram: ram.clone(),
            writes: self.writes.clone(),
        };
        let binder = EmuProcessorBinder {
            clock: self.clock.access("emu-tsc"),
            state: VpState {
                clock_source: self.clock.clone(),
                timer: Arc::new(TimerWake {
                    fired: false.into(),
                    remote: control.remote.clone(),
                }),
                backend: self.backend,
                #[cfg(test)]
                decode_cache_enabled: true,
                #[cfg(test)]
                boundary_in_batch: true,
                #[cfg(test)]
                observed: false,
                apic_id: self.architectural_apic.then_some(self.apic_id),
                apic_delivered: [0; 256],
                first_apic_retired: None,
                first_apic_time: None,
                first_apic_decode: None,
                cpu: CpuLifecycle::Importing(Box::new(SystemState {
                    svm: self.svm,
                    ..SystemState::empty()
                })),
                started: false,
                progress: Some(CompletedBatchProgress::default()),
                code_preparation: CodePreparationDiagnostics::default(),
                #[cfg(feature = "perf")]
                profile: None,
                checkpoint: None,
                checkpoint_guest: false,
                svm_exit_checkpoint: None,
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
    pub(crate) fn is_waiting_for_test(&self) -> bool {
        self.control.waiting.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn write_tracker(&self) -> guestmem::WriteTracker {
        self.writes.tracker()
    }

    /// Captures physical code after revoking CPU writes and excluding DMA writes.
    ///
    /// Every external writer must use this prototype's observed memory backing.
    /// The result is a backing observation, not guest execute authorization;
    /// instruction fetch permissions and current translation remain separate.
    /// This kicks a running VP and waits for its memory lease. Do not call
    /// from inside that lease or while holding the external write-registration gate.
    pub fn capture_code<const N: usize>(
        &self,
        address: u64,
    ) -> Result<Watched<[u8; N]>, CodeCaptureError> {
        self.ram.capture_code(&self.writes, address)
    }

    /// Offers an already-selected vector, not an APIC/PIC arbitration interface.
    pub fn inject_selected(&self, vector: u8) -> Result<(), Error> {
        if self.control.has_apic {
            return Err(Error::Profile(
                "selected-vector ingress bypasses the owned LAPIC",
            ));
        }
        match self.control.remote.post_selected(vector) {
            Injection::Queued => Ok(()),
            Injection::Busy => Err(Error::InterruptBusy),
            Injection::InvalidVector => Err(Error::InterruptVector),
            other => Err(Error::Injection(other)),
        }
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

impl virt::PartitionMemoryMapper for EmuPartition {
    fn memory_mapper(&self, vtl: Vtl) -> Arc<dyn PartitionMemoryMap> {
        assert_eq!(vtl, Vtl::Vtl0);
        Arc::new(self.clone())
    }
}

impl virt::irqcon::IoApicRouting for Control {
    fn set_irq_route(&self, irq: u8, request: Option<virt::irqcon::MsiRequest>) {
        self.irq_routes.set_irq_route(irq, request);
    }
    fn assert_irq(&self, irq: u8) {
        self.irq_routes
            .assert_irq(irq, |request| self.request_apic_msi(request));
    }
}

impl virt::X86Partition for EmuPartition {
    fn ioapic_routing(&self) -> Arc<dyn virt::irqcon::IoApicRouting> {
        self.control.clone()
    }
    fn pulse_lint(&self, vp: VpIndex, vtl: Vtl, lint: u8) {
        if vp != VpIndex::BSP || vtl != Vtl::Vtl0 || lint > 1 {
            self.control.unsupported();
            return;
        }
        if self
            .control
            .routing
            .pulse_lint(&self.control.remote, lint)
            .is_err()
        {
            self.control.unsupported();
        }
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
            self.control.unsupported();
        }
    }
    fn caps(&self) -> &PartitionCapabilities {
        &self.caps
    }
    fn request_yield(&self, vp_index: VpIndex) {
        if vp_index.index() != 0 {
            self.control.unsupported.store(true, Ordering::Release);
        }
        if self.control.yield_requested.request_yield() {
            self.control.remote.request_yield();
        }
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

#[cfg(test)]
impl EmuProcessorBinder {
    pub(crate) fn set_observed_for_test(&mut self, observed: bool) {
        self.state.observed = observed;
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

impl EmuProcessor<'_> {
    /// Run the same VP loop with exact retirement and event accounting.
    pub async fn run_vp_counted(
        &mut self,
        stop: StopVp<'_>,
        dev: &impl CpuIo,
    ) -> Result<Infallible, VpHaltReason> {
        self.run_vp_inner::<true>(stop, dev).await
    }

    async fn run_vp_inner<const COUNTED: bool>(
        &mut self,
        stop: StopVp<'_>,
        dev: &impl CpuIo,
    ) -> Result<Infallible, VpHaltReason> {
        #[cfg(test)]
        let mut stop = stop;
        if self.state.io_active {
            return Err(dev.fatal_error(Box::new(Error::CancelledIo)));
        }
        if COUNTED && self.state.progress.is_none() {
            return Err(dev.fatal_error(Box::new(Error::Profile("incomplete counted VP history"))));
        }
        if !COUNTED {
            #[cfg(feature = "perf")]
            if self.state.profile.is_some() {
                return Err(dev.fatal_error(Box::new(Error::Profile(
                    "guest-PC profiling requires counted execution",
                ))));
            }
            self.state.progress = None;
        }
        self.state.started = true;
        #[cfg(test)]
        let mut observed_batches = 0u8;
        loop {
            stop.check()?;
            if self.control.unsupported.load(Ordering::Acquire) {
                return Err(dev.fatal_error(Box::new(Error::UnsupportedInterrupt)));
            }
            let checkpoint = self.state.checkpoint;
            let checkpoint_guest = self.state.checkpoint_guest;
            if let Some(error) = self.state.fault.take() {
                return Err(dev.fatal_error(Box::new(error)));
            }
            let CpuLifecycle::Ready(core) = &mut self.state.cpu else {
                return Err(dev.fatal_error(Box::new(Error::Uninitialized)));
            };
            if core.svm_exit_stopped() {
                return Err(dev.fatal_error(Box::new(Error::Checkpoint {
                    rip: core.cpu().rip,
                })));
            }
            if self.state.timer.fired.swap(false, Ordering::AcqRel) {
                core.expire_timers().map_err(|reason| {
                    dev.fatal_error(Box::new(Error::LocalDevice {
                        rip: core.cpu().rip,
                        reason,
                    }))
                })?;
                timer::arm(core.next_timer(), self.clock, &self.state.timer, true);
            }
            self.control.yield_requested.maybe_yield().await;
            stop.check()?;
            if core.at_instruction_boundary()
                && checkpoint == Some(core.cpu().rip)
                && (!checkpoint_guest || core.guest_mode())
            {
                return Err(dev.fatal_error(Box::new(Error::Checkpoint {
                    rip: core.cpu().rip,
                })));
            }
            if checkpoint_guest {
                core.set_guest_entry_stop(checkpoint);
            } else {
                core.set_entry_stop(checkpoint);
            }
            let result = {
                let access = self.ram.access();
                let ram = access.ram();
                let is_mmio = |address: u64, width: u8| {
                    (0..u64::from(width)).all(|offset| {
                        !self.ram_ranges.iter().any(|range| {
                            address + offset >= range.start() && address + offset < range.end()
                        })
                    })
                };
                let is_ram_page = |base: u64| {
                    base.checked_add(4096).is_some_and(|end| {
                        self.ram_ranges
                            .iter()
                            .any(|range| range.start() <= base && end <= range.end())
                    })
                };
                let counted =
                    |batch: strudel::Batch| (batch.stop, Some((batch.retired, batch.delivered)));
                if !COUNTED {
                    // SAFETY: this read lease pins mappings and code watches.
                    // Writers rotate the epoch under the exclusive lease. The
                    // partition's RAM classification is immutable for its lifetime.
                    #[allow(unsafe_code)]
                    let lease = unsafe {
                        strudel::BindingLease::new(&ram, access.binding_epoch(), &is_ram_page)
                    };
                    core.run_fast_uncounted_with_binding_lease(&lease, is_mmio)
                        .map(|stop| (stop, None))
                } else {
                    #[cfg(test)]
                    if self.state.observed {
                        core.run(
                            &ram,
                            strudel::RunBudget {
                                memory_effects: 64,
                                steps: 64,
                            },
                            is_mmio,
                            |boundary| {
                                !self.state.boundary_in_batch
                                    || boundary.last_lapic_delivery().is_some()
                                    || (boundary.at_instruction_boundary()
                                        && checkpoint == Some(boundary.cpu().rip)
                                        && (!checkpoint_guest || boundary.guest_mode()))
                            },
                        )
                        .map(counted)
                    } else {
                        core.run_fast_with_ram_pages(&ram, is_mmio, is_ram_page)
                            .map(counted)
                    }
                    #[cfg(not(test))]
                    core.run_fast_with_ram_pages(&ram, is_mmio, is_ram_page)
                        .map(counted)
                }
            };
            let (batch_stop, counts) = match result {
                Ok(batch) => batch,
                Err(RunError::DecodeCompletion(_)) => {
                    return Err(dev.fatal_error(Box::new(Error::DecodeCompletion)));
                }
                Err(RunError::NativeCompilation(reason)) => {
                    return Err(dev.fatal_error(Box::new(Error::NativeCompilation {
                        rip: core.cpu().rip,
                        instruction: core
                            .describe_instruction(&self.ram.access().ram())
                            .unwrap_or_else(|| "instruction bytes unavailable".into()),
                        reason,
                    })));
                }
                Err(error) => return Err(dev.fatal_error(Box::new(Error::Memory(error)))),
            };
            if let Some((retired, delivered)) = counts {
                let progress = self.state.progress.as_mut().expect("counted VP history");
                let Some(retired) = progress.retired.checked_add(retired) else {
                    return Err(dev.fatal_error(Box::new(Error::ProgressExhausted)));
                };
                let Some(delivered) = progress.delivered.checked_add(delivered) else {
                    return Err(dev.fatal_error(Box::new(Error::ProgressExhausted)));
                };
                *progress = CompletedBatchProgress {
                    core_returns: progress.core_returns.wrapping_add(1),
                    retired,
                    delivered,
                };
            }
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
            if COUNTED
                && let (Some(profile), Some(progress)) =
                    (&mut self.state.profile, self.state.progress)
            {
                profile.record(progress.retired, progress.delivered, || core.cpu().rip);
            }
            #[cfg(test)]
            if COUNTED && self.state.observed {
                observed_batches += 1;
                if observed_batches == 64 {
                    self.control.yield_requested.request_yield();
                    observed_batches = 0;
                }
            }
            if let Some(vector) = core.last_lapic_delivery() {
                let slot = &mut self.state.apic_delivered[usize::from(vector)];
                let Some(count) = slot.checked_add(1) else {
                    return Err(dev.fatal_error(Box::new(Error::ProgressExhausted)));
                };
                *slot = count;
                if self.state.first_apic_time.is_none() {
                    self.state.first_apic_retired = self.state.progress.map(|p| p.retired);
                    self.state.first_apic_time = Some(self.clock.now().as_100ns());
                    self.state.first_apic_decode = Some(core.decode_diagnostics());
                }
            }
            match batch_stop {
                BatchStop::TimerChanged(next) => {
                    timer::arm(next, self.clock, &self.state.timer, false)
                }
                BatchStop::Eoi(vector) => {
                    dev.handle_eoi(vector.into());
                    timer::arm(core.next_timer(), self.clock, &self.state.timer, false);
                }
                BatchStop::LocalError(reason) => {
                    return Err(dev.fatal_error(Box::new(Error::LocalDevice {
                        rip: core.cpu().rip,
                        reason,
                    })));
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
                    #[cfg(test)]
                    if COUNTED && self.state.observed {
                        stop.until_stop(std::future::poll_fn(|cx| {
                            self.control.remote.poll_wake(cx)
                        }))
                        .await?;
                        continue;
                    }
                    #[cfg(test)]
                    self.control.waiting.store(true, Ordering::Release);
                    self.control.remote.wait_for_wake();
                    #[cfg(test)]
                    self.control.waiting.store(false, Ordering::Release);
                }
                BatchStop::Stopped(reason) => {
                    return Err(dev.fatal_error(Box::new(Error::Cpu {
                        rip: core.cpu().rip,
                        instruction: core
                            .describe_instruction(&self.ram.access().ram())
                            .unwrap_or_else(|| "instruction bytes unavailable".into()),
                        reason,
                    })));
                }
            }
        }
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
        stop: StopVp<'_>,
        dev: &impl CpuIo,
    ) -> Result<Infallible, VpHaltReason> {
        self.run_vp_inner::<false>(stop, dev).await
    }

    fn flush_async_requests(&mut self) {
        if let CpuLifecycle::Ready(core) = &mut self.state.cpu {
            if let Err(error) = core.flush_vp_control() {
                self.state.fault = Some(Error::ApicIngress(error));
            }
        }
    }

    fn access_state(&mut self, vtl: Vtl) -> EmuStateAccess<'_> {
        EmuStateAccess {
            state: self.state,
            control: &self.control,
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
    control: &'a Control,
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
    regs.efer =
        x86_system::arch::svm::read_efer(regs.efer | u64::from(system.efer_sce), system.svm);
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

impl virt::PartitionAccessState for EmuPartition {
    type StateAccess<'a> = &'a Self;
    fn access_state(&self, vtl: Vtl) -> Self::StateAccess<'_> {
        assert_eq!(vtl, Vtl::Vtl0);
        self
    }
}

impl virt::vm::AccessVmState for &EmuPartition {
    type Error = Error;
    fn caps(&self) -> &PartitionCapabilities {
        &self.caps
    }
    fn commit(&mut self) -> Result<(), Error> {
        Ok(())
    }
    unsupported_state! {
        (hypercall, set_hypercall, virt::vm::HypercallMsrs),
        (reference_tsc_page, set_reference_tsc_page, virt::vm::ReferenceTscPage),
        (reftime, set_reftime, virt::vm::ReferenceTime),
    }
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
        let state = core.state();
        let mut registers = with_system(
            long_mode_registers(state.registers, state.config, state.tables, state.cr2),
            state.system,
        );
        if let Some(apic) = core.lapic() {
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
        if self.state.apic_id.is_some() {
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
        let mut core = Machine::new_with_backend(
            CpuState {
                registers: cpu,
                config,
                cr2: regs.cr2,
                tables,
                system,
            },
            self.state.backend,
        )?;
        core.set_svm_exit_stop(self.state.svm_exit_checkpoint);
        core.set_vp_control(self.control.remote.clone());
        #[cfg(test)]
        core.set_test_options(strudel::TestOptions {
            cache: self.state.decode_cache_enabled,
        });
        let clock = self.state.clock_source.access("strudel-vp-clock");
        core.set_vm_clock(move || clock.now().as_100ns());
        if let Some(id) = self.state.apic_id {
            if !core.configure_apic(id) {
                return Err(Error::Profile("initial APIC metadata"));
            }
            core.set_cr8(regs.cr8).map_err(Error::Apic)?;
            core.set_local_routing(self.control.routing.clone());
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
