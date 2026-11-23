// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod gic_software_device;
pub mod gic_v2m;
pub mod vm;
pub mod vp;

use crate::IsolationType;
use crate::state::StateElement;
use aarch64defs::Vendor;
use inspect::Inspect;
use mesh_protobuf::Protobuf;
use thiserror::Error;
use vm_topology::processor::aarch64::Aarch64VpInfo;

/// VP state that can be set for initial boot.
#[derive(Debug, PartialEq, Eq, Protobuf)]
pub struct Aarch64InitialRegs {
    /// Register state to be set on the BSP.
    pub registers: vp::Registers,
    /// System register state for the BSP.
    pub system_registers: vp::SystemRegisters,
}

impl Aarch64InitialRegs {
    pub fn at_reset(caps: &Aarch64PartitionCapabilities, bsp: &Aarch64VpInfo) -> Self {
        Self {
            registers: vp::Registers::at_reset(caps, bsp),
            system_registers: vp::SystemRegisters::at_reset(caps, bsp),
        }
    }
}

#[derive(Debug, Inspect)]
pub struct Aarch64PartitionCapabilities {
    /// Isolation type for the partition.
    pub isolation: IsolationType,
    /// Whether the processor supports aarch32 execution at EL0.
    pub supports_aarch32_el0: bool,
    #[inspect(display)]
    pub vendor: Vendor,
}

#[derive(Error, Debug)]
pub enum Aarch64PartitionCapabilitiesError {}

/// Versioned native execution state, separate from guest construction facts.
#[derive(PartialEq, Eq, mesh_protobuf::Protobuf)]
#[mesh(package = "virt.aarch64")]
pub struct BackendExecutionState {
    #[mesh(1)]
    pub format: String,
    #[mesh(2)]
    pub data: Vec<u8>,
}

impl std::fmt::Debug for BackendExecutionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendExecutionState")
            .field("format", &self.format)
            .field("bytes", &self.data.len())
            .finish()
    }
}
