// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::native_memory::{PartitionMemory, RamError};
use guestmem::{AlignedHeapMemory, GuestMemory, GuestMemoryAccess};
use std::sync::Arc;
use virt::PartitionMemoryMap;
use x86_system::memory::physical::{AtomicOperation, AtomicResult, CopyError, PhysicalRam};

/// Keeps direct CPU backing alive until synchronous unmap has drained its users.
pub(crate) struct MappedTestMemory<M: PartitionMemoryMap> {
    map: Arc<M>,
    memory: GuestMemory,
    size: u64,
}

impl<M: PartitionMemoryMap> MappedTestMemory<M> {
    pub fn new(map: Arc<M>, bytes: &[u8]) -> Self {
        let mut allocation = AlignedHeapMemory::new(bytes.len());
        allocation.as_mut_bytes()[..bytes.len()].copy_from_slice(bytes);
        let size = allocation.len();
        let allocation = Arc::new(allocation);
        let data = allocation.mapping().unwrap().as_ptr();
        let fixture = Self {
            map,
            memory: GuestMemory::new("mapped-test-memory", allocation),
            size: size as u64,
        };
        // SAFETY: GuestMemory retains this stable shared allocation until after
        // Drop synchronously unmaps it, including any outstanding CPU leases.
        // UNSAFETY: Installs the fixture-owned backing in the partition map.
        #[expect(unsafe_code)]
        unsafe {
            fixture.map.map_range(data, size, 0, true, true).unwrap();
        }
        fixture
    }

    pub fn guest_memory(&self) -> GuestMemory {
        self.memory.clone()
    }
}

impl<M: PartitionMemoryMap> std::ops::Deref for MappedTestMemory<M> {
    type Target = GuestMemory;

    fn deref(&self) -> &Self::Target {
        &self.memory
    }
}

impl<M: PartitionMemoryMap> Drop for MappedTestMemory<M> {
    fn drop(&mut self) {
        self.map.unmap_range(0, self.size).unwrap();
    }
}

/// Test-only convenience adapter; production leases once per synchronous batch.
#[derive(Clone)]
pub(crate) struct TestRam(Arc<MappedTestMemory<PartitionMemory>>);

impl TestRam {
    pub fn new(bytes: &[u8]) -> Self {
        Self(Arc::new(MappedTestMemory::new(
            Arc::new(PartitionMemory::new()),
            bytes,
        )))
    }

    pub fn guest_memory(&self) -> GuestMemory {
        self.0.guest_memory()
    }
}

impl PhysicalRam for TestRam {
    type Error = RamError;

    fn read<const N: usize>(&self, address: u64) -> Result<[u8; N], Self::Error> {
        self.0.map.access().ram().read(address)
    }

    fn write<const N: usize>(&self, address: u64, value: [u8; N]) -> Result<(), Self::Error> {
        self.0.map.access().ram().write(address, value)
    }

    fn read_bytes(
        &self,
        address: u64,
        destination: &mut [u8],
    ) -> Result<(), CopyError<Self::Error>> {
        self.0.map.access().ram().read_bytes(address, destination)
    }

    fn write_bytes(&self, address: u64, source: &[u8]) -> Result<(), CopyError<Self::Error>> {
        self.0.map.access().ram().write_bytes(address, source)
    }

    fn atomic(
        &self,
        address: u64,
        width: u8,
        operation: AtomicOperation,
    ) -> Result<AtomicResult, CopyError<Self::Error>> {
        self.0.map.access().ram().atomic(address, width, operation)
    }

    fn barrier(&self) {
        self.0.map.access().ram().barrier();
    }
}
