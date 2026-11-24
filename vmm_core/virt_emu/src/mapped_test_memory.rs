// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::native_memory::PartitionMemory;
use guestmem::{AlignedHeapMemory, GuestMemory, GuestMemoryAccess, WriteTracker};
use std::ptr::NonNull;
use std::sync::Arc;
use virt::PartitionMemoryMap;

struct ObservedAllocation {
    allocation: Arc<AlignedHeapMemory>,
    tracker: WriteTracker,
}

// SAFETY: the shared allocation remains stable for the backing's lifetime.
// UNSAFETY: Exposes the fixture-owned mapping for guarded GuestMemory operations.
#[expect(unsafe_code)]
unsafe impl GuestMemoryAccess for ObservedAllocation {
    fn mapping(&self) -> Option<NonNull<u8>> {
        self.allocation.mapping()
    }

    fn max_address(&self) -> u64 {
        self.allocation.len() as u64
    }

    fn write_tracker(&self) -> Option<WriteTracker> {
        Some(self.tracker.clone())
    }
}

/// Keeps direct CPU backing alive until synchronous unmap has drained its users.
pub(crate) struct MappedTestMemory<M: PartitionMemoryMap> {
    map: Arc<M>,
    memory: GuestMemory,
    size: u64,
}

impl<M: PartitionMemoryMap> MappedTestMemory<M> {
    pub fn new(map: Arc<M>, bytes: &[u8]) -> Self {
        Self::build(map, bytes, None)
    }

    pub fn observed(map: Arc<M>, bytes: &[u8], tracker: WriteTracker) -> Self {
        Self::build(map, bytes, Some(tracker))
    }

    fn build(map: Arc<M>, bytes: &[u8], tracker: Option<WriteTracker>) -> Self {
        let mut allocation = AlignedHeapMemory::new(bytes.len());
        allocation.as_mut_bytes()[..bytes.len()].copy_from_slice(bytes);
        let size = allocation.len();
        let allocation = Arc::new(allocation);
        let data = allocation.mapping().unwrap().as_ptr();
        let memory = match tracker {
            Some(tracker) => GuestMemory::new(
                "observed-test-memory",
                ObservedAllocation {
                    allocation,
                    tracker,
                },
            ),
            None => GuestMemory::new("mapped-test-memory", allocation),
        };
        let fixture = Self {
            map,
            memory,
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

impl MappedTestMemory<PartitionMemory> {
    pub fn fixture(bytes: &[u8]) -> Self {
        Self::new(Arc::new(PartitionMemory::new()), bytes)
    }
    pub fn access(&self) -> crate::native_memory::NativeAccess<'_> {
        self.map.access()
    }
    /// Retry tests can omit part of the same backing for exactly one run,
    /// without a mock provider or making a host page inaccessible.
    pub fn with_hole<T>(
        &self,
        hole: std::ops::Range<u64>,
        run: impl FnOnce(&crate::native_memory::NativeAccess<'_>) -> T,
    ) -> T {
        assert!(hole.start < hole.end && hole.end <= self.size);
        let (ptr, _) = self.memory.full_mapping().unwrap();
        let partial = PartitionMemory::new();
        for range in [0..hole.start, hole.end..self.size] {
            if !range.is_empty() {
                // SAFETY: the fixture owns this populated extent throughout
                // the callback and until the temporary mapping table drops.
                // UNSAFETY: installs a subrange of the fixture-owned backing.
                #[expect(unsafe_code)]
                unsafe {
                    partial.map_range(
                        ptr.add(range.start as usize).cast(),
                        (range.end - range.start) as usize,
                        range.start,
                        true,
                        true,
                    )
                }
                .unwrap();
            }
        }
        run(&partial.access())
    }
}
