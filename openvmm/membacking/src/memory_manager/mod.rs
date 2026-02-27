// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenVMM's top-level memory manager.
//!
//! [`GuestMemoryManager`] is the entry point for all guest RAM and device
//! memory management. It is responsible for:
//!
//! - **Allocating guest RAM** — either as a shared file-backed section
//!   (`CreateFileMappingW` / `memfd_create`) or as private anonymous memory
//!   (`VirtualAlloc` / `mmap MAP_ANONYMOUS`) depending on configuration.
//! - **Coordinating the internal pipeline**: region manager → mapping
//!   manager → VA mappers → partition mappers.
//! - **Providing access handles**: [`GuestMemoryClient`] gives callers a
//!   [`GuestMemory`] object backed by a `VaMapper`, and
//!   [`DeviceMemoryMapper`] lets devices map VRAM / ROM regions into guest
//!   address space.
//!
//! # Construction via [`GuestMemoryBuilder`]
//!
//! The builder offers several mutually exclusive modes:
//!
//! - **Default (file-backed)**: `alloc_shared_memory()` creates a page-file-
//!   backed section sized to hold all RAM. Each RAM range becomes a region
//!   with a single mapping into this section.
//! - **Existing backing**: An already-allocated `Mappable` is reused (for
//!   servicing / live migration).
//! - **Private memory**: No shared section is created. RAM regions have no
//!   file-backed mapping; instead `VaMapper::alloc_range()` eagerly commits
//!   anonymous pages in the `SparseMapping`. This eliminates page-file
//!   pressure on Windows and enables decommit.
//!
//! # Partition attachment
//!
//! Once built, `attach_partition()` creates a [`PartitionMapper`] that maps
//! the VA mapper's address range into the hypervisor partition's GPA space.
//! On Windows, a separate remote-process VA mapper can be created to work
//! around WHP's limitation of mapping a single VA range to a single
//! partition.

mod device_memory;

pub use device_memory::DeviceMemoryMapper;

use crate::RemoteProcess;
use crate::mapping_manager::Mappable;
use crate::mapping_manager::MappingManager;
use crate::mapping_manager::MappingManagerClient;
use crate::mapping_manager::VaMapper;
use crate::mapping_manager::VaMapperError;
use crate::partition_mapper::PartitionMapper;
use crate::region_manager::MapParams;
use crate::region_manager::RegionHandle;
use crate::region_manager::RegionManager;
use guestmem::GuestMemory;
use hvdef::Vtl;
use inspect::Inspect;
use memory_range::MemoryRange;
use mesh::MeshPayload;
use pal_async::DefaultPool;
use std::sync::Arc;
use std::thread::JoinHandle;
use thiserror::Error;
use vm_topology::memory::MemoryLayout;

/// The top-level memory manager for an OpenVMM VM instance.
///
/// Owns all the infrastructure for guest memory: the shared RAM allocation
/// (if any), the region manager, the mapping manager, the primary
/// `VaMapper`, and the background thread that drives them. Created via
/// [`GuestMemoryBuilder::build()`].
///
/// After construction, call [`attach_partition()`](Self::attach_partition)
/// to wire the VA mapper into a hypervisor partition's GPA space.
#[derive(Debug, Inspect)]
pub struct GuestMemoryManager {
    /// Guest RAM allocation (file-backed section). `None` in private memory
    /// mode, where RAM is backed by anonymous pages in the `VaMapper`'s
    /// `SparseMapping` instead.
    #[inspect(skip)]
    guest_ram: Option<Mappable>,

    /// RAM regions, in GPA order. Used by `RamVisibilityControl` to
    /// manipulate individual RAM sub-ranges (e.g., VGA window, PAM regions).
    #[inspect(skip)]
    ram_regions: Arc<Vec<RamRegion>>,

    #[inspect(flatten)]
    mapping_manager: MappingManager,

    #[inspect(flatten)]
    region_manager: RegionManager,

    /// The primary VA mapper for this process. Shared by all callers of
    /// `client().guest_memory()` (deduplicated via the mapper cache).
    #[inspect(skip)]
    va_mapper: Arc<VaMapper>,

    /// Background thread running the memory manager's async event loop.
    #[inspect(skip)]
    _thread: JoinHandle<()>,

    /// Offset for the VTL0 alias map, if enabled.
    vtl0_alias_map_offset: Option<u64>,
    /// Whether to pin all mapped ranges (for device assignment / IOMMU).
    pin_mappings: bool,
}

#[derive(Debug)]
struct RamRegion {
    range: MemoryRange,
    handle: RegionHandle,
}

/// Errors when attaching a partition to a [`GuestMemoryManager`].
#[derive(Error, Debug)]
pub enum PartitionAttachError {
    /// Failure to allocate a VA mapper.
    #[error("failed to reserve VA range for partition mapping")]
    VaMapper(#[source] VaMapperError),
    /// Failure to map memory into a partition.
    #[error("failed to attach partition to memory manager")]
    PartitionMapper(#[source] crate::partition_mapper::PartitionMapperError),
}

/// Errors creating a [`GuestMemoryManager`].
#[derive(Error, Debug)]
pub enum MemoryBuildError {
    /// RAM too large.
    #[error("ram size {0} is too large")]
    RamTooLarge(u64),
    /// Couldn't allocate RAM.
    #[error("failed to allocate memory")]
    AllocationFailed(#[source] std::io::Error),
    /// Couldn't allocate VA mapper.
    #[error("failed to create VA mapper")]
    VaMapper(#[source] VaMapperError),
    /// Memory layout incompatible with VTL0 alias map.
    #[error("not enough guest address space available for the vtl0 alias map")]
    AliasMapWontFit,
    /// Memory layout incompatible with x86 legacy support.
    #[error("x86 support requires RAM to start at 0 and contain at least 1MB")]
    InvalidRamForX86,
    /// Private memory is incompatible with x86 legacy support.
    #[error("private memory is incompatible with x86 legacy support")]
    PrivateMemoryWithLegacy,
    /// Private memory is incompatible with existing memory backing.
    #[error("private memory is incompatible with existing memory backing")]
    PrivateMemoryWithExistingBacking,
    /// Failed to allocate private RAM range.
    #[error("failed to allocate private RAM range")]
    PrivateRamAlloc(#[source] std::io::Error),
}

/// A builder for [`GuestMemoryManager`].
///
/// Configures RAM allocation strategy, VTL aliasing, page pinning, and
/// platform-specific legacy support before constructing the full memory
/// management pipeline. See the module documentation for the
/// supported modes (file-backed vs. private vs. existing backing).
pub struct GuestMemoryBuilder {
    existing_mapping: Option<SharedMemoryBacking>,
    vtl0_alias_map: Option<u64>,
    prefetch_ram: bool,
    pin_mappings: bool,
    x86_legacy_support: bool,
    private_memory: bool,
}

impl GuestMemoryBuilder {
    /// Returns a new builder.
    pub fn new() -> Self {
        Self {
            existing_mapping: None,
            vtl0_alias_map: None,
            pin_mappings: false,
            prefetch_ram: false,
            x86_legacy_support: false,
            private_memory: false,
        }
    }

    /// Specifies an existing memory backing to use.
    pub fn existing_backing(mut self, mapping: Option<SharedMemoryBacking>) -> Self {
        self.existing_mapping = mapping;
        self
    }

    /// Specifies the offset of the VTL0 alias map, if enabled for VTL2. This is
    /// a mirror of VTL0 memory into a high portion of the VM's physical address
    /// space.
    pub fn vtl0_alias_map(mut self, offset: Option<u64>) -> Self {
        self.vtl0_alias_map = offset;
        self
    }

    /// Specify whether to pin mappings in memory. This is used to support
    /// device assignment for devices that require the IOMMU to be programmed
    /// for all addresses.
    pub fn pin_mappings(mut self, enable: bool) -> Self {
        self.pin_mappings = enable;
        self
    }

    /// Specify whether to prefetch RAM mappings. This improves boot performance
    /// by reducing memory intercepts at the cost of pre-allocating all of RAM.
    pub fn prefetch_ram(mut self, enable: bool) -> Self {
        self.prefetch_ram = enable;
        self
    }

    /// Enables legacy x86 support.
    ///
    /// When set, create separate RAM regions for the various low memory ranges
    /// that are special on x86 platforms. Specifically:
    ///
    /// 1. Create a separate RAM region for the VGA VRAM window:
    ///    0xa0000-0xbffff.
    /// 2. Create separate RAM regions within 0xc0000-0xfffff for control by PAM
    ///    registers.
    ///
    /// The caller can use [`RamVisibilityControl`] to adjust the visibility of
    /// these ranges.
    pub fn x86_legacy_support(mut self, enable: bool) -> Self {
        self.x86_legacy_support = enable;
        self
    }

    /// Enables private anonymous memory for guest RAM.
    ///
    /// When set, guest RAM is backed by anonymous pages (`mmap
    /// MAP_ANONYMOUS` on Linux, `VirtualAlloc` on Windows) rather than
    /// shared file-backed sections. This supports decommit to release
    /// physical pages back to the host.
    ///
    /// This is incompatible with [`x86_legacy_support`](Self::x86_legacy_support)
    /// and [`existing_backing`](Self::existing_backing).
    pub fn private_memory(mut self, enable: bool) -> Self {
        self.private_memory = enable;
        self
    }

    /// Builds the memory backing, allocating memory if existing memory was not
    /// provided by [`existing_backing`](Self::existing_backing).
    pub async fn build(
        self,
        mem_layout: &MemoryLayout,
    ) -> Result<GuestMemoryManager, MemoryBuildError> {
        // Validate private memory constraints.
        if self.private_memory {
            if self.x86_legacy_support {
                return Err(MemoryBuildError::PrivateMemoryWithLegacy);
            }
            if self.existing_mapping.is_some() {
                return Err(MemoryBuildError::PrivateMemoryWithExistingBacking);
            }
        }

        let ram_size = mem_layout.ram_size() + mem_layout.vtl2_range().map_or(0, |r| r.len());

        let memory: Option<Mappable> = if self.private_memory {
            // Private memory mode: no shared file-backed allocation.
            // RAM will be backed by anonymous pages in the VaMapper's SparseMapping.
            None
        } else if let Some(memory) = self.existing_mapping {
            Some(memory.guest_ram)
        } else {
            Some(
                sparse_mmap::alloc_shared_memory(
                    ram_size
                        .try_into()
                        .map_err(|_| MemoryBuildError::RamTooLarge(ram_size))?,
                )
                .map_err(MemoryBuildError::AllocationFailed)?
                .into(),
            )
        };

        // Spawn a thread to handle memory requests.
        //
        // FUTURE: move this to a task once the GuestMemory deadlocks are resolved.
        let (thread, spawner) = DefaultPool::spawn_on_thread("memory_manager");

        let max_addr =
            (mem_layout.end_of_ram_or_mmio()).max(mem_layout.vtl2_range().map_or(0, |r| r.end()));

        let vtl0_alias_map_offset = if let Some(offset) = self.vtl0_alias_map {
            if max_addr > offset {
                return Err(MemoryBuildError::AliasMapWontFit);
            }
            Some(offset)
        } else {
            None
        };

        let mapping_manager = MappingManager::new(&spawner, max_addr);
        let va_mapper = if self.private_memory {
            mapping_manager
                .client()
                .new_private_mapper()
                .await
                .map_err(MemoryBuildError::VaMapper)?
        } else {
            mapping_manager
                .client()
                .new_mapper()
                .await
                .map_err(MemoryBuildError::VaMapper)?
        };

        let region_manager = RegionManager::new(&spawner, mapping_manager.client().clone());

        let mut ram_ranges = mem_layout
            .ram()
            .iter()
            .map(|x| x.range)
            .chain(mem_layout.vtl2_range())
            .collect::<Vec<_>>();

        if self.x86_legacy_support {
            if ram_ranges[0].start() != 0 || ram_ranges[0].end() < 0x100000 {
                return Err(MemoryBuildError::InvalidRamForX86);
            }

            // Split RAM ranges to support PAM registers and VGA RAM.
            let range_starts = [
                0,
                0xa0000,
                0xc0000,
                0xc4000,
                0xc8000,
                0xcc000,
                0xd0000,
                0xd4000,
                0xd8000,
                0xdc000,
                0xe0000,
                0xe4000,
                0xe8000,
                0xec000,
                0xf0000,
                0x100000,
                ram_ranges[0].end(),
            ];

            ram_ranges.splice(
                0..1,
                range_starts
                    .iter()
                    .zip(range_starts.iter().skip(1))
                    .map(|(&start, &end)| MemoryRange::new(start..end)),
            );
        }

        // In private memory mode, eagerly commit all RAM ranges with
        // anonymous memory. alloc_range() handles both Linux (mmap MAP_FIXED)
        // and Windows (MEM_REPLACE_PLACEHOLDER).
        if self.private_memory {
            for range in &ram_ranges {
                va_mapper
                    .alloc_range(range.start() as usize, range.len() as usize)
                    .map_err(MemoryBuildError::PrivateRamAlloc)?;
            }
        }

        let mut ram_regions = Vec::new();
        let mut start = 0;
        for range in &ram_ranges {
            let region = region_manager
                .client()
                .new_region("ram".into(), *range, RAM_PRIORITY)
                .await
                .expect("regions cannot overlap yet");

            if let Some(ref memory) = memory {
                // File-backed mode: add mapping for this RAM range.
                region
                    .add_mapping(
                        MemoryRange::new(0..range.len()),
                        memory.clone(),
                        start,
                        true,
                    )
                    .await;
            }
            // In private_memory mode, skip add_mapping — no file-backed RAM.
            // The SparseMapping VA is already committed via alloc_range() above.

            region
                .map(MapParams {
                    writable: true,
                    executable: true,
                    prefetch: self.prefetch_ram && !self.private_memory,
                })
                .await;

            ram_regions.push(RamRegion {
                range: *range,
                handle: region,
            });
            start += range.len();
        }

        let gm = GuestMemoryManager {
            guest_ram: memory,
            _thread: thread,
            ram_regions: Arc::new(ram_regions),
            mapping_manager,
            region_manager,
            va_mapper,
            vtl0_alias_map_offset,
            pin_mappings: self.pin_mappings,
        };
        Ok(gm)
    }
}

/// The transferable backing objects used to recreate guest memory across
/// processes (e.g., during VM servicing or live migration).
///
/// Contains the file-backed `Mappable` for guest RAM. Not available in
/// private-memory mode — calling
/// [`GuestMemoryManager::shared_memory_backing()`] will panic if no
/// shared backing exists.
#[derive(Debug, MeshPayload)]
pub struct SharedMemoryBacking {
    guest_ram: Mappable,
}

/// A mesh-serializable client for obtaining [`GuestMemory`] handles.
///
/// Can be sent across mesh channels to remote processes. Each call to
/// [`guest_memory()`](Self::guest_memory) is deduplicated via the
/// per-process `MAPPER_CACHE`, ensuring only one `VaMapper` (and thus
/// one `SparseMapping`) is allocated per process, regardless of how many
/// callers request access.
#[derive(Debug, MeshPayload)]
pub struct GuestMemoryClient {
    mapping_manager: MappingManagerClient,
}

impl GuestMemoryClient {
    /// Retrieves a [`GuestMemory`] object to access guest memory from this
    /// process.
    ///
    /// This call will ensure only one VA mapper is allocated per process, so
    /// this is safe to call many times without allocating tons of virtual
    /// address space.
    pub async fn guest_memory(&self) -> Result<GuestMemory, VaMapperError> {
        Ok(GuestMemory::new(
            "ram",
            self.mapping_manager.new_mapper().await?,
        ))
    }
}

/// Region priority for RAM. This is the highest priority, so RAM always
/// shadows overlapping device memory unless explicitly unmapped via
/// `RamVisibilityControl`.
const RAM_PRIORITY: u8 = 255;

/// Region priority for device memory. Lower than RAM, so device MMIO /
/// VRAM regions only become guest-visible in address ranges not covered
/// by an active RAM region.
const DEVICE_PRIORITY: u8 = 0;

impl GuestMemoryManager {
    /// Returns an object to access guest memory.
    pub fn client(&self) -> GuestMemoryClient {
        GuestMemoryClient {
            mapping_manager: self.mapping_manager.client().clone(),
        }
    }

    /// Returns an object to map device memory into the VM.
    pub fn device_memory_mapper(&self) -> DeviceMemoryMapper {
        DeviceMemoryMapper::new(self.region_manager.client().clone())
    }

    /// Returns an object for manipulating the visibility state of different RAM
    /// regions.
    pub fn ram_visibility_control(&self) -> RamVisibilityControl {
        RamVisibilityControl {
            regions: self.ram_regions.clone(),
        }
    }

    /// Returns the shared memory resources that can be used to reconstruct the
    /// memory backing.
    ///
    /// This can be used with [`GuestMemoryBuilder::existing_backing`] to create a
    /// new memory manager with the same memory state. Only one instance of this
    /// type should be managing a given memory backing at a time, though, or the
    /// guest may see unpredictable results.
    pub fn shared_memory_backing(&self) -> SharedMemoryBacking {
        let guest_ram = self
            .guest_ram
            .clone()
            .expect("shared memory backing is not available in private memory mode");
        SharedMemoryBacking { guest_ram }
    }

    /// Attaches the guest memory to a partition, mapping it to the guest
    /// physical address space.
    ///
    /// If `process` is provided, then allocate a VA range in that process for
    /// the guest memory, and map the memory into the partition from that
    /// process. This is necessary to work around WHP's lack of support for
    /// mapping multiple partitions from a single process.
    ///
    /// TODO: currently, all VTLs will get the same mappings--no support for
    /// per-VTL memory protections is supported.
    pub async fn attach_partition(
        &mut self,
        vtl: Vtl,
        partition: &Arc<dyn virt::PartitionMemoryMap>,
        process: Option<RemoteProcess>,
    ) -> Result<(), PartitionAttachError> {
        let va_mapper = if let Some(process) = process {
            self.mapping_manager
                .client()
                .new_remote_mapper(process)
                .await
                .map_err(PartitionAttachError::VaMapper)?
        } else {
            self.va_mapper.clone()
        };

        if vtl == Vtl::Vtl2 {
            if let Some(offset) = self.vtl0_alias_map_offset {
                let partition =
                    PartitionMapper::new(partition, va_mapper.clone(), offset, self.pin_mappings);
                self.region_manager
                    .client()
                    .add_partition(partition)
                    .await
                    .map_err(PartitionAttachError::PartitionMapper)?;
            }
        }

        let partition = PartitionMapper::new(partition, va_mapper, 0, self.pin_mappings);
        self.region_manager
            .client()
            .add_partition(partition)
            .await
            .map_err(PartitionAttachError::PartitionMapper)?;
        Ok(())
    }
}

/// A client to the [`GuestMemoryManager`] used to control the visibility of
/// RAM regions.
pub struct RamVisibilityControl {
    regions: Arc<Vec<RamRegion>>,
}

/// The RAM visibility for use with [`RamVisibilityControl::set_ram_visibility`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RamVisibility {
    /// RAM is unmapped, so reads and writes will go to device memory or MMIO.
    Unmapped,
    /// RAM is read-only. Writes will go to device memory or MMIO.
    ///
    /// Note that writes will take exits even if there is mapped device memory.
    ReadOnly,
    /// RAM is read-write by the guest.
    ReadWrite,
}

/// An error returned by [`RamVisibilityControl::set_ram_visibility`].
#[derive(Debug, Error)]
#[error("{0} is not a controllable RAM range")]
pub struct InvalidRamRegion(MemoryRange);

impl RamVisibilityControl {
    /// Sets the visibility of a RAM region.
    ///
    /// A whole region's visibility must be controlled at once, or an error will
    /// be returned. [`GuestMemoryBuilder::x86_legacy_support`] can be used to
    /// ensure that there are RAM regions corresponding to x86 memory ranges
    /// that need to be controlled.
    pub async fn set_ram_visibility(
        &self,
        range: MemoryRange,
        visibility: RamVisibility,
    ) -> Result<(), InvalidRamRegion> {
        let region = self
            .regions
            .iter()
            .find(|region| region.range == range)
            .ok_or(InvalidRamRegion(range))?;

        match visibility {
            RamVisibility::ReadWrite | RamVisibility::ReadOnly => {
                region
                    .handle
                    .map(MapParams {
                        writable: matches!(visibility, RamVisibility::ReadWrite),
                        executable: true,
                        prefetch: false,
                    })
                    .await
            }
            RamVisibility::Unmapped => region.handle.unmap().await,
        }
        Ok(())
    }
}
