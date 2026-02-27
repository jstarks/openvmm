// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The mapping manager subsystem.
//!
//! This module contains the components responsible for maintaining virtual
//! address (VA) mappings that back guest memory access. The key types are:
//!
//! - [`MappingManager`] — coordinates mapping state across multiple VA
//!   mappers. It receives active-mapping updates from the region manager and
//!   distributes them (on demand) to individual VA mappers while also
//!   orchestrating invalidations when mappings are torn down.
//!
//! - [`VaMapper`] — owns a [`SparseMapping`](sparse_mmap::SparseMapping) that
//!   provides a single contiguous VA range covering the entire guest physical
//!   address space. Implements
//!   [`GuestMemoryAccess`](guestmem::GuestMemoryAccess), so a `VaMapper` can
//!   be wrapped in a [`GuestMemory`](guestmem::GuestMemory) for device
//!   emulation, DMA, and other VMM-side memory access. In *normal* (file-backed)
//!   mode, the VA is populated lazily via `map_file()` from OS-level mappable
//!   objects. In *private-RAM* mode, the VA is backed by anonymous committed
//!   pages and supports commit-on-fault plus decommit.
//!
//! - [`Mappable`] — a cross-platform, cheaply cloneable handle to an OS object
//!   (section on Windows, fd on Linux) that can be memory-mapped into the
//!   `SparseMapping`.
//!
//! See the [crate-level documentation](crate) for how these fit into the
//! broader memory manager architecture.

mod manager;
mod mappable;
mod object_cache;
mod va_mapper;

pub use manager::MappingManager;
pub use manager::MappingManagerClient;
pub use mappable::Mappable;
pub use va_mapper::VaMapper;
pub use va_mapper::VaMapperError;
