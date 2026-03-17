// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Guest memory bridge for vhost-user.
//!
//! Implements `GuestMemoryAccess` over mmap'd memory regions received via
//! the vhost-user `SET_MEM_TABLE` message. Regions are dynamically updateable
//! so that the same [`GuestMemory`] handle passed to the device at construction
//! time transparently reflects memory table updates.

#![cfg(unix)]
// UNSAFETY: Required for mmap/munmap of memory regions and implementing
// the unsafe GuestMemoryAccess trait.
#![expect(unsafe_code)]

use guestmem::GuestMemory;
use guestmem::GuestMemoryBackingError;
use parking_lot::RwLock;
use std::fmt;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::ptr::NonNull;
use std::sync::Arc;
use thiserror::Error;

/// Maximum guest physical address we'll support (48-bit PA = 256 TB).
/// This doesn't allocate any memory; it just sets the upper bound for
/// `max_address()` so the GuestMemory framework doesn't reject addresses
/// above a too-small limit.
const MAX_GUEST_ADDRESS: u64 = 1u64 << 48;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("mmap failed")]
    Mmap(#[source] std::io::Error),
    #[error("munmap failed")]
    Munmap(#[source] std::io::Error),
}

/// A single mmap'd memory region from the vhost-user frontend.
struct MappedRegion {
    guest_phys_addr: u64,
    size: u64,
    /// The frontend's userspace VA for this region (for VA→GPA translation).
    userspace_addr: u64,
    /// Host pointer from mmap.
    host_ptr: *mut u8,
    /// Original fd (kept alive for the duration of the mapping).
    _fd: OwnedFd,
}

// SAFETY: The mmap'd pointers are valid for the lifetime of the MappedRegion
// and access is synchronized by the RwLock in VhostUserMemoryRegions.
unsafe impl Send for MappedRegion {}
// SAFETY: see above.
unsafe impl Sync for MappedRegion {}

impl Drop for MappedRegion {
    fn drop(&mut self) {
        if !self.host_ptr.is_null() && self.size > 0 {
            // SAFETY: we mmap'd this region and own it.
            unsafe {
                libc::munmap(self.host_ptr.cast(), self.size as usize);
            }
        }
    }
}

/// Shared, dynamically-updateable memory region table.
///
/// This is stored inside the `GuestMemoryAccess` impl and also held by the
/// server to update regions on `SET_MEM_TABLE`.
#[derive(Clone)]
pub struct VhostUserMemoryRegions {
    inner: Arc<RwLock<Vec<MappedRegion>>>,
}

impl fmt::Debug for VhostUserMemoryRegions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let regions = self.inner.read();
        f.debug_struct("VhostUserMemoryRegions")
            .field("count", &regions.len())
            .finish()
    }
}

impl Default for VhostUserMemoryRegions {
    fn default() -> Self {
        Self::new()
    }
}

impl VhostUserMemoryRegions {
    /// Create a new empty region table.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Replace all regions with a new set from `SET_MEM_TABLE`.
    ///
    /// Each entry is `(guest_phys_addr, memory_size, userspace_addr, mmap_offset, fd)`.
    pub fn set_regions(
        &self,
        regions: Vec<(u64, u64, u64, u64, OwnedFd)>,
    ) -> Result<(), MemoryError> {
        let mut mapped = Vec::with_capacity(regions.len());
        for (guest_phys_addr, memory_size, userspace_addr, mmap_offset, fd) in regions {
            // SAFETY: mmap with the provided fd and offset.
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    memory_size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd.as_raw_fd(),
                    mmap_offset as libc::off_t,
                )
            };
            if ptr == libc::MAP_FAILED {
                return Err(MemoryError::Mmap(std::io::Error::last_os_error()));
            }
            mapped.push(MappedRegion {
                guest_phys_addr,
                size: memory_size,
                userspace_addr,
                host_ptr: ptr.cast(),
                _fd: fd,
            });
        }

        // Swap in the new regions; old ones are dropped (and munmap'd).
        let mut guard = self.inner.write();
        *guard = mapped;
        Ok(())
    }

    /// Translate a frontend userspace virtual address to a guest physical address.
    ///
    /// Returns `None` if the VA doesn't fall within any known region.
    pub fn va_to_gpa(&self, va: u64) -> Option<u64> {
        let regions = self.inner.read();
        for r in regions.iter() {
            if va >= r.userspace_addr && va < r.userspace_addr.saturating_add(r.size) {
                return Some(va - r.userspace_addr + r.guest_phys_addr);
            }
        }
        None
    }

    /// Check if any regions are configured.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

/// `GuestMemoryAccess` implementation backed by dynamically-updateable
/// vhost-user memory regions.
///
/// Since regions are scattered (not a single contiguous VA), `mapping()`
/// returns `None` and all access goes through the fallback methods which
/// look up the correct region by GPA.
struct VhostUserMemoryAccess {
    regions: VhostUserMemoryRegions,
}

// SAFETY: We implement the GuestMemoryAccess contract:
// - mapping() returns None, so the framework uses fallbacks
// - read_fallback/write_fallback correctly copy data from mmap'd regions
// - max_address returns a large constant so all valid GPAs are in range
unsafe impl guestmem::GuestMemoryAccess for VhostUserMemoryAccess {
    fn mapping(&self) -> Option<NonNull<u8>> {
        None
    }

    fn max_address(&self) -> u64 {
        MAX_GUEST_ADDRESS
    }

    unsafe fn read_fallback(
        &self,
        addr: u64,
        dest: *mut u8,
        len: usize,
    ) -> Result<(), GuestMemoryBackingError> {
        let regions = self.regions.inner.read();
        let mut offset = 0usize;
        let mut remaining = len;
        let mut current_addr = addr;

        while remaining > 0 {
            let (region_ptr, avail) = find_region(&regions, current_addr)
                .ok_or_else(|| GuestMemoryBackingError::other(addr, NotMapped))?;
            let copy_len = remaining.min(avail as usize);
            // SAFETY: region_ptr is valid for `avail` bytes, dest+offset is
            // valid for `copy_len` bytes per caller contract.
            unsafe {
                std::ptr::copy_nonoverlapping(region_ptr, dest.add(offset), copy_len);
            }
            offset += copy_len;
            remaining -= copy_len;
            current_addr += copy_len as u64;
        }
        Ok(())
    }

    unsafe fn write_fallback(
        &self,
        addr: u64,
        src: *const u8,
        len: usize,
    ) -> Result<(), GuestMemoryBackingError> {
        let regions = self.regions.inner.read();
        let mut offset = 0usize;
        let mut remaining = len;
        let mut current_addr = addr;

        while remaining > 0 {
            let (region_ptr, avail) = find_region(&regions, current_addr)
                .ok_or_else(|| GuestMemoryBackingError::other(addr, NotMapped))?;
            let copy_len = remaining.min(avail as usize);
            // SAFETY: region_ptr is valid for `avail` bytes, src+offset is
            // valid for `copy_len` bytes per caller contract.
            unsafe {
                std::ptr::copy_nonoverlapping(src.add(offset), region_ptr, copy_len);
            }
            offset += copy_len;
            remaining -= copy_len;
            current_addr += copy_len as u64;
        }
        Ok(())
    }

    fn fill_fallback(&self, addr: u64, val: u8, len: usize) -> Result<(), GuestMemoryBackingError> {
        let regions = self.regions.inner.read();
        let mut remaining = len;
        let mut current_addr = addr;

        while remaining > 0 {
            let (region_ptr, avail) = find_region(&regions, current_addr)
                .ok_or_else(|| GuestMemoryBackingError::other(addr, NotMapped))?;
            let fill_len = remaining.min(avail as usize);
            // SAFETY: region_ptr is valid for `avail` bytes.
            unsafe {
                std::ptr::write_bytes(region_ptr, val, fill_len);
            }
            remaining -= fill_len;
            current_addr += fill_len as u64;
        }
        Ok(())
    }
}

/// Find the region containing `addr` and return a pointer to the byte at
/// `addr` within that region, along with the number of bytes available from
/// that point to the end of the region.
fn find_region(regions: &[MappedRegion], addr: u64) -> Option<(*mut u8, u64)> {
    for r in regions {
        if addr >= r.guest_phys_addr && addr < r.guest_phys_addr.saturating_add(r.size) {
            let offset = addr - r.guest_phys_addr;
            // SAFETY: offset < r.size, and host_ptr was mmap'd with r.size bytes.
            let ptr = unsafe { r.host_ptr.add(offset as usize) };
            let available = r.size - offset;
            return Some((ptr, available));
        }
    }
    None
}

#[derive(Debug)]
struct NotMapped;

impl fmt::Display for NotMapped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("address not mapped in vhost-user memory regions")
    }
}

impl std::error::Error for NotMapped {}

/// Create a `GuestMemory` backed by the given shared region table.
///
/// The returned `GuestMemory` dynamically reflects updates to the regions
/// (via `VhostUserMemoryRegions::set_regions`), so it can be passed to a
/// device at construction time before any regions are configured.
pub fn guest_memory_from_regions(regions: &VhostUserMemoryRegions) -> GuestMemory {
    let access = VhostUserMemoryAccess {
        regions: regions.clone(),
    };
    GuestMemory::new("vhost-user", access)
}
