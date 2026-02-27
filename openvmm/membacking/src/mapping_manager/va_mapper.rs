// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The VA mapper — a linear virtual address space backing guest memory.
//!
//! Each `VaMapper` owns a [`SparseMapping`] that reserves a contiguous VA
//! range equal to the guest physical address space. This VA is registered
//! with the hypervisor (via [`PartitionMapper`](crate::partition_mapper::PartitionMapper))
//! so that VCPU memory accesses resolve through the host MMU to this VA.
//! Device emulation code accesses the same VA through the
//! [`GuestMemoryAccess`] trait.
//!
//! # Modes of operation
//!
//! ## File-backed (normal) mode — `private_ram = false`
//!
//! Pages are populated lazily: when the VMM first accesses an address, the
//! `SparseMapping` has no backing at that offset, triggering a page fault.
//! [`GuestMemoryAccess::page_fault`] sends a request to the
//! [`MappingManager`](super::manager::MappingManager), which responds with
//! the [`Mappable`](super::mappable::Mappable) + file offset for the range.
//! The mapper then calls `SparseMapping::map_file()` and returns
//! [`PageFaultAction::Retry`].
//!
//! This lazy approach avoids keeping every VA mapper synchronized with every
//! mapping change, but it has a caveat: the hypervisor may not propagate
//! host page faults back to the VMM. KVM, for example, will fail the VP
//! instead of delivering a clean exit. For the partition-facing mapper,
//! [`PartitionMapper`](crate::partition_mapper::PartitionMapper) calls
//! `ensure_mapped()` eagerly to pre-populate the VA before handing the range
//! to the hypervisor, but this is best-effort (the result is discarded with
//! `let _ =`).
//!
//! ## Private-RAM mode — `private_ram = true`
//!
//! Guest RAM is backed by anonymous committed pages rather than file-backed
//! sections. During `build()`,
//! [`GuestMemoryBuilder`](crate::memory_manager::GuestMemoryBuilder) calls
//! `alloc_range()` to eagerly replace the `SparseMapping`'s placeholders
//! with committed anonymous memory for each RAM range.
//!
//! - **Windows**: `page_fault()` calls `SparseMapping::commit()` in
//!   64 KB-aligned chunks, returns `Retry`. This handles the case where a
//!   page was previously decommitted and the hypervisor delivers a memory
//!   access exit when the VCPU touches the uncommitted VA.
//! - **Linux**: The kernel handles anonymous page faults transparently
//!   (copy-on-write from zero page). `page_fault()` should never be
//!   reached in normal operation — if it is, something is wrong.
//!
//! Device memory (VRAM, ROM BARs, etc.) always goes through the file-backed
//! `map_file()` path, even when RAM is private. Both RAM and device data
//! coexist in the same `SparseMapping`.
//!
//! # Decommit support
//!
//! In private-RAM mode, `decommit(offset, len)` releases physical pages
//! back to the host:
//! - **Windows**: `VirtualFree(MEM_DECOMMIT)` — pages return to reserved
//!   state; next VCPU access triggers a memory intercept → `page_fault()` →
//!   `commit()` → resume.
//! - **Linux**: `madvise(MADV_DONTNEED)` — pages are released; next access
//!   gets fresh zero pages from the kernel with no VMM involvement.
//!
//! This enables future balloon / free-page-reporting integration without
//! needing a tracking bitmap — the OS commit state *is* the tracking
//! mechanism.

// UNSAFETY: Implementing the unsafe GuestMemoryAccess trait by calling unsafe
// low level memory manipulation functions.
#![expect(unsafe_code)]

use super::manager::MapperId;
use super::manager::MapperRequest;
use super::manager::MappingParams;
use super::manager::MappingRequest;
use crate::RemoteProcess;
use futures::executor::block_on;
use guestmem::GuestMemoryAccess;
use guestmem::PageFaultAction;
use guestmem::PageFaultError;
use memory_range::MemoryRange;
use mesh::rpc::RpcError;
use mesh::rpc::RpcSend;
use parking_lot::Mutex;
use sparse_mmap::SparseMapping;
use std::ptr::NonNull;
use std::sync::Arc;
use std::thread::JoinHandle;
use thiserror::Error;

/// A linear VA space covering all guest memory.
///
/// See the [module documentation](self) for a full description of normal
/// vs. private-RAM mode. A `VaMapper` is always created through the
/// [`MappingManager`](super::manager::MappingManager) so it can receive
/// mapping updates and invalidations.
///
/// # Thread model
///
/// The mapper spawns a background thread that runs the `MapperTask` event
/// loop, processing `MapperRequest` messages from the mapping manager.
/// This thread is joined on drop.
pub struct VaMapper {
    inner: Arc<MapperInner>,
    /// Remote process handle for cross-process VA mapping (WHP workaround).
    process: Option<RemoteProcess>,
    /// When `true`, guest RAM is anonymous committed memory, not file-backed.
    private_ram: bool,
    _thread: JoinHandle<()>,
}

impl std::fmt::Debug for VaMapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaMapper")
            .field("inner", &self.inner)
            .field("_thread", &self._thread)
            .finish()
    }
}

/// Shared state between the `VaMapper` (GuestMemoryAccess impl) and the
/// `MapperTask` (async event loop). The `SparseMapping` is the actual VA
/// reservation that backs all guest memory access.
#[derive(Debug)]
struct MapperInner {
    /// The underlying VA reservation. Covers `[0, max_guest_address)` and
    /// is populated either by `map_file()` (file-backed) or `alloc()` /
    /// `commit()` (private-RAM).
    mapping: SparseMapping,
    /// Pending page-fault waiters. `None` after the mapper task exits, to
    /// prevent new waiters from blocking forever.
    waiters: Mutex<Option<Vec<MapWaiter>>>,
    /// Channel to the mapping manager for requesting mappings.
    req_send: mesh::Sender<MappingRequest>,
    /// Unique ID assigned by the mapping manager.
    id: MapperId,
}

#[derive(Debug)]
struct MapWaiter {
    range: MemoryRange,
    writable: bool,
    done: mesh::OneshotSender<bool>,
}

impl MapWaiter {
    fn complete(&mut self, range: MemoryRange, writable: Option<bool>) -> Option<bool> {
        if range.contains_addr(self.range.start()) {
            if writable.is_none() || (self.writable && writable == Some(false)) {
                return Some(false);
            }
            let new_start = self.range.end().min(range.end());
            let remaining = MemoryRange::new(new_start..self.range.end());
            if remaining.is_empty() {
                return Some(true);
            }
            tracing::debug!(%remaining, "waiting for more");
            self.range = remaining;
        }
        None
    }
}

struct MapperTask {
    inner: Arc<MapperInner>,
}

impl MapperTask {
    async fn run(mut self, mut req_recv: mesh::Receiver<MapperRequest>) {
        while let Ok(req) = req_recv.recv().await {
            match req {
                MapperRequest::Unmap(rpc) => rpc.handle_sync(|range| {
                    tracing::debug!(%range, "invalidate received");
                    self.inner
                        .mapping
                        .unmap(range.start() as usize, range.len() as usize)
                        .expect("invalidate request should be valid");
                }),
                MapperRequest::Map(MappingParams {
                    range,
                    mappable,
                    writable,
                    file_offset,
                }) => {
                    tracing::debug!(%range, "mapping received for range");

                    self.inner
                        .mapping
                        .map_file(
                            range.start() as usize,
                            range.len() as usize,
                            &mappable,
                            file_offset,
                            writable,
                        )
                        .expect("oom mapping file");

                    self.wake_waiters(range, Some(writable));
                }
                MapperRequest::NoMapping(range) => {
                    // Wake up waiters. They'll see a failure when they try to
                    // access the VA.
                    tracing::debug!(%range, "no mapping received for range");
                    self.wake_waiters(range, None);
                }
            }
        }
        // Don't allow more waiters.
        *self.inner.waiters.lock() = None;
        // Invalidate everything.
        let _ = self.inner.mapping.unmap(0, self.inner.mapping.len());
    }

    fn wake_waiters(&mut self, range: MemoryRange, writable: Option<bool>) {
        let mut waiters = self.inner.waiters.lock();
        let waiters = waiters.as_mut().unwrap();

        let mut i = 0;
        while i < waiters.len() {
            if let Some(success) = waiters[i].complete(range, writable) {
                waiters.swap_remove(i).done.send(success);
            } else {
                i += 1;
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum VaMapperError {
    #[error("failed to communicate with the memory manager")]
    MemoryManagerGone(#[source] RpcError),
    #[error("failed to reserve address space")]
    Reserve(#[source] std::io::Error),
}

#[derive(Debug, Error)]
#[error("no mapping for {0}")]
pub struct NoMapping(MemoryRange);

impl MapperInner {
    async fn request_mapping(&self, range: MemoryRange, writable: bool) -> Result<(), NoMapping> {
        let (send, recv) = mesh::oneshot();
        self.waiters
            .lock()
            .as_mut()
            .ok_or(NoMapping(range))?
            .push(MapWaiter {
                range,
                writable,
                done: send,
            });

        tracing::debug!(%range, "waiting for mappings");
        self.req_send
            .send(MappingRequest::SendMappings(self.id, range));
        match recv.await {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(NoMapping(range)),
        }
    }
}

impl VaMapper {
    pub(crate) async fn new(
        req_send: mesh::Sender<MappingRequest>,
        len: u64,
        remote_process: Option<RemoteProcess>,
        private_ram: bool,
    ) -> Result<Self, VaMapperError> {
        let mapping = match &remote_process {
            None => SparseMapping::new(len as usize),
            Some(process) => match process {
                #[cfg(not(windows))]
                _ => unreachable!(),
                #[cfg(windows)]
                process => SparseMapping::new_remote(
                    process.as_handle().try_clone_to_owned().unwrap().into(),
                    None,
                    len as usize,
                ),
            },
        }
        .map_err(VaMapperError::Reserve)?;

        let (send, req_recv) = mesh::channel();
        let id = req_send
            .call(MappingRequest::AddMapper, send)
            .await
            .map_err(VaMapperError::MemoryManagerGone)?;

        let inner = Arc::new(MapperInner {
            mapping,
            waiters: Mutex::new(Some(Vec::new())),
            req_send,
            id,
        });

        // FUTURE: use a task once we resolve the block_ons in the
        // GuestMemoryAccess implementation.
        let thread = std::thread::Builder::new()
            .name("mapper".to_owned())
            .spawn({
                let runner = MapperTask {
                    inner: inner.clone(),
                };
                || block_on(runner.run(req_recv))
            })
            .unwrap();

        Ok(VaMapper {
            inner,
            process: remote_process,
            private_ram,
            _thread: thread,
        })
    }

    /// Ensures a file-backed mapping has been established for the given range.
    ///
    /// In normal mode, this triggers a round-trip to the mapping manager to
    /// populate the VA with `map_file()`. In private-RAM mode, this is a
    /// no-op for RAM ranges (the VA is already committed) but the result
    /// is intentionally discarded by callers, so failure is benign.
    pub async fn ensure_mapped(&self, range: MemoryRange) -> Result<(), NoMapping> {
        self.inner.request_mapping(range, false).await
    }

    /// Returns a raw pointer to the base of the VA mapping.
    ///
    /// This pointer remains valid for the lifetime of the `VaMapper`, but
    /// individual pages may be uncommitted or unmapped.
    pub fn as_ptr(&self) -> *mut u8 {
        self.inner.mapping.as_ptr().cast()
    }

    /// Returns the length of the VA reservation in bytes.
    pub fn len(&self) -> usize {
        self.inner.mapping.len()
    }

    /// Returns the remote process handle, if this is a cross-process mapper.
    pub fn process(&self) -> Option<&RemoteProcess> {
        self.process.as_ref()
    }

    /// Allocates private anonymous memory for a range within the mapping.
    ///
    /// This replaces the placeholder at the given offset with committed
    /// anonymous memory. Only valid when private_ram mode is enabled.
    pub fn alloc_range(&self, offset: usize, len: usize) -> Result<(), std::io::Error> {
        assert!(self.private_ram, "alloc_range requires private RAM mode");
        self.inner.mapping.alloc(offset, len)
    }

    /// Decommits a range of private RAM, releasing physical pages back to the
    /// host.
    ///
    /// Only valid when private_ram mode is enabled.
    #[allow(dead_code)] // Will be used by ballooning / memory hot-remove.
    pub fn decommit(&self, offset: usize, len: usize) -> Result<(), std::io::Error> {
        assert!(self.private_ram, "decommit requires private RAM mode");
        self.inner.mapping.decommit(offset, len)
    }
}

/// SAFETY: the underlying VA mapping is guaranteed to be reserved (though not
/// necessarily committed at every offset) for the lifetime of this object.
/// In file-backed mode, individual pages are lazily mapped on fault.
/// In private-RAM mode, pages are eagerly committed in `build()` and may be
/// decommitted/recommitted during the VM's lifetime.
unsafe impl GuestMemoryAccess for VaMapper {
    fn mapping(&self) -> Option<NonNull<u8>> {
        // No one should be using this as a GuestMemoryAccess for remote
        // mappings, but it's convenient to have the same type for both local
        // and remote mappings for the sake of simplicity in
        // `PartitionRegionMapper`.
        assert!(self.inner.mapping.is_local());

        NonNull::new(self.inner.mapping.as_ptr().cast())
    }

    fn max_address(&self) -> u64 {
        self.inner.mapping.len() as u64
    }

    fn page_fault(
        &self,
        address: u64,
        len: usize,
        write: bool,
        bitmap_failure: bool,
    ) -> PageFaultAction {
        assert!(!bitmap_failure, "bitmaps are not used");

        if self.private_ram {
            // Private RAM mode: commit the page(s) directly.
            #[cfg(windows)]
            {
                // Commit in 64KB-aligned chunks to amortize overhead.
                let commit_start = address & !0xFFFF; // round down to 64KB
                let commit_end = ((address + len as u64) + 0xFFFF) & !0xFFFF; // round up
                let commit_end = commit_end.min(self.inner.mapping.len() as u64);
                let commit_len = (commit_end - commit_start) as usize;

                if let Err(err) = self.inner.mapping.commit(commit_start as usize, commit_len) {
                    return PageFaultAction::Fail(PageFaultError::new(
                        guestmem::GuestMemoryErrorKind::OutOfRange,
                        err,
                    ));
                }
                return PageFaultAction::Retry;
            }
            #[cfg(unix)]
            {
                // On Linux, the kernel handles page faults transparently.
                // If we get here, something is wrong.
                return PageFaultAction::Fail(PageFaultError::new(
                    guestmem::GuestMemoryErrorKind::OutOfRange,
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "unexpected page fault in private RAM mode on Linux",
                    ),
                ));
            }
        }

        // File-backed path: request mapping from MappingManager.
        // `block_on` is OK to call here (will not deadlock) because this is
        // never called from the page fault handler thread or any threads it
        // depends on.
        //
        // Removing this `block_on` would make all guest memory access `async`,
        // which would be a difficult change.
        if let Err(err) = block_on(
            self.inner
                .request_mapping(MemoryRange::bounding(address..address + len as u64), write),
        ) {
            return PageFaultAction::Fail(PageFaultError::new(
                guestmem::GuestMemoryErrorKind::OutOfRange,
                err,
            ));
        }
        PageFaultAction::Retry
    }
}

#[cfg(test)]
mod tests {
    use sparse_mmap::SparseMapping;

    /// Tests that private RAM pages can be allocated, written to, and read from.
    #[test]
    fn test_private_ram_alloc_write_read() {
        let page_size = SparseMapping::page_size();
        let mapping = SparseMapping::new(4 * page_size).unwrap();

        // Allocate (commit) the first two pages.
        mapping.alloc(0, 2 * page_size).unwrap();

        // Write and read through SparseMapping methods.
        let data = [0xABu8; 128];
        mapping.write_at(0, &data).unwrap();

        let mut buf = [0u8; 128];
        mapping.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, data);

        // Verify zeros at an untouched offset within committed range.
        let mut zero_buf = [0xFFu8; 64];
        mapping.read_at(page_size, &mut zero_buf).unwrap();
        assert!(
            zero_buf.iter().all(|&b| b == 0),
            "untouched committed memory should be zeros"
        );
    }

    /// Tests that decommitting pages releases their contents (zeros on re-read on Linux).
    #[test]
    fn test_private_ram_decommit_zeros() {
        let page_size = SparseMapping::page_size();
        let mapping = SparseMapping::new(4 * page_size).unwrap();

        // Commit and write data.
        mapping.alloc(0, 2 * page_size).unwrap();
        let pattern = vec![0xABu8; 64];
        mapping.write_at(0, &pattern).unwrap();
        mapping.write_at(page_size, &pattern).unwrap();

        // Decommit first page.
        mapping.decommit(0, page_size).unwrap();

        // On Linux, decommitted pages read as zeros.
        #[cfg(unix)]
        {
            let mut buf = vec![0xFFu8; 64];
            mapping.read_at(0, &mut buf).unwrap();
            assert!(
                buf.iter().all(|&b| b == 0),
                "decommitted page should be zeros on Linux"
            );
        }

        // Second page should still have its data.
        let mut buf2 = vec![0u8; 64];
        mapping.read_at(page_size, &mut buf2).unwrap();
        assert_eq!(buf2, pattern);
    }

    /// Tests that recommitting pages after decommit provides zeroed memory.
    #[test]
    fn test_private_ram_recommit_after_decommit() {
        let page_size = SparseMapping::page_size();
        let mapping = SparseMapping::new(4 * page_size).unwrap();

        // Commit, write, decommit, recommit.
        mapping.alloc(0, page_size).unwrap();
        let pattern = vec![0xCDu8; 64];
        mapping.write_at(0, &pattern).unwrap();

        mapping.decommit(0, page_size).unwrap();
        mapping.commit(0, page_size).unwrap();

        // After recommit, the page should be zeros (old data is gone).
        let mut buf = vec![0xFFu8; 64];
        mapping.read_at(0, &mut buf).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0),
            "recommitted page should be zeros"
        );

        // Can write and read new data.
        let new_data = vec![0xEFu8; 64];
        mapping.write_at(0, &new_data).unwrap();
        let mut buf2 = vec![0u8; 64];
        mapping.read_at(0, &mut buf2).unwrap();
        assert_eq!(buf2, new_data);
    }

    /// Tests that commit is idempotent (committing already-committed pages is
    /// a no-op).
    #[test]
    fn test_private_ram_commit_idempotent() {
        let page_size = SparseMapping::page_size();
        let mapping = SparseMapping::new(4 * page_size).unwrap();

        // Alloc then commit the same range again.
        mapping.alloc(0, 2 * page_size).unwrap();
        mapping.commit(0, 2 * page_size).unwrap();
        mapping.commit(0, page_size).unwrap();

        // Write and read should work.
        let pattern = vec![0xEFu8; 64];
        mapping.write_at(0, &pattern).unwrap();
        let mut buf = vec![0u8; 64];
        mapping.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, pattern);
    }
}
