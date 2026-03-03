// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Write-back page cache for VHDX metadata pages.
//!
//! Provides a hash-table-backed, page-granularity (4 KiB) caching layer over
//! an [`AsyncFile`]. Pages are identified by a [`PageKey`] consisting of a tag
//! (u8) and an offset within a tagged region. Tags map to base file offsets,
//! allowing region relocation without invalidating cached pages.
//!
//! Modified pages accumulate as **Dirty** in the cache. On [`flush()`](PageCache::flush),
//! dirty pages are sent to the log task via a mesh channel for WAL persistence.
//! The log task applies them to their final file offsets in the background.
//!
//! Page data is stored as `Arc<[u8; PAGE_SIZE]>` to enable zero-copy flush
//! (Arc::clone) and implicit COW (Arc::make_mut) when a page is modified while
//! the log task holds a reference.

use crate::AsyncFile;
use crate::error::VhdxError;
use crate::log_task::DirtyPage;
use crate::log_task::LogRequest;
use crate::log_task::PAGE_CLEAN;
use crate::log_task::PAGE_DIRTY;
use crate::log_task::PAGE_IN_LOG;
use mesh::rpc::RpcSend;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

/// Page size used by the cache (4 KiB).
pub const PAGE_SIZE: usize = 4096;

/// Key identifying a cached page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PageKey {
    /// Tag selecting the region (e.g., 0 = BAT, 1 = metadata).
    pub tag: u8,
    /// Byte offset within the tagged region. Must be 4 KiB aligned.
    pub offset: u64,
}

/// Write mode for page acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Page is loaded from file if not cached. Caller will modify parts.
    Modify,
    /// Page is NOT loaded from file (caller will overwrite the entire page).
    Overwrite,
}

/// Internal per-page data.
struct PageData {
    /// The page contents as `Arc` for zero-copy flush and COW.
    /// `None` if the page has not been loaded yet.
    data: Option<Arc<[u8; PAGE_SIZE]>>,
    /// Page state: Clean, Dirty, or InLog.
    state: Arc<AtomicU8>,
    /// If set, the log task must wait for this FSN to complete before
    /// including this page in a log entry. Set per-page by the write
    /// path when a BAT page references newly-allocated data that may
    /// not yet be flushed to stable storage.
    pre_log_fsn: Option<u64>,
}

/// Write-back page cache backed by an [`AsyncFile`].
///
/// Pages are loaded on first access and kept in memory indefinitely (no
/// eviction). Modified pages are marked dirty in the cache and sent to
/// the log task on [`flush()`](Self::flush).
///
/// When no log sender is configured (read-only mode), dirty pages are
/// written directly to the file on commit (write-through fallback).
pub struct PageCache<F: AsyncFile> {
    file: Arc<F>,
    /// Page map: `PageKey` → shared handle to the cached page mutex.
    pages: Mutex<HashMap<PageKey, Arc<Mutex<PageData>>>>,
    /// Tag → base file offset mapping.
    tags: Mutex<HashMap<u8, u64>>,
    /// When true, dirty pages are deferred to [`flush()`](Self::flush)
    /// for write-back through the log task. When false, dirty pages are
    /// written directly to the file on [`commit()`](PageCommit::commit).
    write_back_mode: bool,
}

impl<F: AsyncFile> PageCache<F> {
    /// Create a new cache backed by the given file.
    pub fn new(file: Arc<F>) -> Self {
        Self {
            file,
            pages: Mutex::new(HashMap::new()),
            tags: Mutex::new(HashMap::new()),
            write_back_mode: false,
        }
    }

    /// Returns a reference to the underlying file.
    pub(crate) fn file(&self) -> &F {
        &self.file
    }

    /// Enable write-back mode.
    ///
    /// Must be called before any writes. When enabled, dirty pages are
    /// deferred in the cache and sent to the log task on
    /// [`flush()`](Self::flush) instead of being written directly on
    /// [`commit()`](PageCommit::commit).
    pub fn enable_write_back(&mut self) {
        self.write_back_mode = true;
    }

    /// Register a tag with its base file offset.
    ///
    /// Must be called before any [`acquire()`](Self::acquire_read) with that tag.
    pub fn register_tag(&mut self, tag: u8, base_offset: u64) {
        self.tags.lock().insert(tag, base_offset);
    }

    /// Update the base file offset for a previously registered tag.
    ///
    /// Subsequent acquires will use the new base offset. Already-cached pages
    /// are NOT invalidated — they will be written to the new location on
    /// release.
    pub fn update_tag_offset(&self, tag: u8, new_base: u64) {
        self.tags.lock().insert(tag, new_base);
    }

    /// Resolve a [`PageKey`] to an absolute file offset.
    pub(crate) fn resolve_offset(&self, key: PageKey) -> Result<u64, std::io::Error> {
        let tags = self.tags.lock();
        let base = tags.get(&key.tag).ok_or_else(|| {
            std::io::Error::other(format!("cache tag {} not registered", key.tag))
        })?;
        Ok(base + key.offset)
    }

    /// Internal: validate key, load page if needed, acquire lock.
    async fn acquire_inner(
        &self,
        key: PageKey,
        load_from_disk: bool,
    ) -> Result<parking_lot::ArcMutexGuard<parking_lot::RawMutex, PageData>, std::io::Error> {
        // Validate alignment.
        if !key.offset.is_multiple_of(PAGE_SIZE as u64) {
            return Err(std::io::Error::other(format!(
                "page offset {:#x} is not {PAGE_SIZE}-byte aligned",
                key.offset
            )));
        }

        // Resolve the file offset eagerly so we fail fast on unregistered tags.
        let file_offset = self.resolve_offset(key)?;

        // Get or create the page entry (brief lock on the page map).
        let entry = {
            let mut pages = self.pages.lock();
            pages
                .entry(key)
                .or_insert_with(|| {
                    Arc::new(Mutex::new(PageData {
                        data: None,
                        state: Arc::new(AtomicU8::new(PAGE_CLEAN)),
                        pre_log_fsn: None,
                    }))
                })
                .clone()
        };

        // Load the page from disk if necessary. We do the async I/O
        // *before* acquiring the long-held ArcMutexGuard so we never
        // hold a sync lock across an await point.
        if load_from_disk {
            let needs_load = entry.lock().data.is_none();
            if needs_load {
                let mut buf = [0u8; PAGE_SIZE];
                self.file.read_at(file_offset, &mut buf).await?;

                let mut page = entry.lock();
                // Another task may have loaded while we were reading.
                if page.data.is_none() {
                    page.data = Some(Arc::new(buf));
                }
            }
        } else {
            let mut page = entry.lock();
            if page.data.is_none() {
                page.data = Some(Arc::new([0u8; PAGE_SIZE]));
            }
        }

        // Acquire the page lock for the lifetime of the guard.
        Ok(Mutex::lock_arc(&entry))
    }

    /// Acquire read access to a page.
    ///
    /// Returns a [`ReadPageGuard`] that provides `&[u8; PAGE_SIZE]`.
    /// The page is loaded from disk if not already cached. The lock
    /// is released when the guard is dropped.
    pub async fn acquire_read(&self, key: PageKey) -> Result<ReadPageGuard, std::io::Error> {
        let guard = self.acquire_inner(key, true).await?;
        Ok(ReadPageGuard { guard })
    }

    /// Acquire write access to a page.
    ///
    /// Returns a [`WritePageGuard`] that provides `&[u8; PAGE_SIZE]`
    /// and `&mut [u8; PAGE_SIZE]`. With [`WriteMode::Modify`] the page
    /// is loaded from disk first; with [`WriteMode::Overwrite`] it is not.
    ///
    /// The caller **must** call [`WritePageGuard::release()`] to produce a
    /// [`PageCommit`], then `.commit().await` to mark the page dirty.
    pub async fn acquire_write(
        &self,
        key: PageKey,
        mode: WriteMode,
    ) -> Result<WritePageGuard<'_, F>, std::io::Error> {
        let load = mode == WriteMode::Modify;
        let guard = self.acquire_inner(key, load).await?;
        Ok(WritePageGuard {
            cache: self,
            key,
            guard: Some(guard),
            dirty: false,
        })
    }

    /// Set the pre-log FSN on a specific page. The log task will wait for
    /// this FSN to complete before including this page in a log entry.
    /// Only meaningful for Dirty pages.
    ///
    /// If the page already has a pre_log_fsn, the maximum of the existing
    /// and new values is used.
    pub fn set_pre_log_fsn(&self, key: PageKey, fsn: u64) {
        let pages = self.pages.lock();
        if let Some(entry) = pages.get(&key) {
            let mut page = entry.lock();
            page.pre_log_fsn = Some(match page.pre_log_fsn {
                Some(existing) => existing.max(fsn),
                None => fsn,
            });
        }
    }

    /// Get the pre-log FSN for a specific page, if set.
    ///
    /// Returns `None` if the page does not exist in the cache or has no
    /// pre_log_fsn constraint.
    #[allow(dead_code)]
    pub fn get_pre_log_fsn(&self, key: PageKey) -> Option<u64> {
        let pages = self.pages.lock();
        if let Some(entry) = pages.get(&key) {
            let page = entry.lock();
            page.pre_log_fsn
        } else {
            None
        }
    }

    /// Flush all dirty pages through the log task.
    ///
    /// Collects all dirty pages, clones their data via `Arc::clone`
    /// (cheap refcount bump), transitions them to InLog, and sends
    /// a `LogRequest::Flush` to the log task.
    ///
    /// Returns the FSN after the log entry is durable.
    ///
    /// If no log sender is provided (read-only mode or no log task),
    /// delegates to `file.flush()` directly.
    pub async fn flush(
        &self,
        log_sender: Option<&mesh::Sender<LogRequest>>,
    ) -> Result<u64, VhdxError> {
        let Some(sender) = log_sender else {
            // No log task — write-through fallback for read-only.
            self.file.flush().await?;
            return Ok(0);
        };

        // Collect dirty pages.
        let dirty_pages = {
            let pages = self.pages.lock();
            let mut dirty = Vec::new();
            for (&key, entry) in pages.iter() {
                let mut page = entry.lock();
                if page.state.load(Ordering::Acquire) == PAGE_DIRTY {
                    let file_offset = self.resolve_offset(key).map_err(VhdxError::Io)?;
                    let data = page.data.as_ref().expect("dirty page has no data").clone();
                    let state = page.state.clone();
                    // Move per-page FSN to DirtyPage, clearing it from the cache.
                    let pre_log_fsn = page.pre_log_fsn.take();
                    // Transition to InLog.
                    state.store(PAGE_IN_LOG, Ordering::Release);
                    dirty.push(DirtyPage {
                        file_offset,
                        data,
                        state,
                        pre_log_fsn,
                    });
                }
            }
            dirty
        };

        if dirty_pages.is_empty() {
            return Ok(0);
        }

        sender
            .call(LogRequest::Flush, dirty_pages)
            .await
            .map_err(|_| VhdxError::Io(std::io::Error::other("log task closed")))?
    }

    /// Flush all dirty pages with an optional pre_log_fsn constraint.
    ///
    /// Like [`flush()`](Self::flush), but attaches the given FSN as a
    /// pre_log_fsn to all dirty pages. The log task will wait for this
    /// FSN to complete before including the pages in a log entry.
    ///
    /// If a page already has a per-page FSN set, the maximum of the
    /// per-page FSN and the argument FSN is used.
    #[allow(dead_code)]
    pub async fn flush_with_pre_log_fsn(
        &self,
        log_sender: Option<&mesh::Sender<LogRequest>>,
        pre_log_fsn: Option<u64>,
    ) -> Result<u64, VhdxError> {
        let Some(sender) = log_sender else {
            self.file.flush().await?;
            return Ok(0);
        };

        // Collect dirty pages.
        let dirty_pages = {
            let pages = self.pages.lock();
            let mut dirty = Vec::new();
            for (&key, entry) in pages.iter() {
                let mut page = entry.lock();
                if page.state.load(Ordering::Acquire) == PAGE_DIRTY {
                    let file_offset = self.resolve_offset(key).map_err(VhdxError::Io)?;
                    let data = page.data.as_ref().expect("dirty page has no data").clone();
                    let state = page.state.clone();
                    // Combine per-page FSN with argument FSN: use maximum.
                    let effective_fsn = match (page.pre_log_fsn.take(), pre_log_fsn) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (a, b) => a.or(b),
                    };
                    state.store(PAGE_IN_LOG, Ordering::Release);
                    dirty.push(DirtyPage {
                        file_offset,
                        data,
                        state,
                        pre_log_fsn: effective_fsn,
                    });
                }
            }
            dirty
        };

        if dirty_pages.is_empty() {
            return Ok(0);
        }

        sender
            .call(LogRequest::Flush, dirty_pages)
            .await
            .map_err(|_| VhdxError::Io(std::io::Error::other("log task closed")))?
    }
}

/// RAII guard providing read-only access to a cached page.
///
/// The page lock is released when the guard is dropped.
/// No explicit release is needed for reads.
#[must_use = "page guard holds a lock; drop it when done reading"]
pub struct ReadPageGuard {
    guard: parking_lot::ArcMutexGuard<parking_lot::RawMutex, PageData>,
}

impl std::ops::Deref for ReadPageGuard {
    type Target = [u8; PAGE_SIZE];

    fn deref(&self) -> &[u8; PAGE_SIZE] {
        self.guard.data.as_ref().expect("page data missing")
    }
}

/// RAII guard providing write access to a cached page.
///
/// Provides `Deref<Target = [u8; PAGE_SIZE]>` and `DerefMut`.
/// The caller **must** call [`release()`](Self::release) to get a
/// [`PageCommit`], then `.commit().await` to mark the page dirty.
///
/// Dropping a dirty `WritePageGuard` without calling `release()` panics
/// in debug builds.
///
/// Arc COW: When the page is InLog (refcount > 1), `DerefMut` calls
/// `Arc::make_mut`, which automatically clones the underlying buffer.
/// The writer gets a private copy while the log task retains the original.
#[must_use = "write guard must be released via .release().commit().await"]
pub struct WritePageGuard<'a, F: AsyncFile> {
    cache: &'a PageCache<F>,
    key: PageKey,
    guard: Option<parking_lot::ArcMutexGuard<parking_lot::RawMutex, PageData>>,
    dirty: bool,
}

impl<'a, F: AsyncFile> WritePageGuard<'a, F> {
    /// Release the page lock and return a [`PageCommit`] handle.
    ///
    /// If the page was mutated, it is marked dirty in the cache.
    /// The `ArcMutexGuard` is dropped synchronously in this method,
    /// so the returned [`PageCommit`] is `Send`.
    #[must_use = "call .commit().await to finalize the page write"]
    pub fn release(mut self) -> PageCommit<'a, F> {
        let guard = self.guard.take().expect("guard already released");

        if self.dirty {
            // Mark the page dirty in the cache (if not already InLog or Dirty).
            let current = guard.state.load(Ordering::Acquire);
            if current == PAGE_CLEAN {
                guard.state.store(PAGE_DIRTY, Ordering::Release);
            } else if current == PAGE_IN_LOG {
                // Page was InLog — Arc::make_mut already gave us a new copy.
                // Mark the new copy as dirty.
                guard.state.store(PAGE_DIRTY, Ordering::Release);
            }
            // If already Dirty, keep it Dirty.
        }
        drop(guard);

        PageCommit {
            cache: self.cache,
            key: self.key,
            was_dirty: self.dirty,
        }
    }
}

impl<F: AsyncFile> std::ops::Deref for WritePageGuard<'_, F> {
    type Target = [u8; PAGE_SIZE];

    fn deref(&self) -> &[u8; PAGE_SIZE] {
        self.guard
            .as_ref()
            .expect("guard already released")
            .data
            .as_ref()
            .expect("page data missing")
    }
}

impl<F: AsyncFile> std::ops::DerefMut for WritePageGuard<'_, F> {
    fn deref_mut(&mut self) -> &mut [u8; PAGE_SIZE] {
        self.dirty = true;
        let guard = self.guard.as_mut().expect("guard already released");
        // Arc COW: if page is InLog (refcount > 1), this clones the buffer.
        // If refcount == 1 (Clean or Dirty), this is a no-op.
        Arc::make_mut(guard.data.as_mut().expect("page data missing"))
    }
}

impl<F: AsyncFile> Drop for WritePageGuard<'_, F> {
    fn drop(&mut self) {
        if let Some(_guard) = self.guard.take() {
            if self.dirty {
                debug_assert!(
                    false,
                    "dirty WritePageGuard dropped without calling release() — data may be lost"
                );
            }
        }
    }
}

/// Handle for completing a page write operation.
///
/// Returned by [`WritePageGuard::release()`]. This type is `Send` (it does
/// not hold any mutex guard).
///
/// In write-back mode, [`commit()`](Self::commit) is a no-op — the page
/// is already marked dirty in the cache by `release()`. The actual disk
/// write happens through the log task on flush.
///
/// In write-through mode (no log sender), `commit()` writes the dirty
/// page data directly to disk.
#[must_use = "call .commit().await to finalize the page write"]
pub struct PageCommit<'a, F: AsyncFile> {
    cache: &'a PageCache<F>,
    key: PageKey,
    was_dirty: bool,
}

impl<F: AsyncFile> PageCommit<'_, F> {
    /// Finalize the page write.
    ///
    /// In write-back mode (log sender configured): no-op, the page
    /// is already marked dirty in the cache.
    ///
    /// In write-through mode (no log sender): writes the dirty page
    /// data directly to the file. This provides backward compatibility
    /// for read-only mode and tests.
    pub async fn commit(self) -> Result<(), std::io::Error> {
        if !self.was_dirty {
            return Ok(());
        }

        if self.cache.write_back_mode {
            // Write-back mode: page is already dirty in cache.
            // Actual write happens via flush() → log task.
            return Ok(());
        }

        // Write-through fallback: read the page data from the cache and
        // write it directly to the file.
        let file_offset = self.cache.resolve_offset(self.key)?;
        let entry = {
            let pages = self.cache.pages.lock();
            pages.get(&self.key).cloned()
        };
        if let Some(entry) = entry {
            let page = entry.lock();
            if let Some(data) = &page.data {
                self.cache
                    .file
                    .write_at(file_offset, data.as_slice())
                    .await?;
                // Mark clean after write-through.
                page.state.store(PAGE_CLEAN, Ordering::Release);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::support::{FailingInterceptor, InMemoryFile};
    use pal_async::async_test;
    use std::sync::Arc;

    #[async_test]
    async fn acquire_read_loads_from_file() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);
        // Write a known pattern at offset 0.
        let pattern: Vec<u8> = (0..PAGE_SIZE).map(|i| (i & 0xFF) as u8).collect();
        file.write_at(0, &pattern).await.unwrap();

        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(0, 0);

        let guard = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(&guard[..], &pattern[..]);
        drop(guard);
    }

    #[async_test]
    async fn acquire_modify_loads_and_writes_back() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);
        let pattern: Vec<u8> = (0..PAGE_SIZE).map(|i| (i & 0xFF) as u8).collect();
        file.write_at(0, &pattern).await.unwrap();

        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(0, 0);

        {
            let mut guard = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Modify)
                .await
                .unwrap();
            // Verify data was loaded.
            assert_eq!(guard[0], 0x00);
            assert_eq!(guard[1], 0x01);
            // Mutate.
            guard[0] = 0xAA;
            guard[1] = 0xBB;
            guard.release().commit().await.unwrap();
        }

        // Read directly from the file to verify write-through.
        let snap = cache.file().snapshot();
        assert_eq!(snap[0], 0xAA);
        assert_eq!(snap[1], 0xBB);
        // Rest unchanged.
        assert_eq!(snap[2], 0x02);
    }

    #[async_test]
    async fn acquire_overwrite_skips_read() {
        // File with a FailingInterceptor that fails reads.
        let file = InMemoryFile::with_interceptor(
            PAGE_SIZE as u64,
            Box::new(FailingInterceptor {
                fail_reads: true,
                fail_writes: false,
                fail_flushes: false,
                fail_set_file_size: false,
            }),
        );

        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(0, 0);

        // Overwrite should succeed even though reads fail.
        let mut guard = cache
            .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Overwrite)
            .await
            .unwrap();
        guard.fill(0xCC);
        guard.release().commit().await.unwrap();

        // Verify the data was written to the file.
        let snap = cache.file().snapshot();
        assert!(snap.iter().all(|&b| b == 0xCC));
    }

    #[async_test]
    async fn concurrent_reads_return_correct_data() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);
        let pattern: Vec<u8> = (0..PAGE_SIZE).map(|i| ((i * 3) & 0xFF) as u8).collect();
        file.write_at(0, &pattern).await.unwrap();

        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(0, 0);

        // First read loads from file.
        let g1 = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(&g1[..], &pattern[..]);
        drop(g1);

        // Second read uses cached data.
        let g2 = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(&g2[..], &pattern[..]);
        drop(g2);
    }

    #[async_test]
    async fn sequential_modify_acquires_work() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);

        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(0, 0);

        // First modify.
        {
            let mut guard = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Modify)
                .await
                .unwrap();
            guard[0] = 0x11;
            guard.release().commit().await.unwrap();
        }

        // Second modify on the same page.
        {
            let mut guard = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Modify)
                .await
                .unwrap();
            // Should see the previously written value.
            assert_eq!(guard[0], 0x11);
            guard[0] = 0x22;
            guard.release().commit().await.unwrap();
        }

        let snap = cache.file().snapshot();
        assert_eq!(snap[0], 0x22);
    }

    #[async_test]
    async fn modify_then_modify_same_page() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);

        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(0, 0);

        {
            let mut g = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Modify)
                .await
                .unwrap();
            g[0] = 0xAA;
            g.release().commit().await.unwrap();
        }

        {
            let mut g = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Modify)
                .await
                .unwrap();
            assert_eq!(g[0], 0xAA);
            g[1] = 0xBB;
            g.release().commit().await.unwrap();
        }

        let snap = cache.file().snapshot();
        assert_eq!(snap[0], 0xAA);
        assert_eq!(snap[1], 0xBB);
    }

    #[async_test]
    async fn different_pages_independent() {
        let file = InMemoryFile::new(PAGE_SIZE as u64 * 4);

        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(0, 0);

        // Write to page at offset 0.
        {
            let mut g = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Modify)
                .await
                .unwrap();
            g[0] = 0x11;
            g.release().commit().await.unwrap();
        }

        // Write to page at offset PAGE_SIZE.
        {
            let mut g = cache
                .acquire_write(
                    PageKey {
                        tag: 0,
                        offset: PAGE_SIZE as u64,
                    },
                    WriteMode::Modify,
                )
                .await
                .unwrap();
            g[0] = 0x22;
            g.release().commit().await.unwrap();
        }

        // Verify both pages are independent.
        let snap = cache.file().snapshot();
        assert_eq!(snap[0], 0x11);
        assert_eq!(snap[PAGE_SIZE], 0x22);
    }

    #[async_test]
    async fn tag_offset_resolution() {
        let base: u64 = 0x10000;
        let page_offset: u64 = 0x1000;
        let file = InMemoryFile::new(base + page_offset + PAGE_SIZE as u64);

        // Write a known pattern at the resolved file offset.
        let pattern = [0xDE; PAGE_SIZE];
        file.write_at(base + page_offset, &pattern).await.unwrap();

        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(0, base);

        let guard = cache
            .acquire_read(PageKey {
                tag: 0,
                offset: page_offset,
            })
            .await
            .unwrap();
        assert_eq!(&guard[..], &pattern[..]);
        drop(guard);
    }

    #[async_test]
    async fn update_tag_offset() {
        let old_base: u64 = 0x10000;
        let new_base: u64 = 0x20000;
        let file = InMemoryFile::new(new_base + PAGE_SIZE as u64);

        // Write different patterns at the old and new base.
        let old_pattern = [0xAA; PAGE_SIZE];
        let new_pattern = [0xBB; PAGE_SIZE];
        file.write_at(old_base, &old_pattern).await.unwrap();
        file.write_at(new_base, &new_pattern).await.unwrap();

        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(0, old_base);

        // Read from old base.
        {
            let guard = cache
                .acquire_read(PageKey { tag: 0, offset: 0 })
                .await
                .unwrap();
            assert_eq!(guard[0], 0xAA);
            drop(guard);
        }

        // Invalidate the cached page by creating a fresh cache (update_tag_offset
        // doesn't invalidate). For a true relocation test, use a fresh cache.
        let mut cache = PageCache::new(cache.file.clone());
        cache.register_tag(0, old_base);
        cache.update_tag_offset(0, new_base);

        let guard = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(guard[0], 0xBB);
        drop(guard);
    }

    #[async_test]
    async fn write_through_then_read_back() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);

        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(0, 0);

        // Modify and release (write-through).
        {
            let mut guard = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Modify)
                .await
                .unwrap();
            guard[42] = 0xFF;
            guard.release().commit().await.unwrap();
        }

        // Verify the file was updated.
        let snap = cache.file().snapshot();
        assert_eq!(snap[42], 0xFF);

        // Re-acquire as Read and verify cached data.
        let guard = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(guard[42], 0xFF);
        drop(guard);
    }

    #[async_test]
    async fn flush_delegates_to_file() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);
        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(0, 0);

        // Write some data, release, then flush.
        let mut guard = cache
            .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Modify)
            .await
            .unwrap();
        guard[0] = 0x42;
        guard.release().commit().await.unwrap();

        // flush() should succeed (delegates to InMemoryFile::flush which is a no-op).
        cache.flush(None).await.unwrap();

        let snap = cache.file().snapshot();
        assert_eq!(snap[0], 0x42);
    }
}
