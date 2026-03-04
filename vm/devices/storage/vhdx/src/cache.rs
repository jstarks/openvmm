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
use crate::log_task::LOG_APPLIED;
use crate::log_task::LOG_FAILED;
use crate::log_task::LOG_PENDING;
use crate::log_task::LogRequest;
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
    /// Cache-local dirty flag. Only accessed under the page mutex.
    dirty: bool,
    /// Completion signal from the most recent flush that included this
    /// page. The log task stores `LOG_APPLIED` or `LOG_FAILED` when it
    /// finishes processing the batch. Each flush creates a **fresh**
    /// `Arc<AtomicU8>` so that applying batch N does not clobber the
    /// state of batch N+1.
    log_completion: Option<Arc<AtomicU8>>,
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
/// Dirty pages are always deferred to [`flush()`](Self::flush).
pub struct PageCache<F: AsyncFile> {
    file: Arc<F>,
    /// Page map: `PageKey` → shared handle to the cached page mutex.
    pages: Mutex<HashMap<PageKey, Arc<Mutex<PageData>>>>,
    /// Tag → base file offset mapping.
    tags: Mutex<HashMap<u8, u64>>,
}

impl<F: AsyncFile> PageCache<F> {
    /// Create a new cache backed by the given file.
    pub fn new(file: Arc<F>) -> Self {
        Self {
            file,
            pages: Mutex::new(HashMap::new()),
            tags: Mutex::new(HashMap::new()),
        }
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
                        dirty: false,
                        log_completion: None,
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
    /// Collects all dirty pages from the cache, transitions them to InLog,
    /// and sends a `LogRequest::Flush` to the log task.
    ///
    /// Returns the FSN after the log entry is durable.
    pub async fn flush(&self, log_sender: &mesh::Sender<LogRequest>) -> Result<u64, VhdxError> {
        // Collect dirty pages.
        let dirty_pages = {
            let pages = self.pages.lock();
            let mut dirty = Vec::new();
            for (&key, entry) in pages.iter() {
                let mut page = entry.lock();
                // Drain any completed log signal from a previous batch.
                if let Some(ref completion) = page.log_completion {
                    let status = completion.load(Ordering::Acquire);
                    if status == LOG_APPLIED {
                        page.log_completion = None;
                    } else if status == LOG_FAILED {
                        page.log_completion = None;
                        page.dirty = true;
                    }
                    // LOG_PENDING: old batch still in flight — leave it.
                    // If the page is dirty we'll create a fresh signal below,
                    // replacing the old one (the old DirtyPage still holds
                    // its clone, which is fine — we don't read it anymore).
                }
                if page.dirty {
                    let file_offset = self.resolve_offset(key).map_err(VhdxError::Io)?;
                    let data = page.data.as_ref().expect("dirty page has no data").clone();
                    // Create a FRESH completion signal for this batch.
                    let completion = Arc::new(AtomicU8::new(LOG_PENDING));
                    page.log_completion = Some(completion.clone());
                    // Move per-page FSN to DirtyPage, clearing it from the cache.
                    let pre_log_fsn = page.pre_log_fsn.take();
                    page.dirty = false;
                    dirty.push(DirtyPage {
                        file_offset,
                        data,
                        state: completion,
                        pre_log_fsn,
                    });
                }
            }
            dirty
        };

        if dirty_pages.is_empty() {
            return Ok(0);
        }

        log_sender
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
        log_sender: &mesh::Sender<LogRequest>,
        pre_log_fsn: Option<u64>,
    ) -> Result<u64, VhdxError> {
        // Collect dirty pages.
        let dirty_pages = {
            let pages = self.pages.lock();
            let mut dirty = Vec::new();
            for (&key, entry) in pages.iter() {
                let mut page = entry.lock();
                // Drain any completed log signal from a previous batch.
                if let Some(ref completion) = page.log_completion {
                    let status = completion.load(Ordering::Acquire);
                    if status == LOG_APPLIED {
                        page.log_completion = None;
                    } else if status == LOG_FAILED {
                        page.log_completion = None;
                        page.dirty = true;
                    }
                }
                if page.dirty {
                    let file_offset = self.resolve_offset(key).map_err(VhdxError::Io)?;
                    let data = page.data.as_ref().expect("dirty page has no data").clone();
                    let completion = Arc::new(AtomicU8::new(LOG_PENDING));
                    page.log_completion = Some(completion.clone());
                    // Combine per-page FSN with argument FSN: use maximum.
                    let effective_fsn = match (page.pre_log_fsn.take(), pre_log_fsn) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (a, b) => a.or(b),
                    };
                    page.dirty = false;
                    dirty.push(DirtyPage {
                        file_offset,
                        data,
                        state: completion,
                        pre_log_fsn: effective_fsn,
                    });
                }
            }
            dirty
        };

        if dirty_pages.is_empty() {
            return Ok(0);
        }

        log_sender
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
        let mut guard = self.guard.take().expect("guard already released");

        if self.dirty {
            guard.dirty = true;
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
/// `commit()` is a no-op — the page is already marked dirty in the cache
/// by `release()`. The actual disk write happens through
/// [`PageCache::flush()`].
#[must_use = "call .commit().await to finalize the page write"]
pub struct PageCommit<'a, F: AsyncFile> {
    cache: &'a PageCache<F>,
    key: PageKey,
    was_dirty: bool,
}

impl<F: AsyncFile> PageCommit<'_, F> {
    /// Finalize the page write.
    ///
    /// This is a no-op — the page was already marked dirty by
    /// [`WritePageGuard::release()`]. The actual disk write happens
    /// through [`PageCache::flush()`].
    pub async fn commit(self) -> Result<(), std::io::Error> {
        // Suppress unused-field warnings.
        let _ = self.cache;
        let _ = self.key;
        let _ = self.was_dirty;
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

        // Re-read via cache to verify mutation is visible.
        let guard = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(guard[0], 0xAA);
        assert_eq!(guard[1], 0xBB);
        // Rest unchanged.
        assert_eq!(guard[2], 0x02);
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

        // Verify via cache re-read that the overwrite took effect.
        let guard = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert!(guard.iter().all(|&b| b == 0xCC));
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

        // Verify via cache re-read.
        let guard = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(guard[0], 0x22);
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

        // Verify via cache re-read.
        let guard = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(guard[0], 0xAA);
        assert_eq!(guard[1], 0xBB);
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

        // Verify both pages are independent via cache re-read.
        let g1 = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(g1[0], 0x11);
        drop(g1);

        let g2 = cache
            .acquire_read(PageKey {
                tag: 0,
                offset: PAGE_SIZE as u64,
            })
            .await
            .unwrap();
        assert_eq!(g2[0], 0x22);
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

    /// Regression test: when the same cache page is flushed in two
    /// consecutive batches, applying batch 1 (state → APPLIED) must
    /// not clobber batch 2's PENDING state. Each flush must create a
    /// **fresh** `Arc<AtomicU8>` so that the log task's store on a
    /// completed batch is invisible to newer batches.
    #[async_test]
    async fn flush_batches_have_independent_state() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);
        let mut cache = PageCache::new(Arc::new(file));
        cache.register_tag(0, 0);
        let key = PageKey { tag: 0, offset: 0 };

        let (tx, mut rx) = mesh::channel::<LogRequest>();

        // Write "A" and flush → batch 1.
        {
            let mut g = cache.acquire_write(key, WriteMode::Modify).await.unwrap();
            g.fill(0xAA);
            g.release().commit().await.unwrap();
        }
        let (flush1_result, batch1_pages) = futures::future::join(cache.flush(&tx), async {
            match rx.recv().await.unwrap() {
                LogRequest::Flush(rpc) => {
                    let (pages, response) = rpc.split();
                    response.complete(Ok(1u64));
                    pages
                }
                _ => panic!("expected Flush request"),
            }
        })
        .await;
        flush1_result.unwrap();
        assert_eq!(batch1_pages.len(), 1, "batch 1 should have one page");

        // Write "B" (re-dirty the same page) and flush → batch 2.
        {
            let mut g = cache.acquire_write(key, WriteMode::Modify).await.unwrap();
            g.fill(0xBB);
            g.release().commit().await.unwrap();
        }
        let (flush2_result, batch2_pages) = futures::future::join(cache.flush(&tx), async {
            match rx.recv().await.unwrap() {
                LogRequest::Flush(rpc) => {
                    let (pages, response) = rpc.split();
                    response.complete(Ok(2u64));
                    pages
                }
                _ => panic!("expected Flush request"),
            }
        })
        .await;
        flush2_result.unwrap();
        assert_eq!(batch2_pages.len(), 1, "batch 2 should have one page");

        // Both batches should have LOG_PENDING (fresh Arcs, not shared).
        assert_eq!(
            batch1_pages[0].state.load(Ordering::Acquire),
            LOG_PENDING,
            "batch 1 page should be LOG_PENDING"
        );
        assert_eq!(
            batch2_pages[0].state.load(Ordering::Acquire),
            LOG_PENDING,
            "batch 2 page should be LOG_PENDING before any apply"
        );

        // The two Arcs must NOT be the same allocation.
        assert!(
            !Arc::ptr_eq(&batch1_pages[0].state, &batch2_pages[0].state),
            "batches must have independent state Arcs"
        );

        // Simulate applying batch 1 (as apply_batch does).
        batch1_pages[0].state.store(LOG_APPLIED, Ordering::Release);

        // CRITICAL INVARIANT: batch 2's state must still be LOG_PENDING.
        assert_eq!(
            batch2_pages[0].state.load(Ordering::Acquire),
            LOG_PENDING,
            "applying batch 1 must not clobber batch 2's LOG_PENDING state"
        );
    }
}
