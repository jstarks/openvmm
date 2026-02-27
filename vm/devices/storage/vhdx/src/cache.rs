// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generic page cache for VHDX metadata pages.
//!
//! Provides a hash-table-backed, page-granularity (4 KiB) caching layer over
//! an [`AsyncFile`]. Pages are identified by a [`PageKey`] consisting of a tag
//! (u8) and an offset within a tagged region. Tags map to base file offsets,
//! allowing region relocation without invalidating cached pages.
//!
//! This module is fully generic — it has no VHDX-specific knowledge and depends
//! only on [`AsyncFile`] from the crate root.

use crate::AsyncFile;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

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

/// Access mode for page acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    /// Shared read access. Page is loaded from file if not cached.
    Read,
    /// Exclusive write access. Page is loaded from file if not cached.
    Modify,
    /// Exclusive write access. Page is NOT loaded from file (caller
    /// will overwrite the entire page).
    Overwrite,
}

/// Internal per-page data.
struct PageData {
    /// The page contents. `None` if the page has not been loaded yet.
    data: Option<Box<[u8; PAGE_SIZE]>>,
}

/// Write-through page cache backed by an [`AsyncFile`].
///
/// Pages are loaded on first access and kept in memory indefinitely (no
/// eviction). Modified pages are written back to the file when the guard
/// is released via [`PageGuard::release()`].
pub struct PageCache<F: AsyncFile> {
    file: F,
    /// Page map: `PageKey` → shared handle to the cached page mutex.
    pages: Mutex<HashMap<PageKey, Arc<Mutex<PageData>>>>,
    /// Tag → base file offset mapping.
    tags: Mutex<HashMap<u8, u64>>,
}

impl<F: AsyncFile> PageCache<F> {
    /// Create a new cache backed by the given file.
    pub fn new(file: F) -> Self {
        Self {
            file,
            pages: Mutex::new(HashMap::new()),
            tags: Mutex::new(HashMap::new()),
        }
    }

    /// Register a tag with its base file offset.
    ///
    /// Must be called before any [`acquire()`](Self::acquire) with that tag.
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
    fn resolve_offset(&self, key: PageKey) -> Result<u64, std::io::Error> {
        let tags = self.tags.lock();
        let base = tags.get(&key.tag).ok_or_else(|| {
            std::io::Error::other(format!("cache tag {} not registered", key.tag))
        })?;
        Ok(base + key.offset)
    }

    /// Acquire access to a page.
    ///
    /// Returns a [`PageGuard`] that provides `&[u8; PAGE_SIZE]` (for read) or
    /// `&mut [u8; PAGE_SIZE]` (for modify/overwrite). The caller **must** call
    /// [`PageGuard::release()`] when done — dropping the guard without
    /// releasing it will panic in debug builds.
    ///
    /// The returned guard holds the page's mutex via an [`ArcMutexGuard`],
    /// giving zero-copy access to the cached data. Only dirty releases
    /// perform a copy (to avoid holding the sync lock across the async
    /// file write).
    pub async fn acquire(
        &self,
        key: PageKey,
        mode: AccessMode,
    ) -> Result<PageGuard<'_, F>, std::io::Error> {
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
                .or_insert_with(|| Arc::new(Mutex::new(PageData { data: None })))
                .clone()
        };

        // Load the page from disk if necessary. We do the async I/O
        // *before* acquiring the long-held ArcMutexGuard so we never
        // hold a sync lock across an await point.
        match mode {
            AccessMode::Read | AccessMode::Modify => {
                let needs_load = entry.lock().data.is_none();
                if needs_load {
                    let mut buf = Box::new([0u8; PAGE_SIZE]);
                    self.file.read_at(file_offset, buf.as_mut_slice()).await?;

                    let mut page = entry.lock();
                    // Another task may have loaded while we were reading.
                    if page.data.is_none() {
                        page.data = Some(buf);
                    }
                }
            }
            AccessMode::Overwrite => {
                let mut page = entry.lock();
                if page.data.is_none() {
                    page.data = Some(Box::new([0u8; PAGE_SIZE]));
                }
            }
        }

        // Acquire the page lock for the lifetime of the guard.
        let guard = Mutex::lock_arc(&entry);

        Ok(PageGuard {
            cache: self,
            key,
            guard: Some(guard),
            writable: mode != AccessMode::Read,
            dirty: false,
            released: false,
        })
    }

    /// Ensure all previously written pages are durable on disk.
    ///
    /// In write-through mode every [`PageGuard::release()`] already writes the
    /// page data to the file. This method calls `file.flush()` to ensure
    /// OS-level durability.
    ///
    /// The caller must ensure all guards have been released before calling
    /// this.
    pub async fn flush(&self) -> Result<(), std::io::Error> {
        self.file.flush().await
    }
}

/// RAII guard providing access to a cached page.
///
/// Provides `Deref<Target = [u8; PAGE_SIZE]>` for read access and `DerefMut`
/// when the page was acquired with [`AccessMode::Modify`] or
/// [`AccessMode::Overwrite`].
///
/// The caller **must** call [`release()`](Self::release) to write dirty pages
/// back to the file and release the page lock. Dropping without releasing
/// panics in debug builds.
pub struct PageGuard<'a, F: AsyncFile> {
    cache: &'a PageCache<F>,
    key: PageKey,
    /// Arc-owned mutex guard — keeps the `Arc<Mutex<PageData>>` alive and
    /// the lock held, giving zero-copy access to the cached page data.
    guard: Option<parking_lot::ArcMutexGuard<parking_lot::RawMutex, PageData>>,
    /// Whether the guard permits mutation (acquired with Modify or Overwrite).
    writable: bool,
    /// Whether the page has actually been mutated (set on first `DerefMut`).
    dirty: bool,
    /// Set to `true` by [`release()`](Self::release).
    released: bool,
}

impl<F: AsyncFile> PageGuard<'_, F> {
    /// Write the page back to the file (if dirty) and release the page lock.
    ///
    /// This is the only correct way to finish using a `PageGuard`. Dropping
    /// the guard without calling this method panics in debug builds.
    pub async fn release(mut self) -> Result<(), std::io::Error> {
        let guard = self.guard.take().expect("guard already released");
        self.released = true;

        if self.dirty {
            // Copy the data so we can release the sync lock before
            // the async file write.
            let data = guard.data.as_ref().expect("page data missing").clone();
            drop(guard);

            let file_offset = self.cache.resolve_offset(self.key)?;
            self.cache
                .file
                .write_at(file_offset, data.as_slice())
                .await?;
        }
        // If not dirty, `guard` is dropped here, releasing the lock.
        Ok(())
    }
}

impl<F: AsyncFile> std::ops::Deref for PageGuard<'_, F> {
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

impl<F: AsyncFile> std::ops::DerefMut for PageGuard<'_, F> {
    fn deref_mut(&mut self) -> &mut [u8; PAGE_SIZE] {
        assert!(self.writable, "cannot mutate a read-only page guard");
        self.dirty = true;
        self.guard
            .as_mut()
            .expect("guard already released")
            .data
            .as_mut()
            .expect("page data missing")
    }
}

impl<F: AsyncFile> Drop for PageGuard<'_, F> {
    fn drop(&mut self) {
        if !self.released {
            // The ArcMutexGuard is dropped here, releasing the lock.
            // But dirty data may be lost since we can't do async I/O in Drop.
            if self.dirty {
                debug_assert!(
                    false,
                    "dirty PageGuard dropped without calling release() — data may be lost"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::support::{FailingInterceptor, InMemoryFile};
    use pal_async::async_test;

    #[async_test]
    async fn acquire_read_loads_from_file() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);
        // Write a known pattern at offset 0.
        let pattern: Vec<u8> = (0..PAGE_SIZE).map(|i| (i & 0xFF) as u8).collect();
        file.write_at(0, &pattern).await.unwrap();

        let mut cache = PageCache::new(file);
        cache.register_tag(0, 0);

        let guard = cache
            .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Read)
            .await
            .unwrap();
        assert_eq!(&guard[..], &pattern[..]);
        guard.release().await.unwrap();
    }

    #[async_test]
    async fn acquire_modify_loads_and_writes_back() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);
        let pattern: Vec<u8> = (0..PAGE_SIZE).map(|i| (i & 0xFF) as u8).collect();
        file.write_at(0, &pattern).await.unwrap();

        let mut cache = PageCache::new(file);
        cache.register_tag(0, 0);

        {
            let mut guard = cache
                .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Modify)
                .await
                .unwrap();
            // Verify data was loaded.
            assert_eq!(guard[0], 0x00);
            assert_eq!(guard[1], 0x01);
            // Mutate.
            guard[0] = 0xAA;
            guard[1] = 0xBB;
            guard.release().await.unwrap();
        }

        // Read directly from the file to verify write-through.
        let snap = cache.file.snapshot();
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
            }),
        );

        let mut cache = PageCache::new(file);
        cache.register_tag(0, 0);

        // Overwrite should succeed even though reads fail.
        let mut guard = cache
            .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Overwrite)
            .await
            .unwrap();
        guard.fill(0xCC);
        guard.release().await.unwrap();

        // Verify the data was written to the file.
        let snap = cache.file.snapshot();
        assert!(snap.iter().all(|&b| b == 0xCC));
    }

    #[async_test]
    async fn concurrent_reads_return_correct_data() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);
        let pattern: Vec<u8> = (0..PAGE_SIZE).map(|i| ((i * 3) & 0xFF) as u8).collect();
        file.write_at(0, &pattern).await.unwrap();

        let mut cache = PageCache::new(file);
        cache.register_tag(0, 0);

        // First read loads from file.
        let g1 = cache
            .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Read)
            .await
            .unwrap();
        assert_eq!(&g1[..], &pattern[..]);
        g1.release().await.unwrap();

        // Second read uses cached data.
        let g2 = cache
            .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Read)
            .await
            .unwrap();
        assert_eq!(&g2[..], &pattern[..]);
        g2.release().await.unwrap();
    }

    #[async_test]
    async fn sequential_modify_acquires_work() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);

        let mut cache = PageCache::new(file);
        cache.register_tag(0, 0);

        // First modify.
        {
            let mut guard = cache
                .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Modify)
                .await
                .unwrap();
            guard[0] = 0x11;
            guard.release().await.unwrap();
        }

        // Second modify on the same page.
        {
            let mut guard = cache
                .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Modify)
                .await
                .unwrap();
            // Should see the previously written value.
            assert_eq!(guard[0], 0x11);
            guard[0] = 0x22;
            guard.release().await.unwrap();
        }

        let snap = cache.file.snapshot();
        assert_eq!(snap[0], 0x22);
    }

    #[async_test]
    async fn modify_then_modify_same_page() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);

        let mut cache = PageCache::new(file);
        cache.register_tag(0, 0);

        {
            let mut g = cache
                .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Modify)
                .await
                .unwrap();
            g[0] = 0xAA;
            g.release().await.unwrap();
        }

        {
            let mut g = cache
                .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Modify)
                .await
                .unwrap();
            assert_eq!(g[0], 0xAA);
            g[1] = 0xBB;
            g.release().await.unwrap();
        }

        let snap = cache.file.snapshot();
        assert_eq!(snap[0], 0xAA);
        assert_eq!(snap[1], 0xBB);
    }

    #[async_test]
    async fn different_pages_independent() {
        let file = InMemoryFile::new(PAGE_SIZE as u64 * 4);

        let mut cache = PageCache::new(file);
        cache.register_tag(0, 0);

        // Write to page at offset 0.
        {
            let mut g = cache
                .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Modify)
                .await
                .unwrap();
            g[0] = 0x11;
            g.release().await.unwrap();
        }

        // Write to page at offset PAGE_SIZE.
        {
            let mut g = cache
                .acquire(
                    PageKey {
                        tag: 0,
                        offset: PAGE_SIZE as u64,
                    },
                    AccessMode::Modify,
                )
                .await
                .unwrap();
            g[0] = 0x22;
            g.release().await.unwrap();
        }

        // Verify both pages are independent.
        let snap = cache.file.snapshot();
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

        let mut cache = PageCache::new(file);
        cache.register_tag(0, base);

        let guard = cache
            .acquire(
                PageKey {
                    tag: 0,
                    offset: page_offset,
                },
                AccessMode::Read,
            )
            .await
            .unwrap();
        assert_eq!(&guard[..], &pattern[..]);
        guard.release().await.unwrap();
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

        let mut cache = PageCache::new(file);
        cache.register_tag(0, old_base);

        // Read from old base.
        {
            let guard = cache
                .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Read)
                .await
                .unwrap();
            assert_eq!(guard[0], 0xAA);
            guard.release().await.unwrap();
        }

        // Invalidate the cached page by creating a fresh cache (update_tag_offset
        // doesn't invalidate). For a true relocation test, use a fresh cache.
        let mut cache = PageCache::new(cache.file);
        cache.register_tag(0, old_base);
        cache.update_tag_offset(0, new_base);

        let guard = cache
            .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Read)
            .await
            .unwrap();
        assert_eq!(guard[0], 0xBB);
        guard.release().await.unwrap();
    }

    #[async_test]
    async fn write_through_then_read_back() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);

        let mut cache = PageCache::new(file);
        cache.register_tag(0, 0);

        // Modify and release (write-through).
        {
            let mut guard = cache
                .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Modify)
                .await
                .unwrap();
            guard[42] = 0xFF;
            guard.release().await.unwrap();
        }

        // Verify the file was updated.
        let snap = cache.file.snapshot();
        assert_eq!(snap[42], 0xFF);

        // Re-acquire as Read and verify cached data.
        let guard = cache
            .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Read)
            .await
            .unwrap();
        assert_eq!(guard[42], 0xFF);
        guard.release().await.unwrap();
    }

    #[async_test]
    async fn flush_delegates_to_file() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);
        let mut cache = PageCache::new(file);
        cache.register_tag(0, 0);

        // Write some data, release, then flush.
        let mut guard = cache
            .acquire(PageKey { tag: 0, offset: 0 }, AccessMode::Modify)
            .await
            .unwrap();
        guard[0] = 0x42;
        guard.release().await.unwrap();

        // flush() should succeed (delegates to InMemoryFile::flush which is a no-op).
        cache.flush().await.unwrap();

        let snap = cache.file.snapshot();
        assert_eq!(snap[0], 0x42);
    }
}
