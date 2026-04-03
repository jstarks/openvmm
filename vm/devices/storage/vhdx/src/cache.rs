// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Write-back page cache for VHDX metadata pages.
//!
//! Provides a hash-table-backed, page-granularity (4 KiB) caching layer over
//! an [`AsyncFile`]. Pages are identified by a [`PageKey`] consisting of a tag
//! (u8) and an offset within a tagged region. Tags map to base file offsets,
//! allowing region relocation without invalidating cached pages.
//!
//! Modified pages accumulate as **Dirty** in the cache. On [`commit()`](PageCache::commit),
//! dirty pages are sent to the log task via a mesh channel for WAL persistence.
//! The log task applies them to their final file offsets in the background.
//!
//! Page data is stored as `Arc<[u8; PAGE_SIZE]>` to enable zero-copy commit
//! (Arc::clone) and implicit COW (Arc::make_mut) when a page is modified while
//! the log task holds a reference.
//!
//! # Write Ordering
//!
//! The cache guarantees that writes are **ordered** through the log. If a
//! caller writes page A, then later writes page B, the only crash-recovery
//! outcomes are: {neither}, {A only}, or {both A and B}. It is never the case
//! that B is persisted without A.
//!
//! This ordering is maintained by **eager commit**: when the dirty page count
//! reaches [`MAX_COMMIT_PAGES`] and a new page is about to become dirty, the
//! cache automatically commits the current dirty set to the log before
//! allowing the new page to enter the dirty set.

use crate::AsyncFile;
use crate::error::VhdxError;
use crate::log_permits::LogPermits;
use crate::log_task::CommittedPage;
use crate::log_task::LogRequest;
use crate::log_task::Transaction;
use crate::lsn_watermark::LsnWatermark;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

/// Page size used by the cache (4 KiB).
pub const PAGE_SIZE: usize = 4096;

/// Maximum number of dirty pages per commit batch.
///
/// Derived from 1/4 of the minimum 1 MiB VHDX log. With 0 zero ranges:
///   entry_length(N) = ceil((64 + 32*N) / 4096) * 4096 + N * 4096
///   (N+1)*4096 + 4096 (guard) ≤ 262144  →  N ≤ 62
///
/// Used as the initial permit count for [`LogPermits`].
pub const MAX_COMMIT_PAGES: usize = 62;

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

/// Per-page lifecycle state.
///
/// Encodes both the dirty flag and the permit state as a single enum
/// to prevent invalid combinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PageState {
    /// Page is clean. No permit held, not dirty.
    Clean,
    /// Page data is being loaded from disk by another task.
    /// Other acquirers wait on `state_event`.
    Loading,
    /// A log permit is being acquired for this page.
    /// Other acquirers wait on `state_event`.
    AcquiringPermit,
    /// A log permit has been acquired but the page has not been mutated yet.
    /// The `WritePageGuard` holds the page lock. On drop:
    /// - If mutated → transitions to `Dirty`.
    /// - If not mutated → transitions to `Clean` (permit refunded).
    HasPermit,
    /// Page has been modified. A permit is consumed (transfers to the log
    /// task on commit).
    Dirty,
}

/// Internal per-page data.
struct PageData {
    /// The page contents as `Arc` for zero-copy commit and COW.
    /// `None` if the page has not been loaded yet.
    data: Option<Arc<[u8; PAGE_SIZE]>>,
    /// Page lifecycle state.
    state: PageState,
    /// If set, the log task must wait for this FSN to complete before
    /// including this page in a log entry.
    pre_log_fsn: Option<u64>,
    /// The LSN of the most recent commit that included this page.
    committed_lsn: Option<u64>,
}

/// Internal page map wrapping the `HashMap` and a dirty page counter.
struct PageMap {
    map: HashMap<PageKey, Arc<Mutex<PageData>>>,
    dirty_count: usize,
}

/// Write-back page cache backed by an [`AsyncFile`].
pub struct PageCache<F: AsyncFile> {
    pub(crate) file: Arc<F>,
    pages: Mutex<PageMap>,
    tags: Mutex<HashMap<u8, u64>>,
    log_sender: Option<mesh::Sender<LogRequest>>,
    log_permits: Option<Arc<LogPermits>>,
    logged_lsn: Option<Arc<LsnWatermark>>,
    lsn_counter: std::sync::atomic::AtomicU64,
    /// Notified when a page transitions out of `Loading` or `AcquiringPermit`.
    state_event: event_listener::Event,
}

impl<F: AsyncFile> PageCache<F> {
    /// Create a new cache backed by the given file.
    pub fn new(
        file: Arc<F>,
        log_sender: Option<mesh::Sender<LogRequest>>,
        log_permits: Option<Arc<LogPermits>>,
        logged_lsn: Option<Arc<LsnWatermark>>,
    ) -> Self {
        Self {
            file,
            pages: Mutex::new(PageMap {
                map: HashMap::new(),
                dirty_count: 0,
            }),
            tags: Mutex::new(HashMap::new()),
            log_sender,
            log_permits,
            logged_lsn,
            lsn_counter: std::sync::atomic::AtomicU64::new(0),
            state_event: event_listener::Event::new(),
        }
    }

    /// Take the log sender out of the cache, returning it.
    pub fn take_log_sender(&mut self) -> Option<mesh::Sender<LogRequest>> {
        self.log_sender.take()
    }

    /// Set the log permits (for late initialization after log task spawn).
    pub fn set_log_permits(&mut self, permits: Arc<LogPermits>) {
        self.log_permits = Some(permits);
    }

    /// Set the logged LSN watermark (for late initialization after log task spawn).
    pub fn set_logged_lsn(&mut self, lsn: Arc<LsnWatermark>) {
        self.logged_lsn = Some(lsn);
    }

    /// Register a tag with its base file offset.
    pub fn register_tag(&mut self, tag: u8, base_offset: u64) {
        self.tags.lock().insert(tag, base_offset);
    }

    /// Update the base file offset for a previously registered tag.
    #[allow(dead_code)]
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

    /// Get or create the page entry in the map.
    fn get_or_create_entry(
        &self,
        key: PageKey,
    ) -> Result<(u64, Arc<Mutex<PageData>>), std::io::Error> {
        if !key.offset.is_multiple_of(PAGE_SIZE as u64) {
            return Err(std::io::Error::other(format!(
                "page offset {:#x} is not {PAGE_SIZE}-byte aligned",
                key.offset
            )));
        }
        let file_offset = self.resolve_offset(key)?;
        let entry = {
            let mut pages = self.pages.lock();
            pages
                .map
                .entry(key)
                .or_insert_with(|| {
                    Arc::new(Mutex::new(PageData {
                        data: None,
                        state: PageState::Clean,
                        pre_log_fsn: None,
                        committed_lsn: None,
                    }))
                })
                .clone()
        };
        Ok((file_offset, entry))
    }

    /// Acquire read access to a page.
    pub async fn acquire_read(&self, key: PageKey) -> Result<ReadPageGuard, std::io::Error> {
        let (file_offset, entry) = self.get_or_create_entry(key)?;

        let guard = loop {
            let mut guard = Mutex::lock_arc(&entry);
            match guard.state {
                PageState::Loading | PageState::AcquiringPermit => {
                    let listener = self.state_event.listen();
                    drop(guard);
                    listener.await;
                    continue;
                }
                _ => {
                    if guard.data.is_some() {
                        break guard;
                    }
                    // Need to load data from disk.
                    guard.state = PageState::Loading;
                    drop(guard);

                    let mut buf = [0u8; PAGE_SIZE];
                    let result = self.file.read_at(file_offset, &mut buf).await;

                    let mut page = entry.lock();
                    if page.data.is_none() {
                        match result {
                            Ok(()) => page.data = Some(Arc::new(buf)),
                            Err(e) => {
                                page.state = PageState::Clean;
                                self.state_event.notify(usize::MAX);
                                return Err(e);
                            }
                        }
                    }
                    if page.state == PageState::Loading {
                        page.state = PageState::Clean;
                    }
                    drop(page);
                    self.state_event.notify(usize::MAX);
                    continue;
                }
            }
        };

        Ok(ReadPageGuard { guard })
    }

    /// Acquire write access to a page.
    ///
    /// If a log is configured, acquires a permit (backpressure). If dirty
    /// pages have accumulated, triggers an eager commit first.
    pub async fn acquire_write(
        &self,
        key: PageKey,
        mode: WriteMode,
    ) -> Result<WritePageGuard<'_, F>, std::io::Error> {
        let load = mode == WriteMode::Modify;
        let (file_offset, entry) = self.get_or_create_entry(key)?;

        let guard = loop {
            let mut guard = Mutex::lock_arc(&entry);

            match guard.state {
                PageState::Loading | PageState::AcquiringPermit => {
                    // Another task is doing async work on this page. Wait.
                    let listener = self.state_event.listen();
                    drop(guard);
                    listener.await;
                    continue;
                }

                PageState::Dirty | PageState::HasPermit => {
                    // Already has a permit. Data must be loaded already.
                    assert!(
                        guard.data.is_some(),
                        "page in state {:?} has no data",
                        guard.state
                    );
                    break guard;
                }

                PageState::Clean => {
                    // Ensure data loaded.
                    if guard.data.is_none() {
                        if load {
                            guard.state = PageState::Loading;
                            drop(guard);
                            let mut buf = [0u8; PAGE_SIZE];
                            self.file.read_at(file_offset, &mut buf).await?;
                            let mut page = entry.lock();
                            if page.data.is_none() {
                                page.data = Some(Arc::new(buf));
                            }
                            if page.state == PageState::Loading {
                                page.state = PageState::Clean;
                            }
                            self.state_event.notify(usize::MAX);
                            continue;
                        } else {
                            guard.data = Some(Arc::new([0u8; PAGE_SIZE]));
                        }
                    }

                    // Log is required for writes.
                    let permits = self.log_permits.as_ref().ok_or_else(|| {
                        std::io::Error::other(
                            "acquire_write requires a log task (use open_writable)",
                        )
                    })?;

                    // Eager commit: ship accumulated dirty pages first.
                    let should_commit = {
                        let dirty_count = self.pages.lock().dirty_count;
                        dirty_count >= MAX_COMMIT_PAGES && self.log_sender.is_some()
                    };
                    if should_commit {
                        guard.state = PageState::AcquiringPermit;
                        drop(guard);
                        self.commit().await.map_err(|e| match e {
                            VhdxError::Io(io) => io,
                            other => std::io::Error::other(other.to_string()),
                        })?;
                        let mut page = entry.lock();
                        if page.state != PageState::AcquiringPermit {
                            self.state_event.notify(usize::MAX);
                            continue;
                        }
                        drop(page);

                        let result = permits.acquire(1).await;
                        {
                            let mut page = entry.lock();
                            if result.is_ok() {
                                page.state = PageState::HasPermit;
                            } else {
                                page.state = PageState::Clean;
                            }
                        }
                        self.state_event.notify(usize::MAX);
                        result.map_err(|e| match e {
                            VhdxError::Io(io) => io,
                            other => std::io::Error::other(other.to_string()),
                        })?;
                        continue;
                    }

                    // No eager commit needed. Acquire permit directly.
                    guard.state = PageState::AcquiringPermit;
                    drop(guard);

                    let result = permits.acquire(1).await;
                    {
                        let mut page = entry.lock();
                        if result.is_ok() {
                            page.state = PageState::HasPermit;
                        } else {
                            page.state = PageState::Clean;
                        }
                    }
                    self.state_event.notify(usize::MAX);
                    result.map_err(|e| match e {
                        VhdxError::Io(io) => io,
                        other => std::io::Error::other(other.to_string()),
                    })?;
                    continue;
                }
            }
        };

        Ok(WritePageGuard {
            cache: self,
            guard: Some(guard),
            mutated: false,
        })
    }

    /// Set the pre-log FSN on a specific page.
    pub fn set_pre_log_fsn(&self, key: PageKey, fsn: u64) {
        let pages = self.pages.lock();
        if let Some(entry) = pages.map.get(&key) {
            let mut page = entry.lock();
            page.pre_log_fsn = Some(match page.pre_log_fsn {
                Some(existing) => existing.max(fsn),
                None => fsn,
            });
        }
    }

    /// Get the pre-log FSN for a specific page, if set.
    #[allow(dead_code)]
    pub fn get_pre_log_fsn(&self, key: PageKey) -> Option<u64> {
        let pages = self.pages.lock();
        if let Some(entry) = pages.map.get(&key) {
            let page = entry.lock();
            page.pre_log_fsn
        } else {
            None
        }
    }

    /// Commit all dirty pages to the log task (fire-and-forget).
    ///
    /// Returns the assigned LSN, or 0 if there were no dirty pages.
    pub async fn commit(&self) -> Result<u64, VhdxError> {
        let log_sender = self
            .log_sender
            .as_ref()
            .ok_or_else(|| VhdxError::Io(std::io::Error::other("no log sender configured")))?;

        let (committed_pages, pre_log_fsn, lsn) = {
            let lsn = self
                .lsn_counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;

            let mut pages = self.pages.lock();
            let mut committed = Vec::new();
            let mut max_pre_log_fsn: Option<u64> = None;

            for (&key, entry) in pages.map.iter() {
                let mut page = entry.lock();
                if page.state == PageState::Dirty {
                    let file_offset = self.resolve_offset(key).map_err(VhdxError::Io)?;
                    let data = page.data.as_ref().expect("dirty page has no data").clone();

                    if let Some(fsn) = page.pre_log_fsn.take() {
                        max_pre_log_fsn = Some(max_pre_log_fsn.map_or(fsn, |m: u64| m.max(fsn)));
                    }

                    page.state = PageState::Clean;
                    page.committed_lsn = Some(lsn);
                    committed.push(CommittedPage { file_offset, data });
                }
            }

            if committed.is_empty() {
                return Ok(0);
            }

            pages.dirty_count -= committed.len();
            (committed, max_pre_log_fsn, lsn)
        };

        log_sender.send(LogRequest::Commit(Transaction {
            lsn,
            pages: committed_pages,
            pre_log_fsn,
        }));

        Ok(lsn)
    }

    /// Wait for the log task to durably write everything through `lsn`.
    pub async fn wait_for_lsn(&self, lsn: u64) -> Result<(), VhdxError> {
        if lsn == 0 {
            return Ok(());
        }
        if let Some(ref logged_lsn) = self.logged_lsn {
            logged_lsn.wait_for(lsn).await?;
        }
        Ok(())
    }

    /// Returns `true` if the cache has a log sender configured.
    pub fn has_log_sender(&self) -> bool {
        self.log_sender.is_some()
    }
}

/// RAII guard providing read-only access to a cached page.
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
/// Mutating via `DerefMut` transitions the page to `Dirty` (if it has
/// a permit via `HasPermit`). Arc COW ensures the writer gets a private
/// copy if the log task holds a reference.
pub struct WritePageGuard<'a, F: AsyncFile> {
    cache: &'a PageCache<F>,
    guard: Option<parking_lot::ArcMutexGuard<parking_lot::RawMutex, PageData>>,
    /// Set to true by `DerefMut`.
    mutated: bool,
}

impl<F: AsyncFile> std::ops::Deref for WritePageGuard<'_, F> {
    type Target = [u8; PAGE_SIZE];

    fn deref(&self) -> &[u8; PAGE_SIZE] {
        self.guard
            .as_ref()
            .expect("guard consumed")
            .data
            .as_ref()
            .expect("page data missing")
    }
}

impl<F: AsyncFile> std::ops::DerefMut for WritePageGuard<'_, F> {
    fn deref_mut(&mut self) -> &mut [u8; PAGE_SIZE] {
        let guard = self.guard.as_mut().expect("guard consumed");

        // Transition HasPermit → Dirty on first mutation.
        if !self.mutated {
            self.mutated = true;
            if guard.state == PageState::HasPermit {
                guard.state = PageState::Dirty;
                self.cache.pages.lock().dirty_count += 1;
            }
            // If state is Dirty (re-acquire on already-dirty page), no-op.
            // If state is Clean (no log configured), no-op.
        }

        Arc::make_mut(guard.data.as_mut().expect("page data missing"))
    }
}

impl<F: AsyncFile> Drop for WritePageGuard<'_, F> {
    fn drop(&mut self) {
        if let Some(mut guard) = self.guard.take() {
            if guard.state == PageState::HasPermit {
                // Guard dropped without mutation. Refund the permit.
                guard.state = PageState::Clean;
                drop(guard);
                if let Some(ref permits) = self.cache.log_permits {
                    permits.release(1);
                }
                self.cache.state_event.notify(usize::MAX);
            }
            // Dirty or Clean: nothing to do. Guard drops, releasing the lock.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::support::{FailingInterceptor, InMemoryFile};
    use pal_async::async_test;
    use std::sync::Arc;

    /// Helper to create a writable cache with log sender + permits.
    fn writable_cache(file: InMemoryFile) -> (PageCache<InMemoryFile>, mesh::Receiver<LogRequest>) {
        let (tx, rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let cache = PageCache::new(Arc::new(file), Some(tx), Some(permits), None);
        (cache, rx)
    }

    #[async_test]
    async fn acquire_read_loads_from_file() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);
        let pattern: Vec<u8> = (0..PAGE_SIZE).map(|i| (i & 0xFF) as u8).collect();
        file.write_at(0, &pattern).await.unwrap();

        let mut cache = PageCache::new(Arc::new(file), None, None, None);
        cache.register_tag(0, 0);

        let guard = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(&guard[..], &pattern[..]);
    }

    #[async_test]
    async fn acquire_modify_loads_and_writes_back() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);
        let pattern: Vec<u8> = (0..PAGE_SIZE).map(|i| (i & 0xFF) as u8).collect();
        file.write_at(0, &pattern).await.unwrap();

        let (mut cache, _rx) = writable_cache(InMemoryFile::new(PAGE_SIZE as u64));
        // Re-create with the patterned file.
        let file = InMemoryFile::new(PAGE_SIZE as u64);
        file.write_at(0, &pattern).await.unwrap();
        let (tx, _rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        cache = PageCache::new(Arc::new(file), Some(tx), Some(permits), None);
        cache.register_tag(0, 0);

        {
            let mut guard = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Modify)
                .await
                .unwrap();
            assert_eq!(guard[0], 0x00);
            assert_eq!(guard[1], 0x01);
            guard[0] = 0xAA;
            guard[1] = 0xBB;
        }

        let guard = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(guard[0], 0xAA);
        assert_eq!(guard[1], 0xBB);
        assert_eq!(guard[2], 0x02);
    }

    #[async_test]
    async fn acquire_overwrite_skips_read() {
        let file = InMemoryFile::with_interceptor(
            PAGE_SIZE as u64,
            Box::new(FailingInterceptor {
                fail_reads: true,
                fail_writes: false,
                fail_flushes: false,
                fail_set_file_size: false,
            }),
        );

        let (tx, _rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(Arc::new(file), Some(tx), Some(permits), None);
        cache.register_tag(0, 0);

        {
            let mut guard = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Overwrite)
                .await
                .unwrap();
            guard.fill(0xCC);
        }

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

        let mut cache = PageCache::new(Arc::new(file), None, None, None);
        cache.register_tag(0, 0);

        let g1 = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(&g1[..], &pattern[..]);
        drop(g1);

        let g2 = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(&g2[..], &pattern[..]);
    }

    #[async_test]
    async fn sequential_modify_acquires_work() {
        let (tx, _rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64)),
            Some(tx),
            Some(permits),
            None,
        );
        cache.register_tag(0, 0);

        {
            let mut guard = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Modify)
                .await
                .unwrap();
            guard[0] = 0x11;
        }

        {
            let mut guard = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Modify)
                .await
                .unwrap();
            assert_eq!(guard[0], 0x11);
            guard[0] = 0x22;
        }

        let guard = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(guard[0], 0x22);
    }

    #[async_test]
    async fn modify_then_modify_same_page() {
        let (tx, _rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64)),
            Some(tx),
            Some(permits),
            None,
        );
        cache.register_tag(0, 0);

        {
            let mut g = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Modify)
                .await
                .unwrap();
            g[0] = 0xAA;
        }

        {
            let mut g = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Modify)
                .await
                .unwrap();
            assert_eq!(g[0], 0xAA);
            g[1] = 0xBB;
        }

        let guard = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(guard[0], 0xAA);
        assert_eq!(guard[1], 0xBB);
    }

    #[async_test]
    async fn different_pages_independent() {
        let (tx, _rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64 * 4)),
            Some(tx),
            Some(permits),
            None,
        );
        cache.register_tag(0, 0);

        {
            let mut g = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Modify)
                .await
                .unwrap();
            g[0] = 0x11;
        }

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
        }

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
        let pattern = [0xDE; PAGE_SIZE];
        file.write_at(base + page_offset, &pattern).await.unwrap();

        let mut cache = PageCache::new(Arc::new(file), None, None, None);
        cache.register_tag(0, base);

        let guard = cache
            .acquire_read(PageKey {
                tag: 0,
                offset: page_offset,
            })
            .await
            .unwrap();
        assert_eq!(&guard[..], &pattern[..]);
    }

    #[async_test]
    async fn update_tag_offset_test() {
        let old_base: u64 = 0x10000;
        let new_base: u64 = 0x20000;
        let file = InMemoryFile::new(new_base + PAGE_SIZE as u64);
        file.write_at(old_base, &[0xAA; PAGE_SIZE]).await.unwrap();
        file.write_at(new_base, &[0xBB; PAGE_SIZE]).await.unwrap();

        let mut cache = PageCache::new(Arc::new(file), None, None, None);
        cache.register_tag(0, old_base);

        {
            let guard = cache
                .acquire_read(PageKey { tag: 0, offset: 0 })
                .await
                .unwrap();
            assert_eq!(guard[0], 0xAA);
        }

        let mut cache = PageCache::new(cache.file.clone(), None, None, None);
        cache.register_tag(0, old_base);
        cache.update_tag_offset(0, new_base);

        let guard = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(guard[0], 0xBB);
    }

    #[async_test]
    async fn commit_sends_transaction() {
        let (tx, mut rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64)),
            Some(tx),
            Some(permits),
            None,
        );
        cache.register_tag(0, 0);
        let key = PageKey { tag: 0, offset: 0 };

        {
            let mut g = cache.acquire_write(key, WriteMode::Modify).await.unwrap();
            g.fill(0xAA);
        }
        let lsn = cache.commit().await.unwrap();
        assert!(lsn > 0);

        match rx.recv().await.unwrap() {
            LogRequest::Commit(txn) => {
                assert_eq!(txn.lsn, lsn);
                assert_eq!(txn.pages.len(), 1);
                assert!(txn.pages[0].data.iter().all(|&b| b == 0xAA));
            }
            _ => panic!("expected Commit"),
        }
    }

    #[async_test]
    async fn consecutive_commits_get_increasing_lsns() {
        let (tx, mut rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64)),
            Some(tx),
            Some(permits),
            None,
        );
        cache.register_tag(0, 0);
        let key = PageKey { tag: 0, offset: 0 };

        {
            let mut g = cache.acquire_write(key, WriteMode::Modify).await.unwrap();
            g.fill(0xAA);
        }
        let lsn1 = cache.commit().await.unwrap();

        {
            let mut g = cache.acquire_write(key, WriteMode::Modify).await.unwrap();
            g.fill(0xBB);
        }
        let lsn2 = cache.commit().await.unwrap();

        assert!(lsn2 > lsn1);

        match rx.recv().await.unwrap() {
            LogRequest::Commit(txn) => assert_eq!(txn.lsn, lsn1),
            _ => panic!("expected Commit"),
        }
        match rx.recv().await.unwrap() {
            LogRequest::Commit(txn) => assert_eq!(txn.lsn, lsn2),
            _ => panic!("expected Commit"),
        }
    }

    #[async_test]
    async fn commit_sets_committed_lsn() {
        let (tx, _rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64)),
            Some(tx),
            Some(permits),
            None,
        );
        cache.register_tag(0, 0);
        let key = PageKey { tag: 0, offset: 0 };

        {
            let mut g = cache.acquire_write(key, WriteMode::Modify).await.unwrap();
            g.fill(0xAA);
        }
        let lsn = cache.commit().await.unwrap();

        let pages = cache.pages.lock();
        let entry = pages.map.get(&key).unwrap();
        let page = entry.lock();
        assert_eq!(page.committed_lsn, Some(lsn));
    }

    async fn dirty_pages<F: AsyncFile>(cache: &PageCache<F>, count: usize) {
        for i in 0..count {
            let key = PageKey {
                tag: 0,
                offset: (i * PAGE_SIZE) as u64,
            };
            let mut g = cache
                .acquire_write(key, WriteMode::Overwrite)
                .await
                .unwrap();
            g.fill(i as u8);
        }
    }

    #[async_test]
    async fn eager_commit_on_dirty_overflow() {
        let (tx, mut rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64 * 200)),
            Some(tx),
            Some(permits),
            None,
        );
        cache.register_tag(0, 0);

        dirty_pages(&cache, MAX_COMMIT_PAGES).await;

        let new_key = PageKey {
            tag: 0,
            offset: (MAX_COMMIT_PAGES * PAGE_SIZE) as u64,
        };
        {
            let mut guard = cache
                .acquire_write(new_key, WriteMode::Overwrite)
                .await
                .unwrap();
            guard.fill(0xFF);
        }

        match rx.recv().await.unwrap() {
            LogRequest::Commit(txn) => {
                assert_eq!(txn.pages.len(), MAX_COMMIT_PAGES);
            }
            _ => panic!("expected Commit from eager commit"),
        }

        cache.commit().await.unwrap();
        match rx.recv().await.unwrap() {
            LogRequest::Commit(txn) => {
                assert_eq!(txn.pages.len(), 1);
            }
            _ => panic!("expected Commit from explicit commit"),
        }
    }

    #[async_test]
    async fn redirty_does_not_trigger_eager_commit() {
        let (tx, mut rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64 * 200)),
            Some(tx),
            Some(permits),
            None,
        );
        cache.register_tag(0, 0);

        dirty_pages(&cache, MAX_COMMIT_PAGES).await;

        let key = PageKey { tag: 0, offset: 0 };
        let mut g = cache.acquire_write(key, WriteMode::Modify).await.unwrap();
        g[0] = 0xDD;

        assert!(
            rx.try_recv().is_err(),
            "re-dirtying an already-dirty page must not trigger eager commit"
        );

        assert_eq!(cache.pages.lock().dirty_count, MAX_COMMIT_PAGES);
    }

    #[async_test]
    async fn write_ordering_across_batches() {
        let (tx, mut rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64 * 200)),
            Some(tx),
            Some(permits),
            None,
        );
        cache.register_tag(0, 0);

        dirty_pages(&cache, MAX_COMMIT_PAGES).await;

        let key_b = PageKey {
            tag: 0,
            offset: (MAX_COMMIT_PAGES * PAGE_SIZE) as u64,
        };
        {
            let mut g = cache
                .acquire_write(key_b, WriteMode::Overwrite)
                .await
                .unwrap();
            g.fill(0xBB);
        }

        let batch1 = match rx.recv().await.unwrap() {
            LogRequest::Commit(txn) => txn,
            _ => panic!("expected Commit"),
        };
        assert_eq!(batch1.pages.len(), MAX_COMMIT_PAGES);

        let key_c = PageKey {
            tag: 0,
            offset: ((MAX_COMMIT_PAGES + 1) * PAGE_SIZE) as u64,
        };
        {
            let mut g = cache
                .acquire_write(key_c, WriteMode::Overwrite)
                .await
                .unwrap();
            g.fill(0xCC);
        }

        cache.commit().await.unwrap();
        let batch2 = match rx.recv().await.unwrap() {
            LogRequest::Commit(txn) => txn,
            _ => panic!("expected Commit"),
        };
        assert_eq!(batch2.pages.len(), 2);
        assert!(batch1.lsn < batch2.lsn);
    }
}
