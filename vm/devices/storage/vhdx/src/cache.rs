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
//! This ordering is maintained by **batch-full commit**: when the dirty page
//! count reaches [`MAX_COMMIT_PAGES`] and a new page is about to become dirty,
//! the cache automatically commits the current dirty set to the log before
//! allowing the new page to enter the dirty set.

use crate::AsyncFile;
use crate::error::VhdxError;
use crate::log_permits::LogPermits;
use crate::log_task::CommittedPage;
use crate::log_task::LogClient;
use crate::lsn_watermark::LsnWatermark;
use parking_lot::ArcMutexGuard;
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
/// Note: the permit count is a *multiple* of this value (see `open.rs`)
/// to allow pipelining — multiple batches can be in-flight in the
/// log/apply pipeline simultaneously.
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
    /// Page is clean. Data is loaded and unmodified.
    ///
    /// Invariant: `data.is_some()` when `state == Clean`.
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
    Overwritten,
    /// Page has been modified. A permit is consumed (transfers to the log
    /// task on commit).
    Dirty,
}

/// Internal per-page data.
struct PageData {
    /// The page contents as `Arc` for zero-copy commit and COW.
    /// Always `Some` when `state` is `Clean`, `HasPermit`, or `Dirty`.
    /// `None` only when the page entry is freshly created (before loading)
    /// or in `Loading`/`AcquiringPermit` state.
    data: Option<Arc<[u8; PAGE_SIZE]>>,
    /// Page lifecycle state.
    state: PageState,
    /// If set, the log task must wait for this FSN to complete before
    /// including this page in a log entry.
    pre_log_fsn: Option<u64>,
    /// The LSN of the most recent commit that included this page.
    committed_lsn: Option<u64>,
}

/// Internal page map wrapping the `HashMap` and dirty page counter.
struct PageMap {
    map: HashMap<PageKey, Arc<Mutex<PageData>>>,
    /// Number of pages in `HasPermit` or `Dirty` state.
    /// Maintained under the map lock to prevent races.
    dirty_count: usize,
    /// Log client for sending transactions. `None` for read-only caches.
    log_client: Option<LogClient>,
}

/// Action to perform when a page isn't ready (returned by sync helpers).
/// This enum is `Send` — it never contains `ArcMutexGuard`.
enum PendingAction {
    /// Wait for another task to finish loading/acquiring.
    Wait(event_listener::EventListener),
    /// Load page data from disk at this file offset. Carries the page
    /// entry Arc so `complete_load` can skip the map re-lookup.
    Load(u64, Arc<Mutex<PageData>>),
}

/// Action for acquire_write when the page isn't ready.
/// This enum is `Send` — it never contains `ArcMutexGuard`.
enum WritePendingAction {
    /// Wait for another task to finish loading/acquiring.
    Wait(event_listener::EventListener),
    /// Load page data from disk at this file offset. Carries the page
    /// entry Arc so `complete_load` can skip the map re-lookup.
    Load(u64, Arc<Mutex<PageData>>),
    /// Acquire a log permit. Carries the page entry Arc so
    /// `finalize_permit` can skip the map re-lookup.
    AcquirePermit(Arc<Mutex<PageData>>),
    /// Dirty batch was full and has been committed. Retry from the top.
    Retry,
}

/// Write-back page cache backed by an [`AsyncFile`].
pub struct PageCache<F: AsyncFile> {
    pub(crate) file: Arc<F>,
    pages: Mutex<PageMap>,
    tags: Mutex<HashMap<u8, u64>>,
    log_permits: Option<Arc<LogPermits>>,
    applied_lsn: Option<Arc<LsnWatermark>>,
    /// Notified when a page transitions out of `Loading` or `AcquiringPermit`.
    state_event: event_listener::Event,
    /// Maximum number of pages to keep in the cache. 0 = unlimited.
    quota: usize,
}

impl<F: AsyncFile> PageCache<F> {
    /// Create a new cache backed by the given file.
    pub fn new(
        file: Arc<F>,
        log_client: Option<LogClient>,
        log_permits: Option<Arc<LogPermits>>,
        applied_lsn: Option<Arc<LsnWatermark>>,
        quota: usize,
    ) -> Self {
        Self {
            file,
            pages: Mutex::new(PageMap {
                map: HashMap::new(),
                dirty_count: 0,
                log_client,
            }),
            tags: Mutex::new(HashMap::new()),
            log_permits,
            applied_lsn,
            state_event: event_listener::Event::new(),
            quota,
        }
    }

    /// Take the log client out of the cache, returning it.
    pub fn take_log_client(&mut self) -> Option<LogClient> {
        self.pages.lock().log_client.take()
    }

    /// Set the log permits (for late initialization after log task spawn).
    pub fn set_log_permits(&mut self, permits: Arc<LogPermits>) {
        self.log_permits = Some(permits);
    }

    /// Set the applied LSN watermark (for late initialization after apply task spawn).
    pub fn set_applied_lsn(&mut self, lsn: Arc<LsnWatermark>) {
        self.applied_lsn = Some(lsn);
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
    ///
    /// # Panics
    ///
    /// Panics if `key.tag` has not been registered via [`register_tag`](Self::register_tag).
    pub(crate) fn resolve_offset(&self, key: PageKey) -> u64 {
        let tags = self.tags.lock();
        let base = tags
            .get(&key.tag)
            .unwrap_or_else(|| panic!("cache tag {} not registered", key.tag));
        base + key.offset
    }

    /// Try to evict one clean, applied page to make room.
    /// Must be called with the pages map lock held.
    /// `skip_key` is the page being acquired — never evict it.
    fn try_evict_under_lock(&self, pages: &mut PageMap, skip_key: Option<PageKey>) {
        let applied = self.applied_lsn.as_ref().map(|w| w.get()).unwrap_or(0);

        // Find first evictable page.
        let evict_key = pages.map.iter().find_map(|(&key, entry)| {
            if skip_key == Some(key) {
                return None;
            }
            // Try to lock the page. If contended, skip (someone is using it).
            if let Some(page) = entry.try_lock() {
                if page.state == PageState::Clean
                    && page.data.is_some()
                    && match page.committed_lsn {
                        None => true,
                        Some(lsn) => lsn <= applied,
                    }
                {
                    return Some(key);
                }
            }
            None
        });

        if let Some(key) = evict_key {
            pages.map.remove(&key);
        }
    }

    /// Acquire read access to a page.
    pub async fn acquire_read(&self, key: PageKey) -> Result<ReadPageGuard, std::io::Error> {
        loop {
            let action = match self.try_acquire_read(key) {
                Ok(guard) => return Ok(guard),
                Err(action) => action,
            };
            match action {
                PendingAction::Wait(listener) => listener.await,
                PendingAction::Load(file_offset, entry) => {
                    let mut buf = Arc::new([0u8; PAGE_SIZE]);
                    match self
                        .file
                        .read_at(file_offset, Arc::get_mut(&mut buf).unwrap())
                        .await
                    {
                        Ok(()) => self.complete_load(entry, Some(buf)),
                        Err(e) => {
                            self.complete_load(entry, None);
                            return Err(e);
                        }
                    }
                }
            }
        }
    }

    /// Sync helper: try to acquire read access.
    fn try_acquire_read(&self, key: PageKey) -> Result<ReadPageGuard, PendingAction> {
        assert!(
            key.offset.is_multiple_of(PAGE_SIZE as u64),
            "page offset {:#x} is not {PAGE_SIZE}-byte aligned",
            key.offset
        );
        let file_offset = self.resolve_offset(key);
        let mut pages = self.pages.lock();

        // Evict if over quota (but not the page we're about to acquire).
        if self.quota > 0 && pages.map.len() >= self.quota {
            self.try_evict_under_lock(&mut pages, Some(key));
        }

        let entry = pages.map.entry(key).or_insert_with(|| {
            Arc::new(Mutex::new(PageData {
                data: None,
                state: PageState::Clean,
                pre_log_fsn: None,
                committed_lsn: None,
            }))
        });

        let mut guard = Mutex::lock_arc(entry);
        drop(pages);

        match guard.state {
            PageState::Loading | PageState::AcquiringPermit => {
                let listener = self.state_event.listen();
                drop(guard);
                Err(PendingAction::Wait(listener))
            }
            PageState::Clean if guard.data.is_none() => {
                guard.state = PageState::Loading;
                Err(PendingAction::Load(
                    file_offset,
                    ArcMutexGuard::into_arc(guard),
                ))
            }
            PageState::Clean | PageState::HasPermit | PageState::Overwritten | PageState::Dirty => {
                assert!(
                    guard.data.is_some(),
                    "page in {:?} has no data",
                    guard.state
                );
                Ok(ReadPageGuard { guard })
            }
        }
    }

    /// Complete a page load: store data and transition out of Loading.
    ///
    /// On success (`data` is `Some`): stores data, transitions `Loading → Clean`.
    /// Uses the `entry` Arc directly — no map re-lookup needed.
    ///
    /// On failure (`data` is `None`): removes the entry from the cache so the
    /// next acquirer creates a fresh entry and retries.
    fn complete_load(&self, entry: Arc<Mutex<PageData>>, data: Option<Arc<[u8; PAGE_SIZE]>>) {
        let mut page = entry.lock();
        assert!(
            page.state == PageState::Loading,
            "complete_load called but page state is {:?}, expected Loading",
            page.state
        );
        assert!(
            page.data.is_none(),
            "complete_load called but page already has data"
        );
        page.state = PageState::Clean;
        page.data = data;
        self.state_event.notify(usize::MAX);
    }

    /// Acquire write access to a page.
    ///
    /// If a log is configured, acquires a permit (backpressure). If the
    /// dirty batch is full, commits it first (batch-full commit).
    pub async fn acquire_write(
        &self,
        key: PageKey,
        mode: WriteMode,
    ) -> Result<WritePageGuard<'_, F>, std::io::Error> {
        let load = mode == WriteMode::Modify;

        loop {
            let action = match self.try_acquire_write(key, load) {
                Ok(guard) => return Ok(guard),
                Err(action) => action,
            };
            match action {
                WritePendingAction::Wait(listener) => listener.await,
                WritePendingAction::Load(file_offset, entry) => {
                    let mut buf = Arc::new([0u8; PAGE_SIZE]);
                    match self
                        .file
                        .read_at(file_offset, Arc::get_mut(&mut buf).unwrap())
                        .await
                    {
                        Ok(()) => self.complete_load(entry, Some(buf)),
                        Err(e) => {
                            self.complete_load(entry, None);
                            return Err(e);
                        }
                    }
                }
                WritePendingAction::AcquirePermit(entry) => {
                    let permits = self.log_permits.as_ref().unwrap();
                    let result = permits.acquire(1).await;
                    self.finalize_permit(entry, result.is_ok());
                    result.map_err(|e| match e {
                        VhdxError::Io(io) => io,
                        other => std::io::Error::other(other.to_string()),
                    })?;
                }
                WritePendingAction::Retry => {
                    // Batch-full commit was done; loop to re-acquire page.
                    continue;
                }
            }
        }
    }

    /// Sync helper: try to acquire write access.
    ///
    /// Owns the map lock for the entire operation. If the dirty batch is
    /// full, commits it under the same lock (batch-full commit) before
    /// transitioning the page to AcquiringPermit. No TOCTOU gap.
    fn try_acquire_write(
        &self,
        key: PageKey,
        load: bool,
    ) -> Result<WritePageGuard<'_, F>, WritePendingAction> {
        assert!(
            self.log_permits.is_some(),
            "acquire_write requires a log (use open_writable)"
        );

        assert!(
            key.offset.is_multiple_of(PAGE_SIZE as u64),
            "page offset {:#x} is not {PAGE_SIZE}-byte aligned",
            key.offset
        );
        let file_offset = self.resolve_offset(key);

        let mut pages = self.pages.lock();

        // Evict if over quota.
        if self.quota > 0 && pages.map.len() >= self.quota {
            self.try_evict_under_lock(&mut pages, Some(key));
        }

        let entry = pages.map.entry(key).or_insert_with(|| {
            Arc::new(Mutex::new(PageData {
                data: None,
                state: PageState::Clean,
                pre_log_fsn: None,
                committed_lsn: None,
            }))
        });

        let mut guard = Mutex::lock_arc(entry);

        match guard.state {
            PageState::Loading | PageState::AcquiringPermit => {
                Err(WritePendingAction::Wait(self.state_event.listen()))
            }
            PageState::Dirty | PageState::Overwritten | PageState::HasPermit => {
                assert!(
                    guard.data.is_some(),
                    "page in {:?} has no data",
                    guard.state
                );
                Ok(WritePageGuard {
                    cache: self,
                    guard: Some(guard),
                })
            }
            PageState::Clean if load && guard.data.is_none() => {
                guard.state = PageState::Loading;
                Err(WritePendingAction::Load(
                    file_offset,
                    ArcMutexGuard::into_arc(guard),
                ))
            }
            PageState::Clean => {
                // Batch-full commit: if the dirty batch has reached
                // MAX_COMMIT_PAGES, commit it now under the same map lock.
                // Drop the page guard first — commit_locked iterates all
                // pages and would deadlock on this one.
                if pages.dirty_count >= MAX_COMMIT_PAGES {
                    drop(guard);
                    let _ = self.commit_locked(&mut pages);
                    drop(pages);
                    return Err(WritePendingAction::Retry);
                }

                guard.state = PageState::AcquiringPermit;
                Err(WritePendingAction::AcquirePermit(ArcMutexGuard::into_arc(
                    guard,
                )))
            }
        }
    }

    /// Finalize a permit acquisition: transition page to HasPermit or Clean.
    /// The dirty_count increment is under the map lock, synchronized with
    /// commit_locked which also holds the map lock when collecting dirty pages.
    fn finalize_permit(&self, entry: Arc<Mutex<PageData>>, success: bool) {
        {
            let mut pages = self.pages.lock();
            let mut page = entry.lock();
            // TODO: this seems broken, TOCTOU
            if success {
                pages.dirty_count += 1;
            }
            drop(pages);
            assert!(page.state == PageState::AcquiringPermit);
            page.state = if success {
                if page.data.is_some() {
                    PageState::HasPermit
                } else {
                    page.data = Some(Arc::new([0u8; PAGE_SIZE]));
                    PageState::Overwritten
                }
            } else {
                PageState::Clean
            };
        }
        self.state_event.notify(usize::MAX);
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
    /// Returns the current LSN. If there were dirty pages, they are sent
    /// to the log task and the returned LSN is the one assigned to that
    /// batch. If there were no dirty pages, returns the most recently
    /// assigned LSN (so that concurrent `flush()` callers still wait
    /// for any in-flight WAL writes).
    pub fn commit(&self) -> Result<u64, VhdxError> {
        let mut pages = self.pages.lock();
        self.commit_locked(&mut pages)
    }

    /// Send pre-built pages through the log, bypassing the cache's
    /// dirty-page tracking. Used for non-cache metadata writes
    /// (e.g., region table repair).
    ///
    /// Returns the assigned LSN.
    pub fn commit_raw(&self, raw_pages: Vec<CommittedPage>, pre_log_fsn: Option<u64>) -> u64 {
        let mut map = self.pages.lock();
        let client = map
            .log_client
            .as_mut()
            .expect("commit_raw requires a log client (use open_writable)");
        let txn = client.begin();
        txn.commit(raw_pages, pre_log_fsn)
    }

    /// Inner commit implementation that takes an already-held map lock.
    ///
    /// This allows `finalize_permit` to check dirty_count and commit
    /// atomically under the same lock — no TOCTOU gap.
    fn commit_locked(&self, pages: &mut PageMap) -> Result<u64, VhdxError> {
        let client = pages
            .log_client
            .as_mut()
            .expect("commit requires a log client (use open_writable)");

        let mut committed = Vec::new();
        let mut max_pre_log_fsn: Option<u64> = None;

        let txn = client.begin();
        let lsn = txn.lsn();

        for (&key, entry) in pages.map.iter() {
            let mut page = entry.lock();
            if matches!(page.state, PageState::Dirty | PageState::Overwritten) {
                let file_offset = self.resolve_offset(key);
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
            drop(txn);
            return Ok(client.current_lsn());
        }

        let committed_count = committed.len();
        pages.dirty_count -= committed_count;

        txn.commit(committed, max_pre_log_fsn);

        // Do NOT release permits here. Permits stay consumed until the
        // apply task writes pages to their final offsets and releases
        // them. This bounds the total in-flight page data (Arc clones)
        // in the log/apply pipeline, preventing unbounded memory growth.

        Ok(lsn)
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
    guard: Option<ArcMutexGuard<parking_lot::RawMutex, PageData>>,
}

impl<F: AsyncFile> WritePageGuard<'_, F> {
    /// Whether the page data was already in the cache when acquired.
    ///
    /// - `true`: page was already cached — the guard contains valid data
    ///   that can be patched in-place.
    /// - `false`: page was freshly created (zeroed) — the caller must
    ///   populate the entire page before dropping the guard.
    pub fn is_populated(&self) -> bool {
        self.guard.as_ref().unwrap().state != PageState::Overwritten
    }
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
        guard.state = PageState::Dirty;
        Arc::make_mut(guard.data.as_mut().expect("page data missing"))
    }
}

impl<F: AsyncFile> Drop for WritePageGuard<'_, F> {
    fn drop(&mut self) {
        if let Some(mut guard) = self.guard.take() {
            if guard.state == PageState::HasPermit {
                // Guard dropped without mutation. Refund the permit
                // and decrement dirty_count.
                guard.state = PageState::Clean;
                drop(guard);
                self.cache.pages.lock().dirty_count -= 1;
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
    use crate::log_task::LogRequest;
    use crate::tests::support::{FailingInterceptor, InMemoryFile};
    use pal_async::async_test;
    use std::sync::Arc;

    /// Helper to create a writable cache with log sender + permits.
    fn writable_cache(file: InMemoryFile) -> (PageCache<InMemoryFile>, mesh::Receiver<LogRequest>) {
        let (tx, rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let cache = PageCache::new(
            Arc::new(file),
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
        );
        (cache, rx)
    }

    #[async_test]
    async fn acquire_read_loads_from_file() {
        let file = InMemoryFile::new(PAGE_SIZE as u64);
        let pattern: Vec<u8> = (0..PAGE_SIZE).map(|i| (i & 0xFF) as u8).collect();
        file.write_at(0, &pattern).await.unwrap();

        let mut cache = PageCache::new(Arc::new(file), None, None, None, 0);
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
        cache = PageCache::new(
            Arc::new(file),
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
        );
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
            Arc::new(FailingInterceptor {
                fail_reads: true,
                fail_writes: false,
                fail_flushes: false,
                fail_set_file_size: false,
            }),
        );

        let (tx, _rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(file),
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
        );
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

        let mut cache = PageCache::new(Arc::new(file), None, None, None, 0);
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
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
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
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
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
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
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

        let mut cache = PageCache::new(Arc::new(file), None, None, None, 0);
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

        let mut cache = PageCache::new(Arc::new(file), None, None, None, 0);
        cache.register_tag(0, old_base);

        {
            let guard = cache
                .acquire_read(PageKey { tag: 0, offset: 0 })
                .await
                .unwrap();
            assert_eq!(guard[0], 0xAA);
        }

        let mut cache = PageCache::new(cache.file.clone(), None, None, None, 0);
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
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
        );
        cache.register_tag(0, 0);
        let key = PageKey { tag: 0, offset: 0 };

        {
            let mut g = cache.acquire_write(key, WriteMode::Modify).await.unwrap();
            g.fill(0xAA);
        }
        let lsn = cache.commit().unwrap();
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
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
        );
        cache.register_tag(0, 0);
        let key = PageKey { tag: 0, offset: 0 };

        {
            let mut g = cache.acquire_write(key, WriteMode::Modify).await.unwrap();
            g.fill(0xAA);
        }
        let lsn1 = cache.commit().unwrap();

        {
            let mut g = cache.acquire_write(key, WriteMode::Modify).await.unwrap();
            g.fill(0xBB);
        }
        let lsn2 = cache.commit().unwrap();

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
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
        );
        cache.register_tag(0, 0);
        let key = PageKey { tag: 0, offset: 0 };

        {
            let mut g = cache.acquire_write(key, WriteMode::Modify).await.unwrap();
            g.fill(0xAA);
        }
        let lsn = cache.commit().unwrap();

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
    async fn batch_full_commit_on_dirty_overflow() {
        let (tx, mut rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64 * 200)),
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
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
            _ => panic!("expected Commit from batch-full commit"),
        }

        cache.commit().unwrap();
        match rx.recv().await.unwrap() {
            LogRequest::Commit(txn) => {
                assert_eq!(txn.pages.len(), 1);
            }
            _ => panic!("expected Commit from explicit commit"),
        }
    }

    #[async_test]
    async fn redirty_does_not_trigger_batch_full_commit() {
        let (tx, mut rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64 * 200)),
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
        );
        cache.register_tag(0, 0);

        dirty_pages(&cache, MAX_COMMIT_PAGES).await;

        let key = PageKey { tag: 0, offset: 0 };
        let mut g = cache.acquire_write(key, WriteMode::Modify).await.unwrap();
        g[0] = 0xDD;

        assert!(
            rx.try_recv().is_err(),
            "re-dirtying an already-dirty page must not trigger batch-full commit"
        );

        assert_eq!(cache.pages.lock().dirty_count, MAX_COMMIT_PAGES);
    }

    #[async_test]
    async fn write_ordering_across_batches() {
        let (tx, mut rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64 * 200)),
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
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

        cache.commit().unwrap();
        let batch2 = match rx.recv().await.unwrap() {
            LogRequest::Commit(txn) => txn,
            _ => panic!("expected Commit"),
        };
        assert_eq!(batch2.pages.len(), 2);
        assert!(batch1.lsn < batch2.lsn);
    }

    // ---- Eviction tests ----

    #[async_test]
    async fn eviction_removes_clean_page() {
        let file = InMemoryFile::new(PAGE_SIZE as u64 * 4);
        let pattern_a = [0xAA; PAGE_SIZE];
        let pattern_b = [0xBB; PAGE_SIZE];
        file.write_at(0, &pattern_a).await.unwrap();
        file.write_at(PAGE_SIZE as u64, &pattern_b).await.unwrap();

        // Quota of 1 page.
        let mut cache = PageCache::new(Arc::new(file), None, None, None, 1);
        cache.register_tag(0, 0);

        // Load page A.
        let g = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(g[0], 0xAA);
        drop(g);

        // Cache has 1 page (at quota). Loading page B should evict page A.
        let g = cache
            .acquire_read(PageKey {
                tag: 0,
                offset: PAGE_SIZE as u64,
            })
            .await
            .unwrap();
        assert_eq!(g[0], 0xBB);
        drop(g);

        // Page A was evicted — cache should have 1 entry.
        assert_eq!(cache.pages.lock().map.len(), 1);
    }

    #[async_test]
    async fn eviction_reloads_from_disk() {
        let file = InMemoryFile::new(PAGE_SIZE as u64 * 4);
        let pattern_a = [0xAA; PAGE_SIZE];
        let pattern_b = [0xBB; PAGE_SIZE];
        file.write_at(0, &pattern_a).await.unwrap();
        file.write_at(PAGE_SIZE as u64, &pattern_b).await.unwrap();

        let mut cache = PageCache::new(Arc::new(file), None, None, None, 1);
        cache.register_tag(0, 0);

        // Load page A.
        let g = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(g[0], 0xAA);
        drop(g);

        // Load page B (evicts A).
        let g = cache
            .acquire_read(PageKey {
                tag: 0,
                offset: PAGE_SIZE as u64,
            })
            .await
            .unwrap();
        assert_eq!(g[0], 0xBB);
        drop(g);

        // Re-load page A (evicts B, reloads from disk).
        let g = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(g[0], 0xAA);
        drop(g);
    }

    #[async_test]
    async fn eviction_skips_dirty_pages() {
        let file = InMemoryFile::new(PAGE_SIZE as u64 * 4);
        file.write_at(PAGE_SIZE as u64, &[0xBB; PAGE_SIZE])
            .await
            .unwrap();

        let (tx, _rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        // Quota of 1, but page 0 will be dirty.
        let mut cache = PageCache::new(
            Arc::new(file),
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            1,
        );
        cache.register_tag(0, 0);

        // Write page A (makes it Dirty).
        {
            let mut g = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Overwrite)
                .await
                .unwrap();
            g.fill(0xAA);
        }

        // Try to load page B. Eviction should skip dirty page A.
        // Cache will have 2 entries (over quota but nothing evictable).
        let g = cache
            .acquire_read(PageKey {
                tag: 0,
                offset: PAGE_SIZE as u64,
            })
            .await
            .unwrap();
        assert_eq!(g[0], 0xBB);
        drop(g);

        // Both pages present.
        assert_eq!(cache.pages.lock().map.len(), 2);

        // Verify page A is still readable (not evicted).
        let g = cache
            .acquire_read(PageKey { tag: 0, offset: 0 })
            .await
            .unwrap();
        assert_eq!(g[0], 0xAA);
    }

    #[async_test]
    async fn eviction_skips_uncommitted_page() {
        let file = InMemoryFile::new(PAGE_SIZE as u64 * 4);
        file.write_at(0, &[0xAA; PAGE_SIZE]).await.unwrap();
        file.write_at(PAGE_SIZE as u64, &[0xBB; PAGE_SIZE])
            .await
            .unwrap();

        let applied = Arc::new(crate::lsn_watermark::LsnWatermark::new());
        // applied_lsn = 0, so committed pages with lsn > 0 are not evictable.

        let (tx, _rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(file),
            Some(LogClient::new(tx)),
            Some(permits),
            Some(applied.clone()),
            1,
        );
        cache.register_tag(0, 0);

        // Write and commit page A (committed_lsn = 1, applied_lsn = 0).
        {
            let mut g = cache
                .acquire_write(PageKey { tag: 0, offset: 0 }, WriteMode::Overwrite)
                .await
                .unwrap();
            g.fill(0xAA);
        }
        cache.commit().unwrap();

        // Page A is Clean with committed_lsn=1. applied_lsn=0.
        // Eviction should skip it (not yet applied).
        let g = cache
            .acquire_read(PageKey {
                tag: 0,
                offset: PAGE_SIZE as u64,
            })
            .await
            .unwrap();
        assert_eq!(g[0], 0xBB);
        drop(g);

        // Both pages present (A is not evictable).
        assert_eq!(cache.pages.lock().map.len(), 2);

        // Now advance applied_lsn past the committed_lsn.
        applied.advance(1, 0);

        // Load another page — now A is evictable.
        let file_size = PAGE_SIZE as u64 * 4;
        // Load page at offset 2*PAGE_SIZE (need data there).
        cache
            .file
            .write_at(PAGE_SIZE as u64 * 2, &[0xCC; PAGE_SIZE])
            .await
            .unwrap();
        let g = cache
            .acquire_read(PageKey {
                tag: 0,
                offset: PAGE_SIZE as u64 * 2,
            })
            .await
            .unwrap();
        assert_eq!(g[0], 0xCC);
        drop(g);

        // Should have evicted one of the old pages (A or B).
        assert!(cache.pages.lock().map.len() <= 2);
    }

    #[async_test]
    async fn no_deadlock_with_quota() {
        // Regression test: verify that acquiring pages with a small quota
        // doesn't deadlock. The dual-lock pattern
        // should prevent lock-order issues.
        let (tx, _rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64 * 10)),
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            2,
        );
        cache.register_tag(0, 0);

        // Rapidly acquire and drop pages, cycling through more than the quota.
        for i in 0..5u64 {
            let mut g = cache
                .acquire_write(
                    PageKey {
                        tag: 0,
                        offset: i * PAGE_SIZE as u64,
                    },
                    WriteMode::Overwrite,
                )
                .await
                .unwrap();
            g.fill(i as u8);
        }
        // If we get here without hanging, no deadlock.
    }

    #[async_test]
    async fn overwrite_uncached_reports_not_cached() {
        let (tx, _rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64)),
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
        );
        cache.register_tag(0, 0);

        let key = PageKey { tag: 0, offset: 0 };
        let g = cache
            .acquire_write(key, WriteMode::Overwrite)
            .await
            .unwrap();
        assert!(
            !g.is_populated(),
            "first Overwrite acquire should report not cached"
        );
    }

    #[async_test]
    async fn overwrite_cached_reports_cached() {
        let (tx, _rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(InMemoryFile::new(PAGE_SIZE as u64)),
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
        );
        cache.register_tag(0, 0);

        let key = PageKey { tag: 0, offset: 0 };

        // First write populates the cache.
        {
            let mut g = cache
                .acquire_write(key, WriteMode::Overwrite)
                .await
                .unwrap();
            g.fill(0xAA);
        }

        // Second write should find it cached.
        let g = cache
            .acquire_write(key, WriteMode::Overwrite)
            .await
            .unwrap();
        assert!(
            g.is_populated(),
            "second Overwrite acquire should report cached"
        );
        // Data should still be 0xAA (not zeroed).
        assert_eq!(g[0], 0xAA);
        assert_eq!(g[PAGE_SIZE - 1], 0xAA);
    }

    #[async_test]
    async fn modify_always_reports_cached() {
        // Modify loads from disk if not cached, so populated reflects
        // map presence after load — always true since load populates it.
        let file = InMemoryFile::new(PAGE_SIZE as u64);
        file.write_at(0, &[0xBB; PAGE_SIZE]).await.unwrap();

        let (tx, _rx) = mesh::channel::<LogRequest>();
        let permits = Arc::new(LogPermits::new(1000));
        let mut cache = PageCache::new(
            Arc::new(file),
            Some(LogClient::new(tx)),
            Some(permits),
            None,
            0,
        );
        cache.register_tag(0, 0);

        let key = PageKey { tag: 0, offset: 0 };

        // Modify loads from disk then retries — page is in map on retry.
        let g = cache.acquire_write(key, WriteMode::Modify).await.unwrap();
        assert!(
            g.is_populated(),
            "Modify always reports cached (loaded before permit)"
        );
        assert_eq!(g[0], 0xBB);
    }
}
