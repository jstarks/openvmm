// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::filesystem::NativeFile;
use crate::io::{Io, check};
use crate::native;
use async_trait::async_trait;
use event_listener::Event;
use futures::FutureExt;
use futures::lock::{Mutex, OwnedMutexGuard};
use pal_async::timer::PolledTimer;
use pal_async::windows::overlapped::OverlappedFile;
use parking_lot::Mutex as SyncMutex;
use smb::provider::locking::software::SoftwareLockOwner;
use smb::provider::{ByteRange, LockScope, LockSettlement, RequestContext};
use smb::spec::Status;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

const LOCK_LIMIT: usize = 4096;
const WAITER_LIMIT: usize = 1024;
const ACTIVE_LIMIT: usize = 1024;

#[derive(Default)]
struct Active {
    count: AtomicUsize,
    changed: Event,
}

pub(crate) struct ActiveIo(Arc<Active>);

impl Drop for ActiveIo {
    fn drop(&mut self) {
        self.0.count.fetch_sub(1, Ordering::Release);
        self.0.changed.notify(usize::MAX);
    }
}

#[derive(Default)]
pub(crate) struct Coordination {
    changed: Event,
    next: AtomicU64,
    locks: AtomicUsize,
    waiters: SyncMutex<HashMap<u64, usize>>,
}

impl Coordination {
    pub fn lock_count(&self) -> usize {
        self.locks.load(Ordering::Relaxed)
    }

    pub fn waiter_count(&self) -> usize {
        self.waiters.lock().values().sum()
    }

    pub fn changed(&self) {
        self.changed.notify(usize::MAX);
    }

    #[cfg(test)]
    pub fn pending(&self, request: u64) -> bool {
        self.waiters.lock().contains_key(&request)
    }
}

struct LockPermit(Arc<Coordination>);

impl LockPermit {
    fn new(coordination: &Arc<Coordination>) -> Result<Self, Status> {
        coordination
            .locks
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < LOCK_LIMIT).then_some(count + 1)
            })
            .map_err(|_| Status::INSUFFICIENT_RESOURCES)?;
        Ok(Self(coordination.clone()))
    }
}

impl Drop for LockPermit {
    fn drop(&mut self) {
        self.0.locks.fetch_sub(1, Ordering::Relaxed);
    }
}

struct Waiter(Arc<Coordination>, u64);

impl Waiter {
    fn new(coordination: &Arc<Coordination>, request: u64) -> Result<Self, Status> {
        let mut waiters = coordination.waiters.lock();
        if waiters.values().sum::<usize>() == WAITER_LIMIT {
            return Err(Status::INSUFFICIENT_RESOURCES);
        }
        *waiters.entry(request).or_default() += 1;
        Ok(Self(coordination.clone(), request))
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        let mut waiters = self.0.waiters.lock();
        let count = waiters.get_mut(&self.1).expect("registered lock waiter");
        *count -= 1;
        if *count == 0 {
            waiters.remove(&self.1);
        }
    }
}

struct Acquisition {
    scope: u64,
    range: ByteRange,
    exclusive: bool,
    _permit: LockPermit,
}

struct Group {
    range: ByteRange,
    exclusive: bool,
    shared: bool,
}

#[derive(Default)]
pub(crate) struct Ledger {
    acquired: Vec<Acquisition>,
    groups: Vec<Group>,
}

/// Serializes a native open's accepted I/O with tentative lock requests.
pub(crate) struct DataFile {
    pub file: OverlappedFile,
    pub gate: Arc<Mutex<Ledger>>,
    pub closing: AtomicBool,
    pub coordination: Arc<Coordination>,
    active: Arc<Active>,
    pub synthetic: Option<SoftwareLockOwner<u64>>,
}

impl DataFile {
    pub fn new(file: OverlappedFile, coordination: Arc<Coordination>) -> Self {
        Self {
            file,
            gate: Arc::new(Mutex::new(Ledger::default())),
            closing: AtomicBool::new(false),
            coordination,
            active: Arc::new(Active::default()),
            synthetic: None,
        }
    }

    pub async fn admit(&self, request: &RequestContext) -> Result<OwnedMutexGuard<Ledger>, Status> {
        check(request)?;
        let mut gate = std::pin::pin!(self.gate.clone().lock_owned().fuse());
        let mut cancelled = std::pin::pin!(request.cancelled().fuse());
        let guard = futures::select_biased! {
            () = cancelled => return Err(Status::CANCELLED),
            guard = gate => guard,
        };
        if self.closing.load(Ordering::Acquire) {
            return Err(Status::FILE_CLOSED);
        }
        Ok(guard)
    }

    /// Called under the ledger gate; completion owns the returned admission.
    pub fn active(&self) -> Result<ActiveIo, Status> {
        self.active
            .count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < ACTIVE_LIMIT).then_some(count + 1)
            })
            .map_err(|_| Status::INSUFFICIENT_RESOURCES)?;
        Ok(ActiveIo(self.active.clone()))
    }

    pub async fn drain(&self, request: &RequestContext) -> Result<(), Status> {
        loop {
            let listener = self.active.changed.listen();
            if self.active.count.load(Ordering::Acquire) == 0 {
                return Ok(());
            }
            let mut changed = std::pin::pin!(listener.fuse());
            let mut cancelled = std::pin::pin!(request.cancelled().fuse());
            futures::select_biased! {
                () = cancelled => return Err(Status::CANCELLED),
                () = changed => {},
            }
        }
    }

    pub fn needs_realization(&self, ledger: &Ledger) -> bool {
        ledger.groups.iter().any(|group| {
            !group.shared
                && ledger
                    .acquired
                    .iter()
                    .any(|lock| lock.range == group.range && !lock.exclusive)
        })
    }

    pub fn close(&self, ledger: &mut Ledger) -> Result<(), Status> {
        for group in &mut ledger.groups {
            if group.exclusive {
                native::unlock(self.file.get(), group.range, 0)?;
                group.exclusive = false;
            }
            if group.shared {
                native::unlock(self.file.get(), group.range, 0)?;
                group.shared = false;
            }
        }
        ledger.groups.clear();
        ledger.acquired.clear();
        if let Some(owner) = &self.synthetic {
            owner.close();
        }
        self.coordination.changed();
        Ok(())
    }

    fn backing(&self, range: ByteRange, exclusive: bool) -> Result<(), Status> {
        let ((status, _), ()) =
            futures::executor::block_on(native::lock(&self.file, range, 0, exclusive, true));
        native::status(status)
    }

    pub fn realize(&self, ledger: &mut Ledger) -> Result<(), Status> {
        for group in &mut ledger.groups {
            if !group.shared
                && ledger
                    .acquired
                    .iter()
                    .any(|lock| lock.range == group.range && !lock.exclusive)
            {
                self.backing(group.range, false)?;
                group.shared = true;
            }
        }
        Ok(())
    }

    fn acquire(
        &self,
        ledger: &mut Ledger,
        scope: u64,
        range: ByteRange,
        exclusive: bool,
    ) -> Result<(), Status> {
        if exclusive
            && ledger
                .acquired
                .iter()
                .any(|lock| lock.range.overlaps(range))
        {
            return Err(Status::LOCK_NOT_GRANTED);
        }
        let permit = LockPermit::new(&self.coordination)?;
        let index = ledger.groups.iter().position(|group| group.range == range);
        match index {
            Some(index) => {
                let group = &mut ledger.groups[index];
                if exclusive && !group.exclusive {
                    self.backing(range, true)?;
                    group.exclusive = true;
                } else if !exclusive && !group.shared && !group.exclusive {
                    self.backing(range, false)?;
                    group.shared = true;
                }
            }
            None => {
                self.backing(range, exclusive)?;
                ledger.groups.push(Group {
                    range,
                    exclusive,
                    shared: !exclusive,
                });
            }
        }
        ledger.acquired.push(Acquisition {
            scope,
            range,
            exclusive,
            _permit: permit,
        });
        Ok(())
    }

    fn remove(&self, ledger: &mut Ledger, index: usize, rollback: bool) -> Result<(), Status> {
        let acquisition = &ledger.acquired[index];
        let range = acquisition.range;
        let exclusive = acquisition.exclusive;
        if ledger
            .acquired
            .iter()
            .filter(|lock| lock.range == range && lock.exclusive == exclusive)
            .count()
            == 1
        {
            let group = ledger
                .groups
                .iter_mut()
                .find(|group| group.range == range)
                .expect("acquisition has backing group");
            if exclusive
                && !group.shared
                && ledger
                    .acquired
                    .iter()
                    .any(|lock| lock.range == range && !lock.exclusive)
            {
                self.backing(range, false)?;
                group.shared = true;
            }
            if if exclusive {
                group.exclusive
            } else {
                group.shared
            } {
                if !exclusive && group.exclusive {
                    tracelimit::error_ratelimited!(rollback, "ambiguous native shared unlock");
                    return Err(Status::INTERNAL_ERROR);
                }
                native::unlock(self.file.get(), range, 0)?;
                if exclusive {
                    group.exclusive = false;
                } else {
                    group.shared = false;
                }
            }
        }
        ledger.acquired.remove(index);
        if !ledger.acquired.iter().any(|lock| lock.range == range) {
            ledger.groups.retain(|group| group.range != range);
        }
        self.coordination.changed();
        Ok(())
    }
}

impl Drop for DataFile {
    fn drop(&mut self) {
        self.coordination.changed();
    }
}

pub(crate) struct Scope<'a> {
    file: Result<Arc<NativeFile>, Status>,
    io: &'a Io,
    id: Result<u64, Status>,
    guard: Option<OwnedMutexGuard<Ledger>>,
}

impl<'a> Scope<'a> {
    pub fn new(
        file: Result<Arc<NativeFile>, Status>,
        io: &'a Io,
        coordination: &Arc<Coordination>,
    ) -> Self {
        let file = file.and_then(|file| {
            if !Arc::ptr_eq(&file.data()?.coordination, coordination) {
                return Err(Status::FILE_CLOSED);
            }
            Ok(file)
        });
        Self {
            file,
            io,
            id: coordination
                .next
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(1)
                })
                .map_err(|_| Status::INSUFFICIENT_RESOURCES),
            guard: None,
        }
    }

    async fn operation(
        &mut self,
        request: &RequestContext,
        operation: impl FnOnce(&DataFile, &mut Ledger, u64) -> Result<(), Status> + Send + 'static,
    ) -> Result<(), Status> {
        let file = self.file.as_ref().map_err(|status| *status)?.clone();
        let data = file.data()?;
        let id = self.id?;
        let mut guard = match self.guard.take() {
            Some(guard) => guard,
            None => {
                let guard = data.admit(request).await?;
                data.drain(request).await?;
                guard
            }
        };
        let (guard, result) = self
            .io
            .worker(request, move || {
                let data = file.data()?;
                let result = if data.closing.load(Ordering::Acquire) {
                    Err(Status::FILE_CLOSED)
                } else {
                    operation(data, &mut guard, id)
                };
                Ok((guard, result))
            })
            .await?;
        self.guard = Some(guard);
        result
    }
}

#[async_trait]
impl LockScope for Scope<'_> {
    async fn lock(
        &mut self,
        range: ByteRange,
        exclusive: bool,
        fail_immediately: bool,
        request: &RequestContext,
    ) -> Result<(), Status> {
        range.validate()?;
        let file = self.file.as_ref().map_err(|status| *status)?.clone();
        let coordination = &file.data()?.coordination;
        let mut waiter = None;
        let mut timer = PolledTimer::new(&*self.io.driver);
        let mut delay = Duration::from_millis(1);
        loop {
            let listener = coordination.changed.listen();
            let result = self
                .operation(request, move |data, ledger, scope| {
                    if !fail_immediately && ledger.acquired.iter().any(|lock| lock.scope == scope) {
                        return Err(Status::INVALID_PARAMETER);
                    }

                    data.acquire(ledger, scope, range, exclusive)
                })
                .await;
            if fail_immediately || result != Err(Status::LOCK_NOT_GRANTED) {
                return result;
            }
            self.guard = None;
            if waiter.is_none() {
                waiter = Some(Waiter::new(coordination, request.id())?);
            }
            let mut changed = std::pin::pin!(listener.fuse());
            let mut cancelled = std::pin::pin!(request.cancelled().fuse());
            let mut retry = std::pin::pin!(timer.sleep(delay).fuse());
            futures::select_biased! {
                () = cancelled => return Err(Status::CANCELLED),
                () = changed => {},
                _ = retry => {},
            }
            delay = (delay * 2).min(Duration::from_millis(100));
        }
    }

    async fn unlock(&mut self, range: ByteRange, request: &RequestContext) -> Result<(), Status> {
        range.validate()?;
        self.operation(request, move |data, ledger, _| {
            let index = ledger
                .acquired
                .iter()
                .enumerate()
                .filter(|(_, lock)| lock.range == range)
                .max_by_key(|(_, lock)| lock.exclusive)
                .map(|(index, _)| index)
                .ok_or(Status::RANGE_NOT_LOCKED)?;
            data.remove(ledger, index, false)
        })
        .await
    }

    async fn settle(
        mut self: Box<Self>,
        settlement: LockSettlement,
        request: &RequestContext,
    ) -> Result<(), Status> {
        if settlement == LockSettlement::Rollback {
            self.operation(request, |data, ledger, scope| {
                while let Some(index) = ledger.acquired.iter().rposition(|lock| lock.scope == scope)
                {
                    data.remove(ledger, index, true)?;
                }
                Ok(())
            })
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pal_async::{DefaultDriver, async_test};
    use std::os::windows::fs::{FileExt, OpenOptionsExt};
    use test_with_tracing::test;
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;

    #[async_test]
    async fn accepted_lock_attempt_survives_unpolled_future_and_late_cancel(driver: DefaultDriver) {
        accepted_attempt(driver, false).await;
    }

    #[async_test]
    async fn accepted_lock_attempt_keeps_ledger_and_admission_after_awaiter_drop(
        driver: DefaultDriver,
    ) {
        accepted_attempt(driver, true).await;
    }

    async fn accepted_attempt(driver: DefaultDriver, drop_awaiter: bool) {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("accepted");
        let io = Io::new(Arc::new(driver));
        let coordination = Arc::new(Coordination::default());
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED)
            .open(&path)
            .unwrap();
        let file = Arc::new(NativeFile::Data(DataFile::new(
            native::overlapped(&*io.driver, file).unwrap(),
            coordination.clone(),
        )));
        let peer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let range = ByteRange {
            offset: 0,
            length: 1,
        };
        let request = RequestContext::new(1);
        let cleanup = RequestContext::new(2);
        let (started, starts) = async_channel::bounded(1);
        let (finished, finishes) = async_channel::bounded(1);
        let (release, wait) = std::sync::mpsc::channel();
        let mut scope = Scope::new(Ok(file.clone()), &io, &coordination);
        let mut attempt = Box::pin(scope.operation(&request, move |data, ledger, scope| {
            started.try_send(()).unwrap();
            wait.recv().unwrap();
            let result = data.acquire(ledger, scope, range, true);
            finished.try_send(()).unwrap();
            result
        }));
        assert!(futures::poll!(&mut attempt).is_pending());
        starts.recv().await.unwrap();
        request.cancel();
        if drop_awaiter {
            drop(attempt);
            drop(scope);
            release.send(()).unwrap();
            finishes.recv().await.unwrap();
        } else {
            release.send(()).unwrap();
            finishes.recv().await.unwrap();
            assert_eq!(
                peer.seek_write(b"x", 0).unwrap_err().raw_os_error(),
                Some(ERROR_LOCK_VIOLATION as i32)
            );
            attempt.await.unwrap();
            Box::new(scope)
                .settle(LockSettlement::Preserve, &cleanup)
                .await
                .unwrap();
        }
        assert_eq!(
            peer.seek_write(b"x", 0).unwrap_err().raw_os_error(),
            Some(ERROR_LOCK_VIOLATION as i32)
        );
        let mut unlock = Scope::new(Ok(file), &io, &coordination);
        unlock.unlock(range, &cleanup).await.unwrap();
        Box::new(unlock)
            .settle(LockSettlement::Preserve, &cleanup)
            .await
            .unwrap();
        assert_eq!(peer.seek_write(b"x", 0).unwrap(), 1);
    }
}
