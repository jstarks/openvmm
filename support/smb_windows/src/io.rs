// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use async_channel::{Receiver, Sender};
use futures::FutureExt;
use pal_async::driver::Driver;
use smb::provider::RequestContext;
use smb::spec::Status;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct Buffer {
    bytes: Vec<u8>,
    start: usize,
    length: usize,
}

impl Buffer {
    pub fn new(length: usize, alignment: usize) -> Result<Self, Status> {
        if !alignment.is_power_of_two() {
            return Err(Status::NOT_SUPPORTED);
        }
        let allocation = length
            .checked_add(alignment - 1)
            .ok_or(Status::INSUFFICIENT_RESOURCES)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(allocation)
            .map_err(|_| Status::INSUFFICIENT_RESOURCES)?;
        bytes.resize(allocation, 0);
        let start = bytes.as_ptr().align_offset(alignment);
        Ok(Self {
            bytes,
            start,
            length,
        })
    }

    pub fn into_vec(mut self, count: usize) -> Vec<u8> {
        if self.start != 0 {
            self.bytes.copy_within(self.start..self.start + count, 0);
        }
        self.bytes.truncate(count);
        self.bytes
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[self.start..self.start + self.length]
    }
}

impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[self.start..self.start + self.length]
    }
}

pub(crate) struct Io {
    pub driver: Arc<dyn Driver>,
    workers: Arc<Workers>,
    pub submitted: AtomicU64,
}

struct Workers {
    available: Receiver<()>,
    returned: Sender<()>,
}

struct Permit(Arc<Workers>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.returned.try_send(()).expect("one token per worker");
    }
}

pub(crate) fn check(request: &RequestContext) -> Result<(), Status> {
    if request.is_cancelled() {
        Err(Status::CANCELLED)
    } else {
        Ok(())
    }
}

impl Io {
    pub fn new(driver: Arc<dyn Driver>) -> Self {
        let (returned, available) = async_channel::bounded(4);
        for _ in 0..4 {
            returned.try_send(()).expect("initial worker tokens");
        }
        Self {
            driver,
            workers: Arc::new(Workers {
                available,
                returned,
            }),
            submitted: AtomicU64::new(0),
        }
    }

    /// Cancel admission, but drain submitted work and preserve its actual result.
    pub async fn worker<T: Send + 'static>(
        &self,
        request: &RequestContext,
        work: impl FnOnce() -> Result<T, Status> + Send + 'static,
    ) -> Result<T, Status> {
        check(request)?;
        let mut available = std::pin::pin!(self.workers.available.recv().fuse());
        let mut cancelled = std::pin::pin!(request.cancelled().fuse());
        futures::select_biased! {
            () = cancelled => return Err(Status::CANCELLED),
            result = available => result.expect("worker queue remains open"),
        }
        let permit = Permit(self.workers.clone());
        check(request)?;
        let keepalive = request.clone();
        self.submitted.fetch_add(1, Ordering::Relaxed);
        blocking::unblock(move || {
            let _permit = permit;
            let _keepalive = keepalive;
            work()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pal_async::{DefaultDriver, async_test};
    use std::sync::atomic::AtomicBool;
    use test_with_tracing::test;

    #[async_test]
    async fn worker_retains_admission_context_after_awaiter_is_dropped(driver: DefaultDriver) {
        struct Admission(Sender<()>);
        impl Drop for Admission {
            fn drop(&mut self) {
                self.0.try_send(()).unwrap();
            }
        }
        let io = Arc::new(Io::new(Arc::new(driver)));
        let (released, releases) = async_channel::bounded(1);
        let request = RequestContext::new(1).with_keepalive(Admission(released));
        let (started, starts) = async_channel::bounded(1);
        let (release, wait) = std::sync::mpsc::channel();
        let mut operation = Box::pin(async move {
            io.worker(&request, move || {
                started.try_send(()).unwrap();
                wait.recv().unwrap();
                Ok(())
            })
            .await
        });
        assert!(futures::poll!(&mut operation).is_pending());
        starts.recv().await.unwrap();
        drop(operation);
        assert!(releases.try_recv().is_err());
        release.send(()).unwrap();
        releases.recv().await.unwrap();
    }

    #[async_test]
    async fn worker_capacity_survives_dropped_waiters_and_cancels_admission(driver: DefaultDriver) {
        let io = Io::new(Arc::new(driver));
        let request = RequestContext::new(1);
        let (started, starts) = async_channel::bounded(4);
        let mut releases = Vec::new();
        let mut operations = Vec::new();
        for _ in 0..4 {
            let (release, wait) = std::sync::mpsc::channel();
            releases.push(release);
            let started = started.clone();
            let mut operation = Box::pin(io.worker(&request, move || {
                started.try_send(()).unwrap();
                wait.recv().unwrap();
                Ok(())
            }));
            assert!(futures::poll!(&mut operation).is_pending());
            operations.push(operation);
        }
        for _ in 0..4 {
            starts.recv().await.unwrap();
        }
        let effect = Arc::new(AtomicBool::new(false));
        let work = effect.clone();
        let cancellation = RequestContext::new(2);
        let mut queued = std::pin::pin!(io.worker(&cancellation, move || {
            work.store(true, Ordering::Relaxed);
            Ok(())
        }));
        assert!(futures::poll!(&mut queued).is_pending());
        cancellation.cancel();
        assert_eq!(queued.await, Err(Status::CANCELLED));
        assert!(!effect.load(Ordering::Relaxed));
        assert_eq!(io.submitted.load(Ordering::Relaxed), 4);
        drop(operations);
        assert!(io.workers.available.is_empty());
        for release in releases {
            release.send(()).unwrap();
        }
        for _ in 0..4 {
            io.workers.available.recv().await.unwrap();
        }
        for _ in 0..4 {
            io.workers.returned.try_send(()).unwrap();
        }
        io.worker(&request, || Ok(())).await.unwrap();
    }

    #[async_test]
    async fn submitted_worker_preserves_committed_effect_after_late_cancellation(
        driver: DefaultDriver,
    ) {
        let io = Io::new(Arc::new(driver));
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("committed");
        let backing = path.clone();
        let (started, starts) = async_channel::bounded(1);
        let (release, wait) = std::sync::mpsc::channel();
        let request = RequestContext::new(1);
        let mut operation = Box::pin(io.worker(&request, move || {
            started.try_send(()).unwrap();
            wait.recv().unwrap();
            std::fs::write(backing, b"committed").unwrap();
            Ok(())
        }));
        assert!(futures::poll!(&mut operation).is_pending());
        starts.recv().await.unwrap();
        request.cancel();
        release.send(()).unwrap();
        operation.await.unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"committed");
    }
}
