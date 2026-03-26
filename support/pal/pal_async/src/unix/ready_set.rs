// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`NestedFdReadySet`] — a [`PollReadySet`] backed by a nested poller fd.
//!
//! The platform-specific poller operations are provided via the
//! [`FdPoller`] trait, implemented in `epoll.rs` (Linux) and `kqueue.rs`
//! (macOS).

use crate::fd::FdReadyDriver;
use crate::fd::PollFdReady;
use crate::interest::InterestSlot;
use crate::interest::PollEvents;
use crate::ready_set::PollReadySet;
use crate::ready_set::ReadyEvent;
use std::collections::HashMap;
use std::io;
use std::os::unix::prelude::*;
use std::task::Context;
use std::task::Poll;
use std::task::ready;

/// A batch fd poller.
///
/// Implementors are newtypes around `OwnedFd` that implement [`AsFd`].
/// Implemented by the epoll backend (Linux) and kqueue backend (macOS).
pub trait FdPoller: AsFd + Send + Unpin {
    /// Creates a new poller.
    fn new() -> io::Result<Self>
    where
        Self: Sized;

    /// Registers an fd with the poller.
    fn register(&self, fd: RawFd, key: usize, events: PollEvents) -> io::Result<()>;

    /// Deregisters an fd from the poller.
    fn deregister(&self, fd: RawFd, events: PollEvents) -> io::Result<()>;

    /// Changes the monitored events for an fd.
    fn reregister(
        &self,
        fd: RawFd,
        key: usize,
        old_events: PollEvents,
        new_events: PollEvents,
    ) -> io::Result<()>;

    /// Non-blocking drain of all ready events from the poller.
    fn drain(&self, entries: &HashMap<usize, FdEntry>, out: &mut Vec<ReadyEvent>)
    -> io::Result<()>;
}

/// A ready set backed by a nested epoll (Linux) or kqueue (macOS) fd.
///
/// An inner poller fd is created and registered with the outer driver as a
/// single file descriptor. When any monitored fd becomes ready, the outer
/// driver wakes the set, which performs a non-blocking batch drain of the
/// poller.
///
/// `F` is the outer driver's [`PollFdReady`] implementation.
/// `P` is the platform's [`FdPoller`] implementation.
pub struct NestedFdReadySet<F, P> {
    // Drop order matters: outer_ready must be dropped first (deregisters
    // the inner fd from the outer poller), then inner poller (closes the
    // inner fd).
    outer_ready: F,
    inner: P,
    entries: HashMap<usize, FdEntry>,
}

pub struct FdEntry {
    pub fd: RawFd,
    pub events: PollEvents,
}

impl<F: PollFdReady, P: FdPoller> NestedFdReadySet<F, P> {
    /// Creates a new nested-fd ready set, registering the inner poller with
    /// the given driver for wakeup integration.
    pub fn new(driver: &impl FdReadyDriver<FdReady = F>) -> io::Result<Self> {
        let inner = P::new()?;
        let outer_ready = driver.new_fd_ready(inner.as_fd().as_raw_fd())?;
        Ok(Self {
            outer_ready,
            inner,
            entries: HashMap::new(),
        })
    }
}

impl<F: PollFdReady, P: FdPoller> PollReadySet for NestedFdReadySet<F, P> {
    fn add(&mut self, key: usize, fd: RawFd, events: PollEvents) -> io::Result<()> {
        if self.entries.contains_key(&key) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "key already exists in ready set",
            ));
        }
        self.inner.register(fd, key, events)?;
        self.entries.insert(key, FdEntry { fd, events });
        Ok(())
    }

    fn remove(&mut self, key: usize) -> io::Result<()> {
        let entry = self
            .entries
            .remove(&key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "key not found in ready set"))?;
        self.inner.deregister(entry.fd, entry.events)?;
        Ok(())
    }

    fn modify(&mut self, key: usize, events: PollEvents) -> io::Result<()> {
        let entry = self
            .entries
            .get_mut(&key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "key not found in ready set"))?;
        let old_events = entry.events;
        self.inner.reregister(entry.fd, key, old_events, events)?;
        entry.events = events;
        Ok(())
    }

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut Vec<ReadyEvent>,
    ) -> Poll<io::Result<()>> {
        loop {
            ready!(
                self.outer_ready
                    .poll_fd_ready(cx, InterestSlot::Read, PollEvents::IN)
            );

            let start_len = out.len();
            self.inner.drain(&self.entries, out)?;

            // Clear outer readiness — the inner poller has been fully drained.
            self.outer_ready.clear_fd_ready(InterestSlot::Read);

            if out.len() > start_len {
                return Poll::Ready(Ok(()));
            }
            // Spurious wakeup, loop to re-poll.
        }
    }
}
