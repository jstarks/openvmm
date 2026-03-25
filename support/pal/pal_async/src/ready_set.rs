// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Batch readiness monitoring.
//!
//! This module defines the [`ReadySetDriver`] and [`PollReadySet`]
//! traits for monitoring many file descriptors (or sockets on Windows)
//! through a single polling point, returning all currently-ready entries
//! in one batch. This enables multiplexing with custom scheduling
//! policies (e.g., priority queues) instead of handling each fd in a
//! separate task.
//!
//! Platform-specific implementations live alongside their drivers:
//! - Linux: `NestedFdReadySet` (in `unix/ready_set.rs`) via nested epoll
//! - macOS: `NestedFdReadySet` (in `unix/ready_set.rs`) via nested kqueue

use crate::interest::PollEvents;
use std::io;
#[cfg(unix)]
use std::os::unix::prelude::*;
#[cfg(windows)]
use std::os::windows::prelude::*;
use std::task::Context;
use std::task::Poll;

/// A readiness event returned by [`PollReadySet::poll_ready`].
#[derive(Debug, Clone)]
pub struct ReadyEvent {
    /// The user-provided key identifying which fd is ready.
    pub key: usize,
    /// The readiness events (IN, OUT, ERR, HUP, etc.).
    pub events: PollEvents,
}

/// A trait for drivers that support creating [`PollReadySet`] instances.
pub trait ReadySetDriver: Unpin {
    /// The ready set type.
    type ReadySet: 'static + PollReadySet;

    /// Creates a new ready set for batch readiness monitoring.
    fn new_ready_set(&self) -> io::Result<Self::ReadySet>;
}

/// A trait for polling batch readiness.
///
/// File descriptors (or sockets on Windows) are registered with unique
/// integer keys. When polled, all currently-ready entries are returned
/// in one batch.
pub trait PollReadySet: Unpin + Send {
    /// Adds an fd to the set, monitoring for `events`.
    ///
    /// The `key` is returned in [`ReadyEvent`] to identify which fd
    /// is ready. Keys must be unique within the set.
    #[cfg(unix)]
    fn add(&mut self, key: usize, fd: RawFd, events: PollEvents) -> io::Result<()>;

    /// Adds a socket to the set, monitoring for `events`.
    #[cfg(windows)]
    fn add(&mut self, key: usize, socket: RawSocket, events: PollEvents) -> io::Result<()>;

    /// Removes an fd from the set.
    fn remove(&mut self, key: usize) -> io::Result<()>;

    /// Changes the monitored events for an fd.
    fn modify(&mut self, key: usize, events: PollEvents) -> io::Result<()>;

    /// Polls for readiness, appending all ready events to `out`.
    ///
    /// Returns `Poll::Ready(Ok(()))` when at least one event has been
    /// appended. Returns `Poll::Pending` when no sockets are currently ready.
    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut Vec<ReadyEvent>,
    ) -> Poll<io::Result<()>>;
}
