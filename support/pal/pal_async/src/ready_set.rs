// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Batch socket readiness monitoring.
//!
//! This module defines the [`SocketReadySetDriver`] and [`PollReadySet`]
//! traits for monitoring many sockets through a single polling point,
//! returning all currently-ready sockets in one batch. This enables
//! multiplexing sockets with custom scheduling policies (e.g., priority
//! queues) instead of handling each socket in a separate task.
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
    /// The user-provided key identifying which socket is ready.
    pub key: usize,
    /// The readiness events (IN, OUT, ERR, HUP, etc.).
    pub events: PollEvents,
}

/// A trait for drivers that support creating [`PollReadySet`] instances.
pub trait SocketReadySetDriver: Unpin {
    /// The ready set type.
    type ReadySet: 'static + PollReadySet;

    /// Creates a new ready set for batch socket monitoring.
    fn new_ready_set(&self) -> io::Result<Self::ReadySet>;
}

/// A trait for polling batch socket readiness.
///
/// Sockets are registered with unique integer keys. When polled, all
/// currently-ready sockets are returned in one batch.
pub trait PollReadySet: Unpin + Send {
    /// Adds a socket to the set, monitoring for `events`.
    ///
    /// The `key` is returned in [`ReadyEvent`] to identify which socket
    /// is ready. Keys must be unique within the set.
    #[cfg(unix)]
    fn add(&mut self, key: usize, fd: RawFd, events: PollEvents) -> io::Result<()>;

    /// Adds a socket to the set, monitoring for `events`.
    #[cfg(windows)]
    fn add(&mut self, key: usize, socket: RawSocket, events: PollEvents) -> io::Result<()>;

    /// Removes a socket from the set.
    fn remove(&mut self, key: usize) -> io::Result<()>;

    /// Changes the monitored events for a socket.
    fn modify(&mut self, key: usize, events: PollEvents) -> io::Result<()>;

    /// Polls for socket readiness, appending all ready events to `out`.
    ///
    /// Returns `Poll::Ready(Ok(()))` when at least one event has been
    /// appended. Returns `Poll::Pending` when no sockets are currently ready.
    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut Vec<ReadyEvent>,
    ) -> Poll<io::Result<()>>;
}
