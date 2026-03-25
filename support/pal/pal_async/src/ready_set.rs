// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Batch socket readiness monitoring.
//!
//! [`NestedFdReadySet`] monitors many sockets through a single polling point,
//! returning all currently-ready sockets in one batch. This enables
//! multiplexing sockets with custom scheduling policies (e.g., priority
//! queues) instead of handling each socket in a separate task.

// UNSAFETY: libc calls for epoll (Linux) and kqueue (macOS) management.
#![cfg_attr(unix, expect(unsafe_code))]

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

// --- Unix: NestedFdReadySet using epoll (Linux) or kqueue (macOS) ---

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::fd::FdReadyDriver;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::fd::PollFdReady;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::interest::InterestSlot;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::HashMap;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::task::ready;

/// A ready set backed by a nested epoll (Linux) or kqueue (macOS) fd.
///
/// An inner poller fd is created and registered with the outer driver as a
/// single file descriptor. When any monitored socket becomes ready, the
/// outer driver wakes the set, which performs a non-blocking batch drain
/// of the inner poller.
///
/// The type parameter `F` is the outer driver's [`PollFdReady`]
/// implementation.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct NestedFdReadySet<F> {
    // Drop order matters: outer_ready must be dropped first (deregisters
    // the inner fd from the outer poller), then inner_fd (closes the inner
    // poller fd).
    outer_ready: F,
    inner_fd: OwnedFd,
    entries: HashMap<usize, SocketEntry>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct SocketEntry {
    fd: RawFd,
    events: PollEvents,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl<F: PollFdReady> NestedFdReadySet<F> {
    /// Creates a new nested-fd ready set, registering the inner poller with
    /// the given driver for wakeup integration.
    pub fn new(driver: &impl FdReadyDriver<FdReady = F>) -> io::Result<Self> {
        let inner_fd = create_inner()?;
        let outer_ready = driver.new_fd_ready(inner_fd.as_raw_fd())?;
        Ok(Self {
            outer_ready,
            inner_fd,
            entries: HashMap::new(),
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl<F: PollFdReady> PollReadySet for NestedFdReadySet<F> {
    fn add(&mut self, key: usize, fd: RawFd, events: PollEvents) -> io::Result<()> {
        if self.entries.contains_key(&key) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "key already exists in ready set",
            ));
        }
        inner_register(&self.inner_fd, fd, key, events)?;
        self.entries.insert(key, SocketEntry { fd, events });
        Ok(())
    }

    fn remove(&mut self, key: usize) -> io::Result<()> {
        let entry = self
            .entries
            .remove(&key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "key not found in ready set"))?;
        inner_deregister(&self.inner_fd, entry.fd, entry.events)?;
        Ok(())
    }

    fn modify(&mut self, key: usize, events: PollEvents) -> io::Result<()> {
        let entry = self
            .entries
            .get_mut(&key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "key not found in ready set"))?;
        let old_events = entry.events;
        inner_reregister(&self.inner_fd, entry.fd, key, old_events, events)?;
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
            inner_drain(&self.inner_fd, &self.entries, out)?;

            // Clear outer readiness — the inner poller has been fully drained.
            self.outer_ready.clear_fd_ready(InterestSlot::Read);

            if out.len() > start_len {
                return Poll::Ready(Ok(()));
            }
            // Spurious wakeup, loop to re-poll.
        }
    }
}

// --- Linux: epoll helpers ---

#[cfg(target_os = "linux")]
fn create_inner() -> io::Result<OwnedFd> {
    // SAFETY: epoll_create1 creates a new, uniquely owned fd.
    let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a newly created, uniquely owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn inner_register(inner_fd: &OwnedFd, fd: RawFd, key: usize, events: PollEvents) -> io::Result<()> {
    let mut event = libc::epoll_event {
        events: poll_events_to_epoll(events),
        u64: key as u64,
    };
    // SAFETY: calling epoll_ctl with valid epoll fd.
    if unsafe { libc::epoll_ctl(inner_fd.as_raw_fd(), libc::EPOLL_CTL_ADD, fd, &mut event) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn inner_deregister(inner_fd: &OwnedFd, fd: RawFd, _events: PollEvents) -> io::Result<()> {
    // SAFETY: calling epoll_ctl with valid epoll fd.
    if unsafe {
        libc::epoll_ctl(
            inner_fd.as_raw_fd(),
            libc::EPOLL_CTL_DEL,
            fd,
            std::ptr::null_mut(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn inner_reregister(
    inner_fd: &OwnedFd,
    fd: RawFd,
    key: usize,
    _old_events: PollEvents,
    new_events: PollEvents,
) -> io::Result<()> {
    let mut event = libc::epoll_event {
        events: poll_events_to_epoll(new_events),
        u64: key as u64,
    };
    // SAFETY: calling epoll_ctl with valid epoll fd.
    if unsafe { libc::epoll_ctl(inner_fd.as_raw_fd(), libc::EPOLL_CTL_MOD, fd, &mut event) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn inner_drain(
    inner_fd: &OwnedFd,
    entries: &HashMap<usize, SocketEntry>,
    out: &mut Vec<ReadyEvent>,
) -> io::Result<()> {
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 32];
    loop {
        // SAFETY: epoll_wait with valid fd and properly sized buffer.
        let n = unsafe {
            libc::epoll_wait(
                inner_fd.as_raw_fd(),
                events.as_mut_ptr(),
                events.len() as i32,
                0, // non-blocking
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        let n = n as usize;
        if n == 0 {
            break;
        }
        for event in &events[..n] {
            let key = event.u64 as usize;
            if entries.contains_key(&key) {
                let revents = PollEvents::from_epoll_events(event.events);
                if !revents.is_empty() {
                    out.push(ReadyEvent {
                        key,
                        events: revents,
                    });
                }
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn poll_events_to_epoll(events: PollEvents) -> u32 {
    let mut ep = libc::EPOLLET as u32;
    if events.has_in() {
        ep |= libc::EPOLLIN as u32;
    }
    if events.has_out() {
        ep |= libc::EPOLLOUT as u32;
    }
    if events.has_err() {
        ep |= libc::EPOLLERR as u32;
    }
    if events.has_hup() {
        ep |= libc::EPOLLHUP as u32;
    }
    if events.has_pri() {
        ep |= libc::EPOLLPRI as u32;
    }
    if events.has_rdhup() {
        ep |= libc::EPOLLRDHUP as u32;
    }
    ep
}

// --- macOS: kqueue helpers ---

#[cfg(target_os = "macos")]
fn create_inner() -> io::Result<OwnedFd> {
    // SAFETY: kqueue creates a new, uniquely owned fd.
    let fd = unsafe { libc::kqueue() };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a newly created, uniquely owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "macos")]
fn inner_register(inner_fd: &OwnedFd, fd: RawFd, key: usize, events: PollEvents) -> io::Result<()> {
    let mut changelist = Vec::new();
    if events.has_in() {
        changelist.push(libc::kevent64_s {
            ident: fd as u64,
            filter: libc::EVFILT_READ,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            udata: key as u64,
            ..empty_kevent()
        });
    }
    if events.has_out() {
        changelist.push(libc::kevent64_s {
            ident: fd as u64,
            filter: libc::EVFILT_WRITE,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            udata: key as u64,
            ..empty_kevent()
        });
    }
    if !changelist.is_empty() {
        kevent64(inner_fd, &changelist, &mut [])?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn inner_deregister(inner_fd: &OwnedFd, fd: RawFd, events: PollEvents) -> io::Result<()> {
    let mut changelist = Vec::new();
    if events.has_in() {
        changelist.push(libc::kevent64_s {
            ident: fd as u64,
            filter: libc::EVFILT_READ,
            flags: libc::EV_DELETE,
            ..empty_kevent()
        });
    }
    if events.has_out() {
        changelist.push(libc::kevent64_s {
            ident: fd as u64,
            filter: libc::EVFILT_WRITE,
            flags: libc::EV_DELETE,
            ..empty_kevent()
        });
    }
    if !changelist.is_empty() {
        kevent64(inner_fd, &changelist, &mut [])?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn inner_reregister(
    inner_fd: &OwnedFd,
    fd: RawFd,
    key: usize,
    old_events: PollEvents,
    new_events: PollEvents,
) -> io::Result<()> {
    let mut changelist = Vec::new();
    // Remove filters no longer needed.
    if old_events.has_in() && !new_events.has_in() {
        changelist.push(libc::kevent64_s {
            ident: fd as u64,
            filter: libc::EVFILT_READ,
            flags: libc::EV_DELETE,
            ..empty_kevent()
        });
    }
    if old_events.has_out() && !new_events.has_out() {
        changelist.push(libc::kevent64_s {
            ident: fd as u64,
            filter: libc::EVFILT_WRITE,
            flags: libc::EV_DELETE,
            ..empty_kevent()
        });
    }
    // Add or re-add filters.
    if new_events.has_in() {
        changelist.push(libc::kevent64_s {
            ident: fd as u64,
            filter: libc::EVFILT_READ,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            udata: key as u64,
            ..empty_kevent()
        });
    }
    if new_events.has_out() {
        changelist.push(libc::kevent64_s {
            ident: fd as u64,
            filter: libc::EVFILT_WRITE,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            udata: key as u64,
            ..empty_kevent()
        });
    }
    if !changelist.is_empty() {
        kevent64(inner_fd, &changelist, &mut [])?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn inner_drain(
    inner_fd: &OwnedFd,
    entries: &HashMap<usize, SocketEntry>,
    out: &mut Vec<ReadyEvent>,
) -> io::Result<()> {
    let mut events = [empty_kevent(); 32];
    loop {
        let n = kevent64(inner_fd, &[], &mut events)?;
        if n == 0 {
            break;
        }
        for event in &events[..n] {
            let key = event.udata as usize;
            if entries.contains_key(&key) {
                let mut revents = PollEvents::EMPTY;
                match event.filter {
                    libc::EVFILT_READ => {
                        revents |= PollEvents::IN;
                        if event.flags & libc::EV_EOF != 0 {
                            revents |= PollEvents::RDHUP;
                        }
                    }
                    libc::EVFILT_WRITE => {
                        revents |= PollEvents::OUT;
                        if event.flags & libc::EV_EOF != 0 {
                            revents |= PollEvents::HUP;
                        }
                    }
                    _ => {}
                }
                if !revents.is_empty() {
                    out.push(ReadyEvent {
                        key,
                        events: revents,
                    });
                }
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn kevent64(
    fd: &OwnedFd,
    changelist: &[libc::kevent64_s],
    eventlist: &mut [libc::kevent64_s],
) -> io::Result<usize> {
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        // SAFETY: calling kevent64 with valid fd and properly sized buffers.
        let n = unsafe {
            libc::kevent64(
                fd.as_raw_fd(),
                changelist.as_ptr(),
                changelist.len() as i32,
                eventlist.as_mut_ptr(),
                eventlist.len() as i32,
                0,
                &timeout,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        return Ok(n as usize);
    }
}

#[cfg(target_os = "macos")]
fn empty_kevent() -> libc::kevent64_s {
    libc::kevent64_s {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: 0,
        ext: [0; 2],
    }
}
