// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows [`PollReadySet`] implementations.
//!
//! Each socket gets a per-socket AFD poll issued directly against the
//! backend's completion mechanism. Completions push [`ReadyEvent`]s into
//! a shared buffer and wake a single task-level waker. `poll_ready`
//! drains the buffer, making it O(ready_count).
//!
//! There is no `PollSocketReady` involved — the AFD IOCTLs are issued
//! directly, bypassing the per-socket waker overhead.

// UNSAFETY: Issues AFD poll IOCTLs with overlapped IO and handles raw
// pointers to overlapped structures in completion callbacks.
#![expect(unsafe_code)]

use crate::interest::PollEvents;
use crate::ready_set::PollReadySet;
use crate::ready_set::ReadyEvent;
use crate::waker::WakerList;
use pal::windows::Overlapped;
use pal::windows::afd;
use parking_lot::Mutex;
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::io;
use std::os::windows::prelude::*;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::Foundation::STATUS_CANCELLED;
use windows_sys::Win32::Foundation::STATUS_SUCCESS;
use windows_sys::Win32::System::IO::CancelIoEx;
use windows_sys::Win32::System::IO::OVERLAPPED;

use super::socket::AfdHandle;
use super::socket::make_poll_handle_info;
use super::socket::parse_poll_handle_info;

/// Shared state for a ready set: the event buffer, the task waker, and
/// the AFD handle used by completion callbacks to reissue polls.
pub(super) struct ReadySetShared<A> {
    pub(super) afd: A,
    inner: Mutex<ReadySetInner>,
}

struct ReadySetInner {
    events: Vec<ReadyEvent>,
    waker: Option<Waker>,
}

impl<A: AfdHandle> ReadySetShared<A> {
    fn new(afd: A) -> Self {
        Self {
            afd,
            inner: Mutex::new(ReadySetInner {
                events: Vec::new(),
                waker: None,
            }),
        }
    }

    /// Called by completion callbacks to push a ready event and wake.
    fn push_event(&self, event: ReadyEvent, wakers: &mut WakerList) {
        let mut inner = self.inner.lock();
        inner.events.push(event);
        if let Some(waker) = inner.waker.take() {
            wakers.push(waker);
        }
    }

    /// Sets or updates the task-level waker.
    fn set_waker(&self, waker: &Waker) {
        let mut inner = self.inner.lock();
        if !inner.waker.as_ref().is_some_and(|w| w.will_wake(waker)) {
            inner.waker = Some(waker.clone());
        }
    }

    /// Drains all buffered events into `out`. Returns `true` if any.
    fn drain(&self, out: &mut Vec<ReadyEvent>) -> bool {
        let mut inner = self.inner.lock();
        if inner.events.is_empty() {
            return false;
        }
        out.append(&mut inner.events);
        true
    }

    /// Removes any buffered events for a given key.
    fn remove_key(&self, key: usize) {
        let mut inner = self.inner.lock();
        inner.events.retain(|e| e.key != key);
    }
}

/// Per-socket AFD poll operation. The `overlapped` field must be first
/// so that a `*mut OVERLAPPED` can be cast to `*mut ReadySetOp<A>`.
#[repr(C)]
struct ReadySetOp<A> {
    overlapped: Overlapped,
    key: usize,
    socket: RawSocket,
    poll_info: UnsafeCell<PollInfoInput>,
    state: Mutex<OpState>,
    shared: Arc<ReadySetShared<A>>,
}

// SAFETY: The UnsafeCell<PollInfoInput> is only accessed when no IO is
// in flight (synchronized by OpState::in_flight).
unsafe impl<A: Send> Send for ReadySetOp<A> {}
// SAFETY: See above.
unsafe impl<A: Sync> Sync for ReadySetOp<A> {}

#[repr(C)]
#[derive(Default)]
struct PollInfoInput {
    header: afd::PollInfo,
    data: afd::PollHandleInfo,
}

struct OpState {
    events: PollEvents,
    in_flight: bool,
    cancelled: bool,
}

impl<A: AfdHandle> ReadySetOp<A> {
    fn new(
        key: usize,
        socket: RawSocket,
        events: PollEvents,
        shared: Arc<ReadySetShared<A>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            overlapped: Overlapped::new(),
            key,
            socket,
            poll_info: UnsafeCell::new(PollInfoInput::default()),
            state: Mutex::new(OpState {
                events,
                in_flight: false,
                cancelled: false,
            }),
            shared,
        })
    }

    /// Issues the AFD poll. Returns `true` if it completed synchronously.
    #[must_use]
    fn issue_io(self: &Arc<Self>, state: &mut OpState) -> bool {
        state.in_flight = true;
        // SAFETY: No IO is in flight, so we have exclusive access.
        let poll_info = unsafe { &mut *self.poll_info.get() };
        *poll_info = PollInfoInput {
            header: afd::PollInfo {
                timeout: i64::MAX,
                number_of_handles: 1,
                exclusive: 0,
            },
            data: make_poll_handle_info(self.socket as RawHandle, state.events),
        };

        let len = size_of_val(poll_info);
        // SAFETY: Buffers are valid for the lifetime of the operation.
        let done = unsafe {
            afd::poll(
                self.shared.afd.ref_io(),
                &mut poll_info.header,
                len,
                self.overlapped.as_ptr(),
            )
        };

        if done {
            // SAFETY: IO completed synchronously.
            unsafe { self.shared.afd.deref_io() };
            true
        } else {
            // The IO completion will reclaim this reference.
            let _proof = state;
            let _ = Arc::into_raw(self.clone());
            false
        }
    }

    fn cancel_io(&self) {
        // SAFETY: no safety requirements.
        unsafe {
            CancelIoEx(self.shared.afd.handle(), self.overlapped.as_ptr());
        }
    }

    /// Starts monitoring. Called by `add` and after readiness is consumed.
    fn start(self: &Arc<Self>) {
        let mut wakers = WakerList::default();
        let mut state = self.state.lock();
        if state.in_flight {
            return;
        }
        if self.issue_io(&mut state) {
            self.handle_completion(&mut state, STATUS_SUCCESS, &mut wakers);
        }
        drop(state);
        wakers.wake();
    }

    fn handle_completion(
        self: &Arc<Self>,
        state: &mut OpState,
        mut status: NTSTATUS,
        wakers: &mut WakerList,
    ) {
        loop {
            let revents = if windows_result::HRESULT::from_nt(status).is_ok() {
                // SAFETY: No IO is in flight.
                let poll_info = unsafe { &*self.poll_info.get() };
                assert_eq!(poll_info.header.number_of_handles, 1);
                parse_poll_handle_info(&poll_info.data)
            } else {
                assert_eq!(
                    status,
                    STATUS_CANCELLED,
                    "unexpected afd poll failure: {}",
                    pal::windows::status_to_error(status)
                );
                PollEvents::EMPTY
            };

            state.in_flight = false;
            state.cancelled = false;

            if !revents.is_empty() {
                self.shared.push_event(
                    ReadyEvent {
                        key: self.key,
                        events: revents,
                    },
                    wakers,
                );
                // Don't reissue — wait for poll_ready to drain and re-arm.
                break;
            }

            // Cancelled or spurious — reissue if events are still wanted.
            if state.events.is_empty() {
                break;
            }
            if self.issue_io(state) {
                status = STATUS_SUCCESS;
            } else {
                break;
            }
        }
    }

    /// Called from the completion callback.
    ///
    /// # Safety
    /// `overlapped` must point to a `ReadySetOp<A>` whose IO has completed.
    unsafe fn io_complete(overlapped: *mut OVERLAPPED, wakers: &mut WakerList) {
        let op_ptr = overlapped.cast::<ReadySetOp<A>>();
        // SAFETY: caller ensures overlapped points to a ReadySetOp.
        let op = unsafe { &*op_ptr };
        let (status, _) = op.overlapped.io_status().expect("io should be done");
        let mut state = op.state.lock();
        // SAFETY: Reclaim the Arc reference acquired in issue_io.
        let op = unsafe { Arc::from_raw(op_ptr) };
        op.handle_completion(&mut state, status, wakers);
        drop(state);
    }

    /// Cancels any in-flight IO.
    fn teardown(&self) {
        let state = self.state.lock();
        if state.in_flight {
            self.cancel_io();
        }
    }

    /// Updates the monitored events. Cancels in-flight IO if needed.
    fn modify_events(&self, events: PollEvents) {
        let mut state = self.state.lock();
        state.events = events;
        if state.in_flight && !state.cancelled {
            state.cancelled = true;
            self.cancel_io();
        }
    }
}

/// A [`PollReadySet`] backed by direct AFD polls against a backend's
/// completion mechanism.
///
/// `A` is the `AfdHandle` implementation that owns the AFD file and
/// routes completions. Each backend provides its own `A`.
pub struct AfdReadySet<A: AfdHandle> {
    ops: HashMap<usize, Arc<ReadySetOp<A>>>,
    shared: Arc<ReadySetShared<A>>,
}

impl<A: AfdHandle> AfdReadySet<A> {
    pub fn new(afd: A) -> Self {
        let shared = Arc::new(ReadySetShared::new(afd));
        Self {
            ops: HashMap::new(),
            shared,
        }
    }

    /// Returns a reference to the shared state (used by LocalReadySet
    /// to access the inner IOCP).
    pub(super) fn shared(&self) -> &ReadySetShared<A> {
        &self.shared
    }
}

impl<A: AfdHandle + Unpin + Send + Sync + 'static> PollReadySet for AfdReadySet<A> {
    fn add(&mut self, key: usize, socket: RawSocket, events: PollEvents) -> io::Result<()> {
        if self.ops.contains_key(&key) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "key already exists in ready set",
            ));
        }
        let op = ReadySetOp::new(key, socket, events, self.shared.clone());
        op.start();
        self.ops.insert(key, op);
        Ok(())
    }

    fn remove(&mut self, key: usize) -> io::Result<()> {
        let op = self
            .ops
            .remove(&key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "key not found in ready set"))?;
        op.teardown();
        self.shared.remove_key(key);
        Ok(())
    }

    fn modify(&mut self, key: usize, events: PollEvents) -> io::Result<()> {
        let op = self
            .ops
            .get(&key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "key not found in ready set"))?;
        op.modify_events(events);
        Ok(())
    }

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut Vec<ReadyEvent>,
    ) -> Poll<io::Result<()>> {
        self.shared.set_waker(cx.waker());
        let start_len = out.len();
        if self.shared.drain(out) {
            // Re-arm the drained sockets.
            for event in &out[start_len..] {
                if let Some(op) = self.ops.get(&event.key) {
                    op.start();
                }
            }
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl<A: AfdHandle> Drop for AfdReadySet<A> {
    fn drop(&mut self) {
        for (_, op) in self.ops.drain() {
            op.teardown();
        }
    }
}

/// Dispatches a ready set AFD poll completion for the IOCP backend.
///
/// # Safety
/// `overlapped` must point to a `ReadySetOp<super::iocp::OwnedIocpReadySetAfd>`
/// whose IO has completed.
pub(super) unsafe fn iocp_ready_set_io_complete(
    overlapped: *mut OVERLAPPED,
    wakers: &mut WakerList,
) {
    // SAFETY: caller ensures overlapped is valid and the type matches.
    unsafe {
        ReadySetOp::<super::iocp::OwnedIocpReadySetAfd>::io_complete(overlapped, wakers);
    }
}

/// Dispatches a ready set AFD poll completion for the TpPool backend.
///
/// # Safety
/// `overlapped` must point to a `ReadySetOp<super::tp::OwnedTpReadySetAfd>`
/// whose IO has completed.
pub(super) unsafe fn tp_ready_set_io_complete(overlapped: *mut OVERLAPPED, wakers: &mut WakerList) {
    // SAFETY: caller ensures overlapped is valid and the type matches.
    unsafe {
        ReadySetOp::<super::tp::OwnedTpReadySetAfd>::io_complete(overlapped, wakers);
    }
}

/// Dispatches a ready set AFD poll completion for the LocalDriver backend.
///
/// # Safety
/// `overlapped` must point to a `ReadySetOp<super::local::OwnedLocalReadySetAfd>`
/// whose IO has completed.
pub(super) unsafe fn local_ready_set_io_complete(
    overlapped: *mut OVERLAPPED,
    wakers: &mut WakerList,
) {
    // SAFETY: caller ensures overlapped is valid and the type matches.
    unsafe {
        ReadySetOp::<super::local::OwnedLocalReadySetAfd>::io_complete(overlapped, wakers);
    }
}
