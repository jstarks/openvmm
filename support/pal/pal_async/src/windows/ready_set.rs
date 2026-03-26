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
//!
//! The [`ReadySetOp`] type is not parameterized by the backend — it
//! stores a raw AFD handle and never reissues polls from completion
//! callbacks. Instead, cancelled polls push to a `needs_rearm` list
//! that `poll_ready` processes on the next call. This keeps the op
//! type-erased and gives a single [`ready_set_io_complete`] dispatch
//! function shared by all backends.

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

/// Shared buffer between completion callbacks and `poll_ready`.
///
/// Not parameterized by the backend — all backends share the same type.
struct ReadySetShared {
    inner: Mutex<ReadySetInner>,
}

struct ReadySetInner {
    events: Vec<ReadyEvent>,
    needs_rearm: Vec<usize>,
    waker: Option<Waker>,
}

impl ReadySetShared {
    fn new() -> Self {
        Self {
            inner: Mutex::new(ReadySetInner {
                events: Vec::new(),
                needs_rearm: Vec::new(),
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

    /// Called by completion callbacks when a cancelled poll needs
    /// re-arming (events are still wanted).
    fn push_needs_rearm(&self, key: usize, wakers: &mut WakerList) {
        let mut inner = self.inner.lock();
        inner.needs_rearm.push(key);
        if let Some(waker) = inner.waker.take() {
            wakers.push(waker);
        }
    }

    fn set_waker(&self, waker: &Waker) {
        let mut inner = self.inner.lock();
        if !inner.waker.as_ref().is_some_and(|w| w.will_wake(waker)) {
            inner.waker = Some(waker.clone());
        }
    }

    /// Drains buffered events into `out`. Returns `true` if any.
    fn drain(&self, out: &mut Vec<ReadyEvent>) -> bool {
        let mut inner = self.inner.lock();
        if inner.events.is_empty() {
            return false;
        }
        out.append(&mut inner.events);
        true
    }

    /// Takes the needs-rearm list.
    fn take_needs_rearm(&self) -> Vec<usize> {
        let mut inner = self.inner.lock();
        std::mem::take(&mut inner.needs_rearm)
    }

    fn remove_key(&self, key: usize) {
        let mut inner = self.inner.lock();
        inner.events.retain(|e| e.key != key);
        inner.needs_rearm.retain(|&k| k != key);
    }
}

/// Per-socket AFD poll operation.
///
/// Not parameterized by the backend. Stores a raw AFD handle for
/// `CancelIoEx` and never reissues polls from completion callbacks.
/// The `overlapped` field must be first so that a `*mut OVERLAPPED`
/// can be cast to `*mut ReadySetOp`.
#[repr(C)]
struct ReadySetOp {
    overlapped: Overlapped,
    key: usize,
    socket: RawSocket,
    afd_handle: RawHandle,
    poll_info: UnsafeCell<PollInfoInput>,
    state: Mutex<OpState>,
    shared: Arc<ReadySetShared>,
}

// SAFETY: The UnsafeCell<PollInfoInput> is only accessed when no IO is
// in flight (synchronized by OpState::in_flight). RawHandle is just a
// pointer-sized value.
unsafe impl Send for ReadySetOp {}
// SAFETY: See above.
unsafe impl Sync for ReadySetOp {}

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

impl ReadySetOp {
    fn new(
        key: usize,
        socket: RawSocket,
        afd_handle: RawHandle,
        events: PollEvents,
        shared: Arc<ReadySetShared>,
    ) -> Arc<Self> {
        Arc::new(Self {
            overlapped: Overlapped::new(),
            key,
            socket,
            afd_handle,
            poll_info: UnsafeCell::new(PollInfoInput::default()),
            state: Mutex::new(OpState {
                events,
                in_flight: false,
                cancelled: false,
            }),
            shared,
        })
    }

    /// Issues the AFD poll using `io_handle` (the return value of
    /// `AfdHandle::ref_io`). Returns `true` on sync completion.
    ///
    /// The caller is responsible for calling `ref_io` before and
    /// `deref_io` after (on sync completion).
    #[must_use]
    fn issue_io(self: &Arc<Self>, state: &mut OpState, io_handle: RawHandle) -> bool {
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
                io_handle,
                &mut poll_info.header,
                len,
                self.overlapped.as_ptr(),
            )
        };

        if done {
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
            CancelIoEx(self.afd_handle, self.overlapped.as_ptr());
        }
    }

    /// Processes a completion. Never reissues — pushes to
    /// `needs_rearm` if events are still wanted after cancellation.
    fn handle_completion(&self, state: &mut OpState, status: NTSTATUS, wakers: &mut WakerList) {
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
        } else if !state.events.is_empty() {
            // Cancelled but still interested — request re-arm from poll_ready.
            self.shared.push_needs_rearm(self.key, wakers);
        }
    }

    /// Cancels any in-flight IO and clears events so the completion
    /// handler will not request re-arm.
    fn teardown(&self) {
        let mut state = self.state.lock();
        state.events = PollEvents::EMPTY;
        if state.in_flight && !state.cancelled {
            state.cancelled = true;
            self.cancel_io();
        }
    }

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
/// `A` is the [`AfdHandle`] implementation that owns the AFD file and
/// manages IO lifecycle (`ref_io`/`deref_io`). The per-socket
/// [`ReadySetOp`]s are not parameterized by `A`.
pub struct AfdReadySet<A: AfdHandle> {
    afd: A,
    ops: HashMap<usize, Arc<ReadySetOp>>,
    shared: Arc<ReadySetShared>,
}

impl<A: AfdHandle> AfdReadySet<A> {
    pub fn new(afd: A) -> Self {
        Self {
            afd,
            ops: HashMap::new(),
            shared: Arc::new(ReadySetShared::new()),
        }
    }

    /// Arms an op: calls `ref_io`, issues the AFD poll, handles sync
    /// completion with `deref_io`.
    fn arm_op(&self, op: &Arc<ReadySetOp>) {
        let mut wakers = WakerList::default();
        let mut state = op.state.lock();
        if state.in_flight {
            return;
        }
        let io_handle = self.afd.ref_io();
        if op.issue_io(&mut state, io_handle) {
            // SAFETY: IO completed synchronously.
            unsafe { self.afd.deref_io() };
            op.handle_completion(&mut state, STATUS_SUCCESS, &mut wakers);
        }
        drop(state);
        wakers.wake();
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
        let op = ReadySetOp::new(key, socket, self.afd.handle(), events, self.shared.clone());
        self.arm_op(&op);
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

        // Re-arm ops that were cancelled (from modify) and need reissuing.
        for key in self.shared.take_needs_rearm() {
            if let Some(op) = self.ops.get(&key) {
                self.arm_op(op);
            }
        }

        let start_len = out.len();
        if self.shared.drain(out) {
            // Re-arm the drained sockets.
            for event in &out[start_len..] {
                if let Some(op) = self.ops.get(&event.key) {
                    self.arm_op(op);
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

/// Dispatches a ready set AFD poll completion.
///
/// All backends use the same [`ReadySetOp`] type, so there is one
/// dispatch function shared by IOCP, TpPool, and LocalDriver.
///
/// # Safety
/// `overlapped` must point to a [`ReadySetOp`] whose IO has completed.
pub(super) unsafe fn ready_set_io_complete(overlapped: *mut OVERLAPPED, wakers: &mut WakerList) {
    let op_ptr = overlapped.cast::<ReadySetOp>();
    // SAFETY: caller ensures overlapped points to a ReadySetOp.
    let op = unsafe { &*op_ptr };
    let (status, _) = op.overlapped.io_status().expect("io should be done");
    let mut state = op.state.lock();
    // SAFETY: Reclaim the Arc reference acquired in issue_io.
    let op = unsafe { Arc::from_raw(op_ptr) };
    op.handle_completion(&mut state, status, wakers);
    drop(state);
}
