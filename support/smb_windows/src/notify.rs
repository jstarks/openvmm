// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::native::{self, NotifyBuffer};
use event_listener::Event;
use futures::FutureExt;
use futures::task::{ArcWake, waker_ref};
use pal_async::windows::overlapped::{CustomNt, OverlappedFile};
use parking_lot::Mutex;
use smb::provider::{Change, NotifyResult, RequestContext};
use smb::spec::{NotifyFilter, Status};
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

const WAITER_LIMIT: usize = 1024;
const BUFFER_LIMIT: usize = 256 * 1024;

struct Wake(Arc<Event>);

impl ArcWake for Wake {
    fn wake_by_ref(this: &Arc<Self>) {
        this.0.notify(usize::MAX);
    }
}

struct State {
    operation: Option<CustomNt<NotifyBuffer>>,
    queue: Vec<Change>,
    overflow: bool,
    terminal: Option<Status>,
    waiters: VecDeque<(u64, u64)>,
    next: u64,
}

pub(crate) struct Watch {
    state: Mutex<State>,
    file: Arc<OverlappedFile>,
    filter: NotifyFilter,
    tree: bool,
    changed: Arc<Event>,
    wake: Arc<Wake>,
    draining: futures::lock::Mutex<()>,
}

struct Waiter<'a> {
    watch: &'a Watch,
    id: u64,
}

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        self.watch
            .state
            .lock()
            .waiters
            .retain(|(id, _)| *id != self.id);
        self.watch.changed.notify(usize::MAX);
    }
}

impl Watch {
    pub fn new(
        file: Arc<OverlappedFile>,
        filter: NotifyFilter,
        tree: bool,
    ) -> Result<Arc<Self>, Status> {
        let changed = Arc::new(Event::new());
        let watch = Arc::new(Self {
            state: Mutex::new(State {
                operation: Some(native::notify(file.clone(), filter, tree)),
                queue: Vec::new(),
                overflow: false,
                terminal: None,
                waiters: VecDeque::new(),
                next: 1,
            }),
            file,
            filter,
            tree,
            wake: Arc::new(Wake(changed.clone())),
            changed,
            draining: futures::lock::Mutex::new(()),
        });
        let terminal = {
            let mut state = watch.state.lock();
            watch.refresh(&mut state);
            state.terminal
        };
        if let Some(status) = terminal {
            return Err(status);
        }
        Ok(watch)
    }

    fn refresh(&self, state: &mut State) {
        if state.terminal.is_some() {
            return;
        }
        let Some(operation) = state.operation.as_mut() else {
            return;
        };
        let wake = waker_ref(&self.wake);
        let mut cx = Context::from_waker(&wake);
        let Poll::Ready(((status, used), buffer)) = Pin::new(operation).poll(&mut cx) else {
            return;
        };
        state.operation = None;
        match native::notify_changes(status, used, &buffer) {
            Ok(Some(changes)) => {
                if state
                    .queue
                    .iter()
                    .chain(&changes)
                    .map(Change::encoded_len)
                    .sum::<usize>()
                    > BUFFER_LIMIT
                {
                    state.queue.clear();
                    state.overflow = true;
                } else {
                    state.queue.extend(changes);
                }
            }
            Ok(None) => {
                state.queue.clear();
                state.overflow = true;
            }
            Err(error) => {
                state.terminal = Some(if error == Status::NOTIFY_CLEANUP {
                    Status::DELETE_PENDING
                } else {
                    error
                });
            }
        }
        if state.terminal.is_none() {
            state.operation = Some(native::notify(self.file.clone(), self.filter, self.tree));
            // Register a stable wake target independent of any guest waiter.
            self.changed.notify(usize::MAX);
        }
    }

    pub fn invalidated(&self) -> bool {
        let mut state = self.state.lock();
        self.refresh(&mut state);
        state.terminal.is_some()
    }

    pub fn invalidate(&self) {
        let mut state = self.state.lock();
        state.terminal = Some(Status::DELETE_PENDING);
        state.queue.clear();
        if let Some(operation) = &mut state.operation {
            operation.cancel();
        }
        drop(state);
        self.changed.notify(usize::MAX);
    }

    #[cfg(test)]
    pub fn pending(&self, request: u64) -> bool {
        self.state
            .lock()
            .waiters
            .iter()
            .any(|(_, id)| *id == request)
    }

    pub async fn shutdown(&self) {
        let _drain = self.draining.lock().await;
        let operation = {
            let mut state = self.state.lock();
            state.terminal.get_or_insert(Status::NOTIFY_CLEANUP);
            state.operation.take()
        };
        self.changed.notify(usize::MAX);
        if let Some(mut operation) = operation {
            operation.cancel();
            operation.await;
        }
    }

    pub async fn notify(
        &self,
        output: usize,
        request: &RequestContext,
    ) -> Result<NotifyResult, Status> {
        let id = {
            let mut state = self.state.lock();
            if state.waiters.len() == WAITER_LIMIT {
                return Err(Status::INSUFFICIENT_RESOURCES);
            }
            let id = state.next;
            state.next = id.checked_add(1).ok_or(Status::INSUFFICIENT_RESOURCES)?;
            state.waiters.push_back((id, request.id()));
            id
        };
        let _waiter = Waiter { watch: self, id };
        loop {
            let listener = self.changed.listen();
            {
                let mut state = self.state.lock();
                if let Some(status) = state.terminal {
                    return Err(status);
                }
                if request.is_cancelled() {
                    return Err(Status::CANCELLED);
                }
                if state.waiters.front().is_some_and(|(first, _)| *first == id) {
                    self.refresh(&mut state);
                    if let Some(status) = state.terminal {
                        return Err(status);
                    }
                    if state.overflow {
                        state.overflow = false;
                        return Ok(NotifyResult::Overflow);
                    }
                    if !state.queue.is_empty() {
                        if state.queue.iter().map(Change::encoded_len).sum::<usize>() > output {
                            return Ok(NotifyResult::Overflow);
                        }
                        return Ok(NotifyResult::Changes(std::mem::take(&mut state.queue)));
                    }
                }
            }
            let mut listener = std::pin::pin!(listener.fuse());
            let mut cancelled = std::pin::pin!(request.cancelled().fuse());
            futures::select! {
                () = listener => {},
                () = cancelled => {},
            }
        }
    }
}
