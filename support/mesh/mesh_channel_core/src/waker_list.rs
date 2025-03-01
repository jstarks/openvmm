#![allow(unsafe_code)]

use parking_lot::Mutex;
use std::cell::UnsafeCell;
use std::future::Future;
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::ptr::null;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Acquire;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::Ordering::Release;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

struct AsyncDone {
    done: AtomicBool,
    lock: Mutex<()>,
    list: WakerNode,
}

impl AsyncDone {
    pub const fn new() -> Self {
        Self {
            done: AtomicBool::new(false),
            lock: Mutex::new(()),
            list: WakerNode::new(),
        }
    }

    pub fn mark_done(&self) {
        self.done.store(true, Release);
        let _lock = self.lock.lock();
        let mut next = std::mem::replace(unsafe { &mut (*self.list.next.get()) }, null());
        if next.is_null() {
            return;
        }
        let head = std::ptr::from_ref(&self.list).cast();
        while next != head {
            let waker = unsafe {
                let entry = &*next;
                next = *entry.node.next.get();
                let waker = (*entry.waker.get()).take();
                // Can't access the entry after this.
                entry.done.store(true, Release);
                waker
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    pub fn wait_done(&self) -> WaitDone<'_> {
        WaitDone {
            done: self,
            entry: WakerEntry {
                node: WakerNode::new(),
                waker: UnsafeCell::new(None),
                done: AtomicBool::new(false),
            },
            maybe_on_list: false,
            _pin: PhantomPinned,
        }
    }
}

struct WakerNode {
    next: UnsafeCell<*const WakerEntry>,
    prev: UnsafeCell<*const WakerEntry>,
}

impl WakerNode {
    const fn new() -> Self {
        Self {
            next: UnsafeCell::new(null()),
            prev: UnsafeCell::new(null()),
        }
    }
}

#[repr(C)]
struct WakerEntry {
    // Must come first.
    node: WakerNode,
    waker: UnsafeCell<Option<Waker>>,
    done: AtomicBool,
}

struct WaitDone<'a> {
    done: &'a AsyncDone,
    entry: WakerEntry,
    maybe_on_list: bool,
    _pin: PhantomPinned,
}

impl Future for WaitDone<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        let done = this.done;
        let done_bool = if this.maybe_on_list {
            &this.entry.done
        } else {
            &done.done
        };
        if done_bool.load(Acquire) {
            this.maybe_on_list = false;
            return Poll::Ready(());
        }
        let _lock = done.lock.lock();
        if done_bool.load(Relaxed) {
            this.maybe_on_list = false;
            return Poll::Ready(());
        }
        if !this.maybe_on_list {
            let entry_ptr = std::ptr::from_ref(&this.entry);
            let list_ptr = std::ptr::from_ref(&done.list).cast();
            let node = &this.entry.node;
            unsafe {
                if (*done.list.next.get()).is_null() {
                    // The list is empty. This is special cased since the list can
                    // move while it's empty.
                    *done.list.next.get() = entry_ptr;
                    *done.list.prev.get() = entry_ptr;
                    *node.next.get() = list_ptr;
                    *node.prev.get() = list_ptr;
                } else {
                    let prev = &**done.list.prev.get();
                    *prev.node.next.get() = entry_ptr;
                    *node.prev.get() = *done.list.prev.get();
                    *node.next.get() = list_ptr;
                    *done.list.prev.get() = entry_ptr;
                }
            }
            this.maybe_on_list = true;
        }
        let waker = unsafe { &mut *this.entry.waker.get() };
        if let Some(waker) = waker {
            waker.clone_from(cx.waker());
        } else {
            *waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }
}

impl Drop for WaitDone<'_> {
    fn drop(&mut self) {
        if !self.maybe_on_list {
            return;
        }
        if self.entry.done.load(Acquire) {
            // No longer on the list.
            return;
        }
        let _lock = self.done.lock.lock();
        if self.entry.done.load(Relaxed) {
            // No longer on the list.
            return;
        }
        // SAFETY: The entry nodes of all nodes on the list are protected by the
        // list lock.
        unsafe {
            let node = &self.entry.node;
            let next = *node.next.get();
            let prev = *node.prev.get();
            *(*prev).node.next.get() = next;
            *(*next).node.prev.get() = prev;
            let list_ptr = std::ptr::from_ref(&self.done.list).cast();
            let list_next = &mut *self.done.list.next.get();
            if *list_next == list_ptr {
                // The list is now empty and so it might move. Clear the pointer to
                // remember this.
                *list_next = null();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;
    use futures::future::join;
    use futures::future::join_all;
    use futures::FutureExt;
    use std::pin::pin;

    #[test]
    fn test_already_done() {
        let done = super::AsyncDone::new();
        done.mark_done();
        let fut = done.wait_done();
        fut.now_or_never().unwrap();
    }

    #[test]
    fn test_wait_done() {
        let done = super::AsyncDone::new();
        let fut = pin!(done.wait_done());
        block_on(join(fut, async { done.mark_done() }));
    }

    #[test]
    fn test_wait_done_many() {
        let done = super::AsyncDone::new();
        let mut futs = Vec::new();
        for _ in 0..100 {
            futs.push(Box::pin(done.wait_done()));
        }
        for fut in &mut futs {
            assert!((&mut *fut).now_or_never().is_none());
        }
        let mut n = 0;
        futs.retain(|_| {
            let i = n;
            n += 1;
            i % 2 == 0
        });
        block_on(join(join_all(futs), async { done.mark_done() }));
    }

    #[test]
    fn test_cancel() {
        let done = super::AsyncDone::new();
        let mut fut = pin!(done.wait_done());
        assert!((&mut fut).now_or_never().is_none());
    }

    #[test]
    fn test_cancel_after_wake() {
        let done = super::AsyncDone::new();
        let mut fut = pin!(done.wait_done());
        assert!((&mut fut).now_or_never().is_none());
        done.mark_done();
    }
}
