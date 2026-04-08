// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A watch channel for broadcasting a single value to multiple receivers,
//! usable across mesh nodes.
//!
//! Follows `tokio::watch` semantics: a single sender updates a value, and
//! multiple receivers observe the latest value. The sender is not cloneable
//! but is transferable. Receivers are cloneable and transferable.
//!
//! For in-process use, sender and receivers share an [`Arc`]-backed core
//! with a [`RwLock`]. No serialization occurs. When an endpoint crosses a
//! process boundary, a port-based protocol handles remote updates with
//! credit-based backpressure (at most one in-flight message per subscriber).

// UNSAFETY: needed to avoid monomorphization (type-erased value storage).
#![expect(unsafe_code)]

use crate::error::ChannelError;
use crate::error::RecvError;
use mesh_node::local_node::HandleMessageError;
use mesh_node::local_node::HandlePortEvent;
use mesh_node::local_node::NodeError;
use mesh_node::local_node::Port;
use mesh_node::local_node::PortControl;
use mesh_node::local_node::PortWithHandler;
use mesh_node::message::MeshField;
use mesh_node::message::Message;
use mesh_node::message::OwnedMessage;
use mesh_node::resource::Resource;
use mesh_protobuf::DefaultEncoding;
use mesh_protobuf::MessageDecode;
use mesh_protobuf::MessageEncode;
use mesh_protobuf::Protobuf;
use mesh_protobuf::encoding::MessageEncoding;
use mesh_protobuf::inplace_none;
use parking_lot::Mutex;
use parking_lot::RwLock;
use parking_lot::RwLockReadGuard;
use std::fmt;
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::mem;
use std::ops::Deref;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::Weak;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

// ---- Type-erased value ---------------------------------------------------

struct ErasedValue(NonNull<()>);

// SAFETY: the public API enforces Send/Sync via PhantomData on typed wrappers.
unsafe impl Send for ErasedValue {}
// SAFETY: see above.
unsafe impl Sync for ErasedValue {}

impl ErasedValue {
    fn new<T>(value: Box<T>) -> Self {
        Self(NonNull::new(Box::into_raw(value).cast()).unwrap())
    }

    /// # Safety
    /// `T` must match the type used at construction.
    unsafe fn as_ref<T>(&self) -> &T {
        // SAFETY: caller guarantees T matches.
        unsafe { &*self.0.cast::<T>().as_ptr() }
    }

    /// Consumes self and returns the value.
    ///
    /// # Safety
    /// `T` must match the type used at construction.
    unsafe fn into_box<T>(self) -> Box<T> {
        // SAFETY: caller guarantees T matches.
        unsafe { Box::from_raw(self.0.cast::<T>().as_ptr()) }
    }

    fn dangling() -> Self {
        Self(NonNull::dangling())
    }

    /// Clones the value and returns a new `ErasedValue` containing the clone.
    ///
    /// # Safety
    ///
    /// `T` must match the type used at construction.
    unsafe fn clone_as<T: Clone>(&self) -> Self {
        // SAFETY: caller must ensure T matches the type used at construction.
        let clone: Box<T> = Box::new(unsafe { self.as_ref::<T>().clone() });
        Self::new(clone)
    }
}

// ---- Vtable --------------------------------------------------------------

struct WatchVtable {
    drop_value: unsafe fn(ErasedValue),
}

impl WatchVtable {
    const fn new<T: 'static + Send + Clone>() -> Self {
        /// # Safety
        /// `v` must contain a value of type `T`.
        unsafe fn drop_value<T>(v: ErasedValue) {
            // SAFETY: guaranteed by caller.
            let _ = unsafe { v.into_box::<T>() };
        }
        Self {
            drop_value: drop_value::<T>,
        }
    }
}

/// Clones a type-erased value and wraps it in an `EncodedUpdate<T>` message.
///
/// # Safety
/// The `ErasedValue` must contain a value of type `T`.
unsafe fn make_update_msg<T: 'static + MeshField + Send + Clone>(
    v: &ErasedValue,
    version: u64,
) -> Message<'static> {
    Message::new(EncodedUpdate::<T> {
        version,
        // SAFETY: guaranteed by caller.
        value: Box::new(unsafe { v.as_ref::<T>() }.clone()),
    })
}

/// Decodes an `EncodedUpdate<T>` from a message.
///
/// # Safety
/// The message must have been encoded as `EncodedUpdate<T>`.
unsafe fn decode_update_msg<T: 'static + MeshField>(
    message: Message<'_>,
) -> Result<(u64, ErasedValue), ChannelError> {
    let u: EncodedUpdate<T> = message.parse().map_err(ChannelError::from)?;
    Ok((u.version, ErasedValue::new::<T>(u.value)))
}

// ---- Wire protocol -------------------------------------------------------

#[derive(Protobuf)]
#[mesh(resource = "Resource")]
struct EncodedUpdate<T> {
    version: u64,
    value: Box<T>,
}

#[derive(Protobuf)]
#[mesh(resource = "Resource")]
enum ReceiverMessage {
    Ack(u64),
    Subscribe(u64, Port),
}

// ---- Shared core ---------------------------------------------------------

struct WatchCore {
    state: RwLock<WatchState>,
    waiters: Mutex<Vec<Waker>>,
    vtable: &'static WatchVtable,
    /// How to register new remote subscribers.
    ///
    /// - Sender-side core (`Local`): pending queue drained by the sender
    ///   during `send()`.
    /// - Receiver-side core (`Upstream`): forwards subscribe requests
    ///   through the upstream port to the sender.
    subscribe: Mutex<SubscribeState>,
}

/// How a `WatchCore` routes subscribe requests for new remote subscribers.
enum SubscribeState {
    /// Sender-side: pending queue for subscriber registrations.
    /// The `make_msg` fn is set at encoding boundaries where `MeshField`
    /// is available; `None` if no receiver has been encoded yet.
    Local {
        pending: Vec<(u64, Port)>,
        make_msg: Option<unsafe fn(&ErasedValue, u64) -> Message<'static>>,
    },
    /// Receiver-side: upstream port for forwarding subscribe requests.
    Upstream(PortWithHandler<WatchPortHandler>),
}

struct WatchState {
    version: u64,
    value: ErasedValue,
    closed: bool,
}

impl Drop for WatchCore {
    fn drop(&mut self) {
        let state = self.state.get_mut();
        let val = mem::replace(&mut state.value, ErasedValue::dangling());
        // SAFETY: vtable matches the type.
        unsafe { (self.vtable.drop_value)(val) };
    }
}

impl Debug for WatchCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.read();
        f.debug_struct("WatchCore")
            .field("version", &state.version)
            .field("closed", &state.closed)
            .finish()
    }
}

// ---- SubHandler (sender side, one per remote receiver) -------------------

struct SubHandler {
    core: Arc<WatchCore>,
    pending_ack: bool,
    sent_version: u64,
    /// Type-erased fn to build an update message from the current value.
    /// Captured at encoding boundaries where `MeshField` is available.
    make_msg: unsafe fn(&ErasedValue, u64) -> Message<'static>,
}

impl HandlePortEvent for SubHandler {
    fn message(
        &mut self,
        control: &mut PortControl<'_, '_>,
        message: Message<'_>,
    ) -> Result<(), HandleMessageError> {
        let msg: ReceiverMessage = message.parse().map_err(HandleMessageError::new)?;
        match msg {
            ReceiverMessage::Ack(_) => {
                self.pending_ack = false;
                let state = self.core.state.read();
                if self.sent_version < state.version {
                    // SAFETY: make_msg matches the type.
                    let msg = unsafe { (self.make_msg)(&state.value, state.version) };
                    control.respond(msg);
                    self.pending_ack = true;
                    self.sent_version = state.version;
                }
            }
            ReceiverMessage::Subscribe(version, port) => {
                // Hold state(R) across the eager send AND the subscriber
                // registration so that the version we register with matches
                // the value we sent (or the current version if no send was
                // needed). Dropping state before registering would allow
                // send() to fire in between, and the subscriber would miss
                // that update.
                let state = self.core.state.read();
                if version > state.version {
                    return Err(HandleMessageError::new(
                        "subscriber claims to have seen future version",
                    ));
                }
                if version < state.version {
                    // SAFETY: make_msg matches the type.
                    let msg = unsafe { (self.make_msg)(&state.value, state.version) };
                    port.send(msg);
                }
                // state(R) → subscribe(M) is safe because send() drops
                // state(W) before acquiring subscribe(M).
                register_subscriber(&self.core, &state, port, self.make_msg);
            }
        }
        Ok(())
    }

    fn close(&mut self, _control: &mut PortControl<'_, '_>) {}
    fn fail(&mut self, _control: &mut PortControl<'_, '_>, _err: NodeError) {}
    fn drain(&mut self) -> Vec<OwnedMessage> {
        Vec::new()
    }
}

// ---- WatchPortHandler (receiver side, upstream) --------------------------

struct WatchPortHandler {
    core: Weak<WatchCore>,
    decode: unsafe fn(Message<'_>) -> Result<(u64, ErasedValue), ChannelError>,
}

impl HandlePortEvent for WatchPortHandler {
    fn message(
        &mut self,
        control: &mut PortControl<'_, '_>,
        message: Message<'_>,
    ) -> Result<(), HandleMessageError> {
        let core = self
            .core
            .upgrade()
            .ok_or_else(|| HandleMessageError::new("watch core dropped"))?;
        let (version, value) =
            // SAFETY: decode matches the type used to encode.
            unsafe { (self.decode)(message) }.map_err(HandleMessageError::new)?;
        let mut state = core.state.write();
        let current = state.version;
        let (old, r) = if version > current {
            let old = mem::replace(&mut state.value, value);
            state.version = version;
            drop(state);
            control.respond(Message::new(ReceiverMessage::Ack(version)));
            for waker in core.waiters.lock().drain(..) {
                control.wake(waker);
            }
            (old, Ok(()))
        } else {
            drop(state);
            (
                value,
                Err(HandleMessageError::new(
                    "received stale or duplicate update",
                )),
            )
        };
        // SAFETY: vtable matches the type.
        unsafe { (core.vtable.drop_value)(old) };
        r
    }

    fn close(&mut self, control: &mut PortControl<'_, '_>) {
        let Some(core) = self.core.upgrade() else {
            return;
        };
        core.state.write().closed = true;
        for waker in core.waiters.lock().drain(..) {
            control.wake(waker);
        }
    }

    fn fail(&mut self, control: &mut PortControl<'_, '_>, _err: NodeError) {
        self.close(control);
    }

    fn drain(&mut self) -> Vec<OwnedMessage> {
        Vec::new()
    }
}

// ---- WatchSender ---------------------------------------------------------

/// The sending half of a watch channel, created by [`watch`].
///
/// Not cloneable, but transferable across mesh nodes via encoding.
pub struct WatchSender<T> {
    core: WatchSenderCore,
    /// Cached encoded form, built during `compute_message_size` and
    /// consumed during `write_message`.
    cached_encoding: Option<EncodedWatchSender<T>>,
}

impl<T> Debug for WatchSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchSender")
            .field("core", &self.core.core)
            .finish()
    }
}

struct WatchSenderCore {
    core: Arc<WatchCore>,
    subscribers: Vec<PortWithHandler<SubHandler>>,
}

impl<T: 'static + Send + Sync> WatchSender<T> {
    /// Updates the watched value. Non-blocking. Returns the previous value.
    pub fn send(&mut self, value: T) -> T {
        // SAFETY: the core has element type T.
        unsafe { self.core.send::<T>(value) }
    }

    /// Reads the current value via an RAII guard.
    pub fn borrow(&self) -> Ref<'_, T> {
        Ref {
            guard: self.core.core.state.read(),
            _phantom: PhantomData,
        }
    }

    /// Creates a new receiver subscribed to this sender.
    pub fn subscribe(&mut self) -> WatchReceiver<T> {
        let version = self.core.core.state.read().version;
        WatchReceiver {
            core: WatchReceiverCore {
                core: self.core.core.clone(),
                last_seen: version,
            },
            cached_encoding: None,
        }
    }
}

impl WatchSenderCore {
    /// # Safety
    /// The core must have element type `T`.
    unsafe fn send<T>(&mut self, value: T) -> T {
        fn send_erased(this: &mut WatchSenderCore, value: ErasedValue) -> ErasedValue {
            // Bump version and swap value.
            let (version, old_value) = {
                let mut state = this.core.state.write();
                state.version += 1;
                let old = mem::replace(&mut state.value, value);
                (state.version, old)
            };
            // state(W) is now released.

            // Drain pending subscribes from the core (from receiver
            // encoding or SubHandler Subscribe messages).
            this.drain_pending_subscribes(version);

            // Send update to non-pending subscribers.
            //
            // N.B. We use `with_handler` + `pwh.send()` instead of
            // `with_port_and_handler` + `control.respond()` to avoid a deadlock:
            // `with_port_and_handler` holds the port lock during event processing,
            // and if the peer responds with an ack that targets this port, the ack
            // delivery tries to reacquire the lock. `Port::send()` releases the
            // port lock before processing events.
            this.subscribers.retain(|sub| {
                if sub.is_closed().unwrap_or(true) {
                    return false;
                }
                let make_msg = sub.with_handler(|handler| {
                    if !handler.pending_ack && handler.sent_version < version {
                        handler.pending_ack = true;
                        handler.sent_version = version;
                        Some(handler.make_msg)
                    } else {
                        None
                    }
                });
                if let Some(make_msg) = make_msg {
                    // N.B. state(R) is held while send synchronously delivers
                    // to the peer's WatchPortHandler, which acquires *its own*
                    // core's state(W). This is safe because SubHandler and
                    // WatchPortHandler always belong to different WatchCore
                    // instances (created on opposite sides of the port encoding
                    // boundary), so there is no same-lock contention.
                    let state = this.core.state.read();
                    // SAFETY: make_msg matches the type (set at encoding boundary).
                    let msg = unsafe { make_msg(&state.value, state.version) };
                    sub.send(msg);
                }
                true
            });

            // Wake local receivers.
            for waker in this.core.waiters.lock().drain(..) {
                waker.wake();
            }

            old_value
        }

        let old_value = send_erased(self, ErasedValue::new::<T>(Box::new(value)));
        // SAFETY: core has element type T.
        *unsafe { old_value.into_box::<T>() }
    }

    fn drain_pending_subscribes(&mut self, current_version: u64) {
        let (subs, make_msg) = {
            let mut subscribe = self.core.subscribe.lock();
            match &mut *subscribe {
                SubscribeState::Local { pending, make_msg } => (mem::take(pending), *make_msg),
                SubscribeState::Upstream(_) => (Vec::new(), None),
            }
        };
        if let (Some(make_msg), false) = (make_msg, subs.is_empty()) {
            self.register_subscribers(subs, current_version, make_msg);
        }
    }

    fn register_subscribers(
        &mut self,
        subs: Vec<(u64, Port)>,
        current_version: u64,
        make_msg: unsafe fn(&ErasedValue, u64) -> Message<'static>,
    ) {
        for (ver, port) in subs {
            let handler = SubHandler {
                core: self.core.clone(),
                pending_ack: false,
                sent_version: ver,
                make_msg,
            };
            let sub = port.set_handler(handler);
            if ver < current_version {
                sub.with_handler(|handler| {
                    handler.pending_ack = true;
                    handler.sent_version = current_version;
                });
                // Same cross-core safety argument as in send() above.
                let state = self.core.state.read();
                // SAFETY: make_msg matches the type.
                let msg = unsafe { make_msg(&state.value, state.version) };
                sub.send(msg);
            }
            self.subscribers.push(sub);
        }
    }
}

impl Drop for WatchSenderCore {
    fn drop(&mut self) {
        {
            self.core.state.write().closed = true;
        }
        for waker in self.core.waiters.lock().drain(..) {
            waker.wake();
        }
        // subscriber PortWithHandlers are dropped here, closing their ports.
    }
}

// ---- WatchReceiver -------------------------------------------------------

/// The receiving half of a watch channel, created by [`watch`].
///
/// Cloneable. Transferable across mesh nodes via encoding.
pub struct WatchReceiver<T> {
    core: WatchReceiverCore,
    /// Cached encoded form for the encoding pipeline.
    cached_encoding: Option<EncodedWatchReceiver<T>>,
}

impl<T> Debug for WatchReceiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchReceiver")
            .field("core", &self.core.core)
            .field("last_seen", &self.core.last_seen)
            .finish()
    }
}

impl<T> Clone for WatchReceiver<T> {
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
            cached_encoding: None,
        }
    }
}

struct WatchReceiverCore {
    core: Arc<WatchCore>,
    last_seen: u64,
}

impl Clone for WatchReceiverCore {
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
            last_seen: self.last_seen,
        }
    }
}

impl WatchReceiverCore {
    fn poll_changed(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), RecvError>> {
        loop {
            {
                let state = self.core.state.read();
                if self.last_seen < state.version {
                    self.last_seen = state.version;
                    return Poll::Ready(Ok(()));
                }
                if state.closed {
                    return Poll::Ready(Err(RecvError::Closed));
                }
            }
            // Register waker under waiters lock, double-check to avoid
            // lost wakeup.
            let mut waiters = self.core.waiters.lock();
            {
                let state = self.core.state.read();
                if self.last_seen < state.version || state.closed {
                    drop(waiters);
                    continue;
                }
            }
            if !waiters.iter().any(|w| w.will_wake(cx.waker())) {
                waiters.push(cx.waker().clone());
            }
            return Poll::Pending;
        }
    }
}

impl<T: 'static + Send + Sync + Clone> WatchReceiver<T> {
    /// Gets a clone of the current value.
    pub fn get(&self) -> T {
        let state = self.core.core.state.read();
        // SAFETY: core has element type T.
        unsafe { state.value.as_ref::<T>() }.clone()
    }
}

impl<T: 'static + Send + Sync> WatchReceiver<T> {
    /// Reads the current value via an RAII guard.
    pub fn borrow(&self) -> Ref<'_, T> {
        Ref {
            guard: self.core.core.state.read(),
            _phantom: PhantomData,
        }
    }

    /// Reads the current value and marks it as seen.
    pub fn borrow_and_update(&mut self) -> Ref<'_, T> {
        let guard = self.core.core.state.read();
        self.core.last_seen = guard.version;
        Ref {
            guard,
            _phantom: PhantomData,
        }
    }

    /// Waits until the value has changed since the last observation.
    pub fn changed(&mut self) -> impl Future<Output = Result<(), RecvError>> + '_ {
        std::future::poll_fn(|cx| self.core.poll_changed(cx))
    }

    /// Polls the watch receiver to check if the value has changed since the
    /// last observation.
    pub fn poll_changed(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), RecvError>> {
        self.core.poll_changed(cx)
    }
}

// ---- Ref -----------------------------------------------------------------

/// RAII guard for reading the watched value.
pub struct Ref<'a, T> {
    guard: RwLockReadGuard<'a, WatchState>,
    _phantom: PhantomData<&'a T>,
}

impl<T> Deref for Ref<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the core has element type T.
        unsafe { self.guard.value.as_ref::<T>() }
    }
}

impl<T: Debug> Debug for Ref<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&**self, f)
    }
}

// ---- Encoding: WatchSender -----------------------------------------------

/// Encoding type for [`WatchSender`]. Not intended for direct use.
pub struct WatchSenderEncoding;

impl<T> DefaultEncoding for WatchSender<T> {
    type Encoding = MessageEncoding<WatchSenderEncoding>;
}

#[derive(Protobuf)]
#[mesh(resource = "Resource")]
struct EncodedWatchSender<T> {
    version: u64,
    value: Box<T>,
    subscribers: Vec<EncodedSubscriber>,
}

struct ErasedWatchSender {
    version: u64,
    value: ErasedValue,
    subscribers: Vec<EncodedSubscriber>,
}

#[derive(Protobuf)]
#[mesh(resource = "Resource")]
struct EncodedSubscriber {
    port: Port,
    pending_ack: bool,
    sent_version: u64,
}

impl<T: 'static + MeshField + Send + Sync + Clone> MessageEncode<WatchSender<T>, Resource>
    for WatchSenderEncoding
{
    fn compute_message_size(
        item: &mut WatchSender<T>,
        sizer: mesh_protobuf::protobuf::MessageSizer<'_>,
    ) {
        let mut encoded = build_encoded_sender::<T>(&mut item.core);
        <EncodedWatchSender<T> as DefaultEncoding>::Encoding::compute_message_size(
            &mut encoded,
            sizer,
        );
        item.cached_encoding = Some(encoded);
    }

    fn write_message(
        item: WatchSender<T>,
        writer: mesh_protobuf::protobuf::MessageWriter<'_, '_, Resource>,
    ) {
        let inner = mem::ManuallyDrop::new(item);
        // SAFETY: reading cached_encoding from ManuallyDrop, won't be used again.
        let encoded = unsafe { std::ptr::read(&inner.cached_encoding) }
            .expect("compute_message_size must be called before write_message");
        // Don't run WatchSenderCore::drop (which would set closed + wake waiters)
        // since the core has already been transferred.
        <EncodedWatchSender<T> as DefaultEncoding>::Encoding::write_message(encoded, writer);
    }
}

impl<'a, T: 'static + MeshField + Send + Sync + Clone> MessageDecode<'a, WatchSender<T>, Resource>
    for WatchSenderEncoding
{
    fn read_message(
        item: &mut mesh_protobuf::inplace::InplaceOption<'_, WatchSender<T>>,
        reader: mesh_protobuf::protobuf::MessageReader<'a, '_, Resource>,
    ) -> mesh_protobuf::Result<()> {
        inplace_none!(encoded: EncodedWatchSender<T>);
        <EncodedWatchSender<T> as DefaultEncoding>::Encoding::read_message(&mut encoded, reader)?;
        let encoded = encoded.take().unwrap();
        item.set(decode_sender(encoded));
        Ok(())
    }
}

/// Builds an `EncodedWatchSender<T>` by extracting state from the sender core.
/// This is destructive — it drains subscribers and pending requests.
fn build_encoded_sender<T: 'static + MeshField + Send + Sync + Clone>(
    core_ref: &mut WatchSenderCore,
) -> EncodedWatchSender<T> {
    fn build_encoded_sender(
        core_ref: &mut WatchSenderCore,
        clone: unsafe fn(&ErasedValue) -> ErasedValue,
        decode: unsafe fn(Message<'_>) -> Result<(u64, ErasedValue), ChannelError>,
    ) -> ErasedWatchSender {
        // Extract SubHandler state from active subscribers. This drops
        // the Arc<WatchCore> refs held by each SubHandler, which is
        // needed for get_mut to succeed below.
        let mut subscribers: Vec<EncodedSubscriber> = core_ref
            .subscribers
            .drain(..)
            .map(|sub| {
                let (port, handler) = sub.remove_handler();
                EncodedSubscriber {
                    port,
                    pending_ack: handler.pending_ack,
                    sent_version: handler.sent_version,
                }
            })
            .collect();

        // Try sole-owner fast path: take value without cloning.
        if let Some(core) = Arc::get_mut(&mut core_ref.core) {
            // Drain any pending subscribers too.
            let SubscribeState::Local { pending, .. } = core.subscribe.get_mut() else {
                panic!("sender core should never be in Upstream state");
            };
            subscribers.extend(mem::take(pending).into_iter().map(|(ver, port)| {
                EncodedSubscriber {
                    port,
                    pending_ack: false,
                    sent_version: ver,
                }
            }));
            let state = core.state.get_mut();
            let version = state.version;
            let value = mem::replace(&mut state.value, ErasedValue::dangling());
            return ErasedWatchSender {
                version,
                value,
                subscribers,
            };
        }

        // Shared path: local receivers exist. Install upstream port,
        // then drain pending + swap under lock while holding state(R).
        let (left, right) = Port::new_pair();
        let handler = WatchPortHandler {
            core: Arc::downgrade(&core_ref.core),
            decode,
        };
        let pwh = right.set_handler(handler);

        let state = core_ref.core.state.read();
        let version = state.version;
        // SAFETY: clone matches the type.
        let value = unsafe { clone(&state.value) };
        {
            let mut subscribe = core_ref.core.subscribe.lock();
            let SubscribeState::Local { pending, .. } = &mut *subscribe else {
                panic!("sender core should never be in Upstream state");
            };
            subscribers.extend(mem::take(pending).into_iter().map(|(ver, port)| {
                EncodedSubscriber {
                    port,
                    pending_ack: false,
                    sent_version: ver,
                }
            }));
            *subscribe = SubscribeState::Upstream(pwh);
        }
        drop(state);

        subscribers.push(EncodedSubscriber {
            port: left,
            pending_ack: false,
            sent_version: version,
        });

        ErasedWatchSender {
            version,
            value,
            subscribers,
        }
    }

    let ErasedWatchSender {
        version,
        value,
        subscribers,
    } = build_encoded_sender(core_ref, ErasedValue::clone_as::<T>, decode_update_msg::<T>);

    EncodedWatchSender {
        version,
        value: {
            // SAFETY: the core has element type T, and the value was cloned from it.
            unsafe { value.into_box::<T>() }
        },
        subscribers,
    }
}

/// Reconstructs a `WatchSender<T>` from its encoded form.
fn decode_sender<T: 'static + MeshField + Send + Sync + Clone>(
    encoded: EncodedWatchSender<T>,
) -> WatchSender<T> {
    /// Non-generic core of sender decoding: creates the WatchCore and
    /// installs SubHandlers on each subscriber port.
    fn decode_sender_core(
        encoded: ErasedWatchSender,
        vtable: &'static WatchVtable,
        make_msg: unsafe fn(&ErasedValue, u64) -> Message<'static>,
    ) -> (Arc<WatchCore>, Vec<PortWithHandler<SubHandler>>) {
        let core = Arc::new(WatchCore {
            state: RwLock::new(WatchState {
                version: encoded.version,
                value: encoded.value,
                closed: false,
            }),
            waiters: Mutex::new(Vec::new()),
            vtable,
            subscribe: Mutex::new(SubscribeState::Local {
                pending: Vec::new(),
                make_msg: Some(make_msg),
            }),
        });

        let subscribers = encoded
            .subscribers
            .into_iter()
            .map(|es| {
                es.port.set_handler(SubHandler {
                    core: core.clone(),
                    pending_ack: es.pending_ack,
                    sent_version: es.sent_version,
                    make_msg,
                })
            })
            .collect();

        (core, subscribers)
    }

    let encoded = ErasedWatchSender {
        version: encoded.version,
        value: ErasedValue::new::<T>(encoded.value),
        subscribers: encoded.subscribers,
    };

    let (core, subscribers) = decode_sender_core(
        encoded,
        const { &WatchVtable::new::<T>() },
        make_update_msg::<T>,
    );
    WatchSender {
        core: WatchSenderCore { core, subscribers },
        cached_encoding: None,
    }
}

// ---- Encoding: WatchReceiver ---------------------------------------------

/// Encoding type for [`WatchReceiver`]. Not intended for direct use.
pub struct WatchReceiverEncoding;

impl<T> DefaultEncoding for WatchReceiver<T> {
    type Encoding = MessageEncoding<WatchReceiverEncoding>;
}

#[derive(Protobuf)]
#[mesh(resource = "Resource")]
struct EncodedWatchReceiver<T> {
    version: u64,
    value: Box<T>,
    port: Port,
}

struct ErasedWatchReceiver {
    version: u64,
    value: ErasedValue,
    port: Port,
}

impl<T: 'static + MeshField + Send + Sync + Clone> MessageEncode<WatchReceiver<T>, Resource>
    for WatchReceiverEncoding
{
    fn compute_message_size(
        item: &mut WatchReceiver<T>,
        sizer: mesh_protobuf::protobuf::MessageSizer<'_>,
    ) {
        let mut encoded = build_encoded_receiver::<T>(&mut item.core);
        <EncodedWatchReceiver<T> as DefaultEncoding>::Encoding::compute_message_size(
            &mut encoded,
            sizer,
        );
        item.cached_encoding = Some(encoded);
    }

    fn write_message(
        item: WatchReceiver<T>,
        writer: mesh_protobuf::protobuf::MessageWriter<'_, '_, Resource>,
    ) {
        let encoded = item
            .cached_encoding
            .expect("compute_message_size must be called before write_message");
        <EncodedWatchReceiver<T> as DefaultEncoding>::Encoding::write_message(encoded, writer);
    }
}

impl<'a, T: 'static + MeshField + Send + Sync + Clone> MessageDecode<'a, WatchReceiver<T>, Resource>
    for WatchReceiverEncoding
{
    fn read_message(
        item: &mut mesh_protobuf::inplace::InplaceOption<'_, WatchReceiver<T>>,
        reader: mesh_protobuf::protobuf::MessageReader<'a, '_, Resource>,
    ) -> mesh_protobuf::Result<()> {
        inplace_none!(encoded: EncodedWatchReceiver<T>);
        <EncodedWatchReceiver<T> as DefaultEncoding>::Encoding::read_message(&mut encoded, reader)?;
        let encoded = encoded.take().unwrap();
        item.set(decode_receiver(encoded));
        Ok(())
    }
}

/// Builds an `EncodedWatchReceiver<T>` from a receiver core.
/// Registers a subscriber port and snapshots the current value.
fn build_encoded_receiver<T: 'static + MeshField + Send + Sync + Clone>(
    core_ref: &mut WatchReceiverCore,
) -> EncodedWatchReceiver<T> {
    fn build_encoded_receiver(
        core_ref: &mut WatchReceiverCore,
        clone: unsafe fn(&ErasedValue) -> ErasedValue,
        make_msg: unsafe fn(&ErasedValue, u64) -> Message<'static>,
    ) -> ErasedWatchReceiver {
        // If we're the sole owner of the core, take the value directly
        // without cloning or locking.
        if let Some(core) = Arc::get_mut(&mut core_ref.core) {
            let state = core.state.get_mut();
            let version = state.version;
            let value = mem::replace(&mut state.value, ErasedValue::dangling());
            let port = {
                let subscribe: &mut SubscribeState = core.subscribe.get_mut();
                match mem::replace(
                    subscribe,
                    SubscribeState::Local {
                        pending: Vec::new(),
                        make_msg: None,
                    },
                ) {
                    SubscribeState::Upstream(_pwh) => {
                        unreachable!("TODO: should this have been removed already?")
                    }
                    SubscribeState::Local { .. } => {
                        // Sender-side core, sole owner — the sender is gone.
                        // Create a dead port for the encoded receiver.
                        Port::new_pair().0
                    }
                }
            };
            return ErasedWatchReceiver {
                version,
                value,
                port,
            };
        }

        // Multiple clones exist. Hold state(R) across the snapshot AND the
        // subscriber registration to ensure the version we subscribe with
        // matches the value we encode — preventing a TOCTOU where send()
        // fires between the snapshot and the registration.
        let (left, right) = Port::new_pair();
        let state = core_ref.core.state.read();
        // Non-generic helper; state(R) → subscribe(M) is safe because
        // send() drops state(W) before acquiring subscribe(M).
        register_subscriber(&core_ref.core, &state, right, make_msg);
        ErasedWatchReceiver {
            version: state.version,
            value: {
                // SAFETY: core has element type T.
                unsafe { clone(&state.value) }
            },
            port: left,
        }
    }

    let ErasedWatchReceiver {
        version,
        value,
        port,
    } = build_encoded_receiver(core_ref, ErasedValue::clone_as::<T>, make_update_msg::<T>);

    EncodedWatchReceiver {
        version,
        value: {
            // SAFETY: the core has element type T, and the value was cloned from it.
            unsafe { value.into_box::<T>() }
        },
        port,
    }
}

/// Registers a subscriber port with the sender (non-generic).
///
/// Caller must hold `state` read lock to ensure the version matches the
/// current value — preventing a TOCTOU where `send()` fires between the
/// snapshot and registration.
fn register_subscriber(
    core: &WatchCore,
    state: &RwLockReadGuard<'_, WatchState>,
    port: Port,
    make_msg: unsafe fn(&ErasedValue, u64) -> Message<'static>,
) {
    let version = state.version;
    let mut subscribe = core.subscribe.lock();
    match &mut *subscribe {
        SubscribeState::Local {
            pending,
            make_msg: mm,
        } => {
            *mm = Some(make_msg);
            pending.push((version, port));
        }
        SubscribeState::Upstream(pwh) => {
            pwh.send(Message::new(ReceiverMessage::Subscribe(version, port)));
        }
    }
}

/// Reconstructs a `WatchReceiver<T>` from its encoded form.
fn decode_receiver<T: 'static + MeshField + Send + Sync + Clone>(
    encoded: EncodedWatchReceiver<T>,
) -> WatchReceiver<T> {
    /// Non-generic core of receiver decoding: creates the WatchCore and
    /// installs the upstream port handler.
    fn decode_receiver_core(
        encoded: ErasedWatchReceiver,
        vtable: &'static WatchVtable,
        decode: unsafe fn(Message<'_>) -> Result<(u64, ErasedValue), ChannelError>,
    ) -> WatchReceiverCore {
        let core = Arc::new(WatchCore {
            state: RwLock::new(WatchState {
                version: encoded.version,
                value: encoded.value,
                closed: false,
            }),
            waiters: Mutex::new(Vec::new()),
            vtable,
            subscribe: Mutex::new(SubscribeState::Local {
                pending: Vec::new(),
                make_msg: None,
            }),
        });

        let handler = WatchPortHandler {
            core: Arc::downgrade(&core),
            decode,
        };
        let upstream_pwh = encoded.port.set_handler(handler);
        *core.subscribe.lock() = SubscribeState::Upstream(upstream_pwh);
        WatchReceiverCore {
            core,
            last_seen: encoded.version,
        }
    }

    let encoded = ErasedWatchReceiver {
        version: encoded.version,
        value: ErasedValue::new::<T>(encoded.value),
        port: encoded.port,
    };

    let core = decode_receiver_core(
        encoded,
        const { &WatchVtable::new::<T>() },
        decode_update_msg::<T>,
    );
    WatchReceiver {
        core,
        cached_encoding: None,
    }
}

// ---- Constructor ---------------------------------------------------------

/// Creates a watch channel with the given initial value.
///
/// Returns the sender and an initial receiver. Additional receivers can
/// be created via [`WatchSender::subscribe`].
pub fn watch<T: 'static + Send + Sync + Clone>(initial: T) -> (WatchSender<T>, WatchReceiver<T>) {
    let vtable: &'static WatchVtable = const { &WatchVtable::new::<T>() };
    let core = Arc::new(WatchCore {
        state: RwLock::new(WatchState {
            version: 0,
            value: ErasedValue::new::<T>(Box::new(initial)),
            closed: false,
        }),
        waiters: Mutex::new(Vec::new()),
        vtable,
        subscribe: Mutex::new(SubscribeState::Local {
            pending: Vec::new(),
            make_msg: None,
        }),
    });

    let sender = WatchSenderCore {
        core: core.clone(),
        subscribers: Vec::new(),
    };
    let receiver = WatchReceiverCore { core, last_seen: 0 };

    (
        WatchSender {
            core: sender,
            cached_encoding: None,
        },
        WatchReceiver {
            core: receiver,
            cached_encoding: None,
        },
    )
}

// ---- Tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use mesh_node::resource::SerializedMessage;
    use test_with_tracing::test;

    /// Round-trip a value through mesh protobuf encoding/decoding.
    fn round_trip<T>(value: T) -> T
    where
        T: DefaultEncoding,
        T::Encoding: MessageEncode<T, Resource> + for<'a> MessageDecode<'a, T, Resource>,
    {
        SerializedMessage::from_message(value)
            .into_message()
            .unwrap()
    }

    // Verify Send/Sync bounds.
    static_assertions::assert_impl_all!(WatchSender<i32>: Send, Sync);
    static_assertions::assert_impl_all!(WatchReceiver<i32>: Send, Sync);
    static_assertions::assert_not_impl_any!(WatchSender<*const ()>: Send, Sync);
    static_assertions::assert_not_impl_any!(WatchReceiver<*const ()>: Send, Sync);

    #[test]
    fn test_send_borrow() {
        let (mut sender, receiver) = watch(5u32);
        assert_eq!(*sender.borrow(), 5);
        assert_eq!(*receiver.borrow(), 5);
        let old = sender.send(10);
        assert_eq!(old, 5);
        assert_eq!(*sender.borrow(), 10);
        assert_eq!(*receiver.borrow(), 10);
    }

    #[test]
    fn test_get() {
        let (mut sender, receiver) = watch(42u32);
        assert_eq!(receiver.get(), 42);
        sender.send(99);
        assert_eq!(receiver.get(), 99);
    }

    #[test]
    fn test_multiple_receivers() {
        let (mut sender, _r0) = watch(0u32);
        let r1 = sender.subscribe();
        let r2 = sender.subscribe();
        let r3 = sender.subscribe();
        sender.send(7);
        assert_eq!(*r1.borrow(), 7);
        assert_eq!(*r2.borrow(), 7);
        assert_eq!(*r3.borrow(), 7);
    }

    #[test]
    fn test_changed() {
        block_on(async {
            let (mut sender, mut receiver) = watch(0u32);
            sender.send(1);
            receiver.changed().await.unwrap();
            assert_eq!(*receiver.borrow(), 1);
        });
    }

    #[test]
    fn test_borrow_and_update() {
        block_on(async {
            let (mut sender, mut receiver) = watch(0u32);
            sender.send(1);
            {
                let val = receiver.borrow_and_update();
                assert_eq!(*val, 1);
            }
            // changed() should pend since we've seen version 1.
            #[allow(clippy::disallowed_methods)]
            let noop = futures::task::noop_waker_ref();
            let mut cx = Context::from_waker(noop);
            assert!(receiver.poll_changed(&mut cx).is_pending());
            // Send again.
            sender.send(2);
            assert!(receiver.poll_changed(&mut cx).is_ready());
        });
    }

    #[test]
    fn test_sender_drop_closes() {
        block_on(async {
            let (sender, mut receiver) = watch(0u32);
            drop(sender);
            let result = receiver.changed().await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_receiver_clone() {
        let (mut sender, receiver) = watch(0u32);
        let r2 = receiver.clone();
        sender.send(5);
        assert_eq!(*receiver.borrow(), 5);
        assert_eq!(*r2.borrow(), 5);
    }

    #[test]
    fn test_receiver_drop_sender_works() {
        let (mut sender, r1) = watch(0u32);
        let r2 = sender.subscribe();
        drop(r1);
        sender.send(10);
        assert_eq!(*r2.borrow(), 10);
    }

    #[test]
    fn test_sender_port_roundtrip() {
        block_on(async {
            let (sender, mut receiver) = watch(5u32);
            // Round-trip the sender through a Port.
            let mut sender = round_trip(sender);
            assert_eq!(*sender.borrow(), 5);
            sender.send(10);
            receiver.changed().await.unwrap();
            assert_eq!(*receiver.borrow(), 10);
        });
    }

    #[test]
    fn test_receiver_port_roundtrip() {
        block_on(async {
            let (mut sender, receiver) = watch(5u32);
            // Round-trip the receiver through a Port.
            let mut receiver = round_trip(receiver);
            assert_eq!(*receiver.borrow(), 5);
            sender.send(10);
            receiver.changed().await.unwrap();
            assert_eq!(*receiver.borrow(), 10);
        });
    }

    #[test]
    fn test_both_sides_remote() {
        block_on(async {
            let (sender, receiver) = watch(5u32);
            let mut sender = round_trip(sender);
            let mut receiver = round_trip(receiver);
            assert_eq!(*sender.borrow(), 5);
            assert_eq!(*receiver.borrow(), 5);
            sender.send(10);
            receiver.changed().await.unwrap();
            assert_eq!(*receiver.borrow(), 10);
        });
    }

    #[test]
    fn test_cloned_receiver_goes_remote() {
        block_on(async {
            let (mut sender, _r0) = watch(0u32);
            let r1 = sender.subscribe();
            // Clone r1, then send the clone through a port round-trip.
            // This triggers SubscribeRequest through the local pending queue
            // since both share the sender-side core.
            let mut r2 = round_trip(r1.clone());
            sender.send(7);
            assert_eq!(*r1.borrow(), 7);
            r2.changed().await.unwrap();
            assert_eq!(*r2.borrow(), 7);
        });
    }

    #[test]
    fn test_sender_moves_local_receivers_survive() {
        block_on(async {
            let (sender, mut receiver) = watch(0u32);
            // Move sender to a "remote" process. The local receiver should
            // get a WatchPortHandler installed on its core.
            let mut sender = round_trip(sender);
            sender.send(42);
            receiver.changed().await.unwrap();
            assert_eq!(*receiver.borrow(), 42);
        });
    }

    #[test]
    fn test_subscribe_after_send_no_more_sends() {
        // Verify that a cloned remote receiver gets the correct current
        // value, and that sender close propagates even when the subscriber
        // port is still pending in the core's subscribe list.
        block_on(async {
            let (mut sender, receiver) = watch(0u32);
            // Make receiver remote so it has an upstream port.
            let receiver = round_trip(receiver);
            // Send version 1.
            sender.send(1);
            // Clone the remote receiver and send the clone through a port
            // round-trip. This sends a SubscribeRequest to the SubHandler,
            // which eagerly sends the current value.
            let mut r2 = round_trip(receiver.clone());
            // r2 should have the current value even though we never send again.
            assert_eq!(r2.get(), 1);
            // Dropping the sender should close r2 as well.
            drop(sender);
            let result = r2.changed().await;
            assert!(result.is_err());
        });
    }
}
