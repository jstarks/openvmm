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
use mesh_node::local_node::PortField;
use mesh_node::local_node::PortWithHandler;
use mesh_node::message::MeshField;
use mesh_node::message::Message;
use mesh_node::message::OwnedMessage;
use mesh_node::resource::Resource;
use mesh_node::resource::SerializedMessage;
use mesh_protobuf::DefaultEncoding;
use mesh_protobuf::Protobuf;
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
    fn new<T>(value: T) -> Self {
        Self(NonNull::new(Box::into_raw(Box::new(value)).cast()).unwrap())
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
    unsafe fn take<T>(self) -> T {
        // SAFETY: caller guarantees T matches.
        *unsafe { Box::from_raw(self.0.cast::<T>().as_ptr()) }
    }

    fn dangling() -> Self {
        Self(NonNull::dangling())
    }
}

// ---- Vtable --------------------------------------------------------------

struct WatchVtable {
    drop_value: unsafe fn(ErasedValue),
    #[expect(dead_code)] // will be used when sender encoding snapshots values
    clone_value: unsafe fn(&ErasedValue) -> ErasedValue,
    /// Clones the value and wraps it in an `EncodedUpdate<T>` message.
    /// Callers choose how to send: `control.respond()`, `pwh.send()`,
    /// `port.send()`, etc.
    make_update_msg: unsafe fn(&ErasedValue, u64) -> Message<'static>,
    decode_update: unsafe fn(Message<'_>) -> Result<(u64, ErasedValue), ChannelError>,
}

impl WatchVtable {
    const fn new<T: 'static + MeshField + Send + Clone>() -> Self {
        /// # Safety
        /// `v` must contain a value of type `T`.
        unsafe fn drop_value<T>(v: ErasedValue) {
            // SAFETY: guaranteed by caller.
            let _ = unsafe { v.take::<T>() };
        }
        /// # Safety
        /// `v` must contain a value of type `T`.
        unsafe fn clone_value<T: Clone>(v: &ErasedValue) -> ErasedValue {
            // SAFETY: guaranteed by caller.
            ErasedValue::new(unsafe { v.as_ref::<T>() }.clone())
        }
        /// # Safety
        /// `v` must contain a value of type `T`.
        unsafe fn make_update_msg<T: 'static + MeshField + Send + Clone>(
            v: &ErasedValue,
            version: u64,
        ) -> Message<'static> {
            Message::new(EncodedUpdate::<T> {
                version,
                // SAFETY: guaranteed by caller.
                value: unsafe { v.as_ref::<T>() }.clone(),
            })
        }
        /// # Safety
        /// The message must have been encoded as `EncodedUpdate<T>`.
        unsafe fn decode_update<T: 'static + MeshField>(
            message: Message<'_>,
        ) -> Result<(u64, ErasedValue), ChannelError> {
            let u: EncodedUpdate<T> = message.parse().map_err(ChannelError::from)?;
            Ok((u.version, ErasedValue::new(u.value)))
        }
        Self {
            drop_value: drop_value::<T>,
            clone_value: clone_value::<T>,
            make_update_msg: make_update_msg::<T>,
            decode_update: decode_update::<T>,
        }
    }
}

// ---- Wire protocol -------------------------------------------------------

#[derive(Protobuf)]
#[mesh(resource = "Resource")]
struct EncodedUpdate<T> {
    version: u64,
    value: T,
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
    Local(Vec<(u64, Port)>),
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
    pending_subscribes: Vec<(u64, Port)>,
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
                    // SAFETY: vtable matches the type.
                    let msg =
                        unsafe { (self.core.vtable.make_update_msg)(&state.value, state.version) };
                    control.respond(msg);
                    self.pending_ack = true;
                    self.sent_version = state.version;
                }
            }
            ReceiverMessage::Subscribe(version, port) => {
                // Eagerly send the current value if the subscriber is behind.
                // This is necessary because `send()` may never be called again,
                // and the subscriber would be stuck with stale data.
                let state = self.core.state.read();
                let effective_version = if version < state.version {
                    // SAFETY: vtable matches the type.
                    let msg =
                        unsafe { (self.core.vtable.make_update_msg)(&state.value, state.version) };
                    port.send(msg);
                    state.version
                } else {
                    version
                };
                drop(state);
                // Store the effective version so that register_subscribers()
                // won't redundantly re-send the same value.
                self.pending_subscribes.push((effective_version, port));
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
        if version > state.version {
            let old = mem::replace(&mut state.value, value);
            state.version = version;
            drop(state);
            control.respond(Message::new(ReceiverMessage::Ack(version)));
            for waker in core.waiters.lock().drain(..) {
                control.wake(waker);
            }
            // SAFETY: vtable matches the type.
            unsafe { (core.vtable.drop_value)(old) };
        } else {
            drop(state);
            control.respond(Message::new(ReceiverMessage::Ack(version)));
        }
        Ok(())
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
pub struct WatchSender<T>(WatchSenderCore, PhantomData<Arc<Mutex<T>>>);

impl<T> Debug for WatchSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchSender")
            .field("core", &self.0.core)
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
        unsafe { self.0.send::<T>(value) }
    }

    /// Reads the current value via an RAII guard.
    pub fn borrow(&self) -> Ref<'_, T> {
        Ref {
            guard: self.0.core.state.read(),
            _phantom: PhantomData,
        }
    }

    /// Creates a new receiver subscribed to this sender.
    pub fn subscribe(&mut self) -> WatchReceiver<T> {
        let version = self.0.core.state.read().version;
        WatchReceiver(
            WatchReceiverCore {
                core: self.0.core.clone(),
                last_seen: version,
            },
            PhantomData,
        )
    }
}

impl WatchSenderCore {
    /// # Safety
    /// The core must have element type `T`.
    unsafe fn send<T>(&mut self, value: T) -> T {
        // Bump version and swap value.
        let (version, old_value) = {
            let mut state = self.core.state.write();
            state.version += 1;
            let old = mem::replace(&mut state.value, ErasedValue::new(value));
            (state.version, old)
        };
        // state(W) is now released.

        // Drain pending subscribes from the core (from receiver encoding).
        self.drain_pending_subscribes(version);

        // Drain pending subscribes from each SubHandler.
        let mut new_subs: Vec<(u64, Port)> = Vec::new();
        for sub in &self.subscribers {
            sub.with_handler(|h| new_subs.append(&mut h.pending_subscribes));
        }
        self.register_subscribers(new_subs, version);

        // Send update to non-pending subscribers.
        //
        // N.B. We use `with_handler` + `send_update` instead of
        // `with_port_and_handler` + `encode_and_respond` to avoid a deadlock:
        // `with_port_and_handler` holds the port lock during event processing,
        // and if the peer responds with an ack that targets this port, the ack
        // delivery tries to reacquire the lock. `Port::send()` (used by
        // `send_update`) releases the port lock before processing events.
        self.subscribers.retain(|sub| {
            if sub.is_closed().unwrap_or(true) {
                return false;
            }
            let should_send = sub.with_handler(|handler| {
                if !handler.pending_ack {
                    handler.pending_ack = true;
                    handler.sent_version = version;
                    true
                } else {
                    false
                }
            });
            if should_send {
                // N.B. state(R) is held while send synchronously delivers
                // to the peer's WatchPortHandler, which acquires *its own*
                // core's state(W). This is safe because SubHandler and
                // WatchPortHandler always belong to different WatchCore
                // instances (created on opposite sides of the port encoding
                // boundary), so there is no same-lock contention.
                let state = self.core.state.read();
                // SAFETY: vtable matches the type.
                let msg =
                    unsafe { (self.core.vtable.make_update_msg)(&state.value, state.version) };
                sub.send(msg);
            }
            true
        });

        // Wake local receivers.
        for waker in self.core.waiters.lock().drain(..) {
            waker.wake();
        }

        // SAFETY: core has element type T.
        unsafe { old_value.take::<T>() }
    }

    fn drain_pending_subscribes(&mut self, current_version: u64) {
        let subs = {
            let mut subscribe = self.core.subscribe.lock();
            match &mut *subscribe {
                SubscribeState::Local(vec) => mem::take(vec),
                SubscribeState::Upstream(_) => Vec::new(),
            }
        };
        self.register_subscribers(subs, current_version);
    }

    fn register_subscribers(&mut self, subs: Vec<(u64, Port)>, current_version: u64) {
        for (ver, port) in subs {
            let handler = SubHandler {
                core: self.core.clone(),
                pending_ack: false,
                sent_version: ver,
                pending_subscribes: Vec::new(),
            };
            let sub = port.set_handler(handler);
            if ver < current_version {
                sub.with_handler(|handler| {
                    handler.pending_ack = true;
                    handler.sent_version = current_version;
                });
                // Same cross-core safety argument as in send() above.
                let state = self.core.state.read();
                // SAFETY: vtable matches the type.
                let msg =
                    unsafe { (self.core.vtable.make_update_msg)(&state.value, state.version) };
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
pub struct WatchReceiver<T>(WatchReceiverCore, PhantomData<Arc<Mutex<T>>>);

impl<T> Debug for WatchReceiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchReceiver")
            .field("core", &self.0.core)
            .field("last_seen", &self.0.last_seen)
            .finish()
    }
}

impl<T> Clone for WatchReceiver<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
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

impl<T: 'static + Send + Sync + Clone> WatchReceiver<T> {
    /// Gets a clone of the current value.
    pub fn get(&self) -> T {
        let state = self.0.core.state.read();
        // SAFETY: core has element type T.
        unsafe { state.value.as_ref::<T>() }.clone()
    }
}

impl<T: 'static + Send + Sync> WatchReceiver<T> {
    /// Reads the current value via an RAII guard.
    pub fn borrow(&self) -> Ref<'_, T> {
        Ref {
            guard: self.0.core.state.read(),
            _phantom: PhantomData,
        }
    }

    /// Reads the current value and marks it as seen.
    pub fn borrow_and_update(&mut self) -> Ref<'_, T> {
        let guard = self.0.core.state.read();
        self.0.last_seen = guard.version;
        Ref {
            guard,
            _phantom: PhantomData,
        }
    }

    /// Waits until the value has changed since the last observation.
    pub fn changed(&mut self) -> impl Future<Output = Result<(), RecvError>> + '_ {
        std::future::poll_fn(|cx| self.poll_changed(cx))
    }

    fn poll_changed(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), RecvError>> {
        loop {
            {
                let state = self.0.core.state.read();
                if self.0.last_seen < state.version {
                    self.0.last_seen = state.version;
                    return Poll::Ready(Ok(()));
                }
                if state.closed {
                    return Poll::Ready(Err(RecvError::Closed));
                }
            }
            // Register waker under waiters lock, double-check to avoid
            // lost wakeup.
            let mut waiters = self.0.core.waiters.lock();
            {
                let state = self.0.core.state.read();
                if self.0.last_seen < state.version || state.closed {
                    drop(waiters);
                    continue;
                }
            }
            waiters.push(cx.waker().clone());
            return Poll::Pending;
        }
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

// ---- Encoding: WatchSender <-> Port --------------------------------------

impl<T> DefaultEncoding for WatchSender<T> {
    type Encoding = PortField;
}

#[derive(Protobuf)]
#[mesh(resource = "Resource")]
struct EncodedWatchSender<T> {
    version: u64,
    value: T,
    ports: Vec<Port>,
}

impl<T: 'static + MeshField + Send + Sync + Clone> From<WatchSender<T>> for Port {
    fn from(sender: WatchSender<T>) -> Self {
        // Destructure without running Drop on WatchSenderCore.
        let inner = mem::ManuallyDrop::new(sender);
        // SAFETY: we won't use inner.0 again after reading its fields.
        // SAFETY: inner is ManuallyDrop so the original fields won't be dropped.
        let core: Arc<WatchCore> = unsafe { std::ptr::read(&inner.0.core) };
        let subscribers: Vec<PortWithHandler<SubHandler>> =
            // SAFETY: see above.
            unsafe { std::ptr::read(&inner.0.subscribers) };

        let version;
        let value: T;
        {
            let state = core.state.read();
            version = state.version;
            // SAFETY: core has element type T.
            value = unsafe { state.value.as_ref::<T>() }.clone();
        }

        // Drain pending subscribes from the core and SubHandlers.
        let mut pending: Vec<(u64, Port)> = {
            let mut subscribe = core.subscribe.lock();
            match &mut *subscribe {
                SubscribeState::Local(vec) => mem::take(vec),
                SubscribeState::Upstream(_) => Vec::new(),
            }
        };
        for sub in &subscribers {
            sub.with_handler(|h| pending.append(&mut h.pending_subscribes));
        }

        let mut ports: Vec<Port> = subscribers
            .into_iter()
            .map(|sub| sub.remove_handler().0)
            .collect();
        ports.extend(pending.into_iter().map(|(_, port)| port));

        // If local receivers exist, create a port so they keep getting updates.
        if Arc::strong_count(&core) > 1 {
            let (left, right) = Port::new_pair();
            let handler = WatchPortHandler {
                core: Arc::downgrade(&core),
                decode: core.vtable.decode_update,
            };
            let pwh = right.set_handler(handler);
            *core.subscribe.lock() = SubscribeState::Upstream(pwh);
            ports.push(left);
        }

        // Send state as first message. Using Port::send with Message::new
        // which will serialize the Protobuf-derived type into the port.
        let (left, right) = Port::new_pair();
        left.send(Message::new(EncodedWatchSender::<T> {
            version,
            value,
            ports,
        }));
        drop(left);
        right
    }
}

impl<T: 'static + MeshField + Send + Sync + Clone> From<Port> for WatchSender<T> {
    fn from(port: Port) -> Self {
        // Receive the encoded state from the port. The message was sent
        // via send_protobuf_and_close, so it's delivered synchronously
        // when we set the handler.
        let recv = OneshotRecvHandler::default();
        let pwh = port.set_handler(recv);
        let data = pwh
            .with_handler(|h| h.data.take())
            .expect("no message received for WatchSender");
        let encoded: EncodedWatchSender<T> = OwnedMessage::serialized(data)
            .parse()
            .expect("failed to decode WatchSender");
        let _ = pwh.remove_handler();

        let vtable: &'static WatchVtable = const { &WatchVtable::new::<T>() };
        let core = Arc::new(WatchCore {
            state: RwLock::new(WatchState {
                version: encoded.version,
                value: ErasedValue::new(encoded.value),
                closed: false,
            }),
            waiters: Mutex::new(Vec::new()),
            vtable,
            subscribe: Mutex::new(SubscribeState::Local(Vec::new())),
        });

        let subscribers: Vec<PortWithHandler<SubHandler>> = encoded
            .ports
            .into_iter()
            .map(|port| {
                port.set_handler(SubHandler {
                    core: core.clone(),
                    pending_ack: false,
                    sent_version: encoded.version,
                    pending_subscribes: Vec::new(),
                })
            })
            .collect();

        WatchSender(WatchSenderCore { core, subscribers }, PhantomData)
    }
}

// ---- Encoding: WatchReceiver <-> Port ------------------------------------

impl<T> DefaultEncoding for WatchReceiver<T> {
    type Encoding = PortField;
}

#[derive(Protobuf)]
#[mesh(resource = "Resource")]
struct EncodedWatchReceiver<T> {
    version: u64,
    value: T,
    port: Port,
}

impl<T: 'static + MeshField + Send + Sync + Clone> From<WatchReceiver<T>> for Port {
    fn from(receiver: WatchReceiver<T>) -> Self {
        let core = &receiver.0.core;

        // Create a port pair. The right side goes to the sender.
        let (sub_left, sub_right) = Port::new_pair();

        // Register the right port with the sender for updates.
        // - Sender-side core (Local): push to the pending queue.
        // - Receiver-side core (Upstream): forward through the upstream port.
        {
            let mut subscribe = core.subscribe.lock();
            match &mut *subscribe {
                SubscribeState::Local(vec) => {
                    vec.push((receiver.0.last_seen, sub_right));
                }
                SubscribeState::Upstream(pwh) => {
                    // N.B. subscribe(M) is held here while pwh.send()
                    // synchronously delivers to the sender's SubHandler.
                    // This is safe because SubHandler only touches the
                    // *sender's* core (different lock instances).
                    pwh.send(Message::new(ReceiverMessage::Subscribe(
                        receiver.0.last_seen,
                        sub_right,
                    )));
                }
            }
        }

        let version;
        let value: T;
        {
            let state = core.state.read();
            version = state.version;
            // SAFETY: core has element type T.
            value = unsafe { state.value.as_ref::<T>() }.clone();
        }

        let (left, right) = Port::new_pair();
        left.send(Message::new(EncodedWatchReceiver::<T> {
            version,
            value,
            port: sub_left,
        }));
        drop(left);
        right
    }
}

impl<T: 'static + MeshField + Send + Sync + Clone> From<Port> for WatchReceiver<T> {
    fn from(port: Port) -> Self {
        let recv = OneshotRecvHandler::default();
        let pwh = port.set_handler(recv);
        let data = pwh
            .with_handler(|h| h.data.take())
            .expect("no message received for WatchReceiver");
        let encoded: EncodedWatchReceiver<T> = OwnedMessage::serialized(data)
            .parse()
            .expect("failed to decode WatchReceiver");
        let _ = pwh.remove_handler();

        let vtable: &'static WatchVtable = const { &WatchVtable::new::<T>() };

        // Create the core first, then install the upstream port handler.
        // We use Weak in the handler to avoid a reference cycle
        // (WatchCore → subscribe → PWH → handler → Arc<WatchCore>).
        let core = Arc::new(WatchCore {
            state: RwLock::new(WatchState {
                version: encoded.version,
                value: ErasedValue::new(encoded.value),
                closed: false,
            }),
            waiters: Mutex::new(Vec::new()),
            vtable,
            // Placeholder — replaced below with Upstream.
            subscribe: Mutex::new(SubscribeState::Local(Vec::new())),
        });

        let handler = WatchPortHandler {
            core: Arc::downgrade(&core),
            decode: vtable.decode_update,
        };
        let upstream_pwh = encoded.port.set_handler(handler);
        *core.subscribe.lock() = SubscribeState::Upstream(upstream_pwh);

        WatchReceiver(
            WatchReceiverCore {
                core,
                last_seen: encoded.version,
            },
            PhantomData,
        )
    }
}

// ---- OneshotRecvHandler: receives one message from a port ----------------

/// Receives exactly one message from a port, storing the raw serialized data.
#[derive(Default)]
struct OneshotRecvHandler {
    data: Option<SerializedMessage>,
}

impl HandlePortEvent for OneshotRecvHandler {
    fn message(
        &mut self,
        _control: &mut PortControl<'_, '_>,
        message: Message<'_>,
    ) -> Result<(), HandleMessageError> {
        self.data = Some(SerializedMessage::from_message(message));
        Ok(())
    }

    fn close(&mut self, _control: &mut PortControl<'_, '_>) {}
    fn fail(&mut self, _control: &mut PortControl<'_, '_>, _err: NodeError) {}
    fn drain(&mut self) -> Vec<OwnedMessage> {
        self.data
            .take()
            .into_iter()
            .map(OwnedMessage::serialized)
            .collect()
    }
}

// ---- Constructor ---------------------------------------------------------

/// Creates a watch channel with the given initial value.
///
/// Returns the sender and an initial receiver. Additional receivers can
/// be created via [`WatchSender::subscribe`].
pub fn watch<T: 'static + Send + Sync + Clone + MeshField>(
    initial: T,
) -> (WatchSender<T>, WatchReceiver<T>) {
    let vtable: &'static WatchVtable = const { &WatchVtable::new::<T>() };
    let core = Arc::new(WatchCore {
        state: RwLock::new(WatchState {
            version: 0,
            value: ErasedValue::new(initial),
            closed: false,
        }),
        waiters: Mutex::new(Vec::new()),
        vtable,
        subscribe: Mutex::new(SubscribeState::Local(Vec::new())),
    });

    let sender = WatchSenderCore {
        core: core.clone(),
        subscribers: Vec::new(),
    };
    let receiver = WatchReceiverCore { core, last_seen: 0 };

    (
        WatchSender(sender, PhantomData),
        WatchReceiver(receiver, PhantomData),
    )
}

// ---- Tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use test_with_tracing::test;

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
    fn test_port_message_delivery() {
        let (left, right) = Port::new_pair();
        left.send(Message::new(EncodedUpdate::<u32> {
            version: 1,
            value: 42,
        }));

        let handler = OneshotRecvHandler::default();
        let pwh = right.set_handler(handler);
        let data = pwh.with_handler(|h| h.data.take());
        assert!(data.is_some(), "message should have been received");
    }

    #[test]
    fn test_sender_port_roundtrip() {
        block_on(async {
            let (sender, mut receiver) = watch(5u32);
            // Round-trip the sender through a Port.
            let mut sender = WatchSender::<u32>::from(Port::from(sender));
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
            let mut receiver = WatchReceiver::<u32>::from(Port::from(receiver));
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
            let mut sender = WatchSender::<u32>::from(Port::from(sender));
            let mut receiver = WatchReceiver::<u32>::from(Port::from(receiver));
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
            let mut r2 = WatchReceiver::<u32>::from(Port::from(r1.clone()));
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
            let mut sender = WatchSender::<u32>::from(Port::from(sender));
            sender.send(42);
            receiver.changed().await.unwrap();
            assert_eq!(*receiver.borrow(), 42);
        });
    }

    #[test]
    fn test_subscribe_after_send_no_more_sends() {
        // Verify that a cloned remote receiver gets the correct current
        // value, and that sender close propagates even when the subscriber
        // port is still in SubHandler's pending_subscribes.
        block_on(async {
            let (mut sender, receiver) = watch(0u32);
            // Make receiver remote so it has an upstream port.
            let receiver = WatchReceiver::<u32>::from(Port::from(receiver));
            // Send version 1.
            sender.send(1);
            // Clone the remote receiver and send the clone through a port
            // round-trip. This sends a SubscribeRequest to the SubHandler,
            // which eagerly sends the current value.
            let mut r2 = WatchReceiver::<u32>::from(Port::from(receiver.clone()));
            // r2 should have the current value even though we never send again.
            assert_eq!(r2.get(), 1);
            // Dropping the sender should close r2 as well.
            drop(sender);
            let result = r2.changed().await;
            assert!(result.is_err());
        });
    }
}
