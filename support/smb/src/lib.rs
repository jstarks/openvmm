// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A VM-independent SMB 2.1 server core and synthetic filesystem.
//!
//! This initial implementation supports unsigned guest sessions for local
//! testing. It is not a network authentication service. Compounds, leases,
//! locks, notifications, security descriptor updates, and host filesystem
//! providers are not yet implemented.

#![forbid(unsafe_code)]

pub mod memory;
pub mod protocol;
pub mod provider;
pub mod tcp;

use event_listener::Event;
use inspect::Inspect;
use parking_lot::Mutex;
use protocol::*;
use provider::{FileSystem, Metadata, OpenOptions, RequestContext, map_access};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use thiserror::Error;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

/// Failure that cannot be represented by a response to a valid SMB header.
#[derive(Debug, Error)]
pub enum Error {
    /// The connection must be closed because its packet header is invalid.
    #[error("invalid SMB2 packet header")]
    InvalidHeader,
    /// Transport failures retain the underlying OS diagnostic.
    #[error("SMB transport failed")]
    Io(#[from] std::io::Error),
    /// A Direct TCP frame is not within the supported size bounds.
    #[error("invalid Direct TCP frame length or type")]
    InvalidFrame,
    /// Two outstanding requests used the same client message ID.
    #[error("duplicate SMB message ID {0}")]
    DuplicateMessageId(u64),
    /// Admission requires the caller to finish an existing request first.
    #[error("SMB outstanding request limit reached")]
    RequestLimit,
    /// A backend could not complete destructive shutdown.
    #[error("SMB backend shutdown failed: {0:?}")]
    Backend(Status),
}

pub(crate) const MAX_REQUESTS: usize = 32;

/// Shared configuration and object store for one share.
pub struct Server<B: FileSystem> {
    name: String,
    backend: B,
    guid: guid::Guid,
    next_session: AtomicU64,
    next_request: AtomicU64,
    next_connection: AtomicU64,
    connections: Mutex<BTreeMap<u64, Weak<Mutex<ConnectionState<B::File>>>>>,
}

impl<B: FileSystem> Server<B> {
    /// Configure an unsigned guest-access share.
    pub fn new(name: impl Into<String>, backend: B) -> Result<Arc<Self>, Status> {
        let name = name.into();
        if name.is_empty() || name.contains(['\\', '/', '\0']) {
            return Err(Status::OBJECT_NAME_INVALID);
        }
        Ok(Arc::new(Self {
            name,
            backend,
            guid: guid::Guid::new_random(),
            next_session: AtomicU64::new(1),
            next_request: AtomicU64::new(1),
            next_connection: AtomicU64::new(1),
            connections: Mutex::new(BTreeMap::new()),
        }))
    }

    /// Start an independent protocol connection sharing this provider.
    pub fn connect(self: &Arc<Self>) -> Connection<B> {
        let state = Arc::new(Mutex::new(ConnectionState {
            negotiated: false,
            session: 0,
            session_active: false,
            trees: BTreeSet::new(),
            next_tree: 1,
            next_file: 1,
            files: BTreeMap::new(),
            requests: BTreeMap::new(),
            credits: 1,
            credits_in_use: 0,
            disconnected: false,
        }));
        let id = self.next_connection.fetch_add(1, Ordering::Relaxed);
        let mut connections = self.connections.lock();
        connections.retain(|_, state| state.strong_count() != 0);
        connections.insert(id, Arc::downgrade(&state));
        Connection {
            server: self.clone(),
            state,
        }
    }
}

struct OpenFile<F> {
    file: F,
    identity: u64,
    access: u32,
    tree: u32,
    position: u64,
    directory: Mutex<Option<(Vec<Metadata>, usize)>>,
    closing: AtomicBool,
    closed: AtomicBool,
    close_gate: futures::lock::Mutex<()>,
    active: Mutex<BTreeMap<u64, (RequestContext, bool)>>,
    changed: Event,
    close_error: Mutex<Option<Status>>,
}

/// Protocol state for one connection. Dropping it closes all provider opens.
pub struct Connection<B: FileSystem> {
    server: Arc<Server<B>>,
    state: Arc<Mutex<ConnectionState<B::File>>>,
}

struct ConnectionState<F> {
    negotiated: bool,
    session: u64,
    session_active: bool,
    trees: BTreeSet<u32>,
    next_tree: u32,
    next_file: u64,
    files: BTreeMap<u64, Arc<OpenFile<F>>>,
    requests: BTreeMap<u64, RequestInfo<F>>,
    credits: u32,
    credits_in_use: u32,
    disconnected: bool,
}

struct RequestInfo<F> {
    context: RequestContext,
    command: Command,
    tree: u32,
    open: Option<Arc<OpenFile<F>>>,
    charge: u32,
    response_session: u64,
    response_tree: u32,
    creating: bool,
}

/// An admitted request. Its future must be retained until completion.
pub struct Request<B: FileSystem> {
    connection: Connection<B>,
    header: Header,
    packet: Vec<u8>,
    context: RequestContext,
    error: Option<Status>,
    retired: Vec<Arc<OpenFile<B::File>>>,
}

impl<B: FileSystem> Clone for Connection<B> {
    fn clone(&self) -> Self {
        Self {
            server: self.server.clone(),
            state: self.state.clone(),
        }
    }
}

impl<F> OpenFile<F> {
    fn retire(&self) {
        self.closing.store(true, Ordering::Release);
        for (request, _) in self.active.lock().values() {
            request.cancel();
        }
    }

    async fn wait(&self, context: &RequestContext, closing: bool) -> Result<(), Status> {
        loop {
            let listener = self.changed.listen();
            let blocked = {
                let active = self.active.lock();
                if closing {
                    !active.is_empty()
                } else {
                    let barrier = active
                        .get(&context.id())
                        .is_some_and(|(_, barrier)| *barrier);
                    active
                        .range(..context.id())
                        .any(|(_, (_, earlier_barrier))| barrier || *earlier_barrier)
                }
            };
            if !blocked {
                return Ok(());
            }
            if closing {
                listener.await;
            } else {
                use futures::FutureExt;
                let mut cancelled = std::pin::pin!(context.cancelled().fuse());
                let mut listener = std::pin::pin!(listener.fuse());
                futures::select! {
                    () = cancelled => return Err(Status::CANCELLED),
                    () = listener => {}
                }
            }
        }
    }
}

impl<F> Inspect for OpenFile<F> {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("identity", self.identity)
            .hex("access", self.access)
            .field("tree", self.tree)
            .field("closing", self.closing.load(Ordering::Acquire))
            .field("closed", self.closed.load(Ordering::Acquire))
            .field("close_error", inspect::AsDebug(*self.close_error.lock()))
            .field("active_operations", self.active.lock().len())
            .field(
                "directory_cursor",
                self.directory.lock().as_ref().map(|(_, cursor)| *cursor),
            );
    }
}

impl<B: FileSystem> Inspect for Server<B> {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("share", &self.name)
            .field("backend", &self.backend)
            .child("connections", |req| {
                let connections = self.connections.lock();
                let mut resp = req.respond();
                for (id, state) in connections.iter() {
                    if let Some(state) = state.upgrade() {
                        resp.child(&id.to_string(), |req| state.lock().inspect(req));
                    }
                }
            });
    }
}

impl<F> Inspect for ConnectionState<F> {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("negotiated", self.negotiated)
            .field("session", self.session)
            .field("session_active", self.session_active)
            .field("disconnected", self.disconnected)
            .field("credits", self.credits)
            .field("credits_in_use", self.credits_in_use)
            .field("trees", inspect::iter_by_index(self.trees.iter()))
            .field("opens", inspect::iter_by_key(self.files.iter()))
            .child("requests", |req| {
                let mut resp = req.respond();
                for (id, info) in &self.requests {
                    resp.child(&id.to_string(), |req| {
                        req.respond()
                            .field("command", inspect::AsDebug(info.command))
                            .field("operation_id", info.context.id())
                            .field("tree", info.tree)
                            .field("cancel_requested", info.context.is_cancelled());
                    });
                }
            });
    }
}

impl<B: FileSystem> Inspect for Connection<B> {
    fn inspect(&self, req: inspect::Request<'_>) {
        self.state.lock().inspect(req);
    }
}

impl<B: FileSystem> Drop for Request<B> {
    fn drop(&mut self) {
        let request = self
            .connection
            .state
            .lock()
            .requests
            .remove(&self.header.message_id.get());
        if let Some(request) = request {
            if request.charge != 0 {
                let mut state = self.connection.state.lock();
                state.credits_in_use -= request.charge;
                state.credits += request.charge;
            }
            if let Some(file) = request.open {
                file.active.lock().remove(&request.context.id());
                file.changed.notify(usize::MAX);
            }
        }
    }
}

fn read_body<T: FromBytes + IntoBytes + KnownLayout + Immutable>(
    packet: &[u8],
    size: u16,
) -> Result<T, Status> {
    decode(
        packet.get(HEADER_SIZE..).ok_or(Status::INVALID_PARAMETER)?,
        size,
    )
}

fn variable(packet: &[u8], offset: usize, length: usize, fixed: usize) -> Result<&[u8], Status> {
    field(packet, offset, length, HEADER_SIZE + fixed)
}

fn u32_bytes(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn u64_bytes(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn basic_info(info: &Metadata) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    for time in [info.created, info.accessed, info.written, info.changed] {
        u64_bytes(&mut out, time);
    }
    u32_bytes(&mut out, info.attributes);
    u32_bytes(&mut out, 0);
    out
}

fn standard_info(info: &Metadata) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    u64_bytes(&mut out, info.size);
    u64_bytes(&mut out, info.size);
    u32_bytes(&mut out, 1);
    out.extend_from_slice(&[
        u8::from(info.delete_pending),
        u8::from(info.is_directory()),
        0,
        0,
    ]);
    out
}

fn buffer_response(bytes: Vec<u8>, maximum: u32) -> Result<Vec<u8>, Status> {
    if bytes.len() > maximum as usize {
        return Err(Status::BUFFER_TOO_SMALL);
    }
    let mut out = BufferResponse {
        structure_size: 9.into(),
        output_buffer_offset: 72.into(),
        output_buffer_length: (bytes.len() as u32).into(),
    }
    .as_bytes()
    .to_vec();
    out.extend_from_slice(&bytes);
    Ok(out)
}

impl<B: FileSystem> Connection<B> {
    /// Process one complete SMB packet, excluding transport framing.
    ///
    /// Well-formed headers receive explicit SMB error responses for invalid
    /// requests. Invalid headers produce an error requiring disconnect.
    pub async fn process(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        self.request(packet.to_vec())?.execute().await
    }

    /// Admit work synchronously, before polling its owned operation future.
    pub fn request(&self, packet: Vec<u8>) -> Result<Request<B>, Error> {
        let (header, _) = Header::read_from_prefix(&packet).map_err(|_| Error::InvalidHeader)?;
        if header.protocol != *b"\xfeSMB"
            || header.structure_size.get() != 64
            || header.flags.get() & FLAG_SERVER_TO_REDIR != 0
        {
            return Err(Error::InvalidHeader);
        }
        let command = Command(header.command.get());
        if command == Command::CANCEL {
            return Err(Error::InvalidHeader);
        }
        let context = RequestContext::new(self.server.next_request.fetch_add(1, Ordering::Relaxed));
        let mut state = self.state.lock();
        if state.requests.contains_key(&header.message_id.get()) {
            return Err(Error::DuplicateMessageId(header.message_id.get()));
        }
        if state.requests.len() >= MAX_REQUESTS {
            return Err(Error::RequestLimit);
        }
        let mut error = None;
        if packet.len() > MAX_MESSAGE_SIZE {
            error = Some(Status::INVALID_PARAMETER);
        } else if header.next_command.get() != 0
            || header.flags.get() & (FLAG_ASYNC | FLAG_RELATED | FLAG_SIGNED) != 0
        {
            error = Some(Status::NOT_SUPPORTED);
        } else if state.disconnected {
            error = Some(Status::USER_SESSION_DELETED);
        } else if command != Command::NEGOTIATE {
            if !state.negotiated {
                error = Some(Status::INVALID_PARAMETER);
            } else if command != Command::SESSION_SETUP && command != Command::ECHO {
                if !state.session_active || header.session_id.get() != state.session {
                    error = Some(Status::USER_SESSION_DELETED);
                } else if command != Command::TREE_CONNECT
                    && command != Command::LOGOFF
                    && !state.trees.contains(&header.tree_id.get())
                {
                    error = Some(Status::NETWORK_NAME_DELETED);
                }
            }
        }
        let charge = u32::from(header.credit_charge.get().max(1));
        if charge > state.credits {
            error = Some(Status::INVALID_PARAMETER);
        }
        let charge = charge.min(state.credits);
        state.credits -= charge;
        state.credits_in_use += charge;
        let mut open = None;
        let mut retired = Vec::new();
        if error.is_none() {
            let file_id = match command {
                Command::READ => read_body::<ReadRequest>(&packet, 49).map(|r| Some(r.file_id)),
                Command::WRITE => read_body::<WriteRequest>(&packet, 49).map(|r| Some(r.file_id)),
                Command::CLOSE | Command::FLUSH => {
                    read_body::<CloseRequest>(&packet, 24).map(|r| Some(r.file_id))
                }
                Command::QUERY_INFO => {
                    read_body::<QueryInfoRequest>(&packet, 41).map(|r| Some(r.file_id))
                }
                Command::SET_INFO => {
                    read_body::<SetInfoRequest>(&packet, 33).map(|r| Some(r.file_id))
                }
                Command::QUERY_DIRECTORY => {
                    read_body::<QueryDirectoryRequest>(&packet, 33).map(|r| Some(r.file_id))
                }
                _ => Ok(None),
            };
            match file_id {
                Err(status) => error = Some(status),
                Ok(Some(id)) => {
                    match state.files.get(&id.volatile.get()).filter(|file| {
                        file.identity == id.persistent.get()
                            && file.tree == header.tree_id.get()
                            && !file.closing.load(Ordering::Acquire)
                    }) {
                        None => error = Some(Status::FILE_CLOSED),
                        Some(file) => {
                            if command == Command::CLOSE {
                                file.retire();
                            } else {
                                file.active.lock().insert(
                                    context.id(),
                                    (
                                        context.clone(),
                                        matches!(
                                            command,
                                            Command::FLUSH
                                                | Command::SET_INFO
                                                | Command::QUERY_DIRECTORY
                                        ),
                                    ),
                                );
                            }
                            open = Some(file.clone());
                        }
                    }
                }
                Ok(None) => {}
            }
        }
        if error.is_none() && matches!(command, Command::LOGOFF | Command::TREE_DISCONNECT) {
            match read_body::<SimpleBody>(&packet, 4) {
                Err(status) => error = Some(status),
                Ok(_) => {
                    let tree = header.tree_id.get();
                    retired.extend(
                        state
                            .files
                            .values()
                            .filter(|file| command == Command::LOGOFF || file.tree == tree)
                            .cloned(),
                    );
                    for file in &retired {
                        file.retire();
                    }
                    for info in state.requests.values() {
                        if command == Command::LOGOFF || info.tree == tree {
                            if info.command != Command::CLOSE {
                                info.context.cancel();
                            }
                        }
                    }
                    if command == Command::LOGOFF {
                        state.trees.clear();
                        state.session_active = false;
                        state.session = 0;
                    } else {
                        state.trees.remove(&tree);
                    }
                }
            }
        }
        state.requests.insert(
            header.message_id.get(),
            RequestInfo {
                context: context.clone(),
                command,
                tree: header.tree_id.get(),
                open,
                charge,
                response_session: header.session_id.get(),
                response_tree: header.tree_id.get(),
                creating: false,
            },
        );
        drop(state);
        Ok(Request {
            connection: self.clone(),
            header,
            packet,
            context,
            error,
            retired,
        })
    }

    /// Expedite cancellation without consuming a credit or producing a reply.
    pub fn cancel(&self, packet: &[u8]) -> Result<(), Error> {
        let (header, _) = Header::read_from_prefix(packet).map_err(|_| Error::InvalidHeader)?;
        if header.protocol != *b"\xfeSMB"
            || header.structure_size.get() != 64
            || Command(header.command.get()) != Command::CANCEL
            || read_body::<SimpleBody>(packet, 4).is_err()
            || header.flags.get() & (FLAG_SERVER_TO_REDIR | FLAG_SIGNED) != 0
        {
            return Err(Error::InvalidHeader);
        }
        if header.flags.get() & FLAG_ASYNC == 0 {
            if let Some(info) = self.state.lock().requests.get(&header.message_id.get()) {
                if !matches!(
                    info.command,
                    Command::CLOSE | Command::TREE_DISCONNECT | Command::LOGOFF
                ) {
                    info.context.cancel();
                }
            }
        }
        Ok(())
    }

    fn file(
        &self,
        id: FileId,
        tree: u32,
        context: &RequestContext,
    ) -> Result<Arc<OpenFile<B::File>>, Status> {
        self.state
            .lock()
            .requests
            .values()
            .find(|info| info.context.id() == context.id())
            .and_then(|info| info.open.as_ref())
            .filter(|file| file.identity == id.persistent.get() && file.tree == tree)
            .cloned()
            .ok_or(Status::FILE_CLOSED)
    }

    async fn close_file(
        &self,
        file: &OpenFile<B::File>,
        context: &RequestContext,
    ) -> Result<(), Status> {
        let _closing = file.close_gate.lock().await;
        if file.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        file.wait(context, true).await?;
        if let Err(error) = self.server.backend.close(&file.file, context).await {
            *file.close_error.lock() = Some(error);
            return Err(error);
        }
        *file.close_error.lock() = None;
        file.closed.store(true, Ordering::Release);
        self.state
            .lock()
            .files
            .retain(|_, entry| !std::ptr::eq(entry.as_ref(), file));
        Ok(())
    }

    /// Close all opens after the owner has driven accepted requests to completion.
    pub async fn shutdown(&self) -> Result<(), Error> {
        let files = {
            let mut state = self.state.lock();
            state.disconnected = true;
            state.trees.clear();
            state.session_active = false;
            for info in state.requests.values() {
                if !matches!(
                    info.command,
                    Command::CLOSE | Command::TREE_DISCONNECT | Command::LOGOFF
                ) {
                    info.context.cancel();
                }
            }
            let files: Vec<_> = state.files.values().cloned().collect();
            for file in &files {
                file.retire();
            }
            files
        };
        let context = RequestContext::new(self.server.next_request.fetch_add(1, Ordering::Relaxed));
        let mut failure = None;
        for file in files {
            if let Err(error) = self.close_file(&file, &context).await {
                if failure.is_none() {
                    failure = Some(Error::Backend(error));
                }
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(crate) fn cancel_all(&self) {
        let mut state = self.state.lock();
        state.disconnected = true;
        for info in state.requests.values() {
            if !matches!(
                info.command,
                Command::CLOSE | Command::TREE_DISCONNECT | Command::LOGOFF
            ) {
                info.context.cancel();
            }
        }
    }
}

impl<B: FileSystem> Request<B> {
    /// Run admitted work. Dropping this future is not a backend cancellation API.
    pub async fn execute(self) -> Result<Vec<u8>, Error> {
        let header = &self.header;
        let command = Command(header.command.get());
        let packet = &self.packet;
        let connection = &self.connection;
        let result = if let Some(error) = self.error {
            Err(error)
        } else if self.context.is_cancelled()
            && !matches!(
                command,
                Command::CLOSE | Command::TREE_DISCONNECT | Command::LOGOFF
            )
        {
            Err(Status::CANCELLED)
        } else {
            let open = connection
                .state
                .lock()
                .requests
                .get(&header.message_id.get())
                .and_then(|info| info.open.clone());
            let ready = if command != Command::CLOSE {
                if let Some(file) = open {
                    file.wait(&self.context, false).await
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            };
            match ready {
                Err(status) => Err(status),
                Ok(()) if command == Command::SESSION_SETUP => {
                    connection.session_setup(header, packet)
                }
                Ok(()) => connection
                    .dispatch(header, command, packet, &self.context, &self.retired)
                    .await
                    .map(|body| (Status::SUCCESS, body)),
            }
        };
        let (status, body) = match result {
            Ok(response) => response,
            Err(status) => {
                let mut body = ErrorResponse {
                    structure_size: 9.into(),
                    context_count: 0,
                    reserved: 0,
                    byte_count: 0.into(),
                }
                .as_bytes()
                .to_vec();
                body.push(0);
                (status, body)
            }
        };
        let mut response = Header {
            protocol: *b"\xfeSMB",
            structure_size: 64.into(),
            credit_charge: header.credit_charge,
            status: status.0.into(),
            command: header.command,
            credits: 0.into(),
            flags: FLAG_SERVER_TO_REDIR.into(),
            next_command: 0.into(),
            message_id: header.message_id,
            process_id: header.process_id,
            tree_id: header.tree_id,
            session_id: header.session_id,
            signature: [0; 16],
        };
        {
            let mut state = connection.state.lock();
            if let Some(info) = state.requests.get(&header.message_id.get()) {
                response.session_id = info.response_session.into();
                response.tree_id = info.response_tree.into();
            }
            let charge = state
                .requests
                .get(&header.message_id.get())
                .map_or(0, |info| info.charge);
            state.credits_in_use -= charge;
            if let Some(info) = state.requests.get_mut(&header.message_id.get()) {
                info.charge = 0;
            }
            let grant = u32::from(header.credits.get().max(1))
                .min(MAX_REQUESTS as u32 - state.credits - state.credits_in_use);
            state.credits += grant;
            response.credits = (grant as u16).into();
        }
        let mut out = response.as_bytes().to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }
}

impl<B: FileSystem> Connection<B> {
    fn session_setup(&self, header: &Header, packet: &[u8]) -> Result<(Status, Vec<u8>), Status> {
        let request: SessionSetupRequest = read_body(packet, 25)?;
        let token = variable(
            packet,
            request.security_buffer_offset.get() as usize,
            request.security_buffer_length.get() as usize,
            24,
        )?;
        let mut state = self.state.lock();
        if request.flags != 0 || request.security_mode & 2 != 0 || state.session_active {
            return Err(Status::NOT_SUPPORTED);
        }
        let mut security = Vec::new();
        let status;
        if token.is_empty() && state.session == 0 {
            status = Status::SUCCESS;
        } else if token.starts_with(b"NTLMSSP\0") && token.len() >= 12 {
            let message = u32::from_le_bytes(
                token[8..12]
                    .try_into()
                    .map_err(|_| Status::INVALID_PARAMETER)?,
            );
            match message {
                1 if state.session == 0 => {
                    // This is a guest-only test handshake, not credential verification.
                    // MS-NLMP 2.2.1.2 defines the raw CHALLENGE_MESSAGE layout.
                    security.extend_from_slice(b"NTLMSSP\0");
                    u32_bytes(&mut security, 2);
                    security.extend_from_slice(&[0; 4]);
                    u32_bytes(&mut security, 48);
                    u32_bytes(&mut security, 0x008a0205);
                    security.extend_from_slice(&[0; 16]);
                    security.extend_from_slice(&4u16.to_le_bytes());
                    security.extend_from_slice(&4u16.to_le_bytes());
                    u32_bytes(&mut security, 48);
                    u32_bytes(&mut security, 0);
                    status = Status::MORE_PROCESSING_REQUIRED;
                }
                3 if state.session != 0
                    && header.session_id.get() == state.session
                    && token.len() >= 64 =>
                {
                    status = Status::SUCCESS;
                }
                _ => return Err(Status::INVALID_PARAMETER),
            }
        } else {
            return Err(Status::NOT_SUPPORTED);
        }
        if state.session == 0 {
            state.session = self
                .server
                .next_session
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| Status::INSUFFICIENT_RESOURCES)?;
        }
        state.session_active = status == Status::SUCCESS;
        let session = state.session;
        if let Some(info) = state.requests.get_mut(&header.message_id.get()) {
            info.response_session = session;
        }
        let mut body = SessionSetupResponse {
            structure_size: 9.into(),
            session_flags: u16::from(state.session_active).into(),
            security_buffer_offset: 72.into(),
            security_buffer_length: (security.len() as u16).into(),
        }
        .as_bytes()
        .to_vec();
        body.extend_from_slice(&security);
        Ok((status, body))
    }

    async fn dispatch(
        &self,
        header: &Header,
        command: Command,
        packet: &[u8],
        context: &RequestContext,
        retired: &[Arc<OpenFile<B::File>>],
    ) -> Result<Vec<u8>, Status> {
        if command == Command::NEGOTIATE {
            return self.negotiate(packet);
        }
        if command == Command::ECHO {
            let _: SimpleBody = read_body(packet, 4)?;
            return Ok(SimpleBody {
                structure_size: 4.into(),
                reserved: 0.into(),
            }
            .as_bytes()
            .to_vec());
        }
        if command == Command::LOGOFF {
            for file in retired {
                self.close_file(file, context).await?;
            }
            return Ok(SimpleBody {
                structure_size: 4.into(),
                reserved: 0.into(),
            }
            .as_bytes()
            .to_vec());
        }
        if command == Command::TREE_CONNECT {
            let request: TreeConnectRequest = read_body(packet, 9)?;
            let path = decode_name(variable(
                packet,
                request.path_offset.get() as usize,
                request.path_length.get() as usize,
                8,
            )?)?;
            let parts: Vec<_> = path.split('\\').filter(|s| !s.is_empty()).collect();
            if !path.starts_with("\\\\")
                || parts.len() != 2
                || !parts[1].eq_ignore_ascii_case(&self.server.name)
            {
                return Err(Status::BAD_NETWORK_NAME);
            }
            let mut state = self.state.lock();
            if state.trees.len() >= 1024 {
                return Err(Status::INSUFFICIENT_RESOURCES);
            }
            let next_tree = state
                .next_tree
                .checked_add(1)
                .ok_or(Status::INSUFFICIENT_RESOURCES)?;
            let tree = state.next_tree;
            state.trees.insert(tree);
            state.next_tree = next_tree;
            if let Some(info) = state.requests.get_mut(&header.message_id.get()) {
                info.response_tree = tree;
            }
            return Ok(TreeConnectResponse {
                structure_size: 16.into(),
                share_type: 1,
                reserved: 0,
                share_flags: 0.into(),
                capabilities: 0.into(),
                maximal_access: 0x1f01ff.into(),
            }
            .as_bytes()
            .to_vec());
        }
        let tree = header.tree_id.get();
        match command {
            Command::TREE_DISCONNECT => {
                for file in retired {
                    self.close_file(file, context).await?;
                }
                Ok(SimpleBody {
                    structure_size: 4.into(),
                    reserved: 0.into(),
                }
                .as_bytes()
                .to_vec())
            }
            Command::CREATE => {
                self.create(packet, tree, header.session_id.get(), context)
                    .await
            }
            Command::CLOSE => {
                let request: CloseRequest = read_body(packet, 24)?;
                let file = self.file(request.file_id, tree, context)?;
                file.wait(context, true).await?;
                let info = if request.flags.get() & 1 != 0 {
                    // MS-SMB2 3.3.5.10 permits omitting unavailable optional attributes.
                    self.server.backend.metadata(&file.file, context).await.ok()
                } else {
                    None
                };
                self.close_file(&file, context).await?;
                let mut response = CloseResponse::new_zeroed();
                response.structure_size = 60.into();
                if let Some(info) = info {
                    response.flags = 1.into();
                    response.creation_time = info.created.into();
                    response.last_access_time = info.accessed.into();
                    response.last_write_time = info.written.into();
                    response.change_time = info.changed.into();
                    response.allocation_size = info.size.into();
                    response.end_of_file = info.size.into();
                    response.file_attributes = info.attributes.into();
                }
                Ok(response.as_bytes().to_vec())
            }
            Command::FLUSH => {
                let request: CloseRequest = read_body(packet, 24)?;
                self.server
                    .backend
                    .flush(&self.file(request.file_id, tree, context)?.file, context)
                    .await?;
                Ok(SimpleBody {
                    structure_size: 4.into(),
                    reserved: 0.into(),
                }
                .as_bytes()
                .to_vec())
            }
            Command::READ => self.read(packet, tree, context).await,
            Command::WRITE => self.write(packet, tree, context).await,
            Command::QUERY_INFO => self.query_info(packet, tree, context).await,
            Command::QUERY_DIRECTORY => self.query_directory(packet, tree, context).await,
            Command::SET_INFO => self.set_info(packet, tree, context).await,
            _ => Err(Status::NOT_SUPPORTED),
        }
    }

    fn negotiate(&self, packet: &[u8]) -> Result<Vec<u8>, Status> {
        let request: NegotiateRequest = read_body(packet, 36)?;
        let mut state = self.state.lock();
        if state.negotiated || request.security_mode.get() & 2 != 0 {
            return Err(Status::NOT_SUPPORTED);
        }
        let dialects = variable(packet, 100, request.dialect_count.get() as usize * 2, 36)?;
        if !dialects
            .chunks_exact(2)
            .any(|p| u16::from_le_bytes([p[0], p[1]]) == DIALECT_210)
        {
            return Err(Status::NOT_SUPPORTED);
        }
        state.negotiated = true;
        Ok(NegotiateResponse {
            structure_size: 65.into(),
            security_mode: 1.into(),
            dialect: DIALECT_210.into(),
            reserved: 0.into(),
            server_guid: self
                .server
                .guid
                .as_bytes()
                .try_into()
                .map_err(|_| Status::INVALID_PARAMETER)?,
            capabilities: 4.into(),
            max_transact_size: (MAX_TRANSFER_SIZE as u32).into(),
            max_read_size: (MAX_TRANSFER_SIZE as u32).into(),
            max_write_size: (MAX_TRANSFER_SIZE as u32).into(),
            system_time: memory::nt_time().into(),
            server_start_time: 0.into(),
            security_buffer_offset: 128.into(),
            security_buffer_length: 0.into(),
            reserved2: 0.into(),
        }
        .as_bytes()
        .to_vec())
    }

    async fn create(
        &self,
        packet: &[u8],
        tree: u32,
        session: u64,
        context: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let request: CreateRequest = read_body(packet, 57)?;
        let name = decode_name(variable(
            packet,
            request.name_offset.get() as usize,
            request.name_length.get() as usize,
            56,
        )?)?;
        variable(
            packet,
            request.contexts_offset.get() as usize,
            request.contexts_length.get() as usize,
            56,
        )?;
        if request.contexts_length.get() != 0 {
            return Err(Status::NOT_SUPPORTED);
        }
        if request.create_disposition.get() > 5
            || request.share_access.get() & !7 != 0
            || request.create_options.get() & 0x41 == 0x41
            || request.impersonation_level.get() > 3
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let access = map_access(request.desired_access.get());
        let access = if access & 0x02000000 != 0 {
            (access & !0x02000000) | 0x1f01ff
        } else {
            access
        };
        let volatile = {
            let mut state = self.state.lock();
            if state.files.len() + state.requests.values().filter(|info| info.creating).count()
                >= 1024
            {
                return Err(Status::INSUFFICIENT_RESOURCES);
            }
            let id = state.next_file;
            state.next_file = id.checked_add(1).ok_or(Status::INSUFFICIENT_RESOURCES)?;
            if let Some(info) = state
                .requests
                .values_mut()
                .find(|info| info.context.id() == context.id())
            {
                info.creating = true;
            }
            id
        };
        let (file, action) = self
            .server
            .backend
            .open(
                &name,
                OpenOptions {
                    access,
                    share_access: request.share_access.get(),
                    disposition: request.create_disposition.get(),
                    options: request.create_options.get(),
                    attributes: request.file_attributes.get(),
                },
                context,
            )
            .await?;
        let info = match self.server.backend.metadata(&file, context).await {
            Ok(info) => info,
            Err(error) => {
                let cleanup =
                    RequestContext::new(self.server.next_request.fetch_add(1, Ordering::Relaxed));
                self.server.backend.close(&file, &cleanup).await?;
                return Err(error);
            }
        };
        let file_id = FileId {
            persistent: info.id.into(),
            volatile: volatile.into(),
        };
        let file = Arc::new(OpenFile {
            file,
            identity: info.id,
            access,
            tree,
            position: 0,
            directory: Mutex::new(None),
            closing: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            close_gate: futures::lock::Mutex::new(()),
            active: Mutex::new(BTreeMap::new()),
            changed: Event::new(),
            close_error: Mutex::new(None),
        });
        let invalid = {
            let mut state = self.state.lock();
            if !state.session_active || state.session != session {
                Some(Status::USER_SESSION_DELETED)
            } else if !state.trees.contains(&tree) {
                Some(Status::NETWORK_NAME_DELETED)
            } else if context.is_cancelled() {
                Some(Status::CANCELLED)
            } else {
                state.files.insert(volatile, file.clone());
                if let Some(info) = state
                    .requests
                    .values_mut()
                    .find(|info| info.context.id() == context.id())
                {
                    info.creating = false;
                }
                None
            }
        };
        if let Some(error) = invalid {
            let cleanup =
                RequestContext::new(self.server.next_request.fetch_add(1, Ordering::Relaxed));
            self.server.backend.close(&file.file, &cleanup).await?;
            return Err(error);
        }
        Ok(CreateResponse {
            structure_size: 89.into(),
            oplock_level: 0,
            flags: 0,
            create_action: action.into(),
            creation_time: info.created.into(),
            last_access_time: info.accessed.into(),
            last_write_time: info.written.into(),
            change_time: info.changed.into(),
            allocation_size: info.size.into(),
            end_of_file: info.size.into(),
            file_attributes: info.attributes.into(),
            reserved: 0.into(),
            file_id,
            contexts_offset: 0.into(),
            contexts_length: 0.into(),
        }
        .as_bytes()
        .to_vec())
    }

    async fn read(
        &self,
        packet: &[u8],
        tree: u32,
        context: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let request: ReadRequest = read_body(packet, 49)?;
        if request.length.get() as usize > MAX_TRANSFER_SIZE
            || request.channel.get() != 0
            || request.offset.get() > i64::MAX as u64 - u64::from(request.length.get())
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let file = self.file(request.file_id, tree, context)?;
        if file.access & 1 == 0 {
            return Err(Status::ACCESS_DENIED);
        }
        let bytes = if request.length.get() == 0 {
            Vec::new()
        } else {
            self.server
                .backend
                .read(
                    &file.file,
                    request.offset.get(),
                    request.length.get() as usize,
                    context,
                )
                .await?
        };
        if bytes.is_empty() && request.length.get() != 0 {
            return Err(Status::END_OF_FILE);
        }
        if bytes.len() < request.minimum_count.get() as usize {
            return Err(Status::END_OF_FILE);
        }
        let mut out = ReadResponse {
            structure_size: 17.into(),
            data_offset: 80,
            reserved: 0,
            data_length: (bytes.len() as u32).into(),
            data_remaining: 0.into(),
            reserved2: 0.into(),
        }
        .as_bytes()
        .to_vec();
        out.extend_from_slice(&bytes);
        Ok(out)
    }

    async fn write(
        &self,
        packet: &[u8],
        tree: u32,
        context: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let request: WriteRequest = read_body(packet, 49)?;
        if request.length.get() as usize > MAX_TRANSFER_SIZE
            || request.channel.get() != 0
            || request.offset.get() > i64::MAX as u64 - u64::from(request.length.get())
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let bytes = variable(
            packet,
            request.data_offset.get() as usize,
            request.length.get() as usize,
            48,
        )?;
        let file = self.file(request.file_id, tree, context)?;
        if file.access & 2 == 0 {
            return Err(Status::ACCESS_DENIED);
        }
        let written = self
            .server
            .backend
            .write(&file.file, request.offset.get(), bytes, context)
            .await?;
        Ok(WriteResponse {
            structure_size: 17.into(),
            reserved: 0.into(),
            count: (written as u32).into(),
            remaining: 0.into(),
            channel_info_offset: 0.into(),
            channel_info_length: 0.into(),
        }
        .as_bytes()
        .to_vec())
    }

    async fn query_info(
        &self,
        packet: &[u8],
        tree: u32,
        context: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let request: QueryInfoRequest = read_body(packet, 41)?;
        variable(
            packet,
            request.input_buffer_offset.get() as usize,
            request.input_buffer_length.get() as usize,
            40,
        )?;
        let file = self.file(request.file_id, tree, context)?;
        if request.info_type == 1
            && matches!(request.info_class, 4 | 18 | 34)
            && file.access & 0x80 == 0
        {
            return Err(Status::ACCESS_DENIED);
        }
        let info = self.server.backend.metadata(&file.file, context).await?;
        let mut out = Vec::new();
        match (request.info_type, request.info_class) {
            (1, 4) => out = basic_info(&info),
            (1, 5) => out = standard_info(&info),
            (1, 6) => u64_bytes(&mut out, info.id),
            (1, 9) => {
                let name = encode_name(&info.name);
                u32_bytes(&mut out, name.len() as u32);
                out.extend_from_slice(&name);
            }
            (1, 14) => u64_bytes(&mut out, file.position),
            (1, 18) => {
                out = basic_info(&info);
                out.extend_from_slice(&standard_info(&info));
                u64_bytes(&mut out, info.id);
                u32_bytes(&mut out, 0);
                u32_bytes(&mut out, file.access);
                u64_bytes(&mut out, file.position);
                u32_bytes(&mut out, 0);
                u32_bytes(&mut out, 0);
                let name = encode_name(&info.name);
                u32_bytes(&mut out, name.len() as u32);
                out.extend_from_slice(&name);
            }
            (1, 34) => {
                out = basic_info(&info);
                out.truncate(32);
                u64_bytes(&mut out, info.size);
                u64_bytes(&mut out, info.size);
                u32_bytes(&mut out, info.attributes);
                u32_bytes(&mut out, 0);
            }
            (2, 4) => {
                u32_bytes(&mut out, 7);
                u32_bytes(&mut out, 0);
            }
            (2, 5) => {
                let name = encode_name("MEMORY");
                u32_bytes(&mut out, 2 | 4);
                u32_bytes(&mut out, 255);
                u32_bytes(&mut out, name.len() as u32);
                out.extend_from_slice(&name);
            }
            _ => return Err(Status::NOT_SUPPORTED),
        }
        buffer_response(out, request.output_buffer_length.get())
    }

    async fn set_info(
        &self,
        packet: &[u8],
        tree: u32,
        context: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let request: SetInfoRequest = read_body(packet, 33)?;
        let data = variable(
            packet,
            request.buffer_offset.get() as usize,
            request.buffer_length.get() as usize,
            32,
        )?;
        let file = self.file(request.file_id, tree, context)?;
        match (request.info_type, request.info_class) {
            (1, 20) if data.len() == 8 => {
                if file.access & 2 == 0 {
                    return Err(Status::ACCESS_DENIED);
                }
                let length =
                    u64::from_le_bytes(data.try_into().map_err(|_| Status::INVALID_PARAMETER)?);
                if length > i64::MAX as u64 {
                    return Err(Status::INVALID_PARAMETER);
                }
                self.server
                    .backend
                    .set_len(&file.file, length, context)
                    .await?;
            }
            (1, 13) if !data.is_empty() => {
                if file.access & 0x10000 == 0 {
                    return Err(Status::ACCESS_DENIED);
                }
                self.server
                    .backend
                    .set_delete_on_close(&file.file, data[0] != 0, context)
                    .await?;
            }
            (1, 14) if data.len() == 8 => return Err(Status::NOT_SUPPORTED),
            _ => return Err(Status::NOT_SUPPORTED),
        }
        Ok(2u16.to_le_bytes().to_vec())
    }

    async fn query_directory(
        &self,
        packet: &[u8],
        tree: u32,
        context: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let request: QueryDirectoryRequest = read_body(packet, 33)?;
        let pattern = decode_name(variable(
            packet,
            request.name_offset.get() as usize,
            request.name_length.get() as usize,
            32,
        )?)?;
        let fixed = match request.info_class {
            1 => 64,
            2 => 68,
            3 => 94,
            12 => 12,
            37 => 104,
            38 => 80,
            _ => return Err(Status::NOT_SUPPORTED),
        };
        if request.flags & 4 != 0 {
            return Err(Status::NOT_SUPPORTED);
        }
        let file = self.file(request.file_id, tree, context)?;
        if file.access & 1 == 0 {
            return Err(Status::ACCESS_DENIED);
        }
        if file.directory.lock().is_none() || request.flags & (1 | 0x10) != 0 {
            if pattern != "*" && pattern != "*.*" && pattern.contains(['*', '?', '<', '>', '"']) {
                return Err(Status::NOT_SUPPORTED);
            }
            let entries = self.server.backend.list(&file.file, context).await?;
            let entries = entries
                .into_iter()
                .filter(|n| {
                    pattern.is_empty()
                        || pattern == "*"
                        || pattern == "*.*"
                        || n.name.eq_ignore_ascii_case(&pattern)
                })
                .collect();
            *file.directory.lock() = Some((entries, 0));
        }
        let mut directory = file.directory.lock();
        let (entries, cursor) = directory.as_mut().ok_or(Status::INVALID_PARAMETER)?;
        let maximum = (request.output_buffer_length.get() as usize).min(MAX_TRANSFER_SIZE);
        let mut out = Vec::new();
        let mut previous = None;
        while let Some(info) = entries.get(*cursor) {
            let name = encode_name(&info.name);
            let entry_len = (fixed + name.len() + 7) & !7;
            if out.len() + entry_len > maximum {
                if out.is_empty() {
                    return Err(Status::BUFFER_TOO_SMALL);
                }
                break;
            }
            let start = out.len();
            if let Some(previous) = previous {
                out[previous..previous + 4]
                    .copy_from_slice(&((start - previous) as u32).to_le_bytes());
            }
            out.resize(start + entry_len, 0);
            let entry = &mut out[start..];
            if request.info_class == 12 {
                entry[8..12].copy_from_slice(&(name.len() as u32).to_le_bytes());
            } else {
                entry[8..40].copy_from_slice(&basic_info(info)[..32]);
                entry[40..48].copy_from_slice(&info.size.to_le_bytes());
                entry[48..56].copy_from_slice(&info.size.to_le_bytes());
                entry[56..60].copy_from_slice(&info.attributes.to_le_bytes());
                entry[60..64].copy_from_slice(&(name.len() as u32).to_le_bytes());
                if request.info_class == 37 {
                    entry[96..104].copy_from_slice(&info.id.to_le_bytes());
                } else if request.info_class == 38 {
                    entry[72..80].copy_from_slice(&info.id.to_le_bytes());
                }
            }
            entry[fixed..fixed + name.len()].copy_from_slice(&name);
            previous = Some(start);
            *cursor += 1;
            if request.flags & 2 != 0 {
                break;
            }
        }
        if out.is_empty() {
            return Err(Status::NO_MORE_FILES);
        }
        buffer_response(out, request.output_buffer_length.get())
    }
}

#[cfg(test)]
mod tests;
