// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A VM-independent SMB 2.1 server core and synthetic filesystem.
//!
//! This initial implementation supports unsigned guest sessions for local
//! testing, including bounded related/unrelated compound requests with retained
//! operation ownership. It is not a network authentication service. Leases,
//! security descriptor updates and host filesystem
//! providers are not yet implemented.

#![forbid(unsafe_code)]

mod codec;
mod compound;
mod credits;
mod namespace;
pub use compound::Request;
pub mod memory;
pub mod provider;
pub mod security;
pub mod spec;
pub mod tcp;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

use codec::*;
use event_listener::Event;
use inspect::Inspect;
use parking_lot::Mutex;
use provider::{
    BasicInformation, ByteRange, CachingGrant, CachingRequest, FileControl, FileControlResult,
    FileSystem, FileSystemInformation, Metadata, NotifyResult, OpenError, OpenOptions, Opened,
    RequestContext, StreamInformation, SymbolicLink, map_access,
};
use spec::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use thiserror::Error;
use zerocopy::little_endian::U16;
use zerocopy::{FromBytes, FromZeros, IntoBytes};

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
    /// A compound chain has invalid boundaries or exceeds the command bound.
    #[error("invalid SMB compound chain")]
    InvalidCompound,
    /// A message ID, replay, or multi-credit range was not granted to the peer.
    #[error("invalid SMB credit sequence number {0}")]
    InvalidCreditSequence(u64),
    /// Sequence numbers cannot wrap or be reused.
    #[error("SMB credit sequence exhausted")]
    CreditSequenceExhausted,
    /// The caller stopped receiving responses; accepted backend work was still drained.
    #[error("SMB response channel closed")]
    ResponseChannelClosed,
    /// A backend could not complete destructive shutdown.
    #[error("SMB backend shutdown failed: {0:?}")]
    Backend(Status),
}

pub(crate) const MAX_REQUESTS: usize = 32;
/// Implementation transfer bound, not a protocol maximum.
pub const MAX_TRANSFER_SIZE: usize = 1024 * 1024;
/// Implementation packet bound including fixed fields and context overhead.
pub const MAX_MESSAGE_SIZE: usize = MAX_TRANSFER_SIZE + 1024;
const MAX_SEARCH_PATTERN_LENGTH: usize = 255;
const MAX_TREES: usize = 1024;
const MAX_OPENS: usize = 1024;

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
            window: credits::Window::new(),
            credits_in_use: 0,
            disconnected: false,
            next_async: 1,
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
    access: AccessMask,
    mode: AtomicU32,
    is_directory: bool,
    tree: u32,
    position: AtomicI64,
    directory: Mutex<Option<DirectorySearch>>,
    ea_cursor: futures::lock::Mutex<u32>,
    closing: AtomicBool,
    closed: AtomicBool,
    close_gate: futures::lock::Mutex<()>,
    active: Mutex<Vec<Activity>>,
    changed: Event,
    close_error: Mutex<Option<Status>>,
}

struct DirectorySearch {
    pattern: String,
    // Resume by stable identity and link name, not an offset into a stale snapshot.
    after: Option<(u8, u64, String)>,
    cursor: usize,
}

struct Activity {
    context: RequestContext,
    barrier: bool,
    notification: bool,
    locking: bool,
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
    window: credits::Window,
    credits_in_use: u32,
    disconnected: bool,
    next_async: u64,
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
    group: u64,
    activated: bool,
    async_id: Option<u64>,
}

/// An admitted request. Its future must be retained until completion.
struct CommandRequest<B: FileSystem> {
    connection: Connection<B>,
    header: Header,
    packet: Vec<u8>,
    context: RequestContext,
    error: Option<Status>,
    retired: Vec<Arc<OpenFile<B::File>>>,
    activated: bool,
}

struct CommandResponse {
    header: Header,
    bytes: Vec<u8>,
    async_id: Option<u64>,
}

fn error_body() -> Vec<u8> {
    let mut body = ErrorResponse {
        structure_size: ErrorResponse::STRUCTURE_SIZE.into(),
        context_count: 0,
        reserved: 0,
        byte_count: 0.into(),
    }
    .as_bytes()
    .to_vec();
    body.push(0);
    body
}

fn symbolic_link_error(name: &str, link: SymbolicLink) -> Result<Vec<u8>, Status> {
    let substitute = encode_name(&link.substitute_name);
    let print = encode_name(&link.print_name);
    let suffix = link.unparsed_suffix.encode_utf16().count() * 2;
    if substitute.is_empty()
        || link.substitute_name.contains('\0')
        || link.print_name.contains('\0')
        || (link.relative && link.substitute_name.starts_with('\\'))
        || !name.ends_with(&link.unparsed_suffix)
        || (!link.unparsed_suffix.is_empty() && !link.unparsed_suffix.starts_with(['\\', ':']))
        || 20 + substitute.len() + print.len() > MAX_REPARSE_DATA_SIZE
        || suffix > u16::MAX as usize
    {
        return Err(Status::INTERNAL_ERROR);
    }
    let length = size_of::<SymbolicLinkErrorResponse>() + substitute.len() + print.len();
    let mut out = ErrorResponse {
        structure_size: ErrorResponse::STRUCTURE_SIZE.into(),
        context_count: 0,
        reserved: 0,
        byte_count: (length as u32).into(),
    }
    .as_bytes()
    .to_vec();
    out.extend_from_slice(
        SymbolicLinkErrorResponse {
            symlink_length: ((length - 4) as u32).into(),
            symlink_error_tag: 0x4c4d5953.into(),
            reparse_tag: IO_REPARSE_TAG_SYMLINK.into(),
            reparse_data_length: ((12 + substitute.len() + print.len()) as u16).into(),
            unparsed_path_length: (suffix as u16).into(),
            substitute_name_offset: 0.into(),
            substitute_name_length: (substitute.len() as u16).into(),
            print_name_offset: (substitute.len() as u16).into(),
            print_name_length: (print.len() as u16).into(),
            flags: u32::from(link.relative).into(),
        }
        .as_bytes(),
    );
    out.extend_from_slice(&substitute);
    out.extend_from_slice(&print);
    Ok(out)
}

fn notify_body(bytes: &[u8]) -> Vec<u8> {
    let mut body = BufferResponse {
        structure_size: BufferResponse::STRUCTURE_SIZE.into(),
        output_buffer_offset: if bytes.is_empty() {
            0
        } else {
            body_end::<BufferResponse>() as u16
        }
        .into(),
        output_buffer_length: (bytes.len() as u32).into(),
    }
    .as_bytes()
    .to_vec();
    body.extend_from_slice(bytes);
    body
}

fn response_bytes(header: &Header, async_id: Option<u64>, body: &[u8]) -> Vec<u8> {
    let mut bytes = if let Some(async_id) = async_id {
        AsyncHeader {
            protocol: header.protocol,
            structure_size: header.structure_size,
            credit_charge: header.credit_charge,
            status: header.status,
            command: header.command,
            credits: header.credits,
            flags: header
                .flags
                .with_async_command(true)
                .with_related_operations(false),
            next_command: 0.into(),
            message_id: header.message_id,
            async_id: async_id.into(),
            session_id: header.session_id,
            signature: header.signature,
        }
        .as_bytes()
        .to_vec()
    } else {
        header.as_bytes().to_vec()
    };
    bytes.extend_from_slice(body);
    bytes
}

impl<F> ConnectionState<F> {
    fn grant(&mut self, header: &Header) -> Result<u16, Error> {
        let info = self
            .requests
            .get_mut(&header.message_id.get())
            .ok_or(Error::Backend(Status::INTERNAL_ERROR))?;
        self.credits_in_use -= info.charge;
        info.charge = 0;
        self.grant_credits(header.credits.get())
    }

    fn grant_credits(&mut self, requested: u16) -> Result<u16, Error> {
        let grant = u32::from(requested.max(1))
            .min(MAX_REQUESTS as u32 - self.window.len() - self.credits_in_use);
        self.window.grant(grant)
    }
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
    fn track(&self, context: &RequestContext, command: Command) {
        let mut active = self.active.lock();
        if !active
            .iter()
            .any(|activity| activity.context.id() == context.id())
        {
            // Binding order, not allocation of a compound's queued context IDs,
            // determines which operations precede this open's barriers.
            active.push(Activity {
                context: context.clone(),
                barrier: matches!(
                    command,
                    Command::FLUSH | Command::SET_INFO | Command::QUERY_DIRECTORY | Command::IOCTL
                ),
                notification: command == Command::CHANGE_NOTIFY,
                locking: command == Command::LOCK,
            });
        }
    }

    fn untrack(&self, id: u64) {
        self.active
            .lock()
            .retain(|activity| activity.context.id() != id);
        self.changed.notify(usize::MAX);
    }

    fn retire(&self) {
        self.closing.store(true, Ordering::Release);
        for activity in self.active.lock().iter() {
            activity.context.cancel();
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
                    let position = active
                        .iter()
                        .position(|activity| activity.context.id() == context.id())
                        .ok_or(Status::FILE_CLOSED)?;
                    let current = &active[position];
                    // Lock waits bypass I/O barriers so UNLOCK can make progress.
                    // Notifications have their own FIFO; CLOSE drains all activities.
                    active[..position].iter().any(|earlier| {
                        if current.locking {
                            false
                        } else if current.notification {
                            earlier.notification
                        } else {
                            !earlier.notification
                                && !earlier.locking
                                && (current.barrier || earlier.barrier)
                        }
                    })
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
            .hex("access", self.access.into_bits())
            .hex("mode", self.mode.load(Ordering::Relaxed))
            .field("position", self.position.load(Ordering::Relaxed))
            .field("ea_index", self.ea_cursor.try_lock().map(|index| *index))
            .field("is_directory", self.is_directory)
            .field("tree", self.tree)
            .field("closing", self.closing.load(Ordering::Acquire))
            .field("closed", self.closed.load(Ordering::Acquire))
            .field("close_error", inspect::AsDebug(*self.close_error.lock()))
            .field("active_operations", self.active.lock().len())
            .field(
                "directory_cursor",
                self.directory.lock().as_ref().map(|search| search.cursor),
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
            .field("credits", self.window.len())
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
                            .field("compound_group", info.group)
                            .field("activated", info.activated)
                            .field("async_id", info.async_id)
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

impl<B: FileSystem> Drop for CommandRequest<B> {
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
                // A discarded accepted request cannot reissue its consumed IDs.
                state.disconnected = true;
            }
            if let Some(file) = request.open {
                file.untrack(request.context.id());
            }
        }
    }
}

fn basic_info(info: &Metadata) -> FileBasicInformation {
    FileBasicInformation {
        creation_time: (info.created as i64).into(),
        last_access_time: (info.accessed as i64).into(),
        last_write_time: (info.written as i64).into(),
        change_time: (info.changed as i64).into(),
        file_attributes: info.attributes.into(),
        reserved: 0.into(),
    }
}

fn standard_info(info: &Metadata) -> FileStandardInformation {
    FileStandardInformation {
        allocation_size: info.allocation_size.into(),
        end_of_file: info.size.into(),
        number_of_links: info.number_of_links.into(),
        delete_pending: u8::from(info.delete_pending || info.number_of_links == 0),
        directory: u8::from(info.is_directory()),
        reserved: [0; 2],
    }
}

fn ea_size(info: &Metadata) -> Result<u32, Status> {
    if info.extended_attributes_length == 0 {
        Ok(0)
    } else {
        info.extended_attributes_length
            .checked_add(4)
            .ok_or(Status::INTERNAL_ERROR)
    }
}

fn directory_key(info: &Metadata) -> (u8, u64, &str) {
    let order = match info.name.as_str() {
        "." => 0,
        ".." => 1,
        _ => 2,
    };
    (order, info.id, &info.name)
}

// MS-FSA §2.1.4.4, using bounded UTF-16 prefix states rather than backtracking.
fn name_matches(name: &str, pattern: &str) -> bool {
    if name.is_empty() || pattern.is_empty() {
        return name == pattern;
    }
    if pattern == "*" || pattern == "*.*" {
        return true;
    }
    if !pattern.contains(['*', '?', '<', '>', '"']) {
        return namespace::equal(name, pattern);
    }
    const STAR: u16 = b'*' as u16;
    const QUESTION: u16 = b'?' as u16;
    const DOS_STAR: u16 = b'<' as u16;
    const DOS_QUESTION: u16 = b'>' as u16;
    const DOS_DOT: u16 = b'"' as u16;
    const DOT: u16 = b'.' as u16;
    let fold = namespace::upcase;
    let name: Vec<_> = name.encode_utf16().map(fold).collect();
    let last_dot = name.iter().rposition(|&unit| unit == DOT);
    let mut previous = vec![false; name.len() + 1];
    let mut next = vec![false; name.len() + 1];
    previous[0] = true;
    for token in pattern.encode_utf16().map(fold) {
        next.fill(false);
        let mut running = false;
        for offset in 0..=name.len() {
            match token {
                STAR | DOS_STAR => {
                    running |= previous[offset];
                    next[offset] |= running;
                    if offset < name.len() {
                        next[offset + 1] |= running;
                    }
                    if token == DOS_STAR && last_dot == Some(offset) {
                        running = false;
                    }
                }
                DOS_QUESTION if offset == name.len() || name[offset] == DOT => {
                    next[offset] |= previous[offset];
                }
                DOS_DOT if offset == name.len() => {
                    next[offset] |= previous[offset];
                }
                _ if offset < name.len()
                    && (token == QUESTION
                        || token == DOS_QUESTION
                        || (token == DOS_DOT && name[offset] == DOT)
                        || token == name[offset]) =>
                {
                    next[offset + 1] |= previous[offset];
                }
                _ => {}
            }
        }
        std::mem::swap(&mut previous, &mut next);
    }
    previous[name.len()]
}

fn directory_short_name(info: &Metadata) -> Result<DirectoryShortName, Status> {
    let mut short_name = DirectoryShortName::new_zeroed();
    if let Some(name) = &info.short_name {
        let units: Vec<_> = name.encode_utf16().collect();
        if units.len() > SHORT_NAME_CAPACITY {
            return Err(Status::INTERNAL_ERROR);
        }
        short_name.length = (units.len() * size_of::<U16>()) as u8;
        for (target, unit) in short_name.name.iter_mut().zip(units) {
            *target = unit.into();
        }
    }
    Ok(short_name)
}

fn directory_record(class: FileInformationClass, info: &Metadata) -> Result<Vec<u8>, Status> {
    let name = encode_name(&info.name);
    let basic = basic_info(info);
    let header = DirectoryEntryHeader::new_zeroed();
    let directory = FileDirectoryInformation {
        header,
        creation_time: basic.creation_time,
        last_access_time: basic.last_access_time,
        last_write_time: basic.last_write_time,
        change_time: basic.change_time,
        end_of_file: info.size.into(),
        allocation_size: info.allocation_size.into(),
        file_attributes: info.attributes.into(),
        file_name_length: (name.len() as u32).into(),
    };
    let full = FileFullDirectoryInformation {
        directory,
        ea_size: info.extended_attributes_length.into(),
    };
    let extended = FileId64ExtdDirectoryInformation {
        full,
        reparse_point_tag: info.reparse_tag.into(),
        file_id: info.id.into(),
    };
    let mut out = match class {
        FileInformationClass::DIRECTORY => directory.as_bytes().to_vec(),
        FileInformationClass::FULL_DIRECTORY => full.as_bytes().to_vec(),
        FileInformationClass::ID_FULL_DIRECTORY => FileIdFullDirectoryInformation {
            full,
            reserved: 0.into(),
            file_id: info.id.into(),
        }
        .as_bytes()
        .to_vec(),
        FileInformationClass::NAMES => FileNamesInformation {
            header,
            file_name_length: (name.len() as u32).into(),
        }
        .as_bytes()
        .to_vec(),
        FileInformationClass::BOTH_DIRECTORY | FileInformationClass::ID_BOTH_DIRECTORY => {
            let short_name = directory_short_name(info)?;
            let both = FileBothDirectoryInformation { full, short_name };
            if class == FileInformationClass::BOTH_DIRECTORY {
                both.as_bytes().to_vec()
            } else {
                FileIdBothDirectoryInformation {
                    both,
                    reserved: 0.into(),
                    file_id: info.id.into(),
                }
                .as_bytes()
                .to_vec()
            }
        }
        FileInformationClass::ID_EXTD_DIRECTORY => FileIdExtdDirectoryInformation {
            full,
            reparse_point_tag: info.reparse_tag.into(),
            file_id: info.id128.ok_or(Status::NOT_SUPPORTED)?,
        }
        .as_bytes()
        .to_vec(),
        FileInformationClass::ID64_EXTD_DIRECTORY => extended.as_bytes().to_vec(),
        FileInformationClass::ID64_EXTD_BOTH_DIRECTORY => FileId64ExtdBothDirectoryInformation {
            extended,
            short_name: directory_short_name(info)?,
        }
        .as_bytes()
        .to_vec(),
        FileInformationClass::ID_ALL_EXTD_DIRECTORY
        | FileInformationClass::ID_ALL_EXTD_BOTH_DIRECTORY => {
            let extended = FileIdAllExtdDirectoryInformation {
                extended,
                file_id128: info.id128.ok_or(Status::NOT_SUPPORTED)?,
            };
            if class == FileInformationClass::ID_ALL_EXTD_DIRECTORY {
                extended.as_bytes().to_vec()
            } else {
                FileIdAllExtdBothDirectoryInformation {
                    extended,
                    short_name: directory_short_name(info)?,
                }
                .as_bytes()
                .to_vec()
            }
        }
        _ => return Err(Status::NOT_SUPPORTED),
    };
    out.extend_from_slice(&name);
    Ok(out)
}

fn buffer_response(bytes: Vec<u8>, maximum: u32) -> Result<Vec<u8>, Status> {
    if bytes.len() > maximum as usize {
        return Err(Status::BUFFER_TOO_SMALL);
    }
    let mut out = BufferResponse {
        structure_size: BufferResponse::STRUCTURE_SIZE.into(),
        output_buffer_offset: (body_end::<BufferResponse>() as u16).into(),
        output_buffer_length: (bytes.len() as u32).into(),
    }
    .as_bytes()
    .to_vec();
    out.extend_from_slice(&bytes);
    Ok(out)
}

fn stream_response(
    streams: &[StreamInformation],
    maximum: u32,
) -> Result<(Status, Vec<u8>), Status> {
    if maximum as usize > MAX_TRANSFER_SIZE {
        return Err(Status::INVALID_PARAMETER);
    }
    if (maximum as usize) < size_of::<FileStreamInformation>() {
        return Err(Status::INFO_LENGTH_MISMATCH);
    }
    let mut status = Status::SUCCESS;
    let mut out = Vec::new();
    let mut previous = None;
    for stream in streams {
        if stream.name.contains([':', '\0']) || stream.name.encode_utf16().count() > MAX_PATH_LENGTH
        {
            return Err(Status::INTERNAL_ERROR);
        }
        let size = i64::try_from(stream.size).map_err(|_| Status::INTERNAL_ERROR)?;
        let allocation =
            i64::try_from(stream.allocation_size).map_err(|_| Status::INTERNAL_ERROR)?;
        let name_length = (stream.name.encode_utf16().count() + 7) * 2;
        let start = if out.is_empty() {
            0
        } else {
            align_up(out.len(), STREAM_ALIGNMENT)?
        };
        if start + size_of::<FileStreamInformation>() + name_length > maximum as usize {
            status = Status::BUFFER_OVERFLOW;
            break;
        }
        out.resize(start, 0);
        if let Some(previous) = previous {
            FileStreamInformation::mut_from_prefix(&mut out[previous..])
                .map_err(|_| Status::INTERNAL_ERROR)?
                .0
                .next_entry_offset = ((start - previous) as u32).into();
        }
        previous = Some(start);
        out.extend_from_slice(
            FileStreamInformation {
                next_entry_offset: 0.into(),
                stream_name_length: (name_length as u32).into(),
                stream_size: size.into(),
                stream_allocation_size: allocation.into(),
            }
            .as_bytes(),
        );
        out.extend_from_slice(&encode_name(&format!(":{}:$DATA", stream.name)));
    }
    buffer_response(out, maximum).map(|body| (status, body))
}

fn file_control_output(
    control: FileControl<'_>,
    result: FileControlResult,
) -> Result<(Status, Vec<u8>), Status> {
    let mut status = Status::SUCCESS;
    let output = match (control, result) {
        (FileControl::GetReparsePoint { maximum }, FileControlResult::ReparsePoint(info)) => {
            validate_reparse_data(info.tag, info.guid, &info.data)
                .map_err(|_| Status::INTERNAL_ERROR)?;
            let header = size_of::<ReparseDataHeader>() + usize::from(info.guid.is_some()) * 16;
            if (maximum as usize) < header {
                return Err(Status::BUFFER_TOO_SMALL);
            }
            let mut out = ReparseDataHeader {
                tag: info.tag.into(),
                data_length: (info.data.len() as u16).into(),
                reserved: 0.into(),
            }
            .as_bytes()
            .to_vec();
            if let Some(guid) = info.guid {
                out.extend_from_slice(&guid);
            }
            let count = info.data.len().min(maximum as usize - header);
            out.extend_from_slice(&info.data[..count]);
            if count < info.data.len() {
                status = Status::BUFFER_OVERFLOW;
            }
            out
        }
        (
            FileControl::SetReparsePoint { .. }
            | FileControl::DeleteReparsePoint { .. }
            | FileControl::SetSparse { .. },
            FileControlResult::Done,
        ) => Vec::new(),
        (FileControl::SetCompression { .. }, FileControlResult::Done) => Vec::new(),
        (
            FileControl::GetObjectId | FileControl::CreateOrGetObjectId,
            FileControlResult::ObjectId(info),
        ) => {
            if info.object_id == [0; 16] {
                return Err(Status::INTERNAL_ERROR);
            }
            FileObjectIdBuffer {
                object_id: info.object_id,
                birth_volume_id: info.birth_volume_id,
                birth_object_id: info.birth_object_id,
                domain_id: info.domain_id,
            }
            .as_bytes()
            .to_vec()
        }
        (
            FileControl::SetObjectId(_)
            | FileControl::DeleteObjectId
            | FileControl::SetObjectIdExtended { .. },
            FileControlResult::Done,
        ) => Vec::new(),
        (FileControl::GetCompression, FileControlResult::Compression(format)) => {
            format.to_le_bytes().to_vec()
        }
        (FileControl::SetZeroData { .. }, FileControlResult::Done) => Vec::new(),
        (
            FileControl::QueryAllocatedRanges {
                range,
                maximum_ranges,
            },
            FileControlResult::AllocatedRanges { ranges, overflow },
        ) => {
            if ranges.len() > maximum_ranges
                || (range.length == 0 && (!ranges.is_empty() || overflow))
            {
                return Err(Status::INTERNAL_ERROR);
            }
            let mut out = Vec::new();
            let mut previous_end = 0;
            for allocated in ranges {
                let end = allocated
                    .offset
                    .checked_add(allocated.length)
                    .filter(|end| *end <= i64::MAX as u64)
                    .ok_or(Status::INTERNAL_ERROR)?;
                if allocated.length == 0
                    || !allocated.overlaps(range)
                    || allocated.offset < previous_end
                {
                    return Err(Status::INTERNAL_ERROR);
                }
                previous_end = end;
                out.extend_from_slice(
                    FileAllocatedRangeBuffer {
                        file_offset: (allocated.offset as i64).into(),
                        length: (allocated.length as i64).into(),
                    }
                    .as_bytes(),
                );
            }
            if overflow {
                status = Status::BUFFER_OVERFLOW;
            }
            out
        }
        _ => return Err(Status::INTERNAL_ERROR),
    };
    Ok((status, output))
}

fn filesystem_response(
    info: &FileSystemInformation,
    class: FileSystemInformationClass,
    maximum: u32,
) -> Result<(Status, Vec<u8>), Status> {
    let minimum = match class {
        FileSystemInformationClass::VOLUME => FILE_FS_VOLUME_MIN_BUFFER_SIZE,
        FileSystemInformationClass::SIZE => size_of::<FileFsSizeInformation>(),
        FileSystemInformationClass::FULL_SIZE => size_of::<FileFsFullSizeInformation>(),
        FileSystemInformationClass::DEVICE => size_of::<FileFsDeviceInformation>(),
        FileSystemInformationClass::ATTRIBUTE => size_of::<FileFsAttributeInformation>(),
        FileSystemInformationClass::SECTOR_SIZE => size_of::<FileFsSectorSizeInformation>(),
        FileSystemInformationClass::OBJECT_ID => size_of::<FileFsObjectIdInformation>(),
        _ => return Err(Status::INVALID_PARAMETER),
    };
    if (maximum as usize) < minimum {
        return Err(Status::INFO_LENGTH_MISMATCH);
    }
    let mut out = Vec::new();
    match class {
        FileSystemInformationClass::OBJECT_ID => {
            let object = info.object_information.ok_or(Status::INVALID_PARAMETER)?;
            if object.object_id == [0; 16] {
                return Err(Status::OBJECT_NAME_NOT_FOUND);
            }
            out.extend_from_slice(
                FileFsObjectIdInformation {
                    object_id: object.object_id,
                    extended_info: object.extended_info,
                }
                .as_bytes(),
            );
        }
        FileSystemInformationClass::VOLUME => {
            let label: String = info
                .label
                .chars()
                .take(FILE_FS_VOLUME_MAX_LABEL_LENGTH)
                .collect();
            let label = encode_name(&label);
            out.extend_from_slice(
                FileFsVolumeInformation {
                    volume_creation_time: info.created.into(),
                    volume_serial_number: info.serial.into(),
                    volume_label_length: (label.len() as u32).into(),
                    supports_objects: u8::from(info.supports_objects),
                    reserved: 0,
                }
                .as_bytes(),
            );
            out.extend_from_slice(&label);
        }
        FileSystemInformationClass::DEVICE => out.extend_from_slice(
            FileFsDeviceInformation {
                device_type: info.device_type.into(),
                characteristics: info.device_characteristics.into(),
            }
            .as_bytes(),
        ),
        FileSystemInformationClass::SECTOR_SIZE => {
            let sector = info.sector_size.ok_or(Status::NOT_SUPPORTED)?;
            out.extend_from_slice(
                FileFsSectorSizeInformation {
                    logical_bytes_per_sector: sector.logical_bytes.into(),
                    physical_bytes_per_sector_for_atomicity: sector.physical_atomic_bytes.into(),
                    physical_bytes_per_sector_for_performance: sector
                        .physical_performance_bytes
                        .into(),
                    file_system_effective_physical_bytes_per_sector_for_atomicity: sector
                        .effective_atomic_bytes
                        .into(),
                    flags: SectorSizeFlags::from_bits(sector.flags),
                    byte_offset_for_sector_alignment: sector.sector_alignment.into(),
                    byte_offset_for_partition_alignment: sector.partition_alignment.into(),
                }
                .as_bytes(),
            );
        }
        FileSystemInformationClass::ATTRIBUTE => {
            let name = encode_name(&info.name);
            out.extend_from_slice(
                FileFsAttributeInformation {
                    file_system_attributes: FileSystemAttributes::from_bits(info.attributes),
                    maximum_component_name_length: info.maximum_component_name_length.into(),
                    file_system_name_length: (name.len() as u32).into(),
                }
                .as_bytes(),
            );
            out.extend_from_slice(&name);
        }
        FileSystemInformationClass::SIZE | FileSystemInformationClass::FULL_SIZE => {
            if info.total_allocation_units < 0
                || info.caller_available_allocation_units < 0
                || info.actual_available_allocation_units < 0
                || info.sectors_per_allocation_unit == 0
                || info.bytes_per_sector == 0
            {
                return Err(Status::INTERNAL_ERROR);
            }
            if class == FileSystemInformationClass::SIZE {
                out.extend_from_slice(
                    FileFsSizeInformation {
                        total_allocation_units: info.total_allocation_units.into(),
                        available_allocation_units: info.caller_available_allocation_units.into(),
                        sectors_per_allocation_unit: info.sectors_per_allocation_unit.into(),
                        bytes_per_sector: info.bytes_per_sector.into(),
                    }
                    .as_bytes(),
                );
            } else {
                out.extend_from_slice(
                    FileFsFullSizeInformation {
                        total_allocation_units: info.total_allocation_units.into(),
                        caller_available_allocation_units: info
                            .caller_available_allocation_units
                            .into(),
                        actual_available_allocation_units: info
                            .actual_available_allocation_units
                            .into(),
                        sectors_per_allocation_unit: info.sectors_per_allocation_unit.into(),
                        bytes_per_sector: info.bytes_per_sector.into(),
                    }
                    .as_bytes(),
                );
            }
        }
        _ => return Err(Status::INVALID_PARAMETER),
    }
    let status = if out.len() > maximum as usize {
        out.truncate(maximum as usize);
        Status::BUFFER_OVERFLOW
    } else {
        Status::SUCCESS
    };
    Ok((status, buffer_response(out, maximum)?))
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
        self.request_ref(&packet)
    }

    pub(crate) fn request_ref(&self, packet: &[u8]) -> Result<Request<B>, Error> {
        let ranges = compound::ranges(packet)?;
        let headers: Vec<_> = ranges
            .iter()
            .map(|range| {
                Header::read_from_prefix(&packet[range.clone()])
                    .map(|(header, _)| header)
                    .map_err(|_| Error::InvalidHeader)
            })
            .collect::<Result<_, _>>()?;
        let related = headers.len() > 1
            && headers[1..]
                .iter()
                .all(|header| header.flags.related_operations());
        let invalid_style = headers[0].flags.related_operations()
            || (headers[1..]
                .iter()
                .any(|header| header.flags.related_operations())
                && !related);
        let mut state = self.state.lock();
        let mut ids = BTreeSet::new();
        for header in &headers {
            if !ids.insert(header.message_id.get())
                || state.requests.contains_key(&header.message_id.get())
            {
                return Err(Error::DuplicateMessageId(header.message_id.get()));
            }
        }
        if state.requests.len() + headers.len() > MAX_REQUESTS {
            return Err(Error::RequestLimit);
        }
        let sequence_ranges: Vec<_> = headers
            .iter()
            .map(|header| {
                (
                    header.message_id.get(),
                    u32::from(header.credit_charge.get().max(1)),
                )
            })
            .collect();
        state.window.consume(&sequence_ranges)?;
        let group = self
            .server
            .next_request
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                id.checked_add(headers.len() as u64)
            })
            .map_err(|_| Error::Backend(Status::INSUFFICIENT_RESOURCES))?;
        let mut commands = Vec::new();
        let command_count = headers.len();
        let mut previous_file = None;
        for (index, (header, range)) in headers.into_iter().zip(ranges).enumerate() {
            let mut bytes = packet[range].to_vec();
            let command = header.command();
            let context = RequestContext::new(group + index as u64);
            let error = if invalid_style || packet.len() > MAX_MESSAGE_SIZE {
                Some(Status::INVALID_PARAMETER)
            } else if header.flags.async_command() || header.flags.signed() {
                Some(Status::NOT_SUPPORTED)
            } else {
                compound::charge(&bytes, &header).err().or_else(|| {
                    // MS-SMB2 §3.3.5.2.7 permits rejecting asynchronous compounds.
                    // Indefinite waits must not strand later commands in this executor.
                    ((command == Command::CHANGE_NOTIFY
                        || (command == Command::LOCK
                            && read_body::<LockRequest>(&bytes).is_ok_and(|request| {
                                !request.first_lock.flags.unlock()
                                    && !request.first_lock.flags.fail_immediately()
                            })))
                        && index + 1 < command_count)
                        .then_some(Status::NOT_SUPPORTED)
                })
            };
            let charge = u32::from(header.credit_charge.get().max(1));
            state.credits_in_use += charge;
            let file = compound::request_file_id(&mut bytes, None).ok().flatten();
            let bound_file = if related && index != 0 {
                previous_file
            } else {
                file
            };
            let open = if error.is_none()
                && file.is_some()
                && !matches!(command, Command::CLOSE | Command::CREATE)
            {
                bound_file.and_then(|id: FileId| {
                    state
                        .files
                        .get(&id.volatile.get())
                        .filter(|file| {
                            file.identity == id.persistent.get()
                                && !file.closing.load(Ordering::Acquire)
                        })
                        .cloned()
                })
            } else {
                None
            };
            if let Some(file) = &open {
                file.track(&context, command);
            }
            previous_file = if command == Command::CREATE {
                None
            } else {
                bound_file.filter(|_| file.is_some())
            };
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
                    group,
                    activated: false,
                    async_id: None,
                },
            );
            commands.push(CommandRequest {
                connection: self.clone(),
                header,
                packet: bytes,
                context,
                error,
                retired: Vec::new(),
                activated: false,
            });
        }
        if let Some(first) = commands.first_mut() {
            self.activate(first, &mut state);
        }
        Ok(Request { commands, related })
    }

    fn activate(&self, request: &mut CommandRequest<B>, state: &mut ConnectionState<B::File>) {
        request.activated = true;
        let header = &request.header;
        let command = header.command();
        let context = &request.context;
        let mut error = request.error;
        if error.is_none() {
            if state.disconnected {
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
        }
        let mut open = None;
        let mut retired = Vec::new();
        if error.is_none() && command == Command::IOCTL {
            match read_body::<IoctlRequest>(&request.packet) {
                Err(status) => error = Some(status),
                Ok(ioctl)
                    if ioctl.flags.into_bits()
                        != IoctlFlags::new().with_fsctl(true).into_bits() =>
                {
                    error = Some(Status::NOT_SUPPORTED);
                }
                Ok(_) => {}
            }
        }
        if error.is_none() {
            let file_id = compound::request_file_id(&mut request.packet, None);
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
                                file.track(context, command);
                            }
                            open = Some(file.clone());
                        }
                    }
                }
                Ok(None) => {}
            }
        }
        if error.is_none() && matches!(command, Command::LOGOFF | Command::TREE_DISCONNECT) {
            match read_body::<SimpleBody>(&request.packet) {
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
        // A close/teardown must not wait for later, unstarted commands in its
        // own chain. They retain descriptors but cannot submit backend I/O.
        if let Some(group) = state
            .requests
            .get(&header.message_id.get())
            .map(|info| info.group)
        {
            for info in state
                .requests
                .values_mut()
                .filter(|info| info.group == group && !info.activated)
            {
                let retiring = info.open.as_ref().is_some_and(|file| {
                    (command == Command::CLOSE
                        && open
                            .as_ref()
                            .is_some_and(|closing| Arc::ptr_eq(file, closing)))
                        || retired.iter().any(|closing| Arc::ptr_eq(file, closing))
                });
                if retiring {
                    if let Some(file) = info.open.take() {
                        file.untrack(info.context.id());
                    }
                    info.context.cancel();
                }
            }
        }
        if let Some(info) = state.requests.get_mut(&header.message_id.get()) {
            if let Some(previous) = info.open.take() {
                if open
                    .as_ref()
                    .is_none_or(|current| !Arc::ptr_eq(current, &previous))
                {
                    previous.untrack(context.id());
                }
            }
            info.tree = header.tree_id.get();
            info.response_session = header.session_id.get();
            info.response_tree = header.tree_id.get();
            info.open = open;
            info.activated = true;
        }
        request.error = error;
        request.retired = retired;
    }

    // Interim credit grants must not let a full registry obstruct subsequent CANCEL.
    pub(crate) fn busy_response(&self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let ranges = compound::ranges(packet)?;
        let headers = ranges
            .iter()
            .map(|range| {
                Header::read_from_prefix(&packet[range.clone()])
                    .map(|(header, _)| header)
                    .map_err(|_| Error::InvalidHeader)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let sequences = headers
            .iter()
            .map(|header| {
                (
                    header.message_id.get(),
                    u32::from(header.credit_charge.get().max(1)),
                )
            })
            .collect::<Vec<_>>();
        let mut state = self.state.lock();
        state.window.consume(&sequences)?;
        let mut output = Vec::new();
        let mut last = None;
        for (index, mut header) in headers.into_iter().enumerate() {
            let related = index != 0 && header.flags.related_operations();
            header.status = Status::INSUFFICIENT_RESOURCES.0.into();
            header.flags = HeaderFlags::new().with_server_to_redir(true);
            header.next_command = 0.into();
            header.signature = [0; 16];
            header.credits = state.grant_credits(header.credits.get())?.into();
            let response = response_bytes(&header, None, &error_body());
            if ranges.len() == 1 {
                return Ok(response);
            }
            compound::append_response(&mut output, &mut last, response, related)?;
        }
        Ok(output)
    }

    /// Expedite cancellation without consuming a credit or producing a reply.
    pub fn cancel(&self, packet: &[u8]) -> Result<(), Error> {
        let (header, _) = Header::read_from_prefix(packet).map_err(|_| Error::InvalidHeader)?;
        if header.protocol != SIGNATURE
            || header.structure_size.get() as usize != HEADER_SIZE
            || header.command() != Command::CANCEL
            || header.next_command.get() != 0
            || read_body::<SimpleBody>(packet).is_err()
            || header.flags.server_to_redir()
            || header.flags.signed()
        {
            return Err(Error::InvalidHeader);
        }
        {
            let state = self.state.lock();
            let target = if header.flags.async_command() {
                let id = AsyncHeader::read_from_prefix(packet)
                    .map_err(|_| Error::InvalidHeader)?
                    .0
                    .async_id
                    .get();
                state
                    .requests
                    .values()
                    .find(|info| info.async_id == Some(id))
            } else {
                state.requests.get(&header.message_id.get())
            };
            if let Some(info) = target {
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

    fn pending_response(&self, header: &Header, session: u64) -> Result<Option<Vec<u8>>, Error> {
        let mut state = self.state.lock();
        let info = state
            .requests
            .get(&header.message_id.get())
            .ok_or(Error::Backend(Status::INTERNAL_ERROR))?;
        if info.async_id.is_some() {
            return Ok(None);
        }
        let id = state.next_async;
        state.next_async = id
            .checked_add(1)
            .ok_or(Error::Backend(Status::INSUFFICIENT_RESOURCES))?;
        state
            .requests
            .get_mut(&header.message_id.get())
            .ok_or(Error::Backend(Status::INTERNAL_ERROR))?
            .async_id = Some(id);
        let mut response = *header;
        response.status = Status::PENDING.0.into();
        response.flags = HeaderFlags::new().with_server_to_redir(true);
        response.next_command = 0.into();
        response.session_id = session.into();
        response.signature = [0; 16];
        response.credits = state.grant(header)?.into();
        Ok(Some(response_bytes(&response, Some(id), &error_body())))
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

impl<B: FileSystem> CommandRequest<B> {
    /// Run admitted work. Dropping this future is not a backend cancellation API.
    async fn execute(mut self) -> Result<CommandResponse, Error> {
        if !self.activated {
            let connection = self.connection.clone();
            connection.activate(&mut self, &mut connection.state.lock());
        }
        let header = &self.header;
        let command = header.command();
        let packet = &self.packet;
        let connection = &self.connection;
        let result = if let Some(error) = self.error {
            Err(error)
        } else if self.context.is_cancelled()
            && !matches!(
                command,
                Command::CLOSE
                    | Command::TREE_DISCONNECT
                    | Command::LOGOFF
                    | Command::CHANGE_NOTIFY
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
                Ok(()) if command == Command::CHANGE_NOTIFY => {
                    connection
                        .change_notify(header, packet, &self.context)
                        .await
                }
                Ok(()) if command == Command::QUERY_INFO => {
                    connection
                        .query_info(packet, header.tree_id.get(), &self.context)
                        .await
                }
                Ok(()) if command == Command::IOCTL => {
                    connection
                        .ioctl(packet, header.tree_id.get(), &self.context)
                        .await
                }
                Ok(()) if command == Command::CREATE => {
                    connection
                        .create(
                            packet,
                            header.tree_id.get(),
                            header.session_id.get(),
                            &self.context,
                        )
                        .await
                }
                Ok(()) => connection
                    .dispatch(header, command, packet, &self.context, &self.retired)
                    .await
                    .map(|body| (Status::SUCCESS, body)),
            }
        };
        let result = result.map_err(|status| {
            if command == Command::CHANGE_NOTIFY
                && status == Status::CANCELLED
                && connection
                    .state
                    .lock()
                    .requests
                    .get(&header.message_id.get())
                    .and_then(|info| info.open.as_ref())
                    .is_some_and(|file| file.closing.load(Ordering::Acquire))
            {
                Status::NOTIFY_CLEANUP
            } else {
                status
            }
        });
        let (status, body) = match result {
            Ok(response) => response,
            Err(Status::NOTIFY_CLEANUP) => (Status::NOTIFY_CLEANUP, notify_body(&[])),
            Err(status) => (status, error_body()),
        };
        let mut response = Header {
            protocol: SIGNATURE,
            structure_size: (HEADER_SIZE as u16).into(),
            credit_charge: header.credit_charge,
            status: status.0.into(),
            command: header.command,
            credits: 0.into(),
            flags: HeaderFlags::new().with_server_to_redir(true),
            next_command: 0.into(),
            message_id: header.message_id,
            process_id: header.process_id,
            tree_id: header.tree_id,
            session_id: header.session_id,
            signature: [0; 16],
        };
        let async_id = {
            let mut state = connection.state.lock();
            if let Some(info) = state.requests.get(&header.message_id.get()) {
                response.session_id = info.response_session.into();
                response.tree_id = info.response_tree.into();
            }
            let async_id = state
                .requests
                .get(&header.message_id.get())
                .and_then(|info| info.async_id);
            if async_id.is_none() {
                response.credits = state.grant(header)?.into();
            }
            async_id
        };
        Ok(CommandResponse {
            bytes: response_bytes(&response, async_id, &body),
            header: response,
            async_id,
        })
    }
}

impl<B: FileSystem> Connection<B> {
    async fn change_notify(
        &self,
        header: &Header,
        packet: &[u8],
        context: &RequestContext,
    ) -> Result<(Status, Vec<u8>), Status> {
        let request: ChangeNotifyRequest = read_body(packet)?;
        let length = request.output_buffer_length.get() as usize;
        if length > MAX_TRANSFER_SIZE {
            return Err(Status::INVALID_PARAMETER);
        }
        let file = self.file(request.file_id, header.tree_id.get(), context)?;
        if !file.is_directory {
            return Err(Status::INVALID_PARAMETER);
        }
        if !file.access.read_data() {
            return Err(Status::ACCESS_DENIED);
        }
        match self
            .server
            .backend
            .notify(
                &file.file,
                NotifyFilter::from_bits(
                    request.completion_filter.into_bits() & NotifyFilter::VALID,
                ),
                request.flags.watch_tree(),
                length,
                context,
            )
            .await?
        {
            NotifyResult::Overflow => Ok((Status::NOTIFY_ENUM_DIR, notify_body(&[]))),
            NotifyResult::Changes(changes) => {
                if changes.is_empty() {
                    return Err(Status::INTERNAL_ERROR);
                }
                let mut bytes = Vec::new();
                for (index, change) in changes.iter().enumerate() {
                    if change.encoded_len() > length.saturating_sub(bytes.len()) {
                        return Ok((Status::NOTIFY_ENUM_DIR, notify_body(&[])));
                    }
                    let name = encode_name(&change.name);
                    let next = if index + 1 == changes.len() {
                        0
                    } else {
                        change.encoded_len() as u32
                    };
                    bytes.extend_from_slice(
                        FileNotifyInformation {
                            next_entry_offset: next.into(),
                            action: change.action.0.into(),
                            file_name_length: (name.len() as u32).into(),
                        }
                        .as_bytes(),
                    );
                    bytes.extend_from_slice(&name);
                    bytes.resize(align_up(bytes.len(), NOTIFY_ALIGNMENT)?, 0);
                }
                Ok((Status::SUCCESS, notify_body(&bytes)))
            }
        }
    }

    fn session_setup(&self, header: &Header, packet: &[u8]) -> Result<(Status, Vec<u8>), Status> {
        let request: SessionSetupRequest = read_body(packet)?;
        let token = variable::<SessionSetupRequest>(
            packet,
            request.security_buffer_offset.get() as usize,
            request.security_buffer_length.get() as usize,
        )?;
        let mut state = self.state.lock();
        if request.flags.into_bits() != 0
            || request.security_mode.signing_required()
            || state.session_active
        {
            return Err(Status::NOT_SUPPORTED);
        }
        let mut security = Vec::new();
        let status;
        if token.is_empty() && state.session == 0 {
            status = Status::SUCCESS;
        } else if token.starts_with(&ntlm::SIGNATURE)
            && token.len() >= size_of::<ntlm::MessageHeader>()
        {
            let message = ntlm::MessageHeader::read_from_prefix(token)
                .map_err(|_| Status::INVALID_PARAMETER)?
                .0;
            let message = ntlm::MessageType(message.message_type.get());
            match message {
                ntlm::MessageType::NEGOTIATE if state.session == 0 => {
                    // This is a guest-only test handshake, not credential verification.
                    let payload_offset = size_of::<ntlm::ChallengeMessage>() as u32;
                    let mut challenge = ntlm::ChallengeMessage::new_zeroed();
                    challenge.header = ntlm::MessageHeader {
                        signature: ntlm::SIGNATURE,
                        message_type: ntlm::MessageType::CHALLENGE.0.into(),
                    };
                    challenge.target_name.offset = payload_offset.into();
                    challenge.negotiate_flags = ntlm::NegotiateFlags::new()
                        .with_unicode(true)
                        .with_request_target(true)
                        .with_ntlm(true)
                        .with_target_type_server(true)
                        .with_extended_session_security(true)
                        .with_target_info(true);
                    challenge.target_info = ntlm::SecurityBuffer {
                        length: (size_of::<ntlm::AvPair>() as u16).into(),
                        maximum_length: (size_of::<ntlm::AvPair>() as u16).into(),
                        offset: payload_offset.into(),
                    };
                    security.extend_from_slice(challenge.as_bytes());
                    security.extend_from_slice(
                        ntlm::AvPair {
                            id: ntlm::MSV_AV_EOL.into(),
                            length: 0.into(),
                        }
                        .as_bytes(),
                    );
                    status = Status::MORE_PROCESSING_REQUIRED;
                }
                ntlm::MessageType::AUTHENTICATE
                    if state.session != 0
                        && header.session_id.get() == state.session
                        && token.len() >= size_of::<ntlm::AuthenticateMessage>() =>
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
            structure_size: SessionSetupResponse::STRUCTURE_SIZE.into(),
            session_flags: if state.session_active {
                SESSION_FLAG_IS_GUEST.into()
            } else {
                0.into()
            },
            security_buffer_offset: (body_end::<SessionSetupResponse>() as u16).into(),
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
            let _: SimpleBody = read_body(packet)?;
            return Ok(SimpleBody {
                structure_size: SimpleBody::STRUCTURE_SIZE.into(),
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
                structure_size: SimpleBody::STRUCTURE_SIZE.into(),
                reserved: 0.into(),
            }
            .as_bytes()
            .to_vec());
        }
        if command == Command::TREE_CONNECT {
            let request: TreeConnectRequest = read_body(packet)?;
            let path = decode_name(variable::<TreeConnectRequest>(
                packet,
                request.path_offset.get() as usize,
                request.path_length.get() as usize,
            )?)?;
            let parts: Vec<_> = path.split('\\').filter(|s| !s.is_empty()).collect();
            if !path.starts_with("\\\\")
                || parts.len() != 2
                || !parts[1].eq_ignore_ascii_case(&self.server.name)
            {
                return Err(Status::BAD_NETWORK_NAME);
            }
            let mut state = self.state.lock();
            if state.trees.len() >= MAX_TREES {
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
                structure_size: TreeConnectResponse::STRUCTURE_SIZE.into(),
                share_type: ShareType::DISK,
                reserved: 0,
                share_flags: 0.into(),
                capabilities: 0.into(),
                maximal_access: AccessMask::FILE_ALL_ACCESS,
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
                    structure_size: SimpleBody::STRUCTURE_SIZE.into(),
                    reserved: 0.into(),
                }
                .as_bytes()
                .to_vec())
            }
            Command::CLOSE => {
                let request: CloseRequest = read_body(packet)?;
                let file = self.file(request.file_id, tree, context)?;
                file.wait(context, true).await?;
                let info = if request.flags.postquery_attrib() {
                    // MS-SMB2 3.3.5.10 permits omitting unavailable optional attributes.
                    self.server.backend.metadata(&file.file, context).await.ok()
                } else {
                    None
                };
                self.close_file(&file, context).await?;
                let mut response = CloseResponse::new_zeroed();
                response.structure_size = CloseResponse::STRUCTURE_SIZE.into();
                if let Some(info) = info {
                    response.flags = CloseFlags::new().with_postquery_attrib(true);
                    response.creation_time = info.created.into();
                    response.last_access_time = info.accessed.into();
                    response.last_write_time = info.written.into();
                    response.change_time = info.changed.into();
                    response.allocation_size = info.allocation_size.into();
                    response.end_of_file = info.size.into();
                    response.file_attributes = info.attributes.into();
                }
                Ok(response.as_bytes().to_vec())
            }
            Command::FLUSH => {
                let request: FlushRequest = read_body(packet)?;
                self.server
                    .backend
                    .flush(&self.file(request.file_id, tree, context)?.file, context)
                    .await?;
                Ok(SimpleBody {
                    structure_size: SimpleBody::STRUCTURE_SIZE.into(),
                    reserved: 0.into(),
                }
                .as_bytes()
                .to_vec())
            }
            Command::READ => self.read(packet, tree, context).await,
            Command::WRITE => self.write(packet, tree, context).await,
            Command::LOCK => self.lock(packet, tree, context).await,
            Command::OPLOCK_BREAK => self.oplock_acknowledgement(packet, tree, context),
            Command::QUERY_DIRECTORY => self.query_directory(packet, tree, context).await,
            Command::SET_INFO => self.set_info(packet, tree, context).await,
            _ => Err(Status::NOT_SUPPORTED),
        }
    }

    async fn ioctl(
        &self,
        packet: &[u8],
        tree: u32,
        context: &RequestContext,
    ) -> Result<(Status, Vec<u8>), Status> {
        let request: IoctlRequest = read_body(packet)?;
        if request.flags.into_bits() != IoctlFlags::new().with_fsctl(true).into_bits() {
            return Err(Status::NOT_SUPPORTED);
        }
        let code = FsctlCode(request.control_code.get());
        if code.uses_file() {
            let _ = self.file(request.file_id, tree, context)?;
        } else if request.file_id.persistent.get() != u64::MAX
            || request.file_id.volatile.get() != u64::MAX
        {
            return Err(Status::INVALID_PARAMETER);
        }
        if [
            request.input_count.get(),
            request.max_input_response.get(),
            request.max_output_response.get(),
        ]
        .into_iter()
        .any(|length| length as usize > MAX_TRANSFER_SIZE)
        {
            return Err(Status::INVALID_PARAMETER);
        }
        if request.input_count.get() != 0
            && !(request.input_offset.get() as usize).is_multiple_of(8)
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let input = variable::<IoctlRequest>(
            packet,
            request.input_offset.get() as usize,
            request.input_count.get() as usize,
        )?;
        if matches!(
            code,
            FsctlCode::QUERY_SHARED_VIRTUAL_DISK_SUPPORT
                | FsctlCode::SVHDX_SYNC_TUNNEL_REQUEST
                | FsctlCode::SVHDX_ASYNC_TUNNEL_REQUEST
        ) {
            return Err(Status::INVALID_DEVICE_REQUEST);
        }
        let control = match code {
            FsctlCode::SET_SPARSE => FileControl::SetSparse {
                sparse: if input.is_empty() {
                    true
                } else {
                    FileSetSparseBuffer::read_from_prefix(input)
                        .map_err(|_| Status::INVALID_PARAMETER)?
                        .0
                        .set_sparse
                        != 0
                },
            },
            FsctlCode::GET_REPARSE_POINT => FileControl::GetReparsePoint {
                maximum: request.max_output_response.get(),
            },
            FsctlCode::SET_REPARSE_POINT => {
                let (tag, guid, data) = decode_reparse_data(input, false)?;
                FileControl::SetReparsePoint { tag, guid, data }
            }
            FsctlCode::DELETE_REPARSE_POINT => {
                let (tag, guid, _) = decode_reparse_data(input, true)?;
                FileControl::DeleteReparsePoint { tag, guid }
            }
            FsctlCode::GET_OBJECT_ID | FsctlCode::CREATE_OR_GET_OBJECT_ID => {
                if request.max_output_response.get() < size_of::<FileObjectIdBuffer>() as u32 {
                    return Err(Status::INVALID_PARAMETER);
                }
                if code == FsctlCode::GET_OBJECT_ID {
                    FileControl::GetObjectId
                } else {
                    FileControl::CreateOrGetObjectId
                }
            }
            FsctlCode::SET_OBJECT_ID => {
                let info = FileObjectIdBuffer::read_from_bytes(input)
                    .map_err(|_| Status::INVALID_PARAMETER)?;
                FileControl::SetObjectId(provider::ObjectIdInformation {
                    object_id: info.object_id,
                    birth_volume_id: info.birth_volume_id,
                    birth_object_id: info.birth_object_id,
                    domain_id: info.domain_id,
                })
            }
            FsctlCode::DELETE_OBJECT_ID => FileControl::DeleteObjectId,
            FsctlCode::SET_OBJECT_ID_EXTENDED => {
                let info = FileObjectIdExtendedInformation::read_from_bytes(input)
                    .map_err(|_| Status::INVALID_PARAMETER)?;
                FileControl::SetObjectIdExtended {
                    birth_volume_id: info.birth_volume_id,
                    birth_object_id: info.birth_object_id,
                    domain_id: info.domain_id,
                }
            }
            FsctlCode::GET_COMPRESSION => {
                if request.max_output_response.get() < 2 {
                    return Err(Status::INVALID_PARAMETER);
                }
                FileControl::GetCompression
            }
            FsctlCode::SET_COMPRESSION => {
                let format = U16::read_from_prefix(input)
                    .map_err(|_| Status::INVALID_PARAMETER)?
                    .0
                    .get();
                if format > 2 {
                    return Err(Status::INVALID_PARAMETER);
                }
                FileControl::SetCompression { format }
            }
            FsctlCode::SET_ZERO_DATA => {
                let info = FileZeroDataInformation::read_from_prefix(input)
                    .map_err(|_| Status::INVALID_PARAMETER)?
                    .0;
                let offset =
                    u64::try_from(info.file_offset.get()).map_err(|_| Status::INVALID_PARAMETER)?;
                let end = u64::try_from(info.beyond_final_zero.get())
                    .map_err(|_| Status::INVALID_PARAMETER)?;
                if offset > end {
                    return Err(Status::INVALID_PARAMETER);
                }
                FileControl::SetZeroData { offset, end }
            }
            FsctlCode::QUERY_ALLOCATED_RANGES => {
                let info = FileAllocatedRangeBuffer::read_from_prefix(input)
                    .map_err(|_| Status::INVALID_PARAMETER)?
                    .0;
                let offset =
                    u64::try_from(info.file_offset.get()).map_err(|_| Status::INVALID_PARAMETER)?;
                let length =
                    u64::try_from(info.length.get()).map_err(|_| Status::INVALID_PARAMETER)?;
                offset
                    .checked_add(length)
                    .filter(|end| *end <= i64::MAX as u64)
                    .ok_or(Status::INVALID_PARAMETER)?;
                if length != 0
                    && request.max_output_response.get()
                        < size_of::<FileAllocatedRangeBuffer>() as u32
                {
                    return Err(Status::BUFFER_TOO_SMALL);
                }
                FileControl::QueryAllocatedRanges {
                    range: ByteRange { offset, length },
                    maximum_ranges: request.max_output_response.get() as usize
                        / size_of::<FileAllocatedRangeBuffer>(),
                }
            }
            _ => return Err(Status::NOT_SUPPORTED),
        };
        let file = self.file(request.file_id, tree, context)?;
        if matches!(control, FileControl::SetCompression { .. }) && !file.access.write_data() {
            return Err(Status::ACCESS_DENIED);
        }
        if matches!(
            control,
            FileControl::SetReparsePoint { .. }
                | FileControl::DeleteReparsePoint { .. }
                | FileControl::SetSparse { .. }
        ) && !(file.access.write_data() || file.access.write_attributes())
        {
            return Err(Status::ACCESS_DENIED);
        }
        if matches!(control, FileControl::SetObjectIdExtended { .. })
            && !(file.access.write_data() || file.access.write_attributes())
        {
            return Err(Status::ACCESS_DENIED);
        }
        if matches!(control, FileControl::SetZeroData { .. }) && !file.access.write_data() {
            return Err(Status::ACCESS_DENIED);
        }
        if matches!(control, FileControl::QueryAllocatedRanges { .. }) && !file.access.read_data() {
            return Err(Status::ACCESS_DENIED);
        }
        if matches!(
            control,
            FileControl::SetZeroData { .. } | FileControl::QueryAllocatedRanges { .. }
        ) && file.is_directory
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let result = self
            .server
            .backend
            .file_control(&file.file, control, context)
            .await?;
        let (status, output) = file_control_output(control, result)?;
        let mut body = IoctlResponse {
            structure_size: IoctlResponse::STRUCTURE_SIZE.into(),
            reserved: 0.into(),
            control_code: request.control_code,
            file_id: request.file_id,
            input_offset: (body_end::<IoctlResponse>() as u32).into(),
            input_count: 0.into(),
            output_offset: if output.is_empty() {
                0
            } else {
                body_end::<IoctlResponse>() as u32
            }
            .into(),
            output_count: (output.len() as u32).into(),
            flags: 0.into(),
            reserved2: 0.into(),
        }
        .as_bytes()
        .to_vec();
        body.extend_from_slice(&output);
        Ok((status, body))
    }

    fn oplock_acknowledgement(
        &self,
        packet: &[u8],
        tree: u32,
        context: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let size =
            U16::read_from_prefix(packet.get(HEADER_SIZE..).ok_or(Status::INVALID_PARAMETER)?)
                .map_err(|_| Status::INVALID_PARAMETER)?
                .0
                .get();
        if size == LeaseBreakAcknowledgement::STRUCTURE_SIZE {
            let _: LeaseBreakAcknowledgement = read_body(packet)?;
            return Err(Status::OBJECT_NAME_NOT_FOUND);
        }
        let request: OplockBreakAcknowledgement = read_body(packet)?;
        let _ = self.file(request.file_id, tree, context)?;
        // No caching rights are granted, so no open can be awaiting a break ACK.
        Err(Status::INVALID_DEVICE_STATE)
    }

    async fn lock(
        &self,
        packet: &[u8],
        tree: u32,
        context: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let request: LockRequest = read_body(packet)?;
        let count = usize::from(request.lock_count.get());
        if count == 0 {
            return Err(Status::INVALID_PARAMETER);
        }
        let start = HEADER_SIZE + std::mem::offset_of!(LockRequest, first_lock);
        let bytes = field(packet, start, count * size_of::<LockElement>(), start)?;
        let locks =
            <[LockElement]>::ref_from_bytes(bytes).map_err(|_| Status::INVALID_PARAMETER)?;
        let file = self.file(request.file_id, tree, context)?;
        let unlocking = request.first_lock.flags.unlock();
        if !unlocking && count > 1 && locks.iter().any(|lock| !lock.flags.fail_immediately()) {
            return Err(Status::INVALID_PARAMETER);
        }
        let mut acquired = Vec::new();
        for lock in locks {
            let range = ByteRange {
                offset: lock.offset.get(),
                length: lock.length.get(),
            };
            let flags = lock.flags;
            if unlocking {
                if flags.shared_lock() || flags.exclusive_lock() || flags.fail_immediately() {
                    return Err(Status::INVALID_PARAMETER);
                }
                self.server
                    .backend
                    .unlock(&file.file, range, context)
                    .await?;
            } else {
                let expected = LockFlags::new()
                    .with_shared_lock(flags.shared_lock())
                    .with_exclusive_lock(flags.exclusive_lock())
                    .with_fail_immediately(flags.fail_immediately());
                if flags.shared_lock() == flags.exclusive_lock()
                    || flags.into_bits() != expected.into_bits()
                {
                    return Err(Status::INVALID_PARAMETER);
                }
                let result = self
                    .server
                    .backend
                    .lock(
                        &file.file,
                        range,
                        flags.exclusive_lock(),
                        flags.fail_immediately(),
                        context,
                    )
                    .await;
                if result == Err(Status::LOCK_NOT_GRANTED) && flags.fail_immediately() {
                    let rollback = RequestContext::new(
                        self.server.next_request.fetch_add(1, Ordering::Relaxed),
                    );
                    for &acquired in acquired.iter().rev() {
                        if let Err(status) = self
                            .server
                            .backend
                            .rollback_lock(&file.file, acquired, &rollback)
                            .await
                        {
                            tracelimit::error_ratelimited!(?status, "SMB lock rollback failed");
                            return Err(status);
                        }
                    }
                }
                acquired.push(result?);
            }
        }
        Ok(SimpleBody {
            structure_size: SimpleBody::STRUCTURE_SIZE.into(),
            reserved: 0.into(),
        }
        .as_bytes()
        .to_vec())
    }

    fn negotiate(&self, packet: &[u8]) -> Result<Vec<u8>, Status> {
        let request: NegotiateRequest = read_body(packet)?;
        let mut state = self.state.lock();
        if state.negotiated || request.security_mode.signing_required() {
            return Err(Status::NOT_SUPPORTED);
        }
        let dialects = variable::<NegotiateRequest>(
            packet,
            body_end::<NegotiateRequest>(),
            request.dialect_count.get() as usize * size_of::<U16>(),
        )?;
        if !dialects
            .chunks_exact(size_of::<U16>())
            .any(|p| u16::from_le_bytes([p[0], p[1]]) == DIALECT_210)
        {
            return Err(Status::NOT_SUPPORTED);
        }
        state.negotiated = true;
        Ok(NegotiateResponse {
            structure_size: NegotiateResponse::STRUCTURE_SIZE.into(),
            security_mode: SecurityMode::new().with_signing_enabled(true),
            dialect: DIALECT_210.into(),
            reserved: 0.into(),
            server_guid: self
                .server
                .guid
                .as_bytes()
                .try_into()
                .map_err(|_| Status::INVALID_PARAMETER)?,
            capabilities: Capabilities::new().with_large_mtu(true),
            max_transact_size: (MAX_TRANSFER_SIZE as u32).into(),
            max_read_size: (MAX_TRANSFER_SIZE as u32).into(),
            max_write_size: (MAX_TRANSFER_SIZE as u32).into(),
            system_time: memory::nt_time().into(),
            server_start_time: 0.into(),
            security_buffer_offset: (body_end::<NegotiateResponse>() as u16).into(),
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
    ) -> Result<(Status, Vec<u8>), Status> {
        let request: CreateRequest = read_body(packet)?;
        let name = decode_name(variable::<CreateRequest>(
            packet,
            request.name_offset.get() as usize,
            request.name_length.get() as usize,
        )?)?;
        let contexts = variable::<CreateRequest>(
            packet,
            request.contexts_offset.get() as usize,
            request.contexts_length.get() as usize,
        )?;
        if !contexts.is_empty()
            && !(request.contexts_offset.get() as usize).is_multiple_of(CREATE_CONTEXT_ALIGNMENT)
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let contexts = create_contexts(contexts)?;
        let mut names = BTreeSet::new();
        let mut maximal_access = None;
        let mut disk_id = false;
        let mut security = None;
        let mut extended_attributes = None;
        let mut allocation_size = 0;
        for context in contexts {
            if context.name == RESERVED_CREATE_CONTEXT_NAME {
                continue;
            }
            if !names.insert(context.name) {
                return Err(Status::INVALID_PARAMETER);
            }
            match context.name() {
                Some(CreateContextName::QUERY_MAXIMAL_ACCESS) => {
                    let timestamp = match context.data.len() {
                        0 => None,
                        length if length == size_of::<MaximalAccessRequest>() => Some(
                            MaximalAccessRequest::read_from_bytes(context.data)
                                .map_err(|_| Status::INVALID_PARAMETER)?
                                .timestamp
                                .get(),
                        ),
                        _ => return Err(Status::INVALID_PARAMETER),
                    };
                    maximal_access = Some(timestamp);
                }
                Some(CreateContextName::QUERY_ON_DISK_ID) if context.data.is_empty() => {
                    disk_id = true
                }
                // The object store does not grant durable handles or leases.
                Some(CreateContextName::DURABLE_HANDLE_REQUEST)
                    if context.data.len() == size_of::<DurableHandleRequest>() => {}
                Some(CreateContextName::ALLOCATION_SIZE)
                    if context.data.len() == size_of::<AllocationSizeContext>() =>
                {
                    allocation_size = AllocationSizeContext::read_from_bytes(context.data)
                        .map_err(|_| Status::INVALID_PARAMETER)?
                        .allocation_size
                        .get();
                }
                Some(CreateContextName::REQUEST_LEASE) => {}
                Some(CreateContextName::EA_BUFFER) => extended_attributes = Some(context.data),
                Some(CreateContextName::SECURITY_DESCRIPTOR) => security = Some(context.data),
                Some(CreateContextName::TIMEWARP)
                    if context.data.len() == size_of::<TimewarpContext>() =>
                {
                    return Err(Status::OBJECT_NAME_NOT_FOUND);
                }
                Some(CreateContextName::DURABLE_HANDLE_RECONNECT)
                    if context.data.len() == size_of::<DurableHandleReconnect>() =>
                {
                    return Err(Status::OBJECT_NAME_NOT_FOUND);
                }
                Some(
                    CreateContextName::QUERY_ON_DISK_ID
                    | CreateContextName::DURABLE_HANDLE_REQUEST
                    | CreateContextName::ALLOCATION_SIZE
                    | CreateContextName::TIMEWARP
                    | CreateContextName::DURABLE_HANDLE_RECONNECT,
                ) => {
                    return Err(Status::INVALID_PARAMETER);
                }
                _ => return Err(Status::NOT_SUPPORTED),
            }
        }
        let options = request
            .create_options
            .with_complete_if_oplocked(false)
            .with_synchronous_io_alert(false)
            .with_synchronous_io_nonalert(false)
            .with_no_compression(
                request.create_options.no_compression() && !request.create_options.directory_file(),
            )
            .with_open_for_free_space_query(false);
        if options.open_by_file_id() {
            return Err(Status::NOT_SUPPORTED);
        }
        if options.no_ea_knowledge() && extended_attributes.is_some() {
            return Err(Status::ACCESS_DENIED);
        }
        if request.impersonation_level.get() > ImpersonationLevel::DELEGATE.0 {
            return Err(Status::BAD_IMPERSONATION_LEVEL);
        }
        if name.starts_with('\\')
            || !request.file_attributes.is_valid()
            || !request.disposition().is_valid()
            || !request.share_access.is_valid()
            || (options.directory_file() && options.non_directory_file())
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let access = map_access(request.desired_access.into_bits());
        let access = AccessMask::from_bits(access);
        let access = if options.no_intermediate_buffering() {
            access.with_append_data(false)
        } else {
            access
        };
        let volatile = {
            let mut state = self.state.lock();
            if state.files.len() + state.requests.values().filter(|info| info.creating).count()
                >= MAX_OPENS
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
        let opened = self
            .server
            .backend
            .open_with_caching(
                &name,
                OpenOptions {
                    access: access.into_bits(),
                    share_access: request.share_access.into_bits(),
                    disposition: request.create_disposition.get(),
                    options: options.into_bits(),
                    attributes: request.file_attributes.into_bits(),
                    allocation_size,
                    security,
                    extended_attributes,
                },
                // Keep the wire profile uncached until break delivery is integrated.
                CachingRequest::None,
                context,
            )
            .await;
        let Opened {
            file,
            action,
            caching,
        } = match opened {
            Ok(opened) => opened,
            Err(OpenError::SymbolicLink(link)) => {
                return symbolic_link_error(&name, link)
                    .map(|body| (Status::STOPPED_ON_SYMLINK, body));
            }
            Err(OpenError::Status(Status::STOPPED_ON_SYMLINK)) => {
                return Err(Status::INTERNAL_ERROR);
            }
            Err(OpenError::Status(status)) => return Err(status),
        };
        if !matches!(caching, CachingGrant::None) {
            let cleanup =
                RequestContext::new(self.server.next_request.fetch_add(1, Ordering::Relaxed));
            self.server.backend.close(&file, &cleanup).await?;
            return Err(Status::INTERNAL_ERROR);
        }
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
        let access = AccessMask::from_bits(info.granted_access);
        let file = Arc::new(OpenFile {
            file,
            identity: info.id,
            access,
            mode: AtomicU32::new(options.into_bits() & FILE_MODE_INFORMATION_MASK),
            is_directory: info.is_directory(),
            tree,
            position: AtomicI64::new(0),
            directory: Mutex::new(None),
            ea_cursor: futures::lock::Mutex::new(1),
            closing: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            close_gate: futures::lock::Mutex::new(()),
            active: Mutex::new(Vec::new()),
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
        let mut response_contexts = Vec::new();
        let mut previous = None;
        if let Some(timestamp) = maximal_access {
            let unchanged = timestamp == Some(info.changed);
            append_create_context(
                &mut response_contexts,
                &mut previous,
                CreateContextName::QUERY_MAXIMAL_ACCESS,
                MaximalAccessResponse {
                    query_status: if unchanged {
                        Status::NONE_MAPPED.0.into()
                    } else {
                        Status::SUCCESS.0.into()
                    },
                    maximal_access: if unchanged {
                        0.into()
                    } else {
                        info.maximal_access.into()
                    },
                }
                .as_bytes(),
            );
        }
        if disk_id {
            let mut volume_id = [0; 8];
            volume_id.copy_from_slice(&self.server.guid.as_bytes()[..8]);
            append_create_context(
                &mut response_contexts,
                &mut previous,
                CreateContextName::QUERY_ON_DISK_ID,
                OnDiskIdResponse {
                    file_id: info.id.into(),
                    volume_id: u64::from_le_bytes(volume_id).into(),
                    reserved: [0; 16],
                }
                .as_bytes(),
            );
        }
        let mut response = CreateResponse {
            structure_size: CreateResponse::STRUCTURE_SIZE.into(),
            oplock_level: OplockLevel::NONE,
            flags: 0,
            create_action: action.into(),
            creation_time: info.created.into(),
            last_access_time: info.accessed.into(),
            last_write_time: info.written.into(),
            change_time: info.changed.into(),
            allocation_size: info.allocation_size.into(),
            end_of_file: info.size.into(),
            file_attributes: info.attributes.into(),
            reserved: 0.into(),
            file_id,
            contexts_offset: if response_contexts.is_empty() {
                0.into()
            } else {
                (body_end::<CreateResponse>() as u32).into()
            },
            contexts_length: (response_contexts.len() as u32).into(),
        }
        .as_bytes()
        .to_vec();
        response.extend_from_slice(&response_contexts);
        Ok((Status::SUCCESS, response))
    }

    async fn read(
        &self,
        packet: &[u8],
        tree: u32,
        context: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let request: ReadRequest = read_body(packet)?;
        if request.length.get() as usize > MAX_TRANSFER_SIZE
            || Channel(request.channel.get()) != Channel::NONE
            || request.offset.get() > i64::MAX as u64 - u64::from(request.length.get())
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let file = self.file(request.file_id, tree, context)?;
        // MS-SMB2 §3.3.5.12 authorizes READ through EXECUTE without adding LIST_DIRECTORY.
        if !file.access.read_data() && !file.access.execute() {
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
            structure_size: ReadResponse::STRUCTURE_SIZE.into(),
            data_offset: body_end::<ReadResponse>() as u8,
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
        let request: WriteRequest = read_body(packet)?;
        if request.length.get() as usize > MAX_TRANSFER_SIZE
            || Channel(request.channel.get()) != Channel::NONE
            || request.offset.get() > i64::MAX as u64 - u64::from(request.length.get())
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let bytes = variable::<WriteRequest>(
            packet,
            request.data_offset.get() as usize,
            request.length.get() as usize,
        )?;
        let file = self.file(request.file_id, tree, context)?;
        if !file.access.write_data() {
            return Err(Status::ACCESS_DENIED);
        }
        let written = self
            .server
            .backend
            .write(&file.file, request.offset.get(), bytes, context)
            .await?;
        Ok(WriteResponse {
            structure_size: WriteResponse::STRUCTURE_SIZE.into(),
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
    ) -> Result<(Status, Vec<u8>), Status> {
        let request: QueryInfoRequest = read_body(packet)?;
        let input = variable::<QueryInfoRequest>(
            packet,
            request.input_buffer_offset.get() as usize,
            request.input_buffer_length.get() as usize,
        )?;
        let file = self.file(request.file_id, tree, context)?;
        let info_type = request.info_type;
        let class = FileInformationClass(request.info_class);
        if info_type == InformationType::SECURITY {
            let information = SecurityInformation::from_bits(
                request.additional_information.get() & SecurityInformation::VALID,
            );
            if (information.owner()
                || information.group()
                || information.dacl()
                || information.label())
                && !file.access.read_control()
                || information.sacl() && !file.access.access_system_security()
            {
                return Err(Status::ACCESS_DENIED);
            }
            let descriptor = self
                .server
                .backend
                .query_security(&file.file, information, context)
                .await?;
            let bytes = descriptor.encode();
            if bytes.len() > request.output_buffer_length.get() as usize {
                let mut body = ErrorResponse {
                    structure_size: ErrorResponse::STRUCTURE_SIZE.into(),
                    context_count: 0,
                    reserved: 0,
                    byte_count: 4.into(),
                }
                .as_bytes()
                .to_vec();
                body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                return Ok((Status::BUFFER_TOO_SMALL, body));
            }
            return buffer_response(bytes, request.output_buffer_length.get())
                .map(|body| (Status::SUCCESS, body));
        }
        if info_type == InformationType::FILESYSTEM {
            let class = FileSystemInformationClass(request.info_class);
            match class {
                FileSystemInformationClass::VOLUME
                | FileSystemInformationClass::SIZE
                | FileSystemInformationClass::FULL_SIZE
                | FileSystemInformationClass::DEVICE
                | FileSystemInformationClass::SECTOR_SIZE
                | FileSystemInformationClass::OBJECT_ID
                | FileSystemInformationClass::ATTRIBUTE => {}
                FileSystemInformationClass::LABEL
                | FileSystemInformationClass::DRIVER_PATH
                | FileSystemInformationClass::VOLUME_FLAGS => {
                    return Err(Status::INVALID_INFO_CLASS);
                }
                _ => return Err(Status::INVALID_PARAMETER),
            }
            let info = self
                .server
                .backend
                .filesystem_information(&file.file, context)
                .await?;
            return filesystem_response(&info, class, request.output_buffer_length.get());
        }
        if info_type != InformationType::FILE {
            return Err(Status::NOT_SUPPORTED);
        }
        if matches!(
            class,
            FileInformationClass::NAME | FileInformationClass::NORMALIZED_NAME
        ) {
            return Err(Status::NOT_SUPPORTED);
        }
        if class == FileInformationClass::FULL_EA {
            if !file.access.read_ea() {
                return Err(Status::ACCESS_DENIED);
            }
            if request.output_buffer_length.get() as usize > MAX_TRANSFER_SIZE
                || input.len() > MAX_TRANSFER_SIZE
            {
                return Err(Status::INVALID_PARAMETER);
            }
            if request.output_buffer_length.get() < size_of::<FileFullEaInformation>() as u32 {
                return Err(Status::INFO_LENGTH_MISMATCH);
            }
            let names = if input.is_empty() {
                None
            } else {
                Some(decode_ea_names(input)?)
            };
            let flags = EaQueryFlags::from_bits(request.flags.get());
            let indexed = names.is_none() && flags.index_specified();
            let mut cursor = file.ea_cursor.lock().await;
            if context.is_cancelled() {
                return Err(Status::CANCELLED);
            }
            let entries = self.server.backend.query_eas(&file.file, context).await?;
            if encode_ea_list(&entries)
                .map_err(|_| Status::INTERNAL_ERROR)?
                .len()
                > MAX_EA_LENGTH
            {
                return Err(Status::INTERNAL_ERROR);
            }
            if flags.restart_scan() && names.is_none() && !indexed {
                *cursor = 1;
            }
            if indexed
                && (request.additional_information.get() == 0
                    || request.additional_information.get() as usize > entries.len())
            {
                return Err(Status::NONEXISTENT_EA_ENTRY);
            }
            if entries.is_empty() {
                return Err(Status::NO_EAS_ON_FILE);
            }
            let start = if indexed {
                request.additional_information.get()
            } else {
                *cursor
            };
            let selected: Vec<_> = if let Some(names) = &names {
                let mut lookup = BTreeMap::new();
                for entry in &entries {
                    if lookup
                        .insert(entry.name.to_ascii_uppercase(), entry)
                        .is_some()
                    {
                        return Err(Status::INTERNAL_ERROR);
                    }
                }
                let mut selected = Vec::new();
                for name in names {
                    selected.push(
                        lookup
                            .get(&name.to_ascii_uppercase())
                            .copied()
                            .ok_or(Status::NONEXISTENT_EA_ENTRY),
                    );
                }
                selected
            } else {
                entries
                    .get(start.saturating_sub(1) as usize..)
                    .ok_or(Status::NO_MORE_EAS)?
                    .iter()
                    .map(Ok)
                    .collect()
            };
            if selected.is_empty() {
                return Err(Status::NO_MORE_EAS);
            }
            let mut length = 0;
            let mut count = 0;
            for (index, entry) in selected.iter().enumerate() {
                if let Some(names) = &names {
                    let start = if count == 0 { 0 } else { align_up(length, 4)? };
                    // Do not query later names after the output buffer is full.
                    if start + size_of::<FileFullEaInformation>() + names[index].len() + 1
                        > request.output_buffer_length.get() as usize
                    {
                        break;
                    }
                }
                let entry = entry.as_ref().map_err(|status| *status)?;
                let next_length = if count == 0 {
                    entry.encoded_len()
                } else {
                    align_up(length, 4)? + entry.encoded_len()
                };
                if next_length > request.output_buffer_length.get() as usize {
                    break;
                }
                length = next_length;
                count += 1;
                if flags.return_single_entry() {
                    break;
                }
            }
            if count == 0 {
                return Err(Status::BUFFER_TOO_SMALL);
            }
            let bytes = encode_ea_list(
                &selected[..count]
                    .iter()
                    .map(|entry| {
                        entry
                            .as_ref()
                            .map(|entry| (**entry).clone())
                            .map_err(|_| Status::INTERNAL_ERROR)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .map_err(|_| Status::INTERNAL_ERROR)?;
            if names.is_none() && !indexed {
                *cursor = start + count as u32;
            }
            let status = if count < selected.len() && !flags.return_single_entry() {
                Status::BUFFER_OVERFLOW
            } else {
                Status::SUCCESS
            };
            return buffer_response(bytes, request.output_buffer_length.get())
                .map(|body| (status, body));
        }
        if class == FileInformationClass::STREAM {
            if request.output_buffer_length.get() as usize > MAX_TRANSFER_SIZE {
                return Err(Status::INVALID_PARAMETER);
            }
            if request.output_buffer_length.get() < size_of::<FileStreamInformation>() as u32 {
                return Err(Status::INFO_LENGTH_MISMATCH);
            }
            let streams = self
                .server
                .backend
                .query_streams(&file.file, context)
                .await?;
            return stream_response(&streams, request.output_buffer_length.get());
        }
        let minimum = match class {
            FileInformationClass::BASIC => size_of::<FileBasicInformation>(),
            FileInformationClass::STANDARD => size_of::<FileStandardInformation>(),
            FileInformationClass::COMPRESSION => size_of::<FileCompressionInformation>(),
            FileInformationClass::INTERNAL => size_of::<FileInternalInformation>(),
            FileInformationClass::EA => size_of::<FileEaInformation>(),
            FileInformationClass::ACCESS => size_of::<FileAccessInformation>(),
            FileInformationClass::MODE => size_of::<FileModeInformation>(),
            FileInformationClass::ALIGNMENT => size_of::<FileAlignmentInformation>(),
            FileInformationClass::POSITION => size_of::<FilePositionInformation>(),
            FileInformationClass::ALL => FILE_ALL_INFORMATION_MIN_BUFFER_SIZE,
            FileInformationClass::ALTERNATE_NAME => FILE_NAME_INFORMATION_MIN_BUFFER_SIZE,
            FileInformationClass::NETWORK_OPEN => size_of::<FileNetworkOpenInformation>(),
            FileInformationClass::ATTRIBUTE_TAG => size_of::<FileAttributeTagInformation>(),
            FileInformationClass::DIRECTORY
            | FileInformationClass::FULL_DIRECTORY
            | FileInformationClass::BOTH_DIRECTORY
            | FileInformationClass::NAMES
            | FileInformationClass::ID_BOTH_DIRECTORY
            | FileInformationClass::ID_FULL_DIRECTORY
            | FileInformationClass::ID_EXTD_DIRECTORY
            | FileInformationClass::ID64_EXTD_DIRECTORY
            | FileInformationClass::ID64_EXTD_BOTH_DIRECTORY
            | FileInformationClass::ID_ALL_EXTD_DIRECTORY
            | FileInformationClass::ID_ALL_EXTD_BOTH_DIRECTORY => {
                return Err(Status::INVALID_INFO_CLASS);
            }
            _ => return Err(Status::NOT_SUPPORTED),
        };
        let maximum = request.output_buffer_length.get();
        if (maximum as usize) < minimum {
            return Err(Status::INFO_LENGTH_MISMATCH);
        }
        if matches!(
            class,
            FileInformationClass::ACCESS | FileInformationClass::MODE
        ) {
            let out = if class == FileInformationClass::ACCESS {
                FileAccessInformation {
                    access_flags: file.access,
                }
                .as_bytes()
                .to_vec()
            } else {
                FileModeInformation {
                    mode: file.mode.load(Ordering::Relaxed).into(),
                }
                .as_bytes()
                .to_vec()
            };
            return buffer_response(out, maximum).map(|body| (Status::SUCCESS, body));
        }
        if info_type == InformationType::FILE
            && matches!(
                class,
                FileInformationClass::BASIC
                    | FileInformationClass::ALL
                    | FileInformationClass::NETWORK_OPEN
                    | FileInformationClass::ATTRIBUTE_TAG
            )
            && !file.access.read_attributes()
        {
            return Err(Status::ACCESS_DENIED);
        }
        let info = self.server.backend.metadata(&file.file, context).await?;
        let mut out = Vec::new();
        match info_type {
            InformationType::FILE => match class {
                FileInformationClass::BASIC => out.extend_from_slice(basic_info(&info).as_bytes()),
                FileInformationClass::STANDARD => {
                    out.extend_from_slice(standard_info(&info).as_bytes())
                }
                FileInformationClass::COMPRESSION => {
                    let compression = info.compression.ok_or(Status::NOT_SUPPORTED)?;
                    out.extend_from_slice(
                        FileCompressionInformation {
                            compressed_file_size: compression.compressed_size.into(),
                            compression_format: compression.format.into(),
                            compression_unit_shift: compression.unit_shift,
                            chunk_shift: compression.chunk_shift,
                            cluster_shift: compression.cluster_shift,
                            reserved: [0; 3],
                        }
                        .as_bytes(),
                    );
                }
                FileInformationClass::INTERNAL => out.extend_from_slice(
                    FileInternalInformation {
                        index_number: info.id.into(),
                    }
                    .as_bytes(),
                ),
                FileInformationClass::ATTRIBUTE_TAG => out.extend_from_slice(
                    FileAttributeTagInformation {
                        file_attributes: info.attributes(),
                        reparse_tag: info.reparse_tag.into(),
                    }
                    .as_bytes(),
                ),
                FileInformationClass::EA => out.extend_from_slice(
                    FileEaInformation {
                        ea_size: ea_size(&info)?.into(),
                    }
                    .as_bytes(),
                ),
                FileInformationClass::ALIGNMENT => out.extend_from_slice(
                    FileAlignmentInformation {
                        alignment_requirement: info.alignment_requirement.into(),
                    }
                    .as_bytes(),
                ),
                FileInformationClass::ALTERNATE_NAME => {
                    let name = info
                        .short_name
                        .as_deref()
                        .ok_or(Status::OBJECT_NAME_NOT_FOUND)?;
                    let name = encode_name(name);
                    out.extend_from_slice(
                        FileNameInformation {
                            file_name_length: (name.len() as u32).into(),
                        }
                        .as_bytes(),
                    );
                    out.extend_from_slice(&name);
                }
                FileInformationClass::POSITION => out.extend_from_slice(
                    FilePositionInformation {
                        current_byte_offset: file.position.load(Ordering::Relaxed).into(),
                    }
                    .as_bytes(),
                ),
                FileInformationClass::ALL => {
                    let name = encode_name(&info.path);
                    out.extend_from_slice(
                        FileAllInformation {
                            basic: basic_info(&info),
                            standard: standard_info(&info),
                            internal: FileInternalInformation {
                                index_number: info.id.into(),
                            },
                            ea_size: ea_size(&info)?.into(),
                            access_flags: file.access,
                            position: FilePositionInformation {
                                current_byte_offset: file.position.load(Ordering::Relaxed).into(),
                            },
                            mode: file.mode.load(Ordering::Relaxed).into(),
                            alignment_requirement: info.alignment_requirement.into(),
                            name: FileNameInformation {
                                file_name_length: (name.len() as u32).into(),
                            },
                        }
                        .as_bytes(),
                    );
                    out.extend_from_slice(&name);
                }
                FileInformationClass::NETWORK_OPEN => {
                    let basic = basic_info(&info);
                    out.extend_from_slice(
                        FileNetworkOpenInformation {
                            creation_time: basic.creation_time,
                            last_access_time: basic.last_access_time,
                            last_write_time: basic.last_write_time,
                            change_time: basic.change_time,
                            allocation_size: info.allocation_size.into(),
                            end_of_file: info.size.into(),
                            file_attributes: info.attributes.into(),
                            reserved: 0.into(),
                        }
                        .as_bytes(),
                    );
                }
                _ => return Err(Status::NOT_SUPPORTED),
            },
            _ => return Err(Status::NOT_SUPPORTED),
        }
        let status = if out.len() > maximum as usize {
            out.truncate(maximum as usize & !1);
            Status::BUFFER_OVERFLOW
        } else {
            Status::SUCCESS
        };
        buffer_response(out, maximum).map(|body| (status, body))
    }

    async fn set_info(
        &self,
        packet: &[u8],
        tree: u32,
        context: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let request: SetInfoRequest = read_body(packet)?;
        let data = variable::<SetInfoRequest>(
            packet,
            request.buffer_offset.get() as usize,
            request.buffer_length.get() as usize,
        )?;
        let file = self.file(request.file_id, tree, context)?;
        let class = FileInformationClass(request.info_class);
        match (request.info_type, class) {
            (InformationType::FILE, FileInformationClass::LINK) => {
                if data.len() < FILE_LINK_INFORMATION_MIN_SIZE {
                    return Err(Status::INFO_LENGTH_MISMATCH);
                }
                let (info, rest) = FileLinkInformation::read_from_prefix(data)
                    .map_err(|_| Status::INFO_LENGTH_MISMATCH)?;
                let length = info.file_name_length.get() as usize;
                if info.root_directory.get() != 0 || length == 0 || !length.is_multiple_of(2) {
                    return Err(Status::INVALID_PARAMETER);
                }
                let name = decode_name(rest.get(..length).ok_or(Status::INVALID_PARAMETER)?)?;
                if name.starts_with('\\') {
                    return Err(Status::INVALID_PARAMETER);
                }
                self.server
                    .backend
                    .link(&file.file, &name, info.replace_if_exists != 0, context)
                    .await?;
            }
            (InformationType::FILESYSTEM, _)
                if FileSystemInformationClass(request.info_class)
                    == FileSystemInformationClass::OBJECT_ID =>
            {
                if !file.access.write_data() {
                    return Err(Status::ACCESS_DENIED);
                }
                let info = FileFsObjectIdInformation::read_from_prefix(data)
                    .map_err(|_| Status::INVALID_INFO_CLASS)?
                    .0;
                self.server
                    .backend
                    .set_volume_object_id(
                        &file.file,
                        provider::VolumeObjectInformation {
                            object_id: info.object_id,
                            extended_info: info.extended_info,
                        },
                        context,
                    )
                    .await?;
            }
            (InformationType::FILE, FileInformationClass::SHORT_NAME) => {
                if data.len() < FILE_NAME_INFORMATION_MIN_BUFFER_SIZE {
                    return Err(Status::INFO_LENGTH_MISMATCH);
                }
                if !file.access.delete() {
                    return Err(Status::ACCESS_DENIED);
                }
                let (info, rest) = FileNameInformation::read_from_prefix(data)
                    .map_err(|_| Status::INFO_LENGTH_MISMATCH)?;
                let length = info.file_name_length.get() as usize;
                if !length.is_multiple_of(2) {
                    return Err(Status::INVALID_PARAMETER);
                }
                let name = decode_name(rest.get(..length).ok_or(Status::INVALID_PARAMETER)?)?;
                self.server
                    .backend
                    .set_short_name(&file.file, &name, context)
                    .await?;
            }
            (InformationType::FILE, FileInformationClass::FULL_EA) => {
                if !file.access.write_ea() {
                    return Err(Status::ACCESS_DENIED);
                }
                let attributes = decode_ea_list(data)?;
                self.server
                    .backend
                    .set_eas(&file.file, &attributes, context)
                    .await?;
            }
            (InformationType::SECURITY, _) => {
                let information = SecurityInformation::from_bits(
                    request.additional_information.get() & SecurityInformation::VALID,
                );
                let system = information.sacl() || information.scope() || information.backup();
                let dac = information.dacl() || information.attribute() || information.backup();
                let owner = information.owner()
                    || information.group()
                    || information.label()
                    || information.backup();
                if (system && !file.access.access_system_security())
                    || (dac && !file.access.write_dac())
                    || (owner && !file.access.write_owner())
                {
                    return Err(Status::ACCESS_DENIED);
                }
                let descriptor =
                    security::SecurityDescriptor::decode(data).map_err(Status::from)?;
                self.server
                    .backend
                    .set_security(&file.file, information, &descriptor, context)
                    .await?;
            }
            (InformationType::FILE, FileInformationClass::RENAME) => {
                if data.len() < FILE_RENAME_INFORMATION_MIN_SIZE {
                    return Err(Status::INFO_LENGTH_MISMATCH);
                }
                if !file.access.delete() {
                    return Err(Status::ACCESS_DENIED);
                }
                let (info, rest) = FileRenameInformation::read_from_prefix(data)
                    .map_err(|_| Status::INFO_LENGTH_MISMATCH)?;
                let length = info.file_name_length.get() as usize;
                if info.root_directory.get() != 0 || length == 0 || !length.is_multiple_of(2) {
                    return Err(Status::INVALID_PARAMETER);
                }
                let name = decode_name(rest.get(..length).ok_or(Status::INVALID_PARAMETER)?)?;
                if name.starts_with('\\') {
                    return Err(Status::INVALID_PARAMETER);
                }
                self.server
                    .backend
                    .rename(&file.file, &name, info.replace_if_exists != 0, context)
                    .await?;
            }
            (InformationType::FILE, FileInformationClass::BASIC) => {
                if !file.access.write_attributes() {
                    return Err(Status::ACCESS_DENIED);
                }
                let info = FileBasicInformation::read_from_prefix(data)
                    .map_err(|_| Status::INFO_LENGTH_MISMATCH)?
                    .0;
                self.server
                    .backend
                    .set_basic(
                        &file.file,
                        BasicInformation {
                            created: info.creation_time.get(),
                            accessed: info.last_access_time.get(),
                            written: info.last_write_time.get(),
                            changed: info.change_time.get(),
                            attributes: info.file_attributes.into_bits(),
                        },
                        context,
                    )
                    .await?;
            }
            (
                InformationType::FILE,
                FileInformationClass::ALLOCATION | FileInformationClass::END_OF_FILE,
            ) => {
                let length = if class == FileInformationClass::ALLOCATION {
                    FileAllocationInformation::read_from_prefix(data)
                        .map_err(|_| Status::INFO_LENGTH_MISMATCH)?
                        .0
                        .allocation_size
                        .get()
                } else {
                    FileEndOfFileInformation::read_from_prefix(data)
                        .map_err(|_| Status::INFO_LENGTH_MISMATCH)?
                        .0
                        .end_of_file
                        .get()
                };
                if !file.access.write_data() {
                    return Err(Status::ACCESS_DENIED);
                }
                let length = u64::try_from(length).map_err(|_| Status::INVALID_PARAMETER)?;
                if class == FileInformationClass::ALLOCATION {
                    self.server
                        .backend
                        .set_allocation_size(&file.file, length, context)
                        .await?;
                } else {
                    self.server
                        .backend
                        .set_len(&file.file, length, context)
                        .await?;
                }
            }
            (InformationType::FILE, FileInformationClass::MODE) => {
                let mode = FileModeInformation::read_from_prefix(data)
                    .map_err(|_| Status::INFO_LENGTH_MISMATCH)?
                    .0
                    .mode
                    .get();
                let flags = CreateOptions::from_bits(mode);
                if mode & !FILE_MODE_INFORMATION_SET_MASK != 0
                    || flags.synchronous_io_alert()
                    || flags.synchronous_io_nonalert()
                {
                    return Err(Status::INVALID_PARAMETER);
                }
                let applied = self
                    .server
                    .backend
                    .set_mode(&file.file, mode, context)
                    .await?;
                if applied & !FILE_MODE_INFORMATION_MASK != 0 {
                    return Err(Status::INTERNAL_ERROR);
                }
                file.mode.store(applied, Ordering::Relaxed);
            }
            (InformationType::FILE, FileInformationClass::DISPOSITION) if !data.is_empty() => {
                if !file.access.delete() {
                    return Err(Status::ACCESS_DENIED);
                }
                self.server
                    .backend
                    .set_delete_on_close(
                        &file.file,
                        FileDispositionInformation::read_from_prefix(data)
                            .map_err(|_| Status::INVALID_PARAMETER)?
                            .0
                            .delete_pending
                            != 0,
                        context,
                    )
                    .await?;
            }
            (InformationType::FILE, FileInformationClass::POSITION) => {
                let position = FilePositionInformation::read_from_prefix(data)
                    .map_err(|_| Status::INFO_LENGTH_MISMATCH)?
                    .0
                    .current_byte_offset
                    .get();
                if position < 0 {
                    return Err(Status::INVALID_PARAMETER);
                }
                if CreateOptions::from_bits(file.mode.load(Ordering::Relaxed))
                    .no_intermediate_buffering()
                {
                    let volume = self
                        .server
                        .backend
                        .filesystem_information(&file.file, context)
                        .await?;
                    if volume.bytes_per_sector == 0 {
                        return Err(Status::INTERNAL_ERROR);
                    }
                    if !(position as u64).is_multiple_of(u64::from(volume.bytes_per_sector)) {
                        return Err(Status::INVALID_PARAMETER);
                    }
                }
                file.position.store(position, Ordering::Relaxed);
            }
            _ => return Err(Status::NOT_SUPPORTED),
        }
        Ok(SetInfoResponse {
            structure_size: SetInfoResponse::STRUCTURE_SIZE.into(),
        }
        .as_bytes()
        .to_vec())
    }

    async fn query_directory(
        &self,
        packet: &[u8],
        tree: u32,
        context: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let request: QueryDirectoryRequest = read_body(packet)?;
        let pattern = decode_name(variable::<QueryDirectoryRequest>(
            packet,
            request.name_offset.get() as usize,
            request.name_length.get() as usize,
        )?)?;
        let file = self.file(request.file_id, tree, context)?;
        if !file.is_directory {
            return Err(Status::INVALID_PARAMETER);
        }
        if !file.access.read_data() {
            return Err(Status::ACCESS_DENIED);
        }
        let class = FileInformationClass(request.info_class);
        let fixed = match class {
            FileInformationClass::DIRECTORY => size_of::<FileDirectoryInformation>(),
            FileInformationClass::FULL_DIRECTORY => size_of::<FileFullDirectoryInformation>(),
            FileInformationClass::BOTH_DIRECTORY => size_of::<FileBothDirectoryInformation>(),
            FileInformationClass::NAMES => size_of::<FileNamesInformation>(),
            FileInformationClass::ID_BOTH_DIRECTORY => size_of::<FileIdBothDirectoryInformation>(),
            FileInformationClass::ID_FULL_DIRECTORY => size_of::<FileIdFullDirectoryInformation>(),
            FileInformationClass::ID_EXTD_DIRECTORY => size_of::<FileIdExtdDirectoryInformation>(),
            FileInformationClass::ID64_EXTD_DIRECTORY => {
                size_of::<FileId64ExtdDirectoryInformation>()
            }
            FileInformationClass::ID64_EXTD_BOTH_DIRECTORY => {
                size_of::<FileId64ExtdBothDirectoryInformation>()
            }
            FileInformationClass::ID_ALL_EXTD_DIRECTORY => {
                size_of::<FileIdAllExtdDirectoryInformation>()
            }
            FileInformationClass::ID_ALL_EXTD_BOTH_DIRECTORY => {
                size_of::<FileIdAllExtdBothDirectoryInformation>()
            }
            _ => return Err(Status::INVALID_INFO_CLASS),
        };
        let flags = request.flags;
        let first = file.directory.lock().is_none();
        let restart = first || flags.restart_scans() || flags.reopen();
        if restart {
            if pattern.encode_utf16().count() > MAX_SEARCH_PATTERN_LENGTH {
                return Err(Status::NAME_TOO_LONG);
            }
            if pattern
                .chars()
                .any(|character| character < ' ' || matches!(character, '\\' | '/' | ':' | '|'))
            {
                return Err(Status::OBJECT_NAME_INVALID);
            }
        }
        let maximum = (request.output_buffer_length.get() as usize).min(MAX_TRANSFER_SIZE);
        if maximum < fixed {
            return Err(Status::INFO_LENGTH_MISMATCH);
        }
        let mut entries = self.server.backend.list(&file.file, context).await?;
        entries.sort_unstable_by(|left, right| directory_key(left).cmp(&directory_key(right)));
        let mut directory = file.directory.lock();
        if restart {
            *directory = Some(DirectorySearch {
                pattern: if pattern.is_empty() {
                    "*".into()
                } else {
                    pattern
                },
                after: None,
                cursor: 0,
            });
        }
        let search = directory.as_mut().ok_or(Status::INVALID_PARAMETER)?;
        let mut out = Vec::new();
        let mut previous = None;
        for info in &entries {
            let (order, id, name) = directory_key(info);
            if search
                .after
                .as_ref()
                .is_some_and(|(after_order, after_id, after_name)| {
                    (order, id, name) <= (*after_order, *after_id, after_name.as_str())
                })
            {
                continue;
            }
            if !(name_matches(&info.name, &search.pattern)
                || info
                    .short_name
                    .as_ref()
                    .is_some_and(|name| name_matches(name, &search.pattern)))
            {
                search.after = Some((order, id, name.to_owned()));
                continue;
            }
            let name_length = info
                .name
                .encode_utf16()
                .count()
                .checked_mul(size_of::<U16>())
                .ok_or(Status::INTERNAL_ERROR)?;
            let entry_len = fixed
                .checked_add(name_length)
                .ok_or(Status::INTERNAL_ERROR)?;
            let start = align_up(out.len(), DIRECTORY_ALIGNMENT)?;
            let end = start.checked_add(entry_len).ok_or(Status::INTERNAL_ERROR)?;
            if end > maximum {
                if out.is_empty() {
                    // SMB2 3.3.4.4 requires an ERROR response, not partial directory data.
                    return Err(Status::BUFFER_OVERFLOW);
                }
                break;
            }
            let record = directory_record(class, info)?;
            if let Some(previous) = previous {
                let (header, _) = DirectoryEntryHeader::mut_from_prefix(&mut out[previous..])
                    .expect("encoded directory record");
                header.next_entry_offset = ((start - previous) as u32).into();
            }
            out.resize(start, 0);
            out.extend_from_slice(&record);
            previous = Some(start);
            search.after = Some((order, id, name.to_owned()));
            search.cursor = search.cursor.saturating_add(1);
            if flags.return_single_entry() {
                break;
            }
        }
        if out.is_empty() {
            return Err(if first {
                Status::NO_SUCH_FILE
            } else {
                Status::NO_MORE_FILES
            });
        }
        buffer_response(out, request.output_buffer_length.get())
    }
}

#[cfg(test)]
mod tests;
