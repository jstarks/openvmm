// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A bounded writable in-memory filesystem for synthetic shares.

use crate::provider::{
    BasicInformation, Change, FileSystem, Metadata, NotifyResult, OpenOptions, RequestContext,
};
use crate::spec::{
    AccessMask, CreateAction, CreateDisposition, FileAttributes, NT_TICKS_PER_SECOND, NotifyAction,
    NotifyFilter, ShareAccess, Status, TIME_RESTORE, TIME_SUPPRESS, TIME_UNCHANGED,
    UNIX_EPOCH_NT_TIME,
};
use async_trait::async_trait;
use event_listener::Event;
use futures::FutureExt;
use parking_lot::{Mutex, MutexGuard};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const MAX_COMPONENT_NAME_LENGTH: u32 = 255;
pub(crate) const NOTIFY_BUFFER_LIMIT: usize = 64 * 1024;
const NOTIFY_WAITER_LIMIT: usize = 32;
const NOTIFY_WATCH_LIMIT: usize = 1024;

/// A writable filesystem with a shared byte quota and object limit.
#[derive(Clone)]
pub struct MemoryFs(Arc<Mutex<State>>);

struct Node {
    metadata: Metadata,
    parent: u64,
    data: Vec<u8>,
    delete_committed: bool,
}

struct Open {
    node: u64,
    access: u32,
    sharing: u32,
    delete: bool,
    user_set_access_time: bool,
    user_set_write_time: bool,
    user_set_change_time: bool,
    watch: Option<Watch>,
}

struct Watch {
    filter: NotifyFilter,
    tree: bool,
    events: VecDeque<Change>,
    bytes: usize,
    overflow: bool,
    waiters: VecDeque<u64>,
}

struct State {
    nodes: BTreeMap<u64, Node>,
    opens: BTreeMap<u64, Open>,
    next_id: u64,
    next_open: u64,
    next_notify: u64,
    watches: usize,
    bytes: usize,
    byte_limit: usize,
    object_limit: usize,
    changed: Arc<Event>,
}

fn wake(state: MutexGuard<'_, State>) {
    let changed = state.changed.clone();
    drop(state);
    changed.notify(usize::MAX);
}

fn emit(state: &mut State, node: u64, action: NotifyAction, filter: NotifyFilter) {
    let Some(node) = state.nodes.get(&node) else {
        return;
    };
    if node.parent == node.metadata.id {
        return;
    }
    let mut name = node.metadata.name.clone();
    let mut parent = node.parent;
    let mut depth = 0;
    loop {
        for open in state.opens.values_mut().filter(|open| open.node == parent) {
            let Some(watch) = &mut open.watch else {
                continue;
            };
            if watch.overflow
                || (!watch.tree && depth != 0)
                || watch.filter.into_bits() & filter.into_bits() == 0
            {
                continue;
            }
            let change = Change {
                action,
                name: name.clone(),
            };
            let bytes = change.encoded_len();
            if watch.bytes + bytes > NOTIFY_BUFFER_LIMIT {
                watch.events.clear();
                watch.bytes = 0;
                watch.overflow = true;
            } else {
                watch.bytes += bytes;
                watch.events.push_back(change);
            }
        }
        let Some(node) = state.nodes.get(&parent) else {
            break;
        };
        if node.parent == parent {
            break;
        }
        name = format!("{}\\{name}", node.metadata.name);
        parent = node.parent;
        depth += 1;
    }
}

fn name_filter(directory: bool) -> NotifyFilter {
    NotifyFilter::new()
        .with_dir_name(directory)
        .with_file_name(!directory)
}

struct NotifyWaiter {
    state: Arc<Mutex<State>>,
    open: u64,
    id: u64,
}

impl Drop for NotifyWaiter {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        if let Some(watch) = state
            .opens
            .get_mut(&self.open)
            .and_then(|open| open.watch.as_mut())
        {
            watch.waiters.retain(|id| *id != self.id);
        }
        wake(state);
    }
}

/// An open object whose lifetime reserves sharing rights in the provider.
pub struct MemoryFile {
    state: Arc<Mutex<State>>,
    node: u64,
    open: u64,
}

/// Current time in the Windows NT epoch.
pub(crate) fn nt_time() -> u64 {
    const NANOSECONDS_PER_NT_TICK: u128 = 1_000_000_000 / NT_TICKS_PER_SECOND as u128;
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => UNIX_EPOCH_NT_TIME + (elapsed.as_nanos() / NANOSECONDS_PER_NT_TICK) as u64,
        Err(before_epoch) => {
            UNIX_EPOCH_NT_TIME
                - (before_epoch.duration().as_nanos() / NANOSECONDS_PER_NT_TICK) as u64
        }
    }
}

impl MemoryFs {
    /// Create an empty share. The root counts toward `object_limit`.
    pub fn new(byte_limit: usize, object_limit: usize) -> Self {
        let now = nt_time();
        let root = Node {
            metadata: Metadata {
                id: 1,
                name: String::new(),
                short_name: None,
                attributes: FileAttributes::new().with_directory(true).into_bits(),
                created: now,
                accessed: now,
                written: now,
                changed: now,
                size: 0,
                delete_pending: false,
                maximal_access: AccessMask::FILE_ALL_ACCESS.into_bits(),
            },
            parent: 1,
            data: Vec::new(),
            delete_committed: false,
        };
        Self(Arc::new(Mutex::new(State {
            nodes: BTreeMap::from([(1, root)]),
            opens: BTreeMap::new(),
            next_id: 2,
            next_open: 1,
            next_notify: 1,
            watches: 0,
            bytes: 0,
            byte_limit,
            object_limit: object_limit.max(1),
            changed: Arc::new(Event::new()),
        })))
    }
}

fn components(name: &str) -> Result<Vec<&str>, Status> {
    if name.starts_with('\\') {
        return Err(Status::OBJECT_PATH_SYNTAX_BAD);
    }
    if name.starts_with('/') || name.contains(['/', ':']) {
        return Err(Status::OBJECT_NAME_INVALID);
    }
    let parts: Vec<_> = name.split('\\').filter(|s| !s.is_empty()).collect();
    if parts.iter().any(|s| *s == "." || *s == "..") {
        return Err(Status::OBJECT_PATH_SYNTAX_BAD);
    }
    if parts.iter().any(|s| s.contains('\0')) {
        return Err(Status::OBJECT_NAME_INVALID);
    }
    if parts
        .iter()
        .any(|name| name.encode_utf16().count() > MAX_COMPONENT_NAME_LENGTH as usize)
    {
        return Err(Status::NAME_TOO_LONG);
    }
    Ok(parts)
}

fn child(state: &State, parent: u64, name: &str) -> Option<u64> {
    state.nodes.iter().find_map(|(&id, node)| {
        (id != 1 && node.parent == parent && node.metadata.name.eq_ignore_ascii_case(name))
            .then_some(id)
    })
}

fn share_categories(access: u32) -> u32 {
    let access = AccessMask::from_bits(access);
    ShareAccess::new()
        .with_read(access.read_data() || access.execute())
        .with_write(access.write_data() || access.append_data())
        .with_delete(access.delete())
        .into_bits()
}

fn resize(state: &mut State, node_id: u64, length: usize) -> Result<(), Status> {
    let node = state.nodes.get_mut(&node_id).ok_or(Status::FILE_CLOSED)?;
    let old_len = node.data.len();
    let new_bytes = state
        .bytes
        .checked_sub(old_len)
        .and_then(|n| n.checked_add(length))
        .ok_or(Status::DISK_FULL)?;
    if new_bytes > state.byte_limit {
        return Err(Status::DISK_FULL);
    }
    if length > old_len {
        node.data
            .try_reserve_exact(length - old_len)
            .map_err(|_| Status::INSUFFICIENT_RESOURCES)?;
    }
    node.data.resize(length, 0);
    if length < old_len {
        node.data.shrink_to_fit();
    }
    node.metadata.size = length as u64;
    state.bytes = new_bytes;
    Ok(())
}

fn modified(state: &mut State, file: &MemoryFile) -> Result<(), Status> {
    let open = state.opens.get(&file.open).ok_or(Status::FILE_CLOSED)?;
    let node = state.nodes.get_mut(&file.node).ok_or(Status::FILE_CLOSED)?;
    let now = nt_time();
    if !open.user_set_write_time {
        node.metadata.written = now;
    }
    if !open.user_set_change_time {
        node.metadata.changed = now;
    }
    Ok(())
}

impl Drop for MemoryFile {
    fn drop(&mut self) {
        self.close();
    }
}

impl MemoryFile {
    fn close(&self) {
        let mut state = self.state.lock();
        let Some(open) = state.opens.remove(&self.open) else {
            return;
        };
        if open.watch.is_some() {
            state.watches -= 1;
        }
        if let Some(node) = state.nodes.get_mut(&self.node) {
            node.delete_committed |= open.delete;
        }
        let committed = state
            .nodes
            .get(&self.node)
            .is_some_and(|n| n.delete_committed);
        if committed {
            if !state.opens.values().any(|o| o.node == self.node)
                && !state
                    .nodes
                    .values()
                    .any(|n| n.parent == self.node && n.metadata.id != self.node)
            {
                let directory = state
                    .nodes
                    .get(&self.node)
                    .is_some_and(|node| node.metadata.is_directory());
                emit(
                    &mut state,
                    self.node,
                    NotifyAction::REMOVED,
                    name_filter(directory),
                );
                if let Some(node) = state.nodes.remove(&self.node) {
                    state.bytes -= node.data.len();
                }
            }
        }
        wake(state);
    }
}

impl inspect::Inspect for MemoryFs {
    fn inspect(&self, req: inspect::Request<'_>) {
        let state = self.0.lock();
        req.respond()
            .field("objects", state.nodes.len())
            .field("opens", state.opens.len())
            .field("bytes", state.bytes)
            .field("byte_limit", state.byte_limit)
            .field("object_limit", state.object_limit)
            .field("watch_count", state.watches)
            .field("watch_limit", NOTIFY_WATCH_LIMIT)
            .field(
                "notify_waiters",
                state
                    .opens
                    .values()
                    .filter_map(|open| open.watch.as_ref())
                    .map(|watch| watch.waiters.len())
                    .sum::<usize>(),
            )
            .field("notify_buffer_limit", NOTIFY_BUFFER_LIMIT)
            .child("watches", |req| {
                let mut resp = req.respond();
                for (id, open) in &state.opens {
                    if let Some(watch) = &open.watch {
                        resp.child(&id.to_string(), |req| {
                            req.respond()
                                .field("node", open.node)
                                .hex("filter", watch.filter.into_bits())
                                .field("tree", watch.tree)
                                .field("queued_events", watch.events.len())
                                .field("queued_bytes", watch.bytes)
                                .field("overflow", watch.overflow)
                                .field("waiters", watch.waiters.len());
                        });
                    }
                }
            })
            .child("nodes", |req| {
                let mut resp = req.respond();
                for (id, node) in &state.nodes {
                    resp.child(&id.to_string(), |req| {
                        req.respond()
                            .field("name", &node.metadata.name)
                            .field("parent", node.parent)
                            .field("size", node.data.len())
                            .hex("attributes", node.metadata.attributes)
                            .field("delete_pending", node.metadata.delete_pending);
                    });
                }
            });
    }
}

#[async_trait]
impl FileSystem for MemoryFs {
    type File = MemoryFile;

    async fn open(
        &self,
        name: &str,
        options: OpenOptions,
        _request: &RequestContext,
    ) -> Result<(MemoryFile, u32), Status> {
        let parts = components(name)?;
        let mut state = self.0.lock();
        let mut parent = 1;
        for part in &parts[..parts.len().saturating_sub(1)] {
            parent = child(&state, parent, part).ok_or(Status::OBJECT_PATH_NOT_FOUND)?;
            if !state.nodes[&parent].metadata.is_directory() {
                return Err(Status::NOT_A_DIRECTORY);
            }
            if state.nodes[&parent].metadata.delete_pending {
                return Err(Status::DELETE_PENDING);
            }
        }
        let existing = match parts.last() {
            Some(name) => child(&state, parent, name),
            None => Some(1),
        };
        let next_open = state
            .next_open
            .checked_add(1)
            .ok_or(Status::INSUFFICIENT_RESOURCES)?;
        let delete = options.options().delete_on_close();
        if delete && !options.access().delete() {
            return Err(Status::ACCESS_DENIED);
        }
        let (id, action) = if let Some(id) = existing {
            let node = &state.nodes[&id];
            if node.metadata.delete_pending {
                return Err(Status::DELETE_PENDING);
            }
            if options.disposition() == CreateDisposition::CREATE {
                return Err(Status::OBJECT_NAME_COLLISION);
            }
            if options.options().directory_file() && !node.metadata.is_directory() {
                return Err(Status::NOT_A_DIRECTORY);
            }
            if options.options().non_directory_file() && node.metadata.is_directory() {
                return Err(Status::FILE_IS_A_DIRECTORY);
            }
            if node.metadata.attributes().readonly()
                && (options.access().write_data() || options.access().append_data() || delete)
            {
                return Err(Status::ACCESS_DENIED);
            }
            for other in state.opens.values().filter(|o| o.node == id) {
                if share_categories(options.access) & !other.sharing != 0
                    || share_categories(other.access) & !options.share_access != 0
                {
                    return Err(Status::SHARING_VIOLATION);
                }
            }
            if matches!(
                options.disposition(),
                CreateDisposition::SUPERSEDE
                    | CreateDisposition::OVERWRITE
                    | CreateDisposition::OVERWRITE_IF
            ) {
                if node.metadata.is_directory() {
                    return Err(Status::FILE_IS_A_DIRECTORY);
                }
                let permitted = if options.disposition() == CreateDisposition::SUPERSEDE {
                    options.access().delete()
                } else {
                    options.access().write_data()
                };
                if !permitted {
                    return Err(Status::ACCESS_DENIED);
                }
                let size_changed = node.metadata.size != 0;
                resize(&mut state, id, 0)?;
                let node = state.nodes.get_mut(&id).ok_or(Status::FILE_CLOSED)?;
                node.metadata.written = nt_time();
                node.metadata.changed = node.metadata.written;
                emit(
                    &mut state,
                    id,
                    NotifyAction::MODIFIED,
                    NotifyFilter::new()
                        .with_size(size_changed)
                        .with_last_write(true),
                );
                (
                    id,
                    if options.disposition() == CreateDisposition::SUPERSEDE {
                        CreateAction::SUPERSEDED.0
                    } else {
                        CreateAction::OVERWRITTEN.0
                    },
                )
            } else {
                (id, CreateAction::OPENED.0)
            }
        } else {
            if matches!(
                options.disposition(),
                CreateDisposition::OPEN | CreateDisposition::OVERWRITE
            ) {
                return Err(Status::OBJECT_NAME_NOT_FOUND);
            }
            if state.nodes.len() >= state.object_limit {
                return Err(Status::DISK_FULL);
            }
            let id = state.next_id;
            state.next_id = id.checked_add(1).ok_or(Status::INSUFFICIENT_RESOURCES)?;
            let now = nt_time();
            let directory = options.options().directory_file();
            state.nodes.insert(
                id,
                Node {
                    metadata: Metadata {
                        id,
                        name: parts.last().ok_or(Status::OBJECT_NAME_INVALID)?.to_string(),
                        short_name: None,
                        attributes: if directory {
                            FileAttributes::new().with_directory(true).into_bits()
                        } else {
                            options
                                .attributes()
                                .with_directory(false)
                                .with_normal(false)
                                .with_archive(true)
                                .into_bits()
                        },
                        created: now,
                        accessed: now,
                        written: now,
                        changed: now,
                        size: 0,
                        delete_pending: false,
                        maximal_access: AccessMask::FILE_ALL_ACCESS.into_bits(),
                    },
                    parent,
                    data: Vec::new(),
                    delete_committed: false,
                },
            );
            emit(&mut state, id, NotifyAction::ADDED, name_filter(directory));
            (id, CreateAction::CREATED.0)
        };
        if delete
            && (id == 1
                || state
                    .nodes
                    .values()
                    .any(|n| n.parent == id && n.metadata.id != id))
        {
            return Err(Status::DIRECTORY_NOT_EMPTY);
        }
        let open = state.next_open;
        state.next_open = next_open;
        state.opens.insert(
            open,
            Open {
                node: id,
                access: options.access,
                sharing: options.share_access,
                delete,
                user_set_access_time: false,
                user_set_write_time: false,
                user_set_change_time: false,
                watch: None,
            },
        );
        if delete {
            state
                .nodes
                .get_mut(&id)
                .ok_or(Status::FILE_CLOSED)?
                .metadata
                .delete_pending = true;
        }
        wake(state);
        Ok((
            MemoryFile {
                state: self.0.clone(),
                node: id,
                open,
            },
            action,
        ))
    }

    async fn close(&self, file: &MemoryFile, _request: &RequestContext) -> Result<(), Status> {
        file.close();
        Ok(())
    }

    async fn metadata(
        &self,
        file: &MemoryFile,
        _request: &RequestContext,
    ) -> Result<Metadata, Status> {
        self.0
            .lock()
            .nodes
            .get(&file.node)
            .map(|n| n.metadata.clone())
            .ok_or(Status::FILE_CLOSED)
    }

    async fn read(
        &self,
        file: &MemoryFile,
        offset: u64,
        length: usize,
        _request: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let mut state = self.0.lock();
        let user_set_access_time = state
            .opens
            .get(&file.open)
            .ok_or(Status::FILE_CLOSED)?
            .user_set_access_time;
        let node = state.nodes.get_mut(&file.node).ok_or(Status::FILE_CLOSED)?;
        if node.metadata.is_directory() {
            return Err(Status::INVALID_DEVICE_REQUEST);
        }
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(node.data.len());
        let end = start.saturating_add(length).min(node.data.len());
        let old_accessed = node.metadata.accessed;
        if !user_set_access_time {
            node.metadata.accessed = nt_time();
        }
        let data = node.data[start..end].to_vec();
        let changed = node.metadata.accessed != old_accessed;
        if changed {
            emit(
                &mut state,
                file.node,
                NotifyAction::MODIFIED,
                NotifyFilter::new().with_last_access(true),
            );
        }
        wake(state);
        Ok(data)
    }

    async fn write(
        &self,
        file: &MemoryFile,
        offset: u64,
        data: &[u8],
        _request: &RequestContext,
    ) -> Result<usize, Status> {
        let mut state = self.0.lock();
        state.opens.get(&file.open).ok_or(Status::FILE_CLOSED)?;
        let node = state.nodes.get(&file.node).ok_or(Status::FILE_CLOSED)?;
        if node.metadata.is_directory() {
            return Err(Status::INVALID_DEVICE_REQUEST);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let offset = usize::try_from(offset).map_err(|_| Status::DISK_FULL)?;
        let end = offset.checked_add(data.len()).ok_or(Status::DISK_FULL)?;
        let size_changed = end > node.data.len();
        if size_changed {
            resize(&mut state, file.node, end)?;
        }
        let node = state.nodes.get_mut(&file.node).ok_or(Status::FILE_CLOSED)?;
        node.data[offset..end].copy_from_slice(data);
        modified(&mut state, file)?;
        let open = &state.opens[&file.open];
        let filter = NotifyFilter::new()
            .with_size(size_changed)
            .with_last_write(!open.user_set_write_time);
        emit(&mut state, file.node, NotifyAction::MODIFIED, filter);
        wake(state);
        Ok(data.len())
    }

    async fn list(
        &self,
        file: &MemoryFile,
        _request: &RequestContext,
    ) -> Result<Vec<Metadata>, Status> {
        let state = self.0.lock();
        if !state
            .nodes
            .get(&file.node)
            .ok_or(Status::FILE_CLOSED)?
            .metadata
            .is_directory()
        {
            return Err(Status::NOT_A_DIRECTORY);
        }
        let node = state.nodes.get(&file.node).ok_or(Status::FILE_CLOSED)?;
        let mut current = node.metadata.clone();
        current.name = ".".to_owned();
        let mut parent = state
            .nodes
            .get(&node.parent)
            .ok_or(Status::FILE_CLOSED)?
            .metadata
            .clone();
        parent.name = "..".to_owned();
        let mut entries = vec![current, parent];
        entries.extend(
            state
                .nodes
                .values()
                .filter(|n| n.parent == file.node && n.metadata.id != file.node)
                .map(|n| n.metadata.clone()),
        );
        Ok(entries)
    }

    async fn flush(&self, file: &MemoryFile, _request: &RequestContext) -> Result<(), Status> {
        self.0
            .lock()
            .nodes
            .get(&file.node)
            .ok_or(Status::FILE_CLOSED)?;
        Ok(())
    }

    async fn set_len(
        &self,
        file: &MemoryFile,
        length: u64,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        let mut state = self.0.lock();
        state.opens.get(&file.open).ok_or(Status::FILE_CLOSED)?;
        if state
            .nodes
            .get(&file.node)
            .ok_or(Status::FILE_CLOSED)?
            .metadata
            .is_directory()
        {
            return Err(Status::FILE_IS_A_DIRECTORY);
        }
        let size_changed = state.nodes[&file.node].metadata.size != length;
        resize(
            &mut state,
            file.node,
            usize::try_from(length).map_err(|_| Status::DISK_FULL)?,
        )?;
        modified(&mut state, file)?;
        let filter = NotifyFilter::new()
            .with_size(size_changed)
            .with_last_write(!state.opens[&file.open].user_set_write_time);
        emit(&mut state, file.node, NotifyAction::MODIFIED, filter);
        wake(state);
        Ok(())
    }

    async fn set_delete_on_close(
        &self,
        file: &MemoryFile,
        delete: bool,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        let mut state = self.0.lock();
        if delete
            && (file.node == 1
                || state
                    .nodes
                    .values()
                    .any(|n| n.parent == file.node && n.metadata.id != file.node))
        {
            return Err(Status::DIRECTORY_NOT_EMPTY);
        }
        state
            .opens
            .get_mut(&file.open)
            .ok_or(Status::FILE_CLOSED)?
            .delete = delete;
        let pending = state
            .opens
            .values()
            .any(|o| o.node == file.node && o.delete);
        let node = state.nodes.get_mut(&file.node).ok_or(Status::FILE_CLOSED)?;
        node.metadata.delete_pending = node.delete_committed || pending;
        Ok(())
    }

    async fn set_basic(
        &self,
        file: &MemoryFile,
        info: BasicInformation,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        if [info.created, info.accessed, info.written, info.changed]
            .iter()
            .any(|time| *time < TIME_RESTORE)
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let mut state = self.0.lock();
        let directory = state
            .nodes
            .get(&file.node)
            .ok_or(Status::FILE_CLOSED)?
            .metadata
            .is_directory();
        let attributes = FileAttributes::from_bits(info.attributes);
        if (attributes.directory() && !directory) || (attributes.temporary() && directory) {
            return Err(Status::INVALID_PARAMETER);
        }
        let open = state.opens.get_mut(&file.open).ok_or(Status::FILE_CLOSED)?;
        let old_change_time = open.user_set_change_time;
        for (time, flag) in [
            (info.accessed, &mut open.user_set_access_time),
            (info.written, &mut open.user_set_write_time),
            (info.changed, &mut open.user_set_change_time),
        ] {
            if time != TIME_UNCHANGED {
                *flag = time != TIME_RESTORE;
            }
        }
        let user_set_change_time = open.user_set_change_time;
        let node = state.nodes.get_mut(&file.node).ok_or(Status::FILE_CLOSED)?;
        let before = node.metadata.clone();
        let now = nt_time();
        if info.attributes != 0 {
            // MS-FSA §2.1.5.15.2 defines this update mask and protects root HIDDEN/SYSTEM.
            let mut valid = FileAttributes::new()
                .with_readonly(true)
                .with_hidden(true)
                .with_system(true)
                .with_archive(true)
                .with_temporary(true)
                .with_offline(true)
                .with_not_content_indexed(true);
            if file.node == 1 {
                valid = valid.with_hidden(false).with_system(false);
            }
            let valid = valid.into_bits();
            let attributes = (node.metadata.attributes().with_normal(false).into_bits() & !valid)
                | (info.attributes & valid);
            let attributes = if attributes == 0 {
                FileAttributes::new().with_normal(true).into_bits()
            } else {
                attributes
            };
            if attributes != node.metadata.attributes
                && !old_change_time
                && info.changed != TIME_SUPPRESS
            {
                node.metadata.changed = now;
            }
            node.metadata.attributes = attributes;
        }
        if info.changed > 0 {
            node.metadata.changed = info.changed as u64;
        }
        for (time, field) in [
            (info.created, &mut node.metadata.created),
            (info.accessed, &mut node.metadata.accessed),
            (info.written, &mut node.metadata.written),
        ] {
            if time > 0 {
                *field = time as u64;
                if !user_set_change_time && info.changed != TIME_SUPPRESS {
                    node.metadata.changed = now;
                }
            }
        }
        let filter = NotifyFilter::new()
            .with_attributes(node.metadata.attributes != before.attributes)
            .with_creation(node.metadata.created != before.created)
            .with_last_access(node.metadata.accessed != before.accessed)
            .with_last_write(node.metadata.written != before.written);
        emit(&mut state, file.node, NotifyAction::MODIFIED, filter);
        wake(state);
        Ok(())
    }

    async fn notify(
        &self,
        file: &MemoryFile,
        filter: NotifyFilter,
        tree: bool,
        output_length: usize,
        request: &RequestContext,
    ) -> Result<NotifyResult, Status> {
        let (changed, id) = {
            let mut state = self.0.lock();
            if !state
                .nodes
                .get(&file.node)
                .ok_or(Status::FILE_CLOSED)?
                .metadata
                .is_directory()
            {
                return Err(Status::INVALID_PARAMETER);
            }
            let id = state.next_notify;
            state.next_notify = id.checked_add(1).ok_or(Status::INSUFFICIENT_RESOURCES)?;
            let first = state
                .opens
                .get(&file.open)
                .ok_or(Status::FILE_CLOSED)?
                .watch
                .is_none();
            if first {
                if state.watches == NOTIFY_WATCH_LIMIT {
                    return Err(Status::INSUFFICIENT_RESOURCES);
                }
                state.watches += 1;
            }
            let open = state.opens.get_mut(&file.open).ok_or(Status::FILE_CLOSED)?;
            let watch = open.watch.get_or_insert_with(|| Watch {
                filter: NotifyFilter::from_bits(filter.into_bits() & NotifyFilter::VALID),
                tree,
                events: VecDeque::new(),
                bytes: 0,
                overflow: false,
                waiters: VecDeque::new(),
            });
            if watch.waiters.len() == NOTIFY_WAITER_LIMIT {
                return Err(Status::INSUFFICIENT_RESOURCES);
            }
            watch.waiters.push_back(id);
            (state.changed.clone(), id)
        };
        let _waiter = NotifyWaiter {
            state: self.0.clone(),
            open: file.open,
            id,
        };
        loop {
            let listener = changed.listen();
            if request.is_cancelled() {
                return Err(Status::CANCELLED);
            }
            {
                let mut state = self.0.lock();
                let watch = state
                    .opens
                    .get_mut(&file.open)
                    .ok_or(Status::FILE_CLOSED)?
                    .watch
                    .as_mut()
                    .expect("registered watch");
                if watch.waiters.front() == Some(&id) {
                    if watch.overflow {
                        watch.overflow = false;
                        return Ok(NotifyResult::Overflow);
                    }
                    if !watch.events.is_empty() {
                        if watch.bytes > output_length {
                            return Ok(NotifyResult::Overflow);
                        }
                        watch.bytes = 0;
                        return Ok(NotifyResult::Changes(watch.events.drain(..).collect()));
                    }
                }
            }
            let mut listener = std::pin::pin!(listener.fuse());
            let mut cancelled = std::pin::pin!(request.cancelled().fuse());
            futures::select! {
                () = listener => {}
                () = cancelled => return Err(Status::CANCELLED),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use test_with_tracing::test;

    #[test]
    fn persistent_watch_capacity_is_released_by_close() {
        block_on(async {
            let fs = MemoryFs::new(0, 1);
            let request = RequestContext::new(1);
            request.cancel();
            let options = OpenOptions {
                access: AccessMask::FILE_ALL_ACCESS.into_bits(),
                share_access: ShareAccess::ALL.into_bits(),
                disposition: CreateDisposition::OPEN.0,
                options: 0,
                attributes: 0,
            };
            let filter = NotifyFilter::new().with_file_name(true);
            let mut opens = Vec::new();
            for _ in 0..NOTIFY_WATCH_LIMIT {
                let (file, _) = fs.open("", options, &request).await.unwrap();
                assert!(matches!(
                    fs.notify(&file, filter, false, 32, &request).await,
                    Err(Status::CANCELLED)
                ));
                opens.push(file);
            }
            let (extra, _) = fs.open("", options, &request).await.unwrap();
            assert!(matches!(
                fs.notify(&extra, filter, false, 32, &request).await,
                Err(Status::INSUFFICIENT_RESOURCES)
            ));
            fs.close(&opens.pop().unwrap(), &request).await.unwrap();
            assert!(matches!(
                fs.notify(&extra, filter, false, 32, &request).await,
                Err(Status::CANCELLED)
            ));
            fs.close(&extra, &request).await.unwrap();
            drop(opens);
            assert_eq!(fs.0.lock().watches, 0);
        });
    }

    #[test]
    fn truncation_releases_backing_memory_before_quota_is_reused() {
        block_on(async {
            let fs = MemoryFs::new(64, 8);
            let request = RequestContext::new(1);
            let options = OpenOptions {
                access: AccessMask::FILE_ALL_ACCESS.into_bits(),
                share_access: ShareAccess::ALL.into_bits(),
                disposition: CreateDisposition::CREATE.0,
                options: 0,
                attributes: 0,
            };
            let (first, _) = fs.open("first", options, &request).await.unwrap();
            fs.write(&first, 0, &[1; 64], &request).await.unwrap();
            fs.set_len(&first, 8, &request).await.unwrap();
            let (second, _) = fs.open("second", options, &request).await.unwrap();
            fs.write(&second, 0, &[2; 56], &request).await.unwrap();
            let state = fs.0.lock();
            assert_eq!(state.bytes, 64);
            assert!(
                state
                    .nodes
                    .values()
                    .map(|n| n.data.capacity())
                    .sum::<usize>()
                    <= 64
            );
        });
    }
}
