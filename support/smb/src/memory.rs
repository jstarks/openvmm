// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A bounded writable in-memory filesystem for synthetic shares.

use crate::provider::{BasicInformation, FileSystem, Metadata, OpenOptions, RequestContext};
use crate::spec::{
    AccessMask, CreateAction, CreateDisposition, FileAttributes, NT_TICKS_PER_SECOND, ShareAccess,
    Status, TIME_RESTORE, TIME_SUPPRESS, TIME_UNCHANGED, UNIX_EPOCH_NT_TIME,
};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const MAX_COMPONENT_NAME_LENGTH: u32 = 255;

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
}

struct State {
    nodes: BTreeMap<u64, Node>,
    opens: BTreeMap<u64, Open>,
    next_id: u64,
    next_open: u64,
    bytes: usize,
    byte_limit: usize,
    object_limit: usize,
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
            bytes: 0,
            byte_limit,
            object_limit: object_limit.max(1),
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
                if let Some(node) = state.nodes.remove(&self.node) {
                    state.bytes -= node.data.len();
                }
            }
        }
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
                resize(&mut state, id, 0)?;
                let node = state.nodes.get_mut(&id).ok_or(Status::FILE_CLOSED)?;
                node.metadata.written = nt_time();
                node.metadata.changed = node.metadata.written;
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
        if !user_set_access_time {
            node.metadata.accessed = nt_time();
        }
        Ok(node.data[start..end].to_vec())
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
        if end > node.data.len() {
            resize(&mut state, file.node, end)?;
        }
        let node = state.nodes.get_mut(&file.node).ok_or(Status::FILE_CLOSED)?;
        node.data[offset..end].copy_from_slice(data);
        modified(&mut state, file)?;
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
        resize(
            &mut state,
            file.node,
            usize::try_from(length).map_err(|_| Status::DISK_FULL)?,
        )?;
        modified(&mut state, file)
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use test_with_tracing::test;

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
