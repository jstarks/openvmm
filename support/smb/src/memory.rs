// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A bounded writable in-memory filesystem for synthetic shares.

use crate::provider::{
    BasicInformation, ByteRange, Change, CompressionInformation, FileSystem, FileSystemInformation,
    LockId, Metadata, NotifyResult, OpenOptions, RequestContext,
};
use crate::security::{AccessAce, Acl, AclState, SecurityDescriptor, Sid};
use crate::spec::{
    AccessMask, AceFlags, CreateAction, CreateDisposition, CreateOptions, FILE_DEVICE_DISK,
    FILE_MODE_INFORMATION_MASK, FILE_MODE_INFORMATION_SET_MASK, FileAttributes,
    FileSystemAttributes, MAX_PATH_LENGTH, NT_TICKS_PER_SECOND, NotifyAction, NotifyFilter,
    SecurityDescriptorControl, SecurityInformation, ShareAccess, Status, TIME_RESTORE,
    TIME_SUPPRESS, TIME_UNCHANGED, UNIX_EPOCH_NT_TIME,
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
const LOCK_LIMIT: usize = 4096;
const LOCK_WAITER_LIMIT: usize = 1024;

/// A writable filesystem with a shared byte quota and object limit.
#[derive(Clone)]
pub struct MemoryFs(Arc<Mutex<State>>);

struct Node {
    metadata: Metadata,
    security: SecurityDescriptor,
    parent: u64,
    data: Vec<u8>,
}

struct Open {
    node: u64,
    access: u32,
    sharing: u32,
    delete_on_close: bool,
    mode: u32,
    user_set_access_time: bool,
    user_set_write_time: bool,
    user_set_change_time: bool,
    notify_deleted: bool,
    watch: Option<Watch>,
}

struct Watch {
    id: u64,
    filter: NotifyFilter,
    tree: bool,
    events: VecDeque<Change>,
    bytes: usize,
    overflow: bool,
    waiters: VecDeque<u64>,
}

struct State {
    created: u64,
    nodes: BTreeMap<u64, Node>,
    opens: BTreeMap<u64, Open>,
    next_id: u64,
    next_open: u64,
    next_notify: u64,
    next_lock: u64,
    watches: usize,
    locks: Vec<RangeLock>,
    lock_waiters: usize,
    bytes: usize,
    byte_limit: usize,
    object_limit: usize,
    changed: Arc<Event>,
}

struct RangeLock {
    id: LockId,
    node: u64,
    owner: u64,
    range: ByteRange,
    exclusive: bool,
}

fn conflicts(
    state: &State,
    file: &MemoryFile,
    range: ByteRange,
    exclusive: bool,
    locking: bool,
) -> bool {
    state.locks.iter().any(|lock| {
        lock.node == file.node
            && lock.range.overlaps(range)
            && if lock.exclusive {
                lock.owner != file.open || (exclusive && locking)
            } else {
                exclusive
            }
    })
}

struct LockWaiter(Arc<Mutex<State>>);

impl Drop for LockWaiter {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.lock_waiters -= 1;
        wake(state);
    }
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

fn delete_watches(state: &mut State, node: u64) {
    // MS-FSA §2.1.5.15.3 removes registrations and completes all their waiters.
    // A replacement registration must not absorb waiters from the old generation.
    for open in state.opens.values_mut().filter(|open| open.node == node) {
        if open.watch.take().is_some() {
            state.watches -= 1;
        }
    }
}

struct NotifyWaiter {
    state: Arc<Mutex<State>>,
    open: u64,
    id: u64,
    watch: u64,
}

impl Drop for NotifyWaiter {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        if let Some(watch) = state
            .opens
            .get_mut(&self.open)
            .and_then(|open| open.watch.as_mut())
            .filter(|watch| watch.id == self.watch)
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
                path: String::new(),
                short_name: None,
                attributes: FileAttributes::new().with_directory(true).into_bits(),
                reparse_tag: 0,
                created: now,
                accessed: now,
                written: now,
                changed: now,
                size: 0,
                allocation_size: 0,
                compression: Some(CompressionInformation::default()),
                number_of_links: 1,
                extended_attributes_length: 0,
                alignment_requirement: 0,
                delete_pending: false,
                maximal_access: AccessMask::FILE_ALL_ACCESS.into_bits(),
                granted_access: 0,
            },
            parent: 1,
            security: default_security(true),
            data: Vec::new(),
        };
        Self(Arc::new(Mutex::new(State {
            created: now,
            nodes: BTreeMap::from([(1, root)]),
            opens: BTreeMap::new(),
            next_id: 2,
            next_open: 1,
            next_notify: 1,
            next_lock: 1,
            watches: 0,
            locks: Vec::new(),
            lock_waiters: 0,
            bytes: 0,
            byte_limit,
            object_limit: object_limit.max(1),
            changed: Arc::new(Event::new()),
        })))
    }
}

fn components(name: &str) -> Result<Vec<&str>, Status> {
    if name.encode_utf16().count() > MAX_PATH_LENGTH {
        return Err(Status::NAME_TOO_LONG);
    }
    if name.starts_with('\\') {
        return Err(Status::OBJECT_PATH_SYNTAX_BAD);
    }
    if name.starts_with('/') || name.contains(['/', ':']) {
        return Err(Status::OBJECT_NAME_INVALID);
    }
    let parts: Vec<_> = name.split('\\').filter(|s| !s.is_empty()).collect();
    if parts.iter().any(|part| {
        part.chars().any(|character| {
            character < ' ' || matches!(character, '"' | '|' | '<' | '>' | '*' | '?')
        })
    }) {
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

fn node_metadata(state: &State, id: u64) -> Result<Metadata, Status> {
    let mut metadata = state
        .nodes
        .get(&id)
        .ok_or(Status::FILE_CLOSED)?
        .metadata
        .clone();
    let mut components = Vec::new();
    let mut current = id;
    loop {
        let node = state.nodes.get(&current).ok_or(Status::FILE_CLOSED)?;
        if node.parent == current {
            break;
        }
        components.push(node.metadata.name.as_str());
        current = node.parent;
    }
    components.reverse();
    metadata.path = format!("\\{}", components.join("\\"));
    metadata.number_of_links = u32::from(!metadata.delete_pending);
    if let Some(compression) = &mut metadata.compression {
        compression.compressed_size = metadata.allocation_size;
    }
    metadata.maximal_access = acl_access(&state.nodes[&id].security);
    Ok(metadata)
}

fn system_sid() -> Sid {
    Sid::new([0, 0, 0, 0, 0, 5], &[18]).expect("well-known SID")
}

fn owner_rights_sid() -> Sid {
    Sid::new([0, 0, 0, 0, 0, 3], &[4]).expect("well-known SID")
}

fn acl_access(security: &SecurityDescriptor) -> u32 {
    let all = AccessMask::FILE_ALL_ACCESS.into_bits();
    let mut granted = all;
    if let AclState::Present(acl) = &security.dacl {
        let owner = security.owner.as_ref() == Some(&system_sid());
        let owner_rights = owner_rights_sid();
        let implicit_owner = owner
            && !acl.entries().any(|ace| {
                ace.access()
                    .is_some_and(|ace| !ace.flags.inherit_only() && ace.sid == owner_rights)
            });
        let implicit = if implicit_owner {
            AccessMask::new()
                .with_read_control(true)
                .with_write_dac(true)
                .into_bits()
        } else {
            0
        };
        granted = implicit;
        let mut denied = 0;
        let world = Sid::new([0, 0, 0, 0, 0, 1], &[0]).expect("well-known SID");
        for ace in acl.entries() {
            // Stored MemoryFs DACLs contain only validated basic access ACEs.
            let ace = ace.access().expect("supported memory ACL");
            if ace.flags.inherit_only()
                || !(ace.sid == system_sid()
                    || ace.sid == world
                    || (owner && ace.sid == owner_rights))
            {
                continue;
            }
            let mask = crate::provider::map_access(ace.mask) & all;
            if ace.deny {
                // MS-FSA §2.1.5.1.2.1 checks each individual right even for
                // MAXIMUM_ALLOWED, preserving earlier allows for that right.
                denied |= mask & !granted;
            } else {
                granted |= mask & !denied;
            }
        }
        granted = implicit | (granted & !denied);
    }
    granted & all
}

fn allowed_access(state: &State, id: u64) -> u32 {
    let node = &state.nodes[&id];
    let mut granted = acl_access(&node.security);
    if node.parent != id {
        let parent = AccessMask::from_bits(acl_access(&state.nodes[&node.parent].security));
        granted |= AccessMask::new()
            .with_delete(parent.delete_child())
            .with_read_attributes(parent.read_data())
            .into_bits();
    }
    granted
}

fn can_add(state: &State, parent: u64, directory: bool) -> bool {
    let access = AccessMask::from_bits(acl_access(&state.nodes[&parent].security));
    if directory {
        access.append_data()
    } else {
        access.write_data()
    }
}

fn default_security(directory: bool) -> SecurityDescriptor {
    let system = system_sid();
    let world = Sid::new([0, 0, 0, 0, 0, 1], &[0]).expect("well-known SID");
    let dacl = Acl::access(&[AccessAce {
        deny: false,
        flags: AceFlags::new()
            .with_object_inherit(directory)
            .with_container_inherit(directory),
        mask: AccessMask::FILE_ALL_ACCESS.into_bits(),
        sid: world,
    }])
    .expect("one bounded default ACE");
    SecurityDescriptor {
        owner: Some(system.clone()),
        group: Some(system),
        dacl: AclState::Present(dacl),
        control: SecurityDescriptorControl::new()
            .with_self_relative(true)
            .with_dacl_present(true),
        ..SecurityDescriptor::empty()
    }
}

fn inherited_security(
    parent: &SecurityDescriptor,
    directory: bool,
    owner: &Sid,
    group: &Sid,
) -> Result<SecurityDescriptor, Status> {
    let mut descriptor = default_security(directory);
    descriptor.owner = Some(owner.clone());
    descriptor.group = Some(group.clone());
    let AclState::Present(acl) = &parent.dacl else {
        return Ok(descriptor);
    };
    let mut entries = Vec::new();
    let creator_owner = Sid::new([0, 0, 0, 0, 0, 3], &[0]).expect("well-known SID");
    let creator_group = Sid::new([0, 0, 0, 0, 0, 3], &[1]).expect("well-known SID");
    for ace in acl.entries() {
        let ace = ace.access().expect("supported memory ACL");
        let effective = if directory {
            ace.flags.container_inherit()
        } else {
            ace.flags.object_inherit()
        };
        let propagate = directory
            && !ace.flags.no_propagate_inherit()
            && (ace.flags.object_inherit() || ace.flags.container_inherit());
        let mut mapped = ace.clone();
        mapped.mask = crate::provider::map_access(ace.mask);
        if ace.sid == creator_owner {
            mapped.sid = owner.clone();
        } else if ace.sid == creator_group {
            mapped.sid = group.clone();
        }
        // Effective ACEs specialize generic information; container templates
        // retain it for the next generation.
        if effective && propagate && mapped.mask == ace.mask && mapped.sid == ace.sid {
            mapped.flags = ace.flags.with_inherit_only(false).with_inherited(true);
            entries.push(mapped);
        } else {
            if effective {
                mapped.flags = AceFlags::new().with_inherited(true);
                entries.push(mapped);
            }
            if propagate {
                let mut template = ace;
                template.flags = template.flags.with_inherit_only(true).with_inherited(true);
                entries.push(template);
            }
        }
    }
    if !entries.is_empty() {
        descriptor.dacl =
            AclState::Present(Acl::access(&entries).map_err(|_| Status::INSUFFICIENT_RESOURCES)?);
        descriptor.control.set_dacl_auto_inherited(true);
    }
    Ok(descriptor)
}

fn validate_security(
    descriptor: &SecurityDescriptor,
    information: SecurityInformation,
) -> Result<(), Status> {
    let supported = SecurityInformation::new()
        .with_owner(true)
        .with_group(true)
        .with_dacl(true)
        .into_bits();
    if information.into_bits() & !supported != 0
        || descriptor.control.server_security()
        || descriptor.control.dacl_trusted()
        || descriptor.control.dacl_auto_inherit_required()
    {
        return Err(Status::NOT_SUPPORTED);
    }
    if information.owner() && descriptor.owner.as_ref() != Some(&system_sid()) {
        return Err(Status::INVALID_OWNER);
    }
    if information.group() && descriptor.group.is_none() {
        return Err(Status::INVALID_PRIMARY_GROUP);
    }
    if information.dacl() {
        if let AclState::Present(acl) = &descriptor.dacl {
            for ace in acl.entries() {
                let ace = ace.access().ok_or(Status::NOT_SUPPORTED)?;
                if ace.flags.into_bits() & 0xe0 != 0
                    || crate::provider::map_access(ace.mask)
                        & !AccessMask::FILE_ALL_ACCESS.into_bits()
                        != 0
                {
                    return Err(Status::NOT_SUPPORTED);
                }
            }
        }
    }
    Ok(())
}

fn creation_security(
    parent: &SecurityDescriptor,
    directory: bool,
    bytes: &[u8],
) -> Result<SecurityDescriptor, Status> {
    let mut descriptor = SecurityDescriptor::decode(bytes).map_err(Status::from)?;
    descriptor.owner.get_or_insert_with(system_sid);
    descriptor.group.get_or_insert_with(system_sid);
    validate_security(
        &descriptor,
        SecurityInformation::new()
            .with_owner(true)
            .with_group(true)
            .with_dacl(true),
    )?;
    if descriptor.sacl != AclState::Absent {
        return Err(Status::NOT_SUPPORTED);
    }
    let owner = descriptor.owner.as_ref().expect("owner was defaulted");
    let group = descriptor.group.as_ref().expect("group was defaulted");
    let inherited = inherited_security(parent, directory, owner, group)?;
    let protected = descriptor.control.dacl_protected();
    if descriptor.dacl == AclState::Absent {
        if protected {
            descriptor.dacl = default_security(directory).dacl;
        } else {
            descriptor.dacl = inherited.dacl;
            descriptor
                .control
                .set_dacl_auto_inherited(inherited.control.dacl_auto_inherited());
        }
        return Ok(descriptor);
    }
    let mut entries = Vec::new();
    let creator_owner = Sid::new([0, 0, 0, 0, 0, 3], &[0]).expect("well-known SID");
    let creator_group = Sid::new([0, 0, 0, 0, 0, 3], &[1]).expect("well-known SID");
    if let AclState::Present(acl) = &descriptor.dacl {
        for ace in acl.entries() {
            let mut ace = ace.access().expect("creation policy was validated");
            if ace.flags.inherited() && !protected {
                continue;
            }
            ace.flags.set_inherited(false);
            let mut mapped = ace.clone();
            if !ace.flags.inherit_only() {
                mapped.mask = crate::provider::map_access(ace.mask);
                if ace.sid == creator_owner {
                    mapped.sid = owner.clone();
                } else if ace.sid == creator_group {
                    mapped.sid = group.clone();
                }
            }
            if directory
                && !ace.flags.inherit_only()
                && (ace.flags.object_inherit() || ace.flags.container_inherit())
                && (mapped.mask != ace.mask || mapped.sid != ace.sid)
            {
                mapped.flags = AceFlags::new();
                entries.push(mapped);
                ace.flags.set_inherit_only(true);
                entries.push(ace);
            } else {
                entries.push(mapped);
            }
        }
    }
    if !protected && inherited.control.dacl_auto_inherited() {
        if let AclState::Present(acl) = inherited.dacl {
            entries.extend(
                acl.entries()
                    .map(|ace| ace.access().expect("supported inherited ACL")),
            );
        }
        descriptor.control.set_dacl_auto_inherited(true);
    }
    if !entries.is_empty() || matches!(descriptor.dacl, AclState::Present(_)) {
        descriptor.dacl =
            AclState::Present(Acl::access(&entries).map_err(|_| Status::INSUFFICIENT_RESOURCES)?);
    }
    Ok(descriptor)
}

fn grant_access(available: u32, requested: u32, delete: bool) -> Result<u32, Status> {
    let mask = AccessMask::from_bits(requested);
    let requested = mask.with_maximum_allowed(false).into_bits();
    if requested & !available != 0 {
        return Err(Status::ACCESS_DENIED);
    }
    let granted = if mask.maximum_allowed() {
        available
    } else {
        requested
    };
    if delete && !AccessMask::from_bits(granted).delete() {
        return Err(Status::ACCESS_DENIED);
    }
    Ok(granted)
}

fn has_children(state: &State, node: u64) -> bool {
    // Pending links remain directory entries until their last open closes.
    state
        .nodes
        .values()
        .any(|child| child.parent == node && child.metadata.id != node)
}

fn resolve_directory(state: &State, parts: &[&str]) -> Result<u64, Status> {
    let mut parent = 1;
    for part in parts {
        if !AccessMask::from_bits(acl_access(&state.nodes[&parent].security)).execute() {
            return Err(Status::ACCESS_DENIED);
        }
        parent = match *part {
            "." => parent,
            ".." => state.nodes[&parent].parent,
            _ => child(state, parent, part).ok_or(Status::OBJECT_PATH_NOT_FOUND)?,
        };
        if !state.nodes[&parent].metadata.is_directory() {
            return Err(Status::NOT_A_DIRECTORY);
        }
        if state.nodes[&parent].metadata.delete_pending {
            return Err(Status::DELETE_PENDING);
        }
    }
    if state.nodes[&parent].metadata.delete_pending {
        return Err(Status::DELETE_PENDING);
    }
    Ok(parent)
}

fn beneath(state: &State, mut node: u64, ancestor: u64) -> bool {
    loop {
        if node == ancestor {
            return true;
        }
        let parent = state.nodes[&node].parent;
        if parent == node {
            return false;
        }
        node = parent;
    }
}

fn share_categories(access: u32) -> u32 {
    let access = AccessMask::from_bits(access);
    ShareAccess::new()
        .with_read(access.read_data() || access.execute())
        .with_write(access.write_data() || access.append_data())
        .with_delete(access.delete())
        .into_bits()
}

fn sharing_conflict(access: u32, sharing: u32, other: &Open) -> bool {
    let access = share_categories(access);
    let other_access = share_categories(other.access);
    access != 0
        && other_access != 0
        && (access & !other.sharing != 0 || other_access & !sharing != 0)
}

fn settable_attributes() -> FileAttributes {
    FileAttributes::new()
        .with_readonly(true)
        .with_hidden(true)
        .with_system(true)
        .with_archive(true)
        .with_temporary(true)
        .with_offline(true)
        .with_not_content_indexed(true)
}

fn allocation_charge(state: &State, old_len: usize, length: usize) -> Result<usize, Status> {
    let new_bytes = state
        .bytes
        .checked_sub(old_len)
        .and_then(|n| n.checked_add(length))
        .ok_or(Status::DISK_FULL)?;
    if new_bytes > state.byte_limit {
        return Err(Status::DISK_FULL);
    }
    Ok(new_bytes)
}

fn allocate(state: &mut State, node_id: u64, length: usize) -> Result<(), Status> {
    let old_len = state
        .nodes
        .get(&node_id)
        .ok_or(Status::FILE_CLOSED)?
        .data
        .len();
    let new_bytes = allocation_charge(state, old_len, length)?;
    let node = state.nodes.get_mut(&node_id).ok_or(Status::FILE_CLOSED)?;
    if length > old_len {
        node.data
            .try_reserve_exact(length - old_len)
            .map_err(|_| Status::INSUFFICIENT_RESOURCES)?;
    }
    node.data.resize(length, 0);
    if length < old_len {
        node.data.shrink_to_fit();
    }
    node.metadata.size = node.metadata.size.min(length as u64);
    node.metadata.allocation_size = length as u64;
    state.bytes = new_bytes;
    Ok(())
}

fn resize(state: &mut State, node_id: u64, length: usize) -> Result<(), Status> {
    let node = state.nodes.get(&node_id).ok_or(Status::FILE_CLOSED)?;
    let allocation = if length as u64 >= node.metadata.size {
        node.data.len().max(length)
    } else {
        length
    };
    allocate(state, node_id, allocation)?;
    state
        .nodes
        .get_mut(&node_id)
        .ok_or(Status::FILE_CLOSED)?
        .metadata
        .size = length as u64;
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
        state.locks.retain(|lock| lock.owner != self.open);
        let directory = state.nodes[&self.node].metadata.is_directory();
        let empty = !directory || !has_children(&state, self.node);
        // MS-FSA §2.1.5.5 phase 1 applies CREATE's mode at close. A nonempty
        // directory is left intact; SET_INFO disposition is separate link state.
        if open.delete_on_close && (!directory || empty) {
            state
                .nodes
                .get_mut(&self.node)
                .expect("open's node exists")
                .metadata
                .delete_pending = true;
            if directory {
                delete_watches(&mut state, self.node);
            }
        }
        if state.nodes[&self.node].metadata.delete_pending
            && !state.opens.values().any(|o| o.node == self.node)
            && empty
        {
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
        wake(state);
    }
}

impl inspect::Inspect for MemoryFs {
    fn inspect(&self, req: inspect::Request<'_>) {
        let state = self.0.lock();
        req.respond()
            .field("objects", state.nodes.len())
            .field("opens", state.opens.len())
            .field(
                "delete_on_close_opens",
                state
                    .opens
                    .values()
                    .filter(|open| open.delete_on_close)
                    .count(),
            )
            .field("bytes", state.bytes)
            .field("byte_limit", state.byte_limit)
            .field("object_limit", state.object_limit)
            .field("watch_count", state.watches)
            .field("watch_limit", NOTIFY_WATCH_LIMIT)
            .field(
                "notify_deleted_opens",
                state
                    .opens
                    .values()
                    .filter(|open| open.notify_deleted)
                    .count(),
            )
            .field("lock_count", state.locks.len())
            .field("lock_limit", LOCK_LIMIT)
            .field("lock_waiters", state.lock_waiters)
            .field("lock_waiter_limit", LOCK_WAITER_LIMIT)
            .child("locks", |req| {
                let mut resp = req.respond();
                for (id, lock) in state.locks.iter().enumerate() {
                    resp.child(&id.to_string(), |req| {
                        req.respond()
                            .field("node", lock.node)
                            .field("owner", lock.owner)
                            .field("offset", lock.range.offset)
                            .field("length", lock.range.length)
                            .field("exclusive", lock.exclusive);
                    });
                }
            })
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
                                .field("registration", watch.id)
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
                            .field("size", node.metadata.size)
                            .field("allocation_size", node.metadata.allocation_size)
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
        options: OpenOptions<'_>,
        _request: &RequestContext,
    ) -> Result<(MemoryFile, u32), Status> {
        let mut options = options;
        let parts = components(name)?;
        if matches!(parts.last().copied(), Some("." | ".."))
            && !matches!(
                options.disposition(),
                CreateDisposition::OPEN | CreateDisposition::OPEN_IF
            )
        {
            return Err(Status::OBJECT_PATH_SYNTAX_BAD);
        }
        let mut state = self.0.lock();
        let parent = resolve_directory(&state, &parts[..parts.len().saturating_sub(1)])?;
        if !parts.is_empty()
            && !AccessMask::from_bits(acl_access(&state.nodes[&parent].security)).execute()
        {
            return Err(Status::ACCESS_DENIED);
        }
        let existing = match parts.last().copied() {
            Some(".") => Some(parent),
            Some("..") => Some(state.nodes[&parent].parent),
            Some(name) => child(&state, parent, name),
            None => Some(1),
        };
        let next_open = state
            .next_open
            .checked_add(1)
            .ok_or(Status::INSUFFICIENT_RESOURCES)?;
        let delete = options.options().delete_on_close();
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
            if delete && node.metadata.attributes().readonly() {
                return Err(Status::CANNOT_DELETE);
            }
            let replacement = matches!(
                options.disposition(),
                CreateDisposition::SUPERSEDE
                    | CreateDisposition::OVERWRITE
                    | CreateDisposition::OVERWRITE_IF
            );
            if replacement {
                if node.metadata.is_directory() {
                    return Err(Status::FILE_IS_A_DIRECTORY);
                }
                if (node.metadata.attributes().hidden() && !options.attributes().hidden())
                    || (node.metadata.attributes().system() && !options.attributes().system())
                {
                    return Err(Status::ACCESS_DENIED);
                }
                let supersede = options.disposition() == CreateDisposition::SUPERSEDE;
                options.access = options
                    .access()
                    .with_write_ea(true)
                    .with_write_attributes(true)
                    .with_write_data(!supersede || options.access().write_data())
                    .with_delete(supersede || options.access().delete())
                    .into_bits();
            }
            let mut available = AccessMask::from_bits(allowed_access(&state, id));
            if options.access().maximum_allowed() && node.metadata.attributes().readonly() {
                available.set_write_data(false);
                available.set_append_data(false);
                available.set_delete_child(false);
            }
            options.access = grant_access(available.into_bits(), options.access, delete)?;
            if !node.metadata.is_directory()
                && node.metadata.attributes().readonly()
                && (options.access().write_data() || options.access().append_data())
            {
                return Err(Status::ACCESS_DENIED);
            }
            for other in state.opens.values().filter(|o| o.node == id) {
                if sharing_conflict(options.access, options.share_access, other) {
                    return Err(Status::SHARING_VIOLATION);
                }
            }
            if replacement {
                let size_changed = node.metadata.size != 0;
                let attributes = FileAttributes::from_bits(
                    options.attributes & settable_attributes().into_bits(),
                )
                .with_archive(true)
                .with_not_content_indexed(false)
                .into_bits();
                let attributes_changed = attributes != node.metadata.attributes;
                let allocation =
                    usize::try_from(options.allocation_size).map_err(|_| Status::DISK_FULL)?;
                allocate(&mut state, id, allocation)?;
                let node = state.nodes.get_mut(&id).ok_or(Status::FILE_CLOSED)?;
                node.data.fill(0);
                node.metadata.size = 0;
                node.metadata.attributes = attributes;
                node.metadata.written = nt_time();
                node.metadata.changed = node.metadata.written;
                emit(
                    &mut state,
                    id,
                    NotifyAction::MODIFIED,
                    NotifyFilter::new()
                        .with_attributes(attributes_changed)
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
            if options.extended_attributes.is_some() {
                return Err(Status::EAS_NOT_SUPPORTED);
            }
            if !can_add(&state, parent, options.options().directory_file()) {
                return Err(Status::ACCESS_DENIED);
            }
            if delete && options.attributes().readonly() {
                return Err(Status::CANNOT_DELETE);
            }
            let directory = options.options().directory_file();
            if directory && options.attributes().temporary() {
                return Err(Status::INVALID_PARAMETER);
            }
            options.access = grant_access(
                AccessMask::FILE_ALL_ACCESS.into_bits(),
                options.access,
                delete,
            )?;
            if state.nodes.len() >= state.object_limit {
                return Err(Status::DISK_FULL);
            }
            let security = match options.security {
                Some(bytes) => creation_security(&state.nodes[&parent].security, directory, bytes)?,
                None => inherited_security(
                    &state.nodes[&parent].security,
                    directory,
                    &system_sid(),
                    &system_sid(),
                )?,
            };
            let id = state.next_id;
            let next_id = id.checked_add(1).ok_or(Status::INSUFFICIENT_RESOURCES)?;
            let allocation = if directory {
                0
            } else {
                usize::try_from(options.allocation_size).map_err(|_| Status::DISK_FULL)?
            };
            let new_bytes = allocation_charge(&state, 0, allocation)?;
            let mut data = Vec::new();
            data.try_reserve_exact(allocation)
                .map_err(|_| Status::INSUFFICIENT_RESOURCES)?;
            data.resize(allocation, 0);
            let now = nt_time();
            let attributes =
                FileAttributes::from_bits(options.attributes & settable_attributes().into_bits())
                    .with_readonly(!directory && options.attributes().readonly())
                    .with_directory(directory)
                    .with_archive(!directory || options.attributes().archive())
                    .with_not_content_indexed(
                        state.nodes[&parent]
                            .metadata
                            .attributes()
                            .not_content_indexed(),
                    )
                    .into_bits();
            state.nodes.insert(
                id,
                Node {
                    security,
                    metadata: Metadata {
                        id,
                        name: parts.last().ok_or(Status::OBJECT_NAME_INVALID)?.to_string(),
                        path: String::new(),
                        short_name: None,
                        attributes,
                        reparse_tag: 0,
                        created: now,
                        accessed: now,
                        written: now,
                        changed: now,
                        size: 0,
                        allocation_size: allocation as u64,
                        compression: Some(CompressionInformation::default()),
                        number_of_links: 1,
                        extended_attributes_length: 0,
                        alignment_requirement: 0,
                        delete_pending: false,
                        maximal_access: AccessMask::FILE_ALL_ACCESS.into_bits(),
                        granted_access: 0,
                    },
                    parent,
                    data,
                },
            );
            state.next_id = next_id;
            state.bytes = new_bytes;
            emit(&mut state, id, NotifyAction::ADDED, name_filter(directory));
            (id, CreateAction::CREATED.0)
        };
        if delete && id == 1 {
            return Err(Status::DIRECTORY_NOT_EMPTY);
        }
        let open = state.next_open;
        state.next_open = next_open;
        let notify_deleted = delete && state.nodes[&id].metadata.is_directory();
        state.opens.insert(
            open,
            Open {
                node: id,
                access: options.access,
                sharing: options.share_access,
                delete_on_close: delete,
                mode: options.options & FILE_MODE_INFORMATION_MASK,
                user_set_access_time: false,
                user_set_write_time: false,
                user_set_change_time: false,
                notify_deleted,
                watch: None,
            },
        );
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

    async fn rename(
        &self,
        file: &MemoryFile,
        name: &str,
        replace: bool,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        let parts = components(name)?;
        if name.ends_with('\\')
            || parts.is_empty()
            || matches!(parts.last().copied(), Some("." | ".."))
        {
            return Err(Status::OBJECT_NAME_INVALID);
        }
        let mut state = self.0.lock();
        let opened = state.opens.get(&file.open).ok_or(Status::FILE_CLOSED)?;
        let user_set_change_time = opened.user_set_change_time;
        let source = state.nodes.get(&file.node).ok_or(Status::FILE_CLOSED)?;
        if file.node == 1 {
            return Err(Status::ACCESS_DENIED);
        }
        let directory = source.metadata.is_directory();
        let old_parent = source.parent;
        let new_name = parts.last().ok_or(Status::OBJECT_NAME_INVALID)?;
        let parent = resolve_directory(&state, &parts[..parts.len() - 1])?;
        let parent_access = AccessMask::new()
            .with_write_data(!directory)
            .with_append_data(directory)
            .into_bits();
        if state.opens.values().any(|open| {
            open.node == parent
                && sharing_conflict(parent_access, ShareAccess::ALL.into_bits(), open)
        }) {
            return Err(Status::SHARING_VIOLATION);
        }
        if source.metadata.delete_pending {
            return Err(Status::ACCESS_DENIED);
        }
        if directory
            && (beneath(&state, parent, file.node)
                || state
                    .opens
                    .values()
                    .any(|open| open.node != file.node && beneath(&state, open.node, file.node)))
        {
            return Err(Status::ACCESS_DENIED);
        }
        if parent == old_parent && source.metadata.name == *new_name {
            return Ok(());
        }
        if !AccessMask::from_bits(acl_access(&state.nodes[&parent].security)).execute()
            || !can_add(&state, parent, directory)
        {
            return Err(Status::ACCESS_DENIED);
        }
        let target = child(&state, parent, new_name).filter(|&id| id != file.node);
        let exact_target = target.is_some_and(|id| state.nodes[&id].metadata.name == *new_name);
        if let Some(target) = target {
            if !replace {
                return Err(Status::OBJECT_NAME_COLLISION);
            }
            let metadata = &state.nodes[&target].metadata;
            if metadata.is_directory() || metadata.attributes().readonly() {
                return Err(Status::ACCESS_DENIED);
            }
            if metadata.delete_pending {
                return Err(Status::DELETE_PENDING);
            }
            if !AccessMask::from_bits(allowed_access(&state, target)).delete() {
                return Err(Status::ACCESS_DENIED);
            }
            if state.opens.values().any(|open| open.node == target) {
                return Err(Status::ACCESS_DENIED);
            }
        }

        // Validate everything before changing the namespace or publishing records.
        // MS-FSA §2.1.5.15.12 uses metadata notification, not a new-name record,
        // when replacing an exact-case destination.
        let moving = parent != old_parent;
        let filter = name_filter(directory);
        let new_name = new_name.to_string();
        if let Some(target) = target {
            if !exact_target {
                emit(
                    &mut state,
                    target,
                    NotifyAction::REMOVED,
                    name_filter(false),
                );
            }
            let node = state
                .nodes
                .remove(&target)
                .expect("replacement target was validated under the namespace lock");
            state.bytes -= node.data.len();
        }
        emit(
            &mut state,
            file.node,
            if moving || exact_target {
                NotifyAction::REMOVED
            } else {
                NotifyAction::RENAMED_OLD_NAME
            },
            filter,
        );
        let now = nt_time();
        let node = state.nodes.get_mut(&file.node).ok_or(Status::FILE_CLOSED)?;
        node.parent = parent;
        node.metadata.name = new_name;
        if !user_set_change_time {
            node.metadata.changed = now;
        }
        if !directory {
            node.metadata.attributes = node.metadata.attributes().with_archive(true).into_bits();
        }
        for parent in [old_parent, parent] {
            let metadata = &mut state
                .nodes
                .get_mut(&parent)
                .ok_or(Status::FILE_CLOSED)?
                .metadata;
            metadata.written = now;
            metadata.accessed = now;
            metadata.changed = now;
        }
        let (action, filter) = if exact_target {
            (
                NotifyAction::MODIFIED,
                NotifyFilter::new()
                    .with_attributes(true)
                    .with_size(true)
                    .with_last_write(true)
                    .with_last_access(true)
                    .with_creation(true)
                    .with_security(true)
                    .with_ea(true),
            )
        } else {
            (
                if moving {
                    NotifyAction::ADDED
                } else {
                    NotifyAction::RENAMED_NEW_NAME
                },
                filter,
            )
        };
        emit(&mut state, file.node, action, filter);
        if !directory && !exact_target {
            // File renames also invalidate attribute/creation watches, even
            // when those values are unchanged. Replacement already reports this.
            emit(
                &mut state,
                file.node,
                NotifyAction::MODIFIED,
                NotifyFilter::new()
                    .with_attributes(true)
                    .with_creation(true),
            );
        }
        wake(state);
        Ok(())
    }

    async fn metadata(
        &self,
        file: &MemoryFile,
        _request: &RequestContext,
    ) -> Result<Metadata, Status> {
        let state = self.0.lock();
        let open = state.opens.get(&file.open).ok_or(Status::FILE_CLOSED)?;
        let mut metadata = node_metadata(&state, file.node)?;
        metadata.granted_access = open.access;
        Ok(metadata)
    }

    async fn filesystem_information(
        &self,
        file: &MemoryFile,
        _request: &RequestContext,
    ) -> Result<FileSystemInformation, Status> {
        let state = self.0.lock();
        state.opens.get(&file.open).ok_or(Status::FILE_CLOSED)?;
        let total = i64::try_from(state.byte_limit).map_err(|_| Status::NOT_SUPPORTED)?;
        let available =
            i64::try_from(state.byte_limit - state.bytes).map_err(|_| Status::NOT_SUPPORTED)?;
        Ok(FileSystemInformation {
            created: state.created,
            serial: 0,
            label: "Memory".into(),
            supports_objects: true,
            name: "MEMORY".into(),
            attributes: FileSystemAttributes::new()
                .with_case_preserved_names(true)
                .with_unicode_on_disk(true)
                .into_bits(),
            maximum_component_name_length: MAX_COMPONENT_NAME_LENGTH,
            device_type: FILE_DEVICE_DISK,
            device_characteristics: 0,
            total_allocation_units: total,
            caller_available_allocation_units: available,
            actual_available_allocation_units: available,
            sectors_per_allocation_unit: 1,
            bytes_per_sector: 1,
        })
    }

    async fn query_security(
        &self,
        file: &MemoryFile,
        information: SecurityInformation,
        _request: &RequestContext,
    ) -> Result<SecurityDescriptor, Status> {
        let state = self.0.lock();
        state.opens.get(&file.open).ok_or(Status::FILE_CLOSED)?;
        let node = state.nodes.get(&file.node).ok_or(Status::FILE_CLOSED)?;
        let information =
            SecurityInformation::from_bits(information.into_bits() & SecurityInformation::VALID);
        if information.into_bits()
            & !SecurityInformation::new()
                .with_owner(true)
                .with_group(true)
                .with_dacl(true)
                .into_bits()
            != 0
        {
            return Err(Status::NOT_SUPPORTED);
        }
        let mut descriptor = node.security.clone();
        if !information.owner() {
            descriptor.owner = None;
        }
        if !information.group() {
            descriptor.group = None;
        }
        if !information.dacl() {
            descriptor.dacl = AclState::Absent;
            descriptor.control.set_dacl_present(false);
        }
        Ok(descriptor)
    }

    async fn set_security(
        &self,
        file: &MemoryFile,
        information: SecurityInformation,
        descriptor: &SecurityDescriptor,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        let mut state = self.0.lock();
        let open = state.opens.get(&file.open).ok_or(Status::FILE_CLOSED)?;
        let access = AccessMask::from_bits(open.access);
        if (information.dacl() && !access.write_dac())
            || ((information.owner() || information.group()) && !access.write_owner())
        {
            return Err(Status::ACCESS_DENIED);
        }
        let user_set_change_time = open.user_set_change_time;
        let node = state.nodes.get_mut(&file.node).ok_or(Status::FILE_CLOSED)?;
        validate_security(descriptor, information)?;
        if information.owner() {
            node.security.owner.clone_from(&descriptor.owner);
            node.security
                .control
                .set_owner_defaulted(descriptor.control.owner_defaulted());
        }
        if information.group() {
            node.security.group.clone_from(&descriptor.group);
            node.security
                .control
                .set_group_defaulted(descriptor.control.group_defaulted());
        }
        if information.dacl() {
            node.security.dacl.clone_from(&descriptor.dacl);
            node.security
                .control
                .set_dacl_present(descriptor.dacl != AclState::Absent);
            node.security
                .control
                .set_dacl_defaulted(descriptor.control.dacl_defaulted());
            node.security
                .control
                .set_dacl_protected(descriptor.control.dacl_protected());
            node.security
                .control
                .set_dacl_auto_inherited(descriptor.control.dacl_auto_inherited());
        }
        if information.into_bits() != 0 {
            if !node.metadata.is_directory() {
                node.metadata.attributes =
                    node.metadata.attributes().with_archive(true).into_bits();
                if !user_set_change_time {
                    node.metadata.changed = nt_time();
                }
            }
            emit(
                &mut state,
                file.node,
                NotifyAction::MODIFIED,
                NotifyFilter::new().with_security(true),
            );
        }
        wake(state);
        Ok(())
    }

    async fn read(
        &self,
        file: &MemoryFile,
        offset: u64,
        length: usize,
        _request: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let mut state = self.0.lock();
        if length != 0
            && conflicts(
                &state,
                file,
                ByteRange {
                    offset,
                    length: length as u64,
                },
                false,
                false,
            )
        {
            return Err(Status::FILE_LOCK_CONFLICT);
        }
        let user_set_access_time = state
            .opens
            .get(&file.open)
            .ok_or(Status::FILE_CLOSED)?
            .user_set_access_time;
        let node = state.nodes.get_mut(&file.node).ok_or(Status::FILE_CLOSED)?;
        if node.metadata.is_directory() {
            return Err(Status::INVALID_DEVICE_REQUEST);
        }
        let file_size = node.metadata.size as usize;
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(file_size);
        let end = start.saturating_add(length).min(file_size);
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
        if conflicts(
            &state,
            file,
            ByteRange {
                offset,
                length: data.len() as u64,
            },
            true,
            false,
        ) {
            return Err(Status::FILE_LOCK_CONFLICT);
        }
        let offset = usize::try_from(offset).map_err(|_| Status::DISK_FULL)?;
        let end = offset.checked_add(data.len()).ok_or(Status::DISK_FULL)?;
        let size_changed = end as u64 > node.metadata.size;
        if end > node.data.len() {
            allocate(&mut state, file.node, end)?;
        }
        let node = state.nodes.get_mut(&file.node).ok_or(Status::FILE_CLOSED)?;
        node.data[offset..end].copy_from_slice(data);
        node.metadata.size = node.metadata.size.max(end as u64);
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
        let mut current = node_metadata(&state, file.node)?;
        current.name = ".".to_owned();
        let mut parent = node_metadata(&state, node.parent)?;
        parent.name = "..".to_owned();
        let mut entries = vec![current, parent];
        entries.extend(
            state
                .nodes
                .values()
                .filter(|n| n.parent == file.node && n.metadata.id != file.node)
                .map(|n| node_metadata(&state, n.metadata.id))
                .collect::<Result<Vec<_>, _>>()?,
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

    async fn lock(
        &self,
        file: &MemoryFile,
        range: ByteRange,
        exclusive: bool,
        fail_immediately: bool,
        request: &RequestContext,
    ) -> Result<LockId, Status> {
        range.validate()?;
        let changed = self.0.lock().changed.clone();
        let mut waiter = None;
        loop {
            let listener = changed.listen();
            {
                let mut state = self.0.lock();
                state.opens.get(&file.open).ok_or(Status::FILE_CLOSED)?;
                if state.nodes[&file.node].metadata.is_directory() {
                    return Err(Status::INVALID_PARAMETER);
                }
                if request.is_cancelled() {
                    return Err(Status::CANCELLED);
                }
                if !conflicts(&state, file, range, exclusive, true) {
                    if state.locks.len() >= LOCK_LIMIT {
                        return Err(Status::INSUFFICIENT_RESOURCES);
                    }
                    let id = LockId(state.next_lock);
                    state.next_lock = state
                        .next_lock
                        .checked_add(1)
                        .ok_or(Status::INSUFFICIENT_RESOURCES)?;
                    state.locks.push(RangeLock {
                        id,
                        node: file.node,
                        owner: file.open,
                        range,
                        exclusive,
                    });
                    return Ok(id);
                }
                if fail_immediately {
                    return Err(Status::LOCK_NOT_GRANTED);
                }
                if waiter.is_none() {
                    if state.lock_waiters >= LOCK_WAITER_LIMIT {
                        return Err(Status::INSUFFICIENT_RESOURCES);
                    }
                    state.lock_waiters += 1;
                    waiter = Some(LockWaiter(self.0.clone()));
                }
            }
            let mut listener = std::pin::pin!(listener.fuse());
            let mut cancelled = std::pin::pin!(request.cancelled().fuse());
            futures::select! {
                () = listener => {},
                () = cancelled => return Err(Status::CANCELLED),
            }
        }
    }

    async fn rollback_lock(
        &self,
        file: &MemoryFile,
        lock: LockId,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        let mut state = self.0.lock();
        if let Some(index) = state
            .locks
            .iter()
            .position(|entry| entry.owner == file.open && entry.id == lock)
        {
            state.locks.remove(index);
        }
        wake(state);
        Ok(())
    }

    async fn unlock(
        &self,
        file: &MemoryFile,
        range: ByteRange,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        range.validate()?;
        let mut state = self.0.lock();
        state.opens.get(&file.open).ok_or(Status::FILE_CLOSED)?;
        if state.nodes[&file.node].metadata.is_directory() {
            return Err(Status::INVALID_PARAMETER);
        }
        let index = state
            .locks
            .iter()
            .enumerate()
            .filter(|(_, lock)| lock.owner == file.open && lock.range == range)
            .max_by_key(|(_, lock)| lock.exclusive)
            .map(|(index, _)| index)
            .ok_or(Status::RANGE_NOT_LOCKED)?;
        state.locks.remove(index);
        wake(state);
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

    async fn set_allocation_size(
        &self,
        file: &MemoryFile,
        length: u64,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        let mut state = self.0.lock();
        let open = state.opens.get(&file.open).ok_or(Status::FILE_CLOSED)?;
        let user_set_change_time = open.user_set_change_time;
        let node = state.nodes.get(&file.node).ok_or(Status::FILE_CLOSED)?;
        if node.metadata.is_directory() {
            return Err(Status::INVALID_PARAMETER);
        }
        let before = node.metadata.size;
        let length = usize::try_from(length).map_err(|_| Status::INVALID_PARAMETER)?;
        let unchanged = node.data.len() == length;
        allocate(&mut state, file.node, length)?;
        if state.nodes[&file.node].metadata.size < before {
            modified(&mut state, file)?;
            let filter = NotifyFilter::new()
                .with_size(true)
                .with_last_write(!state.opens[&file.open].user_set_write_time);
            emit(&mut state, file.node, NotifyAction::MODIFIED, filter);
        } else if unchanged {
            let node = state.nodes.get_mut(&file.node).ok_or(Status::FILE_CLOSED)?;
            if !user_set_change_time {
                node.metadata.changed = nt_time();
            }
            node.metadata.attributes = node.metadata.attributes().with_archive(true).into_bits();
        }
        wake(state);
        Ok(())
    }

    async fn set_mode(
        &self,
        file: &MemoryFile,
        mode: u32,
        _request: &RequestContext,
    ) -> Result<u32, Status> {
        let mut state = self.0.lock();
        let open = state.opens.get_mut(&file.open).ok_or(Status::FILE_CLOSED)?;
        let old = CreateOptions::from_bits(open.mode);
        let new = CreateOptions::from_bits(mode);
        let was_sync = old.synchronous_io_alert() || old.synchronous_io_nonalert();
        let is_sync = new.synchronous_io_alert() || new.synchronous_io_nonalert();
        if mode & !FILE_MODE_INFORMATION_SET_MASK != 0
            || was_sync != is_sync
            || (new.synchronous_io_alert() && new.synchronous_io_nonalert())
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let mut applied = old
            .with_sequential_only(new.sequential_only())
            .with_synchronous_io_alert(new.synchronous_io_alert())
            .with_synchronous_io_nonalert(new.synchronous_io_nonalert());
        if !old.no_intermediate_buffering() {
            applied.set_write_through(new.write_through());
        }
        open.mode = applied.into_bits();
        Ok(open.mode)
    }

    async fn set_delete_on_close(
        &self,
        file: &MemoryFile,
        delete: bool,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        let mut state = self.0.lock();
        state.opens.get(&file.open).ok_or(Status::FILE_CLOSED)?;
        let metadata = &state
            .nodes
            .get(&file.node)
            .ok_or(Status::FILE_CLOSED)?
            .metadata;
        if delete && metadata.attributes().readonly() {
            return Err(Status::CANNOT_DELETE);
        }
        let directory = metadata.is_directory();
        if delete && (file.node == 1 || has_children(&state, file.node)) {
            return Err(Status::DIRECTORY_NOT_EMPTY);
        }
        let open = state.opens.get_mut(&file.open).ok_or(Status::FILE_CLOSED)?;
        open.notify_deleted |= delete && directory;
        if delete && directory {
            delete_watches(&mut state, file.node);
        }
        let node = state.nodes.get_mut(&file.node).ok_or(Status::FILE_CLOSED)?;
        node.metadata.delete_pending = delete;
        wake(state);
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
            let mut valid = settable_attributes();
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
        let (changed, id, watch_id) = {
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
            let open = state.opens.get(&file.open).ok_or(Status::FILE_CLOSED)?;
            if open.notify_deleted {
                return Err(Status::DELETE_PENDING);
            }
            let first = open.watch.is_none();
            if first {
                if state.watches == NOTIFY_WATCH_LIMIT {
                    return Err(Status::INSUFFICIENT_RESOURCES);
                }
                state.watches += 1;
            }
            let open = state.opens.get_mut(&file.open).ok_or(Status::FILE_CLOSED)?;
            let watch = open.watch.get_or_insert_with(|| Watch {
                id,
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
            let watch_id = watch.id;
            (state.changed.clone(), id, watch_id)
        };
        let _waiter = NotifyWaiter {
            state: self.0.clone(),
            open: file.open,
            id,
            watch: watch_id,
        };
        loop {
            let listener = changed.listen();
            {
                let mut state = self.0.lock();
                let watch = state
                    .opens
                    .get_mut(&file.open)
                    .ok_or(Status::FILE_CLOSED)?
                    .watch
                    .as_mut()
                    .filter(|watch| watch.id == watch_id)
                    .ok_or(Status::DELETE_PENDING)?;
                if request.is_cancelled() {
                    return Err(Status::CANCELLED);
                }
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
                () = cancelled => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::CreateOptions;
    use crate::test_support::Operation;
    use crate::test_support::contracts::{self, Expectations, Feature, Fixture};
    use futures::executor::block_on;
    use std::task::Poll;
    use test_with_tracing::test;

    struct ContractFixture(MemoryFs);

    #[test]
    fn creation_security_specializes_explicit_creator_templates_and_rejects_sacls() {
        block_on(async {
            let fs = MemoryFs::new(1024, 16);
            let context = RequestContext::new(1);
            let world = Sid::new([0, 0, 0, 0, 0, 1], &[0]).unwrap();
            let creator_group = Sid::new([0, 0, 0, 0, 0, 3], &[1]).unwrap();
            let mut descriptor = SecurityDescriptor::empty();
            descriptor.group = Some(world.clone());
            descriptor.control.set_dacl_protected(true);
            descriptor.dacl = AclState::Present(
                Acl::access(&[
                    AccessAce {
                        deny: false,
                        flags: AceFlags::new(),
                        mask: AccessMask::FILE_ALL_ACCESS.into_bits(),
                        sid: world.clone(),
                    },
                    AccessAce {
                        deny: false,
                        flags: AceFlags::new()
                            .with_object_inherit(true)
                            .with_container_inherit(true),
                        mask: AccessMask::new().with_generic_read(true).into_bits(),
                        sid: creator_group.clone(),
                    },
                ])
                .unwrap(),
            );
            let encoded = descriptor.encode();
            let options = OpenOptions {
                access: AccessMask::FILE_ALL_ACCESS.into_bits(),
                share_access: 7,
                disposition: 2,
                options: 1,
                attributes: 0,
                security: Some(encoded.as_slice()),
                extended_attributes: None,
                allocation_size: 0,
            };
            let (directory, _) = fs.open("explicit", options, &context).await.unwrap();
            let actual = fs
                .query_security(
                    &directory,
                    SecurityInformation::new().with_group(true).with_dacl(true),
                    &context,
                )
                .await
                .unwrap();
            assert_eq!(actual.group, Some(world.clone()));
            let AclState::Present(acl) = actual.dacl else {
                panic!("missing explicit ACL")
            };
            let entries: Vec<_> = acl.entries().map(|ace| ace.access().unwrap()).collect();
            assert_eq!(entries.len(), 3);
            assert_eq!(entries[1].sid, world);
            assert_eq!(entries[1].mask, AccessMask::FILE_GENERIC_READ.into_bits());
            assert!(!entries[1].flags.object_inherit());
            assert_eq!(entries[2].sid, creator_group);
            assert!(entries[2].flags.inherit_only());
            let (file, _) = fs
                .open(
                    "explicit\\file",
                    OpenOptions {
                        options: 0,
                        security: None,
                        ..options
                    },
                    &context,
                )
                .await
                .unwrap();
            fs.write(&file, 0, b"created", &context).await.unwrap();
            let read = OpenOptions {
                access: 1,
                disposition: 1,
                options: 0,
                security: None,
                ..options
            };
            let (reopened, _) = fs.open("explicit\\file", read, &context).await.unwrap();
            assert_eq!(
                fs.read(&reopened, 0, 7, &context).await.unwrap(),
                b"created"
            );
            assert_eq!(
                fs.open(
                    "explicit\\file",
                    OpenOptions { access: 2, ..read },
                    &context
                )
                .await
                .err(),
                Some(Status::ACCESS_DENIED)
            );
            descriptor.sacl = AclState::Null;
            let rejected = descriptor.encode();
            assert_eq!(
                fs.open(
                    "sacl",
                    OpenOptions {
                        options: 0,
                        security: Some(&rejected),
                        ..options
                    },
                    &context
                )
                .await
                .err(),
                Some(Status::NOT_SUPPORTED)
            );
            assert_eq!(
                fs.open("sacl", read, &context).await.err(),
                Some(Status::OBJECT_NAME_NOT_FOUND)
            );
            for file in [reopened, file, directory] {
                fs.close(&file, &context).await.unwrap();
            }
        });
    }

    #[test]
    fn inherited_creator_templates_preserve_generic_information_for_descendants() {
        for rid in [0, 1] {
            let creator = Sid::new([0, 0, 0, 0, 0, 3], &[rid]).unwrap();
            let generic = AccessMask::new().with_generic_read(true).into_bits();
            let mut parent = SecurityDescriptor::empty();
            parent.dacl = AclState::Present(
                Acl::access(&[AccessAce {
                    deny: false,
                    flags: AceFlags::new()
                        .with_object_inherit(true)
                        .with_container_inherit(true)
                        .with_inherit_only(true),
                    mask: generic,
                    sid: creator.clone(),
                }])
                .unwrap(),
            );
            let directory =
                inherited_security(&parent, true, &system_sid(), &system_sid()).unwrap();
            let AclState::Present(acl) = &directory.dacl else {
                panic!("missing inherited ACL")
            };
            let entries: Vec<_> = acl.entries().map(|ace| ace.access().unwrap()).collect();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].sid, system_sid());
            assert_eq!(entries[0].mask, AccessMask::FILE_GENERIC_READ.into_bits());
            assert_eq!(
                entries[0].flags.into_bits(),
                AceFlags::new().with_inherited(true).into_bits()
            );
            assert_eq!(entries[1].sid, creator);
            assert_eq!(entries[1].mask, generic);
            assert!(entries[1].flags.inherit_only() && entries[1].flags.inherited());
            let child =
                inherited_security(&directory, false, &system_sid(), &system_sid()).unwrap();
            let AclState::Present(acl) = child.dacl else {
                panic!("missing inherited ACL")
            };
            let entries: Vec<_> = acl.entries().map(|ace| ace.access().unwrap()).collect();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].sid, system_sid());
            assert_eq!(entries[0].mask, AccessMask::FILE_GENERIC_READ.into_bits());
            assert!(!entries[0].flags.inherit_only());
        }
    }

    impl Fixture for ContractFixture {
        type Backend = MemoryFs;

        fn filesystem(&self) -> &MemoryFs {
            &self.0
        }

        fn expectations(&self) -> Expectations {
            Expectations {
                filesystem_information: Feature::Supported,
                allocation: Feature::Supported,
                creation_allocation: true,
                file_mode: Feature::Supported,
                security_queries: Feature::Supported,
                file_acl_updates: Feature::Supported,
                directory_acl_updates: Feature::Supported,
                acl_inheritance: Feature::Supported,
                security_creation: Feature::Supported,
                creation_eas: Feature::Unsupported(Status::EAS_NOT_SUPPORTED),
                basic_information: Feature::Supported,
                rename: Feature::Supported,
                locks: Feature::Supported,
                notifications: Feature::Supported,
            }
        }

        async fn wait_until_pending(&self, operation: Operation, request: &RequestContext) {
            assert!(!request.is_cancelled());
            let state = self.0.0.lock();
            match operation {
                Operation::Lock => assert!(state.lock_waiters > 0),
                Operation::Notify => assert!(
                    state
                        .opens
                        .values()
                        .filter_map(|open| open.watch.as_ref())
                        .any(|watch| !watch.waiters.is_empty())
                ),
                _ => panic!("unexpected pending probe: {operation:?}"),
            }
        }
    }

    fn run_contract(test: impl AsyncFnOnce(&ContractFixture)) {
        let fixture = ContractFixture(MemoryFs::new(1024, 32));
        block_on(test(&fixture));
        let state = fixture.0.0.lock();
        assert!(state.opens.is_empty());
        assert!(state.locks.is_empty());
        assert_eq!(state.lock_waiters, 0);
        assert_eq!(state.watches, 0);
    }

    #[test]
    fn contract_data_and_identity() {
        run_contract(contracts::data_and_identity);
    }

    #[test]
    fn contract_filesystem_information() {
        run_contract(contracts::filesystem_information);
    }

    #[test]
    fn contract_maximum_allowed_access() {
        run_contract(contracts::maximum_allowed_access);
    }

    #[test]
    fn contract_security_queries() {
        run_contract(contracts::security_queries);
    }

    #[test]
    fn contract_file_acl_updates() {
        run_contract(contracts::file_acl_updates);
    }

    #[test]
    fn contract_directory_acl_updates() {
        run_contract(contracts::directory_acl_updates);
    }

    #[test]
    fn contract_acl_inheritance() {
        run_contract(contracts::acl_inheritance);
    }

    #[test]
    fn contract_security_creation() {
        run_contract(contracts::security_creation);
    }

    #[test]
    fn contract_creation_eas() {
        run_contract(contracts::creation_eas);
    }

    #[test]
    fn contract_allocation_reservations() {
        run_contract(contracts::allocation_reservations);
    }

    #[test]
    fn contract_file_mode_updates() {
        run_contract(contracts::file_mode_updates);
    }

    #[test]
    fn contract_sharing_and_handle_release() {
        run_contract(contracts::sharing_and_handle_release);
    }

    #[test]
    fn contract_delete_on_close() {
        run_contract(contracts::delete_on_close);
    }

    #[test]
    fn contract_basic_information() {
        run_contract(contracts::basic_information);
    }

    #[test]
    fn contract_delete_mode_is_deferred_to_close() {
        run_contract(contracts::delete_mode_is_deferred_to_close);
    }

    #[test]
    fn contract_directory_delete_mode_checks_emptiness_at_close() {
        run_contract(contracts::directory_delete_mode_checks_emptiness_at_close);
    }

    #[test]
    fn contract_notify_nonempty_delete_mode_preserves_watch() {
        run_contract(contracts::notify_nonempty_delete_mode_preserves_watch);
    }

    #[test]
    fn contract_rename_identity() {
        run_contract(contracts::rename_identity);
    }

    #[test]
    fn contract_rename_namespace_and_replacement() {
        run_contract(contracts::rename_namespace_and_replacement);
    }

    #[test]
    fn contract_rename_notifications() {
        run_contract(contracts::rename_notifications);
    }

    #[test]
    fn rename_replacement_reclaims_quota_and_rejects_readonly_targets() {
        block_on(async {
            let fs = MemoryFs::new(4, 8);
            let request = RequestContext::new(1);
            let options = OpenOptions {
                access: AccessMask::FILE_ALL_ACCESS.into_bits(),
                share_access: ShareAccess::ALL.into_bits(),
                disposition: CreateDisposition::CREATE.0,
                options: 0,
                attributes: 0,
                security: None,
                extended_attributes: None,
                allocation_size: 0,
            };
            let (source, _) = fs.open("source", options, &request).await.unwrap();
            let (target, _) = fs.open("target", options, &request).await.unwrap();
            fs.write(&target, 0, b"full", &request).await.unwrap();
            let info = BasicInformation {
                created: 0,
                accessed: 0,
                written: 0,
                changed: 0,
                attributes: FileAttributes::new().with_readonly(true).into_bits(),
            };
            fs.set_basic(&target, info, &request).await.unwrap();
            fs.close(&target, &request).await.unwrap();
            assert_eq!(
                fs.rename(&source, "target", true, &request).await,
                Err(Status::ACCESS_DENIED)
            );
            let (attributes, _) = fs
                .open(
                    "target",
                    OpenOptions {
                        access: AccessMask::new().with_write_attributes(true).into_bits(),
                        disposition: CreateDisposition::OPEN.0,
                        ..options
                    },
                    &request,
                )
                .await
                .unwrap();
            fs.set_basic(
                &attributes,
                BasicInformation {
                    attributes: FileAttributes::new().with_normal(true).into_bits(),
                    ..info
                },
                &request,
            )
            .await
            .unwrap();
            fs.close(&attributes, &request).await.unwrap();
            assert_eq!(
                fs.rename(&source, &"x".repeat(MAX_PATH_LENGTH + 1), false, &request)
                    .await,
                Err(Status::NAME_TOO_LONG)
            );
            fs.rename(&source, "target", true, &request).await.unwrap();
            assert_eq!(fs.write(&source, 0, b"live", &request).await.unwrap(), 4);
            assert_eq!(fs.0.lock().bytes, 4);
            assert_eq!(fs.0.lock().nodes.len(), 2);
            fs.close(&source, &request).await.unwrap();
        });
    }

    #[test]
    fn contract_lock_conflicts_and_io() {
        run_contract(contracts::lock_conflicts_and_io);
    }

    #[test]
    fn contract_lock_waiters_and_cancellation() {
        run_contract(contracts::lock_waiters_and_cancellation);
    }

    #[test]
    fn contract_lock_rollback_and_drop() {
        run_contract(contracts::lock_rollback_and_drop);
    }

    #[test]
    fn contract_notify_registration_and_cancellation() {
        run_contract(contracts::notify_registration_and_cancellation);
    }

    #[test]
    fn contract_notify_fifo_and_small_buffer() {
        run_contract(contracts::notify_fifo_and_small_buffer);
    }

    #[test]
    fn contract_notify_subtree_and_filters() {
        run_contract(contracts::notify_subtree_and_filters);
    }

    #[test]
    fn contract_notify_deletion_generations() {
        run_contract(contracts::notify_deletion_generations);
    }

    #[test]
    fn deletion_invalidates_old_watch_generations_without_stealing_a_new_registration() {
        block_on(async {
            let fs = MemoryFs::new(1024, 16);
            let context = RequestContext::new(1);
            let options = OpenOptions {
                access: AccessMask::FILE_ALL_ACCESS.into_bits(),
                share_access: ShareAccess::ALL.into_bits(),
                disposition: CreateDisposition::OPEN_IF.0,
                options: CreateOptions::new().with_directory_file(true).into_bits(),
                attributes: 0,
                security: None,
                extended_attributes: None,
                allocation_size: 0,
            };
            let (watched, _) = fs.open("generation", options, &context).await.unwrap();
            let (deleting, _) = fs.open("generation", options, &context).await.unwrap();
            let first_context = RequestContext::new(2);
            let second_context = RequestContext::new(3);
            let mut first = std::pin::pin!(fs.notify(
                &watched,
                NotifyFilter::new().with_file_name(true),
                false,
                1024,
                &first_context
            ));
            let mut second = std::pin::pin!(fs.notify(
                &watched,
                NotifyFilter::new().with_file_name(true),
                false,
                1024,
                &second_context
            ));
            assert!(futures::poll!(&mut first).is_pending());
            assert!(futures::poll!(&mut second).is_pending());
            fs.set_delete_on_close(&deleting, true, &context)
                .await
                .unwrap();
            fs.set_delete_on_close(&deleting, false, &context)
                .await
                .unwrap();
            first_context.cancel();
            second_context.cancel();
            let mut fresh = std::pin::pin!(fs.notify(
                &watched,
                NotifyFilter::new().with_dir_name(true),
                false,
                1024,
                &context
            ));
            assert!(futures::poll!(&mut fresh).is_pending());
            for notification in [&mut first, &mut second] {
                assert!(matches!(
                    futures::poll!(notification),
                    Poll::Ready(Err(Status::DELETE_PENDING))
                ));
            }
            {
                let state = fs.0.lock();
                assert_eq!(state.watches, 1);
                assert_eq!(
                    state
                        .opens
                        .values()
                        .filter_map(|open| open.watch.as_ref())
                        .map(|watch| watch.waiters.len())
                        .sum::<usize>(),
                    1
                );
            }
            let (child, _) = fs
                .open("generation\\child", options, &context)
                .await
                .unwrap();
            let result = fresh.await.unwrap();
            assert!(
                matches!(result, NotifyResult::Changes(ref changes) if changes == &[Change { action: NotifyAction::ADDED, name: "child".into() }])
            );
            assert!(matches!(
                fs.notify(&deleting, NotifyFilter::new(), false, 1024, &context)
                    .await,
                Err(Status::DELETE_PENDING)
            ));
            fs.close(&child, &context).await.unwrap();
            fs.close(&watched, &context).await.unwrap();
            fs.close(&deleting, &context).await.unwrap();
            let state = fs.0.lock();
            assert_eq!(state.watches, 0);
            assert!(state.opens.is_empty());
        });
    }

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
                security: None,
                extended_attributes: None,
                allocation_size: 0,
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
                security: None,
                extended_attributes: None,
                allocation_size: 0,
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
