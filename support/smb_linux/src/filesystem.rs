// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::io::Io;
use crate::names;
use crate::notify::Watch;
use async_trait::async_trait;
use event_listener::Event;
use futures::FutureExt;
use inspect::Inspect;
use pal_async::driver::Driver;
use parking_lot::Mutex;
use smb::provider::caching::software::CachingKey;
use smb::provider::caching::software::mediated::{
    Change as CacheChange, MediatedCaching, MediatedOpen, NamespaceAdmission,
};
use smb::provider::locking::software::{SoftwareIo, SoftwareLockOwner, SoftwareLocks};
use smb::provider::{
    BasicInformation, ByteRange, CachingGrant, CachingRequest, FileControl, FileControlResult,
    FileSystem, FileSystemInformation, LockId, LockScope, Metadata, NotifyResult, OpenError,
    OpenOptions, Opened, ReparsePoint, RequestContext, SymbolicLink, map_access, sharing_conflict,
};
use smb::security::{AccessAce, Acl, AclState, SecurityDescriptor, Sid};
use smb::spec::{
    AccessMask, AceFlags, CreateAction, CreateDisposition, FileAttributes, IO_REPARSE_TAG_SYMLINK,
    NotifyFilter, SecurityInformation, Status,
};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

const OPEN_LIMIT: usize = 4096;
const IDENTITY_LIMIT: usize = 65536;
const NT_EPOCH: i64 = 11_644_473_600;

#[cfg(test)]
mod tests;

/// Failure to capture an export or initialize its required asynchronous I/O.
#[derive(Debug, thiserror::Error)]
#[error("cannot initialize Linux SMB filesystem")]
pub struct OpenRootError(#[from] std::io::Error);

/// Native Linux provider with a pinned export root and no SMB caching grants.
///
/// Linux 6.6 is the minimum supported target. Namespace traversal acquires only
/// confined descriptors; retained descriptors remain capabilities if the host
/// later renames their objects. External writers are not constrained by SMB locks.
pub struct LinuxFs(Arc<Inner>);

struct Inner {
    io: Io,
    root: Arc<File>,
    state: Mutex<State>,
    changed: Event,
    locks: SoftwareLocks<Key>,
    security: SecurityDescriptor,
    caching: Option<MediatedCaching>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Key {
    device: u64,
    inode: u64,
}

impl Key {
    fn of(stat: &libc::statx) -> Self {
        Self {
            device: (u64::from(stat.stx_dev_major) << 32) | u64::from(stat.stx_dev_minor),
            inode: stat.stx_ino,
        }
    }
}

#[derive(Clone)]
struct Location {
    parent: Arc<File>,
    parent_key: Key,
    name: CString,
    path: String,
}

impl Location {
    fn identity(&self) -> (Key, CString) {
        (self.parent_key, self.name.clone())
    }
}

#[derive(Default)]
struct State {
    next: u64,
    identities: HashMap<Key, u64>,
    opens: HashMap<u64, Record>,
    deletes: HashMap<(Key, CString), Key>,
    claims: HashMap<ClaimKey, u64>,
    pending_opens: usize,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum ClaimKey {
    Name(Key, CString),
    Node(Key),
}

struct Claim {
    inner: Arc<Inner>,
    id: u64,
    opening: bool,
}

impl Drop for Claim {
    fn drop(&mut self) {
        let mut state = self.inner.state.lock();
        state.claims.retain(|_, owner| *owner != self.id);
        if self.opening {
            state.pending_opens -= 1;
        }
        drop(state);
        self.inner.changed.notify(usize::MAX);
    }
}

#[derive(Clone)]
struct Record {
    key: Key,
    access: u32,
    sharing: u32,
    location: Location,
    directory: bool,
    reparse: bool,
    write_through: bool,
    watch: Option<Weak<Watch>>,
    notify_deleted: bool,
    closing: bool,
    delete_on_close: bool,
    locks: SoftwareLockOwner<Key>,
}

struct Closing {
    inner: Arc<Inner>,
    id: u64,
    locks: SoftwareLockOwner<Key>,
}

impl Drop for Closing {
    fn drop(&mut self) {
        if let Some(record) = self.inner.state.lock().opens.get_mut(&self.id) {
            record.closing = false;
        }
        self.locks.resume();
        self.inner.changed.notify(usize::MAX);
    }
}

struct Reservation {
    inner: Arc<Inner>,
    id: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.inner.release(self.id);
    }
}

/// Opaque open retaining its native object and provider-wide reservations.
pub struct LinuxFile {
    reservation: Reservation,
    file: Mutex<Option<Arc<File>>>,
    pin: Mutex<Option<Arc<File>>>,
    key: Key,
    closed: AtomicBool,
    watch: futures::lock::Mutex<Option<Arc<Watch>>>,
    caching: Option<Arc<MediatedOpen>>,
}

struct Resolved {
    file: Option<Arc<File>>,
    stat: Option<libc::statx>,
    location: Location,
}

impl LinuxFile {
    fn retain_caching(&self, request: &RequestContext) -> RequestContext {
        match &self.caching {
            Some(owner) => request.with_keepalive(owner.clone()),
            None => request.clone(),
        }
    }

    async fn caching_request(
        &self,
        change: CacheChange,
        request: &RequestContext,
    ) -> Result<RequestContext, Status> {
        match &self.caching {
            Some(owner) => owner.request(change, request).await,
            None => Ok(request.clone()),
        }
    }

    fn pin(&self) -> Result<Arc<File>, Status> {
        self.pin.lock().clone().ok_or(Status::FILE_CLOSED)
    }
}

impl std::fmt::Debug for LinuxFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxFile")
            .field("open", &self.reservation.id)
            .field("closed", &self.closed.load(Ordering::Acquire))
            .finish()
    }
}

pub(crate) fn status(error: std::io::Error) -> Status {
    match error.raw_os_error() {
        Some(libc::ECANCELED) => Status::CANCELLED,
        Some(libc::ENOENT) => Status::OBJECT_NAME_NOT_FOUND,
        Some(libc::EACCES | libc::EPERM) => Status::ACCESS_DENIED,
        Some(libc::EEXIST) => Status::OBJECT_NAME_COLLISION,
        Some(libc::ENOTDIR) => Status::NOT_A_DIRECTORY,
        Some(libc::EISDIR) => Status::FILE_IS_A_DIRECTORY,
        Some(libc::ENOTEMPTY) => Status::DIRECTORY_NOT_EMPTY,
        Some(libc::EBADF) => Status::FILE_CLOSED,
        Some(libc::EXDEV) => Status::NOT_SAME_DEVICE,
        Some(libc::EROFS) => Status::MEDIA_WRITE_PROTECTED,
        Some(libc::ENOSPC | libc::EDQUOT) => Status::DISK_FULL,
        Some(libc::ENAMETOOLONG) => Status::OBJECT_NAME_INVALID,
        Some(libc::EINVAL | libc::EFBIG) => Status::INVALID_PARAMETER,
        Some(libc::ENOMEM | libc::EMFILE | libc::ENFILE | libc::EOVERFLOW) => {
            Status::INSUFFICIENT_RESOURCES
        }
        Some(libc::ENOSYS | libc::EOPNOTSUPP) => Status::NOT_SUPPORTED,
        Some(libc::ELOOP) => Status::IO_REPARSE_TAG_NOT_HANDLED,
        _ if error.kind() == std::io::ErrorKind::Unsupported => Status::NOT_SUPPORTED,
        _ => {
            tracelimit::warn_ratelimited!(error = ?error, "Linux SMB filesystem operation failed");
            Status::UNSUCCESSFUL
        }
    }
}

fn kind(stat: &libc::statx) -> u32 {
    u32::from(stat.stx_mode) & libc::S_IFMT
}

fn nt_time(time: libc::statx_timestamp) -> u64 {
    let ticks = (i128::from(time.tv_sec) + i128::from(NT_EPOCH)) * 10_000_000
        + i128::from(time.tv_nsec / 100);
    ticks.clamp(0, i128::from(u64::MAX)) as u64
}

fn share_security() -> SecurityDescriptor {
    let world = Sid::new([0, 0, 0, 0, 0, 1], &[0]).expect("well-known world SID");
    let system = Sid::new([0, 0, 0, 0, 0, 5], &[18]).expect("well-known system SID");
    SecurityDescriptor {
        owner: Some(system.clone()),
        group: Some(system),
        dacl: AclState::Present(
            Acl::access(&[AccessAce {
                deny: false,
                flags: AceFlags::new(),
                mask: AccessMask::FILE_ALL_ACCESS.into_bits(),
                sid: world,
            }])
            .expect("one bounded share ACE"),
        ),
        ..SecurityDescriptor::empty()
    }
}

impl Inner {
    fn release(&self, id: u64) {
        let mut state = self.state.lock();
        state.opens.remove(&id);
        let State { deletes, opens, .. } = &mut *state;
        deletes.retain(|location, _| {
            opens
                .values()
                .any(|open| open.location.identity() == *location)
        });
        drop(state);
        self.changed.notify(usize::MAX);
    }
}

impl LinuxFs {
    fn invalidate_watches(&self, key: Key) {
        let watches = self
            .0
            .state
            .lock()
            .opens
            .values()
            .filter(|open| open.key == key)
            .filter_map(|open| open.watch.as_ref().and_then(Weak::upgrade))
            .collect::<Vec<_>>();
        for watch in watches {
            watch.invalidate();
        }
    }

    async fn claim(
        &self,
        keys: &[ClaimKey],
        opening: bool,
        request: &RequestContext,
    ) -> Result<Claim, Status> {
        loop {
            let listener = self.0.changed.listen();
            crate::io::check(request).map_err(status)?;
            {
                let mut state = self.0.state.lock();
                if !keys.iter().any(|key| state.claims.contains_key(key)) {
                    if opening && state.opens.len() + state.pending_opens >= OPEN_LIMIT {
                        return Err(Status::INSUFFICIENT_RESOURCES);
                    }
                    let id = state.next;
                    state.next = id.checked_add(1).ok_or(Status::INSUFFICIENT_RESOURCES)?;
                    for key in keys {
                        state.claims.insert(key.clone(), id);
                    }
                    if opening {
                        state.pending_opens += 1;
                    }
                    return Ok(Claim {
                        inner: self.0.clone(),
                        id,
                        opening,
                    });
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

    async fn refresh(
        &self,
        resolved: &mut Resolved,
        request: &RequestContext,
    ) -> Result<(), Status> {
        match self
            .0
            .io
            .open(
                resolved.location.parent.clone(),
                resolved.location.name.clone(),
                libc::O_PATH,
                0,
                request,
            )
            .await
        {
            Ok(file) => {
                resolved.stat = Some(
                    self.0
                        .io
                        .stat(file.clone(), request)
                        .await
                        .map_err(status)?,
                );
                resolved.file = Some(file);
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                resolved.file = None;
                resolved.stat = None;
            }
            Err(error) => return Err(status(error)),
        }
        Ok(())
    }

    async fn same_entry(&self, record: &Record, request: &RequestContext) -> Result<bool, Status> {
        let file = match self
            .0
            .io
            .open(
                record.location.parent.clone(),
                record.location.name.clone(),
                libc::O_PATH,
                0,
                request,
            )
            .await
        {
            Ok(file) => file,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(false),
            Err(error) => return Err(status(error)),
        };
        Ok(Key::of(&self.0.io.stat(file, request).await.map_err(status)?) == record.key)
    }

    /// Capture a configured host directory. Guest paths never become absolute host paths.
    pub async fn new(root: &Path, driver: Arc<dyn Driver>) -> Result<Self, OpenRootError> {
        Self::new_inner(root, driver, None).await
    }

    /// Software caching requires all mutations and SMB paths to use this instance.
    /// The host must not modify the backing files outside this SMB service.
    pub async fn new_with_software_caching(
        root: &Path,
        driver: Arc<dyn Driver>,
    ) -> Result<Self, OpenRootError> {
        Self::new_inner(root, driver, Some(MediatedCaching::default())).await
    }

    async fn new_inner(
        root: &Path,
        driver: Arc<dyn Driver>,
        caching: Option<MediatedCaching>,
    ) -> Result<Self, OpenRootError> {
        let io = Io::new(driver, 4)?;
        let name = CString::new(root.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in export path")
        })?;
        let request = RequestContext::new(0);
        let root = io.open_root(name, &request).await?;
        Ok(Self(Arc::new(Inner {
            io,
            root,
            state: Mutex::new(State {
                next: 1,
                ..State::default()
            }),
            changed: Event::new(),
            locks: SoftwareLocks::default(),
            security: share_security(),
            caching,
        })))
    }

    fn stable_identity(&self, key: Key) -> Result<u64, Status> {
        let mut state = self.0.state.lock();
        if let Some(id) = state.identities.get(&key) {
            return Ok(*id);
        }
        if state.identities.len() == IDENTITY_LIMIT {
            return Err(Status::INSUFFICIENT_RESOURCES);
        }
        let id = state.next;
        state.next = id.checked_add(1).ok_or(Status::INSUFFICIENT_RESOURCES)?;
        state.identities.insert(key, id);
        Ok(id)
    }

    async fn caching_open_admission(
        &self,
        name: &str,
        options: OpenOptions<'_>,
        requested: CachingRequest,
        request: &RequestContext,
    ) -> Result<Option<NamespaceAdmission>, OpenError> {
        let Some(cache) = &self.0.caching else {
            return Ok(None);
        };
        loop {
            let admission = cache.namespace(request).await?;
            let admitted = admission.request(request);
            let resolved = self
                .resolve(name, options.options().open_reparse_point(), &admitted)
                .await?;
            let key = resolved
                .stat
                .as_ref()
                .map(|stat| {
                    self.stable_identity(Key::of(stat))
                        .map(|file| CachingKey { file, stream: 0 })
                })
                .transpose()?;
            if let (Some(key), Some(stat)) = (key, resolved.stat.as_ref()) {
                let access = if options.access().maximum_allowed() {
                    AccessMask::FILE_ALL_ACCESS.into_bits()
                } else {
                    map_access(options.access)
                };
                let sharing = self.0.state.lock().opens.values().any(|open| {
                    open.key == Key::of(stat)
                        && sharing_conflict(access, options.share_access, open.access, open.sharing)
                });
                if sharing {
                    if let Some(wait) = admission.prepare_sharing(key, requested)? {
                        drop(admitted);
                        drop(admission);
                        wait.wait(request).await?;
                        continue;
                    }
                }
            }
            let replacement = matches!(
                options.disposition(),
                CreateDisposition::SUPERSEDE
                    | CreateDisposition::OVERWRITE
                    | CreateDisposition::OVERWRITE_IF
            );
            if let Some(wait) = admission.prepare_open(
                key,
                map_access(options.access),
                replacement,
                options.options().delete_on_close(),
                requested,
            )? {
                drop(admitted);
                drop(admission);
                wait.wait(request).await?;
                continue;
            }
            return Ok(Some(admission));
        }
    }

    async fn namespace_request(
        &self,
        file: &LinuxFile,
        request: &RequestContext,
    ) -> Result<RequestContext, Status> {
        match (&self.0.caching, &file.caching) {
            (Some(store), Some(owner)) => store.namespace_request(owner, request).await,
            (None, Some(_)) => Err(Status::FILE_CLOSED),
            _ => Ok(request.clone()),
        }
    }

    async fn resolve(
        &self,
        name: &str,
        reparse_leaf: bool,
        request: &RequestContext,
    ) -> Result<Resolved, OpenError> {
        let name = match name.find(':') {
            Some(index) if name[index..].eq_ignore_ascii_case("::$DATA") => &name[..index],
            Some(_) => return Err(Status::NOT_SUPPORTED.into()),
            None => name,
        };
        let parts: Vec<_> = name.split('\\').filter(|part| !part.is_empty()).collect();
        let root_stat = self
            .0
            .io
            .stat(self.0.root.clone(), request)
            .await
            .map_err(status)?;
        let mut stack = vec![(self.0.root.clone(), root_stat, String::new())];
        let mut consumed = 0;
        for (index, part) in parts.iter().enumerate() {
            consumed += name[consumed..].find(part).ok_or(Status::INTERNAL_ERROR)? + part.len();
            if *part == "." {
                continue;
            }
            if *part == ".." {
                if stack.len() > 1 {
                    stack.pop();
                }
                continue;
            }
            let (parent, parent_stat, path) = stack.last().expect("root frame remains");
            let native = names::component(part)?;
            let path = if path.is_empty() {
                (*part).to_owned()
            } else {
                format!("{path}\\{part}")
            };
            let location = Location {
                parent: parent.clone(),
                parent_key: Key::of(parent_stat),
                name: native.clone(),
                path,
            };
            if self
                .0
                .state
                .lock()
                .deletes
                .contains_key(&location.identity())
            {
                return Err(Status::DELETE_PENDING.into());
            }
            let leaf = index + 1 == parts.len();
            let file = match self
                .0
                .io
                .open(parent.clone(), native, libc::O_PATH, 0, request)
                .await
            {
                Ok(file) => file,
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) && leaf => {
                    return Ok(Resolved {
                        file: None,
                        stat: None,
                        location,
                    });
                }
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                    return Err(Status::OBJECT_PATH_NOT_FOUND.into());
                }
                Err(error) => return Err(status(error).into()),
            };
            let stat = self
                .0
                .io
                .stat(file.clone(), request)
                .await
                .map_err(status)?;
            if kind(&stat) == libc::S_IFLNK && !(leaf && reparse_leaf) {
                let target = self.0.io.readlink(file, request).await.map_err(status)?;
                let target =
                    std::str::from_utf8(&target).map_err(|_| Status::OBJECT_NAME_INVALID)?;
                if target.starts_with('/') {
                    return Err(Status::NOT_SUPPORTED.into());
                }
                let target = names::target(target);
                return Err(OpenError::SymbolicLink(SymbolicLink {
                    substitute_name: target.clone(),
                    print_name: target,
                    relative: true,
                    unparsed_suffix: name[consumed..].to_owned(),
                }));
            }
            if leaf {
                return Ok(Resolved {
                    file: Some(file),
                    stat: Some(stat),
                    location,
                });
            }
            if kind(&stat) != libc::S_IFDIR {
                return Err(Status::NOT_A_DIRECTORY.into());
            }
            stack.push((file, stat, location.path));
        }
        let (file, stat, path) = stack.pop().expect("root frame remains");
        Ok(Resolved {
            file: Some(file.clone()),
            stat: Some(stat),
            location: Location {
                parent: file,
                parent_key: Key::of(&stat),
                name: c".".to_owned(),
                path,
            },
        })
    }

    fn reserve(
        &self,
        key: Key,
        location: Location,
        access: u32,
        options: OpenOptions<'_>,
        directory: bool,
        reparse: bool,
    ) -> Result<Reservation, Status> {
        let mut state = self.0.state.lock();
        if state.opens.len() == OPEN_LIMIT {
            return Err(Status::INSUFFICIENT_RESOURCES);
        }
        if state.deletes.contains_key(&location.identity()) {
            return Err(Status::DELETE_PENDING);
        }
        for other in state.opens.values().filter(|open| open.key == key) {
            if sharing_conflict(access, options.share_access, other.access, other.sharing) {
                return Err(Status::SHARING_VIOLATION);
            }
        }
        let id = state.next;
        state.next = id.checked_add(1).ok_or(Status::INSUFFICIENT_RESOURCES)?;
        state.opens.insert(
            id,
            Record {
                key,
                access,
                sharing: options.share_access,
                location,
                directory,
                reparse,
                write_through: options.options().write_through(),
                watch: None,
                notify_deleted: directory && options.options().delete_on_close(),
                closing: false,
                delete_on_close: options.options().delete_on_close(),
                locks: self.0.locks.open(key)?,
            },
        );
        Ok(Reservation {
            inner: self.0.clone(),
            id,
        })
    }

    fn record(&self, file: &LinuxFile) -> Result<Record, Status> {
        if !Arc::ptr_eq(&self.0, &file.reservation.inner) || file.closed.load(Ordering::Acquire) {
            return Err(Status::FILE_CLOSED);
        }
        self.0
            .state
            .lock()
            .opens
            .get(&file.reservation.id)
            .cloned()
            .ok_or(Status::FILE_CLOSED)
    }

    fn data(file: &LinuxFile) -> Result<Arc<File>, Status> {
        file.file.lock().clone().ok_or(Status::FILE_CLOSED)
    }

    async fn operation(
        &self,
        file: &LinuxFile,
        range: ByteRange,
        write: bool,
        eof: bool,
        request: &RequestContext,
    ) -> Result<SoftwareIo<Key>, Status> {
        let open = self.record(file)?;
        crate::io::check(request).map_err(status)?;
        if open.closing {
            return Err(Status::FILE_CLOSED);
        }
        if open.directory {
            return Err(Status::FILE_IS_A_DIRECTORY);
        }
        if open.reparse {
            return Err(Status::INVALID_DEVICE_REQUEST);
        }
        let access = AccessMask::from_bits(open.access);
        if if write {
            !(access.write_data() || access.append_data())
        } else {
            !(access.read_data() || access.execute())
        } {
            return Err(Status::ACCESS_DENIED);
        }
        open.locks.operation(range, write, eof, request).await
    }

    async fn describe(
        &self,
        file: Arc<File>,
        location: &Location,
        access: u32,
        delete_pending: bool,
        request: &RequestContext,
    ) -> Result<Metadata, Status> {
        let stat = self.0.io.stat(file, request).await.map_err(status)?;
        let key = Key::of(&stat);
        let id = self.stable_identity(key)?;
        let symlink = kind(&stat) == libc::S_IFLNK;
        let directory = kind(&stat) == libc::S_IFDIR
            || (symlink && !location.path.is_empty() && {
                let path = location
                    .path
                    .split('\\')
                    .map(names::component)
                    .collect::<Result<Vec<_>, _>>()?;
                let path = path
                    .iter()
                    .map(|part| part.to_bytes())
                    .collect::<Vec<_>>()
                    .join(&b'/');
                let path = CString::new(path).map_err(|_| Status::OBJECT_NAME_INVALID)?;
                self.0
                    .io
                    .directory_hint(self.0.root.clone(), path, request)
                    .await
                    .map_err(status)?
            });
        let attributes = FileAttributes::new()
            .with_directory(directory)
            .with_reparse_point(symlink)
            .with_readonly(stat.stx_mode & 0o222 == 0)
            .into_bits();
        let mut id128 = [0; 16];
        id128[..8].copy_from_slice(&key.device.to_le_bytes());
        id128[8..].copy_from_slice(&key.inode.to_le_bytes());
        Ok(Metadata {
            stream_name: None,
            id,
            id128: Some(id128),
            name: location.path.rsplit('\\').next().unwrap_or("").to_owned(),
            path: format!("\\{}", location.path),
            short_name: None,
            attributes: if attributes == 0 {
                FileAttributes::new().with_normal(true).into_bits()
            } else {
                attributes
            },
            reparse_tag: if symlink { IO_REPARSE_TAG_SYMLINK } else { 0 },
            created: if stat.stx_mask & libc::STATX_BTIME != 0 {
                nt_time(stat.stx_btime)
            } else {
                0
            },
            accessed: nt_time(stat.stx_atime),
            written: nt_time(stat.stx_mtime),
            changed: nt_time(stat.stx_ctime),
            size: if directory { 0 } else { stat.stx_size },
            allocation_size: stat.stx_blocks.saturating_mul(512),
            compression: None,
            number_of_links: stat.stx_nlink,
            extended_attributes_length: 0,
            alignment_requirement: 0,
            delete_pending,
            maximal_access: AccessMask::FILE_ALL_ACCESS.into_bits(),
            granted_access: access,
        })
    }
}

impl Inspect for LinuxFs {
    fn inspect(&self, req: inspect::Request<'_>) {
        let state = self.0.state.lock();
        req.respond()
            .field("opens", state.opens.len())
            .field("software_caching", &self.0.caching)
            .field("lock_count", self.0.locks.lock_count())
            .field("lock_waiters", self.0.locks.waiter_count())
            .field(
                "watch_count",
                state
                    .opens
                    .values()
                    .filter(|open| open.watch.as_ref().and_then(Weak::upgrade).is_some())
                    .count(),
            )
            .field(
                "notify_waiters",
                state
                    .opens
                    .values()
                    .filter_map(|open| open.watch.as_ref().and_then(Weak::upgrade))
                    .map(|watch| watch.waiter_count())
                    .sum::<usize>(),
            )
            .field("active_io", self.0.locks.active_count())
            .field("identities", state.identities.len())
            .field("submitted_io", self.0.io.submitted.load(Ordering::Relaxed));
    }
}

#[async_trait]
impl FileSystem for LinuxFs {
    type File = LinuxFile;

    fn supports_leases(&self) -> bool {
        self.0.caching.is_some()
    }

    fn lock_request<'a>(&'a self, file: &'a LinuxFile) -> Box<dyn LockScope + 'a> {
        if self.0.caching.is_none() {
            return smb::provider::locking::with_ids(self, file);
        }
        let owner = self.record(file).and_then(|record| {
            if record.closing {
                Err(Status::FILE_CLOSED)
            } else if record.directory {
                Err(Status::INVALID_PARAMETER)
            } else {
                Ok(record.locks)
            }
        });
        let scope = smb::provider::locking::software::scope(owner);
        match &file.caching {
            Some(owner) => owner.lock_scope(scope),
            None => scope,
        }
    }

    async fn open(
        &self,
        name: &str,
        options: OpenOptions<'_>,
        request: &RequestContext,
    ) -> Result<(LinuxFile, u32), Status> {
        self.open_with_reparse(name, options, request)
            .await
            .map_err(|error| error.status())
    }

    async fn open_with_reparse(
        &self,
        name: &str,
        options: OpenOptions<'_>,
        request: &RequestContext,
    ) -> Result<(LinuxFile, u32), OpenError> {
        let opened = self
            .open_with_caching(name, options, CachingRequest::None, request)
            .await?;
        Ok((opened.file, opened.action))
    }

    async fn open_with_caching(
        &self,
        name: &str,
        options: OpenOptions<'_>,
        requested: CachingRequest,
        request: &RequestContext,
    ) -> Result<Opened<LinuxFile>, OpenError> {
        let admission = self
            .caching_open_admission(name, options, requested, request)
            .await?;
        let admitted = match &admission {
            Some(admission) => admission.request(request),
            None => request.clone(),
        };
        let request = &admitted;
        let disposition = options.disposition();
        if disposition.0 > CreateDisposition::OVERWRITE_IF.0 {
            return Err(Status::INVALID_PARAMETER.into());
        }
        let mut resolved = self
            .resolve(name, options.options().open_reparse_point(), request)
            .await?;
        let _claim = self
            .claim(
                &[ClaimKey::Name(
                    resolved.location.parent_key,
                    resolved.location.name.clone(),
                )],
                true,
                request,
            )
            .await?;
        self.refresh(&mut resolved, request).await?;
        if resolved
            .stat
            .as_ref()
            .is_some_and(|stat| kind(stat) == libc::S_IFLNK)
            && !options.options().open_reparse_point()
        {
            let target = self
                .0
                .io
                .readlink(
                    resolved.file.take().expect("stat and file are paired"),
                    request,
                )
                .await
                .map_err(status)?;
            let target = std::str::from_utf8(&target).map_err(|_| Status::OBJECT_NAME_INVALID)?;
            if target.starts_with('/') {
                return Err(Status::NOT_SUPPORTED.into());
            }
            let target = names::target(target);
            return Err(OpenError::SymbolicLink(SymbolicLink {
                substitute_name: target.clone(),
                print_name: target,
                relative: true,
                unparsed_suffix: String::new(),
            }));
        }
        let exists = resolved.file.is_some();
        if exists && disposition == CreateDisposition::CREATE {
            return Err(Status::OBJECT_NAME_COLLISION.into());
        }
        if !exists
            && matches!(
                disposition,
                CreateDisposition::OPEN | CreateDisposition::OVERWRITE
            )
        {
            return Err(Status::OBJECT_NAME_NOT_FOUND.into());
        }
        if !exists && (options.security.is_some() || options.extended_attributes.is_some()) {
            return Err(Status::NOT_SUPPORTED.into());
        }
        let supported_attributes = FileAttributes::new()
            .with_normal(true)
            .with_archive(true)
            .with_directory(true)
            .into_bits();
        if !exists && options.attributes & !supported_attributes != 0 {
            return Err(Status::NOT_SUPPORTED.into());
        }
        let mut access = map_access(options.access);
        if AccessMask::from_bits(access).maximum_allowed() {
            access = AccessMask::FILE_ALL_ACCESS.into_bits();
            if let Some(pin) = &resolved.file {
                let (read, write, execute) = self
                    .0
                    .io
                    .permissions(pin.clone(), request)
                    .await
                    .map_err(status)?;
                let (_, parent_write, parent_execute) = self
                    .0
                    .io
                    .permissions(resolved.location.parent.clone(), request)
                    .await
                    .map_err(status)?;
                let directory = resolved
                    .stat
                    .as_ref()
                    .is_some_and(|stat| kind(stat) == libc::S_IFDIR);
                access = AccessMask::from_bits(access)
                    .with_read_data(read)
                    .with_execute(if directory { execute } else { read })
                    .with_write_data(write && (!directory || execute))
                    .with_append_data(write && (!directory || execute))
                    .with_delete(parent_write && parent_execute)
                    .into_bits();
            }
        }
        if options.options().delete_on_close() && !AccessMask::from_bits(access).delete() {
            return Err(Status::ACCESS_DENIED.into());
        }
        let truncated = exists
            && matches!(
                disposition,
                CreateDisposition::OVERWRITE
                    | CreateDisposition::OVERWRITE_IF
                    | CreateDisposition::SUPERSEDE
            );
        if truncated && !AccessMask::from_bits(access).write_data() {
            return Err(Status::ACCESS_DENIED.into());
        }
        let directory = resolved
            .stat
            .as_ref()
            .map_or(options.options().directory_file(), |stat| {
                kind(stat) == libc::S_IFDIR
            })
            || if resolved
                .stat
                .as_ref()
                .is_some_and(|stat| kind(stat) == libc::S_IFLNK)
            {
                self.describe(
                    resolved.file.clone().expect("stat and file are paired"),
                    &resolved.location,
                    access,
                    false,
                    request,
                )
                .await?
                .is_directory()
            } else {
                false
            };
        if directory && options.options().non_directory_file() {
            return Err(Status::FILE_IS_A_DIRECTORY.into());
        }
        if !directory && options.options().directory_file() {
            return Err(Status::NOT_A_DIRECTORY.into());
        }
        if directory && truncated {
            return Err(Status::INVALID_PARAMETER.into());
        }
        let mut flags = match (
            AccessMask::from_bits(access).read_data() || AccessMask::from_bits(access).execute(),
            AccessMask::from_bits(access).write_data()
                || AccessMask::from_bits(access).append_data(),
        ) {
            (true, true) => libc::O_RDWR,
            (false, true) => libc::O_WRONLY,
            (true, false) => libc::O_RDONLY,
            (false, false) => libc::O_PATH,
        };
        if options.options().write_through() && flags != libc::O_PATH {
            flags |= libc::O_DSYNC;
        }
        if AccessMask::from_bits(access).append_data()
            && !AccessMask::from_bits(access).write_data()
        {
            flags |= libc::O_APPEND;
        }
        let committed = RequestContext::new(request.id()).with_keepalive(request.clone());
        let continuation = if exists { request } else { &committed };
        let location = resolved.location;
        if options.options().delete_on_close() && location.path.is_empty() {
            return Err(Status::CANNOT_DELETE.into());
        }
        let pin = match resolved.file {
            Some(file) => file,
            None if directory => {
                self.0
                    .io
                    .mkdir(location.parent.clone(), location.name.clone(), request)
                    .await
                    .map_err(status)?;
                self.0
                    .io
                    .open(
                        location.parent.clone(),
                        location.name.clone(),
                        libc::O_PATH,
                        0,
                        continuation,
                    )
                    .await
                    .map_err(status)?
            }
            None => self
                .0
                .io
                .open(
                    location.parent.clone(),
                    location.name.clone(),
                    if flags & libc::O_PATH != 0 {
                        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL
                    } else {
                        flags | libc::O_CREAT | libc::O_EXCL
                    },
                    0o666,
                    request,
                )
                .await
                .map_err(status)?,
        };
        let stat = self
            .0
            .io
            .stat(pin.clone(), continuation)
            .await
            .map_err(status)?;
        if !matches!(kind(&stat), libc::S_IFREG | libc::S_IFDIR | libc::S_IFLNK) {
            return Err(Status::NOT_SUPPORTED.into());
        }
        let key = Key::of(&stat);
        let reservation = self.reserve(
            key,
            location,
            access,
            options,
            kind(&stat) == libc::S_IFDIR,
            kind(&stat) == libc::S_IFLNK,
        )?;
        let native =
            if directory || kind(&stat) == libc::S_IFLNK || flags & libc::O_PATH != 0 || !exists {
                pin.clone()
            } else {
                self.0
                    .io
                    .reopen(pin.clone(), flags, request)
                    .await
                    .map_err(status)?
            };
        let mut file = LinuxFile {
            reservation,
            file: Mutex::new(Some(native)),
            pin: Mutex::new(Some(pin)),
            key,
            closed: AtomicBool::new(false),
            watch: futures::lock::Mutex::new(None),
            caching: None,
        };
        if truncated {
            self.set_len(&file, 0, request).await?;
        }
        let action = if !exists {
            CreateAction::CREATED.0
        } else if truncated {
            if disposition == CreateDisposition::SUPERSEDE {
                CreateAction::SUPERSEDED.0
            } else {
                CreateAction::OVERWRITTEN.0
            }
        } else {
            CreateAction::OPENED.0
        };
        let caching = if let Some(admission) = admission {
            let metadata = match self.metadata(&file, request).await {
                Ok(metadata) => metadata,
                Err(status) => {
                    self.close(
                        &file,
                        &RequestContext::new(request.id()).with_keepalive(request.clone()),
                    )
                    .await?;
                    return Err(status.into());
                }
            };
            let registered = admission.register(
                CachingKey {
                    file: metadata.id,
                    stream: 0,
                },
                metadata.granted_access,
                !metadata.is_directory() && !metadata.attributes().reparse_point(),
                options.options().delete_on_close(),
                requested,
            );
            let (owner, grant) = match registered {
                Ok(result) => result,
                Err(status) => {
                    self.close(
                        &file,
                        &RequestContext::new(request.id()).with_keepalive(request.clone()),
                    )
                    .await?;
                    return Err(status.into());
                }
            };
            file.caching = Some(owner);
            grant
        } else {
            CachingGrant::None
        };
        Ok(Opened {
            file,
            action,
            caching,
        })
    }

    async fn close(&self, file: &LinuxFile, original: &RequestContext) -> Result<(), Status> {
        if !Arc::ptr_eq(&self.0, &file.reservation.inner) {
            return Err(Status::FILE_CLOSED);
        }
        if file.closed.load(Ordering::Acquire) {
            if let Some(owner) = &file.caching {
                owner.close();
            }
            return Ok(());
        }
        let cleanup = RequestContext::new(original.id()).with_keepalive(original.clone());
        let request = if file
            .caching
            .as_ref()
            .is_some_and(|owner| owner.is_deleting())
        {
            self.namespace_request(file, &cleanup).await?
        } else {
            file.retain_caching(&cleanup)
        };
        let _closing = Closing {
            inner: self.0.clone(),
            id: file.reservation.id,
            locks: self.record(file)?.locks,
        };
        {
            let mut state = self.0.state.lock();
            state
                .opens
                .get_mut(&file.reservation.id)
                .ok_or(Status::FILE_CLOSED)?
                .closing = true;
            _closing.locks.start_close()?;
        }
        _closing.locks.drain().await;
        let _node = self
            .claim(&[ClaimKey::Node(file.key)], false, &request)
            .await?;
        let record = self.record(file)?;
        let _name = self
            .claim(
                &[ClaimKey::Name(
                    record.location.parent_key,
                    record.location.name.clone(),
                )],
                false,
                &request,
            )
            .await?;
        let deferred_delete = record.delete_on_close
            && (!record.directory
                || self
                    .0
                    .io
                    .list(file.pin()?, &request)
                    .await
                    .map_err(status)?
                    .is_empty());
        let delete = {
            let mut state = self.0.state.lock();
            if deferred_delete {
                state.deletes.insert(record.location.identity(), file.key);
            }
            state.deletes.contains_key(&record.location.identity())
                && !state.opens.iter().any(|(&id, open)| {
                    id != file.reservation.id
                        && open.location.identity() == record.location.identity()
                })
        };
        if deferred_delete && record.directory {
            self.invalidate_watches(file.key);
        }
        if delete && self.same_entry(&record, &request).await? {
            match self
                .0
                .io
                .unlink(
                    record.location.parent.clone(),
                    record.location.name.clone(),
                    record.directory,
                    &request,
                )
                .await
            {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                Err(error) => return Err(status(error)),
            }
        }
        if let Some(watch) = file.watch.lock().await.take() {
            watch.shutdown(&self.0.io).await?;
        }
        let native = file.file.lock().take();
        let pin = file.pin.lock().take();
        let data_result = match native {
            Some(native) => self.0.io.close(native).await.map_err(status),
            None => Ok(()),
        };
        let pin_result = match pin {
            Some(pin) => self.0.io.close(pin).await.map_err(status),
            None => Ok(()),
        };
        file.closed.store(true, Ordering::Release);
        _closing.locks.close();
        self.0.release(file.reservation.id);
        if let Some(owner) = &file.caching {
            owner.close();
        }
        if let Err(error) = data_result {
            tracelimit::warn_ratelimited!(?error, "Linux SMB data descriptor close failed");
        }
        if let Err(error) = pin_result {
            tracelimit::warn_ratelimited!(?error, "Linux SMB metadata descriptor close failed");
        }
        data_result.and(pin_result)
    }

    async fn metadata(
        &self,
        file: &LinuxFile,
        request: &RequestContext,
    ) -> Result<Metadata, Status> {
        let admitted = file.retain_caching(request);
        let request = &admitted;
        let record = self.record(file)?;
        let deleted = self
            .0
            .state
            .lock()
            .deletes
            .contains_key(&record.location.identity());
        self.describe(
            file.pin()?,
            &record.location,
            record.access,
            deleted,
            request,
        )
        .await
    }

    async fn read(
        &self,
        file: &LinuxFile,
        offset: u64,
        length: usize,
        request: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        let admitted = file.retain_caching(request);
        let request = &admitted;
        if offset > i64::MAX as u64
            || length > smb::MAX_TRANSFER_SIZE
            || offset
                .checked_add(length as u64)
                .is_none_or(|end| end > i64::MAX as u64)
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let operation = self
            .operation(
                file,
                ByteRange {
                    offset,
                    length: length as u64,
                },
                false,
                false,
                request,
            )
            .await?;
        self.0
            .io
            .read(Self::data(file)?, offset, length as u32, operation, request)
            .await
            .map_err(status)
    }

    async fn write(
        &self,
        file: &LinuxFile,
        offset: u64,
        data: &[u8],
        request: &RequestContext,
    ) -> Result<usize, Status> {
        let admitted = file.caching_request(CacheChange::Data, request).await?;
        let request = &admitted;
        if offset > i64::MAX as u64
            || data.len() > smb::MAX_TRANSFER_SIZE
            || offset
                .checked_add(data.len() as u64)
                .is_none_or(|end| end > i64::MAX as u64)
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let record = self.record(file)?;
        let append = AccessMask::from_bits(record.access).append_data()
            && !AccessMask::from_bits(record.access).write_data();
        let range = if append && !data.is_empty() {
            ByteRange {
                offset: 0,
                length: i64::MAX as u64,
            }
        } else {
            ByteRange {
                offset,
                length: data.len() as u64,
            }
        };
        let operation = self
            .operation(file, range, true, append && !data.is_empty(), request)
            .await?;
        if append && !data.is_empty() {
            let size = self
                .0
                .io
                .stat(file.pin()?, request)
                .await
                .map_err(status)?
                .stx_size;
            if size
                .checked_add(data.len() as u64)
                .is_none_or(|end| end > i64::MAX as u64)
            {
                return Err(Status::INVALID_PARAMETER);
            }
            operation.set_range(ByteRange {
                offset: size,
                length: data.len() as u64,
            })?;
        }
        self.0
            .io
            .write(Self::data(file)?, offset, data.to_vec(), operation, request)
            .await
            .map_err(status)
    }

    async fn flush(&self, file: &LinuxFile, request: &RequestContext) -> Result<(), Status> {
        let admitted = file.retain_caching(request);
        let request = &admitted;
        let record = self.record(file)?;
        if record.reparse {
            return Err(Status::INVALID_DEVICE_REQUEST);
        }
        let access = AccessMask::from_bits(record.access);
        if record.directory
            || !(access.read_data()
                || access.execute()
                || access.write_data()
                || access.append_data())
        {
            return Err(Status::NOT_SUPPORTED);
        }
        // A WRITE may share this context after its bytes have already committed.
        let committed = RequestContext::new(request.id()).with_keepalive(request.clone());
        self.0
            .io
            .flush(Self::data(file)?, &committed)
            .await
            .map_err(status)
    }

    async fn list(
        &self,
        file: &LinuxFile,
        request: &RequestContext,
    ) -> Result<Vec<Metadata>, Status> {
        let admitted = file.retain_caching(request);
        let request = &admitted;
        let record = self.record(file)?;
        if !record.directory {
            return Err(Status::NOT_A_DIRECTORY);
        }
        let mut entries = Vec::new();
        for name in self.0.io.list(file.pin()?, request).await.map_err(status)? {
            let text = match name.to_str() {
                Ok(text) => text,
                Err(error) => {
                    tracelimit::warn_ratelimited!(error = ?error, "omitting non-UTF-8 SMB directory entry");
                    continue;
                }
            };
            let pin = match self
                .0
                .io
                .open(file.pin()?, name.clone(), libc::O_PATH, 0, request)
                .await
            {
                Ok(pin) => pin,
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(error) => return Err(status(error)),
            };
            let stat = self.0.io.stat(pin.clone(), request).await.map_err(status)?;
            if !matches!(kind(&stat), libc::S_IFREG | libc::S_IFDIR | libc::S_IFLNK) {
                tracelimit::warn_ratelimited!(
                    kind = kind(&stat),
                    "omitting unsupported Linux object from SMB directory listing"
                );
                continue;
            }
            let projected = names::project(text);
            let path = if record.location.path.is_empty() {
                projected
            } else {
                format!("{}\\{projected}", record.location.path)
            };
            let location = Location {
                parent: file.pin()?,
                parent_key: file.key,
                name,
                path,
            };
            if self
                .0
                .state
                .lock()
                .deletes
                .contains_key(&location.identity())
            {
                continue;
            }
            let metadata = self.describe(pin, &location, 0, false, request).await?;
            entries.push(metadata);
        }
        Ok(entries)
    }

    async fn set_len(
        &self,
        file: &LinuxFile,
        length: u64,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let admitted = file.caching_request(CacheChange::Data, request).await?;
        let request = &admitted;
        if length > i64::MAX as u64 {
            return Err(Status::INVALID_PARAMETER);
        }
        if !AccessMask::from_bits(self.record(file)?.access).write_data() {
            return Err(Status::ACCESS_DENIED);
        }
        let operation = self
            .operation(
                file,
                ByteRange {
                    offset: 0,
                    length: i64::MAX as u64,
                },
                true,
                true,
                request,
            )
            .await?;
        operation.set_range(ByteRange {
            offset: 0,
            length: i64::MAX as u64,
        })?;
        let operation = Arc::new(operation);
        self.0
            .io
            .truncate(Self::data(file)?, length, operation.clone(), request)
            .await
            .map_err(status)?;
        if self.record(file)?.write_through {
            self.flush(file, request).await?;
        }
        Ok(())
    }

    async fn set_delete_on_close(
        &self,
        file: &LinuxFile,
        delete: bool,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let admitted = self.namespace_request(file, request).await?;
        let request = &admitted;
        crate::io::check(request).map_err(status)?;
        let record = self.record(file)?;
        if !AccessMask::from_bits(record.access).delete() {
            return Err(Status::ACCESS_DENIED);
        }
        if record.location.path.is_empty() {
            return Err(Status::CANNOT_DELETE);
        }
        if delete
            && record.directory
            && !self
                .0
                .io
                .list(file.pin()?, request)
                .await
                .map_err(status)?
                .is_empty()
        {
            return Err(Status::DIRECTORY_NOT_EMPTY);
        }
        let mut state = self.0.state.lock();
        if delete {
            if state.opens.iter().any(|(&id, open)| {
                id != file.reservation.id && open.key == file.key && open.sharing & 4 == 0
            }) {
                return Err(Status::SHARING_VIOLATION);
            }
            state.deletes.insert(record.location.identity(), file.key);
            if record.directory {
                state
                    .opens
                    .get_mut(&file.reservation.id)
                    .ok_or(Status::FILE_CLOSED)?
                    .notify_deleted = true;
            }
        } else {
            state.deletes.remove(&record.location.identity());
        }
        drop(state);
        if let Some(owner) = &file.caching {
            owner.set_deleting(delete)?;
        }
        if delete && record.directory {
            self.invalidate_watches(file.key);
        }
        Ok(())
    }

    async fn set_basic(
        &self,
        file: &LinuxFile,
        info: BasicInformation,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let admitted = file.caching_request(CacheChange::Metadata, request).await?;
        let request = &admitted;
        let record = self.record(file)?;
        if !AccessMask::from_bits(record.access).write_attributes() {
            return Err(Status::ACCESS_DENIED);
        }
        if info.created != 0 || info.changed != 0 || info.accessed < 0 || info.written < 0 {
            return Err(Status::NOT_SUPPORTED);
        }
        if info.attributes != 0 && info.attributes != self.metadata(file, request).await?.attributes
        {
            return Err(Status::NOT_SUPPORTED);
        }
        if info.accessed == 0 && info.written == 0 {
            return Ok(());
        }
        let access = AccessMask::from_bits(record.access);
        if record.write_through
            && (record.directory
                || record.reparse
                || !(access.read_data()
                    || access.execute()
                    || access.write_data()
                    || access.append_data()))
        {
            return Err(Status::NOT_SUPPORTED);
        }
        let time = |ticks: i64| libc::timespec {
            tv_sec: if ticks == 0 {
                0
            } else {
                ticks / 10_000_000 - NT_EPOCH
            },
            tv_nsec: if ticks == 0 {
                libc::UTIME_OMIT
            } else {
                (ticks % 10_000_000) * 100
            },
        };
        self.0
            .io
            .times(
                file.pin()?,
                [time(info.accessed), time(info.written)],
                request,
            )
            .await
            .map_err(status)?;
        if record.write_through {
            self.flush(file, request).await?;
        }
        Ok(())
    }

    async fn query_security(
        &self,
        file: &LinuxFile,
        information: SecurityInformation,
        _request: &RequestContext,
    ) -> Result<SecurityDescriptor, Status> {
        self.record(file)?;
        let mut result = self.0.security.clone();
        if !information.owner() {
            result.owner = None;
        }
        if !information.group() {
            result.group = None;
        }
        if !information.dacl() {
            result.dacl = AclState::Absent;
        }
        Ok(result)
    }

    async fn filesystem_information(
        &self,
        file: &LinuxFile,
        request: &RequestContext,
    ) -> Result<FileSystemInformation, Status> {
        let admitted = file.retain_caching(request);
        let request = &admitted;
        self.record(file)?;
        let stat = self
            .0
            .io
            .filesystem(file.pin()?, request)
            .await
            .map_err(status)?;
        let block = u32::try_from(if stat.f_frsize > 0 {
            stat.f_frsize
        } else {
            stat.f_bsize
        })
        .map_err(|_| Status::INVALID_PARAMETER)?;
        if block == 0 {
            return Err(Status::INVALID_PARAMETER);
        }
        Ok(FileSystemInformation {
            created: 0,
            serial: file.key.device as u32,
            label: "Linux".to_owned(),
            supports_objects: false,
            name: "Linux".to_owned(),
            attributes: 0x1 | 0x2 | 0x4,
            maximum_component_name_length: u32::try_from(stat.f_namelen)
                .map_err(|_| Status::INVALID_PARAMETER)?,
            device_type: 7,
            device_characteristics: 0,
            total_allocation_units: i64::try_from(stat.f_blocks)
                .map_err(|_| Status::INVALID_PARAMETER)?,
            caller_available_allocation_units: i64::try_from(stat.f_bavail)
                .map_err(|_| Status::INVALID_PARAMETER)?,
            actual_available_allocation_units: i64::try_from(stat.f_bfree)
                .map_err(|_| Status::INVALID_PARAMETER)?,
            // These scale native allocation units, not physical device geometry.
            sectors_per_allocation_unit: block,
            bytes_per_sector: 1,
            sector_size: None,
            object_information: None,
        })
    }

    async fn lock(
        &self,
        file: &LinuxFile,
        range: ByteRange,
        exclusive: bool,
        fail_immediately: bool,
        request: &RequestContext,
    ) -> Result<LockId, Status> {
        if self.0.caching.is_some() {
            return Err(Status::NOT_SUPPORTED);
        }
        range.validate()?;
        let open = self.record(file)?;
        crate::io::check(request).map_err(status)?;
        if open.closing {
            return Err(Status::FILE_CLOSED);
        }
        if open.directory {
            return Err(Status::INVALID_PARAMETER);
        }
        open.locks
            .lock(range, exclusive, fail_immediately, request)
            .await
    }

    async fn unlock(
        &self,
        file: &LinuxFile,
        range: ByteRange,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        if self.0.caching.is_some() {
            return Err(Status::NOT_SUPPORTED);
        }
        range.validate()?;
        self.record(file)?.locks.unlock(range)
    }

    async fn rollback_lock(
        &self,
        file: &LinuxFile,
        lock: LockId,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        if self.0.caching.is_some() {
            return Err(Status::NOT_SUPPORTED);
        }
        if !Arc::ptr_eq(&self.0, &file.reservation.inner) {
            return Err(Status::FILE_CLOSED);
        }
        if let Some(record) = self.0.state.lock().opens.get(&file.reservation.id) {
            record.locks.rollback(lock);
        }
        Ok(())
    }

    async fn notify(
        &self,
        file: &LinuxFile,
        filter: NotifyFilter,
        watch_tree: bool,
        output_length: usize,
        request: &RequestContext,
    ) -> Result<NotifyResult, Status> {
        let record = self.record(file)?;
        if record.closing {
            return Err(Status::FILE_CLOSED);
        }
        if !record.directory {
            return Err(Status::NOT_A_DIRECTORY);
        }
        if record.notify_deleted
            || self
                .0
                .state
                .lock()
                .deletes
                .contains_key(&record.location.identity())
        {
            return Err(Status::DELETE_PENDING);
        }
        let watch = {
            let mut slot = file.watch.lock().await;
            if slot.as_ref().is_none_or(|watch| watch.invalidated()) {
                *slot = Some(Watch::new(&self.0.io, file.pin()?, filter, watch_tree).await?);
            }
            slot.as_ref().expect("watch initialized").clone()
        };
        {
            let mut state = self.0.state.lock();
            let record = state
                .opens
                .get_mut(&file.reservation.id)
                .ok_or(Status::FILE_CLOSED)?;
            if record.closing {
                return Err(Status::FILE_CLOSED);
            }
            record.watch = Some(Arc::downgrade(&watch));
        }
        self.0.changed.notify(usize::MAX);
        let result = watch.notify(&self.0.io, output_length, request).await;
        if let Err(error) = watch.retire_if_idle(&self.0.io).await {
            tracelimit::warn_ratelimited!(?error, "retired Linux SMB watch close failed");
            if result.is_ok() {
                return Err(error);
            }
        }
        result
    }

    async fn file_control(
        &self,
        file: &LinuxFile,
        control: FileControl<'_>,
        request: &RequestContext,
    ) -> Result<FileControlResult, Status> {
        self.record(file)?;
        if !matches!(control, FileControl::GetReparsePoint { .. }) {
            return Err(Status::INVALID_DEVICE_REQUEST);
        }
        let pin = file.pin()?;
        if kind(&self.0.io.stat(pin.clone(), request).await.map_err(status)?) != libc::S_IFLNK {
            return Err(Status::NOT_A_REPARSE_POINT);
        }
        let target = self.0.io.readlink(pin, request).await.map_err(status)?;
        let target = std::str::from_utf8(&target).map_err(|_| Status::OBJECT_NAME_INVALID)?;
        let relative = !target.starts_with('/');
        let target: Vec<_> = names::target(target).encode_utf16().collect();
        let length =
            u16::try_from(target.len() * 2).map_err(|_| Status::IO_REPARSE_DATA_INVALID)?;
        let mut data = Vec::new();
        for value in [0, length, 0, length] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        data.extend_from_slice(&u32::from(relative).to_le_bytes());
        for value in &target {
            data.extend_from_slice(&value.to_le_bytes());
        }
        Ok(FileControlResult::ReparsePoint(ReparsePoint {
            tag: IO_REPARSE_TAG_SYMLINK,
            guid: None,
            data,
        }))
    }

    async fn rename(
        &self,
        file: &LinuxFile,
        name: &str,
        replace: bool,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let admitted = self.namespace_request(file, request).await?;
        let request = &admitted;
        let _node = self
            .claim(&[ClaimKey::Node(file.key)], false, request)
            .await?;
        let record = self.record(file)?;
        if !AccessMask::from_bits(record.access).delete() {
            return Err(Status::ACCESS_DENIED);
        }
        if record.location.path.is_empty() {
            return Err(Status::ACCESS_DENIED);
        }
        let mut destination = self
            .resolve(name, true, request)
            .await
            .map_err(|error| error.status())?;
        let _names = self
            .claim(
                &[
                    ClaimKey::Name(record.location.parent_key, record.location.name.clone()),
                    ClaimKey::Name(
                        destination.location.parent_key,
                        destination.location.name.clone(),
                    ),
                ],
                false,
                request,
            )
            .await?;
        if !self.same_entry(&record, request).await? {
            return Err(Status::OBJECT_NAME_NOT_FOUND);
        }
        self.refresh(&mut destination, request).await?;
        if destination.location.identity() == record.location.identity() {
            return Ok(());
        }
        if let Some(stat) = destination.stat {
            let key = Key::of(&stat);
            if self
                .0
                .state
                .lock()
                .opens
                .values()
                .any(|open| open.key == key)
            {
                return Err(Status::ACCESS_DENIED);
            }
        }
        if record.directory
            && self.0.state.lock().opens.values().any(|open| {
                open.location
                    .path
                    .starts_with(&format!("{}\\", record.location.path))
            })
        {
            return Err(Status::ACCESS_DENIED);
        }
        self.0
            .io
            .rename(
                (record.location.parent.clone(), record.location.name.clone()),
                (
                    destination.location.parent.clone(),
                    destination.location.name.clone(),
                ),
                replace,
                request,
            )
            .await
            .map_err(status)?;
        let mut state = self.0.state.lock();
        for open in state
            .opens
            .values_mut()
            .filter(|open| open.location.identity() == record.location.identity())
        {
            open.location = destination.location.clone();
        }
        if let Some(key) = state.deletes.remove(&record.location.identity()) {
            state.deletes.insert(destination.location.identity(), key);
        }
        Ok(())
    }
}
