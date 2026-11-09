// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::io::{Io, check};
use crate::native::{self, Create};
use crate::notify::Watch;
use async_trait::async_trait;
use futures::FutureExt;
use inspect::Inspect;
use pal_async::driver::Driver;
use pal_async::windows::overlapped::OverlappedFile;
use parking_lot::Mutex;
use smb::provider::{
    BasicInformation, FileSystem, FileSystemInformation, Metadata, NotifyResult, OpenOptions,
    RequestContext, map_access,
};
use smb::security::SecurityDescriptor;
use smb::spec::{
    AccessMask, CreateAction, CreateDisposition, NotifyFilter, SecurityInformation, Status,
};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use windows_sys::Wdk::Storage::FileSystem as nt;
use windows_sys::Win32::Storage::FileSystem as fs;

const OPEN_LIMIT: usize = 4096;
const IO_LIMIT: usize = 1024 * 1024;

/// Failure to capture a supported, case-insensitive local NTFS export root.
#[derive(Debug, thiserror::Error)]
#[error("cannot initialize Windows SMB filesystem: {0:?}")]
pub struct OpenRootError(Status);

/// A VM-independent, process-identity Windows filesystem with no caching grants.
///
/// Every intermediate directory is retained during resolution. An object
/// already opened remains a capability if a host application later moves it.
/// Host hard links are not confined by pathname containment.
/// Traversed directories require attribute-query access to enforce the initial
/// exclusion of case-sensitive directories.
///
/// EXECUTE requests also require native READ_DATA so SMB can load executable
/// contents. That additional physical right is not a guest-visible data/list
/// grant; the host ACL must permit it.
///
/// Metadata follows native names within the captured root. Name queries on
/// objects subsequently moved outside that root fail explicitly.
///
/// MAXIMUM_ALLOWED uses the native open's access decision. In particular,
/// Windows can accept explicit DELETE_CHILD together with MAXIMUM_ALLOWED on
/// a readonly file, unlike MS-FSA 2.1.5.1.2.1. Rechecking attributes after open
/// would race with external host changes and require extra query permissions.
///
/// Notifications retain the first registration's filter and scope across guest
/// cancellations. Once deletion invalidates a registration, watching again
/// requires a fresh directory open, even if delete disposition is cleared.
pub struct WindowsFs(Arc<Inner>);

struct Inner {
    io: Io,
    root: Arc<File>,
    opens: AtomicUsize,
    watches: Mutex<HashMap<u64, Vec<Weak<Watch>>>>,
}

struct Reservation(Arc<Inner>);

impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.opens.fetch_sub(1, Ordering::Relaxed);
    }
}

/// An independent native open; closing it releases native sharing reservations.
pub struct WindowsFile {
    file: Mutex<Option<Open>>,
    append_only: bool,
    hidden_access: u32,
    watch: Arc<futures::lock::Mutex<Option<Arc<Watch>>>>,
}

struct Open {
    file: Arc<NativeFile>,
    _reservation: Reservation,
}

enum NativeFile {
    Data(OverlappedFile),
    Directory(Directory),
}

struct Directory {
    file: Arc<OverlappedFile>,
    scan: Mutex<()>,
    id: u64,
    closing: AtomicBool,
}

impl NativeFile {
    fn get(&self) -> &File {
        match self {
            Self::Data(file) => file.get(),
            Self::Directory(directory) => directory.file.get(),
        }
    }

    fn overlapped(&self) -> Result<&OverlappedFile, Status> {
        match self {
            Self::Data(file) => Ok(file),
            Self::Directory(_) => Err(Status::FILE_IS_A_DIRECTORY),
        }
    }

    fn directory(&self) -> Result<&Directory, Status> {
        match self {
            Self::Directory(directory) => Ok(directory),
            Self::Data(_) => Err(Status::NOT_A_DIRECTORY),
        }
    }

    fn list(&self) -> Result<Vec<String>, Status> {
        match self {
            Self::Data(_) => Err(Status::NOT_A_DIRECTORY),
            Self::Directory(directory) => {
                let _scan = directory.scan.lock();
                native::list(&directory.file)
            }
        }
    }
}

impl WindowsFile {
    fn get(&self) -> Result<Arc<NativeFile>, Status> {
        self.file
            .lock()
            .as_ref()
            .map(|open| open.file.clone())
            .ok_or(Status::FILE_CLOSED)
    }
}

impl Inspect for WindowsFs {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("opens", self.0.opens.load(Ordering::Relaxed))
            .field("open_limit", OPEN_LIMIT)
            .field(
                "workers_submitted",
                self.0.io.submitted.load(Ordering::Relaxed),
            );
    }
}

impl WindowsFs {
    /// Captures an export root. Native setup executes on a bounded worker.
    pub async fn new(
        root: impl AsRef<Path>,
        driver: Arc<dyn Driver>,
    ) -> Result<Self, OpenRootError> {
        let io = Io::new(driver);
        let root = root.as_ref().to_owned();
        let root = io
            .worker(&RequestContext::new(0), move || native::root(&root))
            .await
            .map_err(OpenRootError)?;
        Ok(Self(Arc::new(Inner {
            io,
            root: Arc::new(root),
            opens: AtomicUsize::new(0),
            watches: Mutex::new(HashMap::new()),
        })))
    }

    fn reserve(&self) -> Result<Reservation, Status> {
        self.0
            .opens
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < OPEN_LIMIT).then_some(count + 1)
            })
            .map_err(|_| Status::INSUFFICIENT_RESOURCES)?;
        Ok(Reservation(self.0.clone()))
    }
}

fn components(name: &str) -> Result<Vec<String>, Status> {
    if name.starts_with('\\') || name.contains('/') || name.encode_utf16().count() > 32767 {
        return Err(Status::OBJECT_NAME_INVALID);
    }
    let mut result = Vec::new();
    for part in name.split('\\').filter(|part| !part.is_empty()) {
        if part.contains(':') {
            return Err(Status::NOT_SUPPORTED);
        }
        if part
            .chars()
            .any(|c| c < ' ' || matches!(c, '*' | '?' | '"' | '<' | '>' | '|'))
            || part.encode_utf16().count() > 255
        {
            return Err(Status::OBJECT_NAME_INVALID);
        }
        result.push(part.to_owned());
    }
    Ok(result)
}

fn create(options: &OpenOptions<'_>) -> Result<Create, Status> {
    let supported = nt::FILE_DIRECTORY_FILE
        | nt::FILE_NON_DIRECTORY_FILE
        | nt::FILE_WRITE_THROUGH
        | nt::FILE_SEQUENTIAL_ONLY
        | nt::FILE_RANDOM_ACCESS
        | nt::FILE_DELETE_ON_CLOSE
        | nt::FILE_NO_EA_KNOWLEDGE;
    if options.options & !supported != 0
        || options.access().access_system_security()
        || options.disposition > nt::FILE_OVERWRITE_IF
    {
        return Err(Status::NOT_SUPPORTED);
    }
    Ok(Create {
        // SMB READ accepts EXECUTE, whereas NtReadFile requires READ_DATA.
        // Keep this physical right private to the provider.
        access: {
            let access = map_access(options.access) | replacement_access(options.disposition());
            if AccessMask::from_bits(access).execute() {
                access | fs::FILE_READ_DATA
            } else {
                access
            }
        },
        sharing: options.share_access,
        disposition: options.disposition,
        options: options.options,
        attributes: options.attributes,
    })
}

fn replacement_access(disposition: CreateDisposition) -> u32 {
    // MS-FSA 2.1.5.1.2 requires these grants for replacing existing default data.
    match disposition {
        CreateDisposition::SUPERSEDE => fs::DELETE | fs::FILE_WRITE_ATTRIBUTES | fs::FILE_WRITE_EA,
        CreateDisposition::OVERWRITE | CreateDisposition::OVERWRITE_IF => {
            fs::FILE_WRITE_DATA | fs::FILE_WRITE_ATTRIBUTES | fs::FILE_WRITE_EA
        }
        _ => 0,
    }
}

fn walk(root: Arc<File>, parts: Vec<String>, create: &Create) -> Result<(File, u32), Status> {
    let mut parents = vec![root];
    for (index, part) in parts.iter().enumerate() {
        if part == "." {
            continue;
        }
        if part == ".." {
            if parents.len() > 1 {
                parents.pop();
            }
            continue;
        }
        let parent = parents.last().expect("root remains on the parent stack");
        native::check_directory(parent)?;
        if index + 1 == parts.len() {
            let (file, action) = native::open(
                Some(parent),
                &part.encode_utf16().collect::<Vec<_>>(),
                create,
            )?;
            if native::is_directory(&file)? {
                native::check_directory(&file)?;
            }
            return Ok((file, action));
        }
        let (directory, _) = native::open(
            Some(parent),
            &part.encode_utf16().collect::<Vec<_>>(),
            &Create {
                access: fs::FILE_READ_ATTRIBUTES,
                sharing: fs::FILE_SHARE_READ | fs::FILE_SHARE_WRITE | fs::FILE_SHARE_DELETE,
                disposition: nt::FILE_OPEN,
                options: nt::FILE_DIRECTORY_FILE,
                attributes: 0,
            },
        )?;
        native::check_directory(&directory)?;
        parents.push(Arc::new(directory));
    }
    if !matches!(create.disposition, nt::FILE_OPEN | nt::FILE_OPEN_IF) {
        return Err(Status::ACCESS_DENIED);
    }
    let parent = parents.last().expect("root remains on the parent stack");
    native::check_directory(parent)?;
    let (file, action) = native::open(Some(parent), &[], create)?;
    Ok((file, action))
}

#[async_trait]
impl FileSystem for WindowsFs {
    type File = WindowsFile;

    async fn open(
        &self,
        name: &str,
        options: OpenOptions<'_>,
        request: &RequestContext,
    ) -> Result<(WindowsFile, u32), Status> {
        check(request)?;
        let parts = components(name)?;
        let mut create = create(&options)?;
        let logical_access = AccessMask::from_bits(map_access(options.access));
        let hidden_read = logical_access.execute()
            && !logical_access.read_data()
            && !logical_access.maximum_allowed();
        let unsupported_creation =
            options.security.is_some() || options.extended_attributes.is_some();
        if unsupported_creation {
            create.disposition = match options.disposition() {
                CreateDisposition::OPEN | CreateDisposition::OPEN_IF => nt::FILE_OPEN,
                CreateDisposition::OVERWRITE | CreateDisposition::OVERWRITE_IF => {
                    nt::FILE_OVERWRITE
                }
                _ => return Err(Status::NOT_SUPPORTED),
            };
        }
        let reservation = self.reserve()?;
        let root = self.0.root.clone();
        let result = self
            .0
            .io
            .worker(request, move || {
                // Retain the open slot even if an initialization future is dropped.
                let (file, action) = walk(root, parts, &create)?;
                let directory = if native::is_directory(&file)? {
                    Some(native::identity(&file)?)
                } else {
                    None
                };
                Ok(((file, action, directory), reservation))
            })
            .await;
        let ((file, action, directory), reservation) = match result {
            Err(Status::OBJECT_NAME_NOT_FOUND) if unsupported_creation => {
                return Err(Status::NOT_SUPPORTED);
            }
            result => result?,
        };
        let file = native::overlapped(&*self.0.io.driver, file).map_err(|error| {
            tracelimit::error_ratelimited!(?error, "cannot associate native SMB open with IOCP");
            Status::INTERNAL_ERROR
        })?;
        let file = if let Some(id) = directory {
            NativeFile::Directory(Directory {
                file: Arc::new(file),
                scan: Mutex::new(()),
                id,
                closing: AtomicBool::new(false),
            })
        } else {
            NativeFile::Data(file)
        };
        Ok((
            WindowsFile {
                file: Mutex::new(Some(Open {
                    file: Arc::new(file),
                    _reservation: reservation,
                })),
                append_only: options.access().append_data()
                    && !options.access().write_data()
                    && !options.access().generic_write()
                    && !options.access().generic_all(),
                hidden_access: if hidden_read { fs::FILE_READ_DATA } else { 0 }
                    | if action == CreateAction::CREATED.0 && !logical_access.maximum_allowed() {
                        replacement_access(options.disposition()) & !logical_access.into_bits()
                    } else {
                        0
                    },
                watch: Arc::new(futures::lock::Mutex::new(None)),
            },
            action,
        ))
    }

    async fn close(&self, file: &WindowsFile, _request: &RequestContext) -> Result<(), Status> {
        let native = file.file.lock().take();
        if let Some(open) = &native {
            if let NativeFile::Directory(directory) = &*open.file {
                directory.closing.store(true, Ordering::Release);
            }
        }
        if let Some(watch) = file.watch.lock().await.take() {
            watch.shutdown().await;
        }
        // The engine has already drained this open's operations. Closing does
        // not issue an implicit flush and is not prevented by cancellation.
        self.0
            .io
            .worker(&RequestContext::new(0), move || {
                drop(native);
                Ok(())
            })
            .await
    }

    async fn metadata(
        &self,
        file: &WindowsFile,
        request: &RequestContext,
    ) -> Result<Metadata, Status> {
        let native = file.get()?;
        let root = self.0.root.clone();
        let mut metadata = self
            .0
            .io
            .worker(request, move || {
                let path = native::relative_path(&root, native.get())?;
                native::metadata(native.get(), path)
            })
            .await?;
        metadata.granted_access &= !file.hidden_access;
        Ok(metadata)
    }

    async fn query_security(
        &self,
        file: &WindowsFile,
        information: SecurityInformation,
        request: &RequestContext,
    ) -> Result<SecurityDescriptor, Status> {
        let file = file.get()?;
        self.0
            .io
            .worker(request, move || {
                native::query_security(file.get(), information.into_bits())
            })
            .await
    }

    async fn filesystem_information(
        &self,
        file: &WindowsFile,
        request: &RequestContext,
    ) -> Result<FileSystemInformation, Status> {
        let file = file.get()?;
        self.0
            .io
            .worker(request, move || native::filesystem_information(file.get()))
            .await
    }

    async fn read(
        &self,
        file: &WindowsFile,
        offset: u64,
        length: usize,
        request: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        check(request)?;
        let offset = i64::try_from(offset).map_err(|_| Status::INVALID_PARAMETER)?;
        let file = file.get()?;
        let mut io = native::read(file.overlapped()?, offset, vec![0; length.min(IO_LIMIT)]);
        let mut cancelled = std::pin::pin!(request.cancelled().fuse());
        let ((result, count), mut data) = futures::select_biased! {
            result = (&mut io).fuse() => result,
            () = cancelled => {
                io.cancel();
                io.await
            },
        };
        native::status(result)?;
        if count > data.len() {
            return Err(Status::INTERNAL_ERROR);
        }
        data.truncate(count);
        Ok(data)
    }

    async fn write(
        &self,
        file: &WindowsFile,
        offset: u64,
        data: &[u8],
        request: &RequestContext,
    ) -> Result<usize, Status> {
        check(request)?;
        let offset = if file.append_only {
            -1
        } else {
            i64::try_from(offset).map_err(|_| Status::INVALID_PARAMETER)?
        };
        let file = file.get()?;
        let data = data[..data.len().min(IO_LIMIT)].to_vec();
        let mut io = native::write(file.overlapped()?, offset, data);
        let mut cancelled = std::pin::pin!(request.cancelled().fuse());
        let ((result, count), data) = futures::select_biased! {
            result = (&mut io).fuse() => result,
            () = cancelled => {
                io.cancel();
                io.await
            },
        };
        native::status(result)?;
        if count > data.len() {
            return Err(Status::INTERNAL_ERROR);
        }
        Ok(count)
    }

    async fn flush(&self, file: &WindowsFile, request: &RequestContext) -> Result<(), Status> {
        let file = file.get()?;
        self.0
            .io
            .worker(request, move || native::flush(file.get()))
            .await
    }

    async fn list(
        &self,
        directory: &WindowsFile,
        request: &RequestContext,
    ) -> Result<Vec<Metadata>, Status> {
        let file = directory.get()?;
        if directory.hidden_access & fs::FILE_READ_DATA != 0 {
            return Err(Status::ACCESS_DENIED);
        }
        let root = self.0.root.clone();
        self.0
            .io
            .worker(request, move || {
                let names = file.list()?;
                let path = native::relative_path(&root, file.get())?;
                let mut entries = Vec::with_capacity(names.len());
                for name in names {
                    let (child, _) = native::open(
                        Some(file.get()),
                        &name.encode_utf16().collect::<Vec<_>>(),
                        &Create {
                            access: fs::FILE_READ_ATTRIBUTES,
                            sharing: fs::FILE_SHARE_READ
                                | fs::FILE_SHARE_WRITE
                                | fs::FILE_SHARE_DELETE,
                            disposition: nt::FILE_OPEN,
                            options: 0,
                            attributes: 0,
                        },
                    )?;
                    let path = format!("{}\\{}", path.trim_end_matches('\\'), name);
                    entries.push(native::metadata(&child, path)?);
                }
                Ok(entries)
            })
            .await
    }

    async fn set_len(
        &self,
        file: &WindowsFile,
        length: u64,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let file = file.get()?;
        self.0
            .io
            .worker(request, move || native::set_len(file.get(), length))
            .await
    }

    async fn set_delete_on_close(
        &self,
        file: &WindowsFile,
        delete: bool,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let file = file.get()?;
        let inner = self.0.clone();
        self.0
            .io
            .worker(request, move || {
                let mut watches = inner.watches.lock();
                native::set_disposition(file.get(), delete)?;
                if delete {
                    if let NativeFile::Directory(directory) = &*file {
                        if let Some(watches) = watches.remove(&directory.id) {
                            for watch in watches.into_iter().filter_map(|watch| watch.upgrade()) {
                                watch.invalidate();
                            }
                        }
                    }
                }
                Ok(())
            })
            .await
    }

    async fn set_basic(
        &self,
        file: &WindowsFile,
        info: BasicInformation,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let file = file.get()?;
        self.0
            .io
            .worker(request, move || native::set_basic(file.get(), info))
            .await
    }

    async fn notify(
        &self,
        file: &WindowsFile,
        filter: NotifyFilter,
        watch_tree: bool,
        output_length: usize,
        request: &RequestContext,
    ) -> Result<NotifyResult, Status> {
        let native = file.get()?;
        native.directory()?;
        if file.hidden_access & fs::FILE_READ_DATA != 0 {
            return Err(Status::ACCESS_DENIED);
        }
        let existing = file.watch.lock().await.clone();
        let watch = match existing {
            Some(watch) => watch,
            None => {
                let inner = self.0.clone();
                let native = native.clone();
                let slot = file.watch.clone();
                self.0
                    .io
                    .worker(&RequestContext::new(request.id()), move || {
                        // Store the registration before returning the worker result,
                        // so dropping an awaiting future cannot discard accepted work.
                        let mut slot = futures::executor::block_on(slot.lock());
                        let directory = native.directory()?;
                        if directory.closing.load(Ordering::Acquire) {
                            return Err(Status::FILE_CLOSED);
                        }
                        if let Some(watch) = &*slot {
                            return Ok(watch.clone());
                        }
                        let mut watches = inner.watches.lock();
                        if native::delete_pending(native.get())? {
                            return Err(Status::DELETE_PENDING);
                        }
                        let watch = Watch::new(directory.file.clone(), filter, watch_tree)?;
                        watches.retain(|_, entries| {
                            entries.retain(|entry| entry.strong_count() != 0);
                            !entries.is_empty()
                        });
                        watches
                            .entry(directory.id)
                            .or_default()
                            .push(Arc::downgrade(&watch));
                        *slot = Some(watch.clone());
                        Ok(watch)
                    })
                    .await?
            }
        };
        let result = watch.notify(output_length, request).await;
        if watch.invalidated() {
            watch.shutdown().await;
        }
        result
    }

    async fn set_allocation_size(
        &self,
        file: &WindowsFile,
        length: u64,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let file = file.get()?;
        self.0
            .io
            .worker(request, move || native::set_allocation(file.get(), length))
            .await
    }

    async fn rename(
        &self,
        file: &WindowsFile,
        name: &str,
        replace: bool,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let file = file.get()?;
        let root = self.0.root.clone();
        let mut parts = components(name)?;
        let leaf = parts.pop().ok_or(Status::OBJECT_NAME_INVALID)?;
        if leaf == "." || leaf == ".." {
            return Err(Status::OBJECT_NAME_INVALID);
        }
        self.0
            .io
            .worker(request, move || {
                let source = native::relative_path(&root, file.get())?;
                if source == "\\" || native::delete_pending(file.get())? {
                    return Err(Status::ACCESS_DENIED);
                }
                let (parent, _) = walk(
                    root.clone(),
                    parts,
                    &Create {
                        access: fs::FILE_READ_ATTRIBUTES,
                        sharing: fs::FILE_SHARE_READ | fs::FILE_SHARE_WRITE | fs::FILE_SHARE_DELETE,
                        disposition: nt::FILE_OPEN,
                        options: nt::FILE_DIRECTORY_FILE,
                        attributes: 0,
                    },
                )
                .map_err(|status| {
                    if status == Status::OBJECT_NAME_NOT_FOUND {
                        Status::OBJECT_PATH_NOT_FOUND
                    } else {
                        status
                    }
                })?;
                let destination = native::relative_path(&root, &parent)?;
                if native::is_directory(file.get())?
                    && (destination == source || destination.starts_with(&format!("{source}\\")))
                {
                    return Err(Status::ACCESS_DENIED);
                }
                native::rename(file.get(), &parent, &leaf, replace)
            })
            .await
    }
}

#[cfg(test)]
mod tests;
