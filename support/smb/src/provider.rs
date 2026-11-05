// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filesystem semantics independent of host files and VM resources.

use crate::spec::{
    AccessMask, CreateDisposition, CreateOptions, FileAttributes, FileNotifyInformation,
    NOTIFY_ALIGNMENT, NotifyAction, NotifyFilter, Status,
};
use async_trait::async_trait;
use event_listener::Event;
use inspect::Inspect;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Identity and cooperative cancellation shared by calls of one server operation.
#[derive(Clone)]
pub struct RequestContext(Arc<RequestState>);

struct RequestState {
    id: u64,
    cancelled: AtomicBool,
    changed: Event,
}

impl RequestContext {
    /// Create an independent operation context.
    pub fn new(id: u64) -> Self {
        Self(Arc::new(RequestState {
            id,
            cancelled: AtomicBool::new(false),
            changed: Event::new(),
        }))
    }

    /// Server-assigned identity, distinct from the client's message ID.
    /// Sequential provider calls such as CREATE's open and metadata query share it.
    pub fn id(&self) -> u64 {
        self.0.id
    }

    /// Whether cancellation has been requested, not whether it succeeded.
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }

    /// Wait for a cancellation request. The provider chooses a safe outcome.
    pub async fn cancelled(&self) {
        loop {
            let listener = self.0.changed.listen();
            if self.is_cancelled() {
                return;
            }
            listener.await;
        }
    }

    pub(crate) fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.0.changed.notify(usize::MAX);
    }
}

/// Metadata expressed in Windows file attributes and 100 ns NT timestamps.
#[derive(Debug, Clone)]
pub struct Metadata {
    /// Stable identity within this provider.
    pub id: u64,
    /// Last component of the object's name.
    pub name: String,
    /// Canonical backslash-prefixed path within the share's virtual volume.
    pub path: String,
    /// Optional short filename supplied by providers that expose short names.
    pub short_name: Option<String>,
    /// Windows file attribute bits.
    pub attributes: u32,
    /// Creation time.
    pub created: u64,
    /// Last data access time.
    pub accessed: u64,
    /// Last data write time.
    pub written: u64,
    /// Last metadata change time.
    pub changed: u64,
    /// Logical length of the default data stream.
    pub size: u64,
    /// Space allocated to the default stream, independent of logical length.
    pub allocation_size: u64,
    /// Provider-reported count of nondeleted links.
    pub number_of_links: u32,
    /// Encoded extended-attribute bytes, excluding the query's outer length field.
    pub extended_attributes_length: u32,
    /// Required byte alignment minus one; zero permits byte-aligned I/O.
    pub alignment_requirement: u32,
    /// Whether the shared delete disposition is set, excluding CREATE's
    /// deferred per-open delete mode (MS-FSA §2.1.5.12.27).
    pub delete_pending: bool,
    /// Maximal access for the share's established identity, not the current open.
    pub maximal_access: u32,
}

impl Metadata {
    /// Whether this object is a directory.
    pub fn is_directory(&self) -> bool {
        self.attributes().directory()
    }

    /// Decoded DOS attributes, preserving unknown bits.
    pub fn attributes(&self) -> FileAttributes {
        FileAttributes::from_bits(self.attributes)
    }
}

/// One coherent volume snapshot, supplied by the filesystem rather than the SMB engine.
#[derive(Debug, Clone)]
pub struct FileSystemInformation {
    /// Volume creation time in NT ticks.
    pub created: u64,
    /// Provider-assigned opaque volume serial; uniqueness is not required.
    pub serial: u32,
    /// Volume label.
    pub label: String,
    /// Whether the volume supports object-oriented filesystem objects.
    pub supports_objects: bool,
    /// Filesystem name.
    pub name: String,
    /// FILE_FS_ATTRIBUTE_INFORMATION capability flags.
    pub attributes: u32,
    /// Maximum component length in UTF-16 code units.
    pub maximum_component_name_length: u32,
    /// FILE_DEVICE_* volume type.
    pub device_type: u32,
    /// FILE_* device characteristics.
    pub device_characteristics: u32,
    /// Nonnegative allocation units available in total to the share identity.
    pub total_allocation_units: i64,
    /// Nonnegative free units available to the share identity.
    pub caller_available_allocation_units: i64,
    /// Nonnegative free units on the volume, before identity-specific quotas.
    pub actual_available_allocation_units: i64,
    /// Nonzero sectors per allocation unit.
    pub sectors_per_allocation_unit: u32,
    /// Nonzero logical bytes per sector.
    pub bytes_per_sector: u32,
}

/// Parameters of an SMB open, after protocol validation.
#[derive(Debug, Clone, Copy)]
pub struct OpenOptions {
    /// Specific file access rights, with generic bits already mapped.
    pub access: u32,
    /// FILE_SHARE_READ/WRITE/DELETE bits.
    pub share_access: u32,
    /// FILE_SUPERSEDE through FILE_OVERWRITE_IF.
    pub disposition: u32,
    /// FILE_* create options.
    pub options: u32,
    /// Requested Windows file attributes.
    pub attributes: u32,
}

impl OpenOptions {
    /// Decoded access rights.
    pub fn access(&self) -> AccessMask {
        AccessMask::from_bits(self.access)
    }
    /// Decoded create options, preserving unsupported option bits.
    pub fn options(&self) -> CreateOptions {
        CreateOptions::from_bits(self.options)
    }
    /// Specified create disposition, including unknown values.
    pub fn disposition(&self) -> CreateDisposition {
        CreateDisposition(self.disposition)
    }
    /// Requested DOS attributes.
    pub fn attributes(&self) -> FileAttributes {
        FileAttributes::from_bits(self.attributes)
    }
}

/// FILE_BASIC_INFORMATION updates, including the -1/-2 per-open time controls.
#[derive(Debug, Clone, Copy)]
pub struct BasicInformation {
    /// Positive NT time, zero to leave unchanged.
    pub created: i64,
    /// Positive NT time, zero unchanged, -1 suppresses automatic updates, -2 restores them.
    pub accessed: i64,
    /// Last-write time and automatic-update control.
    pub written: i64,
    /// Change time and automatic-update control.
    pub changed: i64,
    /// DOS attributes; zero leaves them unchanged.
    pub attributes: u32,
}

/// One change relative to the directory being watched, not a host pathname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// Filesystem event.
    pub action: NotifyAction,
    /// Backslash-separated relative name, preserving the provider's spelling.
    pub name: String,
}

impl Change {
    /// Byte budget of this aligned MS-FSCC 2.7.1 notification record.
    pub fn encoded_len(&self) -> usize {
        (size_of::<FileNotifyInformation>() + self.name.encode_utf16().count() * size_of::<u16>())
            .next_multiple_of(NOTIFY_ALIGNMENT)
    }
}

/// A completed watch either delivers actual events or requires re-enumeration.
#[derive(Debug)]
pub enum NotifyResult {
    /// Nonempty changes, in provider order.
    Changes(Vec<Change>),
    /// Events were lost, or the output buffer cannot hold the pending batch.
    Overflow,
}

/// An exact byte range, including the zero-length ranges allowed by MS-FSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// First byte offset.
    pub offset: u64,
    /// Number of bytes; may be zero.
    pub length: u64,
}

/// Provider-owned identity of one acquisition, for exact rollback of a lock array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockId(pub u64);

impl ByteRange {
    pub(crate) fn validate(self) -> Result<(), Status> {
        if self.length != 0 && self.offset.checked_add(self.length - 1).is_none() {
            return Err(Status::INVALID_LOCK_RANGE);
        }
        Ok(())
    }

    pub(crate) fn overlaps(self, other: Self) -> bool {
        // MS-FSA §2.1.4.10 gives {0, 0} special treatment and uses inclusive ends.
        self != (Self {
            offset: 0,
            length: 0,
        }) && other
            != (Self {
                offset: 0,
                length: 0,
            })
            && self.offset <= other.offset.wrapping_add(other.length).wrapping_sub(1)
            && other.offset <= self.offset.wrapping_add(self.length).wrapping_sub(1)
    }
}

/// The object store behind a share.
///
/// Handles own their open lifetime: dropping one releases its share-access
/// reservation. Names are relative to the share root and never host paths.
/// Calls may overlap, including on the same handle. Cancellation is a request:
/// return STATUS_CANCELLED only when cancellation actually succeeds. The caller
/// retains the operation future and its inputs until it finishes.
#[async_trait]
pub trait FileSystem: Inspect + Send + Sync + 'static {
    /// Provider-owned open object, not an OS handle or protocol file ID.
    type File: Send + Sync;

    /// Open an object and return its handle and SMB create-action value.
    async fn open(
        &self,
        name: &str,
        options: OpenOptions,
        request: &RequestContext,
    ) -> Result<(Self::File, u32), Status>;
    /// Finalize an open after its other operations have settled. Must be idempotent.
    async fn close(&self, file: &Self::File, request: &RequestContext) -> Result<(), Status>;
    /// Get current metadata for an open object.
    async fn metadata(
        &self,
        file: &Self::File,
        request: &RequestContext,
    ) -> Result<Metadata, Status>;
    /// Query the volume containing this open. Do not invent native geometry or capabilities.
    async fn filesystem_information(
        &self,
        _file: &Self::File,
        _request: &RequestContext,
    ) -> Result<FileSystemInformation, Status> {
        Err(Status::NOT_SUPPORTED)
    }
    /// Read at most `length` bytes from a default data stream.
    /// At EOF, an empty result or STATUS_END_OF_FILE is accepted by the engine.
    async fn read(
        &self,
        file: &Self::File,
        offset: u64,
        length: usize,
        request: &RequestContext,
    ) -> Result<Vec<u8>, Status>;
    /// Write to a default data stream, returning the accepted byte count.
    async fn write(
        &self,
        file: &Self::File,
        offset: u64,
        data: &[u8],
        request: &RequestContext,
    ) -> Result<usize, Status>;
    /// Make accepted writes durable according to the provider's storage model.
    async fn flush(&self, file: &Self::File, request: &RequestContext) -> Result<(), Status>;
    /// Return the current children of an open directory.
    async fn list(
        &self,
        directory: &Self::File,
        request: &RequestContext,
    ) -> Result<Vec<Metadata>, Status>;
    /// Change the logical length, zero-filling any extension.
    async fn set_len(
        &self,
        file: &Self::File,
        length: u64,
        request: &RequestContext,
    ) -> Result<(), Status>;
    /// Set or clear the object's shared delete disposition through this open.
    /// This does not change CREATE's per-open FILE_DELETE_ON_CLOSE mode.
    async fn set_delete_on_close(
        &self,
        file: &Self::File,
        delete: bool,
        request: &RequestContext,
    ) -> Result<(), Status>;
    /// Update basic metadata and per-open automatic timestamp policy.
    async fn set_basic(
        &self,
        file: &Self::File,
        info: BasicInformation,
        request: &RequestContext,
    ) -> Result<(), Status>;
    /// Rename this open's object to a share-root-relative name (MS-FSA §2.1.5.15.12).
    /// The caller checks DELETE access. Preserve object identity, data, locks and
    /// existing source opens; enforce destination sharing and replacement rules.
    /// Deny replacement of an open target and directory renames with open descendants.
    /// Namespace changes and their ordered notifications must be atomic to observers.
    /// File renames also notify attribute/creation watchers at the destination;
    /// exact replacement's metadata notification must not be duplicated.
    async fn rename(
        &self,
        _file: &Self::File,
        _name: &str,
        _replace: bool,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        Err(Status::NOT_SUPPORTED)
    }
    /// Acquire a byte-range lock owned by this open (MS-FSA §2.1.5.8).
    /// Conflicts and read/write enforcement span all opens/connections to the stream.
    /// Shared locks block all writes; exclusive locks permit the owner's I/O.
    /// Waiting requests must honor cancellation unless the lock was already acquired.
    /// Explicit close and fallback handle drop release all of the open's locks.
    /// Providers implementing this operation must also implement unlock and rollback_lock.
    async fn lock(
        &self,
        _file: &Self::File,
        _range: ByteRange,
        _exclusive: bool,
        _fail_immediately: bool,
        _request: &RequestContext,
    ) -> Result<LockId, Status> {
        Err(Status::NOT_SUPPORTED)
    }
    /// Roll back one successful acquisition, never an older exact-range match.
    /// Idempotent if that acquisition was already unlocked by concurrent work.
    /// Cleanup must not be prevented by cancellation of the originating request.
    async fn rollback_lock(
        &self,
        _file: &Self::File,
        _lock: LockId,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        Err(Status::NOT_SUPPORTED)
    }
    /// Remove one exact lock owned by this open (MS-FSA §2.1.5.9).
    /// Prefer an exclusive lock when multiple exact matches exist.
    async fn unlock(
        &self,
        _file: &Self::File,
        _range: ByteRange,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        Err(Status::NOT_SUPPORTED)
    }
    /// Watch directory changes. The first call fixes filter/scope for its registration;
    /// buffer changes between calls and complete overlapping requests FIFO.
    /// Cancellation removes a waiter, not the open's watch or buffered changes.
    /// Directory deletion invalidates registrations and completes pending waits with
    /// STATUS_DELETE_PENDING; later registration must not absorb the old waiters.
    /// Establish the watch even if the request was canceled before its first poll.
    /// Pending waits must honor cancellation unless an actual result was already obtained.
    /// Providers must bound storage and report overflow rather than silently lose events.
    /// An undersized reply reports overflow without consuming the buffered batch;
    /// storage overflow may discard events and require re-enumeration.
    async fn notify(
        &self,
        _file: &Self::File,
        _filter: NotifyFilter,
        _watch_tree: bool,
        _output_length: usize,
        _request: &RequestContext,
    ) -> Result<NotifyResult, Status> {
        Err(Status::NOT_SUPPORTED)
    }
}

/// Expand generic access bits using the file-object generic mapping.
pub fn map_access(mut access: u32) -> u32 {
    let mask = AccessMask::from_bits(access);
    for (present, generic, specific) in [
        (
            mask.generic_read(),
            AccessMask::new().with_generic_read(true),
            AccessMask::FILE_GENERIC_READ,
        ),
        (
            mask.generic_write(),
            AccessMask::new().with_generic_write(true),
            AccessMask::FILE_GENERIC_WRITE,
        ),
        (
            mask.generic_execute(),
            AccessMask::new().with_generic_execute(true),
            AccessMask::FILE_GENERIC_EXECUTE,
        ),
        (
            mask.generic_all(),
            AccessMask::new().with_generic_all(true),
            AccessMask::FILE_ALL_ACCESS,
        ),
    ] {
        if present {
            access = (access & !generic.into_bits()) | specific.into_bits();
        }
    }
    let mut mask = AccessMask::from_bits(access);
    if mask.execute() {
        // MS-SMB2 §3.3.5.12 permits READ through FILE_EXECUTE as well as FILE_READ_DATA.
        mask.set_read_data(true);
    }
    mask.into_bits()
}
