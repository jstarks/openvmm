// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filesystem semantics independent of host files and VM resources.

use crate::security::SecurityDescriptor;
use crate::spec::{
    AccessMask, CreateDisposition, CreateOptions, FileAttributes, FileNotifyInformation,
    NOTIFY_ALIGNMENT, NotifyAction, NotifyFilter, SecurityInformation, Status,
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

/// One named extended attribute, shared by all opens of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedAttribute {
    /// ASCII name, matched without ASCII case.
    pub name: Vec<u8>,
    /// Opaque contents; an empty value in an update deletes this name.
    pub value: Vec<u8>,
    /// The file requires an application that understands EAs.
    pub need_ea: bool,
}

impl ExtendedAttribute {
    /// Validate the public EA name and value constraints.
    pub fn validate(&self) -> Result<(), Status> {
        validate_ea_name(&self.name)?;
        if self.value.len() > u16::MAX as usize {
            return Err(Status::EA_TOO_LARGE);
        }
        Ok(())
    }

    /// Unaligned FILE_FULL_EA_INFORMATION record length.
    pub fn encoded_len(&self) -> usize {
        8 + self.name.len() + 1 + self.value.len()
    }
}

pub(crate) fn validate_ea_name(name: &[u8]) -> Result<(), Status> {
    if name.is_empty()
        || name.len() >= 255
        || !name.is_ascii()
        || name.iter().any(|byte| {
            *byte < 0x20
                || matches!(
                    *byte,
                    b'\\'
                        | b'/'
                        | b':'
                        | b'*'
                        | b'?'
                        | b'"'
                        | b'<'
                        | b'>'
                        | b'|'
                        | b','
                        | b'+'
                        | b'='
                        | b'['
                        | b']'
                        | b';'
                )
        })
    {
        return Err(Status::INVALID_EA_NAME);
    }
    Ok(())
}

/// One data stream of a file or directory, independent of its open handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamInformation {
    /// Unqualified stream name; empty identifies the default data stream.
    pub name: String,
    /// Logical length.
    pub size: u64,
    /// Actual allocation, which may differ from logical length.
    pub allocation_size: u64,
}

/// Provider-reported compression state, independent of wire layouts.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompressionInformation {
    /// Actual allocated bytes occupied by stream data.
    pub compressed_size: u64,
    /// COMPRESSION_FORMAT_* identifier.
    pub format: u16,
    /// Log2 compression unit size.
    pub unit_shift: u8,
    /// Log2 compression chunk size.
    pub chunk_shift: u8,
    /// Log2 allocation cluster size used by compression.
    pub cluster_shift: u8,
}

/// Metadata expressed in Windows file attributes and 100 ns NT timestamps.
#[derive(Debug, Clone)]
pub struct Metadata {
    /// Unqualified named data stream; None for default data/directory opens.
    pub stream_name: Option<String>,
    /// Stable identity within this provider.
    pub id: u64,
    /// Opaque stable 128-bit volume-scoped file identity, when supported.
    pub id128: Option<[u8; 16]>,
    /// Last component of the object's name.
    pub name: String,
    /// Canonical backslash-prefixed path within the share's virtual volume.
    pub path: String,
    /// Optional short filename supplied by providers that expose short names.
    pub short_name: Option<String>,
    /// Windows file attribute bits.
    pub attributes: u32,
    /// Provider-owned reparse tag; zero when REPARSE_POINT is clear.
    pub reparse_tag: u32,
    /// Creation time.
    pub created: u64,
    /// Last data access time.
    pub accessed: u64,
    /// Last data write time.
    pub written: u64,
    /// Last metadata change time.
    pub changed: u64,
    /// Logical length of the opened stream.
    pub size: u64,
    /// Space allocated to the opened stream, independent of logical length.
    pub allocation_size: u64,
    /// Actual compression metadata; None explicitly declines compression queries.
    pub compression: Option<CompressionInformation>,
    /// Provider-reported count of nondeleted links.
    pub number_of_links: u32,
    /// Encoded extended-attribute bytes, excluding the query's outer length field.
    pub extended_attributes_length: u32,
    /// Required byte alignment minus one; zero permits byte-aligned I/O.
    pub alignment_requirement: u32,
    /// Whether the shared delete disposition is set, excluding CREATE's
    /// deferred per-open delete mode (MS-FSA §2.1.5.12.27).
    pub delete_pending: bool,
    /// Descriptor-derived maximal access for the share's established identity,
    /// independent of the current open's grant and readonly attribute restrictions.
    pub maximal_access: u32,
    /// Actual logical rights granted to this open, without generic/MAXIMUM_ALLOWED bits.
    /// Directory enumeration entries need not populate this field.
    pub granted_access: u32,
}

impl Metadata {
    /// Whether this open addresses a directory namespace rather than a data stream.
    pub fn is_directory(&self) -> bool {
        self.attributes().directory() && self.stream_name.is_none()
    }

    /// Decoded DOS attributes, preserving unknown bits.
    pub fn attributes(&self) -> FileAttributes {
        FileAttributes::from_bits(self.attributes)
    }
}

/// Selected filesystem controls, decoded independently of SMB buffer layouts.
#[derive(Debug, Clone, Copy)]
pub enum FileControl {
    /// Query the stream or directory's COMPRESSION_FORMAT_* state.
    GetCompression,
    /// Zero [offset, end) without extending EOF or moving the open's position.
    SetZeroData {
        /// First byte to zero.
        offset: u64,
        /// Exclusive end, clamped to EOF; both offsets must fit signed 64 bits.
        end: u64,
    },
    /// Query allocated byte ranges intersecting a nonnegative signed-64-bit range.
    QueryAllocatedRanges {
        /// Queried interval; offset plus length must fit signed 64 bits.
        range: ByteRange,
        /// Maximum records to return; report overflow if more remain.
        maximum_ranges: usize,
    },
}

/// Semantic result of a selected filesystem control.
#[derive(Debug)]
pub enum FileControlResult {
    /// A mutation completed without output data.
    Done,
    /// Current COMPRESSION_FORMAT_* state.
    Compression(u16),
    /// Contiguous allocated ranges, bounded by the request's record limit.
    AllocatedRanges {
        /// Nonempty intersecting ranges in increasing offset order.
        ranges: Vec<ByteRange>,
        /// More records remain than fit in the requested limit.
        overflow: bool,
    },
}

/// Provider-owned sector geometry and alignment, including synthetic devices.
#[derive(Debug, Clone, Copy)]
pub struct SectorSizeInformation {
    /// Logical addressing unit in bytes.
    pub logical_bytes: u32,
    /// Physical unit of atomic write.
    pub physical_atomic_bytes: u32,
    /// Physical unit used for performance alignment.
    pub physical_performance_bytes: u32,
    /// Filesystem-effective unit of atomic write.
    pub effective_atomic_bytes: u32,
    /// SSINFO_FLAGS_* geometry flags.
    pub flags: u32,
    /// Logical-to-physical sector offset, or SSINFO_OFFSET_UNKNOWN.
    pub sector_alignment: u32,
    /// Partition offset, or SSINFO_OFFSET_UNKNOWN.
    pub partition_alignment: u32,
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
    /// Extended geometry when supported; None declines this optional query.
    pub sector_size: Option<SectorSizeInformation>,
}

/// Parameters of an SMB open, after protocol validation.
#[derive(Debug, Clone, Copy)]
pub struct OpenOptions<'a> {
    /// Specific access rights, with generic bits mapped. MAXIMUM_ALLOWED is
    /// retained for the provider to resolve against the established identity.
    pub access: u32,
    /// FILE_SHARE_READ/WRITE/DELETE bits.
    pub share_access: u32,
    /// FILE_SUPERSEDE through FILE_OVERWRITE_IF.
    pub disposition: u32,
    /// FILE_* create options.
    pub options: u32,
    /// Requested Windows file attributes.
    pub attributes: u32,
    /// Allocation hint for a created or replaced data stream, without extending EOF.
    /// Existing OPEN/OPEN_IF objects and directory objects ignore this value.
    /// Supporting stores reserve atomically before publication or truncation;
    /// unsupported stores may ignore the hint as permitted by MS-SMB2 §3.3.5.9.3.
    pub allocation_size: u64,
    /// Optional self-relative DTYP descriptor, applied atomically only on creation.
    /// Ignore it for existing objects, including malformed bytes. New-object
    /// validation must finish before publication; unsupported policy must fail.
    pub security: Option<&'a [u8]>,
    /// Optional FSCC EA list for atomic creation; ignore it for existing objects.
    /// Unsupported stores must reject new-object EAs without publishing an object.
    pub extended_attributes: Option<&'a [u8]>,
}

impl OpenOptions<'_> {
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
    /// Validate filename components before publishing a new object (MS-FSCC §2.1.5.2).
    /// Resolve dot-directory components within the share; ".." at the root stays
    /// at that root, never at a host parent (MS-FSCC §2.1.5.1).
    async fn open(
        &self,
        name: &str,
        options: OpenOptions<'_>,
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
    /// Execute a selected filesystem control on this open.
    /// Unsupported controls fail without effects. The caller retains the future,
    /// request and open through completion, including cancellation and CLOSE drain.
    async fn file_control(
        &self,
        _file: &Self::File,
        _control: FileControl,
        _request: &RequestContext,
    ) -> Result<FileControlResult, Status> {
        Err(Status::INVALID_DEVICE_REQUEST)
    }
    /// Return a coherent, ordered EA snapshot. Empty means no EAs, not unsupported.
    /// Stored encoded EA data is bounded by MS-FSA's 64 KiB minus five limit.
    async fn query_eas(
        &self,
        _file: &Self::File,
        _request: &RequestContext,
    ) -> Result<Vec<ExtendedAttribute>, Status> {
        Err(Status::INVALID_DEVICE_REQUEST)
    }
    /// Atomically replace named EAs, delete empty values and preserve other names.
    /// Reject invalid names/values, unsupported storage and capacity failures
    /// without modifying any EA. Existing opens and their access grants survive.
    async fn set_eas(
        &self,
        _file: &Self::File,
        _attributes: &[ExtendedAttribute],
        _request: &RequestContext,
    ) -> Result<(), Status> {
        Err(Status::INVALID_DEVICE_REQUEST)
    }
    /// Return a coherent snapshot of this file's data streams.
    /// Directory/index streams are not data streams. Empty is an actual empty
    /// list, not an unsupported-store fallback.
    async fn query_streams(
        &self,
        _file: &Self::File,
        _request: &RequestContext,
    ) -> Result<Vec<StreamInformation>, Status> {
        Err(Status::INVALID_INFO_CLASS)
    }
    /// Query selected security components for the established share identity.
    /// Unsupported security stores reject rather than fabricate an ACL.
    async fn query_security(
        &self,
        _file: &Self::File,
        _information: SecurityInformation,
        _request: &RequestContext,
    ) -> Result<SecurityDescriptor, Status> {
        Err(Status::INVALID_DEVICE_REQUEST)
    }
    /// Set selected security components for the established share identity.
    /// The caller validates the wire descriptor and open rights. Providers enforcing
    /// security apply components atomically and validate ownership, ACL policy and
    /// inheritance; existing opens retain their grants. A store may explicitly model
    /// successful no-op security updates. The frontend returns its result without
    /// imposing mutation or reading the descriptor back.
    async fn set_security(
        &self,
        _file: &Self::File,
        _information: SecurityInformation,
        _descriptor: &SecurityDescriptor,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        Err(Status::INVALID_DEVICE_REQUEST)
    }
    /// Read at most `length` bytes from a default data stream.
    /// SMB authorizes READ through either FILE_READ_DATA or FILE_EXECUTE.
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
    /// The engine may request fresh snapshots when continuing an enumeration.
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
    /// Reserve allocation without extending EOF; smaller reservations may truncate it.
    async fn set_allocation_size(
        &self,
        _file: &Self::File,
        _length: u64,
        _request: &RequestContext,
    ) -> Result<(), Status> {
        Err(Status::NOT_SUPPORTED)
    }
    /// Update per-open mode and return the applied mode, retaining immutable flags.
    async fn set_mode(
        &self,
        _file: &Self::File,
        _mode: u32,
        _request: &RequestContext,
    ) -> Result<u32, Status> {
        Err(Status::NOT_SUPPORTED)
    }
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
    access
}
