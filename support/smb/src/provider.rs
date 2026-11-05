// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filesystem semantics independent of host files and VM resources.

use crate::protocol::Status;
use async_trait::async_trait;
use event_listener::Event;
use inspect::Inspect;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Identity and cooperative cancellation of one backend operation.
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

    /// Server-wide operation identity, distinct from the client's message ID.
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
    /// Whether deletion is pending.
    pub delete_pending: bool,
}

impl Metadata {
    /// Whether this object is a directory.
    pub fn is_directory(&self) -> bool {
        self.attributes & 0x10 != 0
    }
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
    /// Read at most `length` bytes from a default data stream.
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
    /// Set or clear delete-on-close on an open object.
    async fn set_delete_on_close(
        &self,
        file: &Self::File,
        delete: bool,
        request: &RequestContext,
    ) -> Result<(), Status>;
}

/// Expand generic access bits using the file-object generic mapping.
pub fn map_access(mut access: u32) -> u32 {
    for (generic, specific) in [
        (0x80000000, 0x120089),
        (0x40000000, 0x120116),
        (0x20000000, 0x1200a0),
        (0x10000000, 0x1f01ff),
    ] {
        if access & generic != 0 {
            access = (access & !generic) | specific;
        }
    }
    if access & 0x20 != 0 {
        access |= 1;
    }
    access
}
