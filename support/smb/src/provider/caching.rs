// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provider-owned caching coherence, independent of SMB packet layouts.

use super::RequestContext;
use crate::spec::Status;
use async_trait::async_trait;
use inspect::Inspect;
use std::sync::Arc;

/// Classic opportunistic caching requested for one open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Oplock {
    /// Read caching shared with other readers.
    LevelII,
    /// Read and write caching.
    Exclusive,
    /// Read, write and handle caching.
    Batch,
}

/// Semantic caching rights, including the states supported by SMB 2.1 leases.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CachingState {
    /// No caching rights.
    #[default]
    None,
    /// Read caching.
    Read,
    /// Read and write caching.
    ReadWrite,
    /// Read and handle caching.
    ReadHandle,
    /// Read, write and handle caching.
    ReadWriteHandle,
}

/// Client-scoped lease identity, independent of a connection or open handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseIdentity {
    /// Client identity established at protocol negotiation.
    pub client_guid: [u8; 16],
    /// Opaque client-assigned lease key.
    pub key: [u8; 16],
}

/// Caching requested as part of opening a filesystem object.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CachingRequest {
    /// Open without acquiring caching rights; the result must be CachingGrant::None.
    #[default]
    None,
    /// A classic, per-open oplock.
    Oplock(Oplock),
    /// A lease that may be shared by multiple opens from the same client.
    Lease {
        /// Identity of the lease, not the file.
        identity: LeaseIdentity,
        /// Requested caching rights.
        state: CachingState,
    },
}

/// Caching actually acquired by an open. Absence of a grant is not an error.
///
/// The provider must coordinate grants and breaks with every conflicting effect,
/// including other opens, truncation, namespace changes and external mutations.
/// A grant is a coherence guarantee, not merely an indication of read-only access.
/// Related lease opens share provider state; closing one must not revoke another.
pub enum CachingGrant {
    /// No rights were acquired, including when the provider does not support caching.
    None,
    /// A classic oplock associated with this open.
    Oplock {
        /// Actual level, which may be weaker than the request.
        level: Oplock,
        /// Provider-owned break delivery and completion.
        control: Arc<dyn Caching>,
    },
    /// A lease associated with the client's identity and file.
    Lease {
        /// Lease identity retained by the provider.
        identity: LeaseIdentity,
        /// Actual rights, including previously held rights on an existing lease.
        state: CachingState,
        /// An existing lease is already being broken.
        breaking: bool,
        /// Provider-owned state shared by the lease's opens.
        control: Arc<dyn Caching>,
    },
}

/// Result of a provider open, including optional caching rights.
pub struct Opened<F> {
    /// Provider-owned open object.
    pub file: F,
    /// FILE_SUPERSEDED/OPENED/CREATED/OVERWRITTEN create-action value.
    pub action: u32,
    /// Rights actually acquired, never inferred by the caller.
    pub caching: CachingGrant,
}

/// Provider-assigned identity of one break, distinct from protocol request IDs.
///
/// Identities must not be reused during the caching control's lifetime, so a late
/// completion cannot acknowledge a subsequent break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachingBreakId(pub u64);

/// A provider's request to relinquish caching rights before a conflicting effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachingBreak {
    /// Identity used to complete this particular break.
    pub id: CachingBreakId,
    /// Maximum rights that may remain after the break.
    pub state: CachingState,
}

/// Retained provider control for an oplock or lease.
///
/// The engine owns client routing, wire notifications, acknowledgment validation
/// and timers. It completes breaks here after client acknowledgment, immediately
/// when no client acknowledgment is needed, or with no rights on timeout.
/// The provider owns object identity, conflicting-operation admission and coherence.
///
/// Closing the last associated provider open releases the caching reservation and
/// wakes pending waits with FILE_CLOSED. Retaining this control must not keep an
/// otherwise closed file or lease alive. Dropping provider files must provide the
/// same fallback release as other open-owned state. A shared lease control survives
/// until its last associated open closes, not merely the open delivering a break.
#[async_trait]
pub trait Caching: Inspect + Send + Sync {
    /// Wait for the next break. The caller serializes waits for each control.
    ///
    /// Cancellation removes this waiter, not the caching reservation or a queued
    /// break. Once returned, the break remains outstanding until acknowledged or
    /// released by close. Do not lose breaks between consecutive waits.
    async fn wait_for_break(&self, request: &RequestContext) -> Result<CachingBreak, Status>;

    /// Complete a particular break and return the rights actually retained.
    ///
    /// The provider may retain fewer rights than requested. Reject stale break IDs
    /// and incompatible states without completing another break. Use an independent
    /// uncancelled request for timeout/teardown cleanup; late cancellation must not
    /// hide an acknowledgment that already took effect.
    async fn acknowledge(
        &self,
        id: CachingBreakId,
        state: CachingState,
        request: &RequestContext,
    ) -> Result<CachingState, Status>;
}
