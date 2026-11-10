// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Request-scoped provider locks and shared synthetic enforcement.

pub mod software;

use super::{ByteRange, FileSystem, LockId, RequestContext};
use crate::spec::Status;
use async_trait::async_trait;

/// How the protocol settles the successfully processed prefix of a lock request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockSettlement {
    /// Retain the successful prefix, including on a later validation failure.
    Preserve,
    /// Remove only this request's acquisitions, never earlier locks or unlocks.
    Rollback,
}

/// One lock request's ownership and rollback window.
///
/// Retain every operation future through actual completion. Explicitly settle
/// the scope before returning a protocol result. Dropping a scope is not a
/// request to undo accepted work; providers must retain accurate prefix state.
#[async_trait]
pub trait LockScope: Send {
    /// Acquire a range without publishing a rollback token beyond this request.
    async fn lock(
        &mut self,
        range: ByteRange,
        exclusive: bool,
        fail_immediately: bool,
        request: &RequestContext,
    ) -> Result<(), Status>;

    /// Remove an ordinary exact match, preferring exclusive locks.
    async fn unlock(&mut self, range: ByteRange, request: &RequestContext) -> Result<(), Status>;

    /// End the rollback window. Supply an uncancelled cleanup context even
    /// when the originating request was cancelled after acquiring locks.
    async fn settle(
        self: Box<Self>,
        settlement: LockSettlement,
        request: &RequestContext,
    ) -> Result<(), Status>;
}

/// Adapt acquisition-ID hooks when a provider selects its software configuration.
pub fn with_ids<'a, B: FileSystem + ?Sized>(
    backend: &'a B,
    file: &'a B::File,
) -> Box<dyn LockScope + 'a> {
    Box::new(IdScope::new(backend, file))
}

pub(super) struct IdScope<'a, B: FileSystem + ?Sized> {
    backend: &'a B,
    file: &'a B::File,
    acquired: Vec<LockId>,
}

impl<'a, B: FileSystem + ?Sized> IdScope<'a, B> {
    pub fn new(backend: &'a B, file: &'a B::File) -> Self {
        Self {
            backend,
            file,
            acquired: Vec::new(),
        }
    }
}

#[async_trait]
impl<B: FileSystem + ?Sized> LockScope for IdScope<'_, B> {
    async fn lock(
        &mut self,
        range: ByteRange,
        exclusive: bool,
        fail_immediately: bool,
        request: &RequestContext,
    ) -> Result<(), Status> {
        let id = self
            .backend
            .lock(self.file, range, exclusive, fail_immediately, request)
            .await?;
        self.acquired.push(id);
        Ok(())
    }

    async fn unlock(&mut self, range: ByteRange, request: &RequestContext) -> Result<(), Status> {
        self.backend.unlock(self.file, range, request).await
    }

    async fn settle(
        self: Box<Self>,
        settlement: LockSettlement,
        request: &RequestContext,
    ) -> Result<(), Status> {
        if settlement == LockSettlement::Rollback {
            for &id in self.acquired.iter().rev() {
                self.backend.rollback_lock(self.file, id, request).await?;
            }
        }
        Ok(())
    }
}
