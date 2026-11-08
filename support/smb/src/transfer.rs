// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Transport-owned external data access, independent of filesystem providers.

use crate::spec::Status;

/// Access needed to an external buffer.
#[derive(Clone, Copy)]
pub enum Direction {
    /// Read the source of a filesystem WRITE.
    Read,
    /// Write the destination of a filesystem READ.
    Write,
}

/// A transport's external READ/WRITE buffers.
///
/// Descriptor validation must finish before filesystem effects. Implementations
/// own descriptor interpretation and retain their memory resources until the
/// connection's accepted operations have drained.
#[async_trait::async_trait]
pub trait ExternalData: Send + Sync {
    /// Validate the complete descriptor and its capacity without changing data.
    fn validate(
        &self,
        channel: u32,
        descriptor: &[u8],
        length: usize,
        direction: Direction,
    ) -> Result<(), Status>;

    /// Copy an external WRITE source into owned server storage.
    async fn read(&self, channel: u32, descriptor: &[u8], length: usize)
    -> Result<Vec<u8>, Status>;

    /// Publish actual READ bytes to an external destination.
    async fn write(&self, channel: u32, descriptor: &[u8], bytes: &[u8]) -> Result<(), Status>;
}
