// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code to recover a corrupt TPM NVRAM blob due to truncation.

use crate::TpmError;
use crate::TpmErrorKind;
use vmcore::non_volatile_store::NonVolatileStore;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

const LEGACY_SIZE: usize = 16384;
const FULL_SIZE: usize = 32768;

fn is_good_blob(blob: &[u8]) -> bool {
    check_blob(blob).is_some()
}

/// Check if the TPM blob's persistent data structures all fit inside it.
///
/// This can return false if the blob was incorrectly truncated (by a previous
/// bug that reported a 32KB blob size for a 16KB blob).
fn check_blob(blob: &[u8]) -> Option<()> {
    const NV_USER_DYNAMIC: usize = 3508; // from the TPM reference implementation
    let mut dynamic = blob.get(NV_USER_DYNAMIC..)?;
    loop {
        let size = u32::from_ne_bytes(dynamic.get(..4)?.try_into().unwrap());
        if size == 0 {
            break;
        }
        dynamic = dynamic.get((size as usize)..)?;
    }
    Some(())
}

#[repr(C)]
#[derive(AsBytes, FromBytes, FromZeroes)]
struct OriginalSize {
    size: u32,
}

pub async fn recover_blob(
    blob: &mut Vec<u8>,
    original_nvram_size_store: &mut dyn NonVolatileStore,
) -> Result<(), TpmError> {
    if blob.len() != LEGACY_SIZE {
        tracing::debug!("TPM NVRAM size is not legacy size, skipping recovery");
        return Ok(());
    }
    if is_good_blob(&blob) {
        tracing::debug!("TPM NVRAM is already good, skipping recovery");
        return Ok(());
    }
    blob.resize(FULL_SIZE, 0);
    if is_good_blob(&blob) {
        tracing::warn!("recovered undersized TPM NVRAM");
        // Save the original size for diagnostics and future use.
        original_nvram_size_store
            .persist(
                OriginalSize {
                    size: blob.len() as u32,
                }
                .as_bytes()
                .to_vec(),
            )
            .await
            .map_err(TpmErrorKind::FailedToWriteOriginalSize)?;
    } else {
        tracing::error!("failed to recover corrupt TPM NVRAM, continuing anyway");
        blob.truncate(LEGACY_SIZE);
    }

    Ok(())
}
