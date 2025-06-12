// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code to recover a corrupt TPM NVRAM blob due to truncation.

use crate::TpmError;
use crate::TpmErrorKind;
use vmcore::non_volatile_store::NonVolatileStore;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

const LEGACY_SIZE: usize = 16384;
const FULL_SIZE: usize = 32768;

fn is_good_blob(blob: &[u8]) -> bool {
    check_blob(blob).is_some()
}

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
#[derive(IntoBytes, FromBytes)]
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
        original_nvram_size_store
            .persist(16384u32.to_le_bytes().to_vec())
            .await
            .map_err(TpmErrorKind::FailedToWriteOriginalSize)?;
    } else {
        tracing::error!("failed to recover corrupt TPM NVRAM, continuing anyway");
        blob.truncate(LEGACY_SIZE);
    }

    Ok(())
}
