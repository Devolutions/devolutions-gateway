//! File integrity validation utilities.

use sha2::{Digest as _, Sha256};

use crate::updater::{UpdaterCtx, UpdaterError};

/// Validate the hash of downloaded artifact (Hash should be provided in encoded hex string).
pub(crate) fn validate_artifact_hash(ctx: &UpdaterCtx, data: &[u8], hash: &str) -> Result<(), UpdaterError> {
    let expected_hash_bytes = hex::decode(hash).map_err(|_| UpdaterError::HashEncoding {
        product: ctx.product,
        hash: hash.to_owned(),
    })?;

    let actual_hash_bytes = Sha256::digest(data);

    let actual_hash_slice: &[u8] = actual_hash_bytes.as_ref();

    if expected_hash_bytes.as_slice() != actual_hash_slice {
        return Err(UpdaterError::IntegrityCheck {
            product: ctx.product,
            expected_hash: hex::encode(expected_hash_bytes),
            actual_hash: hex::encode(actual_hash_slice),
        });
    }

    Ok(())
}
