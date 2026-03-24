/// Current protocol version.
pub const CURRENT_PROTOCOL_VERSION: u16 = 1;

/// Minimum protocol version that is still accepted.
pub const MIN_SUPPORTED_VERSION: u16 = 1;

/// Validate that a received protocol version is within the supported range.
pub fn validate_protocol_version(version: u16) -> Result<(), crate::error::ProtoError> {
    if version < MIN_SUPPORTED_VERSION || version > CURRENT_PROTOCOL_VERSION {
        return Err(crate::error::ProtoError::UnsupportedVersion {
            received: version,
            min: MIN_SUPPORTED_VERSION,
            max: CURRENT_PROTOCOL_VERSION,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_current_version() {
        assert!(validate_protocol_version(CURRENT_PROTOCOL_VERSION).is_ok());
    }

    #[test]
    fn reject_zero_version() {
        assert!(validate_protocol_version(0).is_err());
    }

    #[test]
    fn reject_future_version() {
        assert!(validate_protocol_version(CURRENT_PROTOCOL_VERSION + 1).is_err());
    }
}
