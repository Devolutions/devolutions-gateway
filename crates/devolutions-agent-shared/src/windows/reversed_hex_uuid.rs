//! Windows-specific UUID format conversion functions.

use std::str::FromStr;

use uuid::Uuid;

const REVERSED_UUID_STR_LENGTH: usize = uuid::fmt::Simple::LENGTH;
const UUID_REVERSING_PATTERN: &[usize] = &[8, 4, 4, 2, 2, 2, 2, 2, 2, 2, 2];

#[derive(Debug, thiserror::Error)]
#[error("invalid UUID representation {uuid}")]
pub struct InvalidReversedHexUuid {
    uuid: String,
}

/// Converts standard UUID to its reversed hex representation used in Windows Registry
/// for upgrade code table.
///
/// e.g.: `{82318d3c-811f-4d5d-9a82-b7c31b076755}` => `C3D81328F118D5D4A9287B3CB1707655`
pub(crate) fn uuid_to_reversed_hex(uuid: Uuid) -> String {
    let mut simple_uuid_buffer = [0u8; REVERSED_UUID_STR_LENGTH];
    let mut hex_chars_slice: &str = uuid.as_simple().encode_upper(&mut simple_uuid_buffer);

    let mut reversed_hex = String::with_capacity(REVERSED_UUID_STR_LENGTH);

    for block_len in UUID_REVERSING_PATTERN.iter() {
        let (block, rest) = hex_chars_slice.split_at(*block_len);
        reversed_hex.extend(block.chars().rev());
        hex_chars_slice = rest;
    }

    assert!(
        reversed_hex.len() == REVERSED_UUID_STR_LENGTH,
        "UUID_REVERSING_PATTERN should ensure output length"
    );

    reversed_hex
}

/// Converts reversed hex UUID back to standard Windows Registry format (upper case letters).
///
/// e.g.: `C3D81328F118D5D4A9287B3CB1707655` => `{82318d3c-811f-4d5d-9a82-b7c31b076755}`
pub(crate) fn reversed_hex_to_uuid(mut hex: &str) -> Result<Uuid, InvalidReversedHexUuid> {
    if hex.len() != REVERSED_UUID_STR_LENGTH {
        return Err(InvalidReversedHexUuid { uuid: hex.to_owned() });
    }

    let mut uuid_chars = String::with_capacity(uuid::fmt::Simple::LENGTH);

    for pattern in UUID_REVERSING_PATTERN.iter() {
        let (part, rest) = hex.split_at(*pattern);
        uuid_chars.extend(part.chars().rev());
        hex = rest;
    }

    assert!(
        uuid_chars.len() == REVERSED_UUID_STR_LENGTH,
        "UUID_REVERSING_PATTERN should ensure output length"
    );

    let uuid = Uuid::from_str(&uuid_chars).map_err(|_| InvalidReversedHexUuid { uuid: hex.to_owned() })?;

    Ok(uuid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_uuid_to_reversed_hex() {
        assert_eq!(
            uuid_to_reversed_hex(uuid::uuid!("{82318d3c-811f-4d5d-9a82-b7c31b076755}")),
            "C3D81328F118D5D4A9287B3CB1707655"
        );
    }

    #[test]
    fn convert_reversed_hex_to_uuid() {
        assert_eq!(
            reversed_hex_to_uuid("C3D81328F118D5D4A9287B3CB1707655").expect("failed to convert reversed hex to UUID"),
            uuid::uuid!("{82318D3C-811F-4D5D-9A82-B7C31B076755}")
        );
    }

    #[test]
    fn reversed_hex_to_uuid_failure() {
        assert!(reversed_hex_to_uuid("XXX81328F118D5D4A9287B3CB1707655").is_err());
        assert!(reversed_hex_to_uuid("ABCD").is_err());
    }
}
