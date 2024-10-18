//! Windows-specific UUID format conversion functions.

use smallvec::SmallVec;

use crate::updater::UpdaterError;

const UUID_CHARS: usize = 32;
const UUID_REVERSING_PATTERN: &[usize] = &[8, 4, 4, 2, 2, 2, 2, 2, 2, 2, 2];
const UUID_ALPHABET: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

/// Converts standard UUID to its reversed hex representation used in Windows Registry
/// for upgrade code table.
///
/// e.g.: `{82318d3c-811f-4d5d-9a82-b7c31b076755}` => `C3D81328F118D5D4A9287B3CB1707655`
pub fn uuid_to_reversed_hex(uuid: &str) -> Result<String, UpdaterError> {
    const IGNORED_CHARS: &[char] = &['-', '{', '}'];

    let hex_chars = uuid
        .chars()
        .filter_map(|ch| {
            if IGNORED_CHARS.contains(&ch) {
                return None;
            }

            Some(ch.to_ascii_uppercase())
        })
        .collect::<SmallVec<[char; 32]>>();

    let mut hex_chars_slice = hex_chars.as_slice();

    let mut reversed_hex = String::with_capacity(UUID_CHARS);

    for block_len in UUID_REVERSING_PATTERN.iter() {
        let (block, rest) = hex_chars_slice.split_at(*block_len);
        reversed_hex.extend(block.iter().copied().rev());
        hex_chars_slice = rest;
    }

    if reversed_hex.len() != 32 || reversed_hex.chars().any(|ch| !UUID_ALPHABET.contains(&ch)) {
        return Err(UpdaterError::Uuid { uuid: uuid.to_string() });
    }

    Ok(reversed_hex)
}

/// Converts reversed hex UUID back to standard Windows Registry format (upper case letters).
///
/// e.g.: `C3D81328F118D5D4A9287B3CB1707655` => `{82318d3c-811f-4d5d-9a82-b7c31b076755}`
pub fn reversed_hex_to_uuid(mut hex: &str) -> Result<String, UpdaterError> {
    if hex.len() != 32 || hex.chars().any(|ch| !UUID_ALPHABET.contains(&ch)) {
        return Err(UpdaterError::Uuid { uuid: hex.to_string() });
    }

    const FORMATTED_UUID_LEN: usize = UUID_CHARS
        + 4 // hyphens
        + 2; // braces

    let mut formatted = String::with_capacity(FORMATTED_UUID_LEN);

    formatted.push('{');

    // Hyphen pattern is not same as reversing pattern blocks.
    const HYPEN_PATTERN: &[usize] = &[1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0];

    for (pattern, hypen) in UUID_REVERSING_PATTERN.iter().zip(HYPEN_PATTERN) {
        let (part, rest) = hex.split_at(*pattern);
        formatted.extend(part.chars().rev());

        if *hypen == 1 {
            formatted.push('-');
        }
        hex = rest;
    }

    formatted.push('}');

    Ok(formatted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_to_reversed_hex() {
        assert_eq!(
            uuid_to_reversed_hex("{82318d3c-811f-4d5d-9a82-b7c31b076755}").unwrap(),
            "C3D81328F118D5D4A9287B3CB1707655"
        );
    }

    #[test]
    fn test_format_win_hex_uuid() {
        assert_eq!(
            reversed_hex_to_uuid("C3D81328F118D5D4A9287B3CB1707655").unwrap(),
            "{82318D3C-811F-4D5D-9A82-B7C31B076755}"
        );
    }
}
