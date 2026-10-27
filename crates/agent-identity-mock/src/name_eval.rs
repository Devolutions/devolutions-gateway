//! Metadata limits ([CONTRACT.agent-identity.md][contract], "3. Metadata") and friendly-name format evaluation
//! ([shared intent][intent], "Enrollment").
//!
//! [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#3-metadata
//! [intent]: ../../../docs/agent-identity/INTENT.agent-identity.md#enrollment

use serde_json::{Map, Value};

/// Known metadata keys (placeholders besides `token_name`).
pub(crate) const KNOWN_KEYS: [&str; 8] = [
    "hostname",
    "fqdn",
    "domain",
    "os_name",
    "os_version",
    "arch",
    "agent_version",
    "machine_id",
];

pub(crate) const MAX_METADATA_KEYS: usize = 32;
pub(crate) const MAX_METADATA_VALUE_BYTES: usize = 1024;
pub(crate) const MAX_METADATA_TOTAL_BYTES: usize = 16 * 1024;
pub(crate) const MAX_FRIENDLY_NAME_CHARS: usize = 255;
pub(crate) const DEFAULT_FRIENDLY_NAME_FORMAT: &str = "{hostname}";

/// Validates a metadata object against the §3 limits. Returns a message for
/// `invalid_request` on violation.
pub(crate) fn validate_metadata(metadata: &Map<String, Value>) -> Result<(), String> {
    if metadata.len() > MAX_METADATA_KEYS {
        return Err(format!("metadata has more than {MAX_METADATA_KEYS} keys"));
    }
    let mut total = 0usize;
    for (key, value) in metadata {
        if !valid_metadata_key(key) {
            return Err(format!("invalid metadata key {key:?}"));
        }
        let Value::String(value) = value else {
            return Err(format!("metadata value for {key:?} is not a string"));
        };
        if value.len() > MAX_METADATA_VALUE_BYTES {
            return Err(format!(
                "metadata value for {key:?} exceeds {MAX_METADATA_VALUE_BYTES} bytes"
            ));
        }
        if value
            .chars()
            .any(|c| c < '\u{20}' || ('\u{7f}'..='\u{9f}').contains(&c))
        {
            return Err(format!("metadata value for {key:?} contains control characters"));
        }
        if value.chars().any(is_invisible_format_character) {
            return Err(format!(
                "metadata value for {key:?} contains invisible format characters"
            ));
        }
        total += key.len() + value.len();
    }
    if total > MAX_METADATA_TOTAL_BYTES {
        return Err(format!("metadata object exceeds {MAX_METADATA_TOTAL_BYTES} bytes"));
    }
    Ok(())
}

/// Whether `c` is an invisible format character that [CONTRACT.agent-identity.md][contract] ("3. Metadata") refuses in a metadata value.
///
/// The contract lists them as code points rather than as Unicode general category `Cf`, so that the agent and every authority agree on the set whatever Unicode version their runtimes ship.
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#3-metadata
fn is_invisible_format_character(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{61c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

fn valid_metadata_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    key.len() <= 64 && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Validates a friendly-name format at token creation: placeholders must be known and
/// braces balanced. Returns a message for a 400 on violation.
pub(crate) fn validate_friendly_name_format(format: &str) -> Result<(), String> {
    parse_format(format).map(|_| ())
}

/// Renders the friendly name: validated format, missing values evaluate to empty,
/// `{{`/`}}` escape braces, and the result is trimmed, truncated to 255 Unicode scalar values and trimmed again.
/// `str::trim` removes exactly Unicode `White_Space`; an empty result falls back to the identity ID.
pub(crate) fn render_friendly_name(
    format: &str,
    metadata: &Map<String, Value>,
    token_name: &str,
    identity_id: uuid::Uuid,
) -> String {
    let mut out = String::new();
    // The format was validated at token creation.
    if let Ok(parts) = parse_format(format) {
        for part in parts {
            match part {
                FormatPart::Literal(text) => out.push_str(text),
                FormatPart::Placeholder("token_name") => out.push_str(token_name),
                FormatPart::Placeholder(name) => {
                    if let Some(value) = metadata.get(name).and_then(Value::as_str) {
                        out.push_str(value);
                    }
                }
            }
        }
    }
    let truncated: String = out.trim().chars().take(MAX_FRIENDLY_NAME_CHARS).collect();
    let trimmed = truncated.trim();
    if trimmed.is_empty() {
        identity_id.to_string()
    } else {
        trimmed.to_owned()
    }
}

enum FormatPart<'a> {
    Literal(&'a str),
    Placeholder(&'a str),
}

fn parse_format(format: &str) -> Result<Vec<FormatPart<'_>>, String> {
    let mut rest = format;
    let mut parts = Vec::new();
    while let Some(pos) = rest.find(['{', '}']) {
        parts.push(FormatPart::Literal(&rest[..pos]));
        let tail = &rest[pos..];
        if let Some(stripped) = tail.strip_prefix("{{") {
            parts.push(FormatPart::Literal("{"));
            rest = stripped;
        } else if let Some(stripped) = tail.strip_prefix("}}") {
            parts.push(FormatPart::Literal("}"));
            rest = stripped;
        } else if let Some(stripped) = tail.strip_prefix('{') {
            let end = stripped.find('}').ok_or_else(|| "unclosed `{` in format".to_owned())?;
            let name = &stripped[..end];
            if name.is_empty() {
                return Err("empty placeholder in format".to_owned());
            }
            if !KNOWN_KEYS.contains(&name) && name != "token_name" {
                return Err(format!("unknown placeholder {{{name}}}"));
            }
            parts.push(FormatPart::Placeholder(name));
            rest = &stripped[end + 1..];
        } else {
            return Err("unpaired `}` in format".to_owned());
        }
    }
    parts.push(FormatPart::Literal(rest));
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::{Map, Value};

    use super::{render_friendly_name, validate_metadata};

    /// `count` entries `k00`, `k01`… whose values are `value_len` bytes.
    fn entries(count: usize, value_len: usize) -> Map<String, Value> {
        (0..count)
            .map(|i| (format!("k{i:02}"), Value::String("v".repeat(value_len))))
            .collect()
    }

    /// 16 entries of 3-byte keys and 1021-byte values, 16 × 1024 = 16,384 bytes, with one value a byte longer.
    fn one_byte_past_16_kib() -> Map<String, Value> {
        let mut metadata = entries(16, 1021);
        metadata.insert("k00".to_owned(), Value::String("v".repeat(1022)));
        metadata
    }

    fn with_key(key: &str) -> Map<String, Value> {
        Map::from_iter([(key.to_owned(), Value::String("v".to_owned()))])
    }

    fn with_value(value: &str) -> Map<String, Value> {
        Map::from_iter([("hostname".to_owned(), Value::String(value.to_owned()))])
    }

    /// CONTRACT.agent-identity.md §3 limits: at most 32 keys, each matching `^[a-z][a-z0-9_]{0,63}$`, each value at most 1024 UTF-8 bytes without a C0, DEL or C1 control character or a listed invisible format character, and at most 16 KiB of keys and values in all.
    /// The tests below cover the invisible format characters.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    #[rstest]
    #[case::keys_32(entries(32, 1), true)]
    #[case::keys_33(entries(33, 1), false)]
    #[case::key_64_bytes(with_key(&"k".repeat(64)), true)]
    #[case::key_65_bytes(with_key(&"k".repeat(65)), false)]
    #[case::key_leading_digit(with_key("1k"), false)]
    #[case::key_uppercase(with_key("kK"), false)]
    #[case::value_1024_bytes(with_value(&"é".repeat(512)), true)]
    #[case::value_1025_bytes(with_value(&format!("{}x", "é".repeat(512))), false)]
    #[case::space(with_value(" "), true)]
    #[case::c0_unit_separator(with_value("\u{1f}"), false)]
    #[case::del(with_value("\u{7f}"), false)]
    #[case::c1_application_program_command(with_value("\u{9f}"), false)]
    #[case::no_break_space(with_value("\u{a0}"), true)]
    #[case::total_16_kib(entries(16, 1021), true)]
    #[case::total_past_16_kib(one_byte_past_16_kib(), false)]
    fn metadata_limits_follow_the_contract(#[case] metadata: Map<String, Value>, #[case] accepted: bool) {
        assert_eq!(validate_metadata(&metadata).is_ok(), accepted);
    }

    /// Whether a value holding `c` between other characters is accepted.
    fn accepts_value_holding(c: char) -> bool {
        validate_metadata(&with_value(&format!("host{c}name"))).is_ok()
    }

    /// CONTRACT.agent-identity.md §3 refuses a value holding an invisible format character, which it lists as these code points and ranges, so the code points on either side of each are accepted.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    #[rstest]
    #[case::soft_hyphen('\u{ad}', '\u{ad}')]
    #[case::arabic_letter_mark('\u{61c}', '\u{61c}')]
    #[case::mongolian_vowel_separator('\u{180e}', '\u{180e}')]
    #[case::zero_width_and_directional_marks('\u{200b}', '\u{200f}')]
    #[case::directional_embeddings_and_overrides('\u{202a}', '\u{202e}')]
    #[case::word_joiner_and_invisible_operators('\u{2060}', '\u{2064}')]
    #[case::directional_isolates_and_deprecated_formats('\u{2066}', '\u{206f}')]
    #[case::zero_width_no_break_space('\u{feff}', '\u{feff}')]
    #[case::interlinear_annotations('\u{fff9}', '\u{fffb}')]
    #[case::language_tag('\u{e0001}', '\u{e0001}')]
    #[case::tags('\u{e0020}', '\u{e007f}')]
    fn listed_format_characters_are_refused_but_not_their_neighbors(#[case] first: char, #[case] last: char) {
        for c in first..=last {
            assert!(!accepts_value_holding(c), "U+{:04X} is accepted", u32::from(c));
        }
        let before = char::from_u32(u32::from(first) - 1).expect("not a surrogate");
        let after = char::from_u32(u32::from(last) + 1).expect("not a surrogate");
        for c in [before, after] {
            assert!(accepts_value_holding(c), "U+{:04X} is refused", u32::from(c));
        }
    }

    /// CONTRACT.agent-identity.md §3 refuses only the invisible format characters it lists as code points, so a code point of Unicode general category `Cf` that it leaves out is accepted.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    #[rstest]
    #[case::arabic_number_signs('\u{600}', '\u{605}')]
    #[case::arabic_end_of_ayah('\u{6dd}', '\u{6dd}')]
    #[case::syriac_abbreviation_mark('\u{70f}', '\u{70f}')]
    #[case::arabic_pound_and_piastre_marks_above('\u{890}', '\u{891}')]
    #[case::arabic_disputed_end_of_ayah('\u{8e2}', '\u{8e2}')]
    #[case::kaithi_number_sign('\u{110bd}', '\u{110bd}')]
    #[case::kaithi_number_sign_above('\u{110cd}', '\u{110cd}')]
    #[case::egyptian_hieroglyph_format_controls('\u{13430}', '\u{1343f}')]
    #[case::shorthand_format_controls('\u{1bca0}', '\u{1bca3}')]
    #[case::musical_symbol_beams_and_phrases('\u{1d173}', '\u{1d17a}')]
    fn format_characters_the_contract_leaves_out_are_accepted(#[case] first: char, #[case] last: char) {
        for c in first..=last {
            assert!(accepts_value_holding(c), "U+{:04X} is refused", u32::from(c));
        }
    }

    /// [Shared intent][intent] ("Enrollment"): "The result is trimmed, truncated to 255 Unicode scalar values without splitting one,
    /// and trimmed again, so a stored name never starts or ends with white space (Unicode `White_Space`);
    /// an empty result falls back to the identity ID."
    ///
    /// [intent]: ../../../docs/agent-identity/INTENT.agent-identity.md#enrollment
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Enrollment
    #[rstest]
    #[case::trimmed_again_after_truncation(format!("{} b", "a".repeat(254)), "a".repeat(254))]
    #[case::trimmed_before_truncation(format!("  {}", "a".repeat(255)), "a".repeat(255))]
    #[case::truncated_by_scalar_value("é".repeat(300), "é".repeat(255))]
    #[case::unicode_white_space("\u{3000}host\u{a0}\u{2029}".to_owned(), "host".to_owned())]
    #[case::not_white_space("\u{2800}host".to_owned(), "\u{2800}host".to_owned())]
    #[case::empty_falls_back_to_identity_id("\u{3000} ".to_owned(), uuid::Uuid::nil().to_string())]
    fn friendly_name_is_trimmed_truncated_and_trimmed_again(#[case] hostname: String, #[case] expected: String) {
        let metadata = Map::from_iter([("hostname".to_owned(), Value::String(hostname))]);
        assert_eq!(
            render_friendly_name("{hostname}", &metadata, "token", uuid::Uuid::nil()),
            expected
        );
    }
}
