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
        total += key.len() + value.len();
    }
    if total > MAX_METADATA_TOTAL_BYTES {
        return Err(format!("metadata object exceeds {MAX_METADATA_TOTAL_BYTES} bytes"));
    }
    Ok(())
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

    use super::render_friendly_name;

    /// [Shared intent][intent] ("Enrollment"): "The result is trimmed, truncated to 255 Unicode scalar values without splitting one,
    /// and trimmed again, so a stored name never starts or ends with white space (Unicode `White_Space`);
    /// an empty result falls back to the identity ID."
    ///
    /// [intent]: ../../../docs/agent-identity/INTENT.agent-identity.md#enrollment
    #[rstest]
    #[case::trimmed_again_after_truncation(format!("{} b", "a".repeat(254)), "a".repeat(254))]
    #[case::trimmed_before_truncation(format!("  {}", "a".repeat(255)), "a".repeat(255))]
    #[case::truncated_by_scalar_value("é".repeat(300), "é".repeat(255))]
    #[case::unicode_white_space("\u{3000}host\u{a0}\u{2029}".to_owned(), "host".to_owned())]
    #[case::not_white_space("\u{200b}host".to_owned(), "\u{200b}host".to_owned())]
    #[case::empty_falls_back_to_identity_id("\u{3000} ".to_owned(), uuid::Uuid::nil().to_string())]
    fn friendly_name_is_trimmed_truncated_and_trimmed_again(#[case] hostname: String, #[case] expected: String) {
        let metadata = Map::from_iter([("hostname".to_owned(), Value::String(hostname))]);
        assert_eq!(
            render_friendly_name("{hostname}", &metadata, "token", uuid::Uuid::nil()),
            expected
        );
    }
}
