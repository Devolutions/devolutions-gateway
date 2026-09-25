//! CONTRACT.md §3: metadata limits and friendly-name format evaluation.

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
pub(crate) const MAX_METADATA_TOTAL_BYTES: usize = 8 * 1024;
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
/// `{{`/`}}` escape braces, result trimmed and truncated to 255 chars, empty falls back
/// to the device ID.
pub(crate) fn render_friendly_name(
    format: &str,
    metadata: &Map<String, Value>,
    token_name: &str,
    device_id: uuid::Uuid,
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
    let trimmed = out.trim();
    let truncated: String = trimmed.chars().take(MAX_FRIENDLY_NAME_CHARS).collect();
    if truncated.is_empty() {
        device_id.to_string()
    } else {
        truncated
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
