//! Installer-only document conversion; callers retain responsibility for source trust and publication.

use anyhow::{Context as _, bail};
use serde::Deserialize;
use serde_json::value::RawValue;

const LEGACY_SCHEMA: &str = "https://devolutions.net/schemas/now-policy.schema.1.0.json";
pub const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct LegacyDocument<'a> {
    #[serde(rename = "$schema")]
    schema: String,
    policy_version: now_policy::PolicyFormatVersion,
    #[serde(borrow)]
    policy_type: &'a RawValue,
    #[serde(borrow)]
    metadata: &'a RawValue,
    #[serde(borrow)]
    enforcement: &'a RawValue,
    #[serde(borrow)]
    rules: &'a RawValue,
}

/// Convert a committed legacy document without rewriting its publisher-authored values.
///
/// # Errors
///
/// Rejects oversized, ambiguous, unsupported or invalid documents.
pub fn convert_document(input: &str) -> anyhow::Result<String> {
    if input.len() as u64 > MAX_DOCUMENT_BYTES {
        bail!("policy exceeds the installer migration size limit");
    }
    // Parse typed text, not a Value: duplicate fields must not be collapsed.
    let output = if now_policy::schema::parse_policy_json(input).is_ok() {
        input.to_owned()
    } else {
        let legacy: LegacyDocument<'_> =
            serde_json::from_str(input).context("invalid or unsupported legacy policy document")?;
        if legacy.schema != LEGACY_SCHEMA {
            bail!("unsupported legacy policy schema");
        }
        // Keep raw values: reserializing typed metadata would normalize timestamps,
        // optional fields and sets, changing the publisher's original content.
        format!(
            "{{\"PolicyFormatVersion\":{},\"PolicyType\":{},\"Metadata\":{},\"Enforcement\":{},\"Rules\":{}}}",
            serde_json::to_string(&legacy.policy_version)?,
            legacy.policy_type,
            legacy.metadata,
            legacy.enforcement,
            legacy.rules,
        )
    };
    let policy = now_policy::schema::parse_policy_json(&output).map_err(anyhow::Error::msg)?;
    let validation = crate::policy_store::validation::validate_committed_policy(&policy);
    if !validation.is_valid {
        bail!(
            "converted policy failed authoritative validation: {:?}",
            validation.findings
        );
    }
    Ok(output)
}
