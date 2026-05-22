//! Policy file loader.
//!
//! Loads policy documents from the configured directory:
//! `%PROGRAMDATA%/Devolutions/Agent/unigetui-policy.json`

use std::path::{Path, PathBuf};

use crate::models::PolicyDocument;
use crate::schema::SchemaValidators;

/// Default policy directory.
pub fn default_policy_dir() -> PathBuf {
    if cfg!(windows) {
        let program_data = std::env::var("PROGRAMDATA").unwrap_or_else(|_| r"C:\ProgramData".to_owned());
        PathBuf::from(program_data).join("Devolutions").join("Agent")
    } else {
        PathBuf::from("/etc/devolutions-agent")
    }
}

/// Default policy file name.
pub const POLICY_FILE_NAME: &str = "unigetui-policy.json";

/// Load a policy document from a file path, validating against the generated JSON Schema.
pub fn load_policy(path: &Path, validators: &SchemaValidators) -> anyhow::Result<PolicyDocument> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read policy file at {}: {e}", path.display()))?;

    let value: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("failed to parse policy JSON at {}: {e}", path.display()))?;

    // Validate against generated schema.
    crate::evaluator::validate_policy(validators, &value)
        .map_err(|e| anyhow::anyhow!("policy schema validation failed at {}: {e}", path.display()))?;

    // Deserialize into typed struct (this also validates enum values via serde).
    let policy: PolicyDocument = serde_json::from_value(value)
        .map_err(|e| anyhow::anyhow!("policy deserialization failed at {}: {e}", path.display()))?;

    tracing::info!(
        policy_id = %policy.metadata.id,
        revision = policy.metadata.revision,
        rules_count = policy.rules.len(),
        "Loaded policy"
    );

    Ok(policy)
}

/// Find the policy file in the default location.
pub fn find_default_policy() -> anyhow::Result<PathBuf> {
    let dir = default_policy_dir();
    let path = dir.join(POLICY_FILE_NAME);
    if path.exists() {
        Ok(path)
    } else {
        anyhow::bail!(
            "policy file not found at {}; create the file to enable the broker",
            path.display()
        )
    }
}
