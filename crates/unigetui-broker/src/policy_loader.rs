//! Policy file loader.
//!
//! Loads policy documents from the configured directory:
//! `%PROGRAMDATA%/Devolutions/Agent/unigetui-policy.json`

use std::path::{Path, PathBuf};

use crate::models::PolicyDocument;

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

/// Load a policy document from a file path.
///
/// Deserialization performs all validation (structure, types, length constraints, patterns).
pub fn load_policy(path: &Path) -> anyhow::Result<PolicyDocument> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read policy file at {}: {e}", path.display()))?;

    let policy: PolicyDocument =
        serde_json::from_str(&content).map_err(|e| anyhow::anyhow!("invalid policy at {}: {e}", path.display()))?;

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
