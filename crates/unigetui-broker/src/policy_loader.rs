//! Policy file loader.
//!
//! Loads policy documents from the configured directory.
//! Supports both JSON (`.json`) and YAML (`.yaml`, `.yml`) formats.
//! Default location: `%PROGRAMDATA%/Devolutions/Agent/`

use std::path::{Path, PathBuf};

use crate::model::PolicyDocument;

/// Default policy directory.
pub fn default_policy_dir() -> PathBuf {
    if cfg!(windows) {
        let program_data = std::env::var("PROGRAMDATA").unwrap_or_else(|_| r"C:\ProgramData".to_owned());
        PathBuf::from(program_data).join("Devolutions").join("Agent")
    } else {
        PathBuf::from("/etc/devolutions-agent")
    }
}

/// Base name for the policy file (without extension).
const POLICY_FILE_BASE: &str = "unigetui-policy";

/// Supported policy file extensions in priority order.
const POLICY_EXTENSIONS: &[&str] = &["json", "yaml", "yml"];

/// Load a policy document from a file path.
///
/// The file format is detected from the extension:
/// - `.json` — parsed as JSON
/// - `.yaml` or `.yml` — parsed as YAML
///
/// Deserialization performs all validation (structure, types, length constraints, patterns).
pub fn load_policy(path: &Path) -> anyhow::Result<PolicyDocument> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read policy file at {}: {e}", path.display()))?;

    let policy = deserialize_policy(&content, path)?;

    tracing::info!(
        policy_id = %policy.metadata.id,
        revision = policy.metadata.revision,
        rules_count = policy.rules.len(),
        "Loaded policy"
    );

    Ok(policy)
}

/// Deserialize policy content, detecting format from file extension.
fn deserialize_policy(content: &str, path: &Path) -> anyhow::Result<PolicyDocument> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match ext.as_str() {
        "yaml" | "yml" => serde_yaml::from_str(content)
            .map_err(|e| anyhow::anyhow!("invalid YAML policy at {}: {e}", path.display())),
        _ => serde_json::from_str(content)
            .map_err(|e| anyhow::anyhow!("invalid JSON policy at {}: {e}", path.display())),
    }
}

/// Find the policy file in the default location.
///
/// Searches for `unigetui-policy.{json,yaml,yml}` in priority order.
pub fn find_default_policy() -> anyhow::Result<PathBuf> {
    let dir = default_policy_dir();

    for ext in POLICY_EXTENSIONS {
        let path = dir.join(format!("{POLICY_FILE_BASE}.{ext}"));
        if path.exists() {
            return Ok(path);
        }
    }

    anyhow::bail!(
        "policy file not found in {}; create unigetui-policy.{{json,yaml,yml}} to enable the broker",
        dir.display()
    )
}
