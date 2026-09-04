//! Policy file loader.
//!
//! Loads policy documents from the configured directory.
//! Supports JSON (`.json`) policies.
//! Default location: `%PROGRAMDATA%/Devolutions/Agent/`

use std::io::Read as _;
use std::path::{Path, PathBuf};

use now_policy::PolicyDocument;
use now_policy::schema::parse_policy_json;
use tracing::info;

use crate::policy_security;

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
const POLICY_FILE_BASE: &str = "package-broker-policy";

/// Load a policy document from a file path.
///
/// The file must use the `.json` extension.
///
/// Deserialization performs all validation (structure, types, length constraints, patterns).
///
/// Before trusting the policy, the file's owner and DACL are verified to restrict write
/// access to SYSTEM/Administrators.
/// This function fails when the check does not pass, so the broker pauses (fail-closed).
pub fn load_policy(path: &Path) -> anyhow::Result<PolicyDocument> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open policy file at {}: {e}", path.display()))?;

    // Verify security on the open handle (not the path), and read from the same handle,
    // so the verified security descriptor belongs to the very same file being parsed.
    policy_security::verify_policy_file_security(&file)
        .map_err(|e| anyhow::anyhow!("policy file at {} failed security validation: {e}", path.display()))?;

    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| anyhow::anyhow!("failed to read policy file at {}: {e}", path.display()))?;

    let policy = deserialize_policy(&content, path)?;

    info!(
        policy_id = %policy.metadata.id,
        revision = policy.metadata.revision,
        rules_count = policy.rules.len(),
        "Loaded policy"
    );

    Ok(policy)
}

/// Deserialize JSON policy content.
fn deserialize_policy(content: &str, path: &Path) -> anyhow::Result<PolicyDocument> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if ext != "json" {
        anyhow::bail!(
            "unsupported policy file extension at {}; expected .json",
            path.display()
        );
    }

    parse_policy_json(content).map_err(|e| anyhow::anyhow!("invalid JSON policy at {}: {e}", path.display()))
}

/// Find the policy file in the default location.
///
/// Looks for `package-broker-policy.json`.
pub fn find_default_policy() -> anyhow::Result<PathBuf> {
    let dir = default_policy_dir();
    if let Some(path) = find_default_policy_in(&dir) {
        return Ok(path);
    }

    anyhow::bail!(
        "policy file not found in {}; create package-broker-policy.json to enable the broker",
        dir.display()
    )
}

fn find_default_policy_in(dir: &Path) -> Option<PathBuf> {
    let path = dir.join(format!("{POLICY_FILE_BASE}.json"));
    path.exists().then_some(path)
}

/// Candidate default policy path used when no default policy file exists yet.
pub fn default_policy_candidate() -> PathBuf {
    default_policy_dir().join(format!("{POLICY_FILE_BASE}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_policy_is_supported() {
        deserialize_policy(
            include_str!("assets/samples/corporate-allowlist.policy.json"),
            Path::new("policy.json"),
        )
        .expect("deserialize JSON policy");
    }

    #[test]
    fn yaml_policy_extension_is_rejected() {
        for path in ["policy.yaml", "policy.yml"] {
            let error = deserialize_policy("Rules: []", Path::new(path)).expect_err("reject YAML policy extension");
            assert_eq!(
                error.to_string(),
                format!("unsupported policy file extension at {path}; expected .json")
            );
        }
    }

    #[test]
    fn yaml_content_with_json_extension_is_rejected() {
        let error = deserialize_policy("Rules: []", Path::new("policy.json")).expect_err("reject YAML policy content");
        assert!(error.to_string().starts_with("invalid JSON policy at policy.json:"));
    }

    #[test]
    fn default_discovery_ignores_yaml_policy_files() {
        let dir = tempfile::tempdir().expect("create temporary policy directory");
        std::fs::write(dir.path().join("package-broker-policy.yaml"), "Rules: []").expect("write YAML policy");
        std::fs::write(dir.path().join("package-broker-policy.yml"), "Rules: []").expect("write YML policy");

        assert_eq!(find_default_policy_in(dir.path()), None);

        let json_path = dir.path().join("package-broker-policy.json");
        std::fs::write(&json_path, "{}").expect("write JSON policy");
        assert_eq!(find_default_policy_in(dir.path()), Some(json_path));
    }
}
