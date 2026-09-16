//! Policy file loader.
//!
//! Loads policy documents from the configured directory.
//! Supports JSON (`.json`) policies.
//! Policies use `%PROGRAMDATA%/Devolutions/PackageBroker/`.

use std::path::{Path, PathBuf};

fn program_data_dir() -> PathBuf {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

/// Directory used by the policy store.
pub fn default_policy_dir() -> PathBuf {
    program_data_dir().join("Devolutions").join("PackageBroker")
}

/// Base name for the policy file (without extension).
const POLICY_FILE_BASE: &str = "package-broker-policy";

/// Canonical policy path used when no explicit path is configured.
pub fn default_policy_path() -> PathBuf {
    default_policy_path_in(&program_data_dir())
}

fn default_policy_path_in(program_data: &Path) -> PathBuf {
    program_data
        .join("Devolutions")
        .join("PackageBroker")
        .join(format!("{POLICY_FILE_BASE}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_uses_the_canonical_managed_directory() {
        let root = tempfile::tempdir().expect("create policy root");
        let other = root
            .path()
            .join("Devolutions")
            .join("Agent")
            .join("package-broker-policy.json");
        std::fs::create_dir_all(other.parent().expect("other path has a parent")).expect("create other directory");
        std::fs::write(&other, "{}").expect("write other policy");
        let path = default_policy_path_in(root.path());

        assert_eq!(
            path.file_name().expect("default path has a leaf"),
            "package-broker-policy.json"
        );
        assert_eq!(
            path.parent()
                .and_then(Path::file_name)
                .expect("default path has a parent"),
            "PackageBroker"
        );
        assert_ne!(path, other);
    }
}
