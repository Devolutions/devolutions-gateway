mod file;
#[cfg(windows)]
mod keystore;
#[cfg(windows)]
mod windows_acl;

use anyhow::ensure;
use camino::Utf8PathBuf;
use p256::ecdsa::{Signature, VerifyingKey};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum KeyBackend {
    /// Creating a key waits at most five seconds for another creator of the same name.
    WindowsSoftwareProvider,
    /// File operations wait at most five seconds for the key-directory lock.
    File { dir: Utf8PathBuf },
}

/// A requested backend is unavailable on this platform or machine.
///
/// Operations return [`anyhow::Error`]; callers can distinguish this failure with
/// `error.downcast_ref::<device_key::BackendUnavailable>()`.
#[derive(Debug)]
pub struct BackendUnavailable {
    pub backend: &'static str,
}

impl std::fmt::Display for BackendUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "backend {} is unavailable", self.backend)
    }
}

impl std::error::Error for BackendUnavailable {}

/// A device key exposes its public key and fallible raw P-256 signatures, but not its private key.
pub trait DeviceKey: Send + Sync {
    fn name(&self) -> &str;
    fn public_key(&self) -> VerifyingKey;
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature>;
}

pub fn new_key_name(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4())
}

pub fn generate(backend: &KeyBackend, name: &str) -> anyhow::Result<Box<dyn DeviceKey>> {
    validate_name(name)?;
    match backend {
        #[cfg(windows)]
        KeyBackend::WindowsSoftwareProvider => keystore::generate(name),
        #[cfg(not(windows))]
        KeyBackend::WindowsSoftwareProvider => Err(BackendUnavailable {
            backend: "WindowsSoftwareProvider",
        }
        .into()),
        KeyBackend::File { dir } => file::generate(dir, name),
    }
}

pub fn open(backend: &KeyBackend, name: &str) -> anyhow::Result<Option<Box<dyn DeviceKey>>> {
    validate_name(name)?;
    match backend {
        #[cfg(windows)]
        KeyBackend::WindowsSoftwareProvider => keystore::open(name),
        #[cfg(not(windows))]
        KeyBackend::WindowsSoftwareProvider => Err(BackendUnavailable {
            backend: "WindowsSoftwareProvider",
        }
        .into()),
        KeyBackend::File { dir } => file::open(dir, name),
    }
}

pub fn delete(backend: &KeyBackend, name: &str) -> anyhow::Result<()> {
    validate_name(name)?;
    match backend {
        #[cfg(windows)]
        KeyBackend::WindowsSoftwareProvider => keystore::delete(name),
        #[cfg(not(windows))]
        KeyBackend::WindowsSoftwareProvider => Err(BackendUnavailable {
            backend: "WindowsSoftwareProvider",
        }
        .into()),
        KeyBackend::File { dir } => file::delete(dir, name),
    }
}

pub fn list(backend: &KeyBackend, prefix: &str) -> anyhow::Result<Vec<String>> {
    validate_prefix(prefix)?;
    match backend {
        #[cfg(windows)]
        KeyBackend::WindowsSoftwareProvider => keystore::list(prefix),
        #[cfg(not(windows))]
        KeyBackend::WindowsSoftwareProvider => Err(BackendUnavailable {
            backend: "WindowsSoftwareProvider",
        }
        .into()),
        KeyBackend::File { dir } => file::list(dir, prefix),
    }
}

/// Checks the lowercase prefix used to create and list device keys.
pub fn validate_prefix(prefix: &str) -> anyhow::Result<()> {
    ensure!(
        (1..=64).contains(&prefix.len())
            && prefix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "invalid device key prefix: expected 1-64 lowercase letters, digits or hyphens"
    );
    Ok(())
}

fn validate_name(name: &str) -> anyhow::Result<()> {
    let (prefix, part) = name
        .split_once('_')
        .ok_or_else(|| anyhow::anyhow!("invalid device key name"))?;
    validate_prefix(prefix)?;
    ensure!(
        (1..=128).contains(&part.len())
            && part
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')),
        "invalid device key name"
    );
    Ok(())
}

fn name_matches_prefix(name: &str, prefix: &str) -> bool {
    name.split_once('_')
        .is_some_and(|(name_prefix, _)| name_prefix == prefix && validate_name(name).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    // oracle: intent crates/device-key/INTENT.md §Key name
    #[test]
    fn key_names_are_well_formed_and_scoped() -> anyhow::Result<()> {
        let name = new_key_name("devolutions-agent-identity");
        validate_name(&name)?;
        // oracle: intent crates/device-key/INTENT.md §Operations
        assert!(name_matches_prefix(&name, "devolutions-agent-identity"));
        // oracle: intent crates/device-key/INTENT.md §Operations
        assert!(!name_matches_prefix(&name, "devolutions-agent"));
        validate_name(&format!("{}_{}", "a".repeat(64), "z_9-".repeat(32)))?;
        for invalid in [
            "",
            "no-part_",
            "_no-prefix",
            "upper_X",
            "Upper-case_foo",
            "invalid/name_part",
            "prefix_part.with.dot",
            "prefix_part with space",
            "prefix_part/with/slash",
            "prefix_é",
        ] {
            assert!(validate_name(invalid).is_err(), "{invalid}");
        }
        assert!(validate_name(&format!("a_{}", "b".repeat(129))).is_err());
        assert!(validate_name(&format!("{}_b", "a".repeat(65))).is_err());
        assert!(validate_prefix(&"a".repeat(65)).is_err());
        assert!(validate_prefix("A").is_err());
        assert!(validate_prefix("a_b").is_err());
        assert!(validate_prefix("").is_err());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Backends
    #[cfg(not(windows))]
    #[test]
    fn windows_provider_is_distinguishably_unavailable() -> anyhow::Result<()> {
        let backend = KeyBackend::WindowsSoftwareProvider;
        let name = new_key_name("test");
        for error in [
            generate(&backend, &name)
                .err()
                .ok_or_else(|| anyhow::anyhow!("unexpected key"))?,
            open(&backend, &name)
                .err()
                .ok_or_else(|| anyhow::anyhow!("unexpected key"))?,
            delete(&backend, &name)
                .err()
                .ok_or_else(|| anyhow::anyhow!("unexpected key"))?,
            list(&backend, "test")
                .err()
                .ok_or_else(|| anyhow::anyhow!("unexpected key list"))?,
        ] {
            assert_eq!(
                error.downcast_ref::<BackendUnavailable>().map(|error| error.backend),
                Some("WindowsSoftwareProvider")
            );
        }
        Ok(())
    }
}
