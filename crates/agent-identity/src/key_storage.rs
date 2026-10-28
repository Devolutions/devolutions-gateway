//! Key storage names ([CONTRACT.agent-identity.md §5.7 "Key storage"][key-storage]) and the device-key backend each
//! one names on this machine.
//!
//! [key-storage]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#key-storage

use std::fmt;

use camino::Utf8Path;
use device_key::{BackendUnavailable, KeyBackend};
use serde::{Deserialize, Deserializer, Serialize};

/// A well-formed key storage name, which may name a key storage this agent doesn't know.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct KeyStorage(String);

impl KeyStorage {
    pub const FILE: &str = "file";
    pub const WINDOWS_SOFTWARE_PROVIDER: &str = "windows_software_provider";
    pub const TPM: &str = "tpm";

    /// Accepts a name matching `^[a-z][a-z0-9_]{0,63}$`.
    pub fn parse(name: &str) -> anyhow::Result<Self> {
        let mut bytes = name.bytes();
        anyhow::ensure!(
            name.len() <= 64
                && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
                && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
            "invalid key storage name"
        );
        Ok(Self(name.to_owned()))
    }

    pub(crate) fn known(name: &'static str) -> Self {
        Self(name.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the device-key backend this name stands for, or `None` for a name without one, such as `tpm` or a name
    /// this agent doesn't know.
    pub fn backend(&self, data_dir: &Utf8Path) -> Option<KeyBackend> {
        match self.as_str() {
            Self::FILE => Some(KeyBackend::File {
                dir: data_dir.join("identity").join("keys"),
            }),
            Self::WINDOWS_SOFTWARE_PROVIDER => Some(KeyBackend::WindowsSoftwareProvider),
            _ => None,
        }
    }

    /// Returns the error of a key storage that is unavailable for `reason`.
    pub(crate) fn unavailable(&self, reason: &'static str) -> anyhow::Error {
        anyhow::Error::new(KeyStorageUnavailable { storage: self.clone() }).context(reason)
    }

    /// Tags an error that the device-key crate reports as an unavailable backend with [`KeyStorageUnavailable`].
    pub(crate) fn classify(&self, error: anyhow::Error) -> anyhow::Error {
        if error.downcast_ref::<BackendUnavailable>().is_some() {
            error.context(KeyStorageUnavailable { storage: self.clone() })
        } else {
            error
        }
    }
}

impl fmt::Display for KeyStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for KeyStorage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Self::parse(&name).map_err(serde::de::Error::custom)
    }
}

/// A key storage that a key needs is not available on this machine, or has no backend in this agent.
///
/// Callers find it with [`unavailable_key_storage`].
#[derive(Debug)]
pub struct KeyStorageUnavailable {
    pub storage: KeyStorage,
}

impl fmt::Display for KeyStorageUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "key storage {} is unavailable", self.storage)
    }
}

impl std::error::Error for KeyStorageUnavailable {}

/// Returns the unavailable key storage an error reports, if any.
pub fn unavailable_key_storage(error: &anyhow::Error) -> Option<&KeyStorage> {
    error
        .downcast_ref::<KeyStorageUnavailable>()
        .map(|unavailable| &unavailable.storage)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    #[rstest]
    #[case::file("file")]
    #[case::windows_software_provider("windows_software_provider")]
    #[case::tpm("tpm")]
    #[case::unknown_name("future_storage_2")]
    #[case::one_letter("a")]
    #[case::sixty_four_characters("abcdefghijklmnopqrstuvwxyz0123456789_abcdefghijklmnopqrstuvwxyz0")]
    fn accepts_a_well_formed_name(#[case] name: &str) -> anyhow::Result<()> {
        assert_eq!(KeyStorage::parse(name)?.as_str(), name);
        assert_eq!(
            serde_json::from_value::<KeyStorage>(serde_json::Value::from(name))?.as_str(),
            name
        );
        Ok(())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    #[rstest]
    #[case::empty("")]
    #[case::leading_digit("1file")]
    #[case::leading_underscore("_file")]
    #[case::upper_case("File")]
    #[case::hyphen("windows-software-provider")]
    #[case::sixty_five_characters("abcdefghijklmnopqrstuvwxyz0123456789_abcdefghijklmnopqrstuvwxyz01")]
    #[case::non_ascii("fil\u{e9}")]
    fn refuses_a_malformed_name(#[case] name: &str) {
        assert!(KeyStorage::parse(name).is_err());
        assert!(serde_json::from_value::<KeyStorage>(serde_json::Value::from(name)).is_err());
    }

    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    // The file backend stores `<data-dir>/identity/keys/<key_name>.p8`.
    #[test]
    fn file_names_the_file_backend_under_the_data_directory() -> anyhow::Result<()> {
        let data_dir = Utf8Path::new("data");
        let backend = KeyStorage::parse("file")?.backend(data_dir);
        assert!(
            matches!(&backend, Some(KeyBackend::File { dir }) if *dir == data_dir.join("identity").join("keys")),
            "{backend:?}"
        );
        Ok(())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    #[test]
    fn windows_software_provider_names_the_windows_software_provider() -> anyhow::Result<()> {
        let backend = KeyStorage::parse("windows_software_provider")?.backend(Utf8Path::new("data"));
        assert!(
            matches!(backend, Some(KeyBackend::WindowsSoftwareProvider)),
            "{backend:?}"
        );
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Identities
    // TPM has no backend yet, and a well-formed name the agent doesn't know has none either.
    #[rstest]
    #[case::tpm("tpm")]
    #[case::unknown_name("future_storage")]
    fn a_name_without_a_backend_names_none(#[case] name: &str) -> anyhow::Result<()> {
        assert!(KeyStorage::parse(name)?.backend(Utf8Path::new("data")).is_none());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Backends
    // The device-key crate's unavailable-backend error, through any context, is what marks a key storage unavailable.
    #[test]
    fn only_an_unavailable_backend_marks_its_key_storage_unavailable() -> anyhow::Result<()> {
        let storage = KeyStorage::parse("windows_software_provider")?;
        let unavailable = storage.classify(anyhow::Error::new(BackendUnavailable {
            backend: "WindowsSoftwareProvider",
        }));
        assert_eq!(
            unavailable_key_storage(&unavailable.context("open key")),
            Some(&storage)
        );
        let failed = storage.classify(anyhow::anyhow!("access denied"));
        assert_eq!(unavailable_key_storage(&failed), None);
        Ok(())
    }
}
