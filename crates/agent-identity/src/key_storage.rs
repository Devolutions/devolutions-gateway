//! Key storage names ([CONTRACT.agent-identity.md §5.7 "Key storage"][key-storage]) and the device-key backend each
//! one names on this machine.
//!
//! [key-storage]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#key-storage

use std::fmt;

use anyhow::{Context as _, ensure};
use camino::Utf8Path;
use device_key::{BackendUnavailable, KeyBackend};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

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

/// A key storage policy, `config.key_storage` ([CONTRACT.agent-identity.md §5.7 "Key storage"][key-storage]).
///
/// [key-storage]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#key-storage
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyStoragePolicy {
    /// The key storages a new key goes to, in the authority's order of preference.
    pub backends: Vec<KeyStorage>,
    /// Whether a new key never goes outside `backends`, even when none of them is available.
    pub required: bool,
}

impl KeyStoragePolicy {
    /// The most key storages a policy lists.
    const MAX_BACKENDS: usize = 8;

    /// Reads the key storage policy of a config, `Ok(None)` when it has none.
    ///
    /// An error means the policy is malformed, which the agent treats as absent.
    /// Unknown members of the policy are ignored, as receivers ignore unknown JSON fields
    /// ([CONTRACT.agent-identity.md §1 "Protocol conventions"][conventions]).
    ///
    /// [conventions]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#1-protocol-conventions
    pub fn from_config(config: &Value) -> anyhow::Result<Option<Self>> {
        let policy = match config.get("key_storage") {
            // An optional field may be `null`, which means absent.
            None | Some(Value::Null) => return Ok(None),
            Some(Value::Object(policy)) => policy,
            Some(_) => anyhow::bail!("key storage policy is not an object"),
        };
        let names = policy
            .get("backends")
            .and_then(Value::as_array)
            .context("key storage policy has no backends array")?;
        ensure!(
            (1..=Self::MAX_BACKENDS).contains(&names.len()),
            "key storage policy lists {} key storages instead of 1 to {}",
            names.len(),
            Self::MAX_BACKENDS
        );
        let mut backends = Vec::with_capacity(names.len());
        for name in names {
            let storage = KeyStorage::parse(name.as_str().context("key storage name is not a string")?)?;
            ensure!(!backends.contains(&storage), "key storage policy repeats {storage}");
            backends.push(storage);
        }
        let required = policy
            .get("required")
            .and_then(Value::as_bool)
            .context("key storage policy has no boolean required")?;
        Ok(Some(Self { backends, required }))
    }

    /// Returns whether the policy holds every renewal back: it is required and none of its key storages is available.
    pub(crate) fn holds_renewal(&self, check: impl Fn(&KeyStorage) -> anyhow::Result<()>) -> anyhow::Result<bool> {
        Ok(self.required && self.first_available(check)?.is_none())
    }

    /// Returns whether the policy calls for a renewal of a key in `current`: it is required, excludes `current`, and
    /// one of its key storages is available.
    pub(crate) fn calls_for_renewal(
        &self,
        current: &KeyStorage,
        check: impl Fn(&KeyStorage) -> anyhow::Result<()>,
    ) -> anyhow::Result<bool> {
        Ok(self.required && !self.backends.contains(current) && self.first_available(check)?.is_some())
    }

    /// Returns the first of the policy's key storages that `check` finds available.
    ///
    /// An error other than an unavailable key storage stops the search, so that a passing failure never places a key in
    /// a key storage the authority prefers less, nor holds a renewal back.
    fn first_available(
        &self,
        check: impl Fn(&KeyStorage) -> anyhow::Result<()>,
    ) -> anyhow::Result<Option<&KeyStorage>> {
        for storage in &self.backends {
            match check(storage) {
                Ok(()) => return Ok(Some(storage)),
                Err(error) if unavailable_key_storage(&error).is_some() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }
}

/// Where a new key of an identity goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Placement {
    /// In this key storage of the policy.
    Listed(KeyStorage),
    /// In the agent's own choice of key storage.
    Default,
    /// Nowhere: no key is created.
    Held,
}

/// Places a new key of an identity under `policy`, given `check`, which tells whether a key storage is available.
pub(crate) fn place_new_key(
    policy: Option<&KeyStoragePolicy>,
    check: impl Fn(&KeyStorage) -> anyhow::Result<()>,
) -> anyhow::Result<Placement> {
    let Some(policy) = policy else {
        return Ok(Placement::Default);
    };
    Ok(match policy.first_available(check)? {
        Some(storage) => Placement::Listed(storage.clone()),
        None if policy.required => Placement::Held,
        None => Placement::Default,
    })
}

/// No new key of an identity is created, because its required key storage policy lists no available key storage
/// ([CONTRACT.agent-identity.md §5.7 "Key storage"][key-storage]).
///
/// Callers find it with [`renewal_held`].
///
/// [key-storage]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#key-storage
#[derive(Debug)]
pub struct RenewalHeld;

impl fmt::Display for RenewalHeld {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the required key storage policy lists no available key storage")
    }
}

impl std::error::Error for RenewalHeld {}

/// Returns whether an error reports a renewal that the identity's key storage policy holds back.
pub fn renewal_held(error: &anyhow::Error) -> bool {
    error.downcast_ref::<RenewalHeld>().is_some()
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
    use serde_json::json;

    use super::*;

    fn policy(backends: &[&str], required: bool) -> anyhow::Result<KeyStoragePolicy> {
        Ok(KeyStoragePolicy {
            backends: backends
                .iter()
                .map(|name| KeyStorage::parse(name))
                .collect::<anyhow::Result<_>>()?,
            required,
        })
    }

    /// Returns a check that finds available only the key storages named in `available`.
    fn available_among(available: &'static [&'static str]) -> impl Fn(&KeyStorage) -> anyhow::Result<()> {
        move |storage| {
            if available.contains(&storage.as_str()) {
                Ok(())
            } else {
                Err(storage.unavailable("not available in this test"))
            }
        }
    }

    fn listed(name: &'static str) -> Placement {
        Placement::Listed(KeyStorage::known(name))
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // The agent creates each new key in the first of `backends` available on the device; when none is, it creates the
    // key in a key storage of its own choosing unless `required` is `true`.
    #[rstest]
    #[case::first_listed_available(
        &["tpm", "windows_software_provider", "file"],
        true,
        &["file", "windows_software_provider"],
        listed(KeyStorage::WINDOWS_SOFTWARE_PROVIDER)
    )]
    #[case::in_the_authority_s_order(
        &["file", "windows_software_provider"],
        true,
        &["windows_software_provider", "file"],
        listed(KeyStorage::FILE)
    )]
    #[case::listed_available_not_required(
        &["tpm", "file"],
        false,
        &["file", "windows_software_provider"],
        listed(KeyStorage::FILE)
    )]
    #[case::none_available_not_required(&["tpm", "future_storage"], false, &["file"], Placement::Default)]
    #[case::none_available_required(&["tpm", "future_storage"], true, &["file"], Placement::Held)]
    fn a_new_key_follows_the_policy(
        #[case] backends: &[&str],
        #[case] required: bool,
        #[case] available: &'static [&'static str],
        #[case] expected: Placement,
    ) -> anyhow::Result<()> {
        let policy = policy(backends, required)?;
        assert_eq!(place_new_key(Some(&policy), available_among(available))?, expected);
        Ok(())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // Without a policy, the agent creates the key in a key storage of its own choosing.
    #[test]
    fn a_new_key_without_a_policy_takes_the_default() -> anyhow::Result<()> {
        assert_eq!(place_new_key(None, available_among(&["file"]))?, Placement::Default);
        Ok(())
    }

    // oracle: mutant a failed availability check counts as an unavailable key storage, which places the key lower
    // A key storage whose availability can't be determined stops the choice instead of counting as unavailable, so
    // that a passing failure never places a key in a key storage the authority prefers less, or holds a renewal back.
    #[test]
    fn a_failed_availability_check_stops_the_placement() -> anyhow::Result<()> {
        let policy = policy(&["windows_software_provider", "file"], false)?;
        let failing = |storage: &KeyStorage| {
            if storage.as_str() == KeyStorage::WINDOWS_SOFTWARE_PROVIDER {
                anyhow::bail!("access denied")
            }
            Ok(())
        };
        assert!(place_new_key(Some(&policy), failing).is_err());
        Ok(())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // While `required` is `true` and none of `backends` is available, the agent sends no `renew` request.
    #[rstest]
    #[case::required_none_available(true, &["file"], true)]
    #[case::required_one_available(true, &["file", "windows_software_provider"], false)]
    #[case::not_required_none_available(false, &["file"], false)]
    fn a_required_policy_without_an_available_key_storage_holds_renewal(
        #[case] required: bool,
        #[case] available: &'static [&'static str],
        #[case] holds: bool,
    ) -> anyhow::Result<()> {
        let policy = policy(&["tpm", "windows_software_provider"], required)?;
        assert_eq!(policy.holds_renewal(available_among(available))?, holds);
        Ok(())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // The agent renews without waiting for its schedule when `required` is `true`, the key storage of its current key is
    // not in `backends`, and one of `backends` is available.
    #[rstest]
    #[case::required_current_outside_listed_available(true, "file", &["file", "windows_software_provider"], true)]
    #[case::required_current_listed(true, "windows_software_provider", &["file", "windows_software_provider"], false)]
    #[case::not_required(false, "file", &["file", "windows_software_provider"], false)]
    #[case::required_none_available(true, "file", &["file"], false)]
    fn a_required_policy_that_excludes_the_current_key_calls_for_renewal(
        #[case] required: bool,
        #[case] current: &str,
        #[case] available: &'static [&'static str],
        #[case] calls: bool,
    ) -> anyhow::Result<()> {
        let policy = policy(&["tpm", "windows_software_provider"], required)?;
        let current = KeyStorage::parse(current)?;
        assert_eq!(policy.calls_for_renewal(&current, available_among(available))?, calls);
        Ok(())
    }

    fn eight_names() -> Value {
        Value::from((1..=8).map(|index| format!("storage_{index}")).collect::<Vec<_>>())
    }

    fn nine_names() -> Value {
        Value::from((1..=9).map(|index| format!("storage_{index}")).collect::<Vec<_>>())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    #[rstest]
    #[case::contract_example(
        json!({ "backends": ["tpm", "windows_software_provider"], "required": true }),
        &["tpm", "windows_software_provider"],
        true
    )]
    #[case::not_required(json!({ "backends": ["file"], "required": false }), &["file"], false)]
    #[case::unknown_name(json!({ "backends": ["future_storage"], "required": true }), &["future_storage"], true)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    // Receivers ignore unknown JSON fields.
    #[case::unknown_member(
        json!({ "backends": ["file"], "required": false, "future_member": [1] }),
        &["file"],
        false
    )]
    fn reads_a_well_formed_policy(
        #[case] key_storage: Value,
        #[case] backends: &[&str],
        #[case] required: bool,
    ) -> anyhow::Result<()> {
        let config = json!({ "version": 1, "revision": 1, "key_storage": key_storage });
        assert_eq!(
            KeyStoragePolicy::from_config(&config)?,
            Some(policy(backends, required)?)
        );
        Ok(())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // `backends` holds 1 to 8 names.
    #[test]
    fn reads_a_policy_of_eight_key_storages() -> anyhow::Result<()> {
        let config =
            json!({ "version": 1, "revision": 1, "key_storage": { "backends": eight_names(), "required": true } });
        let read = KeyStoragePolicy::from_config(&config)?.context("no policy read")?;
        assert_eq!(read.backends.len(), 8);
        Ok(())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    // `key_storage` is absent when the authority sets none, and an optional field may be `null`.
    #[rstest]
    #[case::absent(json!({ "version": 1, "revision": 1 }))]
    #[case::null(json!({ "version": 1, "revision": 1, "key_storage": null }))]
    fn a_config_without_a_policy_has_none(#[case] config: Value) -> anyhow::Result<()> {
        assert_eq!(KeyStoragePolicy::from_config(&config)?, None);
        Ok(())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    #[rstest]
    #[case::string(json!("tpm"))]
    #[case::array(json!(["tpm"]))]
    #[case::boolean(json!(true))]
    #[case::without_backends(json!({ "required": true }))]
    #[case::without_required(json!({ "backends": ["tpm"] }))]
    #[case::backends_not_an_array(json!({ "backends": "tpm", "required": true }))]
    #[case::backends_null(json!({ "backends": null, "required": true }))]
    #[case::empty_backends(json!({ "backends": [], "required": true }))]
    #[case::nine_backends(json!({ "backends": nine_names(), "required": true }))]
    #[case::repeated_name(json!({ "backends": ["tpm", "file", "tpm"], "required": true }))]
    #[case::malformed_name(json!({ "backends": ["file", "Windows-Software-Provider"], "required": false }))]
    #[case::name_not_a_string(json!({ "backends": ["file", 1], "required": false }))]
    #[case::required_a_string(json!({ "backends": ["file"], "required": "true" }))]
    #[case::required_null(json!({ "backends": ["file"], "required": null }))]
    fn a_malformed_policy_is_refused(#[case] key_storage: Value) {
        let config = json!({ "version": 1, "revision": 1, "key_storage": key_storage });
        assert!(KeyStoragePolicy::from_config(&config).is_err());
    }

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
        assert_eq!(serde_json::from_value::<KeyStorage>(Value::from(name))?.as_str(), name);
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
        assert!(serde_json::from_value::<KeyStorage>(Value::from(name)).is_err());
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
