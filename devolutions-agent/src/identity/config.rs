//! The `Identity` and `__debug__.identity` sections of `agent.json`.

use anyhow::Context as _;
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

use crate::config::normalize_data_path;

#[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum IdentityKeyBackend {
    WindowsSoftwareProvider,
    File,
}

impl Default for IdentityKeyBackend {
    fn default() -> Self {
        if cfg!(windows) {
            Self::WindowsSoftwareProvider
        } else {
            Self::File
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IdentityConf {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub key_backend: IdentityKeyBackend,
}

impl Default for IdentityConf {
    fn default() -> Self {
        Self {
            enabled: true,
            key_backend: IdentityKeyBackend::default(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(PartialEq, Eq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityDebugConf {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renewal_after_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_jitter: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_trusted_root: Option<Utf8PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backoff_max_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_poll_interval_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acl_grant_current_user: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_name_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_override_path: Option<Utf8PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_in_interval_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_failure_check_in_after_secs: Option<u64>,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

impl IdentityDebugConf {
    pub fn has_settings(&self) -> bool {
        *self != Self::default()
    }

    /// Validates the key-name prefix and resolves relative paths against the data directory.
    pub(crate) fn normalize(&mut self, data_dir: &Utf8Path) -> anyhow::Result<()> {
        if let Some(prefix) = &self.key_name_prefix {
            device_key::validate_prefix(prefix).context("invalid __debug__.identity.key_name_prefix")?;
        }
        self.extra_trusted_root = self
            .extra_trusted_root
            .as_deref()
            .map(|path| normalize_data_path(path, data_dir));
        self.metadata_override_path = self
            .metadata_override_path
            .as_deref()
            .map(|path| normalize_data_path(path, data_dir));
        Ok(())
    }
}

/// Logs the start-up warning required whenever `__debug__.identity` contains a setting.
pub fn warn_about_debug_settings(settings: Option<&IdentityDebugConf>) {
    if settings.is_some_and(IdentityDebugConf::has_settings) {
        warn!("Agent Identity debug settings are enabled; remove __debug__.identity for production");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Conf, dto};

    #[test]
    fn identity_config_parses_all_debug_controls_and_defaults() -> anyhow::Result<()> {
        let config: dto::ConfFile = serde_json::from_value(serde_json::json!({
            "Identity": { "KeyBackend": "File" },
            "__debug__": {
                "identity": {
                    "renewal_after_secs": 1,
                    "disable_jitter": false,
                    "extra_trusted_root": "ca.pem",
                    "backoff_max_secs": 2,
                    "pending_poll_interval_ms": 200,
                    "acl_grant_current_user": true,
                    "key_name_prefix": "test-run",
                    "metadata_override_path": "metadata.json",
                    "check_in_interval_secs": 3,
                    "channel_failure_check_in_after_secs": 4
                }
            }
        }))?;
        let identity = config.identity.context("missing identity config")?;
        assert!(identity.enabled);
        assert_eq!(identity.key_backend, IdentityKeyBackend::File);
        let debug = config
            .debug
            .context("missing debug config")?
            .identity
            .context("missing identity debug config")?;
        assert!(debug.has_settings());
        assert_eq!(debug.renewal_after_secs, Some(1));
        assert_eq!(debug.disable_jitter, Some(false));
        assert_eq!(debug.extra_trusted_root.as_deref(), Some(Utf8Path::new("ca.pem")));
        assert_eq!(debug.backoff_max_secs, Some(2));
        assert_eq!(debug.pending_poll_interval_ms, Some(200));
        assert_eq!(debug.acl_grant_current_user, Some(true));
        assert_eq!(debug.key_name_prefix.as_deref(), Some("test-run"));
        assert_eq!(
            debug.metadata_override_path.as_deref(),
            Some(Utf8Path::new("metadata.json"))
        );
        assert_eq!(debug.check_in_interval_secs, Some(3));
        assert_eq!(debug.channel_failure_check_in_after_secs, Some(4));
        let empty: IdentityDebugConf = serde_json::from_str("{}")?;
        assert!(!empty.has_settings());
        let explicit_false: IdentityDebugConf = serde_json::from_str(r#"{"disable_jitter":false}"#)?;
        assert!(explicit_false.has_settings());
        Ok(())
    }

    #[test]
    fn identity_backend_values_are_platform_independent() -> anyhow::Result<()> {
        for (backend, expected) in [
            ("File", IdentityKeyBackend::File),
            ("WindowsSoftwareProvider", IdentityKeyBackend::WindowsSoftwareProvider),
        ] {
            let file: dto::ConfFile = serde_json::from_value(serde_json::json!({"Identity": {"KeyBackend": backend}}))?;
            assert_eq!(Conf::from_conf_file(&file)?.identity.key_backend, expected);
        }
        let config: IdentityConf = serde_json::from_str("{}")?;
        let expected = if cfg!(windows) {
            IdentityKeyBackend::WindowsSoftwareProvider
        } else {
            IdentityKeyBackend::File
        };
        assert_eq!(config.key_backend, expected);
        assert!(serde_json::from_str::<IdentityKeyBackend>("\"KeyStore\"").is_err());
        Ok(())
    }

    #[test]
    fn invalid_identity_key_prefix_is_rejected_at_config_load() -> anyhow::Result<()> {
        for prefix in ["", "Upper", "with_underscore", &"a".repeat(65)] {
            let file: dto::ConfFile =
                serde_json::from_value(serde_json::json!({"__debug__": {"identity": {"key_name_prefix": prefix}}}))?;
            let error = Conf::from_conf_file(&file)
                .err()
                .context("invalid identity key prefix was accepted")?;
            assert!(
                format!("{error:#}").contains("__debug__.identity.key_name_prefix"),
                "{error:#}"
            );
        }
        Ok(())
    }
}
