//! Compatibility layer for legacy PowerShell Universal agent configuration.
//!
//! This module is concerned exclusively with parsing PowerShell Universal's *own*
//! configuration format (its `eventHubClient.json` / `agent.json` files and `PSU_`
//! environment variables) and importing it into the Devolutions Agent configuration.
//!
//! It is a temporary migration shim: long term, this foreign-format parsing is expected
//! to back a dedicated one-time migration step that rewrites the legacy files into the
//! native Devolutions Agent format, after which [`merge_into_conf_file`] can be removed.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;

use anyhow::{Context, bail};
use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;
use tap::prelude::*;
use url::Url;

use crate::config::dto;

/// Mirrors PowerShell Universal's own Event Hub client configuration file.
///
/// This is a foreign on-disk format, not part of the Devolutions Agent `agent.json` schema.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CompatFile {
    #[serde(default)]
    connections: Vec<dto::PsuEventHubConnectionConf>,
}

/// Imports legacy PowerShell Universal configuration into `conf_file`, if any is found.
///
/// The caller is responsible for gating this behind `enable_unstable`; this function only
/// asserts that invariant for sanity.
pub(crate) fn merge_into_conf_file(conf_file: &mut dto::ConfFile) -> anyhow::Result<()> {
    assert!(
        conf_file.debug.as_ref().is_some_and(|debug| debug.enable_unstable),
        "PowerShell Universal compatibility import must only run when unstable features are enabled"
    );

    let Some(compat_conf) = load_compat_config()? else {
        return Ok(());
    };

    // We never auto-enable the feature from a foreign config. The caller only invokes this when the
    // feature is already enabled (see `config::load_conf_file_or_generate_new`), so we merely fill in
    // the connections of an enabled configuration that doesn't define any of its own yet. An
    // explicit configuration (any connections, or the feature left disabled) always wins.
    if let Some(current) = &mut conf_file.psu_event_hub
        && current.enabled
        && current.connections.is_empty()
    {
        current.connections = compat_conf.connections;
    }

    Ok(())
}

fn load_compat_config() -> anyhow::Result<Option<dto::PsuEventHubConf>> {
    let mut connections = Vec::new();

    for path in compat_config_paths() {
        let Some(file) = load_compat_file(&path)? else {
            continue;
        };

        if !file.connections.is_empty() {
            connections = file.connections;
        }
    }

    apply_env_overrides(&mut connections)?;

    if connections.is_empty() {
        return Ok(None);
    }

    Ok(Some(dto::PsuEventHubConf {
        enabled: true,
        connections,
        powershell: dto::PsuPowerShellConf::default(),
    }))
}

fn load_compat_file(path: &Utf8Path) -> anyhow::Result<Option<CompatFile>> {
    match File::open(path) {
        Ok(file) => BufReader::new(file)
            .pipe(serde_json::from_reader)
            .map(Some)
            .with_context(|| format!("invalid PowerShell Universal agent config file at {path}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(anyhow::anyhow!(error).context(format!(
            "couldn't open PowerShell Universal agent config file at {path}"
        ))),
    }
}

fn compat_config_paths() -> Vec<Utf8PathBuf> {
    let mut paths = Vec::new();

    if let Some(program_data) = env_path("ProgramData") {
        paths.push(program_data.join("PowerShellUniversal").join("eventHubClient.json"));
        paths.push(program_data.join("PowerShellUniversal").join("agent.json"));
    }

    if let Some(app_data) = env_path("APPDATA") {
        paths.push(app_data.join("PowerShellUniversal").join("agent.json"));
    }

    paths
}

fn env_path(name: &str) -> Option<Utf8PathBuf> {
    std::env::var_os(name).and_then(|path| Utf8PathBuf::from_path_buf(path.into()).ok())
}

#[derive(Default)]
struct ConnectionPatch {
    hub: Option<String>,
    url: Option<String>,
    app_token: Option<Option<String>>,
    use_default_credentials: Option<bool>,
    script_path: Option<Option<Utf8PathBuf>>,
    description: Option<Option<String>>,
}

impl ConnectionPatch {
    fn apply_to(&self, connection: &mut dto::PsuEventHubConnectionConf) -> anyhow::Result<()> {
        if let Some(hub) = &self.hub {
            connection.hub = hub.clone();
        }
        if let Some(url) = &self.url {
            connection.url =
                Url::parse(url).with_context(|| format!("invalid PSU Event Hub URL from environment: {url}"))?;
        }
        if let Some(app_token) = &self.app_token {
            connection.app_token = app_token.clone();
        }
        if let Some(use_default_credentials) = self.use_default_credentials {
            connection.use_default_credentials = use_default_credentials;
        }
        if let Some(script_path) = &self.script_path {
            connection.script_path = script_path.clone();
        }
        if let Some(description) = &self.description {
            connection.description = description.clone();
        }

        Ok(())
    }

    fn try_build(&self) -> anyhow::Result<Option<dto::PsuEventHubConnectionConf>> {
        let (Some(hub), Some(url)) = (&self.hub, &self.url) else {
            return Ok(None);
        };

        Ok(Some(dto::PsuEventHubConnectionConf {
            hub: hub.clone(),
            url: Url::parse(url).with_context(|| format!("invalid PSU Event Hub URL from environment: {url}"))?,
            app_token: self.app_token.clone().flatten(),
            use_default_credentials: self.use_default_credentials.unwrap_or(false),
            script_path: self.script_path.clone().flatten(),
            description: self.description.clone().flatten(),
        }))
    }

    fn is_empty(&self) -> bool {
        self.hub.is_none()
            && self.url.is_none()
            && self.app_token.is_none()
            && self.use_default_credentials.is_none()
            && self.script_path.is_none()
            && self.description.is_none()
    }
}

fn apply_env_overrides(connections: &mut Vec<dto::PsuEventHubConnectionConf>) -> anyhow::Result<()> {
    let mut patches = BTreeMap::<usize, ConnectionPatch>::new();

    for (name, value) in std::env::vars() {
        let Some(key) = name.strip_prefix("PSU_") else {
            continue;
        };

        let key = key.replace("__", ":");
        if let Some((index, field)) = parse_connection_env_key(&key)? {
            apply_patch_field(patches.entry(index).or_default(), field, value)?;
        } else if let Some(field) = connection_field_name(&key) {
            apply_patch_field(patches.entry(0).or_default(), field, value)?;
        }
    }

    for (index, patch) in patches {
        if patch.is_empty() {
            continue;
        }

        if let Some(connection) = connections.get_mut(index) {
            patch.apply_to(connection)?;
        } else if let Some(connection) = patch.try_build()? {
            connections.push(connection);
        }
    }

    Ok(())
}

fn parse_connection_env_key(key: &str) -> anyhow::Result<Option<(usize, &'static str)>> {
    let parts = key.split(':').collect::<Vec<_>>();
    if parts.len() != 3 || !parts[0].eq_ignore_ascii_case("Connections") {
        return Ok(None);
    }

    let index = parts[1]
        .parse::<usize>()
        .with_context(|| format!("invalid PSU connection environment index: {}", parts[1]))?;
    let Some(field) = connection_field_name(parts[2]) else {
        return Ok(None);
    };

    Ok(Some((index, field)))
}

fn connection_field_name(key: &str) -> Option<&'static str> {
    if key.eq_ignore_ascii_case("Hub") {
        Some("Hub")
    } else if key.eq_ignore_ascii_case("Url") {
        Some("Url")
    } else if key.eq_ignore_ascii_case("AppToken") {
        Some("AppToken")
    } else if key.eq_ignore_ascii_case("UseDefaultCredentials") {
        Some("UseDefaultCredentials")
    } else if key.eq_ignore_ascii_case("ScriptPath") {
        Some("ScriptPath")
    } else if key.eq_ignore_ascii_case("Description") {
        Some("Description")
    } else {
        None
    }
}

fn apply_patch_field(patch: &mut ConnectionPatch, field: &str, value: String) -> anyhow::Result<()> {
    match field {
        "Hub" => patch.hub = Some(value),
        "Url" => patch.url = Some(value),
        "AppToken" => patch.app_token = Some(non_empty_string(value)),
        "UseDefaultCredentials" => patch.use_default_credentials = Some(parse_bool(&value)?),
        "ScriptPath" => patch.script_path = Some(non_empty_string(value).map(Utf8PathBuf::from)),
        "Description" => patch.description = Some(non_empty_string(value)),
        _ => unreachable!("unsupported PSU Event Hub connection field"),
    }

    Ok(())
}

fn non_empty_string(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn parse_bool(value: &str) -> anyhow::Result<bool> {
    if value.eq_ignore_ascii_case("true") || value == "1" || value.eq_ignore_ascii_case("yes") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") || value == "0" || value.eq_ignore_ascii_case("no") {
        Ok(false)
    } else {
        bail!("invalid PSU boolean environment value: {value}");
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use parking_lot::{Mutex, MutexGuard};

    use super::*;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        _guard: MutexGuard<'static, ()>,
        saved: Vec<(OsString, Option<OsString>)>,
    }

    impl EnvGuard {
        fn new(vars: &[(&str, &str)]) -> Self {
            let guard = ENV_LOCK.lock();
            let mut saved = std::env::vars_os()
                .filter(|(name, _)| {
                    let name = name.to_string_lossy();
                    name == "ProgramData" || name == "APPDATA" || name.starts_with("PSU_")
                })
                .map(|(name, value)| (name, Some(value)))
                .collect::<Vec<_>>();

            for (name, _) in &saved {
                // SAFETY: These tests hold ENV_LOCK while mutating process environment.
                unsafe {
                    std::env::remove_var(name);
                }
            }

            for (name, value) in vars {
                let name = OsString::from(name);
                if !saved.iter().any(|(saved_name, _)| saved_name == &name) {
                    saved.push((name.clone(), None));
                }
                // SAFETY: These tests hold ENV_LOCK while mutating process environment.
                unsafe {
                    std::env::set_var(name, value);
                }
            }

            Self { _guard: guard, saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (name, value) in &self.saved {
                match value {
                    Some(value) => {
                        // SAFETY: These tests hold ENV_LOCK while mutating process environment.
                        unsafe {
                            std::env::set_var(name, value);
                        }
                    }
                    None => {
                        // SAFETY: These tests hold ENV_LOCK while mutating process environment.
                        unsafe {
                            std::env::remove_var(name);
                        }
                    }
                }
            }
        }
    }

    fn conf_file_with_unstable() -> dto::ConfFile {
        let mut conf_file = dto::ConfFile::generate_new();
        conf_file.debug = Some(dto::DebugConf {
            enable_unstable: true,
            ..Default::default()
        });
        conf_file
    }

    #[test]
    fn does_not_auto_enable_when_feature_absent() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let program_data = Utf8PathBuf::from_path_buf(temp_dir.path().to_owned()).expect("temp path is UTF-8");
        let psu_dir = program_data.join("PowerShellUniversal");
        std::fs::create_dir_all(&psu_dir).expect("create PSU dir");
        std::fs::write(
            psu_dir.join("eventHubClient.json"),
            r#"{"Connections":[{"Hub":"Compat","Url":"http://localhost:5000"}]}"#,
        )
        .expect("write compat config");

        let _env = EnvGuard::new(&[
            ("ProgramData", program_data.as_str()),
            ("APPDATA", program_data.as_str()),
        ]);
        // The feature is not configured at all: a stray third-party PSU config must never bring it
        // into existence, even with unstable features enabled.
        let mut conf_file = conf_file_with_unstable();

        merge_into_conf_file(&mut conf_file).expect("merge compat config");

        assert!(conf_file.psu_event_hub.is_none());
    }

    #[test]
    fn imports_compat_connections_when_enabled_empty() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let program_data = Utf8PathBuf::from_path_buf(temp_dir.path().to_owned()).expect("temp path is UTF-8");
        let psu_dir = program_data.join("PowerShellUniversal");
        std::fs::create_dir_all(&psu_dir).expect("create PSU dir");
        std::fs::write(
            psu_dir.join("eventHubClient.json"),
            r#"{"Connections":[{"Hub":"Compat","Url":"http://localhost:5000"}]}"#,
        )
        .expect("write compat config");

        let _env = EnvGuard::new(&[
            ("ProgramData", program_data.as_str()),
            ("APPDATA", program_data.as_str()),
        ]);
        let mut conf_file = conf_file_with_unstable();
        conf_file.psu_event_hub = Some(dto::PsuEventHubConf {
            enabled: true,
            connections: Vec::new(),
            powershell: dto::PsuPowerShellConf::default(),
        });

        merge_into_conf_file(&mut conf_file).expect("merge compat config");

        let psu_event_hub = conf_file.psu_event_hub.expect("compat config");
        assert!(psu_event_hub.enabled);
        assert_eq!(psu_event_hub.connections[0].hub, "Compat");
    }

    #[test]
    fn explicit_connections_win_over_compat_config() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let program_data = Utf8PathBuf::from_path_buf(temp_dir.path().to_owned()).expect("temp path is UTF-8");
        let psu_dir = program_data.join("PowerShellUniversal");
        std::fs::create_dir_all(&psu_dir).expect("create PSU dir");
        std::fs::write(
            psu_dir.join("eventHubClient.json"),
            r#"{"Connections":[{"Hub":"Compat","Url":"http://localhost:5000"}]}"#,
        )
        .expect("write compat config");

        let _env = EnvGuard::new(&[
            ("ProgramData", program_data.as_str()),
            ("APPDATA", program_data.as_str()),
        ]);
        let mut conf_file: dto::ConfFile = serde_json::from_value(serde_json::json!({
            "__debug__": { "enable_unstable": true },
            "PsuEventHub": {
                "Enabled": true,
                "Connections": [{"Hub":"Explicit","Url":"http://localhost:5001"}]
            }
        }))
        .expect("deserialize config");

        merge_into_conf_file(&mut conf_file).expect("merge compat config");

        let psu_event_hub = conf_file.psu_event_hub.expect("compat config");
        assert_eq!(psu_event_hub.connections[0].hub, "Explicit");
    }

    #[test]
    fn explicit_disabled_config_stays_disabled() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let program_data = Utf8PathBuf::from_path_buf(temp_dir.path().to_owned()).expect("temp path is UTF-8");
        let psu_dir = program_data.join("PowerShellUniversal");
        std::fs::create_dir_all(&psu_dir).expect("create PSU dir");
        std::fs::write(
            psu_dir.join("eventHubClient.json"),
            r#"{"Connections":[{"Hub":"Compat","Url":"http://localhost:5000"}]}"#,
        )
        .expect("write compat config");

        let _env = EnvGuard::new(&[
            ("ProgramData", program_data.as_str()),
            ("APPDATA", program_data.as_str()),
        ]);
        let mut conf_file = conf_file_with_unstable();
        conf_file.psu_event_hub = Some(dto::PsuEventHubConf::default());

        merge_into_conf_file(&mut conf_file).expect("merge compat config");

        let psu_event_hub = conf_file.psu_event_hub.expect("compat config");
        assert!(!psu_event_hub.enabled);
        assert!(psu_event_hub.connections.is_empty());
    }

    #[test]
    fn reads_scalar_env_connection() {
        let _env = EnvGuard::new(&[
            ("PSU_Hub", "EnvHub"),
            ("PSU_Url", "http://localhost:5000"),
            ("PSU_AppToken", "token"),
            ("PSU_UseDefaultCredentials", "true"),
            ("PSU_ScriptPath", "event.ps1"),
            ("PSU_Description", "env agent"),
        ]);

        let compat = load_compat_config()
            .expect("load compat config")
            .expect("env compat config");

        assert!(compat.enabled);
        assert_eq!(compat.connections[0].hub, "EnvHub");
        assert_eq!(compat.connections[0].app_token.as_deref(), Some("token"));
        assert!(compat.connections[0].use_default_credentials);
        assert_eq!(
            compat.connections[0].script_path.as_deref(),
            Some(Utf8Path::new("event.ps1"))
        );
        assert_eq!(compat.connections[0].description.as_deref(), Some("env agent"));
    }

    #[test]
    fn reads_indexed_env_connection() {
        let _env = EnvGuard::new(&[
            ("PSU_Connections__0__Hub", "IndexedHub"),
            ("PSU_Connections__0__Url", "http://localhost:5000"),
        ]);

        let compat = load_compat_config()
            .expect("load compat config")
            .expect("env compat config");

        assert_eq!(compat.connections[0].hub, "IndexedHub");
    }
}
