//! Agent auto-update configuration and helpers.
//!
//! This module defines the `AgentAutoUpdateConf` structure and provides helpers to read
//! and write the auto-update section of `agent.json` without touching the rest of the file.

use camino::Utf8PathBuf;

use crate::get_data_dir;

/// Default check interval expressed as a humantime string (`"1d"` = 24 hours).
pub const DEFAULT_INTERVAL: &str = "1d";
pub const DEFAULT_WINDOW_START: &str = "02:00";
/// Default maintenance window end time (exclusive, local time `HH:MM`).
pub const DEFAULT_WINDOW_END: &str = "04:00";

fn default_interval() -> String {
    DEFAULT_INTERVAL.to_owned()
}

fn default_window_start() -> String {
    DEFAULT_WINDOW_START.to_owned()
}

fn default_window_end() -> Option<String> {
    Some(DEFAULT_WINDOW_END.to_owned())
}

/// Auto-update schedule configuration for Devolutions Agent.
///
/// When enabled, the agent periodically checks whether a new version of itself is
/// available in the Devolutions productinfo database.  If a newer version is found
/// and the current local time falls inside the configured maintenance window, the
/// agent writes the new target version to `update.json`, which is then picked up by
/// the updater task to perform the silent MSI installation.
///
/// Settings changes take effect when the agent service (re)starts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct AgentAutoUpdateConf {
    /// Enable periodic Devolutions Agent self-update checks.
    pub enabled: bool,

    /// Minimum interval between auto-update checks.
    ///
    /// Accepts humantime duration strings such as `"1d"`, `"12h"`, `"30m 20s"`, or a
    /// bare integer treated as seconds (e.g. `"3600"`).  Defaults to `"1d"`.
    #[serde(default = "default_interval")]
    pub interval: String,

    /// Start of the maintenance window (local time, `HH:MM` format).
    ///
    /// Defaults to `"02:00"`.
    #[serde(default = "default_window_start")]
    pub update_window_start: String,

    /// End of the maintenance window (local time, `HH:MM` format, exclusive).
    ///
    /// Defaults to `"04:00"`.  When `null`, the window has no upper bound.
    /// If the end time is earlier than or equal to the start time the window is
    /// assumed to cross midnight (e.g. `"22:00"`–`"03:00"` is a 5-hour window).
    #[serde(default = "default_window_end")]
    pub update_window_end: Option<String>,
}

impl Default for AgentAutoUpdateConf {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: DEFAULT_INTERVAL.to_owned(),
            update_window_start: DEFAULT_WINDOW_START.to_owned(),
            update_window_end: Some(DEFAULT_WINDOW_END.to_owned()),
        }
    }
}

/// Returns the path to `agent.json`.
pub fn get_agent_config_path() -> Utf8PathBuf {
    get_data_dir().join("agent.json")
}

/// Read the current auto-update configuration from `agent.json`.
///
/// Returns defaults when the file is absent or the `AgentAutoUpdate` section is missing.
pub fn read_agent_auto_update_conf() -> std::io::Result<AgentAutoUpdateConf> {
    let path = get_agent_config_path();

    let content = match std::fs::read(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(AgentAutoUpdateConf::default()),
        Err(e) => return Err(e),
    };

    // Strip UTF-8 BOM if present.
    let content = if content.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &content[3..]
    } else {
        &content
    };

    let value: serde_json::Value =
        serde_json::from_slice(content).map_err(|e| std::io::Error::other(format!("invalid agent.json: {e}")))?;

    let section = value
        .get("Updater")
        .and_then(|u| u.get("AgentAutoUpdate"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    if section.is_null() {
        return Ok(AgentAutoUpdateConf::default());
    }

    serde_json::from_value(section).map_err(|e| std::io::Error::other(format!("invalid AgentAutoUpdate section: {e}")))
}

/// Write `conf` into the `Updater.AgentAutoUpdate` section of `agent.json`.
///
/// All other keys in the file are preserved.
pub fn write_agent_auto_update_conf(conf: &AgentAutoUpdateConf) -> std::io::Result<()> {
    let path = get_agent_config_path();

    // Read or create the root JSON value.
    let mut root: serde_json::Value = if path.exists() {
        let content = std::fs::read(&path)?;
        let content = if content.starts_with(&[0xEF, 0xBB, 0xBF]) {
            content[3..].to_vec()
        } else {
            content
        };
        serde_json::from_slice(&content)
            .map_err(|e| std::io::Error::other(format!("invalid agent.json: {e}")))?
    } else {
        serde_json::json!({})
    };

    // Ensure the `Updater` object exists (with `Enabled: true` as default).
    if root.get("Updater").is_none() {
        root["Updater"] = serde_json::json!({ "Enabled": true });
    }

    root["Updater"]["AgentAutoUpdate"] =
        serde_json::to_value(conf).map_err(|e| std::io::Error::other(format!("serialization error: {e}")))?;

    let json = serde_json::to_string_pretty(&root)
        .map_err(|e| std::io::Error::other(format!("serialization error: {e}")))?;

    std::fs::write(&path, json)
}
