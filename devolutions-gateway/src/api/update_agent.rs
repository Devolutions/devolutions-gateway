use axum::Json;
use devolutions_agent_shared::AgentAutoUpdateConf;
use devolutions_agent_shared::agent_auto_update::{
    DEFAULT_INTERVAL, DEFAULT_WINDOW_END, DEFAULT_WINDOW_START, read_agent_auto_update_conf,
    write_agent_auto_update_conf,
};

use crate::extract::UpdateScope;
use crate::http::HttpError;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct GetAgentAutoUpdateResponse {
    /// Whether periodic Devolutions Agent self-update is enabled.
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    /// Minimum interval between auto-update checks (humantime string, e.g. `"1d"`, `"12h"`).
    #[serde(rename = "Interval")]
    pub interval: String,
    /// Start of the maintenance window (local time, `HH:MM`).
    #[serde(rename = "UpdateWindowStart")]
    pub update_window_start: String,
    /// End of the maintenance window (local time, `HH:MM`, exclusive).
    /// `null` means no upper bound (the window runs until midnight and beyond).
    #[serde(rename = "UpdateWindowEnd")]
    pub update_window_end: Option<String>,
}

impl From<AgentAutoUpdateConf> for GetAgentAutoUpdateResponse {
    fn from(c: AgentAutoUpdateConf) -> Self {
        Self {
            enabled: c.enabled,
            interval: c.interval,
            update_window_start: c.update_window_start,
            update_window_end: c.update_window_end,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Deserialize)]
pub(crate) struct SetAgentAutoUpdateRequest {
    /// Whether periodic Devolutions Agent self-update is enabled.
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    /// Minimum interval between auto-update checks (default: `"1d"`).
    ///
    /// Accepts humantime duration strings such as `"1d"`, `"12h"`, `"30m"`, or a bare integer
    /// treated as seconds (e.g. `"3600"`).
    #[serde(rename = "Interval", default = "default_interval")]
    pub interval: String,
    /// Start of the maintenance window in `HH:MM` local time (default: `"02:00"`).
    #[serde(rename = "UpdateWindowStart", default = "default_window_start")]
    pub update_window_start: String,
    /// End of the maintenance window in `HH:MM` local time, exclusive (default: `"04:00"`).
    ///
    /// `null` means the window has no upper bound (any time from `UpdateWindowStart` onward).
    /// If end ≤ start the window is assumed to cross midnight.
    #[serde(rename = "UpdateWindowEnd", default = "default_window_end")]
    pub update_window_end: Option<String>,
}

fn default_interval() -> String {
    DEFAULT_INTERVAL.to_owned()
}

fn default_window_start() -> String {
    DEFAULT_WINDOW_START.to_owned()
}

fn default_window_end() -> Option<String> {
    Some(DEFAULT_WINDOW_END.to_owned())
}

impl From<SetAgentAutoUpdateRequest> for AgentAutoUpdateConf {
    fn from(r: SetAgentAutoUpdateRequest) -> Self {
        Self {
            enabled: r.enabled,
            interval: r.interval,
            update_window_start: r.update_window_start,
            update_window_end: r.update_window_end,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct SetAgentAutoUpdateResponse {}

/// Retrieve Devolutions Agent auto-update settings.
///
/// Returns the current `AgentAutoUpdate` configuration from `agent.json`.
/// When the section is absent the response contains the built-in defaults
/// (`Enabled: false`, `IntervalHours: 24`, window `02:00`-`04:00`).
///
/// The Devolutions Agent service must be restarted for changes to take effect.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetAgentAutoUpdate",
    tag = "Update",
    path = "/jet/agent-update-config",
    responses(
        (status = 200, description = "Agent auto-update settings", body = GetAgentAutoUpdateResponse),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Failed to read agent configuration"),
    ),
    security(("scope_token" = ["gateway.update"])),
))]
pub(super) async fn get_agent_auto_update(
    _scope: UpdateScope,
) -> Result<Json<GetAgentAutoUpdateResponse>, HttpError> {
    let conf = read_agent_auto_update_conf().map_err(
        HttpError::internal()
            .with_msg("failed to read agent auto-update configuration")
            .err(),
    )?;

    Ok(Json(GetAgentAutoUpdateResponse::from(conf)))
}

/// Update Devolutions Agent auto-update settings.
///
/// Writes the supplied configuration into the `Updater.AgentAutoUpdate` section of
/// `agent.json`, preserving all other keys in the file.
///
/// The Devolutions Agent service must be restarted for changes to take effect.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "SetAgentAutoUpdate",
    tag = "Update",
    path = "/jet/agent-update-config",
    request_body = SetAgentAutoUpdateRequest,
    responses(
        (status = 200, description = "Agent auto-update settings updated successfully", body = SetAgentAutoUpdateResponse),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Failed to write agent configuration"),
    ),
    security(("scope_token" = ["gateway.update"])),
))]
pub(super) async fn set_agent_auto_update(
    _scope: UpdateScope,
    Json(body): Json<SetAgentAutoUpdateRequest>,
) -> Result<Json<SetAgentAutoUpdateResponse>, HttpError> {
    let conf = AgentAutoUpdateConf::from(body);

    write_agent_auto_update_conf(&conf).map_err(
        HttpError::internal()
            .with_msg("failed to write agent auto-update configuration")
            .err(),
    )?;

    Ok(Json(SetAgentAutoUpdateResponse {}))
}
