use axum::{Extension, Json};
use devolutions_pedm_shared::policy::ElevationConfigurations;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{elevations, policy};

use super::NamedPipeConnectInfo;

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TemporaryElevationStatus {
    pub enabled: bool,
    pub maximum_seconds: u64,
    pub time_left: u64,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct SessionElevationStatus {
    pub enabled: bool,
}

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub struct StatusResponse {
    pub elevated: bool,
    pub temporary: TemporaryElevationStatus,
    pub session: SessionElevationStatus,
}

pub async fn get_status(Extension(named_pipe_info): Extension<NamedPipeConnectInfo>) -> Json<StatusResponse> {
    info!(user = ?named_pipe_info.user, "Querying status for user");

    let policy = policy::policy().read();
    let default_elevation_settings = ElevationConfigurations::default();
    let elevation_settings = policy
        .user_current_profile(&named_pipe_info.user)
        .map(|x| &x.elevation_settings)
        .unwrap_or_else(|| &default_elevation_settings);

    Json(StatusResponse {
        elevated: elevations::is_elevated(&named_pipe_info.user),
        temporary: TemporaryElevationStatus {
            enabled: elevation_settings.temporary.enabled,
            maximum_seconds: elevation_settings.temporary.maximum_seconds,
            time_left: elevations::elevation_time_left_secs(&named_pipe_info.user).unwrap_or(0),
        },
        session: SessionElevationStatus {
            enabled: elevation_settings.session.enabled,
        },
    })
}
