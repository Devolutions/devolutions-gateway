use std::sync::Arc;

use aide::NoApi;
use axum::extract::State;
use axum::{Extension, Json};
use parking_lot::RwLock;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::elevations;
use crate::policy::Policy;

use super::NamedPipeConnectInfo;

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct TemporaryElevationStatus {
    pub(crate) enabled: bool,
    pub(crate) maximum_seconds: u64,
    pub(crate) time_left: u64,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SessionElevationStatus {
    pub(crate) enabled: bool,
}

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct StatusResponse {
    pub(crate) elevated: bool,
    pub(crate) temporary: TemporaryElevationStatus,
    pub(crate) session: SessionElevationStatus,
}

pub(crate) async fn get_status(
    Extension(info): Extension<NamedPipeConnectInfo>,
    NoApi(State(policy)): NoApi<State<Arc<RwLock<Policy>>>>,
) -> Json<StatusResponse> {
    info!(user = ?info.user, "Querying status for user");

    let policy = policy.read();
    let config = policy
        .user_current_profile(&info.user)
        .map(|x| x.elevation_settings.clone())
        .unwrap_or_default();

    Json(StatusResponse {
        elevated: elevations::is_elevated(&info.user),
        temporary: TemporaryElevationStatus {
            enabled: config.temporary.enabled,
            maximum_seconds: config.temporary.maximum_seconds,
            time_left: elevations::elevation_time_left_secs(&info.user).unwrap_or_default(),
        },
        session: SessionElevationStatus {
            enabled: config.session.enabled,
        },
    })
}
