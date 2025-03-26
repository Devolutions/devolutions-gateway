use std::time::Duration;

use axum::{Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::Error;
use crate::{elevations, policy};

use super::NamedPipeConnectInfo;

#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ElevateTemporaryPayload {
    pub seconds: u64,
}

pub async fn post_elevate_temporary(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    Json(payload): Json<ElevateTemporaryPayload>,
) -> Result<(), Error> {
    let policy = policy::policy().read();

    let profile = policy.user_current_profile(&named_pipe_info.user);
    if profile.is_none() {
        info!(user = ?named_pipe_info.user, "User tried to elevate temporarily, but wasn't assigned to profile");
        return Err(Error::AccessDenied);
    }

    let settings = policy
        .user_current_profile(&named_pipe_info.user)
        .map(|p| &p.elevation_settings.temporary)
        .ok_or(Error::AccessDenied)?;

    if !settings.enabled {
        info!(
            user = ?named_pipe_info.user,
            "User tried to elevate temporarily, but wasn't allowed",
        );
        return Err(Error::AccessDenied);
    }

    let req_duration = Duration::from_secs(payload.seconds);

    if Duration::from_secs(settings.maximum_seconds) < req_duration {
        info!(
            user = ?named_pipe_info.user,
            seconds = req_duration.as_secs(),
            "User tried to elevate temporarily for too long"
        );
        return Err(Error::AccessDenied);
    }

    info!(
        user = ?named_pipe_info.user,
        seconds = req_duration.as_secs(),
        "Elevating user"
    );

    elevations::elevate_temporary(named_pipe_info.user, &req_duration);

    Ok(())
}
