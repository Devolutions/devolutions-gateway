use std::sync::Arc;
use std::time::Duration;

use aide::NoApi;
use axum::extract::State;
use axum::{Extension, Json};
use hyper::StatusCode;
use parking_lot::RwLock;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::elevations;
use crate::policy::Policy;

use super::err::HandlerError;
use super::state::Db;
use super::NamedPipeConnectInfo;

#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ElevateTemporaryPayload {
    /// The number of seconds to elevate the user for.
    ///
    /// This must be between 1 and `i32::MAX`.
    pub(crate) seconds: u64,
}

/// Temporarily elevates the user's session.
pub(crate) async fn elevate_temporary(
    Extension(req_id): Extension<i32>,
    Extension(info): Extension<NamedPipeConnectInfo>,
    NoApi(Db(db)): NoApi<Db>,
    NoApi(State(policy)): NoApi<State<Arc<RwLock<Policy>>>>,
    Json(payload): Json<ElevateTemporaryPayload>,
) -> Result<(), HandlerError> {
    // validate input
    fn invalid_secs_err() -> HandlerError {
        HandlerError::new(
            StatusCode::BAD_REQUEST,
            Some("number of seconds must be between 1 and 2,147,483,647"),
        )
    }
    let seconds = i32::try_from(payload.seconds).map_err(|_| invalid_secs_err())?;
    if seconds < 1 {
        return Err(invalid_secs_err());
    }

    db.insert_elevate_tmp_request(req_id, seconds).await?;

    let policy = policy.read();
    if policy.user_current_profile(&info.user).is_none() {
        return Err(HandlerError::new(
            StatusCode::FORBIDDEN,
            Some("user not assigned to profile"),
        ));
    }

    let settings = policy
        .user_current_profile(&info.user)
        .map(|p| &p.elevation_settings.temporary)
        .ok_or_else(|| {
            HandlerError::new(
                StatusCode::FORBIDDEN,
                Some("could not get temporary elevation configuration"),
            )
        })?;

    if !settings.enabled {
        return Err(HandlerError::new(
            StatusCode::FORBIDDEN,
            Some("temporary elevation is not permitted"),
        ));
    }

    let duration = Duration::from_secs(payload.seconds);
    if Duration::from_secs(settings.maximum_seconds) < duration {
        return Err(HandlerError::new(
            StatusCode::FORBIDDEN,
            Some("requested duration exceeds maximum"),
        ));
    }
    elevations::elevate_temporary(info.user, &duration);

    Ok(())
}
