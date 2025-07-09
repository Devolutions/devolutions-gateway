use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::DgwState;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct Identity {
    /// This Gateway's unique ID
    id: Option<Uuid>,
    /// This Gateway's hostname
    hostname: String,
    /// Gateway service version
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'static str>,
}

pub(super) enum HealthResponse {
    Identity(Identity),
    /// Legacy response for DVLS prior to 2022.3.x
    // TODO(axum): REST API compatibility tests
    HealthyMessage(String),
}

impl IntoResponse for HealthResponse {
    fn into_response(self) -> Response {
        match self {
            HealthResponse::Identity(identity) => Json(identity).into_response(),
            HealthResponse::HealthyMessage(message) => message.into_response(),
        }
    }
}

/// Performs a health check
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetHealth",
    tag = "Health",
    path = "/jet/health",
    responses(
        (status = 200, description = "Identity for this Gateway", body = Identity),
        (status = 400, description = "Invalid Accept header"),
    ),
))]
pub(super) async fn get_health(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    headers: HeaderMap,
) -> HealthResponse {
    let conf = conf_handle.get_conf();

    for hval in headers
        .get(axum::http::header::ACCEPT)
        .and_then(|hval| hval.to_str().ok())
        .into_iter()
        .flat_map(|hval| hval.split(','))
    {
        if hval == "application/json" {
            return HealthResponse::Identity(Identity {
                id: conf.id,
                hostname: conf.hostname.clone(),
                version: Some(env!("CARGO_PKG_VERSION")),
            });
        }
    }

    HealthResponse::HealthyMessage(format!(
        "Devolutions Gateway \"{}\" is alive and healthy.",
        conf.hostname
    ))
}
