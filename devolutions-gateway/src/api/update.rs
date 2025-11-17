use axum::Json;
use axum::extract::Query;
use hyper::StatusCode;

use devolutions_agent_shared::{ProductUpdateInfo, UpdateJson, VersionSpecification, get_updater_file_path};

use crate::extract::UpdateScope;
use crate::http::{HttpError, HttpErrorBuilder};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateQueryParam {
    version: VersionSpecification,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct UpdateResponse {}

/// Triggers Devolutions Gateway update process.
///
/// This is done via updating `Agent/update.json` file, which is then read by Devolutions Agent
/// when changes are detected. If the version written to `update.json` is indeed higher than the
/// currently installed version, Devolutions Agent will proceed with the update process.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "TriggerUpdate",
    tag = "Update",
    path = "/jet/update",
    params(
        ("version" = String, Query, description = "The version to install; use 'latest' for the latest version, or 'w.x.y.z' for a specific version"),
    ),
    responses(
        (status = 200, description = "Update request has been processed successfully", body = UpdateResponse),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Agent updater service is malfunctioning"),
        (status = 503, description = "Agent updater service is unavailable"),
    ),
    security(("scope_token" = ["gateway.update"])),
))]
pub(super) async fn trigger_update_check(
    Query(query): Query<UpdateQueryParam>,
    _scope: UpdateScope,
) -> Result<Json<UpdateResponse>, HttpError> {
    let target_version = query.version;

    let updater_file_path = get_updater_file_path();

    if !updater_file_path.exists() {
        return Err(
            HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("Agent updater service is not installed")
        );
    }

    let update_json = UpdateJson {
        gateway: Some(ProductUpdateInfo {
            target_version,
            local_package_path: None,
        }),
        hub_service: None,
    };

    let update_json = serde_json::to_string(&update_json).map_err(
        HttpError::internal()
            .with_msg("failed to serialize the update manifest")
            .err(),
    )?;

    std::fs::write(updater_file_path, update_json).map_err(
        HttpError::internal()
            .with_msg("failed to write the new `update.json` manifest on disk")
            .err(),
    )?;

    Ok(Json(UpdateResponse {}))
}
