use axum::extract::Query;
use axum::Json;
use hyper::StatusCode;

use devolutions_agent_shared::{get_updater_file_path, ProductUpdateInfo, UpdateJson, VersionSpecification};

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

/// Starts Devolutions Gateway update process
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "Update",
    tag = "Update",
    path = "/jet/update",
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
pub(super) async fn start_update(
    Query(query): Query<UpdateQueryParam>,
    _scope: UpdateScope,
) -> Result<Json<UpdateResponse>, HttpError> {
    let target_version = query.version;

    let updater_file_path = get_updater_file_path();

    if !updater_file_path.exists() {
        error!("Failed to start Gateway update, `update.json` does not exist (should be created by Devolutions Agent)");

        return Err(HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("Agent updater service is unavailable"));
    }

    let update_json = UpdateJson {
        gateway: Some(ProductUpdateInfo { target_version }),
    };

    serde_json::to_string(&update_json)
        .ok()
        .and_then(|serialized| std::fs::write(updater_file_path, serialized).ok())
        .ok_or_else(|| {
            error!("Failed to write new Gateway version to `update.json`");
            HttpErrorBuilder::new(StatusCode::INTERNAL_SERVER_ERROR).msg("Agent updater service is unavailable")
        })?;

    Ok(Json(UpdateResponse {}))
}
