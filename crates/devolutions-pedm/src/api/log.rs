use axum::Json;

use super::err::HandlerError;

/// Placeholder route.
pub(crate) async fn get_logs() -> Result<Json<Vec<()>>, HandlerError> {
    Ok(Json(vec![]))
}
