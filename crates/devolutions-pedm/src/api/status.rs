use axum::Json;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

pub(crate) async fn get_status() -> Json<StatusResponse> {
    unimplemented!()
}
