use axum::Json;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[expect(dead_code, reason = "work in progress feature")]
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct TemporaryElevationStatus {
    pub(crate) enabled: bool,
    pub(crate) maximum_seconds: u64,
    pub(crate) time_left: u64,
}

#[expect(dead_code, reason = "work in progress feature")]
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SessionElevationStatus {
    pub(crate) enabled: bool,
}

#[expect(dead_code, reason = "work in progress feature")]
#[derive(Deserialize, Serialize, Debug, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct StatusResponse {
    pub(crate) elevated: bool,
    pub(crate) temporary: TemporaryElevationStatus,
    pub(crate) session: SessionElevationStatus,
}

#[expect(dead_code, reason = "work in progress feature")]
pub(crate) async fn get_status() -> Json<StatusResponse> {
    unimplemented!()
}
