use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct AboutData {
    #[serde(flatten)]
    pub startup_info: StartupInfo,
    /// The number of requests received since the server started.
    pub requests_received: i32,
    /// The time of the most recent request.
    ///
    /// This can be `None` if `/about` is the first request made.
    pub last_request_time: Option<DateTime<Utc>>,
}

/// Immutable startup info.
///
/// It is used in the `/about` endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct StartupInfo {
    pub(crate) run_id: i32,
    /// The request count at the time of the server startup.
    pub(crate) startup_request_count: i32,
    pub(crate) start_time: DateTime<Utc>,
}
