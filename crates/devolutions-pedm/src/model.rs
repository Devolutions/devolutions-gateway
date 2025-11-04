#![cfg_attr(
    unix,
    expect(
        dead_code,
        reason = "only used in the windows implementation, nothing is planned for linux yet"
    )
)]

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct AboutData {
    pub run_id: i32,
    pub start_time: DateTime<Utc>,
    pub startup_request_count: i32,
    pub current_request_count: i32,
    /// The time of the most recent request.
    ///
    /// This can be `None` if `/about` is the first request made.
    pub last_request_time: Option<DateTime<Utc>>,
    pub version: String,
}

/// Immutable startup info.
///
/// It is used in the `/about` endpoint.
#[derive(Clone)]
pub(crate) struct StartupInfo {
    pub(crate) run_id: i32,
    pub(crate) start_time: DateTime<Utc>,
    /// The request count at the time of the server startup.
    pub(crate) request_count: i32,
}
