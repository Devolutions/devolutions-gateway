#![cfg_attr(
    unix,
    expect(
        dead_code,
        reason = "only used in the windows implementation, nothing is planned for linux yet"
    )
)]

use devolutions_pedm_shared::policy::{ElevationResult, Hash, Signature, User};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::db::DbHandle;

#[derive(Serialize, Deserialize, JsonSchema, Clone, Hash, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct JitElevationLogQueryOptions {
    pub page_number: u32,
    pub page_size: u32,
    pub user: Option<User>,
    pub start_time: i64,
    pub end_time: i64,
    pub sort_column: String,
    pub sort_descending: bool,
}

#[derive(Serialize, JsonSchema, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct JitElevationLogRow {
    pub id: i64,
    pub timestamp: i64,
    pub success: i64,
    pub asker_path: Option<String>,
    pub target_path: Option<String>,
    pub target_command_line: Option<String>,
    pub target_working_directory: Option<String>,
    pub target_hash: Option<Hash>,
    pub target_signature: Option<Signature>,
    pub user: Option<User>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct JitElevationLogPage {
    pub total_pages: u32,
    pub total_records: u32,
    pub results: Vec<JitElevationLogRow>,
}

pub(crate) fn log_elevation(db_handle: &DbHandle, result: ElevationResult) {
    std::thread::scope(|s| {
        s.spawn(||
            match db_handle.insert_jit_elevation_result(result) {
                Ok(()) => {}
                Err(error) => {
                    // We also log the elevation result here, so it's not completely lost.
                    error!(error = ?error.db_error, result = ?error.value, "Failed to insert the JIT elevation result in the database");
                }
            }
        );
    });
}
