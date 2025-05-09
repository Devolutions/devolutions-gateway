use devolutions_pedm_shared::policy::ElevationResult;
use tracing::error;

use crate::db::DbHandle;

pub(crate) fn log_elevation(db_handle: &DbHandle, result: ElevationResult) {
    match db_handle.insert_jit_elevation_result(result) {
        Ok(()) => {}
        Err(error) => {
            // We also log the elevation result here, so it’s not completely lost.
            error!(error = ?error.db_error, result = ?error.value, "Failed to insert the JIT elevation result in the database");
        }
    }
}
