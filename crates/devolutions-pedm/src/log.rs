use devolutions_pedm_shared::policy::ElevationResult;

use crate::db::DbHandle;

pub(crate) fn log_elevation(db_handle: &DbHandle, result: ElevationResult) {
    db_handle.insert_jit_elevation_result(result);
}
