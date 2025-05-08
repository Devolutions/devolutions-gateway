use std::sync::Arc;

use devolutions_pedm_shared::policy::ElevationResult;

use crate::db;

// The previous function was commented out. The function call for `log_elevation` in `validate_elevation` still remains.
pub(crate) fn log_elevation(
    db: &Arc<(dyn db::Database + Send + Sync + 'static)>,
    _res: &ElevationResult,
) -> anyhow::Result<()> {
    let _ = db.insert_jit_elevation_result();
    Ok(())
}
