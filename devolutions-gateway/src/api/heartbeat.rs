use axum::extract::State;
use axum::Json;
use uuid::Uuid;

use crate::extract::HeartbeatReadScope;
use crate::http::HttpError;
use crate::DgwState;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct Heartbeat {
    /// This Gateway's unique ID
    id: Option<Uuid>,
    /// This Gateway's hostname
    hostname: String,
    /// Gateway service version
    version: &'static str,
    /// Number of running sessions
    running_session_count: usize,
    /// The total space of the disk used to store recordings, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_storage_total_space: Option<u64>,
    /// The remaining available space to store recordings, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_storage_available_space: Option<u64>,
}

/// Performs a heartbeat check
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetHeartbeat",
    tag = "Heartbeat",
    path = "/jet/heartbeat",
    responses(
        (status = 200, description = "Heartbeat for this Gateway", body = Heartbeat),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("scope_token" = ["gateway.heartbeat.read"])),
))]
pub(super) async fn get_heartbeat(
    State(DgwState {
        conf_handle, sessions, ..
    }): State<DgwState>,
    _scope: HeartbeatReadScope,
) -> Result<Json<Heartbeat>, HttpError> {
    use sysinfo::Disks;

    let conf = conf_handle.get_conf();

    let running_session_count = sessions
        .get_running_session_count()
        .await
        .map_err(HttpError::internal().err())?;

    let (recording_storage_total_space, recording_storage_available_space) = if sysinfo::IS_SUPPORTED_SYSTEM {
        trace!("System is supporting listing storage disks");

        let recording_path = conf
            .recording_path
            .canonicalize()
            .unwrap_or_else(|_| conf.recording_path.clone().into_std_path_buf());

        let disks = Disks::new_with_refreshed_list();

        debug!(?disks, "Found disks");

        let mut recording_disk = None;
        let mut longest_path = 0;

        for disk in disks.list() {
            let mount_point = disk.mount_point();
            let path_len = mount_point.components().count();
            if recording_path.starts_with(mount_point) && longest_path < path_len {
                recording_disk = Some(disk);
                longest_path = path_len;
            }
        }

        if let Some(disk) = recording_disk {
            debug!(?disk, "Disk used to store recordings");

            (Some(disk.total_space()), Some(disk.available_space()))
        } else {
            warn!("Failed to find disk used for recording storage");

            (None, None)
        }
    } else {
        debug!("This system does not support listing storage disks");

        (None, None)
    };

    Ok(Json(Heartbeat {
        id: conf.id,
        hostname: conf.hostname.clone(),
        version: env!("CARGO_PKG_VERSION"),
        running_session_count,
        recording_storage_total_space,
        recording_storage_available_space,
    }))
}
