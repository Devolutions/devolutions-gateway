use axum::Json;
use axum::extract::State;
use devolutions_agent_shared::get_installed_agent_version;
use uuid::Uuid;

use crate::DgwState;
use crate::extract::HeartbeatReadScope;
use crate::http::HttpError;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct Heartbeat {
    /// This Gateway's unique ID.
    id: Option<Uuid>,
    /// This Gateway's hostname.
    hostname: String,
    /// Gateway service version.
    version: &'static str,
    /// Agent version, if installed.
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_version: Option<String>,
    /// Number of running sessions.
    running_session_count: usize,
    /// Whether the recording storage is writeable or not.
    ///
    /// Since v2024.1.6.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<bool>))]
    recording_storage_is_writeable: bool,
    /// The total space of the disk used to store recordings, in bytes.
    ///
    /// Since v2024.1.6.
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_storage_total_space: Option<u64>,
    /// The remaining available space to store recordings, in bytes.
    ///
    /// Since v2024.1.6.
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
    let conf = conf_handle.get_conf();

    let running_session_count = sessions
        .get_running_session_count()
        .await
        .map_err(HttpError::internal().err())?;

    let recording_storage_result = recording_storage_health(conf.recording_path.as_std_path());

    let agent_version = match get_installed_agent_version() {
        Ok(Some(version)) => Some(version.fmt_without_revision()),
        Ok(None) => None,
        Err(error) => {
            warn!(error = %error, "Failed to get Agent version");
            None
        }
    };

    Ok(Json(Heartbeat {
        id: conf.id,
        hostname: conf.hostname.clone(),
        version: env!("CARGO_PKG_VERSION"),
        agent_version,
        running_session_count,
        recording_storage_is_writeable: recording_storage_result.recording_storage_is_writeable,
        recording_storage_total_space: recording_storage_result.recording_storage_total_space,
        recording_storage_available_space: recording_storage_result.recording_storage_available_space,
    }))
}

pub(crate) struct RecordingStorageResult {
    pub(crate) recording_storage_is_writeable: bool,
    pub(crate) recording_storage_total_space: Option<u64>,
    pub(crate) recording_storage_available_space: Option<u64>,
}

pub(crate) fn recording_storage_health(recording_path: &std::path::Path) -> RecordingStorageResult {
    use sysinfo::Disks;

    let recording_storage_is_writeable = {
        let probe_file = recording_path.join("probe");

        let is_ok = std::fs::write(&probe_file, ".").is_ok();

        if is_ok {
            let _ = std::fs::remove_file(probe_file);
        }

        is_ok
    };

    let (recording_storage_total_space, recording_storage_available_space) = if sysinfo::IS_SUPPORTED_SYSTEM {
        trace!("System is supporting listing storage disks");

        let recording_path = dunce::canonicalize(recording_path)
            .inspect_err(
                |error| debug!(%error, recording_path = %recording_path.display(), "Failed to canonicalize recording path"),
            )
            .unwrap_or_else(|_| recording_path.to_owned());

        let disks = Disks::new_with_refreshed_list();

        debug!(recording_path = %recording_path.display(), "Search mount point for path");
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

    RecordingStorageResult {
        recording_storage_is_writeable,
        recording_storage_total_space,
        recording_storage_available_space,
    }
}
