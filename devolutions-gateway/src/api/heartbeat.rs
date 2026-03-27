use std::sync::atomic::{AtomicBool, Ordering};

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

/// Tracks whether the "no disk found for recording storage" condition has already been emitted at
/// WARN level for the current fault period.
///
/// The first occurrence in a fault period is logged at WARN; subsequent repeated occurrences
/// are downgraded to DEBUG to avoid log noise on every failure.
/// When the disk becomes available again, the state resets so that a future recurrence can
/// surface at WARN once more.
struct NoDiskState {
    /// Set to `true` once a WARN has been emitted for the current fault period.
    /// Reset to `false` when the disk is successfully found (recovery).
    already_warned: AtomicBool,
}

impl NoDiskState {
    const fn new() -> Self {
        Self {
            already_warned: AtomicBool::new(false),
        }
    }

    /// Called when disk space cannot be determined for the recording path.
    ///
    /// `reason` is a short description of why (e.g. "no matching disk mount point found" or an OS
    /// error string).  Logs at WARN on the first occurrence in a fault period; subsequent repeated
    /// occurrences are downgraded to DEBUG to avoid log noise.
    fn on_disk_missing(&self, recording_path: &std::path::Path, reason: &str) {
        let already_warned = self
            .already_warned
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_err();

        if !already_warned {
            warn!(
                recording_path = %recording_path.display(),
                reason,
                "Failed to retrieve recording storage space"
            );
            trace!(covmark = "no_disk_first_occurrence");
        } else {
            debug!(
                recording_path = %recording_path.display(),
                reason,
                "Failed to retrieve recording storage space"
            );
            trace!(covmark = "no_disk_repeated_occurrence");
        }
    }

    /// Called when the disk is successfully found.
    ///
    /// Resets the warned state so that a future fault surfaces at WARN again.
    fn on_disk_present(&self) {
        self.already_warned.store(false, Ordering::Relaxed);
    }
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
    let recording_storage_is_writeable = {
        let probe_file = recording_path.join("probe");

        let is_ok = std::fs::write(&probe_file, ".").is_ok();

        if is_ok {
            let _ = std::fs::remove_file(probe_file);
        }

        is_ok
    };

    let (recording_storage_total_space, recording_storage_available_space) = query_storage_space(recording_path);

    RecordingStorageResult {
        recording_storage_is_writeable,
        recording_storage_total_space,
        recording_storage_available_space,
    }
}

/// Queries total and available disk space for the given path.
///
/// On Windows, calls `GetDiskFreeSpaceExW` directly against the configured recording path.
/// This supports UNC paths (`\\server\share\...`) and mapped drive letters without needing
/// to enumerate mount points or canonicalize the path.
///
/// On other platforms, enumerates disks via `sysinfo` and finds the longest-prefix mount point.
fn query_storage_space(recording_path: &std::path::Path) -> (Option<u64>, Option<u64>) {
    static NO_DISK_STATE: NoDiskState = NoDiskState::new();

    return query_storage_space_impl(recording_path);

    #[cfg(windows)]
    fn query_storage_space_impl(recording_path: &std::path::Path) -> (Option<u64>, Option<u64>) {
        use std::os::windows::ffi::OsStrExt as _;

        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

        // Build a null-terminated UTF-16 path.  We use the path as-is (no canonicalization)
        // so that UNC paths and mapped drive letters are passed straight to the OS.
        let wide: Vec<u16> = recording_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0u16))
            .collect();

        let mut free_bytes_available_to_caller: u64 = 0;
        let mut total_number_of_bytes: u64 = 0;
        let mut total_number_of_free_bytes: u64 = 0;

        // SAFETY: `wide` is null-terminated, all output pointers are valid stack locations.
        let result = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut free_bytes_available_to_caller,
                &mut total_number_of_bytes,
                &mut total_number_of_free_bytes,
            )
        };

        if result != 0 {
            NO_DISK_STATE.on_disk_present();
            debug!(
                recording_path = %recording_path.display(),
                total_bytes = total_number_of_bytes,
                free_bytes_available = free_bytes_available_to_caller,
                "Retrieved disk space via GetDiskFreeSpaceExW"
            );
            (Some(total_number_of_bytes), Some(free_bytes_available_to_caller))
        } else {
            let error = std::io::Error::last_os_error();
            NO_DISK_STATE.on_disk_missing(recording_path, &error.to_string());
            (None, None)
        }
    }

    #[cfg(not(windows))]
    fn query_storage_space_impl(recording_path: &std::path::Path) -> (Option<u64>, Option<u64>) {
        use sysinfo::Disks;

        if !sysinfo::IS_SUPPORTED_SYSTEM {
            debug!("This system does not support listing storage disks");
            return (None, None);
        }

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
            NO_DISK_STATE.on_disk_present();
            debug!(?disk, "Disk used to store recordings");
            (Some(disk.total_space()), Some(disk.available_space()))
        } else {
            NO_DISK_STATE.on_disk_missing(&recording_path, "no matching disk mount point found");
            (None, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use tracing_cov_mark::init_cov_mark;

    use super::*;

    /// A writable temp directory should report is_writeable = true and return space values on
    /// supported platforms.
    #[test]
    fn writeable_temp_dir_is_healthy() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let result = recording_storage_health(dir.path());

        assert!(result.recording_storage_is_writeable);

        // Space values may be None only on platforms where sysinfo is unsupported;
        // on Windows and common Unix platforms they should be Some.
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        {
            assert!(
                result.recording_storage_total_space.is_some(),
                "expected total space to be available on this platform"
            );
            assert!(
                result.recording_storage_available_space.is_some(),
                "expected available space to be available on this platform"
            );
            assert!(
                result.recording_storage_total_space >= result.recording_storage_available_space,
                "total space must be >= available space"
            );
        }
    }

    /// A non-existent path should be reported as not writeable.
    #[test]
    fn nonexistent_path_is_not_writeable() {
        let result = recording_storage_health(std::path::Path::new("/tmp/__devolutions_gateway_no_such_dir_8f3a2b__"));
        assert!(!result.recording_storage_is_writeable);
    }

    #[test]
    fn no_disk_repeated_occurrence_is_debug() {
        let (cov, _guard) = init_cov_mark();
        let state = NoDiskState::new();

        state.on_disk_missing(
            std::path::Path::new("/recordings"),
            "no matching disk mount point found",
        );
        cov.assert_mark("no_disk_first_occurrence");

        state.on_disk_missing(
            std::path::Path::new("/recordings"),
            "no matching disk mount point found",
        );
        cov.assert_mark("no_disk_repeated_occurrence");

        // Further calls remain at debug.
        state.on_disk_missing(
            std::path::Path::new("/recordings"),
            "no matching disk mount point found",
        );
        cov.assert_mark("no_disk_repeated_occurrence");
    }

    #[test]
    fn no_disk_recovery_re_warns() {
        let (cov, _guard) = init_cov_mark();
        let state = NoDiskState::new();

        // First failure — WARN.
        state.on_disk_missing(
            std::path::Path::new("/recordings"),
            "no matching disk mount point found",
        );
        cov.assert_mark("no_disk_first_occurrence");

        // Second failure — DEBUG (repeated).
        state.on_disk_missing(
            std::path::Path::new("/recordings"),
            "no matching disk mount point found",
        );
        cov.assert_mark("no_disk_repeated_occurrence");

        // Disk comes back.
        state.on_disk_present();

        // Condition returns — should WARN again.
        state.on_disk_missing(
            std::path::Path::new("/recordings"),
            "no matching disk mount point found",
        );
        cov.assert_mark("no_disk_first_occurrence");
    }
}
