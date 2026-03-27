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
/// On Unix, calls `statvfs(2)` directly against the configured recording path.
/// This supports network filesystems (NFS, CIFS/Samba) and any mount point without needing
/// to enumerate mount points.
///
/// On other platforms, space values are not available and `(None, None)` is returned.
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

    #[cfg(unix)]
    #[allow(
        clippy::useless_conversion,
        reason = "statvfs field types differ across Unix platforms: fsblkcnt_t is u64 on Linux but u32 on macOS"
    )]
    fn query_storage_space_impl(recording_path: &std::path::Path) -> (Option<u64>, Option<u64>) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        let c_path = match CString::new(recording_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                NO_DISK_STATE.on_disk_missing(recording_path, "path contains null byte");
                return (None, None);
            }
        };

        // SAFETY: `stat` is zeroed stack memory whose layout matches what the OS writes into it.
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };

        // SAFETY: `c_path` is a valid null-terminated C string.
        let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };

        if ret == 0 {
            NO_DISK_STATE.on_disk_present();

            // f_frsize is the fundamental block size; fall back to f_bsize if zero.
            let block_size = if stat.f_frsize != 0 {
                u64::from(stat.f_frsize)
            } else {
                u64::from(stat.f_bsize)
            };

            let total = u64::from(stat.f_blocks).saturating_mul(block_size);

            // f_bavail is the space available to unprivileged users (vs f_bfree which is root-only).
            let available = u64::from(stat.f_bavail).saturating_mul(block_size);

            debug!(
                recording_path = %recording_path.display(),
                total_bytes = total,
                free_bytes_available = available,
                "Retrieved disk space via statvfs"
            );

            (Some(total), Some(available))
        } else {
            let error = std::io::Error::last_os_error();
            NO_DISK_STATE.on_disk_missing(recording_path, &error.to_string());

            (None, None)
        }
    }

    #[cfg(not(any(windows, unix)))]
    fn query_storage_space_impl(recording_path: &std::path::Path) -> (Option<u64>, Option<u64>) {
        NO_DISK_STATE.on_disk_missing(recording_path, "unsupported platform");
        (None, None)
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

        // Space values are Some on Windows (GetDiskFreeSpaceExW) and all Unix platforms (statvfs).
        #[cfg(any(windows, unix))]
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

        // Space values are None on other unsupported platforms.
        #[cfg(not(any(windows, unix)))]
        {
            assert!(result.recording_storage_total_space.is_none());
            assert!(result.recording_storage_available_space.is_none());
        }
    }

    /// A non-existent path should be reported as not writeable.
    #[test]
    fn nonexistent_path_is_not_writeable() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let nonexistent = dir.path().join("does_not_exist");
        let result = recording_storage_health(&nonexistent);
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
