#[cfg(windows)]
pub mod windows;

mod date_version;
mod update_manifest;
mod update_status;

use std::env;

use camino::Utf8PathBuf;
use cfg_if::cfg_if;
pub use date_version::{DateVersion, DateVersionError};
pub use update_manifest::{
    ProductUpdateInfo, UPDATE_MANIFEST_V2_MINOR_VERSION, UpdateManifest, UpdateManifestV1, UpdateManifestV2,
    UpdateProductKey, UpdateSchedule, VersionMajorV2, VersionSpecification, default_schedule_window_start,
    detect_update_manifest_major_version,
};
pub use update_status::{UpdateStatus, UpdateStatusV2};

cfg_if! {
    if #[cfg(target_os = "windows")] {
        const COMPANY_DIR: &str = "Devolutions";
        const PROGRAM_DIR: &str = "Agent";
        const APPLICATION_DIR: &str = "Devolutions\\Agent";
    } else if #[cfg(target_os = "macos")] {
        const COMPANY_DIR: &str = "Devolutions";
        const PROGRAM_DIR: &str = "Agent";
        const APPLICATION_DIR: &str = "Devolutions Agent";
    } else {
        const COMPANY_DIR: &str = "devolutions";
        const PROGRAM_DIR: &str = "agent";
        const APPLICATION_DIR: &str = "devolutions-agent";
    }
}

#[derive(Debug, thiserror::Error)]
#[error("failed to get package info")]
pub struct PackageInfoError {
    #[cfg(windows)]
    #[from]
    source: windows::registry::RegistryError,
}

#[cfg(windows)]
pub fn get_installed_agent_version() -> Result<Option<DateVersion>, PackageInfoError> {
    Ok(windows::registry::get_installed_product_version(
        windows::AGENT_UPDATE_CODE,
        windows::registry::ProductVersionEncoding::Agent,
    )?)
}

#[cfg(not(windows))]
pub fn get_installed_agent_version() -> Result<Option<DateVersion>, PackageInfoError> {
    Ok(None)
}

pub fn get_data_dir() -> Utf8PathBuf {
    if let Ok(config_path_env) = env::var("DAGENT_CONFIG_PATH") {
        Utf8PathBuf::from(config_path_env)
    } else {
        let mut config_path = Utf8PathBuf::new();

        if cfg!(target_os = "windows") {
            let program_data_env = env::var("ProgramData").expect("ProgramData env variable should be set on Windows");
            config_path.push(program_data_env);
            config_path.push(COMPANY_DIR);
            config_path.push(PROGRAM_DIR);
        } else if cfg!(target_os = "macos") {
            config_path.push("/Library/Application Support");
            config_path.push(APPLICATION_DIR);
        } else {
            config_path.push("/etc");
            config_path.push(APPLICATION_DIR);
        }

        config_path
    }
}

/// Returns the path to the `update.json` file.
pub fn get_updater_file_path() -> Utf8PathBuf {
    get_data_dir().join("update.json")
}

/// Returns the path to the `agent_status.json` file.
pub fn get_agent_status_file_path() -> Utf8PathBuf {
    get_data_dir().join("agent_status.json")
}
