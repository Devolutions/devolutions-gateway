use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use camino::Utf8PathBuf;
use win_api_wrappers::process::Module;
use win_api_wrappers::raw::Win32::Foundation::LUID;

// TODO: clarify usage of static keyword in this file

pub(crate) static PEDM_DESKTOP_RELPATH: &str = r"desktop/DevolutionsDesktopAgent.exe";

pub(crate) static PIPE_NAME: &str = r"\\.\pipe\DevolutionsPEDM";

pub(crate) const LADM_SRC_NAME: &[u8; 8] = b"DevoPEDM";
pub(crate) static LADM_SRC_LUID: LUID = LUID {
    HighPart: 0,
    LowPart: 0x1337,
};

pub(crate) const VADM_RID: u32 = 99;
pub(crate) static VADM_DOMAIN: &str = "_DEPM";

pub(crate) fn pedm_desktop_path() -> &'static Path {
    static PEDM_DESKTOP_PATH: OnceLock<PathBuf> = OnceLock::new();

    PEDM_DESKTOP_PATH.get_or_init(|| install_directory().join(PEDM_DESKTOP_RELPATH))
}

pub(crate) fn install_directory() -> &'static Path {
    static INSTALL_DIRECTORY: OnceLock<PathBuf> = OnceLock::new();

    INSTALL_DIRECTORY.get_or_init(|| {
        Module::current()
            .and_then(|m| m.file_name())
            .map(|mut p| {
                p.pop();
                p
            })
            .expect("invalid module file name")
    })
}

pub(crate) fn data_dir() -> Utf8PathBuf {
    let mut dir = devolutions_agent_shared::get_data_dir();
    dir.push("pedm");
    dir
}
