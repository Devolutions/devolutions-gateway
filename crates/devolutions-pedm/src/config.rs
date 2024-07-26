use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

use camino::Utf8PathBuf;
use win_api_wrappers::{raw::Win32::Foundation::LUID, win::Module};

pub static PEDM_DESKTOP_RELPATH: &'static str = r"desktop/DevolutionsPedmDesktop.exe"; // TODO change this

pub static PIPE_NAME: &'static str = r"\\.\pipe\DevolutionsPEDM";

pub const LADM_SRC_NAME: &'static [u8; 8] = b"DevoPEDM";
pub static LADM_SRC_LUID: LUID = LUID {
    HighPart: 0,
    LowPart: 0x1337,
};

pub const VADM_RID: u32 = 99;
pub static VADM_DOMAIN: &'static str = "_DEPM";

pub fn pedm_desktop_path() -> &'static Path {
    static PEDM_DESKTOP_PATH: OnceLock<PathBuf> = OnceLock::new();

    PEDM_DESKTOP_PATH.get_or_init(|| install_directory().join(PEDM_DESKTOP_RELPATH))
}

pub fn install_directory() -> &'static Path {
    static INSTALL_DIRECTORY: OnceLock<PathBuf> = OnceLock::new();

    INSTALL_DIRECTORY.get_or_init(|| {
        Module::current()
            .and_then(|m| m.file_name())
            .map(|mut p| {
                p.pop();
                p
            })
            .unwrap()
    })
}

pub fn data_dir() -> Utf8PathBuf {
    let mut dir = devolutions_agent_shared::get_data_dir();
    dir.push("pedm");
    dir
}
