use std::os::windows::io::{AsHandle, AsRawHandle};
use std::path::PathBuf;

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};

use win_api_wrappers::utils::WideString;

/// Guard for created temporary file. (File is removed on drop)
pub struct TmpFileGuard(PathBuf);

impl TmpFileGuard {
    pub fn new(extension: &str) -> anyhow::Result<Self> {
        let (_file, path) = tempfile::Builder::new()
            .prefix("devolutions-")
            .suffix(&format!(".{}", extension))
            .tempfile()?
            .keep()?;

        Ok(Self(path))
    }

    pub fn write_content(&self, content: &str) -> anyhow::Result<()> {
        std::fs::write(&self.0, content)?;

        let wide_name = WideString::from(self.0.as_os_str());

        // Remove file on reboot.
        // SAFETY: File path is valid, therefore it is safe to call.
        unsafe { MoveFileExW(wide_name.as_pcwstr(), PCWSTR::null(), MOVEFILE_DELAY_UNTIL_REBOOT) }?;

        Ok(())
    }

    pub fn path(&self) -> &PathBuf {
        &self.0
    }

    pub fn path_string(&self) -> String {
        format!("{}", self.0.display())
    }
}

impl Drop for TmpFileGuard {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.0) {
            let path = format!("{}", self.0.display());
            error!(%error, path, "Failed to remove temporary file");
        }
    }
}
