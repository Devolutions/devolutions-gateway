use std::path::PathBuf;

/// Guard for created temporary file. Associated file is deleted on drop.
pub struct TmpFileGuard(PathBuf);

impl TmpFileGuard {
    pub fn new(extension: &str) -> anyhow::Result<Self> {
        // Create empty temporary file and release the handle.
        let (_file, path) = tempfile::Builder::new()
            .prefix("devolutions-")
            .suffix(&format!(".{extension}"))
            .tempfile()?
            .keep()?;

        Ok(Self(path))
    }

    pub fn write_content(&self, content: &str) -> anyhow::Result<()> {
        std::fs::write(&self.0, content)?;
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
        // We can't use `MoveFileExW` for scheduled deletion by OS via MOVEFILE_DELAY_UNTIL_REBOOT
        // because it requires administrative rights to work, however devolutions-session
        // is running under non-elevated user account.
        // (see [MSDN](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexa#remarks)).

        if let Err(error) = std::fs::remove_file(&self.0) {
            let path = format!("{}", self.0.display());
            error!(%error, path, "Failed to remove temporary file");
        }
    }
}
