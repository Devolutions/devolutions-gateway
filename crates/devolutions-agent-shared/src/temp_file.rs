use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use tracing::error;

pub const BATCH_UTF8_PREAMBLE: &str = "@chcp 65001 > nul";
pub const POWERSHELL_UTF8_ENCODING_PREAMBLE: &str =
    "$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()";

/// Guard for a temporary file that is removed on drop.
pub struct TmpFileGuard {
    path: PathBuf,
}

impl TmpFileGuard {
    pub fn new(extension: &str) -> io::Result<Self> {
        Self::with_prefix_in("devolutions-", extension, None)
    }

    pub fn with_prefix_in(prefix: &str, extension: &str, temp_dir: Option<&Path>) -> io::Result<Self> {
        let suffix = format!(".{extension}");
        let mut builder = tempfile::Builder::new();
        builder.prefix(prefix).suffix(&suffix);

        let tempfile = match temp_dir {
            Some(temp_dir) => builder.tempfile_in(temp_dir),
            None => builder.tempfile(),
        }?;

        let (_file, path) = tempfile.keep().map_err(|error| error.error)?;

        Ok(Self { path })
    }

    pub fn write_content(&self, content: &str) -> io::Result<()> {
        self.write_bytes(content.as_bytes())
    }

    pub fn write_bytes(&self, content: &[u8]) -> io::Result<()> {
        fs::write(&self.path, content)
    }

    /// Write content as UTF-8 with a BOM prefix for Windows PowerShell 5.x script files.
    pub fn write_content_utf8_bom(&self, content: &str) -> io::Result<()> {
        let mut file = fs::File::create(&self.path)?;
        file.write_all(b"\xEF\xBB\xBF")?;
        file.write_all(content.as_bytes())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn path_string(&self) -> String {
        self.path.display().to_string()
    }
}

impl Drop for TmpFileGuard {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.path) {
            error!(%error, path = %self.path.display(), "Failed to remove temporary file");
        }
    }
}
