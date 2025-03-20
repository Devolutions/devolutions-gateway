use std::io::{self, Read, Seek};
use std::path::PathBuf;

use crate::reopenable::Reopenable;

#[cfg(windows)]
const FILE_SHARE_WRITE: u32 = 0x00000002;
#[cfg(windows)]
const FILE_SHARE_READ: u32 = 0x00000001;
#[cfg(windows)]
const FILE_SHARE_DELETE: u32 = 0x00000004;

pub struct ReOpenableFile {
    inner: std::fs::File,
    file_path: PathBuf,
}

impl ReOpenableFile {
    pub fn open(file_path: impl Into<PathBuf>) -> io::Result<Self> {
        let mut open_option = std::fs::OpenOptions::new();
        open_option.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            open_option.share_mode(FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE);
        }

        let file_path: PathBuf = file_path.into();
        let inner = open_option.open(&file_path)?;

        Ok(Self { inner, file_path })
    }
}

impl Read for ReOpenableFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Seek for ReOpenableFile {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

impl Reopenable for ReOpenableFile {
    fn reopen(&mut self) -> io::Result<()> {
        let mut open_option = std::fs::OpenOptions::new();
        open_option.read(true);

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            open_option.share_mode(FILE_SHARE_WRITE | FILE_SHARE_READ);
        }

        let inner = open_option.open(&self.file_path)?;

        self.inner = inner;
        Ok(())
    }
}
