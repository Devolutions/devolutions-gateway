use std::{io::Seek, os::windows::fs::OpenOptionsExt, path::PathBuf};

use std::io::{self, Read};

use crate::traits::Reopenable;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const FILE_SHARE_READ: u32 = 0x00000001;

pub struct ReOpenableFile {
    inner: std::fs::File,
    file_path: PathBuf,
}

impl ReOpenableFile {
    pub fn open(file_path: impl Into<PathBuf>) -> io::Result<Self> {
        let file_path: PathBuf = file_path.into();
        let inner = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_WRITE | FILE_SHARE_READ)
            .open(&file_path)?;

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
        self.inner = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_WRITE | FILE_SHARE_READ)
            .open(&self.file_path)?;
        Ok(())
    }
}
