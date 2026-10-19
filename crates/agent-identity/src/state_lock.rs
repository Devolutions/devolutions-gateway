use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::io::ErrorKind;

use anyhow::Context as _;
#[cfg(windows)]
use anyhow::ensure;
use camino::Utf8Path;

use crate::private_file;

pub(crate) fn acquire(data_dir: &Utf8Path, grant_current_user: bool) -> anyhow::Result<File> {
    #[cfg(unix)]
    {
        private_file::prepare_directories(data_dir, grant_current_user)?;
        lock_file(&data_dir.join("identity").join(".agent-identity.lock"))
    }
    #[cfg(windows)]
    lock_directory(data_dir, grant_current_user)
}

#[cfg(unix)]
fn lock_file(path: &Utf8Path) -> anyhow::Result<File> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    match private_file::open_read(path) {
        Ok(file) => drop(file),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|source| source.kind() == ErrorKind::NotFound) => {}
        Err(error) => return Err(error),
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .context("open identity state lock")?;
    private_file::verify_open_file(&file)?;
    loop {
        // SAFETY: The file descriptor stays open until the caller drops the lock guard.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(file);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error).context("lock identity state");
        }
    }
}

#[cfg(windows)]
fn lock_directory(data_dir: &Utf8Path, grant_current_user: bool) -> anyhow::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::time::Duration;

    use windows::Win32::Foundation::ERROR_SHARING_VIOLATION;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
        READ_CONTROL,
    };

    let started = std::time::Instant::now();
    let mut options = OpenOptions::new();
    options
        .read(true)
        .access_mode((FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL).0)
        .share_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0);
    let sharing_violation = i32::try_from(ERROR_SHARING_VIOLATION.0)?;
    loop {
        match private_file::prepare_directories(data_dir, grant_current_user) {
            Ok(()) => {}
            Err(error) if is_sharing_violation(&error, sharing_violation) => {
                ensure!(
                    started.elapsed() < Duration::from_secs(30),
                    "identity state lock remained busy"
                );
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(error) => return Err(error),
        }
        let identity = data_dir.join("identity");
        match options.open(&identity) {
            Ok(directory) => {
                crate::windows::verify_protected_directory(&directory, grant_current_user, false)?;
                let obsolete = identity.join(".agent-identity.lock");
                if std::fs::symlink_metadata(&obsolete).is_ok() {
                    let _ = private_file::verify_state_path(&obsolete);
                }
                return Ok(directory);
            }
            Err(error) if error.raw_os_error() == Some(sharing_violation) => {
                ensure!(
                    started.elapsed() < Duration::from_secs(30),
                    "identity state lock remained busy"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error).context("open identity state lock"),
        }
    }
}

#[cfg(windows)]
fn is_sharing_violation(error: &anyhow::Error, code: i32) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|error| error.raw_os_error() == Some(code))
}

#[cfg(all(test, windows))]
mod tests {
    use std::fs;
    use std::time::Duration;

    use super::*;

    #[test]
    fn trusted_lock_serializes_concurrent_writers() -> anyhow::Result<()> {
        let data_dir = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("lock-tests")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&data_dir)?;
        let lock = acquire(&data_dir, true)?;
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker_dir = data_dir.clone();
        let worker = std::thread::spawn(move || {
            let result = acquire(&worker_dir, true).map(|_lock| ());
            let _ = sender.send(result);
        });
        std::thread::sleep(Duration::from_millis(50));
        match receiver.try_recv() {
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => anyhow::bail!("identity lock worker disconnected"),
            Ok(Ok(())) => anyhow::bail!("concurrent writer acquired the identity lock before release"),
            Ok(Err(error)) => return Err(error).context("concurrent writer failed before release"),
        }
        drop(lock);
        receiver.recv_timeout(Duration::from_secs(5))??;
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("identity lock worker panicked"))?;
        fs::remove_dir_all(data_dir)?;
        Ok(())
    }
}
