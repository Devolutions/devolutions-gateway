#[cfg(unix)]
use std::fs::File;

use anyhow::Context as _;
#[cfg(windows)]
use anyhow::ensure;
use camino::Utf8Path;
#[cfg(windows)]
use private_fs::Dir;

use crate::private_file;

/// An exclusive lock on the identity state, held until dropped.
pub(crate) struct StateLock {
    #[cfg(unix)]
    _file: File,
    #[cfg(windows)]
    _directory: Dir,
}

pub(crate) fn acquire(data_dir: &Utf8Path, grant_current_user: bool) -> anyhow::Result<StateLock> {
    #[cfg(unix)]
    {
        lock_file(data_dir, grant_current_user).map(|file| StateLock { _file: file })
    }
    #[cfg(windows)]
    lock_directory(data_dir, grant_current_user).map(|directory| StateLock { _directory: directory })
}

/// Locks the identity state through `<data-dir>/identity/.agent-identity.lock`.
#[cfg(unix)]
fn lock_file(data_dir: &Utf8Path, grant_current_user: bool) -> anyhow::Result<File> {
    use std::io::ErrorKind;
    use std::os::fd::AsRawFd as _;

    use private_fs::FileOptions;

    let data = private_file::provision_directories(data_dir, grant_current_user)?;
    let identity = data
        .open_dir(
            "identity",
            &private_file::tree_rule(grant_current_user),
            private_fs::Share::Shared,
        )
        .context("open identity directory")?
        .context("identity directory disappeared after its creation")?;
    let file = identity
        .open_or_create_file(
            ".agent-identity.lock",
            &private_file::state_file_rule(grant_current_user),
            FileOptions::new().read(true).write(true),
        )
        .context("open identity state lock")?;
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

/// Locks the identity state through an unshared handle on `<data-dir>/identity` itself rather than a lock file.
///
/// The lock needs no object of its own: it is the directory the agent provisions and checks before each lock, opened
/// without following a reparse point, so no file another account created or replaced can stand in for it.
/// Any other handle open on the directory, a backup's or an antivirus scan's for example, also fails the open with a
/// sharing violation, so a busy lock is retried for 30 s.
#[cfg(windows)]
fn lock_directory(data_dir: &Utf8Path, grant_current_user: bool) -> anyhow::Result<Dir> {
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::ERROR_SHARING_VIOLATION;

    let started = Instant::now();
    let sharing_violation = i32::try_from(ERROR_SHARING_VIOLATION.0)?;
    loop {
        let locked = private_file::provision_directories(data_dir, grant_current_user).and_then(|data| {
            data.open_dir(
                "identity",
                &private_file::tree_rule(grant_current_user),
                private_fs::Share::Exclusive,
            )
            .context("open identity state lock")
        });
        match locked {
            Ok(Some(directory)) => return Ok(directory),
            Ok(None) => anyhow::bail!("identity directory disappeared after its creation"),
            Err(error) if is_sharing_violation(&error, sharing_violation) => {
                ensure!(
                    started.elapsed() < Duration::from_secs(30),
                    "identity state lock remained busy"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error),
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
impl StateLock {
    /// The unshared handle on `<data-dir>/identity` that holds the lock.
    pub(crate) fn directory(&self) -> &Dir {
        &self._directory
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::fs;
    use std::time::Duration;

    use camino::Utf8PathBuf;

    use super::*;

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn trusted_lock_serializes_concurrent_writers() -> anyhow::Result<()> {
        let data_dir = Utf8PathBuf::from_path_buf(std::env::temp_dir())
            .map_err(|_| anyhow::anyhow!("the temporary directory path is not UTF-8"))?
            .join(format!("ai-{}", uuid::Uuid::new_v4().simple()));
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
