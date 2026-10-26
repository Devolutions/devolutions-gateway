#[cfg(unix)]
use std::fs::File;

use anyhow::Context as _;
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

    private_file::retry_sharing_violation(
        Instant::now(),
        Duration::from_secs(30),
        Duration::from_millis(25),
        || {
            private_file::provision_directories(data_dir, grant_current_user)?
                .open_dir(
                    "identity",
                    &private_file::tree_rule(grant_current_user),
                    private_fs::Share::Exclusive,
                )
                .context("open identity state lock")
        },
    )
    .map_err(|error| {
        if private_file::is_sharing_violation(&error) {
            error.context("identity state lock remained busy")
        } else {
            error
        }
    })?
    .context("identity directory disappeared after its creation")
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
    use std::time::Duration;

    use super::*;

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn trusted_lock_serializes_concurrent_writers() -> anyhow::Result<()> {
        let directory = private_file::TestDir::new()?;
        let lock = acquire(directory.path(), true)?;
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                let result = acquire(directory.path(), true).map(|_lock| ());
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
                .map_err(|_| anyhow::anyhow!("identity lock worker panicked"))
        })
    }
}
