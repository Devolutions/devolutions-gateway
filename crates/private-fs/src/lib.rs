//! Unix helpers for files and directories that only their owner can access.
//!
//! Each helper reports a fact or the I/O error of the step that failed.
//! Callers keep their own owner rules and error wording, and decide where their files live.
#![cfg(unix)]

#[cfg(target_os = "macos")]
mod macos;

use std::fs::{self, File};
use std::io::{self, ErrorKind};
use std::os::unix::fs::DirBuilderExt as _;

use camino::{Utf8Path, Utf8PathBuf};

#[cfg(target_os = "macos")]
pub use self::macos::{ExtendedAclError, has_extended_acl, volume_ignores_ownership};

/// Returns the process's effective user ID.
pub fn effective_uid() -> libc::uid_t {
    // SAFETY: Reading the process's effective UID has no preconditions.
    unsafe { libc::geteuid() }
}

/// Flushes the entries of `dir` to disk.
pub fn sync_directory(dir: &Utf8Path) -> io::Result<()> {
    File::open(dir).and_then(|file| file.sync_all())
}

/// The step of [`create_dir_chain`] that failed, and the path it failed on.
#[derive(Debug)]
pub enum DirChainError {
    /// The path exists and is not a directory; a link to a directory is not one.
    NotADirectory(Utf8PathBuf),
    Inspect(Utf8PathBuf, io::Error),
    Create(Utf8PathBuf, io::Error),
    Sync(Utf8PathBuf, io::Error),
}

/// Creates `dir` and its missing ancestors with mode `0700`, and syncs each directory it creates and that directory's
/// parent.
///
/// A link is never followed: every existing ancestor must be a directory itself.
/// A directory that another process creates first counts as created.
pub fn create_dir_chain(dir: &Utf8Path) -> Result<(), DirChainError> {
    let mut missing = Vec::new();
    let mut path = dir;
    while !directory_exists(path)? {
        missing.push(path);
        path = parent_or_current(path);
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    for &path in missing.iter().rev() {
        // UNTESTED: a directory that another process creates between the check and `create` counts as created.
        // Processes that create the same ancestors at once would otherwise fail at random; no test runs such a race.
        // When changing this, keep accepting `AlreadyExists` for a path that is now a directory, and only then.
        if let Err(error) = builder.create(path)
            && (error.kind() != ErrorKind::AlreadyExists || !directory_exists(path)?)
        {
            return Err(DirChainError::Create(path.to_owned(), error));
        }
        // UNTESTED: each created directory and its parent are synced before the next one is created.
        // Without it, a power loss can drop a directory whose files a caller already reported as written; no test can cut power.
        // When changing this loop, keep syncing both before creating the next directory.
        for synced in [path, parent_or_current(path)] {
            sync_directory(synced).map_err(|error| DirChainError::Sync(synced.to_owned(), error))?;
        }
    }
    Ok(())
}

fn directory_exists(path: &Utf8Path) -> Result<bool, DirChainError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err(DirChainError::NotADirectory(path.to_owned())),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(DirChainError::Inspect(path.to_owned(), error)),
    }
}

fn parent_or_current(path: &Utf8Path) -> &Utf8Path {
    path.parent()
        .filter(|parent| !parent.as_str().is_empty())
        .unwrap_or_else(|| Utf8Path::new("."))
}
