//! Files and directories that only the accounts a rule allows can access.
//!
//! A caller describes who may own and access a file or directory with a [`Rule`], opens a base directory with
//! [`Dir::create_base`] or [`Dir::open_base`], and creates, opens, renames and removes what lies below it through
//! [`Dir`] handles, each checked against its rule, never by resolving a path again.
//!
//! See [`INTENT.md`] for what private-fs guarantees and why.
//!
//! [`INTENT.md`]: https://github.com/Devolutions/devolutions-gateway/blob/master/crates/private-fs/INTENT.md

mod error;
mod rule;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use std::ffi::OsString;
use std::fs::File;

use camino::{Utf8Path, Utf8PathBuf};

pub use self::error::{Error, ErrorKind, Refusal};
pub use self::rule::{Access, Account, Fallback, Rule};
#[cfg(unix)]
use self::unix as sys;
#[cfg(windows)]
use self::windows as sys;
#[cfg(windows)]
pub use self::windows::BackupPrivilege;

pub type Result<T> = std::result::Result<T, Error>;

/// An open directory, checked against a rule, through which the files and directories below it are created and opened.
#[derive(Debug)]
pub struct Dir {
    inner: sys::Dir,
    path: Utf8PathBuf,
}

/// What [`Dir::create_dir`] does with a directory that already exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Existing {
    /// The directory counts as created only if it passes the rule.
    Check,
    /// The directory is brought into line with the rule.
    Repair,
}

/// Whether a rename may replace an existing entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replace {
    Allow,
    Refuse,
}

/// Whether other handles may be open on a file or directory while this one is.
///
/// Linux and macOS have no such sharing control, and ignore it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Share {
    Shared,
    Exclusive,
}

/// How [`Dir::open_file`] and [`Dir::create_file`] open a file.
///
/// A file opened with neither read nor write is open only for checking its owner and access.
#[derive(Clone, Copy, Debug)]
pub struct FileOptions {
    read: bool,
    write: bool,
    share: Share,
}

/// An entry of a directory, as [`Dir::entries`] lists it.
#[derive(Clone, Debug)]
pub struct Entry {
    pub name: OsString,
    pub kind: EntryKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    /// A symbolic link or another reparse point.
    Link,
    Other,
}

impl FileOptions {
    pub fn new() -> Self {
        Self {
            read: false,
            write: false,
            share: Share::Shared,
        }
    }

    #[must_use]
    pub fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    #[must_use]
    pub fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    #[must_use]
    pub fn share(mut self, share: Share) -> Self {
        self.share = share;
        self
    }
}

impl Default for FileOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl Dir {
    /// Opens the directory at `path`, creating it and its missing parents under `rule`.
    ///
    /// The first directory of `path` that exists, and every directory above it on its resolved path up to the root,
    /// must be owned by the system account, administrators or an account of `rule`, and no other account may be able
    /// to rename or replace them; being able to add an entry beside one does not count.
    /// That first directory and everything below it must not be a link.
    /// Each directory created has exactly `rule` from the moment it exists, and one that another process creates first
    /// counts as created only if it passes `rule`.
    pub fn create_base(path: &Utf8Path, rule: &Rule) -> Result<Self> {
        sys::create_base(path, rule).map(|inner| Self {
            inner,
            path: path.to_owned(),
        })
    }

    /// Opens the existing directory at `path`, with the checks of [`Dir::create_base`] on it and the directories above it,
    /// and returns `None` when it doesn't exist.
    pub fn open_base(path: &Utf8Path, rule: &Rule) -> Result<Option<Self>> {
        Ok(sys::open_base(path, rule)?.map(|inner| Self {
            inner,
            path: path.to_owned(),
        }))
    }

    pub fn path(&self) -> &Utf8Path {
        &self.path
    }

    /// Creates the directory `name` with exactly `rule` from the moment it exists, and makes its entry durable.
    pub fn create_dir(&self, name: &str, rule: &Rule, existing: Existing) -> Result<Self> {
        let path = self.child(name)?;
        sys::create_dir(&self.inner, &path, name, rule, existing).map(|inner| Self { inner, path })
    }

    /// Opens the existing directory `name` once it passes `rule`, and returns `None` when it doesn't exist.
    pub fn open_dir(&self, name: &str, rule: &Rule, share: Share) -> Result<Option<Self>> {
        let path = self.child(name)?;
        Ok(sys::open_dir(&self.inner, &path, name, rule, share)?.map(|inner| Self { inner, path }))
    }

    /// Opens the existing file `name` once it passes `rule`, and returns `None` when it doesn't exist.
    ///
    /// A file with more than one hard link fails the check.
    pub fn open_file(&self, name: &str, rule: &Rule, options: FileOptions) -> Result<Option<File>> {
        let path = self.child(name)?;
        sys::open_file(&self.inner, &path, name, rule, options)
    }

    /// Creates the file `name`, which must not exist, with exactly `rule` from the moment it exists.
    ///
    /// The file is open for writing whatever `options` says.
    /// Its entry is durable only once [`Dir::persist`] or [`Dir::sync`] returns.
    pub fn create_file(&self, name: &str, rule: &Rule, options: FileOptions) -> Result<File> {
        let path = self.child(name)?;
        sys::create_file(&self.inner, &path, name, rule, options.write(true))
    }

    /// Opens the file `name` once it passes `rule`, or creates it as [`Dir::create_file`] does when it doesn't exist.
    pub fn open_or_create_file(&self, name: &str, rule: &Rule, options: FileOptions) -> Result<File> {
        loop {
            if let Some(file) = self.open_file(name, rule, options)? {
                return Ok(file);
            }
            match self.create_file(name, rule, options) {
                Err(error) if error.already_exists() => continue,
                created => return created,
            }
        }
    }

    /// Renames the entry `from` to `to`, both in this directory.
    pub fn rename(&self, from: &str, to: &str, replace: Replace) -> Result<()> {
        let path = self.child(from)?;
        self.child(to)?;
        sys::rename(&self.inner, &path, from, to, replace)
    }

    /// Makes `file`, written under the name `from` in this directory, durable under the name `to`.
    ///
    /// Once this returns, a power cut leaves `to` with the content of `file`.
    pub fn persist(&self, file: &File, from: &str, to: &str, replace: Replace) -> Result<()> {
        let path = self.child(from)?;
        self.child(to)?;
        sys::persist(&self.inner, &path, file, from, to, replace)
    }

    /// Removes the file `name` that this handle created as `file`, through `file` itself where the platform allows.
    ///
    /// A file can be created with a rule that gives its creator no access once created, so removing it by name again
    /// could be refused.
    pub fn discard(&self, file: &File, name: &str) -> Result<()> {
        let path = self.child(name)?;
        sys::discard(&self.inner, &path, file, name)
    }

    /// Removes the file `name`, and returns `false` when it doesn't exist.
    pub fn remove_file(&self, name: &str) -> Result<bool> {
        let path = self.child(name)?;
        sys::remove_file(&self.inner, &path, name)
    }

    /// Lists the entries of this directory, without `.` and `..`.
    pub fn entries(&self) -> Result<Vec<Entry>> {
        sys::entries(&self.inner, &self.path)
    }

    /// Makes the entries created, renamed and removed in this directory durable.
    pub fn sync(&self) -> Result<()> {
        sys::sync(&self.inner, &self.path)
    }

    /// Checks this directory against `rule`.
    pub fn check(&self, rule: &Rule) -> Result<()> {
        sys::check_dir(&self.inner, &self.path, rule)
    }

    /// Brings this directory into line with `rule`, without changing anything below it.
    pub fn repair(&self, rule: &Rule) -> Result<()> {
        sys::repair_dir(&self.inner, &self.path, rule)
    }

    fn child(&self, name: &str) -> Result<Utf8PathBuf> {
        let path = self.path.join(name);
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) || name.contains('\0') {
            return Err(Error::io(
                &path,
                "use entry name",
                std::io::Error::from(std::io::ErrorKind::InvalidInput),
            ));
        }
        Ok(path)
    }
}

/// Checks an open file, at `path`, against `rule`.
pub fn check_file(file: &File, path: &Utf8Path, rule: &Rule) -> Result<()> {
    sys::check_file(file, path, rule)
}

impl Error {
    fn already_exists(&self) -> bool {
        matches!(self.kind(), ErrorKind::Io { source, .. } if source.kind() == std::io::ErrorKind::AlreadyExists)
    }
}
