//! Backend contract, implemented per platform.

use std::fs::File;

use camino::Utf8Path;

use crate::{Entry, Existing, FileOptions, Replace, Result, Rule, Share};

#[derive(Debug)]
pub(crate) struct Dir;

pub(crate) fn create_base(path: &Utf8Path, rule: &Rule) -> Result<Dir> {
    todo!()
}

pub(crate) fn open_base(path: &Utf8Path, rule: &Rule) -> Result<Option<Dir>> {
    todo!()
}

pub(crate) fn create_dir(parent: &Dir, path: &Utf8Path, name: &str, rule: &Rule, existing: Existing) -> Result<Dir> {
    todo!()
}

pub(crate) fn open_dir(parent: &Dir, path: &Utf8Path, name: &str, rule: &Rule, share: Share) -> Result<Option<Dir>> {
    todo!()
}

pub(crate) fn open_file(
    parent: &Dir,
    path: &Utf8Path,
    name: &str,
    rule: &Rule,
    options: FileOptions,
) -> Result<Option<File>> {
    todo!()
}

pub(crate) fn create_file(
    parent: &Dir,
    path: &Utf8Path,
    name: &str,
    rule: &Rule,
    options: FileOptions,
) -> Result<File> {
    todo!()
}

pub(crate) fn rename(parent: &Dir, path: &Utf8Path, from: &str, to: &str, replace: Replace) -> Result<()> {
    todo!()
}

pub(crate) fn persist(
    parent: &Dir,
    path: &Utf8Path,
    file: &File,
    from: &str,
    to: &str,
    replace: Replace,
) -> Result<()> {
    todo!()
}

pub(crate) fn remove_file(parent: &Dir, path: &Utf8Path, name: &str) -> Result<bool> {
    todo!()
}

pub(crate) fn entries(dir: &Dir, path: &Utf8Path) -> Result<Vec<Entry>> {
    todo!()
}

pub(crate) fn sync(dir: &Dir, path: &Utf8Path) -> Result<()> {
    todo!()
}

pub(crate) fn check_dir(dir: &Dir, path: &Utf8Path, rule: &Rule) -> Result<()> {
    todo!()
}

pub(crate) fn repair_dir(dir: &Dir, path: &Utf8Path, rule: &Rule) -> Result<()> {
    todo!()
}

pub(crate) fn check_file(file: &File, path: &Utf8Path, rule: &Rule) -> Result<()> {
    todo!()
}

/// Enables the backup privilege for the current thread until dropped, so that private-fs can read the owner and access
/// of directories the process token cannot read otherwise.
#[derive(Debug)]
pub struct BackupPrivilege;

impl BackupPrivilege {
    pub fn enable() -> Result<Self> {
        todo!()
    }
}
