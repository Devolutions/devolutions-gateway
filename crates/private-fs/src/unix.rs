//! Linux and macOS backend.
//!
//! The owner of a file or directory can always change its mode, so it always has full access, and root can access
//! everything whatever the mode says.
//! A rule therefore reduces to an owner, mode `0700` for a directory or `0600` for a file, and no extended ACL.

use std::ffi::{CStr, CString, OsString};
use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::ptr::NonNull;

use camino::{Utf8Component, Utf8Path, Utf8PathBuf};

#[cfg(target_os = "linux")]
use crate::linux as os;
#[cfg(target_os = "macos")]
use crate::macos as os;
use crate::rule::Grant;
use crate::{
    Access, Account, Entry, EntryKind, Error, Existing, Fallback, FileOptions, Refusal, Replace, Result, Rule, Share,
};

/// The mode of a directory, owner-only.
const DIR_MODE: u32 = 0o700;
/// [`DIR_MODE`] as `mkdirat` takes it.
const MKDIR_MODE: libc::mode_t = 0o700;
/// The mode of a file, owner-only, as `openat` takes it.
const FILE_MODE: libc::c_uint = 0o600;
/// The permission bits of the group and other classes.
const GROUP_OTHER_BITS: u32 = 0o077;
const GROUP_WRITE: u32 = 0o020;
const OTHER_WRITE: u32 = 0o002;
const STICKY: u32 = 0o1000;

#[derive(Debug)]
pub(crate) struct Dir {
    file: File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Directory,
    File,
}

/// The accounts that may own a directory above a base directory, or be able to rename or replace it.
pub(crate) struct Allowed {
    /// The effective user ID, when the rule names [`Account::CurrentUser`].
    current_user: Option<libc::uid_t>,
}

impl Allowed {
    fn new(rule: &Rule) -> Self {
        Self {
            current_user: rule
                .accounts()
                .any(|account| account == Account::CurrentUser)
                .then(effective_uid),
        }
    }

    /// Reports whether `uid` is root or an account of the rule; System and Administrators are root.
    pub(crate) fn uid(&self, uid: libc::uid_t) -> bool {
        uid == 0 || self.current_user == Some(uid)
    }
}

/// Reports whether `gid` is a group of administrators, whose write access to a directory above doesn't count.
pub(crate) fn admin_gid(gid: libc::gid_t) -> bool {
    os::ADMIN_GIDS.contains(&gid)
}

pub(crate) fn create_base(path: &Utf8Path, rule: &Rule) -> Result<Dir> {
    let base = Base::open(path, rule)?;
    let mut dir = base.dir;
    let mut current = base.prefix;
    for name in base.missing {
        current.push(name);
        dir = create_dir(&dir, &current, name, rule, Existing::Check)?;
    }
    Ok(dir)
}

pub(crate) fn open_base(path: &Utf8Path, rule: &Rule) -> Result<Option<Dir>> {
    let base = Base::open(path, rule)?;
    let allowed = Allowed::new(rule);
    let mut dir = base.dir;
    let mut current = base.prefix;
    for name in base.missing {
        current.push(name);
        let Some(file) = open_at(
            &dir,
            &current,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            Kind::Directory,
        )?
        else {
            return Ok(None);
        };
        check_not_replaceable_handle(&file, &current, &allowed)?;
        dir = Dir { file };
    }
    Ok(Some(dir))
}

pub(crate) fn create_dir(parent: &Dir, path: &Utf8Path, name: &str, rule: &Rule, existing: Existing) -> Result<Dir> {
    check_creatable(path, rule, Kind::Directory)?;
    os::refuse_inheritable_acl(&parent.file, parent_path(path))?;
    let c_name = c_name(path, name)?;
    // SAFETY: The parent descriptor is open and the name is NUL-terminated.
    let created = unsafe { libc::mkdirat(parent.file.as_raw_fd(), c_name.as_ptr(), MKDIR_MODE) } == 0;
    if !created {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(Error::io(path, "create directory", error));
        }
    }
    let Some(file) = open_at(parent, path, name, libc::O_RDONLY | libc::O_DIRECTORY, Kind::Directory)? else {
        return Err(Error::io(path, "open directory", io::ErrorKind::NotFound.into()));
    };
    let dir = Dir { file };
    if created {
        if let Err(error) = protect_created_dir(&dir, path, rule) {
            discard_entry(parent, &c_name, &dir.file, libc::AT_REMOVEDIR);
            return Err(error);
        }
    } else {
        match existing {
            Existing::Check => check_dir(&dir, path, rule)?,
            Existing::Repair => repair_dir(&dir, path, rule)?,
        }
    }
    // UNTESTED: the new directory and its parent are synced before the directory is returned.
    // Without it, a power cut can drop a directory whose files a caller already reported as written; no test can cut
    // power.
    // When changing this, keep syncing both, also for a directory another process created first.
    dir.file
        .sync_all()
        .map_err(|error| Error::io(path, "sync directory", error))?;
    parent
        .file
        .sync_all()
        .map_err(|error| Error::io(parent_path(path), "sync directory", error))?;
    Ok(dir)
}

pub(crate) fn open_dir(parent: &Dir, path: &Utf8Path, name: &str, rule: &Rule, _share: Share) -> Result<Option<Dir>> {
    let Some(file) = open_at(
        parent,
        path,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
        Kind::Directory,
    )?
    else {
        return Ok(None);
    };
    check_item(&file, path, rule, Kind::Directory)?;
    Ok(Some(Dir { file }))
}

pub(crate) fn open_file(
    parent: &Dir,
    path: &Utf8Path,
    name: &str,
    rule: &Rule,
    options: FileOptions,
) -> Result<Option<File>> {
    // O_NONBLOCK keeps a FIFO at the name from blocking the open; reads and writes of a regular file ignore it.
    let flags = access_flags(options) | libc::O_NONBLOCK;
    let Some(file) = open_at(parent, path, name, flags, Kind::File)? else {
        return Ok(None);
    };
    check_item(&file, path, rule, Kind::File)?;
    Ok(Some(file))
}

pub(crate) fn create_file(
    parent: &Dir,
    path: &Utf8Path,
    name: &str,
    rule: &Rule,
    options: FileOptions,
) -> Result<File> {
    check_creatable(path, rule, Kind::File)?;
    os::refuse_inheritable_acl(&parent.file, parent_path(path))?;
    let c_name = c_name(path, name)?;
    let flags =
        access_flags(options) | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY;
    // SAFETY: The parent descriptor is open, the name is NUL-terminated, and O_CREAT takes the mode argument.
    let fd = unsafe { libc::openat(parent.file.as_raw_fd(), c_name.as_ptr(), flags, FILE_MODE) };
    if fd < 0 {
        return Err(Error::io(path, "create file", io::Error::last_os_error()));
    }
    // SAFETY: openat returned a new descriptor that nothing else owns.
    let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    if let Err(error) = check_item(&file, path, rule, Kind::File) {
        discard_entry(parent, &c_name, &file, 0);
        return Err(error);
    }
    Ok(file)
}

pub(crate) fn rename(parent: &Dir, path: &Utf8Path, from: &str, to: &str, replace: Replace) -> Result<()> {
    let from = c_name(path, from)?;
    let to = c_name(path, to)?;
    let fd = parent.file.as_raw_fd();
    let renamed = match replace {
        // SAFETY: The descriptor is open and both names are NUL-terminated.
        Replace::Allow => match unsafe { libc::renameat(fd, from.as_ptr(), fd, to.as_ptr()) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        },
        Replace::Refuse => match os::rename_exclusive(fd, &from, &to) {
            Err(error) if error.raw_os_error().is_some_and(rename_exclusive_unsupported) => {
                // UNTESTED: without an exclusive rename, the entry is linked under its new name, which fails when
                // the name exists, and then unlinked under its old one.
                // The kernels and file systems CI runs on support the exclusive rename.
                // When changing this, keep the link step failing on an existing name rather than replacing it.
                link_then_unlink(fd, &from, &to)
            }
            renamed => renamed,
        },
    };
    renamed.map_err(|error| Error::io(path, "rename", error))
}

pub(crate) fn persist(
    parent: &Dir,
    path: &Utf8Path,
    file: &File,
    from: &str,
    to: &str,
    replace: Replace,
) -> Result<()> {
    file.sync_all().map_err(|error| Error::io(path, "sync file", error))?;
    rename(parent, path, from, to, replace)?;
    // UNTESTED: the directory is synced after the rename, so the new name survives a power cut.
    // No test can cut power; when changing this, keep the file sync before the rename and the directory sync after.
    sync(parent, parent_path(path))
}

pub(crate) fn remove_file(parent: &Dir, path: &Utf8Path, name: &str) -> Result<bool> {
    let c_name = c_name(path, name)?;
    // SAFETY: The descriptor is open and the name is NUL-terminated.
    if unsafe { libc::unlinkat(parent.file.as_raw_fd(), c_name.as_ptr(), 0) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(false);
        }
        return Err(Error::io(path, "remove file", error));
    }
    sync(parent, parent_path(path))?;
    Ok(true)
}

/// Removes the file `name`, which `file` was created as, unless the name now holds another file.
pub(crate) fn discard(parent: &Dir, path: &Utf8Path, file: &File, name: &str) -> Result<()> {
    let c_name = c_name(path, name)?;
    let created = fstat(file).map_err(|error| Error::io(path, "inspect file", error))?;
    let current = match stat_at(&parent.file, &c_name) {
        Ok(current) => current,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(Error::io(path, "inspect file", error)),
    };
    if !same_file(&created, &current) {
        return Ok(());
    }
    // SAFETY: The descriptor is open and the name is NUL-terminated.
    if unsafe { libc::unlinkat(parent.file.as_raw_fd(), c_name.as_ptr(), 0) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(Error::io(path, "remove file", error));
        }
    }
    Ok(())
}

pub(crate) fn entries(dir: &Dir, path: &Utf8Path) -> Result<Vec<Entry>> {
    let list_error = |error| Error::io(path, "list directory", error);
    // fdopendir takes over a descriptor and its position, so it reads a fresh descriptor of the same directory.
    // SAFETY: The descriptor is open and the name is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            dir.file.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(list_error(io::Error::last_os_error()));
    }
    // SAFETY: openat returned a new descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: The descriptor is an open directory.
    let stream = unsafe { libc::fdopendir(fd.as_raw_fd()) };
    let Some(stream) = NonNull::new(stream) else {
        return Err(list_error(io::Error::last_os_error()));
    };
    // The stream owns the descriptor from here on, and closedir closes it.
    let _ = fd.into_raw_fd();
    let stream = DirStream(stream);
    let mut entries = Vec::new();
    loop {
        os::clear_errno();
        // SAFETY: The stream is open, and no other reference to an entry it returned is alive.
        let entry = unsafe { libc::readdir(stream.0.as_ptr()) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(0) {
                return Ok(entries);
            }
            return Err(list_error(error));
        }
        // SAFETY: readdir returned an entry that stays valid until the next call on the stream.
        let entry = unsafe { &*entry };
        // SAFETY: d_name is a NUL-terminated name inside the entry.
        let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) };
        if name == c"." || name == c".." {
            continue;
        }
        let kind = match entry.d_type {
            libc::DT_REG => EntryKind::File,
            libc::DT_DIR => EntryKind::Directory,
            libc::DT_LNK => EntryKind::Link,
            libc::DT_UNKNOWN => match stat_at(&dir.file, name) {
                Ok(stat) => entry_kind(stat.st_mode),
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(list_error(error)),
            },
            _ => EntryKind::Other,
        };
        entries.push(Entry {
            name: OsString::from_vec(name.to_bytes().to_vec()),
            kind,
        });
    }
}

pub(crate) fn sync(dir: &Dir, path: &Utf8Path) -> Result<()> {
    dir.file
        .sync_all()
        .map_err(|error| Error::io(path, "sync directory", error))
}

pub(crate) fn check_dir(dir: &Dir, path: &Utf8Path, rule: &Rule) -> Result<()> {
    check_item(&dir.file, path, rule, Kind::Directory)
}

pub(crate) fn repair_dir(dir: &Dir, path: &Utf8Path, rule: &Rule) -> Result<()> {
    let euid = effective_uid();
    let metadata = dir
        .file
        .metadata()
        .map_err(|error| Error::io(path, "inspect directory", error))?;
    let owner = if owner_allowed(rule, metadata.uid(), euid) {
        metadata.uid()
    } else {
        euid
    };
    check_rule(path, rule, owner, euid, Kind::Directory)?;
    if owner != metadata.uid() {
        std::os::unix::fs::fchown(&dir.file, Some(owner), None)
            .map_err(|error| Error::io(path, "change owner", error))?;
    }
    os::remove_extended_acl(&dir.file, path)?;
    dir.file
        .set_permissions(Permissions::from_mode(DIR_MODE))
        .map_err(|error| Error::io(path, "change mode", error))?;
    check_item(&dir.file, path, rule, Kind::Directory)
}

pub(crate) fn check_file(file: &File, path: &Utf8Path, rule: &Rule) -> Result<()> {
    check_item(file, path, rule, Kind::File)
}

/// The first existing directory of a path, open and checked with the directories above it, and the names of the
/// directories below it that didn't exist.
struct Base<'a> {
    dir: Dir,
    /// The path of the directory as the caller wrote it, empty for the current directory.
    prefix: Utf8PathBuf,
    missing: Vec<&'a str>,
}

impl<'a> Base<'a> {
    fn open(path: &'a Utf8Path, rule: &Rule) -> Result<Self> {
        let mut missing = Vec::new();
        let mut components = path.components();
        let (prefix, candidate) = loop {
            let prefix = components.as_path();
            let candidate = if prefix.as_str().is_empty() {
                Utf8Path::new(".")
            } else {
                prefix
            };
            match std::fs::symlink_metadata(candidate) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(Error::refused(candidate, Refusal::Link));
                }
                Ok(metadata) if !metadata.is_dir() => return Err(Error::refused(candidate, Refusal::NotADirectory)),
                Ok(_) => break (prefix.to_owned(), candidate),
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ENOTDIR) =>
                {
                    match components.next_back() {
                        Some(Utf8Component::Normal(name)) => missing.push(name),
                        Some(_) => {
                            return Err(Error::io(
                                candidate,
                                "use directory path",
                                io::ErrorKind::InvalidInput.into(),
                            ));
                        }
                        None => return Err(Error::io(candidate, "inspect directory", error)),
                    }
                }
                Err(error) => return Err(Error::io(candidate, "inspect directory", error)),
            }
        };
        missing.reverse();
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(candidate)
            .map_err(|error| match std::fs::symlink_metadata(candidate) {
                Ok(metadata) if metadata.file_type().is_symlink() => Error::refused(candidate, Refusal::Link),
                Ok(metadata) if !metadata.is_dir() => Error::refused(candidate, Refusal::NotADirectory),
                _ => Error::io(candidate, "open directory", error),
            })?;
        check_ancestors(&file, candidate, rule)?;
        Ok(Self {
            dir: Dir { file },
            prefix,
            missing,
        })
    }
}

/// Refuses when an account outside the system account, administrators and the accounts of `rule` owns the open
/// directory `dir`, at `path`, or a directory above it on its resolved path, or can rename or replace one of them.
fn check_ancestors(dir: &File, path: &Utf8Path, rule: &Rule) -> Result<()> {
    let resolved = std::fs::canonicalize(path).map_err(|error| Error::io(path, "resolve directory", error))?;
    let resolved = Utf8PathBuf::from_path_buf(resolved)
        .map_err(|_| Error::io(path, "resolve directory", io::ErrorKind::InvalidData.into()))?;
    let opened = dir
        .metadata()
        .map_err(|error| Error::io(path, "inspect directory", error))?;
    // UNTESTED: the resolved path must name the directory that was opened.
    // Another account that swaps a directory on the path between the open and the resolution would otherwise get a
    // different directory checked; no test runs that race.
    // When changing this, keep comparing the device and inode of the resolved path with those of the handle.
    match std::fs::symlink_metadata(&resolved) {
        Ok(found) if found.dev() == opened.dev() && found.ino() == opened.ino() => {}
        Ok(_) => return Err(Error::refused(&resolved, Refusal::Replaceable)),
        Err(error) => return Err(Error::refused(&resolved, Refusal::Unreadable(error))),
    }
    let allowed = Allowed::new(rule);
    check_not_replaceable_handle(dir, &resolved, &allowed)?;
    resolved
        .ancestors()
        .skip(1)
        .try_for_each(|ancestor| check_not_replaceable_path(ancestor, &allowed))
}

fn check_not_replaceable_handle(dir: &File, path: &Utf8Path, allowed: &Allowed) -> Result<()> {
    let metadata = dir
        .metadata()
        .map_err(|error| Error::refused(path, Refusal::Unreadable(error)))?;
    let acl = os::ancestor_acl_of_file(dir).map_err(|error| Error::refused(path, Refusal::Unreadable(error)))?;
    check_not_replaceable(path, &metadata, &acl, allowed)
}

fn check_not_replaceable_path(path: &Utf8Path, allowed: &Allowed) -> Result<()> {
    let unreadable = |error| Error::refused(path, Refusal::Unreadable(error));
    let before = std::fs::symlink_metadata(path).map_err(unreadable)?;
    if !before.is_dir() {
        return Err(Error::refused(path, Refusal::Replaceable));
    }
    let acl = os::ancestor_acl_of_path(path).map_err(unreadable)?;
    let after = std::fs::symlink_metadata(path).map_err(unreadable)?;
    // UNTESTED: the ACL read by path must belong to the directory whose owner and mode are checked.
    // A directory swapped in between would lend its ACL to another; no test runs that race.
    // When changing this, keep the second look at the path and its comparison with the first.
    if !(after.is_dir() && after.dev() == before.dev() && after.ino() == before.ino()) {
        return Err(Error::refused(path, Refusal::Replaceable));
    }
    check_not_replaceable(path, &after, &acl, allowed)
}

fn check_not_replaceable(path: &Utf8Path, metadata: &Metadata, acl: &os::AncestorAcl, allowed: &Allowed) -> Result<()> {
    if !allowed.uid(metadata.uid()) || replaceable(metadata.mode(), metadata.gid(), acl, allowed) {
        return Err(Error::refused(path, Refusal::Replaceable));
    }
    Ok(())
}

/// Reports whether an account that `allowed` doesn't name can rename or replace the entries of a directory with
/// `mode`, group `gid` and `acl`.
///
/// Write access to a directory with the sticky bit only lets an account add entries and remove its own.
fn replaceable(mode: u32, gid: libc::gid_t, acl: &os::AncestorAcl, allowed: &Allowed) -> bool {
    let sticky = mode & STICKY != 0;
    if os::acl_lets_replace(acl, sticky, allowed) {
        return true;
    }
    if sticky {
        return false;
    }
    let group_write = os::owning_group_writes(acl).unwrap_or(mode & GROUP_WRITE != 0);
    mode & OTHER_WRITE != 0 || (group_write && !admin_gid(gid))
}

fn protect_created_dir(dir: &Dir, path: &Utf8Path, rule: &Rule) -> Result<()> {
    let mode = dir
        .file
        .metadata()
        .map_err(|error| Error::io(path, "inspect directory", error))?
        .mode();
    // UNTESTED: a umask that removes owner bits doesn't leave the new directory unusable.
    // The umask is process-wide, so a test can't set one without racing every other test.
    // When changing this, keep the mode change before the check.
    if mode & 0o777 != DIR_MODE {
        dir.file
            .set_permissions(Permissions::from_mode(DIR_MODE))
            .map_err(|error| Error::io(path, "change mode", error))?;
    }
    check_item(&dir.file, path, rule, Kind::Directory)
}

fn check_item(file: &File, path: &Utf8Path, rule: &Rule, kind: Kind) -> Result<()> {
    let step = match kind {
        Kind::Directory => "inspect directory",
        Kind::File => "inspect file",
    };
    let metadata = file.metadata().map_err(|error| Error::io(path, step, error))?;
    match kind {
        Kind::Directory if !metadata.is_dir() => return Err(Error::refused(path, Refusal::NotADirectory)),
        Kind::File if !metadata.is_file() => return Err(Error::refused(path, Refusal::NotAFile)),
        Kind::File if 1 < metadata.nlink() => return Err(Error::refused(path, Refusal::Link)),
        Kind::Directory | Kind::File => {}
    }
    os::check_volume(file, path)?;
    let euid = effective_uid();
    if !owner_allowed(rule, metadata.uid(), euid) {
        return Err(Error::refused(path, Refusal::Owner));
    }
    check_rule(path, rule, metadata.uid(), euid, kind)?;
    if metadata.mode() & GROUP_OTHER_BITS != 0 {
        return Err(Error::refused(path, Refusal::Access));
    }
    os::check_no_extended_acl(file, path, kind == Kind::Directory)
}

/// Fails when `rule` can't create an item: private-fs creates items owned by the current user.
fn check_creatable(path: &Utf8Path, rule: &Rule, kind: Kind) -> Result<()> {
    if !rule.owners.contains(&Account::CurrentUser) {
        return Err(Error::refused(path, Refusal::Owner));
    }
    let euid = effective_uid();
    check_rule(path, rule, euid, euid, kind)
}

/// Fails when this platform can't enforce a grant of `rule` on an item owned by `owner`, and the grant states no
/// usable fallback.
fn check_rule(path: &Utf8Path, rule: &Rule, owner: libc::uid_t, euid: libc::uid_t, kind: Kind) -> Result<()> {
    let mut owner_access = None;
    for grant in &rule.grants {
        let uid = account_uid(grant.account, euid);
        let Some(access) = effective_access(path, grant, uid, owner, kind)? else {
            continue;
        };
        if uid == owner {
            owner_access = Some(owner_access.map_or(access, |current| broader(current, access)));
        }
    }
    if owner == 0 || owner_access == Some(Access::Full) {
        return Ok(());
    }
    // The owner keeps full access whatever the rule gives it, which only an owner fallback to full access accepts.
    // An owner other than root is the current user, the only other account a rule can name here.
    match rule.owner_fallback {
        Some(Fallback::Access(Access::Full)) => Ok(()),
        Some(Fallback::Access(_) | Fallback::NoAccess) | None => Err(Error::unsupported(
            path,
            Account::CurrentUser,
            owner_access.unwrap_or(Access::Full),
        )),
    }
}

/// Returns the access `grant` gives on this platform, after its fallback, or `None` when it falls back to none.
fn effective_access(
    path: &Utf8Path,
    grant: &Grant,
    uid: libc::uid_t,
    owner: libc::uid_t,
    kind: Kind,
) -> Result<Option<Access>> {
    if supported(grant.access, uid, owner, kind) {
        return Ok(Some(grant.access));
    }
    match grant.fallback {
        None => Err(Error::unsupported(path, grant.account, grant.access)),
        Some(Fallback::NoAccess) => Ok(None),
        Some(Fallback::Access(access)) if supported(access, uid, owner, kind) => Ok(Some(access)),
        Some(Fallback::Access(access)) => Err(Error::unsupported(path, grant.account, access)),
    }
}

/// Reports whether this platform can give `uid` exactly `access` on an item owned by `owner`.
///
/// Root has every access, so a grant to root needs nothing on disk, and an owner always has full access.
fn supported(access: Access, uid: libc::uid_t, owner: libc::uid_t, kind: Kind) -> bool {
    if access == Access::AddOnly && kind == Kind::File {
        return false;
    }
    uid == 0 || (uid == owner && access == Access::Full)
}

fn broader(left: Access, right: Access) -> Access {
    let rank = |access| match access {
        Access::AddOnly => 0,
        Access::ReadWrite => 1,
        Access::Full => 2,
    };
    if rank(left) < rank(right) { right } else { left }
}

fn owner_allowed(rule: &Rule, owner: libc::uid_t, euid: libc::uid_t) -> bool {
    rule.owners.iter().any(|&account| account_uid(account, euid) == owner)
}

fn account_uid(account: Account, euid: libc::uid_t) -> libc::uid_t {
    match account {
        Account::CurrentUser => euid,
        Account::System | Account::Administrators => 0,
    }
}

fn effective_uid() -> libc::uid_t {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn access_flags(options: FileOptions) -> libc::c_int {
    match (options.read, options.write) {
        (true, true) => libc::O_RDWR,
        (false, true) => libc::O_WRONLY,
        (_, false) => libc::O_RDONLY,
    }
}

/// Opens the entry `name` of `parent` without following a link, and returns `None` when it doesn't exist.
fn open_at(parent: &Dir, path: &Utf8Path, name: &str, flags: libc::c_int, kind: Kind) -> Result<Option<File>> {
    let c_name = c_name(path, name)?;
    let flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY;
    // SAFETY: The parent descriptor is open, the name is NUL-terminated, and the flags don't include O_CREAT.
    let fd = unsafe { libc::openat(parent.file.as_raw_fd(), c_name.as_ptr(), flags) };
    if 0 <= fd {
        // SAFETY: openat returned a new descriptor that nothing else owns.
        return Ok(Some(File::from(unsafe { OwnedFd::from_raw_fd(fd) })));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        return Ok(None);
    }
    // A link, or an entry of the wrong type, fails the open in ways that differ between platforms and flags.
    let (refusal, step) = match kind {
        Kind::Directory => (Refusal::NotADirectory, "open directory"),
        Kind::File => (Refusal::NotAFile, "open file"),
    };
    Err(match stat_at(&parent.file, &c_name) {
        Ok(stat) => match (entry_kind(stat.st_mode), kind) {
            (EntryKind::Link, _) => Error::refused(path, Refusal::Link),
            (EntryKind::Directory, Kind::Directory) | (EntryKind::File, Kind::File) => Error::io(path, step, error),
            _ => Error::refused(path, refusal),
        },
        Err(_) => Error::io(path, step, error),
    })
}

/// Removes the entry `name` of `parent` if it is still `file`, after a creation whose check failed.
fn discard_entry(parent: &Dir, name: &CStr, file: &File, flags: libc::c_int) {
    let (Ok(created), Ok(current)) = (fstat(file), stat_at(&parent.file, name)) else {
        return;
    };
    if same_file(&created, &current) {
        // SAFETY: The descriptor is open and the name is NUL-terminated.
        let _ = unsafe { libc::unlinkat(parent.file.as_raw_fd(), name.as_ptr(), flags) };
    }
}

fn link_then_unlink(fd: libc::c_int, from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: The descriptor is open and both names are NUL-terminated.
    if unsafe { libc::linkat(fd, from.as_ptr(), fd, to.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The descriptor is open and the name is NUL-terminated.
    if unsafe { libc::unlinkat(fd, from.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn rename_exclusive_unsupported(code: libc::c_int) -> bool {
    code == libc::ENOSYS || code == libc::EINVAL || code == libc::EOPNOTSUPP || code == libc::ENOTSUP
}

fn stat_at(dir: &File, name: &CStr) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: The descriptor is open, the name is NUL-terminated and the output buffer is writable.
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat initialized the output buffer on success.
    Ok(unsafe { stat.assume_init() })
}

fn fstat(file: &File) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: The descriptor is open and the output buffer is writable.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat initialized the output buffer on success.
    Ok(unsafe { stat.assume_init() })
}

fn same_file(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn entry_kind(mode: libc::mode_t) -> EntryKind {
    match mode & libc::S_IFMT {
        libc::S_IFREG => EntryKind::File,
        libc::S_IFDIR => EntryKind::Directory,
        libc::S_IFLNK => EntryKind::Link,
        _ => EntryKind::Other,
    }
}

fn c_name(path: &Utf8Path, name: &str) -> Result<CString> {
    CString::new(name).map_err(|_| Error::io(path, "use entry name", io::ErrorKind::InvalidInput.into()))
}

fn parent_path(path: &Utf8Path) -> &Utf8Path {
    path.parent().unwrap_or(path)
}

struct DirStream(NonNull<libc::DIR>);

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: fdopendir returned this stream, and it is closed only here.
        let _ = unsafe { libc::closedir(self.0.as_ptr()) };
    }
}

#[cfg(test)]
impl Allowed {
    pub(crate) fn new_for_tests(current_user: Option<libc::uid_t>) -> Self {
        Self { current_user }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: libc::uid_t = 1000;

    fn check(rule: &Rule, owner: libc::uid_t, euid: libc::uid_t, kind: Kind) -> Result<()> {
        check_rule(Utf8Path::new("item"), rule, owner, euid, kind)
    }

    fn unsupported(result: Result<()>) -> Option<(Account, Access)> {
        match result.err()?.kind() {
            crate::ErrorKind::Unsupported { account, access } => Some((*account, *access)),
            _ => None,
        }
    }

    // A backend that let the owner keep less than full access, or chose a broader access than the rule, would leave
    // the owner, who can always change the mode, with access the rule withholds.
    // oracle: intent crates/private-fs/INTENT.md §rules
    #[test]
    fn a_grant_this_platform_cannot_enforce_needs_a_fallback() {
        let rule = Rule::new()
            .owner(Account::CurrentUser)
            .grant(Account::CurrentUser, Access::ReadWrite);
        assert_eq!(
            unsupported(check(&rule, USER, USER, Kind::Directory)),
            Some((Account::CurrentUser, Access::ReadWrite))
        );

        let rule = Rule::new().owner(Account::CurrentUser).grant_or(
            Account::CurrentUser,
            Access::ReadWrite,
            Fallback::Access(Access::Full),
        );
        assert!(check(&rule, USER, USER, Kind::Directory).is_ok());

        // A fallback is checked as the grant itself is.
        let rule = Rule::new().owner(Account::CurrentUser).grant_or(
            Account::CurrentUser,
            Access::ReadWrite,
            Fallback::Access(Access::AddOnly),
        );
        assert_eq!(
            unsupported(check(&rule, USER, USER, Kind::Directory)),
            Some((Account::CurrentUser, Access::AddOnly))
        );
    }

    // oracle: intent crates/private-fs/INTENT.md §rules
    #[test]
    fn an_owner_without_full_access_needs_an_owner_fallback() {
        let rule = Rule::new().owner(Account::CurrentUser).grant_or(
            Account::CurrentUser,
            Access::ReadWrite,
            Fallback::NoAccess,
        );
        assert_eq!(
            unsupported(check(&rule, USER, USER, Kind::Directory)),
            Some((Account::CurrentUser, Access::Full))
        );
        assert!(
            check(
                &rule.owner_fallback(Fallback::Access(Access::Full)),
                USER,
                USER,
                Kind::Directory
            )
            .is_ok()
        );

        let rule = Rule::new()
            .owner(Account::CurrentUser)
            .owner_fallback(Fallback::NoAccess);
        assert!(unsupported(check(&rule, USER, USER, Kind::Directory)).is_some());
    }

    // Root has every access whatever the mode says, so a rule may give root, or a root owner, any access.
    // oracle: intent crates/private-fs/INTENT.md §mechanisms
    #[test]
    fn grants_to_root_need_nothing_on_disk() {
        let rule = Rule::new()
            .owner(Account::System)
            .grant(Account::System, Access::ReadWrite)
            .grant(Account::Administrators, Access::AddOnly);
        assert!(check(&rule, 0, USER, Kind::Directory).is_ok());

        // Running as root, the current user is root.
        let rule = Rule::new()
            .owner(Account::CurrentUser)
            .grant(Account::CurrentUser, Access::ReadWrite);
        assert!(check(&rule, 0, 0, Kind::Directory).is_ok());
    }

    // An account other than root that doesn't own the item gets no access from mode 0700 or 0600.
    // oracle: intent crates/private-fs/INTENT.md §rules
    #[test]
    fn a_grant_to_a_user_who_does_not_own_the_item_is_unsupported() {
        let rule = Rule::new()
            .owner(Account::System)
            .owner(Account::CurrentUser)
            .grant(Account::CurrentUser, Access::Full);
        assert_eq!(
            unsupported(check(&rule, 0, USER, Kind::Directory)),
            Some((Account::CurrentUser, Access::Full))
        );

        let rule = Rule::new().owner(Account::System).owner(Account::CurrentUser).grant_or(
            Account::CurrentUser,
            Access::Full,
            Fallback::NoAccess,
        );
        assert!(check(&rule, 0, USER, Kind::Directory).is_ok());
    }

    // oracle: intent crates/private-fs/INTENT.md §rules
    #[test]
    fn add_only_access_to_a_file_is_unsupported_even_for_root() {
        let rule = Rule::new()
            .owner(Account::CurrentUser)
            .grant(Account::CurrentUser, Access::Full)
            .grant(Account::System, Access::AddOnly);
        assert_eq!(
            unsupported(check(&rule, USER, USER, Kind::File)),
            Some((Account::System, Access::AddOnly))
        );
        assert!(check(&rule, USER, USER, Kind::Directory).is_ok());
    }

    // oracle: intent crates/private-fs/INTENT.md §mechanisms
    #[test]
    fn only_root_and_the_accounts_a_rule_names_may_own_an_item() {
        let current_user_only = Rule::new().owner(Account::CurrentUser);
        assert!(owner_allowed(&current_user_only, USER, USER));
        assert!(!owner_allowed(&current_user_only, 0, USER));
        assert!(!owner_allowed(&current_user_only, USER + 1, USER));

        let system_only = Rule::new().owner(Account::System);
        assert!(owner_allowed(&system_only, 0, USER));
        assert!(!owner_allowed(&system_only, USER, USER));
    }

    // StrictModes: write access to a directory above lets an account rename or replace its entries, unless the sticky
    // bit limits it to adding entries and removing its own, or the account is root or in an administrators group.
    // oracle: intent crates/private-fs/INTENT.md §paths
    #[test]
    fn write_access_for_others_makes_a_directory_above_replaceable() {
        let acl = os::AncestorAcl::empty();
        let allowed = Allowed::new_for_tests(Some(USER));
        let staff = 20;
        assert!(replaceable(0o777, staff, &acl, &allowed));
        assert!(replaceable(0o775, staff, &acl, &allowed));
        assert!(replaceable(0o757, 0, &acl, &allowed));
        assert!(!replaceable(0o1777, staff, &acl, &allowed));
        assert!(!replaceable(0o775, 0, &acl, &allowed));
        assert!(!replaceable(0o755, staff, &acl, &allowed));
    }
}
