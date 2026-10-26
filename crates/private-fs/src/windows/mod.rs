//! Backend contract, implemented for Windows.
//!
//! Files and directories are opened and created with `NtCreateFile` relative to a directory handle, so no path is
//! resolved again below a checked directory, and created with a security descriptor holding the owner and the protected
//! DACL of their rule, so they have it from the moment they exist.

mod nt;
mod security;

use std::fs::{File, OpenOptions};
use std::io;
use std::marker::PhantomData;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::{AsHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle};

use camino::{Utf8Path, Utf8PathBuf};
use windows::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NTCREATEFILE_CREATE_OPTIONS,
};
use windows::Win32::Foundation::{ERROR_NO_TOKEN, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DACL_SECURITY_INFORMATION, DuplicateTokenEx, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    OWNER_SECURITY_INFORMATION, RevertToSelf, SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED, SecurityImpersonation,
    SetKernelObjectSecurity, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES,
    TOKEN_QUERY, TokenImpersonation,
};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_ACCESS_RIGHTS, FILE_ADD_FILE, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_MODE, FILE_SHARE_NONE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, READ_CONTROL, SYNCHRONIZE,
    WRITE_DAC, WRITE_OWNER,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
};

use self::nt::{Request, raw};
use self::security::{Descriptor, Kind, OwnerAndDacl, Policy, administrators_member};
use crate::{Entry, EntryKind, Error, Existing, FileOptions, Refusal, Replace, Result, Rule, Share};

/// The access to check an item: its attributes and its owner and DACL.
const CHECK_ACCESS: FILE_ACCESS_RIGHTS = FILE_ACCESS_RIGHTS(FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | SYNCHRONIZE.0);

/// The access a directory handle has: checking it, listing it and opening what it holds.
const DIRECTORY_ACCESS: FILE_ACCESS_RIGHTS =
    FILE_ACCESS_RIGHTS(CHECK_ACCESS.0 | FILE_LIST_DIRECTORY.0 | FILE_TRAVERSE.0);

/// The options of every open: never follow a reparse point, let the backup privilege apply, and give std a
/// synchronous handle.
const OPEN_OPTIONS: NTCREATEFILE_CREATE_OPTIONS = NTCREATEFILE_CREATE_OPTIONS(
    FILE_OPEN_REPARSE_POINT.0 | FILE_OPEN_FOR_BACKUP_INTENT.0 | FILE_SYNCHRONOUS_IO_NONALERT.0,
);

const SHARE_ALL: FILE_SHARE_MODE = FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0);

#[derive(Debug)]
pub(crate) struct Dir {
    handle: OwnedHandle,
}

impl Dir {
    fn handle(&self) -> BorrowedHandle<'_> {
        self.handle.as_handle()
    }
}

pub(crate) fn create_base(path: &Utf8Path, rule: &Rule) -> Result<Dir> {
    let policy = creation_policy(rule, Kind::Directory, path)?;
    let (existing, missing) = first_existing(path)?;
    let mut dir = open_first_existing(&existing, &policy)?;
    let mut current = existing;
    for name in missing {
        current.push(&name);
        dir = create_dir(&dir, &current, &name, rule, Existing::Check)?;
    }
    Ok(dir)
}

pub(crate) fn open_base(path: &Utf8Path, rule: &Rule) -> Result<Option<Dir>> {
    let policy = Policy::new(rule, Kind::Directory, path)?;
    let (existing, missing) = first_existing(path)?;
    let mut dir = open_first_existing(&existing, &policy)?;
    let mut current = existing;
    for name in missing {
        current.push(&name);
        validate_name(&current, &name)?;
        let Some(handle) = open_entry(
            dir.handle(),
            &current,
            &name,
            DIRECTORY_ACCESS,
            SHARE_ALL,
            "open directory",
        )?
        else {
            return Ok(None);
        };
        // Below the first existing directory, a directory is checked as the first one is, not against the rule.
        classify(handle.as_handle(), &current, Kind::Directory)?;
        let security = OwnerAndDacl::of_handle(handle.as_handle())
            .map_err(|error| Error::refused(&current, Refusal::Unreadable(error)))?;
        policy.check_ancestor(&security, &current, false, &administrators_member)?;
        dir = Dir { handle };
    }
    Ok(Some(dir))
}

pub(crate) fn create_dir(parent: &Dir, path: &Utf8Path, name: &str, rule: &Rule, existing: Existing) -> Result<Dir> {
    validate_name(path, name)?;
    let policy = creation_policy(rule, Kind::Directory, path)?;
    let descriptor = Descriptor::new(&policy.accounts.user, &policy.dacl(&policy.accounts.user))
        .map_err(|error| Error::io(path, "build security descriptor", error))?;
    let request = Request {
        // FILE_ADD_FILE lets the new directory's handle be flushed.
        access: FILE_ACCESS_RIGHTS(DIRECTORY_ACCESS.0 | FILE_ADD_FILE.0),
        share: SHARE_ALL,
        disposition: FILE_CREATE,
        options: NTCREATEFILE_CREATE_OPTIONS(OPEN_OPTIONS.0 | FILE_DIRECTORY_FILE.0),
        attributes: FILE_FLAGS_AND_ATTRIBUTES(0),
        descriptor: Some(descriptor.as_ref()),
    };
    match nt::create(parent.handle(), name, &request) {
        Ok(handle) => {
            check_item(handle.as_handle(), path, Kind::Directory, &policy)?;
            // UNTESTED: once this returns, a power cut leaves the new directory's entry in its parent.
            // No test can cut the power; NTFS logs the entry's creation, and flushing the new directory commits the
            // log up to it.
            // When changing this, keep a flush of a handle on the new directory after its creation.
            nt::flush(handle.as_handle()).map_err(|error| Error::io(path, "flush directory", error))?;
            Ok(Dir { handle })
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let handle = open_entry(
                parent.handle(),
                path,
                name,
                DIRECTORY_ACCESS,
                SHARE_ALL,
                "open directory",
            )?
            .ok_or_else(|| Error::io(path, "open directory", io::Error::from(io::ErrorKind::NotFound)))?;
            let dir = Dir { handle };
            match existing {
                Existing::Check => check_dir(&dir, path, rule)?,
                Existing::Repair => repair_dir(&dir, path, rule)?,
            }
            Ok(dir)
        }
        Err(error) => Err(Error::io(path, "create directory", error)),
    }
}

pub(crate) fn open_dir(parent: &Dir, path: &Utf8Path, name: &str, rule: &Rule, share: Share) -> Result<Option<Dir>> {
    validate_name(path, name)?;
    let policy = Policy::new(rule, Kind::Directory, path)?;
    let Some(handle) = open_entry(
        parent.handle(),
        path,
        name,
        DIRECTORY_ACCESS,
        share_mode(share),
        "open directory",
    )?
    else {
        return Ok(None);
    };
    check_item(handle.as_handle(), path, Kind::Directory, &policy)?;
    Ok(Some(Dir { handle }))
}

pub(crate) fn open_file(
    parent: &Dir,
    path: &Utf8Path,
    name: &str,
    rule: &Rule,
    options: FileOptions,
) -> Result<Option<File>> {
    validate_name(path, name)?;
    let policy = Policy::new(rule, Kind::File, path)?;
    let Some(handle) = open_entry(
        parent.handle(),
        path,
        name,
        file_access(options),
        share_mode(options.share),
        "open file",
    )?
    else {
        return Ok(None);
    };
    check_item(handle.as_handle(), path, Kind::File, &policy)?;
    Ok(Some(File::from(handle)))
}

pub(crate) fn create_file(
    parent: &Dir,
    path: &Utf8Path,
    name: &str,
    rule: &Rule,
    options: FileOptions,
) -> Result<File> {
    validate_name(path, name)?;
    let policy = creation_policy(rule, Kind::File, path)?;
    let descriptor = Descriptor::new(&policy.accounts.user, &policy.dacl(&policy.accounts.user))
        .map_err(|error| Error::io(path, "build security descriptor", error))?;
    let request = Request {
        // DELETE lets `persist` rename the file through this handle.
        access: FILE_ACCESS_RIGHTS(file_access(options).0 | DELETE.0 | SYNCHRONIZE.0),
        share: share_mode(options.share),
        disposition: FILE_CREATE,
        options: NTCREATEFILE_CREATE_OPTIONS(
            FILE_NON_DIRECTORY_FILE.0 | FILE_OPEN_REPARSE_POINT.0 | FILE_SYNCHRONOUS_IO_NONALERT.0,
        ),
        attributes: FILE_ATTRIBUTE_NORMAL,
        descriptor: Some(descriptor.as_ref()),
    };
    let handle = nt::create(parent.handle(), name, &request).map_err(|error| Error::io(path, "create file", error))?;
    if let Err(error) = check_item(handle.as_handle(), path, Kind::File, &policy) {
        // A file that fails its rule, as on a volume that drops DACLs, is not left behind.
        let _ = nt::delete_on_close(handle.as_handle());
        return Err(error);
    }
    Ok(File::from(handle))
}

pub(crate) fn rename(parent: &Dir, path: &Utf8Path, from: &str, to: &str, replace: Replace) -> Result<()> {
    validate_name(path, from)?;
    validate_name(path, to)?;
    let source = open_entry(
        parent.handle(),
        path,
        from,
        FILE_ACCESS_RIGHTS(DELETE.0 | SYNCHRONIZE.0),
        SHARE_ALL,
        "open entry",
    )?
    .ok_or_else(|| Error::io(path, "open entry", io::Error::from(io::ErrorKind::NotFound)))?;
    nt::rename(source.as_handle(), parent.handle(), to, replace == Replace::Allow)
        .map_err(|error| Error::io(path, "rename entry", error))
}

pub(crate) fn persist(
    parent: &Dir,
    path: &Utf8Path,
    file: &File,
    from: &str,
    to: &str,
    replace: Replace,
) -> Result<()> {
    validate_name(path, from)?;
    validate_name(path, to)?;
    file.sync_all().map_err(|error| Error::io(path, "sync file", error))?;
    nt::rename(file.as_handle(), parent.handle(), to, replace == Replace::Allow)
        .map_err(|error| Error::io(path, "rename file", error))?;
    // UNTESTED: once this returns, a power cut leaves `to` with the file's content.
    // No test can cut the power; Windows has no directory fsync, but NTFS logs the rename, and flushing the renamed
    // file commits the log up to that record.
    // When changing this, keep the flush of the file after the rename.
    nt::flush(file.as_handle()).map_err(|error| Error::io(path, "flush file", error))
}

pub(crate) fn remove_file(parent: &Dir, path: &Utf8Path, name: &str) -> Result<bool> {
    validate_name(path, name)?;
    let request = Request {
        access: FILE_ACCESS_RIGHTS(DELETE.0 | SYNCHRONIZE.0),
        share: SHARE_ALL,
        disposition: FILE_OPEN,
        options: NTCREATEFILE_CREATE_OPTIONS(
            FILE_NON_DIRECTORY_FILE.0 | FILE_OPEN_REPARSE_POINT.0 | FILE_SYNCHRONOUS_IO_NONALERT.0,
        ),
        attributes: FILE_FLAGS_AND_ATTRIBUTES(0),
        descriptor: None,
    };
    let handle = match nt::create(parent.handle(), name, &request) {
        Ok(handle) => handle,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(Error::io(path, "open file", error)),
    };
    nt::delete_on_close(handle.as_handle()).map_err(|error| Error::io(path, "remove file", error))?;
    Ok(true)
}

/// Removes `file`, which this directory's handle created as `name`, through the file's own handle.
#[expect(dead_code, reason = "lib.rs exposes it as Dir::discard")]
pub(crate) fn discard(_parent: &Dir, path: &Utf8Path, file: &File, _name: &str) -> Result<()> {
    nt::delete_on_close(file.as_handle()).map_err(|error| Error::io(path, "remove file", error))
}

pub(crate) fn entries(dir: &Dir, path: &Utf8Path) -> Result<Vec<Entry>> {
    let listed = nt::list(dir.handle()).map_err(|error| Error::io(path, "list directory", error))?;
    Ok(listed
        .into_iter()
        .map(|(name, attributes)| Entry {
            name,
            kind: if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                EntryKind::Link
            } else if attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
                EntryKind::Directory
            } else if attributes & FILE_ATTRIBUTE_DEVICE.0 != 0 {
                EntryKind::Other
            } else {
                EntryKind::File
            },
        })
        .collect())
}

/// Windows has no directory fsync: [`create_dir`] and [`persist`] flush what they change.
pub(crate) fn sync(_dir: &Dir, _path: &Utf8Path) -> Result<()> {
    Ok(())
}

pub(crate) fn check_dir(dir: &Dir, path: &Utf8Path, rule: &Rule) -> Result<()> {
    let policy = Policy::new(rule, Kind::Directory, path)?;
    check_item(dir.handle(), path, Kind::Directory, &policy)
}

pub(crate) fn repair_dir(dir: &Dir, path: &Utf8Path, rule: &Rule) -> Result<()> {
    let policy = Policy::new(rule, Kind::Directory, path)?;
    classify(dir.handle(), path, Kind::Directory)?;
    let security =
        OwnerAndDacl::of_handle(dir.handle()).map_err(|error| Error::io(path, "read access control list", error))?;
    let current_owner = security.owner();
    let owner_allowed = match current_owner {
        Some(owner) => policy.owner_allowed(owner, path, &administrators_member)?,
        None => false,
    };
    let owner = match current_owner {
        Some(owner) if owner_allowed => owner.clone(),
        // The repair would make the current user the owner, which the rule must then allow.
        _ if policy.allows_user_owner() => policy.accounts.user.clone(),
        _ => return Err(Error::refused(path, Refusal::Owner)),
    };
    let descriptor = Descriptor::new(&owner, &policy.dacl(&owner))
        .map_err(|error| Error::io(path, "build security descriptor", error))?;
    let mut access = READ_CONTROL.0 | WRITE_DAC.0 | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0;
    let mut information = DACL_SECURITY_INFORMATION;
    if !owner_allowed {
        access |= WRITE_OWNER.0;
        information |= OWNER_SECURITY_INFORMATION;
    }
    // An empty name relative to a handle opens the object that handle refers to.
    let request = Request {
        access: FILE_ACCESS_RIGHTS(access),
        share: SHARE_ALL,
        disposition: FILE_OPEN,
        options: OPEN_OPTIONS,
        attributes: FILE_FLAGS_AND_ATTRIBUTES(0),
        descriptor: None,
    };
    let reopened =
        nt::create(dir.handle(), "", &request).map_err(|error| Error::io(path, "open directory for repair", error))?;
    let original = nt::file_id(dir.handle()).map_err(|error| Error::io(path, "read file ID", error))?;
    let current = nt::file_id(reopened.as_handle()).map_err(|error| Error::io(path, "read file ID", error))?;
    if original != current {
        return Err(Error::io(
            path,
            "open directory for repair",
            io::Error::other("the directory was replaced while reopening it"),
        ));
    }
    // Unlike SetSecurityInfo, SetKernelObjectSecurity doesn't propagate inheritable entries to existing children, so a
    // repair never changes what lies below the directory.
    // SAFETY: The handle is open and the descriptor stays live for the call.
    unsafe { SetKernelObjectSecurity(raw(reopened.as_handle()), information, descriptor.as_raw()) }
        .map_err(|error| Error::io(path, "set access control list", nt::win32_error(error)))?;
    check_item(dir.handle(), path, Kind::Directory, &policy.exact())
}

pub(crate) fn check_file(file: &File, path: &Utf8Path, rule: &Rule) -> Result<()> {
    let policy = Policy::new(rule, Kind::File, path)?;
    check_item(file.as_handle(), path, Kind::File, &policy)
}

/// Enables the backup privilege for the current thread until dropped, so that private-fs can read the owner and access
/// of directories the process token cannot read otherwise.
///
/// The current thread impersonates a copy of the process token with the privilege enabled, and goes back to its earlier
/// token when this is dropped, so it is tied to the thread that enabled it.
#[derive(Debug)]
pub struct BackupPrivilege {
    /// The thread's token before this one, which it impersonates again on drop.
    previous: Option<OwnedHandle>,
    _token: OwnedHandle,
    /// Impersonation is a property of the thread, so this stays on the thread that created it.
    _thread: PhantomData<*const ()>,
}

impl BackupPrivilege {
    pub fn enable() -> Result<Self> {
        let path = Utf8Path::new("");
        let error = |step, error| Error::io(path, step, nt::win32_error(error));
        // SAFETY: Getting the pseudo-handle of the current thread has no preconditions.
        let thread = unsafe { GetCurrentThread() };
        let mut previous = HANDLE::default();
        // SAFETY: The pseudo-handle of the current thread is always valid and the output is writable.
        let previous = match unsafe { OpenThreadToken(thread, TOKEN_IMPERSONATE, true, &raw mut previous) } {
            // SAFETY: OpenThreadToken succeeded, so the handle is open and nothing else owns it.
            Ok(()) => Some(unsafe { OwnedHandle::from_raw_handle(previous.0) }),
            Err(cause) if cause.code() == ERROR_NO_TOKEN.to_hresult() => None,
            Err(cause) => return Err(error("open thread token", cause)),
        };
        // SAFETY: Getting the pseudo-handle of the current process has no preconditions.
        let current_process = unsafe { GetCurrentProcess() };
        let mut process = HANDLE::default();
        // SAFETY: The pseudo-handle of the current process is always valid and the output is writable.
        unsafe { OpenProcessToken(current_process, TOKEN_DUPLICATE | TOKEN_QUERY, &raw mut process) }
            .map_err(|cause| error("open process token", cause))?;
        // SAFETY: OpenProcessToken succeeded, so the handle is open and nothing else owns it.
        let process = unsafe { OwnedHandle::from_raw_handle(process.0) };
        let mut token = HANDLE::default();
        // SAFETY: The process token is open with TOKEN_DUPLICATE and the output is writable.
        unsafe {
            DuplicateTokenEx(
                raw(process.as_handle()),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_IMPERSONATE,
                None,
                SecurityImpersonation,
                TokenImpersonation,
                &raw mut token,
            )
        }
        .map_err(|cause| error("duplicate process token", cause))?;
        // SAFETY: DuplicateTokenEx succeeded, so the handle is open and nothing else owns it.
        let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
        let mut luid = LUID::default();
        // SAFETY: The privilege name is a NUL-terminated constant and the output is writable.
        unsafe { LookupPrivilegeValueW(None, SE_BACKUP_NAME, &raw mut luid) }
            .map_err(|cause| error("look up backup privilege", cause))?;
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        // SAFETY: The token is open with TOKEN_ADJUST_PRIVILEGES and the new state stays live for the call.
        unsafe {
            AdjustTokenPrivileges(
                raw(token.as_handle()),
                false,
                Some(&raw const privileges),
                0,
                None,
                None,
            )
        }
        .map_err(|cause| error("enable backup privilege", cause))?;
        // AdjustTokenPrivileges succeeds without enabling a privilege the token doesn't hold, and says so in the last
        // error.
        let last = io::Error::last_os_error();
        if last.raw_os_error() == Some(ERROR_NOT_ALL_ASSIGNED.0.cast_signed()) {
            return Err(Error::io(path, "enable backup privilege", last));
        }
        // SAFETY: The token is an impersonation token open with TOKEN_IMPERSONATE.
        unsafe { SetThreadToken(None, Some(raw(token.as_handle()))) }
            .map_err(|cause| error("impersonate backup token", cause))?;
        Ok(Self {
            previous,
            _token: token,
            _thread: PhantomData,
        })
    }
}

impl Drop for BackupPrivilege {
    fn drop(&mut self) {
        // A failure leaves the thread with the backup privilege, and there is no caller to report it to.
        match &self.previous {
            Some(previous) => {
                // SAFETY: The earlier token is open with TOKEN_IMPERSONATE.
                let _ = unsafe { SetThreadToken(None, Some(raw(previous.as_handle()))) };
            }
            None => {
                // SAFETY: Reverting the current thread to the process token has no preconditions.
                let _ = unsafe { RevertToSelf() };
            }
        }
    }
}

/// Maps a rule for creating a directory or file: the rule must allow the current user to own it, since creation makes
/// the current user the owner.
fn creation_policy(rule: &Rule, kind: Kind, path: &Utf8Path) -> Result<Policy> {
    let policy = Policy::new(rule, kind, path)?;
    if !policy.allows_user_owner() {
        return Err(Error::io(
            path,
            "use rule",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the rule doesn't allow the current user to own what it creates",
            ),
        ));
    }
    Ok(policy)
}

fn validate_name(path: &Utf8Path, name: &str) -> Result<()> {
    // A colon names an alternate data stream of a file, not an entry of the directory.
    if name.contains(':') {
        return Err(Error::io(
            path,
            "use entry name",
            io::Error::from(io::ErrorKind::InvalidInput),
        ));
    }
    Ok(())
}

fn share_mode(share: Share) -> FILE_SHARE_MODE {
    match share {
        Share::Shared => SHARE_ALL,
        Share::Exclusive => FILE_SHARE_NONE,
    }
}

fn file_access(options: FileOptions) -> FILE_ACCESS_RIGHTS {
    let mut access = CHECK_ACCESS.0;
    if options.read {
        access |= FILE_GENERIC_READ.0;
    }
    if options.write {
        access |= FILE_GENERIC_WRITE.0;
    }
    FILE_ACCESS_RIGHTS(access)
}

/// Opens the existing entry `name` of `parent` without following a reparse point, or returns `None` when it doesn't
/// exist.
fn open_entry(
    parent: BorrowedHandle<'_>,
    path: &Utf8Path,
    name: &str,
    access: FILE_ACCESS_RIGHTS,
    share: FILE_SHARE_MODE,
    step: &'static str,
) -> Result<Option<OwnedHandle>> {
    let request = Request {
        access,
        share,
        disposition: FILE_OPEN,
        // Neither FILE_DIRECTORY_FILE nor FILE_NON_DIRECTORY_FILE, so that an entry of the wrong type opens and is
        // refused by type rather than failing to open.
        options: OPEN_OPTIONS,
        attributes: FILE_FLAGS_AND_ATTRIBUTES(0),
        descriptor: None,
    };
    match nt::create(parent, name, &request) {
        Ok(handle) => Ok(Some(handle)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::io(path, step, error)),
    }
}

/// Refuses an item that is a link, isn't of `kind`, or is on a volume that doesn't enforce ACLs.
fn classify(handle: BorrowedHandle<'_>, path: &Utf8Path, kind: Kind) -> Result<()> {
    let attributes = nt::attributes(handle).map_err(|error| Error::io(path, "read attributes", error))?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(Error::refused(path, Refusal::Link));
    }
    let is_directory = attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
    match kind {
        Kind::Directory if !is_directory => return Err(Error::refused(path, Refusal::NotADirectory)),
        Kind::File if is_directory || attributes & FILE_ATTRIBUTE_DEVICE.0 != 0 => {
            return Err(Error::refused(path, Refusal::NotAFile));
        }
        Kind::File => {
            let links = nt::link_count(handle).map_err(|error| Error::io(path, "read link count", error))?;
            if 1 < links {
                return Err(Error::refused(path, Refusal::Link));
            }
        }
        Kind::Directory => {}
    }
    if !nt::persistent_acls(handle).map_err(|error| Error::io(path, "read volume information", error))? {
        return Err(Error::refused(path, Refusal::Volume));
    }
    Ok(())
}

/// Checks an item's type, link status, volume, owner and DACL against `policy`.
fn check_item(handle: BorrowedHandle<'_>, path: &Utf8Path, kind: Kind, policy: &Policy) -> Result<()> {
    classify(handle, path, kind)?;
    let security =
        OwnerAndDacl::of_handle(handle).map_err(|error| Error::io(path, "read access control list", error))?;
    policy.check(&security, path, &administrators_member)
}

/// Finds the first existing directory of `path`, walking up without following a link, and returns it with the names
/// below it that don't exist, from the top down.
fn first_existing(path: &Utf8Path) -> Result<(Utf8PathBuf, Vec<String>)> {
    let mut candidate = path.to_owned();
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                    return Err(Error::refused(&candidate, Refusal::Link));
                }
                if !metadata.is_dir() {
                    return Err(Error::refused(&candidate, Refusal::NotADirectory));
                }
                missing.reverse();
                return Ok((candidate, missing));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // Only a plain name can be created; `..` or a prefix that doesn't exist cannot.
                let Some(name) = candidate.file_name() else {
                    return Err(Error::io(&candidate, "inspect directory", error));
                };
                missing.push(name.to_owned());
                candidate = match candidate.parent() {
                    Some(parent) if !parent.as_str().is_empty() => parent.to_owned(),
                    Some(_) => Utf8PathBuf::from("."),
                    None => return Err(Error::io(&candidate, "inspect directory", error)),
                };
            }
            Err(error) => return Err(Error::io(&candidate, "inspect directory", error)),
        }
    }
}

/// Opens the first existing directory of a base path without following a link, and checks it and every directory above
/// it on its resolved path.
fn open_first_existing(path: &Utf8Path, policy: &Policy) -> Result<Dir> {
    let handle = open_path(path, DIRECTORY_ACCESS).map_err(|error| Error::io(path, "open directory", error))?;
    // The directory may have been replaced since it was inspected by path.
    classify(handle.as_handle(), path, Kind::Directory)?;
    let resolved =
        nt::final_path(handle.as_handle()).map_err(|error| Error::io(path, "resolve directory path", error))?;
    let resolved = Utf8PathBuf::from(resolved);
    let security = OwnerAndDacl::of_handle(handle.as_handle())
        .map_err(|error| Error::refused(path, Refusal::Unreadable(error)))?;
    policy.check_ancestor(&security, path, resolved.parent().is_none(), &administrators_member)?;
    let mut above = resolved.parent();
    while let Some(directory) = above {
        check_above(directory, policy)?;
        above = directory.parent();
    }
    Ok(Dir { handle })
}

/// Checks a directory above the first existing one, at its resolved path.
fn check_above(path: &Utf8Path, policy: &Policy) -> Result<()> {
    let unreadable = |error| Error::refused(path, Refusal::Unreadable(error));
    let handle = open_path(path, CHECK_ACCESS).map_err(unreadable)?;
    let attributes = nt::attributes(handle.as_handle()).map_err(unreadable)?;
    // The path was resolved through every link, so a link on it now was put there since.
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 || attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
        return Err(Error::refused(path, Refusal::Replaceable));
    }
    let security = OwnerAndDacl::of_handle(handle.as_handle()).map_err(unreadable)?;
    policy.check_ancestor(&security, path, path.parent().is_none(), &administrators_member)
}

/// Opens a directory by path without following a reparse point.
fn open_path(path: &Utf8Path, access: FILE_ACCESS_RIGHTS) -> io::Result<OwnedHandle> {
    let file = OpenOptions::new()
        .access_mode(access.0)
        .share_mode(SHARE_ALL.0)
        // FILE_FLAG_BACKUP_SEMANTICS opens a directory, and asks for backup intent so the backup privilege applies.
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)?;
    Ok(OwnedHandle::from(file))
}
