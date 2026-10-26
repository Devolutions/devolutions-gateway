//! Backend contract, implemented for Windows.
//!
//! Files and directories are opened and created with `NtCreateFile` relative to a directory handle, so no path is
//! resolved again below a checked directory, and created with a security descriptor holding the owner and the protected
//! DACL of their rule, so they have it from the moment they exist.

mod nt;
mod security;

use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io;
use std::marker::PhantomData;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::{AsHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle};
use std::sync::{Mutex, PoisonError};

use camino::{Utf8Path, Utf8PathBuf};
use windows::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NTCREATEFILE_CREATE_OPTIONS,
};
use windows::Win32::Foundation::{ERROR_DIRECTORY, ERROR_NO_TOKEN, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID};
use windows::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DACL_SECURITY_INFORMATION, DuplicateTokenEx, GetTokenInformation, LUID_AND_ATTRIBUTES,
    LookupPrivilegeValueW, OWNER_SECURITY_INFORMATION, RevertToSelf, SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED,
    SecurityImpersonation, SetKernelObjectSecurity, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_STATISTICS, TokenImpersonation, TokenStatistics,
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

/// The options of an open for a repair: as [`OPEN_OPTIONS`], but asynchronous, so the open doesn't need SYNCHRONIZE,
/// which an owner's implicit access doesn't include.
const REPAIR_OPTIONS: NTCREATEFILE_CREATE_OPTIONS =
    NTCREATEFILE_CREATE_OPTIONS(FILE_OPEN_REPARSE_POINT.0 | FILE_OPEN_FOR_BACKUP_INTENT.0);

/// The access a repair opens with: what it reads and writes, all within an owner's implicit READ_CONTROL and WRITE_DAC,
/// and FILE_READ_ATTRIBUTES, which a directory's parent grants with FILE_LIST_DIRECTORY.
const REPAIR_ACCESS: FILE_ACCESS_RIGHTS = FILE_ACCESS_RIGHTS(READ_CONTROL.0 | WRITE_DAC.0 | FILE_READ_ATTRIBUTES.0);

const SHARE_ALL: FILE_SHARE_MODE = FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0);

#[derive(Debug)]
pub(crate) struct Dir {
    handle: OwnedHandle,
    /// Whether the handle has FILE_ADD_FILE, the write access a flush of a directory needs.
    flushable: bool,
    /// Serializes listings, which move the handle's one enumeration cursor.
    listing: Mutex<()>,
}

impl Dir {
    fn new(handle: OwnedHandle, flushable: bool) -> Self {
        Self {
            handle,
            flushable,
            listing: Mutex::new(()),
        }
    }

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
        dir = Dir::new(handle, false);
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
        // Not DELETE, which would make every open of the directory that doesn't share deletion fail while it lives.
        access: FILE_ACCESS_RIGHTS(DIRECTORY_ACCESS.0 | FILE_ADD_FILE.0),
        share: SHARE_ALL,
        disposition: FILE_CREATE,
        options: NTCREATEFILE_CREATE_OPTIONS(OPEN_OPTIONS.0 | FILE_DIRECTORY_FILE.0),
        attributes: FILE_FLAGS_AND_ATTRIBUTES(0),
        descriptor: Some(descriptor.as_ref()),
    };
    match nt::create(parent.handle(), name, &request) {
        Ok(handle) => {
            if let Err(error) = check_item(handle.as_handle(), path, Kind::Directory, &policy) {
                // A directory that fails its rule, as on a volume that drops DACLs, is removed where the rule it got
                // lets the current user delete it; otherwise it is left behind, empty, and the error still reported.
                // UNTESTED: a new directory that fails its rule is removed.
                // Tests run on NTFS, where a new directory always has its rule; a FAT volume, which drops DACLs, would
                // show it.
                // When changing this, keep the removal best effort, so that the check's error is the one reported.
                if let Ok(deleting) = reopen(handle.as_handle(), FILE_ACCESS_RIGHTS(DELETE.0 | SYNCHRONIZE.0)) {
                    let _ = nt::delete(deleting.as_handle());
                }
                return Err(error);
            }
            // UNTESTED: once this returns, a power cut leaves the new directory's entry in its parent.
            // No test can cut the power; NTFS logs the entry's creation, and flushing the new directory commits the
            // log up to it.
            // When changing this, keep a flush of a handle on the new directory after its creation.
            nt::flush(handle.as_handle()).map_err(|error| Error::io(path, "flush directory", error))?;
            Ok(Dir::new(handle, true))
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => match existing {
            Existing::Check => {
                let handle = open_entry(
                    parent.handle(),
                    path,
                    name,
                    DIRECTORY_ACCESS,
                    SHARE_ALL,
                    "open directory",
                )?
                .ok_or_else(|| Error::io(path, "open directory", io::Error::from(io::ErrorKind::NotFound)))?;
                let dir = Dir::new(handle, false);
                check_dir(&dir, path, rule)?;
                Ok(dir)
            }
            Existing::Repair => {
                // A directory whose DACL no longer grants the current user anything is still repairable by its owner,
                // so it is opened with the repair's access only, and opened normally once repaired.
                let request = Request {
                    access: REPAIR_ACCESS,
                    share: SHARE_ALL,
                    disposition: FILE_OPEN,
                    options: REPAIR_OPTIONS,
                    attributes: FILE_FLAGS_AND_ATTRIBUTES(0),
                    descriptor: None,
                };
                let repairing = nt::create(parent.handle(), name, &request)
                    .map_err(|error| Error::io(path, "open directory for repair", error))?;
                let policy = Policy::new(rule, Kind::Directory, path)?;
                repair(repairing.as_handle(), path, Kind::Directory, &policy)?;
                let handle = reopen(repairing.as_handle(), DIRECTORY_ACCESS)
                    .map_err(|error| Error::io(path, "open directory", error))?;
                check_item(handle.as_handle(), path, Kind::Directory, &policy.exact())?;
                Ok(Dir::new(handle, false))
            }
        },
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
    Ok(Some(Dir::new(handle, false)))
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
        let _ = nt::delete(handle.as_handle());
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
    nt::delete(handle.as_handle()).map_err(|error| Error::io(path, "remove file", error))?;
    Ok(true)
}

/// Removes `file` while it is still the entry `name` of this directory, through the file's own handle, and does
/// nothing once it has been renamed, as by a persist whose flush failed after its rename.
///
/// The file's own handle deletes it because an account that may only add to the directory has no access by name.
pub(crate) fn discard(parent: &Dir, path: &Utf8Path, file: &File, name: &str) -> Result<()> {
    validate_name(path, name)?;
    let directory = nt::final_path(parent.handle()).map_err(|error| Error::io(path, "read directory path", error))?;
    let current = nt::final_path(file.as_handle()).map_err(|error| Error::io(path, "read file path", error))?;
    let separator = if directory.ends_with('\\') { "" } else { "\\" };
    let expected = format!("{directory}{separator}{name}");
    if !same_name(&current, &expected) {
        return Ok(());
    }
    nt::delete(file.as_handle()).map_err(|error| Error::io(path, "remove file", error))
}

/// Reports whether two names are the same file name, ignoring case as NTFS does: with the simple, one-to-one upcase
/// table, under which `ß` and `SS` differ, unlike Unicode's full case mapping.
fn same_name(left: &str, right: &str) -> bool {
    let left: Vec<u16> = left.encode_utf16().collect();
    let right: Vec<u16> = right.encode_utf16().collect();
    // SAFETY: CompareStringOrdinal only reads both slices for their lengths.
    let compared = unsafe { CompareStringOrdinal(&left, &right, true) };
    compared == CSTR_EQUAL
}

pub(crate) fn entries(dir: &Dir, path: &Utf8Path) -> Result<Vec<Entry>> {
    let listed = {
        // A listing restarts and moves the handle's one enumeration cursor, so listings take turns.
        // UNTESTED: concurrent listings of one directory each return every entry.
        // A test racing two threads would pass whether or not they overlap, so it couldn't catch a missing lock; when
        // changing this, keep every listing through this handle under the lock, from the restart to the last entry.
        let _listing = dir.listing.lock().unwrap_or_else(PoisonError::into_inner);
        nt::list(dir.handle()).map_err(|error| Error::io(path, "list directory", error))?
    };
    Ok(listed
        .into_iter()
        .map(|(name, attributes, tag)| Entry {
            name,
            kind: entry_kind(attributes, tag),
        })
        .collect())
}

/// Returns the kind of a listed entry: a reparse point that stands for another name is a link, and any other reparse
/// point is neither a plain file nor a plain directory.
fn entry_kind(attributes: u32, tag: u32) -> EntryKind {
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        if nt::is_name_surrogate(tag) {
            EntryKind::Link
        } else {
            EntryKind::Other
        }
    } else if attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        EntryKind::Directory
    } else if attributes & FILE_ATTRIBUTE_DEVICE.0 != 0 {
        EntryKind::Other
    } else {
        EntryKind::File
    }
}

pub(crate) fn sync(dir: &Dir, path: &Utf8Path) -> Result<()> {
    // FlushFileBuffers needs write access, which on a directory is FILE_ADD_FILE.
    // A directory this handle didn't create is opened again with it, which fails when the directory is open
    // exclusively or the rule doesn't give the current user that access.
    let reopened;
    let flushing = if dir.flushable {
        dir.handle()
    } else {
        reopened = reopen(dir.handle(), FILE_ACCESS_RIGHTS(FILE_ADD_FILE.0 | SYNCHRONIZE.0))
            .map_err(|error| Error::io(path, "open directory", error))?;
        reopened.as_handle()
    };
    // UNTESTED: once this returns, a power cut leaves the entries created, renamed and removed in the directory.
    // No test can cut the power; Windows has no directory fsync, but NTFS logs every change of an entry, and flushing a
    // handle on the directory commits the log up to the last change.
    // When changing this, keep a flush of a handle on the directory itself.
    nt::flush(flushing).map_err(|error| Error::io(path, "flush directory", error))
}

pub(crate) fn check_dir(dir: &Dir, path: &Utf8Path, rule: &Rule) -> Result<()> {
    let policy = Policy::new(rule, Kind::Directory, path)?;
    check_item(dir.handle(), path, Kind::Directory, &policy)
}

pub(crate) fn repair_dir(dir: &Dir, path: &Utf8Path, rule: &Rule) -> Result<()> {
    let policy = Policy::new(rule, Kind::Directory, path)?;
    repair(dir.handle(), path, Kind::Directory, &policy)?;
    check_item(dir.handle(), path, Kind::Directory, &policy.exact())
}

/// Brings an open file's owner and DACL into line with `rule`, then checks it exactly.
pub(crate) fn repair_file(file: &File, path: &Utf8Path, rule: &Rule) -> Result<()> {
    let policy = Policy::new(rule, Kind::File, path)?;
    repair(file.as_handle(), path, Kind::File, &policy)?;
    check_item(file.as_handle(), path, Kind::File, &policy.exact())
}

/// Brings the owner and DACL of the item `handle` refers to into line with `policy`, through a handle opened again
/// with the repair's access only, without checking the result.
fn repair(handle: BorrowedHandle<'_>, path: &Utf8Path, kind: Kind, policy: &Policy) -> Result<()> {
    classify(handle, path, kind)?;
    let security =
        OwnerAndDacl::of_handle(handle).map_err(|error| Error::io(path, "read access control list", error))?;
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
    let mut access = REPAIR_ACCESS.0;
    let mut information = DACL_SECURITY_INFORMATION;
    if !owner_allowed {
        access |= WRITE_OWNER.0;
        information |= OWNER_SECURITY_INFORMATION;
    }
    let request = Request {
        access: FILE_ACCESS_RIGHTS(access),
        share: SHARE_ALL,
        disposition: FILE_OPEN,
        options: REPAIR_OPTIONS,
        attributes: FILE_FLAGS_AND_ATTRIBUTES(0),
        descriptor: None,
    };
    // An empty name relative to a handle names its object.
    let reopened = nt::create(handle, "", &request).map_err(|error| Error::io(path, "open for repair", error))?;
    let original = nt::file_id(handle).map_err(|error| Error::io(path, "read file ID", error))?;
    let current = nt::file_id(reopened.as_handle()).map_err(|error| Error::io(path, "read file ID", error))?;
    if original != current {
        return Err(Error::io(
            path,
            "open for repair",
            io::Error::other("the item was replaced while reopening it"),
        ));
    }
    // Unlike SetSecurityInfo, SetKernelObjectSecurity doesn't propagate inheritable entries to existing children, so a
    // repair never changes what lies below a directory.
    // SAFETY: The handle is open and the descriptor stays live for the call.
    unsafe { SetKernelObjectSecurity(raw(reopened.as_handle()), information, descriptor.as_raw()) }
        .map_err(|error| Error::io(path, "set access control list", nt::win32_error(error)))
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
/// A thread holds at most one at a time.
#[derive(Debug)]
pub struct BackupPrivilege {
    /// The thread's token before this one, which it impersonates again on drop.
    previous: Option<OwnedHandle>,
    /// The ID of the token this sets on the thread, so that a drop restores the earlier token only over it.
    token_id: LUID,
    _token: OwnedHandle,
    /// Impersonation is a property of the thread, so this stays on the thread that created it.
    _thread: PhantomData<*const ()>,
}

impl BackupPrivilege {
    pub fn enable() -> Result<Self> {
        let path = Utf8Path::new("");
        let error = |step, error| Error::io(path, step, nt::win32_error(error));
        // Guards dropped out of order would restore each other's earlier token, so nesting is refused.
        if BACKUP_PRIVILEGE_HELD.get() {
            return Err(Error::io(
                path,
                "enable backup privilege",
                io::Error::other("this thread already holds the backup privilege"),
            ));
        }
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
        let token_id =
            token_id(token.as_handle()).map_err(|cause| Error::io(path, "read backup token statistics", cause))?;
        // SAFETY: The token is an impersonation token open with TOKEN_IMPERSONATE.
        unsafe { SetThreadToken(None, Some(raw(token.as_handle()))) }
            .map_err(|cause| error("impersonate backup token", cause))?;
        BACKUP_PRIVILEGE_HELD.set(true);
        Ok(Self {
            previous,
            token_id,
            _token: token,
            _thread: PhantomData,
        })
    }
}

thread_local! {
    /// Whether a `BackupPrivilege` of this thread is alive.
    static BACKUP_PRIVILEGE_HELD: Cell<bool> = const { Cell::new(false) };
}

/// Returns the ID of a token, which tells apart two tokens even when they are copies of one.
fn token_id(token: BorrowedHandle<'_>) -> io::Result<LUID> {
    let mut statistics = TOKEN_STATISTICS::default();
    let mut length = 0;
    // SAFETY: The token is open with TOKEN_QUERY, and the output is a writable TOKEN_STATISTICS of the size passed.
    unsafe {
        GetTokenInformation(
            raw(token),
            TokenStatistics,
            Some((&raw mut statistics).cast()),
            u32::try_from(size_of::<TOKEN_STATISTICS>()).expect("TOKEN_STATISTICS is a few dozen bytes"),
            &raw mut length,
        )
    }
    .map_err(nt::win32_error)?;
    Ok(statistics.TokenId)
}

/// Returns the ID of the token the current thread impersonates, or `None` when it impersonates none.
fn thread_token_id() -> io::Result<Option<LUID>> {
    // SAFETY: Getting the pseudo-handle of the current thread has no preconditions.
    let thread = unsafe { GetCurrentThread() };
    let mut token = HANDLE::default();
    // SAFETY: The pseudo-handle of the current thread is always valid and the output is writable.
    match unsafe { OpenThreadToken(thread, TOKEN_QUERY, true, &raw mut token) } {
        Ok(()) => {
            // SAFETY: OpenThreadToken succeeded, so the handle is open and nothing else owns it.
            let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
            token_id(token.as_handle()).map(Some)
        }
        Err(cause) if cause.code() == ERROR_NO_TOKEN.to_hresult() => Ok(None),
        Err(cause) => Err(nt::win32_error(cause)),
    }
}

impl Drop for BackupPrivilege {
    fn drop(&mut self) {
        BACKUP_PRIVILEGE_HELD.set(false);
        // A thread that impersonates another token since, or none, is left as it is: restoring the earlier token over
        // it would take away an impersonation this guard didn't set.
        // When the thread token can't be read, the earlier token is restored, since leaving the privilege enabled is
        // the worse failure.
        // UNTESTED: a thread that impersonates another token since this guard was created keeps it, unless its token
        // can't be read.
        // The guard can't be created without the backup privilege, which tests can't rely on; when changing this, keep
        // comparing token IDs, not handles, since OpenThreadToken returns a new handle each time.
        match thread_token_id() {
            Ok(Some(current)) if current != self.token_id => return,
            Ok(None) => return,
            Ok(Some(_)) | Err(_) => {}
        }
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

/// Refuses a name that Win32 path functions would reach as another entry or as no entry at all, so that what
/// private-fs creates and opens is what other programs see under that name.
fn validate_name(path: &Utf8Path, name: &str) -> Result<()> {
    // A colon names an alternate data stream of a file, not an entry of the directory.
    let stream = name.contains(':');
    // Win32 path functions strip a trailing dot or space.
    let stripped = name.ends_with(['.', ' ']);
    if stream || stripped || is_reserved_device_name(name) {
        return Err(Error::io(
            path,
            "use entry name",
            io::Error::from(io::ErrorKind::InvalidInput),
        ));
    }
    Ok(())
}

/// Reports whether Win32 path functions take `name` for a device rather than an entry, with or without an extension.
fn is_reserved_device_name(name: &str) -> bool {
    const DEVICES: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];
    const NUMBERED: [&str; 2] = ["COM", "LPT"];
    const DIGITS: [&str; 13] = [
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "\u{b9}", "\u{b2}", "\u{b3}",
    ];
    let stem = name
        .split_once('.')
        .map_or(name, |(stem, _)| stem)
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    DEVICES.contains(&stem.as_str())
        || NUMBERED
            .iter()
            .any(|prefix| stem.strip_prefix(prefix).is_some_and(|digit| DIGITS.contains(&digit)))
}

/// Opens the object `handle` refers to again, with `access`: an empty name relative to a handle names its object.
fn reopen(handle: BorrowedHandle<'_>, access: FILE_ACCESS_RIGHTS) -> io::Result<OwnedHandle> {
    let request = Request {
        access,
        share: SHARE_ALL,
        disposition: FILE_OPEN,
        options: OPEN_OPTIONS,
        attributes: FILE_FLAGS_AND_ATTRIBUTES(0),
        descriptor: None,
    };
    nt::create(handle, "", &request)
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

/// Refuses an item that is a reparse point, isn't of `kind`, or is on a volume that doesn't enforce ACLs or is remote.
fn classify(handle: BorrowedHandle<'_>, path: &Utf8Path, kind: Kind) -> Result<()> {
    let (attributes, tag) =
        nt::attributes_and_tag(handle).map_err(|error| Error::io(path, "read attributes", error))?;
    if let Some(refusal) = reparse_refusal(attributes, tag) {
        return Err(Error::refused(path, refusal));
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
    let volume_error = |error| Error::io(path, "read volume information", error);
    if !nt::persistent_acls(handle).map_err(volume_error)? || nt::is_remote(handle).map_err(volume_error)? {
        return Err(Error::refused(path, Refusal::Volume));
    }
    Ok(())
}

/// Returns why an item that is a reparse point is refused.
///
/// One that stands for another name, such as a symbolic link or a junction, is a link.
/// Any other is opened as the reparse point itself rather than its content, as a cloud placeholder's or a deduplicated
/// file's, or stands for a FIFO, socket or device, as the WSL tags do, so it is not a file private-fs can vouch for.
fn reparse_refusal(attributes: u32, tag: u32) -> Option<Refusal> {
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0 {
        None
    } else if nt::is_name_surrogate(tag) {
        Some(Refusal::Link)
    } else {
        Some(Refusal::NotAFile)
    }
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
                // A reparse point is opened without following it, and refused once its tag is read.
                let reparse_point = metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0;
                if !reparse_point && !metadata.is_dir() {
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
    Ok(Dir::new(handle, false))
}

/// Checks a directory above the first existing one, at its resolved path, such as `\\?\C:\Users`.
///
/// The directory is opened with READ_CONTROL only, so that reading its owner and DACL is all the check needs, besides
/// traversing the directories above it.
fn check_above(path: &Utf8Path, policy: &Policy) -> Result<()> {
    let unreadable = |error| Error::refused(path, Refusal::Unreadable(error));
    let nt_path = path
        .as_str()
        .strip_prefix(r"\\?\")
        .map(|rest| format!(r"\??\{rest}"))
        .ok_or_else(|| {
            unreadable(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the path is not a resolved path",
            ))
        })?;
    let request = Request {
        // Not FILE_READ_ATTRIBUTES or SYNCHRONIZE, which the directory may not grant, and which CreateFileW would add.
        access: READ_CONTROL,
        share: SHARE_ALL,
        disposition: FILE_OPEN,
        // A reparse point is followed, since its attributes can't be read without FILE_READ_ATTRIBUTES.
        options: NTCREATEFILE_CREATE_OPTIONS(FILE_DIRECTORY_FILE.0 | FILE_OPEN_FOR_BACKUP_INTENT.0),
        attributes: FILE_FLAGS_AND_ATTRIBUTES(0),
        descriptor: None,
    };
    let handle = match nt::create_absolute(&nt_path, &request) {
        Ok(handle) => handle,
        // STATUS_NOT_A_DIRECTORY: a file has replaced the directory since its path was resolved.
        Err(error) if error.raw_os_error() == Some(ERROR_DIRECTORY.0.cast_signed()) => {
            return Err(Error::refused(path, Refusal::Replaceable));
        }
        Err(error) => return Err(unreadable(error)),
    };
    // The path was resolved through every link, so a directory that now resolves elsewhere, through a link put there
    // since or a folder on which a volume with a drive letter is mounted, is refused.
    let resolved = nt::final_path(handle.as_handle()).map_err(unreadable)?;
    if !same_name(&resolved, path.as_str()) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Access, Account};

    /// A directory under the system temporary directory, whose ancestors pass the ancestor check, removed on drop.
    struct TestDir(Utf8PathBuf);

    impl TestDir {
        fn new() -> Self {
            let temp = Utf8PathBuf::from_path_buf(std::env::temp_dir()).expect("the temporary directory path is UTF-8");
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the clock is after 1970")
                .as_nanos();
            Self(temp.join(format!("pfs-unit-{}-{unique}", std::process::id())))
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // oracle: intent crates/private-fs/INTENT.md §paths
    #[test]
    fn repair_file_brings_a_file_into_line_with_its_rule() -> Result<()> {
        // Catches a file repair that leaves an entry the rule doesn't name.
        let test = TestDir::new();
        let user_full = Rule::new()
            .owner(Account::CurrentUser)
            .grant(Account::CurrentUser, Access::Full);
        let base = crate::Dir::create_base(&test.0, &user_full)?;
        let wider = user_full.clone().grant(Account::System, Access::Full);
        let file = base.create_file("file", &wider, FileOptions::new())?;
        let exact = user_full.exact();
        let path = test.0.join("file");
        assert!(check_file(&file, &path, &exact).is_err());
        repair_file(&file, &path, &exact)?;
        check_file(&file, &path, &exact)
    }

    /// Reparse tags, from [MS-FSCC] "Reparse Tags".
    ///
    /// [MS-FSCC]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/
    const SYMLINK: u32 = 0xA000_000C;
    const MOUNT_POINT: u32 = 0xA000_0003;
    const CLOUD: u32 = 0x9000_001A;
    const DEDUP: u32 = 0x8000_0013;
    const LX_FIFO: u32 = 0x8000_0024;

    const REPARSE_POINT: u32 = FILE_ATTRIBUTE_REPARSE_POINT.0;

    // oracle: reference crates/private-fs/src/lib.rs Dir::discard
    #[test]
    fn names_compare_ignoring_case_one_character_at_a_time() {
        assert!(same_name("C:\\Dir\\Staged", "c:\\dir\\STAGED"));
        assert!(same_name("\u{e9}t\u{e9}", "\u{c9}T\u{c9}"));
        // Full case mapping uppercases ß to SS; the simple mapping NTFS uses leaves it.
        assert!(!same_name("x\u{df}", "xSS"));
        assert!(!same_name("staged", "staged2"));
    }

    // oracle: spec MS-FSCC §2.1.2.1 Reparse Tags
    // oracle: reference crates/private-fs/src/error.rs Refusal
    #[test]
    fn a_name_surrogate_item_is_a_link() {
        for tag in [SYMLINK, MOUNT_POINT] {
            assert!(
                matches!(reparse_refusal(REPARSE_POINT, tag), Some(Refusal::Link)),
                "{tag:#x}"
            );
        }
    }

    // oracle: spec MS-FSCC §2.1.2.1 Reparse Tags
    // oracle: reference crates/private-fs/src/error.rs Refusal
    #[test]
    fn any_other_reparse_point_item_is_not_a_file() {
        // Opened without following the reparse point, a stub's content is not the file's, and a FIFO is not a file.
        for tag in [CLOUD, DEDUP, LX_FIFO] {
            assert!(
                matches!(reparse_refusal(REPARSE_POINT, tag), Some(Refusal::NotAFile)),
                "{tag:#x}"
            );
        }
    }

    // oracle: spec MS-FSCC §2.1.2.1 Reparse Tags
    // oracle: reference crates/private-fs/src/lib.rs EntryKind
    #[test]
    fn a_listed_reparse_point_is_a_link_only_when_it_stands_for_another_name() {
        assert_eq!(entry_kind(REPARSE_POINT, SYMLINK), EntryKind::Link);
        assert_eq!(
            entry_kind(REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY.0, MOUNT_POINT),
            EntryKind::Link
        );
        assert_eq!(entry_kind(REPARSE_POINT, CLOUD), EntryKind::Other);
        assert_eq!(entry_kind(REPARSE_POINT, LX_FIFO), EntryKind::Other);
    }
}
