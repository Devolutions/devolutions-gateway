//! macOS ACLs and volumes.
//!
//! The ACL constants are those of Apple's [`sys/acl.h`].
//!
//! [`sys/acl.h`]: https://github.com/apple-oss-distributions/Libc/blob/main/include/sys/acl.h

use std::ffi::{CStr, CString, c_void};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd as _;
use std::ptr::NonNull;

use camino::Utf8Path;

use crate::unix::Allowed;
use crate::{Error, Refusal, Result};

/// The `statfs` type names of file systems that ignore or fake ownership, besides those starting with `fuse`.
const IGNORING_FILE_SYSTEMS: [&[u8]; 9] = [
    b"smbfs", b"nfs", b"webdav", b"afpfs", b"msdos", b"exfat", b"ntfs", b"macfuse", b"osxfuse",
];

const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
const ACL_FIRST_ENTRY: libc::c_int = 0;
const ACL_NEXT_ENTRY: libc::c_int = -1;
const ACL_EXTENDED_ALLOW: libc::c_int = 1;
const ACL_DELETE: libc::c_int = 1 << 4;
const ACL_DELETE_CHILD: libc::c_int = 1 << 6;
const ACL_WRITE_SECURITY: libc::c_int = 1 << 12;
const ACL_CHANGE_OWNER: libc::c_int = 1 << 13;
const ACL_ENTRY_FILE_INHERIT: libc::c_int = 1 << 5;
const ACL_ENTRY_DIRECTORY_INHERIT: libc::c_int = 1 << 6;

unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut c_void;
    fn acl_get_link_np(path: *const libc::c_char, acl_type: libc::c_int) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, entry_id: libc::c_int, entry: *mut *mut c_void) -> libc::c_int;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut libc::c_int) -> libc::c_int;
    fn acl_get_flagset_np(object: *mut c_void, flagset: *mut *mut c_void) -> libc::c_int;
    fn acl_get_flag_np(flagset: *mut c_void, flag: libc::c_int) -> libc::c_int;
    fn acl_get_permset(entry: *mut c_void, permset: *mut *mut c_void) -> libc::c_int;
    fn acl_get_perm_np(permset: *mut c_void, perm: libc::c_int) -> libc::c_int;
    fn acl_init(count: libc::c_int) -> *mut c_void;
    fn acl_set_fd_np(fd: libc::c_int, acl: *mut c_void, acl_type: libc::c_int) -> libc::c_int;
    fn acl_free(object: *mut c_void) -> libc::c_int;
}

/// What the checks need to know of an extended ACL.
#[derive(Clone, Copy, Debug, Default)]
struct AclSummary {
    has_entries: bool,
    /// An entry that new files or directories inherit.
    inheritable: bool,
    /// An allow entry that lets its account delete, delete children, change the ACL or take ownership.
    replace_allowed: bool,
}

/// What a directory above's ACL lets other accounts do.
pub(crate) struct AncestorAcl {
    replace_allowed: bool,
}

struct Acl(NonNull<c_void>);

impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: acl_get_fd_np, acl_get_link_np or acl_init returned this ACL, and it is freed only here.
        let _ = unsafe { acl_free(self.0.as_ptr()) };
    }
}

pub(crate) fn check_volume(file: &File, path: &Utf8Path) -> Result<()> {
    let mut info = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: The descriptor is open and the output buffer is writable.
    if unsafe { libc::fstatfs(file.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err(Error::io(path, "inspect volume", io::Error::last_os_error()));
    }
    // SAFETY: fstatfs initialized the output buffer on success.
    let info = unsafe { info.assume_init() };
    // UNTESTED: a volume with "Ignore ownership on this volume" set, or of one of the listed file system types, is
    // refused, and the boot volume is not.
    // CI has no such volume; on one, every owner check passes whatever the file's owner, or the owner and mode are
    // made up by the driver.
    // When changing this, check a disk image after `diskutil disableOwnership`, an SMB or MS-DOS volume, and the boot
    // volume on a Mac.
    let type_name = info.f_fstypename.map(libc::c_char::cast_unsigned);
    let type_name = CStr::from_bytes_until_nul(&type_name).map_or(&type_name[..], CStr::to_bytes);
    if info.f_flags & libc::MNT_IGNORE_OWNERSHIP.cast_unsigned() != 0 || type_ignores_ownership(type_name) {
        return Err(Error::refused(path, Refusal::Volume));
    }
    Ok(())
}

/// Reports whether volumes of the file system type `name`, as `statfs` reports it, ignore or fake ownership.
fn type_ignores_ownership(name: &[u8]) -> bool {
    name.starts_with(b"fuse") || IGNORING_FILE_SYSTEMS.contains(&name)
}

pub(crate) fn check_no_extended_acl(file: &File, path: &Utf8Path, _is_dir: bool) -> Result<()> {
    let summary = acl_of_file(file).map_err(|error| Error::io(path, "read access control list", error))?;
    if summary.has_entries {
        return Err(Error::refused(path, Refusal::Access));
    }
    Ok(())
}

/// Refuses to create an entry in `parent` when an entry of its ACL is inheritable, because the new entry would
/// inherit it.
pub(crate) fn refuse_inheritable_acl(parent: &File, path: &Utf8Path) -> Result<()> {
    let summary = acl_of_file(parent).map_err(|error| Error::io(path, "read access control list", error))?;
    if summary.inheritable {
        return Err(Error::refused(path, Refusal::Access));
    }
    Ok(())
}

pub(crate) fn remove_extended_acl(file: &File, path: &Utf8Path) -> Result<()> {
    let remove_error = |error| Error::io(path, "remove access control list", error);
    // SAFETY: acl_init has no preconditions.
    let empty = unsafe { acl_init(0) };
    let empty = Acl(NonNull::new(empty).ok_or_else(|| remove_error(io::Error::last_os_error()))?);
    // SAFETY: The descriptor is open and the ACL is live.
    if unsafe { acl_set_fd_np(file.as_raw_fd(), empty.0.as_ptr(), ACL_TYPE_EXTENDED) } != 0 {
        return Err(remove_error(io::Error::last_os_error()));
    }
    Ok(())
}

pub(crate) fn ancestor_acl_of_file(file: &File) -> io::Result<AncestorAcl> {
    acl_of_file(file).map(|summary| AncestorAcl {
        replace_allowed: summary.replace_allowed,
    })
}

/// Reads the ACL at `path` without following a link.
///
/// The caller compares the directory at `path` before and after, because a missing ACL and a missing path both read
/// as `ENOENT`.
pub(crate) fn ancestor_acl_of_path(path: &Utf8Path) -> io::Result<AncestorAcl> {
    let path = CString::new(path.as_str()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: The path is NUL-terminated.
    let acl = unsafe { acl_get_link_np(path.as_ptr(), ACL_TYPE_EXTENDED) };
    summarize(acl).map(|summary| AncestorAcl {
        replace_allowed: summary.replace_allowed,
    })
}

/// Reports whether an allow entry lets an account rename or replace a directory or its entries.
///
/// The sticky bit doesn't limit what an ACL entry allows, and the check counts an entry for any account, the rule's
/// included.
pub(crate) fn acl_lets_replace(acl: &AncestorAcl, _sticky: bool, _allowed: &Allowed) -> bool {
    acl.replace_allowed
}

/// The mode's group bits are the owning group's access on macOS.
pub(crate) fn owning_group_writes(_acl: &AncestorAcl) -> Option<bool> {
    None
}

pub(crate) fn rename_exclusive(fd: libc::c_int, from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: The descriptor is open and both names are NUL-terminated.
    if unsafe { libc::renameatx_np(fd, from.as_ptr(), fd, to.as_ptr(), libc::RENAME_EXCL) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Reports whether `renameatx_np` failed with `code` because the file system has no exclusive rename.
///
/// `EINVAL` is left out: `RENAME_EXCL` is a valid flag on every supported macOS, and the names are single components
/// of one directory, so it can't mean the flag is unsupported.
pub(crate) fn exclusive_rename_unsupported(code: libc::c_int) -> bool {
    code == libc::ENOTSUP || code == libc::EOPNOTSUPP || code == libc::ENOSYS
}

pub(crate) fn clear_errno() {
    // SAFETY: __error has no preconditions and returns the calling thread's errno.
    let errno = unsafe { libc::__error() };
    // SAFETY: The pointer is valid for the calling thread.
    unsafe { *errno = 0 };
}

fn acl_of_file(file: &File) -> io::Result<AclSummary> {
    // SAFETY: The descriptor is open.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    summarize(acl)
}

/// Summarizes an ACL that `acl_get_fd_np` or `acl_get_link_np` returned, taking ownership of it.
fn summarize(acl: *mut c_void) -> io::Result<AclSummary> {
    let Some(acl) = NonNull::new(acl) else {
        let error = io::Error::last_os_error();
        // An item without an extended ACL reads as ENOENT.
        return match error.raw_os_error() {
            Some(libc::ENOENT | libc::ENOATTR) => Ok(AclSummary::default()),
            _ => Err(error),
        };
    };
    let acl = Acl(acl);
    let mut summary = AclSummary::default();
    let mut entry_id = ACL_FIRST_ENTRY;
    loop {
        let mut entry = std::ptr::null_mut();
        // SAFETY: The ACL is live and the output pointer is writable.
        if unsafe { acl_get_entry(acl.0.as_ptr(), entry_id, &mut entry) } != 0 {
            let error = io::Error::last_os_error();
            // Reading past the last entry fails with EINVAL.
            if error.raw_os_error() == Some(libc::EINVAL) {
                return Ok(summary);
            }
            return Err(error);
        }
        entry_id = ACL_NEXT_ENTRY;
        summary.has_entries = true;

        let mut flagset = std::ptr::null_mut();
        // SAFETY: The entry belongs to the live ACL and the output pointer is writable.
        if unsafe { acl_get_flagset_np(entry, &mut flagset) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if flag(flagset, ACL_ENTRY_FILE_INHERIT)? || flag(flagset, ACL_ENTRY_DIRECTORY_INHERIT)? {
            summary.inheritable = true;
        }

        let mut tag = 0;
        // SAFETY: The entry belongs to the live ACL and the output pointer is writable.
        if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if tag != ACL_EXTENDED_ALLOW {
            continue;
        }
        let mut permset = std::ptr::null_mut();
        // SAFETY: The entry belongs to the live ACL and the output pointer is writable.
        if unsafe { acl_get_permset(entry, &mut permset) } != 0 {
            return Err(io::Error::last_os_error());
        }
        for perm in [ACL_DELETE, ACL_DELETE_CHILD, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER] {
            // SAFETY: The permission set belongs to the live ACL.
            match unsafe { acl_get_perm_np(permset, perm) } {
                0 => {}
                1 => summary.replace_allowed = true,
                _ => return Err(io::Error::last_os_error()),
            }
        }
    }
}

fn flag(flagset: *mut c_void, flag: libc::c_int) -> io::Result<bool> {
    // SAFETY: The flag set belongs to a live ACL.
    match unsafe { acl_get_flag_np(flagset, flag) } {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(io::Error::last_os_error()),
    }
}

#[cfg(test)]
impl AncestorAcl {
    pub(crate) fn empty() -> Self {
        Self { replace_allowed: false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A network or foreign file system shows owners and modes its driver makes up.
    // oracle: intent crates/private-fs/INTENT.md §mechanisms
    #[test]
    fn recognizes_file_systems_that_fake_ownership() {
        for name in ["smbfs", "nfs", "msdos", "exfat", "macfuse", "fuse-t"] {
            assert!(type_ignores_ownership(name.as_bytes()), "{name}");
        }
        for name in ["apfs", "hfs", "devfs"] {
            assert!(!type_ignores_ownership(name.as_bytes()), "{name}");
        }
    }
}
