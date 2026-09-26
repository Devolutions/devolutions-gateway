use std::ffi::c_void;
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::ptr::NonNull;

use anyhow::{Context as _, ensure};

const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
const ACL_FIRST_ENTRY: libc::c_int = 0;

unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, entry_id: libc::c_int, entry: *mut *mut c_void) -> libc::c_int;
    fn acl_valid(acl: *mut c_void) -> libc::c_int;
    fn acl_free(acl: *mut c_void) -> libc::c_int;
}

struct Acl(NonNull<c_void>);

impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: acl_get_fd_np returned this owned ACL.
        let _ = unsafe { acl_free(self.0.as_ptr()) };
    }
}

fn ensure_private_volume(file: &File) -> anyhow::Result<()> {
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: The file stays open and the output buffer is writable.
    if unsafe { libc::fstatfs(file.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("inspect identity volume");
    }
    // SAFETY: fstatfs initialized info after returning success.
    let info = unsafe { info.assume_init() };
    ensure!(
        info.f_flags & u32::try_from(libc::MNT_IGNORE_OWNERSHIP)? == 0,
        "identity volume ignores ownership"
    );
    Ok(())
}

fn ensure_no_extended_acl(file: &File) -> anyhow::Result<()> {
    // SAFETY: The descriptor remains live and ACL_TYPE_EXTENDED is supported by macOS.
    let raw = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    let Some(raw) = NonNull::new(raw) else {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOENT | libc::ENOATTR) => Ok(()),
            _ => Err(std::io::Error::last_os_error()).context("inspect identity ACL"),
        };
    };
    let acl = Acl(raw);
    // SAFETY: This ACL was returned by acl_get_fd_np and remains live.
    if unsafe { acl_valid(acl.0.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("validate identity ACL");
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: The ACL remains live and entry is a writable output pointer.
    match unsafe { acl_get_entry(acl.0.as_ptr(), ACL_FIRST_ENTRY, &mut entry) } {
        0 => anyhow::bail!("identity path has extended ACL entries"),
        -1 if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) => Ok(()),
        _ => Err(std::io::Error::last_os_error()).context("read identity ACL entries"),
    }
}

pub(crate) fn ensure_private_file(file: &File) -> anyhow::Result<()> {
    ensure_private_volume(file)?;
    // SAFETY: Reading the process's effective UID has no preconditions.
    let user = unsafe { libc::geteuid() };
    ensure!(
        file.metadata()?.uid() == user,
        "identity file owner is not the process user"
    );
    ensure_no_extended_acl(file)
}

pub(crate) fn ensure_private_pending_file(file: &File) -> anyhow::Result<()> {
    ensure_private_volume(file)?;
    ensure_no_extended_acl(file)
}

pub(crate) fn ensure_private_directory(file: &File) -> anyhow::Result<()> {
    ensure_private_volume(file)?;
    let metadata = file.metadata()?;
    // SAFETY: Reading the process's effective UID has no preconditions.
    let user = unsafe { libc::geteuid() };
    ensure!(
        metadata.uid() == user,
        "identity directory owner is not the process user"
    );
    ensure!(
        metadata.permissions().mode() & 0o022 == 0,
        "identity directory is writable by other users"
    );
    ensure_no_extended_acl(file)
}
