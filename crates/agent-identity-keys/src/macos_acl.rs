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
    // SAFETY: The file remains open and the output buffer is writable.
    let status = unsafe { libc::fstatfs(file.as_raw_fd(), info.as_mut_ptr()) };
    if status != 0 {
        return Err(std::io::Error::last_os_error()).context("inspect key volume");
    }
    // SAFETY: fstatfs initialized the output buffer on success.
    let info = unsafe { info.assume_init() };
    let ignore_ownership = u32::try_from(libc::MNT_IGNORE_OWNERSHIP)?;
    ensure!(
        info.f_flags & ignore_ownership == 0,
        "key volume ignores file ownership"
    );
    Ok(())
}

fn ensure_no_extended_acl(file: &File) -> anyhow::Result<()> {
    // SAFETY: The file descriptor is live and ACL_TYPE_EXTENDED is supported on macOS.
    let raw = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    let Some(raw) = NonNull::new(raw) else {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT | libc::ENOATTR) => Ok(()),
            _ => Err(error).context("inspect key path ACL"),
        };
    };
    let acl = Acl(raw);
    // SAFETY: The ACL remains live and was returned by acl_get_fd_np.
    if unsafe { acl_valid(acl.0.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("validate key path ACL");
    }
    let mut first_entry = std::ptr::null_mut();
    // SAFETY: The ACL is valid and the output pointer is writable.
    let status = unsafe { acl_get_entry(acl.0.as_ptr(), ACL_FIRST_ENTRY, &mut first_entry) };
    match status {
        0 => anyhow::bail!("key path has extended ACL entries"),
        -1 if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) => Ok(()),
        _ => Err(std::io::Error::last_os_error()).context("read key path ACL entries"),
    }
}

pub(crate) fn ensure_private_file(file: &File) -> anyhow::Result<()> {
    ensure_private_volume(file)?;
    // SAFETY: Reading the current effective UID has no preconditions.
    let user = unsafe { libc::geteuid() };
    ensure!(file.metadata()?.uid() == user, "key file owner is not the process user");
    ensure_no_extended_acl(file)
}

pub(crate) fn ensure_private_directory(file: &File) -> anyhow::Result<()> {
    ensure_private_volume(file)?;
    let metadata = file.metadata()?;
    // SAFETY: Reading the current effective UID has no preconditions.
    let user = unsafe { libc::geteuid() };
    ensure!(metadata.uid() == user, "key directory owner is not the process user");
    ensure!(
        metadata.permissions().mode() & 0o022 == 0,
        "key directory is writable by other users"
    );
    ensure_no_extended_acl(file)
}
