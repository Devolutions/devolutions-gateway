use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;
use std::ptr::NonNull;

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

/// Reports whether the volume holding `file` ignores file ownership.
pub fn volume_ignores_ownership(file: &File) -> io::Result<bool> {
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: The file stays open and the output buffer is writable.
    if unsafe { libc::fstatfs(file.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs initialized the output buffer on success.
    let info = unsafe { info.assume_init() };
    Ok(info.f_flags & libc::MNT_IGNORE_OWNERSHIP.cast_unsigned() != 0)
}

/// The step of [`has_extended_acl`] that failed.
#[derive(Debug)]
pub enum ExtendedAclError {
    Inspect(io::Error),
    Validate(io::Error),
    ReadEntries(io::Error),
}

/// Reports whether `file` has extended ACL entries.
pub fn has_extended_acl(file: &File) -> Result<bool, ExtendedAclError> {
    // SAFETY: The file descriptor is live and ACL_TYPE_EXTENDED is supported on macOS.
    let raw = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    let Some(raw) = NonNull::new(raw) else {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT | libc::ENOATTR) => Ok(false),
            _ => Err(ExtendedAclError::Inspect(error)),
        };
    };
    let acl = Acl(raw);
    // SAFETY: The ACL remains live and was returned by acl_get_fd_np.
    if unsafe { acl_valid(acl.0.as_ptr()) } != 0 {
        return Err(ExtendedAclError::Validate(io::Error::last_os_error()));
    }
    let mut first_entry = std::ptr::null_mut();
    // SAFETY: The ACL is valid and the output pointer is writable.
    match unsafe { acl_get_entry(acl.0.as_ptr(), ACL_FIRST_ENTRY, &mut first_entry) } {
        0 => Ok(true),
        -1 if io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) => Ok(false),
        _ => Err(ExtendedAclError::ReadEntries(io::Error::last_os_error())),
    }
}
