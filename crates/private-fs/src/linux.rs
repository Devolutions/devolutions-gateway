//! Linux ACLs and volumes.
//!
//! POSIX ACLs are read from the `system.posix_acl_access` and `system.posix_acl_default` extended attributes, in the
//! format of the kernel's [`include/uapi/linux/posix_acl_xattr.h`]: a 4-byte little-endian version, 2, then 8-byte
//! entries of a 2-byte tag, a 2-byte permission set and a 4-byte user or group ID, all little-endian.
//!
//! [`include/uapi/linux/posix_acl_xattr.h`]: https://github.com/torvalds/linux/blob/master/include/uapi/linux/posix_acl_xattr.h

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd as _;

use camino::Utf8Path;

use crate::unix::Allowed;
use crate::{Error, Refusal, Result};

const ACCESS_ACL: &CStr = c"system.posix_acl_access";
const DEFAULT_ACL: &CStr = c"system.posix_acl_default";
const ACL_VERSION: u32 = 2;
/// `XATTR_SIZE_MAX`, the largest extended attribute value the kernel stores.
const XATTR_SIZE_MAX: usize = 65536;
/// The size of the first read of an ACL attribute, which holds an ACL of up to 32 entries; a larger one is read again.
const ACL_READ_SIZE: usize = 4 /* a_version */ + 32 * 8 /* a_entries */;
/// [`libc::RENAME_NOREPLACE`] as the `long` that `syscall` reads its arguments as.
const RENAME_NOREPLACE: libc::c_long = 1;

const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_GROUP: u16 = 0x08;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;
const ACL_WRITE: u16 = 0x02;
/// Read, write and execute, the permissions a missing mask leaves.
const ACL_ALL: u16 = 0x07;

/// The `statfs` types of volumes that ignore or fake ownership: FUSE, CIFS, SMB2, SMB, NFS, 9P, vboxsf, MSDOS/vfat,
/// exFAT, ntfs3, NTFS (the legacy in-kernel ntfs driver; ntfs-3g is FUSE) and UDF.
const IGNORING_VOLUMES: [u32; 12] = [
    0x6573_5546,
    0xFF53_4D42,
    0xFE53_4D42,
    0x0000_517B,
    0x0000_6969,
    0x0102_1997,
    0x786F_4256,
    0x0000_4D44,
    0x2011_BAB0,
    0x7366_746E,
    0x5346_544E,
    0x1501_3346,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AclEntry {
    tag: u16,
    perm: u16,
    id: u32,
}

/// The access ACL of a directory above, if it has one.
pub(crate) struct AncestorAcl(Option<Vec<AclEntry>>);

pub(crate) fn check_volume(file: &File, path: &Utf8Path) -> Result<()> {
    let mut info = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: The descriptor is open and the output buffer is writable.
    if unsafe { libc::fstatfs(file.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err(Error::io(path, "inspect volume", io::Error::last_os_error()));
    }
    // SAFETY: fstatfs initialized the output buffer on success.
    let info = unsafe { info.assume_init() };
    // UNTESTED: a file on one of the listed volume types is refused.
    // CI has no such volume; on one, the owner and mode that the other checks read are made up by the driver.
    // When changing this, check a file on a FUSE or SMB mount and on a vfat, NTFS or UDF image, and one on ext4.
    if ignores_ownership(i128::from(info.f_type)) {
        return Err(Error::refused(path, Refusal::Volume));
    }
    Ok(())
}

/// Reports whether `f_type`, of the platform's signed or unsigned width, is the type of a volume that ignores or fakes
/// ownership.
fn ignores_ownership(f_type: i128) -> bool {
    // A 32-bit platform stores the type in a signed 32-bit word, so a type such as CIFS's reads as negative there.
    let f_type = f_type & 0xFFFF_FFFF;
    IGNORING_VOLUMES.iter().any(|&magic| i128::from(magic) == f_type)
}

pub(crate) fn check_no_extended_acl(file: &File, path: &Utf8Path, is_dir: bool) -> Result<()> {
    let read_error = |error| Error::io(path, "read access control list", error);
    if let Some(entries) = read_acl(file, ACCESS_ACL).map_err(read_error)?
        && entries
            .iter()
            .any(|entry| !matches!(entry.tag, ACL_USER_OBJ | ACL_GROUP_OBJ | ACL_OTHER))
    {
        return Err(Error::refused(path, Refusal::Access));
    }
    if is_dir && read_acl(file, DEFAULT_ACL).map_err(read_error)?.is_some() {
        return Err(Error::refused(path, Refusal::Access));
    }
    Ok(())
}

/// Refuses to create an entry in `parent` when it has a default ACL, which the entry would inherit.
pub(crate) fn refuse_inheritable_acl(parent: &File, path: &Utf8Path) -> Result<()> {
    let default = read_acl(parent, DEFAULT_ACL).map_err(|error| Error::io(path, "read access control list", error))?;
    if default.is_some() {
        return Err(Error::refused(path, Refusal::Access));
    }
    Ok(())
}

pub(crate) fn remove_extended_acl(file: &File, path: &Utf8Path) -> Result<()> {
    for name in [ACCESS_ACL, DEFAULT_ACL] {
        // SAFETY: The descriptor is open and the name is NUL-terminated.
        if unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr()) } != 0 {
            let error = io::Error::last_os_error();
            if !no_acl(&error) {
                return Err(Error::io(path, "remove access control list", error));
            }
        }
    }
    Ok(())
}

pub(crate) fn ancestor_acl_of_file(file: &File) -> io::Result<AncestorAcl> {
    read_acl(file, ACCESS_ACL).map(AncestorAcl)
}

pub(crate) fn ancestor_acl_of_path(path: &Utf8Path) -> io::Result<AncestorAcl> {
    let path = CString::new(path.as_str()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    read_xattr(|value, size| {
        // SAFETY: The path and name are NUL-terminated, and `value` is writable for `size` bytes.
        unsafe { libc::lgetxattr(path.as_ptr(), ACCESS_ACL.as_ptr(), value, size) }
    })
    .map(AncestorAcl)
}

/// Reports whether a named user entry for an account that `allowed` doesn't name, or any named group entry, of `acl`
/// can write, so rename or replace entries, unless the sticky bit limits writers to adding entries and removing their
/// own.
///
/// A group is never allowed: administrators are root alone, and any account can be a member of a group.
pub(crate) fn acl_lets_replace(acl: &AncestorAcl, sticky: bool, allowed: &Allowed) -> bool {
    let Some(entries) = &acl.0 else {
        return false;
    };
    if sticky {
        return false;
    }
    let mask = mask(entries);
    entries.iter().any(|entry| {
        entry.perm & mask & ACL_WRITE != 0
            && match entry.tag {
                ACL_USER => !allowed.uid(entry.id),
                ACL_GROUP => true,
                _ => false,
            }
    })
}

/// Reports whether the owning group can write, from the ACL's group entry and mask, when the directory has an ACL.
///
/// With an ACL, the mode's group bits show the mask rather than the owning group's access.
pub(crate) fn owning_group_writes(acl: &AncestorAcl) -> Option<bool> {
    let entries = acl.0.as_ref()?;
    let group = entries.iter().find(|entry| entry.tag == ACL_GROUP_OBJ)?;
    Some(group.perm & mask(entries) & ACL_WRITE != 0)
}

pub(crate) fn rename_exclusive(fd: libc::c_int, from: &CStr, to: &CStr) -> io::Result<()> {
    // The raw system call avoids glibc's renameat2 wrapper, which needs glibc 2.28; the release baseline is 2.27.
    // `syscall` reads each argument as a `long`, so each is passed as one.
    let fd = libc::c_long::from(fd);
    // SAFETY: The descriptor is open and both names are NUL-terminated.
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            fd,
            from.as_ptr() as libc::c_long,
            fd,
            to.as_ptr() as libc::c_long,
            RENAME_NOREPLACE,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Reports whether `renameat2` failed with `code` because the kernel or file system has no `RENAME_NOREPLACE`.
///
/// A kernel before 3.15 fails with `ENOSYS`, and a file system without the flag with `EINVAL` on older kernels or
/// `EOPNOTSUPP` on newer ones.
/// `EINVAL` has no other cause here: the names are single components of one directory, never `.` or `..`, so neither
/// is an ancestor of the other.
pub(crate) fn exclusive_rename_unsupported(code: libc::c_int) -> bool {
    matches!(code, libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP)
}

pub(crate) fn clear_errno() {
    // SAFETY: __errno_location has no preconditions and returns the calling thread's errno.
    let errno = unsafe { libc::__errno_location() };
    // SAFETY: The pointer is valid for the calling thread.
    unsafe { *errno = 0 };
}

fn mask(entries: &[AclEntry]) -> u16 {
    entries
        .iter()
        .find(|entry| entry.tag == ACL_MASK)
        .map_or(ACL_ALL, |entry| entry.perm)
}

/// Reads the ACL in the extended attribute `name` of `file`, and returns `None` when it has none.
fn read_acl(file: &File, name: &CStr) -> io::Result<Option<Vec<AclEntry>>> {
    read_xattr(|value, size| {
        // SAFETY: The descriptor is open, the name is NUL-terminated, and `value` is writable for `size` bytes.
        unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), value, size) }
    })
}

/// Reads an ACL attribute with `get`, which takes a buffer and its size as `getxattr` does.
fn read_xattr(get: impl Fn(*mut libc::c_void, usize) -> isize) -> io::Result<Option<Vec<AclEntry>>> {
    let mut buffer = vec![0u8; ACL_READ_SIZE];
    // INVARIANT: the buffer grows on each retry and never past XATTR_SIZE_MAX, so the loop ends.
    loop {
        let size = get(buffer.as_mut_ptr().cast(), buffer.len());
        if let Ok(size) = usize::try_from(size) {
            buffer.truncate(size);
            return parse_acl(&buffer).map(Some);
        }
        let error = io::Error::last_os_error();
        if no_acl(&error) {
            return Ok(None);
        }
        if error.raw_os_error() != Some(libc::ERANGE) || buffer.len() == XATTR_SIZE_MAX {
            return Err(error);
        }
        // The attribute is larger than the buffer: ask for its size, which may grow again before the next read.
        let needed = get(std::ptr::null_mut(), 0);
        let Ok(needed) = usize::try_from(needed) else {
            let error = io::Error::last_os_error();
            return if no_acl(&error) { Ok(None) } else { Err(error) };
        };
        let grown = needed.max(buffer.len() * 2).min(XATTR_SIZE_MAX);
        buffer.resize(grown, 0);
    }
}

fn no_acl(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENODATA | libc::EOPNOTSUPP))
        || error.raw_os_error() == Some(libc::ENOTSUP)
}

fn parse_acl(bytes: &[u8]) -> io::Result<Vec<AclEntry>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "malformed POSIX ACL attribute");
    let (version, entries) = bytes.split_first_chunk::<4>().ok_or_else(invalid)?;
    if u32::from_le_bytes(*version) != ACL_VERSION || entries.len() % 8 != 0 {
        return Err(invalid());
    }
    entries
        .chunks_exact(8)
        .map(|entry| {
            let entry = AclEntry {
                tag: u16::from_le_bytes([entry[0], entry[1]]),
                perm: u16::from_le_bytes([entry[2], entry[3]]),
                id: u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]),
            };
            match entry.tag {
                ACL_USER_OBJ | ACL_USER | ACL_GROUP_OBJ | ACL_GROUP | ACL_MASK | ACL_OTHER => Ok(entry),
                _ => Err(invalid()),
            }
        })
        .collect()
}

#[cfg(test)]
impl AncestorAcl {
    pub(crate) fn empty() -> Self {
        Self(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOBODY: u32 = 65534;

    fn entry(tag: u16, perm: u16, id: u32) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[..2].copy_from_slice(&tag.to_le_bytes());
        bytes[2..4].copy_from_slice(&perm.to_le_bytes());
        bytes[4..].copy_from_slice(&id.to_le_bytes());
        bytes
    }

    fn attribute(entries: &[[u8; 8]]) -> Vec<u8> {
        let mut bytes = 2u32.to_le_bytes().to_vec();
        entries.iter().for_each(|entry| bytes.extend_from_slice(entry));
        bytes
    }

    fn ancestor(entries: &[[u8; 8]]) -> AncestorAcl {
        AncestorAcl(Some(parse_acl(&attribute(entries)).expect("valid ACL")))
    }

    /// `setfacl -m u:nobody:rwx` on a directory with mode 0755: owner rwx, nobody rwx, group r-x, mask rwx, other r-x.
    fn nobody_can_write() -> [[u8; 8]; 5] {
        [
            entry(ACL_USER_OBJ, 7, u32::MAX),
            entry(ACL_USER, 7, NOBODY),
            entry(ACL_GROUP_OBJ, 5, u32::MAX),
            entry(ACL_MASK, 7, u32::MAX),
            entry(ACL_OTHER, 5, u32::MAX),
        ]
    }

    // A parser that misread the header or an entry would hide a named entry from the checks.
    // oracle: spec Linux include/uapi/linux/posix_acl_xattr.h
    #[test]
    fn parses_the_kernel_attribute_format() {
        // Version 2, then user nobody with read and write: tag 0x0002, perm 0x0006, ID 65534 (0x0000FFFE).
        let bytes = [2, 0, 0, 0, 0x02, 0x00, 0x06, 0x00, 0xFE, 0xFF, 0x00, 0x00];
        assert_eq!(
            parse_acl(&bytes).expect("valid ACL"),
            [AclEntry {
                tag: ACL_USER,
                perm: 6,
                id: NOBODY
            }]
        );
    }

    // A reader that kept the first, small buffer would fail on a large ACL, or read part of it.
    // oracle: spec getxattr(2) §ERRORS
    #[test]
    fn reads_an_attribute_larger_than_the_first_buffer() {
        let entries: Vec<[u8; 8]> = (0..40).map(|id| entry(ACL_USER, 4, id)).collect();
        let value = attribute(&entries);
        assert!(ACL_READ_SIZE < value.len());
        // Behaves as getxattr does: a zero size asks for the value's size, and a smaller buffer fails with ERANGE.
        let get = |buffer: *mut libc::c_void, size: usize| -> isize {
            if size == 0 {
                return isize::try_from(value.len()).expect("small value");
            }
            if size < value.len() {
                clear_errno();
                // SAFETY: __errno_location has no preconditions and returns the calling thread's errno.
                let errno = unsafe { libc::__errno_location() };
                // SAFETY: The pointer is valid for the calling thread.
                unsafe { *errno = libc::ERANGE };
                return -1;
            }
            // SAFETY: read_xattr passes a buffer writable for `size` bytes, which holds the value.
            unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), buffer.cast::<u8>(), value.len()) };
            isize::try_from(value.len()).expect("small value")
        };

        let read = read_xattr(get).expect("read").expect("an ACL");
        assert_eq!(read.len(), 40);
        assert_eq!(
            read[39],
            AclEntry {
                tag: ACL_USER,
                perm: 4,
                id: 39
            }
        );
    }

    // oracle: spec Linux include/uapi/linux/fs.h RENAME_NOREPLACE
    #[test]
    fn passes_the_kernel_flag_for_an_exclusive_rename() {
        assert_eq!(u32::try_from(RENAME_NOREPLACE).ok(), Some(libc::RENAME_NOREPLACE));
    }

    // oracle: spec Linux include/uapi/linux/posix_acl_xattr.h
    #[test]
    fn rejects_an_attribute_it_cannot_read() {
        // Version 1.
        assert!(parse_acl(&[1, 0, 0, 0]).is_err());
        // A truncated entry.
        assert!(parse_acl(&[2, 0, 0, 0, 1, 0, 7, 0]).is_err());
        // A tag the format doesn't define.
        assert!(parse_acl(&attribute(&[entry(0x40, 7, 0)])).is_err());
        assert!(parse_acl(&[]).is_err());
    }

    // StrictModes: a named user who can write to a directory above can rename or replace its entries.
    // oracle: intent crates/private-fs/INTENT.md §paths
    #[test]
    fn a_named_user_who_can_write_makes_a_directory_replaceable() {
        let allowed = Allowed::new_for_tests(Some(1000));
        assert!(acl_lets_replace(&ancestor(&nobody_can_write()), false, &allowed));
        // The sticky bit limits nobody to adding entries and removing its own.
        assert!(!acl_lets_replace(&ancestor(&nobody_can_write()), true, &allowed));
        // A mask without write takes write away from named entries.
        let mut masked = nobody_can_write();
        masked[3] = entry(ACL_MASK, 5, u32::MAX);
        assert!(!acl_lets_replace(&ancestor(&masked), false, &allowed));
        // The current user, named by the rule, may write.
        let mut current_user = nobody_can_write();
        current_user[1] = entry(ACL_USER, 7, 1000);
        assert!(!acl_lets_replace(&ancestor(&current_user), false, &allowed));
    }

    // oracle: intent crates/private-fs/INTENT.md §paths
    #[test]
    fn a_named_group_that_can_write_makes_a_directory_replaceable() {
        let allowed = Allowed::new_for_tests(None);
        let mut group = nobody_can_write();
        group[1] = entry(ACL_GROUP, 7, 100);
        assert!(acl_lets_replace(&ancestor(&group), false, &allowed));
        // Root's group too: its members need not be root.
        group[1] = entry(ACL_GROUP, 7, 0);
        assert!(acl_lets_replace(&ancestor(&group), false, &allowed));
    }

    // With an ACL, the mode's group bits are the mask, so the owning group's write comes from its entry.
    // oracle: spec acl(5) §ACCESS CHECK ALGORITHM
    #[test]
    fn the_owning_group_writes_only_through_its_entry_and_the_mask() {
        assert_eq!(owning_group_writes(&ancestor(&nobody_can_write())), Some(false));
        let mut group_writes = nobody_can_write();
        group_writes[2] = entry(ACL_GROUP_OBJ, 7, u32::MAX);
        assert_eq!(owning_group_writes(&ancestor(&group_writes)), Some(true));
        group_writes[3] = entry(ACL_MASK, 5, u32::MAX);
        assert_eq!(owning_group_writes(&ancestor(&group_writes)), Some(false));
        assert_eq!(owning_group_writes(&AncestorAcl(None)), None);
    }

    // oracle: spec Linux include/uapi/linux/magic.h
    #[test]
    fn recognizes_volumes_that_fake_ownership() {
        // CIFS_SUPER_MAGIC as a 64-bit platform reports it, and as a 32-bit one does, sign-extended.
        assert!(ignores_ownership(0xFF53_4D42));
        assert!(ignores_ownership(i128::from(0xFF53_4D42u32.cast_signed())));
        // EXT4_SUPER_MAGIC and TMPFS_MAGIC.
        assert!(!ignores_ownership(0xEF53));
        assert!(!ignores_ownership(0x0102_1994));
    }
}
