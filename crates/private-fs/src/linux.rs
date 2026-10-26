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

use crate::unix::{Allowed, admin_gid};
use crate::{Error, Refusal, Result};

/// Groups whose write access to a directory above doesn't count: root's.
pub(crate) const ADMIN_GIDS: &[libc::gid_t] = &[0];

const ACCESS_ACL: &CStr = c"system.posix_acl_access";
const DEFAULT_ACL: &CStr = c"system.posix_acl_default";
const ACL_VERSION: u32 = 2;
/// `XATTR_SIZE_MAX`, the largest extended attribute value the kernel stores.
const XATTR_SIZE_MAX: usize = 65536;

const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_GROUP: u16 = 0x08;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;
const ACL_WRITE: u16 = 0x02;
/// Read, write and execute, the permissions a missing mask leaves.
const ACL_ALL: u16 = 0x07;

/// The `statfs` types of volumes that ignore or fake ownership: FUSE, CIFS, SMB2, SMB, NFS, 9P, vboxsf, MSDOS/vfat and
/// exFAT.
const IGNORING_VOLUMES: [u32; 9] = [
    0x6573_5546,
    0xFF53_4D42,
    0xFE53_4D42,
    0x0000_517B,
    0x0000_6969,
    0x0102_1997,
    0x786F_4256,
    0x0000_4D44,
    0x2011_BAB0,
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
    // When changing this, check a file on a FUSE or SMB mount and on a vfat image, and one on ext4.
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

/// Reports whether a named user or group entry of `acl` lets an account that `allowed` doesn't name write, so rename or
/// replace entries, unless the sticky bit limits writers to adding entries and removing their own.
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
                ACL_GROUP => !admin_gid(entry.id),
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
    // SAFETY: The descriptor is open and both names are NUL-terminated.
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            fd,
            from.as_ptr(),
            fd,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
fn read_xattr(get: impl FnOnce(*mut libc::c_void, usize) -> isize) -> io::Result<Option<Vec<AclEntry>>> {
    let mut buffer = vec![0u8; XATTR_SIZE_MAX];
    let size = get(buffer.as_mut_ptr().cast(), buffer.len());
    let Ok(size) = usize::try_from(size) else {
        let error = io::Error::last_os_error();
        return if no_acl(&error) { Ok(None) } else { Err(error) };
    };
    buffer.truncate(size);
    parse_acl(&buffer).map(Some)
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
    use std::io::Write as _;

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
    fn a_named_group_other_than_root_that_can_write_makes_a_directory_replaceable() {
        let allowed = Allowed::new_for_tests(None);
        let mut group = nobody_can_write();
        group[1] = entry(ACL_GROUP, 7, 100);
        assert!(acl_lets_replace(&ancestor(&group), false, &allowed));
        group[1] = entry(ACL_GROUP, 7, 0);
        assert!(!acl_lets_replace(&ancestor(&group), false, &allowed));
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

    /// A directory under the system temporary directory, removed when dropped.
    struct Scratch(camino::Utf8PathBuf);

    impl Scratch {
        fn new(test: &str) -> Self {
            let path = camino::Utf8PathBuf::from_path_buf(std::env::temp_dir())
                .expect("UTF-8 temporary directory")
                .join(format!("private-fs-{test}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir(&path).expect("create a scratch directory");
            set_mode(&path, 0o700);
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn set_mode(path: &Utf8Path, mode: u32) {
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode)).expect("set a test mode");
    }

    fn rule() -> crate::Rule {
        crate::Rule::new()
            .owner(crate::Account::CurrentUser)
            .grant(crate::Account::CurrentUser, crate::Access::Full)
    }

    /// Sets the ACL attribute `name` of `path` as `setfacl` would, and returns `false` when the volume has no ACLs.
    fn set_acl(path: &Utf8Path, name: &CStr, entries: &[[u8; 8]]) -> bool {
        let path = CString::new(path.as_str()).expect("NUL-free path");
        let value = attribute(entries);
        // SAFETY: The path and name are NUL-terminated, and the value is readable for its length.
        let status = unsafe { libc::setxattr(path.as_ptr(), name.as_ptr(), value.as_ptr().cast(), value.len(), 0) };
        if status == 0 {
            return true;
        }
        let error = io::Error::last_os_error();
        assert!(no_acl(&error), "set a test ACL: {error}");
        // The test harness captures `eprintln!` output from a passing test, but not direct writes to stderr.
        let _ = writeln!(io::stderr(), "SKIP: the temporary directory's volume has no POSIX ACLs");
        false
    }

    fn refusal(error: &Error) -> Option<&Refusal> {
        match error.kind() {
            crate::ErrorKind::Refused(refusal) => Some(refusal),
            crate::ErrorKind::Io { .. } | crate::ErrorKind::Unsupported { .. } => None,
        }
    }

    /// `setfacl -m u:nobody:r,m::-` on a file with mode 0600: nobody is named, and the mask leaves it nothing, so the
    /// mode still reads 0600.
    fn nobody_named() -> [[u8; 8]; 5] {
        [
            entry(ACL_USER_OBJ, 6, u32::MAX),
            entry(ACL_USER, 4, NOBODY),
            entry(ACL_GROUP_OBJ, 0, u32::MAX),
            entry(ACL_MASK, 0, u32::MAX),
            entry(ACL_OTHER, 0, u32::MAX),
        ]
    }

    // A named entry is an access the mode doesn't show, and a mask change can open it up.
    // oracle: intent crates/private-fs/INTENT.md §mechanisms
    #[test]
    fn a_file_with_a_named_acl_entry_is_refused() {
        let scratch = Scratch::new("named-entry");
        let base = crate::Dir::create_base(&scratch.0, &rule()).expect("open the scratch directory");
        drop(
            base.create_file("key", &rule(), crate::FileOptions::new())
                .expect("create a file"),
        );
        if !set_acl(&scratch.0.join("key"), ACCESS_ACL, &nobody_named()) {
            return;
        }
        assert_eq!(
            std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(scratch.0.join("key")).expect("inspect")) & 0o777,
            0o600
        );

        let error = base
            .open_file("key", &rule(), crate::FileOptions::new())
            .expect_err("refused");
        assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");
    }

    // A new entry would inherit the default ACL, and so not have exactly its rule from the moment it exists.
    // oracle: intent crates/private-fs/INTENT.md §paths
    #[test]
    fn a_default_acl_refuses_creation_until_repaired() {
        let scratch = Scratch::new("default-acl");
        let base = crate::Dir::create_base(&scratch.0, &rule()).expect("open the scratch directory");
        let parent = base
            .create_dir("parent", &rule(), crate::Existing::Check)
            .expect("create a directory");
        let default = [
            entry(ACL_USER_OBJ, 7, u32::MAX),
            entry(ACL_GROUP_OBJ, 0, u32::MAX),
            entry(ACL_OTHER, 0, u32::MAX),
        ];
        if !set_acl(&scratch.0.join("parent"), DEFAULT_ACL, &default) {
            return;
        }

        let error = parent
            .create_file("file", &rule(), crate::FileOptions::new())
            .expect_err("refused");
        assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");
        assert!(!scratch.0.join("parent").join("file").exists());
        let error = parent.check(&rule()).expect_err("refused");
        assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");

        parent.repair(&rule()).expect("repair");
        drop(
            parent
                .create_file("file", &rule(), crate::FileOptions::new())
                .expect("create a file"),
        );
    }

    // StrictModes: a named user who can write to a directory above can rename or replace its entries.
    // oracle: intent crates/private-fs/INTENT.md §paths
    #[test]
    fn a_directory_above_that_a_named_user_can_write_is_refused() {
        let scratch = Scratch::new("ancestor-acl");
        let shared = scratch.0.join("shared");
        std::fs::create_dir(&shared).expect("create a directory");
        set_mode(&shared, 0o755);
        // The mask makes the mode read 0775, but the owning group can't write: only the named entry can.
        if !set_acl(&shared, ACCESS_ACL, &nobody_can_write()) {
            return;
        }

        let error = crate::Dir::create_base(&shared.join("base"), &rule()).expect_err("refused");
        assert!(matches!(refusal(&error), Some(Refusal::Replaceable)), "{error:?}");

        set_mode(&shared, 0o1775);
        crate::Dir::create_base(&shared.join("base"), &rule()).expect("accepted with the sticky bit");
    }
}
