//! private-fs on Linux and macOS, through its public API on real directories.
//!
//! Each test works in its own directory under the system temporary directory, whose ancestors are root's.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::os::unix::net::UnixListener;
use std::process::Command;

use camino::{Utf8Path, Utf8PathBuf};
use private_fs::{
    Access, Account, Dir, EntryKind, Error, ErrorKind, Existing, Fallback, FileOptions, Refusal, Replace, Rule, Share,
};
use rstest::rstest;

/// A directory owned by the test's account, with mode 0700, removed when dropped.
struct Scratch {
    _dir: tempfile::TempDir,
    path: Utf8PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("create a temporary directory");
        let path = Utf8PathBuf::from_path_buf(dir.path().to_owned()).expect("UTF-8 temporary directory");
        Self { _dir: dir, path }
    }

    fn base(&self) -> Dir {
        Dir::create_base(&self.path, &rule()).expect("open the scratch directory")
    }

    /// Reports whether the test runs as root, which owns what it creates.
    fn as_root(&self) -> bool {
        fs::metadata(&self.path).expect("inspect the scratch directory").uid() == 0
    }
}

/// The rule of a directory or file only the current user and root may own and access.
fn rule() -> Rule {
    Rule::new()
        .owner(Account::CurrentUser)
        .owner(Account::System)
        .grant(Account::CurrentUser, Access::Full)
        .grant(Account::System, Access::Full)
}

fn refusal(error: &Error) -> Option<&Refusal> {
    match error.kind() {
        ErrorKind::Refused(refusal) => Some(refusal),
        ErrorKind::Io { .. } | ErrorKind::Unsupported { .. } => None,
    }
}

fn unsupported(error: &Error) -> Option<(Account, Access)> {
    match error.kind() {
        ErrorKind::Unsupported { account, access } => Some((*account, *access)),
        ErrorKind::Io { .. } | ErrorKind::Refused(_) => None,
    }
}

fn mode(path: &Utf8Path) -> u32 {
    fs::symlink_metadata(path).expect("inspect a test path").mode() & 0o7777
}

fn set_mode(path: &Utf8Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set a test path's mode");
}

fn canonical(path: &Utf8Path) -> Utf8PathBuf {
    Utf8PathBuf::from_path_buf(fs::canonicalize(path).expect("resolve a test path")).expect("UTF-8 test path")
}

fn skip(test: &str, reason: &str) {
    // The test harness captures `eprintln!` output from a passing test, but not direct writes to stderr.
    let _ = writeln!(std::io::stderr(), "SKIP: {test} {reason}");
}

#[cfg(target_os = "linux")]
mod acl {
    //! POSIX ACLs, set without `setfacl`, which a CI runner may lack.
    //!
    //! They are written as the kernel reads them from the `system.posix_acl_access` and `system.posix_acl_default`
    //! extended attributes: a 4-byte little-endian version, 2, then 8-byte entries of a 2-byte tag, a 2-byte
    //! permission set and a 4-byte ID, as `include/uapi/linux/posix_acl_xattr.h` defines them.

    use std::ffi::{CStr, CString};
    use std::os::unix::fs::MetadataExt as _;

    use camino::Utf8Path;

    const ACCESS: &CStr = c"system.posix_acl_access";
    const DEFAULT: &CStr = c"system.posix_acl_default";
    const USER_OBJ: u16 = 0x01;
    const USER: u16 = 0x02;
    const GROUP_OBJ: u16 = 0x04;
    const MASK: u16 = 0x10;
    const OTHER: u16 = 0x20;
    /// The ID of an entry that names no account.
    const NO_ID: u32 = u32::MAX;
    const NOBODY: u32 = 65534;

    /// Sets the ACL attribute `name` of `path`, and returns `false` when its volume has no POSIX ACLs.
    fn set(path: &Utf8Path, name: &CStr, entries: &[(u16, u16, u32)]) -> bool {
        let mut value = 2u32.to_le_bytes().to_vec();
        for &(tag, perm, id) in entries {
            value.extend_from_slice(&tag.to_le_bytes());
            value.extend_from_slice(&perm.to_le_bytes());
            value.extend_from_slice(&id.to_le_bytes());
        }
        let path = CString::new(path.as_str()).expect("NUL-free test path");
        // SAFETY: The path and name are NUL-terminated, and the value is readable for its length.
        let status = unsafe { libc::setxattr(path.as_ptr(), name.as_ptr(), value.as_ptr().cast(), value.len(), 0) };
        if status == 0 {
            return true;
        }
        let error = std::io::Error::last_os_error();
        assert_eq!(error.raw_os_error(), Some(libc::EOPNOTSUPP), "set a test ACL: {error}");
        false
    }

    /// The owner's permissions, which an access ACL's owner entry must repeat.
    fn owner_perm(path: &Utf8Path) -> u16 {
        let mode = std::fs::metadata(path).expect("inspect a test path").mode();
        u16::try_from((mode >> 6) & 0o7).expect("three permission bits")
    }

    /// Names nobody with read access, behind a mask that leaves it none, so the mode doesn't change.
    pub(super) fn name_another_account(path: &Utf8Path) -> bool {
        let entries = [
            (USER_OBJ, owner_perm(path), NO_ID),
            (USER, 4, NOBODY),
            (GROUP_OBJ, 0, NO_ID),
            (MASK, 0, NO_ID),
            (OTHER, 0, NO_ID),
        ];
        set(path, ACCESS, &entries)
    }

    /// Gives the directory `path` a default ACL, which new entries inherit.
    pub(super) fn make_inheritable(path: &Utf8Path) -> bool {
        set(
            path,
            DEFAULT,
            &[(USER_OBJ, 7, NO_ID), (GROUP_OBJ, 0, NO_ID), (OTHER, 0, NO_ID)],
        )
    }

    /// Lets nobody write to the directory `path`, while its owning group can only read and search.
    ///
    /// The mode's group bits then show the mask, rwx.
    pub(super) fn let_others_replace(path: &Utf8Path) -> bool {
        let entries = [
            (USER_OBJ, 7, NO_ID),
            (USER, 7, NOBODY),
            (GROUP_OBJ, 5, NO_ID),
            (MASK, 7, NO_ID),
            (OTHER, 5, NO_ID),
        ];
        set(path, ACCESS, &entries)
    }
}

/// Extended ACLs, set with `chmod +a`.
#[cfg(target_os = "macos")]
mod acl {
    use std::process::Command;

    use camino::Utf8Path;

    fn add(path: &Utf8Path, entry: &str) -> bool {
        Command::new("chmod")
            .args(["+a", entry, path.as_str()])
            .status()
            .is_ok_and(|status| status.success())
    }

    /// Gives everyone read access, which leaves the mode as it is.
    pub(super) fn name_another_account(path: &Utf8Path) -> bool {
        add(path, "everyone allow read")
    }

    pub(super) fn make_inheritable(path: &Utf8Path) -> bool {
        add(path, "everyone allow read,file_inherit,directory_inherit")
    }

    pub(super) fn let_others_replace(path: &Utf8Path) -> bool {
        add(path, "everyone allow delete_child")
    }
}

// A backend that created directories with the process umask's mode, or only the last one, would leave a new
// directory open to other accounts.
// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn create_base_creates_each_missing_directory_owner_only() {
    let scratch = Scratch::new();
    let path = scratch.path.join("data").join("keys");
    Dir::create_base(&path, &rule()).unwrap();
    assert_eq!(mode(&scratch.path.join("data")), 0o700);
    assert_eq!(mode(&path), 0o700);
    assert!(Dir::open_base(&path, &rule()).unwrap().is_some());
}

// A directory another process created first, open to other accounts, must not count as created.
// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn an_existing_directory_open_to_others_is_refused_until_repaired() {
    let scratch = Scratch::new();
    let shared = scratch.path.join("shared");
    fs::create_dir(&shared).unwrap();
    set_mode(&shared, 0o755);
    let base = scratch.base();

    let error = base.create_dir("shared", &rule(), Existing::Check).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");
    assert_eq!(mode(&shared), 0o755, "a check changed the directory");

    base.create_dir("shared", &rule(), Existing::Repair).unwrap();
    assert_eq!(mode(&shared), 0o700);
    assert!(base.open_dir("shared", &rule(), Share::Shared).unwrap().is_some());
}

// Catches an exact check that accepted a mode taking access away from the owner, which a repair then never resets.
// oracle: intent crates/private-fs/INTENT.md §vocabulary
#[test]
fn an_exact_rule_requires_the_rule_s_mode_and_a_repair_restores_it() {
    let scratch = Scratch::new();
    let base = scratch.base();
    drop(base.create_dir("dir", &rule(), Existing::Check).unwrap());
    let dir = scratch.path.join("dir");
    set_mode(&dir, 0o500);

    assert!(base.open_dir("dir", &rule(), Share::Shared).unwrap().is_some());
    let error = base.open_dir("dir", &rule().exact(), Share::Shared).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");

    base.create_dir("dir", &rule().exact(), Existing::Repair).unwrap();
    assert_eq!(mode(&dir), 0o700);
}

// Catches a repair that opens the directory first, which could never fix one whose mode shuts out its own owner.
// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_directory_its_owner_cannot_open_is_repaired() {
    let scratch = Scratch::new();
    if scratch.as_root() {
        skip(
            "a_directory_its_owner_cannot_open_is_repaired",
            "needs an account other than root, which opens any directory",
        );
        return;
    }
    let base = scratch.base();
    drop(base.create_dir("locked", &rule(), Existing::Check).unwrap());
    let locked = scratch.path.join("locked");
    set_mode(&locked, 0o000);

    assert!(base.create_dir("locked", &rule(), Existing::Check).is_err());
    assert_eq!(mode(&locked), 0o000, "a check changed the directory");

    base.create_dir("locked", &rule(), Existing::Repair).unwrap();
    assert_eq!(mode(&locked), 0o700);
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_symbolic_link_from_the_first_existing_directory_down_is_refused() {
    let scratch = Scratch::new();
    fs::create_dir(scratch.path.join("real")).unwrap();
    set_mode(&scratch.path.join("real"), 0o700);
    let link = scratch.path.join("link");
    symlink(scratch.path.join("real"), &link).unwrap();

    let error = Dir::create_base(&link.join("new"), &rule()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Link)), "{error:?}");
    assert_eq!(error.path(), link);
    assert!(!scratch.path.join("real").join("new").exists());

    let error = Dir::open_base(&link, &rule()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Link)), "{error:?}");
}

// oracle: intent crates/private-fs/INTENT.md §mechanisms
#[test]
fn an_entry_that_is_a_symbolic_link_is_refused() {
    let scratch = Scratch::new();
    let base = scratch.base();
    let real = base.create_dir("real", &rule(), Existing::Check).unwrap();
    drop(real.create_file("file", &rule(), FileOptions::new()).unwrap());
    symlink("real", scratch.path.join("dir-link")).unwrap();
    symlink("real/file", scratch.path.join("file-link")).unwrap();

    let error = base.open_dir("dir-link", &rule(), Share::Shared).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Link)), "{error:?}");
    let error = base
        .open_file("file-link", &rule(), FileOptions::new().read(true))
        .unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Link)), "{error:?}");
}

// Another hard link lets whoever can reach it in another directory open the file.
// oracle: intent crates/private-fs/INTENT.md §mechanisms
#[test]
fn a_file_with_another_hard_link_is_refused() {
    let scratch = Scratch::new();
    let base = scratch.base();
    drop(base.create_file("key", &rule(), FileOptions::new()).unwrap());
    fs::hard_link(scratch.path.join("key"), scratch.path.join("other")).unwrap();

    let error = base.open_file("key", &rule(), FileOptions::new()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Link)), "{error:?}");
}

// oracle: intent crates/private-fs/INTENT.md §mechanisms
#[test]
fn a_file_readable_by_others_is_refused() {
    let scratch = Scratch::new();
    let base = scratch.base();
    drop(base.create_file("key", &rule(), FileOptions::new()).unwrap());
    assert_eq!(mode(&scratch.path.join("key")), 0o600);
    set_mode(&scratch.path.join("key"), 0o644);

    let error = base.open_file("key", &rule(), FileOptions::new()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");
}

#[derive(Debug)]
enum Special {
    Fifo,
    Socket,
    Directory,
}

// Opening a FIFO for reading blocks until a writer comes, unless the open doesn't wait.
// oracle: mutant a check that takes a FIFO or a socket for a regular file
#[rstest]
#[case::fifo(Special::Fifo)]
#[case::socket(Special::Socket)]
#[case::directory(Special::Directory)]
fn an_entry_that_is_not_a_regular_file_is_refused_without_blocking(#[case] special: Special) {
    let scratch = Scratch::new();
    let path = scratch.path.join("entry");
    let _listener = match special {
        Special::Fifo => {
            assert!(Command::new("mkfifo").arg(&path).status().unwrap().success());
            None
        }
        Special::Socket => Some(UnixListener::bind(&path).unwrap()),
        Special::Directory => {
            fs::create_dir(&path).unwrap();
            None
        }
    };
    set_mode(&path, 0o600);
    let base = scratch.base();

    let error = base
        .open_file("entry", &rule(), FileOptions::new().read(true))
        .unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::NotAFile)), "{error:?}");
}

// StrictModes: another account that can write to a directory above can rename it and put its own in its place.
// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_directory_above_that_others_can_write_is_refused() {
    let scratch = Scratch::new();
    let shared = scratch.path.join("shared");
    fs::create_dir(&shared).unwrap();
    set_mode(&shared, 0o777);

    let error = Dir::create_base(&shared.join("base"), &rule()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Replaceable)), "{error:?}");
    assert_eq!(error.path(), canonical(&shared));
    assert!(!shared.join("base").exists());
}

// A missing directory has nothing to protect, so opening it reports it missing whatever the directories above allow.
// oracle: intent crates/device-key/INTENT.md §Operations
#[test]
fn a_missing_directory_under_a_replaceable_one_is_reported_missing() {
    let scratch = Scratch::new();
    let shared = scratch.path.join("shared");
    fs::create_dir(&shared).unwrap();
    set_mode(&shared, 0o777);

    assert!(Dir::open_base(&shared.join("missing"), &rule()).unwrap().is_none());
    let error = Dir::open_base(&shared, &rule()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Replaceable)), "{error:?}");
}

// Any member of the group can rename or replace the directory's entries, and administrators are root alone.
// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_directory_above_that_its_group_can_write_is_refused() {
    let scratch = Scratch::new();
    let shared = scratch.path.join("shared");
    fs::create_dir(&shared).unwrap();
    set_mode(&shared, 0o770);

    let error = Dir::open_base(&shared, &rule()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Replaceable)), "{error:?}");
    assert_eq!(error.path(), canonical(&shared));
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn the_parent_of_the_first_existing_directory_is_checked() {
    // Catches an ancestor walk that starts above the parent of the directory it opened.
    let scratch = Scratch::new();
    let shared = scratch.path.join("shared");
    fs::create_dir(&shared).unwrap();
    fs::create_dir(shared.join("base")).unwrap();
    set_mode(&shared.join("base"), 0o700);
    set_mode(&shared, 0o770);

    let error = Dir::open_base(&shared.join("base"), &rule()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Replaceable)), "{error:?}");
    assert_eq!(error.path(), canonical(&shared));
}

// A member of root's group need not be root, as members of `wheel` and `admin` on macOS are not.
// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn root_only_a_directory_above_that_roots_group_can_write_is_refused() {
    let scratch = Scratch::new();
    if !scratch.as_root() {
        skip(
            "root_only_a_directory_above_that_roots_group_can_write_is_refused",
            "needs root",
        );
        return;
    }
    let shared = scratch.path.join("shared");
    fs::create_dir(&shared).unwrap();
    std::os::unix::fs::chown(&shared, None, Some(0)).unwrap();
    set_mode(&shared, 0o770);

    let error = Dir::create_base(&shared.join("base"), &rule()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Replaceable)), "{error:?}");
    assert_eq!(error.path(), canonical(&shared));
}

// With the sticky bit, other accounts can only add entries and remove their own, as in /tmp.
// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_directory_above_where_others_can_only_add_entries_is_accepted() {
    let scratch = Scratch::new();
    let shared = scratch.path.join("shared");
    fs::create_dir(&shared).unwrap();
    set_mode(&shared, 0o1777);

    Dir::create_base(&shared.join("base"), &rule()).unwrap();
    assert_eq!(mode(&shared.join("base")), 0o700);
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_directory_above_that_an_acl_lets_others_replace_is_refused() {
    let scratch = Scratch::new();
    let shared = scratch.path.join("shared");
    fs::create_dir(&shared).unwrap();
    set_mode(&shared, 0o755);
    if !acl::let_others_replace(&shared) {
        skip(
            "a_directory_above_that_an_acl_lets_others_replace_is_refused",
            "needs ACL support",
        );
        return;
    }

    let error = Dir::create_base(&shared.join("base"), &rule()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Replaceable)), "{error:?}");
    assert_eq!(error.path(), canonical(&shared));
}

// A POSIX ACL entry is group-class access, which the sticky bit limits as it does the mode's group bits.
// oracle: intent crates/private-fs/INTENT.md §paths
#[cfg(target_os = "linux")]
#[test]
fn a_directory_above_that_an_acl_lets_others_write_is_accepted_with_the_sticky_bit() {
    let scratch = Scratch::new();
    let shared = scratch.path.join("shared");
    fs::create_dir(&shared).unwrap();
    set_mode(&shared, 0o1755);
    if !acl::let_others_replace(&shared) {
        skip(
            "a_directory_above_that_an_acl_lets_others_write_is_accepted_with_the_sticky_bit",
            "needs ACL support",
        );
        return;
    }

    Dir::create_base(&shared.join("base"), &rule()).unwrap();
}

// A directory above whose entries can't be read could hide a replaceable directory from the check.
// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_directory_that_cannot_be_searched_is_unreadable() {
    let scratch = Scratch::new();
    if scratch.as_root() {
        skip(
            "a_directory_that_cannot_be_searched_is_unreadable",
            "needs an account other than root",
        );
        return;
    }
    let locked = scratch.path.join("locked");
    fs::create_dir_all(locked.join("inner")).unwrap();
    set_mode(&locked, 0o000);

    let result = Dir::create_base(&locked.join("inner").join("base"), &rule());
    set_mode(&locked, 0o700);
    let error = result.unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Unreadable(_))), "{error:?}");
    assert_eq!(error.path(), locked);
    assert!(!locked.join("inner").join("base").exists());
}

// A link reached while looking for the first existing directory is refused as a link, even when what it points to
// can't be searched.
// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_link_to_a_directory_that_cannot_be_searched_is_a_link() {
    let scratch = Scratch::new();
    if scratch.as_root() {
        skip(
            "a_link_to_a_directory_that_cannot_be_searched_is_a_link",
            "needs an account other than root",
        );
        return;
    }
    let locked = scratch.path.join("locked");
    fs::create_dir_all(locked.join("inner")).unwrap();
    let link = scratch.path.join("link");
    symlink(&locked, &link).unwrap();
    set_mode(&locked, 0o000);

    let result = Dir::create_base(&link.join("inner").join("base"), &rule());
    set_mode(&locked, 0o700);
    let error = result.unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Link)), "{error:?}");
    assert_eq!(error.path(), link);
}

// oracle: intent crates/private-fs/INTENT.md §mechanisms
#[test]
fn a_file_with_an_extended_acl_is_refused() {
    let scratch = Scratch::new();
    let base = scratch.base();
    drop(base.create_file("key", &rule(), FileOptions::new()).unwrap());
    if !acl::name_another_account(&scratch.path.join("key")) {
        skip("a_file_with_an_extended_acl_is_refused", "needs ACL support");
        return;
    }
    // Only the ACL can fail the check.
    assert_eq!(mode(&scratch.path.join("key")), 0o600);

    let error = base.open_file("key", &rule(), FileOptions::new()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");
}

// A new entry would inherit the parent's inheritable ACL, and so not have exactly its rule from the moment it exists.
// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn nothing_is_created_under_an_inheritable_acl() {
    let scratch = Scratch::new();
    let base = scratch.base();
    let parent = base.create_dir("parent", &rule(), Existing::Check).unwrap();
    drop(parent.create_dir("existing", &rule(), Existing::Check).unwrap());
    drop(
        parent
            .create_file("existing-file", &rule(), FileOptions::new())
            .unwrap(),
    );
    if !acl::make_inheritable(&scratch.path.join("parent")) {
        skip("nothing_is_created_under_an_inheritable_acl", "needs ACL support");
        return;
    }

    let error = parent.create_dir("dir", &rule(), Existing::Check).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");
    let error = parent.create_file("file", &rule(), FileOptions::new()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");
    assert!(!scratch.path.join("parent").join("dir").exists());
    assert!(!scratch.path.join("parent").join("file").exists());

    // What already exists inherited nothing, so it is checked as it is, and an existing file still fails a creation as
    // existing.
    parent.create_dir("existing", &rule(), Existing::Check).unwrap();
    let error = parent
        .create_file("existing-file", &rule(), FileOptions::new())
        .unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::Io { source, .. } if source.kind() == std::io::ErrorKind::AlreadyExists),
        "{error:?}"
    );

    let error = parent.check(&rule()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");

    parent.repair(&rule()).unwrap();
    drop(parent.create_file("file", &rule(), FileOptions::new()).unwrap());
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn repair_removes_an_extended_acl() {
    let scratch = Scratch::new();
    let base = scratch.base();
    drop(base.create_dir("dir", &rule(), Existing::Check).unwrap());
    if !acl::name_another_account(&scratch.path.join("dir")) || !acl::make_inheritable(&scratch.path.join("dir")) {
        skip("repair_removes_an_extended_acl", "needs ACL support");
        return;
    }
    let error = base.create_dir("dir", &rule(), Existing::Check).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");

    base.create_dir("dir", &rule(), Existing::Repair).unwrap();
    base.create_dir("dir", &rule(), Existing::Check).unwrap();
}

// Root can access everything, so only root can give the test a directory or file that another account owns.
// oracle: intent crates/private-fs/INTENT.md §mechanisms
#[test]
fn root_only_an_item_owned_by_another_account_is_refused_until_repaired() {
    let scratch = Scratch::new();
    if !scratch.as_root() {
        skip(
            "root_only_an_item_owned_by_another_account_is_refused_until_repaired",
            "needs root",
        );
        return;
    }
    let other = 12345;
    let base = scratch.base();
    drop(base.create_dir("dir", &rule(), Existing::Check).unwrap());
    drop(base.create_file("file", &rule(), FileOptions::new()).unwrap());
    std::os::unix::fs::chown(scratch.path.join("dir"), Some(other), None).unwrap();
    std::os::unix::fs::chown(scratch.path.join("file"), Some(other), None).unwrap();

    let error = base.open_dir("dir", &rule(), Share::Shared).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Owner)), "{error:?}");
    let error = base.open_file("file", &rule(), FileOptions::new()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Owner)), "{error:?}");

    base.create_dir("dir", &rule(), Existing::Repair).unwrap();
    assert_eq!(fs::metadata(scratch.path.join("dir")).unwrap().uid(), 0);
}

// private-fs never chooses a broader access than the rule: an owner other than root can always change the mode.
// oracle: intent crates/private-fs/INTENT.md §rules
#[test]
fn a_grant_the_platform_cannot_enforce_fails_without_a_fallback() {
    let scratch = Scratch::new();
    if scratch.as_root() {
        skip(
            "a_grant_the_platform_cannot_enforce_fails_without_a_fallback",
            "needs an account other than root, which can enforce every grant",
        );
        return;
    }
    let read_write = Rule::new()
        .owner(Account::CurrentUser)
        .grant(Account::CurrentUser, Access::ReadWrite);
    let error = Dir::create_base(&scratch.path.join("dir"), &read_write).unwrap_err();
    assert_eq!(unsupported(&error), Some((Account::CurrentUser, Access::ReadWrite)));
    assert!(!scratch.path.join("dir").exists());

    let with_fallback = Rule::new().owner(Account::CurrentUser).grant_or(
        Account::CurrentUser,
        Access::ReadWrite,
        Fallback::Access(Access::Full),
    );
    Dir::create_base(&scratch.path.join("dir"), &with_fallback).unwrap();
}

// oracle: mutant an add-only grant to root on a file accepted instead of unsupported
#[test]
fn add_only_access_to_a_file_fails_without_a_fallback() {
    let scratch = Scratch::new();
    let add_only = rule().grant(Account::System, Access::AddOnly);
    let error = scratch
        .base()
        .create_file("file", &add_only, FileOptions::new())
        .unwrap_err();
    assert_eq!(unsupported(&error), Some((Account::System, Access::AddOnly)));
    assert!(!scratch.path.join("file").exists());
}

// private-fs creates what it creates owned by the current user, which the rule must allow.
// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_rule_that_does_not_let_the_current_user_own_cannot_create() {
    let scratch = Scratch::new();
    if scratch.as_root() {
        skip(
            "a_rule_that_does_not_let_the_current_user_own_cannot_create",
            "needs an account other than root, which System names",
        );
        return;
    }
    let system_only = Rule::new().owner(Account::System).grant(Account::System, Access::Full);
    let error = scratch
        .base()
        .create_dir("dir", &system_only, Existing::Check)
        .unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Owner)), "{error:?}");
    assert!(!scratch.path.join("dir").exists());
}

/// Writes the file `name` in `scratch` with `mode`, outside private-fs, and opens it.
fn plain_file(scratch: &Scratch, name: &str, mode: u32) -> (Utf8PathBuf, fs::File) {
    let path = scratch.path.join(name);
    fs::write(&path, b"content").unwrap();
    set_mode(&path, mode);
    let file = fs::File::open(&path).unwrap();
    (path, file)
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn repair_brings_a_file_open_to_others_into_line() {
    let scratch = Scratch::new();
    let (path, file) = plain_file(&scratch, "key", 0o644);
    let error = private_fs::check_file(&file, &path, &rule()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");

    private_fs::repair_file(&file, &path, &rule()).unwrap();
    // oracle: mutant a repair that leaves a file mode other than 0600 that a narrower check still accepts
    assert_eq!(mode(&path), 0o600);
    private_fs::check_file(&file, &path, &rule()).unwrap();
}

// A repair that failed on a file, for example on removing a default ACL that only a directory can have, would never
// fix one.
// oracle: intent crates/private-fs/INTENT.md §mechanisms
#[test]
fn repair_removes_a_file_acl() {
    let scratch = Scratch::new();
    let (path, file) = plain_file(&scratch, "key", 0o600);
    if !acl::name_another_account(&path) {
        skip("repair_removes_a_file_acl", "needs ACL support");
        return;
    }
    let error = private_fs::check_file(&file, &path, &rule()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");

    private_fs::repair_file(&file, &path, &rule()).unwrap();
    private_fs::check_file(&file, &path, &rule()).unwrap();
}

// Changing the mode through one name changes it for every other hard link to the file.
// oracle: intent crates/private-fs/INTENT.md §mechanisms
#[test]
fn repair_leaves_a_file_with_another_hard_link_unchanged() {
    let scratch = Scratch::new();
    let (path, file) = plain_file(&scratch, "key", 0o644);
    fs::hard_link(&path, scratch.path.join("other")).unwrap();

    let error = private_fs::repair_file(&file, &path, &rule()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Link)), "{error:?}");
    assert_eq!(mode(&path), 0o644);
}

// oracle: mutant a removal that reports the inverse of whether the file existed
#[test]
fn remove_file_reports_whether_the_file_existed() {
    let scratch = Scratch::new();
    let base = scratch.base();
    drop(base.create_file("key", &rule(), FileOptions::new()).unwrap());
    assert!(base.remove_file("key").unwrap());
    assert!(!base.remove_file("key").unwrap());
}

// A discard that removed by name alone would remove whatever was installed under the name since.
// oracle: mutant a discard that removes the name although it now holds another file
#[test]
fn discard_removes_only_the_file_it_was_given() {
    let scratch = Scratch::new();
    let base = scratch.base();
    let created = base.create_file("key.tmp", &rule(), FileOptions::new()).unwrap();
    base.discard(&created, "key.tmp").unwrap();
    assert!(!scratch.path.join("key.tmp").exists());

    let renamed = base.create_file("key.tmp", &rule(), FileOptions::new()).unwrap();
    base.rename("key.tmp", "key", Replace::Refuse).unwrap();
    drop(base.create_file("key.tmp", &rule(), FileOptions::new()).unwrap());
    base.discard(&renamed, "key.tmp").unwrap();
    assert!(scratch.path.join("key.tmp").exists());
}

// A listing that followed links would report a link to a directory as a directory.
// oracle: mutant a listing that reports a symbolic link as something other than a link
#[test]
fn entries_report_kinds_without_following_links() {
    let scratch = Scratch::new();
    let base = scratch.base();
    drop(base.create_file("file", &rule(), FileOptions::new()).unwrap());
    drop(base.create_dir("dir", &rule(), Existing::Check).unwrap());
    symlink("dir", scratch.path.join("link")).unwrap();
    let _listener = UnixListener::bind(scratch.path.join("socket")).unwrap();

    let mut entries: Vec<_> = base
        .entries()
        .unwrap()
        .into_iter()
        .map(|entry| (entry.name.into_string().unwrap(), entry.kind))
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(
        entries,
        [
            ("dir".to_owned(), EntryKind::Directory),
            ("file".to_owned(), EntryKind::File),
            ("link".to_owned(), EntryKind::Link),
            ("socket".to_owned(), EntryKind::Other),
        ]
    );
}

// The agent's default macOS data directory lives under `/Library/Application Support`, as
// `crates/devolutions-agent-shared/src/lib.rs` sets it, so that directory and `/Library` must pass the check of the
// directories above a base on a stock Mac.
// The test fails rather than skips, so a stock macOS that fails the check shows on CI.
// oracle: intent crates/private-fs/INTENT.md §paths
#[cfg(target_os = "macos")]
#[test]
fn the_stock_macos_application_support_directory_is_a_valid_base() {
    let rule = Rule::new()
        .owner(Account::CurrentUser)
        .grant(Account::System, Access::Full);
    let base = Dir::open_base(Utf8Path::new("/Library/Application Support"), &rule).unwrap();
    assert!(base.is_some());
}
