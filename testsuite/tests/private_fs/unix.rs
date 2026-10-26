//! private-fs on Linux and macOS, through its public API on real directories.
//!
//! Each test works in its own directory under the system temporary directory, whose ancestors are root's.

use std::fs;
use std::io::{Read as _, Write as _};
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

/// Runs a platform command that changes a test path's ACL, and returns `false` when the platform can't run it.
fn run_acl_command(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .status()
        .is_ok_and(|status| status.success())
}

/// Gives another account read access to `path` through an extended ACL.
fn grant_others_read(path: &Utf8Path) -> bool {
    if cfg!(target_os = "macos") {
        run_acl_command("chmod", &["+a", "everyone allow read", path.as_str()])
    } else {
        run_acl_command("setfacl", &["-m", "u:65534:r", path.as_str()])
    }
}

/// Gives the directory `path` an ACL that new entries inherit.
fn make_inheritable(path: &Utf8Path) -> bool {
    if cfg!(target_os = "macos") {
        run_acl_command(
            "chmod",
            &[
                "+a",
                "everyone allow read,file_inherit,directory_inherit",
                path.as_str(),
            ],
        )
    } else {
        run_acl_command("setfacl", &["-d", "-m", "u::rwx", path.as_str()])
    }
}

/// Lets another account remove or rename the entries of the directory `path` through an extended ACL.
fn let_others_replace(path: &Utf8Path) -> bool {
    if cfg!(target_os = "macos") {
        run_acl_command("chmod", &["+a", "everyone allow delete_child", path.as_str()])
    } else {
        run_acl_command("setfacl", &["-m", "u:65534:rwx", path.as_str()])
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

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn open_base_returns_none_for_a_missing_directory() {
    let scratch = Scratch::new();
    assert!(
        Dir::open_base(&scratch.path.join("missing"), &rule())
            .unwrap()
            .is_none()
    );
    assert!(!scratch.path.join("missing").exists());
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
// oracle: intent crates/private-fs/INTENT.md §mechanisms
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

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_directory_above_that_its_group_can_write_is_refused() {
    let scratch = Scratch::new();
    let shared = scratch.path.join("shared");
    fs::create_dir(&shared).unwrap();
    set_mode(&shared, 0o770);
    // Root's group, and `admin` on macOS, are administrators, whose write access doesn't count.
    if [0, 80].contains(&fs::metadata(&shared).unwrap().gid()) {
        skip(
            "a_directory_above_that_its_group_can_write_is_refused",
            "needs a directory group other than administrators",
        );
        return;
    }

    let error = Dir::open_base(&shared, &rule()).unwrap_err();
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
    if !let_others_replace(&shared) {
        skip(
            "a_directory_above_that_an_acl_lets_others_replace_is_refused",
            "needs ACL support and its tools",
        );
        return;
    }

    let error = Dir::create_base(&shared.join("base"), &rule()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Replaceable)), "{error:?}");
    assert_eq!(error.path(), canonical(&shared));
}

// A directory above whose entries can't be read could hide a replaceable directory from the check.
// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_path_through_a_directory_that_cannot_be_searched_fails() {
    let scratch = Scratch::new();
    if scratch.as_root() {
        skip(
            "a_path_through_a_directory_that_cannot_be_searched_fails",
            "needs an account other than root",
        );
        return;
    }
    let locked = scratch.path.join("locked");
    fs::create_dir_all(locked.join("inner")).unwrap();
    set_mode(&locked, 0o000);

    let result = Dir::create_base(&locked.join("inner").join("base"), &rule());
    set_mode(&locked, 0o700);
    assert!(result.is_err());
    assert!(!locked.join("inner").join("base").exists());
}

// oracle: intent crates/private-fs/INTENT.md §mechanisms
#[test]
fn a_file_with_an_extended_acl_is_refused() {
    let scratch = Scratch::new();
    let base = scratch.base();
    drop(base.create_file("key", &rule(), FileOptions::new()).unwrap());
    if !grant_others_read(&scratch.path.join("key")) {
        skip(
            "a_file_with_an_extended_acl_is_refused",
            "needs ACL support and its tools",
        );
        return;
    }

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
    if !make_inheritable(&scratch.path.join("parent")) {
        skip(
            "nothing_is_created_under_an_inheritable_acl",
            "needs ACL support and its tools",
        );
        return;
    }

    let error = parent.create_dir("dir", &rule(), Existing::Check).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");
    let error = parent.create_file("file", &rule(), FileOptions::new()).unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Access)), "{error:?}");
    assert_eq!(parent.entries().unwrap().len(), 0);
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn repair_removes_an_extended_acl() {
    let scratch = Scratch::new();
    let base = scratch.base();
    drop(base.create_dir("dir", &rule(), Existing::Check).unwrap());
    if !grant_others_read(&scratch.path.join("dir")) || !make_inheritable(&scratch.path.join("dir")) {
        skip("repair_removes_an_extended_acl", "needs ACL support and its tools");
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

// oracle: intent crates/private-fs/INTENT.md §rules
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
    let system_only = Rule::new().owner(Account::System).grant(Account::System, Access::Full);
    let error = scratch
        .base()
        .create_dir("dir", &system_only, Existing::Check)
        .unwrap_err();
    assert!(matches!(refusal(&error), Some(Refusal::Owner)), "{error:?}");
    assert!(!scratch.path.join("dir").exists());
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn persist_installs_the_written_file_under_its_name() {
    let scratch = Scratch::new();
    let base = scratch.base();
    let mut file = base.create_file("key.tmp", &rule(), FileOptions::new()).unwrap();
    file.write_all(b"secret").unwrap();
    base.persist(&file, "key.tmp", "key", Replace::Refuse).unwrap();

    let mut content = String::new();
    base.open_file("key", &rule(), FileOptions::new().read(true))
        .unwrap()
        .expect("persisted file")
        .read_to_string(&mut content)
        .unwrap();
    assert_eq!(content, "secret");
    assert!(
        base.open_file("key.tmp", &rule(), FileOptions::new())
            .unwrap()
            .is_none()
    );
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_rename_that_refuses_replacement_keeps_the_existing_entry() {
    let scratch = Scratch::new();
    let base = scratch.base();
    base.create_file("old", &rule(), FileOptions::new())
        .unwrap()
        .write_all(b"old")
        .unwrap();
    base.create_file("new", &rule(), FileOptions::new())
        .unwrap()
        .write_all(b"new")
        .unwrap();

    let error = base.rename("new", "old", Replace::Refuse).unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::Io { source, .. } if source.kind() == std::io::ErrorKind::AlreadyExists),
        "{error:?}"
    );
    assert_eq!(fs::read(scratch.path.join("old")).unwrap(), b"old");

    base.rename("new", "old", Replace::Allow).unwrap();
    assert_eq!(fs::read(scratch.path.join("old")).unwrap(), b"new");
    assert!(!scratch.path.join("new").exists());
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn remove_file_reports_whether_the_file_existed() {
    let scratch = Scratch::new();
    let base = scratch.base();
    drop(base.create_file("key", &rule(), FileOptions::new()).unwrap());
    assert!(base.remove_file("key").unwrap());
    assert!(!base.remove_file("key").unwrap());
}

// A listing that followed links would report a link to a directory as a directory.
// oracle: intent crates/private-fs/INTENT.md §mechanisms
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
