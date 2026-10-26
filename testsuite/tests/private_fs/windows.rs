//! Tests of the Windows backend of private-fs, which read and set owners and DACLs through the Windows API rather than
//! through private-fs.
//!
//! The access masks are the file and directory access rights of [MS-SMB2] "File_Pipe_Printer_Access_Mask" and
//! "Directory_Access_Mask", which NTFS shares.
//!
//! [MS-SMB2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/

use std::io::{Read as _, Write as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::process::{Command, Stdio};

use anyhow::Context as _;
use camino::{Utf8Path, Utf8PathBuf};
use private_fs::{
    Access, Account, BackupPrivilege, Dir, EntryKind, Error, ErrorKind, Existing, Fallback, FileOptions, Refusal,
    Replace, Rule, Share,
};
use rstest::rstest;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::process::Process;
use win_api_wrappers::raw::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use win_api_wrappers::raw::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GRANT_ACCESS, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use win_api_wrappers::raw::Win32::Security::{
    self, ACE_FLAGS, DACL_SECURITY_INFORMATION, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE,
    TOKEN_IMPERSONATE, TOKEN_QUERY, TokenImpersonation,
};
use win_api_wrappers::raw::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT};
use win_api_wrappers::security::acl::{
    Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee, set_named_security_info,
};
use win_api_wrappers::security::descriptor::SecurityDescriptor;
use win_api_wrappers::security::privilege::SE_RESTORE_NAME;
use win_api_wrappers::str::U16CString;
use win_api_wrappers::token::Token;
use windows::core::PWSTR;

/// Full access: `STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF`, the value of `FILE_ALL_ACCESS`.
const FULL: u32 = 0x001F_01FF;
/// Read and write on a directory: `FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE |
/// FILE_DELETE_CHILD`.
const READ_WRITE_DIRECTORY: u32 = 0x0013_01FF;
/// `READ_CONTROL | SYNCHRONIZE | FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES`, `FILE_GENERIC_READ`.
const READ: u32 = 0x0012_0089;
/// `FILE_DELETE_CHILD`.
const DELETE_CHILD: u32 = 0x40;
/// `FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | SYNCHRONIZE`.
const ADD_ENTRIES: u32 = 0x0010_0006;
/// `CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE`.
const INHERITED_BY_CHILDREN: u32 = 0x3;
/// `ERROR_SHARING_VIOLATION`.
const SHARING_VIOLATION: i32 = 32;
/// `ERROR_INVALID_OWNER`, which setting an owner without the restore privilege fails with.
const INVALID_OWNER: u32 = 1307;

/// A directory under the system temporary directory, whose ancestors pass the ancestor check, removed on drop.
struct TestDir(Utf8PathBuf);

impl TestDir {
    /// Returns a path under the temporary directory that doesn't exist yet.
    fn new() -> Self {
        let temp = Utf8PathBuf::from_path_buf(std::env::temp_dir()).expect("the temporary directory path is UTF-8");
        Self(temp.join(format!("pfs-{}", uuid::Uuid::new_v4().simple())))
    }

    fn path(&self) -> &Utf8Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn user() -> Sid {
    Token::current_process_token()
        .sid_and_attributes()
        .expect("read the process user")
        .sid
}

fn well_known(kind: Security::WELL_KNOWN_SID_TYPE) -> Sid {
    Sid::from_well_known(kind, None).expect("make a well-known SID")
}

fn system() -> Sid {
    well_known(Security::WinLocalSystemSid)
}

fn administrators() -> Sid {
    well_known(Security::WinBuiltinAdministratorsSid)
}

fn owner_rights() -> Sid {
    well_known(Security::WinCreatorOwnerRightsSid)
}

fn users() -> Sid {
    well_known(Security::WinBuiltinUsersSid)
}

/// A rule the current user owns with full access, which lets the test clean up.
fn user_rule() -> Rule {
    Rule::new()
        .owner(Account::CurrentUser)
        .grant(Account::CurrentUser, Access::Full)
}

/// An allow entry: its SID, access mask and ACE flags.
type AllowEntry = (Sid, u32, u32);

/// Opens `path` to read its owner and DACL, without following a reparse point.
fn open_for_security(path: &Utf8Path) -> anyhow::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .access_mode(0x0002_0000) // READ_CONTROL
        .share_mode(0x7)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
        .with_context(|| format!("open {path} to read its security"))
}

/// Reads the owner and the DACL entries of `path`, sorted, failing unless the DACL is protected and allow-only.
fn security(path: &Utf8Path) -> anyhow::Result<(Sid, Vec<AllowEntry>)> {
    security_of(&open_for_security(path)?)
}

/// Reads the owner and the DACL entries of an open file or directory, sorted, failing unless the DACL is protected and
/// allow-only.
fn security_of(file: &std::fs::File) -> anyhow::Result<(Sid, Vec<AllowEntry>)> {
    let descriptor = SecurityDescriptor::of_handle(HANDLE(file.as_raw_handle()), SE_FILE_OBJECT)?;
    let owner = descriptor.owner()?.context("no owner")?;
    let mut entries: Vec<_> = descriptor
        .protected_allow_entries()?
        .into_iter()
        .map(|entry| (entry.sid, entry.mask, entry.flags))
        .collect();
    entries.sort();
    Ok((owner, entries))
}

/// Returns the whole DACL of `path` in SDDL, protected or not, inherited entries included.
fn dacl_sddl(path: &Utf8Path) -> anyhow::Result<String> {
    let file = open_for_security(path)?;
    let descriptor = SecurityDescriptor::of_handle(HANDLE(file.as_raw_handle()), SE_FILE_OBJECT)?;
    let mut sddl = PWSTR::null();
    // SAFETY: The descriptor stays live through the call and the output is writable.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.as_raw(),
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut sddl,
            None,
        )
    }?;
    // SAFETY: The conversion returned a NUL-terminated string.
    let text = unsafe { sddl.to_string() };
    // SAFETY: The conversion allocated the string with LocalAlloc, and nothing uses it any more.
    unsafe { LocalFree(Some(HLOCAL(sddl.0.cast()))) };
    Ok(text?)
}

/// Makes `link` a directory junction to `target`, which, unlike a symbolic link, needs no privilege.
fn junction(target: &Utf8Path, link: &Utf8Path) -> anyhow::Result<()> {
    let status = Command::new("cmd")
        .args(["/C", "mklink", "/J", link.as_str(), target.as_str()])
        .stdout(Stdio::null())
        .status()?;
    anyhow::ensure!(status.success(), "mklink /J exited with {status}");
    Ok(())
}

fn sorted(mut entries: Vec<AllowEntry>) -> Vec<AllowEntry> {
    entries.sort();
    entries
}

/// Sets the DACL of `path`, through the path rather than private-fs.
fn set_dacl(path: &Utf8Path, entries: &[AllowEntry], kind: InheritableAclKind) -> anyhow::Result<()> {
    let entries: Vec<_> = entries
        .iter()
        .map(|(sid, mask, flags)| ExplicitAccess {
            access_permissions: *mask,
            access_mode: GRANT_ACCESS,
            inheritance: ACE_FLAGS(*flags),
            trustee: Trustee::Sid(sid.clone()),
        })
        .collect();
    let acl = Acl::new()?.set_entries(&entries)?;
    set_named_security_info(
        &U16CString::from_str(path.as_str())?,
        SE_FILE_OBJECT,
        None,
        None,
        Some(&InheritableAcl { kind, acl }),
        None,
    )
}

/// Makes `owner` the owner of `path` with the restore privilege, or returns `false` when the process token doesn't
/// hold it.
fn set_owner(path: &Utf8Path, owner: &Sid) -> anyhow::Result<bool> {
    let mut token = Process::current_process()
        .token(TOKEN_DUPLICATE | TOKEN_QUERY)?
        .duplicate(
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_IMPERSONATE,
            None,
            SecurityImpersonation,
            TokenImpersonation,
        )?;
    token.enable_privilege(SE_RESTORE_NAME)?;
    let _impersonation = token.impersonate()?;
    let set = set_named_security_info(
        &U16CString::from_str(path.as_str())?,
        SE_FILE_OBJECT,
        Some(owner),
        None,
        None,
        None,
    );
    match set {
        Ok(()) => Ok(true),
        Err(error)
            if error
                .downcast_ref::<windows::core::Error>()
                .is_some_and(|error| error.code() == windows::core::HRESULT::from_win32(INVALID_OWNER)) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn refusal<T>(result: private_fs::Result<T>) -> Error {
    match result {
        Ok(_) => panic!("the operation succeeded"),
        Err(error) => error,
    }
}

fn is_refused(error: &Error, expected: fn(&Refusal) -> bool) -> bool {
    matches!(error.kind(), ErrorKind::Refused(refusal) if expected(refusal))
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn create_base_gives_each_new_directory_exactly_its_rule() -> anyhow::Result<()> {
    // Catches a new directory that inherits its parent's entries, or that maps a kind of access to the wrong mask or
    // inheritance.
    let test = TestDir::new();
    let path = test.path().join("a").join("b");
    let rule = user_rule()
        .grant(Account::System, Access::Full)
        .grant(Account::Administrators, Access::ReadWrite);
    Dir::create_base(&path, &rule)?;
    let expected = sorted(vec![
        (user(), FULL, INHERITED_BY_CHILDREN),
        (system(), FULL, INHERITED_BY_CHILDREN),
        (administrators(), READ_WRITE_DIRECTORY, INHERITED_BY_CHILDREN),
    ]);
    for directory in [test.path().to_owned(), test.path().join("a"), path] {
        assert_eq!(security(&directory)?, (user(), expected.clone()), "{directory}");
    }
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §mechanisms
#[test]
fn a_created_file_takes_its_owner_s_implicit_access_away() -> anyhow::Result<()> {
    // Catches a file whose owner keeps the READ_CONTROL and WRITE_DAC that Windows gives an owner without an OWNER
    // RIGHTS entry, through which the owner can grant itself anything.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    let rule = Rule::new()
        .owner(Account::CurrentUser)
        .grant(Account::System, Access::Full);
    // The creating handle has READ_CONTROL whatever the DACL grants.
    let file = base.create_file("file", &rule, FileOptions::new())?;
    assert_eq!(
        security_of(&file)?,
        (user(), sorted(vec![(system(), FULL, 0), (owner_rights(), 0, 0)]))
    );
    Ok(())
}

// oracle: spec Microsoft Learn "Privilege Constants" §SE_BACKUP_NAME
#[test]
fn the_backup_privilege_opens_a_file_the_token_cannot() -> anyhow::Result<()> {
    // Catches a backup privilege that is not enabled on the thread, or opens that don't ask for backup intent.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    let rule = Rule::new()
        .owner(Account::CurrentUser)
        .grant(Account::System, Access::Full);
    drop(base.create_file("file", &rule, FileOptions::new())?);
    let denied = refusal(base.open_file("file", &rule, FileOptions::new()));
    assert!(
        matches!(denied.kind(), ErrorKind::Io { source, .. } if source.kind() == std::io::ErrorKind::PermissionDenied),
        "{denied:?}"
    );
    let backup = match BackupPrivilege::enable() {
        Ok(backup) => backup,
        Err(error) => {
            println!("SKIP: the process token doesn't hold the backup privilege: {error}");
            return Ok(());
        }
    };
    assert!(base.open_file("file", &rule, FileOptions::new())?.is_some());
    // Dropping the guard takes the privilege away again.
    drop(backup);
    let denied = refusal(base.open_file("file", &rule, FileOptions::new()));
    assert!(
        matches!(denied.kind(), ErrorKind::Io { source, .. } if source.kind() == std::io::ErrorKind::PermissionDenied),
        "{denied:?}"
    );
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §rules
#[test]
fn add_only_access_to_a_file_without_a_fallback_is_unsupported() -> anyhow::Result<()> {
    // Catches a grant that Windows cannot enforce on a file being widened or silently dropped.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    let rule = user_rule().grant(Account::System, Access::AddOnly);
    let error = refusal(base.create_file("file", &rule, FileOptions::new()));
    assert!(
        matches!(
            error.kind(),
            ErrorKind::Unsupported {
                account: Account::System,
                access: Access::AddOnly
            }
        ),
        "{error:?}"
    );
    assert!(!test.path().join("file").exists());
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §rules
#[test]
fn a_no_access_fallback_drops_an_unsupported_grant() -> anyhow::Result<()> {
    // Catches a fallback that is ignored, so that the file grants what the rule's fallback took away.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    let rule = user_rule().grant_or(Account::System, Access::AddOnly, Fallback::NoAccess);
    drop(base.create_file("file", &rule, FileOptions::new())?);
    assert_eq!(security(&test.path().join("file"))?, (user(), vec![(user(), FULL, 0)]));
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §mechanisms
#[test]
fn a_check_refuses_an_account_the_rule_does_not_name() -> anyhow::Result<()> {
    // Catches a check that accepts an extra allow entry.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    drop(base.create_dir("child", &user_rule(), Existing::Check)?);
    set_dacl(
        &test.path().join("child"),
        &[(user(), FULL, INHERITED_BY_CHILDREN), (users(), READ, 0)],
        InheritableAclKind::Protected,
    )?;
    let error = refusal(base.open_dir("child", &user_rule(), Share::Shared));
    assert!(
        is_refused(&error, |refusal| matches!(refusal, Refusal::Access)),
        "{error:?}"
    );
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §mechanisms
#[test]
fn a_check_refuses_an_unprotected_dacl() -> anyhow::Result<()> {
    // Catches a check that ignores inherited entries, which the parent directory decides.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    drop(base.create_dir("child", &user_rule(), Existing::Check)?);
    set_dacl(
        &test.path().join("child"),
        &[(user(), FULL, INHERITED_BY_CHILDREN)],
        InheritableAclKind::Inherit,
    )?;
    let error = refusal(base.open_dir("child", &user_rule(), Share::Shared));
    assert!(
        is_refused(&error, |refusal| matches!(refusal, Refusal::Access)),
        "{error:?}"
    );
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §vocabulary
#[test]
fn a_narrower_check_accepts_less_access_than_the_rule() -> anyhow::Result<()> {
    // Catches a default check that also requires every grant of the rule.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    drop(base.create_dir("child", &user_rule(), Existing::Check)?);
    let wider = user_rule().grant(Account::System, Access::Full);
    assert!(base.open_dir("child", &wider, Share::Shared)?.is_some());
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §vocabulary
#[test]
fn an_exact_check_refuses_less_access_than_the_rule() -> anyhow::Result<()> {
    // Catches an exact check that accepts a missing grant.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    drop(base.create_dir("child", &user_rule(), Existing::Check)?);
    let wider = user_rule().grant(Account::System, Access::Full).exact();
    let error = refusal(base.open_dir("child", &wider, Share::Shared));
    assert!(
        is_refused(&error, |refusal| matches!(refusal, Refusal::Access)),
        "{error:?}"
    );
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_repair_restores_the_rule_without_changing_what_lies_below() -> anyhow::Result<()> {
    // Catches a repair that propagates the new inheritable entries to existing children, as SetSecurityInfo does.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    let child = base.create_dir("child", &user_rule(), Existing::Check)?;
    drop(child.create_file("file", &user_rule(), FileOptions::new())?);
    drop(child);
    let file = test.path().join("child").join("file");
    // The file takes inherited entries from the directory, which a propagating repair would rewrite.
    set_dacl(&file, &[(user(), FULL, 0)], InheritableAclKind::Inherit)?;
    set_dacl(
        &test.path().join("child"),
        &[
            (user(), FULL, INHERITED_BY_CHILDREN),
            (users(), FULL, INHERITED_BY_CHILDREN),
        ],
        InheritableAclKind::Protected,
    )?;
    let file_before = dacl_sddl(&file)?;
    assert!(file_before.contains("(A;ID;FA;;;BU)"), "{file_before}");
    let rule = user_rule().exact();
    drop(base.create_dir("child", &rule, Existing::Repair)?);
    assert_eq!(
        security(&test.path().join("child"))?,
        (user(), vec![(user(), FULL, INHERITED_BY_CHILDREN)])
    );
    assert_eq!(dacl_sddl(&file)?, file_before);
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_repair_restores_a_directory_whose_dacl_grants_its_owner_nothing() -> anyhow::Result<()> {
    // Catches a repair that opens the directory with more access than its owner's implicit READ_CONTROL and WRITE_DAC,
    // which such a directory doesn't grant.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    drop(base.create_dir("child", &user_rule(), Existing::Check)?);
    let child = test.path().join("child");
    set_dacl(&child, &[(users(), READ, 0)], InheritableAclKind::Protected)?;
    let rule = user_rule().exact();
    drop(base.create_dir("child", &rule, Existing::Repair)?);
    assert_eq!(security(&child)?, (user(), vec![(user(), FULL, INHERITED_BY_CHILDREN)]));
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §mechanisms
#[test]
fn a_repair_takes_ownership_from_an_owner_the_rule_does_not_allow() -> anyhow::Result<()> {
    // Catches a check that ignores the owner, which can always rewrite the DACL, and a repair that leaves it.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    drop(base.create_dir("child", &user_rule(), Existing::Check)?);
    let child = test.path().join("child");
    if !set_owner(&child, &well_known(Security::WinLocalServiceSid))? {
        println!("SKIP: the process token doesn't hold the restore privilege");
        return Ok(());
    }
    let error = refusal(base.create_dir("child", &user_rule(), Existing::Check));
    assert!(
        is_refused(&error, |refusal| matches!(refusal, Refusal::Owner)),
        "{error:?}"
    );
    drop(base.create_dir("child", &user_rule(), Existing::Repair)?);
    assert_eq!(security(&child)?.0, user());
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §vocabulary
#[test]
fn administrators_as_an_owner_allow_a_member_of_the_group() -> anyhow::Result<()> {
    // Catches an owner check that compares with the BUILTIN\Administrators SID only.
    let token = Process::current_process().token(TOKEN_QUERY | TOKEN_DUPLICATE)?;
    if !token.is_member(&administrators())? {
        println!("SKIP: the current user is not a member of Administrators");
        return Ok(());
    }
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    drop(base.create_dir("child", &user_rule(), Existing::Check)?);
    let rule = Rule::new()
        .owner(Account::Administrators)
        .grant(Account::CurrentUser, Access::Full);
    assert!(base.open_dir("child", &rule, Share::Shared)?.is_some());
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn open_dir_refuses_a_junction() -> anyhow::Result<()> {
    // Catches an open that follows a link out of the checked directory.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    drop(base.create_dir("target", &user_rule(), Existing::Check)?);
    junction(&test.path().join("target"), &test.path().join("link"))?;
    let error = refusal(base.open_dir("link", &user_rule(), Share::Shared));
    assert!(
        is_refused(&error, |refusal| matches!(refusal, Refusal::Link)),
        "{error:?}"
    );
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn create_base_refuses_a_link_as_the_first_existing_directory() -> anyhow::Result<()> {
    // Catches a base directory resolved through a link that someone else can point elsewhere.
    let test = TestDir::new();
    Dir::create_base(&test.path().join("target"), &user_rule())?;
    junction(&test.path().join("target"), &test.path().join("link"))?;
    let error = refusal(Dir::create_base(&test.path().join("link").join("new"), &user_rule()));
    assert!(
        is_refused(&error, |refusal| matches!(refusal, Refusal::Link)),
        "{error:?}"
    );
    assert_eq!(error.path(), test.path().join("link"));
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §mechanisms
#[test]
fn open_file_refuses_a_file_with_another_hard_link() -> anyhow::Result<()> {
    // Catches a file that another name, in a directory with other access, also reaches.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    drop(base.create_file("file", &user_rule(), FileOptions::new())?);
    std::fs::hard_link(test.path().join("file"), test.path().join("other"))?;
    let error = refusal(base.open_file("file", &user_rule(), FileOptions::new()));
    assert!(
        is_refused(&error, |refusal| matches!(refusal, Refusal::Link)),
        "{error:?}"
    );
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_directory_above_whose_entries_others_can_delete_is_refused() -> anyhow::Result<()> {
    // Catches an ancestor check that misses FILE_DELETE_CHILD, through which another account can replace the base.
    let test = TestDir::new();
    std::fs::create_dir(test.path())?;
    set_dacl(
        test.path(),
        &[(user(), FULL, INHERITED_BY_CHILDREN), (users(), DELETE_CHILD, 0)],
        InheritableAclKind::Protected,
    )?;
    let error = refusal(Dir::create_base(&test.path().join("base"), &user_rule()));
    assert!(
        is_refused(&error, |refusal| matches!(refusal, Refusal::Replaceable)),
        "{error:?}"
    );
    assert_eq!(error.path(), test.path());
    Ok(())
}

// oracle: intent crates/device-key/INTENT.md §Operations
#[test]
fn a_missing_directory_under_a_replaceable_one_is_reported_missing() -> anyhow::Result<()> {
    // Catches an open that refuses a missing directory, which has nothing to protect, because of a directory above it.
    let test = TestDir::new();
    std::fs::create_dir(test.path())?;
    set_dacl(
        test.path(),
        &[(user(), FULL, INHERITED_BY_CHILDREN), (users(), DELETE_CHILD, 0)],
        InheritableAclKind::Protected,
    )?;
    assert!(Dir::open_base(&test.path().join("missing"), &user_rule())?.is_none());
    let error = refusal(Dir::open_base(test.path(), &user_rule()));
    assert!(
        is_refused(&error, |refusal| matches!(refusal, Refusal::Replaceable)),
        "{error:?}"
    );
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn a_directory_above_others_can_only_add_to_is_accepted() -> anyhow::Result<()> {
    // Catches an ancestor check that counts adding an entry beside the base as replacing it.
    let test = TestDir::new();
    std::fs::create_dir(test.path())?;
    set_dacl(
        test.path(),
        &[(user(), FULL, INHERITED_BY_CHILDREN), (users(), ADD_ENTRIES, 0)],
        InheritableAclKind::Protected,
    )?;
    Dir::create_base(&test.path().join("base"), &user_rule())?;
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn open_base_returns_none_for_a_missing_directory() -> anyhow::Result<()> {
    // Catches an open that creates what it should only open.
    let test = TestDir::new();
    assert!(Dir::open_base(&test.path().join("missing"), &user_rule())?.is_none());
    assert!(!test.path().exists());
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn persist_refusing_to_replace_keeps_the_existing_file() -> anyhow::Result<()> {
    // Catches a rename without replacement that overwrites the destination.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    base.create_file("old", &user_rule(), FileOptions::new())?
        .write_all(b"old")?;
    let mut new = base.create_file("new", &user_rule(), FileOptions::new())?;
    new.write_all(b"new")?;
    let error = refusal(base.persist(&new, "new", "old", Replace::Refuse));
    assert!(
        matches!(error.kind(), ErrorKind::Io { source, .. } if source.kind() == std::io::ErrorKind::AlreadyExists),
        "{error:?}"
    );
    assert_eq!(std::fs::read(test.path().join("old"))?, b"old");
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn persist_replacing_moves_the_content_to_the_destination() -> anyhow::Result<()> {
    // Catches a persist that renames something other than the given file, or doesn't replace.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    base.create_file("old", &user_rule(), FileOptions::new())?
        .write_all(b"old")?;
    let mut new = base.create_file("new", &user_rule(), FileOptions::new())?;
    new.write_all(b"new")?;
    base.persist(&new, "new", "old", Replace::Allow)?;
    drop(new);
    let mut content = Vec::new();
    base.open_file("old", &user_rule(), FileOptions::new().read(true))?
        .context("the destination exists")?
        .read_to_end(&mut content)?;
    assert_eq!(content, b"new");
    assert!(!test.path().join("new").exists());
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn rename_refusing_to_replace_fails_on_an_existing_entry() -> anyhow::Result<()> {
    // Catches a rename without replacement that overwrites the destination.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    base.create_file("a", &user_rule(), FileOptions::new())?
        .write_all(b"a")?;
    base.create_file("b", &user_rule(), FileOptions::new())?
        .write_all(b"b")?;
    let error = refusal(base.rename("a", "b", Replace::Refuse));
    assert!(
        matches!(error.kind(), ErrorKind::Io { source, .. } if source.kind() == std::io::ErrorKind::AlreadyExists),
        "{error:?}"
    );
    assert_eq!(std::fs::read(test.path().join("b"))?, b"b");
    base.rename("a", "c", Replace::Refuse)?;
    assert_eq!(std::fs::read(test.path().join("c"))?, b"a");
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §mechanisms
#[test]
fn entries_lists_each_entry_with_its_kind() -> anyhow::Result<()> {
    // Catches a listing that follows links or misses entries.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    drop(base.create_file("file", &user_rule(), FileOptions::new())?);
    drop(base.create_dir("directory", &user_rule(), Existing::Check)?);
    junction(&test.path().join("directory"), &test.path().join("link"))?;
    let expected = vec![
        ("directory".to_owned(), EntryKind::Directory),
        ("file".to_owned(), EntryKind::File),
        ("link".to_owned(), EntryKind::Link),
    ];
    // The second listing checks that each listing starts from the first entry.
    for _ in 0..2 {
        let mut entries: Vec<_> = base
            .entries()?
            .into_iter()
            .map(|entry| (entry.name.into_string().expect("UTF-16 name"), entry.kind))
            .collect();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(entries, expected);
    }
    Ok(())
}

// oracle: intent crates/private-fs/INTENT.md §paths
#[test]
fn remove_file_reports_whether_the_file_existed() -> anyhow::Result<()> {
    // Catches a removal that fails on a missing file or leaves the file.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    drop(base.create_file("file", &user_rule(), FileOptions::new())?);
    assert!(base.remove_file("file")?);
    assert!(!test.path().join("file").exists());
    assert!(!base.remove_file("file")?);
    Ok(())
}

// oracle: spec MS-ERREF §2.2 ERROR_SHARING_VIOLATION
#[test]
fn an_exclusive_open_makes_another_open_fail_with_a_sharing_violation() -> anyhow::Result<()> {
    // Catches an NTSTATUS mapped to an error code callers can't match, since they retry on a sharing violation.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    let _exclusive = base.create_file("file", &user_rule(), FileOptions::new().share(Share::Exclusive))?;
    let error = refusal(base.open_file("file", &user_rule(), FileOptions::new().read(true)));
    assert!(
        matches!(error.kind(), ErrorKind::Io { source, .. } if source.raw_os_error() == Some(SHARING_VIOLATION)),
        "{error:?}"
    );
    Ok(())
}

#[rstest]
// oracle: spec MS-FSCC §2.1.5 Pathname
#[case::stream("file:stream")]
// oracle: spec Microsoft Learn "Naming Files, Paths, and Namespaces" §Naming Conventions
#[case::trailing_dot("file.")]
// oracle: spec Microsoft Learn "Naming Files, Paths, and Namespaces" §Naming Conventions
#[case::trailing_space("file ")]
// oracle: spec Microsoft Learn "Naming Files, Paths, and Namespaces" §Naming Conventions
#[case::device("nul")]
// oracle: spec Microsoft Learn "Naming Files, Paths, and Namespaces" §Naming Conventions
#[case::device_with_extension("COM1.txt")]
fn a_name_win32_paths_reach_differently_is_refused(#[case] name: &str) -> anyhow::Result<()> {
    // Catches an entry that Win32 path functions reach as another entry, a stream of one, or a device.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    let error = refusal(base.create_file(name, &user_rule(), FileOptions::new()));
    assert!(
        matches!(error.kind(), ErrorKind::Io { source, .. } if source.kind() == std::io::ErrorKind::InvalidInput),
        "{error:?}"
    );
    assert!(base.entries()?.is_empty());
    Ok(())
}

// oracle: spec IEEE Std 1003.1-2017 §rename
#[test]
fn persist_replaces_a_destination_another_process_holds_open() -> anyhow::Result<()> {
    // Catches a replacement that fails while a reader, sharing deletion as std does, holds the destination open.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    base.create_file("old", &user_rule(), FileOptions::new())?
        .write_all(b"old")?;
    let reader = std::fs::File::open(test.path().join("old"))?;
    let mut new = base.create_file("new", &user_rule(), FileOptions::new())?;
    new.write_all(b"new")?;
    base.persist(&new, "new", "old", Replace::Allow)?;
    drop((new, reader));
    assert_eq!(std::fs::read(test.path().join("old"))?, b"new");
    Ok(())
}

// oracle: spec IEEE Std 1003.1-2017 §unlink
#[test]
fn removing_a_file_another_process_holds_open_frees_its_name() -> anyhow::Result<()> {
    // Catches a removal that leaves the name pending deletion until the reader closes it, so that creating it again
    // fails.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    drop(base.create_file("file", &user_rule(), FileOptions::new())?);
    let reader = std::fs::File::open(test.path().join("file"))?;
    assert!(base.remove_file("file")?);
    drop(base.create_file("file", &user_rule(), FileOptions::new())?);
    drop(reader);
    Ok(())
}

// oracle: mutant DELETE held by a created directory's handle, which fails every other open that doesn't share deletion
#[test]
fn a_created_directory_opens_elsewhere_without_sharing_deletion() -> anyhow::Result<()> {
    // Catches a directory handle that holds DELETE, so that `cd` or `_wopen` fail while the `Dir` lives.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    let child = base.create_dir("child", &user_rule(), Existing::Check)?;
    let other = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x3) // FILE_SHARE_READ | FILE_SHARE_WRITE
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(test.path().join("child"));
    assert!(other.is_ok(), "{other:?}");
    drop(child);
    Ok(())
}

// oracle: reference crates/private-fs/src/lib.rs Dir::entries
#[test]
fn a_directory_opened_exclusively_lists_its_entries() -> anyhow::Result<()> {
    // Catches a listing through a second handle, which the exclusive open refuses.
    let test = TestDir::new();
    let base = Dir::create_base(test.path(), &user_rule())?;
    let child = base.create_dir("child", &user_rule(), Existing::Check)?;
    drop(child.create_file("file", &user_rule(), FileOptions::new())?);
    drop(child);
    let child = base
        .open_dir("child", &user_rule(), Share::Exclusive)?
        .context("the directory exists")?;
    let names: Vec<_> = child.entries()?.into_iter().map(|entry| entry.name).collect();
    assert_eq!(names, ["file"]);
    Ok(())
}

// oracle: mutant guards nested on one thread, whose drops out of order leave the thread with the privilege
#[test]
fn a_thread_holds_one_backup_privilege_at_a_time() -> anyhow::Result<()> {
    // Catches nested guards, whose drops out of order would leave the thread with the privilege.
    let first = match BackupPrivilege::enable() {
        Ok(first) => first,
        Err(error) => {
            println!("SKIP: the process token doesn't hold the backup privilege: {error}");
            return Ok(());
        }
    };
    assert!(BackupPrivilege::enable().is_err());
    drop(first);
    drop(BackupPrivilege::enable()?);
    Ok(())
}
