//! Admin-only-writable file security validation.
//!
//! Shared by three trust boundaries in the package broker:
//! - The policy file, which is the entire authorization control for the broker.
//! - The dedicated directory hosting the default policy file, which the broker itself
//!   creates and secures.
//! - Package-manager executables resolved for elevated/machine-scope execution
//!   (e.g. `winget.exe`, `choco.exe`).
//!
//! `C:\ProgramData` subtrees (and similar install roots) are a known spot for
//! over-permissive inherited ACEs: if a standard user can write the policy file, they
//! can self-authorize arbitrary elevated installs; if they can write (or replace) the
//! executable the broker launches with an elevated token, they can run arbitrary code
//! as SYSTEM/Administrator.
//!
//! As defense-in-depth, before trusting such a file, we verify that it is owned by
//! a trusted principal and that its DACL does not grant write access to any other
//! principal. Callers fail closed when this check fails.
//!
//! For the policy file and its hosting directory, the trusted principals are SYSTEM and
//! the built-in Administrators group only. `LOCAL SERVICE` is deliberately *not* trusted:
//! it is a low-privilege shared service identity, and the managed policy store must not
//! accept it as a legitimate writer even though other, unrelated Agent subtrees grant it
//! write access. For executables, `LOCAL SERVICE` is likewise not trusted, but
//! `NT SERVICE\TrustedInstaller` is, since Windows-protected binaries (`System32`,
//! `Program Files`, `WindowsApps`) are owned by and writable by that service.
//!
//! For elevated executables the verification additionally defends against
//! time-of-check/time-of-use races: the file is opened without write or delete sharing
//! and the returned [`VerifiedExecutable`] guard keeps that handle alive so the verified
//! object cannot be written, deleted, or renamed until it has been executed. Execution is
//! bound to the final path resolved from the verified handle (defeating reparse-point
//! retargeting of the originally supplied name), and every ancestor directory of that
//! path is checked so untrusted principals cannot swap path components either. The policy
//! directory's own ancestor chain is checked more strictly still (see
//! [`verify_policy_ancestor_chain`]): every level must also reject reparse points outright
//! and resolve to the exact expected location, tolerating create rights at every level
//! since a sibling entry cannot redirect or replace the already-identity-checked directory
//! itself.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::os::windows::ffi::OsStringExt as _;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use sha2::{Digest as _, Sha256};
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::security::acl::{Acl, InheritableAcl, InheritableAclKind};
use win_api_wrappers::security::attributes::{SecurityAttributes, SecurityAttributesInit};
use windows::Win32::Foundation::{ERROR_SUCCESS, GENERIC_ALL, GENERIC_WRITE, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, INHERIT_ONLY_ACE, IsWellKnownSid,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
    GetFinalPathNameByHandleW, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use windows::core::PWSTR;

/// Access rights that allow modifying the file content or its security descriptor.
const WRITE_ACCESS_MASK: u32 = FILE_WRITE_DATA.0 /* modify content */
    | FILE_APPEND_DATA.0 /* append content */
    | FILE_WRITE_EA.0 /* write extended attributes */
    | FILE_WRITE_ATTRIBUTES.0 /* write attributes */
    | DELETE.0 /* delete (and replace) the file */
    | WRITE_DAC.0 /* rewrite the DACL itself */
    | WRITE_OWNER.0 /* take ownership */
    | GENERIC_WRITE.0 /* generic write */
    | GENERIC_ALL.0; /* full control */

/// Access rights on an ancestor directory that allow swapping a path component underneath
/// a verified executable (renaming or deleting entries, or rewriting the directory's own
/// security descriptor). Rights that only allow *adding* new entries are deliberately not
/// included here: they cannot redirect an existing path component. The directory hosting
/// the executable itself is held to the stricter [`PARENT_DIRECTORY_TAMPER_MASK`].
const DIRECTORY_TAMPER_MASK: u32 = FILE_DELETE_CHILD.0 /* delete or rename child entries */
    | DELETE.0 /* delete or rename the directory itself */
    | WRITE_DAC.0 /* rewrite the DACL itself */
    | WRITE_OWNER.0 /* take ownership */
    | GENERIC_ALL.0; /* full control */

/// Access rights on the directory hosting a verified executable that allow tampering with
/// its execution. On top of [`DIRECTORY_TAMPER_MASK`], create rights are rejected: a
/// principal able to add entries beside the executable can plant a DLL or another
/// application-loaded resource that the elevated process picks up at start (side-loading),
/// even though the verified binary itself is pinned. On directories, `FILE_WRITE_DATA` is
/// `FILE_ADD_FILE` and `FILE_APPEND_DATA` is `FILE_ADD_SUBDIRECTORY`.
const PARENT_DIRECTORY_TAMPER_MASK: u32 = DIRECTORY_TAMPER_MASK
    | FILE_WRITE_DATA.0 /* add files (plant DLLs) */
    | FILE_APPEND_DATA.0 /* add subdirectories */
    | GENERIC_WRITE.0; /* generic write (maps to add rights) */

/// `NT SERVICE\TrustedInstaller`, the Windows Modules Installer service SID.
///
/// Windows-protected binaries (under `System32`, `Program Files`, `WindowsApps`, ...) are
/// owned by this SID and grant it full control, so it must be trusted when verifying
/// executables. It is deliberately *not* trusted for the policy file, which is never
/// serviced by the Windows Modules Installer.
const TRUSTED_INSTALLER_SID: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// Principals trusted to hold write access over a verified file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TrustedWriters {
    /// SYSTEM and the built-in Administrators group only (policy file and its hosting
    /// directory). `LOCAL SERVICE` is deliberately not trusted: it is a low-privilege
    /// shared service identity, and the managed policy store must not treat it as a
    /// legitimate writer even though other, unrelated Agent subtrees grant it write access.
    AdminOnly,
    /// SYSTEM, the built-in Administrators group, and `NT SERVICE\TrustedInstaller`
    /// (Windows-protected executables). `LOCAL SERVICE` is deliberately not trusted here:
    /// it is a low-privilege shared service identity, and accepting it for elevated
    /// executables would open a privilege-escalation path.
    AdminOrTrustedInstaller,
}

// ACE type constants from winnt.h (the Win32_System_SystemServices feature is not enabled).
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const SYSTEM_AUDIT_ACE_TYPE: u8 = 2;
const SYSTEM_ALARM_ACE_TYPE: u8 = 3;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 10;

/// String prefix of SIDs issued by the process trust authority (`SECURITY_PROCESS_TRUST_AUTHORITY`,
/// e.g. `S-1-19-512-4096` for "ProtectedLight-WinTcb").
///
/// These SIDs cannot be assigned to regular tokens; the kernel only grants them to
/// Windows-signed protected processes, so ACEs held by them are safe to trust.
const PROCESS_TRUST_SID_PREFIX: &str = "S-1-19-";

/// `IO_REPARSE_TAG_APPEXECLINK`, the reparse tag of Microsoft Store app execution aliases
/// (e.g. the per-user `winget.exe` under `%LOCALAPPDATA%\Microsoft\WindowsApps`).
///
/// From winnt.h (the Win32_System_SystemServices feature is not enabled).
const IO_REPARSE_TAG_APPEXECLINK: u32 = 0x8000_001B;

/// Maximum size of a reparse point data buffer, from ntifs.h.
const MAXIMUM_REPARSE_DATA_BUFFER_SIZE: usize = 16 * 1024;

/// Package family name of Microsoft App Installer, the Store package that delivers `winget.exe`.
///
/// The publisher-hash suffix is derived from Microsoft's signing certificate, so no other
/// publisher can install a package under this family.
const WINGET_PACKAGE_FAMILY: &str = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe";

/// Security descriptor allocated by `GetSecurityInfo`, freed with `LocalFree` on drop.
struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if self.0.0.is_null() {
            return;
        }
        // SAFETY: `self.0` was allocated by GetSecurityInfo and must be freed using LocalFree.
        unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

/// Verify that the policy file may only be written by SYSTEM or built-in Administrators.
///
/// The check is performed on the already-opened file handle so the verified security
/// descriptor belongs to the very same file that is subsequently read (no TOCTOU window
/// via file replacement).
///
/// Rules (fail-closed):
/// - The owner must be a trusted principal.
/// - A DACL must be present (a NULL DACL grants everyone full control).
/// - Every access-allowed ACE granting write access must have a trusted principal as
///   the trustee (inherit-only ACEs are skipped, since they do not apply to the object;
///   callback allow ACEs are treated as unconditional allow ACEs, since their condition
///   can only narrow the grant).
/// - Unsupported (object) access-allowed ACE types are rejected.
pub(crate) fn verify_policy_file_security(file: &File) -> anyhow::Result<()> {
    verify_handle_security(file, "policy file", TrustedWriters::AdminOnly, WRITE_ACCESS_MASK)
}

/// Verify that a directory intended to exclusively host the managed policy file denies
/// untrusted principals every right that would let them interfere with it: creating,
/// renaming, or deleting entries (including the atomic-replace temporary file), or
/// rewriting the directory's own security descriptor.
///
/// Unlike [`verify_ancestor_directories`], which only cares about redirecting an
/// *existing* path component and therefore tolerates create rights on higher ancestors,
/// this directory is exclusively owned by the broker: create rights would let an
/// untrusted principal plant or race the atomic-replace temporary file, so they are
/// rejected here too. The same [`TrustedWriters::AdminOnly`] principals as the policy
/// file itself apply (`LOCAL SERVICE` is not trusted).
pub(crate) fn verify_policy_directory_security(dir: &File) -> anyhow::Result<()> {
    verify_handle_security(
        dir,
        "policy directory",
        TrustedWriters::AdminOnly,
        PARENT_DIRECTORY_TAMPER_MASK,
    )
}

/// Compute a digest over a file or directory's owner and complete DACL entries.
/// Used only to fold "security-relevant state" into the policy store's opaque token so an
/// ACL change rotates it; never to authorize anything by itself.
///
/// Callers must only invoke this after security verification succeeds on the same policy file or directory handle.
/// The complete bytes of each accepted ACE are included, including callback conditions.
pub(crate) fn security_state_digest(file: &File) -> anyhow::Result<[u8; 32]> {
    let handle = HANDLE(file.as_raw_handle());

    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR::default());

    // SAFETY: `handle` is a valid open file handle, all out pointers point to live stack
    // variables, and the requested security information matches the provided out parameters.
    let ret = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor.0),
        )
    };
    if ret != ERROR_SUCCESS {
        bail!("failed to read security information for digest: error {}", ret.0);
    }

    let mut hasher = Sha256::new();

    let owner_string = if owner.0.is_null() {
        "<none>".to_owned()
    } else {
        // SAFETY: `owner` points into `descriptor`, which outlives this call.
        unsafe { sid_to_string(owner) }
    };
    hasher.update(owner_string.as_bytes());
    hasher.update(b"\0");

    if dacl.is_null() {
        hasher.update(b"NULL_DACL");
    } else {
        // SAFETY: On success, `dacl` points into `descriptor`, which outlives this call.
        let ace_count = u32::from(unsafe { (*dacl).AceCount });
        hasher.update(ace_count.to_le_bytes());

        for idx in 0..ace_count {
            let mut ace_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `dacl` is a valid ACL pointer and `idx` is within `AceCount`.
            unsafe { GetAce(dacl, idx, &mut ace_ptr) }.context("failed to read DACL entry for security digest")?;

            // SAFETY: GetAce succeeded, so `ace_ptr` points to an ACE starting with an
            // ACE_HEADER whose AceSize describes the complete entry.
            let header = unsafe { &*ace_ptr.cast::<ACE_HEADER>() };
            let ace_size = usize::from(header.AceSize);
            // SAFETY: AceSize is validated by the ACL and bounds this ACE within the DACL.
            let ace_bytes = unsafe { std::slice::from_raw_parts(ace_ptr.cast::<u8>(), ace_size) };
            update_ace_digest(&mut hasher, ace_bytes);
        }
    }

    Ok(hasher.finalize().into())
}

fn update_ace_digest(hasher: &mut Sha256, ace_bytes: &[u8]) {
    hasher.update(ace_bytes.len().to_le_bytes());
    hasher.update(ace_bytes);
}

/// Build the admin-only ACL (SYSTEM and built-in Administrators only, full control)
/// shared by every place the broker establishes the policy store's on-disk security.
///
/// `inheritance` controls whether the resulting ACEs propagate to children (appropriate
/// for a directory) or apply only to the object itself (appropriate for a leaf file).
fn admin_only_acl(inheritance: windows::Win32::Security::ACE_FLAGS) -> anyhow::Result<Acl> {
    use win_api_wrappers::security::acl::{ExplicitAccess, Trustee};
    use windows::Win32::Security::Authorization::GRANT_ACCESS;

    let system = Sid::from_well_known(WinLocalSystemSid, None).context("resolve SYSTEM SID")?;
    let admins = Sid::from_well_known(WinBuiltinAdministratorsSid, None).context("resolve Administrators SID")?;

    Acl::new()
        .context("initialize ACL")?
        .set_entries(&[
            ExplicitAccess {
                access_permissions: GENERIC_ALL.0,
                access_mode: GRANT_ACCESS,
                inheritance,
                trustee: Trustee::Sid(system),
            },
            ExplicitAccess {
                access_permissions: GENERIC_ALL.0,
                access_mode: GRANT_ACCESS,
                inheritance,
                trustee: Trustee::Sid(admins),
            },
        ])
        .context("build admin-only ACL")
}

/// Build `SECURITY_ATTRIBUTES` granting only SYSTEM and built-in Administrators access
/// (owner: SYSTEM; `Protected` DACL, so inheritance changes to ancestors cannot loosen it
/// later), for use with `CreateDirectoryW`/`CreateFileW` so the object's security is
/// correct from the instant it becomes visible on disk -- no create-then-ACL window an
/// untrusted principal could win.
///
/// Set `inherit_to_children` for a directory whose files/subdirectories should default to
/// the same restrictive ACL; leave it unset for a leaf file, which has no children.
pub(crate) fn admin_only_security_attributes(inherit_to_children: bool) -> anyhow::Result<SecurityAttributes> {
    use windows::Win32::Security::{CONTAINER_INHERIT_ACE, NO_INHERITANCE, OBJECT_INHERIT_ACE};

    let inheritance = if inherit_to_children {
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        NO_INHERITANCE
    };

    let owner = Sid::from_well_known(WinLocalSystemSid, None).context("resolve SYSTEM SID")?;
    let acl = admin_only_acl(inheritance)?;

    Ok(SecurityAttributesInit {
        owner: Some(owner),
        dacl: Some(InheritableAcl {
            kind: InheritableAclKind::Protected,
            acl,
        }),
        ..Default::default()
    }
    .init())
}

/// Volume serial number and 128-bit file id uniquely identifying an open filesystem
/// object: stable across renames of the same object, but distinct across a delete and
/// recreate at the same path (even with byte-identical content), which is exactly the
/// distinction the policy store's opaque tokens depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FileIdentity {
    pub(crate) volume_serial: u64,
    pub(crate) file_id: [u8; 16],
}

/// Query the [`FileIdentity`] of the open object behind `file`.
pub(crate) fn file_identity(file: &File) -> anyhow::Result<FileIdentity> {
    use windows::Win32::Storage::FileSystem::{FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx};

    let mut info = FILE_ID_INFO::default();
    let info_size = u32::try_from(size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO size fits in u32");

    // SAFETY: `file` is an open file handle, and the output pointer points to a properly
    // sized FILE_ID_INFO valid for the duration of the call.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            (&raw mut info).cast(),
            info_size,
        )
    }
    .context("GetFileInformationByHandleEx(FileIdInfo) failed")?;

    Ok(FileIdentity {
        volume_serial: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}

/// Query how many directory entries link to the open file.
pub(crate) fn file_link_count(file: &File) -> anyhow::Result<u32> {
    use windows::Win32::Storage::FileSystem::{FILE_STANDARD_INFO, FileStandardInfo, GetFileInformationByHandleEx};

    let mut info = FILE_STANDARD_INFO::default();
    let info_size = u32::try_from(size_of::<FILE_STANDARD_INFO>()).expect("FILE_STANDARD_INFO size fits in u32");

    // SAFETY: `file` is an open file handle, and the output pointer points to a properly
    // sized FILE_STANDARD_INFO valid for the duration of the call.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileStandardInfo,
            (&raw mut info).cast(),
            info_size,
        )
    }
    .context("GetFileInformationByHandleEx(FileStandardInfo) failed")?;

    Ok(info.NumberOfLinks)
}

/// A package-manager executable that was verified for elevated execution.
///
/// The held file handle was opened without write or delete sharing, so the verified file
/// object cannot be written, deleted, or renamed while the guard is alive. Callers must
/// execute [`VerifiedExecutable::path()`] (the final path resolved from the verified
/// handle) and keep the guard alive until the spawned process — or the script embedding
/// the path — has finished running, closing the TOCTOU window between verification and
/// image load.
#[derive(Debug)]
pub(crate) struct VerifiedExecutable {
    _file: File,
    path: PathBuf,
}

impl VerifiedExecutable {
    /// The final path of the verified executable, resolved from the verified handle.
    ///
    /// This is the path callers must execute (or embed in generated scripts) so execution
    /// is bound to the object that was verified rather than to a reparse point that could
    /// be retargeted after the check.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// Verify that a resolved package-manager executable which will be launched with an
/// elevated or machine-scope token cannot be tampered with by untrusted principals.
///
/// Returns `None` when `requires_elevation` is false, since non-elevated tool installs
/// (pip venvs, `~/.cargo`, `~/.bun`, etc.) are not expected to live under
/// admin-only-writable paths. Otherwise, fails closed on any error and returns a
/// [`VerifiedExecutable`] guard on success:
///
/// - The file is opened without write or delete sharing; the open fails if a writer
///   already has it open, and the guard prevents modification, deletion, and renaming
///   of the verified object until it is dropped.
/// - The executable's owner and DACL must only allow writes by SYSTEM, built-in
///   Administrators, or `NT SERVICE\TrustedInstaller` (see [`verify_policy_file_security`]
///   for the exact DACL rules).
/// - Every ancestor directory of the final path (resolved from the verified handle) must
///   not allow untrusted principals to rename or delete path components, so the name used
///   for execution cannot be redirected to a different file.
pub(crate) fn verify_elevated_executable_security(
    path: &Path,
    requires_elevation: bool,
) -> anyhow::Result<Option<VerifiedExecutable>> {
    if !requires_elevation {
        return Ok(None);
    }

    let subject = format!("elevated package-manager executable '{}'", path.display());

    // App execution aliases (Microsoft Store shims such as the per-user `winget.exe`)
    // are reparse points that cannot be opened for read, so they cannot be verified or
    // pinned directly. `CreateProcess` resolves them internally, but the broker must
    // verify and execute the real target, which lives under the
    // TrustedInstaller-protected `WindowsApps` package directory.
    //
    // The alias reparse data lives in a user-writable location, so its content is
    // untrusted: the target is only substituted after `validate_app_exec_alias` has bound
    // it to the executable and package family expected for the alias (fail closed).
    let alias_target = match resolve_app_exec_alias(path) {
        Some(alias) => Some(validate_app_exec_alias(path, alias)?),
        None => None,
    };
    let path = alias_target.as_deref().unwrap_or(path);

    // Share only read access: while this handle is alive the file cannot be opened for
    // write or delete (rename), and this open fails if such a handle already exists.
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(path)
        .with_context(|| format!("failed to open {subject}"))?;

    // Resolve the path from the handle itself: if `path` traversed a reparse point
    // (symlink, junction, ...), this yields the real target, which is the very object
    // pinned by the guard handle.
    let final_path =
        final_path_from_handle(&file).with_context(|| format!("failed to resolve final path of {subject}"))?;

    verify_handle_security(
        &file,
        &subject,
        TrustedWriters::AdminOrTrustedInstaller,
        WRITE_ACCESS_MASK,
    )?;

    verify_elevated_executable_ancestor_directories(&final_path, &subject)?;

    Ok(Some(VerifiedExecutable {
        _file: file,
        path: final_path,
    }))
}

/// A parsed Microsoft Store app execution alias.
#[derive(Debug, PartialEq, Eq)]
struct AppExecAlias {
    /// Package family name of the app the alias belongs to (e.g.
    /// `Microsoft.DesktopAppInstaller_8wekyb3d8bbwe`).
    package_family: String,
    /// Absolute path of the executable the alias points to.
    target: PathBuf,
}

/// Resolve a Microsoft Store app execution alias to the executable it points to.
///
/// Returns `None` when `path` is not an `IO_REPARSE_TAG_APPEXECLINK` reparse point
/// (including when it cannot be opened at all; the caller's regular open then reports
/// the actual error).
fn resolve_app_exec_alias(path: &Path) -> Option<AppExecAlias> {
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;

    let link = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(path)
        .ok()?;

    let mut buffer = vec![0u8; MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
    let mut returned = 0u32;

    // SAFETY: `link` is an open file handle, and `buffer` and `returned` are live for
    // the duration of the call.
    unsafe {
        DeviceIoControl(
            HANDLE(link.as_raw_handle()),
            FSCTL_GET_REPARSE_POINT,
            None,
            0,
            Some(buffer.as_mut_ptr().cast()),
            u32::try_from(buffer.len()).expect("reparse buffer size fits in u32"),
            Some(&mut returned),
            None,
        )
    }
    // A failure means `path` is not a reparse point (or its data is unreadable): not an alias.
    .ok()?;

    buffer.truncate(usize::try_from(returned).expect("u32 fits in usize on Windows"));
    parse_app_exec_alias(&buffer)
}

/// Validate an app execution alias against the identity expected for the aliased
/// executable and return its target path.
///
/// The alias reparse point lives in a user-writable directory
/// (`%LOCALAPPDATA%\Microsoft\WindowsApps`), so its content is untrusted: without this
/// binding, a crafted alias could redirect e.g. `winget.exe` to any other
/// TrustedInstaller-owned binary, which would then pass the ACL checks and run elevated.
///
/// Rules (fail-closed):
/// - Only `winget.exe` aliases are supported (the only Store-app executable the broker
///   launches).
/// - The alias package family must be [`WINGET_PACKAGE_FAMILY`], whose publisher-hash
///   suffix is bound to Microsoft's signing certificate.
/// - The target file name must match the alias file name.
/// - The target must live inside a package directory of that same family (a
///   `<name>_<version>_<arch>__<publisher-hash>` full-name component).
fn validate_app_exec_alias(alias_path: &Path, alias: AppExecAlias) -> anyhow::Result<PathBuf> {
    let alias_name = alias_path
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("app execution alias '{}' has no file name", alias_path.display()))?;

    if !alias_name.eq_ignore_ascii_case("winget.exe") {
        bail!(
            "app execution alias '{}' is not supported for elevated execution",
            alias_path.display()
        );
    }

    if !alias.package_family.eq_ignore_ascii_case(WINGET_PACKAGE_FAMILY) {
        bail!(
            "app execution alias '{}' belongs to package family '{}'; expected '{WINGET_PACKAGE_FAMILY}'",
            alias_path.display(),
            alias.package_family,
        );
    }

    let target_name_matches = alias
        .target
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(alias_name));
    if !target_name_matches {
        bail!(
            "app execution alias '{}' points to '{}', which is not a '{alias_name}' executable",
            alias_path.display(),
            alias.target.display(),
        );
    }

    if !path_contains_package_full_name(&alias.target, WINGET_PACKAGE_FAMILY) {
        bail!(
            "app execution alias '{}' points to '{}', which is outside the '{WINGET_PACKAGE_FAMILY}' package directory",
            alias_path.display(),
            alias.target.display(),
        );
    }

    Ok(alias.target)
}

/// Whether `path` contains a directory component that is a package full name
/// (`<name>_<version>_<arch>__<publisher-hash>`) of the given package family
/// (`<name>_<publisher-hash>`).
fn path_contains_package_full_name(path: &Path, package_family: &str) -> bool {
    let Some((family_name, publisher_hash)) = package_family.rsplit_once('_') else {
        return false;
    };
    let prefix = format!("{family_name}_");
    let suffix = format!("__{publisher_hash}");

    path.components().any(|component| {
        component.as_os_str().to_str().is_some_and(|component| {
            component.len() >= prefix.len() + suffix.len()
                && component[..prefix.len()].eq_ignore_ascii_case(&prefix)
                && component[component.len() - suffix.len()..].eq_ignore_ascii_case(&suffix)
        })
    })
}

/// Parse the package family name and target executable path out of an
/// `IO_REPARSE_TAG_APPEXECLINK` reparse buffer.
///
/// Layout: a `REPARSE_DATA_BUFFER` header (tag, data length, reserved), then the
/// AppExecLink payload: a version field followed by NUL-separated UTF-16 strings —
/// package family name, application user model id, target executable path, and
/// application type.
fn parse_app_exec_alias(buffer: &[u8]) -> Option<AppExecAlias> {
    // Header: ReparseTag (4 bytes), ReparseDataLength (2 bytes), Reserved (2 bytes).
    let header = buffer.get(..8)?;
    let tag = u32::from_le_bytes(header[..4].try_into().ok()?);
    if tag != IO_REPARSE_TAG_APPEXECLINK {
        return None;
    }
    let data_length = usize::from(u16::from_le_bytes(header[4..6].try_into().ok()?));
    let data = buffer.get(8..8 + data_length)?;

    // AppExecLink payload: Version (4 bytes), then NUL-separated UTF-16 strings.
    let strings = data.get(4..)?;
    let wide: Vec<u16> = strings
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    let mut strings = wide.split(|&c| c == 0);
    let package_family = strings.next()?;
    let target = strings.nth(1)?;
    if package_family.is_empty() || target.is_empty() {
        return None;
    }

    let package_family = String::from_utf16(package_family).ok()?;
    let target = PathBuf::from(OsString::from_wide(target));
    target.is_absolute().then_some(AppExecAlias { package_family, target })
}

/// Verify that every ancestor directory of `path` denies untrusted principals the rights
/// needed to tamper with the executable's resolution or loading.
///
/// The directory hosting the executable is checked against
/// [`PARENT_DIRECTORY_TAMPER_MASK`], which additionally rejects create rights: a principal
/// able to add entries beside the binary can plant a DLL or another application-loaded
/// resource that the elevated process side-loads at start. Higher ancestors are checked
/// against [`DIRECTORY_TAMPER_MASK`]: without it, a principal with delete/rename rights
/// could replace a whole directory subtree so the verified name resolves to a different
/// file when the image is finally loaded. Create rights higher up are harmless (and are
/// granted to unprivileged users on stock drive roots), since they cannot redirect an
/// existing path component.
pub(crate) fn verify_elevated_executable_ancestor_directories(path: &Path, subject: &str) -> anyhow::Result<()> {
    verify_ancestor_directories(path, subject, PARENT_DIRECTORY_TAMPER_MASK)
}

/// Verify that every ancestor of `dir` (starting at its parent; `dir` itself must already
/// be separately verified by the caller, e.g. with [`verify_policy_directory_security`])
/// is a genuine directory resolving to the expected location and denies untrusted
/// principals the rights needed to delete, rename, or replace `dir` out from under an
/// already-verified identity check -- a "path-swap" further up the tree.
///
/// Unlike [`verify_elevated_executable_ancestor_directories`] (and the shared
/// [`verify_ancestor_directories`] helper it relies on, which this deliberately never
/// calls or alters), every level here is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and
/// rejected outright if it turns out to be a reparse point (junction/symlink) rather than
/// transparently traversed, and its handle-resolved final path is compared against the
/// exact literal component being verified: a directory silently retargeted partway up the
/// policy directory's own ancestor chain must never be trusted just because reparse
/// traversal would have "worked". Create rights are still tolerated at *every* level,
/// including the immediate parent: other, unrelated features may legitimately create
/// sibling entries in a shared ancestor (the installer grants `LOCAL SERVICE` write
/// access to the shared `%ProgramData%\Devolutions\Agent` directory for unrelated Agent
/// subtrees), and that alone cannot redirect or replace `dir`, which is what this check
/// actually defends against. Only delete/rename/take-ownership rights
/// ([`DIRECTORY_TAMPER_MASK`]) are rejected.
///
/// Returns a digest summarizing every verified level's resolved path and security state
/// (owner/DACL), so a caller folding this into a fingerprint (see
/// `policy_store::windows::DiskFingerprint`) can detect a change anywhere in the ancestor
/// chain -- not just the immediate parent -- without re-deriving the individual checks.
pub(crate) fn verify_policy_ancestor_chain(dir: &Path, subject: &str) -> anyhow::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut current = dir.parent();

    while let Some(ancestor) = current {
        let dir_subject = format!("{subject} ancestor directory '{}'", ancestor.display());

        let handle = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
            .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
            .open(ancestor)
            .with_context(|| format!("failed to open {dir_subject}"))?;

        let attributes = handle
            .metadata()
            .with_context(|| format!("failed to query metadata for {dir_subject}"))?
            .file_attributes();
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            bail!("{dir_subject} is a reparse point (junction/symlink); ancestor directories must be real directories");
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
            bail!("{dir_subject} is not a directory");
        }

        let resolved = final_path_from_handle(&handle).with_context(|| format!("failed to resolve {dir_subject}"))?;
        if !paths_match_case_insensitive(&resolved, ancestor) {
            bail!(
                "{dir_subject} resolved to an unexpected location '{}'; refusing to trust a retargeted ancestor",
                resolved.display()
            );
        }

        verify_handle_security(
            &handle,
            &dir_subject,
            TrustedWriters::AdminOrTrustedInstaller,
            DIRECTORY_TAMPER_MASK,
        )?;

        let level_security_digest =
            security_state_digest(&handle).with_context(|| format!("failed to digest {dir_subject} security"))?;
        hasher.update(resolved.as_os_str().to_string_lossy().to_lowercase().as_bytes());
        hasher.update(b"\0");
        hasher.update(level_security_digest);

        current = ancestor.parent();
    }

    Ok(hasher.finalize().into())
}

/// Case-insensitive path comparison for verifying a handle's resolved final path against
/// an expected literal component. Falls back to an exact `OsStr` comparison on the rare
/// input that is not valid Unicode, which only ever makes the comparison *stricter*
/// (fail-closed), never more permissive.
pub(crate) fn paths_match_case_insensitive(a: &Path, b: &Path) -> bool {
    match (a.to_str(), b.to_str()) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => a.as_os_str() == b.as_os_str(),
    }
}

/// Verify that every ancestor of `dir` (starting at its parent; `dir` itself must already
/// be separately verified by the caller, e.g. with [`verify_policy_directory_security`])
/// denies untrusted principals the rights needed to delete, rename, or replace `dir` out
/// from under an already-verified identity check -- a "path-swap" further up the tree.
///
/// Unlike [`verify_elevated_executable_ancestor_directories`], create rights are tolerated
/// at *every* level, including the immediate parent: other, unrelated features may
/// legitimately create sibling entries in a shared ancestor (the installer grants
/// `LOCAL SERVICE` write access to the shared `%ProgramData%\Devolutions\Agent` directory
/// for unrelated Agent subtrees), and that alone cannot redirect or replace `dir`, which is
/// what this check actually defends against. Only delete/rename/take-ownership rights
/// ([`DIRECTORY_TAMPER_MASK`]) are rejected.
fn verify_ancestor_directories(path: &Path, subject: &str, first_level_mask: u32) -> anyhow::Result<()> {
    let mut current = path.parent();
    let mut tamper_mask = first_level_mask;

    while let Some(dir) = current {
        let dir_subject = format!("{subject} ancestor directory '{}'", dir.display());

        let handle = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
            .open(dir)
            .with_context(|| format!("failed to open {dir_subject}"))?;

        verify_handle_security(
            &handle,
            &dir_subject,
            TrustedWriters::AdminOrTrustedInstaller,
            tamper_mask,
        )?;

        tamper_mask = DIRECTORY_TAMPER_MASK;
        current = dir.parent();
    }

    Ok(())
}

/// Resolve the normalized final path of an open file from its handle.
pub(crate) fn final_path_from_handle(file: &File) -> anyhow::Result<PathBuf> {
    let handle = HANDLE(file.as_raw_handle());
    let mut buffer = vec![0u16; 512];

    loop {
        // SAFETY: `handle` is a valid open file handle and `buffer` is a live mutable slice.
        let len = unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, FILE_NAME_NORMALIZED) };

        if len == 0 {
            return Err(windows::core::Error::from_win32()).context("GetFinalPathNameByHandleW failed");
        }

        let len = usize::try_from(len).expect("u32 fits in usize on Windows");

        // A return value smaller than the buffer is the number of characters written;
        // otherwise it is the required buffer size (including the null terminator).
        if len < buffer.len() {
            buffer.truncate(len);
            return Ok(dos_path_from_wide(&buffer));
        }

        buffer.resize(len, 0);
    }
}

/// Convert a possibly `\\?\`-prefixed wide path to its plain Win32 form.
///
/// The resolved path is embedded into generated batch scripts and passed to
/// `CreateProcessAsUserW`, and `cmd.exe` does not understand extended-length paths.
fn dos_path_from_wide(wide: &[u16]) -> PathBuf {
    let verbatim: Vec<u16> = r"\\?\".encode_utf16().collect();
    let verbatim_unc: Vec<u16> = r"\\?\UNC\".encode_utf16().collect();

    if wide.starts_with(&verbatim_unc) {
        // `\\?\UNC\server\share\...` → `\\server\share\...`.
        let mut path: Vec<u16> = r"\\".encode_utf16().collect();
        path.extend_from_slice(&wide[verbatim_unc.len()..]);
        PathBuf::from(OsString::from_wide(&path))
    } else if wide.starts_with(&verbatim) {
        // `\\?\C:\...` → `C:\...`.
        PathBuf::from(OsString::from_wide(&wide[verbatim.len()..]))
    } else {
        PathBuf::from(OsString::from_wide(wide))
    }
}

/// Verify that `file` may only be written (per `tamper_mask`) by `trusted_writers` principals.
///
/// The check is performed on the already-opened handle so the verified security
/// descriptor belongs to the very same object that is subsequently used.
fn verify_handle_security(
    file: &File,
    subject: &str,
    trusted_writers: TrustedWriters,
    tamper_mask: u32,
) -> anyhow::Result<()> {
    let handle = HANDLE(file.as_raw_handle());

    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR::default());

    // SAFETY: `handle` is a valid open file handle, all out pointers point to live stack
    // variables, and the requested security information matches the provided out parameters.
    let ret = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor.0),
        )
    };

    if ret != ERROR_SUCCESS {
        bail!("failed to read {subject} security information: error {}", ret.0);
    }

    // SAFETY: On success, `owner` and `dacl` point into `descriptor` (or are null), which
    // outlives this call.
    unsafe { verify_owner_and_dacl(subject, owner, dacl, trusted_writers, tamper_mask) }
}

/// Verify that `owner` is trusted and that `dacl` grants `tamper_mask` rights to
/// `trusted_writers` SIDs only.
///
/// See [`verify_policy_file_security`] for the exact rules.
///
/// # Safety
///
/// - `owner` must be null or point to a valid SID.
/// - `dacl` must be null or point to a valid, initialized ACL.
unsafe fn verify_owner_and_dacl(
    subject: &str,
    owner: PSID,
    dacl: *const ACL,
    trusted_writers: TrustedWriters,
    tamper_mask: u32,
) -> anyhow::Result<()> {
    if owner.0.is_null() {
        bail!("{subject} has no owner information");
    }

    // SAFETY: Per function contract, `owner` points to a valid SID.
    if !unsafe { is_trusted_sid(owner, trusted_writers) } {
        // SAFETY: Per function contract, `owner` points to a valid SID.
        let owner_string = unsafe { sid_to_string(owner) };
        bail!("{subject} owner {owner_string} is not a trusted principal");
    }

    if dacl.is_null() {
        bail!("{subject} has a NULL DACL granting full control to everyone");
    }

    // SAFETY: Per function contract, `dacl` is a valid, non-null pointer to an initialized ACL.
    let ace_count = u32::from(unsafe { (*dacl).AceCount });

    for idx in 0..ace_count {
        let mut ace_ptr: *mut core::ffi::c_void = std::ptr::null_mut();

        // SAFETY: `dacl` is a valid ACL pointer and `idx` is within `AceCount`.
        unsafe { GetAce(dacl, idx, &mut ace_ptr) }.with_context(|| format!("failed to read {subject} DACL entry"))?;

        // SAFETY: GetAce succeeded, so `ace_ptr` points to an ACE starting with an ACE_HEADER.
        let header = unsafe { &*ace_ptr.cast::<ACE_HEADER>() };

        // Inherit-only ACEs do not apply to the object itself, only to its children
        // (e.g. the `CREATOR OWNER` full-control template ACE on `Program Files`).
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE.0 != 0 {
            continue;
        }

        match header.AceType {
            // Deny and audit ACEs never grant access.
            ACCESS_DENIED_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | SYSTEM_AUDIT_ACE_TYPE
            | SYSTEM_ALARM_ACE_TYPE => {}
            // A callback (conditional) allow ACE shares the ACCESS_ALLOWED_ACE prefix layout
            // (header, mask, inline SID); its condition can only narrow the grant, so treating
            // it as an unconditional allow ACE is the fail-closed interpretation. Store-app
            // binaries under `Program Files\WindowsApps` carry such ACEs for trust-label SIDs.
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
                // SAFETY: Both matched ACE types start with the ACCESS_ALLOWED_ACE layout.
                let ace = unsafe { &*ace_ptr.cast::<ACCESS_ALLOWED_ACE>() };

                if ace.Mask & tamper_mask == 0 {
                    continue;
                }

                let trustee = PSID(std::ptr::from_ref(&ace.SidStart).cast_mut().cast());

                // SAFETY: `SidStart` is the first DWORD of the trustee SID stored inline in the ACE.
                if !unsafe { is_trusted_sid(trustee, trusted_writers) } {
                    // SAFETY: `trustee` points to a valid SID inside the ACE.
                    let trustee_string = unsafe { sid_to_string(trustee) };
                    bail!(
                        "{subject} DACL grants write access to {trustee_string}; only trusted principals may write it"
                    );
                }
            }
            // Fail closed on object and other exotic allow ACE types.
            other => bail!("{subject} DACL contains unsupported ACE type {other}"),
        }
    }

    Ok(())
}

/// Returns `true` when the SID is one of the `trusted_writers` principals.
///
/// # Safety
///
/// `sid` must point to a valid SID.
unsafe fn is_trusted_sid(sid: PSID, trusted_writers: TrustedWriters) -> bool {
    // SAFETY: Per function contract, `sid` points to a valid SID.
    if unsafe { IsWellKnownSid(sid, WinLocalSystemSid) }.as_bool() {
        return true;
    }

    // SAFETY: Per function contract, `sid` points to a valid SID.
    if unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) }.as_bool() {
        return true;
    }

    if trusted_writers != TrustedWriters::AdminOrTrustedInstaller {
        return false;
    }

    // SAFETY: Per function contract, `sid` points to a valid SID.
    let sid_string = unsafe { sid_to_string(sid) };

    // Windows-protected executables (e.g. Store apps under `Program Files\WindowsApps`)
    // grant write access to TrustedInstaller and to process trust-label SIDs, which the
    // kernel only assigns to Windows-signed protected processes.
    sid_string.eq_ignore_ascii_case(TRUSTED_INSTALLER_SID) || sid_string.starts_with(PROCESS_TRUST_SID_PREFIX)
}

/// Best-effort conversion of a SID to its string form for diagnostics.
///
/// # Safety
///
/// `sid` must point to a valid SID.
unsafe fn sid_to_string(sid: PSID) -> String {
    let mut string_sid = PWSTR::null();

    // SAFETY: Per function contract, `sid` points to a valid SID; `string_sid` is a live out variable.
    match unsafe { ConvertSidToStringSidW(sid, &mut string_sid) } {
        Ok(()) => {
            // SAFETY: On success, `string_sid` points to a valid null-terminated UTF-16 string.
            let value = unsafe { string_sid.to_string() }.unwrap_or_else(|_| "<invalid SID>".to_owned());
            // SAFETY: The string was allocated by ConvertSidToStringSidW and must be freed with LocalFree.
            unsafe { LocalFree(Some(HLOCAL(string_sid.as_ptr().cast()))) };
            value
        }
        Err(_) => "<unknown SID>".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use win_api_wrappers::identity::sid::Sid;
    use win_api_wrappers::security::acl::{
        Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee, set_named_security_info,
    };
    use win_api_wrappers::str::U16CString;
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GRANT_ACCESS, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, NO_INHERITANCE, WinWorldSid,
    };

    use super::*;

    #[test]
    fn ace_digest_includes_callback_application_data() {
        let mut left = Sha256::new();
        let mut right = Sha256::new();
        update_ace_digest(&mut left, &[1, 2, 3, 4]);
        update_ace_digest(&mut right, &[1, 2, 3, 5]);

        assert_ne!(left.finalize(), right.finalize());
    }

    /// Proves the property [`admin_only_security_attributes`] is relied on for (item 8):
    /// the DACL it builds is `Protected` (`SE_DACL_PROTECTED`), so `CreateFileW`/
    /// `CreateDirectoryW` never merges it with whatever the hosting directory would
    /// otherwise have inherited. An insecure inherited/default DACL on the parent
    /// therefore cannot expose the object even if inheritance were somehow
    /// misconfigured: the new object's DACL is authoritative from the instant of
    /// creation, not a merge. This only inspects the in-memory descriptor this process
    /// just built, so it needs no elevation and touches no real file.
    #[test]
    fn admin_only_security_attributes_use_a_protected_non_inheriting_dacl() {
        let attributes = admin_only_security_attributes(false).expect("build admin-only security attributes");

        // SAFETY: `attributes.as_ptr()` is a valid, live `SECURITY_ATTRIBUTES` this
        // process just constructed.
        let raw = unsafe { &*attributes.as_ptr() };
        // SAFETY: `lpSecurityDescriptor` points to a live `SECURITY_DESCRIPTOR` built the
        // same way, valid for the duration of this read.
        let descriptor = unsafe {
            &*raw
                .lpSecurityDescriptor
                .cast::<windows::Win32::Security::SECURITY_DESCRIPTOR>()
        };
        let control = descriptor.Control;

        assert!(
            control.contains(windows::Win32::Security::SE_DACL_PROTECTED),
            "expected SE_DACL_PROTECTED to be set so the DACL never merges with inherited ACEs"
        );
        assert!(
            control.contains(windows::Win32::Security::SE_DACL_PRESENT),
            "expected a DACL to actually be present (a NULL DACL would grant everyone full control)"
        );
    }

    /// SDDL-backed security descriptor together with its extracted owner and DACL pointers.
    struct SddlDescriptor {
        _descriptor: OwnedSecurityDescriptor,
        owner: PSID,
        dacl: *const ACL,
    }

    impl SddlDescriptor {
        fn parse(sddl: &str) -> Self {
            let wide = U16CString::from_str(sddl).unwrap();
            let mut descriptor = OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR::default());

            // SAFETY: `wide` is a valid null-terminated UTF-16 string, and `descriptor.0` is a
            // live out variable.
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    windows::core::PCWSTR(wide.as_ptr()),
                    SDDL_REVISION_1,
                    &mut descriptor.0,
                    None,
                )
            }
            .unwrap();

            let mut owner = PSID::default();
            let mut owner_defaulted = windows::core::BOOL(0);

            // SAFETY: `descriptor.0` is a valid security descriptor; out pointers are live.
            unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut owner_defaulted) }.unwrap();

            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut dacl_present = windows::core::BOOL(0);
            let mut dacl_defaulted = windows::core::BOOL(0);

            // SAFETY: `descriptor.0` is a valid security descriptor; out pointers are live.
            unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut dacl_present, &mut dacl, &mut dacl_defaulted) }
                .unwrap();

            if !dacl_present.as_bool() {
                dacl = std::ptr::null_mut();
            }

            Self {
                _descriptor: descriptor,
                owner,
                dacl,
            }
        }

        fn verify(&self) -> anyhow::Result<()> {
            // SAFETY: `owner` and `dacl` point into the owned security descriptor, which outlives
            // this call.
            unsafe {
                verify_owner_and_dacl(
                    "test file",
                    self.owner,
                    self.dacl,
                    TrustedWriters::AdminOnly,
                    WRITE_ACCESS_MASK,
                )
            }
        }

        fn verify_as_executable(&self) -> anyhow::Result<()> {
            self.verify_with_mask(WRITE_ACCESS_MASK)
        }

        fn verify_with_mask(&self, mask: u32) -> anyhow::Result<()> {
            // SAFETY: `owner` and `dacl` point into the owned security descriptor, which outlives
            // this call.
            unsafe {
                verify_owner_and_dacl(
                    "test executable",
                    self.owner,
                    self.dacl,
                    TrustedWriters::AdminOrTrustedInstaller,
                    mask,
                )
            }
        }
    }

    #[test]
    fn system_owner_with_admin_only_write_dacl_is_accepted() {
        // Owner: SYSTEM; SYSTEM and Administrators full control, Users read-only.
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)");
        sd.verify().expect("SYSTEM/Administrators-only DACL must be accepted");
    }

    #[test]
    fn administrators_owner_is_accepted() {
        let sd = SddlDescriptor::parse("O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)");
        sd.verify().expect("Administrators owner must be accepted");
    }

    #[test]
    fn local_service_write_ace_is_rejected_for_policy_file() {
        // The managed policy store lives in its own dedicated, broker-secured directory,
        // and LOCAL SERVICE is a low-privilege shared service identity that must not be
        // trusted to write the policy that authorizes elevated installs.
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LS)");
        let error = sd.verify().unwrap_err();
        assert!(
            error.to_string().contains("grants write access"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn local_service_write_ace_is_rejected_for_executables() {
        // LOCAL SERVICE is a low-privilege shared service identity; a LOCAL
        // SERVICE-writable executable must not pass elevated-executable verification.
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LS)");
        let error = sd.verify_as_executable().unwrap_err();
        assert!(
            error.to_string().contains("grants write access"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn network_service_write_ace_is_rejected() {
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;NS)");
        let error = sd.verify().unwrap_err();
        assert!(
            error.to_string().contains("grants write access"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn shared_ancestor_create_only_grant_passes_the_relaxed_ancestor_mask() {
        // Mirrors the installer-configured shared `%ProgramData%\Devolutions\Agent`
        // parent: SYSTEM/Administrators full control, plus LOCAL SERVICE granted only
        // add-file/add-subdirectory rights (0x6: FILE_WRITE_DATA | FILE_APPEND_DATA) for
        // unrelated Agent features. No delete-child, delete, write-DAC, or take-ownership
        // rights are granted, so this must pass the ancestor chain's relaxed
        // `DIRECTORY_TAMPER_MASK` (see `verify_policy_ancestor_chain`): a sibling
        // create right cannot redirect or replace the dedicated policy directory.
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x6;;;LS)");
        sd.verify_with_mask(DIRECTORY_TAMPER_MASK)
            .expect("create-only rights on a shared ancestor must not fail the relaxed ancestor check");
    }

    #[test]
    fn shared_ancestor_delete_child_grant_fails_the_relaxed_ancestor_mask() {
        // If the shared parent ever granted delete-child (path-swap) rights to a
        // non-trusted principal, the dedicated policy directory could be renamed or
        // replaced out from under an already-passed identity check. This must never be
        // silently accepted, even by the deliberately relaxed ancestor mask.
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x40;;;LS)");
        let error = sd.verify_with_mask(DIRECTORY_TAMPER_MASK).unwrap_err();
        assert!(
            error.to_string().contains("grants write access"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn app_exec_alias_reparse_buffer_is_parsed() {
        // Synthetic AppExecLink buffer: version 3, then package family, entry point,
        // target path, and application type as NUL-separated UTF-16 strings.
        let strings: Vec<u16> =
            "Package_8wekyb3d8bbwe\0Package!App\0C:\\Program Files\\WindowsApps\\Package\\winget.exe\x000\0"
                .encode_utf16()
                .collect();
        let mut data = 3u32.to_le_bytes().to_vec();
        data.extend(strings.iter().flat_map(|c| c.to_le_bytes()));

        let mut buffer = IO_REPARSE_TAG_APPEXECLINK.to_le_bytes().to_vec();
        buffer.extend(u16::try_from(data.len()).unwrap().to_le_bytes());
        buffer.extend([0u8, 0]); // Reserved.
        buffer.extend(&data);

        let alias = parse_app_exec_alias(&buffer).expect("alias must be parsed");
        assert_eq!(alias.package_family, "Package_8wekyb3d8bbwe");
        assert_eq!(
            alias.target,
            PathBuf::from("C:\\Program Files\\WindowsApps\\Package\\winget.exe")
        );
    }

    #[test]
    fn non_appexeclink_reparse_buffer_is_ignored() {
        // A symlink reparse tag (0xA000000C) must not be treated as an alias.
        let mut buffer = 0xA000_000Cu32.to_le_bytes().to_vec();
        buffer.extend([0u8; 12]);
        assert!(parse_app_exec_alias(&buffer).is_none());
    }

    #[test]
    fn winget_alias_with_expected_identity_is_validated() {
        let alias_path = Path::new(r"C:\Users\user\AppData\Local\Microsoft\WindowsApps\winget.exe");
        let alias = AppExecAlias {
            package_family: WINGET_PACKAGE_FAMILY.to_owned(),
            target: PathBuf::from(
                r"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.26.430.0_x64__8wekyb3d8bbwe\winget.exe",
            ),
        };
        let target = validate_app_exec_alias(alias_path, alias).expect("valid winget alias must be accepted");
        assert!(target.ends_with("winget.exe"));
    }

    #[test]
    fn alias_with_unexpected_package_family_is_rejected() {
        // A crafted alias claiming another (even Microsoft-published) package family
        // must not be substituted.
        let alias_path = Path::new(r"C:\Users\user\AppData\Local\Microsoft\WindowsApps\winget.exe");
        let alias = AppExecAlias {
            package_family: "Evil.FakeInstaller_0000000000000".to_owned(),
            target: PathBuf::from(
                r"C:\Program Files\WindowsApps\Evil.FakeInstaller_1.0.0.0_x64__0000000000000\winget.exe",
            ),
        };
        let error = validate_app_exec_alias(alias_path, alias).unwrap_err();
        assert!(
            error.to_string().contains("package family"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn alias_targeting_different_executable_is_rejected() {
        // The right family, but the target is redirected to another TrustedInstaller-owned
        // binary of the package.
        let alias_path = Path::new(r"C:\Users\user\AppData\Local\Microsoft\WindowsApps\winget.exe");
        let alias = AppExecAlias {
            package_family: WINGET_PACKAGE_FAMILY.to_owned(),
            target: PathBuf::from(
                r"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.26.430.0_x64__8wekyb3d8bbwe\AppInstallerCLI.exe",
            ),
        };
        let error = validate_app_exec_alias(alias_path, alias).unwrap_err();
        assert!(
            error.to_string().contains("not a 'winget.exe' executable"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn alias_target_outside_package_directory_is_rejected() {
        // The right family and file name, but the target escapes the package directory.
        let alias_path = Path::new(r"C:\Users\user\AppData\Local\Microsoft\WindowsApps\winget.exe");
        let alias = AppExecAlias {
            package_family: WINGET_PACKAGE_FAMILY.to_owned(),
            target: PathBuf::from(r"C:\Users\user\Downloads\winget.exe"),
        };
        let error = validate_app_exec_alias(alias_path, alias).unwrap_err();
        assert!(error.to_string().contains("outside"), "unexpected error: {error}");
    }

    #[test]
    fn non_winget_alias_is_rejected() {
        let alias_path = Path::new(r"C:\Users\user\AppData\Local\Microsoft\WindowsApps\python.exe");
        let alias = AppExecAlias {
            package_family: WINGET_PACKAGE_FAMILY.to_owned(),
            target: PathBuf::from(
                r"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.26.430.0_x64__8wekyb3d8bbwe\winget.exe",
            ),
        };
        let error = validate_app_exec_alias(alias_path, alias).unwrap_err();
        assert!(error.to_string().contains("not supported"), "unexpected error: {error}");
    }

    #[test]
    fn regular_file_is_not_an_app_exec_alias() {
        let exe = std::env::current_exe().expect("current exe");
        assert!(resolve_app_exec_alias(&exe).is_none());
    }

    #[test]
    fn winget_app_exec_alias_resolves_to_windowsapps_target() {
        // Opportunistic: only runs where the per-user winget alias is installed.
        let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") else {
            return;
        };
        let alias_path = PathBuf::from(local_app_data).join("Microsoft\\WindowsApps\\winget.exe");
        if !alias_path.exists() {
            return;
        }

        let alias = resolve_app_exec_alias(&alias_path).expect("winget alias must resolve");
        assert!(alias.target.is_absolute());
        assert!(
            alias
                .target
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case("winget.exe"))
        );
        assert!(alias.package_family.eq_ignore_ascii_case(WINGET_PACKAGE_FAMILY));
        assert_ne!(alias.target, alias_path);
    }

    #[test]
    fn winget_app_exec_alias_passes_elevated_verification() {
        // Opportunistic end-to-end check: the alias itself cannot be opened for read,
        // so verification must transparently target the real WindowsApps binary.
        let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") else {
            return;
        };
        let alias = PathBuf::from(local_app_data).join("Microsoft\\WindowsApps\\winget.exe");
        if !alias.exists() {
            return;
        }

        match verify_elevated_executable_security(&alias, true) {
            Ok(guard) => {
                let guard = guard.expect("a guard must be produced for elevated execution");
                assert_ne!(guard.path(), alias);
            }
            // Non-elevated test runs cannot open `Program Files\WindowsApps` ancestors for
            // READ_CONTROL; the agent service (SYSTEM) can. Everything up to the ancestor
            // walk — alias resolution and file-level verification — must have succeeded.
            Err(error) => {
                assert!(
                    error.to_string().contains("ancestor directory"),
                    "unexpected error: {error:#}"
                );
            }
        }
    }

    #[test]
    fn untrusted_owner_is_rejected() {
        // Owner: Everyone, even though the DACL itself is strict.
        let sd = SddlDescriptor::parse("O:WDD:(A;;FA;;;SY)(A;;FA;;;BA)");
        let error = sd.verify().unwrap_err();
        assert!(error.to_string().contains("owner"), "unexpected error: {error}");
    }

    #[test]
    fn everyone_write_ace_is_rejected() {
        // Trusted owner, but the DACL grants Everyone generic write.
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;GW;;;WD)");
        let error = sd.verify().unwrap_err();
        assert!(
            error.to_string().contains("grants write access"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn users_file_write_ace_is_rejected() {
        // Trusted owner, but BUILTIN\Users can write file data (0x2 = FILE_WRITE_DATA).
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;0x2;;;BU)");
        let error = sd.verify().unwrap_err();
        assert!(
            error.to_string().contains("grants write access"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn users_delete_ace_is_rejected() {
        // DELETE allows replacing the policy file, so it counts as write access (0x10000 = DELETE).
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;0x10000;;;BU)");
        let error = sd.verify().unwrap_err();
        assert!(
            error.to_string().contains("grants write access"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn users_read_only_ace_is_accepted() {
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;FR;;;BU)");
        sd.verify().expect("read-only access for Users must be accepted");
    }

    #[test]
    fn deny_ace_for_untrusted_sid_is_ignored() {
        // A deny ACE never grants access, so it must not trigger a rejection.
        let sd = SddlDescriptor::parse("O:SYD:(D;;FA;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)");
        sd.verify().expect("deny ACEs must be ignored");
    }

    #[test]
    fn inherit_only_write_ace_is_ignored() {
        // Inherit-only ACEs (e.g. the CREATOR OWNER template on Program Files) do not
        // apply to the object itself.
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;OICIIO;GA;;;WD)");
        sd.verify().expect("inherit-only ACEs must be ignored");
    }

    #[test]
    fn trusted_installer_owner_and_write_ace_are_accepted_for_executables() {
        // Windows-protected binaries (System32, WindowsApps, ...) are owned by and
        // writable by NT SERVICE\TrustedInstaller.
        let sddl = format!("O:{TRUSTED_INSTALLER_SID}D:(A;;FA;;;{TRUSTED_INSTALLER_SID})(A;;FR;;;BU)");
        let sd = SddlDescriptor::parse(&sddl);
        sd.verify_as_executable()
            .expect("TrustedInstaller must be trusted for executables");
    }

    #[test]
    fn trusted_installer_owner_is_rejected_for_policy_files() {
        // The policy file is never serviced by the Windows Modules Installer, so
        // TrustedInstaller stays untrusted there.
        let sddl = format!("O:{TRUSTED_INSTALLER_SID}D:(A;;FA;;;SY)(A;;FA;;;BA)");
        let sd = SddlDescriptor::parse(&sddl);
        let error = sd.verify().unwrap_err();
        assert!(error.to_string().contains("owner"), "unexpected error: {error}");
    }

    #[test]
    fn untrusted_add_file_right_is_rejected_on_hosting_directory() {
        // FILE_WRITE_DATA (0x2) on a directory is FILE_ADD_FILE: enough to plant a DLL
        // beside the executable for side-loading into the elevated process.
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x2;;;BU)");
        let error = sd.verify_with_mask(PARENT_DIRECTORY_TAMPER_MASK).unwrap_err();
        assert!(
            error.to_string().contains("grants write access"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn untrusted_add_subdirectory_right_is_rejected_on_hosting_directory() {
        // FILE_APPEND_DATA (0x4) on a directory is FILE_ADD_SUBDIRECTORY.
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x4;;;AU)");
        let error = sd.verify_with_mask(PARENT_DIRECTORY_TAMPER_MASK).unwrap_err();
        assert!(
            error.to_string().contains("grants write access"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn untrusted_create_rights_are_tolerated_on_higher_ancestors() {
        // Stock drive roots grant Authenticated Users add-file/add-subdirectory rights;
        // those cannot redirect an existing path component, so higher ancestors only
        // reject rename/delete and descriptor rewrites.
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x6;;;AU)");
        sd.verify_with_mask(DIRECTORY_TAMPER_MASK)
            .expect("create rights on higher ancestors must be tolerated");
    }

    #[test]
    fn untrusted_delete_child_right_is_rejected_on_higher_ancestors() {
        // FILE_DELETE_CHILD (0x40) lets a principal swap path components underneath the
        // verified executable.
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x40;;;BU)");
        let error = sd.verify_with_mask(DIRECTORY_TAMPER_MASK).unwrap_err();
        assert!(
            error.to_string().contains("grants write access"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn missing_dacl_is_rejected() {
        // Owner only, no DACL: everyone gets full control.
        let sd = SddlDescriptor::parse("O:SY");
        let error = sd.verify().unwrap_err();
        assert!(error.to_string().contains("NULL DACL"), "unexpected error: {error}");
    }

    #[test]
    fn callback_allow_ace_is_treated_as_unconditional_allow() {
        // Conditional (callback) allow ACE for a trusted SID: the condition can only
        // narrow the grant, so it is accepted as if unconditional.
        let sd = SddlDescriptor::parse(r#"O:SYD:(XA;;FA;;;SY;(1==1))"#);
        sd.verify().unwrap();

        // The same callback ACE for an untrusted SID is still rejected.
        let sd = SddlDescriptor::parse(r#"O:SYD:(XA;;FA;;;WD;(1==1))"#);
        let error = sd.verify().unwrap_err();
        assert!(
            error.to_string().contains("grants write access"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn process_trust_label_write_ace_is_accepted_for_executables_only() {
        // `S-1-19-512-4096` (ProtectedLight-WinTcb) appears on Store-app binaries under
        // `Program Files\WindowsApps`; only Windows-signed protected processes hold it.
        let sd = SddlDescriptor::parse("O:SYD:(A;;FA;;;SY)(A;;FA;;;S-1-19-512-4096)");
        sd.verify_as_executable().unwrap();

        // For the policy file it remains untrusted.
        let error = sd.verify().unwrap_err();
        assert!(
            error.to_string().contains("grants write access"),
            "unexpected error: {error}"
        );
    }

    fn grant(permissions: u32, sid: Sid) -> ExplicitAccess {
        ExplicitAccess {
            access_permissions: permissions,
            access_mode: GRANT_ACCESS,
            inheritance: NO_INHERITANCE,
            trustee: Trustee::Sid(sid),
        }
    }

    fn set_security(path: &Path, owner: Option<&Sid>, entries: &[ExplicitAccess]) -> anyhow::Result<()> {
        let dacl = InheritableAcl {
            kind: InheritableAclKind::Protected,
            acl: Acl::new()?.set_entries(entries)?,
        };

        let name = U16CString::from_os_str(path.as_os_str()).expect("no interior NUL in temp path");

        set_named_security_info(&name, SE_FILE_OBJECT, owner, None, Some(&dacl), None)
    }

    #[test]
    fn everyone_writable_policy_file_is_rejected() {
        let temp = tempfile::NamedTempFile::new().unwrap();

        let everyone = Sid::from_well_known(WinWorldSid, None).unwrap();
        set_security(temp.path(), None, &[grant(GENERIC_ALL.0, everyone)]).unwrap();

        let file = File::open(temp.path()).unwrap();
        let result = verify_policy_file_security(&file);

        assert!(result.is_err(), "everyone-writable policy file must be rejected");
    }

    #[test]
    fn system_owned_admin_only_policy_file_is_accepted() {
        let temp = tempfile::NamedTempFile::new().unwrap();

        let admins = Sid::from_well_known(WinBuiltinAdministratorsSid, None).unwrap();

        // Setting the owner to Administrators requires an elevated token; skip otherwise.
        // The equivalent owner/DACL combinations are covered by the SDDL-based tests above.
        if set_security(temp.path(), Some(&admins), &[]).is_err() {
            return;
        }

        let system = Sid::from_well_known(WinLocalSystemSid, None).unwrap();
        let users = Sid::from_well_known(windows::Win32::Security::WinBuiltinUsersSid, None).unwrap();
        set_security(
            temp.path(),
            None,
            &[
                grant(GENERIC_ALL.0, system),
                grant(GENERIC_ALL.0, admins),
                grant(windows::Win32::Foundation::GENERIC_READ.0, users),
            ],
        )
        .unwrap();

        let file = File::open(temp.path()).unwrap();

        verify_policy_file_security(&file).expect("SYSTEM/Administrators-only policy file must be accepted");
    }

    #[test]
    fn everyone_writable_executable_path_is_rejected() {
        let temp_dir = tempfile::tempdir().unwrap();
        let exe = temp_dir.path().join("fake.exe");
        std::fs::write(&exe, b"").unwrap();

        let everyone = Sid::from_well_known(WinWorldSid, None).unwrap();
        set_security(&exe, None, &[grant(GENERIC_ALL.0, everyone)]).unwrap();

        let error = verify_elevated_executable_security(&exe, true).unwrap_err();
        assert!(
            error.to_string().contains("elevated package-manager executable"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn missing_executable_path_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("does-not-exist.exe");

        let error = verify_elevated_executable_security(&missing, true).unwrap_err();
        assert!(
            error.to_string().contains("failed to open"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn non_elevated_executable_is_not_verified() {
        let temp_dir = tempfile::tempdir().unwrap();
        let exe = temp_dir.path().join("fake.exe");
        std::fs::write(&exe, b"").unwrap();

        let guard = verify_elevated_executable_security(&exe, false).unwrap();
        assert!(guard.is_none(), "no guard is produced for non-elevated executions");
    }

    #[test]
    fn protected_system32_executable_is_accepted_for_elevated_execution() {
        // Exercises the full chain on a real Windows-protected binary: TrustedInstaller
        // ownership and write ACEs on the file, plus the ancestor-directory walk over
        // System32, Windows, and the drive root.
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        let cmd = Path::new(&system_root).join("System32").join("cmd.exe");

        let guard = verify_elevated_executable_security(&cmd, true)
            .expect("a protected System32 executable must be accepted")
            .expect("a guard must be produced for elevated executions");

        assert!(guard.path().is_absolute());
        assert!(
            guard.path().ends_with("cmd.exe"),
            "unexpected final path: {}",
            guard.path().display()
        );
        assert!(
            !guard.path().to_string_lossy().starts_with(r"\\?\"),
            "final path must be in plain Win32 form: {}",
            guard.path().display()
        );
    }
}
