//! Admin-only-writable file security validation.
//!
//! Shared by two trust boundaries in the package broker:
//! - The policy file, which is the entire authorization control for the broker.
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
//! For the policy file, the trusted principals are SYSTEM and the built-in
//! Administrators group. For executables, `NT SERVICE\TrustedInstaller` is trusted as
//! well, since Windows-protected binaries (`System32`, `Program Files`, `WindowsApps`)
//! are owned by and writable by that service.
//!
//! For elevated executables the verification additionally defends against
//! time-of-check/time-of-use races: the file is opened without write or delete sharing
//! and the returned [`VerifiedExecutable`] guard keeps that handle alive so the verified
//! object cannot be written, deleted, or renamed until it has been executed. Execution is
//! bound to the final path resolved from the verified handle (defeating reparse-point
//! retargeting of the originally supplied name), and every ancestor directory of that
//! path is checked so untrusted principals cannot swap path components either.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::os::windows::ffi::OsStringExt as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use windows::Win32::Foundation::{ERROR_SUCCESS, GENERIC_ALL, GENERIC_WRITE, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, INHERIT_ONLY_ACE, IsWellKnownSid,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS, FILE_NAME_NORMALIZED,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    FILE_WRITE_EA, GetFinalPathNameByHandleW, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
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
    /// SYSTEM and the built-in Administrators group (policy file).
    AdminOnly,
    /// Additionally trusts `NT SERVICE\TrustedInstaller` (Windows-protected executables).
    AdminOrTrustedInstaller,
}

// ACE type constants from winnt.h (the Win32_System_SystemServices feature is not enabled).
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const SYSTEM_AUDIT_ACE_TYPE: u8 = 2;
const SYSTEM_ALARM_ACE_TYPE: u8 = 3;

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
///   the trustee (inherit-only ACEs are skipped, since they do not apply to the object).
/// - Unsupported (object/callback) access-allowed ACE types are rejected.
pub(crate) fn verify_policy_file_security(file: &File) -> anyhow::Result<()> {
    verify_handle_security(file, "policy file", TrustedWriters::AdminOnly, WRITE_ACCESS_MASK)
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

    verify_ancestor_directories(&final_path, &subject)?;

    Ok(Some(VerifiedExecutable {
        _file: file,
        path: final_path,
    }))
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
fn verify_ancestor_directories(path: &Path, subject: &str) -> anyhow::Result<()> {
    let mut current = path.parent();
    let mut tamper_mask = PARENT_DIRECTORY_TAMPER_MASK;

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
fn final_path_from_handle(file: &File) -> anyhow::Result<PathBuf> {
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
            ACCESS_DENIED_ACE_TYPE | SYSTEM_AUDIT_ACE_TYPE | SYSTEM_ALARM_ACE_TYPE => {}
            ACCESS_ALLOWED_ACE_TYPE => {
                // SAFETY: The ACE type is ACCESS_ALLOWED_ACE_TYPE, so it has the ACCESS_ALLOWED_ACE layout.
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
                        "{subject} DACL grants write access to {trustee_string}; only trusted principals may be able to write it"
                    );
                }
            }
            // Fail closed on object/callback and other exotic allow ACE types.
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

    // SAFETY: Per function contract, `sid` points to a valid SID.
    trusted_writers == TrustedWriters::AdminOrTrustedInstaller
        && unsafe { sid_to_string(sid) }.eq_ignore_ascii_case(TRUSTED_INSTALLER_SID)
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
    fn callback_allow_ace_is_rejected() {
        // Conditional (callback) allow ACE for a trusted SID: unsupported type, fail closed.
        let sd = SddlDescriptor::parse(r#"O:SYD:(XA;;FA;;;SY;(1==1))"#);
        let error = sd.verify().unwrap_err();
        assert!(
            error.to_string().contains("unsupported ACE type"),
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
