//! Policy file security validation.
//!
//! The policy file is the entire authorization control for the package broker.
//! `C:\ProgramData` subtrees are a known spot for over-permissive inherited ACEs:
//! if a standard user can write the policy file, they can self-authorize arbitrary
//! elevated installs.
//!
//! As defense-in-depth, before trusting a loaded policy, we verify that the file is
//! owned by SYSTEM or the built-in Administrators group and that its DACL does not
//! grant write access to any other principal.
//! The broker fails closed (pauses) when this check fails.

use std::fs::File;
use std::os::windows::io::AsRawHandle as _;

use anyhow::{Context as _, bail};
use windows::Win32::Foundation::{ERROR_SUCCESS, GENERIC_ALL, GENERIC_WRITE, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_APPEND_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
};
use windows::core::PWSTR;

/// Access rights that allow modifying the policy file content or its security descriptor.
const WRITE_ACCESS_MASK: u32 = FILE_WRITE_DATA.0 /* modify content */
    | FILE_APPEND_DATA.0 /* append content */
    | FILE_WRITE_EA.0 /* write extended attributes */
    | FILE_WRITE_ATTRIBUTES.0 /* write attributes */
    | DELETE.0 /* delete (and replace) the file */
    | WRITE_DAC.0 /* rewrite the DACL itself */
    | WRITE_OWNER.0 /* take ownership */
    | GENERIC_WRITE.0 /* generic write */
    | GENERIC_ALL.0; /* full control */

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
/// - The owner must be SYSTEM or the built-in Administrators group.
/// - A DACL must be present (a NULL DACL grants everyone full control).
/// - Every access-allowed ACE granting write access must have SYSTEM or the built-in
///   Administrators group as the trustee.
/// - Unsupported (object/callback) access-allowed ACE types are rejected.
pub(crate) fn verify_policy_file_security(file: &File) -> anyhow::Result<()> {
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
        bail!("failed to read policy file security information: error {}", ret.0);
    }

    // SAFETY: On success, `owner` and `dacl` point into `descriptor` (or are null), which
    // outlives this call.
    unsafe { verify_owner_and_dacl(owner, dacl) }
}

/// Verify that `owner` is trusted and that `dacl` grants write access to trusted SIDs only.
///
/// See [`verify_policy_file_security`] for the exact rules.
///
/// # Safety
///
/// - `owner` must be null or point to a valid SID.
/// - `dacl` must be null or point to a valid, initialized ACL.
unsafe fn verify_owner_and_dacl(owner: PSID, dacl: *const ACL) -> anyhow::Result<()> {
    if owner.0.is_null() {
        bail!("policy file has no owner information");
    }

    // SAFETY: Per function contract, `owner` points to a valid SID.
    if !unsafe { is_trusted_sid(owner) } {
        // SAFETY: Per function contract, `owner` points to a valid SID.
        let owner_string = unsafe { sid_to_string(owner) };
        bail!("policy file owner {owner_string} is not SYSTEM or built-in Administrators");
    }

    if dacl.is_null() {
        bail!("policy file has a NULL DACL granting full control to everyone");
    }

    // SAFETY: Per function contract, `dacl` is a valid, non-null pointer to an initialized ACL.
    let ace_count = u32::from(unsafe { (*dacl).AceCount });

    for idx in 0..ace_count {
        let mut ace_ptr: *mut core::ffi::c_void = std::ptr::null_mut();

        // SAFETY: `dacl` is a valid ACL pointer and `idx` is within `AceCount`.
        unsafe { GetAce(dacl, idx, &mut ace_ptr) }.context("failed to read policy file DACL entry")?;

        // SAFETY: GetAce succeeded, so `ace_ptr` points to an ACE starting with an ACE_HEADER.
        let header = unsafe { &*ace_ptr.cast::<ACE_HEADER>() };

        match header.AceType {
            // Deny and audit ACEs never grant access.
            ACCESS_DENIED_ACE_TYPE | SYSTEM_AUDIT_ACE_TYPE | SYSTEM_ALARM_ACE_TYPE => {}
            ACCESS_ALLOWED_ACE_TYPE => {
                // SAFETY: The ACE type is ACCESS_ALLOWED_ACE_TYPE, so it has the ACCESS_ALLOWED_ACE layout.
                let ace = unsafe { &*ace_ptr.cast::<ACCESS_ALLOWED_ACE>() };

                if ace.Mask & WRITE_ACCESS_MASK == 0 {
                    continue;
                }

                let trustee = PSID(std::ptr::from_ref(&ace.SidStart).cast_mut().cast());

                // SAFETY: `SidStart` is the first DWORD of the trustee SID stored inline in the ACE.
                if !unsafe { is_trusted_sid(trustee) } {
                    // SAFETY: `trustee` points to a valid SID inside the ACE.
                    let trustee_string = unsafe { sid_to_string(trustee) };
                    bail!(
                        "policy file DACL grants write access to {trustee_string}; only SYSTEM and built-in Administrators may be able to write the policy"
                    );
                }
            }
            // Fail closed on object/callback and other exotic allow ACE types.
            other => bail!("policy file DACL contains unsupported ACE type {other}"),
        }
    }

    Ok(())
}

/// Returns `true` when the SID is SYSTEM or the built-in Administrators group.
///
/// # Safety
///
/// `sid` must point to a valid SID.
unsafe fn is_trusted_sid(sid: PSID) -> bool {
    // SAFETY: Per function contract, `sid` points to a valid SID.
    let is_system = unsafe { IsWellKnownSid(sid, WinLocalSystemSid) }.as_bool();

    // SAFETY: Per function contract, `sid` points to a valid SID.
    let is_admins = unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) }.as_bool();

    is_system || is_admins
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
            unsafe { verify_owner_and_dacl(self.owner, self.dacl) }
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

    fn set_security(path: &std::path::Path, owner: Option<&Sid>, entries: &[ExplicitAccess]) -> anyhow::Result<()> {
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
}
