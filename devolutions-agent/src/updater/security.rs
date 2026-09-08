//! Security-related functions for the updater (e.g. file permission settings).

use camino::Utf8Path;
use win_api_wrappers::utils::WideString;

use crate::updater::UpdaterError;

/// DACL for the update.json file:
/// Owner: SYSTEM
/// Group: SYSTEM
/// Access:
/// - SYSTEM: Full control
/// - Gateway service account: Write, Read (allow the Devolutions Gateway service to update the file)
/// - Administrators: Full control
/// - Users: Read
///
/// `gateway_sid` is the string SID of the account the Devolutions Gateway service logs on as
/// (`S-1-5-20`, NETWORK SERVICE, by default).
pub(crate) fn update_json_dacl(gateway_sid: &str) -> String {
    format!("D:PAI(A;;FA;;;SY)(A;;0x1201bf;;;{gateway_sid})(A;;FA;;;BA)(A;;FR;;;BU)")
}

/// DACL for the update_status.json file:
/// Owner: SYSTEM
/// Group: SYSTEM
/// Access:
/// - SYSTEM:                  Full control
/// - Gateway service account: Read (allows the Devolutions Gateway service to serve GET endpoints)
/// - Administrators:          Full control
/// - Users:                   Read
///
/// Unlike [`update_json_dacl`], the Gateway service account does not receive write access — the
/// agent is the sole writer of this file.
pub(crate) fn update_status_json_dacl(gateway_sid: &str) -> String {
    format!("D:PAI(A;;FA;;;SY)(A;;FR;;;{gateway_sid})(A;;FA;;;BA)(A;;FR;;;BU)")
}

/// Set DACL (Discretionary Access Control List) on a specified file.
pub(crate) fn set_file_dacl(file_path: &Utf8Path, acl: &str) -> Result<(), UpdaterError> {
    use windows::Win32::Foundation::{ERROR_SUCCESS, FALSE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR};

    struct OwnedPSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for OwnedPSecurityDescriptor {
        fn drop(&mut self) {
            if self.0.0.is_null() {
                return;
            }
            // SAFETY: `self.0` is a valid pointer to a security descriptor, therefore the function
            // is safe to call.
            unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
        }
    }

    // Decode ACL string into a security descriptor and get PACL instance.

    let wide_acl = WideString::from(acl);

    let mut psecurity_descriptor = OwnedPSecurityDescriptor(PSECURITY_DESCRIPTOR::default());

    // SAFETY: `wide_acl` is a valid null-terminated UTF-16 string, `psecurity_descriptor` is a
    // valid pointer to a stack variable, therefore the function is safe to call.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_acl.as_pcwstr(),
            SDDL_REVISION_1,
            &mut psecurity_descriptor.0 as *mut PSECURITY_DESCRIPTOR,
            None,
        )
    }
    .map_err(|_| UpdaterError::AclString { acl: acl.to_owned() })?;

    let mut sec_present = FALSE;
    let mut sec_defaulted = FALSE;

    let mut dacl: *mut ACL = std::ptr::null_mut();

    // SAFETY: `sec_present`, `set_defaulted` and `dacl` are valid pointers to stack variables,
    // `psecurity_descriptor` is a valid pointer returned by the WinAPI call above, therefore the
    // function is safe to call.
    unsafe {
        GetSecurityDescriptorDacl(
            psecurity_descriptor.0,
            &mut sec_present as *mut windows::core::BOOL,
            &mut dacl as *mut *mut ACL,
            &mut sec_defaulted as *mut windows::core::BOOL,
        )
    }
    .map_err(|_| UpdaterError::AclString { acl: acl.to_owned() })?;

    if dacl.is_null() {
        return Err(UpdaterError::AclString { acl: acl.to_owned() });
    }

    let wide_file_path = WideString::from(file_path.as_str());

    // SAFETY: `wide_file_path` points to valid null-terminated UTF-16 string, `dacl` is a valid
    // pointer returned by `GetSecurityDescriptorDacl`, therefore the function is safe to call.
    let set_permissions_result = unsafe {
        SetNamedSecurityInfoW(
            wide_file_path.as_pcwstr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };

    if set_permissions_result != ERROR_SUCCESS {
        return Err(UpdaterError::SetFilePermissions {
            file_path: file_path.to_owned(),
        });
    }

    info!("Changed DACL on `{file_path}` to `{acl}`");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK_SERVICE: &str = "S-1-5-20";

    #[test]
    fn network_service_dacls_match_the_historical_constants() {
        assert_eq!(
            update_json_dacl(NETWORK_SERVICE),
            "D:PAI(A;;FA;;;SY)(A;;0x1201bf;;;S-1-5-20)(A;;FA;;;BA)(A;;FR;;;BU)"
        );
        assert_eq!(
            update_status_json_dacl(NETWORK_SERVICE),
            "D:PAI(A;;FA;;;SY)(A;;FR;;;S-1-5-20)(A;;FA;;;BA)(A;;FR;;;BU)"
        );
    }

    #[test]
    fn custom_account_replaces_only_the_gateway_entry() {
        let sid = "S-1-5-21-1111111111-2222222222-3333333333-1105";
        let dacl = update_json_dacl(sid);
        assert!(dacl.contains(&format!("(A;;0x1201bf;;;{sid})")));
        assert!(!dacl.contains("S-1-5-20"));
        assert!(dacl.starts_with("D:PAI(A;;FA;;;SY)"));
        assert!(dacl.ends_with("(A;;FA;;;BA)(A;;FR;;;BU)"));
    }
}
