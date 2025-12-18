//! Security-related functions for the updater (e.g. file permission settings).

use camino::Utf8Path;
use win_api_wrappers::utils::WideString;

use crate::updater::UpdaterError;

/// DACL for the update.json file:
/// Owner: SYSTEM
/// Group: SYSTEM
/// Access:
/// - SYSTEM: Full control
/// - NETWORK SERVICE: Write, Read (Allow Devolutions Gateway service to update the file)
/// - Administrators: Full control
/// - Users: Read
pub(crate) const UPDATE_JSON_DACL: &str = "D:PAI(A;;FA;;;SY)(A;;0x1201bf;;;NS)(A;;FA;;;BA)(A;;FR;;;BU)";

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
