//! Security-related functions for the updater (e.g. file permission settings).

use camino::Utf8Path;

use crate::updater::UpdaterError;

/// DACL for the update.json file:
/// Owner: SYSTEM
/// Group: SYSTEM
/// Access:
/// - SYSTEM: Full control
/// - NETWORK SERVICE: Write, Read (Allow Devolutions Gateway service to update the file)
/// - Administrators: Full control
/// - Users: Read
pub const UPDATE_JSON_DACL: &str = "D:PAI(A;;FA;;;SY)(A;;0x1201bf;;;NS)(A;;FA;;;BA)(A;;FR;;;BU)";

/// Set DACL (Discretionary Access Control List) on a specified file.
pub fn set_file_dacl(file_path: &Utf8Path, acl: &str) -> Result<(), UpdaterError> {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, FALSE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };

    struct OwnedPSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for OwnedPSecurityDescriptor {
        fn drop(&mut self) {
            if self.0 .0.is_null() {
                return;
            }
            unsafe { LocalFree(HLOCAL(self.0 .0)) };
        }
    }

    // Decode ACL string into a security descriptor and get PACL instance.

    let acl_hstring = HSTRING::from(acl);
    let mut psecurity_descriptor = OwnedPSecurityDescriptor(PSECURITY_DESCRIPTOR::default());

    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &acl_hstring,
            SDDL_REVISION_1,
            &mut psecurity_descriptor.0 as _,
            None,
        )
    }
    .map_err(|_| UpdaterError::AclString { acl: acl.to_owned() })?;

    let mut sec_present = FALSE;
    let mut sec_defaulted = FALSE;

    let mut dacl: *mut ACL = std::ptr::null_mut();

    unsafe {
        GetSecurityDescriptorDacl(
            psecurity_descriptor.0,
            &mut sec_present as _,
            &mut dacl as _,
            &mut sec_defaulted as _,
        )
    }
    .map_err(|_| UpdaterError::AclString { acl: acl.to_owned() })?;

    if dacl.is_null() {
        return Err(UpdaterError::AclString { acl: acl.to_owned() });
    }

    let file_path_hstring = HSTRING::from(file_path.as_str());

    let set_permissions_result = unsafe {
        SetNamedSecurityInfoW(
            &file_path_hstring,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
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
