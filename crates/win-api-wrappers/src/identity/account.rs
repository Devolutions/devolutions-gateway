use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::ptr;

use anyhow::{Context as _, bail};
use windows::Win32::Foundation::{ERROR_INVALID_SID, ERROR_MORE_DATA, GetLastError, MAX_PATH, WIN32_ERROR};
use windows::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NERR_UserNotFound, NetApiBufferFree, NetUserGetInfo, USER_INFO_4,
};
use windows::Win32::Security;
use windows::Win32::Security::Authentication::Identity;
use windows::Win32::System::GroupPolicy::PI_NOUI;
use windows::Win32::UI::Shell::{CreateProfile, LoadUserProfileW, PROFILEINFOW, UnloadUserProfile};
use windows::core::{PCWSTR, PWSTR};

use crate::handle::HandleWrapper;
use crate::identity::sid::Sid;
use crate::raw_buffer::RawBuffer;
use crate::scope_guard::ScopeGuard;
use crate::str::{U16CStr, U16CStrExt, U16CString, UnicodeStr};
use crate::token::Token;
use crate::undoc::{
    LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT, LSA_SID_NAME_MAPPING_OPERATION_GENERIC_OUTPUT, LsaManageSidNameMapping,
    LsaSidNameMappingOperation_Add,
};
use crate::utils::u32size_of;

/// Describes an account and the domain where is found.
#[derive(Debug)]
pub struct Account {
    /// Security identifier for the account.
    pub sid: Sid,
    /// Account name that corresponds to the account SID.
    pub name: U16CString,
    /// Security identifier for the domain where the account is found.
    pub domain_sid: Sid,
    /// Name of the domain where the account is found.
    pub domain_name: U16CString,
}

#[derive(Debug)]
pub struct AccountWithType {
    inner: Account,

    /// SID_NAME_USE indicating the type of the account.
    pub ty: Security::SID_NAME_USE,
}

impl Deref for AccountWithType {
    type Target = Account;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for AccountWithType {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl AccountWithType {
    pub fn wrap(account: Account, ty: Security::SID_NAME_USE) -> Self {
        Self { inner: account, ty }
    }
}

/// Creates a virtual security identifier for a given domain
///
/// # References
///
/// - https://call4cloud.nl/wp-content/uploads/2023/05/flowcreateadmin.bmp
/// - https://github.com/tyranid/setsidmapping/blob/main/SetSidMapping/Program.cs
pub fn create_virtual_identifier(domain_id: u32, domain_name: &U16CStr, token: Option<&Token>) -> anyhow::Result<Sid> {
    let mut sid = Sid::new((1, Security::SECURITY_NT_AUTHORITY), domain_id);

    if let Some(token) = token {
        let token_sid_and_attributes = token.sid_and_attributes()?;

        token_sid_and_attributes
            .sid
            .as_slice()
            .iter()
            .skip(1)
            .copied()
            .for_each(|sub_authority| sid.push(sub_authority));
    }

    let account_name = token.map(virtual_account_name).transpose()?.unwrap_or_default();

    let domain_name = UnicodeStr::new(domain_name).context("domain name")?;
    let account_name = UnicodeStr::new(&account_name).context("account name")?;

    let input = LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT {
        DomainName: domain_name.as_unicode_string(),
        AccountName: account_name.as_unicode_string(),
        Sid: sid.as_psid(),
        ..Default::default()
    };

    let mut output = ScopeGuard::new(
        ptr::null_mut::<LSA_SID_NAME_MAPPING_OPERATION_GENERIC_OUTPUT>(),
        |ptr| {
            if !ptr.is_null() {
                // SAFETY: Pointers allocated by LsaManageSidNameMapping must be freed using LsaFreeMemory.
                let _ = unsafe { Identity::LsaFreeMemory(Some(ptr.cast())) };
            }
        },
    );

    // SAFETY:
    // - When LsaSidNameMappingOperation_Add is specified, OpInput must be a LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT.
    // - LsaManageSidNameMapping is not mutating DomainName nor AccountName.
    let _ = unsafe {
        LsaManageSidNameMapping(
            LsaSidNameMappingOperation_Add,
            &input as *const _ as *const _,
            output.as_mut(),
        )
    };

    // We ignore the result because it will almost run successfully, but still returns a failing status code.

    Ok(sid)
}

pub fn create_virtual_account(
    virt_domain_id: u32,
    virt_domain_name: &U16CStr,
    token: &Token,
) -> anyhow::Result<Account> {
    let domain_sid = create_virtual_identifier(virt_domain_id, virt_domain_name, None)
        .context("create virtual identifier for domain")?;

    let account_sid = create_virtual_identifier(virt_domain_id, virt_domain_name, Some(token))
        .context("create virtual identifier for account")?;

    if account_sid.is_valid() {
        Ok(Account {
            domain_sid,
            sid: account_sid,
            name: virtual_account_name(token).context("find virtual account name for token")?,
            domain_name: virt_domain_name.to_owned(),
        })
    } else {
        Err(anyhow::Error::new(crate::Error::from_win32(ERROR_INVALID_SID)).context("account SID is invalid"))
    }
}

/// Retrieves the name of the user or other security principal associated with the calling thread.
/// You can specify the format of the returned name.
///
/// # Parameters
///
/// - `format`: The format of the name. It cannot be `NameUnknown`.
///   If the user account is not in a domain, only `NameSamCompatible` is supported.
pub fn get_username(format: Identity::EXTENDED_NAME_FORMAT) -> windows::core::Result<U16CString> {
    // The output has a variable size.
    // Therefore, we must call GetUserNameExW once with a zero-size, and check for the ERROR_MORE_DATA status.
    // At this point, we call GetUserNameExW again with a buffer of the correct size.

    let mut required_size = 0u32;

    // SAFETY: lpNameBuffer being null is fine because nSize is set to 0.
    let ret = unsafe { Identity::GetUserNameExW(format, None, &mut required_size) };

    assert!(!ret);

    // SAFETY: FFI call with no outstanding precondition.
    if unsafe { GetLastError() } != ERROR_MORE_DATA {
        return Err(windows::core::Error::from_win32());
    }

    let mut buf = vec![0u16; required_size as usize];

    // SAFETY: lpNameBuffer is correctly sized and matches the size announced in nSize AKA required_size.
    let ret = unsafe { Identity::GetUserNameExW(format, Some(PWSTR::from_raw(buf.as_mut_ptr())), &mut required_size) };

    if !ret {
        return Err(windows::core::Error::from_win32());
    }

    Ok(U16CString::from_vec_truncate(buf))
}

pub fn is_username_valid(server_name: Option<&U16CStr>, username: &U16CStr) -> anyhow::Result<bool> {
    // consent.exe is using USER_INFO_4, so we do the same.
    let mut user_info_4 = ScopeGuard::new(ptr::null_mut::<USER_INFO_4>(), |user_info_4| {
        if !user_info_4.is_null() {
            // SAFETY: Buffer allocated by NetUserGetInfo must be freed using NetApiBufferFree.
            unsafe {
                NetApiBufferFree(Some(user_info_4.cast()));
            }
        }
    });

    // SAFETY: When level is set to 4, USER_INFO_4 is returned.
    let status = unsafe {
        NetUserGetInfo(
            server_name.map_or_else(PCWSTR::null, U16CStrExt::as_pcwstr),
            username.as_pcwstr(),
            4,
            user_info_4.as_mut_ptr().cast(),
        )
    };

    // TODO: Support other errors and hardcheck on NERR_UserNotFound.
    if status == NERR_Success {
        Ok(true)
    } else if status == NERR_UserNotFound {
        Ok(false)
    } else {
        bail!(crate::Error::from_win32(WIN32_ERROR(status)))
    }
}

pub fn virtual_account_name(token: &Token) -> anyhow::Result<U16CString> {
    let mut name = token.username(Identity::NameSamCompatible)?;

    // SAFETY: We ensure no interior nul value is inserted in all of the code using u16_slice
    let u16_slice = unsafe { name.as_mut_slice() };

    // Roughly equivalent to utf8str.replace('\\', '_').
    u16_slice.iter_mut().for_each(|codepoint| {
        if *codepoint == u16::from(b'\\') {
            *codepoint = u16::from(b'_');
        }
    });

    Ok(name)
}

pub fn create_profile(account_sid: &Sid, account_name: &U16CStr) -> anyhow::Result<U16CString> {
    let mut profile_path: Vec<u16> = vec![0u16; MAX_PATH as usize];

    let account_string_sid = account_sid.to_string_sid()?;

    // SAFETY: FFI call with no outstanding precondition.
    unsafe {
        CreateProfile(
            account_string_sid.as_u16cstr().as_pcwstr(),
            account_name.as_pcwstr(),
            profile_path.as_mut_slice(),
        )
        .with_context(|| {
            format!("CreateProfile failed (account_string_sid: {account_string_sid:?}, account_name: {account_name:?}, profile_path: {profile_path:?}")
        })?
    };

    Ok(U16CString::from_vec_truncate(profile_path))
}

pub struct ProfileInfo {
    token: Token,
    username: U16CString,
    raw: PROFILEINFOW, // FIXME: Anti-pattern.
}

impl ProfileInfo {
    pub fn from_token(token: Token, username: U16CString) -> anyhow::Result<Self> {
        let mut profile_info = Self {
            token,
            username,
            raw: PROFILEINFOW {
                dwSize: u32size_of::<PROFILEINFOW>(),
                dwFlags: PI_NOUI,
                ..Default::default()
            },
        };

        profile_info.raw.lpUserName = profile_info.username.as_pwstr();

        // SAFETY: Only prerequisite is for `profile_info`'s `dwSize` member to be set correctly, which it is.
        unsafe {
            LoadUserProfileW(profile_info.token.handle().raw(), &mut profile_info.raw)
                .with_context(|| format!("LoadUserProfileW failed (username: {:?})", profile_info.username))?;
        };

        Ok(profile_info)
    }
}

impl Drop for ProfileInfo {
    fn drop(&mut self) {
        // SAFETY: No preconditions.
        unsafe {
            let _ = UnloadUserProfile(self.token.handle().raw(), self.raw.hProfile);
        }
    }
}

/// Retrieves a security identifier for the account and the name of the domain on which the account was found
pub fn lookup_account_by_name(account_name: &U16CStr) -> windows::core::Result<AccountWithType> {
    // The output has a variable size.
    // Therefore, we must call LookupAccountNameW once with a zero-size, and check for the ERROR_INSUFFICIENT_BUFFER status.
    // At this point, we call LookupAccountNameW again with a buffer of the correct size.

    let mut sid_size: u32 = 0;
    let mut domain_name_size: u32 = 0;
    let mut sid_use = Security::SID_NAME_USE::default();

    // SAFETY: Variable-sized parameters are provided as null pointers for the first call.
    unsafe {
        let _ = Security::LookupAccountNameW(
            None,                     // local system
            account_name.as_pcwstr(), // account name to look up
            None,                     // no SID buffer yet
            &mut sid_size,            // receives required SID buffer size
            None,                     // no domain name buffer yet
            &mut domain_name_size,    // receives required domain name length (characters)
            &mut sid_use,             // receives the SID type (user/group)
        );
    }

    let sid_align = align_of::<Security::SID>();
    let sid_layout = std::alloc::Layout::from_size_align(sid_size as usize, sid_align).expect("valid layout");

    // SAFETY: The layout initialization is checked using the Layout::from_size_align method.
    let mut sid = unsafe { RawBuffer::alloc_zeroed(sid_layout).expect("oom") };

    let mut domain_name = vec![0u16; domain_name_size as usize];

    // SAFETY: The buffers are sized based on the returned values by the first call.
    unsafe {
        Security::LookupAccountNameW(
            None,
            account_name.as_pcwstr(),
            Some(Security::PSID(sid.as_mut_ptr().cast())),
            &mut sid_size,
            Some(PWSTR(domain_name.as_mut_ptr())),
            &mut domain_name_size,
            &mut sid_use,
        )?;
    }

    // SAFETY: LookupAccountNameW returned with success, the SID struct is expected to be initialized.
    let sid = unsafe { sid.assume_init::<Security::SID>() };

    // SAFETY: Again, assuming LookupAccountNameW returned a valid SID.
    let sid = unsafe { Sid::from_raw(sid) };

    let account = Account {
        sid: sid.clone(),
        name: account_name.to_owned(),
        domain_sid: sid,
        domain_name: U16CString::from_vec_truncate(domain_name),
    };

    Ok(AccountWithType::wrap(account, sid_use))
}

pub fn enumerate_account_rights(sid: &Sid) -> anyhow::Result<Vec<U16CString>> {
    // Open the local security policy (LSA Policy)

    let object_attrs = Identity::LSA_OBJECT_ATTRIBUTES {
        Length: u32size_of::<Identity::LSA_OBJECT_ATTRIBUTES>(),
        ..Default::default()
    };

    let mut policy_handle = ScopeGuard::new(Identity::LSA_HANDLE::default(), |handle| {
        // FIXME: maybe we should log the error here.
        // SAFETY: handle is a handle to a Policy object returned by the LsaOpenPolicy function.
        let _ = unsafe { Identity::LsaClose(handle) };
    });

    // SAFETY: FFI call with no outstanding precondition.
    let open_policy_status = unsafe {
        Identity::LsaOpenPolicy(
            None,
            &object_attrs,
            Identity::POLICY_LOOKUP_NAMES as u32,
            policy_handle.as_mut_ptr(),
        )
    };

    if open_policy_status.is_err() {
        // Convert NTSTATUS to a Win32 error code and return as an error
        // SAFETY: LsaNtStatusToWinError is always safe to call with any NTSTATUS value.
        let error_code = unsafe { Identity::LsaNtStatusToWinError(open_policy_status) };
        let error_code = WIN32_ERROR(error_code);

        return Err(anyhow::Error::new(windows::core::Error::from(error_code)).context("LsaOpenPolicy failed"));
    }

    // Enumerate the rights/privileges assigned to the user account.

    let mut rights = ScopeGuard::new(ptr::null_mut::<Identity::LSA_UNICODE_STRING>(), |ptr| {
        if !ptr.is_null() {
            // FIXME: maybe we should log the error here.
            // SAFETY: ptr is a valid pointer returned by LsaEnumerateAccountRights.
            let _ = unsafe { Identity::LsaFreeMemory(Some(ptr as *const std::ffi::c_void)) };
        }
    });

    let mut rights_count: u32 = 0;

    // SAFETY: We pass valid pointers and policy_handle was obtained from LsaOpenPolicy.
    let enum_status = unsafe {
        Identity::LsaEnumerateAccountRights(
            *policy_handle.as_ref(),
            sid.as_psid_const(),
            rights.as_mut_ptr(),
            &mut rights_count,
        )
    };

    let rights = if enum_status == windows::Win32::Foundation::STATUS_OBJECT_NAME_NOT_FOUND {
        // The account doesn’t have any explicitly assigned rights.
        Vec::new()
    } else if enum_status.is_err() {
        // Convert NTSTATUS to a Win32 error code and return as an error
        // SAFETY: LsaNtStatusToWinError is always safe to call with any NTSTATUS value.
        let error_code = unsafe { Identity::LsaNtStatusToWinError(enum_status) };
        let error_code = WIN32_ERROR(error_code);

        return Err(
            anyhow::Error::new(windows::core::Error::from(error_code)).context("LsaEnumerateAccountRights failed")
        );
    } else {
        // SAFETY: We assume LsaEnumerateAccountRights is returing consistent values for rights and rights_count.
        let rights = unsafe { std::slice::from_raw_parts(*rights.as_ref(), rights_count as usize) };

        rights
            .iter()
            .map(|right| {
                // SAFETY: We assume LsaEnumerateAccountRights is returning valid LSA_UNICODE_STRING structs.
                unsafe { U16CString::from_ptr_truncate(right.Buffer.0.cast_const(), right.Length as usize) }
            })
            .collect()
    };

    Ok(rights)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::print_stdout)]

    use super::*;
    use crate::process::Process;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn get_virtual_account_name() {
        // Retrieve a non-pseudo-token with TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE access rights.
        // Without these access rights, Windows will return an "Access is denied." error.
        let current_process = Process::current_process();
        let token = current_process
            .token(Security::TOKEN_QUERY | Security::TOKEN_DUPLICATE | Security::TOKEN_IMPERSONATE)
            .unwrap();

        let account_name = virtual_account_name(&token).unwrap();
        let account_name = account_name.as_ucstr().to_string_lossy();

        // Check that the UTF-16 substring substition logic is working as expected.
        assert!(account_name.contains('_'));
        assert!(!account_name.contains('\\'));
    }

    // Note that in order for this test to be completely reproducible, we would need to use a specific account
    // that we know for sure has a specific set of rights.
    // It’s still better than nothing.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn lookup_and_enumerate_rights() {
        let username = get_username(Identity::NameSamCompatible).unwrap();
        let account = lookup_account_by_name(&username).unwrap();
        let rights = enumerate_account_rights(&account.sid).unwrap();
        print!("{rights:?}");
    }
}
