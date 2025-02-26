use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::ptr;

use anyhow::{bail, Context as _};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_INVALID_SID, MAX_PATH, WIN32_ERROR};
use windows::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NERR_UserNotFound, NetApiBufferFree, NetUserGetInfo, USER_INFO_4,
};
use windows::Win32::Security;
use windows::Win32::Security::Authentication::Identity::{
    GetUserNameExW, LsaFreeMemory, NameSamCompatible, EXTENDED_NAME_FORMAT,
};
use windows::Win32::System::GroupPolicy::PI_NOUI;
use windows::Win32::UI::Shell::{CreateProfile, LoadUserProfileW, UnloadUserProfile, PROFILEINFOW};

use crate::handle::HandleWrapper;
use crate::identity::sid::Sid;
use crate::scope_guard::ScopeGuard;
use crate::str::{U16CStr, U16CStrExt, U16CString, UnicodeStr};
use crate::token::Token;
use crate::undoc::{
    LsaManageSidNameMapping, LsaSidNameMappingOperation_Add, LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT,
    LSA_SID_NAME_MAPPING_OPERATION_GENERIC_OUTPUT,
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
                let _ = unsafe { LsaFreeMemory(Some(ptr.cast())) };
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
    let domain_sid = create_virtual_identifier(virt_domain_id, virt_domain_name, None)?;
    let account_sid = create_virtual_identifier(virt_domain_id, virt_domain_name, Some(token))?;

    if account_sid.is_valid() {
        Ok(Account {
            domain_sid,
            sid: account_sid,
            name: virtual_account_name(token)?,
            domain_name: virt_domain_name.to_owned(),
        })
    } else {
        bail!(crate::Error::from_win32(ERROR_INVALID_SID))
    }
}

pub fn get_username(format: EXTENDED_NAME_FORMAT) -> windows::core::Result<U16CString> {
    let mut required_size = 0u32;

    // Ignore return code since we only care about size.
    // SAFETY: No preconditions. Required size is valid.
    let _ = unsafe { GetUserNameExW(format, PWSTR::null(), &mut required_size) };

    let mut buf = vec![0u16; required_size as usize];

    // SAFETY: lpNameBuffer is correctly sized and matches the size announced in nSize AKA required_size.
    let ret = unsafe { GetUserNameExW(format, PWSTR::from_raw(buf.as_mut_ptr()), &mut required_size) };

    if !ret.as_bool() {
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
    let mut name = token.username(NameSamCompatible)?;

    // SAFETY: We ensure no interior nul value is inserted.
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
        )?
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
        unsafe { LoadUserProfileW(profile_info.token.handle().raw(), &mut profile_info.raw) }?;

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

#[cfg(test)]
mod tests {
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
}
