use std::fmt::Debug;
use std::hash::Hash;
use std::ptr;

use anyhow::{bail, Result};

use crate::handle::HandleWrapper;
use crate::token::Token;
use crate::undoc::{
    LsaManageSidNameMapping, LsaSidNameMappingOperation_Add, LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT,
    LSA_SID_NAME_MAPPING_OPERATION_GENERIC_OUTPUT,
};
use crate::utils::{size_of_u32, WideString};
use crate::Error;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_INVALID_SID, MAX_PATH, WIN32_ERROR};
use windows::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NERR_UserNotFound, NetApiBufferFree, NetUserGetInfo, USER_INFO_4,
};
use windows::Win32::Security::Authentication::Identity::{
    GetUserNameExW, LsaFreeMemory, NameSamCompatible, EXTENDED_NAME_FORMAT,
};
use windows::Win32::Security::SECURITY_NT_AUTHORITY;
use windows::Win32::System::GroupPolicy::PI_NOUI;
use windows::Win32::UI::Shell::{CreateProfile, LoadUserProfileW, UnloadUserProfile, PROFILEINFOW};

use super::sid::{RawSid, Sid};

#[derive(Default, Debug, Hash, PartialEq, Eq, Clone)]
pub struct Account {
    pub domain_sid: Sid,
    pub domain_name: String,
    pub account_sid: Sid,
    pub account_name: String,
}

/// https://call4cloud.nl/wp-content/uploads/2023/05/flowcreateadmin.bmp
/// https://github.com/tyranid/setsidmapping/blob/main/SetSidMapping/Program.cs
pub fn create_virtual_identifier(domain_id: u32, domain_name: &str, token: Option<&Token>) -> Result<Sid> {
    let sid = {
        let mut sub_authority = vec![domain_id];
        if let Some(token) = token {
            let token_sid = token.sid_and_attributes()?.sid;

            sub_authority.extend(token_sid.sub_authority.iter().skip(1));
        }

        Sid {
            revision: 1,
            identifier_identity: SECURITY_NT_AUTHORITY,
            sub_authority,
        }
    };

    let raw_sid = RawSid::try_from(&sid)?;

    let domain_name = WideString::from(domain_name);
    let account_name = token
        .map(virtual_account_name)
        .transpose()?
        .map(WideString::from)
        .unwrap_or_default();

    let input = LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT {
        DomainName: domain_name.as_unicode_string()?,
        AccountName: account_name.as_unicode_string()?,
        Sid: raw_sid.as_psid(),
        ..Default::default()
    };

    let mut output = ptr::null_mut::<LSA_SID_NAME_MAPPING_OPERATION_GENERIC_OUTPUT>();

    // We ignore the result because it will almost run successfully while returning a failing code.
    // SAFETY: Since `LsaSidNameMappingOperation_Add` is specified, `OpInput` will be read as a `LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT`.
    let _ = unsafe {
        LsaManageSidNameMapping(
            LsaSidNameMappingOperation_Add,
            &input as *const _ as *const _,
            &mut output,
        )
    };

    if !output.is_null() {
        // SAFETY: No preconditions, and `output` is non null.
        unsafe {
            LsaFreeMemory(Some(output.cast())).ok()?;
        }
    }

    Ok(sid)
}

pub fn create_virtual_account(virt_domain_id: u32, virt_domain_name: &str, token: &Token) -> Result<Account> {
    let domain_sid = create_virtual_identifier(virt_domain_id, virt_domain_name, None)?;
    let account_sid = create_virtual_identifier(virt_domain_id, virt_domain_name, Some(token))?;

    if account_sid.is_valid()? {
        Ok(Account {
            domain_sid,
            account_sid,
            account_name: virtual_account_name(token)?,
            domain_name: virt_domain_name.to_owned(),
        })
    } else {
        bail!(Error::from_win32(ERROR_INVALID_SID))
    }
}

pub fn get_username(format: EXTENDED_NAME_FORMAT) -> Result<String> {
    let mut required_size = 0u32;

    // Ignore return code since we care about size.
    // SAFETY: No preconditions. Required size is valid.
    let _ = unsafe { GetUserNameExW(format, PWSTR::null(), &mut required_size) };

    let mut buf = Vec::with_capacity(required_size as usize);

    // SAFETY: `lpNameBuffer` is correctly sized and matches the size announced in `nSize` AKA `required_size`.
    let success = unsafe { GetUserNameExW(format, PWSTR::from_raw(buf.as_mut_ptr()), &mut required_size) };

    if success.into() {
        Ok(String::from_utf16(&buf[..required_size as usize])?)
    } else {
        bail!(Error::last_error())
    }
}

pub fn is_username_valid(server_name: Option<&String>, username: &str) -> Result<bool> {
    let server_name = server_name.map(WideString::from);
    let username = WideString::from(username);

    let mut out = ptr::null_mut::<USER_INFO_4>();

    // 4 is arbitrary. consent.exe uses it so we do too
    // SAFETY: `server_name` is either NULL which is defined or defined and NUL terminated.
    // `username` is always valid and NUL terminated.
    let status = unsafe {
        NetUserGetInfo(
            server_name.as_ref().map_or_else(PCWSTR::null, WideString::as_pcwstr),
            username.as_pcwstr(),
            4,
            &mut out as *mut _ as *mut _,
        )
    };

    if out.is_null() {
        // SAFETY: No preconditions. `out` is non null.
        unsafe {
            NetApiBufferFree(Some(out.cast()));
        }
    }

    // TODO: Support other errors and hardcheck on NERR_UserNotFound
    if status == NERR_Success {
        Ok(true)
    } else if status == NERR_UserNotFound {
        Ok(false)
    } else {
        bail!(Error::from_win32(WIN32_ERROR(status)))
    }
}

pub fn virtual_account_name(token: &Token) -> Result<String> {
    Ok(token.username(NameSamCompatible)?.replace('\\', "_"))
}

pub fn create_profile(account_sid: &Sid, account_name: &str) -> Result<String> {
    let mut buf: Vec<u16> = vec![0; MAX_PATH as usize];

    let account_sid = WideString::from(&account_sid.to_string());
    let account_name = WideString::from(account_name);

    // SAFETY: `account_sid` and `account_name` are non NULL and NUL terminated. `buf` is big enough to receive profile path.
    unsafe { CreateProfile(account_sid.as_pcwstr(), account_name.as_pcwstr(), buf.as_mut_slice()) }?;

    let raw_string = buf.into_iter().take_while(|x| *x != 0).collect::<Vec<_>>();

    Ok(String::from_utf16(&raw_string)?)
}

pub struct ProfileInfo {
    token: Token,
    username: WideString,
    raw: PROFILEINFOW,
}

impl ProfileInfo {
    pub fn from_token(token: Token, username: &str) -> Result<Self> {
        let mut profile_info = Self {
            token,
            username: WideString::from(username),
            raw: PROFILEINFOW {
                dwSize: size_of_u32::<PROFILEINFOW>(),
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
