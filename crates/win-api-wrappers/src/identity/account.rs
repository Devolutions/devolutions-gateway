use std::fmt::Debug;
use std::hash::Hash;
use std::mem::{self};
use std::ptr;

use anyhow::{bail, Result};

use crate::error::Error;
use crate::handle::HandleWrapper;
use crate::token::Token;
use crate::undoc::{
    LsaManageSidNameMapping, LsaSidNameMappingOperation_Add, LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT,
    LSA_SID_NAME_MAPPING_OPERATION_GENERIC_OUTPUT,
};
use crate::utils::WideString;
use windows::core::{HRESULT, PWSTR};
use windows::Win32::Foundation::{ERROR_INVALID_SID, MAX_PATH};
use windows::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NERR_UserNotFound, NetApiBufferFree, NetUserGetInfo, USER_INFO_4,
};
use windows::Win32::Security::Authentication::Identity::{
    GetUserNameExW, LsaFreeMemory, NameSamCompatible, EXTENDED_NAME_FORMAT,
};
use windows::Win32::Security::{PSID, SECURITY_NT_AUTHORITY};
use windows::Win32::System::GroupPolicy::PI_NOUI;
use windows::Win32::UI::Shell::{CreateProfile, LoadUserProfileW, PROFILEINFOW};

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

    let raw_sid = RawSid::from(&sid);

    let domain_name = WideString::from(domain_name);
    let account_name = token
        .map(virtual_account_name)
        .transpose()?
        .map(WideString::from)
        .unwrap_or_default();

    // Just as intune?
    let input = LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT {
        DomainName: domain_name.as_unicode_string(),
        AccountName: account_name.as_unicode_string(),
        Sid: PSID(raw_sid.as_raw() as *const _ as _),
        ..Default::default()
    };

    let mut output = ptr::null_mut::<LSA_SID_NAME_MAPPING_OPERATION_GENERIC_OUTPUT>();

    unsafe {
        let _r = LsaManageSidNameMapping(
            LsaSidNameMappingOperation_Add,
            &input as *const _ as _,
            &mut output as _,
        );

        if !output.is_null() {
            LsaFreeMemory(Some(output as _)).ok()?;
        }
    }

    Ok(sid)
}

pub fn create_virtual_account(domain_id: u32, domain_name: &str, token: &Token) -> Result<Account> {
    let domain_sid = create_virtual_identifier(domain_id, domain_name, None)?;
    let account_sid = create_virtual_identifier(domain_id, domain_name, Some(token))?;

    if account_sid.is_valid() {
        Ok(Account {
            domain_sid,
            account_sid,
            account_name: virtual_account_name(token)?,
            domain_name: domain_name.to_owned(),
        })
    } else {
        bail!(Error::from_win32(ERROR_INVALID_SID))
    }
}

pub fn get_username(format: EXTENDED_NAME_FORMAT) -> Result<String> {
    let mut required_size = 0u32;

    let _ = unsafe { GetUserNameExW(format, PWSTR::null(), &mut required_size as _) };

    let mut buf = vec![0u16; required_size as _];
    let mut tchars_copied = buf.len() as u32;
    let success = unsafe { GetUserNameExW(format, PWSTR::from_raw(buf.as_mut_ptr()), &mut tchars_copied as _) };

    if success.into() {
        Ok(String::from_utf16(&buf[..tchars_copied as _])?)
    } else {
        bail!(Error::last_error())
    }
}

pub fn is_username_valid(server_name: Option<&String>, username: &str) -> Result<bool> {
    let server_name = server_name.map(WideString::from).unwrap_or_default();
    let username = WideString::from(username);

    let status = unsafe {
        // 4 is arbitrary. consent.exe uses it so we do too
        let mut out = ptr::null_mut::<USER_INFO_4>();
        let status = NetUserGetInfo(
            server_name.as_pcwstr(),
            username.as_pcwstr(),
            4,
            &mut out as *mut _ as _,
        );

        NetApiBufferFree(Some(out as _));

        status
    };

    // TODO: Support other errors and hardcheck on NERR_UserNotFound
    if status == NERR_Success {
        Ok(true)
    } else if status == NERR_UserNotFound {
        Ok(false)
    } else {
        bail!(Error::from_hresult(HRESULT(status as _)))
    }
}

pub fn virtual_account_name(token: &Token) -> Result<String> {
    Ok(token.username(NameSamCompatible)?.replace("\\", "_"))
}

pub fn create_profile(account_sid: &Sid, account_name: &str) -> Result<String> {
    let mut buf: Vec<u16> = vec![0; MAX_PATH as _];

    unsafe {
        CreateProfile(
            WideString::from(&account_sid.to_string()).as_pcwstr(),
            WideString::from(account_name).as_pcwstr(),
            buf.as_mut_slice(),
        )?;
    }

    let raw_string = buf.into_iter().take_while(|x| *x != 0).collect::<Vec<_>>();

    Ok(String::from_utf16(&raw_string)?)
}

pub struct ProfileInfo<'a> {
    token: &'a Token,
    username: WideString,
    raw: PROFILEINFOW,
}

impl<'a> ProfileInfo<'a> {
    pub fn from_token(token: &'a Token, username: &str) -> Result<Self> {
        let mut profile_info = Self {
            token,
            username: WideString::from(username),
            raw: PROFILEINFOW {
                dwSize: mem::size_of::<PROFILEINFOW>() as _,
                dwFlags: PI_NOUI,
                ..Default::default()
            },
        };

        profile_info.raw.lpUserName = profile_info.username.as_pwstr();

        unsafe {
            LoadUserProfileW(profile_info.token.handle().raw(), &mut profile_info.raw)?;
        }

        Ok(profile_info)
    }
}

impl<'a> Drop for ProfileInfo<'a> {
    fn drop(&mut self) {
        // unsafe {
        // TODO unload
        // let _ = UnloadUserProfile(self.token.handle, self.raw.hProfile);
        // }
    }
}
