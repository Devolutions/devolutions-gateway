use std::ptr::null_mut;

use anyhow::bail;
use windows::Win32::Foundation::WIN32_ERROR;

use crate::identity::account::Account;
use crate::identity::sid::{RawSid, Sid};
use crate::raw::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NetApiBufferFree, NetLocalGroupAddMembers, NetLocalGroupDelMembers, NetLocalGroupGetMembers,
    LOCALGROUP_MEMBERS_INFO_0, MAX_PREFERRED_LENGTH,
};
use crate::raw::Win32::Security::WinBuiltinAdministratorsSid;
use crate::utils::WideString;
use crate::Error;

pub fn add_local_group_member(group_name: &str, security_identifier: &Sid) -> anyhow::Result<()> {
    // SAFETY: It is safe to zero out the structure as it is a simple POD type.
    let mut group_info = unsafe { core::mem::zeroed::<LOCALGROUP_MEMBERS_INFO_0>() };

    let group_name = WideString::from(group_name);

    let user_sid = RawSid::try_from(security_identifier)?;
    group_info.lgrmi0_sid = user_sid.as_psid();

    // SAFETY: All buffers are valid.
    // WideString holds a null-terminated UTF-16 string, and as_pcwstr() returns a valid pointer to it.
    let rc =
        unsafe { NetLocalGroupAddMembers(None, group_name.as_pcwstr(), 0, &group_info as *const _ as *const u8, 1) };

    if rc != NERR_Success {
        bail!(Error::from_win32(WIN32_ERROR(rc)))
    }

    Ok(())
}

pub fn remove_local_group_member(group_name: &str, security_identifier: &Sid) -> anyhow::Result<()> {
    // SAFETY: It is safe to zero out the structure as it is a simple POD type.
    let mut group_info = unsafe { core::mem::zeroed::<LOCALGROUP_MEMBERS_INFO_0>() };

    let group_name = WideString::from(group_name);

    let user_sid = RawSid::try_from(security_identifier)?;
    group_info.lgrmi0_sid = user_sid.as_psid();

    // SAFETY: All buffers are valid.
    // WideString holds a null-terminated UTF-16 string, and as_pcwstr() returns a valid pointer to it.
    let rc =
        unsafe { NetLocalGroupDelMembers(None, group_name.as_pcwstr(), 0, &group_info as *const _ as *const u8, 1) };

    if rc != NERR_Success {
        bail!(Error::from_win32(WIN32_ERROR(rc)))
    }

    Ok(())
}

pub fn get_local_admin_group_members() -> anyhow::Result<Vec<Sid>> {
    let local_admin_group_sid = Sid::from_well_known(WinBuiltinAdministratorsSid, None)?;
    let local_admin_group_account = local_admin_group_sid.account(None)?;
    get_local_group_members(local_admin_group_account.account_name)
}

pub fn get_local_group_members(group_name: String) -> anyhow::Result<Vec<Sid>> {
    let group_name = WideString::from(group_name);
    let mut buffer = null_mut();
    let mut entries_read = 0;
    let mut total_entries = 0;

    // SAFETY: All buffers are valid.
    // WideString holds a null-terminated UTF-16 string, and as_pcwstr() returns a valid pointer to it.
    // `buffer` must be freed by `NetApiBufferFree.
    // Specifying `MAX_PREFERRED_LENGTH` allocates the required amount of memory for the data, and
    // the function will not return `ERROR_MORE_DATA`
    let group_members_slice = unsafe {
        let rc = NetLocalGroupGetMembers(
            None,
            group_name.as_pcwstr(),
            0,
            &mut buffer,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            None,
        );

        if rc != NERR_Success {
            bail!(Error::from_win32(WIN32_ERROR(rc)))
        }

        std::slice::from_raw_parts(
            buffer as *const u8 as *const LOCALGROUP_MEMBERS_INFO_0,
            entries_read as usize,
        )
    };

    let mut group_members = Vec::<Sid>::with_capacity(group_members_slice.len());
    for member in group_members_slice {
        group_members.push(Sid::try_from(member.lgrmi0_sid)?);
    }

    // SAFETY: `buffer` is valid and points to memory allocated by `NetLocalGroupGetMembers`
    unsafe {
        NetApiBufferFree(Some(buffer.cast()));
    }

    Ok(group_members)
}
