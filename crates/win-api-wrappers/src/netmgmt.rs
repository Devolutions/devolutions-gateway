use anyhow::bail;
use windows::Win32::Foundation::WIN32_ERROR;

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
    let group_members_ptr: *mut LOCALGROUP_MEMBERS_INFO_0 = std::ptr::null_mut();
    let mut entries_read = 0;
    let mut total_entries = 0;

    // SAFETY: All buffers are valid.
    // WideString holds a null-terminated UTF-16 string, and as_pcwstr() returns a valid pointer to it.
    // Specifying `MAX_PREFERRED_LENGTH` allocates the required amount of memory for the data, and
    // the function will not return `ERROR_MORE_DATA`
    unsafe {
        let rc = NetLocalGroupGetMembers(
            None,
            group_name.as_pcwstr(),
            0,
            &mut group_members_ptr.cast(),
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            None,
        );

        if rc != NERR_Success {
            bail!(Error::from_win32(WIN32_ERROR(rc)))
        }
    };

    // SAFETY: `group_members_ptr` is always a valid pointer on success.
    // `group_members_ptr` must be freed by `NetApiBufferFree`.
    let group_members_ptr = unsafe { NetMgmtMemory::new(group_members_ptr.cast()) };

    // SAFETY: Verify that all the safety preconditions of from_raw_parts are uphold: https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html#safety
    let group_members_slice = unsafe {
        std::slice::from_raw_parts(
            group_members_ptr.0 as *const u8 as *const LOCALGROUP_MEMBERS_INFO_0,
            entries_read as usize,
        )
    };

    let mut group_members = Vec::<Sid>::with_capacity(group_members_slice.len());
    for member in group_members_slice {
        group_members.push(Sid::try_from(member.lgrmi0_sid)?);
    }

    Ok(group_members)
}

/// RAII wrapper for Network Management memory.
struct NetMgmtMemory(*mut core::ffi::c_void);

impl NetMgmtMemory {
    // SAFETY: `ptr` must be a valid pointer to memory allocated by Network Management.
    unsafe fn new(ptr: *mut core::ffi::c_void) -> Self {
        Self(ptr)
    }
}

impl Drop for NetMgmtMemory {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }

        // SAFETY: FFI call with no outstanding precondition.
        unsafe { NetApiBufferFree(Some(self.0)) };
    }
}

impl Default for NetMgmtMemory {
    fn default() -> Self {
        Self(std::ptr::null_mut())
    }
}
