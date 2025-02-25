use anyhow::{bail, Context as _};
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::NetworkManagement::NetManagement;
use windows::Win32::NetworkManagement::NetManagement::{
    NetLocalGroupGetMembers, LOCALGROUP_MEMBERS_INFO_0, MAX_PREFERRED_LENGTH,
};
use windows::Win32::Security::WinBuiltinAdministratorsSid;

use crate::identity::sid::Sid;
use crate::str::{U16CStr, U16CStrExt as _, U16CString};
use crate::Error;

pub fn add_local_group_member(group_name: &str, security_identifier: &Sid) -> anyhow::Result<()> {
    let group_name = U16CString::from_str(group_name).context("invalid group name")?;

    let group_info = LOCALGROUP_MEMBERS_INFO_0 {
        lgrmi0_sid: security_identifier.as_psid_const(),
    };

    // SAFETY:
    // - level is set to 0, and the buf parameters points to an array of LOCALGROUP_MEMBERS_INFO_0.
    // - lgrmi0_sid is never modified by NetLocalGroupAddMembers.
    let rc = unsafe {
        NetManagement::NetLocalGroupAddMembers(None, group_name.as_pcwstr(), 0, &group_info as *const _ as *const u8, 1)
    };

    if rc != NetManagement::NERR_Success {
        bail!(Error::from_win32(WIN32_ERROR(rc)))
    }

    Ok(())
}

pub fn get_local_admin_group_members() -> anyhow::Result<Vec<Sid>> {
    let local_admin_group_sid = Sid::from_well_known(WinBuiltinAdministratorsSid, None)?;
    let local_admin_group_account = local_admin_group_sid.lookup_account(None)?;
    get_local_group_members(&local_admin_group_account.name)
}

pub fn get_local_group_members(group_name: &U16CStr) -> anyhow::Result<Vec<Sid>> {
    let mut group_members: *mut u8 = std::ptr::null_mut();
    let mut number_of_entries_read = 0;
    let mut total_entries = 0;

    // SAFETY:
    // - group_name holds a null-terminated UTF-16 string, and as_pcwstr() returns a valid pointer to it.
    // - Specifying `MAX_PREFERRED_LENGTH` allocates the required amount of memory for the data, and the function will not return `ERROR_MORE_DATA`.
    let ret = unsafe {
        NetLocalGroupGetMembers(
            None,
            group_name.as_pcwstr(),
            0,
            &mut group_members,
            MAX_PREFERRED_LENGTH,
            &mut number_of_entries_read,
            &mut total_entries,
            None,
        )
    };

    if ret != NetManagement::NERR_Success {
        bail!(Error::from_win32(WIN32_ERROR(ret)))
    }

    // SAFETY:
    // - `NetLocalGroupGetMembers` sets `group_members` to a valid pointer on success.
    // - `group_members` must be freed by `NetApiBufferFree`.
    // - For level = 0, bufptr will be set to a pointer to a LOCALGROUP_MEMBERS_INFO_0.
    let group_members = unsafe { NetmgmtMemory::from_raw(group_members.cast::<LOCALGROUP_MEMBERS_INFO_0>()) };

    // SAFETY:
    // - `NetLocalGroupGetMembers` returns a pointer valid for `number_of_entries_read` reads of `LOCALGROUP_MEMBERS_INFO_0`.
    // - `NetLocalGroupGetMembers` is also returning a pointer properly aligned.
    // - We ensure the memory referenced by the slice is not mutated by shadowing the variable.
    // - There are never so many entries that `number_of_entries_read * mem::size_of::<LOCALGROUP_MEMBERS_INFO_0>()` overflows `isize`.
    let group_members = unsafe { group_members.cast_slice(number_of_entries_read as usize) };

    let group_members = group_members
        .iter()
        .map(|member| {
            // SAFETY: Value returned by Win32 API (NetLocalGroupGetMembers).
            unsafe { Sid::from_psid(member.lgrmi0_sid) }
        })
        .collect::<Result<Vec<Sid>, _>>()?;

    Ok(group_members)
}

struct NetmgmtFreeMemory;

impl crate::memory::FreeMemory for NetmgmtFreeMemory {
    /// # Safety
    ///
    /// `ptr` is a pointer which must be freed by `NetApiBufferFree`
    unsafe fn free(ptr: *mut core::ffi::c_void) {
        // SAFETY: Per invariant on `ptr`, NetApiBufferFree must be called on it for releasing the memory.
        unsafe { NetManagement::NetApiBufferFree(Some(ptr)) };
    }
}

type NetmgmtMemory<T = core::ffi::c_void> = crate::memory::MemoryWrapper<NetmgmtFreeMemory, T>;
