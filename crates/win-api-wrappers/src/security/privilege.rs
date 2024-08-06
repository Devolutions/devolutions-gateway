use std::mem::{self};
use std::ptr;
use std::sync::OnceLock;

use anyhow::Result;

use crate::process::Process;
use crate::token::Token;
use crate::utils::{slice_from_ptr, Snapshot, WideString};
use windows::core::PCWSTR;
use windows::Win32::Foundation::LUID;
use windows::Win32::Security::{
    LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_BACKUP_NAME, SE_CHANGE_NOTIFY_NAME, SE_CREATE_GLOBAL_NAME,
    SE_CREATE_PAGEFILE_NAME, SE_CREATE_SYMBOLIC_LINK_NAME, SE_DEBUG_NAME, SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,
    SE_IMPERSONATE_NAME, SE_INCREASE_QUOTA_NAME, SE_INC_BASE_PRIORITY_NAME, SE_INC_WORKING_SET_NAME,
    SE_LOAD_DRIVER_NAME, SE_MANAGE_VOLUME_NAME, SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT,
    SE_PROF_SINGLE_PROCESS_NAME, SE_REMOTE_SHUTDOWN_NAME, SE_RESTORE_NAME, SE_SECURITY_NAME, SE_SHUTDOWN_NAME,
    SE_SYSTEMTIME_NAME, SE_SYSTEM_ENVIRONMENT_NAME, SE_SYSTEM_PROFILE_NAME, SE_TAKE_OWNERSHIP_NAME, SE_TIME_ZONE_NAME,
    SE_UNDOCK_NAME, TOKEN_ALL_ACCESS, TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES,
};
use windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS;
use windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION;

pub struct TokenPrivileges(pub Vec<LUID_AND_ATTRIBUTES>);

pub struct RawTokenPrivileges(Vec<u8>);

impl TryFrom<&TOKEN_PRIVILEGES> for TokenPrivileges {
    type Error = anyhow::Error;

    fn try_from(value: &TOKEN_PRIVILEGES) -> Result<Self, Self::Error> {
        // SAFETY: We assume `value.Privileges` is truthful and big enough to fit its VLA.
        let privs_slice = unsafe { slice_from_ptr(value.Privileges.as_ptr(), value.PrivilegeCount as _) };

        Ok(Self(privs_slice.to_vec()))
    }
}

impl RawTokenPrivileges {
    pub fn as_raw(&self) -> &TOKEN_PRIVILEGES {
        // SAFETY: It is safe to dereference since it is our buffer.
        unsafe { &*self.0.as_ptr().cast::<TOKEN_PRIVILEGES>() }
    }
}

impl From<&TokenPrivileges> for RawTokenPrivileges {
    fn from(value: &TokenPrivileges) -> Self {
        let mut raw_buf = vec![
            0;
            mem::size_of::<TOKEN_PRIVILEGES>()
                + value.0.len().saturating_sub(1) * mem::size_of::<LUID_AND_ATTRIBUTES>()
        ];

        let raw = raw_buf.as_mut_ptr().cast::<TOKEN_PRIVILEGES>();

        // SAFETY: `raw_buf` can fit `PrivilegeCount` since it is at least `size_of::<TOKEN_PRIVILEGES>` bytes large.
        unsafe { ptr::addr_of_mut!((*raw).PrivilegeCount).write(value.0.len() as _) };

        // SAFETY: No dereference is done in `addr_of_mut!`.
        let privs_ptr = unsafe { ptr::addr_of_mut!((*raw).Privileges).cast::<LUID_AND_ATTRIBUTES>() };

        for (i, v) in value.0.iter().enumerate() {
            // SAFETY: `raw_buf` is at least `size_of::<TOKEN_PRIVILEGES> + (value.0.len() - 1) * size_of::<LUID_AND_ATTRIBUTES>` bytes large.
            // This means it can fit all the entries being iterated on.
            unsafe { privs_ptr.add(i).write(*v) };
        }

        Self(raw_buf)
    }
}

pub fn lookup_privilege_value(system_name: Option<&str>, name: PCWSTR) -> Result<LUID> {
    let system_name = system_name.map(WideString::from);
    let mut luid = LUID::default();

    // SAFETY: `system_name` is either NULL or valid and NUL terminated. We assume `name` is valid. No preconditions.
    unsafe {
        LookupPrivilegeValueW(
            system_name.as_ref().map_or_else(PCWSTR::null, WideString::as_pcwstr),
            name,
            &mut luid,
        )
    }?;

    Ok(luid)
}

pub fn find_token_with_privilege(privilege: LUID) -> Result<Option<Token>> {
    let snapshot = Snapshot::new(TH32CS_SNAPPROCESS, None)?;

    Ok(snapshot.process_ids().find_map(|pid| {
        let proc = Process::try_get_by_pid(pid, PROCESS_QUERY_INFORMATION).ok()?;
        let token = proc.token(TOKEN_ALL_ACCESS).ok()?;

        if token.privileges().ok()?.0.iter().any(|p| p.Luid == privilege) {
            Some(token)
        } else {
            None
        }
    }))
}

#[rustfmt::skip]
pub fn default_admin_privileges() -> &'static TokenPrivileges {
    static PRIVS: OnceLock<TokenPrivileges> = OnceLock::new();

    PRIVS.get_or_init(|| {
        let mut privs = vec![];

        macro_rules! add_priv {
            ($priv:ident, $name:expr, $state:expr) => {
                $priv.push(LUID_AND_ATTRIBUTES {
                    Luid: lookup_privilege_value(None, $name).expect("privilege name not found"),
                    Attributes: $state,
                });
            };
        }

        add_priv!(privs, SE_INCREASE_QUOTA_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_SECURITY_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_TAKE_OWNERSHIP_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_LOAD_DRIVER_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_SYSTEM_PROFILE_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_SYSTEMTIME_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_PROF_SINGLE_PROCESS_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_INC_BASE_PRIORITY_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_CREATE_PAGEFILE_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_BACKUP_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_RESTORE_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_SHUTDOWN_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_DEBUG_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_SYSTEM_ENVIRONMENT_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_REMOTE_SHUTDOWN_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_UNDOCK_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_MANAGE_VOLUME_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_INC_WORKING_SET_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_TIME_ZONE_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_CREATE_SYMBOLIC_LINK_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));

        add_priv!(privs, SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT);
        add_priv!(privs, SE_IMPERSONATE_NAME, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT);
        add_priv!(privs, SE_CREATE_GLOBAL_NAME, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT);

        TokenPrivileges(privs)
    })
}
