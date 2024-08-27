use std::alloc::Layout;
use std::sync::OnceLock;

use anyhow::Result;

use crate::process::Process;
use crate::token::{Token, TokenPrivilegesAdjustment};
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
        let privs_slice = unsafe { slice_from_ptr(value.Privileges.as_ptr(), value.PrivilegeCount as usize) };

        Ok(Self(privs_slice.to_vec()))
    }
}

impl RawTokenPrivileges {
    pub fn as_raw(&self) -> &TOKEN_PRIVILEGES {
        // SAFETY: It is safe to dereference since it is our buffer.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            &*self.0.as_ptr().cast::<TOKEN_PRIVILEGES>()
        }
    }
}

impl TryFrom<&TokenPrivileges> for RawTokenPrivileges {
    type Error = anyhow::Error;

    fn try_from(value: &TokenPrivileges) -> Result<Self> {
        let mut buf = vec![
            0;
            Layout::new::<TOKEN_PRIVILEGES>()
                .extend(Layout::array::<LUID_AND_ATTRIBUTES>(value.0.len().saturating_sub(1))?)?
                .0
                .pad_to_align()
                .size()
        ];

        // SAFETY: `buf` is at least as big as `TOKEN_PRIVILEGES` and its privileges.
        #[allow(clippy::cast_ptr_alignment)]
        let privileges = unsafe { &mut *buf.as_mut_ptr().cast::<TOKEN_PRIVILEGES>() };

        privileges.PrivilegeCount = value.0.len().try_into()?;

        for (i, v) in value.0.iter().enumerate() {
            // SAFETY: `Privileges` is a VLA and we have previously correctly sized it.
            unsafe { *privileges.Privileges.get_unchecked_mut(i) = *v };
        }

        Ok(Self(buf))
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
        let proc = Process::get_by_pid(pid, PROCESS_QUERY_INFORMATION).ok()?;
        let token = proc.token(TOKEN_ALL_ACCESS).ok()?;

        if token.privileges().ok()?.0.iter().any(|p| p.Luid == privilege) {
            Some(token)
        } else {
            None
        }
    }))
}

/// ScopedPrivilege enables a Windows privilege for the lifetime of the object and
/// disables it when going out of scope.
///
/// Token is borrowed to ensure that the token is alive throughout the lifetime of the scope.
pub struct ScopedPrivileges<'a> {
    token: &'a mut Token,
    token_privileges: Vec<LUID>,
    description: String,
}

impl<'a> ScopedPrivileges<'a> {
    pub fn enter(token: &'a mut Token, privileges: &[PCWSTR]) -> Result<ScopedPrivileges<'a>> {
        let mut token_privileges = Vec::with_capacity(privileges.len());

        for privilege in privileges.iter().copied() {
            let luid = lookup_privilege_value(None, privilege)?;
            token_privileges.push(luid);
        }

        let description = privileges
            .iter()
            .map(|p| {
                // SAFETY: `p` is a valid pointer to a NUL-terminated string.
                String::from_utf16_lossy(unsafe { p.as_wide() })
            })
            .reduce(|mut acc, value| {
                acc.push_str(", ");
                acc.push_str(&value);
                acc
            })
            .unwrap_or_default();

        token.adjust_privileges(&TokenPrivilegesAdjustment::Enable(token_privileges.clone()))?;

        Ok(ScopedPrivileges {
            token,
            token_privileges,
            description,
        })
    }

    pub fn token(&self) -> &Token {
        self.token
    }

    pub fn token_mut(&mut self) -> &mut Token {
        self.token
    }
}

impl Drop for ScopedPrivileges<'_> {
    fn drop(&mut self) {
        if let Err(err) = self
            .token
            .adjust_privileges(&TokenPrivilegesAdjustment::Disable(self.token_privileges.clone()))
        {
            error!(%err, "Failed to disable ScopedPrivileges({})", self.description);
        }
    }
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
