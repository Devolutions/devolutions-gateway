use std::mem;
use std::sync::LazyLock;

use tracing::error;
use windows::Win32::Foundation::LUID;
use windows::Win32::Security;
use windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS;
use windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION;
use windows::core::PCWSTR;

use crate::dst::{Win32Dst, Win32DstDef};
use crate::process::Process;
use crate::str::{U16CStr, U16CStrExt, u16cstr};
use crate::token::{Token, TokenPrivilegesAdjustment};
use crate::utils::Snapshot;

pub const SE_ASSIGNPRIMARYTOKEN_NAME: &U16CStr = u16cstr!("SeAssignPrimaryTokenPrivilege");
pub const SE_AUDIT_NAME: &U16CStr = u16cstr!("SeAuditPrivilege");
pub const SE_BACKUP_NAME: &U16CStr = u16cstr!("SeBackupPrivilege");
pub const SE_CHANGE_NOTIFY_NAME: &U16CStr = u16cstr!("SeChangeNotifyPrivilege");
pub const SE_CREATE_GLOBAL_NAME: &U16CStr = u16cstr!("SeCreateGlobalPrivilege");
pub const SE_CREATE_PAGEFILE_NAME: &U16CStr = u16cstr!("SeCreatePagefilePrivilege");
pub const SE_CREATE_PERMANENT_NAME: &U16CStr = u16cstr!("SeCreatePermanentPrivilege");
pub const SE_CREATE_SYMBOLIC_LINK_NAME: &U16CStr = u16cstr!("SeCreateSymbolicLinkPrivilege");
pub const SE_CREATE_TOKEN_NAME: &U16CStr = u16cstr!("SeCreateTokenPrivilege");
pub const SE_DEBUG_NAME: &U16CStr = u16cstr!("SeDebugPrivilege");
pub const SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME: &U16CStr = u16cstr!("SeDelegateSessionUserImpersonatePrivilege");
pub const SE_ENABLE_DELEGATION_NAME: &U16CStr = u16cstr!("SeEnableDelegationPrivilege");
pub const SE_IMPERSONATE_NAME: &U16CStr = u16cstr!("SeImpersonatePrivilege");
pub const SE_INCREASE_QUOTA_NAME: &U16CStr = u16cstr!("SeIncreaseQuotaPrivilege");
pub const SE_INC_BASE_PRIORITY_NAME: &U16CStr = u16cstr!("SeIncreaseBasePriorityPrivilege");
pub const SE_INC_WORKING_SET_NAME: &U16CStr = u16cstr!("SeIncreaseWorkingSetPrivilege");
pub const SE_LOAD_DRIVER_NAME: &U16CStr = u16cstr!("SeLoadDriverPrivilege");
pub const SE_LOCK_MEMORY_NAME: &U16CStr = u16cstr!("SeLockMemoryPrivilege");
pub const SE_MACHINE_ACCOUNT_NAME: &U16CStr = u16cstr!("SeMachineAccountPrivilege");
pub const SE_MANAGE_VOLUME_NAME: &U16CStr = u16cstr!("SeManageVolumePrivilege");
pub const SE_PROF_SINGLE_PROCESS_NAME: &U16CStr = u16cstr!("SeProfileSingleProcessPrivilege");
pub const SE_RELABEL_NAME: &U16CStr = u16cstr!("SeRelabelPrivilege");
pub const SE_REMOTE_SHUTDOWN_NAME: &U16CStr = u16cstr!("SeRemoteShutdownPrivilege");
pub const SE_RESTORE_NAME: &U16CStr = u16cstr!("SeRestorePrivilege");
pub const SE_SECURITY_NAME: &U16CStr = u16cstr!("SeSecurityPrivilege");
pub const SE_SHUTDOWN_NAME: &U16CStr = u16cstr!("SeShutdownPrivilege");
pub const SE_SYNC_AGENT_NAME: &U16CStr = u16cstr!("SeSyncAgentPrivilege");
pub const SE_SYSTEMTIME_NAME: &U16CStr = u16cstr!("SeSystemtimePrivilege");
pub const SE_SYSTEM_ENVIRONMENT_NAME: &U16CStr = u16cstr!("SeSystemEnvironmentPrivilege");
pub const SE_SYSTEM_PROFILE_NAME: &U16CStr = u16cstr!("SeSystemProfilePrivilege");
pub const SE_TAKE_OWNERSHIP_NAME: &U16CStr = u16cstr!("SeTakeOwnershipPrivilege");
pub const SE_TCB_NAME: &U16CStr = u16cstr!("SeTcbPrivilege");
pub const SE_TIME_ZONE_NAME: &U16CStr = u16cstr!("SeTimeZonePrivilege");
pub const SE_TRUSTED_CREDMAN_ACCESS_NAME: &U16CStr = u16cstr!("SeTrustedCredManAccessPrivilege");
pub const SE_UNDOCK_NAME: &U16CStr = u16cstr!("SeUndockPrivilege");
pub const SE_UNSOLICITED_INPUT_NAME: &U16CStr = u16cstr!("SeUnsolicitedInputPrivilege");

pub static DEFAULT_ADMIN_PRIVILEGES: LazyLock<TokenPrivileges> = LazyLock::new(|| {
    use windows::Win32::Security::{
        SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT, TOKEN_PRIVILEGES_ATTRIBUTES,
    };

    const NO_ATTRIBUTE: TOKEN_PRIVILEGES_ATTRIBUTES = TOKEN_PRIVILEGES_ATTRIBUTES(0);

    fn new_privilege(name: &U16CStr, attr: TOKEN_PRIVILEGES_ATTRIBUTES) -> Security::LUID_AND_ATTRIBUTES {
        Security::LUID_AND_ATTRIBUTES {
            Luid: lookup_privilege_value(None, name).expect("known privilege name"),
            Attributes: attr,
        }
    }

    let mut privileges = TokenPrivileges::new((), new_privilege(SE_INCREASE_QUOTA_NAME, NO_ATTRIBUTE));

    privileges.push(new_privilege(SE_SECURITY_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_TAKE_OWNERSHIP_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_LOAD_DRIVER_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_SYSTEM_PROFILE_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_SYSTEMTIME_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_PROF_SINGLE_PROCESS_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_INC_BASE_PRIORITY_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_CREATE_PAGEFILE_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_BACKUP_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_RESTORE_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_SHUTDOWN_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_DEBUG_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_SYSTEM_ENVIRONMENT_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_REMOTE_SHUTDOWN_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_UNDOCK_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_MANAGE_VOLUME_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_INC_WORKING_SET_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_TIME_ZONE_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_CREATE_SYMBOLIC_LINK_NAME, NO_ATTRIBUTE));
    privileges.push(new_privilege(SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME, NO_ATTRIBUTE));

    privileges.push(new_privilege(
        SE_CHANGE_NOTIFY_NAME,
        SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT,
    ));
    privileges.push(new_privilege(
        SE_IMPERSONATE_NAME,
        SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT,
    ));
    privileges.push(new_privilege(
        SE_CREATE_GLOBAL_NAME,
        SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT,
    ));

    privileges
});

pub struct TokenPrivilegesDstDef;

// SAFETY:
// - The offests are in bounds of the container (ensured via the offset_of! macro).
// - The container (TOKEN_PRIVILEGES) is not #[repr(packet)].
// - The container (TOKEN_PRIVILEGES) is #[repr(C)].
// - The array is defined last and its hardcoded size if of 1.
unsafe impl Win32DstDef for TokenPrivilegesDstDef {
    type Container = Security::TOKEN_PRIVILEGES;

    type Item = Security::LUID_AND_ATTRIBUTES;

    type ItemCount = u32;

    type Parameters = ();

    const ITEM_COUNT_OFFSET: usize = mem::offset_of!(Security::TOKEN_PRIVILEGES, PrivilegeCount);

    const ARRAY_OFFSET: usize = mem::offset_of!(Security::TOKEN_PRIVILEGES, Privileges);

    fn new_container(_: Self::Parameters, first_item: Self::Item) -> Self::Container {
        Security::TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [first_item],
        }
    }

    fn increment_count(count: Self::ItemCount) -> Self::ItemCount {
        count + 1
    }
}

pub type TokenPrivileges = Win32Dst<TokenPrivilegesDstDef>;

// SAFETY: Just a POD with no thread-unsafe interior mutabilty.
unsafe impl Send for TokenPrivileges {}

// SAFETY: Just a POD with no thread-unsafe interior mutabilty.
unsafe impl Sync for TokenPrivileges {}

pub fn lookup_privilege_value(system_name: Option<&U16CStr>, name: &U16CStr) -> windows::core::Result<LUID> {
    let mut luid = LUID::default();

    // SAFETY: system_name and name are valid UTF16 strings per U16CStr invariants.
    unsafe {
        Security::LookupPrivilegeValueW(
            system_name.map_or_else(PCWSTR::null, U16CStrExt::as_pcwstr),
            name.as_pcwstr(),
            &mut luid,
        )
    }?;

    Ok(luid)
}

pub fn find_token_with_privilege(privilege: LUID) -> anyhow::Result<Option<Token>> {
    let snapshot = Snapshot::new(TH32CS_SNAPPROCESS, None)?;

    let token = snapshot.process_ids().find_map(|pid| {
        let proc = Process::get_by_pid(pid, PROCESS_QUERY_INFORMATION).ok()?;
        let token = proc.token(Security::TOKEN_ALL_ACCESS).ok()?;

        if token.privileges().ok()?.as_slice().iter().any(|p| p.Luid == privilege) {
            Some(token)
        } else {
            None
        }
    });

    Ok(token)
}

/// [`ScopedPrivileges`] enables Windows privileges for the lifetime of the object and
/// disables it when going out of scope.
///
/// Token is borrowed to ensure that the token is alive throughout the lifetime of the scope.
pub struct ScopedPrivileges<'a> {
    token: &'a mut Token,
    token_privileges: Vec<LUID>,
    description: String,
}

impl<'a> ScopedPrivileges<'a> {
    pub fn enter(token: &'a mut Token, privileges: &[&U16CStr]) -> anyhow::Result<ScopedPrivileges<'a>> {
        let mut token_privileges = Vec::with_capacity(privileges.len());

        for privilege in privileges.iter().copied() {
            let luid = lookup_privilege_value(None, privilege)?;
            token_privileges.push(luid);
        }

        let description = privileges
            .iter()
            .map(|p| p.to_string_lossy())
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

    pub fn description(&self) -> &str {
        &self.description
    }
}

impl Drop for ScopedPrivileges<'_> {
    fn drop(&mut self) {
        if let Err(error) = self
            .token
            .adjust_privileges(&TokenPrivilegesAdjustment::Disable(self.token_privileges.clone()))
        {
            error!(%error, "Failed to disable ScopedPrivileges({})", self.description);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_token_privileges() {
        let mut privileges = TokenPrivileges::new(
            (),
            Security::LUID_AND_ATTRIBUTES {
                Luid: LUID {
                    LowPart: 32,
                    HighPart: 0,
                },
                Attributes: Security::TOKEN_PRIVILEGES_ATTRIBUTES(2),
            },
        );

        privileges.push(Security::LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: 12,
                HighPart: 0,
            },
            Attributes: Security::TOKEN_PRIVILEGES_ATTRIBUTES(10),
        });

        for privilege in privileges.as_slice() {
            println!("{privilege:?}");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn scoped_privileges() {
        let mut token = Process::current_process()
            .token(Security::TOKEN_ADJUST_PRIVILEGES | Security::TOKEN_QUERY)
            .unwrap();

        let privileges = ScopedPrivileges::enter(&mut token, &[SE_TIME_ZONE_NAME]).unwrap();
        assert_eq!(privileges.description(), "SeTimeZonePrivilege");

        let mut found = false;

        // Verify the attribute for the privilege has been adjusted.
        for privilege in privileges.token().privileges().unwrap().as_slice() {
            found = privileges.token_privileges.iter().any(|luid| privilege.Luid == *luid);

            if found {
                assert_eq!(privilege.Attributes.0, 2);
                break;
            }
        }

        assert!(found);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn access_default_admin_privileges() {
        for privilege in DEFAULT_ADMIN_PRIVILEGES.as_slice() {
            println!("{privilege:?}");
        }
    }
}
