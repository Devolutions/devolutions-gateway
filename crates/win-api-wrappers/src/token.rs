use std::any::Any;
use std::ffi::c_void;
use std::fmt::Debug;
use std::mem::MaybeUninit;
use std::ptr;

use anyhow::{Context as _, bail};
use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_INVALID_SECURITY_DESCR, ERROR_INVALID_VARIANT, HANDLE, LUID,
};
use windows::Win32::Security::Authentication::Identity::EXTENDED_NAME_FORMAT;
use windows::Win32::Security::{
    self, AdjustTokenGroups, AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, ImpersonateLoggedOnUser,
    LOGON32_LOGON, LOGON32_PROVIDER, LUID_AND_ATTRIBUTES, RevertToSelf, SECURITY_ATTRIBUTES,
    SECURITY_IMPERSONATION_LEVEL, SECURITY_QUALITY_OF_SERVICE, SecurityIdentification, SecurityImpersonation,
    SetTokenInformation, TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_ELEVATION_TYPE, TOKEN_IMPERSONATE,
    TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_POLICY, TOKEN_MANDATORY_POLICY_ID, TOKEN_PRIVILEGES,
    TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY, TOKEN_SOURCE, TOKEN_STATISTICS, TOKEN_TYPE, TokenElevationTypeDefault,
    TokenElevationTypeFull, TokenElevationTypeLimited,
};
use windows::Win32::System::RemoteDesktop::WTSQueryUserToken;
use windows::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
use windows::core::PCWSTR;

use crate::handle::{Handle, HandleWrapper};
use crate::identity::account::{ProfileInfo, create_profile, get_username};
use crate::identity::sid::{Sid, SidAndAttributes};
use crate::raw_buffer::{InitedBuffer, RawBuffer};
use crate::security::acl::{Acl, AclRef};
use crate::security::privilege::{self, TokenPrivileges, find_token_with_privilege, lookup_privilege_value};
use crate::str::{U16CStr, U16CStrExt as _, U16CString, UnicodeStr};
use crate::token_groups::TokenGroups;
use crate::utils::u32size_of;
use crate::{Error, create_impersonation_context, undoc};

#[derive(Debug)]
pub struct Token {
    // TODO(DGW-215): Create a sort of CowHandle<'a> to wrap `BorrowedHandle` and `OwnedHandle`, superseding the `Handle` helper.
    // This helper would keep track of the resource lifetime as necessary. It would be of course possible to use the 'static lifetime for many things.
    handle: Handle,
}

impl From<Handle> for Token {
    fn from(handle: Handle) -> Self {
        Self { handle }
    }
}

impl Token {
    pub fn current_process_token() -> Self {
        // FIXME: Is it really? What about https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocesstoken
        Self {
            handle: Handle::new_borrowed(HANDLE(-4isize as *mut c_void)).expect("always valid"),
        }
    }

    pub fn for_session(session_id: u32) -> anyhow::Result<Self> {
        let mut user_token = HANDLE::default();

        // SAFETY: Query user token is always safe if dst pointer is valid.
        unsafe { WTSQueryUserToken(session_id, &mut user_token as *mut _)? };

        Ok(Self {
            // SAFETY: As per `WTSQueryUserToken` documentation, returned token should be closed
            // by caller.
            handle: unsafe {
                Handle::new_owned(user_token).expect("BUG: WTSQueryUserToken should return a valid handle")
            },
        })
    }

    /// Helper for enabling a privilege.
    pub fn enable_privilege(&mut self, privilege_name: &U16CStr) -> anyhow::Result<()> {
        let luid = lookup_privilege_value(None, privilege_name).context("lookup privilege")?;

        self.adjust_privileges(&TokenPrivilegesAdjustment::Enable(vec![luid]))
            .context("enable privilege")?;

        Ok(())
    }

    #[expect(clippy::too_many_arguments)] // Wrapper around `NtCreateToken`, which has a lot of arguments.
    pub fn create_token(
        authentication_id: &LUID,
        expiration_time: i64,
        user: &SidAndAttributes,
        groups: &TokenGroups,
        privileges: &TokenPrivileges,
        owner: &Sid,
        primary_group: &Sid,
        default_dacl: Option<&Acl>,
        source: &TOKEN_SOURCE,
    ) -> anyhow::Result<Self> {
        // See https://github.com/decoder-it/CreateTokenExample/blob/master/StopZillaCreateToken.cpp#L344
        let sqos = SECURITY_QUALITY_OF_SERVICE {
            Length: u32size_of::<SECURITY_QUALITY_OF_SERVICE>(),
            ImpersonationLevel: SecurityImpersonation,
            ContextTrackingMode: u8::from(Security::SECURITY_DYNAMIC_TRACKING),
            EffectiveOnly: false,
        };

        let object_attributes = undoc::OBJECT_ATTRIBUTES {
            Length: u32size_of::<undoc::OBJECT_ATTRIBUTES>(),
            SecurityQualityOfService: &sqos as *const _ as *const c_void,
            ..Default::default()
        };

        let create_token_name_privilege = lookup_privilege_value(None, privilege::SE_CREATE_TOKEN_NAME)
            .context("lookup SE_CREATE_TOKEN_NAME privilege")?;

        let mut priv_token = find_token_with_privilege(create_token_name_privilege)
            .context("find_token_with_privilege for SE_CREATE_TOKEN_NAME")?
            .context("no token found for SE_CREATE_TOKEN_NAME privilege")?
            .duplicate_impersonation()
            .context("duplicate_impersonation failed")?;

        priv_token
            .adjust_privileges(&TokenPrivilegesAdjustment::Enable(vec![
                lookup_privilege_value(None, privilege::SE_CREATE_TOKEN_NAME)?,
                lookup_privilege_value(None, privilege::SE_ASSIGNPRIMARYTOKEN_NAME)?,
            ]))
            .context("adjust_privileges failed")?;

        let mut handle = HANDLE::default();
        let _ctx = priv_token.impersonate()?;

        // SAFETY: This function is undocumented, so it’s hard to be sure we are using it correctly for sure.
        // That being said, we ensure that all parameters are reasonables in the usual FFI business way.
        unsafe {
            undoc::NtCreateToken(
                &mut handle,
                TOKEN_ALL_ACCESS,
                &object_attributes,
                Security::TokenPrimary,
                authentication_id,
                &expiration_time,
                &Security::TOKEN_USER { User: user.as_raw() },
                groups.as_raw(),
                privileges.as_raw().as_ref(),
                &Security::TOKEN_OWNER {
                    Owner: owner.as_psid_const(),
                },
                &Security::TOKEN_PRIMARY_GROUP {
                    PrimaryGroup: primary_group.as_psid_const(),
                },
                &Security::TOKEN_DEFAULT_DACL {
                    DefaultDacl: default_dacl.map(|x| x.as_ptr().cast_mut()).unwrap_or(ptr::null_mut()),
                },
                source,
            )?;
        }

        // SAFETY: We create the token, and thus own it.
        let handle = unsafe { Handle::new_owned(handle)? };

        Ok(Self::from(handle))
    }

    pub fn duplicate(
        &self,
        desired_access: TOKEN_ACCESS_MASK,
        attributes: Option<&SECURITY_ATTRIBUTES>,
        impersonation_level: SECURITY_IMPERSONATION_LEVEL,
        token_type: TOKEN_TYPE,
    ) -> anyhow::Result<Self> {
        let mut handle = HANDLE::default();

        // SAFETY: Returned `handle` must be closed, which it is in its RAII wrapper.
        unsafe {
            DuplicateTokenEx(
                self.handle.raw(),
                desired_access,
                attributes.map(|x| x as *const _),
                impersonation_level,
                token_type,
                &mut handle,
            )
            .with_context(|| {
                format!("DuplicateTokenEx failed (desired access: {desired_access:?}, attributes: {attributes:?}, impersonation level: {impersonation_level:?}, token type: {token_type:?})")
            })?
        };

        // SAFETY: We own the handle.
        let handle = unsafe { Handle::new_owned(handle)? };

        Ok(Self::from(handle))
    }

    pub fn duplicate_impersonation(&self) -> anyhow::Result<Self> {
        self.duplicate(
            TOKEN_ACCESS_MASK(0),
            None,
            SecurityImpersonation,
            Security::TokenPrimary,
        )
    }

    pub fn impersonate(&self) -> anyhow::Result<TokenImpersonation<'_>> {
        TokenImpersonation::try_new(self)
    }

    pub fn reset_privileges(&mut self) -> anyhow::Result<()> {
        // SAFETY: No preconditions.
        unsafe { AdjustTokenPrivileges(self.handle.raw(), true, None, 0, None, None) }?;
        Ok(())
    }

    pub fn reset_groups(&mut self) -> anyhow::Result<()> {
        // SAFETY: No preconditions.
        unsafe { AdjustTokenGroups(self.handle.raw(), true, None, 0, None, None) }?;
        Ok(())
    }

    /// Wraps `GetTokenInformation` for DST types.
    /// As a convenience, the `D` generic type is used to perform a conversion into a more idiomatic type.
    ///
    /// # Safety
    ///
    /// For memory alignment purposes, the provided `T` type must correspond to the structure associated to the provided `info_class`.
    unsafe fn get_information_dst<T, D>(&self, info_class: TOKEN_INFORMATION_CLASS) -> anyhow::Result<D>
    where
        D: FromWin32<T>,
    {
        // SAFETY: Same preconditions as this function.
        let info = unsafe { self.get_information_dst_raw::<T>(info_class)? };

        // SAFETY: Win32 API, which is called under the hood, is expected to return valid structures.
        let info = unsafe { D::from_win32(info)? };

        Ok(info)
    }

    /// Wraps `GetTokenInformation` for DST types.
    ///
    /// # Safety
    ///
    /// For memory alignment purposes, the provided `T` type must correspond to the structure associated to the provided `info_class`.
    unsafe fn get_information_dst_raw<T: Sized>(
        &self,
        info_class: TOKEN_INFORMATION_CLASS,
    ) -> anyhow::Result<InitedBuffer<T>> {
        use std::alloc::Layout;

        // The output has a variable size.
        // Therefore, we must call GetTokenInformation once with a zero-size, and check for the ERROR_INSUFFICIENT_BUFFER status.
        // At this point, we call GetTokenInformation again with a buffer of the correct size.

        let mut return_length = 0u32;

        // SAFETY:
        // - `info` is null and,
        // - `info_length` is set to 0.
        let res = unsafe { self.get_information_raw(info_class, ptr::null_mut(), 0, &mut return_length) };

        let Err(err) = res else {
            anyhow::bail!("first call to GetTokenInformation did not fail")
        };

        // SAFETY: FFI call with no outstanding precondition.
        if unsafe { windows::Win32::Foundation::GetLastError() }
            != windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER
        {
            return Err(anyhow::Error::new(err)
                .context("first call to GetTokenInformation did not fail with ERROR_INSUFFICIENT_BUFFER"));
        }

        // We try again, but allocate manually using the length specified in return_length for variable-sized structs.
        // The value *can’t* live on the stack because of its DST nature.

        let allocated_length = return_length;
        let align = align_of::<T>();
        let layout = Layout::from_size_align(allocated_length as usize, align)?;

        // SAFETY: The layout initialization is checked using the Layout::from_size_align method.
        let mut info = unsafe { RawBuffer::alloc_zeroed(layout)? };

        // SAFETY: As per safety preconditions, the alignment is valid for the desired info class.
        unsafe {
            self.get_information_raw(
                info_class,
                info.as_mut_ptr().cast::<c_void>(),
                allocated_length,
                &mut return_length,
            )
            .context("second call to GetTokenInformation")?
        };

        debug_assert_eq!(allocated_length, return_length);

        // SAFETY: get_information_raw returned with success, the info struct is expected to be initialized.
        let info = unsafe { info.assume_init::<T>() };

        Ok(info)
    }

    /// Wraps `GetTokenInformation`.
    ///
    /// # Safety
    ///
    /// The provided `T` type must correspond to the structure associated to the provided `info_class`.
    unsafe fn get_information<T: Sized>(&self, info_class: TOKEN_INFORMATION_CLASS) -> anyhow::Result<T> {
        let mut info = MaybeUninit::<T>::uninit();
        let mut return_length = 0u32;

        // SAFETY:
        // - `info` is a valid pointer,
        // - `info_length` is the size of the expected structure.
        unsafe {
            self.get_information_raw(
                info_class,
                info.as_mut_ptr().cast::<c_void>(),
                u32size_of::<T>(),
                &mut return_length,
            )?
        };

        debug_assert_eq!(u32size_of::<T>(), return_length);

        // SAFETY: `GetTokenInformation` is successful, we assume the value is properly initialized.
        let info = unsafe { info.assume_init() };

        Ok(info)
    }

    /// Very thin wrapper around `GetTokenInformation`
    ///
    /// # Safety
    ///
    /// - `info` must be a valid pointer properly aligned for the struct associated to `info_class` or null.
    /// - if `info` is null, `info_length` must be set to zero.
    unsafe fn get_information_raw(
        &self,
        info_class: TOKEN_INFORMATION_CLASS,
        info: *mut c_void,
        info_length: u32,
        return_length: &mut u32,
    ) -> windows::core::Result<()> {
        // SAFETY:
        // - The alignement of the `info` pointer is valid for writing the struct associated to the provided info class.
        // - When `info` is null, `info_length` is set to zero.
        unsafe { GetTokenInformation(self.handle.raw(), info_class, Some(info), info_length, return_length) }
    }

    // FIXME(DGW-215): audit this too. Probably unsound.
    fn set_information_raw<T: Sized>(&self, info_class: TOKEN_INFORMATION_CLASS, value: &T) -> anyhow::Result<()> {
        // SAFETY: No preconditions. `TokenInformationLength` matches length of `info` in `TokenInformation`.
        unsafe {
            SetTokenInformation(
                self.handle.raw(),
                info_class,
                value as *const _ as *const _,
                u32size_of::<T>(),
            )
            .context("SetTokenInformation")?;
        }

        Ok(())
    }

    pub fn groups(&self) -> anyhow::Result<TokenGroups> {
        // SAFETY: The TokenGroups info class is associated to a TOKEN_GROUPS struct.
        unsafe {
            self.get_information_dst::<Security::TOKEN_GROUPS, TokenGroups>(Security::TokenGroups)
                .context("get TokenGroups information")
        }
    }

    pub fn privileges(&self) -> anyhow::Result<TokenPrivileges> {
        // SAFETY: The TokenPrivileges info class is associated to a TOKEN_PRIVILEGES struct.
        let buffer = unsafe {
            self.get_information_dst_raw::<TOKEN_PRIVILEGES>(Security::TokenPrivileges)
                .context("get TokenPrivileges information")?
        };

        // SAFETY: The TOKEN_PRIVILEGES struct is properly initialized by the Win32 API.
        let privileges = unsafe { TokenPrivileges::from_raw(buffer) };

        Ok(privileges)
    }

    pub fn elevation_type(&self) -> anyhow::Result<TokenElevationType> {
        // SAFETY: The TokenElevationType info class is associated to a TOKEN_ELEVATION_TYPE struct.
        unsafe {
            self.get_information::<TOKEN_ELEVATION_TYPE>(Security::TokenElevationType)
                .context("get TokenElevationType information")?
                .try_into()
        }
    }

    pub fn is_elevated(&self) -> anyhow::Result<bool> {
        // SAFETY: The TokenElevation info class is associated to a i32.
        let elevation = unsafe {
            self.get_information::<i32>(Security::TokenElevation)
                .context("get TokenElevation information")?
        };
        let is_elevated = elevation != 0;
        Ok(is_elevated)
    }

    pub fn linked_token(&self) -> anyhow::Result<Self> {
        // SAFETY: The TokenLinkedToken info class is associated to a HANDLE.
        let handle = unsafe {
            self.get_information::<HANDLE>(Security::TokenLinkedToken)
                .context("get TokenLinkedToken information")?
        };

        // SAFETY: We are responsible for closing the linked token retrived above.
        let handle = unsafe { Handle::new_owned(handle)? };

        Ok(Self::from(handle))
    }

    pub fn username(&self, format: EXTENDED_NAME_FORMAT) -> anyhow::Result<U16CString> {
        let _ctx = self.impersonate().context("failed to impersonate")?;
        get_username(format).context("failed to get username")
    }

    pub fn logon(
        username: &U16CStr,
        domain: Option<&U16CStr>,
        password: Option<&U16CStr>,
        logon_type: LOGON32_LOGON,
        logon_provider: LOGON32_PROVIDER,
        groups: Option<&TokenGroups>,
    ) -> anyhow::Result<Self> {
        let mut raw_token = HANDLE::default();

        // SAFETY: No preconditions. `username` is valid and NUL terminated.
        // `domain` and `password` are either NULL or valid NUL terminated strings.
        // We assume `groups` is well constructed.
        unsafe {
            undoc::LogonUserExExW(
                username.as_pcwstr(),
                domain.as_ref().map_or_else(PCWSTR::null, |x| x.as_pcwstr()),
                password.as_ref().map_or_else(PCWSTR::null, |x| x.as_pcwstr()),
                logon_type,
                logon_provider,
                groups.as_ref().map(|x| x.as_raw() as *const _),
                Some(&mut raw_token),
                None,
                None,
                None,
                None,
            )
            .with_context(|| {
                format!("LogonUserExExW failed (username: {username:?}, domain: {domain:?}, logon_type: {logon_type:?}, logon_provider: {logon_provider:?}, groups: {groups:?})")
            })?
        }

        // SAFETY: We own the handle.
        let handle = unsafe { Handle::new_owned(raw_token)? };

        Ok(Token::from(handle))
    }

    pub fn statistics(&self) -> anyhow::Result<TOKEN_STATISTICS> {
        // SAFETY: The TokenStatistics info class is associated to a TOKEN_STATISTICS struct.
        unsafe {
            self.get_information::<TOKEN_STATISTICS>(Security::TokenStatistics)
                .context("get TokenStatistics information")
        }
    }

    pub fn sid_and_attributes(&self) -> anyhow::Result<SidAndAttributes> {
        // SAFETY: The TokenUser info class is associated to a TOKEN_USER struct.
        let token_user = unsafe {
            self.get_information_dst::<Security::TOKEN_USER, TokenUser>(Security::TokenUser)
                .context("get TokenUser information")?
        };

        Ok(token_user.user)
    }

    pub fn session_id(&self) -> anyhow::Result<u32> {
        // SAFETY: The TokenSessionId info class is associated to a u32.
        unsafe {
            self.get_information::<u32>(Security::TokenSessionId)
                .context("get TokenSessionId information")
        }
    }

    pub fn set_session_id(&mut self, session_id: u32) -> anyhow::Result<()> {
        self.set_information_raw(Security::TokenSessionId, &session_id)
    }

    pub fn ui_access(&self) -> anyhow::Result<u32> {
        // SAFETY: The TokenUIAccess info class is associated to a u32.
        unsafe {
            self.get_information::<u32>(Security::TokenUIAccess)
                .context("get TokenUIAccess information")
        }
    }

    pub fn set_ui_access(&mut self, ui_access: u32) -> anyhow::Result<()> {
        self.set_information_raw(Security::TokenUIAccess, &ui_access)
    }

    pub fn mandatory_policy(&self) -> anyhow::Result<TOKEN_MANDATORY_POLICY_ID> {
        // SAFETY: The TokenMandatoryPolicy info class is associated to a TOKEN_MANDATORY_POLICY struct.
        let mandatory_policy = unsafe {
            self.get_information::<TOKEN_MANDATORY_POLICY>(Security::TokenMandatoryPolicy)
                .context("get TokenMandatoryPolicy information")?
        };

        Ok(mandatory_policy.Policy)
    }

    pub fn set_mandatory_policy(&mut self, mandatory_policy: TOKEN_MANDATORY_POLICY_ID) -> anyhow::Result<()> {
        self.set_information_raw(
            Security::TokenMandatoryPolicy,
            &TOKEN_MANDATORY_POLICY {
                Policy: mandatory_policy,
            },
        )
    }

    pub fn load_profile(&self, username: U16CString) -> anyhow::Result<ProfileInfo> {
        if let Err(err) = create_profile(&self.sid_and_attributes()?.sid, &username) {
            match err.downcast::<windows::core::Error>() {
                Ok(err) => {
                    if err.code() != ERROR_ALREADY_EXISTS.to_hresult() {
                        bail!(err);
                    }
                }
                Err(err) => bail!(err),
            };
        }

        ProfileInfo::from_token(
            self.duplicate(
                TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE,
                None,
                SecurityIdentification,
                Security::TokenPrimary,
            )?,
            username,
        )
    }

    pub fn adjust_groups(&mut self, adjustment: &TokenGroupAdjustment) -> anyhow::Result<()> {
        match adjustment {
            // SAFETY: No preconditions.
            TokenGroupAdjustment::ResetToDefaults => unsafe {
                AdjustTokenGroups(self.handle.raw(), true, None, 0, None, None)?;
            },
            TokenGroupAdjustment::Enable(groups) => {
                // SAFETY: No preconditions. We assume `groups` is well constructed.
                unsafe {
                    AdjustTokenGroups(self.handle.raw(), false, Some(groups.as_raw()), 0, None, None)?;
                }
            }
        }

        Ok(())
    }

    // TODO(DGW-215): Update this API to take a vec of adjustements (we may enable, disable and remove at the same time).
    // DisableAll could be a dedicated function.
    pub fn adjust_privileges(&mut self, adjustment: &TokenPrivilegesAdjustment) -> anyhow::Result<()> {
        match adjustment {
            // SAFETY: FFI call with no outstanding precondition.
            TokenPrivilegesAdjustment::DisableAllPrivileges => unsafe {
                AdjustTokenPrivileges(self.handle.raw(), true, None, 0, None, None)?;
            },
            TokenPrivilegesAdjustment::Enable(ids)
            | TokenPrivilegesAdjustment::Disable(ids)
            | TokenPrivilegesAdjustment::Remove(ids) => {
                let attr = match adjustment {
                    TokenPrivilegesAdjustment::Enable(_) => Security::SE_PRIVILEGE_ENABLED,
                    TokenPrivilegesAdjustment::DisableAllPrivileges | TokenPrivilegesAdjustment::Disable(_) => {
                        TOKEN_PRIVILEGES_ATTRIBUTES(0)
                    }
                    TokenPrivilegesAdjustment::Remove(_) => Security::SE_PRIVILEGE_REMOVED,
                };

                let mut iter = ids.iter();

                let Some(first_id) = iter.next() else { return Ok(()) };

                let first_element = LUID_AND_ATTRIBUTES {
                    Luid: *first_id,
                    Attributes: attr,
                };

                let mut privileges = TokenPrivileges::new((), first_element);

                for id in ids {
                    privileges.push(LUID_AND_ATTRIBUTES {
                        Luid: *id,
                        Attributes: attr,
                    });
                }

                // SAFETY: FFI call with no outstanding precondition.
                unsafe {
                    AdjustTokenPrivileges(
                        self.handle.raw(),
                        false,
                        Some(privileges.as_raw().as_ref()),
                        0,
                        None,
                        None,
                    )
                }?;
            }
        }

        Ok(())
    }

    pub fn default_dacl(&self) -> anyhow::Result<Option<Acl>> {
        // SAFETY: The TokenDefaultDacl info class is associated to a TOKEN_DEFAULT_DACL struct.
        let dacl = unsafe {
            self.get_information_dst::<Security::TOKEN_DEFAULT_DACL, TokenDefaultDacl>(Security::TokenDefaultDacl)
                .context("get TokenDefaultDacl information")?
        };

        Ok(dacl.default_dacl)
    }

    pub fn primary_group(&self) -> anyhow::Result<Sid> {
        // SAFETY: The TokenPrimaryGroup info class is associated to a TOKEN_PRIMARY_GROUP struct.
        let primary_group = unsafe {
            self.get_information_dst::<Security::TOKEN_PRIMARY_GROUP, TokenPrimaryGroup>(Security::TokenPrimaryGroup)
                .context("get TokenPrimaryGroup information")?
        };

        Ok(primary_group.primary_group)
    }

    pub fn try_clone(&self) -> anyhow::Result<Self> {
        Ok(Self {
            handle: self.handle.try_clone()?,
        })
    }

    pub fn logon_sid(&self) -> anyhow::Result<Sid> {
        // Here, losing the sign is fine, because we want to make a bitwise comparison (g.attributes & SE_GROUP_LOGON_ID).
        // TODO: Use `cast_unsigned` / `cast_signed` when stabilized: https://github.com/rust-lang/rust/issues/125882
        #[expect(clippy::cast_sign_loss)]
        Ok(self
            .groups()?
            .iter()
            .find(|g| (g.attributes & SE_GROUP_LOGON_ID as u32) != 0)
            .ok_or_else(|| Error::from_win32(ERROR_INVALID_SECURITY_DESCR))?
            .sid
            .clone())
    }

    pub fn apply_security_attribute(
        &mut self,
        action: undoc::TOKEN_SECURITY_ATTRIBUTE_OPERATION,
        attribute: &TokenSecurityAttribute,
    ) -> anyhow::Result<()> {
        let attribute = RawTokenSecurityAttribute::from(attribute);
        let raw_attribute = attribute.as_raw()?;
        let attribute_info = undoc::TOKEN_SECURITY_ATTRIBUTES_INFORMATION {
            Version: undoc::TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1,
            Reserved: 0,
            AttributeCount: 1,
            pAttributeV1: &raw_attribute,
        };

        let info = undoc::TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION {
            Attributes: &attribute_info,
            Operations: &action,
        };

        self.set_information_raw(Security::TokenSecurityAttributes, &info)
    }
}

impl HandleWrapper for Token {
    fn handle(&self) -> &Handle {
        &self.handle
    }
}

pub struct TokenUser {
    pub user: SidAndAttributes,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TokenElevationType {
    Default = 1,
    Full = 2,
    Limited = 3,
}

impl TryFrom<TOKEN_ELEVATION_TYPE> for TokenElevationType {
    type Error = anyhow::Error;

    fn try_from(value: TOKEN_ELEVATION_TYPE) -> Result<Self, Self::Error> {
        TokenElevationType::try_from(&value)
    }
}

impl TryFrom<&TOKEN_ELEVATION_TYPE> for TokenElevationType {
    type Error = anyhow::Error;

    fn try_from(value: &TOKEN_ELEVATION_TYPE) -> Result<Self, Self::Error> {
        if *value == TokenElevationTypeDefault {
            Ok(TokenElevationType::Default)
        } else if *value == TokenElevationTypeFull {
            Ok(TokenElevationType::Full)
        } else if *value == TokenElevationTypeLimited {
            Ok(TokenElevationType::Limited)
        } else {
            bail!(Error::from_win32(ERROR_INVALID_VARIANT))
        }
    }
}

pub enum TokenGroupAdjustment {
    ResetToDefaults,
    Enable(TokenGroups),
}

pub enum TokenPrivilegesAdjustment {
    DisableAllPrivileges,
    Enable(Vec<LUID>),
    Disable(Vec<LUID>),
    Remove(Vec<LUID>),
}

// FIXME: naming is confusing: too close to TokenSecurityAttributes (only the s is different…)
pub struct TokenSecurityAttribute {
    pub name: U16CString,
    pub flags: undoc::TOKEN_SECURITY_ATTRIBUTE_FLAG,
    pub values: TokenSecurityAttributeValues,
}

struct RawTokenSecurityAttribute<'a> {
    base: &'a TokenSecurityAttribute,
}

impl<'a> From<&'a TokenSecurityAttribute> for RawTokenSecurityAttribute<'a> {
    fn from(value: &'a TokenSecurityAttribute) -> Self {
        Self { base: value }
    }
}

impl RawTokenSecurityAttribute<'_> {
    fn as_raw(&self) -> anyhow::Result<undoc::TOKEN_SECURITY_ATTRIBUTE_V1> {
        // FIXME: Confusing code, where it’s not obvious who is owning what.
        // Maybe it should be inlined?

        struct RawValues {
            value_type: undoc::TOKEN_SECURITY_ATTRIBUTE_TYPE,
            value_count: usize,
            _ctx: Option<Box<dyn Any>>,
            values: undoc::TOKEN_SECURITY_ATTRIBUTE_V1_VALUE,
        }

        impl RawValues {
            fn new(
                value_type: undoc::TOKEN_SECURITY_ATTRIBUTE_TYPE,
                value_count: usize,
                ctx: Option<Box<dyn Any>>,
                values: undoc::TOKEN_SECURITY_ATTRIBUTE_V1_VALUE,
            ) -> Self {
                Self {
                    value_type,
                    value_count,
                    _ctx: ctx,
                    values,
                }
            }
        }

        let values = match &self.base.values {
            TokenSecurityAttributeValues::Int64(x) => RawValues::new(
                undoc::TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64,
                x.len(),
                None,
                undoc::TOKEN_SECURITY_ATTRIBUTE_V1_VALUE { pInt64: x.as_ptr() },
            ),
            TokenSecurityAttributeValues::Uint64(x) => RawValues::new(
                undoc::TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64,
                x.len(),
                None,
                undoc::TOKEN_SECURITY_ATTRIBUTE_V1_VALUE { pUint64: x.as_ptr() },
            ),
            TokenSecurityAttributeValues::String(values) => {
                let value_count = values.len();

                let ctx = values
                    .iter()
                    .map(|val| UnicodeStr::new(val).map(|x| x.as_unicode_string()))
                    .collect::<Result<Vec<_>, _>>()?;

                let values = undoc::TOKEN_SECURITY_ATTRIBUTE_V1_VALUE { pString: ctx.as_ptr() };

                RawValues::new(
                    undoc::TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING,
                    value_count,
                    Some(Box::new(ctx)),
                    values,
                )
            }
            TokenSecurityAttributeValues::Fqbn(x) => {
                let ctx = Box::new(
                    x.iter()
                        .map(|x| {
                            Ok(undoc::TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE {
                                Version: x.version,
                                Name: UnicodeStr::new(&x.name)?.as_unicode_string(),
                            })
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?,
                );

                let values = undoc::TOKEN_SECURITY_ATTRIBUTE_V1_VALUE { pFqbn: ctx.as_ptr() };

                RawValues::new(undoc::TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN, x.len(), Some(ctx), values)
            }
            TokenSecurityAttributeValues::OctetString(x) => {
                let ctx = Box::new(
                    x.iter()
                        .map(|x| {
                            Ok(undoc::TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE {
                                ValueLength: x.len().try_into()?,
                                pValue: x.as_ptr(),
                            })
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?,
                );

                let values = undoc::TOKEN_SECURITY_ATTRIBUTE_V1_VALUE {
                    pOctetString: ctx.as_ptr(),
                };

                RawValues::new(
                    undoc::TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING,
                    x.len(),
                    Some(ctx),
                    values,
                )
            }
            _ => RawValues::new(
                undoc::TOKEN_SECURITY_ATTRIBUTE_TYPE_INVALID,
                0,
                None,
                undoc::TOKEN_SECURITY_ATTRIBUTE_V1_VALUE { pGeneric: ptr::null() },
            ),
        };

        // FIXME: The Box<dyn Any> is going out of scope, while some structs are pointing to the boxed data.

        Ok(undoc::TOKEN_SECURITY_ATTRIBUTE_V1 {
            Name: UnicodeStr::new(&self.base.name)?.as_unicode_string(),
            ValueType: values.value_type,
            Reserved: 0,
            Flags: self.base.flags,
            ValueCount: values.value_count.try_into()?,
            Values: values.values,
        })
    }
}

pub struct TokenSecurityAttributeFqbn {
    pub version: u64,
    pub name: U16CString,
}

pub enum TokenSecurityAttributeValues {
    Invalid,
    Int64(Vec<i64>),
    Uint64(Vec<u64>),
    String(Vec<U16CString>),
    Fqbn(Vec<TokenSecurityAttributeFqbn>),
    Sid(Vec<Sid>),
    Boolean(Vec<bool>),
    OctetString(Vec<Vec<u8>>),
}

pub struct TokenDefaultDacl {
    pub default_dacl: Option<Acl>,
}

pub struct TokenPrimaryGroup {
    pub primary_group: Sid,
}

create_impersonation_context!(TokenImpersonation, Token, ImpersonateLoggedOnUser);

trait FromWin32<Win32Ty>: Sized {
    /// Creates a managed copy of the Win32 struct.
    ///
    /// # Safety
    ///
    /// The pointed Win32 struct must be valid.
    ///
    /// Validity, in this context, means that it is possible to rely on the
    /// fields of the Win32 struct being initialized in a way that would not
    /// cause bugs or UBs in Win32 API itself. For instance, in a TOKEN_GROUPS
    /// struct, GroupCount must hold exactly the number of elements in the
    /// array Groups. If GroupCount is an arbitrary value, reading the groups
    /// may cause cause memory unsafety.
    unsafe fn from_win32(value: InitedBuffer<Win32Ty>) -> anyhow::Result<Self>;
}

impl FromWin32<Security::TOKEN_USER> for TokenUser {
    unsafe fn from_win32(value: InitedBuffer<Security::TOKEN_USER>) -> anyhow::Result<Self> {
        // SAFETY: Per trait method safety requirements, the pointed struct is valid.
        let user = unsafe { SidAndAttributes::from_raw(&value.as_ref().User)? };

        Ok(Self { user })
    }
}

impl FromWin32<Security::TOKEN_GROUPS> for TokenGroups {
    unsafe fn from_win32(value: InitedBuffer<Security::TOKEN_GROUPS>) -> anyhow::Result<Self> {
        // SAFETY: Per trait method safety requirements, the pointed struct is valid.
        unsafe { TokenGroups::from_buffer(value) }
    }
}

impl FromWin32<Security::TOKEN_DEFAULT_DACL> for TokenDefaultDacl {
    unsafe fn from_win32(value: InitedBuffer<Security::TOKEN_DEFAULT_DACL>) -> anyhow::Result<Self> {
        // SAFETY: Per trait method safety requirements, the pointed struct is valid.
        let acl = unsafe { value.as_ref().DefaultDacl.cast::<AclRef>().as_ref() };

        Ok(Self {
            default_dacl: acl.map(|x| x.to_owned()),
        })
    }
}

impl FromWin32<Security::TOKEN_PRIMARY_GROUP> for TokenPrimaryGroup {
    unsafe fn from_win32(value: InitedBuffer<Security::TOKEN_PRIMARY_GROUP>) -> anyhow::Result<Self> {
        // SAFETY: Per trait method safety requirements, the pointed struct is valid.
        let primary_group = unsafe { Sid::from_psid(value.as_ref().PrimaryGroup)? };

        Ok(Self { primary_group })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn get_token_information_token_groups() {
        let token_groups = Token::current_process_token().groups().unwrap();

        for group in token_groups.iter() {
            assert!(group.sid.to_string().starts_with("S-"));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn get_token_information_linked_token() {
        if let Ok(mut linked_token) = Token::current_process_token().linked_token() {
            linked_token.reset_privileges().unwrap();
            linked_token.reset_groups().unwrap();
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn get_token_information_is_elevated() {
        let _ = Token::current_process_token().is_elevated().unwrap();
    }
}
