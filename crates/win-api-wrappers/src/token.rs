use std::alloc::Layout;
use std::any::Any;
use std::ffi::c_void;
use std::fmt::Debug;
use std::mem::MaybeUninit;
use std::{ptr, slice};

use anyhow::{bail, Result};
use windows::core::PCWSTR;

use crate::handle::{Handle, HandleWrapper};
use crate::identity::account::{create_profile, get_username, ProfileInfo};
use crate::identity::sid::{RawSid, RawSidAndAttributes, Sid, SidAndAttributes};
use crate::security::acl::Acl;
use crate::security::privilege::{
    find_token_with_privilege, lookup_privilege_value, RawTokenPrivileges, TokenPrivileges,
};
use crate::undoc::{
    LogonUserExExW, NtCreateToken, OBJECT_ATTRIBUTES, TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION,
    TOKEN_SECURITY_ATTRIBUTES_INFORMATION, TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1,
    TOKEN_SECURITY_ATTRIBUTE_FLAG, TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE,
    TOKEN_SECURITY_ATTRIBUTE_OPERATION, TOKEN_SECURITY_ATTRIBUTE_TYPE, TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN,
    TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64, TOKEN_SECURITY_ATTRIBUTE_TYPE_INVALID,
    TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING, TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING,
    TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64, TOKEN_SECURITY_ATTRIBUTE_V1, TOKEN_SECURITY_ATTRIBUTE_V1_VALUE,
};
use crate::utils::WideString;
use crate::{create_impersonation_context, Error};
use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_INVALID_SECURITY_DESCR, ERROR_INVALID_VARIANT, ERROR_NO_TOKEN, ERROR_SUCCESS, HANDLE,
    LUID,
};
use windows::Win32::Security::Authentication::Identity::EXTENDED_NAME_FORMAT;
use windows::Win32::Security::{
    AdjustTokenGroups, AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, ImpersonateLoggedOnUser,
    RevertToSelf, SecurityIdentification, SecurityImpersonation, SetTokenInformation, TokenElevationTypeDefault,
    TokenElevationTypeFull, TokenElevationTypeLimited, TokenPrimary, TokenSecurityAttributes, LOGON32_LOGON,
    LOGON32_PROVIDER, LUID_AND_ATTRIBUTES, SECURITY_ATTRIBUTES, SECURITY_DYNAMIC_TRACKING,
    SECURITY_IMPERSONATION_LEVEL, SECURITY_QUALITY_OF_SERVICE, SE_ASSIGNPRIMARYTOKEN_NAME, SE_CREATE_TOKEN_NAME,
    SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_REMOVED, SID_AND_ATTRIBUTES, TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS,
    TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_ELEVATION_TYPE, TOKEN_GROUPS, TOKEN_IMPERSONATE,
    TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_POLICY, TOKEN_MANDATORY_POLICY_ID, TOKEN_OWNER, TOKEN_PRIMARY_GROUP,
    TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY, TOKEN_SOURCE, TOKEN_STATISTICS, TOKEN_TYPE, TOKEN_USER,
};
use windows::Win32::System::SystemServices::SE_GROUP_LOGON_ID;

use super::utils::size_of_u32;

#[derive(Debug)]
pub struct Token {
    handle: Handle,
}

impl From<Handle> for Token {
    fn from(handle: Handle) -> Self {
        Self { handle }
    }
}

impl Token {
    pub fn current_process_token() -> Self {
        Self {
            handle: Handle::new_borrowed(HANDLE(-4isize as *mut c_void)).expect("always valid"),
        }
    }

    // Wrapper around `NtCreateToken`, which has a lot of arguments.
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<Self> {
        // See https://github.com/decoder-it/CreateTokenExample/blob/master/StopZillaCreateToken.cpp#L344
        let sqos = SECURITY_QUALITY_OF_SERVICE {
            Length: size_of_u32::<SECURITY_QUALITY_OF_SERVICE>(),
            ImpersonationLevel: SecurityImpersonation,
            ContextTrackingMode: SECURITY_DYNAMIC_TRACKING.0,
            EffectiveOnly: false.into(),
        };

        let object_attributes = OBJECT_ATTRIBUTES {
            Length: size_of_u32::<OBJECT_ATTRIBUTES>(),
            SecurityQualityOfService: &sqos as *const _ as *const c_void,
            ..Default::default()
        };

        let default_dacl = default_dacl.map(Acl::to_raw).transpose()?;
        let owner_sid = RawSid::try_from(owner)?;
        let groups = RawTokenGroups::try_from(groups)?;
        let privileges = RawTokenPrivileges::try_from(privileges)?;
        let primary_group = RawSid::try_from(primary_group)?;
        let user = RawSidAndAttributes::try_from(user)?;

        let mut priv_token = find_token_with_privilege(lookup_privilege_value(None, SE_CREATE_TOKEN_NAME)?)?
            .ok_or_else(|| Error::from_win32(ERROR_NO_TOKEN))?
            .duplicate_impersonation()?;

        priv_token.adjust_privileges(&TokenPrivilegesAdjustment::Enable(vec![
            lookup_privilege_value(None, SE_CREATE_TOKEN_NAME)?,
            lookup_privilege_value(None, SE_ASSIGNPRIMARYTOKEN_NAME)?,
        ]))?;

        let mut handle = HANDLE::default();
        let _ctx = priv_token.impersonate()?;

        // SAFETY: All buffers are valid. No documentation so no known preconditions.
        unsafe {
            NtCreateToken(
                &mut handle,
                TOKEN_ALL_ACCESS,
                &object_attributes,
                TokenPrimary,
                authentication_id,
                &expiration_time,
                &TOKEN_USER { User: *user.as_raw() },
                groups.as_raw(),
                privileges.as_raw(),
                &TOKEN_OWNER {
                    Owner: owner_sid.as_psid(),
                },
                &TOKEN_PRIMARY_GROUP {
                    PrimaryGroup: primary_group.as_psid(),
                },
                &TOKEN_DEFAULT_DACL {
                    DefaultDacl: default_dacl
                        .as_ref()
                        .map(|x| x.as_ptr().cast_mut().cast())
                        .unwrap_or(ptr::null_mut()),
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
    ) -> Result<Self> {
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
        }?;

        // SAFETY: We own the handle.
        let handle = unsafe { Handle::new_owned(handle)? };

        Ok(Self::from(handle))
    }

    pub fn duplicate_impersonation(&self) -> Result<Self> {
        self.duplicate(TOKEN_ACCESS_MASK(0), None, SecurityImpersonation, TokenPrimary)
    }

    pub fn impersonate(&self) -> Result<TokenImpersonation<'_>> {
        TokenImpersonation::try_new(self)
    }

    pub fn reset_privileges(&mut self) -> Result<()> {
        // SAFETY: No preconditions.
        unsafe { AdjustTokenPrivileges(self.handle.raw(), true, None, 0, None, None) }?;
        Ok(())
    }

    pub fn reset_groups(&mut self) -> Result<()> {
        // SAFETY: No preconditions.
        unsafe { AdjustTokenGroups(self.handle.raw(), true, None, 0, None, None) }?;
        Ok(())
    }

    fn information_var_size<S, D: for<'a> TryFrom<&'a S>>(&self, info_class: TOKEN_INFORMATION_CLASS) -> Result<D>
    where
        anyhow::Error: for<'a> From<<D as TryFrom<&'a S>>::Error>,
    {
        let mut required_size = 0u32;

        // SAFETY: No preconditions. We ignore result because we are collecting size.
        let _ = unsafe { GetTokenInformation(self.handle.raw(), info_class, None, 0, &mut required_size) };

        let mut buf = vec![0u8; required_size as usize];

        // SAFETY: No preconditions. `TokenInformationLength` matches length of `buf` in `TokenInformation`.
        unsafe {
            GetTokenInformation(
                self.handle.raw(),
                info_class,
                Some(buf.as_mut_ptr().cast()),
                u32::try_from(buf.len())?,
                &mut required_size,
            )
        }?;

        // SAFETY: We assume the target buffer matches the requested type. We can safely dereference because it is our buffer.
        Ok(unsafe { &*buf.as_ptr().cast::<S>() }.try_into()?)
    }

    fn information_raw<T: Sized>(&self, info_class: TOKEN_INFORMATION_CLASS) -> Result<T> {
        let mut info = MaybeUninit::<T>::uninit();
        let mut return_length = 0u32;

        // SAFETY: No preconditions. `TokenInformationLength` matches length of `info` in `TokenInformation`.
        unsafe {
            GetTokenInformation(
                self.handle.raw(),
                info_class,
                Some(info.as_mut_ptr().cast()),
                size_of_u32::<T>(),
                &mut return_length,
            )
        }?;

        // SAFETY: `GetTokenInformation` is successful here. Assume the value has been initialized.
        Ok(unsafe { info.assume_init() })
    }

    fn set_information_raw<T: Sized>(&self, info_class: TOKEN_INFORMATION_CLASS, value: &T) -> Result<()> {
        // SAFETY: No preconditions. `TokenInformationLength` matches length of `info` in `TokenInformation`.
        unsafe {
            SetTokenInformation(
                self.handle.raw(),
                info_class,
                value as *const _ as *const _,
                size_of_u32::<T>(),
            )?;
        }

        Ok(())
    }

    pub fn groups(&self) -> Result<TokenGroups> {
        self.information_var_size::<TOKEN_GROUPS, TokenGroups>(windows::Win32::Security::TokenGroups)
    }

    pub fn privileges(&self) -> Result<TokenPrivileges> {
        self.information_var_size::<TOKEN_PRIVILEGES, TokenPrivileges>(windows::Win32::Security::TokenPrivileges)
    }

    pub fn elevation_type(&self) -> Result<TokenElevationType> {
        self.information_raw::<TOKEN_ELEVATION_TYPE>(windows::Win32::Security::TokenElevationType)?
            .try_into()
    }

    pub fn is_elevated(&self) -> Result<bool> {
        Ok(self.information_raw::<i32>(windows::Win32::Security::TokenElevation)? != 0)
    }

    pub fn linked_token(&self) -> Result<Self> {
        let handle = self.information_raw::<HANDLE>(windows::Win32::Security::TokenLinkedToken)?;
        // SAFETY: We are responsible for closing the linked token.
        let handle = unsafe { Handle::new_owned(handle)? };

        Self::from(handle)
    }

    pub fn username(&self, format: EXTENDED_NAME_FORMAT) -> Result<String> {
        let _ctx = self.impersonate()?;

        get_username(format)
    }

    pub fn logon(
        username: &str,
        domain: Option<&str>,
        password: Option<&str>,
        logon_type: LOGON32_LOGON,
        logon_provider: LOGON32_PROVIDER,
        groups: Option<&TokenGroups>,
    ) -> Result<Self> {
        let mut raw_token = HANDLE::default();

        let groups = groups.map(RawTokenGroups::try_from).transpose()?;
        let username = WideString::from(username);
        let domain = domain.map(WideString::from);
        let password = password.map(WideString::from);

        // SAFETY: No preconditions. `username` is valid and NUL terminated.
        // `domain` and `password` are either NULL or valid NUL terminated strings.
        // We assume `groups` is well constructed.
        unsafe {
            LogonUserExExW(
                username.as_pcwstr(),
                domain.as_ref().map_or_else(PCWSTR::null, WideString::as_pcwstr),
                password.as_ref().map_or_else(PCWSTR::null, WideString::as_pcwstr),
                logon_type,
                logon_provider,
                groups.as_ref().map(|x| x.as_raw() as *const _),
                Some(&mut raw_token),
                None,
                None,
                None,
                None,
            )
        }?;

        // SAFETY: We own the handle.
        let handle = unsafe { Handle::new_owned(raw_token)? };

        Ok(Token::from(handle))
    }

    pub fn statistics(&self) -> Result<TOKEN_STATISTICS> {
        self.information_raw::<TOKEN_STATISTICS>(windows::Win32::Security::TokenStatistics)
    }

    pub fn sid_and_attributes(&self) -> Result<SidAndAttributes> {
        Ok(self
            .information_var_size::<TOKEN_USER, TokenUser>(windows::Win32::Security::TokenUser)?
            .user)
    }

    pub fn session_id(&self) -> Result<u32> {
        self.information_raw::<u32>(windows::Win32::Security::TokenSessionId)
    }

    pub fn set_session_id(&mut self, session_id: u32) -> Result<()> {
        self.set_information_raw(windows::Win32::Security::TokenSessionId, &session_id)
    }

    pub fn mandatory_policy(&self) -> Result<TOKEN_MANDATORY_POLICY_ID> {
        Ok(self
            .information_raw::<TOKEN_MANDATORY_POLICY>(windows::Win32::Security::TokenMandatoryPolicy)?
            .Policy)
    }

    pub fn set_mandatory_policy(&mut self, mandatory_policy: TOKEN_MANDATORY_POLICY_ID) -> Result<()> {
        self.set_information_raw(
            windows::Win32::Security::TokenMandatoryPolicy,
            &TOKEN_MANDATORY_POLICY {
                Policy: mandatory_policy,
            },
        )
    }

    pub fn load_profile(&self, username: &str) -> Result<ProfileInfo> {
        if let Err(err) = create_profile(&self.sid_and_attributes()?.sid, username) {
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
                TokenPrimary,
            )?,
            username,
        )
    }

    pub fn adjust_groups(&mut self, adjustment: &TokenGroupAdjustment) -> Result<()> {
        match adjustment {
            // SAFETY: No preconditions.
            TokenGroupAdjustment::ResetToDefaults => unsafe {
                AdjustTokenGroups(self.handle.raw(), true, None, 0, None, None)?;
            },
            TokenGroupAdjustment::Enable(groups) => {
                let groups = RawTokenGroups::try_from(groups)?;
                // SAFETY: No preconditions. We assume `groups` is well constructed.
                unsafe {
                    AdjustTokenGroups(self.handle.raw(), false, Some(groups.as_raw()), 0, None, None)?;
                }
            }
        }

        Ok(())
    }

    pub fn adjust_privileges(&mut self, adjustment: &TokenPrivilegesAdjustment) -> Result<()> {
        match adjustment {
            // SAFETY: No preconditions.
            TokenPrivilegesAdjustment::DisableAllPrivileges => unsafe {
                AdjustTokenPrivileges(self.handle.raw(), true, None, 0, None, None)?;
            },
            TokenPrivilegesAdjustment::Enable(privs)
            | TokenPrivilegesAdjustment::Disable(privs)
            | TokenPrivilegesAdjustment::Remove(privs) => {
                let attr = match adjustment {
                    TokenPrivilegesAdjustment::Enable(_) => SE_PRIVILEGE_ENABLED,
                    TokenPrivilegesAdjustment::DisableAllPrivileges | TokenPrivilegesAdjustment::Disable(_) => {
                        TOKEN_PRIVILEGES_ATTRIBUTES(0)
                    }
                    TokenPrivilegesAdjustment::Remove(_) => SE_PRIVILEGE_REMOVED,
                };

                let privs = TokenPrivileges(
                    privs
                        .iter()
                        .map(|p| LUID_AND_ATTRIBUTES {
                            Luid: *p,
                            Attributes: attr,
                        })
                        .collect(),
                );

                let privs = RawTokenPrivileges::try_from(&privs)?;

                // SAFETY: No preconditions. We assume `privs` is well constructed.
                unsafe { AdjustTokenPrivileges(self.handle.raw(), false, Some(privs.as_raw()), 0, None, None) }?;

                let last_err = Error::last_error();
                if last_err.code() != ERROR_SUCCESS.to_hresult().0 {
                    bail!(last_err);
                }
            }
        }

        Ok(())
    }

    pub fn default_dacl(&self) -> Result<Option<Acl>> {
        Ok(self
            .information_var_size::<TOKEN_DEFAULT_DACL, TokenDefaultDacl>(windows::Win32::Security::TokenDefaultDacl)?
            .default_dacl)
    }

    pub fn primary_group(&self) -> Result<Sid> {
        Ok(self
            .information_var_size::<TOKEN_PRIMARY_GROUP, TokenPrimaryGroup>(
                windows::Win32::Security::TokenPrimaryGroup,
            )?
            .primary_group)
    }

    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            handle: self.handle.try_clone()?,
        })
    }

    pub fn logon_sid(&self) -> Result<Sid> {
        #[allow(clippy::cast_sign_loss)]
        Ok(self
            .groups()?
            .0
            .into_iter()
            .find(|g| (g.attributes & SE_GROUP_LOGON_ID as u32) != 0)
            .ok_or_else(|| Error::from_win32(ERROR_INVALID_SECURITY_DESCR))?
            .sid)
    }

    pub fn apply_security_attribute(
        &mut self,
        action: TOKEN_SECURITY_ATTRIBUTE_OPERATION,
        attribute: &TokenSecurityAttribute,
    ) -> Result<()> {
        let attribute = RawTokenSecurityAttribute::from(attribute);
        let raw_attribute = attribute.as_raw()?;
        let attribute_info = TOKEN_SECURITY_ATTRIBUTES_INFORMATION {
            Version: TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1,
            Reserved: 0,
            AttributeCount: 1,
            pAttributeV1: &raw_attribute,
        };

        let info = TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION {
            Attributes: &attribute_info,
            Operations: &action,
        };

        self.set_information_raw(TokenSecurityAttributes, &info)
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

impl TryFrom<&TOKEN_USER> for TokenUser {
    type Error = anyhow::Error;

    fn try_from(value: &TOKEN_USER) -> Result<Self, Self::Error> {
        Ok(Self {
            user: SidAndAttributes::try_from(&value.User)?,
        })
    }
}

pub struct TokenGroups(pub Vec<SidAndAttributes>);

pub struct RawTokenGroups {
    buf: Vec<u8>,
    _sid_and_attributes: Vec<RawSidAndAttributes>,
}

impl RawTokenGroups {
    pub fn as_raw(&self) -> &TOKEN_GROUPS {
        // SAFETY: We assume our buffer is well constructed and aligned. We can safely dereference because it is our buffer.
        unsafe { &*self.buf.as_ptr().cast() }
    }
}

impl TryFrom<&TokenGroups> for RawTokenGroups {
    type Error = anyhow::Error;

    fn try_from(value: &TokenGroups) -> Result<Self> {
        let raw_sid_and_attributes = value
            .0
            .iter()
            .map(RawSidAndAttributes::try_from)
            .collect::<Result<Vec<_>>>()?;

        let mut buf = vec![
            0u8;
            Layout::new::<TOKEN_GROUPS>()
                .extend(Layout::array::<SID_AND_ATTRIBUTES>(
                    raw_sid_and_attributes.len().saturating_sub(1)
                )?)?
                .0
                .pad_to_align()
                .size()
        ];

        // SAFETY: `buf` is at least as big as `TOKEN_GROUPS` and its groups.
        #[allow(clippy::cast_ptr_alignment)]
        let groups = unsafe { &mut *buf.as_mut_ptr().cast::<TOKEN_GROUPS>() };

        groups.GroupCount = value.0.len().try_into()?;

        for (i, v) in raw_sid_and_attributes.iter().enumerate() {
            // SAFETY: `Groups` is a VLA and we have previously correctly sized it.
            unsafe { *groups.Groups.get_unchecked_mut(i) = *v.as_raw() };
        }

        Ok(Self {
            buf,
            _sid_and_attributes: raw_sid_and_attributes,
        })
    }
}

impl TryFrom<&TOKEN_GROUPS> for TokenGroups {
    type Error = anyhow::Error;

    fn try_from(value: &TOKEN_GROUPS) -> Result<Self> {
        // SAFETY: We assume `Groups` and `GroupCount` are well constructed and valid.
        let groups_slice = unsafe { slice::from_raw_parts(value.Groups.as_ptr(), value.GroupCount as usize) };

        let mut groups = Vec::with_capacity(groups_slice.len());

        for group in groups_slice.iter() {
            groups.push(SidAndAttributes::try_from(group)?);
        }

        Ok(TokenGroups(groups))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TokenElevationType {
    Default = 1,
    Full = 2,
    Limited = 3,
}

impl TryFrom<TOKEN_ELEVATION_TYPE> for TokenElevationType {
    type Error = anyhow::Error;

    fn try_from(value: TOKEN_ELEVATION_TYPE) -> std::prelude::v1::Result<Self, Self::Error> {
        TokenElevationType::try_from(&value)
    }
}

impl TryFrom<&TOKEN_ELEVATION_TYPE> for TokenElevationType {
    type Error = anyhow::Error;

    fn try_from(value: &TOKEN_ELEVATION_TYPE) -> std::prelude::v1::Result<Self, Self::Error> {
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

pub struct TokenSecurityAttribute {
    pub name: WideString,
    pub flags: TOKEN_SECURITY_ATTRIBUTE_FLAG,
    pub values: TokenSecurityAttributeValues,
}

pub struct RawTokenSecurityAttribute<'a> {
    base: &'a TokenSecurityAttribute,
}

impl<'a> From<&'a TokenSecurityAttribute> for RawTokenSecurityAttribute<'a> {
    fn from(value: &'a TokenSecurityAttribute) -> Self {
        Self { base: value }
    }
}

impl RawTokenSecurityAttribute<'_> {
    pub fn as_raw(&self) -> Result<TOKEN_SECURITY_ATTRIBUTE_V1> {
        struct RawValues {
            value_type: TOKEN_SECURITY_ATTRIBUTE_TYPE,
            value_count: usize,
            _ctx: Option<Box<dyn Any>>,
            values: TOKEN_SECURITY_ATTRIBUTE_V1_VALUE,
        }

        impl RawValues {
            fn new(
                value_type: TOKEN_SECURITY_ATTRIBUTE_TYPE,
                value_count: usize,
                ctx: Option<Box<dyn Any>>,
                values: TOKEN_SECURITY_ATTRIBUTE_V1_VALUE,
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
                TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64,
                x.len(),
                None,
                TOKEN_SECURITY_ATTRIBUTE_V1_VALUE { pInt64: x.as_ptr() },
            ),
            TokenSecurityAttributeValues::Uint64(x) => RawValues::new(
                TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64,
                x.len(),
                None,
                TOKEN_SECURITY_ATTRIBUTE_V1_VALUE { pUint64: x.as_ptr() },
            ),
            TokenSecurityAttributeValues::String(x) => {
                let ctx = Box::new(
                    x.iter()
                        .map(WideString::as_unicode_string)
                        .collect::<Result<Vec<_>>>()?,
                );

                let values = TOKEN_SECURITY_ATTRIBUTE_V1_VALUE { pString: ctx.as_ptr() };
                RawValues::new(TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING, x.len(), Some(ctx), values)
            }
            TokenSecurityAttributeValues::Fqbn(x) => {
                let ctx = Box::new(
                    x.iter()
                        .map(|x| {
                            Ok(TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE {
                                Version: x.version,
                                Name: x.name.as_unicode_string()?,
                            })
                        })
                        .collect::<Result<Vec<_>>>()?,
                );

                let values = TOKEN_SECURITY_ATTRIBUTE_V1_VALUE { pFqbn: ctx.as_ptr() };

                RawValues::new(TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN, x.len(), Some(ctx), values)
            }
            TokenSecurityAttributeValues::OctetString(x) => {
                let ctx = Box::new(
                    x.iter()
                        .map(|x| {
                            Ok(TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE {
                                ValueLength: x.len().try_into()?,
                                pValue: x.as_ptr(),
                            })
                        })
                        .collect::<Result<Vec<_>>>()?,
                );

                let values = TOKEN_SECURITY_ATTRIBUTE_V1_VALUE {
                    pOctetString: ctx.as_ptr(),
                };

                RawValues::new(TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING, x.len(), Some(ctx), values)
            }
            _ => RawValues::new(
                TOKEN_SECURITY_ATTRIBUTE_TYPE_INVALID,
                0,
                None,
                TOKEN_SECURITY_ATTRIBUTE_V1_VALUE { pGeneric: ptr::null() },
            ),
        };

        Ok(TOKEN_SECURITY_ATTRIBUTE_V1 {
            Name: self.base.name.as_unicode_string()?,
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
    pub name: WideString,
}

pub enum TokenSecurityAttributeValues {
    Invalid,
    Int64(Vec<i64>),
    Uint64(Vec<u64>),
    String(Vec<WideString>),
    Fqbn(Vec<TokenSecurityAttributeFqbn>),
    Sid(Vec<RawSid>),
    Boolean(Vec<bool>),
    OctetString(Vec<Vec<u8>>),
}

pub struct TokenDefaultDacl {
    pub default_dacl: Option<Acl>,
}

impl TryFrom<&TOKEN_DEFAULT_DACL> for TokenDefaultDacl {
    type Error = anyhow::Error;

    fn try_from(value: &TOKEN_DEFAULT_DACL) -> Result<Self, Self::Error> {
        Ok(Self {
            // SAFETY: We assume `DefaultDacl` actually points to an ACL.
            default_dacl: unsafe { value.DefaultDacl.as_ref() }.map(Acl::try_from).transpose()?,
        })
    }
}

pub struct TokenPrimaryGroup {
    pub primary_group: Sid,
}

impl TryFrom<&TOKEN_PRIMARY_GROUP> for TokenPrimaryGroup {
    type Error = anyhow::Error;

    fn try_from(value: &TOKEN_PRIMARY_GROUP) -> Result<Self, Self::Error> {
        Ok(Self {
            primary_group: Sid::try_from(value.PrimaryGroup)?,
        })
    }
}

create_impersonation_context!(TokenImpersonation, Token, ImpersonateLoggedOnUser);
