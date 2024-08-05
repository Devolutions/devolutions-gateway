use std::any::Any;
use std::fmt::Debug;
use std::mem::{self};
use std::{ptr, slice};

use anyhow::{bail, Result};

use crate::error::Error;
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
use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_INVALID_SECURITY_DESCR, ERROR_INVALID_VARIANT, ERROR_NO_TOKEN, ERROR_SUCCESS, E_HANDLE,
    E_POINTER, HANDLE, LUID,
};
use windows::Win32::Security::Authentication::Identity::EXTENDED_NAME_FORMAT;
use windows::Win32::Security::{
    AdjustTokenGroups, AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, ImpersonateLoggedOnUser,
    RevertToSelf, SecurityImpersonation, SetTokenInformation, TokenElevationTypeDefault, TokenElevationTypeFull,
    TokenElevationTypeLimited, TokenPrimary, TokenSecurityAttributes, LOGON32_LOGON, LOGON32_PROVIDER,
    LUID_AND_ATTRIBUTES, PSID, SECURITY_ATTRIBUTES, SECURITY_DYNAMIC_TRACKING, SECURITY_IMPERSONATION_LEVEL,
    SECURITY_QUALITY_OF_SERVICE, SE_ASSIGNPRIMARYTOKEN_NAME, SE_CREATE_TOKEN_NAME, SE_PRIVILEGE_ENABLED,
    SE_PRIVILEGE_REMOVED, SID_AND_ATTRIBUTES, TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS, TOKEN_DEFAULT_DACL,
    TOKEN_ELEVATION_TYPE, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_POLICY, TOKEN_MANDATORY_POLICY_ID,
    TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_SOURCE, TOKEN_STATISTICS,
    TOKEN_TYPE, TOKEN_USER,
};
use windows::Win32::System::SystemServices::SE_GROUP_LOGON_ID;

#[derive(Debug)]
pub struct Token {
    handle: Handle,
}

impl Token {
    pub fn try_with_handle(handle: HANDLE) -> Result<Self> {
        if handle.is_invalid() {
            bail!(Error::from_hresult(E_HANDLE))
        } else {
            Ok(Self { handle: handle.into() })
        }
    }

    pub fn current_process_token() -> Self {
        Self {
            handle: Handle::new(HANDLE(-4 as _), false),
        }
    }

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
            Length: mem::size_of::<SECURITY_QUALITY_OF_SERVICE>() as _,
            ImpersonationLevel: SecurityImpersonation,
            ContextTrackingMode: SECURITY_DYNAMIC_TRACKING.0,
            EffectiveOnly: false.into(),
        };

        let object_attributes = OBJECT_ATTRIBUTES {
            Length: mem::size_of::<OBJECT_ATTRIBUTES>() as _,
            SecurityQualityOfService: &sqos as *const _ as _,
            ..Default::default()
        };

        let default_dacl = default_dacl.map(Acl::to_raw).transpose()?;
        let owner_sid = RawSid::from(owner);
        let groups = RawTokenGroups::from(groups);
        let privileges = RawTokenPrivileges::from(privileges);
        let primary_group = RawSid::from(primary_group);
        let user = RawSidAndAttributes::from(user);

        let mut priv_token = find_token_with_privilege(lookup_privilege_value(None, SE_CREATE_TOKEN_NAME)?)?
            .ok_or_else(|| Error::from_win32(ERROR_NO_TOKEN))?
            .duplicate_impersonation()?;

        priv_token.adjust_privileges(&TokenPrivilegesAdjustment::Enable(vec![
            lookup_privilege_value(None, SE_CREATE_TOKEN_NAME)?,
            lookup_privilege_value(None, SE_ASSIGNPRIMARYTOKEN_NAME)?,
        ]))?;

        let mut handle = HANDLE::default();
        priv_token.impersonate(|| unsafe {
            Ok(NtCreateToken(
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
                    Owner: PSID(owner_sid.as_raw() as *const _ as _),
                },
                &TOKEN_PRIMARY_GROUP {
                    PrimaryGroup: PSID(primary_group.as_raw() as *const _ as _),
                },
                &TOKEN_DEFAULT_DACL {
                    DefaultDacl: default_dacl
                        .as_ref()
                        .map(|x| x.as_ptr().cast_mut().cast())
                        .unwrap_or(ptr::null_mut()),
                },
                source,
            )?)
        })?;

        Ok(Self { handle: handle.into() })
    }

    pub fn duplicate(
        &self,
        desired_access: TOKEN_ACCESS_MASK,
        attributes: Option<&SECURITY_ATTRIBUTES>,
        impersonation_level: SECURITY_IMPERSONATION_LEVEL,
        token_type: TOKEN_TYPE,
    ) -> Result<Self> {
        let mut handle = Default::default();
        unsafe {
            DuplicateTokenEx(
                self.handle.raw(),
                desired_access,
                attributes.map(|x| x as _),
                impersonation_level,
                token_type,
                &mut handle,
            )
        }?;

        Self::try_with_handle(handle)
    }

    pub fn duplicate_impersonation(&self) -> Result<Self> {
        self.duplicate(TOKEN_ACCESS_MASK(0), None, SecurityImpersonation, TokenPrimary)
    }

    pub fn impersonate<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        unsafe { ImpersonateLoggedOnUser(self.handle.raw()) }?;

        let r = f();

        unsafe { RevertToSelf() }?;

        r
    }

    pub fn reset(&mut self) -> Result<()> {
        unsafe { AdjustTokenGroups(self.handle.raw(), true, None, 0, None, None) }?;
        Ok(())
    }

    pub fn reset_groups(&mut self) -> Result<()> {
        unsafe { AdjustTokenGroups(self.handle.raw(), true, None, 0, None, None) }?;
        Ok(())
    }

    fn information_var_size<S, D: for<'a> TryFrom<&'a S>>(&self, info_class: TOKEN_INFORMATION_CLASS) -> Result<D>
    where
        anyhow::Error: for<'a> From<<D as TryFrom<&'a S>>::Error>,
    {
        let mut required_size = 0u32;
        let _ = unsafe { GetTokenInformation(self.handle.raw(), info_class, None, 0, &mut required_size as _) };

        let mut buf: Vec<u8> = Vec::with_capacity(required_size as _);

        unsafe {
            GetTokenInformation(
                self.handle.raw(),
                info_class,
                Some(buf.as_mut_ptr() as _),
                buf.capacity() as _,
                &mut required_size as _,
            )
        }?;

        let raw_groups = unsafe { buf.as_ptr().cast::<S>().as_ref() };

        Ok(raw_groups.ok_or_else(|| Error::from_hresult(E_POINTER))?.try_into()?)
    }

    fn information_raw<T: Default + Sized>(&self, info_class: TOKEN_INFORMATION_CLASS) -> Result<T> {
        let mut info = T::default();
        let mut return_length = 0u32;

        unsafe {
            GetTokenInformation(
                self.handle.raw(),
                info_class,
                Some(&mut info as *mut _ as _),
                mem::size_of::<T>() as _,
                &mut return_length as _,
            )
        }?;

        Ok(info)
    }

    fn set_information_raw<T: Sized>(&self, info_class: TOKEN_INFORMATION_CLASS, value: &T) -> Result<()> {
        unsafe {
            SetTokenInformation(
                self.handle.raw(),
                info_class,
                value as *const _ as _,
                mem::size_of::<T>() as _,
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
        Self::try_with_handle(self.information_raw::<HANDLE>(windows::Win32::Security::TokenLinkedToken)?)
    }

    pub fn username(&self, format: EXTENDED_NAME_FORMAT) -> Result<String> {
        let mut username = String::new();
        self.impersonate(|| {
            username = get_username(format)?;
            Ok(())
        })?;

        Ok(username)
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

        let raw_groups = groups.map(RawTokenGroups::from);

        unsafe {
            LogonUserExExW(
                WideString::from(username).as_pcwstr(),
                domain.map(WideString::from).unwrap_or_default().as_pcwstr(),
                password.map(WideString::from).unwrap_or_default().as_pcwstr(),
                logon_type,
                logon_provider,
                raw_groups.as_ref().map(|x| x.as_raw() as _),
                Some(&mut raw_token as _),
                None,
                None,
                None,
                None,
            )?;
        }

        Token::try_with_handle(raw_token)
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

        ProfileInfo::from_token(self, username)
    }

    pub fn adjust_groups(&mut self, adjustment: &TokenGroupAdjustment) -> Result<()> {
        match adjustment {
            TokenGroupAdjustment::ResetToDefaults => unsafe {
                AdjustTokenGroups(self.handle.raw(), true, None, 0, None, None)?;
            },
            TokenGroupAdjustment::Enable(groups) => {
                let raw_groups = RawTokenGroups::from(groups);
                unsafe {
                    AdjustTokenGroups(self.handle.raw(), false, Some(raw_groups.as_raw()), 0, None, None)?;
                }
            }
        }

        Ok(())
    }

    pub fn adjust_privileges(&mut self, adjustment: &TokenPrivilegesAdjustment) -> Result<()> {
        match adjustment {
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

                let raw_privs = RawTokenPrivileges::from(&privs);

                unsafe {
                    AdjustTokenPrivileges(self.handle.raw(), false, Some(raw_privs.as_raw()), 0, None, None)?;
                }

                let last_err = Error::last_error();
                if last_err.code() != ERROR_SUCCESS.0 as _ {
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
        Ok(self
            .groups()?
            .0
            .into_iter()
            .find(|g| (g.attributes & SE_GROUP_LOGON_ID.unsigned_abs()) != 0)
            .ok_or_else(|| Error::from_win32(ERROR_INVALID_SECURITY_DESCR))?
            .sid)
    }

    pub fn apply_security_attribute(
        &mut self,
        action: TOKEN_SECURITY_ATTRIBUTE_OPERATION,
        attribute: &TokenSecurityAttribute,
    ) -> Result<()> {
        let attribute = RawTokenSecurityAttribute::from(attribute);
        let raw_attribute = attribute.as_raw();
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
        unsafe { &*self.buf.as_ptr().cast::<TOKEN_GROUPS>() }
    }
}

impl From<&TokenGroups> for RawTokenGroups {
    fn from(value: &TokenGroups) -> Self {
        let mut raw_buf = vec![
            0u8;
            mem::size_of::<TOKEN_GROUPS>()
                + (value.0.len().saturating_sub(1)) * mem::size_of::<SID_AND_ATTRIBUTES>()
        ];

        let raw = raw_buf.as_mut_ptr().cast::<TOKEN_GROUPS>();

        let raw_sid_and_attributes = value.0.iter().map(RawSidAndAttributes::from).collect::<Vec<_>>();

        unsafe {
            ptr::addr_of_mut!((*raw).GroupCount).write(value.0.len() as _);

            let groups_ptr = ptr::addr_of_mut!((*raw).Groups).cast::<SID_AND_ATTRIBUTES>();

            for (i, v) in raw_sid_and_attributes.iter().enumerate() {
                groups_ptr.add(i).write(*v.as_raw());
            }
        }

        Self {
            buf: raw_buf,
            _sid_and_attributes: raw_sid_and_attributes,
        }
    }
}

impl TryFrom<&TOKEN_GROUPS> for TokenGroups {
    type Error = anyhow::Error;

    fn try_from(value: &TOKEN_GROUPS) -> Result<Self> {
        let groups_slice = unsafe { slice::from_raw_parts(value.Groups.as_ptr(), value.GroupCount as _) };

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

impl<'a> RawTokenSecurityAttribute<'a> {
    pub fn as_raw(&self) -> TOKEN_SECURITY_ATTRIBUTE_V1 {
        struct RawValues {
            value_type: TOKEN_SECURITY_ATTRIBUTE_TYPE,
            value_count: usize,
            _ctx: Option<Box<dyn Any>>,
            values: TOKEN_SECURITY_ATTRIBUTE_V1_VALUE,
        }

        impl RawValues {
            pub fn new(
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
                let ctx = Box::new(x.iter().map(WideString::as_unicode_string).collect::<Vec<_>>());
                let values = TOKEN_SECURITY_ATTRIBUTE_V1_VALUE { pString: ctx.as_ptr() };
                RawValues::new(TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING, x.len(), Some(ctx), values)
            }
            TokenSecurityAttributeValues::Fqbn(x) => {
                let ctx = Box::new(
                    x.iter()
                        .map(|x| TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE {
                            Version: x.version,
                            Name: x.name.as_unicode_string(),
                        })
                        .collect::<Vec<_>>(),
                );

                let values = TOKEN_SECURITY_ATTRIBUTE_V1_VALUE { pFqbn: ctx.as_ptr() };

                RawValues::new(TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN, x.len(), Some(ctx), values)
            }
            TokenSecurityAttributeValues::OctetString(x) => {
                let ctx = Box::new(
                    x.iter()
                        .map(|x| TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE {
                            ValueLength: x.len() as _,
                            pValue: x.as_ptr(),
                        })
                        .collect::<Vec<_>>(),
                );

                let values = TOKEN_SECURITY_ATTRIBUTE_V1_VALUE {
                    pOctetString: ctx.as_ptr(),
                };

                RawValues::new(TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING, x.len(), Some(ctx), values)
            }
            TokenSecurityAttributeValues::Invalid | _ => RawValues::new(
                TOKEN_SECURITY_ATTRIBUTE_TYPE_INVALID,
                0,
                None,
                TOKEN_SECURITY_ATTRIBUTE_V1_VALUE { pGeneric: ptr::null() },
            ),
        };

        TOKEN_SECURITY_ATTRIBUTE_V1 {
            Name: self.base.name.as_unicode_string(),
            ValueType: values.value_type,
            Reserved: 0,
            Flags: self.base.flags,
            ValueCount: values.value_count as _,
            Values: values.values,
        }
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
