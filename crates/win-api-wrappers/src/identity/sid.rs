use std::fmt::{self, Debug};
use std::hash::Hash;
use std::mem::{self};
use std::ptr;

use anyhow::{bail, Result};

use crate::error::Error;
use crate::undoc::{RtlCreateVirtualAccountSid, SECURITY_MAX_SID_SIZE};
use crate::utils::{SafeWindowsString, WideString};
use windows::core::PWSTR;
use windows::Win32::Foundation::{LocalFree, E_POINTER, HLOCAL};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows::Win32::Security::{
    CreateWellKnownSid, GetLengthSid, GetSidSubAuthority, IsValidSid, LookupAccountSidW, PSID, SID, SID_AND_ATTRIBUTES,
    SID_IDENTIFIER_AUTHORITY, SID_NAME_USE, WELL_KNOWN_SID_TYPE,
};

use super::account::Account;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sid {
    pub revision: u8,
    pub identifier_identity: SID_IDENTIFIER_AUTHORITY,
    pub sub_authority: Vec<u32>,
}

impl Hash for Sid {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.revision.hash(state);
        self.identifier_identity.Value.hash(state);
        self.sub_authority.hash(state);
    }
}

impl Sid {
    pub fn virtual_account_sid(name: &str, base_sub_authority: u32) -> Result<Self> {
        let name = WideString::from(name);
        let mut buf: Vec<u8> = Vec::with_capacity(SECURITY_MAX_SID_SIZE as _);
        let mut out_size = buf.capacity() as u32;

        unsafe {
            RtlCreateVirtualAccountSid(
                &name.as_unicode_string(),
                base_sub_authority,
                PSID(buf.as_mut_ptr() as _),
                &mut out_size as _,
            )?;

            buf.set_len(out_size as _);
        }

        Ok(unsafe { &*buf.as_ptr().cast::<SID>() }.into())
    }

    pub fn from_well_known(sid_type: WELL_KNOWN_SID_TYPE, domain_sid: Option<&Self>) -> Result<Self> {
        let mut out_size = 0u32;

        let domain_sid = domain_sid.map(RawSid::from);

        let domain_sid_ptr = domain_sid.map(|x| x.as_raw() as *const _).unwrap_or_else(ptr::null);

        unsafe {
            let _ = CreateWellKnownSid(
                sid_type,
                PSID(domain_sid_ptr as _),
                PSID(ptr::null_mut()),
                &mut out_size as _,
            );
        }

        let mut buf: Vec<u8> = Vec::with_capacity(out_size as _);

        unsafe {
            CreateWellKnownSid(
                sid_type,
                PSID(domain_sid_ptr as _),
                PSID(buf.as_mut_ptr() as _),
                &mut out_size as _,
            )?;

            buf.set_len(out_size as _);
        }

        Ok(Self::from(unsafe { &*buf.as_ptr().cast::<SID>() }))
    }

    pub fn is_valid(&self) -> bool {
        RawSid::from(self).is_valid()
    }

    pub fn account(&self, system_name: Option<&str>) -> Result<Account> {
        let raw_sid = RawSid::from(self);
        let mut name_size = 0u32;
        let mut domain_size = 0u32;
        let mut sid_name_use = SID_NAME_USE::default();

        let mut account = Account::default();

        unsafe {
            let _ = LookupAccountSidW(
                system_name.map(WideString::from).unwrap_or_default().as_pcwstr(),
                PSID(raw_sid.as_raw() as *const _ as _),
                PWSTR::null(),
                &mut name_size,
                PWSTR::null(),
                &mut domain_size,
                &mut sid_name_use,
            );

            let mut name_buf = vec![0u16; name_size as _];
            let mut domain_buf = vec![0u16; domain_size as _];

            let name_buf_ptr = PWSTR::from_raw(name_buf.as_mut_ptr());
            let domain_buf_ptr = PWSTR::from_raw(domain_buf.as_mut_ptr());

            LookupAccountSidW(
                system_name.map(WideString::from).unwrap_or_default().as_pcwstr(),
                PSID(raw_sid.as_raw() as *const _ as _),
                name_buf_ptr,
                &mut name_size,
                domain_buf_ptr,
                &mut domain_size,
                &mut sid_name_use,
            )?;

            account.account_name = name_buf_ptr.to_string()?;
            account.domain_name = domain_buf_ptr.to_string()?;
        }

        account.account_sid = self.clone();
        account.domain_sid = self.clone();
        account.domain_sid.sub_authority.shrink_to(1);

        Ok(account)
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        RawSid::from(self).fmt(f)
    }
}

impl Default for Sid {
    fn default() -> Self {
        Self {
            revision: 1,
            identifier_identity: Default::default(),
            sub_authority: Default::default(),
        }
    }
}

pub struct RawSid {
    pub buf: Vec<u8>,
}

impl RawSid {
    pub fn len(&self) -> usize {
        unsafe { GetLengthSid(PSID(self.as_raw() as *const _ as _)) as _ }
    }

    pub fn as_raw(&self) -> &SID {
        unsafe { &*self.buf.as_ptr().cast::<SID>() }
    }

    pub fn is_valid(&self) -> bool {
        unsafe { IsValidSid(PSID(self.as_raw() as *const _ as _)) }.as_bool()
    }
}

impl fmt::Display for RawSid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut raw_string_sid = PWSTR::null();
        unsafe {
            ConvertSidToStringSidW(PSID(self.as_raw() as *const _ as _), &mut raw_string_sid as _)
                .map_err(|_| fmt::Error)?;

            let res = (|| {
                f.write_str(&raw_string_sid.to_string_safe().map_err(|_| fmt::Error)?)?;
                Ok(())
            })();

            LocalFree(HLOCAL(raw_string_sid.0 as _));

            res
        }
    }
}

impl TryFrom<&str> for Sid {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = WideString::from(value);
        let mut sid_ptr = PSID::default();

        unsafe {
            ConvertStringSidToSidW(value.as_pcwstr(), &mut sid_ptr)?;
        }

        let sid = Self::from(unsafe {
            sid_ptr
                .0
                .cast::<SID>()
                .as_ref()
                .ok_or_else(|| Error::NullPointer("SID"))
        }?);

        unsafe {
            LocalFree(HLOCAL(sid_ptr.0));
        }

        Ok(sid)
    }
}

impl From<&Sid> for RawSid {
    fn from(value: &Sid) -> Self {
        let raw_sid_buf_size = mem::size_of::<SID>() // Size of the SID's header
            + (value.sub_authority.len() - 1) * mem::size_of::<u32>(); // Size of the SID's data part, minus the trailing VLA entry in the header
        let mut raw_sid_buf = vec![0u8; raw_sid_buf_size];

        let raw_sid = raw_sid_buf.as_mut_ptr().cast::<SID>();

        unsafe {
            ptr::addr_of_mut!((*raw_sid).IdentifierAuthority).write(value.identifier_identity);
            ptr::addr_of_mut!((*raw_sid).Revision).write(value.revision);
            ptr::addr_of_mut!((*raw_sid).SubAuthorityCount).write(value.sub_authority.len() as _);

            let sub_auth_ptr = ptr::addr_of_mut!((*raw_sid).SubAuthority).cast::<u32>();

            for (i, v) in value.sub_authority.iter().enumerate() {
                sub_auth_ptr.add(i).write(*v);
            }
        }

        Self { buf: raw_sid_buf }
    }
}

impl TryFrom<PSID> for Sid {
    type Error = anyhow::Error;

    fn try_from(value: PSID) -> std::result::Result<Self, Self::Error> {
        let value = value.0.cast::<SID>();

        if value.is_null() {
            bail!(Error::from_hresult(E_POINTER));
        }

        Ok(Self::from(unsafe { &*value }))
    }
}

impl From<&SID> for Sid {
    fn from(sid: &SID) -> Self {
        let mut sub_authority = Vec::new();
        for i in 0..sid.SubAuthorityCount {
            unsafe {
                // Use just in case structure changes in the future
                let ptr = GetSidSubAuthority(PSID(sid as *const _ as _), i as _);

                // Doc says pointer is undefined if range is OOB.
                sub_authority.push(ptr.read());
            }
        }

        Self {
            revision: sid.Revision,
            identifier_identity: sid.IdentifierAuthority,
            sub_authority,
        }
    }
}

pub struct SidAndAttributes {
    pub sid: Sid,
    pub attributes: u32,
}

pub struct RawSidAndAttributes {
    _sid: RawSid,
    raw: SID_AND_ATTRIBUTES,
}

impl RawSidAndAttributes {
    pub fn as_raw(&self) -> &SID_AND_ATTRIBUTES {
        &self.raw
    }
}

impl From<&SidAndAttributes> for RawSidAndAttributes {
    fn from(value: &SidAndAttributes) -> Self {
        let raw_sid = RawSid::from(&value.sid);

        let raw_sid_ptr = raw_sid.as_raw() as *const _;

        Self {
            _sid: raw_sid,
            raw: SID_AND_ATTRIBUTES {
                Sid: PSID(raw_sid_ptr as _),
                Attributes: value.attributes,
            },
        }
    }
}

impl TryFrom<&SID_AND_ATTRIBUTES> for SidAndAttributes {
    type Error = anyhow::Error;

    fn try_from(value: &SID_AND_ATTRIBUTES) -> Result<Self, Self::Error> {
        Ok(Self {
            sid: Sid::try_from(value.Sid)?,
            attributes: value.Attributes,
        })
    }
}
