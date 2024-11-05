use std::alloc::Layout;
use std::fmt::{self, Debug};
use std::hash::Hash;
use std::ptr;

use anyhow::{bail, Result};

use crate::undoc::{RtlCreateVirtualAccountSid, SECURITY_MAX_SID_SIZE};
use crate::utils::{nul_slice_wide_str, SafeWindowsString, WideString};
use crate::Error;
use windows::core::{PCWSTR, PWSTR};
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
        let mut buf = vec![0; SECURITY_MAX_SID_SIZE as usize];
        let mut out_size = u32::try_from(buf.len())?;

        // SAFETY: `SidLength` must be the size of `buf`, which it is. Name is valid.
        unsafe {
            RtlCreateVirtualAccountSid(
                &name.as_unicode_string()?,
                base_sub_authority,
                PSID(buf.as_mut_ptr().cast()),
                &mut out_size,
            )
        }?;

        buf.truncate(out_size as usize);

        // SAFETY: We can safely dereference since it is our buffer. We assume it is actually a SID that is held.
        Ok(unsafe { &*buf.as_ptr().cast::<SID>() }.into())
    }

    pub fn from_well_known(sid_type: WELL_KNOWN_SID_TYPE, domain_sid: Option<&Self>) -> Result<Self> {
        let mut out_size = 0u32;

        let domain_sid = domain_sid.map(RawSid::try_from).transpose()?;

        let domain_sid_ptr = domain_sid.as_ref().map(RawSid::as_psid).unwrap_or_default();

        // SAFETY: No preconditions. We assume `RawSid`'s `as_psid()` works correctly.
        let _ = unsafe { CreateWellKnownSid(sid_type, domain_sid_ptr, PSID(ptr::null_mut()), &mut out_size) };

        let mut buf: Vec<u8> = vec![0; out_size as usize];

        // SAFETY: No preconditions. We assume `RawSid`'s `as_psid()` works correctly.
        // `buf`'s size matches the previously returned `out_size` for the same arguments.
        unsafe { CreateWellKnownSid(sid_type, domain_sid_ptr, PSID(buf.as_mut_ptr().cast()), &mut out_size) }?;

        buf.truncate(out_size as usize);

        #[allow(clippy::cast_ptr_alignment)] // FIXME(DGW-221): Raw* hack is flawed.
        // SAFETY: We can safely dereference since this is our buffer. We assume the data in the buffer is a SID.
        Ok(Self::from(unsafe { &*buf.as_ptr().cast::<SID>() }))
    }

    pub fn is_valid(&self) -> Result<bool> {
        Ok(RawSid::try_from(self)?.is_valid())
    }

    pub fn account(&self, system_name: Option<&str>) -> Result<Account> {
        let raw_sid = RawSid::try_from(self)?;
        let mut name_size = 0u32;
        let mut domain_size = 0u32;
        let mut sid_name_use = SID_NAME_USE::default();

        let mut account = Account::default();

        let system_name = system_name.map(WideString::from);

        // SAFETY: `system_name` is borrowed so the original buffer is not dropped. No preconditions.
        let _ = unsafe {
            LookupAccountSidW(
                system_name.as_ref().map_or_else(PCWSTR::null, WideString::as_pcwstr),
                raw_sid.as_psid(),
                PWSTR::null(),
                &mut name_size,
                PWSTR::null(),
                &mut domain_size,
                &mut sid_name_use,
            )
        };

        let mut name_buf = vec![0u16; name_size as usize];
        let mut domain_buf = vec![0u16; domain_size as usize];

        // SAFETY: `system_name` is borrowed so the original buffer is not dropped. No preconditions.
        // `name_buf` and `domain_buf` match the sizes announced.
        unsafe {
            LookupAccountSidW(
                system_name.as_ref().map_or_else(PCWSTR::null, WideString::as_pcwstr),
                raw_sid.as_psid(),
                PWSTR::from_raw(name_buf.as_mut_ptr()),
                &mut name_size,
                PWSTR::from_raw(domain_buf.as_mut_ptr()),
                &mut domain_size,
                &mut sid_name_use,
            )
        }?;

        account.account_name = String::from_utf16(nul_slice_wide_str(&name_buf))?;
        account.domain_name = String::from_utf16(nul_slice_wide_str(&domain_buf))?;

        account.account_sid = self.clone();
        account.domain_sid = self.clone();
        account.domain_sid.sub_authority.shrink_to(1);

        Ok(account)
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        RawSid::try_from(self).map_err(|_| fmt::Error)?.fmt(f)
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
        // SAFETY: The underlying SID must be valid or an undefined value is returned.
        // We assume our buffer is well constructed and valid.
        unsafe { GetLengthSid(self.as_psid()) as usize }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_raw(&self) -> &SID {
        #[allow(clippy::cast_ptr_alignment)] // FIXME(DGW-221): Raw* hack is flawed.
        // SAFETY: Dereferencing is possible since it is our buffer.
        // We assume our buffer is well constructed and valid.
        unsafe {
            &*self.buf.as_ptr().cast::<SID>()
        }
    }

    pub fn as_psid(&self) -> PSID {
        PSID(self.as_raw() as *const _ as *mut _)
    }

    pub fn is_valid(&self) -> bool {
        // SAFETY: The pointer must not be null, which cannot be since it is our buffer.
        unsafe { IsValidSid(self.as_psid()) }.as_bool()
    }
}

impl fmt::Display for RawSid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut raw_string_sid = PWSTR::null();

        // SAFETY: We assume that our SID is well constructed. It must be valid since it is our buffer.
        // We must free the returned buffer with `LocalFree`.
        unsafe { ConvertSidToStringSidW(self.as_psid(), &mut raw_string_sid) }.map_err(|_| fmt::Error)?;

        // To avoid skipping the free, we wrap in a lambda.
        let res = (|| {
            f.write_str(&raw_string_sid.to_string_safe().map_err(|_| fmt::Error)?)?;
            Ok(())
        })();

        // SAFETY: No preconditions. Buffer can be null.
        unsafe { LocalFree(HLOCAL(raw_string_sid.0.cast())) };

        res
    }
}

impl TryFrom<&str> for Sid {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = WideString::from(value);
        let mut sid_ptr = PSID::default();

        // SAFETY: `value` is valid and null terminated. `sid_ptr` must be freed by `LocalFree`.
        unsafe { ConvertStringSidToSidW(value.as_pcwstr(), &mut sid_ptr) }?;

        // SAFETY: We assume the returned pointer points to a valid SID. If it is null, no need to free,
        // so we can early exit.
        let sid = Self::from(unsafe {
            sid_ptr
                .0
                .cast::<SID>()
                .as_ref()
                .ok_or_else(|| Error::NullPointer("SID"))
        }?);

        // SAFETY: `sid_ptr` is a valid pointer at this point.
        unsafe { LocalFree(HLOCAL(sid_ptr.0)) };

        Ok(sid)
    }
}

impl TryFrom<&Sid> for RawSid {
    type Error = anyhow::Error;

    fn try_from(value: &Sid) -> Result<Self> {
        let mut buf = vec![
            0u8;
            Layout::new::<SID>()
                .extend(Layout::array::<u32>(value.sub_authority.len().saturating_sub(1))?)?
                .0
                .pad_to_align()
                .size()
        ];

        let sid = buf.as_mut_ptr().cast::<SID>();

        // SAFETY: Aligment is valid for these `write`s.
        unsafe {
            ptr::addr_of_mut!((*sid).IdentifierAuthority).write(value.identifier_identity);
            ptr::addr_of_mut!((*sid).Revision).write(value.revision);
            ptr::addr_of_mut!((*sid).SubAuthorityCount).write(value.sub_authority.len().try_into()?);
        }

        for (i, v) in value.sub_authority.iter().enumerate() {
            // SAFETY: `SubAuthority` is a VLA and we have previously correctly sized it.
            //   We need to use `write_unaligned`, because we are effectively writing into a [u8] buffer
            //   using a pointer with alignment 1, while aligment 4 is required when writing u32 values.
            unsafe {
                (ptr::addr_of_mut!((*sid).SubAuthority) as *mut u32)
                    .offset(i as isize)
                    .write_unaligned(*v)
            };
        }

        Ok(Self { buf })
    }
}

impl TryFrom<PSID> for Sid {
    type Error = anyhow::Error;

    fn try_from(value: PSID) -> std::result::Result<Self, Self::Error> {
        let value = value.0.cast::<SID>();

        // SAFETY: We assume the pointer actually points to a valid SID.
        match unsafe { value.as_ref() } {
            Some(x) => Ok(Self::from(x)),
            None => bail!(Error::from_hresult(E_POINTER)),
        }
    }
}

impl From<&SID> for Sid {
    fn from(sid: &SID) -> Self {
        let mut sub_authority = Vec::new();
        for i in 0..u32::from(sid.SubAuthorityCount) {
            // SAFETY: We assume `SubAuthorityCount` matches with the actual amount of sub authorities of the SID.
            // *mut cast is safe since `GetSidSubAuthority` does not mutate `SID`.
            let ptr = unsafe { GetSidSubAuthority(PSID(sid as *const _ as *mut _), i) };

            // SAFETY: We assume the returned pointer is valid.
            // Pointer is undefined if index is OOB. We assume it is in range.
            unsafe { sub_authority.push(ptr.read()) };
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

impl TryFrom<&SidAndAttributes> for RawSidAndAttributes {
    type Error = anyhow::Error;

    fn try_from(value: &SidAndAttributes) -> Result<Self> {
        let raw_sid = RawSid::try_from(&value.sid)?;

        let raw_sid_ptr = raw_sid.as_psid();

        Ok(Self {
            _sid: raw_sid,
            raw: SID_AND_ATTRIBUTES {
                Sid: raw_sid_ptr,
                Attributes: value.attributes,
            },
        })
    }
}

impl TryFrom<&SID_AND_ATTRIBUTES> for SidAndAttributes {
    type Error = anyhow::Error;

    fn try_from(value: &SID_AND_ATTRIBUTES) -> Result<Self> {
        Ok(Self {
            sid: Sid::try_from(value.Sid)?,
            attributes: value.Attributes,
        })
    }
}
