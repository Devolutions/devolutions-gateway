use std::alloc::Layout;
use std::mem::{self};
use std::{ptr, slice};

use anyhow::{bail, Result};

use crate::identity::sid::{RawSid, Sid};
use crate::utils::{u32size_of, WideString};
use crate::Error;
use windows::Win32::Foundation::{ERROR_INVALID_DATA, ERROR_INVALID_VARIANT, E_POINTER};
use windows::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_OBJECT_TYPE};
use windows::Win32::Security::{
    AddAce, GetAce, InitializeAcl, ACE_FLAGS, ACE_HEADER, ACE_REVISION, ACL, ACL_REVISION, DACL_SECURITY_INFORMATION,
    GROUP_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PROTECTED_SACL_SECURITY_INFORMATION, PSID, SACL_SECURITY_INFORMATION,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_CONTROL, SE_DACL_AUTO_INHERITED, SE_DACL_DEFAULTED,
    SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_SACL_AUTO_INHERITED, SE_SACL_DEFAULTED, SE_SACL_PRESENT, SE_SACL_PROTECTED,
    SID, UNPROTECTED_DACL_SECURITY_INFORMATION, UNPROTECTED_SACL_SECURITY_INFORMATION,
};
use windows::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, MAXDWORD, SECURITY_DESCRIPTOR_REVISION};

pub enum AceType {
    AccessAllowed(Sid),
}

impl AceType {
    pub fn kind(&self) -> u8 {
        // ACE type is actually encoded on a u8 even though the type in windows crate is u32.
        #[allow(clippy::cast_possible_truncation)]
        match self {
            AceType::AccessAllowed(_) => ACCESS_ALLOWED_ACE_TYPE as u8,
        }
    }

    pub fn to_raw(&self) -> Result<Vec<u8>> {
        Ok(match self {
            AceType::AccessAllowed(sid) => RawSid::try_from(sid)?.buf,
        })
    }

    pub fn from_raw(kind: u8, buf: &[u8]) -> Result<Self> {
        let raw_sid = PSID(buf.as_ptr().cast_mut().cast());

        Ok(match u32::from(kind) {
            ACCESS_ALLOWED_ACE_TYPE => Self::AccessAllowed(Sid::try_from(raw_sid)?),
            _ => bail!(Error::from_win32(ERROR_INVALID_VARIANT)),
        })
    }
}

pub struct Ace {
    pub flags: ACE_FLAGS,
    pub access_mask: u32,
    pub data: AceType,
}

impl Ace {
    pub fn to_raw(&self) -> Result<Vec<u8>> {
        let body = self.data.to_raw()?;

        let size = Layout::new::<ACE_HEADER>()
            .extend(Layout::new::<u32>())?
            .0
            .extend(Layout::array::<u8>(body.len())?)?
            .0
            .pad_to_align()
            .size();

        let header = ACE_HEADER {
            AceType: self.data.kind(),
            AceFlags: self.flags.0.try_into()?,
            AceSize: size.try_into()?,
        };

        let mut buf = vec![0; size];

        let mut ptr = buf.as_mut_ptr();

        #[allow(clippy::cast_ptr_alignment)] // FIXME(DGW-221): Raw* hack is flawed.
        // SAFETY: Buffer is at least `size_of::<ACE_HEADER>` big.
        unsafe {
            ptr.cast::<ACE_HEADER>().write(header)
        };

        // SAFETY: We are adding to the pointer in byte aligned mode to access next field.
        ptr = unsafe { ptr.byte_add(mem::size_of::<ACE_HEADER>()) };

        #[allow(clippy::cast_ptr_alignment)] // FIXME(DGW-221): Raw* hack is flawed.
        // SAFETY: Buffer is at least `size_of::<ACE_HEADER> + size_of::<u32>` big.
        unsafe {
            ptr.cast::<u32>().write(self.access_mask)
        };

        // SAFETY: We are adding to the pointer in byte aligned mode to access next field.
        ptr = unsafe { ptr.byte_add(mem::size_of::<u32>()) };

        // SAFETY: Buffer is at least `size_of::<ACE_HEADER> + size_of::<u32> + body.len()` big.
        unsafe { ptr.copy_from(body.as_ptr(), body.len()) };

        Ok(buf)
    }

    /// Creates an `Ace` from a pointer to an `ACE_HEADER`.
    ///
    /// # Safety
    ///
    /// - if `ptr` is non null, it must point to a valid `ACE` which starts by an `ACE_HEADER`.
    pub unsafe fn from_ptr(mut ptr: *const ACE_HEADER) -> Result<Self> {
        // SAFETY: Assume that the pointer points to a valid ACE_HEADER if not null.
        let header = unsafe { ptr.as_ref() }.ok_or_else(|| Error::NullPointer("ACE header"))?;

        if (header.AceSize as usize) < mem::size_of::<ACE_HEADER>() + mem::size_of::<u32>() {
            bail!(Error::from_win32(ERROR_INVALID_DATA));
        }

        // SAFETY: Assume that the header is followed by a 4 byte access mask.
        ptr = unsafe { ptr.byte_add(mem::size_of::<ACE_HEADER>()) };

        // SAFETY: Assume that the header is followed by a 4 byte access mask.
        #[allow(clippy::cast_ptr_alignment)] // FIXME(DGW-221): Raw* hack is flawed.
        let access_mask = unsafe { ptr.cast::<u32>().read() };

        // SAFETY: Assume buffer is big enough to fit Ace data.
        ptr = unsafe { ptr.byte_add(mem::size_of::<u32>()) };

        let body_size = header.AceSize as usize - mem::size_of::<ACE_HEADER>() - mem::size_of::<u32>();

        // SAFETY: `body_size` must be >= 0 because of previous check. Pointer is valid.
        let body = unsafe { slice::from_raw_parts(ptr.cast::<u8>(), body_size) };

        Ok(Self {
            flags: ACE_FLAGS(u32::from(header.AceFlags)),
            access_mask,
            data: AceType::from_raw(header.AceType, body)?,
        })
    }
}

pub struct Acl {
    pub revision: ACE_REVISION,
    pub aces: Vec<Ace>,
}

impl Acl {
    pub fn new() -> Self {
        Self {
            revision: ACL_REVISION,
            aces: vec![],
        }
    }

    pub fn with_aces(aces: Vec<Ace>) -> Self {
        Self {
            revision: ACL_REVISION,
            aces,
        }
    }

    pub fn to_raw(&self) -> Result<Vec<u8>> {
        let raw_aces = self.aces.iter().map(Ace::to_raw).collect::<Result<Vec<_>>>()?;
        let size = mem::size_of::<ACL>() + raw_aces.iter().map(Vec::len).sum::<usize>();

        // Align on u32 boundary
        let size = (size + mem::size_of::<u32>() - 1) & !3;

        let mut buf = vec![0; size];

        // SAFETY: The buffer must be preallocated and it must be DWORD aligned.
        unsafe { InitializeAcl(buf.as_mut_ptr().cast(), buf.len().try_into()?, self.revision) }?;

        for raw_ace in raw_aces {
            // SAFETY: No preconditions. Buffer is valid and `raw_ace` as well.
            unsafe {
                AddAce(
                    buf.as_mut_ptr().cast(),
                    self.revision,
                    MAXDWORD, // Append to end of list
                    raw_ace.as_ptr().cast(),
                    raw_ace.len().try_into()?,
                )
            }?;
        }

        Ok(buf)
    }
}

impl Default for Acl {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<&ACL> for Acl {
    type Error = anyhow::Error;

    fn try_from(value: &ACL) -> Result<Self, Self::Error> {
        Ok(Self {
            revision: ACE_REVISION(u32::from(value.AclRevision)),
            aces: (0..u32::from(value.AceCount))
                .map(|i| {
                    let mut ace = ptr::null_mut();

                    // SAFETY: We assume `AceCount` is truthful and that `value` is well constructed.
                    unsafe { GetAce(value, i, &mut ace) }?;

                    // SAFETY: We assume the obtained `ACE` is valid and starts with an `ACE_HEADER`.
                    unsafe { Ace::from_ptr(ace.cast_const().cast()) }
                })
                .collect::<Result<_>>()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InheritableAclKind {
    Default,
    Protected,
    Inherit,
}

pub struct InheritableAcl {
    pub kind: InheritableAclKind,
    pub acl: Acl,
}

pub fn set_named_security_info(
    target: &str,
    object_type: SE_OBJECT_TYPE,
    owner: Option<&Sid>,
    group: Option<&Sid>,
    dacl: Option<&InheritableAcl>,
    sacl: Option<&InheritableAcl>,
) -> Result<()> {
    let target = WideString::from(target);

    let mut security_info = OBJECT_SECURITY_INFORMATION(0);
    if owner.is_some() {
        security_info |= OWNER_SECURITY_INFORMATION;
    }

    if group.is_some() {
        security_info |= GROUP_SECURITY_INFORMATION;
    }

    if let Some(dacl) = dacl {
        security_info |= DACL_SECURITY_INFORMATION;
        security_info |= match dacl.kind {
            InheritableAclKind::Protected => PROTECTED_DACL_SECURITY_INFORMATION,
            InheritableAclKind::Inherit | InheritableAclKind::Default => UNPROTECTED_DACL_SECURITY_INFORMATION,
        };
    }

    if let Some(sacl) = sacl {
        security_info |= SACL_SECURITY_INFORMATION;
        security_info |= match sacl.kind {
            InheritableAclKind::Protected => PROTECTED_SACL_SECURITY_INFORMATION,
            InheritableAclKind::Inherit | InheritableAclKind::Default => UNPROTECTED_SACL_SECURITY_INFORMATION,
        };
    }

    let owner = owner.map(RawSid::try_from).transpose()?;
    let group = group.map(RawSid::try_from).transpose()?;
    let dacl = dacl.map(|x| x.acl.to_raw()).transpose()?;
    let sacl = sacl.map(|x| x.acl.to_raw()).transpose()?;

    // SAFETY: No preconditions. `target` is valid and null terminated.
    // We assume `RawSid` builds valid SIDs. We assume the ACL encoding builds valid ACLs.
    unsafe {
        SetNamedSecurityInfoW(
            target.as_pcwstr(),
            object_type,
            security_info,
            owner.as_ref().map(RawSid::as_psid).unwrap_or_default(),
            group.as_ref().map(RawSid::as_psid).unwrap_or_default(),
            dacl.as_ref().map(|x| x.as_ptr().cast()),
            sacl.as_ref().map(|x| x.as_ptr().cast()),
        )
        .ok()?
    };

    Ok(())
}

pub struct SecurityDescriptor {
    pub revision: u8,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub sacl: Option<InheritableAcl>,
    pub dacl: Option<InheritableAcl>,
}

impl Default for SecurityDescriptor {
    fn default() -> Self {
        Self {
            // This is a constant =1.
            #[allow(clippy::cast_possible_truncation)]
            revision: SECURITY_DESCRIPTOR_REVISION as u8,
            owner: None,
            group: None,
            sacl: None,
            dacl: None,
        }
    }
}

pub struct RawSecurityDescriptor {
    _owner: Option<RawSid>,
    _group: Option<RawSid>,
    _sacl: Option<Vec<u8>>,
    _dacl: Option<Vec<u8>>,
    raw: SECURITY_DESCRIPTOR,
}

impl RawSecurityDescriptor {
    pub fn as_raw(&self) -> &SECURITY_DESCRIPTOR {
        &self.raw
    }

    pub fn as_raw_mut(&mut self) -> &mut SECURITY_DESCRIPTOR {
        &mut self.raw
    }
}

impl TryFrom<&SecurityDescriptor> for RawSecurityDescriptor {
    type Error = anyhow::Error;

    fn try_from(value: &SecurityDescriptor) -> std::result::Result<Self, Self::Error> {
        let owner = value.owner.as_ref().map(RawSid::try_from).transpose()?;
        let group = value.group.as_ref().map(RawSid::try_from).transpose()?;
        let sacl = value.sacl.as_ref().map(|x| x.acl.to_raw()).transpose()?;

        let dacl = value.dacl.as_ref().map(|x| x.acl.to_raw()).transpose()?;

        let mut control = SECURITY_DESCRIPTOR_CONTROL(0);
        if let Some(kind) = value.sacl.as_ref().map(|x| x.kind) {
            control |= SE_SACL_PRESENT;

            control |= match kind {
                InheritableAclKind::Protected => SE_SACL_PROTECTED,
                InheritableAclKind::Inherit => SE_SACL_AUTO_INHERITED,
                InheritableAclKind::Default => SE_SACL_DEFAULTED,
            };
        }

        if let Some(kind) = value.dacl.as_ref().map(|x| x.kind) {
            control |= SE_DACL_PRESENT;

            control |= match kind {
                InheritableAclKind::Protected => SE_DACL_PROTECTED,
                InheritableAclKind::Inherit => SE_DACL_AUTO_INHERITED,
                InheritableAclKind::Default => SE_DACL_DEFAULTED,
            };
        }

        // TODO: Per remarks in https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_descriptor, `SECURITY_DESCRIPTOR` must be aligned
        // on `malloc` or `LocalAlloc` boundaries.
        // Per https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/malloc, `malloc` will align to 16 bytes on 64-bit platforms.
        let raw = SECURITY_DESCRIPTOR {
            Revision: value.revision,
            Sbz1: 0,
            Control: control,
            Owner: owner.as_ref().map(RawSid::as_psid).unwrap_or_default(),
            Group: group.as_ref().map(RawSid::as_psid).unwrap_or_default(),
            Sacl: sacl
                .as_ref()
                .map_or_else(ptr::null_mut, |x| x.as_ptr().cast_mut().cast()),
            Dacl: dacl
                .as_ref()
                .map_or_else(ptr::null_mut, |x| x.as_ptr().cast_mut().cast()),
        };

        Ok(Self {
            _owner: owner,
            _group: group,
            _sacl: sacl,
            _dacl: dacl,
            raw,
        })
    }
}

impl TryFrom<&SECURITY_DESCRIPTOR> for SecurityDescriptor {
    type Error = anyhow::Error;

    fn try_from(value: &SECURITY_DESCRIPTOR) -> Result<Self, Self::Error> {
        let acl_conv = |field: *mut ACL, present, prot, inherited| {
            value
                .Control
                .contains(present)
                .then(|| {
                    Ok::<_, anyhow::Error>(InheritableAcl {
                        kind: if value.Control.contains(prot) {
                            InheritableAclKind::Protected
                        } else if value.Control.contains(inherited) {
                            InheritableAclKind::Inherit
                        } else {
                            InheritableAclKind::Default
                        },
                        // SAFETY: We assume `field` actually points to an `ACL`.
                        acl: Acl::try_from(unsafe { field.as_ref() }.ok_or_else(|| Error::from_hresult(E_POINTER))?)?,
                    })
                })
                .transpose()
        };

        let sacl = acl_conv(value.Sacl, SE_SACL_PRESENT, SE_SACL_PROTECTED, SE_SACL_AUTO_INHERITED)?;
        let dacl = acl_conv(value.Dacl, SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_DACL_AUTO_INHERITED)?;

        Ok(Self {
            revision: value.Revision,
            // SAFETY: We assume `Owner` points to a valid `SID`.
            owner: unsafe { value.Owner.0.cast::<SID>().as_ref() }
                .map(Sid::try_from)
                .transpose()?,
            // SAFETY: We assume `Group` points to a valid `SID`.
            group: unsafe { value.Group.0.cast::<SID>().as_ref() }
                .map(Sid::try_from)
                .transpose()?,
            sacl,
            dacl,
        })
    }
}

pub struct SecurityAttributes {
    pub security_descriptor: Option<SecurityDescriptor>,
    pub inherit_handle: bool,
}

pub struct RawSecurityAttributes {
    _security_descriptor: Option<RawSecurityDescriptor>,
    raw: SECURITY_ATTRIBUTES,
}

impl RawSecurityAttributes {
    pub fn as_raw(&self) -> &SECURITY_ATTRIBUTES {
        &self.raw
    }
}

impl TryFrom<&SecurityAttributes> for RawSecurityAttributes {
    type Error = anyhow::Error;

    fn try_from(value: &SecurityAttributes) -> Result<Self, Self::Error> {
        let mut security_descriptor = value
            .security_descriptor
            .as_ref()
            .map(RawSecurityDescriptor::try_from)
            .transpose()?;

        let raw = SECURITY_ATTRIBUTES {
            nLength: u32size_of::<SECURITY_ATTRIBUTES>(),
            lpSecurityDescriptor: security_descriptor
                .as_mut()
                .map_or_else(ptr::null_mut, |x| x.as_raw_mut() as *mut _ as *mut _),
            bInheritHandle: value.inherit_handle.into(),
        };

        Ok(Self {
            _security_descriptor: security_descriptor,
            raw,
        })
    }
}
