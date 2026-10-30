//! Reading the owner and DACL of a security descriptor.

use core::marker::PhantomData;
use core::ptr;

use thiserror::Error;
use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, GetSecurityInfo, SE_OBJECT_TYPE};
use windows::Win32::Security::{
    self, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SE_DACL_PROTECTED,
};
use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows::core::BOOL;

use crate::identity::sid::{FromPsidErr, Sid};
use crate::str::{U16CStr, U16CStrExt as _};

/// A security descriptor, either read from an object and freed on drop, or borrowed.
pub struct SecurityDescriptor<'a> {
    // INVARIANT: Points to a valid security descriptor that stays live for 'a.
    // INVARIANT: When `owned` is true, the pointer must be freed using LocalFree.
    ptr: PSECURITY_DESCRIPTOR,
    owned: bool,
    _borrow: PhantomData<&'a ()>,
}

/// An access-allowed entry of a DACL.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllowEntry {
    pub sid: Sid,
    pub mask: u32,
    /// The ACE flags, such as the inheritance flags.
    pub flags: u32,
}

/// Why a DACL is not a protected list of access-allowed entries.
#[derive(Debug, Error)]
pub enum DaclError {
    #[error("DACL is not protected")]
    NotProtected,
    #[error("no DACL")]
    Missing,
    #[error("invalid ACE")]
    InvalidAce,
    #[error("ACE is not access-allowed")]
    UnexpectedAceType,
    #[error(transparent)]
    Sid(#[from] FromPsidErr),
    #[error(transparent)]
    Windows(#[from] windows::core::Error),
}

impl SecurityDescriptor<'static> {
    /// Reads the owner and DACL of the object behind `handle`.
    pub fn of_handle(handle: HANDLE, object_type: SE_OBJECT_TYPE) -> windows::core::Result<Self> {
        let mut ptr = PSECURITY_DESCRIPTOR::default();
        // SAFETY: The descriptor output pointer is writable, and the other outputs are optional.
        unsafe {
            GetSecurityInfo(
                handle,
                object_type,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                Some(&mut ptr),
            )
        }
        .ok()?;
        // SAFETY: On success, GetSecurityInfo returned a descriptor allocated with LocalAlloc.
        Ok(unsafe { Self::from_local_alloc(ptr) })
    }

    /// Reads the owner and DACL of the object named `path`.
    pub fn of_path(path: &U16CStr, object_type: SE_OBJECT_TYPE) -> windows::core::Result<Self> {
        let mut ptr = PSECURITY_DESCRIPTOR::default();
        // SAFETY: The path is NUL-terminated, the descriptor output pointer is writable, and the other outputs are
        // optional.
        unsafe {
            GetNamedSecurityInfoW(
                path.as_pcwstr(),
                object_type,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut ptr,
            )
        }
        .ok()?;
        // SAFETY: On success, GetNamedSecurityInfoW returned a descriptor allocated with LocalAlloc.
        Ok(unsafe { Self::from_local_alloc(ptr) })
    }

    /// # Safety
    ///
    /// `ptr` must point to a valid security descriptor allocated with `LocalAlloc`.
    unsafe fn from_local_alloc(ptr: PSECURITY_DESCRIPTOR) -> Self {
        Self {
            ptr,
            owned: true,
            _borrow: PhantomData,
        }
    }
}

impl SecurityDescriptor<'_> {
    /// Borrows a security descriptor without taking ownership of it.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a valid security descriptor that stays live while the returned value is used.
    pub unsafe fn from_raw(ptr: PSECURITY_DESCRIPTOR) -> Self {
        Self {
            ptr,
            owned: false,
            _borrow: PhantomData,
        }
    }

    pub fn as_raw(&self) -> PSECURITY_DESCRIPTOR {
        self.ptr
    }

    /// Returns the owner, or `None` when the descriptor has no owner.
    pub fn owner(&self) -> anyhow::Result<Option<Sid>> {
        let mut owner = Security::PSID::default();
        let mut defaulted = BOOL::default();
        // SAFETY: Per invariants, the descriptor is live, and both output pointers are writable.
        unsafe { GetSecurityDescriptorOwner(self.ptr, &mut owner, &mut defaulted) }?;
        if owner.0.is_null() {
            return Ok(None);
        }
        // SAFETY: GetSecurityDescriptorOwner returned a valid SID within the live descriptor.
        Ok(Some(unsafe { Sid::from_psid(owner) }?))
    }

    /// Returns the entries of a protected DACL made only of access-allowed entries, in DACL order.
    pub fn protected_allow_entries(&self) -> Result<Vec<AllowEntry>, DaclError> {
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: Per invariants, the descriptor is live, and both output pointers are writable.
        unsafe { GetSecurityDescriptorControl(self.ptr, &mut control, &mut revision) }?;
        if control & SE_DACL_PROTECTED.0 == 0 {
            return Err(DaclError::NotProtected);
        }

        let mut present = BOOL::default();
        let mut defaulted = BOOL::default();
        let mut acl: *mut ACL = ptr::null_mut();
        // SAFETY: Per invariants, the descriptor is live, and all output pointers are writable.
        unsafe { GetSecurityDescriptorDacl(self.ptr, &mut present, &mut acl, &mut defaulted) }?;
        // A present but null DACL grants everyone full access.
        if !present.as_bool() || acl.is_null() {
            return Err(DaclError::Missing);
        }
        // SAFETY: GetSecurityDescriptorDacl returned a live ACL within the descriptor.
        let count = unsafe { (*acl).AceCount };
        let mut entries = Vec::with_capacity(usize::from(count));
        for index in 0..u32::from(count) {
            let mut raw = ptr::null_mut();
            // SAFETY: The index is less than the ACL's ACE count, and the output pointer is writable.
            unsafe { GetAce(acl, index, &mut raw) }?;
            if raw.is_null() {
                return Err(DaclError::InvalidAce);
            }
            // SAFETY: GetAce returned a live entry that starts with an ACE_HEADER.
            let header = unsafe { &*raw.cast::<ACE_HEADER>() };
            if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
                return Err(DaclError::UnexpectedAceType);
            }
            // SAFETY: This is an access-allowed ACE, so Mask and SidStart exist.
            let entry = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
            // SAFETY: An access-allowed ACE holds a valid SID starting at SidStart.
            let sid = unsafe { Sid::from_psid(Security::PSID(ptr::addr_of!(entry.SidStart).cast_mut().cast())) }?;
            entries.push(AllowEntry {
                sid,
                mask: entry.Mask,
                flags: u32::from(header.AceFlags),
            });
        }
        Ok(entries)
    }
}

impl Drop for SecurityDescriptor<'_> {
    fn drop(&mut self) {
        // UNTESTED: an owned descriptor is freed exactly once, and a borrowed one never.
        // A missing free leaks on every check, and freeing a borrowed descriptor corrupts its owner's heap; tests observe neither.
        // When changing ownership, keep `owned` true only for descriptors that GetSecurityInfo or GetNamedSecurityInfoW allocated.
        if self.owned {
            // SAFETY: Per invariants, an owned descriptor is freed using LocalFree.
            unsafe { LocalFree(Some(HLOCAL(self.ptr.0))) };
        }
    }
}

#[cfg(test)]
mod tests {
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::WinLocalSystemSid;
    use windows::core::HSTRING;

    use super::*;

    fn from_sddl(sddl: &str) -> windows::core::Result<SecurityDescriptor<'static>> {
        let mut ptr = PSECURITY_DESCRIPTOR::default();
        // SAFETY: The SDDL string is NUL-terminated, and the descriptor output pointer is writable.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(&HSTRING::from(sddl), SDDL_REVISION_1, &mut ptr, None)
        }?;
        // SAFETY: On success, the conversion returned a descriptor allocated with LocalAlloc.
        Ok(unsafe { SecurityDescriptor::from_local_alloc(ptr) })
    }

    // oracle: spec MS-DTYP §2.5.1
    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_protected_dacl_yields_its_owner_and_allow_entries() -> anyhow::Result<()> {
        let system = Sid::from_well_known(WinLocalSystemSid, None)?;
        let descriptor = from_sddl("O:SYD:P(A;;GA;;;SY)")?;
        assert_eq!(descriptor.owner()?, Some(system.clone()));
        assert_eq!(
            descriptor.protected_allow_entries()?,
            [AllowEntry {
                sid: system,
                mask: 0x1000_0000, // GENERIC_ALL
                flags: 0,
            }]
        );
        Ok(())
    }

    // oracle: spec MS-DTYP §2.5.1
    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    #[cfg_attr(miri, ignore)]
    fn an_unprotected_dacl_is_refused() -> anyhow::Result<()> {
        let descriptor = from_sddl("O:SYD:(A;;GA;;;SY)")?;
        assert!(matches!(
            descriptor.protected_allow_entries(),
            Err(DaclError::NotProtected)
        ));
        Ok(())
    }

    // oracle: spec MS-DTYP §2.5.1
    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_null_dacl_is_refused() -> anyhow::Result<()> {
        let descriptor = from_sddl("O:SYD:PNO_ACCESS_CONTROL")?;
        assert!(matches!(descriptor.protected_allow_entries(), Err(DaclError::Missing)));
        Ok(())
    }

    // oracle: spec MS-DTYP §2.5.1
    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_dacl_with_a_deny_entry_is_refused() -> anyhow::Result<()> {
        let descriptor = from_sddl("O:SYD:P(D;;GA;;;BU)")?;
        assert!(matches!(
            descriptor.protected_allow_entries(),
            Err(DaclError::UnexpectedAceType)
        ));
        Ok(())
    }
}
