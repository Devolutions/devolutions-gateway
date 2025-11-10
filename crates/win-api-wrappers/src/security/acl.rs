//! Helpers to work with ACL structures.
//!
//! # Implementation
//!
//! Relevant links:
//! - <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl>
//! - <https://learn.microsoft.com/en-us/windows/win32/secauthz/creating-or-modifying-an-acl>
//! - <https://learn.microsoft.com/en-us/windows/win32/secauthz/modifying-the-acls-of-an-object-in-c-->
//! - <https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-initializeacl>

use core::ptr;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security;
use windows::Win32::System::Memory;

use crate::identity::sid::Sid;
use crate::str::{U16CStr, U16CStrExt as _};
use crate::utils::u32size_of;

/// Owned ACL freed by LocalFree on drop.
pub struct Acl {
    // INVARIANT: Valid pointer to a an initialized ACL structure.
    // INVARIANT: The pointer must be freed using LocalFree.
    ptr: HLOCAL,
}

impl Acl {
    pub fn new() -> windows::core::Result<Self> {
        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-initializeacl
        // > To calculate the initial size of an ACL, add the following together, and then align the result to the nearest DWORD:
        // >     Size of the ACL structure.
        // >     Size of each ACE structure that the ACL is to contain minus the SidStart member (DWORD) of the ACE.
        // >     Length of the SID that each ACE is to contain.
        //
        // The pointer must be aligned with a DWORD = u32.
        //
        // The Windows heap managers have always performed heap allocations with a start address that is 8-byte aligned.
        // (On 64-bit platforms the alignment is 16-bytes).
        // Microsoft never documented it as a formal guarantee, but given its multi-decade consistency in practice,
        // it’s essentially become a stable implementation detail.

        // SAFETY: FFI call with no outstanding precondition.
        let ptr = unsafe { Memory::LocalAlloc(Memory::LMEM_ZEROINIT, size_of::<Security::ACL>())? };

        // SAFETY: The buffer is u32-aligned (= DWORD-aligned), since both 8-byte and 16-byte alignments are stricter.
        unsafe { Security::InitializeAcl(ptr.0.cast(), u32size_of::<Security::ACL>(), Security::ACL_REVISION)? };

        Ok(Self {
            // ACL structure is properly initialized using InitializeAcl.
            ptr,
        })
    }

    /// Wraps a ACL pointer
    ///
    /// # Safety
    ///
    /// - `ptr` must point to a valid, initialized ACL
    /// - `ptr` must be freed by `LocalFree`
    pub unsafe fn from_raw(ptr: *mut Security::ACL) -> Self {
        Self {
            ptr: HLOCAL(ptr.cast()),
        }
    }

    pub fn as_ptr(&self) -> *const Security::ACL {
        self.ptr.0.cast_const().cast()
    }

    pub fn as_mut_ptr(&mut self) -> *mut Security::ACL {
        self.ptr.0.cast()
    }
}

impl std::ops::Deref for Acl {
    type Target = AclRef;

    fn deref(&self) -> &Self::Target {
        // SAFETY:
        // - BorrowedAcl representation is transparent over the ACL structure.
        // - ptr is pointing to a valid ACL structure, per OwnedAcl invariants.
        unsafe { self.as_ptr().cast::<AclRef>().as_ref().expect("non-null value") }
    }
}

impl std::borrow::Borrow<AclRef> for Acl {
    fn borrow(&self) -> &AclRef {
        std::ops::Deref::deref(self)
    }
}

impl Clone for Acl {
    fn clone(&self) -> Self {
        self.set_entries(&[]).expect("oom")
    }
}

impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: Per invariants: the pointer can be freed using LocalFree.
        unsafe {
            LocalFree(Some(self.ptr));
        }
    }
}

#[repr(transparent)]
pub struct AclRef {
    inner: Security::ACL,
}

impl AclRef {
    /// Creates a new access control list (ACL) by merging new access control or
    /// audit control information into an existing ACL structure.
    ///
    /// Calling this function with no entry is effectively as creating an owned copy of the ACL object.
    pub fn set_entries(&self, explicit_entries: &[ExplicitAccess]) -> windows::core::Result<Acl> {
        let mut new_acl: *mut Security::ACL = ptr::null_mut();

        let explicit_entries: Option<Vec<Security::Authorization::EXPLICIT_ACCESS_W>> =
            (!explicit_entries.is_empty()).then(|| explicit_entries.iter().map(|x| x.as_raw()).collect());

        // SAFETY: FFI call with no outstanding precondition.
        let ret = unsafe {
            Security::Authorization::SetEntriesInAclW(explicit_entries.as_deref(), Some(self.as_ref()), &mut new_acl)
        };

        if ret.is_err() {
            return Err(windows::core::Error::from(ret));
        }

        // SAFETY:
        // - SetEntriesInAclW will return a valid pointer to an initialized ACL structure.
        // - The pointer must be free-able with LocalFree.
        unsafe { Ok(Acl::from_raw(new_acl)) }
    }
}

impl AsRef<Security::ACL> for AclRef {
    fn as_ref(&self) -> &Security::ACL {
        &self.inner
    }
}

impl ToOwned for AclRef {
    type Owned = Acl;

    fn to_owned(&self) -> Self::Owned {
        self.set_entries(&[]).expect("oom")
    }
}

#[derive(Debug, Clone)]
pub enum Trustee {
    Sid(Sid),
}

#[derive(Debug, Clone)]
pub struct ExplicitAccess {
    pub access_permissions: u32,
    pub access_mode: Security::Authorization::ACCESS_MODE,
    pub inheritance: Security::ACE_FLAGS,
    pub trustee: Trustee,
}

impl ExplicitAccess {
    /// Returns a EXPLICIT_ACCESS_W structure that must not be mutated.
    fn as_raw(&self) -> Security::Authorization::EXPLICIT_ACCESS_W {
        let mut raw_trustee = Security::Authorization::TRUSTEE_W::default();

        match &self.trustee {
            Trustee::Sid(sid) => {
                // Configure the trustee to use a SID
                raw_trustee.TrusteeForm = Security::Authorization::TRUSTEE_IS_SID;
                raw_trustee.TrusteeType = Security::Authorization::TRUSTEE_IS_UNKNOWN;
                raw_trustee.ptstrName = windows::core::PWSTR(sid.as_raw().as_ptr().cast_mut().cast());
            }
        }

        Security::Authorization::EXPLICIT_ACCESS_W {
            grfAccessPermissions: self.access_permissions,
            grfAccessMode: self.access_mode,
            grfInheritance: self.inheritance,
            Trustee: raw_trustee,
        }
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
    object_name: &U16CStr,
    object_type: Security::Authorization::SE_OBJECT_TYPE,
    owner: Option<&Sid>,
    group: Option<&Sid>,
    dacl: Option<&InheritableAcl>,
    sacl: Option<&InheritableAcl>,
) -> anyhow::Result<()> {
    let mut security_info = Security::OBJECT_SECURITY_INFORMATION(0);

    if owner.is_some() {
        security_info |= Security::OWNER_SECURITY_INFORMATION;
    }

    if group.is_some() {
        security_info |= Security::GROUP_SECURITY_INFORMATION;
    }

    if let Some(dacl) = dacl {
        security_info |= Security::DACL_SECURITY_INFORMATION;

        match dacl.kind {
            InheritableAclKind::Protected => security_info |= Security::PROTECTED_DACL_SECURITY_INFORMATION,
            InheritableAclKind::Inherit | InheritableAclKind::Default => {
                security_info |= Security::UNPROTECTED_DACL_SECURITY_INFORMATION
            }
        };
    }

    if let Some(sacl) = sacl {
        security_info |= Security::SACL_SECURITY_INFORMATION;

        match sacl.kind {
            InheritableAclKind::Protected => security_info |= Security::PROTECTED_SACL_SECURITY_INFORMATION,
            InheritableAclKind::Inherit | InheritableAclKind::Default => {
                security_info |= Security::UNPROTECTED_SACL_SECURITY_INFORMATION
            }
        };
    }

    // SAFETY:
    // - When owner is Some, the SecurityInfo parameter includes the OWNER_SECURITY_INFORMATION flag.
    // - When group is Some, the SecurityInfo parameter includes the GROUP_SECURITY_INFORMATION flag.
    // - When dacl is Some, the SecurityInfo parameter includes the DACL_SECURITY_INFORMATION flag.
    // - When sacl is Some, the SecurityInfo parameter includes the SACL_SECURITY_INFORMATION flag.
    unsafe {
        Security::Authorization::SetNamedSecurityInfoW(
            object_name.as_pcwstr(),
            object_type,
            security_info,
            owner.map(|x| x.as_psid_const()),
            group.map(|x| x.as_psid_const()),
            dacl.as_ref().map(|x| x.acl.as_ptr().cast()),
            sacl.as_ref().map(|x| x.acl.as_ptr().cast()),
        )
        .ok()?
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    use crate::token::Token;

    use windows::Win32::Foundation::{GENERIC_ALL, GENERIC_READ, GENERIC_WRITE};
    use windows::Win32::Security::Authorization::GRANT_ACCESS;
    use windows::Win32::Security::NO_INHERITANCE;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn create_acl() {
        Acl::new()
            .unwrap()
            .set_entries(&[
                ExplicitAccess {
                    access_permissions: GENERIC_READ.0 | GENERIC_WRITE.0,
                    access_mode: GRANT_ACCESS,
                    inheritance: NO_INHERITANCE,
                    trustee: Trustee::Sid(Sid::from_well_known(Security::WinBuiltinUsersSid, None).unwrap()),
                },
                ExplicitAccess {
                    access_permissions: GENERIC_ALL.0,
                    access_mode: GRANT_ACCESS,
                    inheritance: NO_INHERITANCE,
                    trustee: Trustee::Sid(Token::current_process_token().sid_and_attributes().unwrap().sid),
                },
            ])
            .unwrap();
    }
}
