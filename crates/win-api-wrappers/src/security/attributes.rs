use core::ptr;
use std::ffi::c_void;

use windows::Win32::Security;
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

use crate::identity::sid::Sid;
use crate::security::acl::{InheritableAcl, InheritableAclKind};
use crate::utils::u32size_of;

#[derive(Default)]
pub struct SecurityAttributesInit {
    pub inherit_handle: bool,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub sacl: Option<InheritableAcl>,
    pub dacl: Option<InheritableAcl>,
}

impl SecurityAttributesInit {
    pub fn init(mut self) -> SecurityAttributes {
        let mut control = Security::SECURITY_DESCRIPTOR_CONTROL(0);

        if let Some(kind) = self.sacl.as_ref().map(|x| x.kind) {
            control |= Security::SE_SACL_PRESENT;

            control |= match kind {
                InheritableAclKind::Protected => Security::SE_SACL_PROTECTED,
                InheritableAclKind::Inherit => Security::SE_SACL_AUTO_INHERITED,
                InheritableAclKind::Default => Security::SE_SACL_DEFAULTED,
            };
        }

        if let Some(kind) = self.dacl.as_ref().map(|x| x.kind) {
            control |= Security::SE_DACL_PRESENT;

            control |= match kind {
                InheritableAclKind::Protected => Security::SE_DACL_PROTECTED,
                InheritableAclKind::Inherit => Security::SE_DACL_AUTO_INHERITED,
                InheritableAclKind::Default => Security::SE_DACL_DEFAULTED,
            };
        }

        let descriptor = Security::SECURITY_DESCRIPTOR {
            // This is a constant =1.
            #[expect(clippy::cast_possible_truncation)]
            Revision: SECURITY_DESCRIPTOR_REVISION as u8,
            Sbz1: 0,
            Control: control,
            Owner: self.owner.as_mut().map(|x| x.as_psid()).unwrap_or_default(),
            Group: self.group.as_mut().map(|x| x.as_psid()).unwrap_or_default(),
            Sacl: self.sacl.as_mut().map_or_else(ptr::null_mut, |x| x.acl.as_mut_ptr()),
            Dacl: self.dacl.as_mut().map_or_else(ptr::null_mut, |x| x.acl.as_mut_ptr()),
        };

        let ptr = Box::into_raw(Box::new(Security::SECURITY_ATTRIBUTES {
            nLength: u32size_of::<Security::SECURITY_ATTRIBUTES>(),
            lpSecurityDescriptor: Box::into_raw(Box::new(descriptor)) as *mut c_void,
            bInheritHandle: self.inherit_handle.into(),
        }));

        SecurityAttributes {
            ptr,
            _owner: self.owner,
            _group: self.group,
            _sacl: self.sacl,
            _dacl: self.dacl,
        }
    }
}

pub struct SecurityAttributes {
    // INVARIANT: A pointer allocated using Box::new.
    // INVARIANT: ptr->lpSecurityDescriptor is also a pointer allocated using Box::new.
    ptr: *mut Security::SECURITY_ATTRIBUTES,

    // Just keeping the data alive.
    _owner: Option<Sid>,
    _group: Option<Sid>,
    _sacl: Option<InheritableAcl>,
    _dacl: Option<InheritableAcl>,
}

impl SecurityAttributes {
    pub fn as_ptr(&self) -> *const Security::SECURITY_ATTRIBUTES {
        self.ptr.cast_const()
    }

    pub fn as_mut_ptr(&self) -> *mut Security::SECURITY_ATTRIBUTES {
        self.ptr
    }
}

impl Drop for SecurityAttributes {
    fn drop(&mut self) {
        // SAFETY: Per invariants, ptr is a ptr allocated using Box::new, and the Rust global allocator.
        let attributes = unsafe { Box::from_raw(self.ptr) };

        // SAFETY: Per invariants, attributes.lpSecurityDescriptor is a ptr allocated using Box::new, and the Rust global allocator.
        let _ = unsafe { Box::from_raw(attributes.lpSecurityDescriptor as *mut Security::SECURITY_DESCRIPTOR) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_attributes_with_inherit_handle() {
        SecurityAttributesInit {
            inherit_handle: true,
            ..Default::default()
        }
        .init();
    }

    #[test]
    fn security_attributes_with_security_descriptor() {
        SecurityAttributesInit {
            group: Some(Sid::new((1, Security::SECURITY_AUTHENTICATION_AUTHORITY), 5)),
            ..Default::default()
        }
        .init();
    }
}
