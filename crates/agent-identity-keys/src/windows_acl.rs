use anyhow::ensure;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::raw::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::{
    self, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
};
use windows::core::BOOL;

pub(crate) struct OwnedDescriptor(pub(crate) PSECURITY_DESCRIPTOR);

impl Drop for OwnedDescriptor {
    fn drop(&mut self) {
        if !self.0.0.is_null() {
            // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
            unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
        }
    }
}

pub(crate) fn require_protected_dacl(descriptor: PSECURITY_DESCRIPTOR, mut expected: Vec<Sid>) -> anyhow::Result<()> {
    ensure!(!descriptor.0.is_null(), "private key has no security descriptor");
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: The descriptor remains live throughout this call.
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }?;
    ensure!(control & SE_DACL_PROTECTED.0 != 0, "private-key DACL is not protected");

    let mut present = BOOL::default();
    let mut defaulted = BOOL::default();
    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: The descriptor remains live and all output pointers are writable.
    unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }?;
    ensure!(present.as_bool() && !acl.is_null(), "private key has no DACL");
    // SAFETY: GetSecurityDescriptorDacl returned a live ACL in the descriptor.
    let count = unsafe { (*acl).AceCount };
    let mut principals = Vec::new();
    for index in 0..u32::from(count) {
        let mut entry = std::ptr::null_mut();
        // SAFETY: The index is within the ACL's ACE count and the output pointer is writable.
        unsafe { GetAce(acl, index, &mut entry) }?;
        ensure!(!entry.is_null(), "private key has an invalid ACE");
        // SAFETY: GetAce returned a live ACE with a valid header.
        let header = unsafe { &*entry.cast::<ACE_HEADER>() };
        ensure!(
            u32::from(header.AceType) == ACCESS_ALLOWED_ACE_TYPE,
            "private key has an unexpected ACE type"
        );
        // SAFETY: An ACCESS_ALLOWED_ACE has a SID beginning at SidStart.
        let sid_start = unsafe { std::ptr::addr_of!((*entry.cast::<ACCESS_ALLOWED_ACE>()).SidStart) };
        // SAFETY: GetAce provided a live access-allowed ACE with a valid SID.
        principals.push(unsafe { Sid::from_psid(Security::PSID(sid_start.cast_mut().cast())) }?);
    }
    principals.sort();
    expected.sort();
    ensure!(
        principals == expected,
        "private-key DACL has extra or missing principals"
    );
    Ok(())
}
