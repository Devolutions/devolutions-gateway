use anyhow::{Context as _, anyhow, ensure};
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::security::descriptor::{DaclError, SecurityDescriptor};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;

pub(crate) fn owner_sid(descriptor: PSECURITY_DESCRIPTOR) -> anyhow::Result<Sid> {
    // SAFETY: Callers pass a descriptor that stays live through this call.
    let descriptor = unsafe { SecurityDescriptor::from_raw(descriptor) };
    descriptor.owner()?.context("private key has no owner")
}

pub(crate) fn require_protected_dacl(descriptor: PSECURITY_DESCRIPTOR, mut expected: Vec<Sid>) -> anyhow::Result<()> {
    ensure!(!descriptor.0.is_null(), "private key has no security descriptor");
    // SAFETY: Callers pass a descriptor that stays live through this call.
    let descriptor = unsafe { SecurityDescriptor::from_raw(descriptor) };
    let entries = descriptor.protected_allow_entries().map_err(|error| match error {
        DaclError::NotProtected => anyhow!("private-key DACL is not protected"),
        DaclError::Missing => anyhow!("private key has no DACL"),
        DaclError::InvalidAce => anyhow!("private key has an invalid ACE"),
        DaclError::UnexpectedAceType => anyhow!("private key has an unexpected ACE type"),
        DaclError::Sid(error) => error.into(),
        DaclError::Windows(error) => error.into(),
    })?;
    let mut principals: Vec<_> = entries.into_iter().map(|entry| entry.sid).collect();
    principals.sort();
    expected.sort();
    ensure!(
        principals == expected,
        "private-key DACL has extra or missing principals"
    );
    Ok(())
}
