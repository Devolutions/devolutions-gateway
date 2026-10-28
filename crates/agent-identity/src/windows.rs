use anyhow::{Context as _, ensure};
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::token::Token;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security;
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::core::{BOOL, PCWSTR};
use zeroize::{Zeroize as _, Zeroizing};

const ENTROPY: &[u8] = b"Devolutions.Agent.PendingEnrollment.v1";

fn user_sid() -> anyhow::Result<Sid> {
    Ok(Token::current_process_token()
        .sid_and_attributes()
        .context("get current user SID")?
        .sid)
}

fn system_sid() -> anyhow::Result<Sid> {
    Sid::from_well_known(Security::WinLocalSystemSid, None).context("get SYSTEM SID")
}

pub(crate) fn is_system() -> anyhow::Result<bool> {
    Ok(user_sid()? == system_sid()?)
}

pub(crate) fn is_administrator_writer() -> anyhow::Result<bool> {
    Ok(!is_system()? && current_user_is_administrator()?)
}

fn current_user_is_administrator() -> anyhow::Result<bool> {
    let administrators =
        Sid::from_well_known(Security::WinBuiltinAdministratorsSid, None).context("get Administrators SID")?;
    let mut is_member = BOOL::default();
    // SAFETY: A null token selects the effective current token and the output pointer is writable.
    unsafe { Security::CheckTokenMembership(None, administrators.as_psid_const(), &mut is_member) }
        .context("check administrator group membership")?;
    Ok(is_member.as_bool())
}

fn blob(bytes: &[u8]) -> anyhow::Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len())?,
        pbData: bytes.as_ptr().cast_mut(),
    })
}

struct LocalBlob(CRYPT_INTEGER_BLOB);

impl Drop for LocalBlob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // SAFETY: CryptProtectData/CryptUnprotectData allocated this buffer with LocalAlloc.
            unsafe { LocalFree(Some(HLOCAL(self.0.pbData.cast()))) };
        }
    }
}

pub(crate) fn protect(contents: &[u8]) -> anyhow::Result<Vec<u8>> {
    let input = blob(contents)?;
    let entropy = blob(ENTROPY)?;
    let mut output = LocalBlob(CRYPT_INTEGER_BLOB::default());
    // SAFETY: Input and entropy remain valid, and the output buffer is writable for this call.
    unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.0,
        )
    }
    .context("encrypt pending enrollment")?;
    ensure!(
        !output.0.pbData.is_null(),
        "encryption produced an empty pending enrollment"
    );
    // SAFETY: DPAPI returned a live allocation of cbData bytes, retained by output.
    Ok(unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize).to_vec() })
}

pub(crate) fn unprotect(contents: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let input = blob(contents)?;
    let entropy = blob(ENTROPY)?;
    let mut output = LocalBlob(CRYPT_INTEGER_BLOB::default());
    // SAFETY: Input and entropy remain valid, and the output buffer is writable for this call.
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.0,
        )
    }
    .context("decrypt pending enrollment")?;
    ensure!(
        !output.0.pbData.is_null(),
        "decryption produced an empty pending enrollment"
    );
    // SAFETY: DPAPI returned a live allocation of cbData bytes, retained by output.
    let plaintext =
        Zeroizing::new(unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize).to_vec() });
    // SAFETY: The DPAPI allocation remains writable until LocalBlob drops it.
    unsafe { std::slice::from_raw_parts_mut(output.0.pbData, output.0.cbData as usize) }.zeroize();
    Ok(plaintext)
}

/// Builds and reads owners and DACLs directly, so that tests can set up states the agent must refuse and check what it
/// provisions independently of private-fs.
#[cfg(test)]
pub(crate) mod test {
    use std::fs;

    use anyhow::Context as _;
    use camino::Utf8Path;
    use win_api_wrappers::identity::sid::{Sid, StringSid};
    use win_api_wrappers::raw::Win32::Security::Authorization::GRANT_ACCESS;
    use win_api_wrappers::security::acl::{
        Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee, set_named_security_info,
    };
    use win_api_wrappers::security::descriptor::{DaclError, SecurityDescriptor};
    use win_api_wrappers::str::U16CString;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::SE_FILE_OBJECT;
    use windows::Win32::Security::{self, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};
    use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    /// One allow entry of a DACL: its SID, access mask and ACE flags.
    pub(crate) type Ace = (Sid, u32, u32);

    pub(crate) fn user_sid() -> anyhow::Result<Sid> {
        super::user_sid()
    }

    pub(crate) fn system_sid() -> anyhow::Result<Sid> {
        super::system_sid()
    }

    pub(crate) fn owner_rights_sid() -> anyhow::Result<Sid> {
        StringSid::from_str("OW")?.to_sid().context("get OWNER RIGHTS SID")
    }

    pub(crate) fn sorted(entries: &[Ace]) -> Vec<Ace> {
        let mut entries = entries.to_vec();
        entries.sort();
        entries
    }

    /// Gives a test path a protected DACL of `entries`.
    pub(crate) fn set_dacl(path: &Utf8Path, entries: &[Ace]) -> anyhow::Result<()> {
        let entries: Vec<_> = entries
            .iter()
            .map(|(sid, mask, flags)| ExplicitAccess {
                access_permissions: *mask,
                access_mode: GRANT_ACCESS,
                inheritance: Security::ACE_FLAGS(*flags),
                trustee: Trustee::Sid(sid.clone()),
            })
            .collect();
        let dacl = InheritableAcl {
            kind: InheritableAclKind::Protected,
            acl: Acl::new()
                .and_then(|acl| acl.set_entries(&entries))
                .context("build test DACL")?,
        };
        set_named_security_info(&wide_path(path)?, SE_FILE_OBJECT, None, None, Some(&dacl), None)
    }

    /// Makes `owner` the owner of a test path, which takes an elevated token for any owner but the current user.
    pub(crate) fn set_owner(path: &Utf8Path, owner: &Sid) -> anyhow::Result<()> {
        set_named_security_info(&wide_path(path)?, SE_FILE_OBJECT, Some(owner), None, None, None)
    }

    /// Returns the entries of a test path's DACL, sorted, or `None` when the DACL is not protected.
    pub(crate) fn protected_dacl_of(path: &Utf8Path) -> anyhow::Result<Option<Vec<Ace>>> {
        let descriptor = SecurityDescriptor::of_path(&wide_path(path)?, SE_FILE_OBJECT).context("read test DACL")?;
        match descriptor.protected_allow_entries() {
            Ok(entries) => Ok(Some(sorted(
                &entries
                    .into_iter()
                    .map(|entry| (entry.sid, entry.mask, entry.flags))
                    .collect::<Vec<_>>(),
            ))),
            Err(DaclError::NotProtected) => Ok(None),
            Err(error) => Err(anyhow::anyhow!("{error:?}")).context("read test DACL entries"),
        }
    }

    fn full_control(sids: &[Sid], flags: Security::ACE_FLAGS) -> Vec<Ace> {
        sids.iter()
            .map(|sid| (sid.clone(), FILE_ALL_ACCESS.0, flags.0))
            .collect()
    }

    fn inherited() -> Security::ACE_FLAGS {
        Security::CONTAINER_INHERIT_ACE | Security::OBJECT_INHERIT_ACE
    }

    /// Gives a test directory the DACL the agent provisions for its directories, with or without the current user.
    pub(crate) fn set_test_directory_access(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<()> {
        let mut sids = vec![system_sid()?];
        if grant_current_user {
            sids.push(user_sid()?);
        }
        set_dacl(path, &full_control(&sids, inherited()))
    }

    /// Gives `other` inherited full control of a test directory, besides SYSTEM and the current user.
    pub(crate) fn grant_test_directory_access(
        path: &Utf8Path,
        other: Security::WELL_KNOWN_SID_TYPE,
    ) -> anyhow::Result<()> {
        let sids = [system_sid()?, user_sid()?, Sid::from_well_known(other, None)?];
        set_dacl(path, &full_control(&sids, inherited()))
    }

    /// Gives a test file the protected DACL the agent provisions for its state files, plus full control for `others`.
    pub(crate) fn set_test_file_access(
        path: &Utf8Path,
        others: &[Security::WELL_KNOWN_SID_TYPE],
    ) -> anyhow::Result<()> {
        let mut sids = vec![system_sid()?, user_sid()?];
        for other in others {
            sids.push(Sid::from_well_known(*other, None)?);
        }
        set_dacl(path, &full_control(&sids, Security::NO_INHERITANCE))
    }

    /// Gives a test file a protected DACL that grants full control to the current user only.
    pub(crate) fn set_test_file_access_for_current_user_only(path: &Utf8Path) -> anyhow::Result<()> {
        set_dacl(path, &full_control(&[user_sid()?], Security::NO_INHERITANCE))
    }

    /// Makes `owner` the owner of a test path, which takes an elevated token for any owner but the current user.
    pub(crate) fn set_test_owner(path: &Utf8Path, owner: Security::WELL_KNOWN_SID_TYPE) -> anyhow::Result<()> {
        set_owner(path, &Sid::from_well_known(owner, None)?)
    }

    /// Checks that a pending file is owned by the current user and has exactly the DACL the agent provisions.
    pub(crate) fn assert_pending_protection(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<()> {
        let descriptor =
            SecurityDescriptor::of_path(&wide_path(path)?, SE_FILE_OBJECT).context("read pending file owner")?;
        assert_eq!(descriptor.owner()?, Some(user_sid()?), "{path}");
        let mut sids = vec![system_sid()?];
        if grant_current_user {
            sids.push(user_sid()?);
        }
        assert_eq!(
            protected_dacl_of(path)?,
            Some(sorted(&full_control(&sids, Security::NO_INHERITANCE))),
            "{path}"
        );
        Ok(())
    }

    /// Returns the owner and DACL of a test path in SDDL, which shows inherited entries and DACL protection.
    pub(crate) fn test_security(path: &Utf8Path) -> anyhow::Result<String> {
        use windows::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::core::PWSTR;

        let descriptor = SecurityDescriptor::of_path(&wide_path(path)?, SE_FILE_OBJECT).context("read test DACL")?;
        let mut sddl = PWSTR::null();
        // SAFETY: The descriptor stays live through the call and the output pointer is writable.
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.as_raw(),
                SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut sddl,
                None,
            )
        }
        .context("convert test security descriptor")?;
        // SAFETY: The conversion returned a NUL-terminated string.
        let text = unsafe { sddl.to_string() };
        // SAFETY: The conversion allocated the string with LocalAlloc.
        unsafe { LocalFree(Some(HLOCAL(sddl.0.cast()))) };
        Ok(text?)
    }

    fn wide_path(path: &Utf8Path) -> anyhow::Result<U16CString> {
        let parent = path.parent().context("test path has no parent")?;
        let name = path.file_name().context("test path has no name")?;
        let full_path = fs::canonicalize(parent)?.join(name);
        Ok(U16CString::from_os_str(full_path.as_os_str())?)
    }
}
