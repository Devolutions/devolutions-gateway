use std::collections::HashSet;
use std::ffi::c_void;
use std::io::Write as _;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::FromRawHandle as _;
use std::path::Path;

use anyhow::{Context as _, ensure};
use windows::Win32::Foundation::{GENERIC_WRITE, HLOCAL, LocalFree, NTE_BAD_KEYSET, NTE_NO_MORE_ITEMS, NTE_NOT_FOUND};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::Cryptography::{
    CERT_KEY_SPEC, CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CryptProtectData, CryptUnprotectData,
    MS_KEY_STORAGE_PROVIDER, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE,
    NCRYPT_MACHINE_KEY_FLAG, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NCRYPT_PROV_HANDLE, NCryptDeleteKey, NCryptEnumKeys,
    NCryptExportKey, NCryptFreeBuffer, NCryptFreeObject, NCryptGetProperty, NCryptKeyName, NCryptOpenKey,
    NCryptOpenStorageProvider,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, OBJECT_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE};
use windows::core::{BOOL, PCWSTR, PWSTR};

const ENTROPY: &[u8] = b"Devolutions.Agent.PendingEnrollment.v1";

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn blob(data: &[u8]) -> anyhow::Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len())?,
        pbData: data.as_ptr().cast_mut(),
    })
}

fn protect(contents: &[u8], decrypt: bool, local_machine: bool) -> anyhow::Result<Vec<u8>> {
    let input = blob(contents)?;
    let entropy = blob(ENTROPY)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    if decrypt {
        // SAFETY: The input and entropy buffers remain live until CryptUnprotectData returns.
        unsafe { CryptUnprotectData(&input, None, Some(&entropy), None, None, 0, &mut output)? };
    } else {
        // SAFETY: The input and entropy buffers remain live until CryptProtectData returns.
        unsafe {
            CryptProtectData(
                &input,
                PCWSTR::null(),
                Some(&entropy),
                None,
                None,
                if local_machine { CRYPTPROTECT_LOCAL_MACHINE } else { 0 },
                &mut output,
            )?
        };
    }
    // SAFETY: DPAPI allocated output.pbData for output.cbData bytes; LocalFree releases it.
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    // SAFETY: The buffer is allocated by CryptProtectData or CryptUnprotectData with LocalAlloc.
    unsafe { LocalFree(Some(HLOCAL(output.pbData.cast()))) };
    Ok(bytes)
}

pub(crate) fn unprotect_pending(contents: &[u8]) -> anyhow::Result<Vec<u8>> {
    protect(contents, true, false)
}

pub(crate) fn assert_machine_scope(contents: &[u8]) -> anyhow::Result<()> {
    // DPAPI's current blob header stores its scope flags at byte 40; reject unfamiliar formats.
    const PROVIDER: [u8; 16] = [
        0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb,
    ];
    ensure!(
        contents.len() >= 44 && contents[..4] == 1u32.to_le_bytes() && contents[4..20] == PROVIDER,
        "unsupported DPAPI blob header"
    );
    let flags = u32::from_le_bytes(contents[40..44].try_into()?);
    ensure!(
        flags & CRYPTPROTECT_LOCAL_MACHINE != 0,
        "pending file is not machine-scoped DPAPI"
    );
    Ok(())
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorW allocated the descriptor.
        unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

fn current_user_sid() -> anyhow::Result<String> {
    let output = std::process::Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .context("look up current user SID")?;
    ensure!(output.status.success(), "could not look up current user SID");
    let text = String::from_utf8(output.stdout)?;
    let sid = text
        .trim()
        .rsplit_once(',')
        .context("missing current user SID")?
        .1
        .trim()
        .trim_matches('"');
    ensure!(
        sid.starts_with("S-1-") && sid.chars().all(|c| c.is_ascii_digit() || c == '-' || c == 'S'),
        "invalid SID"
    );
    Ok(sid.to_owned())
}

pub(crate) fn write_pending(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let encrypted = protect(contents, false, true)?;
    let sddl = format!("D:P(A;;FA;;;SY)(A;;FA;;;{})", current_user_sid()?);
    let sddl = wide(std::ffi::OsStr::new(&sddl));
    let mut raw = PSECURITY_DESCRIPTOR::default();
    // SAFETY: sddl is NUL-terminated and raw is an output pointer owned by this function.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut raw,
            None,
        )?
    };
    let descriptor = SecurityDescriptor(raw);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())?,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: BOOL(0),
    };
    let path = wide(path.as_os_str());
    // SAFETY: Both the NUL-terminated path and security descriptor remain live until CreateFileW returns.
    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(path.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            Some(&attributes),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )?
    };
    // SAFETY: CreateFileW returned an owned handle, transferred to File for closing on drop.
    let mut file = unsafe { std::fs::File::from_raw_handle(handle.0) };
    file.write_all(&encrypted)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn pending_acl_is_protected(path: &Path) -> anyhow::Result<()> {
    let path = wide(path.as_os_str());
    let mut raw = PSECURITY_DESCRIPTOR::default();
    // SAFETY: path is NUL-terminated and raw receives an allocated security descriptor.
    let result = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR::from_raw(path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut raw,
        )
    };
    ensure!(result.0 == 0, "could not read pending-file DACL ({})", result.0);
    let descriptor = SecurityDescriptor(raw);
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: The security descriptor remains live until the function returns.
    unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision)? };
    ensure!(control & SE_DACL_PROTECTED.0 != 0, "pending-file DACL is not protected");
    let mut sddl = PWSTR::null();
    // SAFETY: The descriptor is valid and the output string is owned until freed with LocalFree.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut sddl,
            None,
        )?
    };
    // SAFETY: The conversion returned a NUL-terminated string allocated for the caller.
    let acl = unsafe { sddl.to_string() };
    // SAFETY: LocalFree releases the SDDL string allocated by the conversion.
    unsafe { LocalFree(Some(HLOCAL(sddl.0.cast()))) };
    let acl = acl?;
    ensure!(
        has_only_required_aces(&acl, &current_user_sid()?),
        "pending-file DACL grants access beyond SYSTEM and the current user"
    );
    Ok(())
}

fn has_only_required_aces(sddl: &str, user_sid: &str) -> bool {
    if !sddl.starts_with("D:") {
        return false;
    }
    let Some(start) = sddl.find('(') else {
        return false;
    };
    let mut rest = &sddl[start..];
    let mut aces = Vec::new();
    while let Some(after_open) = rest.strip_prefix('(') {
        let Some(close) = after_open.find(')') else {
            return false;
        };
        aces.push(&after_open[..close]);
        rest = &after_open[close + 1..];
    }
    if !rest.is_empty() {
        return false;
    }
    aces.sort_unstable();
    let user_ace = format!("A;;FA;;;{user_sid}");
    let mut expected = ["A;;FA;;;SY", &user_ace];
    expected.sort_unstable();
    aces == expected
}

struct Provider(NCRYPT_PROV_HANDLE);

impl Provider {
    fn open() -> anyhow::Result<Self> {
        let mut handle = NCRYPT_PROV_HANDLE::default();
        // SAFETY: handle is writable and the provider name is a static NUL-terminated string.
        unsafe { NCryptOpenStorageProvider(&mut handle, MS_KEY_STORAGE_PROVIDER, 0)? };
        Ok(Self(handle))
    }

    fn key(&self, name: &str) -> anyhow::Result<Option<Key>> {
        let mut handle = NCRYPT_KEY_HANDLE::default();
        let name = wide(std::ffi::OsStr::new(name));
        // SAFETY: The key name is NUL-terminated and handle is writable.
        let result = unsafe {
            NCryptOpenKey(
                self.0,
                &mut handle,
                PCWSTR::from_raw(name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_MACHINE_KEY_FLAG,
            )
        };
        match result {
            Ok(()) => Ok(Some(Key(handle))),
            Err(error) if matches!(error.code(), NTE_BAD_KEYSET | NTE_NOT_FOUND) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        // SAFETY: The provider handle belongs to this wrapper.
        let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.0.0)) };
    }
}

struct Key(NCRYPT_KEY_HANDLE);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: The opened key handle belongs to this wrapper.
        let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.0.0)) };
    }
}

pub(crate) fn machine_key_exists(name: &str) -> anyhow::Result<bool> {
    let provider = Provider::open()?;
    Ok(provider.key(name)?.is_some())
}

pub(crate) fn snapshot_machine_identity_keys() -> anyhow::Result<HashSet<String>> {
    struct EnumState(*mut c_void);
    impl Drop for EnumState {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: NCryptEnumKeys allocated the enumeration state for this provider.
                let _ = unsafe { NCryptFreeBuffer(self.0) };
            }
        }
    }
    struct KeyName(*mut NCryptKeyName);
    impl Drop for KeyName {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: NCryptEnumKeys allocated the returned key-name buffer.
                let _ = unsafe { NCryptFreeBuffer(self.0.cast()) };
            }
        }
    }

    let provider = Provider::open()?;
    let mut state = EnumState(std::ptr::null_mut());
    let mut names = HashSet::new();
    loop {
        let mut key = KeyName(std::ptr::null_mut());
        // SAFETY: Both output pointers are writable, and NCryptFreeBuffer releases their allocations.
        let result = unsafe {
            NCryptEnumKeys(
                provider.0,
                PCWSTR::null(),
                &mut key.0,
                &mut state.0,
                NCRYPT_MACHINE_KEY_FLAG,
            )
        };
        match result {
            Ok(()) => {
                ensure!(!key.0.is_null(), "NCryptEnumKeys returned no key name");
                // SAFETY: NCryptEnumKeys returned a valid key-name structure.
                let pointer = unsafe { (*key.0).pszName };
                // SAFETY: The key-name pointer is NUL-terminated and lives until the buffer is freed.
                let name = unsafe { pointer.to_string()? };
                if name.starts_with("DevolutionsAgent-Identity-") {
                    names.insert(name);
                }
            }
            Err(error) if error.code() == NTE_NO_MORE_ITEMS => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(names)
}

pub(crate) fn assert_non_exportable(name: &str) -> anyhow::Result<()> {
    let provider = Provider::open()?;
    let key = provider
        .key(name)?
        .context("machine key not found in Microsoft Software KSP")?;
    let mut policy = [0u8; 4];
    let mut used = 0;
    // SAFETY: NCryptGetProperty writes at most four bytes into policy and reports the count in used.
    unsafe {
        NCryptGetProperty(
            NCRYPT_HANDLE(key.0.0),
            NCRYPT_EXPORT_POLICY_PROPERTY,
            Some(&mut policy),
            &mut used,
            OBJECT_SECURITY_INFORMATION(0),
        )?
    };
    ensure!(
        used == 4 && u32::from_le_bytes(policy) == 0,
        "machine key permits export"
    );
    let mut buffer = [0u8; 4096];
    // SAFETY: The buffer is writable and the blob type is a NUL-terminated static string.
    let exported = unsafe {
        NCryptExportKey(
            key.0,
            None,
            NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
            None,
            Some(&mut buffer),
            &mut used,
            NCRYPT_FLAGS(0),
        )
    };
    buffer.fill(0);
    ensure!(exported.is_err(), "NCryptExportKey exported a private key");
    Ok(())
}

pub(crate) fn cleanup_machine_keys(
    dir: &Path,
    known_keys: &[String],
    preexisting: &HashSet<String>,
    known_authorities: &HashSet<uuid::Uuid>,
) {
    if known_authorities.is_empty() {
        match snapshot_machine_identity_keys() {
            Ok(keys) => {
                let mut leftovers = keys.difference(preexisting).cloned().collect::<Vec<_>>();
                leftovers.sort_unstable();
                eprintln!(
                    "skipping machine key cleanup without --authority-id; leftover candidates: {}",
                    if leftovers.is_empty() {
                        "none".to_owned()
                    } else {
                        leftovers.join(", ")
                    }
                );
            }
            Err(error) => eprintln!("skipping machine key cleanup; could not list leftover candidates: {error:#}"),
        }
        return;
    }
    let names = cleanup_candidates(dir, known_keys, preexisting, known_authorities);
    if names.is_empty() {
        return;
    }
    let Ok(provider) = Provider::open() else {
        return;
    };
    for name in names {
        let Ok(Some(key)) = provider.key(&name) else {
            continue;
        };
        // SAFETY: The machine key handle was opened for this provider; on success NCryptDeleteKey frees it.
        if unsafe { NCryptDeleteKey(key.0, 0) }.is_ok() {
            std::mem::forget(key);
        }
    }
}

fn cleanup_candidates(
    dir: &Path,
    known_keys: &[String],
    preexisting: &HashSet<String>,
    known_authorities: &HashSet<uuid::Uuid>,
) -> HashSet<String> {
    let mut names = known_keys.iter().cloned().collect::<HashSet<_>>();
    let authorities_dir = dir.join("identity").join("authorities");
    if let Ok(entries) = std::fs::read_dir(authorities_dir) {
        for entry in entries.flatten() {
            let Ok(contents) = std::fs::read(entry.path().join("identity.json")) else {
                continue;
            };
            let Ok(state) = serde_json::from_slice::<serde_json::Value>(&contents) else {
                continue;
            };
            for slot in ["current", "pending", "previous"] {
                if let Some(name) = state["keys"][slot]["key_name"].as_str() {
                    names.insert(name.to_owned());
                }
            }
        }
    }
    names.retain(|name| {
        !preexisting.contains(name)
            && known_authorities.iter().any(|authority| {
                name.strip_prefix(&format!("DevolutionsAgent-Identity-{authority}-"))
                    .is_some_and(|generation| {
                        !generation.is_empty()
                            && generation.len() <= 64
                            && generation
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                    })
            })
    });
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_file_dpapi_and_protected_acl() -> anyhow::Result<()> {
        let scratch = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("agent-identity-windows-tests");
        std::fs::create_dir_all(&scratch)?;
        let dir = tempfile::Builder::new().prefix("pending-").tempdir_in(scratch)?;
        let path = dir.path().join("pending-enrollment.dat");
        let json = br#"{"version":1,"token":"test-only"}"#;
        write_pending(&path, json)?;
        pending_acl_is_protected(&path)?;
        let encrypted = std::fs::read(&path)?;
        assert_machine_scope(&encrypted)?;
        ensure!(
            unprotect_pending(&encrypted)? == json,
            "DPAPI pending file did not round-trip"
        );
        assert!(assert_machine_scope(&protect(json, false, false)?).is_err());
        Ok(())
    }

    #[test]
    fn pending_acl_rejects_extra_allow_ace() {
        let sid = "S-1-5-21-42";
        assert!(has_only_required_aces("D:P(A;;FA;;;SY)(A;;FA;;;S-1-5-21-42)", sid));
        assert!(!has_only_required_aces(
            "D:P(A;;FA;;;SY)(A;;FA;;;S-1-5-21-42)(A;;FA;;;WD)",
            sid
        ));
    }

    #[test]
    fn machine_key_snapshot_is_available() -> anyhow::Result<()> {
        let _ = snapshot_machine_identity_keys()?;
        Ok(())
    }

    #[test]
    fn cleanup_never_selects_preexisting_or_unrelated_machine_keys() -> anyhow::Result<()> {
        let scratch = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("agent-identity-windows-tests");
        std::fs::create_dir_all(&scratch)?;
        let dir = tempfile::Builder::new().prefix("keys-").tempdir_in(scratch)?;
        let authority = uuid::Uuid::new_v4();
        let current = format!("DevolutionsAgent-Identity-{authority}-current");
        let previous = format!("DevolutionsAgent-Identity-{authority}-previous");
        let unrelated = format!("DevolutionsAgent-Identity-{}-other", uuid::Uuid::new_v4());
        let authorities = dir
            .path()
            .join("identity")
            .join("authorities")
            .join(authority.to_string());
        std::fs::create_dir_all(&authorities)?;
        std::fs::write(
            authorities.join("identity.json"),
            serde_json::to_vec(&serde_json::json!({
                "authority_id": authority,
                "keys": {
                    "current": { "key_name": current },
                    "previous": { "key_name": previous }
                }
            }))?,
        )?;
        let selected = cleanup_candidates(
            dir.path(),
            &[current.clone(), previous.clone(), unrelated.clone()],
            &HashSet::from([previous]),
            &HashSet::from([authority]),
        );
        assert_eq!(selected, HashSet::from([current]));
        assert!(cleanup_candidates(dir.path(), &[unrelated], &HashSet::new(), &HashSet::new()).is_empty());
        Ok(())
    }
}
