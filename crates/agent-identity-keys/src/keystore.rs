use std::ffi::c_void;
use std::sync::Mutex;

use anyhow::{Context as _, ensure};
use p256::ecdsa::{DerSignature, Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};
use signature::Signer;
use win_api_wrappers::token::Token;
use windows::Win32::Foundation::{HLOCAL, LocalFree, NTE_BAD_KEYSET, NTE_NO_MORE_ITEMS, NTE_NOT_FOUND};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, CERT_KEY_SPEC,
    MS_KEY_STORAGE_PROVIDER, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE,
    NCRYPT_MACHINE_KEY_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SECURITY_DESCR_PROPERTY, NCryptCreatePersistedKey,
    NCryptDeleteKey, NCryptEnumKeys, NCryptExportKey, NCryptFinalizeKey, NCryptFreeBuffer, NCryptFreeObject,
    NCryptGetProperty, NCryptKeyName, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
use windows::core::PCWSTR;

use crate::{IdentityKey, KeyOptions, validate_name};

struct Provider(NCRYPT_PROV_HANDLE);

impl Provider {
    fn open() -> anyhow::Result<Self> {
        let mut handle = NCRYPT_PROV_HANDLE::default();
        // SAFETY: The output pointer is writable and the provider name is a static wide string.
        unsafe { NCryptOpenStorageProvider(&mut handle, MS_KEY_STORAGE_PROVIDER, 0) }
            .context("open Microsoft Software Key Storage Provider")?;
        Ok(Self(handle))
    }

    fn create(&self, name: &str) -> anyhow::Result<Key> {
        let wide_name = wide(name);
        let mut handle = NCRYPT_KEY_HANDLE::default();
        // SAFETY: The output pointer is writable and both algorithm and name are NUL-terminated.
        unsafe {
            NCryptCreatePersistedKey(
                self.0,
                &mut handle,
                BCRYPT_ECDSA_P256_ALGORITHM,
                PCWSTR::from_raw(wide_name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_MACHINE_KEY_FLAG,
            )
        }
        .with_context(|| format!("create machine key {name}"))?;
        Ok(Key(handle))
    }

    fn key(&self, name: &str) -> anyhow::Result<Option<Key>> {
        let wide_name = wide(name);
        let mut handle = NCRYPT_KEY_HANDLE::default();
        // SAFETY: The output pointer is writable and the key name is NUL-terminated.
        match unsafe {
            NCryptOpenKey(
                self.0,
                &mut handle,
                PCWSTR::from_raw(wide_name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_MACHINE_KEY_FLAG,
            )
        } {
            Ok(()) => Ok(Some(Key(handle))),
            Err(error) if matches!(error.code(), NTE_BAD_KEYSET | NTE_NOT_FOUND) => Ok(None),
            Err(error) => Err(error).with_context(|| format!("open machine key {name}")),
        }
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns the provider handle.
        let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.0.0)) };
    }
}

struct Key(NCRYPT_KEY_HANDLE);

impl Key {
    fn delete(self) -> windows::core::Result<()> {
        // SAFETY: NCryptDeleteKey releases this valid key handle on success.
        unsafe { NCryptDeleteKey(self.0, 0) }?;
        std::mem::forget(self);
        Ok(())
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns the key handle unless delete succeeded.
        let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.0.0)) };
    }
}

struct StoreHandle {
    key: Key,
    _provider: Provider,
}

// SAFETY: NCrypt handles may be moved between threads; the Mutex serializes all use of the key.
unsafe impl Send for StoreHandle {}

struct StoreKey {
    name: String,
    public_key: VerifyingKey,
    handle: Mutex<StoreHandle>,
}

impl IdentityKey for StoreKey {
    fn name(&self) -> &str {
        &self.name
    }

    fn public_key(&self) -> VerifyingKey {
        self.public_key
    }
}

impl Signer<Signature> for StoreKey {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        let digest = Sha256::digest(message);
        let handle = self
            .handle
            .lock()
            .map_err(|_| signature::Error::from_source(std::io::Error::other("device key handle lock poisoned")))?;
        let mut bytes = [0u8; 64];
        let mut used = 0;
        // SAFETY: The digest and signature buffers remain live and writable for the call.
        unsafe {
            NCryptSignHash(
                handle.key.0,
                None,
                &digest,
                Some(&mut bytes),
                &mut used,
                NCRYPT_FLAGS(0),
            )
        }
        .map_err(signature::Error::from_source)?;
        if used != 64 {
            return Err(signature::Error::new());
        }
        Signature::from_slice(&bytes)
    }
}

impl Signer<DerSignature> for StoreKey {
    fn try_sign(&self, message: &[u8]) -> signature::Result<DerSignature> {
        Signer::<Signature>::try_sign(self, message).map(|signature| signature.to_der())
    }
}

pub(super) fn generate(name: &str, options: &KeyOptions) -> anyhow::Result<Box<dyn IdentityKey>> {
    let provider = Provider::open()?;
    let key = provider.create(name)?;
    let user = Token::current_process_token()
        .sid_and_attributes()
        .context("get process user SID")?
        .sid
        .to_string();
    configure_and_finalize(&key, &user, options.acl_grant_current_user)?;
    let public_key = export_public_key(&key)?;
    Ok(Box::new(StoreKey {
        name: name.to_owned(),
        public_key,
        handle: Mutex::new(StoreHandle {
            key,
            _provider: provider,
        }),
    }))
}

pub(super) fn open(name: &str) -> anyhow::Result<Option<Box<dyn IdentityKey>>> {
    let provider = Provider::open()?;
    let Some(key) = provider.key(name)? else {
        return Ok(None);
    };
    ensure_non_exportable(&key)?;
    let public_key = export_public_key(&key)?;
    Ok(Some(Box::new(StoreKey {
        name: name.to_owned(),
        public_key,
        handle: Mutex::new(StoreHandle {
            key,
            _provider: provider,
        }),
    })))
}

pub(super) fn delete(name: &str) -> anyhow::Result<()> {
    let provider = Provider::open()?;
    if let Some(key) = provider.key(name)? {
        key.delete().with_context(|| format!("delete machine key {name}"))?;
    }
    Ok(())
}

struct EnumState(*mut c_void);

impl Drop for EnumState {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: NCryptEnumKeys allocated this enumeration state.
            let _ = unsafe { NCryptFreeBuffer(self.0) };
        }
    }
}

struct KeyName(*mut NCryptKeyName);

impl Drop for KeyName {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: NCryptEnumKeys allocated this key-name buffer.
            let _ = unsafe { NCryptFreeBuffer(self.0.cast()) };
        }
    }
}

pub(super) fn list(prefix: &str) -> anyhow::Result<Vec<String>> {
    let provider = Provider::open()?;
    let mut state = EnumState(std::ptr::null_mut());
    let mut names = Vec::new();
    loop {
        let mut key_name = KeyName(std::ptr::null_mut());
        // SAFETY: Both output pointers are writable, and their allocations are freed on drop.
        match unsafe {
            NCryptEnumKeys(
                provider.0,
                PCWSTR::null(),
                &mut key_name.0,
                &mut state.0,
                NCRYPT_MACHINE_KEY_FLAG,
            )
        } {
            Ok(()) => {
                ensure!(!key_name.0.is_null(), "NCryptEnumKeys returned no key name");
                // SAFETY: NCryptEnumKeys returned a valid name structure in this live buffer.
                let pointer = unsafe { (*key_name.0).pszName };
                // SAFETY: The name is NUL-terminated and remains live until the buffer is freed.
                let name = unsafe { pointer.to_string() }.context("decode machine key name")?;
                if name.starts_with(prefix) && validate_name(&name).is_ok() {
                    names.push(name);
                }
            }
            Err(error) if error.code() == NTE_NO_MORE_ITEMS => break,
            Err(error) => return Err(error).context("enumerate machine keys"),
        }
    }
    names.sort_unstable();
    names.dedup();
    Ok(names)
}

fn configure_and_finalize(key: &Key, user_sid: &str, grant_current_user: bool) -> anyhow::Result<()> {
    // SAFETY: Both property values are valid for an unfinalized persisted key.
    unsafe {
        NCryptSetProperty(
            NCRYPT_HANDLE(key.0.0),
            NCRYPT_EXPORT_POLICY_PROPERTY,
            &0u32.to_le_bytes(),
            NCRYPT_FLAGS(0),
        )
    }
    .context("make device key non-exportable")?;

    let descriptor = SecurityDescriptor::new(&key_dacl_sddl(user_sid, grant_current_user))?;
    // SAFETY: The self-relative descriptor remains live for the entire call.
    unsafe {
        NCryptSetProperty(
            NCRYPT_HANDLE(key.0.0),
            NCRYPT_SECURITY_DESCR_PROPERTY,
            descriptor.as_bytes(),
            NCRYPT_FLAGS(DACL_SECURITY_INFORMATION.0),
        )
    }
    .context("set protected machine-key DACL")?;
    // SAFETY: This key was created but has not yet been finalized.
    unsafe { NCryptFinalizeKey(key.0, NCRYPT_FLAGS(0)) }.context("finalize machine key")
}

fn key_dacl_sddl(user_sid: &str, grant_current_user: bool) -> String {
    let mut sddl = String::from("D:P(A;;GA;;;SY)");
    if grant_current_user && user_sid != "S-1-5-18" {
        sddl.push_str(&format!("(A;;GA;;;{user_sid})"));
    }
    sddl
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR, usize);

impl SecurityDescriptor {
    fn new(sddl: &str) -> anyhow::Result<Self> {
        let wide = wide(sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let mut length = 0;
        // SAFETY: The SDDL is NUL-terminated and both output pointers are writable.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR::from_raw(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                Some(&mut length),
            )
        }
        .context("convert machine-key DACL")?;
        Ok(Self(descriptor, length as usize))
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: The descriptor owns a LocalAlloc buffer of the recorded size.
        unsafe { std::slice::from_raw_parts(self.0.0.cast(), self.1) }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorW allocated this buffer.
        unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

fn ensure_non_exportable(key: &Key) -> anyhow::Result<()> {
    let mut bytes = [0u8; 4];
    let mut used = 0;
    // SAFETY: The writable buffer holds one DWORD, as required by the export-policy property.
    unsafe {
        NCryptGetProperty(
            NCRYPT_HANDLE(key.0.0),
            NCRYPT_EXPORT_POLICY_PROPERTY,
            Some(&mut bytes),
            &mut used,
            OBJECT_SECURITY_INFORMATION(0),
        )
    }
    .context("read machine-key export policy")?;
    ensure!(used == 4 && u32::from_le_bytes(bytes) == 0, "machine key is exportable");
    Ok(())
}

fn export_public_key(key: &Key) -> anyhow::Result<VerifyingKey> {
    let mut blob = [0u8; 72];
    let mut used = 0;
    // SAFETY: A P-256 public blob fits in this writable 72-byte buffer.
    unsafe {
        NCryptExportKey(
            key.0,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            None,
            Some(&mut blob),
            &mut used,
            NCRYPT_FLAGS(0),
        )
    }
    .context("export machine-key public point")?;
    ensure!(
        used == 72
            && u32::from_le_bytes(blob[..4].try_into()?) == BCRYPT_ECDSA_PUBLIC_P256_MAGIC
            && u32::from_le_bytes(blob[4..8].try_into()?) == 32,
        "machine key is not ECDSA P-256"
    );
    let mut sec1 = [0u8; 65];
    sec1[0] = 4;
    sec1[1..].copy_from_slice(&blob[8..]);
    VerifyingKey::from_sec1_bytes(&sec1).context("decode machine-key public point")
}

fn wide(string: &str) -> Vec<u16> {
    string.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Verifier as _;
    use win_api_wrappers::identity::sid::Sid;
    use windows::Win32::Security::{self, PSECURITY_DESCRIPTOR};

    use super::*;

    #[test]
    fn dacl_grants_only_system_and_optionally_the_user() {
        let user = "S-1-5-21-42";
        assert_eq!(key_dacl_sddl(user, false), "D:P(A;;GA;;;SY)");
        assert_eq!(key_dacl_sddl(user, true), "D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-21-42)");
        assert_eq!(key_dacl_sddl("S-1-5-18", true), "D:P(A;;GA;;;SY)");
    }

    fn elevated() -> anyhow::Result<bool> {
        Token::current_process_token().is_elevated()
    }

    fn read_dacl(key: &Key) -> windows::core::Result<Vec<u8>> {
        let mut needed = 0;
        // SAFETY: A null buffer asks NCrypt for the security descriptor length.
        let first = unsafe {
            NCryptGetProperty(
                NCRYPT_HANDLE(key.0.0),
                NCRYPT_SECURITY_DESCR_PROPERTY,
                None,
                &mut needed,
                DACL_SECURITY_INFORMATION,
            )
        };
        if needed == 0 {
            first?;
        }
        let mut descriptor = vec![0u8; needed as usize];
        // SAFETY: The buffer is at least as large as the length NCrypt reported.
        unsafe {
            NCryptGetProperty(
                NCRYPT_HANDLE(key.0.0),
                NCRYPT_SECURITY_DESCR_PROPERTY,
                Some(&mut descriptor),
                &mut needed,
                DACL_SECURITY_INFORMATION,
            )
        }?;
        Ok(descriptor)
    }

    struct TestKey(String);

    impl Drop for TestKey {
        #[expect(
            clippy::print_stdout,
            reason = "CI must report keys that test cleanup could not remove"
        )]
        fn drop(&mut self) {
            if let Err(error) = delete(&self.0) {
                println!("leftover machine key {}: {error:#}", self.0);
            }
        }
    }

    #[test]
    #[expect(
        clippy::print_stdout,
        reason = "Windows CI needs explicit skip and cleanup diagnostics"
    )]
    fn machine_key_round_trip() -> anyhow::Result<()> {
        if !elevated()? {
            println!("SKIP: machine-key test requires elevation");
            return Ok(());
        }
        let name = crate::new_key_name("DevolutionsAgentTest-");
        let _cleanup = TestKey(name.clone());
        let key = generate(
            &name,
            &KeyOptions {
                acl_grant_current_user: true,
            },
        )?;
        assert_eq!(key.name(), name);
        let reopened = open(&name)?.context("machine key disappeared")?;
        assert_eq!(reopened.public_key(), key.public_key());
        let message = b"machine-key signature round trip";
        let signature = Signer::<Signature>::try_sign(reopened.as_ref(), message)?;
        reopened.public_key().verify(message, &signature)?;
        let der = Signer::<DerSignature>::try_sign(reopened.as_ref(), message)?;
        reopened.public_key().verify(message, &der)?;
        let provider = Provider::open()?;
        let handle = provider.key(&name)?.context("machine key disappeared")?;
        ensure_non_exportable(&handle)?;
        let user = Token::current_process_token()
            .sid_and_attributes()
            .context("get process user SID")?
            .sid;
        let system = Sid::from_well_known(Security::WinLocalSystemSid, None)?;
        let mut expected = vec![system.clone()];
        if user != system {
            expected.push(user);
        }
        let mut descriptor = read_dacl(&handle)?;
        crate::windows_acl::require_protected_dacl(PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr().cast()), expected)?;
        assert!(list("DevolutionsAgentTest-")?.contains(&name));
        drop(handle);
        drop(provider);
        drop(reopened);
        drop(key);
        delete(&name)?;
        assert!(open(&name)?.is_none());
        delete(&name)?;
        Ok(())
    }
}
