use std::ffi::c_void;
use std::sync::Mutex;

use anyhow::{Context as _, ensure};
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};
use win_api_wrappers::handle::Handle;
use win_api_wrappers::token::Token;
use windows::Win32::Foundation::{
    HLOCAL, LocalFree, NTE_BAD_KEYSET, NTE_BAD_PROVIDER, NTE_NO_MORE_ITEMS, NTE_NOT_FOUND, NTE_NOT_SUPPORTED,
    NTE_PROV_DLL_NOT_FOUND, NTE_PROVIDER_DLL_FAIL, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, CERT_KEY_SPEC,
    MS_KEY_STORAGE_PROVIDER, NCRYPT_ALGORITHM_PROPERTY, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_FLAGS, NCRYPT_HANDLE,
    NCRYPT_KEY_HANDLE, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SECURITY_DESCR_PROPERTY,
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptEnumKeys, NCryptExportKey, NCryptFinalizeKey, NCryptFreeBuffer,
    NCryptFreeObject, NCryptGetProperty, NCryptKeyName, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
    NCryptSignHash,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows::Win32::System::Threading::{
    CreateMutexExW, ReleaseMutex, SYNCHRONIZATION_SYNCHRONIZE, WaitForSingleObject,
};
use windows::core::PCWSTR;

use crate::{BackendUnavailable, DeviceKey, name_matches_prefix};

struct Provider(NCRYPT_PROV_HANDLE);

impl Provider {
    fn open() -> anyhow::Result<Self> {
        let mut handle = NCRYPT_PROV_HANDLE::default();
        // SAFETY: The output pointer is writable and the provider name is a static wide string.
        match unsafe { NCryptOpenStorageProvider(&mut handle, MS_KEY_STORAGE_PROVIDER, 0) } {
            Ok(()) => Ok(Self(handle)),
            Err(error) if provider_is_unavailable(error.code()) => Err(BackendUnavailable {
                backend: "WindowsSoftwareProvider",
            }
            .into()),
            Err(error) => Err(error).context("open Microsoft Software Key Storage Provider"),
        }
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

fn provider_is_unavailable(code: windows::core::HRESULT) -> bool {
    matches!(
        code,
        NTE_BAD_PROVIDER | NTE_NOT_SUPPORTED | NTE_PROV_DLL_NOT_FOUND | NTE_PROVIDER_DLL_FAIL
    )
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

impl DeviceKey for StoreKey {
    fn name(&self) -> &str {
        &self.name
    }

    fn public_key(&self) -> VerifyingKey {
        self.public_key
    }

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

const CREATION_LOCK_TIMEOUT_MS: u32 = 5_000;

/// Serializes the creators of one key name across every process and session.
///
/// The provider persists a key only when it is finalized, and two creators that both started before either finalized both succeed.
/// The existence check and the whole creation therefore run under this lock.
/// The lock name derives from the key name, which only the key's owner knows before the key exists.
struct CreationLock(Handle);

impl CreationLock {
    fn acquire(name: &str, user_sid: &str) -> anyhow::Result<Self> {
        let descriptor = SecurityDescriptor::new(&key_descriptor_sddl(user_sid))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())?,
            lpSecurityDescriptor: descriptor.0.0,
            bInheritHandle: false.into(),
        };
        // Machine keys are shared by every session, so the lock lives in the global namespace.
        let lock_name = wide(&format!("Global\\device-key-{name}"));
        // SAFETY: The attributes, their descriptor and the NUL-terminated name remain live for the call.
        let raw = unsafe {
            CreateMutexExW(
                Some(&attributes),
                PCWSTR::from_raw(lock_name.as_ptr()),
                0,
                SYNCHRONIZATION_SYNCHRONIZE.0,
            )
        }
        .context("open machine-key creation lock")?;
        // SAFETY: CreateMutexExW returned a new handle that this lock owns.
        let handle = unsafe { Handle::new_owned(raw) }.context("own machine-key creation lock")?;
        // SAFETY: The handle is live and has SYNCHRONIZE access.
        match unsafe { WaitForSingleObject(handle.raw(), CREATION_LOCK_TIMEOUT_MS) } {
            // A holder that died either never finalized its key or left it for the existence check.
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(handle)),
            WAIT_TIMEOUT => anyhow::bail!("timed out waiting for machine-key creation lock after five seconds"),
            _ => Err(std::io::Error::last_os_error()).context("wait for machine-key creation lock"),
        }
    }
}

impl Drop for CreationLock {
    fn drop(&mut self) {
        // SAFETY: The thread that acquired this lock owns the mutex until this release.
        let _ = unsafe { ReleaseMutex(self.0.raw()) };
    }
}

pub(super) fn generate(name: &str) -> anyhow::Result<Box<dyn DeviceKey>> {
    let provider = Provider::open()?;
    let user = Token::current_process_token()
        .sid_and_attributes()
        .context("get process user SID")?
        .sid
        .to_string();
    let _lock = CreationLock::acquire(name, &user)?;
    ensure!(provider.key(name)?.is_none(), "machine key {name} already exists");
    let key = provider.create(name)?;
    configure_and_finalize(&key, &user)?;
    if let Err(error) = ensure_trusted_descriptor(&key) {
        let _ = key.delete();
        return Err(error);
    }
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

pub(super) fn open(name: &str) -> anyhow::Result<Option<Box<dyn DeviceKey>>> {
    let provider = Provider::open()?;
    let Some(key) = provider.key(name)? else {
        return Ok(None);
    };
    ensure_non_exportable(&key)?;
    ensure_trusted_descriptor(&key)?;
    ensure_supported_algorithm(&key)?;
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
                if name_matches_prefix(&name, prefix) {
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

fn configure_and_finalize(key: &Key, user_sid: &str) -> anyhow::Result<()> {
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

    let descriptor = SecurityDescriptor::new(&key_descriptor_sddl(user_sid))?;
    // SAFETY: The self-relative descriptor remains live for the entire call.
    unsafe {
        NCryptSetProperty(
            NCRYPT_HANDLE(key.0.0),
            NCRYPT_SECURITY_DESCR_PROPERTY,
            descriptor.as_bytes(),
            NCRYPT_FLAGS((OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION).0),
        )
    }
    .context("set machine-key owner and protected DACL")?;
    // SAFETY: This key was created but has not yet been finalized.
    unsafe { NCryptFinalizeKey(key.0, NCRYPT_FLAGS(0)) }.context("finalize machine key")
}

fn key_descriptor_sddl(user_sid: &str) -> String {
    if user_sid == "S-1-5-18" {
        "O:SYD:P(A;;GA;;;SY)".to_owned()
    } else {
        format!("O:{user_sid}D:P(A;;GA;;;SY)(A;;GA;;;{user_sid})")
    }
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

fn ensure_trusted_descriptor(key: &Key) -> anyhow::Result<()> {
    let mut descriptor = read_descriptor(key)?;
    let descriptor = PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr().cast());
    let caller = Token::current_process_token()
        .sid_and_attributes()
        .context("get process user SID")?
        .sid;
    let system =
        win_api_wrappers::identity::sid::Sid::from_well_known(windows::Win32::Security::WinLocalSystemSid, None)
            .context("get SYSTEM SID")?;
    let owner = crate::windows_acl::owner_sid(descriptor)?;
    ensure!(owner == caller || owner == system, "machine key owner is not trusted");
    let mut expected = vec![system.clone()];
    if caller != system {
        expected.push(caller);
    }
    crate::windows_acl::require_protected_dacl(descriptor, expected)
}

fn read_descriptor(key: &Key) -> anyhow::Result<Vec<u8>> {
    let security_info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut needed = 0;
    // SAFETY: A null buffer asks NCrypt for the security descriptor length.
    let first = unsafe {
        NCryptGetProperty(
            NCRYPT_HANDLE(key.0.0),
            NCRYPT_SECURITY_DESCR_PROPERTY,
            None,
            &mut needed,
            security_info,
        )
    };
    if needed == 0 {
        first.context("read machine-key security descriptor size")?;
    }
    ensure!(
        needed > 0 && needed <= 65_536,
        "invalid machine-key security descriptor size"
    );
    let mut descriptor = vec![0u8; needed as usize];
    // SAFETY: The buffer is at least as large as the length NCrypt reported.
    unsafe {
        NCryptGetProperty(
            NCRYPT_HANDLE(key.0.0),
            NCRYPT_SECURITY_DESCR_PROPERTY,
            Some(&mut descriptor),
            &mut needed,
            security_info,
        )
    }
    .context("read machine-key security descriptor")?;
    ensure!(
        needed as usize <= descriptor.len(),
        "invalid machine-key security descriptor"
    );
    Ok(descriptor)
}

fn ensure_supported_algorithm(key: &Key) -> anyhow::Result<()> {
    let mut bytes = [0u8; 64];
    let mut used = 0;
    // SAFETY: The output buffer holds the null-terminated UTF-16 algorithm name.
    unsafe {
        NCryptGetProperty(
            NCRYPT_HANDLE(key.0.0),
            NCRYPT_ALGORITHM_PROPERTY,
            Some(&mut bytes),
            &mut used,
            OBJECT_SECURITY_INFORMATION(0),
        )
    }
    .context("read machine-key algorithm")?;
    let algorithm = bytes
        .get(..usize::try_from(used)?)
        .filter(|bytes| bytes.len() % 2 == 0)
        .context("invalid machine-key algorithm name")?
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    ensure!(
        algorithm == wide("ECDSA_P256"),
        "machine key algorithm is not ECDSA P-256"
    );
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
    use windows::Win32::Security::WinLocalSystemSid;

    use super::*;

    #[test]
    fn descriptor_owns_the_key_as_the_caller_and_grants_only_caller_and_system() -> anyhow::Result<()> {
        let user = "S-1-5-21-42";
        assert_eq!(
            key_descriptor_sddl(user),
            "O:S-1-5-21-42D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-21-42)"
        );
        assert_eq!(key_descriptor_sddl("S-1-5-18"), "O:SYD:P(A;;GA;;;SY)");
        let caller = Token::current_process_token()
            .sid_and_attributes()
            .context("get process user SID")?
            .sid;
        let system = Sid::from_well_known(WinLocalSystemSid, None)?;
        let expected = if caller == system {
            vec![system]
        } else {
            vec![system, caller.clone()]
        };
        let sddl = key_descriptor_sddl(&caller.to_string());
        let descriptor = SecurityDescriptor::new(&sddl)?;
        assert_eq!(crate::windows_acl::owner_sid(descriptor.0)?, caller);
        crate::windows_acl::require_protected_dacl(descriptor.0, expected.clone())?;

        let extra_allow = SecurityDescriptor::new(&format!("{sddl}(A;;GA;;;BU)"))?;
        assert!(crate::windows_acl::require_protected_dacl(extra_allow.0, expected).is_err());
        Ok(())
    }

    #[test]
    fn unavailable_provider_errors_exclude_access_denied() {
        assert!(provider_is_unavailable(NTE_BAD_PROVIDER));
        assert!(provider_is_unavailable(NTE_NOT_SUPPORTED));
        assert!(provider_is_unavailable(NTE_PROV_DLL_NOT_FOUND));
        assert!(provider_is_unavailable(NTE_PROVIDER_DLL_FAIL));
        assert!(!provider_is_unavailable(windows::Win32::Foundation::E_ACCESSDENIED));
    }

    fn elevated() -> anyhow::Result<bool> {
        Token::current_process_token().is_elevated()
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
    fn machine_key_round_trip() -> anyhow::Result<()> {
        if !run_machine_key_test()? {
            return Ok(());
        }
        let name = crate::new_key_name("devolutions-agent-test");
        let _cleanup = TestKey(name.clone());
        let key = generate(&name)?;
        assert_eq!(key.name(), name);
        let reopened = open(&name)?.context("machine key disappeared")?;
        assert_eq!(reopened.public_key(), key.public_key());
        let message = b"machine-key signature round trip";
        let signature = reopened.try_sign(message)?;
        reopened.public_key().verify(message, &signature)?;
        let provider = Provider::open()?;
        let handle = provider.key(&name)?.context("machine key disappeared")?;
        ensure_non_exportable(&handle)?;
        ensure_supported_algorithm(&handle)?;
        let user = Token::current_process_token()
            .sid_and_attributes()
            .context("get process user SID")?
            .sid;
        let system = Sid::from_well_known(WinLocalSystemSid, None)?;
        let mut expected = vec![system.clone()];
        if user != system {
            expected.push(user.clone());
        }
        let mut descriptor = read_descriptor(&handle)?;
        let descriptor = PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr().cast());
        assert_eq!(crate::windows_acl::owner_sid(descriptor)?, user);
        crate::windows_acl::require_protected_dacl(descriptor, expected)?;
        assert!(list("devolutions-agent-test")?.contains(&name));
        drop(handle);
        drop(provider);
        drop(reopened);
        drop(key);
        delete(&name)?;
        assert!(open(&name)?.is_none());
        delete(&name)?;
        Ok(())
    }

    #[expect(
        clippy::print_stdout,
        reason = "Local machine-key tests explicitly report their elevation skip"
    )]
    fn run_machine_key_test() -> anyhow::Result<bool> {
        if elevated()? {
            return Ok(true);
        }
        ensure!(
            std::env::var_os("CI").is_none(),
            "machine-key tests require elevation in CI"
        );
        println!("SKIP: machine-key test requires elevation");
        Ok(false)
    }

    #[test]
    fn creation_wait_for_another_creator_expires() -> anyhow::Result<()> {
        use windows::Win32::System::Threading::CreateMutexW;

        let name = crate::new_key_name("devolutions-agent-test");
        let _cleanup = TestKey(name.clone());
        let lock_name = wide(&format!("Global\\device-key-{name}"));
        // SAFETY: The lock name is NUL-terminated.
        let raw = unsafe { CreateMutexW(None, true, PCWSTR::from_raw(lock_name.as_ptr())) }?;
        // SAFETY: CreateMutexW returned a new owned handle.
        let _held = unsafe { Handle::new_owned(raw) }?;

        let started = std::time::Instant::now();
        let creator = std::thread::spawn(move || generate(&name).map(|_| ()));
        let error = creator
            .join()
            .map_err(|_| anyhow::anyhow!("generator panicked"))?
            .err()
            .context("creation did not wait for the held lock")?;
        assert!(
            format!("{error:#}").contains("timed out waiting for machine-key creation lock"),
            "{error:#}"
        );
        assert!(started.elapsed() >= std::time::Duration::from_secs(5));
        Ok(())
    }

    #[test]
    fn concurrent_creates_cannot_replace_a_machine_key() -> anyhow::Result<()> {
        use std::sync::{Arc, Barrier};

        if !run_machine_key_test()? {
            return Ok(());
        }
        let name = crate::new_key_name("devolutions-agent-test");
        let _cleanup = TestKey(name.clone());
        let barrier = Arc::new(Barrier::new(3));
        let spawn = |name: String, barrier: Arc<Barrier>| {
            std::thread::spawn(move || {
                barrier.wait();
                generate(&name).map(|key| key.public_key())
            })
        };
        let first = spawn(name.clone(), Arc::clone(&barrier));
        let second = spawn(name.clone(), Arc::clone(&barrier));
        barrier.wait();
        let first = first.join().map_err(|_| anyhow::anyhow!("first generator panicked"))?;
        let second = second
            .join()
            .map_err(|_| anyhow::anyhow!("second generator panicked"))?;
        assert_ne!(first.is_ok(), second.is_ok());
        let public_key = first.or(second)?;
        assert_eq!(
            open(&name)?.context("machine key disappeared")?.public_key(),
            public_key
        );
        delete(&name)?;
        Ok(())
    }
}
