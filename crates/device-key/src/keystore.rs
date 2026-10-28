use std::ffi::c_void;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, ensure};
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};
use win_api_wrappers::handle::Handle;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::token::Token;
use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_NOT_FOUND, ERROR_PATH_NOT_FOUND, HANDLE, HLOCAL, LocalFree, NTE_BAD_KEYSET,
    NTE_BAD_PROVIDER, NTE_NO_MORE_ITEMS, NTE_NOT_FOUND, NTE_NOT_SUPPORTED, NTE_PROV_DLL_NOT_FOUND,
    NTE_PROVIDER_DLL_FAIL, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
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
    AddSIDToBoundaryDescriptor, ClosePrivateNamespace, CreateBoundaryDescriptorW, CreateMutexExW,
    CreatePrivateNamespaceW, DeleteBoundaryDescriptor, OpenPrivateNamespaceW, ReleaseMutex,
    SYNCHRONIZATION_SYNCHRONIZE, WaitForSingleObject,
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
const CREATION_BOUNDARY: &str = "device-key";

/// Serializes the creators of one key name across every process and session.
///
/// The provider persists a key only when it is finalized, and two creators that both started before either finalized both succeed.
/// The existence check and the whole creation therefore run under this lock.
///
/// The lock is a mutex in a private namespace whose boundary holds the caller's SID.
/// Only a process running as the caller's account is within that boundary and can create the namespace, and the namespace's DACL lets only that account and SYSTEM open it.
/// Another account therefore can't hold the lock to block creation, as the [device-key intent][intent] ("Operations") requires:
/// "With the Windows software provider, only the caller's account and SYSTEM can block the creation of a key."
/// Creators running as the same account share the namespace, so they still serialize, and any of them can hold the lock.
///
/// [intent]: ../INTENT.md#operations
struct CreationLock {
    mutex: Handle,
    // The mutex's handle closes before the namespace's, as fields drop in declaration order.
    _namespace: PrivateNamespace,
}

impl CreationLock {
    fn acquire(name: &str, user: &Sid) -> anyhow::Result<Self> {
        let descriptor = SecurityDescriptor::new(&key_descriptor_sddl(&user.to_string()))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())?,
            lpSecurityDescriptor: descriptor.0.0,
            bInheritHandle: false.into(),
        };
        // UNTESTED: another account can neither create nor open the namespace.
        // The boundary holds only the caller's SID and the DACL grants only the caller and SYSTEM; tests run as a single account.
        // When changing the boundary or the descriptor, keep every other account out of both.
        let boundary = BoundaryDescriptor::new(user)?;
        // The boundary identifies the namespace, and an alias names it only within this process.
        // An alias can't name two open handles at once, so each acquisition takes its own.
        static NEXT_ALIAS: AtomicU64 = AtomicU64::new(0);
        let alias = format!("{CREATION_BOUNDARY}-{}", NEXT_ALIAS.fetch_add(1, Ordering::Relaxed));
        let wide_alias = wide(&alias);
        let namespace = create_or_open_namespace(
            || {
                // SAFETY: The attributes, their descriptor, the boundary and the NUL-terminated alias remain live for the call.
                let handle = unsafe {
                    CreatePrivateNamespaceW(
                        Some(&attributes),
                        boundary.0.0.cast_const(),
                        PCWSTR::from_raw(wide_alias.as_ptr()),
                    )
                };
                PrivateNamespace::from_raw(handle)
            },
            || {
                // SAFETY: The boundary and the NUL-terminated alias remain live for the call.
                let handle =
                    unsafe { OpenPrivateNamespaceW(boundary.0.0.cast_const(), PCWSTR::from_raw(wide_alias.as_ptr())) };
                PrivateNamespace::from_raw(handle)
            },
        )?;
        // UNTESTED: creators in different sessions share the lock.
        // The boundary holds no session SID, so the namespace is the same in every session, as machine keys are; tests run in a single session.
        // When changing the boundary, keep it free of session SIDs.
        let lock_name = wide(&format!("{alias}\\{name}"));
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
        let mutex = unsafe { Handle::new_owned(raw) }.context("own machine-key creation lock")?;
        // SAFETY: The handle is live and has SYNCHRONIZE access.
        match unsafe { WaitForSingleObject(mutex.raw(), CREATION_LOCK_TIMEOUT_MS) } {
            // A holder that died either never finalized its key or left it for the existence check.
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self {
                mutex,
                _namespace: namespace,
            }),
            WAIT_TIMEOUT => anyhow::bail!("timed out waiting for machine-key creation lock after five seconds"),
            _ => Err(std::io::Error::last_os_error()).context("wait for machine-key creation lock"),
        }
    }
}

impl Drop for CreationLock {
    fn drop(&mut self) {
        // SAFETY: The thread that acquired this lock owns the mutex until this release.
        let _ = unsafe { ReleaseMutex(self.mutex.raw()) };
    }
}

/// Creates the creation lock's namespace, or opens it when another creator already created it.
///
/// The namespace disappears when its last handle closes, which can happen between a create that found it and the open, so creation is attempted again, a bounded number of times.
fn create_or_open_namespace<T>(
    mut create: impl FnMut() -> windows::core::Result<T>,
    mut open: impl FnMut() -> windows::core::Result<T>,
) -> anyhow::Result<T> {
    const ATTEMPTS: usize = 3;

    for _ in 0..ATTEMPTS {
        match create() {
            Err(error) if error.code() == ERROR_ALREADY_EXISTS.to_hresult() => {}
            result => return result.context("create machine-key creation namespace"),
        }
        match open() {
            Err(error)
                if error.code() == ERROR_PATH_NOT_FOUND.to_hresult()
                    || error.code() == ERROR_NOT_FOUND.to_hresult() => {}
            result => return result.context("open machine-key creation namespace"),
        }
    }
    anyhow::bail!("machine-key creation namespace disappeared before it could be opened {ATTEMPTS} times")
}

struct BoundaryDescriptor(HANDLE);

impl BoundaryDescriptor {
    fn new(sid: &Sid) -> anyhow::Result<Self> {
        let name = wide(CREATION_BOUNDARY);
        // SAFETY: The boundary name is NUL-terminated.
        let handle = unsafe { CreateBoundaryDescriptorW(PCWSTR::from_raw(name.as_ptr()), 0) };
        ensure!(
            !handle.is_invalid(),
            "create machine-key creation boundary: {}",
            std::io::Error::last_os_error()
        );
        let mut descriptor = Self(handle);
        // SAFETY: The descriptor is live and may be reallocated in place; the SID remains live for the call.
        unsafe { AddSIDToBoundaryDescriptor(&mut descriptor.0, sid.as_psid_const()) }
            .context("add caller SID to machine-key creation boundary")?;
        Ok(descriptor)
    }
}

impl Drop for BoundaryDescriptor {
    fn drop(&mut self) {
        // SAFETY: CreateBoundaryDescriptorW allocated this descriptor.
        unsafe { DeleteBoundaryDescriptor(self.0) };
    }
}

struct PrivateNamespace(HANDLE);

impl PrivateNamespace {
    fn from_raw(handle: HANDLE) -> windows::core::Result<Self> {
        if handle.is_invalid() {
            Err(windows::core::Error::from_win32())
        } else {
            Ok(Self(handle))
        }
    }
}

impl Drop for PrivateNamespace {
    fn drop(&mut self) {
        // The namespace is closed without being destroyed, because other creators may still use it.
        // SAFETY: This wrapper owns the namespace handle.
        let _ = unsafe { ClosePrivateNamespace(self.0, 0) };
    }
}

pub(super) fn generate(name: &str) -> anyhow::Result<Box<dyn DeviceKey>> {
    let provider = Provider::open()?;
    let user = Token::current_process_token()
        .sid_and_attributes()
        .context("get process user SID")?
        .sid;
    let _lock = CreationLock::acquire(name, &user)?;
    let user = user.to_string();
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

/// Opens the provider and nothing else, so that the check leaves no key behind.
pub(super) fn check_available() -> anyhow::Result<()> {
    Provider::open().map(drop)
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
                let decoded = unsafe { pointer.to_string() };
                // UNTESTED: a machine-key name that is not valid UTF-16 is skipped instead of failing the listing.
                // Every program on the machine shares this store, so one foreign name must not hide the crate's keys.
                // Creating such a key needs elevation, and whether the provider keeps the name is unverified.
                // When changing this decoding, keep skipping a name that does not decode.
                let Ok(name) = decoded else {
                    continue;
                };
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
    let system = Sid::from_well_known(windows::Win32::Security::WinLocalSystemSid, None).context("get SYSTEM SID")?;
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
    use windows::Win32::Security::Cryptography::{BCRYPT_ECDSA_P384_ALGORITHM, NCRYPT_ALLOW_EXPORT_FLAG};
    use windows::Win32::Security::WinLocalSystemSid;

    use super::*;

    // oracle: intent crates/device-key/INTENT.md §Access
    #[test]
    fn descriptor_owns_the_key_as_the_caller_and_grants_only_caller_and_system() -> anyhow::Result<()> {
        use win_api_wrappers::identity::sid::StringSid;

        let system = Sid::from_well_known(WinLocalSystemSid, None)?;
        let process_user = Token::current_process_token()
            .sid_and_attributes()
            .context("get process user SID")?
            .sid;
        let other_user = StringSid::from_str("S-1-5-21-42")?.to_sid()?;
        for caller in [process_user, other_user, system.clone()] {
            let sddl = key_descriptor_sddl(&caller.to_string());
            let descriptor = SecurityDescriptor::new(&sddl)?;
            let owner = crate::windows_acl::owner_sid(descriptor.0)?;
            assert!(owner == caller || owner == system, "{sddl}");
            let mut expected = vec![system.clone(), caller];
            expected.dedup();
            crate::windows_acl::require_protected_dacl(descriptor.0, expected.clone())?;

            let extra_allow = SecurityDescriptor::new(&format!("{sddl}(A;;GA;;;BU)"))?;
            // oracle: spec MS-DTYP §2.5.1.1
            assert!(crate::windows_acl::require_protected_dacl(extra_allow.0, expected).is_err());
        }
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Backends
    // oracle: spec MS-ERREF §2.1.1
    #[test]
    fn unavailable_provider_errors_exclude_access_denied() {
        assert!(provider_is_unavailable(NTE_BAD_PROVIDER));
        assert!(provider_is_unavailable(NTE_NOT_SUPPORTED));
        assert!(provider_is_unavailable(NTE_PROV_DLL_NOT_FOUND));
        assert!(provider_is_unavailable(NTE_PROVIDER_DLL_FAIL));
        assert!(!provider_is_unavailable(windows::Win32::Foundation::E_ACCESSDENIED));
    }

    // oracle: intent crates/device-key/INTENT.md §Backends
    // Every supported Windows version ships the Microsoft Software Key Storage Provider, so it is available on any
    // machine that runs the tests, elevated or not.
    #[test]
    fn the_software_provider_is_available() -> anyhow::Result<()> {
        crate::check_available(&crate::KeyBackend::WindowsSoftwareProvider)
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

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn machine_key_round_trip() -> anyhow::Result<()> {
        if !run_machine_key_test()? {
            return Ok(());
        }
        let name = crate::new_key_name("devolutions-agent-test");
        let _cleanup = TestKey(name.clone());
        let key = generate(&name)?;
        // oracle: mutant a key reporting a name other than the one it was created under
        assert_eq!(key.name(), name);
        let reopened = open(&name)?.context("machine key disappeared")?;
        // oracle: property round-trip
        assert_eq!(reopened.public_key(), key.public_key());
        let message = b"machine-key signature round trip";
        let signature = reopened.try_sign(message)?;
        // oracle: intent crates/device-key/INTENT.md §Signing
        reopened.public_key().verify(message, &signature)?;
        let provider = Provider::open()?;
        let handle = provider.key(&name)?.context("machine key disappeared")?;
        // oracle: intent crates/device-key/INTENT.md §Private keys
        ensure_non_exportable(&handle)?;
        // oracle: intent crates/device-key/INTENT.md §Device key
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
        let owner = crate::windows_acl::owner_sid(descriptor)?;
        // oracle: intent crates/device-key/INTENT.md §Access
        assert!(owner == user || owner == system);
        // oracle: intent crates/device-key/INTENT.md §Access
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

    /// Persists a machine key with the given algorithm, export policy and security descriptor, bypassing `generate`.
    fn plant(name: &str, algorithm: PCWSTR, export_policy: u32, sddl: &str) -> anyhow::Result<()> {
        let provider = Provider::open()?;
        let wide_name = wide(name);
        let mut handle = NCRYPT_KEY_HANDLE::default();
        // SAFETY: The output pointer is writable and both algorithm and name are NUL-terminated.
        unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut handle,
                algorithm,
                PCWSTR::from_raw(wide_name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_MACHINE_KEY_FLAG,
            )
        }?;
        let key = Key(handle);
        // SAFETY: The export policy is one DWORD, valid for an unfinalized persisted key.
        unsafe {
            NCryptSetProperty(
                NCRYPT_HANDLE(key.0.0),
                NCRYPT_EXPORT_POLICY_PROPERTY,
                &export_policy.to_le_bytes(),
                NCRYPT_FLAGS(0),
            )
        }?;
        let descriptor = SecurityDescriptor::new(sddl)?;
        // SAFETY: The self-relative descriptor remains live for the entire call.
        unsafe {
            NCryptSetProperty(
                NCRYPT_HANDLE(key.0.0),
                NCRYPT_SECURITY_DESCR_PROPERTY,
                descriptor.as_bytes(),
                NCRYPT_FLAGS((OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION).0),
            )
        }?;
        // SAFETY: This key was created but has not yet been finalized.
        unsafe { NCryptFinalizeKey(key.0, NCRYPT_FLAGS(0)) }?;
        Ok(())
    }

    fn trusted_sddl() -> anyhow::Result<String> {
        let user = Token::current_process_token()
            .sid_and_attributes()
            .context("get process user SID")?
            .sid;
        Ok(key_descriptor_sddl(&user.to_string()))
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn an_exportable_machine_key_cannot_be_opened() -> anyhow::Result<()> {
        if !run_machine_key_test()? {
            return Ok(());
        }
        let name = crate::new_key_name("devolutions-agent-test");
        let _cleanup = TestKey(name.clone());
        plant(
            &name,
            BCRYPT_ECDSA_P256_ALGORITHM,
            NCRYPT_ALLOW_EXPORT_FLAG,
            &trusted_sddl()?,
        )?;
        let provider = Provider::open()?;
        let planted = provider.key(&name)?.context("planted machine key is missing")?;
        // The key keeps every other rule, so only its export policy can refuse it.
        ensure_trusted_descriptor(&planted)?;
        ensure_supported_algorithm(&planted)?;

        assert!(open(&name).is_err());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Access
    #[test]
    fn a_machine_key_another_account_can_access_cannot_be_opened() -> anyhow::Result<()> {
        if !run_machine_key_test()? {
            return Ok(());
        }
        let name = crate::new_key_name("devolutions-agent-test");
        let _cleanup = TestKey(name.clone());
        let sddl = format!("{}(A;;GR;;;BU)", trusted_sddl()?);
        plant(&name, BCRYPT_ECDSA_P256_ALGORITHM, 0, &sddl)?;
        let provider = Provider::open()?;
        let planted = provider.key(&name)?.context("planted machine key is missing")?;
        // The key keeps every other rule, so only its descriptor can refuse it.
        ensure_non_exportable(&planted)?;
        ensure_supported_algorithm(&planted)?;

        assert!(open(&name).is_err());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn a_machine_key_of_another_algorithm_cannot_be_opened() -> anyhow::Result<()> {
        if !run_machine_key_test()? {
            return Ok(());
        }
        let name = crate::new_key_name("devolutions-agent-test");
        let _cleanup = TestKey(name.clone());
        plant(&name, BCRYPT_ECDSA_P384_ALGORITHM, 0, &trusted_sddl()?)?;
        let provider = Provider::open()?;
        let planted = provider.key(&name)?.context("planted machine key is missing")?;
        // The key keeps every other rule, so only its algorithm can refuse it, whether the algorithm check or reading
        // its P-256 public key does.
        ensure_non_exportable(&planted)?;
        ensure_trusted_descriptor(&planted)?;

        assert!(open(&name).is_err());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn creation_wait_for_another_creator_expires() -> anyhow::Result<()> {
        let name = crate::new_key_name("devolutions-agent-test");
        let _cleanup = TestKey(name.clone());
        let user = Token::current_process_token()
            .sid_and_attributes()
            .context("get process user SID")?
            .sid;
        let _held = CreationLock::acquire(&name, &user)?;

        let started = std::time::Instant::now();
        let creator = std::thread::spawn(move || generate(&name).map(|_| ()));
        let error = creator
            .join()
            .map_err(|_| anyhow::anyhow!("generator panicked"))?
            .err()
            .context("creation did not wait for the held lock")?;
        // oracle: mutant a creation-lock time-out reported as another failure
        assert!(
            format!("{error:#}").contains("timed out waiting for machine-key creation lock"),
            "{error:#}"
        );
        // Wait time-outs advance in system clock ticks, so a five-second wait can end slightly early.
        // oracle: mutant creation failing without waiting for the lock another creator holds
        assert!(started.elapsed() >= std::time::Duration::from_millis(4_900));
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn a_mutex_under_the_former_global_lock_name_cannot_block_creation() -> anyhow::Result<()> {
        use windows::Win32::System::Threading::CreateMutexW;

        if !run_machine_key_test()? {
            return Ok(());
        }
        let name = crate::new_key_name("devolutions-agent-test");
        let _cleanup = TestKey(name.clone());
        // Any account can create a mutex under this global name, so the squatter stands in for another account.
        let squatted_name = wide(&format!("Global\\device-key-{name}"));
        // SAFETY: The mutex name is NUL-terminated.
        let raw = unsafe { CreateMutexW(None, true, PCWSTR::from_raw(squatted_name.as_ptr())) }?;
        // SAFETY: CreateMutexW returned a new owned handle.
        let _squatter = unsafe { Handle::new_owned(raw) }?;

        // The squatter's thread owns the mutex, which it could acquire again, so creation runs on another thread.
        let creator = std::thread::spawn(move || generate(&name).map(|_| ()));
        creator
            .join()
            .map_err(|_| anyhow::anyhow!("generator panicked"))?
            .context("create a machine key while a mutex holds the former global lock name")
    }

    // oracle: mutant a creator failing when the namespace closes between its failed create and its open
    #[test]
    fn a_namespace_closed_between_create_and_open_is_created_again() -> anyhow::Result<()> {
        let mut creates = 0;
        let namespace = create_or_open_namespace(
            || {
                creates += 1;
                if creates == 1 {
                    Err(ERROR_ALREADY_EXISTS.to_hresult().into())
                } else {
                    Ok("created")
                }
            },
            || Err(ERROR_PATH_NOT_FOUND.to_hresult().into()),
        )?;
        assert_eq!(namespace, "created");
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn a_namespace_that_keeps_disappearing_fails_instead_of_retrying_forever() {
        let result = create_or_open_namespace::<()>(
            || Err(ERROR_ALREADY_EXISTS.to_hresult().into()),
            || Err(ERROR_PATH_NOT_FOUND.to_hresult().into()),
        );
        assert!(result.is_err());
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
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
