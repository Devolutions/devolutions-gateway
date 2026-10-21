use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read as _, Write as _};
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use camino::{Utf8Path, Utf8PathBuf};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::Generate as _;
use p256::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use secure_memory::ProtectedBytes;
use uuid::Uuid;
#[cfg(windows)]
use win_api_wrappers::identity::sid::Sid;
use zeroize::Zeroizing;

use crate::{DeviceKey, name_matches_prefix, validate_name};

const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(25);

struct FileKey {
    name: String,
    scalar: ProtectedBytes<32>,
    public_key: VerifyingKey,
}

impl DeviceKey for FileKey {
    fn name(&self) -> &str {
        &self.name
    }

    fn public_key(&self) -> VerifyingKey {
        self.public_key
    }

    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        let key = SigningKey::from_slice(self.scalar.expose_secret()).map_err(signature::Error::from_source)?;
        signature::Signer::<Signature>::try_sign(&key, message)
    }
}

fn key_path(dir: &Utf8Path, name: &str) -> Utf8PathBuf {
    dir.join(format!("{name}.p8"))
}

struct PendingFile(Utf8PathBuf);

impl Drop for PendingFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub(super) fn generate(dir: &Utf8Path, name: &str) -> anyhow::Result<Box<dyn DeviceKey>> {
    create_key_directory(dir)?;
    let _lock = lock_and_reconcile(dir)?;
    let destination = key_path(dir, name);
    let key = SigningKey::generate_from_rng(&mut rand::rng());
    let pkcs8 = key.to_pkcs8_der().context("encode device key")?;
    let public_key = *key.verifying_key();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&key.to_bytes());
    let scalar = ProtectedBytes::new(&mut bytes);
    drop(key);
    let temporary = PendingFile(dir.join(format!(".{name}-{}.tmp", Uuid::new_v4())));
    {
        let mut file = create_restricted_file(&temporary.0)?;
        #[cfg(unix)]
        ensure_owner_only(&file.metadata()?)?;
        #[cfg(target_os = "macos")]
        crate::macos_acl::ensure_private_file(&file)?;
        #[cfg(windows)]
        ensure_private_file(&file)?;
        file.write_all(pkcs8.as_bytes())
            .with_context(|| format!("write key file {}", temporary.0))?;
        drop(pkcs8);
        file.sync_all()
            .with_context(|| format!("sync key file {}", temporary.0))?;
    }
    rename_new(&temporary.0, &destination).with_context(|| format!("install key file {destination}"))?;
    #[cfg(unix)]
    sync_directory(dir)?;
    Ok(Box::new(FileKey {
        name: name.to_owned(),
        scalar,
        public_key,
    }))
}

pub(super) fn open(dir: &Utf8Path, name: &str) -> anyhow::Result<Option<Box<dyn DeviceKey>>> {
    if !directory_exists(dir)? {
        return Ok(None);
    }
    let _lock = lock_and_reconcile(dir)?;
    let path = key_path(dir, name);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
    }
    let mut file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open key file {path}")),
    };
    let metadata = file.metadata().with_context(|| format!("inspect key file {path}"))?;
    ensure!(metadata.file_type().is_file(), "key file is not a regular file");
    ensure!(link_count(&file)? == 1, "key file has other hard links");
    #[cfg(unix)]
    ensure_owner_only(&metadata)?;
    #[cfg(target_os = "macos")]
    crate::macos_acl::ensure_private_file(&file)?;
    #[cfg(windows)]
    ensure_private_file(&file)?;
    let mut pkcs8 = Zeroizing::new(Vec::new());
    file.read_to_end(&mut pkcs8)
        .with_context(|| format!("read key file {path}"))?;
    let key = SigningKey::from_pkcs8_der(&pkcs8).context("decode device key")?;
    let public_key = *key.verifying_key();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&key.to_bytes());
    let scalar = ProtectedBytes::new(&mut bytes);
    drop(key);
    drop(pkcs8);
    Ok(Some(Box::new(FileKey {
        name: name.to_owned(),
        scalar,
        public_key,
    })))
}

pub(super) fn delete(dir: &Utf8Path, name: &str) -> anyhow::Result<()> {
    if !directory_exists(dir)? {
        return Ok(());
    }
    let _lock = lock_and_reconcile(dir)?;
    delete_key(dir, name)
}

pub(super) fn list(dir: &Utf8Path, prefix: &str) -> anyhow::Result<Vec<String>> {
    if !directory_exists(dir)? {
        return Ok(Vec::new());
    }
    let _lock = lock_and_reconcile(dir)?;
    let entries = fs::read_dir(dir).with_context(|| format!("list key directory {dir}"))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.context("read key directory entry")?;
        if !entry.file_type().context("inspect key directory entry")?.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        if let Some(name) = file_name
            .to_str()
            .and_then(|file_name| file_name.strip_suffix(".p8"))
            .filter(|name| name_matches_prefix(name, prefix))
        {
            names.push(name.to_owned());
        }
    }
    names.sort_unstable();
    Ok(names)
}

fn directory_exists(dir: &Utf8Path) -> anyhow::Result<bool> {
    #[cfg(unix)]
    let metadata = fs::symlink_metadata(dir);
    #[cfg(not(unix))]
    let metadata = fs::metadata(dir);
    match metadata {
        Ok(metadata) => {
            ensure!(metadata.is_dir(), "key directory is not a directory");
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect key directory {dir}")),
    }
}

#[cfg(unix)]
fn create_key_directory(dir: &Utf8Path) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    ensure!(!dir.as_str().is_empty(), "key directory is empty");
    let mut missing = Vec::new();
    let mut path = dir;
    while !directory_exists(path)? {
        missing.push(path.to_owned());
        path = match path.parent() {
            Some(parent) if !parent.as_str().is_empty() => parent,
            _ => Utf8Path::new("."),
        };
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    for path in missing.iter().rev() {
        if let Err(error) = builder.create(path)
            && (error.kind() != ErrorKind::AlreadyExists || !directory_exists(path)?)
        {
            return Err(error).with_context(|| format!("create key directory {path}"));
        }
        sync_directory(path)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_str().is_empty())
            .unwrap_or_else(|| Utf8Path::new("."));
        sync_directory(parent)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_key_directory(dir: &Utf8Path) -> anyhow::Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("create key directory {dir}"))
}

fn lock_and_reconcile(dir: &Utf8Path) -> anyhow::Result<File> {
    #[cfg(target_os = "macos")]
    {
        let directory = File::open(dir).with_context(|| format!("open key directory {dir}"))?;
        crate::macos_acl::ensure_private_directory(&directory)?;
    }
    let lock = lock_directory(dir)?;
    cleanup_abandoned(dir)?;
    Ok(lock)
}

fn abandoned_name(file_name: &str) -> Option<&str> {
    let stem = file_name
        .strip_prefix('.')?
        .strip_suffix(".tmp")
        .or_else(|| file_name.strip_prefix('.')?.strip_suffix(".deleted"))?;
    if !stem.is_ascii() || stem.len() < 37 {
        return None;
    }
    let (name_with_dash, suffix) = stem.split_at(stem.len() - 36);
    let name = name_with_dash.strip_suffix('-')?;
    let uuid = Uuid::parse_str(suffix).ok()?;
    (uuid.get_version_num() == 4
        && uuid.get_variant() == uuid::Variant::RFC4122
        && suffix == uuid.to_string()
        && validate_name(name).is_ok())
    .then_some(name)
}

fn cleanup_abandoned(dir: &Utf8Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    let mut removed = false;
    // A creator holds this lock until it removes its temporary, so every remaining temporary is abandoned.
    for entry in fs::read_dir(dir).with_context(|| format!("inspect abandoned key files in {dir}"))? {
        let entry = entry.context("read abandoned key entry")?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some(name) = abandoned_name(file_name) else {
            continue;
        };
        #[cfg(not(windows))]
        let _ = name;
        if entry.file_type().context("inspect abandoned key entry")?.is_dir() {
            continue;
        }
        #[cfg(windows)]
        let path = {
            let path = dir.join(file_name);
            if file_name.ends_with(".tmp") {
                let tombstone = dir.join(format!(".{name}-{}.deleted", Uuid::new_v4()));
                rename_new(&path, &tombstone).context("retire abandoned key file")?;
                tombstone
            } else {
                path
            }
        };
        #[cfg(not(windows))]
        let path = entry.path();
        fs::remove_file(&path).with_context(|| format!("remove abandoned key file in {dir}"))?;
        #[cfg(unix)]
        {
            removed = true;
        }
    }
    #[cfg(unix)]
    if removed {
        sync_directory(dir)?;
    }
    Ok(())
}

#[cfg(unix)]
fn lock_directory(dir: &Utf8Path) -> anyhow::Result<File> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let path = dir.join(".device-key.lock");
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(&path)
        .with_context(|| format!("open key-directory lock {path}"))?;
    let metadata = file.metadata().context("inspect key-directory lock")?;
    ensure!(
        metadata.file_type().is_file(),
        "key-directory lock is not a regular file"
    );
    ensure_owner_only(&metadata)?;
    let deadline = Instant::now() + LOCK_TIMEOUT;
    loop {
        // SAFETY: The file descriptor stays open until this lock guard is dropped.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        let error = std::io::Error::last_os_error();
        if !matches!(error.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) {
            return Err(error).context("lock key directory");
        }
        wait_for_lock(deadline)?;
    }
}

#[cfg(windows)]
fn lock_directory(dir: &Utf8Path) -> anyhow::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;

    use windows::Win32::Foundation::ERROR_SHARING_VIOLATION;
    use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    let path = dir.join(".device-key.lock");
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
    let sharing_violation = i32::try_from(ERROR_SHARING_VIOLATION.0)?;
    let deadline = Instant::now() + LOCK_TIMEOUT;
    loop {
        match options.open(&path) {
            Ok(file) => {
                ensure!(
                    file.metadata()?.file_type().is_file(),
                    "key-directory lock is not a regular file"
                );
                return Ok(file);
            }
            Err(error) if error.kind() == ErrorKind::NotFound => match create_restricted_file(&path) {
                Ok(file) => return Ok(file),
                Err(create_error) if fs::symlink_metadata(&path).is_ok() => {
                    let _ = create_error;
                    wait_for_lock(deadline)?;
                }
                Err(error) => return Err(error).context("create key-directory lock"),
            },
            Err(error) if error.raw_os_error() == Some(sharing_violation) => {
                wait_for_lock(deadline)?;
            }
            Err(error) => return Err(error).with_context(|| format!("open key-directory lock {path}")),
        }
    }
}

fn wait_for_lock(deadline: Instant) -> anyhow::Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    ensure!(
        !remaining.is_zero(),
        "timed out waiting for key-directory lock after five seconds"
    );
    std::thread::sleep(remaining.min(LOCK_RETRY_INTERVAL));
    Ok(())
}

#[cfg(unix)]
fn link_count(file: &File) -> anyhow::Result<u64> {
    use std::os::unix::fs::MetadataExt as _;

    Ok(file.metadata().context("inspect key file links")?.nlink())
}

#[cfg(windows)]
fn link_count(file: &File) -> anyhow::Result<u64> {
    use std::os::windows::io::AsRawHandle as _;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: The file handle is live and the output pointer is writable.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }
        .context("inspect key file links")?;
    Ok(u64::from(information.nNumberOfLinks))
}

#[cfg(unix)]
fn delete_key(dir: &Utf8Path, name: &str) -> anyhow::Result<()> {
    let path = key_path(dir, name);
    match fs::remove_file(&path) {
        Ok(()) => sync_directory(dir),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("delete key file {path}")),
    }
}

#[cfg(windows)]
fn delete_key(dir: &Utf8Path, name: &str) -> anyhow::Result<()> {
    let path = key_path(dir, name);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("inspect key file {path}")),
    }
    let tombstone = dir.join(format!(".{name}-{}.deleted", Uuid::new_v4()));
    rename_new(&path, &tombstone).with_context(|| format!("retire key file {path}"))?;
    fs::remove_file(&tombstone).with_context(|| format!("delete retired key file {tombstone}"))
}

#[cfg(unix)]
fn sync_directory(dir: &Utf8Path) -> anyhow::Result<()> {
    File::open(dir)
        .and_then(|file| file.sync_all())
        .with_context(|| format!("sync key directory {dir}"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rename_new(from: &Utf8Path, to: &Utf8Path) -> anyhow::Result<()> {
    use std::ffi::CString;

    let from_c = CString::new(from.as_str()).context("invalid source key path")?;
    let to_c = CString::new(to.as_str()).context("invalid destination key path")?;
    // The raw syscall avoids glibc's renameat2 wrapper, which requires glibc 2.28 (the release baseline is 2.27).
    // SAFETY: Both paths are NUL-terminated and point to live buffers.
    #[cfg(target_os = "linux")]
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from_c.as_ptr(),
            libc::AT_FDCWD,
            to_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    // SAFETY: Both paths are NUL-terminated and point to live buffers.
    #[cfg(target_os = "macos")]
    let status = unsafe { libc::renamex_np(from_c.as_ptr(), to_c.as_ptr(), libc::RENAME_EXCL) };
    if status == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP)
    ) {
        return link_new(from, to);
    }
    Err(error).context("rename key without replacement")
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn rename_new(from: &Utf8Path, to: &Utf8Path) -> anyhow::Result<()> {
    link_new(from, to)
}

#[cfg(unix)]
fn link_new(from: &Utf8Path, to: &Utf8Path) -> anyhow::Result<()> {
    fs::hard_link(from, to).context("install key without replacement")?;
    fs::remove_file(from).context("remove installed key's temporary name")
}

#[cfg(windows)]
fn rename_new(from: &Utf8Path, to: &Utf8Path) -> anyhow::Result<()> {
    use windows::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
    use windows::core::PCWSTR;

    let from = wide(from);
    let to = wide(to);
    // SAFETY: The two path buffers are valid NUL-terminated UTF-16 strings.
    unsafe {
        MoveFileExW(
            PCWSTR::from_raw(from.as_ptr()),
            PCWSTR::from_raw(to.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )
    }
    .context("rename key without replacement")
}

#[cfg(windows)]
fn wide(path: &Utf8Path) -> Vec<u16> {
    path.as_str().encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(unix)]
fn ensure_owner_only(metadata: &fs::Metadata) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    ensure!(metadata.permissions().mode() & 0o077 == 0, "key file is not owner-only");
    // SAFETY: Reading the current effective UID has no preconditions.
    let user = unsafe { libc::geteuid() };
    ensure!(
        owner_is_trusted(metadata.uid(), user),
        "key file owner is neither the process user nor root"
    );
    Ok(())
}

#[cfg(unix)]
pub(crate) fn owner_is_trusted(owner: libc::uid_t, user: libc::uid_t) -> bool {
    owner == user || owner == 0
}

#[cfg(windows)]
fn ensure_private_file(file: &File) -> anyhow::Result<()> {
    use std::os::windows::io::AsRawHandle as _;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{self, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};
    use windows::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;

    let handle = HANDLE(file.as_raw_handle());
    let mut volume_flags = 0;
    // SAFETY: The file handle is live and the volume-flags output pointer is writable.
    unsafe { GetVolumeInformationByHandleW(handle, None, None, None, Some(&mut volume_flags), None) }
        .context("inspect key file volume")?;
    ensure!(
        volume_supports_acls(volume_flags),
        "key file volume does not enforce ACLs"
    );

    let mut owner = Security::PSID::default();
    let mut raw = Security::PSECURITY_DESCRIPTOR::default();
    // SAFETY: The file handle is live and both output pointers are writable.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut raw),
        )
    };
    let descriptor = crate::windows_acl::OwnedDescriptor(raw);
    ensure!(status.0 == 0, "read key file ACL failed ({})", status.0);
    ensure!(!owner.0.is_null(), "key file has no owner");
    // SAFETY: GetSecurityInfo returned a live owner SID within the owned descriptor.
    let owner = unsafe { Sid::from_psid(owner) }.context("read key file owner")?;
    let user = win_api_wrappers::token::Token::current_process_token()
        .sid_and_attributes()
        .context("get process user SID")?
        .sid;
    let system = Sid::from_well_known(Security::WinLocalSystemSid, None).context("get SYSTEM SID")?;
    ensure!(trusted_owner(&owner, &user, &system), "key file owner is not trusted");
    let mut expected = vec![system.clone()];
    if user != system {
        expected.push(user);
    }
    crate::windows_acl::require_protected_dacl(descriptor.0, expected)
}

#[cfg(windows)]
fn trusted_owner(owner: &Sid, user: &Sid, system: &Sid) -> bool {
    owner == user || owner == system
}

#[cfg(windows)]
fn volume_supports_acls(flags: u32) -> bool {
    use win_api_wrappers::raw::Win32::System::SystemServices::FILE_PERSISTENT_ACLS;

    flags & FILE_PERSISTENT_ACLS != 0
}

#[cfg(not(windows))]
fn create_restricted_file(path: &Utf8Path) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.mode(0o600);
    }
    options.open(path).with_context(|| format!("create key file {path}"))
}

#[cfg(windows)]
fn create_restricted_file(path: &Utf8Path) -> anyhow::Result<File> {
    use win_api_wrappers::raw::Win32::Security::Authorization::GRANT_ACCESS;
    use win_api_wrappers::raw::Win32::Security::{self};
    use win_api_wrappers::raw::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use win_api_wrappers::security::acl::{Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee};
    use win_api_wrappers::security::attributes::SecurityAttributesInit;
    use win_api_wrappers::token::Token;

    let system = Sid::from_well_known(Security::WinLocalSystemSid, None).context("get SYSTEM SID")?;
    let user = Token::current_process_token()
        .sid_and_attributes()
        .context("get process user SID")?
        .sid;
    let entry = |sid| ExplicitAccess {
        access_permissions: FILE_ALL_ACCESS.0,
        access_mode: GRANT_ACCESS,
        inheritance: Security::NO_INHERITANCE,
        trustee: Trustee::Sid(sid),
    };
    let mut entries = vec![entry(system.clone())];
    if user != system {
        entries.push(entry(user.clone()));
    }
    let dacl = InheritableAcl {
        kind: InheritableAclKind::Protected,
        acl: Acl::new()
            .and_then(|acl| acl.set_entries(&entries))
            .context("build key file DACL")?,
    };
    let attributes = SecurityAttributesInit {
        owner: Some(user),
        dacl: Some(dacl),
        ..Default::default()
    }
    .init();
    win_api_wrappers::fs::create_file(path.as_std_path(), Some(&attributes))
        .with_context(|| format!("create key file {path}"))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use p256::ecdsa::signature::Verifier as _;

    use super::*;
    use crate::{KeyBackend, delete, generate, list, new_key_name, open};

    const TEST_PREFIX: &str = "devolutions-agent-test";

    struct KeyDirectory(Utf8PathBuf);

    impl KeyDirectory {
        fn new() -> anyhow::Result<Self> {
            let target = std::env::var("CARGO_TARGET_DIR")
                .map(Utf8PathBuf::from)
                .unwrap_or_else(|_| Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("target"));
            let dir = target.join("key-tests").join(Uuid::new_v4().to_string());
            fs::create_dir_all(&dir)?;
            Ok(Self(dir))
        }

        fn backend(&self) -> KeyBackend {
            KeyBackend::File { dir: self.0.clone() }
        }
    }

    impl Drop for KeyDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn round_trip_signature_and_delete() -> anyhow::Result<()> {
        let dir = KeyDirectory::new()?;
        let backend = dir.backend();
        let name = new_key_name(TEST_PREFIX);
        let key = generate(&backend, &name)?;
        let reopened = open(&backend, &name)?.context("generated key disappeared")?;
        // oracle: mutant a key reporting a name other than the one it was opened under
        assert_eq!(reopened.name(), name);
        // oracle: property round-trip
        assert_eq!(reopened.public_key(), key.public_key());
        assert_eq!(list(&backend, TEST_PREFIX)?, vec![name.clone()]);
        assert!(generate(&backend, &name).is_err());
        assert_eq!(
            open(&backend, &name)?
                .context("existing key was replaced")?
                .public_key(),
            key.public_key()
        );

        let message = b"file backend signatures";
        let raw = reopened.try_sign(message)?;
        // oracle: intent crates/device-key/INTENT.md §Signing
        reopened.public_key().verify(message, &raw)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = fs::metadata(key_path(&dir.0, &name))?.permissions().mode();
            // oracle: intent crates/device-key/INTENT.md §Access
            assert_eq!(mode & 0o077, 0);
        }

        drop(reopened);
        drop(key);
        delete(&backend, &name)?;
        delete(&backend, &name)?;
        assert!(open(&backend, &name)?.is_none());
        assert!(list(&backend, TEST_PREFIX)?.is_empty());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §File backend
    #[test]
    fn vector_key_file_signs_under_the_vector_public_key() -> anyhow::Result<()> {
        let dir = KeyDirectory::new()?;
        let backend = dir.backend();
        let name = new_key_name(TEST_PREFIX);
        let vector: serde_json::Value = serde_json::from_str(include_str!("../test-data/connect-vector.json"))?;
        let encoded = vector["private_key_pkcs8"]
            .as_str()
            .context("missing vector private key")?;
        let pkcs8 = Zeroizing::new(STANDARD.decode(encoded)?);
        let path = key_path(&dir.0, &name);
        let mut file = create_restricted_file(&path)?;
        file.write_all(&pkcs8)?;
        file.sync_all()?;
        drop(file);
        let public_key = VerifyingKey::from_sec1_bytes(
            &STANDARD.decode(
                vector["public_key_sec1"]
                    .as_str()
                    .context("missing vector public key")?,
            )?,
        )?;
        let key = open(&backend, &name)?.context("missing vector key")?;
        // oracle: reference docs/agent-identity/test-vectors.json
        assert_eq!(key.public_key(), public_key);
        let base = vector["signature_base"].as_str().context("missing signature base")?;
        let signature = key.try_sign(base.as_bytes())?;
        // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Conformance
        public_key.verify(base.as_bytes(), &signature)?;
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Key name
    #[test]
    fn invalid_names_are_refused_by_every_operation() -> anyhow::Result<()> {
        let dir = KeyDirectory::new()?;
        let backend = dir.backend();
        // The second name would be a valid file name, so only the name check can refuse it.
        for invalid in ["../invalid", "Uppercase_part"] {
            assert!(generate(&backend, invalid).is_err(), "{invalid}");
            assert!(open(&backend, invalid).is_err(), "{invalid}");
            assert!(delete(&backend, invalid).is_err(), "{invalid}");
        }
        assert!(list(&backend, "../").is_err());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn concurrent_generators_cannot_replace_a_key() -> anyhow::Result<()> {
        use std::sync::{Arc, Barrier};

        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let name = new_key_name(TEST_PREFIX);
        let barrier = Arc::new(Barrier::new(3));
        let spawn = |backend: KeyBackend, name: String, barrier: Arc<Barrier>| {
            std::thread::spawn(move || {
                barrier.wait();
                generate(&backend, &name).map(|key| key.public_key())
            })
        };
        let first = spawn(backend.clone(), name.clone(), Arc::clone(&barrier));
        let second = spawn(backend.clone(), name.clone(), Arc::clone(&barrier));
        barrier.wait();
        let first = first.join().map_err(|_| anyhow::anyhow!("first generator panicked"))?;
        let second = second
            .join()
            .map_err(|_| anyhow::anyhow!("second generator panicked"))?;
        assert_ne!(first.is_ok(), second.is_ok());
        let public_key = first.or(second)?;
        assert_eq!(
            open(&backend, &name)?.context("missing generated key")?.public_key(),
            public_key
        );
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn abandoned_key_material_is_removed_by_a_later_operation() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let name = new_key_name(TEST_PREFIX);
        let orphan = directory.0.join(format!(".{name}-{}.tmp", Uuid::new_v4()));
        let mut file = create_restricted_file(&orphan)?;
        file.write_all(b"unfinalized private key")?;
        file.sync_all()?;
        drop(file);

        let other_name = new_key_name("other");
        let other_orphan = directory.0.join(format!(".{other_name}-{}.deleted", Uuid::new_v4()));
        let mut file = create_restricted_file(&other_orphan)?;
        file.write_all(b"abandoned key material")?;
        file.sync_all()?;
        drop(file);

        assert!(list(&backend, TEST_PREFIX)?.is_empty());
        assert!(!orphan.exists());
        assert!(!other_orphan.exists());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Key name
    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn leftovers_of_the_longest_key_name_are_recognized() {
        let name = format!("{}_{}", "a".repeat(64), "b".repeat(128));
        let uuid = Uuid::new_v4();

        assert_eq!(abandoned_name(&format!(".{name}-{uuid}.tmp")), Some(name.as_str()));
        assert_eq!(abandoned_name(&format!(".{name}-{uuid}.deleted")), Some(name.as_str()));
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn listing_requires_the_exact_prefix_and_a_well_formed_name() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let name = new_key_name("scope");
        let other_name = new_key_name("scope-longer");
        generate(&backend, &name)?;
        generate(&backend, &other_name)?;
        create_restricted_file(&key_path(&directory.0, "scope_INVALID"))?;

        assert_eq!(list(&backend, "scope")?, vec![name]);
        assert_eq!(list(&backend, "scope-longer")?, vec![other_name]);
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn listing_splits_the_prefix_at_the_first_underscore() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let name = "scope_part_with_underscores";
        generate(&backend, name)?;

        assert_eq!(list(&backend, "scope")?, vec![name.to_owned()]);
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn a_missing_key_directory_holds_no_keys() -> anyhow::Result<()> {
        let root = KeyDirectory::new()?;
        let backend = KeyBackend::File {
            dir: root.0.join("missing"),
        };
        let name = new_key_name(TEST_PREFIX);

        assert!(open(&backend, &name)?.is_none());
        delete(&backend, &name)?;
        assert!(list(&backend, TEST_PREFIX)?.is_empty());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn a_temporary_written_under_the_lock_is_not_a_leftover() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        // The test holds the lock as a creator in another process would while it writes its temporary.
        let lock = lock_directory(&directory.0)?;
        let temporary = directory
            .0
            .join(format!(".{}-{}.tmp", new_key_name(TEST_PREFIX), Uuid::new_v4()));
        create_restricted_file(&temporary)?;
        let lister = std::thread::spawn(move || list(&backend, TEST_PREFIX));
        std::thread::sleep(Duration::from_millis(500));

        assert!(temporary.exists());
        drop(lock);
        lister.join().map_err(|_| anyhow::anyhow!("lister panicked"))??;
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn lock_wait_expires_and_a_later_operation_can_proceed() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let lock = lock_directory(&directory.0)?;
        let error = list(&directory.backend(), TEST_PREFIX)
            .err()
            .context("contended key-directory lock did not time out")?;
        // oracle: mutant a key-directory lock time-out reported as another failure
        assert!(
            error.to_string().contains("timed out waiting for key-directory lock"),
            "{error:#}"
        );
        drop(lock);
        assert!(list(&directory.backend(), TEST_PREFIX)?.is_empty());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn lock_wait_on_an_existing_lock_file_expires() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        // An earlier operation leaves the lock file behind, so the holder below opens it instead of creating it.
        list(&directory.backend(), TEST_PREFIX)?;
        let _lock = lock_directory(&directory.0)?;

        assert!(list(&directory.backend(), TEST_PREFIX).is_err());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Access
    #[cfg(unix)]
    #[test]
    fn key_files_must_not_be_readable_by_other_accounts() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let name = new_key_name(TEST_PREFIX);
        generate(&backend, &name)?;
        let path = key_path(&directory.0, &name);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        assert!(open(&backend, &name).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert!(open(&backend, &name)?.is_some());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Access
    #[cfg(unix)]
    #[test]
    fn only_the_caller_or_root_can_own_a_key_file() {
        assert!(owner_is_trusted(1000, 1000));
        assert!(owner_is_trusted(0, 1000));
        assert!(!owner_is_trusted(1001, 1000));
        assert!(!owner_is_trusted(1001, 0));
    }

    // oracle: intent crates/device-key/INTENT.md §Access
    // oracle: spec MS-FSCC §2.5.1
    #[cfg(windows)]
    #[test]
    fn key_files_require_persistent_volume_acls() {
        use win_api_wrappers::raw::Win32::System::SystemServices::FILE_PERSISTENT_ACLS;

        assert!(!volume_supports_acls(0));
        assert!(!volume_supports_acls(2));
        assert!(volume_supports_acls(FILE_PERSISTENT_ACLS));
    }

    // oracle: intent crates/device-key/INTENT.md §Access
    #[cfg(windows)]
    #[test]
    fn key_file_owner_must_be_process_user_or_system() -> anyhow::Result<()> {
        use win_api_wrappers::token::Token;
        use windows::Win32::Security;

        let system = Sid::from_well_known(Security::WinLocalSystemSid, None)?;
        let users = Sid::from_well_known(Security::WinBuiltinUsersSid, None)?;
        let user = Token::current_process_token().sid_and_attributes()?.sid;
        assert!(trusted_owner(&user, &user, &system));
        assert!(trusted_owner(&system, &user, &system));
        assert!(!trusted_owner(&users, &user, &system));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn nested_key_directories_are_owner_only() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let root = KeyDirectory::new()?;
        let identity_dir = root.0.join("identity");
        let keys_dir = identity_dir.join("keys");
        let backend = KeyBackend::File { dir: keys_dir.clone() };
        generate(&backend, &new_key_name(TEST_PREFIX))?;
        assert_eq!(fs::metadata(identity_dir)?.permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(keys_dir)?.permissions().mode() & 0o777, 0o700);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn existing_keys_work_under_execute_only_ancestor() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        struct RestorePermissions(Utf8PathBuf);

        impl Drop for RestorePermissions {
            fn drop(&mut self) {
                let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
            }
        }

        let root = KeyDirectory::new()?;
        let ancestor = root.0.join("execute-only");
        let keys = ancestor.join("keys");
        fs::create_dir_all(&keys)?;
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o300))?;
        let _restore = RestorePermissions(ancestor);
        let backend = KeyBackend::File { dir: keys };
        let name = new_key_name(TEST_PREFIX);
        generate(&backend, &name)?;
        assert!(open(&backend, &name)?.is_some());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[cfg(windows)]
    #[test]
    fn retired_key_is_discovered_after_interrupted_delete() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let name = new_key_name(TEST_PREFIX);
        generate(&backend, &name)?;
        let retired = directory.0.join(format!(".{name}-{}.deleted", Uuid::new_v4()));
        rename_new(&key_path(&directory.0, &name), &retired)?;

        assert!(open(&backend, &name)?.is_none());
        assert!(!retired.exists());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn hard_linked_key_file_cannot_be_opened() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let real_name = new_key_name(TEST_PREFIX);
        let alias = new_key_name(TEST_PREFIX);
        generate(&backend, &real_name)?;
        fs::hard_link(key_path(&directory.0, &real_name), key_path(&directory.0, &alias))?;
        assert!(open(&backend, &alias).is_err());
        assert!(open(&backend, &real_name).is_err());
        fs::remove_file(key_path(&directory.0, &alias))?;
        assert!(open(&backend, &real_name)?.is_some());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[cfg(windows)]
    #[test]
    fn a_key_file_held_exclusively_is_not_reported_missing() -> anyhow::Result<()> {
        use std::os::windows::fs::OpenOptionsExt as _;

        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let name = new_key_name(TEST_PREFIX);
        generate(&backend, &name)?;
        let _holder = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(key_path(&directory.0, &name))?;

        assert!(!matches!(open(&backend, &name), Ok(None)));
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Access
    #[cfg(windows)]
    #[test]
    fn a_key_file_another_account_can_read_cannot_be_opened() -> anyhow::Result<()> {
        use win_api_wrappers::raw::Win32::Security::Authorization::{GRANT_ACCESS, SE_FILE_OBJECT};
        use win_api_wrappers::raw::Win32::Security::{self, WinBuiltinUsersSid, WinLocalSystemSid};
        use win_api_wrappers::raw::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_GENERIC_READ};
        use win_api_wrappers::security::acl::{
            Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee, set_named_security_info,
        };
        use win_api_wrappers::str::U16CString;
        use win_api_wrappers::token::Token;

        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let name = new_key_name(TEST_PREFIX);
        generate(&backend, &name)?;
        let entry = |sid, access_permissions| ExplicitAccess {
            access_permissions,
            access_mode: GRANT_ACCESS,
            inheritance: Security::NO_INHERITANCE,
            trustee: Trustee::Sid(sid),
        };
        let user = Token::current_process_token().sid_and_attributes()?.sid;
        let dacl = InheritableAcl {
            kind: InheritableAclKind::Protected,
            acl: Acl::new()?.set_entries(&[
                entry(Sid::from_well_known(WinLocalSystemSid, None)?, FILE_ALL_ACCESS.0),
                entry(user, FILE_ALL_ACCESS.0),
                entry(Sid::from_well_known(WinBuiltinUsersSid, None)?, FILE_GENERIC_READ.0),
            ])?,
        };
        let path = U16CString::from_str(key_path(&directory.0, &name).as_str())?;
        set_named_security_info(&path, SE_FILE_OBJECT, None, None, Some(&dacl), None)?;

        assert!(open(&backend, &name).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn key_symlink_cannot_be_opened() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let real_name = new_key_name(TEST_PREFIX);
        let alias = new_key_name(TEST_PREFIX);
        generate(&backend, &real_name)?;
        std::os::unix::fs::symlink(key_path(&directory.0, &real_name), key_path(&directory.0, &alias))?;
        // oracle: intent crates/device-key/INTENT.md §Operations
        assert!(open(&backend, &alias).is_err());
        assert_eq!(list(&backend, TEST_PREFIX)?, vec![real_name.clone()]);
        // oracle: intent crates/device-key/INTENT.md §Operations
        delete(&backend, &alias)?;
        assert!(open(&backend, &real_name)?.is_some());
        Ok(())
    }
}
