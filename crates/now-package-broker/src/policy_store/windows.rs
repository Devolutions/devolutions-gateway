//! Windows filesystem primitives backing the policy store.
//!
//! Resolves and securely creates the default policy directory.
//! Verifies custom directories and their ancestor chains without modifying them.
//! Captures exact file state as an internal [`DiskFingerprint`] that `PolicyStore::token_for` converts into an opaque token.
//! Publishes crash-safe replacements within the hosting directory.
//!
//! Replacement observations retain the exact target without write or delete sharing.
//! Publication renames that handle to a reserved tombstone, then renames a flushed secure temporary handle to the final leaf without replacing any raced-in content.
//! A durable admin-only marker lets startup restore the exact tombstone or preserve a newer final file after interruption.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail, ensure};
use now_policy::PolicyDocument;
use now_policy_api::{
    API_VERSION_STR, InvalidPolicyDiagnostics, PolicyConfigurationSource, PolicyManagementState, PolicyReadOnlyReason,
    PolicyStoreToken, PolicyWriteCapability,
};
use sha2::{Digest as _, Sha256};
use win_api_wrappers::str::{U16CStrExt as _, U16CString};
use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE};
#[cfg(test)]
use windows::Win32::Storage::FileSystem::MOVEFILE_REPLACE_EXISTING;
use windows::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FILE_DISPOSITION_INFO_EX_FLAGS,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_READ,
    FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_RENAME_INFO_0, FILE_SHARE_DELETE, FILE_SHARE_NONE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, FileDispositionInfoEx, FileRenameInfo, FileRenameInfoEx, GetVolumeInformationW,
    GetVolumePathNameW, MOVE_FILE_FLAGS, MOVEFILE_WRITE_THROUGH, MoveFileExW, READ_CONTROL, SetFileInformationByHandle,
};

use crate::policy_security::{self, FileIdentity};
use crate::policy_store::validation;

/// Base file name for the policy file (a fixed name inside its dedicated directory).
pub(super) const POLICY_FILE_NAME: &str = "package-broker-policy.json";
const FILE_SYNCHRONIZE: u32 = 0x0010_0000;

/// Default dedicated directory hosting the policy file: `%PROGRAMDATA%\Devolutions\PackageBroker`.
///
/// Deliberately a top-level sibling of `%PROGRAMDATA%\Devolutions\Agent`, not a
/// subdirectory of it: `Agent` is shared with unrelated Agent features and its own
/// ancestor-security check must tolerate whatever grants those features require there,
/// which can never be proven as strict as the dedicated policy directory itself needs
/// its *own* ancestor chain to be (see [`policy_security::verify_policy_ancestor_chain`]).
/// A directory nested under `Agent` would inherit `Agent` as an ancestor and could never
/// honestly advertise [`PolicyWriteCapability::Writable`]. This dedicated root is created
/// and secured by this crate alone (both by the Agent installer at install time and, as
/// a fallback/self-heal, by this function's own caller at runtime), so it never has to
/// depend on -- or touch -- the shared `Agent` directory's ACL at all.
pub(super) fn default_policy_dir() -> PathBuf {
    let program_data = std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    program_data.join("Devolutions").join("PackageBroker")
}

/// Default policy file path inside [`default_policy_dir`].
pub(super) fn default_policy_path() -> PathBuf {
    default_policy_dir().join(POLICY_FILE_NAME)
}

/// Validate the *shape* of a configured policy path before ever touching disk: it must
/// be an absolute path naming a `.json` (case-insensitive) leaf file, with no `.`/`..`
/// component anywhere and no trailing directory separator. Never applied to the default
/// path, which this crate builds and fully controls itself.
///
/// This is deliberately independent of any filesystem access (a relative path must never
/// be silently resolved against the process's current directory by some later `open`
/// call) and independent of JSON-vs-other-format content sniffing: the extension alone
/// decides, so a legacy `.yaml`/`.yml` (or extensionless) configured path is rejected
/// up front rather than discovered only when its content fails to parse as JSON.
pub(super) fn validate_configured_path_shape(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("configured policy path must be absolute: {}", path.display()));
    }

    let raw = path.as_os_str().to_string_lossy();
    if raw.ends_with('\\') || raw.ends_with('/') {
        return Err(format!(
            "configured policy path must not end with a path separator: {}",
            path.display()
        ));
    }

    // Detected on the *raw* configured string, not via `path.components()`: per
    // `Path::components()`'s own documented normalization, an intermediate `.` segment
    // (e.g. `C:\foo\.\bar.json`) is silently normalized away and never surfaces as a
    // `Component::CurDir` at all, so a components-based check would never catch it.
    for segment in raw.split(['\\', '/']) {
        if segment == "." {
            return Err(format!(
                "configured policy path must not contain a '.' component: {}",
                path.display()
            ));
        }
        if segment == ".." {
            return Err(format!(
                "configured policy path must not contain a '..' component: {}",
                path.display()
            ));
        }
    }

    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(format!("configured policy path must name a file: {}", path.display()));
    };

    let has_json_extension = Path::new(file_name)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
    if !has_json_extension {
        return Err(format!(
            "configured policy path must name a '.json' file (case-insensitive), got '{file_name}'; \
             the package broker no longer supports any other format"
        ));
    }

    Ok(())
}

/// Outcome of the one-time filesystem atomic-replace capability probe, classified into
/// the advisory reason it would map to if unwritable.
type ProbeResult = Result<(), (PolicyReadOnlyReason, String)>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AtomicityProbeKey {
    identity: FileIdentity,
    security_digest: [u8; 32],
}

/// Caches successful filesystem atomic-replace probes by directory identity and security digest.
/// Failed probes are retried on every observation.
pub(super) struct AtomicityProbeCache {
    cached_success: std::sync::Mutex<Option<AtomicityProbeKey>>,
}

impl AtomicityProbeCache {
    pub(super) fn new() -> Self {
        Self {
            cached_success: std::sync::Mutex::new(None),
        }
    }

    /// Returns the cached probe result for `dir`/`dir_identity`/`dir_security_digest`,
    /// re-probing (and updating the cache) if this is the first call or either the
    /// directory's identity or its own security digest no longer matches what was last
    /// cached.
    fn get_or_probe(&self, dir: &Path, dir_identity: FileIdentity, dir_security_digest: [u8; 32]) -> ProbeResult {
        let key = AtomicityProbeKey {
            identity: dir_identity,
            security_digest: dir_security_digest,
        };
        let mut cached_success = self.cached_success.lock().expect("atomicity probe cache lock poisoned");

        if cached_success.as_ref() == Some(&key) {
            return Ok(());
        }

        let result = probe_write_capability(dir).map_err(|error| {
            let reason = if error.downcast_ref::<UnsupportedFilesystem>().is_some() {
                PolicyReadOnlyReason::UnsupportedFileSystem
            } else {
                PolicyReadOnlyReason::InsufficientPermissions
            };
            (reason, format!("{error:#}"))
        });
        if result.is_ok() {
            *cached_success = Some(key);
        } else {
            *cached_success = None;
        }
        result
    }
}

/// Open a directory without following reparse points, sharing read/write but not delete,
/// so the object cannot be renamed or deleted while this handle (and any later handle
/// derived from re-verifying it) is alive.
fn open_directory_no_reparse(path: &Path) -> anyhow::Result<File> {
    OpenOptions::new()
        .access_mode((FILE_READ_ATTRIBUTES | FILE_TRAVERSE | READ_CONTROL).0 | FILE_SYNCHRONIZE)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))
}

/// Open `path`, confirm it is a genuine directory (not a reparse point standing in for
/// one), and resolve its final path from the handle.
///
/// Fails closed on any ambiguity: missing path, wrong object type, or reparse point.
///
/// This only verifies `path` itself; callers additionally verify the ancestor chain with
/// [`policy_security::verify_policy_ancestor_chain`], so an untrusted principal further
/// up the tree (e.g. on the shared `%ProgramData%\Devolutions\Agent` parent, where the
/// installer grants `LOCAL SERVICE` write access for unrelated Agent features) cannot
/// delete or replace this directory out from under an already-verified identity check.
fn open_and_verify_directory_identity(path: &Path) -> anyhow::Result<(File, PathBuf)> {
    let handle = open_directory_no_reparse(path)?;

    let attributes = handle
        .metadata()
        .with_context(|| format!("failed to query metadata for {}", path.display()))?
        .file_attributes();

    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        bail!(
            "{} is a reparse point (symlink/junction); the policy directory must be a real directory",
            path.display()
        );
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
        bail!("{} is not a directory", path.display());
    }

    let final_path = policy_security::final_path_from_handle(&handle)
        .with_context(|| format!("failed to resolve {}", path.display()))?;

    Ok((handle, final_path))
}

/// Holds a verified hosting directory open from observation through handle-based publication.
/// The handle blocks replacement of that object and anchors relative transaction names.
/// Test storage models the same checks with identity and security generations.
pub(super) struct VerifiedHostingDirectory {
    handle: Option<File>,
    canonical_path: PathBuf,
    identity: FileIdentity,
    security_digest: [u8; 32],
}

impl VerifiedHostingDirectory {
    /// The canonical directory path resolved from the verified handle when this was
    /// built (item 22).
    pub(super) fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    /// The hosting directory's identity as observed when this was built.
    pub(super) fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Build a synthetic instance for `FakePolicyStorage`
    /// (`crate::policy_store::tests::FakePolicyStorage`), which models the hosting
    /// directory purely with generation counters and has no real Windows directory
    /// handle to hold.
    #[cfg(test)]
    pub(super) fn for_fake_storage(canonical_path: PathBuf, identity: FileIdentity, security_digest: [u8; 32]) -> Self {
        Self {
            handle: None,
            canonical_path,
            identity,
            security_digest,
        }
    }

    #[cfg(test)]
    pub(super) fn matches_fake_state(&self, identity_generation: u32, security_generation: u32) -> bool {
        self.identity == test_identity(identity_generation)
            && self.security_digest == test_security_digest(security_generation)
    }

    /// Re-verify that this held-open directory still has the identity and security state
    /// observed for the transaction.
    fn verify_unchanged(&self) -> anyhow::Result<[u8; 32]> {
        let handle = self.handle.as_ref().expect(
            "BUG: reverify is only ever called by the real Windows write path (atomic_replace/atomic_create), \
             which always holds a real handle",
        );
        policy_security::verify_policy_directory_security(handle)
            .context("hosting directory failed security verification during post-write verification")?;
        let identity = policy_security::file_identity(handle)
            .context("failed to re-query hosting directory identity during post-write verification")?;
        ensure!(
            identity == self.identity,
            "hosting directory identity changed unexpectedly while its handle was held open"
        );
        let current_security = policy_security::security_state_digest(handle)
            .context("failed to recompute hosting directory security digest during write verification")?;
        ensure!(
            current_security == self.security_digest,
            "hosting directory security changed while its handle was held open"
        );
        Ok(current_security)
    }
}

/// Create the dedicated default policy directory (if it does not already exist) with an
/// admin-only ACL established atomically at creation, then verify it.
///
/// The ACL is passed as explicit `SECURITY_ATTRIBUTES` to `CreateDirectoryW` itself (see
/// [`policy_security::admin_only_security_attributes`]), so there is no window between
/// creation and securing it during which an untrusted principal could race the directory.
///
/// The broker owns this directory end-to-end, but unlike a naive "create, then chmod"
/// approach, an *existing* directory (e.g. from a previous run) is only ever verified,
/// never rewritten: if it already exists with an insecure ACL (inherited, tampered with,
/// or planted by a race/reparse before this call ever ran), this fails closed instead of
/// silently repairing it, since repairing would extend trust to whatever object happened
/// to already occupy the path.
///
/// Returns the canonical directory path resolved from the verified handle (item 22) and
/// a digest summarizing the verified ancestor chain (item 20), for folding into
/// [`DiskFingerprint`].
fn ensure_default_directory_secured(dir: &Path) -> anyhow::Result<(PathBuf, [u8; 32])> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create ancestor directories for {}", dir.display()))?;
    }

    let security_attributes = policy_security::admin_only_security_attributes(true)
        .context("build admin-only security attributes for the policy directory")?;

    if let Err(create_error) = win_api_wrappers::fs::create_directory(dir, Some(&security_attributes)) {
        // Whatever the reason `CreateDirectoryW` failed (already exists, or lost a race
        // with another process), only a directory actually present at this exact path
        // changes the outcome, and even then only via the verification below -- never by
        // trusting the create call's failure reason alone.
        if !dir.is_dir() {
            return Err(create_error).with_context(|| format!("failed to create {}", dir.display()));
        }
    }

    let (handle, final_path) = open_and_verify_directory_identity(dir)?;
    policy_security::verify_policy_directory_security(&handle).context(
        "an existing policy directory does not meet the required security bar; \
         it was not created by this call and will not be silently repaired",
    )?;
    let ancestor_security_digest = policy_security::verify_policy_ancestor_chain(&final_path, "policy directory")?;

    Ok((final_path, ancestor_security_digest))
}

/// Verify (never rewrite) that a custom-configured policy directory already meets the
/// same security bar as the dedicated default directory, including its ancestor chain.
///
/// Returns the canonical directory path resolved from the verified handle (item 22) and
/// a digest summarizing the verified ancestor chain (item 20), for folding into
/// [`DiskFingerprint`].
fn verify_custom_directory_secure(dir: &Path) -> anyhow::Result<(PathBuf, [u8; 32])> {
    let (handle, final_path) = open_and_verify_directory_identity(dir)?;
    policy_security::verify_policy_directory_security(&handle)?;
    let ancestor_security_digest = policy_security::verify_policy_ancestor_chain(&final_path, "policy directory")?;
    Ok((final_path, ancestor_security_digest))
}

/// Marker error indicating [`probe_write_capability`] failed because the hosting
/// filesystem is not known to support the atomic same-directory replacement semantics
/// `atomic_replace` depends on (as opposed to an ACL/quota/permission problem).
#[derive(Debug)]
struct UnsupportedFilesystem(String);

impl std::fmt::Display for UnsupportedFilesystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "filesystem '{}' is not known to support atomic same-directory replacement",
            self.0
        )
    }
}

impl std::error::Error for UnsupportedFilesystem {}

/// Filesystem names known to support atomic same-directory handle renames.
/// Conservative by design: an unrecognized filesystem is treated as unsupported.
const ATOMIC_REPLACE_CAPABLE_FILESYSTEMS: &[&str] = &["NTFS", "ReFS"];

/// Verifies that `dir` supports the handle-based tombstone and create-new publication semantics required by [`atomic_replace`].
///
/// First, it conservatively classifies the filesystem because some filesystems and filter drivers silently use non-atomic copy-then-delete renames.
/// It then runs a nondestructive probe of the exact rename primitives against uniquely named disposable files.
fn probe_write_capability(dir: &Path) -> anyhow::Result<()> {
    let filesystem = volume_filesystem_name(dir).context("query volume filesystem")?;
    if !ATOMIC_REPLACE_CAPABLE_FILESYSTEMS
        .iter()
        .any(|name| name.eq_ignore_ascii_case(&filesystem))
    {
        return Err(UnsupportedFilesystem(filesystem).into());
    }

    let probe_id = uuid::Uuid::new_v4();
    let source_path = dir.join(format!(".package-broker-write-probe-{probe_id}-a.tmp"));
    let target_path = dir.join(format!(".package-broker-write-probe-{probe_id}-b.tmp"));
    let tombstone_path = dir.join(format!(".package-broker-write-probe-{probe_id}-old.tmp"));

    let probe_result = (|| -> anyhow::Result<()> {
        std::fs::write(&source_path, b"probe-source").context("create write-capability probe source file")?;
        std::fs::write(&target_path, b"probe-target").context("create write-capability probe target file")?;
        let dir_handle = open_directory_no_reparse(dir)?;
        let source = open_transaction_file(&source_path)?;
        let target = open_transaction_file(&target_path)?;
        rename_file_handle(
            &target,
            &dir_handle,
            tombstone_path.file_name().expect("probe path has leaf"),
        )
        .context("probe target-to-tombstone handle rename")?;
        rename_file_handle(
            &source,
            &dir_handle,
            target_path.file_name().expect("probe path has leaf"),
        )
        .context("probe create-new handle publication")?;
        let replaced = std::fs::read(&target_path).context("read write-capability probe result")?;
        ensure!(
            replaced == b"probe-source",
            "atomic replacement did not take effect on this filesystem"
        );
        delete_file_handle(&target).context("probe POSIX tombstone unlink")?;
        drop(target);
        ensure!(
            !tombstone_path.exists(),
            "POSIX tombstone unlink did not remove the directory entry"
        );
        drop(source);
        Ok(())
    })();

    // Cleanup is mandatory, not best-effort (item 28): both paths are always attempted
    // regardless of the probe's own outcome or each other, and any leftover probe file
    // -- other than one that was never actually created (tolerated only as `NotFound`)
    // -- itself disqualifies this directory from `Writable`, aggregated into the overall
    // result rather than silently logged and ignored. A probe that leaves a stray file
    // behind in the configured policy directory is not actually side-effect-free,
    // whatever its rename result reported.
    let source_cleanup = cleanup_probe_file(&source_path);
    let target_cleanup = cleanup_probe_file(&target_path);
    let tombstone_cleanup = cleanup_probe_file(&tombstone_path);

    probe_result
        .and(source_cleanup)
        .and(target_cleanup)
        .and(tombstone_cleanup)
}

/// Remove a write-capability probe file, tolerating only the file already being absent
/// (the expected outcome for `source_path` after a successful replace, which consumes
/// it). Any other failure (permission denied, sharing violation, ...) means a stray
/// probe file was left behind in the configured policy directory, which must itself
/// disqualify the directory from `Writable` (item 28): the specific OS error is only
/// ever traced, and the returned error is a single sanitized, aggregated message never
/// exposed through the management API.
fn cleanup_probe_file(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "Failed to remove write-capability probe file");
            bail!("failed to remove a write-capability probe file left behind in the policy directory")
        }
    }
}

/// Classify the filesystem hosting `dir` (e.g. `"NTFS"`, `"ReFS"`, `"FAT32"`).
fn volume_filesystem_name(dir: &Path) -> anyhow::Result<String> {
    let dir_wide = U16CString::from_os_str(dir.as_os_str()).context("directory path contains an interior NUL")?;

    let mut volume_root = vec![0u16; 512];
    // SAFETY: `dir_wide` is a valid NUL-terminated wide string live for the call, and
    // `volume_root` is a live, writable buffer.
    unsafe { GetVolumePathNameW(dir_wide.as_pcwstr(), &mut volume_root) }.context("GetVolumePathNameW failed")?;

    let mut filesystem_name = vec![0u16; 261];
    // SAFETY: `volume_root` is a valid, NUL-terminated wide root path as returned by
    // `GetVolumePathNameW` above, live for the call; `filesystem_name` is a live, writable
    // buffer; every other output parameter is `None`, which the API accepts.
    unsafe {
        GetVolumeInformationW(
            windows::core::PCWSTR(volume_root.as_ptr()),
            None,
            None,
            None,
            None,
            Some(&mut filesystem_name),
        )
    }
    .context("GetVolumeInformationW failed")?;

    let nul_at = filesystem_name
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(filesystem_name.len());
    Ok(String::from_utf16_lossy(&filesystem_name[..nul_at]))
}

/// Internal identity of the object, content, and verified security state observed on disk.
/// Fingerprint changes rotate the opaque store token; fingerprints are never serialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DiskFingerprint {
    /// A successfully parsed, security-verified, and semantically-valid policy file.
    Active {
        parent: FileIdentity,
        target: FileIdentity,
        content_digest: [u8; 32],
        security_digest: [u8; 32],
        /// Digest of the hosting directory's own owner and DACL.
        dir_security_digest: [u8; 32],
        ancestor_security_digest: [u8; 32],
    },
    /// No file at the resolved path. Carries the verified identity of the parent
    /// directory (its own security digest, and its ancestor chain's security summary),
    /// so a parent replacement (or a differently identified custom path) is still
    /// distinguishable even though there is no leaf to identify.
    /// `parent`/`dir_security_digest`/`ancestor_security_digest` are `None` when even the
    /// directory itself could not be verified (its own security/ancestor check failed):
    /// still Missing -- there is no leaf to distrust either way -- but `path` (the
    /// canonical, or best-effort literal, configured path) still prevents two distinct
    /// configured paths in that situation from colliding (mirrors `Invalid::path`; item
    /// 15).
    Missing {
        path: PathBuf,
        parent: Option<FileIdentity>,
        dir_security_digest: Option<[u8; 32]>,
        ancestor_security_digest: Option<[u8; 32]>,
    },
    /// A file exists but could not be trusted or activated: unreadable, failed storage
    /// security validation, not valid JSON matching the expected schema, or (structurally
    /// valid JSON that is nonetheless) semantically invalid.
    ///
    /// Every component is independently optional because how far observation got before
    /// failing determines what could actually be resolved (e.g. a target that cannot
    /// even be opened has no identity or content digest yet). `path` -- the canonical
    /// configured path, or the best-effort literal one when it could not be
    /// canonicalized at all -- is always present precisely so that two distinct
    /// configured paths that both fail identically (e.g. both "parent cannot be opened",
    /// with no identity available to distinguish them) never collide (item 15).
    Invalid {
        path: PathBuf,
        parent: Option<FileIdentity>,
        dir_security_digest: Option<[u8; 32]>,
        ancestor_security_digest: Option<[u8; 32]>,
        target: Option<FileIdentity>,
        content_digest: Option<[u8; 32]>,
        security_digest: Option<[u8; 32]>,
        /// Stable internal failure reason (never itself exposed by the management API;
        /// see `validation::disk_failure_finding`), included so distinct reasons at the
        /// exact same path/identity still rotate the token (e.g. a file that was
        /// insecurely-stored becomes merely malformed after its ACL is fixed).
        reason: validation::DiskFailureReason,
    },
}

#[cfg(test)]
impl DiskFingerprint {
    /// Build a synthetic fingerprint for the in-memory `FakePolicyStorage` test double,
    /// which has no real Windows file handles to derive identity from.
    ///
    /// `target_generation` and `parent_generation` stand in for [`FileIdentity`]: bump
    /// either to simulate the corresponding real-world object being deleted and recreated
    /// (even with byte-identical content), and `acl_generation` to simulate a
    /// security-descriptor change with no content change (folded into both the target's
    /// own security digest and the ancestor-chain summary, since the fake models "some
    /// security-relevant state changed" as a single dimension rather than distinguishing
    /// which level of the tree).
    /// `dir_acl_generation` is independent so a hosting-directory-only ACL change (with no
    /// leaf or ancestor-chain change) still rotates the fingerprint on its own.
    pub(super) fn test_active(
        content: &[u8],
        target_generation: u32,
        parent_generation: u32,
        acl_generation: u32,
        dir_acl_generation: u32,
    ) -> Self {
        Self::Active {
            parent: test_identity(parent_generation),
            target: test_identity(target_generation),
            content_digest: sha256_digest(content),
            security_digest: sha256_digest(&acl_generation.to_le_bytes()),
            dir_security_digest: sha256_digest(&dir_acl_generation.to_le_bytes()),
            ancestor_security_digest: sha256_digest(&acl_generation.to_le_bytes()),
        }
    }

    pub(super) fn test_missing(parent_generation: u32, dir_acl_generation: u32) -> Self {
        Self::Missing {
            path: PathBuf::from(r"C:\fake\package-broker-policy.json"),
            parent: Some(test_identity(parent_generation)),
            dir_security_digest: Some(test_security_digest(dir_acl_generation)),
            ancestor_security_digest: Some(sha256_digest(b"test-ancestor-security")),
        }
    }

    pub(super) fn test_invalid(
        content: &[u8],
        target_generation: u32,
        parent_generation: u32,
        acl_generation: u32,
        dir_acl_generation: u32,
    ) -> Self {
        Self::Invalid {
            path: PathBuf::from(r"C:\fake\package-broker-policy.json"),
            parent: Some(test_identity(parent_generation)),
            dir_security_digest: Some(test_security_digest(dir_acl_generation)),
            ancestor_security_digest: Some(test_security_digest(acl_generation)),
            target: Some(test_identity(target_generation)),
            content_digest: Some(sha256_digest(content)),
            security_digest: Some(test_security_digest(acl_generation)),
            reason: validation::DiskFailureReason::MalformedContent,
        }
    }
}

#[cfg(test)]
pub(super) fn test_identity(generation: u32) -> FileIdentity {
    let mut file_id = [0u8; 16];
    file_id[..4].copy_from_slice(&generation.to_le_bytes());
    FileIdentity {
        volume_serial: 0,
        file_id,
    }
}

#[cfg(test)]
pub(super) fn test_security_digest(generation: u32) -> [u8; 32] {
    sha256_digest(&generation.to_le_bytes())
}

pub(super) fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Exact policy file handle retained from a write transaction's token observation through publication.
pub(super) enum RetainedPolicyFile {
    Real(File),
    #[cfg(test)]
    Fake(Box<DiskFingerprint>),
}

impl RetainedPolicyFile {
    pub(super) fn verify_matches(&self, expected: &DiskFingerprint) -> anyhow::Result<()> {
        #[cfg(test)]
        if let Self::Fake(observed) = self {
            ensure!(
                observed.as_ref() == expected,
                "fake retained target does not match the observed fingerprint"
            );
            return Ok(());
        }
        let handle = match self {
            Self::Real(handle) => handle,
            #[cfg(test)]
            Self::Fake(_) => unreachable!("fake retained target returned before Windows verification"),
        };
        let (expected_target, expected_content, expected_security) = match expected {
            DiskFingerprint::Active {
                target,
                content_digest,
                security_digest,
                ..
            } => (*target, *content_digest, *security_digest),
            DiskFingerprint::Invalid {
                target: Some(target),
                content_digest: Some(content_digest),
                security_digest: Some(security_digest),
                ..
            } => (*target, *content_digest, *security_digest),
            _ => bail!("write observation did not retain a complete target fingerprint"),
        };

        ensure!(
            policy_security::file_identity(handle)? == expected_target,
            "retained policy file identity changed after token validation"
        );
        ensure!(
            policy_security::file_link_count(handle)? == 1,
            "retained policy file acquired another hard link after token validation"
        );
        policy_security::verify_policy_file_security(handle)
            .context("retained policy file security changed after token validation")?;
        ensure!(
            policy_security::security_state_digest(handle)? == expected_security,
            "retained policy file security digest changed after token validation"
        );

        let bytes = read_file_from_start(handle)?;
        ensure!(
            sha256_digest(&bytes) == expected_content,
            "retained policy file content changed after token validation"
        );
        Ok(())
    }

    fn handle(&self) -> &File {
        match self {
            Self::Real(handle) => handle,
            #[cfg(test)]
            Self::Fake(_) => panic!("fake retained targets have no Windows handle"),
        }
    }

    #[cfg(test)]
    fn into_handle(self) -> File {
        match self {
            Self::Real(handle) => handle,
            Self::Fake(_) => panic!("fake retained targets have no Windows handle"),
        }
    }

    #[cfg(test)]
    pub(super) fn for_fake(fingerprint: DiskFingerprint) -> Self {
        Self::Fake(Box::new(fingerprint))
    }
}

/// Exact observed state of the policy file on disk, together with the write capability
/// resolved *as part of the same observation* (item 20/26): capability is never derived
/// from a separately cached snapshot, so it can never silently drift from the state it
/// describes. A malformed-but-securely-stored file (capability follows the directory's
/// own resolved capability, allowing Repair) is distinguished from an insecure/unreadable
/// target (capability is forced to `ReadOnly`/`UnsafePath` regardless of the directory's
/// own capability, and Repair therefore fails): see item 26.
pub(super) struct DiskObservation {
    pub state: PolicyManagementState,
    pub policy: Option<PolicyDocument>,
    pub invalid_diagnostics: Option<InvalidPolicyDiagnostics>,
    pub fingerprint: DiskFingerprint,
    pub write_capability: PolicyWriteCapability,
    pub read_only_reason: Option<PolicyReadOnlyReason>,
    /// Canonical resolved path (parent resolved from a verified handle, joined with the
    /// exact configured `.json` leaf name; see item 22), or the best-effort literal
    /// configured path when it could not be canonicalized at all (an unsupported shape,
    /// or a directory/ancestor chain that failed verification before any handle could be
    /// resolved). `PolicyStore` stores/displays/uses only this value from here on --
    /// never re-deriving it from the original configuration string -- for observation,
    /// the watcher, the store token, audit, and writes.
    pub canonical_path: PathBuf,
    /// The hosting directory verified during this observation.
    /// Writable observations keep it alive through publication and postverification.
    pub hosting_dir: Option<VerifiedHostingDirectory>,
    /// Exact target handle retained by write observations.
    pub retained_target: Option<RetainedPolicyFile>,
}

/// Context accumulated while observation fails partway through, for building the most
/// complete [`DiskFingerprint::Invalid`] the failure allows (item 15): every field is
/// optional because how far observation got before failing determines what could
/// actually be resolved (e.g. a directory that cannot even be opened has no parent
/// identity to report).
#[derive(Default)]
struct InvalidContext {
    parent: Option<FileIdentity>,
    dir_security_digest: Option<[u8; 32]>,
    ancestor_security_digest: Option<[u8; 32]>,
    target: Option<FileIdentity>,
    content_digest: Option<[u8; 32]>,
    security_digest: Option<[u8; 32]>,
}

fn resolved_policy_path_matches(resolved: &Path, canonical_parent: &Path, configured_leaf: &OsStr) -> bool {
    let Some(resolved_parent) = resolved.parent() else {
        return false;
    };
    let Some(resolved_leaf) = resolved.file_name() else {
        return false;
    };

    policy_security::paths_match_case_insensitive(resolved_parent, canonical_parent)
        && paths_component_matches_case_insensitive(resolved_leaf, configured_leaf)
}

fn paths_component_matches_case_insensitive(a: &OsStr, b: &OsStr) -> bool {
    policy_security::os_strings_match_case_insensitive(a, b)
}

/// Observe the exact current disk state of the configured policy file.
///
/// Resolves (and, for the default path, idempotently creates) the canonical directory
/// and re-verifies its shape/security/ancestor chain and write capability on every call
/// (item 20): only the one-time, side-effecting filesystem atomic-replace probe is
/// cached (`probe_cache`; see [`AtomicityProbeCache`]), never the cheap security checks.
///
/// The hosting directory is opened without delete sharing and held open for the whole
/// observation: both to fold its identity into the fingerprint (detecting the directory
/// itself being replaced) and so it cannot be deleted or renamed out from under the
/// target file while it is being examined. The leaf file is opened without following
/// reparse points, and its own handle-resolved final path must match the canonical
/// directory and expected leaf name, case-insensitively (item 22): a reparse point or
/// hard-link alias standing in for the configured file is never trusted, whatever its
/// content, but a leaf whose on-disk casing merely differs from the configured path
/// (Windows filesystems are case-insensitive but case-preserving) is accepted as the same
/// file. Security
/// is verified on the target's open handle before any content is trusted, and content is
/// read from that same handle, so the verified security descriptor always belongs to the
/// exact bytes subsequently parsed (no TOCTOU window via file replacement). A
/// structurally valid document is additionally, authoritatively revalidated the same
/// deterministic way a submitted draft is (item 30): a committed file is never activated
/// on structural parseability alone.
///
/// A configured path whose shape/extension is unsupported (item 18/22) -- relative,
/// empty/non-file leaf, trailing separator, `.`/`..` component, or an extension other
/// than `.json` -- is reported with the shared contract's dedicated
/// [`PolicyReadOnlyReason::UnsupportedFormat`].
pub(super) fn observe(
    source: PolicyConfigurationSource,
    configured_path: &Path,
    probe_cache: &AtomicityProbeCache,
) -> DiskObservation {
    observe_impl(source, configured_path, probe_cache, false)
}

pub(super) fn observe_for_write(
    source: PolicyConfigurationSource,
    configured_path: &Path,
    probe_cache: &AtomicityProbeCache,
) -> DiskObservation {
    observe_impl(source, configured_path, probe_cache, true)
}

fn observe_impl(
    source: PolicyConfigurationSource,
    configured_path: &Path,
    probe_cache: &AtomicityProbeCache,
    retain_target: bool,
) -> DiskObservation {
    if let Err(diagnostic) = validate_configured_path_shape(configured_path) {
        tracing::warn!(
            path = %configured_path.display(), reason = %diagnostic,
            "Configured policy path has an unsupported shape or extension"
        );
        return invalid_observation(
            configured_path,
            validation::DiskFailureReason::UnsupportedFormat,
            InvalidContext::default(),
            PolicyWriteCapability::ReadOnly,
            Some(PolicyReadOnlyReason::UnsupportedFormat),
        );
    }

    let dir = configured_path.parent().unwrap_or_else(|| Path::new("."));
    let leaf_name = configured_path
        .file_name()
        .expect("shape validation already required a named leaf file");

    let secured = match source {
        PolicyConfigurationSource::DefaultPath => ensure_default_directory_secured(dir),
        PolicyConfigurationSource::ConfiguredPath => verify_custom_directory_secure(dir),
    };

    let (canonical_dir, _) = match secured {
        Ok(resolved) => resolved,
        Err(error) => {
            tracing::warn!(
                path = %dir.display(), error = %format!("{error:#}"),
                "Configured policy directory failed security verification"
            );
            let (write_capability, read_only_reason) = match source {
                PolicyConfigurationSource::DefaultPath => (
                    PolicyWriteCapability::Unsupported,
                    PolicyReadOnlyReason::InsufficientPermissions,
                ),
                PolicyConfigurationSource::ConfiguredPath => {
                    (PolicyWriteCapability::ReadOnly, PolicyReadOnlyReason::UnsafePath)
                }
            };
            // An insecure/unverifiable directory must never be trusted to host a policy
            // -- but that alone does not mean there *is* a policy to distrust. If no
            // leaf exists there at all, the correct state is Missing (nothing to
            // activate or reject), not Invalid (which implies some untrusted content is
            // actually present); capability is ReadOnly/Unsupported either way, since
            // Create/Repair both still require a directory that passes verification.
            // This is a best-effort existence probe only (on the literal configured
            // path, since the directory itself could not be canonically verified): it
            // never trusts, reads, or reports the leaf's content.
            return match std::fs::metadata(configured_path) {
                Err(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => DiskObservation {
                    state: PolicyManagementState::Missing,
                    policy: None,
                    invalid_diagnostics: None,
                    fingerprint: DiskFingerprint::Missing {
                        path: configured_path.to_owned(),
                        parent: None,
                        dir_security_digest: None,
                        ancestor_security_digest: None,
                    },
                    write_capability,
                    read_only_reason: Some(read_only_reason),
                    canonical_path: configured_path.to_owned(),
                    hosting_dir: None,
                    retained_target: None,
                },
                _ => invalid_observation(
                    configured_path,
                    validation::DiskFailureReason::Unreadable,
                    InvalidContext::default(),
                    write_capability,
                    Some(read_only_reason),
                ),
            };
        }
    };
    let initial_canonical_path = canonical_dir.join(leaf_name);

    // Held open for the entire observation (see the doc comment above); dropped when this
    // function returns.
    let dir_handle = match open_directory_no_reparse(&canonical_dir) {
        Ok(handle) => handle,
        Err(error) => {
            tracing::warn!(path = %canonical_dir.display(), %error, "Failed to open the configured policy directory");
            return invalid_observation(
                &initial_canonical_path,
                validation::DiskFailureReason::Unreadable,
                InvalidContext::default(),
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::UnsafePath),
            );
        }
    };
    let canonical_dir = match policy_security::final_path_from_handle(&dir_handle) {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(
                path = %canonical_dir.display(), %error,
                "Failed to resolve the configured policy directory's final path"
            );
            return invalid_observation(
                &initial_canonical_path,
                validation::DiskFailureReason::Unreadable,
                InvalidContext::default(),
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::UnsafePath),
            );
        }
    };
    let canonical_path = canonical_dir.join(leaf_name);
    let parent = match policy_security::file_identity(&dir_handle) {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(
                path = %canonical_dir.display(), %error,
                "Failed to query the configured policy directory identity"
            );
            return invalid_observation(
                &canonical_path,
                validation::DiskFailureReason::Unreadable,
                InvalidContext::default(),
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::UnsafePath),
            );
        }
    };

    if let Err(error) = policy_security::verify_policy_directory_security(&dir_handle) {
        tracing::warn!(
            path = %canonical_dir.display(), error = %format!("{error:#}"),
            "Held policy directory failed security verification"
        );
        return invalid_observation(
            &canonical_path,
            validation::DiskFailureReason::InsecureStorage,
            InvalidContext {
                parent: Some(parent),
                ..Default::default()
            },
            PolicyWriteCapability::ReadOnly,
            Some(PolicyReadOnlyReason::UnsafePath),
        );
    }
    let dir_security_digest = match policy_security::security_state_digest(&dir_handle) {
        Ok(digest) => digest,
        Err(error) => {
            tracing::warn!(
                path = %canonical_dir.display(), %error,
                "Failed to compute the policy directory security digest"
            );
            return invalid_observation(
                &canonical_path,
                validation::DiskFailureReason::Unreadable,
                InvalidContext {
                    parent: Some(parent),
                    ..Default::default()
                },
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::UnsafePath),
            );
        }
    };
    let ancestor_security_digest =
        match policy_security::verify_policy_ancestor_chain(&canonical_dir, "policy directory") {
            Ok(digest) => digest,
            Err(error) => {
                tracing::warn!(
                    path = %canonical_dir.display(), error = %format!("{error:#}"),
                    "Held policy directory ancestor chain failed security verification"
                );
                return invalid_observation(
                    &canonical_path,
                    validation::DiskFailureReason::InsecureStorage,
                    InvalidContext {
                        parent: Some(parent),
                        dir_security_digest: Some(dir_security_digest),
                        ..Default::default()
                    },
                    PolicyWriteCapability::ReadOnly,
                    Some(PolicyReadOnlyReason::UnsafePath),
                );
            }
        };

    let recovery = recover_create_temporary_files(&canonical_dir)
        .and_then(|()| recover_interrupted_transaction(&dir_handle, &canonical_dir, leaf_name));
    if let Err(error) = recovery {
        tracing::error!(
            path = %canonical_dir.display(),
            error = %format!("{error:#}"),
            "Policy transaction recovery failed closed"
        );
        return invalid_observation(
            &canonical_path,
            validation::DiskFailureReason::InsecureStorage,
            InvalidContext {
                parent: Some(parent),
                dir_security_digest: Some(dir_security_digest),
                ancestor_security_digest: Some(ancestor_security_digest),
                ..Default::default()
            },
            PolicyWriteCapability::ReadOnly,
            Some(PolicyReadOnlyReason::UnsafePath),
        );
    }

    // The one-time, side-effecting atomic-replace capability probe (item 20): cached per
    // verified directory identity and security digest, never repeated on every observation.
    let (base_write_capability, base_read_only_reason) =
        match probe_cache.get_or_probe(&canonical_dir, parent, dir_security_digest) {
            Ok(()) => (PolicyWriteCapability::Writable, None),
            Err((reason, diagnostic)) => {
                tracing::warn!(
                    path = %canonical_dir.display(), %diagnostic,
                    "Policy directory is not writable through the management API"
                );
                (PolicyWriteCapability::ReadOnly, Some(reason))
            }
        };

    let hosting_dir = (base_write_capability == PolicyWriteCapability::Writable).then_some(VerifiedHostingDirectory {
        handle: Some(dir_handle),
        canonical_path: canonical_dir.clone(),
        identity: parent,
        security_digest: dir_security_digest,
    });

    let invalid_ctx = InvalidContext {
        parent: Some(parent),
        dir_security_digest: Some(dir_security_digest),
        ancestor_security_digest: Some(ancestor_security_digest),
        ..Default::default()
    };

    let file_result = if retain_target {
        OpenOptions::new()
            .access_mode(FILE_GENERIC_READ.0 | DELETE.0 | READ_CONTROL.0)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(&canonical_path)
    } else {
        OpenOptions::new()
            .read(true)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(&canonical_path)
    };
    let file = match file_result {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return DiskObservation {
                state: PolicyManagementState::Missing,
                policy: None,
                invalid_diagnostics: None,
                fingerprint: DiskFingerprint::Missing {
                    path: canonical_path.clone(),
                    parent: Some(parent),
                    dir_security_digest: Some(dir_security_digest),
                    ancestor_security_digest: Some(ancestor_security_digest),
                },
                write_capability: base_write_capability,
                read_only_reason: base_read_only_reason,
                canonical_path,
                hosting_dir,
                retained_target: None,
            };
        }
        Err(error) => {
            tracing::warn!(path = %canonical_path.display(), %error, "Failed to open the configured policy file");
            return invalid_observation(
                &canonical_path,
                validation::DiskFailureReason::Unreadable,
                invalid_ctx,
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::UnsafePath),
            );
        }
    };

    let attributes = match file.metadata() {
        Ok(metadata) => metadata.file_attributes(),
        Err(error) => {
            tracing::warn!(path = %canonical_path.display(), %error, "Failed to query the configured policy file metadata");
            return invalid_observation(
                &canonical_path,
                validation::DiskFailureReason::Unreadable,
                invalid_ctx,
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::UnsafePath),
            );
        }
    };
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        tracing::warn!(
            path = %canonical_path.display(),
            "Configured policy file is a reparse point (symlink); refusing to trust a retargeted file"
        );
        return invalid_observation(
            &canonical_path,
            validation::DiskFailureReason::InsecureStorage,
            invalid_ctx,
            PolicyWriteCapability::ReadOnly,
            Some(PolicyReadOnlyReason::UnsafePath),
        );
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        tracing::warn!(path = %canonical_path.display(), "Configured policy path resolved to a directory, not a file");
        return invalid_observation(
            &canonical_path,
            validation::DiskFailureReason::Unreadable,
            invalid_ctx,
            PolicyWriteCapability::ReadOnly,
            Some(PolicyReadOnlyReason::UnsafePath),
        );
    }

    // A policy leaf with multiple names is ambiguous regardless of which name
    // GetFinalPathNameByHandleW happens to report. Reject it using file metadata rather
    // than inferring link identity from that reported path.
    let link_count = match policy_security::file_link_count(&file) {
        Ok(link_count) => link_count,
        Err(error) => {
            tracing::warn!(path = %canonical_path.display(), %error, "Failed to query the configured policy file link count");
            return invalid_observation(
                &canonical_path,
                validation::DiskFailureReason::Unreadable,
                invalid_ctx,
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::UnsafePath),
            );
        }
    };
    if link_count != 1 {
        tracing::warn!(
            path = %canonical_path.display(),
            link_count,
            "Configured policy file has multiple hard links"
        );
        return invalid_observation(
            &canonical_path,
            validation::DiskFailureReason::InsecureStorage,
            invalid_ctx,
            PolicyWriteCapability::ReadOnly,
            Some(PolicyReadOnlyReason::UnsafePath),
        );
    }

    // Resolve both the parent and leaf from their held handles. This tolerates a lexical
    // 8.3 alias in the configured parent while still requiring the resolved leaf to be
    // exactly the configured name modulo Windows casing.
    match policy_security::final_path_from_handle(&file) {
        Ok(resolved) => {
            let resolved_matches = resolved_policy_path_matches(&resolved, &canonical_dir, leaf_name);
            if !resolved_matches {
                tracing::warn!(
                    path = %canonical_path.display(), resolved = %resolved.display(),
                    "Configured policy file resolved to an unexpected location"
                );
                return invalid_observation(
                    &canonical_path,
                    validation::DiskFailureReason::InsecureStorage,
                    invalid_ctx,
                    PolicyWriteCapability::ReadOnly,
                    Some(PolicyReadOnlyReason::UnsafePath),
                );
            }
        }

        Err(error) => {
            tracing::warn!(
                path = %canonical_path.display(), %error,
                "Failed to resolve the configured policy file's final path"
            );
            return invalid_observation(
                &canonical_path,
                validation::DiskFailureReason::Unreadable,
                invalid_ctx,
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::UnsafePath),
            );
        }
    }

    let target = match policy_security::file_identity(&file) {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(path = %canonical_path.display(), %error, "Failed to query the configured policy file identity");
            return invalid_observation(
                &canonical_path,
                validation::DiskFailureReason::Unreadable,
                invalid_ctx,
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::UnsafePath),
            );
        }
    };
    let invalid_ctx = InvalidContext {
        target: Some(target),
        ..invalid_ctx
    };

    if let Err(security_error) = policy_security::verify_policy_file_security(&file) {
        // Fail closed without ever reading content past a failed security check, exactly
        // like the legacy loader: an insecurely-stored file is never trusted, whatever it
        // contains. Forced ReadOnly regardless of the directory's own writable capability
        // (item 26): an untrustworthy existing file must never be blindly overwritten
        // through the management API either. The detailed reason is only ever traced,
        // never exposed through the management API (see `validation::disk_failure_finding`).
        tracing::warn!(
            path = %canonical_path.display(),
            error = %format!("{security_error:#}"),
            "Configured policy file failed storage security validation"
        );
        return invalid_observation(
            &canonical_path,
            validation::DiskFailureReason::InsecureStorage,
            invalid_ctx,
            PolicyWriteCapability::ReadOnly,
            Some(PolicyReadOnlyReason::UnsafePath),
        );
    }

    let security_digest = match policy_security::security_state_digest(&file) {
        Ok(digest) => digest,
        Err(error) => {
            tracing::warn!(path = %canonical_path.display(), %error, "Failed to compute the configured policy file's security digest");
            return invalid_observation(
                &canonical_path,
                validation::DiskFailureReason::Unreadable,
                invalid_ctx,
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::UnsafePath),
            );
        }
    };
    let invalid_ctx = InvalidContext {
        security_digest: Some(security_digest),
        ..invalid_ctx
    };

    let mut content = Vec::new();
    {
        use std::io::Read as _;
        if let Err(read_error) = (&file).read_to_end(&mut content) {
            tracing::warn!(path = %canonical_path.display(), %read_error, "Failed to read the configured policy file");
            return invalid_observation(
                &canonical_path,
                validation::DiskFailureReason::Unreadable,
                invalid_ctx,
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::UnsafePath),
            );
        }
    }

    // The file itself is securely stored (whatever its content turns out to be): a
    // malformed/semantically-invalid document past this point still allows Repair
    // through the directory's own (already resolved) capability -- item 26.
    let retained_target = retain_target.then_some(RetainedPolicyFile::Real(file));

    observation_from_parts(
        &canonical_path,
        &content,
        VerifiedIdentity {
            parent,
            dir_security_digest,
            ancestor_security_digest,
            target,
            security_digest,
        },
        base_write_capability,
        base_read_only_reason,
        hosting_dir,
        retained_target,
    )
}

/// Verified identity/security components already resolved for the current observation,
/// grouped so [`observation_from_parts`] does not need one parameter per field.
struct VerifiedIdentity {
    parent: FileIdentity,
    dir_security_digest: [u8; 32],
    ancestor_security_digest: [u8; 32],
    target: FileIdentity,
    security_digest: [u8; 32],
}

/// Parse already-obtained (already security-verified) policy file bytes into a
/// [`DiskObservation`], given the fingerprint's already-resolved identity components and
/// the directory's already-resolved write capability.
///
/// A structurally valid [`PolicyDocument`] is additionally, authoritatively revalidated
/// the same deterministic way a submitted draft is (item 30: see
/// [`validation::validate_committed_policy`]): a committed file is never activated on
/// structural parseability alone. Warnings alone (audit mode, default-allow, sensitive
/// options) do not block activation.
fn observation_from_parts(
    path: &Path,
    content: &[u8],
    identity: VerifiedIdentity,
    write_capability: PolicyWriteCapability,
    read_only_reason: Option<PolicyReadOnlyReason>,
    hosting_dir: Option<VerifiedHostingDirectory>,
    retained_target: Option<RetainedPolicyFile>,
) -> DiskObservation {
    let VerifiedIdentity {
        parent,
        dir_security_digest,
        ancestor_security_digest,
        target,
        security_digest,
    } = identity;

    let content_digest = sha256_digest(content);

    let mut retained_target = retained_target;
    let mut invalid_with = |reason: validation::DiskFailureReason, hosting_dir| DiskObservation {
        state: PolicyManagementState::Invalid,
        policy: None,
        invalid_diagnostics: Some(InvalidPolicyDiagnostics {
            diagnostics_version: API_VERSION_STR.into(),
            findings: vec![validation::disk_failure_finding(reason)],
        }),
        fingerprint: DiskFingerprint::Invalid {
            path: path.to_owned(),
            parent: Some(parent),
            dir_security_digest: Some(dir_security_digest),
            ancestor_security_digest: Some(ancestor_security_digest),
            target: Some(target),
            content_digest: Some(content_digest),
            security_digest: Some(security_digest),
            reason,
        },
        write_capability,
        read_only_reason,
        canonical_path: path.to_owned(),
        hosting_dir,
        retained_target: retained_target.take(),
    };

    let policy = match serde_json::from_slice::<PolicyDocument>(content) {
        Ok(policy) => policy,
        Err(parse_error) => {
            // Detailed parse error only ever traced, never exposed through the management
            // API: it is heuristically derived from attacker/corruption-controlled bytes
            // and could otherwise leak content fragments to any authenticated (but not
            // necessarily elevated) caller of `GET /v1/policy/management`.
            tracing::warn!(%parse_error, "Configured policy file content failed to parse");
            return invalid_with(validation::DiskFailureReason::MalformedContent, hosting_dir);
        }
    };

    let committed_validation = validation::validate_committed_policy(&policy);
    if !committed_validation.is_valid {
        // Specific findings only ever traced, for the same reason raw parse errors are
        // not exposed: they are derived from the committed file's own content, which
        // `GET /v1/policy/management` exposes to any authenticated (but not necessarily
        // elevated/Administrator, and not necessarily the file's author) caller.
        tracing::warn!(
            findings = ?committed_validation.findings,
            "Configured policy file failed authoritative semantic validation"
        );
        return invalid_with(validation::DiskFailureReason::FailedSemanticValidation, hosting_dir);
    }

    DiskObservation {
        state: PolicyManagementState::Active,
        policy: Some(policy),
        invalid_diagnostics: None,
        fingerprint: DiskFingerprint::Active {
            parent,
            target,
            content_digest,
            security_digest,
            dir_security_digest,
            ancestor_security_digest,
        },
        write_capability,
        read_only_reason,
        canonical_path: path.to_owned(),
        hosting_dir,
        retained_target,
    }
}

/// Build a generic, sanitized [`DiskObservation`] for a storage-level failure (shape,
/// I/O, or security) that prevented the configured policy file from even being read as
/// JSON. Never includes raw OS/security error text: see [`validation::disk_failure_finding`].
fn invalid_observation(
    path: &Path,
    reason: validation::DiskFailureReason,
    context: InvalidContext,
    write_capability: PolicyWriteCapability,
    read_only_reason: Option<PolicyReadOnlyReason>,
) -> DiskObservation {
    DiskObservation {
        state: PolicyManagementState::Invalid,
        policy: None,
        invalid_diagnostics: Some(InvalidPolicyDiagnostics {
            diagnostics_version: API_VERSION_STR.into(),
            findings: vec![validation::disk_failure_finding(reason)],
        }),
        fingerprint: DiskFingerprint::Invalid {
            path: path.to_owned(),
            parent: context.parent,
            dir_security_digest: context.dir_security_digest,
            ancestor_security_digest: context.ancestor_security_digest,
            target: context.target,
            content_digest: context.content_digest,
            security_digest: context.security_digest,
            reason,
        },
        write_capability,
        read_only_reason,
        canonical_path: path.to_owned(),
        hosting_dir: None,
        retained_target: None,
    }
}

/// Mint a fresh, process-random, opaque token conforming to `PolicyStoreToken`'s own
/// safe-ASCII/length contract. Tokens never encode or derive from disk content/identity:
/// [`PolicyStore::token_for`](super::PolicyStore) is the only place a token is ever
/// produced, and it only ever calls this when the observed [`DiskFingerprint`] changed.
pub(super) fn random_store_token() -> PolicyStoreToken {
    uuid::Uuid::new_v4().hyphenated().to_string().into()
}

/// Result of a successful atomic write.
pub(super) struct PersistedPolicy {
    pub policy: PolicyDocument,
    pub fingerprint: DiskFingerprint,
}

/// A write failure classified by whether publication occurred or a concurrent change won.
pub(super) enum WriteFailure {
    /// Failed before new content was published.
    /// Reobservation recovers any retained tombstone before this maps to `ErrorCode::PolicyPersistenceFailed`.
    PrePublication(anyhow::Error),
    /// A concurrent external change prevented identity-bound publication.
    /// The caller must synchronously reobserve and return a stale-token conflict.
    ConcurrentChange(anyhow::Error),
    /// Failed after the rename made the new content live: the caller must synchronously
    /// reobserve disk under the same write lock and publish whatever that reveals rather
    /// than trusting the previous in-memory snapshot. Maps to
    /// `ErrorCode::PolicyActivationFailed`.
    PostPublication(anyhow::Error),
}

/// Conditionally persist `bytes` against the exact retained target observed for the store token.
///
/// The observed target is moved by handle to a reserved tombstone and the flushed replacement is moved by handle to the final leaf without replacement.
/// Any raced-in final entry is preserved and reported as [`WriteFailure::ConcurrentChange`].
/// A durable marker makes every interruption recoverable before the next observation.
pub(super) fn atomic_replace(
    hosting_dir: &VerifiedHostingDirectory,
    observed_target: Option<RetainedPolicyFile>,
    expected_fingerprint: &DiskFingerprint,
    final_path: &Path,
    bytes: &[u8],
) -> Result<PersistedPolicy, WriteFailure> {
    let observed_target = observed_target
        .context("replacement observation did not retain the target handle")
        .map_err(WriteFailure::ConcurrentChange)?;
    verify_replacement_evidence(hosting_dir, &observed_target, expected_fingerprint)
        .map_err(WriteFailure::ConcurrentChange)?;

    conditional_replace(hosting_dir, observed_target, expected_fingerprint, final_path, bytes)
}

fn verify_replacement_evidence(
    hosting_dir: &VerifiedHostingDirectory,
    observed_target: &RetainedPolicyFile,
    expected_fingerprint: &DiskFingerprint,
) -> anyhow::Result<()> {
    hosting_dir
        .verify_unchanged()
        .context("hosting directory changed after policy observation")?;
    observed_target
        .verify_matches(expected_fingerprint)
        .context("observed policy changed before conditional publication")?;
    let expected_ancestor_security = match expected_fingerprint {
        DiskFingerprint::Active {
            ancestor_security_digest,
            ..
        }
        | DiskFingerprint::Invalid {
            ancestor_security_digest: Some(ancestor_security_digest),
            ..
        } => *ancestor_security_digest,
        _ => {
            return Err(anyhow::anyhow!(
                "replacement observation has no ancestor security fingerprint"
            ));
        }
    };
    let current_ancestor_security =
        policy_security::verify_policy_ancestor_chain(hosting_dir.canonical_path(), "policy directory")
            .context("policy directory ancestor security changed after token validation")?;
    if current_ancestor_security != expected_ancestor_security {
        return Err(anyhow::anyhow!(
            "policy directory ancestor security changed after token validation"
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct TransactionPaths {
    id: uuid::Uuid,
    marker_staging: PathBuf,
    marker: PathBuf,
    old: PathBuf,
    new: PathBuf,
}

impl TransactionPaths {
    fn new(dir: &Path, final_path: &Path) -> anyhow::Result<Self> {
        let leaf = final_path
            .file_name()
            .and_then(OsStr::to_str)
            .context("policy path has no Unicode leaf name")?;
        let id = uuid::Uuid::new_v4();
        let prefix = format!(".{leaf}.txn-{id}");
        Ok(Self {
            id,
            marker_staging: dir.join(format!("{prefix}.marker.prepare")),
            marker: dir.join(format!("{prefix}.marker")),
            old: dir.join(format!("{prefix}.old")),
            new: dir.join(format!("{prefix}.new")),
        })
    }
}

#[derive(Debug)]
struct TransactionMarker {
    id: uuid::Uuid,
    final_leaf: String,
    old_identity: FileIdentity,
    old_content_digest: [u8; 32],
    old_security_digest: [u8; 32],
    new_content_digest: [u8; 32],
}

impl TransactionMarker {
    fn from_observation(
        id: uuid::Uuid,
        final_path: &Path,
        expected: &DiskFingerprint,
        new_bytes: &[u8],
    ) -> anyhow::Result<Self> {
        let (old_identity, old_content_digest, old_security_digest) = match expected {
            DiskFingerprint::Active {
                target,
                content_digest,
                security_digest,
                ..
            } => (*target, *content_digest, *security_digest),
            DiskFingerprint::Invalid {
                target: Some(target),
                content_digest: Some(content_digest),
                security_digest: Some(security_digest),
                ..
            } => (*target, *content_digest, *security_digest),
            _ => bail!("replacement requires a complete observed target fingerprint"),
        };
        Ok(Self {
            id,
            final_leaf: final_path
                .file_name()
                .and_then(OsStr::to_str)
                .context("policy path has no Unicode leaf name")?
                .to_owned(),
            old_identity,
            old_content_digest,
            old_security_digest,
            new_content_digest: sha256_digest(new_bytes),
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "Version": 1,
            "TransactionId": self.id.to_string(),
            "FinalLeaf": self.final_leaf,
            "OldVolumeSerial": self.old_identity.volume_serial,
            "OldFileId": hex::encode(self.old_identity.file_id),
            "OldContentDigest": hex::encode(self.old_content_digest),
            "OldSecurityDigest": hex::encode(self.old_security_digest),
            "NewContentDigest": hex::encode(self.new_content_digest),
        }))
        .expect("transaction marker fields always serialize")
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let value: serde_json::Value = serde_json::from_slice(bytes).context("transaction marker is not valid JSON")?;
        let object = value.as_object().context("transaction marker must be an object")?;
        ensure!(object.len() == 8, "transaction marker contains unexpected fields");
        ensure!(
            object.get("Version").and_then(serde_json::Value::as_u64) == Some(1),
            "unsupported transaction marker"
        );
        let text = |name: &str| -> anyhow::Result<&str> {
            object
                .get(name)
                .and_then(serde_json::Value::as_str)
                .with_context(|| format!("transaction marker {name} is missing or invalid"))
        };
        let decode = |name: &str| -> anyhow::Result<[u8; 32]> {
            let mut output = [0u8; 32];
            hex::decode_to_slice(text(name)?, &mut output)
                .with_context(|| format!("transaction marker {name} is invalid"))?;
            Ok(output)
        };
        let mut file_id = [0u8; 16];
        hex::decode_to_slice(text("OldFileId")?, &mut file_id).context("transaction marker OldFileId is invalid")?;
        Ok(Self {
            id: uuid::Uuid::parse_str(text("TransactionId")?).context("transaction marker id is invalid")?,
            final_leaf: text("FinalLeaf")?.to_owned(),
            old_identity: FileIdentity {
                volume_serial: object
                    .get("OldVolumeSerial")
                    .and_then(serde_json::Value::as_u64)
                    .context("transaction marker OldVolumeSerial is missing or invalid")?,
                file_id,
            },
            old_content_digest: decode("OldContentDigest")?,
            old_security_digest: decode("OldSecurityDigest")?,
            new_content_digest: decode("NewContentDigest")?,
        })
    }
}

fn conditional_replace(
    hosting_dir: &VerifiedHostingDirectory,
    observed_target: RetainedPolicyFile,
    expected_fingerprint: &DiskFingerprint,
    final_path: &Path,
    bytes: &[u8],
) -> Result<PersistedPolicy, WriteFailure> {
    use std::io::Write as _;

    let dir_handle = hosting_dir
        .handle
        .as_ref()
        .expect("real storage always retains the directory handle");
    let paths =
        TransactionPaths::new(hosting_dir.canonical_path(), final_path).map_err(WriteFailure::PrePublication)?;
    let marker = TransactionMarker::from_observation(paths.id, final_path, expected_fingerprint, bytes)
        .map_err(WriteFailure::ConcurrentChange)?;

    let mut marker_file =
        create_secure_transaction_file(&paths.marker_staging).map_err(WriteFailure::PrePublication)?;
    if let Err(error) = marker_file
        .write_all(&marker.to_bytes())
        .and_then(|()| marker_file.sync_all())
        .context("failed to persist policy transaction marker")
    {
        return match delete_file_handle(&marker_file) {
            Ok(()) => Err(WriteFailure::PrePublication(error)),
            Err(cleanup_error) => Err(WriteFailure::PrePublication(error.context(format!(
                "incomplete transaction marker cleanup also failed: {cleanup_error:#}"
            )))),
        };
    }
    if let Err(error) = rename_file_handle(
        &marker_file,
        dir_handle,
        paths.marker.file_name().expect("transaction marker path has leaf"),
    ) {
        return match delete_file_handle(&marker_file) {
            Ok(()) => Err(WriteFailure::PrePublication(
                anyhow::Error::new(error).context("failed to publish completed transaction marker"),
            )),
            Err(cleanup_error) => Err(WriteFailure::PrePublication(anyhow::Error::new(error).context(
                format!("failed to publish completed transaction marker and staging cleanup failed: {cleanup_error:#}"),
            ))),
        };
    }

    let mut temp_file = match create_secure_transaction_file(&paths.new) {
        Ok(file) => file,
        Err(error) => {
            return match delete_file_handle(&marker_file) {
                Ok(()) => Err(WriteFailure::PrePublication(error)),
                Err(cleanup_error) => Err(WriteFailure::PrePublication(
                    error.context(format!("transaction marker cleanup also failed: {cleanup_error:#}")),
                )),
            };
        }
    };
    if let Err(error) = temp_file
        .write_all(bytes)
        .and_then(|()| temp_file.sync_all())
        .context("failed to persist replacement policy")
        .and_then(|()| {
            policy_security::verify_policy_file_security(&temp_file)
                .context("replacement policy temporary file failed security verification")
        })
    {
        if let Err(cleanup_error) = delete_file_handle(&temp_file) {
            return Err(WriteFailure::PrePublication(error.context(format!(
                "temporary replacement cleanup failed; transaction marker retained for recovery: {cleanup_error:#}"
            ))));
        }
        return match delete_file_handle(&marker_file) {
            Ok(()) => Err(WriteFailure::PrePublication(error)),
            Err(cleanup_error) => Err(WriteFailure::PrePublication(
                error.context(format!("transaction marker cleanup also failed: {cleanup_error:#}")),
            )),
        };
    }

    let prepared = PreparedTransaction {
        dir_handle,
        observed_target: &observed_target,
        temp_file: &temp_file,
        paths: &paths,
        final_path,
    };
    publish_prepared_transaction(
        &prepared,
        || Ok(()),
        || verify_replacement_evidence(hosting_dir, &observed_target, expected_fingerprint),
        || Ok(()),
    )?;

    let persisted =
        verify_persisted_handle(hosting_dir, &temp_file, final_path, bytes).map_err(WriteFailure::PostPublication)?;
    delete_file_handle(observed_target.handle()).map_err(WriteFailure::PostPublication)?;
    drop(observed_target);
    delete_file_handle(&marker_file).map_err(WriteFailure::PostPublication)?;
    drop(marker_file);
    Ok(persisted)
}

struct PreparedTransaction<'a> {
    dir_handle: &'a File,
    observed_target: &'a RetainedPolicyFile,
    temp_file: &'a File,
    paths: &'a TransactionPaths,
    final_path: &'a Path,
}

fn publish_prepared_transaction(
    transaction: &PreparedTransaction<'_>,
    after_tombstone: impl FnOnce() -> anyhow::Result<()>,
    verify_before_publish: impl FnOnce() -> anyhow::Result<()>,
    after_publish: impl FnOnce() -> anyhow::Result<()>,
) -> Result<(), WriteFailure> {
    if let Err(error) = rename_file_handle(
        transaction.observed_target.handle(),
        transaction.dir_handle,
        transaction.paths.old.file_name().expect("transaction path has leaf"),
    ) {
        return Err(WriteFailure::PrePublication(
            anyhow::Error::new(error).context("failed to reserve observed policy as transaction tombstone"),
        ));
    }

    after_tombstone().map_err(|error| {
        WriteFailure::PrePublication(error.context("transaction interrupted after reserving the observed policy"))
    })?;

    if let Err(error) = verify_before_publish() {
        let restore_error = rename_file_handle(
            transaction.observed_target.handle(),
            transaction.dir_handle,
            transaction.final_path.file_name().expect("policy path has leaf"),
        )
        .err();
        return Err(WriteFailure::ConcurrentChange(match restore_error {
            Some(restore_error) => error.context(format!(
                "pre-publication evidence changed and the exact tombstone could not be restored: {restore_error}"
            )),
            None => error.context("pre-publication evidence changed; the exact tombstone was restored"),
        }));
    }

    if let Err(publish_error) = rename_file_handle(
        transaction.temp_file,
        transaction.dir_handle,
        transaction.final_path.file_name().expect("policy path has leaf"),
    ) {
        let restore_result = rename_file_handle(
            transaction.observed_target.handle(),
            transaction.dir_handle,
            transaction.final_path.file_name().expect("policy path has leaf"),
        );
        if let Err(restore_error) = restore_result {
            let final_guard = open_optional_final_guard(transaction.final_path).map_err(|error| {
                WriteFailure::ConcurrentChange(error.context(format!(
                    "replacement publication and tombstone restoration failed: {publish_error}; {restore_error}"
                )))
            })?;
            let Some(final_guard) = final_guard else {
                return Err(WriteFailure::PrePublication(
                    anyhow::Error::new(publish_error).context(format!(
                        "replacement publication failed and the original tombstone could not be restored: {restore_error}"
                    )),
                ));
            };
            drop(final_guard);
            return Err(WriteFailure::ConcurrentChange(
                anyhow::Error::new(publish_error).context("replacement lost a create-new publication race"),
            ));
        }
        return Err(WriteFailure::PrePublication(
            anyhow::Error::new(publish_error).context("replacement publication failed and the tombstone was restored"),
        ));
    }

    after_publish()
        .context("transaction interrupted after replacement publication")
        .map_err(WriteFailure::PostPublication)?;

    Ok(())
}

fn create_secure_transaction_file(path: &Path) -> anyhow::Result<File> {
    let security_attributes =
        policy_security::admin_only_security_attributes(false).context("build transaction file security")?;
    let path = U16CString::from_os_str(path.as_os_str()).context("transaction path contains an interior NUL")?;
    // SAFETY: The path and security attributes remain valid for the call, and the returned handle is owned.
    let handle = unsafe {
        CreateFileW(
            path.as_pcwstr(),
            GENERIC_READ.0 | GENERIC_WRITE.0 | DELETE.0 | READ_CONTROL.0,
            FILE_SHARE_NONE,
            Some(security_attributes.as_ptr()),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            None,
        )
    }
    .context("failed to create secure transaction file")?;
    // SAFETY: CreateFileW returned a new owned handle.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(handle.0) }))
}

fn open_transaction_file(path: &Path) -> anyhow::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_GENERIC_READ.0 | DELETE.0 | READ_CONTROL.0)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .with_context(|| format!("failed to open transaction remnant {}", path.display()))
}

fn rename_file_handle(file: &File, root: &File, new_name: &OsStr) -> std::io::Result<()> {
    // Prefer a relative name anchored to the retained directory handle.
    // Some Windows filesystems reject `RootDirectory` through `SetFileInformationByHandle`, so the fallback derives the absolute path from the same retained handle.
    if set_file_rename_information(file, HANDLE(root.as_raw_handle()), new_name).is_ok() {
        return Ok(());
    }

    let absolute = policy_security::final_path_from_handle(root)
        .map_err(|error| std::io::Error::other(format!("failed to resolve rename root: {error:#}")))?
        .join(new_name);
    set_file_rename_information(file, HANDLE::default(), absolute.as_os_str())
}

#[expect(
    clippy::multiple_unsafe_ops_per_block,
    reason = "building and submitting one variable-length Win32 FILE_RENAME_INFO buffer is one logical FFI operation"
)]
fn set_file_rename_information(file: &File, root: HANDLE, new_name: &OsStr) -> std::io::Result<()> {
    let name: Vec<u16> = new_name.encode_wide().collect();
    let name_bytes = name.len().checked_mul(2).expect("file name byte length fits usize");
    let name_offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let buffer_len = name_offset
        .checked_add(name_bytes)
        .expect("rename information length fits usize")
        .max(size_of::<FILE_RENAME_INFO>());
    let mut buffer = vec![0usize; buffer_len.div_ceil(size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    let buffer_ptr = info.cast::<u8>();
    // SAFETY: The buffer is sized for FILE_RENAME_INFO plus the complete UTF-16 file name.
    unsafe {
        (*info).Anonymous = FILE_RENAME_INFO_0 { Flags: 0 };
        (*info).RootDirectory = root;
        (*info).FileNameLength = u32::try_from(name_bytes).expect("Windows file name length fits u32");
        std::ptr::copy_nonoverlapping(name.as_ptr(), buffer_ptr.add(name_offset).cast(), name.len());
        let result = SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileRenameInfoEx,
            buffer_ptr.cast(),
            u32::try_from(name_offset + name_bytes).expect("rename buffer length fits u32"),
        );
        match result {
            Ok(()) => Ok(()),
            Err(error) if error.code() == windows::Win32::Foundation::E_INVALIDARG => SetFileInformationByHandle(
                HANDLE(file.as_raw_handle()),
                FileRenameInfo,
                buffer_ptr.cast(),
                u32::try_from(name_offset + name_bytes).expect("rename buffer length fits u32"),
            )
            .map_err(std::io::Error::from),
            Err(error) => Err(std::io::Error::from(error)),
        }
    }
}

fn delete_file_handle(file: &File) -> anyhow::Result<()> {
    let extended = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_INFO_EX_FLAGS(
            FILE_DISPOSITION_FLAG_DELETE.0
                | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS.0
                | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE.0,
        ),
    };
    // SAFETY: The file handle is valid and extended points to a correctly sized input structure.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfoEx,
            std::ptr::from_ref(&extended).cast(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO_EX>()).expect("disposition structure size fits u32"),
        )
    }
    .context("failed to unlink transaction file by handle")?;

    Ok(())
}

fn recover_create_temporary_files(dir_path: &Path) -> anyhow::Result<()> {
    let prefix = OsString::from(format!(".{POLICY_FILE_NAME}.tmp-"));
    for entry in std::fs::read_dir(dir_path).context("failed to enumerate policy directory for create recovery")? {
        let entry = entry.context("failed to enumerate policy create remnant")?;
        let Some(remainder) = reserved_name_remainder(&entry.file_name(), &prefix)? else {
            continue;
        };
        uuid::Uuid::parse_str(&remainder).context("policy directory contains a malformed create remnant")?;
        let path = entry.path();
        let file = open_transaction_file(&path)?;
        verify_transaction_file_path(&file, &path)?;
        policy_security::verify_policy_file_security(&file).context("policy create remnant security is invalid")?;
        delete_file_handle(&file).context("failed to retire policy create remnant")?;
        drop(file);
    }
    Ok(())
}

fn reserved_name_remainder(name: &OsStr, prefix: &OsStr) -> anyhow::Result<Option<String>> {
    let name_wide: Vec<u16> = name.encode_wide().collect();
    let prefix_wide: Vec<u16> = prefix.encode_wide().collect();
    if name_wide.len() < prefix_wide.len() {
        return Ok(None);
    }
    let candidate_prefix = OsString::from_wide(&name_wide[..prefix_wide.len()]);
    if !policy_security::os_strings_match_case_insensitive(&candidate_prefix, prefix) {
        return Ok(None);
    }
    String::from_utf16(&name_wide[prefix_wide.len()..])
        .context("reserved policy remnant name is not Unicode")
        .map(Some)
}

fn recover_interrupted_transaction(dir: &File, dir_path: &Path, final_leaf: &OsStr) -> anyhow::Result<()> {
    let final_leaf = final_leaf.to_str().context("policy leaf is not valid Unicode")?;
    let transaction_prefix = OsString::from(format!(".{final_leaf}.txn-"));
    let mut transaction_id = None;
    let mut marker_staging_path = None;
    let mut marker_path = None;
    let mut old_path = None;
    let mut new_path = None;

    for entry in std::fs::read_dir(dir_path).context("failed to enumerate policy directory for transaction recovery")? {
        let entry = entry.context("failed to enumerate policy transaction remnant")?;
        let name = entry.file_name();
        let Some(remainder) = reserved_name_remainder(&name, &transaction_prefix)? else {
            continue;
        };
        let Some((id, kind)) = remainder.split_once('.') else {
            bail!("policy directory contains a malformed transaction remnant");
        };
        let id = uuid::Uuid::parse_str(id).context("policy directory contains a malformed transaction id")?;
        if transaction_id.replace(id).is_some_and(|previous| previous != id) {
            bail!("policy directory contains multiple interrupted transactions");
        }
        let slot = match kind {
            "marker.prepare" => &mut marker_staging_path,
            "marker" => &mut marker_path,
            "old" => &mut old_path,
            "new" => &mut new_path,
            _ => bail!("policy directory contains an unsupported transaction remnant"),
        };
        ensure!(
            slot.replace(entry.path()).is_none(),
            "policy directory contains duplicate transaction remnants"
        );
    }

    let Some(id) = transaction_id else {
        return Ok(());
    };
    if let Some(marker_staging_path) = marker_staging_path {
        ensure!(
            marker_path.is_none() && old_path.is_none() && new_path.is_none(),
            "incomplete marker staging is mixed with published transaction remnants"
        );
        let marker_staging = open_transaction_file(&marker_staging_path)?;
        verify_transaction_file_path(&marker_staging, &marker_staging_path)?;
        policy_security::verify_policy_file_security(&marker_staging)
            .context("transaction marker staging security is invalid")?;
        let final_path = dir_path.join(final_leaf);
        return recover_marker_staging(&final_path, marker_staging);
    }
    let marker_path = marker_path.context("interrupted policy transaction has no marker")?;
    let paths = TransactionPaths {
        id,
        marker_staging: dir_path.join(format!(".{final_leaf}.txn-{id}.marker.prepare")),
        marker: marker_path,
        old: old_path.unwrap_or_else(|| dir_path.join(format!(".{final_leaf}.txn-{id}.old"))),
        new: new_path.unwrap_or_else(|| dir_path.join(format!(".{final_leaf}.txn-{id}.new"))),
    };
    let marker_file = open_transaction_file(&paths.marker)?;
    verify_transaction_file_path(&marker_file, &paths.marker)?;
    policy_security::verify_policy_file_security(&marker_file).context("transaction marker security is invalid")?;
    let marker_bytes = read_file_from_start(&marker_file)?;
    let marker = TransactionMarker::from_bytes(&marker_bytes)?;
    ensure!(marker.id == id, "transaction marker id does not match its name");
    ensure!(
        policy_security::os_strings_match_case_insensitive(OsStr::new(&marker.final_leaf), OsStr::new(final_leaf)),
        "transaction marker targets a different policy leaf"
    );

    let old_file = open_optional_transaction_file(&paths.old)?;
    if let Some(old_file) = &old_file {
        verify_transaction_file_path(old_file, &paths.old)?;
        verify_transaction_file_state(
            old_file,
            marker.old_identity,
            marker.old_content_digest,
            marker.old_security_digest,
        )
        .context("transaction tombstone does not match the observed policy")?;
    }

    let new_file = open_optional_transaction_file(&paths.new)?;
    let new_content_matches = if let Some(new_file) = &new_file {
        verify_transaction_file_path(new_file, &paths.new)?;
        policy_security::verify_policy_file_security(new_file)
            .context("transaction replacement security is invalid")?;
        sha256_digest(&read_file_from_start(new_file)?) == marker.new_content_digest
    } else {
        true
    };
    if old_file.is_some() {
        ensure!(
            new_content_matches,
            "transaction replacement content changed after tombstoning"
        );
    }

    recover_verified_transaction(dir, dir_path, OsStr::new(final_leaf), marker_file, old_file, new_file)
}

fn recover_marker_staging(final_path: &Path, marker_staging: File) -> anyhow::Result<()> {
    let final_guard = open_optional_final_guard(final_path)?
        .context("incomplete marker staging exists but the original policy is absent")?;
    delete_file_handle(&marker_staging).context("failed to retire incomplete transaction marker staging")?;
    drop(marker_staging);
    drop(final_guard);
    Ok(())
}

fn recover_verified_transaction(
    dir: &File,
    dir_path: &Path,
    final_leaf: &OsStr,
    marker_file: File,
    mut old_file: Option<File>,
    new_file: Option<File>,
) -> anyhow::Result<()> {
    let final_path = dir_path.join(final_leaf);
    let mut final_guard = open_optional_final_guard(&final_path)?;
    let mut restored = false;
    if final_guard.is_none() {
        let old_file = old_file
            .as_ref()
            .context("interrupted transaction has neither a final policy nor a valid tombstone")?;
        match rename_file_handle(old_file, dir, final_leaf) {
            Ok(()) => restored = true,
            Err(error) => {
                final_guard = open_optional_final_guard(&final_path)?;
                if final_guard.is_none() {
                    return Err(error).context("failed to restore interrupted policy transaction");
                }
                tracing::warn!(%error, "An external policy appeared while transaction recovery restored the tombstone");
            }
        }
    }

    if !restored && let Some(old_file) = old_file.take() {
        delete_file_handle(&old_file).context("failed to retire policy transaction tombstone")?;
        drop(old_file);
    }
    if let Some(new_file) = new_file {
        delete_file_handle(&new_file).context("failed to retire unpublished policy transaction replacement")?;
        drop(new_file);
    }
    delete_file_handle(&marker_file).context("failed to retire policy transaction marker")?;
    drop(marker_file);
    drop(final_guard);
    Ok(())
}

fn open_optional_final_guard(path: &Path) -> anyhow::Result<Option<File>> {
    match OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to retain raced policy {}", path.display())),
    }
}

fn open_optional_transaction_file(path: &Path) -> anyhow::Result<Option<File>> {
    match open_transaction_file(path) {
        Ok(file) => Ok(Some(file)),
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn verify_transaction_file_path(file: &File, expected: &Path) -> anyhow::Result<()> {
    ensure!(
        policy_security::file_link_count(file)? == 1,
        "transaction file has multiple hard links"
    );
    let resolved = policy_security::final_path_from_handle(file)?;
    ensure!(
        policy_security::paths_match_case_insensitive(&resolved, expected),
        "transaction file resolved to an unexpected path"
    );
    Ok(())
}

fn verify_transaction_file_state(
    file: &File,
    identity: FileIdentity,
    content_digest: [u8; 32],
    security_digest: [u8; 32],
) -> anyhow::Result<()> {
    ensure!(
        policy_security::file_identity(file)? == identity,
        "transaction file identity changed"
    );
    policy_security::verify_policy_file_security(file)?;
    ensure!(
        policy_security::security_state_digest(file)? == security_digest,
        "transaction file security changed"
    );
    ensure!(
        sha256_digest(&read_file_from_start(file)?) == content_digest,
        "transaction file content changed"
    );
    Ok(())
}

fn read_file_from_start(file: &File) -> anyhow::Result<Vec<u8>> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut file = file;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Atomically persist `bytes` to `final_path` only if nothing exists there yet: unlike
/// [`atomic_replace`], this never overwrites an existing destination.
///
/// Used for `Create`, where the store already observed Missing under its write lock. If a
/// leaf has raced into existence between that observation and this call, the rename fails
/// (a [`WriteFailure::PrePublication`], since the destination was never touched) and the
/// caller must re-observe and report a stale token (see `PolicyStore::replace`) rather
/// than ever silently overwriting a file it never actually observed as absent.
pub(super) fn atomic_create(
    hosting_dir: &VerifiedHostingDirectory,
    final_path: &Path,
    bytes: &[u8],
) -> Result<PersistedPolicy, WriteFailure> {
    hosting_dir
        .verify_unchanged()
        .context("hosting directory changed after policy observation")
        .map_err(WriteFailure::PrePublication)?;
    write_temp_then(hosting_dir.canonical_path(), bytes, |temp_path| {
        move_create_new(temp_path, final_path)
    })
    .map_err(WriteFailure::PrePublication)?;
    reopen_and_verify_persisted(hosting_dir, final_path, bytes).map_err(WriteFailure::PostPublication)
}

/// Create a uniquely named temporary file in `dir` with an admin-only ACL established at
/// creation (`CreateFileW` with explicit `SECURITY_ATTRIBUTES`, never a create-then-ACL
/// window; see [`policy_security::admin_only_security_attributes`]), verify that security
/// on the just-opened handle before writing anything to it, write and flush `bytes`, then
/// hand the temporary path to `commit` to make it visible at its final location (a
/// same-directory, same-volume rename, so it is atomic). The temporary file is never
/// visible to untrusted principals even before that rename: its ACL is explicit from
/// creation, not inherited.
fn write_temp_then(dir: &Path, bytes: &[u8], commit: impl FnOnce(&Path) -> anyhow::Result<()>) -> anyhow::Result<()> {
    let temp_path = dir.join(format!(".{POLICY_FILE_NAME}.tmp-{}", uuid::Uuid::new_v4()));

    let result = (|| -> anyhow::Result<()> {
        use std::io::Write as _;

        let security_attributes = policy_security::admin_only_security_attributes(false)
            .context("build admin-only security attributes for the temporary policy file")?;
        let mut temp_file = win_api_wrappers::fs::create_file(&temp_path, Some(&security_attributes))
            .with_context(|| format!("failed to create temporary policy file {}", temp_path.display()))?;

        // Verify identity/security on the just-created handle before writing anything to
        // it: never trust that the requested SECURITY_ATTRIBUTES actually took effect
        // without independently re-checking it, the same way every other trusted read in
        // this crate does.
        policy_security::verify_policy_file_security(&temp_file)
            .context("temporary policy file failed security verification immediately after creation")?;

        temp_file
            .write_all(bytes)
            .context("failed to write temporary policy file")?;
        // Strongest supported durability: flush both data and metadata before the rename.
        temp_file
            .sync_all()
            .context("failed to flush temporary policy file to disk")?;
        drop(temp_file);

        commit(&temp_path)
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

/// Reopen `final_path` after a successful atomic write and re-verify its identity,
/// security, ancestor chain, exact bytes, and parse, so the returned [`PersistedPolicy`]
/// always reflects the exact bytes actually active on disk rather than trusting the
/// write path alone. Also authoritatively (re)validates the persisted document the same
/// deterministic way a submitted draft is (item 30), even though the store already
/// validated the draft moments earlier: this is the single path every committed document
/// is trusted through, whether freshly written or later re-observed.
///
fn reopen_and_verify_persisted(
    hosting_dir: &VerifiedHostingDirectory,
    final_path: &Path,
    expected_bytes: &[u8],
) -> anyhow::Result<PersistedPolicy> {
    let final_file = OpenOptions::new()
        .read(true)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(final_path)
        .context("failed to reopen policy file for post-write verification")?;

    verify_persisted_handle(hosting_dir, &final_file, final_path, expected_bytes)
}

fn verify_persisted_handle(
    hosting_dir: &VerifiedHostingDirectory,
    final_file: &File,
    final_path: &Path,
    expected_bytes: &[u8],
) -> anyhow::Result<PersistedPolicy> {
    let dir_security_digest = hosting_dir
        .verify_unchanged()
        .context("held policy directory changed during replacement")?;
    let parent = hosting_dir.identity();
    let ancestor_security_digest =
        policy_security::verify_policy_ancestor_chain(hosting_dir.canonical_path(), "policy directory")
            .context("policy directory ancestor chain failed verification immediately after writing")?;
    let resolved =
        policy_security::final_path_from_handle(final_file).context("failed to resolve persisted policy handle")?;
    ensure!(
        policy_security::paths_match_case_insensitive(&resolved, final_path),
        "persisted policy handle resolved to an unexpected path"
    );
    let target = policy_security::file_identity(final_file)
        .context("failed to query policy file identity for post-write verification")?;

    policy_security::verify_policy_file_security(final_file)
        .context("policy file failed security verification immediately after being written")?;

    let security_digest = policy_security::security_state_digest(final_file)
        .context("failed to compute policy file security digest immediately after being written")?;

    let mut persisted = Vec::new();
    {
        use std::io::{Read as _, Seek as _, SeekFrom};
        let mut reader = final_file;
        reader.seek(SeekFrom::Start(0))?;
        reader
            .read_to_end(&mut persisted)
            .context("failed to re-read persisted policy file")?;
    }

    if persisted != expected_bytes {
        bail!("persisted policy file content does not match what was written");
    }

    let policy = serde_json::from_slice::<PolicyDocument>(&persisted)
        .context("failed to reparse the freshly persisted policy file")?;

    let committed_validation = validation::validate_committed_policy(&policy);
    ensure!(
        committed_validation.is_valid,
        "freshly persisted policy file failed authoritative semantic validation: {:?}",
        committed_validation.findings
    );

    let content_digest = sha256_digest(&persisted);

    Ok(PersistedPolicy {
        policy,
        fingerprint: DiskFingerprint::Active {
            parent,
            target,
            content_digest,
            security_digest,
            dir_security_digest,
            ancestor_security_digest,
        },
    })
}

fn move_file(from: &Path, to: &Path, flags: MOVE_FILE_FLAGS) -> anyhow::Result<()> {
    let from = U16CString::from_os_str(from.as_os_str()).context("temporary path contains an interior NUL")?;
    let to = U16CString::from_os_str(to.as_os_str()).context("final path contains an interior NUL")?;

    // SAFETY: `from` and `to` are valid, NUL-terminated UTF-16 strings live for the call.
    unsafe { MoveFileExW(from.as_pcwstr(), to.as_pcwstr(), flags) }.context("MoveFileExW failed")?;

    Ok(())
}

/// Atomically rename `from` onto `to`, replacing `to` if it already exists.
#[cfg(test)]
fn move_replace(from: &Path, to: &Path) -> anyhow::Result<()> {
    move_file(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
        .context("failed to atomically replace policy file")
}

/// Atomically rename `from` onto `to`, failing if `to` already exists (no
/// `MOVEFILE_REPLACE_EXISTING`): this is the primitive [`atomic_create`] relies on to
/// never silently overwrite a destination it never observed.
fn move_create_new(from: &Path, to: &Path) -> anyhow::Result<()> {
    move_file(from, to, MOVEFILE_WRITE_THROUGH).context("failed to atomically create policy file")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("create temp dir")
    }

    // ─── move_replace / move_create_new: the real Windows race primitives ─────
    //
    // These exercise the actual `MoveFileExW` calls `atomic_replace`/`atomic_create` rely
    // on directly, without needing the admin-only `SECURITY_ATTRIBUTES` machinery (which
    // requires an elevated/SYSTEM token to assign SYSTEM as owner and so cannot run in an
    // arbitrary, non-elevated developer/CI shell): real temporary files owned by whatever
    // account runs the test are enough to prove the rename semantics themselves.

    #[test]
    fn move_create_new_never_replaces_an_existing_destination() {
        let dir = temp_dir();
        let source = dir.path().join("source.tmp");
        let destination = dir.path().join("destination.json");

        std::fs::write(&destination, b"original").unwrap();
        std::fs::write(&source, b"attempted-overwrite").unwrap();

        let error = move_create_new(&source, &destination).unwrap_err();
        assert!(!format!("{error:#}").is_empty());

        // Neither file was touched: the failed rename must be a complete no-op.
        assert_eq!(std::fs::read(&destination).unwrap(), b"original");
        assert_eq!(std::fs::read(&source).unwrap(), b"attempted-overwrite");
    }

    #[test]
    fn move_create_new_succeeds_against_a_missing_destination() {
        let dir = temp_dir();
        let source = dir.path().join("source.tmp");
        let destination = dir.path().join("destination.json");

        std::fs::write(&source, b"content").unwrap();
        move_create_new(&source, &destination).expect("create-new rename against a missing destination succeeds");

        assert!(!source.exists(), "the source is consumed by a successful rename");
        assert_eq!(std::fs::read(&destination).unwrap(), b"content");
    }

    #[test]
    fn move_replace_overwrites_an_existing_destination() {
        let dir = temp_dir();
        let source = dir.path().join("source.tmp");
        let destination = dir.path().join("destination.json");

        std::fs::write(&destination, b"original").unwrap();
        std::fs::write(&source, b"replacement").unwrap();

        move_replace(&source, &destination).expect("replace rename succeeds against an existing destination");

        assert!(!source.exists());
        assert_eq!(std::fs::read(&destination).unwrap(), b"replacement");
    }

    fn open_deletable_test_file(path: &Path, content: &[u8]) -> File {
        std::fs::write(path, content).unwrap();
        OpenOptions::new()
            .access_mode(FILE_GENERIC_READ.0 | DELETE.0 | READ_CONTROL.0)
            .share_mode(FILE_SHARE_READ.0)
            .open(path)
            .unwrap()
    }

    #[test]
    fn handle_rename_never_replaces_an_existing_destination() {
        let dir = temp_dir();
        let source = dir.path().join("source.tmp");
        let destination = dir.path().join("destination.json");
        let source_file = open_deletable_test_file(&source, b"source");
        std::fs::write(&destination, b"destination").unwrap();
        let dir_file = open_directory_no_reparse(dir.path()).unwrap();

        rename_file_handle(&source_file, &dir_file, destination.file_name().unwrap()).unwrap_err();

        assert_eq!(std::fs::read(&source).unwrap(), b"source");
        assert_eq!(std::fs::read(&destination).unwrap(), b"destination");
    }

    #[test]
    fn retained_directory_prevents_path_retarget_during_handle_rename() {
        let root = temp_dir();
        let dir = root.path().join("held");
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("source.tmp");
        let destination = dir.join("destination.json");
        let source_file = open_deletable_test_file(&source, b"source");
        let dir_file = open_directory_no_reparse(&dir).unwrap();

        assert!(std::fs::rename(&dir, root.path().join("retargeted")).is_err());
        rename_file_handle(&source_file, &dir_file, destination.file_name().unwrap()).unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), b"source");
        assert!(!root.path().join("retargeted").exists());
    }

    #[test]
    fn retained_write_observation_blocks_external_target_changes() {
        let dir = temp_dir();
        let path = dir.path().join("policy.json");
        let replacement = dir.path().join("replacement.json");
        let retained = open_deletable_test_file(&path, b"observed");
        std::fs::write(&replacement, b"replacement").unwrap();

        assert!(std::fs::write(&path, b"edited").is_err());
        assert!(std::fs::remove_file(&path).is_err());
        assert!(std::fs::rename(&path, dir.path().join("replaced.json")).is_err());
        assert!(move_replace(&replacement, &path).is_err());
        assert_eq!(read_file_from_start(&retained).unwrap(), b"observed");
        assert_eq!(std::fs::read(&replacement).unwrap(), b"replacement");
    }

    #[test]
    fn handle_cleanup_removes_read_only_transaction_files() {
        let dir = temp_dir();
        let path = dir.path().join("readonly.old");
        std::fs::write(&path, b"old").unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();
        let file = open_transaction_file(&path).unwrap();

        delete_file_handle(&file).unwrap();
        drop(file);

        assert!(!path.exists());
    }

    #[test]
    fn conditional_publication_preserves_a_final_created_after_tombstoning() {
        let dir = temp_dir();
        let dir_file = open_directory_no_reparse(dir.path()).unwrap();
        let final_path = dir.path().join("policy.json");
        let paths = TransactionPaths::new(dir.path(), &final_path).unwrap();
        let observed = RetainedPolicyFile::Real(open_deletable_test_file(&final_path, b"observed"));
        let marker = open_deletable_test_file(&paths.marker, b"marker");
        let replacement = open_deletable_test_file(&paths.new, b"replacement");

        let prepared = PreparedTransaction {
            dir_handle: &dir_file,
            observed_target: &observed,
            temp_file: &replacement,
            paths: &paths,
            final_path: &final_path,
        };
        let result = publish_prepared_transaction(
            &prepared,
            || {
                std::fs::write(&final_path, b"external")?;
                Ok(())
            },
            || Ok(()),
            || Ok(()),
        );

        assert!(matches!(result, Err(WriteFailure::ConcurrentChange(_))));
        let old = observed.into_handle();
        recover_verified_transaction(
            &dir_file,
            dir.path(),
            final_path.file_name().unwrap(),
            marker,
            Some(old),
            Some(replacement),
        )
        .unwrap();
        assert_eq!(std::fs::read(&final_path).unwrap(), b"external");
        assert!(!paths.old.exists());
        assert!(!paths.new.exists());
        assert!(!paths.marker.exists());
    }

    #[test]
    fn interrupted_publication_recovers_the_exact_observed_target() {
        let dir = temp_dir();
        let dir_file = open_directory_no_reparse(dir.path()).unwrap();
        let final_path = dir.path().join("policy.json");
        let paths = TransactionPaths::new(dir.path(), &final_path).unwrap();
        let observed = RetainedPolicyFile::Real(open_deletable_test_file(&final_path, b"observed"));
        let marker = open_deletable_test_file(&paths.marker, b"marker");
        let replacement = open_deletable_test_file(&paths.new, b"replacement");

        let prepared = PreparedTransaction {
            dir_handle: &dir_file,
            observed_target: &observed,
            temp_file: &replacement,
            paths: &paths,
            final_path: &final_path,
        };
        let result = publish_prepared_transaction(
            &prepared,
            || anyhow::bail!("simulated crash after tombstone"),
            || Ok(()),
            || Ok(()),
        );
        assert!(matches!(result, Err(WriteFailure::PrePublication(_))));
        assert!(!final_path.exists());
        assert!(paths.old.exists());

        let old = observed.into_handle();
        recover_verified_transaction(
            &dir_file,
            dir.path(),
            final_path.file_name().unwrap(),
            marker,
            Some(old),
            Some(replacement),
        )
        .unwrap();

        assert_eq!(std::fs::read(&final_path).unwrap(), b"observed");
        assert!(!paths.new.exists());
        assert!(!paths.marker.exists());
    }

    #[test]
    fn changed_post_tombstone_evidence_restores_observed_target_before_conflict() {
        let dir = temp_dir();
        let dir_file = open_directory_no_reparse(dir.path()).unwrap();
        let final_path = dir.path().join("policy.json");
        let paths = TransactionPaths::new(dir.path(), &final_path).unwrap();
        let observed = RetainedPolicyFile::Real(open_deletable_test_file(&final_path, b"observed"));
        let marker = open_deletable_test_file(&paths.marker, b"marker");
        let replacement = open_deletable_test_file(&paths.new, b"replacement");
        let prepared = PreparedTransaction {
            dir_handle: &dir_file,
            observed_target: &observed,
            temp_file: &replacement,
            paths: &paths,
            final_path: &final_path,
        };

        let result = publish_prepared_transaction(
            &prepared,
            || Ok(()),
            || anyhow::bail!("simulated retained target mutation"),
            || Ok(()),
        );

        assert!(matches!(result, Err(WriteFailure::ConcurrentChange(_))));
        assert_eq!(read_file_from_start(observed.handle()).unwrap(), b"observed");
        assert!(final_path.exists());
        assert!(!paths.old.exists());

        drop(observed);
        recover_verified_transaction(
            &dir_file,
            dir.path(),
            final_path.file_name().unwrap(),
            marker,
            None,
            Some(replacement),
        )
        .unwrap();
        assert_eq!(std::fs::read(&final_path).unwrap(), b"observed");
        assert!(!paths.new.exists());
        assert!(!paths.marker.exists());
    }

    #[test]
    fn recovery_preserves_published_replacement_after_interruption() {
        let dir = temp_dir();
        let dir_file = open_directory_no_reparse(dir.path()).unwrap();
        let final_path = dir.path().join("policy.json");
        let paths = TransactionPaths::new(dir.path(), &final_path).unwrap();
        let observed = RetainedPolicyFile::Real(open_deletable_test_file(&final_path, b"observed"));
        let marker = open_deletable_test_file(&paths.marker, b"marker");
        let replacement = open_deletable_test_file(&paths.new, b"replacement");

        let prepared = PreparedTransaction {
            dir_handle: &dir_file,
            observed_target: &observed,
            temp_file: &replacement,
            paths: &paths,
            final_path: &final_path,
        };
        let result = publish_prepared_transaction(
            &prepared,
            || Ok(()),
            || Ok(()),
            || anyhow::bail!("simulated crash after publication"),
        );
        assert!(matches!(result, Err(WriteFailure::PostPublication(_))));
        assert_eq!(read_file_from_start(&replacement).unwrap(), b"replacement");
        assert!(paths.old.exists());

        let old = observed.into_handle();
        drop(replacement);
        recover_verified_transaction(
            &dir_file,
            dir.path(),
            final_path.file_name().unwrap(),
            marker,
            Some(old),
            None,
        )
        .unwrap();

        assert_eq!(std::fs::read(&final_path).unwrap(), b"replacement");
        assert!(!paths.old.exists());
        assert!(!paths.marker.exists());
    }

    #[test]
    fn recovery_restores_exact_tombstone_when_final_is_absent() {
        let dir = temp_dir();
        let dir_file = open_directory_no_reparse(dir.path()).unwrap();
        let marker_path = dir.path().join("marker");
        let old_path = dir.path().join("old");
        let new_path = dir.path().join("new");
        let marker = open_deletable_test_file(&marker_path, b"marker");
        let old = open_deletable_test_file(&old_path, b"old");
        let new = open_deletable_test_file(&new_path, b"new");

        recover_verified_transaction(
            &dir_file,
            dir.path(),
            OsStr::new("policy.json"),
            marker,
            Some(old),
            Some(new),
        )
        .unwrap();

        assert_eq!(std::fs::read(dir.path().join("policy.json")).unwrap(), b"old");
        assert!(!marker_path.exists());
        assert!(!old_path.exists());
        assert!(!new_path.exists());
    }

    #[test]
    fn recovery_discards_incomplete_marker_staging_only_when_final_is_present() {
        let dir = temp_dir();
        let final_path = dir.path().join("policy.json");
        let staging_path = dir.path().join("marker.prepare");
        std::fs::write(&final_path, b"original").unwrap();
        let staging = open_deletable_test_file(&staging_path, b"partial marker");

        recover_marker_staging(&final_path, staging).unwrap();

        assert_eq!(std::fs::read(&final_path).unwrap(), b"original");
        assert!(!staging_path.exists());
    }

    #[test]
    fn recovery_retains_incomplete_marker_staging_when_final_is_absent() {
        let dir = temp_dir();
        let final_path = dir.path().join("policy.json");
        let staging_path = dir.path().join("marker.prepare");
        let staging = open_deletable_test_file(&staging_path, b"partial marker");

        recover_marker_staging(&final_path, staging).unwrap_err();

        assert_eq!(std::fs::read(&staging_path).unwrap(), b"partial marker");
        assert!(staging_path.exists());
    }

    #[test]
    fn recovery_preserves_original_before_tombstoning() {
        let dir = temp_dir();
        let dir_file = open_directory_no_reparse(dir.path()).unwrap();
        let final_path = dir.path().join("policy.json");
        let marker_path = dir.path().join("marker");
        let new_path = dir.path().join("new");
        std::fs::write(&final_path, b"original").unwrap();
        let marker = open_deletable_test_file(&marker_path, b"marker");
        let new = open_deletable_test_file(&new_path, b"new");

        recover_verified_transaction(
            &dir_file,
            dir.path(),
            final_path.file_name().unwrap(),
            marker,
            None,
            Some(new),
        )
        .unwrap();

        assert_eq!(std::fs::read(&final_path).unwrap(), b"original");
        assert!(!marker_path.exists());
        assert!(!new_path.exists());
    }

    #[test]
    fn recovery_preserves_final_created_after_tombstoning() {
        let dir = temp_dir();
        let dir_file = open_directory_no_reparse(dir.path()).unwrap();
        let final_path = dir.path().join("policy.json");
        let marker_path = dir.path().join("marker");
        let old_path = dir.path().join("old");
        let new_path = dir.path().join("new");
        std::fs::write(&final_path, b"external").unwrap();
        let marker = open_deletable_test_file(&marker_path, b"marker");
        let old = open_deletable_test_file(&old_path, b"old");
        let new = open_deletable_test_file(&new_path, b"new");

        recover_verified_transaction(
            &dir_file,
            dir.path(),
            final_path.file_name().unwrap(),
            marker,
            Some(old),
            Some(new),
        )
        .unwrap();

        assert_eq!(std::fs::read(&final_path).unwrap(), b"external");
        assert!(!marker_path.exists());
        assert!(!old_path.exists());
        assert!(!new_path.exists());
    }

    #[test]
    fn recovery_failure_never_discards_the_only_tombstone() {
        let dir = temp_dir();
        let dir_file = open_directory_no_reparse(dir.path()).unwrap();
        let marker_path = dir.path().join("marker");
        let old_path = dir.path().join("old");
        let marker = open_deletable_test_file(&marker_path, b"marker");
        let old = open_deletable_test_file(&old_path, b"old");

        recover_verified_transaction(
            &dir_file,
            dir.path(),
            OsStr::new(r"missing\policy.json"),
            marker,
            Some(old),
            None,
        )
        .unwrap_err();

        assert_eq!(std::fs::read(&old_path).unwrap(), b"old");
        assert!(marker_path.exists());
        assert!(old_path.exists());
    }

    #[test]
    fn recovery_rejects_multiple_or_untrusted_remnants() {
        let dir = temp_dir();
        let dir_file = open_directory_no_reparse(dir.path()).unwrap();
        let id_a = uuid::Uuid::new_v4();
        let id_b = uuid::Uuid::new_v4();
        std::fs::write(dir.path().join(format!(".policy.json.txn-{id_a}.marker")), b"untrusted").unwrap();
        std::fs::write(dir.path().join(format!(".policy.json.txn-{id_b}.marker")), b"untrusted").unwrap();
        assert!(
            recover_interrupted_transaction(&dir_file, dir.path(), OsStr::new("policy.json"))
                .unwrap_err()
                .to_string()
                .contains("multiple")
        );

        std::fs::remove_file(dir.path().join(format!(".policy.json.txn-{id_b}.marker"))).unwrap();
        assert!(recover_interrupted_transaction(&dir_file, dir.path(), OsStr::new("policy.json")).is_err());
    }

    #[test]
    fn create_recovery_rejects_malformed_or_untrusted_remnants() {
        let dir = temp_dir();
        let malformed = dir.path().join(format!(".{POLICY_FILE_NAME}.tmp-not-a-uuid"));
        std::fs::write(&malformed, b"partial").unwrap();
        assert!(recover_create_temporary_files(dir.path()).is_err());

        std::fs::remove_file(&malformed).unwrap();
        let untrusted = dir
            .path()
            .join(format!(".{POLICY_FILE_NAME}.tmp-{}", uuid::Uuid::new_v4()));
        std::fs::write(&untrusted, b"partial").unwrap();
        assert!(recover_create_temporary_files(dir.path()).is_err());
    }

    #[test]
    fn transaction_marker_round_trips_exact_state() {
        let expected = DiskFingerprint::test_active(b"old", 2, 3, 4, 5);
        let marker =
            TransactionMarker::from_observation(uuid::Uuid::new_v4(), Path::new(r"C:\policy.json"), &expected, b"new")
                .unwrap();

        let decoded = TransactionMarker::from_bytes(&marker.to_bytes()).unwrap();

        assert_eq!(decoded.id, marker.id);
        assert_eq!(decoded.final_leaf, marker.final_leaf);
        assert_eq!(decoded.old_identity, marker.old_identity);
        assert_eq!(decoded.old_content_digest, marker.old_content_digest);
        assert_eq!(decoded.old_security_digest, marker.old_security_digest);
        assert_eq!(decoded.new_content_digest, marker.new_content_digest);
    }

    // ─── probe_write_capability / volume_filesystem_name ──────────────────────
    //
    // No elevation required: these never touch `admin_only_security_attributes`.

    #[test]
    fn volume_filesystem_name_reports_a_known_filesystem_for_a_temp_directory() {
        let dir = temp_dir();
        let filesystem = volume_filesystem_name(dir.path()).expect("query temp directory filesystem");
        assert!(!filesystem.is_empty());
    }

    #[test]
    fn probe_write_capability_succeeds_on_an_ordinary_writable_temp_directory() {
        let dir = temp_dir();
        probe_write_capability(dir.path())
            .expect("an ordinary user-writable NTFS temp directory must probe as capable");

        // Nondestructive: the probe must never leave stray files behind.
        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .collect();
        assert!(leftover.is_empty(), "probe left files behind: {leftover:?}");
    }

    #[test]
    fn failed_atomicity_probe_is_not_cached() {
        let dir = temp_dir();
        let missing = dir.path().join("missing");
        let cache = AtomicityProbeCache::new();

        let result = cache.get_or_probe(&missing, test_identity(1), test_security_digest(1));

        assert!(result.is_err());
        assert!(cache.cached_success.lock().unwrap().is_none());
    }

    // ─── DiskFingerprint rotation/stability semantics ─────────────────────────

    #[test]
    fn active_fingerprint_is_stable_for_identical_inputs() {
        let a = DiskFingerprint::test_active(b"same bytes", 1, 1, 1, 1);
        let b = DiskFingerprint::test_active(b"same bytes", 1, 1, 1, 1);
        assert_eq!(a, b);
    }

    #[test]
    fn active_fingerprint_rotates_on_same_byte_target_replacement() {
        // Same content, but a different target generation (the file object itself was
        // replaced, e.g. deleted and recreated with identical bytes).
        let before = DiskFingerprint::test_active(b"same bytes", 1, 1, 1, 1);
        let after = DiskFingerprint::test_active(b"same bytes", 2, 1, 1, 1);
        assert_ne!(before, after);
    }

    #[test]
    fn active_fingerprint_rotates_on_acl_change() {
        let before = DiskFingerprint::test_active(b"same bytes", 1, 1, 1, 1);
        let after = DiskFingerprint::test_active(b"same bytes", 1, 1, 2, 1);
        assert_ne!(before, after);
    }

    #[test]
    fn active_fingerprint_rotates_on_parent_replacement() {
        let before = DiskFingerprint::test_active(b"same bytes", 1, 1, 1, 1);
        let after = DiskFingerprint::test_active(b"same bytes", 1, 2, 1, 1);
        assert_ne!(before, after);
    }

    #[test]
    fn active_fingerprint_rotates_on_hosting_directory_acl_change() {
        let before = DiskFingerprint::test_active(b"same bytes", 1, 1, 1, 1);
        let after = DiskFingerprint::test_active(b"same bytes", 1, 1, 1, 2);
        assert_ne!(before, after);
    }

    #[test]
    fn missing_fingerprints_differ_for_different_parents() {
        let a = DiskFingerprint::test_missing(1, 1);
        let b = DiskFingerprint::test_missing(2, 1);
        assert_ne!(a, b);
    }

    #[test]
    fn missing_fingerprint_is_stable_for_the_same_parent() {
        let a = DiskFingerprint::test_missing(7, 1);
        let b = DiskFingerprint::test_missing(7, 1);
        assert_eq!(a, b);
    }

    // ─── Real, privilege-sensitive Windows behavior ───────────────────────────
    //
    // The Agent service runs as LocalSystem in production, so setting a newly created
    // object's owner to SYSTEM is unprivileged there; a non-elevated developer/CI shell
    // cannot assign an owner it does not itself hold a enabling privilege for. Mirrors the
    // existing `winget_app_exec_alias_passes_elevated_verification` pattern: attempt the
    // real operation, and require the failure (when one occurs) to be exactly the
    // anticipated privilege limitation rather than silently skipping the test.
    #[test]
    fn default_directory_is_created_secured_or_fails_on_the_expected_privilege_limitation() {
        let dir = temp_dir();
        let candidate = dir.path().join("package-broker");

        match ensure_default_directory_secured(&candidate) {
            Ok((canonical, _ancestor_security_digest)) => {
                // Elevated/SYSTEM test host: verify the directory really is admin-only and
                // that a *second* call (existing-directory path) does not need to (and does
                // not) fail.
                assert!(
                    canonical.is_absolute(),
                    "canonical directory must be an absolute, handle-resolved path"
                );
                let (handle, _) = open_and_verify_directory_identity(&candidate).unwrap();
                policy_security::verify_policy_directory_security(&handle)
                    .expect("freshly created directory must already be admin-only secured");
                drop(handle);
                ensure_default_directory_secured(&candidate)
                    .expect("re-verifying an already-secured directory succeeds");
            }
            Err(error) => {
                let message = format!("{error:#}");
                assert!(
                    message.contains("owner") || message.contains("privilege") || message.contains("Owner"),
                    "unexpected error creating the default directory: {message}"
                );
            }
        }
    }

    // ─── validate_configured_path_shape (item 18/22) ──────────────────────────

    #[test]
    fn relative_path_is_rejected() {
        let error = validate_configured_path_shape(Path::new(r"relative\policy.json")).unwrap_err();
        assert!(error.contains("absolute"), "{error}");
    }

    #[test]
    fn trailing_separator_is_rejected() {
        let error = validate_configured_path_shape(Path::new(r"C:\ProgramData\Devolutions\")).unwrap_err();
        assert!(error.contains("separator"), "{error}");
    }

    #[test]
    fn dot_component_is_rejected() {
        let error = validate_configured_path_shape(Path::new(r"C:\ProgramData\.\policy.json")).unwrap_err();
        assert!(error.contains("'.'"), "{error}");
    }

    #[test]
    fn dotdot_component_is_rejected() {
        let error = validate_configured_path_shape(Path::new(r"C:\ProgramData\..\policy.json")).unwrap_err();
        assert!(error.contains("'..'"), "{error}");
    }

    #[test]
    fn yaml_extension_is_rejected() {
        let error = validate_configured_path_shape(Path::new(r"C:\ProgramData\Devolutions\policy.yaml")).unwrap_err();
        assert!(error.contains(".json"), "{error}");
    }

    #[test]
    fn yml_extension_is_rejected() {
        let error = validate_configured_path_shape(Path::new(r"C:\ProgramData\Devolutions\policy.yml")).unwrap_err();
        assert!(error.contains(".json"), "{error}");
    }

    #[test]
    fn extensionless_path_is_rejected() {
        let error = validate_configured_path_shape(Path::new(r"C:\ProgramData\Devolutions\policy")).unwrap_err();
        assert!(error.contains(".json"), "{error}");
    }

    #[test]
    fn other_extension_is_rejected() {
        let error = validate_configured_path_shape(Path::new(r"C:\ProgramData\Devolutions\policy.txt")).unwrap_err();
        assert!(error.contains(".json"), "{error}");
    }

    #[test]
    fn uppercase_json_extension_is_accepted() {
        validate_configured_path_shape(Path::new(r"C:\ProgramData\Devolutions\policy.JSON"))
            .expect("extension check is case-insensitive");
    }

    #[test]
    fn well_formed_absolute_json_path_is_accepted() {
        validate_configured_path_shape(Path::new(r"C:\ProgramData\Devolutions\PackageBroker\policy.json"))
            .expect("well-formed absolute .json path must be accepted");
    }

    /// End-to-end (item 18/31): a configured path with an unsupported extension must be
    /// reported through the *real* `observe` with the shared contract's dedicated
    /// [`PolicyReadOnlyReason::UnsupportedFormat`], and the file must never even be
    /// opened, whatever it (if anything) actually contains at that path.
    fn assert_unsupported_format_is_reported_invalid_and_read_only_end_to_end(file_name: &str) {
        let dir = temp_dir();
        let path = dir.path().join(file_name);
        // If shape validation were ever skipped, this well-formed JSON content would
        // make the file parse as Active; its presence proves the rejection is really
        // about the extension, not a coincidentally-unreadable/absent file.
        std::fs::write(&path, br#"{"not": "even close to a policy, but that's not the point"}"#).unwrap();

        let probe_cache = AtomicityProbeCache::new();
        let observation = observe(PolicyConfigurationSource::ConfiguredPath, &path, &probe_cache);

        assert_eq!(observation.state, PolicyManagementState::Invalid);
        assert_eq!(observation.write_capability, PolicyWriteCapability::ReadOnly);
        assert_eq!(
            observation.read_only_reason,
            Some(PolicyReadOnlyReason::UnsupportedFormat)
        );
        assert!(observation.policy.is_none());
    }

    #[test]
    fn yaml_extension_is_reported_invalid_and_read_only_end_to_end() {
        assert_unsupported_format_is_reported_invalid_and_read_only_end_to_end("policy.yaml");
    }

    #[test]
    fn yml_extension_is_reported_invalid_and_read_only_end_to_end() {
        assert_unsupported_format_is_reported_invalid_and_read_only_end_to_end("policy.yml");
    }

    #[test]
    fn extensionless_path_is_reported_invalid_and_read_only_end_to_end() {
        assert_unsupported_format_is_reported_invalid_and_read_only_end_to_end("policy");
    }

    #[test]
    fn other_extension_is_reported_invalid_and_read_only_end_to_end() {
        assert_unsupported_format_is_reported_invalid_and_read_only_end_to_end("policy.txt");
    }

    // ─── Strict policy ancestor walk: reparse rejection (item 16) ─────────────
    //
    // Directory junctions (unlike symlinks) require no special privilege to create, so
    // this exercises the real reparse-point rejection without needing an elevated shell.

    #[test]
    fn junction_standing_in_for_an_ancestor_is_rejected() {
        let root = temp_dir();
        let real_ancestor = root.path().join("real-ancestor");
        std::fs::create_dir(&real_ancestor).unwrap();
        let junction = root.path().join("junction-ancestor");
        create_directory_junction(&junction, &real_ancestor);

        let candidate_dir = junction.join("policy-dir");
        std::fs::create_dir(&candidate_dir).unwrap();

        let error = policy_security::verify_policy_ancestor_chain(&candidate_dir, "policy directory").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("reparse point"), "unexpected error: {message}");
    }

    /// Create a directory junction (`mklink /J`) without requiring elevation.
    fn create_directory_junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("spawn mklink");
        assert!(
            status.success(),
            "failed to create junction {} -> {}",
            link.display(),
            target.display()
        );
    }

    // ─── Hard-link alias rejection for the leaf file (item 22) ────────────────
    //
    // Hard links (unlike symlinks) require no special privilege to create on the same
    // volume, so this exercises the real alias-rejection path directly.

    #[test]
    fn policy_leaf_with_multiple_hard_links_is_rejected() {
        let dir = temp_dir();
        let real_file = dir.path().join("real-policy.json");
        std::fs::write(&real_file, b"{}").unwrap();
        let alias = dir.path().join("alias-policy.json");
        std::fs::hard_link(&real_file, &alias).expect("create hard link");

        let handle = OpenOptions::new()
            .read(true)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(&alias)
            .unwrap();
        assert_eq!(policy_security::file_link_count(&handle).unwrap(), 2);
    }

    #[test]
    fn resolved_parent_alias_and_leaf_casing_are_compared_independently() {
        let configured = Path::new(r"C:\RUNNER~1\AppData\Local\Temp\policy.json");
        let resolved_parent = Path::new(r"C:\actions\runneradmin\AppData\Local\Temp");
        let resolved_file = resolved_parent.join("Policy.JSON");

        assert!(resolved_policy_path_matches(
            &resolved_file,
            resolved_parent,
            configured.file_name().unwrap()
        ));
        assert!(!resolved_policy_path_matches(
            &resolved_parent.join("other.json"),
            resolved_parent,
            configured.file_name().unwrap()
        ));
    }

    #[test]
    fn resolved_policy_path_accepts_windows_unicode_case_mapping() {
        let configured = Path::new(r"C:\DÉVOLUTIONS\PackageBroker\policé.json");
        let resolved_parent = Path::new(r"c:\dévolutions\packagebroker");
        let resolved_file = resolved_parent.join("POLICÉ.JSON");

        assert!(resolved_policy_path_matches(
            &resolved_file,
            resolved_parent,
            configured.file_name().unwrap()
        ));
        assert!(!resolved_policy_path_matches(
            &resolved_file,
            Path::new(r"c:\dévolutions\other"),
            configured.file_name().unwrap()
        ));
        assert!(!resolved_policy_path_matches(
            &resolved_parent.join("different.json"),
            resolved_parent,
            configured.file_name().unwrap()
        ));
    }

    // ─── DiskFingerprint::Invalid enrichment (item 15) ────────────────────────

    fn invalid_fingerprint_for_path(path: &str, reason: validation::DiskFailureReason) -> DiskFingerprint {
        DiskFingerprint::Invalid {
            path: PathBuf::from(path),
            parent: None,
            dir_security_digest: None,
            ancestor_security_digest: None,
            target: None,
            content_digest: None,
            security_digest: None,
            reason,
        }
    }

    #[test]
    fn invalid_fingerprints_for_distinct_paths_never_collide() {
        // Two different configured paths that both fail identically (e.g. neither
        // parent could even be opened, so no identity is available to distinguish them)
        // must still never be mistaken for each other.
        let a = invalid_fingerprint_for_path(r"C:\a\policy.json", validation::DiskFailureReason::Unreadable);
        let b = invalid_fingerprint_for_path(r"C:\b\policy.json", validation::DiskFailureReason::Unreadable);
        assert_ne!(a, b);
    }

    #[test]
    fn invalid_fingerprint_is_stable_for_the_same_path_and_reason() {
        let a = invalid_fingerprint_for_path(r"C:\a\policy.json", validation::DiskFailureReason::Unreadable);
        let b = invalid_fingerprint_for_path(r"C:\a\policy.json", validation::DiskFailureReason::Unreadable);
        assert_eq!(a, b);
    }

    /// Build a fully-populated `DiskFingerprint::Invalid` for the rotation/stability
    /// tests below, so each test only has to vary the one field it is proving rotates
    /// (or, for the "unchanged" test, none at all).
    fn full_invalid_fingerprint(
        path: &str,
        parent_generation: u32,
        ancestor_marker: &[u8],
        target_generation: u32,
        content: &[u8],
        security_marker: &[u8],
        reason: validation::DiskFailureReason,
    ) -> DiskFingerprint {
        DiskFingerprint::Invalid {
            path: PathBuf::from(path),
            parent: Some(test_identity(parent_generation)),
            dir_security_digest: Some(sha256_digest(b"directory-security")),
            ancestor_security_digest: Some(sha256_digest(ancestor_marker)),
            target: Some(test_identity(target_generation)),
            content_digest: Some(sha256_digest(content)),
            security_digest: Some(sha256_digest(security_marker)),
            reason,
        }
    }

    #[test]
    fn invalid_fingerprint_rotates_on_parent_replacement() {
        let before = full_invalid_fingerprint(
            r"C:\a\policy.json",
            1,
            b"ancestors",
            1,
            b"same content",
            b"security",
            validation::DiskFailureReason::MalformedContent,
        );
        let after = full_invalid_fingerprint(
            r"C:\a\policy.json",
            2, // only the parent generation differs
            b"ancestors",
            1,
            b"same content",
            b"security",
            validation::DiskFailureReason::MalformedContent,
        );
        assert_ne!(before, after);
    }

    #[test]
    fn invalid_fingerprint_rotates_on_same_content_target_replacement() {
        // Same path and same byte-for-byte content digest, but a different target
        // identity (the invalid file object itself was replaced, e.g. deleted and
        // recreated with identical bytes): must still rotate.
        let before = full_invalid_fingerprint(
            r"C:\a\policy.json",
            1,
            b"ancestors",
            1,
            b"same content",
            b"security",
            validation::DiskFailureReason::MalformedContent,
        );
        let after = full_invalid_fingerprint(
            r"C:\a\policy.json",
            1,
            b"ancestors",
            2, // only the target generation differs
            b"same content",
            b"security",
            validation::DiskFailureReason::MalformedContent,
        );
        assert_ne!(before, after);
    }

    #[test]
    fn invalid_fingerprint_rotates_on_acl_change() {
        let before = full_invalid_fingerprint(
            r"C:\a\policy.json",
            1,
            b"ancestors",
            1,
            b"same content",
            b"security-a",
            validation::DiskFailureReason::MalformedContent,
        );
        let after = full_invalid_fingerprint(
            r"C:\a\policy.json",
            1,
            b"ancestors",
            1,
            b"same content",
            b"security-b", // only the security digest marker differs
            validation::DiskFailureReason::MalformedContent,
        );
        assert_ne!(before, after);
    }

    #[test]
    fn invalid_fingerprint_is_stable_when_truly_unchanged() {
        let a = full_invalid_fingerprint(
            r"C:\a\policy.json",
            1,
            b"ancestors",
            1,
            b"same content",
            b"security",
            validation::DiskFailureReason::MalformedContent,
        );
        let b = full_invalid_fingerprint(
            r"C:\a\policy.json",
            1,
            b"ancestors",
            1,
            b"same content",
            b"security",
            validation::DiskFailureReason::MalformedContent,
        );
        assert_eq!(a, b);
    }

    // ─── Mandatory probe cleanup (item 28) ─────────────────────────────────────

    #[test]
    fn cleanup_probe_file_tolerates_an_already_absent_file() {
        let dir = temp_dir();
        let path = dir.path().join("never-created.tmp");
        cleanup_probe_file(&path).expect("removing an already-absent file must be tolerated");
    }

    #[test]
    fn cleanup_probe_file_fails_when_removal_is_blocked() {
        let dir = temp_dir();
        let path = dir.path().join("locked.tmp");
        std::fs::write(&path, b"content").unwrap();

        // Hold the file open without FILE_SHARE_DELETE so the removal attempt below
        // fails with something other than NotFound.
        let _locked = OpenOptions::new()
            .read(true)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
            .open(&path)
            .unwrap();

        let error = cleanup_probe_file(&path).unwrap_err();
        assert!(!format!("{error:#}").is_empty());
        assert!(path.exists(), "the file must still be present after a failed cleanup");
    }
}
