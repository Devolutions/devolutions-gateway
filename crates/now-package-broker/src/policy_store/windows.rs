//! Windows filesystem primitives backing the policy store.
//!
//! Owns: resolving the default policy directory/path, creating that dedicated directory
//! securely (SYSTEM/Administrators only, established atomically at creation), verifying
//! (never rewriting) a custom-configured directory's existing security -- including both
//! directories' ancestor chains -- observing the exact on-disk state of the policy file
//! as an internal [`DiskFingerprint`] (never itself exposed; see `PolicyStore::token_for`
//! for how it becomes the opaque store token), and the atomic same-directory
//! temp-file-then-rename write with post-write verification.
//!
//! Windows provides no target-identity compare-and-swap primitive for file replacement
//! (`ReplaceFileW`'s write-through mode is not universally supported, and there is no
//! `MoveFileEx`-family option conditioned on the destination's current file id). What is
//! implemented here is the strongest supported approximation: the hosting directory is
//! opened without delete sharing and held for the duration of each observation/write (so
//! it cannot be deleted or replaced mid-operation), restricted to trusted principals so
//! untrusted processes cannot race the temporary file, written through a same-volume
//! atomic rename ([`atomic_replace`], or [`atomic_create`] when the destination must not
//! be overwritten), and verified (security, exact bytes, parse) after the fact. This
//! narrows -- it does not eliminate -- the residual race with a *different*, already
//! SYSTEM/Administrators-trusted writer (including an external editor) acting on the same
//! file at the same time; Windows offers no primitive that closes that specific gap.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail, ensure};
use now_policy::PolicyDocument;
use now_policy_api::{
    API_VERSION_STR, InvalidPolicyDiagnostics, PolicyConfigurationSource, PolicyManagementState, PolicyReadOnlyReason,
    PolicyStoreToken, PolicyWriteCapability,
};
use sha2::{Digest as _, Sha256};
use win_api_wrappers::str::{U16CStrExt as _, U16CString};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetVolumeInformationW,
    GetVolumePathNameW, MOVE_FILE_FLAGS, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, READ_CONTROL,
};

use crate::policy_security::{self, FileIdentity};
use crate::policy_store::validation;

/// Base file name for the policy file (a fixed name inside its dedicated directory).
pub(super) const POLICY_FILE_NAME: &str = "package-broker-policy.json";

/// Default dedicated directory hosting the policy file: `%PROGRAMDATA%\Devolutions\PackageBroker`.
///
/// Deliberately a top-level sibling of `%PROGRAMDATA%\Devolutions\Agent`, not a
/// subdirectory of it: `Agent` is shared with unrelated Agent features and its own
/// ancestor-security check must tolerate whatever grants those features require there,
/// which can never be proven as strict as the dedicated policy directory itself needs
/// its *own* ancestor chain to be (see [`policy_security::verify_directory_ancestor_chain`]).
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

/// Caches the one-time, side-effecting filesystem atomic-replace capability probe
/// ([`probe_write_capability`]) so it is not repeated on every re-observation/publication
/// (item 20): only the cheap, side-effect-free security/shape/ancestor verification in
/// [`observe`] happens every time. Invalidated (and re-probed) automatically whenever the
/// verified directory's own identity changes (e.g. it was deleted and recreated, possibly
/// on a different volume), so a stale probe result can never be trusted past the exact
/// directory object it was actually measured against.
pub(super) struct AtomicityProbeCache {
    cached: std::sync::Mutex<Option<(FileIdentity, ProbeResult)>>,
}

impl AtomicityProbeCache {
    pub(super) fn new() -> Self {
        Self {
            cached: std::sync::Mutex::new(None),
        }
    }

    /// Returns the cached probe result for `dir`/`dir_identity`, re-probing (and
    /// updating the cache) if this is the first call or the directory's identity no
    /// longer matches what was last cached.
    fn get_or_probe(&self, dir: &Path, dir_identity: FileIdentity) -> ProbeResult {
        let mut cached = self.cached.lock().expect("atomicity probe cache lock poisoned");

        if let Some((cached_identity, result)) = cached.as_ref()
            && *cached_identity == dir_identity
        {
            return result.clone();
        }

        let result = probe_write_capability(dir).map_err(|error| {
            let reason = if error.downcast_ref::<UnsupportedFilesystem>().is_some() {
                PolicyReadOnlyReason::UnsupportedFileSystem
            } else {
                PolicyReadOnlyReason::InsufficientPermissions
            };
            (reason, format!("{error:#}"))
        });
        *cached = Some((dir_identity, result.clone()));
        result
    }
}

/// Open a directory without following reparse points, sharing read/write but not delete,
/// so the object cannot be renamed or deleted while this handle (and any later handle
/// derived from re-verifying it) is alive.
fn open_directory_no_reparse(path: &Path) -> anyhow::Result<File> {
    OpenOptions::new()
        .access_mode((FILE_READ_ATTRIBUTES | READ_CONTROL).0)
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
/// [`policy_security::verify_directory_ancestor_chain`], so an untrusted principal further
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

/// Filesystem names known to support the exact same-directory atomic-replace-by-rename
/// semantics (`MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`) that [`atomic_replace`]
/// relies on. Conservative by design: an unrecognized filesystem is treated as
/// unsupported rather than assumed compatible.
const ATOMIC_REPLACE_CAPABLE_FILESYSTEMS: &[&str] = &["NTFS", "ReFS"];

/// Prove (rather than merely assume from ACL/create/delete access alone) that `dir`'s
/// filesystem supports the same-directory atomic-replace-by-rename semantics
/// [`atomic_replace`] depends on.
///
/// Two layers: a conservative filesystem-name classification (some filesystems and filter
/// drivers accept a rename call but silently fall back to non-atomic/copy-then-delete
/// behavior), followed by a fully nondestructive probe that exercises the exact rename
/// primitive `atomic_replace` uses against disposable, uniquely named temporary files --
/// never the configured policy file itself.
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

    let probe_result = (|| -> anyhow::Result<()> {
        std::fs::write(&source_path, b"probe-source").context("create write-capability probe source file")?;
        std::fs::write(&target_path, b"probe-target").context("create write-capability probe target file")?;
        // Exercise the exact primitive `atomic_replace` depends on, not just create/delete.
        move_replace(&source_path, &target_path).context("probe atomic same-directory replacement")?;
        let replaced = std::fs::read(&target_path).context("read write-capability probe result")?;
        ensure!(
            replaced == b"probe-source",
            "atomic replacement did not take effect on this filesystem"
        );
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

    probe_result.and(source_cleanup).and(target_cleanup)
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

/// Internal, never-serialized identity of exactly what was observed on disk: resolved
/// target and parent object identity, exact content digest, and security-relevant state
/// (including a summary of the *ancestor chain*, not just the immediate parent; see item
/// 20). Two observations comparing equal here are guaranteed indistinguishable from the
/// store's perspective; anything else (content byte-swap, ACL/security change anywhere
/// from the leaf up through its ancestor chain, the parent directory replaced out from
/// under the leaf, a leaf appearing where it was absent, ...) compares unequal. This is
/// the only signal that drives the opaque store token to rotate (see
/// `PolicyStore::token_for`); the fingerprint itself never leaves the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DiskFingerprint {
    /// A successfully parsed, security-verified, and semantically-valid policy file.
    Active {
        parent: FileIdentity,
        target: FileIdentity,
        content_digest: [u8; 32],
        security_digest: [u8; 32],
        ancestor_security_digest: [u8; 32],
    },
    /// No file at the resolved path. Carries the verified identity of the parent
    /// directory (and its ancestor chain's security summary), so a parent replacement
    /// (or a differently identified custom path) is still distinguishable even though
    /// there is no leaf to identify. `parent`/`ancestor_security_digest` are `None` when
    /// even the directory itself could not be verified (its own security/ancestor check
    /// failed): still Missing -- there is no leaf to distrust either way -- but `path`
    /// (the canonical, or best-effort literal, configured path) still prevents two
    /// distinct configured paths in that situation from colliding (mirrors
    /// `Invalid::path`; item 15).
    Missing {
        path: PathBuf,
        parent: Option<FileIdentity>,
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
    pub(super) fn test_active(
        content: &[u8],
        target_generation: u32,
        parent_generation: u32,
        acl_generation: u32,
    ) -> Self {
        Self::Active {
            parent: test_identity(parent_generation),
            target: test_identity(target_generation),
            content_digest: sha256_digest(content),
            security_digest: sha256_digest(&acl_generation.to_le_bytes()),
            ancestor_security_digest: sha256_digest(&acl_generation.to_le_bytes()),
        }
    }

    pub(super) fn test_missing(parent_generation: u32) -> Self {
        Self::Missing {
            path: PathBuf::from(r"C:\fake\package-broker-policy.json"),
            parent: Some(test_identity(parent_generation)),
            ancestor_security_digest: Some(sha256_digest(b"test-ancestor-security")),
        }
    }

    pub(super) fn test_invalid(content: &[u8], target_generation: u32) -> Self {
        Self::Invalid {
            path: PathBuf::from(r"C:\fake\package-broker-policy.json"),
            parent: Some(test_identity(0)),
            ancestor_security_digest: Some(sha256_digest(b"test-ancestor-security")),
            target: Some(test_identity(target_generation)),
            content_digest: Some(sha256_digest(content)),
            security_digest: Some(sha256_digest(b"test-security")),
            reason: validation::DiskFailureReason::MalformedContent,
        }
    }
}

#[cfg(test)]
fn test_identity(generation: u32) -> FileIdentity {
    let mut file_id = [0u8; 16];
    file_id[..4].copy_from_slice(&generation.to_le_bytes());
    FileIdentity {
        volume_serial: 0,
        file_id,
    }
}

fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
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
}

/// Context accumulated while observation fails partway through, for building the most
/// complete [`DiskFingerprint::Invalid`] the failure allows (item 15): every field is
/// optional because how far observation got before failing determines what could
/// actually be resolved (e.g. a directory that cannot even be opened has no parent
/// identity to report).
#[derive(Default)]
struct InvalidContext {
    parent: Option<FileIdentity>,
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
    match (a.to_str(), b.to_str()) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => a == b,
    }
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

    let (canonical_dir, ancestor_security_digest) = match secured {
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
                        ancestor_security_digest: None,
                    },
                    write_capability,
                    read_only_reason: Some(read_only_reason),
                    canonical_path: configured_path.to_owned(),
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

    // The one-time, side-effecting atomic-replace capability probe (item 20): cached per
    // verified directory identity, never repeated on every observation.
    let (base_write_capability, base_read_only_reason) = match probe_cache.get_or_probe(&canonical_dir, parent) {
        Ok(()) => (PolicyWriteCapability::Writable, None),
        Err((reason, diagnostic)) => {
            tracing::warn!(
                path = %canonical_dir.display(), %diagnostic,
                "Policy directory is not writable through the management API"
            );
            (PolicyWriteCapability::ReadOnly, Some(reason))
        }
    };

    let invalid_ctx = InvalidContext {
        parent: Some(parent),
        ancestor_security_digest: Some(ancestor_security_digest),
        ..Default::default()
    };

    let file = match OpenOptions::new()
        .read(true)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(&canonical_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return DiskObservation {
                state: PolicyManagementState::Missing,
                policy: None,
                invalid_diagnostics: None,
                fingerprint: DiskFingerprint::Missing {
                    path: canonical_path.clone(),
                    parent: Some(parent),
                    ancestor_security_digest: Some(ancestor_security_digest),
                },
                write_capability: base_write_capability,
                read_only_reason: base_read_only_reason,
                canonical_path,
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
    observation_from_parts(
        &canonical_path,
        &content,
        VerifiedIdentity {
            parent,
            ancestor_security_digest,
            target,
            security_digest,
        },
        base_write_capability,
        base_read_only_reason,
    )
}

/// Verified identity/security components already resolved for the current observation,
/// grouped so [`observation_from_parts`] does not need one parameter per field.
struct VerifiedIdentity {
    parent: FileIdentity,
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
) -> DiskObservation {
    let VerifiedIdentity {
        parent,
        ancestor_security_digest,
        target,
        security_digest,
    } = identity;

    let content_digest = sha256_digest(content);

    let invalid_with = |reason: validation::DiskFailureReason| DiskObservation {
        state: PolicyManagementState::Invalid,
        policy: None,
        invalid_diagnostics: Some(InvalidPolicyDiagnostics {
            diagnostics_version: API_VERSION_STR.into(),
            findings: vec![validation::disk_failure_finding(reason)],
        }),
        fingerprint: DiskFingerprint::Invalid {
            path: path.to_owned(),
            parent: Some(parent),
            ancestor_security_digest: Some(ancestor_security_digest),
            target: Some(target),
            content_digest: Some(content_digest),
            security_digest: Some(security_digest),
            reason,
        },
        write_capability,
        read_only_reason,
        canonical_path: path.to_owned(),
    };

    let policy = match serde_json::from_slice::<PolicyDocument>(content) {
        Ok(policy) => policy,
        Err(parse_error) => {
            // Detailed parse error only ever traced, never exposed through the management
            // API: it is heuristically derived from attacker/corruption-controlled bytes
            // and could otherwise leak content fragments to any authenticated (but not
            // necessarily elevated) caller of `GET /v1/policy/management`.
            tracing::warn!(%parse_error, "Configured policy file content failed to parse");
            return invalid_with(validation::DiskFailureReason::MalformedContent);
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
        return invalid_with(validation::DiskFailureReason::FailedSemanticValidation);
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
            ancestor_security_digest,
        },
        write_capability,
        read_only_reason,
        canonical_path: path.to_owned(),
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
            ancestor_security_digest: context.ancestor_security_digest,
            target: context.target,
            content_digest: context.content_digest,
            security_digest: context.security_digest,
            reason,
        },
        write_capability,
        read_only_reason,
        canonical_path: path.to_owned(),
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

/// A write failure, distinguishing whether the atomic rename that publishes new content
/// had already happened when the failure occurred (item 27). Windows offers no
/// transactional rollback across that rename: once it succeeds, the new bytes are live,
/// so a failure discovered only afterward (post-write reopen/identity/security/parse
/// verification) is a fundamentally different situation from one discovered before it
/// (temporary file creation/write/flush, or the rename call itself failing) -- the
/// caller must never assume the previously active policy is still what is being served
/// just because *a* later step failed.
pub(super) enum WriteFailure {
    /// Failed before the rename: disk state is provably unchanged, so the previously
    /// active/invalid/missing policy (if any) is still exactly what it was. Maps to
    /// `ErrorCode::PolicyPersistenceFailed`.
    PrePublication(anyhow::Error),
    /// Failed after the rename made the new content live: the caller must synchronously
    /// reobserve disk under the same write lock and publish whatever that reveals rather
    /// than trusting the previous in-memory snapshot. Maps to
    /// `ErrorCode::PolicyActivationFailed`.
    PostPublication(anyhow::Error),
}

/// Atomically persist `bytes` (the canonical serialization of the new active policy) to
/// `final_path`, replacing whatever is currently there, then reopen and verify it.
///
/// Used for every replacement operation except `Create` (see [`atomic_create`]): the
/// store already observed an Active or Invalid policy at `final_path` under its write
/// lock immediately before calling this, so an existing destination is expected and
/// intentionally replaced.
pub(super) fn atomic_replace(dir: &Path, final_path: &Path, bytes: &[u8]) -> Result<PersistedPolicy, WriteFailure> {
    write_temp_then(dir, bytes, |temp_path| move_replace(temp_path, final_path))
        .map_err(WriteFailure::PrePublication)?;
    reopen_and_verify_persisted(dir, final_path, bytes).map_err(WriteFailure::PostPublication)
}

/// Atomically persist `bytes` to `final_path` only if nothing exists there yet: unlike
/// [`atomic_replace`], this never overwrites an existing destination.
///
/// Used for `Create`, where the store already observed Missing under its write lock. If a
/// leaf has raced into existence between that observation and this call, the rename fails
/// (a [`WriteFailure::PrePublication`], since the destination was never touched) and the
/// caller must re-observe and report a stale token (see `PolicyStore::replace`) rather
/// than ever silently overwriting a file it never actually observed as absent.
pub(super) fn atomic_create(dir: &Path, final_path: &Path, bytes: &[u8]) -> Result<PersistedPolicy, WriteFailure> {
    write_temp_then(dir, bytes, |temp_path| move_create_new(temp_path, final_path))
        .map_err(WriteFailure::PrePublication)?;
    reopen_and_verify_persisted(dir, final_path, bytes).map_err(WriteFailure::PostPublication)
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
/// This narrows -- it does not eliminate -- the residual race with a *different*, already
/// SYSTEM/Administrators-trusted writer (including an external editor) concurrently
/// replacing the same file between the rename and this reopen: Windows provides no
/// identity-conditioned replace primitive, so re-verifying the strongest available
/// handle/content evidence immediately afterward is the strongest supported
/// approximation, not a complete fix.
fn reopen_and_verify_persisted(
    dir: &Path,
    final_path: &Path,
    expected_bytes: &[u8],
) -> anyhow::Result<PersistedPolicy> {
    let dir_handle =
        open_directory_no_reparse(dir).context("failed to reopen policy directory for post-write verification")?;
    let parent = policy_security::file_identity(&dir_handle)
        .context("failed to query policy directory identity for post-write verification")?;
    let ancestor_security_digest = policy_security::verify_policy_ancestor_chain(dir, "policy directory")
        .context("policy directory ancestor chain failed verification immediately after writing")?;

    let final_file = OpenOptions::new()
        .read(true)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(final_path)
        .context("failed to reopen policy file for post-write verification")?;

    let target = policy_security::file_identity(&final_file)
        .context("failed to query policy file identity for post-write verification")?;

    policy_security::verify_policy_file_security(&final_file)
        .context("policy file failed security verification immediately after being written")?;

    let security_digest = policy_security::security_state_digest(&final_file)
        .context("failed to compute policy file security digest immediately after being written")?;

    let mut persisted = Vec::new();
    {
        use std::io::Read as _;
        (&final_file)
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

    // ─── DiskFingerprint rotation/stability semantics ─────────────────────────

    #[test]
    fn active_fingerprint_is_stable_for_identical_inputs() {
        let a = DiskFingerprint::test_active(b"same bytes", 1, 1, 1);
        let b = DiskFingerprint::test_active(b"same bytes", 1, 1, 1);
        assert_eq!(a, b);
    }

    #[test]
    fn active_fingerprint_rotates_on_same_byte_target_replacement() {
        // Same content, but a different target generation (the file object itself was
        // replaced, e.g. deleted and recreated with identical bytes).
        let before = DiskFingerprint::test_active(b"same bytes", 1, 1, 1);
        let after = DiskFingerprint::test_active(b"same bytes", 2, 1, 1);
        assert_ne!(before, after);
    }

    #[test]
    fn active_fingerprint_rotates_on_acl_change() {
        let before = DiskFingerprint::test_active(b"same bytes", 1, 1, 1);
        let after = DiskFingerprint::test_active(b"same bytes", 1, 1, 2);
        assert_ne!(before, after);
    }

    #[test]
    fn active_fingerprint_rotates_on_parent_replacement() {
        let before = DiskFingerprint::test_active(b"same bytes", 1, 1, 1);
        let after = DiskFingerprint::test_active(b"same bytes", 1, 2, 1);
        assert_ne!(before, after);
    }

    #[test]
    fn missing_fingerprints_differ_for_different_parents() {
        let a = DiskFingerprint::test_missing(1);
        let b = DiskFingerprint::test_missing(2);
        assert_ne!(a, b);
    }

    #[test]
    fn missing_fingerprint_is_stable_for_the_same_parent() {
        let a = DiskFingerprint::test_missing(7);
        let b = DiskFingerprint::test_missing(7);
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

    // ─── DiskFingerprint::Invalid enrichment (item 15) ────────────────────────

    fn invalid_fingerprint_for_path(path: &str, reason: validation::DiskFailureReason) -> DiskFingerprint {
        DiskFingerprint::Invalid {
            path: PathBuf::from(path),
            parent: None,
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
