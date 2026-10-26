use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Write as _};
#[cfg(windows)]
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use camino::{Utf8Path, Utf8PathBuf};
use private_fs::{Access, Account, Dir, EntryKind, Existing, Fallback, FileOptions, Replace, Rule, Share};
use tracing::warn;
use uuid::Uuid;

use crate::pending;

/// The message an administrator's submission adds when the service has not provisioned the drop box it writes into.
#[cfg(windows)]
const ENROLLMENT_DIRECTORY_NOT_READY: &str = "the Devolutions Agent service has not prepared the enrollment directory yet; start the Devolutions Agent service once, then retry";

#[derive(Debug)]
struct UntrustedStateFile;

impl fmt::Display for UntrustedStateFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("untrusted identity state file")
    }
}

impl Error for UntrustedStateFile {}

/// An `<data-dir>/identity/authorities/<authority_id>/` directory or its `identity.json` that fails the trust check.
///
/// [`crates/agent-identity/INTENT.md`] ("Local state"): such a directory or file is never repaired or read as absent,
/// and stops all identity processing until it is fixed.
///
/// [`crates/agent-identity/INTENT.md`]: ../INTENT.md
#[derive(Debug)]
pub struct UntrustedStoredIdentity {
    pub path: Utf8PathBuf,
    source: anyhow::Error,
}

impl fmt::Display for UntrustedStoredIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "untrusted stored identity {}", self.path)
    }
}

impl Error for UntrustedStoredIdentity {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub(crate) fn is_untrusted(error: &anyhow::Error) -> bool {
    error.is::<UntrustedStateFile>()
}

fn untrusted() -> anyhow::Error {
    warn!("Ignore untrusted identity state file");
    anyhow::Error::new(UntrustedStateFile)
}

fn untrusted_stored_identity(path: &Utf8Path, source: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(UntrustedStoredIdentity {
        path: path.to_owned(),
        source,
    })
}

/// Gives SYSTEM full control, and the agent's account too when `grant_current_user` is set.
///
/// [`crates/agent-identity/INTENT.md`] ("Local state"): on Linux and macOS the agent's account owns what it creates and
/// keeps full access whatever the rule says, so the grant to it applies only where it owns the item, and the owner's
/// full access is accepted.
///
/// [`crates/agent-identity/INTENT.md`]: ../INTENT.md
fn granted(rule: Rule, grant_current_user: bool) -> Rule {
    let rule = rule
        .grant(Account::System, Access::Full)
        .owner_fallback(Fallback::Access(Access::Full));
    if grant_current_user {
        rule.grant_or(Account::CurrentUser, Access::Full, Fallback::NoAccess)
    } else {
        rule
    }
}

/// The rule of `identity`, `authorities`, `keys`, `rejected`, every authority directory and every `identity.json`, and
/// of `<data-dir>` when the agent creates it; an existing `<data-dir>` gets only the check of the directories above.
///
/// [`crates/agent-identity/INTENT.md`] ("Local state"): they are owned by the agent's account, which in production is
/// SYSTEM or root.
///
/// [`crates/agent-identity/INTENT.md`]: ../INTENT.md
pub(crate) fn tree_rule(grant_current_user: bool) -> Rule {
    tree_rule_owned_by(Account::CurrentUser, grant_current_user)
}

/// The rule of the tree directories as `owner` provisions them; an administrator's submission checks them with SYSTEM
/// as the owner.
fn tree_rule_owned_by(owner: Account, grant_current_user: bool) -> Rule {
    granted(Rule::new().owner(owner), grant_current_user).exact()
}

/// The rule of `identity/pending` as `owner` provisions it, a drop box administrators can add a file to without listing
/// or reading it.
fn drop_box_rule_owned_by(owner: Account, grant_current_user: bool) -> Rule {
    tree_rule_owned_by(owner, grant_current_user).grant(Account::Administrators, Access::AddOnly)
}

/// The rule of in-progress records, rejection markers and the Unix lock file, which the agent's account owns and which
/// are checked for giving no account more than it allows.
pub(crate) fn state_file_rule(grant_current_user: bool) -> Rule {
    granted(Rule::new().owner(Account::CurrentUser), grant_current_user)
}

/// The rule of a pending-enrollment file, which an administrator can own.
///
/// [`crates/agent-identity/INTENT.md`] ("Pending-enrollment files"): on Windows, the exact check accepts the rule's DACL,
/// plus a zero-access OWNER RIGHTS entry when an administrator who is not the agent's account owns the file.
///
/// UNTESTED: on Linux and macOS, a pending file owned by root is accepted when the agent runs as another account, since
/// SYSTEM and Administrators are root there.
/// Only root can create a root-owned file, and a test run as root is the agent's own account, so no test separates the
/// two; when changing the owners, keep System and Administrators among them, because an `identity enroll` run as root
/// writes the file as root.
///
/// [`crates/agent-identity/INTENT.md`]: ../INTENT.md
fn pending_file_rule(grant_current_user: bool) -> Rule {
    granted(
        Rule::new()
            .owner(Account::CurrentUser)
            .owner(Account::System)
            .owner(Account::Administrators),
        grant_current_user,
    )
    .exact()
}

fn not_found() -> anyhow::Error {
    anyhow::Error::new(io::Error::from(io::ErrorKind::NotFound))
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
}

/// Reports whether a state file fails its rule, or is closed to the agent, which only another account can do.
fn fails_trust_check(error: &private_fs::Error) -> bool {
    error.is_refused()
        || matches!(
            error.kind(),
            private_fs::ErrorKind::Io { source, .. } if source.kind() == io::ErrorKind::PermissionDenied
        )
}

/// Opens the directory holding `path`, once it and the directories above it pass the check for directories above, and
/// fails with a top-level `NotFound` I/O error when it doesn't exist.
fn open_parent(path: &Utf8Path) -> anyhow::Result<(Dir, &str)> {
    let parent = path.parent().context("identity path has no parent directory")?;
    let name = path.file_name().context("identity path has no name")?;
    // The check for directories above only asks who owns them and who can replace them, so a rule giving the agent's
    // account access fits whether or not the agent runs as SYSTEM.
    let directory = Dir::open_base(parent, &tree_rule(true))
        .context("open identity directory")?
        .ok_or_else(not_found)?;
    Ok((directory, name))
}

/// Provisions the identity directories, and returns `<data-dir>`.
///
/// [`crates/agent-identity/INTENT.md`] ("Local state"): an identity directory with a wrong owner or wrong permissions is
/// reset, without changing anything below it.
///
/// [`crates/agent-identity/INTENT.md`]: ../INTENT.md
pub(crate) fn provision_directories(data_dir: &Utf8Path, grant_current_user: bool) -> anyhow::Result<Dir> {
    #[cfg(windows)]
    ensure!(
        grant_current_user || crate::windows::is_system()?,
        "identity directory must be created by SYSTEM"
    );
    let rule = tree_rule(grant_current_user);
    let data = Dir::create_base(data_dir, &rule).context("open identity data directory")?;
    let identity = provision(&data, "identity", &rule)?;
    for name in ["authorities", "keys", "rejected"] {
        provision(&identity, name, &rule)?;
    }
    provision(
        &identity,
        "pending",
        &drop_box_rule_owned_by(Account::CurrentUser, grant_current_user),
    )?;
    return Ok(data);

    fn provision(parent: &Dir, name: &str, rule: &Rule) -> anyhow::Result<Dir> {
        // Repairing only a directory that fails its rule leaves a correct one unwritten.
        // A directory whose access denies the agent fails to open rather than failing the rule, and is repaired too,
        // since repair needs only the access its owner always keeps.
        match parent.create_dir(name, rule, Existing::Check) {
            Err(error) if fails_trust_check(&error) => parent.create_dir(name, rule, Existing::Repair),
            created => created,
        }
        .context("provision identity directory")
    }
}

/// Checks, without changing anything, that every authority directory and its `identity.json` are owned by the agent's
/// account and protected from other users, and returns the authority IDs of the directories that exist.
pub(crate) fn check_stored_identities(data_dir: &Utf8Path, grant_current_user: bool) -> anyhow::Result<Vec<Uuid>> {
    let path = data_dir.join("identity").join("authorities");
    let Some(authorities) =
        Dir::open_base(&path, &tree_rule(grant_current_user)).context("open authority directories")?
    else {
        return Ok(Vec::new());
    };
    let mut authority_ids = Vec::new();
    for entry in authorities.entries().context("list authority directories")? {
        // A case variant of an authority ID names the same directory on a case-insensitive file system, such as the
        // default ones of Windows and macOS.
        let Some((name, authority_id)) = entry.name.to_str().and_then(|name| {
            Uuid::parse_str(name)
                .ok()
                .filter(|uuid| uuid.to_string().eq_ignore_ascii_case(name))
                .map(|uuid| (name, uuid))
        }) else {
            continue;
        };
        let authority_path = path.join(name);
        if let Some(authority) = open_authority(&authorities, name, &authority_path, grant_current_user)? {
            let identity_path = authority_path.join("identity.json");
            // Opening a file for its data just after a write can take tens of milliseconds, for example while an
            // antivirus scans it, and this check precedes every use of the state.
            open_identity_in(&authority, &identity_path, grant_current_user, FileOptions::new())?;
            authority_ids.push(authority_id);
        }
    }
    authority_ids.sort_unstable();
    authority_ids.dedup();
    Ok(authority_ids)
}

/// Opens an authority directory, without changing it, once it is owned by the agent's account and protected from other
/// users, and returns `None` when it doesn't exist.
pub(crate) fn open_authority_directory(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<Option<Dir>> {
    let (authorities, name) = match open_parent(path) {
        Ok(opened) => opened,
        Err(error) if is_not_found(&error) => return Ok(None),
        Err(error) => return Err(untrusted_stored_identity(path, error)),
    };
    open_authority(&authorities, name, path, grant_current_user)
}

fn open_authority(
    authorities: &Dir,
    name: &str,
    path: &Utf8Path,
    grant_current_user: bool,
) -> anyhow::Result<Option<Dir>> {
    authorities
        .open_dir(name, &tree_rule(grant_current_user), Share::Shared)
        .map_err(|error| untrusted_stored_identity(path, error.into()))
}

/// Opens the `identity.json` at `path` in its checked `authority` directory, without changing it, once it passes the
/// trust check, and returns `None` when it doesn't exist.
///
/// [`crates/agent-identity/INTENT.md`] ("Local state"): the file must pass the check of its authority directory, so it is
/// a regular file owned by the agent's account and is, on Unix, closed to group and other, or on Windows, protected by
/// exactly the DACL the agent provisions for it.
///
/// [`crates/agent-identity/INTENT.md`]: ../INTENT.md
pub(crate) fn open_identity_file(
    authority: &Dir,
    path: &Utf8Path,
    grant_current_user: bool,
) -> anyhow::Result<Option<File>> {
    open_identity_in(authority, path, grant_current_user, FileOptions::new().read(true))
}

/// Opens `identity.json` in its checked authority directory once it passes the trust check.
///
/// UNTESTED: an `identity.json` owned by another account fails the check, because that owner can always change its
/// access.
/// Only an elevated process on Windows or root on Linux and macOS can give a test file another owner, and the tests that
/// do run that way cover the authority directory, which the same rule governs; when changing this, keep the agent's
/// account the only owner the rule allows.
fn open_identity_in(
    authority: &Dir,
    path: &Utf8Path,
    grant_current_user: bool,
    options: FileOptions,
) -> anyhow::Result<Option<File>> {
    let name = path.file_name().context("identity path has no name")?;
    authority
        .open_file(name, &tree_rule(grant_current_user), options)
        .map_err(|error| untrusted_stored_identity(path, error.into()))
}

fn create_authority(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<Dir> {
    #[cfg(windows)]
    ensure!(
        grant_current_user || crate::windows::is_system()?,
        "identity directory must be created by SYSTEM"
    );
    let (authorities, name) = open_parent(path)?;
    authorities
        .create_dir(name, &tree_rule(grant_current_user), Existing::Check)
        .map_err(|error| {
            if error.is_refused() {
                untrusted_stored_identity(path, error.into())
            } else {
                anyhow::Error::new(error).context("create authority directory")
            }
        })
}

pub(crate) fn write_atomic(
    data_dir: &Utf8Path,
    path: &Utf8Path,
    bytes: &[u8],
    grant_current_user: bool,
) -> anyhow::Result<()> {
    #[cfg(windows)]
    ensure!(
        grant_current_user || crate::windows::is_system()?,
        "identity file must be written by SYSTEM"
    );
    let parent = path.parent().context("identity file has no parent directory")?;
    let name = path.file_name().context("identity file has no name")?;
    let identity = data_dir.join("identity");
    let (directory, rule) = if parent.parent() == Some(identity.join("authorities").as_path()) {
        (
            create_authority(parent, grant_current_user)?,
            tree_rule(grant_current_user),
        )
    } else if parent == identity.join("pending") {
        let rule = if pending::pending_hash_from_name(name).is_some() {
            pending_file_rule(grant_current_user)
        } else {
            state_file_rule(grant_current_user)
        };
        (open_parent(path)?.0, rule)
    } else {
        ensure!(
            parent == identity.join("rejected"),
            "identity file is outside its state directories"
        );
        (open_parent(path)?.0, state_file_rule(grant_current_user))
    };
    let temporary = format!(".{name}-{}.tmp", Uuid::new_v4());
    let mut file = directory
        .create_file(&temporary, &rule, FileOptions::new())
        .context("create identity file")?;
    let installed = file
        .write_all(bytes)
        .context("write identity file")
        .and_then(|()| persist_replacing(&directory, &file, &temporary, name));
    if installed.is_err() {
        let _ = directory.discard(&file, &temporary);
    }
    installed
}

/// Makes `file`, written as `temporary`, durable as `name`, replacing the file of that name.
#[cfg(unix)]
fn persist_replacing(directory: &Dir, file: &File, temporary: &str, name: &str) -> anyhow::Result<()> {
    directory
        .persist(file, temporary, name, Replace::Allow)
        .context("install identity file")
}

/// Makes `file`, written as `temporary`, durable as `name`, replacing the file of that name.
///
/// While another process has the file it replaces open, even sharing deletion, the replacement fails with
/// `ERROR_ACCESS_DENIED`, so it is retried for 5 s; a reader such as a backup or an antivirus scan
/// holds the file only briefly.
#[cfg(windows)]
fn persist_replacing(directory: &Dir, file: &File, temporary: &str, name: &str) -> anyhow::Result<()> {
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    /// How long a replacement of an identity file waits for other processes to close the file it replaces.
    const REPLACE_TIMEOUT: Duration = Duration::from_secs(5);
    const REPLACE_RETRY_INTERVAL: Duration = Duration::from_millis(25);

    let access_denied = i32::try_from(ERROR_ACCESS_DENIED.0)?;
    let started = Instant::now();
    loop {
        match directory.persist(file, temporary, name, Replace::Allow) {
            Err(error)
                if matches!(
                    error.kind(),
                    private_fs::ErrorKind::Io { source, .. } if source.raw_os_error() == Some(access_denied)
                ) && started.elapsed() < REPLACE_TIMEOUT =>
            {
                std::thread::sleep(REPLACE_RETRY_INTERVAL);
            }
            persisted => return persisted.context("install identity file"),
        }
    }
}

/// Opens a rejection marker or an in-progress record once it passes the trust check.
///
/// The check lets the file give SYSTEM and the agent's account access, whether or not the agent runs as SYSTEM, so that
/// a reader that doesn't know the configured grant can tell a file the agent wrote from one another account wrote.
pub(crate) fn open_read(path: &Utf8Path) -> anyhow::Result<File> {
    open_checked(path, &state_file_rule(true))
}

pub(crate) fn open_pending_read(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<File> {
    open_checked(path, &pending_file_rule(grant_current_user))
}

fn open_checked(path: &Utf8Path, rule: &Rule) -> anyhow::Result<File> {
    let (directory, name) = open_parent(path)?;
    let open = |options| match directory.open_file(name, rule, options) {
        Ok(Some(file)) => Ok(file),
        Ok(None) => Err(not_found()),
        Err(error) if fails_trust_check(&error) => Err(untrusted()),
        Err(error) => Err(anyhow::Error::new(error).context("open identity file")),
    };
    // Reading a file's owner and access takes no access to its data, which a handle that shares nothing still allows on
    // Windows, so a file that fails its rule is ignored even while another process holds it.
    drop(open(FileOptions::new())?);
    open(FileOptions::new().read(true))
}

pub(crate) fn remove_file(path: &Utf8Path) -> anyhow::Result<()> {
    remove_checked_file(path, &state_file_rule(true))
}

pub(crate) fn remove_pending_file(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<()> {
    remove_checked_file(path, &pending_file_rule(grant_current_user))
}

/// Removes the file at `path` once it passes `rule`, and keeps a file that fails it.
fn remove_checked_file(path: &Utf8Path, rule: &Rule) -> anyhow::Result<()> {
    let (directory, name) = match open_parent(path) {
        Ok(opened) => opened,
        Err(error) if is_not_found(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    match directory.open_file(name, rule, FileOptions::new()) {
        Ok(Some(file)) => drop(file),
        Ok(None) => return Ok(()),
        Err(error) if fails_trust_check(&error) => {
            drop(untrusted());
            return Ok(());
        }
        Err(error) => return Err(anyhow::Error::new(error).context("open identity file")),
    }
    directory.remove_file(name).context("remove identity file")?;
    Ok(())
}

pub(crate) fn cleanup_temporary_files(
    directory: &Utf8Path,
    matches_stem: impl Fn(&str) -> bool,
    remove: impl Fn(&Utf8Path, &str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let Some(opened) = Dir::open_base(directory, &tree_rule(true)).context("open identity directory")? else {
        return Ok(());
    };
    for entry in opened.entries().context("list identity directory")? {
        let Some(name) = entry.name.to_str() else {
            continue;
        };
        let Some(stem) = temporary_stem(name) else {
            continue;
        };
        if matches_stem(stem) && entry.kind == EntryKind::File {
            remove(&directory.join(name), stem)?;
        }
    }
    Ok(())
}

fn temporary_stem(name: &str) -> Option<&str> {
    let name = name.strip_suffix(".tmp")?;
    let (stem, suffix) = name.split_at_checked(name.len().checked_sub(36)?)?;
    let stem = stem.strip_suffix('-')?;
    let uuid = Uuid::parse_str(suffix).ok()?;
    (uuid.get_version_num() == 4 && uuid.to_string() == suffix).then_some(stem)
}

/// The rules an administrator's submission checks the drop box and the directories above it against.
#[cfg(windows)]
struct DropBox {
    base: Rule,
    identity: Rule,
    pending: Rule,
}

#[cfg(windows)]
impl DropBox {
    /// The directories as the service provisions them running as `owner`, with the rules it provisions them with.
    fn provisioned_by(owner: Account, grant_current_user: bool) -> Self {
        Self {
            base: tree_rule_owned_by(owner, grant_current_user),
            identity: tree_rule_owned_by(owner, grant_current_user),
            pending: drop_box_rule_owned_by(owner, grant_current_user),
        }
    }
}

/// Submits a pending-enrollment file into the drop box the service provisioned, as an administrator who can neither
/// list nor read it.
///
/// [`crates/agent-identity/INTENT.md`] ("Pending-enrollment files"): the file is owned by the administrator, with a
/// zero-access OWNER RIGHTS entry, so the administrator can neither read it back nor rewrite its DACL.
///
/// [`crates/agent-identity/INTENT.md`]: ../INTENT.md
#[cfg(windows)]
pub(crate) fn submit_pending_as_administrator(
    data_dir: &Utf8Path,
    path: &Utf8Path,
    contents: &[u8],
) -> anyhow::Result<()> {
    submit_into_drop_box(
        data_dir,
        path,
        contents,
        &DropBox::provisioned_by(Account::System, false),
        true,
    )
}

/// Submits a pending-enrollment file into the drop box under `data_dir` once its directories pass `rules`, opening them
/// with the backup privilege when `backup` is set.
#[cfg(windows)]
fn submit_into_drop_box(
    data_dir: &Utf8Path,
    path: &Utf8Path,
    contents: &[u8],
    rules: &DropBox,
    backup: bool,
) -> anyhow::Result<()> {
    let pending_path = data_dir.join("identity").join("pending");
    ensure!(
        path.parent() == Some(pending_path.as_path()),
        "pending file is outside the drop box"
    );
    let name = path.file_name().context("pending file has no name")?;
    // The state lock stays held until the file is published.
    let (_state_lock, pending) = open_drop_box(data_dir, rules, backup)?;
    let staging = format!(".{name}-{}.tmp", Uuid::new_v4());
    let mut file = pending
        .create_file(
            &staging,
            &pending_file_rule(false),
            FileOptions::new().share(Share::Exclusive),
        )
        .context("submit pending enrollment")?;
    let published = file
        .write_all(contents)
        .context("write pending enrollment")
        .and_then(|()| match pending.persist(&file, &staging, name, Replace::Refuse) {
            Ok(()) => Ok(true),
            // A pending file for the same token is already there, as after a replayed install.
            Err(error)
                if matches!(
                    error.kind(),
                    private_fs::ErrorKind::Io { source, .. } if source.kind() == io::ErrorKind::AlreadyExists
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(anyhow::Error::new(error).context("publish pending enrollment")),
        });
    if !matches!(published, Ok(true)) {
        // The rule gives the administrator no access to the file, so only the handle that created it can remove it.
        let _ = pending.discard(&file, &staging);
    }
    // The handle shares nothing, so the service can read the published file only once it is closed.
    drop(file);
    published.map(drop)
}

/// Opens the drop box under `data_dir` once its directories pass `rules`, with the backup privilege when `backup` is
/// set, and returns the state lock on `identity` with it.
///
/// [`crates/agent-identity/INTENT.md`] ("Local state"): every state change holds the exclusive lock on the identity
/// directory, which on Windows is an unshared handle on it.
///
/// [`crates/agent-identity/INTENT.md`]: ../INTENT.md
#[cfg(windows)]
fn open_drop_box(data_dir: &Utf8Path, rules: &DropBox, backup: bool) -> anyhow::Result<(Dir, Dir)> {
    let started = Instant::now();
    // The backup privilege lets an administrator open the identity directories, which grant it no list or read access,
    // to check who owns them and who can access them; it ends before anything is written.
    let _backup = backup
        .then(private_fs::BackupPrivilege::enable)
        .transpose()
        .context("enable administrator backup privilege")?;
    let data = retry_sharing_violation(started, SUBMISSION_TIMEOUT, SUBMISSION_RETRY_INTERVAL, || {
        Ok(Dir::open_base(data_dir, &rules.base)?)
    })
    .and_then(|data| data.ok_or_else(not_found))
    .context("inspect identity data directory")
    .map_err(explain_unprepared_drop_box)?;
    let identity = open_drop_box_directory(&data, "identity", &rules.identity, Share::Exclusive, started)
        .context("inspect protected identity directory")
        .map_err(explain_unprepared_drop_box)?;
    let pending = open_drop_box_directory(&identity, "pending", &rules.pending, Share::Shared, started)
        .context("inspect protected pending drop box")
        .map_err(explain_unprepared_drop_box)?;
    Ok((identity, pending))
}

/// How long an administrator's submission waits for the service to release the identity directory.
#[cfg(windows)]
const SUBMISSION_TIMEOUT: Duration = Duration::from_secs(10);

/// How often an administrator's submission tries again while the service holds the identity directory.
#[cfg(windows)]
const SUBMISSION_RETRY_INTERVAL: Duration = Duration::from_millis(100);

#[cfg(windows)]
fn open_drop_box_directory(
    parent: &Dir,
    name: &str,
    rule: &Rule,
    share: Share,
    started: Instant,
) -> anyhow::Result<Dir> {
    retry_sharing_violation(started, SUBMISSION_TIMEOUT, SUBMISSION_RETRY_INTERVAL, || {
        Ok(parent.open_dir(name, rule, share)?)
    })?
    .ok_or_else(not_found)
}

/// Retries `operation` every `interval` while it fails with a sharing violation, as while another process holds the
/// identity directory, until `timeout` after `started`.
#[cfg(windows)]
pub(crate) fn retry_sharing_violation<T>(
    started: Instant,
    timeout: Duration,
    interval: Duration,
    mut operation: impl FnMut() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    loop {
        match operation() {
            Err(error) if is_sharing_violation(&error) => {
                let remaining = timeout.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(error);
                }
                std::thread::sleep(remaining.min(interval));
            }
            result => return result,
        }
    }
}

#[cfg(windows)]
pub(crate) fn is_sharing_violation(error: &anyhow::Error) -> bool {
    use windows::Win32::Foundation::ERROR_SHARING_VIOLATION;

    error.chain().any(|cause| {
        cause.downcast_ref::<io::Error>().is_some_and(|source| {
            source.raw_os_error().and_then(|code| u32::try_from(code).ok()) == Some(ERROR_SHARING_VIOLATION.0)
        })
    })
}

/// Explains a drop box that is missing, closed to the administrator or not provisioned as the service does.
#[cfg(windows)]
fn explain_unprepared_drop_box(error: anyhow::Error) -> anyhow::Error {
    let unprepared = error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|source| matches!(source.kind(), io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied))
            || cause
                .downcast_ref::<private_fs::Error>()
                .is_some_and(private_fs::Error::is_refused)
    });
    if unprepared {
        error.context(ENROLLMENT_DIRECTORY_NOT_READY)
    } else {
        error
    }
}

#[cfg(test)]
pub(crate) fn prepare_directories(data_dir: &Utf8Path, grant_current_user: bool) -> anyhow::Result<()> {
    provision_directories(data_dir, grant_current_user).map(drop)
}

/// Creates a missing authority directory, and only checks an existing one, which is never repaired.
#[cfg(test)]
pub(crate) fn create_authority_directory(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<()> {
    create_authority(path, grant_current_user).map(drop)
}

/// An empty data directory under the system temporary directory, removed on drop.
///
/// The system temporary directory keeps test paths under Windows' 260-character limit wherever the repository is checked
/// out, and its directories above pass the checks of the agent's state, which a workspace `target` directory's may not.
#[cfg(test)]
pub(crate) struct TestDir(pub(crate) Utf8PathBuf);

#[cfg(test)]
impl TestDir {
    pub(crate) fn path(&self) -> &Utf8Path {
        &self.0
    }

    pub(crate) fn new() -> anyhow::Result<Self> {
        let path = Utf8PathBuf::from_path_buf(std::env::temp_dir())
            .map_err(|_| anyhow::anyhow!("the temporary directory path is not UTF-8"))?
            .join(format!("ai-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

#[cfg(test)]
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn recognizes_only_own_temporary_file_names() {
        let uuid = Uuid::new_v4();
        assert_eq!(
            temporary_stem(&format!(".identity.json-{uuid}.tmp")),
            Some(".identity.json")
        );
        assert_eq!(temporary_stem(".identity.json-not-a-uuid.tmp"), None);
        assert_eq!(temporary_stem(&format!(".identity.json-{uuid}.backup")), None);
        assert_eq!(temporary_stem(&format!(".x-é{}.tmp", "a".repeat(35))), None);
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    impl TestDir {
        fn provisioned() -> anyhow::Result<Self> {
            let directory = Self::new()?;
            prepare_directories(&directory.0, true)?;
            Ok(directory)
        }

        fn pending_file(&self) -> anyhow::Result<Utf8PathBuf> {
            let path = pending::file_path(&self.0, &"a".repeat(64))?;
            write_atomic(&self.0, &path, br#"{"version":1,"token":"x"}"#, true)?;
            Ok(path)
        }
    }

    /// Gives `path` an owner other than root and the current user, which only root can do.
    fn give_to_another_account(path: &Utf8Path) -> anyhow::Result<bool> {
        // SAFETY: Reading the process's effective UID has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            writeln!(io::stderr(), "SKIP: giving a file another owner needs root")?;
            return Ok(false);
        }
        // The conventional `nobody` account, which is neither root nor the agent's account here.
        std::os::unix::fs::chown(path, Some(65534), None)?;
        Ok(true)
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn a_pending_file_owned_by_another_account_is_ignored() -> anyhow::Result<()> {
        let directory = TestDir::provisioned()?;
        let path = directory.pending_file()?;
        if !give_to_another_account(&path)? {
            return Ok(());
        }

        let error = open_pending_read(&path, true).expect_err("a pending file owned by another account was read");

        assert!(is_untrusted(&error), "{error:#}");
        assert!(path.exists());
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[rstest::rstest]
    #[case::group_read(0o640)]
    #[case::other_read(0o604)]
    #[case::group_and_other_read(0o644)]
    #[case::group_write(0o620)]
    fn a_pending_file_open_to_group_or_other_is_ignored(#[case] mode: u32) -> anyhow::Result<()> {
        let directory = TestDir::provisioned()?;
        let path = directory.pending_file()?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;

        let error = open_pending_read(&path, true).expect_err("a pending file open to other users was read");

        assert!(is_untrusted(&error), "{error:#}");
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn an_owner_only_pending_file_is_read() -> anyhow::Result<()> {
        let directory = TestDir::provisioned()?;
        let path = directory.pending_file()?;

        open_pending_read(&path, true)?;

        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn an_authority_directory_owned_by_another_account_fails_the_check() -> anyhow::Result<()> {
        let directory = TestDir::provisioned()?;
        let authority = directory
            .0
            .join("identity")
            .join("authorities")
            .join(Uuid::new_v4().to_string());
        create_authority_directory(&authority, true)?;
        if !give_to_another_account(&authority)? {
            return Ok(());
        }

        let error = open_authority_directory(&authority, true)
            .err()
            .context("an authority directory owned by another account passed the check")?;

        let untrusted = error
            .downcast_ref::<UntrustedStoredIdentity>()
            .context("the failure is not an untrusted stored identity")?;
        assert_eq!(untrusted.path, authority);
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::fs;
    use std::io::Write as _;

    use ::windows::Win32::Security::{
        CONTAINER_INHERIT_ACE, NO_INHERITANCE, OBJECT_INHERIT_ACE, WinBuiltinAdministratorsSid, WinBuiltinUsersSid,
    };
    use ::windows::Win32::Storage::FileSystem::{
        FILE_ADD_FILE, FILE_ALL_ACCESS, FILE_GENERIC_READ, SYNCHRONIZE, WRITE_DAC,
    };
    use win_api_wrappers::identity::sid::Sid;

    use super::*;
    use crate::windows::test::{self as acl, Ace};

    impl TestDir {
        fn provisioned() -> anyhow::Result<Self> {
            let directory = Self::new()?;
            prepare_directories(&directory.0, true)?;
            Ok(directory)
        }

        fn identity(&self) -> Utf8PathBuf {
            self.0.join("identity")
        }

        fn pending(&self) -> Utf8PathBuf {
            self.identity().join("pending")
        }

        fn pending_file(&self, letter: char) -> Utf8PathBuf {
            self.pending().join(format!("{}.dat", letter.to_string().repeat(64)))
        }
    }

    /// The rules of a drop box that the current user provisioned under `__debug__.identity.acl_grant_current_user`, as a
    /// test session without SYSTEM can.
    fn provisioned_by_current_user() -> DropBox {
        DropBox::provisioned_by(Account::CurrentUser, true)
    }

    const INHERITED: u32 = CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0;

    fn full(sid: &Sid, flags: u32) -> Ace {
        (sid.clone(), FILE_ALL_ACCESS.0, flags)
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    // oracle: intent devolutions-agent/src/identity/INTENT.md §Configuration
    #[test]
    fn provisioned_directories_grant_system_the_agent_and_administrators_add_only_on_the_drop_box() -> anyhow::Result<()>
    {
        let directory = TestDir::provisioned()?;
        let user = acl::user_sid()?;
        let system = acl::system_sid()?;
        let administrators = Sid::from_well_known(WinBuiltinAdministratorsSid, None)?;
        let tree = vec![full(&system, INHERITED), full(&user, INHERITED)];
        let mut drop_box = tree.clone();
        drop_box.push((administrators, FILE_ADD_FILE.0 | SYNCHRONIZE.0, NO_INHERITANCE.0));

        for (name, expected) in [
            ("identity", &tree),
            ("identity/authorities", &tree),
            ("identity/keys", &tree),
            ("identity/rejected", &tree),
            ("identity/pending", &drop_box),
        ] {
            assert_eq!(
                acl::protected_dacl_of(&directory.0.join(name))?,
                Some(acl::sorted(expected)),
                "{name}"
            );
        }
        Ok(())
    }

    // oracle: mutant dropping the guard lets an account other than SYSTEM create identity directories that only SYSTEM can
    // open
    #[test]
    fn provisioning_without_system_or_the_debug_grant_is_refused() -> anyhow::Result<()> {
        if crate::windows::is_system()? {
            writeln!(
                io::stderr(),
                "SKIP: the refusal applies to an account other than SYSTEM"
            )?;
            return Ok(());
        }
        let directory = TestDir::new()?;

        assert!(prepare_directories(&directory.0, false).is_err());
        assert!(!directory.identity().exists());
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn replacing_a_file_waits_for_a_reader_to_close_it() -> anyhow::Result<()> {
        // A reader holding the destination open, even one sharing deletion as the standard library does, makes the
        // replacement fail with `ERROR_ACCESS_DENIED` until it closes the file.
        let directory = TestDir::provisioned()?;
        let path = directory
            .identity()
            .join("rejected")
            .join(format!("{}.json", "a".repeat(64)));
        write_atomic(&directory.0, &path, b"old", true)?;
        let reader = File::open(&path)?;
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(reader);
        });

        let replaced = write_atomic(&directory.0, &path, b"new", true);
        let _ = closer.join();

        replaced?;
        assert_eq!(fs::read(&path)?, b"new");
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn repairs_a_directory_whose_access_denies_the_agent() -> anyhow::Result<()> {
        // Catches a start-up that repairs only a directory failing its rule, not one it can't open.
        let directory = TestDir::new()?;
        let identity = directory.identity();
        fs::create_dir(&identity)?;
        // An elevated token makes BUILTIN\Administrators the owner of what it creates, so the agent's ownership is set
        // explicitly.
        acl::set_owner(&identity, &acl::user_sid()?)?;
        let users = Sid::from_well_known(WinBuiltinUsersSid, None)?;
        acl::set_dacl(&identity, &[(users, FILE_GENERIC_READ.0, 0)])?;

        prepare_directories(&directory.0, true)?;

        assert_eq!(
            acl::protected_dacl_of(&identity)?,
            Some(acl::sorted(&[
                full(&acl::system_sid()?, INHERITED),
                full(&acl::user_sid()?, INHERITED)
            ]))
        );
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn repairs_a_directory_with_an_extra_allow_principal() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        let identity = directory.identity();
        fs::create_dir(&identity)?;
        let user = acl::user_sid()?;
        let system = acl::system_sid()?;
        let users = Sid::from_well_known(WinBuiltinUsersSid, None)?;
        acl::set_dacl(
            &identity,
            &[
                full(&system, INHERITED),
                full(&user, INHERITED),
                full(&users, INHERITED),
            ],
        )?;
        // `crates/agent-identity/INTENT.md` ("Local state"): start-up resets the directory's permissions, so the
        // identities and keys stored beneath it must survive the repair.
        let state = [
            (
                identity
                    .join("authorities")
                    .join(Uuid::new_v4().to_string())
                    .join("identity.json"),
                br#"{"version":1}"#.as_slice(),
            ),
            (
                identity.join("keys").join("devolutions-agent-identity_test.p8"),
                b"device key".as_slice(),
            ),
        ];
        for (path, contents) in &state {
            fs::create_dir_all(path.parent().context("test state file has no parent")?)?;
            fs::write(path, contents)?;
        }

        prepare_directories(&directory.0, true)?;

        assert_eq!(
            acl::protected_dacl_of(&identity)?,
            Some(acl::sorted(&[full(&system, INHERITED), full(&user, INHERITED)]))
        );
        for (path, contents) in &state {
            let actual = fs::read(path).with_context(|| format!("read {path} after the repair"))?;
            assert_eq!(actual, *contents, "{path}");
        }
        Ok(())
    }

    /// The DACL a test gives a pending file the current user owns.
    #[derive(Clone, Copy, Debug)]
    enum PendingDacl {
        /// SYSTEM and the agent's account, as the agent writes it under `__debug__.identity.acl_grant_current_user`.
        Provisioned,
        /// The same with a zero-access OWNER RIGHTS entry, which only an administrator owner's file carries.
        WithZeroOwnerRights,
        /// The same with full control for Users.
        WithUsers,
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[rstest::rstest]
    #[case::provisioned(PendingDacl::Provisioned, true)]
    #[case::with_zero_owner_rights(PendingDacl::WithZeroOwnerRights, false)]
    #[case::with_users(PendingDacl::WithUsers, false)]
    fn a_pending_file_owned_by_the_agent_is_read_only_in_the_provisioned_form(
        #[case] dacl: PendingDacl,
        #[case] readable: bool,
    ) -> anyhow::Result<()> {
        let directory = TestDir::provisioned()?;
        let path = directory.pending_file('a');
        write_atomic(&directory.0, &path, b"blob", true)?;
        let user = acl::user_sid()?;
        let system = acl::system_sid()?;
        let mut entries = vec![full(&system, NO_INHERITANCE.0), full(&user, NO_INHERITANCE.0)];
        match dacl {
            PendingDacl::Provisioned => {}
            PendingDacl::WithZeroOwnerRights => entries.push((acl::owner_rights_sid()?, 0, NO_INHERITANCE.0)),
            PendingDacl::WithUsers => entries.push(full(&Sid::from_well_known(WinBuiltinUsersSid, None)?, 0)),
        }
        acl::set_owner(&path, &user)?;
        acl::set_dacl(&path, &entries)?;

        let read = open_pending_read(&path, true);

        assert_eq!(read.is_ok(), readable, "{dacl:?}: {read:?}");
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[rstest::rstest]
    #[case::with_zero_owner_rights(true, true)]
    #[case::without_owner_rights(false, false)]
    fn a_pending_file_owned_by_administrators_needs_a_zero_owner_rights_entry(
        #[case] owner_rights: bool,
        #[case] readable: bool,
    ) -> anyhow::Result<()> {
        let directory = TestDir::provisioned()?;
        let path = directory.pending_file('b');
        write_atomic(&directory.0, &path, b"blob", true)?;
        let administrators = Sid::from_well_known(WinBuiltinAdministratorsSid, None)?;
        if acl::set_owner(&path, &administrators).is_err() {
            writeln!(
                io::stderr(),
                "SKIP: giving a file another owner needs an elevated token"
            )?;
            return Ok(());
        }
        let mut entries = vec![full(&acl::system_sid()?, NO_INHERITANCE.0)];
        if owner_rights {
            entries.push((acl::owner_rights_sid()?, 0, NO_INHERITANCE.0));
        }
        acl::set_dacl(&path, &entries)?;

        // The zero OWNER RIGHTS entry takes away even the owner's right to read the DACL, so the test reads the file as
        // SYSTEM can, through the backup privilege, which private-fs opens with.
        let read = {
            let _backup = private_fs::BackupPrivilege::enable()?;
            open_pending_read(&path, false)
        };

        assert_eq!(read.is_ok(), readable, "{read:?}");
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn a_pending_file_the_agent_wrote_without_owner_rights_is_readable() -> anyhow::Result<()> {
        let directory = TestDir::provisioned()?;
        let path = directory.pending_file('a');
        write_atomic(
            &directory.0,
            &path,
            &crate::windows::protect(b"invalid pending JSON")?,
            true,
        )?;

        assert!(matches!(pending::read(&path, true)?, pending::PendingRead::Unusable));
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn drop_box_writer_cannot_reopen_its_file_and_replays_succeed() -> anyhow::Result<()> {
        use std::os::windows::fs::OpenOptionsExt as _;

        let directory = TestDir::provisioned()?;
        let path = directory.pending_file('a');
        let rules = provisioned_by_current_user();

        submit_into_drop_box(&directory.0, &path, b"test payload", &rules, false)?;

        assert!(fs::symlink_metadata(&path)?.file_type().is_file());
        assert!(File::open(&path).is_err());
        assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::OpenOptions::new().access_mode(WRITE_DAC.0).open(&path).is_err());
        submit_into_drop_box(&directory.0, &path, b"different payload", &rules, false)?;
        assert_eq!(fs::read_dir(directory.pending())?.count(), 1);
        Ok(())
    }

    /// Runs `operation` impersonating a copy of the process token with the backup, restore and take-ownership privileges
    /// enabled, which let an elevated test give a directory SYSTEM as its owner, read the directories below it while
    /// their inheritance is applied again, and take it back.
    fn with_restore_privilege<T>(operation: impl FnOnce() -> anyhow::Result<T>) -> anyhow::Result<T> {
        use ::windows::Win32::Security::{
            SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
            TokenImpersonation,
        };
        use win_api_wrappers::process::Process;
        use win_api_wrappers::security::privilege;

        let mut token = Process::current_process()
            .token(TOKEN_DUPLICATE | TOKEN_QUERY)?
            .duplicate(
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_IMPERSONATE,
                None,
                SecurityImpersonation,
                TokenImpersonation,
            )?;
        token.enable_privilege(privilege::SE_BACKUP_NAME)?;
        token.enable_privilege(privilege::SE_RESTORE_NAME)?;
        token.enable_privilege(privilege::SE_TAKE_OWNERSHIP_NAME)?;
        let _impersonation = token.impersonate()?;
        operation()
    }

    /// Gives a test's `identity` and drop box the owner and DACLs the service running as SYSTEM provisions them with,
    /// until restored or dropped, so that a failing test leaves no directory in the temporary directory that only SYSTEM
    /// can remove.
    struct SystemProvisioned<'a> {
        directory: &'a TestDir,
        restored: bool,
    }

    impl<'a> SystemProvisioned<'a> {
        fn new(directory: &'a TestDir) -> anyhow::Result<Self> {
            let mut provisioned = Self {
                directory,
                restored: false,
            };
            let system = acl::system_sid()?;
            // SYSTEM owns them, only SYSTEM can list or read them, and administrators can only add a file to the drop
            // box.
            // `identity` comes first: changing its DACL applies its inheritance again below it, which reads the drop box
            // while the current user still has access to it.
            let provisioning = with_restore_privilege(|| {
                for path in [directory.identity(), directory.pending()] {
                    acl::set_owner(&path, &system)?;
                }
                acl::set_dacl(&directory.identity(), &[full(&system, INHERITED)])?;
                acl::set_dacl(&directory.pending(), &[full(&system, INHERITED), add_only()?])
            });
            if let Err(error) = provisioning {
                let _ = provisioned.restore();
                return Err(error);
            }
            Ok(provisioned)
        }

        /// Gives the directories back to the current user, as `TestDir::provisioned` made them.
        fn restore(&mut self) -> anyhow::Result<()> {
            self.restored = true;
            let system = acl::system_sid()?;
            let user = acl::user_sid()?;
            let directory = self.directory;
            // Taking ownership back gives the current user the owner's implicit right to change the DACLs.
            with_restore_privilege(|| {
                for path in [directory.identity(), directory.pending()] {
                    acl::set_owner(&path, &user)?;
                }
                acl::set_dacl(
                    &directory.identity(),
                    &[full(&system, INHERITED), full(&user, INHERITED)],
                )?;
                acl::set_dacl(
                    &directory.pending(),
                    &[full(&system, INHERITED), full(&user, INHERITED), add_only()?],
                )
            })
        }
    }

    impl Drop for SystemProvisioned<'_> {
        fn drop(&mut self) {
            if !self.restored {
                let _ = self.restore();
            }
        }
    }

    fn add_only() -> anyhow::Result<Ace> {
        Ok((
            Sid::from_well_known(WinBuiltinAdministratorsSid, None)?,
            FILE_ADD_FILE.0 | SYNCHRONIZE.0,
            NO_INHERITANCE.0,
        ))
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    // oracle: intent devolutions-agent/src/identity/INTENT.md §CLI
    #[test]
    fn elevated_only_an_administrator_submits_into_the_drop_box_system_provisioned_and_a_replay_is_a_no_op()
    -> anyhow::Result<()> {
        use win_api_wrappers::token::Token;

        if !Token::current_process_token().is_elevated()? || crate::windows::is_system()? {
            writeln!(
                io::stderr(),
                "SKIP: elevated_only_an_administrator_submits_into_the_drop_box_system_provisioned_and_a_replay_is_a_no_op \
                 needs an elevated administrator other than SYSTEM"
            )?;
            return Ok(());
        }
        let directory = TestDir::provisioned()?;
        let path = directory.pending_file('a');
        let mut provisioned = SystemProvisioned::new(&directory)?;
        // The test's data directory is the current user's, unlike the directories the service provisions.
        let rules = DropBox {
            base: tree_rule(true),
            ..DropBox::provisioned_by(Account::System, false)
        };

        let submitted = submit_into_drop_box(&directory.0, &path, b"test payload", &rules, true);
        // The same token again finds its pending file there, so the second submission discards its staging file through
        // the handle that created it, which is all the access an administrator has to it.
        let replayed = submit_into_drop_box(&directory.0, &path, b"test payload", &rules, true);
        provisioned.restore()?;

        submitted?;
        replayed?;
        let entries = fs::read_dir(directory.pending())?
            .map(|entry| Ok(entry?.file_name()))
            .collect::<io::Result<Vec<_>>>()?;
        assert_eq!(entries, [path.file_name().context("pending file has no name")?]);
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn a_submission_holds_the_state_lock_while_the_drop_box_is_open() -> anyhow::Result<()> {
        let directory = TestDir::provisioned()?;
        let data = Dir::open_base(directory.path(), &tree_rule(true))?.context("missing data directory")?;

        let (state_lock, pending) = open_drop_box(directory.path(), &provisioned_by_current_user(), false)?;
        let while_held = data.open_dir("identity", &tree_rule(true), Share::Shared);
        drop((state_lock, pending));

        let error = anyhow::Error::from(
            while_held
                .err()
                .context("the identity directory opened while a submission held the drop box")?,
        );
        assert!(is_sharing_violation(&error), "{error:#}");
        // Another process, such as an antivirus scan of the new directory, can hold it briefly without sharing.
        let reopened = retry_sharing_violation(
            Instant::now(),
            Duration::from_secs(5),
            Duration::from_millis(25),
            || Ok(data.open_dir("identity", &tree_rule(true), Share::Shared)?),
        )?;
        assert!(reopened.is_some());
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn interrupted_staging_does_not_block_a_replayed_enrollment() -> anyhow::Result<()> {
        let directory = TestDir::provisioned()?;
        let path = directory.pending_file('e');
        let name = path.file_name().context("pending file has no name")?;
        let staging = directory.pending().join(format!(".{name}-{}.tmp", Uuid::new_v4()));
        fs::write(&staging, b"incomplete DPAPI blob")?;

        submit_into_drop_box(
            &directory.0,
            &path,
            b"complete DPAPI blob",
            &provisioned_by_current_user(),
            false,
        )?;

        assert!(fs::symlink_metadata(&path)?.file_type().is_file());
        assert!(fs::symlink_metadata(&staging)?.file_type().is_file());
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn drop_box_denies_a_token_without_administrators_membership() -> anyhow::Result<()> {
        if crate::windows::is_administrator_writer()? || crate::windows::is_system()? {
            writeln!(
                io::stderr(),
                "SKIP: the denial applies to a token without Administrators membership"
            )?;
            return Ok(());
        }
        let directory = TestDir::provisioned()?;
        let administrators = Sid::from_well_known(WinBuiltinAdministratorsSid, None)?;
        // The drop box as the service provisions it, still owned by the current user so that the test can restore it.
        acl::set_dacl(
            &directory.pending(),
            &[
                full(&acl::system_sid()?, INHERITED),
                (administrators, FILE_ADD_FILE.0 | SYNCHRONIZE.0, NO_INHERITANCE.0),
            ],
        )?;
        let rules = DropBox {
            pending: granted(Rule::new().owner(Account::CurrentUser), true)
                .grant(Account::Administrators, Access::AddOnly),
            ..provisioned_by_current_user()
        };
        let path = directory.pending_file('c');

        let submitted = submit_into_drop_box(&directory.0, &path, b"test payload", &rules, false);
        acl::set_dacl(
            &directory.pending(),
            &[full(&acl::system_sid()?, INHERITED), full(&acl::user_sid()?, INHERITED)],
        )?;

        assert!(submitted.is_err());
        assert!(!path.exists());
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn drop_box_refuses_a_link_in_place_of_the_pending_directory_before_writing() -> anyhow::Result<()> {
        let directory = TestDir::provisioned()?;
        let pending = directory.pending();
        fs::remove_dir(&pending)?;
        let redirected = directory.0.join("redirected");
        fs::create_dir(&redirected)?;
        if let Err(error) = std::os::windows::fs::symlink_dir(&redirected, &pending) {
            if error.kind() == io::ErrorKind::PermissionDenied {
                writeln!(
                    io::stderr(),
                    "SKIP: creating a directory link needs Developer Mode or an elevated token"
                )?;
                return Ok(());
            }
            return Err(error).context("create test reparse point");
        }

        let error = submit_into_drop_box(
            &directory.0,
            &directory.pending_file('d'),
            b"test payload",
            &provisioned_by_current_user(),
            false,
        )
        .expect_err("a redirected drop box accepted a pending enrollment");

        let refusal = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<private_fs::Error>())
            .context("the failure is not a refusal")?;
        assert!(
            matches!(
                refusal.kind(),
                private_fs::ErrorKind::Refused(private_fs::Refusal::Link)
            ),
            "{error:#}"
        );
        assert!(fs::read_dir(&redirected)?.next().is_none());
        fs::remove_dir(&pending)?;
        Ok(())
    }

    // oracle: intent devolutions-agent/src/identity/INTENT.md §CLI
    #[test]
    fn administrator_writer_requires_system_provisioned_directories() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        let path = directory.pending_file('f');
        // The test's data directory is the current user's, unlike the directories the service provisions.
        let rules = DropBox {
            base: tree_rule(true),
            ..DropBox::provisioned_by(Account::System, false)
        };

        let missing = submit_into_drop_box(&directory.0, &path, b"test payload", &rules, false)
            .expect_err("a missing identity directory was accepted");
        prepare_directories(&directory.0, true)?;
        let untrusted = submit_into_drop_box(&directory.0, &path, b"test payload", &rules, false)
            .expect_err("a directory the current user provisioned was trusted as SYSTEM's");

        assert_eq!(missing.to_string(), ENROLLMENT_DIRECTORY_NOT_READY);
        assert!(
            format!("{missing:#}").contains("inspect protected identity directory"),
            "{missing:#}"
        );
        assert_eq!(untrusted.to_string(), ENROLLMENT_DIRECTORY_NOT_READY);
        assert!(
            untrusted
                .chain()
                .filter_map(|cause| cause.downcast_ref::<private_fs::Error>())
                .any(private_fs::Error::is_refused),
            "{untrusted:#}"
        );
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn retries_only_sharing_violations() -> anyhow::Result<()> {
        use ::windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};

        let sharing = || {
            anyhow::Error::new(io::Error::from_raw_os_error(
                i32::try_from(ERROR_SHARING_VIOLATION.0).expect("Win32 error codes fit an i32"),
            ))
        };
        // oracle: mutant a sharing violation, as while the service holds the identity directory, fails at once
        let mut attempts = 0;
        retry_sharing_violation(Instant::now(), SUBMISSION_TIMEOUT, SUBMISSION_RETRY_INTERVAL, || {
            attempts += 1;
            if attempts == 1 { Err(sharing()) } else { Ok(()) }
        })?;
        assert_eq!(attempts, 2);

        // oracle: mutant any failure is retried until the timeout
        let mut attempts = 0;
        let result: anyhow::Result<()> =
            retry_sharing_violation(Instant::now(), SUBMISSION_TIMEOUT, SUBMISSION_RETRY_INTERVAL, || {
                attempts += 1;
                Err(anyhow::Error::new(io::Error::from_raw_os_error(i32::try_from(
                    ERROR_ACCESS_DENIED.0,
                )?)))
            });
        assert!(result.is_err());
        assert_eq!(attempts, 1);

        // oracle: intent devolutions-agent/src/identity/INTENT.md §CLI
        let inaccessible = explain_unprepared_drop_box(
            anyhow::Error::new(io::Error::from(io::ErrorKind::PermissionDenied))
                .context("inspect protected pending drop box"),
        );
        assert_eq!(inaccessible.to_string(), ENROLLMENT_DIRECTORY_NOT_READY);
        assert!(
            format!("{inaccessible:#}").contains("inspect protected pending drop box"),
            "{inaccessible:#}"
        );
        Ok(())
    }
}
