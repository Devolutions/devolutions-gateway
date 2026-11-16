//! Durable record of package operations, keyed by authority operation ID.
//!
//! An operation ID is never executed twice, whichever authority delivers it.
//! Delivering the same ID and request again, whether after a restart or a re-enrollment, returns the recorded outcome.
//! Only the admitting authority can update that outcome.
//!
//! A pending record is durable before the caller may submit an operation.
//! A pending record found without a live submission in this journal means the outcome cannot be recovered, so it reads
//! as [`Outcome::Unknown`] and the operation is never submitted again.
//! Every failure to open, read, validate or write the journal is an error, never an absent record.
//!
//! The journal keeps `<data-dir>/package-operations/`, owned by the Agent's account, created and never repaired.
//! One opener at a time owns it, across processes, until its [`OperationJournal`] is dropped: an unshared directory
//! handle on Windows, an `flock` elsewhere.
//! A busy or unavailable journal is an error, never a second owner, because two owners would each cache an index and
//! overwrite the other's admissions.
//! The directory holds a `records` directory with `journal.json`, written when the journal is created, and
//! `<hash of operation ID>.json` per operation.
//! The hash only names the file: each record stores the authority, the operation ID and the full request, and a record
//! that does not match the caller's operation ID is an error rather than another operation's result.
//! Records are never deleted.
//!
//! `journal.json` lists the name of every record admitted.
//! A delivery is admitted by first making that list durable with its name and only then writing its pending record, so a
//! record that exists is always listed.
//! A listed name whose record is missing, and a record whose name is not listed, are errors for that operation ID, never
//! a new operation: the record was lost, or a crash interrupted the admission and the journal cannot tell which.
//! The journal repairs neither, and every other operation ID keeps working.
//! The list is rewritten whole at each admission and is limited to [`MAX_INDEX_SIZE`] bytes, beyond which admission
//! fails closed.
//! The membership snapshot includes unlisted record names and is bounded by the same serialized size.
//! The journal refuses to open or admit another ID if the snapshot cannot fit.
//!
//! A wholly missing journal is created, so operations recorded in a journal that was deleted whole may execute again.
//! A journal directory that exists but lacks its records directory or journal.json is unrecoverable and is refused.

use std::collections::{BTreeSet, HashSet};
use std::ffi::OsStr;
use std::io::{Read as _, Write as _};
use std::sync::Arc;

use agent_channel_proto::PackageOperationRequest;
use anyhow::{Context as _, bail, ensure};
use arc_swap::ArcSwap;
use camino::Utf8Path;
use parking_lot::{Condvar, Mutex};
use private_fs::{Access, Account, Dir, Existing, Fallback, FileOptions, Replace, Rule, Share};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const DIRECTORY_NAME: &str = "package-operations";
const RECORDS_NAME: &str = "records";
const INITIALIZATION_LOCK_NAME: &str = ".package-operations-initialization.lock";
const LOCK_FILE_NAME: &str = ".lock";
const INDEX_NAME: &str = "journal.json";
const VERSION: u32 = 1;
const MAX_RECORD_SIZE: u64 = 1024 * 1024;
const MAX_INDEX_SIZE: u64 = 64 * 1024 * 1024;
const HASH_HEX_LEN: usize = 64;
const RECORD_SUFFIX: &str = ".json";

/// The confirmed end of an operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Outcome {
    Succeeded,
    Failed {
        error: String,
    },
    /// The outcome cannot be recovered, as after a crash or a disconnection.
    Unknown,
}

/// A recorded outcome with the start evidence recorded for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Settled {
    pub outcome: Outcome,
    /// `Some(true)` only when the Broker proved that the operation's process started; `None` proves nothing.
    pub execution_started: Option<bool>,
}

impl Settled {
    fn new(outcome: Outcome, started: bool) -> Self {
        Self {
            outcome,
            execution_started: started.then_some(true),
        }
    }
}

/// What [`OperationJournal::admit`] decided about a delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Admission {
    /// A pending record is now durable; this delivery alone may submit the operation.
    Admitted,
    /// Another delivery admitted the operation in this journal and has not recorded its outcome yet.
    ///
    /// [`OperationJournal::wait`] returns its outcome once recorded.
    InFlight,
    /// The operation was admitted before and ended with this outcome; submit nothing.
    ///
    /// A pending record found after a restart is recorded as [`Outcome::Unknown`] and keeps any start evidence.
    Recorded(Settled),
    /// The operation ID belongs to a different request; execute nothing.
    PayloadMismatch,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u32,
    /// The record file names of every admitted operation.
    operations: BTreeSet<String>,
}

#[derive(Serialize)]
struct IndexRef<'a> {
    version: u32,
    operations: &'a BTreeSet<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    authority_id: String,
    operation_id: String,
    /// The Agent channel encoding of the whole `PackageOperationRequest`.
    request: String,
    /// `None` while the operation is pending.
    outcome: Option<Outcome>,
    /// Whether the Broker proved that the process started; records written without it mean no evidence.
    #[serde(default)]
    execution_started: bool,
}

#[derive(Debug)]
struct State {
    /// The record names listed in `journal.json`.
    admitted: BTreeSet<String>,
    /// The record names admitted by this journal whose outcome is not recorded yet.
    in_flight: HashSet<String>,
}

#[derive(Clone, Debug)]
struct Membership {
    names: BTreeSet<String>,
    /// INVARIANT: The compact JSON index containing exactly `names` has this size in bytes.
    index_size: u64,
}

impl Membership {
    fn new(names: BTreeSet<String>, limit: u64) -> anyhow::Result<Self> {
        let index_size = index_bytes(&names, limit)?.len() as u64;
        Ok(Self { names, index_size })
    }

    fn insert(&mut self, name: String, limit: u64) -> anyhow::Result<()> {
        debug_assert!(is_canonical_record_name(&name));
        if self.names.contains(&name) {
            return Ok(());
        }
        let index_size = self.size_with(&name);
        ensure!(index_size <= limit, "package operation journal index is too large");
        self.names.insert(name);
        self.index_size = index_size;
        Ok(())
    }

    fn size_with(&self, name: &str) -> u64 {
        // Each added name is ASCII, so JSON adds only quotes and, after the first name, a comma.
        self.index_size + (name.len() + 2 + usize::from(!self.names.is_empty())) as u64
    }
}

/// The journal of every authority of this Agent.
///
/// Hold one journal at a time: the directory handle can keep another open of it from sharing.
#[derive(Debug)]
pub(super) struct OperationJournal {
    /// The directory holding `journal.json` and the records.
    directory: Dir,
    state: Mutex<State>,
    // UNTESTED: Only the Agent writes the journal while it is open; the snapshot cannot see out-of-band writes.
    // When changing ownership, account for those writes before treating absence as proof.
    // Out-of-band records still present are discovered at the next open.
    membership: ArcSwap<Membership>,
    #[cfg(test)]
    index_write_hook: Mutex<Option<tests::IndexWriteHook>>,
    // Tests lower this limit to exercise its boundary with small files.
    index_size_limit: u64,
    recorded: Condvar,
    // UNTESTED: The exclusive lock must outlive the records handle to prevent overlapping owners during drop.
    // Check declaration and drop order when changing this struct.
    _lock: JournalLock,
}

fn directory_rule() -> Rule {
    file_rule().exact()
}

/// SYSTEM and the Agent's own account, which on Unix owns what it creates and keeps full access whatever the rule says.
fn file_rule() -> Rule {
    Rule::new()
        .owner(Account::CurrentUser)
        .grant(Account::System, Access::Full)
        .grant_or(Account::CurrentUser, Access::Full, Fallback::NoAccess)
        .owner_fallback(Fallback::Access(Access::Full))
}

/// The exclusive ownership of the journal, held until dropped.
///
/// On Windows it is an unshared handle on the journal directory.
/// Elsewhere it is an `flock` on a file in that directory.
/// The directory's content, `journal.json` included, is read only after the lock is held, and never cached from before.
#[derive(Debug)]
struct JournalLock {
    dir: Dir,
    #[cfg(unix)]
    _file: std::fs::File,
}

fn lock_file(directory: &Dir, name: &str) -> anyhow::Result<std::fs::File> {
    let busy = "package operation journal lock is in use or unavailable";
    let file = directory
        .open_or_create_file(
            name,
            &file_rule(),
            FileOptions::new().read(true).write(true).share(Share::Exclusive),
        )
        .context(busy)?;

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;

        ensure!(
            // SAFETY: The file descriptor stays open until the lock is dropped.
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "{busy}: {}",
            std::io::Error::last_os_error()
        );
    }

    Ok(file)
}

fn acquire_lock(data: &Dir, rule: &Rule) -> anyhow::Result<(JournalLock, bool)> {
    let busy = "package operation journal is in use or unavailable";
    const EXCLUSIVE: Share = if cfg!(windows) { Share::Exclusive } else { Share::Shared };

    let (dir, was_missing) = match data
        .open_dir(DIRECTORY_NAME, rule, EXCLUSIVE)
        .context(busy)
        .context("open package operation journal directory")?
    {
        Some(dir) => (dir, false),
        None => {
            // The handle that creates the directory is not exclusive, so it is closed and the directory opened again
            // exclusively; the journal is read only after that, and a competing opener then fails the exclusive open or
            // the lock instead of reading.
            drop(
                data.create_dir(DIRECTORY_NAME, rule, Existing::Check)
                    .context("create package operation journal directory")?,
            );
            (
                data.open_dir(DIRECTORY_NAME, rule, EXCLUSIVE)
                    .context(busy)
                    .context("open created package operation journal directory")?
                    .context("package operation journal directory disappeared after its creation")?,
                true,
            )
        }
    };

    #[cfg(unix)]
    {
        let file = lock_file(&dir, LOCK_FILE_NAME)?;
        Ok((JournalLock { dir, _file: file }, was_missing))
    }
    #[cfg(windows)]
    Ok((JournalLock { dir }, was_missing))
}

fn hashed(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub(super) fn record_name(operation_id: &str) -> String {
    format!("{}{RECORD_SUFFIX}", hashed(operation_id))
}

fn is_record_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == HASH_HEX_LEN + RECORD_SUFFIX.len()
        && bytes[..HASH_HEX_LEN].iter().all(u8::is_ascii_hexdigit)
        && bytes[HASH_HEX_LEN..].eq_ignore_ascii_case(RECORD_SUFFIX.as_bytes())
}

fn is_canonical_record_name(name: &str) -> bool {
    is_record_name(name) && !name.bytes().any(|byte| byte.is_ascii_uppercase())
}

fn normalized_record_name(name: &OsStr) -> anyhow::Result<Option<String>> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;

        // A non-ASCII name of the same UTF-16 length may compare equal to a generated name on Windows.
        let mut non_ascii = false;
        let length = name.encode_wide().inspect(|unit| non_ascii |= *unit > 0x7f).count();
        ensure!(
            length != HASH_HEX_LEN + RECORD_SUFFIX.len() || !non_ascii,
            "package operation record name cannot be normalized"
        );
    }
    Ok(name
        .to_str()
        .filter(|name| is_record_name(name))
        .map(str::to_ascii_lowercase))
}

fn index_bytes(admitted: &BTreeSet<String>, limit: u64) -> anyhow::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(&IndexRef {
        version: VERSION,
        operations: admitted,
    })
    .context("serialize package operation journal index")?;
    ensure!(
        bytes.len() as u64 <= limit,
        "package operation journal index is too large"
    );
    Ok(bytes)
}

impl OperationJournal {
    /// Returns false only when the nonempty ID has no journal record under ["Package operations"].
    ///
    /// This reads a lock-free snapshot without waiting for journal I/O.
    /// The caller tracks admissions until this journal publishes them.
    ///
    /// ["Package operations"]: https://github.com/Devolutions/devolutions-gateway/blob/master/crates/agent-channel-proto/CONTRACT.package-management.md#operations
    pub(super) fn may_contain(&self, operation_id: &str) -> bool {
        operation_id.is_empty() || self.membership.load().names.contains(&record_name(operation_id))
    }

    /// Returns whether the membership index has room for a record named `name`.
    #[cfg(any(windows, test))]
    pub(super) fn has_index_capacity(&self, name: &str) -> bool {
        let membership = self.membership.load();
        membership.names.contains(name) || membership.size_with(name) <= self.index_size_limit
    }

    /// Reads an existing operation under ["Package operations"] without admitting a new one.
    ///
    /// Returns `None` only when the journal establishes absence.
    /// This can block on journal I/O and must run off the async runtime.
    ///
    /// ["Package operations"]: https://github.com/Devolutions/devolutions-gateway/blob/master/crates/agent-channel-proto/CONTRACT.package-management.md#operations
    pub(super) fn lookup(
        &self,
        authority_id: &str,
        request: &PackageOperationRequest,
    ) -> anyhow::Result<Option<Admission>> {
        let (name, encoded) = locate(authority_id, request)?;
        let state = self.state.lock();
        self.read_admission(&state, &name, request, &encoded)
    }

    /// Opens the journal, creating it when the data directory or the journal directory is missing.
    ///
    /// A journal deleted whole cannot be told from a first run, so operations recorded in it may execute again.
    /// An existing journal missing its records directory or `journal.json` is refused, as is one that is not private
    /// to the Agent's account.
    pub(super) fn open(data_dir: &Utf8Path) -> anyhow::Result<Self> {
        Self::open_with_index_size_limit(data_dir, MAX_INDEX_SIZE)
    }

    fn open_with_index_size_limit(data_dir: &Utf8Path, limit: u64) -> anyhow::Result<Self> {
        let rule = directory_rule();
        let data = Dir::create_base(data_dir, &rule).context("open data directory")?;
        // UNTESTED: The initialization lock prevents another process from treating an existing journal as new.
        // Tests contend in one process; check cross-process contention when changing this lock.
        let _initialization_lock =
            lock_file(&data, INITIALIZATION_LOCK_NAME).context("open package operation journal initialization lock")?;
        let (lock, was_missing) = acquire_lock(&data, &rule)?;
        let directory = match lock
            .dir
            .open_dir(RECORDS_NAME, &rule, Share::Shared)
            .context("open package operation records directory")?
        {
            Some(directory) => directory,
            None => {
                ensure!(was_missing, "package operation records directory is missing");
                ensure!(
                    lock.dir
                        .entries()
                        .context("list package operation journal directory")?
                        .iter()
                        .all(|entry| entry.name == LOCK_FILE_NAME),
                    "package operation journal directory has content but no records directory"
                );
                lock.dir
                    .create_dir(RECORDS_NAME, &rule, Existing::Check)
                    .context("create package operation records directory")?
            }
        };

        let mut journal = Self {
            _lock: lock,
            directory,
            state: Mutex::new(State {
                admitted: BTreeSet::new(),
                in_flight: HashSet::new(),
            }),
            membership: ArcSwap::from_pointee(Membership::new(BTreeSet::new(), limit)?),
            #[cfg(test)]
            index_write_hook: Mutex::new(None),
            index_size_limit: limit,
            recorded: Condvar::new(),
        };
        let admitted = journal.load_index(was_missing)?;
        let mut membership = Membership::new(admitted.clone(), limit)?;
        for entry in journal.directory.entries().context("list package operation records")? {
            if let Some(name) = normalized_record_name(&entry.name)? {
                membership.insert(name, limit)?;
            }
        }
        journal.membership.store(Arc::new(membership));
        journal.state.get_mut().admitted = admitted;
        Ok(journal)
    }

    fn load_index(&self, was_missing: bool) -> anyhow::Result<BTreeSet<String>> {
        let Some(file) = self
            .directory
            .open_file(INDEX_NAME, &file_rule(), FileOptions::new().read(true))
            .context("open package operation journal index")?
        else {
            ensure!(was_missing, "package operation journal index is missing");
            ensure!(
                self.directory
                    .entries()
                    .context("list package operation journal directory")?
                    .is_empty(),
                "package operation journal has content but no index"
            );
            let admitted = BTreeSet::new();
            let bytes = index_bytes(&admitted, self.index_size_limit)?;
            self.write_index(&bytes)
                .context("persist package operation journal index")?;
            return Ok(admitted);
        };

        let index: Index = serde_json::from_slice(&read_limited(file, MAX_INDEX_SIZE)?)
            .context("parse package operation journal index")?;
        ensure!(
            index.version == VERSION,
            "unsupported package operation journal version"
        );
        ensure!(
            index.operations.iter().all(|name| is_canonical_record_name(name)),
            "invalid package operation journal index record name"
        );
        Ok(index.operations)
    }

    /// Decides whether this delivery of `request` for `authority_id` may submit its operation, persisting a pending
    /// record first when it may.
    ///
    /// Of any number of concurrent deliveries of one new operation ID, exactly one is [`Admission::Admitted`].
    pub(super) fn admit(&self, authority_id: &str, request: &PackageOperationRequest) -> anyhow::Result<Admission> {
        let (name, encoded) = locate(authority_id, request)?;
        let mut state = self.state.lock();

        if let Some(admission) = self.read_admission(&state, &name, request, &encoded)? {
            return Ok(admission);
        }

        let mut admitted = state.admitted.clone();
        admitted.insert(name.clone());
        let mut membership = self.membership.load_full().as_ref().clone();
        membership.insert(name.clone(), self.index_size_limit)?;
        let bytes = index_bytes(&admitted, self.index_size_limit)?;
        self.membership.store(Arc::new(membership));
        state.admitted = admitted;
        self.write_index(&bytes)
            .context("persist package operation journal index")?;

        let record = Record {
            version: VERSION,
            authority_id: authority_id.to_owned(),
            operation_id: request.operation_id.clone(),
            request: encoded,
            outcome: None,
            execution_started: false,
        };
        self.write_record(&name, &record, Replace::Refuse)
            .context("persist pending package operation record")?;
        state.in_flight.insert(name);
        Ok(Admission::Admitted)
    }

    /// Durably records that the Broker proved the process of an operation [`admitted`](Self::admit) for `request` started.
    ///
    /// Call it after the grant is delivered and before [`complete`](Self::complete) when the evidence exists.
    /// The evidence is never withdrawn, so recording it again succeeds.
    pub(super) fn mark_started(&self, authority_id: &str, request: &PackageOperationRequest) -> anyhow::Result<()> {
        let (name, encoded) = locate(authority_id, request)?;
        let state = self.state.lock();

        let mut record = self
            .read(&state, &name, request)?
            .context("no package operation record to mark as started")?;
        ensure!(
            record.authority_id == authority_id && record.request == encoded,
            "package operation record belongs to a different request"
        );
        if record.execution_started {
            return Ok(());
        }
        record.execution_started = true;
        self.write_record(&name, &record, Replace::Allow)
            .context("persist package operation start evidence")
    }

    /// Durably records the end of an operation [`admitted`](Self::admit) for `request`, and wakes its waiters.
    ///
    /// Recording the outcome already recorded succeeds; recording a different outcome over a recorded one is an error.
    /// When the outcome cannot be written, the operation stops being in flight, so waiters read it as unknown.
    pub(super) fn complete(
        &self,
        authority_id: &str,
        request: &PackageOperationRequest,
        outcome: Outcome,
    ) -> anyhow::Result<()> {
        let (name, encoded) = locate(authority_id, request)?;
        let mut state = self.state.lock();

        let record = self.read(&state, &name, request);
        if let Ok(Some(record)) = &record {
            ensure!(
                record.authority_id == authority_id && record.request == encoded,
                "package operation record belongs to a different request"
            );
        }

        let completed = record.and_then(|record| {
            let mut record = record.context("no package operation record to complete")?;
            match record.outcome {
                Some(recorded) if recorded == outcome => Ok(()),
                Some(_) => bail!("package operation already has a different recorded outcome"),
                None => {
                    record.outcome = Some(outcome);
                    self.write_record(&name, &record, Replace::Allow)
                        .context("persist package operation outcome")
                }
            }
        });
        if state.in_flight.remove(&name) {
            self.recorded.notify_all();
        }
        completed
    }

    /// Blocks until the operation in flight for `request` has its outcome recorded, and returns it.
    ///
    /// An operation that is not in flight returns its recorded outcome at once, or [`Outcome::Unknown`] when it is
    /// still pending, with the start evidence recorded.
    /// Call it off the async runtime.
    pub(super) fn wait(&self, authority_id: &str, request: &PackageOperationRequest) -> anyhow::Result<Settled> {
        let (name, encoded) = locate(authority_id, request)?;
        let mut state = self.state.lock();
        while state.in_flight.contains(&name) {
            self.recorded.wait(&mut state);
        }

        let record = self
            .read(&state, &name, request)?
            .context("no package operation record to wait for")?;
        ensure!(
            record.request == encoded,
            "package operation record belongs to a different request"
        );
        Ok(Settled::new(
            record.outcome.unwrap_or(Outcome::Unknown),
            record.execution_started,
        ))
    }

    fn read_admission(
        &self,
        state: &State,
        name: &str,
        request: &PackageOperationRequest,
        encoded: &str,
    ) -> anyhow::Result<Option<Admission>> {
        let Some(record) = self.read(state, name, request)? else {
            return Ok(None);
        };
        if record.request != encoded {
            return Ok(Some(Admission::PayloadMismatch));
        }
        let started = record.execution_started;
        Ok(Some(match record.outcome {
            Some(outcome) => Admission::Recorded(Settled::new(outcome, started)),
            None if state.in_flight.contains(name) => Admission::InFlight,
            None => Admission::Recorded(Settled::new(Outcome::Unknown, started)),
        }))
    }

    /// Reads and validates the record `name`, and returns `None` only when it neither exists nor is listed.
    fn read(&self, state: &State, name: &str, request: &PackageOperationRequest) -> anyhow::Result<Option<Record>> {
        let listed = state.admitted.contains(name);
        let Some(file) = self
            .directory
            .open_file(name, &file_rule(), FileOptions::new().read(true))
            .context("open package operation record")?
        else {
            ensure!(
                !listed && !self.membership.load().names.contains(name),
                "package operation record is missing, so its history may be lost"
            );
            return Ok(None);
        };
        ensure!(
            listed,
            "package operation record is not in the journal index, so the journal cannot vouch for it"
        );

        let record: Record =
            serde_json::from_slice(&read_limited(file, MAX_RECORD_SIZE)?).context("parse package operation record")?;
        ensure!(
            record.version == VERSION,
            "unsupported package operation record version"
        );
        ensure!(
            !matches!(&record.outcome, Some(Outcome::Failed { error }) if error.is_empty()),
            "package operation failure has no error"
        );
        ensure!(
            record.operation_id == request.operation_id,
            "package operation record belongs to another operation ID"
        );
        let stored = hex::decode(&record.request).context("decode stored package operation request")?;
        let stored =
            PackageOperationRequest::decode(stored.as_slice()).context("parse stored package operation request")?;
        ensure!(
            stored.operation_id == record.operation_id,
            "stored package operation request has another operation ID"
        );
        Ok(Some(record))
    }

    fn write_index(&self, bytes: &[u8]) -> anyhow::Result<()> {
        #[cfg(test)]
        let hook = self.index_write_hook.lock().take();
        #[cfg(test)]
        if let Some(hook) = &hook {
            hook.before()?;
        }
        self.write(INDEX_NAME, bytes, Replace::Allow)?;
        #[cfg(test)]
        if let Some(hook) = &hook {
            hook.after()?;
        }
        Ok(())
    }

    fn write_record(&self, name: &str, record: &Record, replace: Replace) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(record).context("serialize package operation record")?;
        self.write(name, &bytes, replace)
    }

    /// Makes `bytes` durable as `name`; a crash leaves either the old file or the new one, and possibly a stray
    /// temporary file, which nothing reads.
    fn write(&self, name: &str, bytes: &[u8], replace: Replace) -> anyhow::Result<()> {
        let temporary = format!(".{name}-{}.tmp", Uuid::new_v4());
        let mut file = self
            .directory
            .create_file(&temporary, &file_rule(), FileOptions::new())
            .context("create package operation file")?;
        let persisted = file
            .write_all(bytes)
            .context("write package operation file")
            .and_then(|()| {
                self.directory
                    .persist(&file, &temporary, name, replace)
                    .context("install package operation file")
            });
        if persisted.is_err() {
            let _ = self.directory.discard(&file, &temporary);
        }
        persisted
    }
}

fn read_limited(file: std::fs::File, limit: u64) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .context("read package operation file")?;
    ensure!(bytes.len() as u64 <= limit, "package operation file is too large");
    Ok(bytes)
}

fn locate(authority_id: &str, request: &PackageOperationRequest) -> anyhow::Result<(String, String)> {
    ensure!(!authority_id.is_empty(), "authority ID is empty");
    ensure!(!request.operation_id.is_empty(), "operation ID is empty");
    Ok((record_name(&request.operation_id), hex::encode(request.encode_to_vec())))
}

#[cfg(test)]
impl OperationJournal {
    pub(crate) fn pause_index_write_for_test(
        &mut self,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let hook = tests::IndexWriteHook::Pause {
            entered: entered_tx,
            resume: resume_rx,
        };
        assert!(self.index_write_hook.get_mut().replace(hook).is_none());
        (entered_rx, resume_tx)
    }

    #[cfg(windows)]
    pub(crate) fn exhaust_index_for_test(&mut self) {
        self.index_size_limit = self.membership.load().index_size;
    }

    #[cfg(windows)]
    pub(crate) fn restore_index_limit_for_test(&mut self) {
        self.index_size_limit = MAX_INDEX_SIZE;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use camino::Utf8PathBuf;

    use super::*;

    #[derive(Debug)]
    pub(super) enum IndexWriteHook {
        Pause {
            entered: mpsc::Sender<()>,
            resume: mpsc::Receiver<()>,
        },
        FailAfterPersist,
    }

    impl IndexWriteHook {
        pub(super) fn before(&self) -> anyhow::Result<()> {
            if let Self::Pause { entered, resume } = self {
                entered.send(())?;
                resume.recv()?;
            }
            Ok(())
        }

        pub(super) fn after(&self) -> anyhow::Result<()> {
            if let Self::FailAfterPersist = self {
                bail!("injected index persistence failure");
            }
            Ok(())
        }
    }

    /// A data directory removed on drop.
    struct TestDir(Utf8PathBuf);

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The system temporary directory can be writable by other accounts, which fails the journal's check of the
    /// directories above, so tests use the user's local application data directory where there is one.
    fn data_dir() -> anyhow::Result<(TestDir, Utf8PathBuf)> {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = Utf8PathBuf::from_path_buf(base)
            .map_err(|_| anyhow::anyhow!("base directory is not UTF-8"))?
            .join(format!("oj-{}", Uuid::new_v4().simple()));
        let data = root.join("data");
        Ok((TestDir(root), data))
    }

    fn request(operation_id: &str, package_id: &str) -> PackageOperationRequest {
        PackageOperationRequest {
            operation_id: operation_id.to_owned(),
            package_id: package_id.to_owned(),
            target_user_uuid: "user-1".to_owned(),
            ..Default::default()
        }
    }

    fn settled(outcome: Outcome) -> Settled {
        Settled {
            outcome,
            execution_started: None,
        }
    }

    fn journal_path(data: &Utf8Path) -> Utf8PathBuf {
        data.join(DIRECTORY_NAME).join(RECORDS_NAME)
    }

    fn record_path(data: &Utf8Path, operation_id: &str) -> Utf8PathBuf {
        journal_path(data).join(record_name(operation_id))
    }

    fn assert_membership_matches_records(journal: &OperationJournal, data: &Utf8Path) -> anyhow::Result<()> {
        let index: Index = serde_json::from_slice(&std::fs::read(journal_path(data).join(INDEX_NAME))?)?;
        let mut records = BTreeSet::new();
        for entry in std::fs::read_dir(journal_path(data))? {
            let name = entry?.file_name().into_string().expect("record name is UTF-8");
            if name != INDEX_NAME {
                records.insert(name);
            }
        }
        assert_eq!(&journal.membership.load().names, &index.operations);
        assert_eq!(records, index.operations);
        Ok(())
    }

    #[test]
    fn membership_tracks_the_agents_own_writes_after_reopen() -> anyhow::Result<()> {
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-remote-operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let request = request("recorded", "pkg");

        // oracle: mutant a new ID cannot be distinguished from recorded operations
        assert!(!journal.may_contain("new"));
        assert_membership_matches_records(&journal, &data)?;
        journal.admit("authority", &request)?;
        journal.complete("authority", &request, Outcome::Succeeded)?;
        assert_membership_matches_records(&journal, &data)?;
        journal.admit("authority", &self::request("pending", "pkg"))?;
        assert!(journal.may_contain("recorded"));
        assert!(journal.may_contain("pending"));
        assert_membership_matches_records(&journal, &data)?;
        drop(journal);

        let journal = OperationJournal::open(&data)?;
        assert!(journal.may_contain("recorded"));
        assert!(journal.may_contain("pending"));
        assert!(!journal.may_contain("new"));
        assert_membership_matches_records(&journal, &data)?;
        Ok(())
    }

    #[test]
    fn membership_keeps_orphaned_records_after_another_admission() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let orphan = request("orphan", "pkg");
        let recorded = request("recorded", "pkg");
        journal.admit("authority", &orphan)?;
        journal.admit("authority", &recorded)?;
        journal.complete("authority", &recorded, Outcome::Succeeded)?;
        drop(journal);
        std::fs::write(
            journal_path(&data).join(INDEX_NAME),
            serde_json::to_vec(&Index {
                version: VERSION,
                operations: BTreeSet::from([record_name("recorded")]),
            })?,
        )?;

        let journal = OperationJournal::open(&data)?;
        assert!(journal.may_contain("orphan"));
        assert!(journal.lookup("authority", &orphan).is_err());
        assert!(journal.admit("authority", &orphan).is_err());
        assert!(journal.may_contain("recorded"));
        assert_eq!(
            journal.admit("authority", &recorded)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
        // oracle: mutant an orphan prevents unrelated operations from being admitted
        assert!(!journal.may_contain("new"));
        assert_eq!(journal.admit("authority", &request("new", "pkg"))?, Admission::Admitted);
        assert!(journal.may_contain("orphan"));
        Ok(())
    }

    #[test]
    fn membership_refuses_open_when_orphans_exceed_the_budget() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request("first", "pkg"))?;
        let limit = std::fs::metadata(journal_path(&data).join(INDEX_NAME))?.len();
        journal.admit("authority", &request("second", "pkg"))?;
        drop(journal);
        std::fs::write(
            journal_path(&data).join(INDEX_NAME),
            serde_json::to_vec(&Index {
                version: VERSION,
                operations: BTreeSet::new(),
            })?,
        )?;

        let error = OperationJournal::open_with_index_size_limit(&data, limit)
            .expect_err("two orphan records exceed the index limit");
        assert!(
            error
                .to_string()
                .contains("package operation journal index is too large")
        );
        let journal = OperationJournal::open(&data)?;
        assert!(journal.may_contain("first"));
        assert!(journal.may_contain("second"));
        Ok(())
    }

    #[test]
    fn membership_recognizes_an_orphan_with_different_filename_case() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let orphan = request("orphan", "pkg");
        journal.admit("authority", &orphan)?;
        drop(journal);
        std::fs::write(
            journal_path(&data).join(INDEX_NAME),
            serde_json::to_vec(&Index {
                version: VERSION,
                operations: BTreeSet::new(),
            })?,
        )?;
        let intermediate = journal_path(&data).join("renaming");
        let uppercase = journal_path(&data).join(record_name("orphan").to_ascii_uppercase());
        std::fs::rename(record_path(&data, "orphan"), &intermediate)?;
        std::fs::rename(intermediate, uppercase)?;

        let journal = OperationJournal::open(&data)?;
        assert!(journal.may_contain("orphan"));
        assert!(journal.lookup("authority", &orphan).is_err());
        assert_eq!(journal.admit("authority", &request("new", "pkg"))?, Admission::Admitted);
        assert!(journal.may_contain("orphan"));
        Ok(())
    }

    #[rstest::rstest]
    #[case::uppercase(record_name("recorded").to_ascii_uppercase())]
    #[case::malformed(format!("g{}", &record_name("recorded")[1..]))]
    #[case::invalid_length("not-a-record.json".to_owned())]
    fn noncanonical_index_entry_refuses_open(#[case] indexed_name: String) -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let recorded = request("recorded", "pkg");
        journal.admit("authority", &recorded)?;
        drop(journal);
        std::fs::remove_file(record_path(&data, "recorded"))?;
        std::fs::write(
            journal_path(&data).join(INDEX_NAME),
            serde_json::to_vec(&Index {
                version: VERSION,
                operations: BTreeSet::from([indexed_name]),
            })?,
        )?;

        assert!(OperationJournal::open(&data).is_err());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn ambiguous_windows_record_name_refuses_open() -> anyhow::Result<()> {
        // oracle: mutant a possible Windows case alias is ignored as evidence of a record
        let (_dir, data) = data_dir()?;
        drop(OperationJournal::open(&data)?);
        let name = format!("{}.jſon", hashed("orphan"));
        std::fs::write(journal_path(&data).join(name), b"orphan")?;

        assert!(OperationJournal::open(&data).is_err());
        Ok(())
    }

    #[test]
    fn lookup_does_not_admit_and_reports_existing_outcomes() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let request = request("lookup", "pkg");

        assert_eq!(journal.lookup("authority", &request)?, None);
        assert_eq!(journal.admit("authority", &request)?, Admission::Admitted);
        assert_eq!(journal.lookup("another", &request)?, Some(Admission::InFlight));
        assert_eq!(
            journal.lookup("another", &self::request("lookup", "other"))?,
            Some(Admission::PayloadMismatch)
        );
        journal.complete("authority", &request, Outcome::Succeeded)?;
        assert_eq!(
            journal.lookup("another", &request)?,
            Some(Admission::Recorded(settled(Outcome::Succeeded)))
        );
        Ok(())
    }

    #[test]
    fn membership_retains_an_index_write_that_failed_after_rename() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        *journal.index_write_hook.lock() = Some(IndexWriteHook::FailAfterPersist);
        let failed = request("failed", "pkg");

        assert!(journal.admit("authority", &failed).is_err());
        assert!(journal.may_contain("failed"));
        assert!(journal.lookup("authority", &failed).is_err());
        assert!(!record_path(&data, "failed").exists());
        assert_eq!(
            journal.admit("authority", &request("other", "pkg"))?,
            Admission::Admitted
        );
        drop(journal);

        let journal = OperationJournal::open(&data)?;
        assert!(journal.may_contain("failed"));
        assert!(journal.lookup("authority", &failed).is_err());
        Ok(())
    }

    #[test]
    fn membership_stays_live_while_index_write_is_blocked() -> anyhow::Result<()> {
        // oracle: mutant membership waits for an admission's journal I/O lock
        let (_dir, data) = data_dir()?;
        let mut journal = OperationJournal::open(&data)?;
        let (entered_rx, resume_tx) = journal.pause_index_write_for_test();
        let journal = Arc::new(journal);
        let writer = {
            let journal = Arc::clone(&journal);
            std::thread::spawn(move || journal.admit("authority", &request("blocked", "pkg")))
        };
        if let Err(error) = entered_rx.recv_timeout(Duration::from_secs(10)) {
            drop(resume_tx);
            let _ = writer.join();
            return Err(error.into());
        }

        let (observed_tx, observed_rx) = mpsc::channel();
        let reader = {
            let journal = Arc::clone(&journal);
            std::thread::spawn(move || {
                let _ = observed_tx.send((journal.may_contain("blocked"), journal.may_contain("new")));
            })
        };
        let observed = observed_rx.recv_timeout(Duration::from_secs(3));
        let released = resume_tx.send(());
        let admission = writer.join().expect("writer thread panicked");
        reader.join().expect("reader thread panicked");

        released?;
        assert_eq!(observed?, (true, false));
        assert_eq!(admission?, Admission::Admitted);
        Ok(())
    }

    #[test]
    fn membership_does_not_publish_past_the_index_budget() -> anyhow::Result<()> {
        // oracle: mutant failed index writes grow the snapshot beyond the index's size limit
        let (_dir, data) = data_dir()?;
        let mut journal = OperationJournal::open(&data)?;
        *journal.index_write_hook.lock() = Some(IndexWriteHook::FailAfterPersist);
        assert!(journal.admit("authority", &request("retained", "pkg")).is_err());
        journal.index_size_limit = std::fs::metadata(journal_path(&data).join(INDEX_NAME))?.len();

        assert!(journal.may_contain("retained"));
        assert!(journal.admit("authority", &request("beyond", "pkg")).is_err());
        assert!(!journal.may_contain("beyond"));
        assert!(journal.admit("authority", &request("also-beyond", "pkg")).is_err());
        assert!(!journal.may_contain("also-beyond"));
        assert!(journal.may_contain("retained"));
        drop(journal);

        let journal = OperationJournal::open(&data)?;
        assert!(journal.may_contain("retained"));
        Ok(())
    }

    #[test]
    fn orphaned_records_count_against_the_index_budget() -> anyhow::Result<()> {
        // oracle: mutant orphaned records allow the snapshot to exceed the index's size limit
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request("orphan", "pkg"))?;
        let limit = std::fs::metadata(journal_path(&data).join(INDEX_NAME))?.len();
        drop(journal);
        std::fs::write(
            journal_path(&data).join(INDEX_NAME),
            serde_json::to_vec(&Index {
                version: VERSION,
                operations: BTreeSet::new(),
            })?,
        )?;

        let mut journal = OperationJournal::open(&data)?;
        journal.index_size_limit = limit;
        assert!(journal.may_contain("orphan"));
        assert!(journal.admit("authority", &request("beyond", "pkg")).is_err());
        assert!(!journal.may_contain("beyond"));
        assert!(journal.may_contain("orphan"));
        Ok(())
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-remote-operations
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn an_index_at_its_budget_reopens_with_its_records() -> anyhow::Result<()> {
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let recorded = request("first", "pkg");
        journal.admit("authority", &recorded)?;
        journal.complete("authority", &recorded, Outcome::Succeeded)?;
        let limit = std::fs::metadata(journal_path(&data).join(INDEX_NAME))?.len();
        drop(journal);

        let reopened = OperationJournal::open_with_index_size_limit(&data, limit);
        assert!(reopened.is_ok(), "an index at its budget must reopen: {reopened:?}");
        let reopened = reopened?;
        assert_eq!(
            reopened.lookup("authority", &recorded)?,
            Some(Admission::Recorded(settled(Outcome::Succeeded)))
        );
        Ok(())
    }

    #[test]
    fn index_budget_accepts_an_exact_fit() -> anyhow::Result<()> {
        // oracle: mutant an off-by-one in the JSON index size permits publication past its limit
        let (_dir, data) = data_dir()?;
        let mut journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request("first", "pkg"))?;
        let current_size = std::fs::metadata(journal_path(&data).join(INDEX_NAME))?.len();
        let next_entry_size = format!(",\"{:064x}.json\"", 0).len() as u64;
        journal.index_size_limit = current_size + next_entry_size - 1;

        assert!(journal.admit("authority", &request("second", "pkg")).is_err());
        assert!(!journal.may_contain("second"));
        assert!(!journal.has_index_capacity(&record_name("second")));
        journal.index_size_limit += 1;
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        assert!(journal.has_index_capacity(&record_name("second")));
        assert_eq!(
            journal.admit("authority", &request("second", "pkg"))?,
            Admission::Admitted
        );
        assert!(journal.may_contain("first"));
        assert!(journal.may_contain("second"));
        Ok(())
    }

    #[test]
    fn first_delivery_is_admitted_and_repeat_is_in_flight() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let request = request("op", "pkg");

        assert_eq!(journal.admit("authority", &request)?, Admission::Admitted);
        assert_eq!(journal.admit("authority", &request)?, Admission::InFlight);
        Ok(())
    }

    #[test]
    fn repeat_after_completion_returns_recorded_outcome() -> anyhow::Result<()> {
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-remote-operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let request = request("op", "pkg");
        let outcome = Outcome::Failed {
            error: "nope".to_owned(),
        };

        journal.admit("authority", &request)?;
        journal.complete("authority", &request, outcome.clone())?;

        assert_eq!(
            journal.admit("authority", &request)?,
            Admission::Recorded(settled(outcome))
        );
        Ok(())
    }

    #[test]
    fn waiter_receives_the_outcome_of_the_in_flight_operation() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = Arc::new(OperationJournal::open(&data)?);
        let request = Arc::new(request("op", "pkg"));
        journal.admit("authority", &request)?;

        let waiter = {
            let (journal, request) = (Arc::clone(&journal), Arc::clone(&request));
            std::thread::spawn(move || journal.wait("authority", &request))
        };
        std::thread::sleep(Duration::from_millis(100));
        assert!(!waiter.is_finished());
        journal.complete("authority", &request, Outcome::Succeeded)?;

        assert_eq!(
            waiter.join().expect("waiter thread panicked")?,
            settled(Outcome::Succeeded)
        );
        Ok(())
    }

    #[test]
    fn same_id_with_changed_payload_is_rejected() -> anyhow::Result<()> {
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;

        journal.admit("authority", &request("op", "pkg"))?;

        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        assert_eq!(
            journal.admit("authority", &request("op", "other"))?,
            Admission::PayloadMismatch
        );
        // oracle: mutant a changed payload can record an outcome over the operation it does not match
        assert!(
            journal
                .complete("authority", &request("op", "other"), Outcome::Succeeded)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn same_request_from_another_authority_returns_recorded_outcome() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let request = request("op", "pkg");
        journal.admit("first", &request)?;
        assert_eq!(journal.admit("second", &request)?, Admission::InFlight);
        journal.complete("first", &request, Outcome::Succeeded)?;

        assert_eq!(
            journal.admit("second", &request)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
        assert_eq!(journal.wait("second", &request)?, settled(Outcome::Succeeded));
        assert!(journal.complete("second", &request, Outcome::Unknown).is_err());
        assert_eq!(
            journal.admit("first", &request)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
        Ok(())
    }

    #[test]
    fn another_authority_cannot_finish_or_interrupt_an_in_flight_operation() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let request = request("op", "pkg");
        journal.admit("first", &request)?;

        assert!(journal.mark_started("second", &request).is_err());
        assert!(journal.complete("second", &request, Outcome::Succeeded).is_err());
        assert_eq!(journal.admit("first", &request)?, Admission::InFlight);
        journal.complete("first", &request, Outcome::Succeeded)?;
        Ok(())
    }

    #[test]
    fn pending_record_reads_as_unknown_after_reopen() -> anyhow::Result<()> {
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-remote-operations
        let (_dir, data) = data_dir()?;
        let request = request("op", "pkg");
        let journal = OperationJournal::open(&data)?;
        assert_eq!(journal.admit("authority", &request)?, Admission::Admitted);
        drop(journal);

        let journal = OperationJournal::open(&data)?;

        assert_eq!(
            journal.admit("authority", &request)?,
            Admission::Recorded(settled(Outcome::Unknown))
        );
        assert_eq!(journal.wait("authority", &request)?, settled(Outcome::Unknown));
        Ok(())
    }

    #[test]
    fn terminal_outcome_survives_reopen_and_cannot_be_replaced() -> anyhow::Result<()> {
        let (_dir, data) = data_dir()?;
        let request = request("op", "pkg");
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request)?;
        journal.complete("authority", &request, Outcome::Succeeded)?;
        drop(journal);

        let journal = OperationJournal::open(&data)?;

        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-remote-operations
        assert_eq!(
            journal.admit("authority", &request)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
        // oracle: mutant a late or repeated completion overwrites the recorded terminal outcome
        journal.complete("authority", &request, Outcome::Succeeded)?;
        assert!(journal.complete("authority", &request, Outcome::Unknown).is_err());
        assert_eq!(
            journal.admit("authority", &request)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
        Ok(())
    }

    #[test]
    fn deleted_record_is_refused_while_the_journal_is_open() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let (finished, pending) = (request("finished", "pkg"), request("pending", "pkg"));
        journal.admit("authority", &finished)?;
        journal.complete("authority", &finished, Outcome::Succeeded)?;
        journal.admit("authority", &pending)?;
        std::fs::remove_file(record_path(&data, "finished"))?;
        std::fs::remove_file(record_path(&data, "pending"))?;

        assert!(journal.admit("authority", &finished).is_err());
        assert!(journal.admit("authority", &pending).is_err());
        assert!(journal.wait("authority", &finished).is_err());
        assert!(journal.complete("authority", &pending, Outcome::Succeeded).is_err());
        assert!(!record_path(&data, "finished").exists());
        assert_eq!(
            journal.admit("authority", &request("other", "pkg"))?,
            Admission::Admitted
        );
        Ok(())
    }

    #[test]
    fn deleted_record_is_refused_after_reopen() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let (finished, pending) = (request("finished", "pkg"), request("pending", "pkg"));
        journal.admit("authority", &finished)?;
        journal.complete("authority", &finished, Outcome::Succeeded)?;
        journal.admit("authority", &pending)?;
        drop(journal);
        std::fs::remove_file(record_path(&data, "finished"))?;
        std::fs::remove_file(record_path(&data, "pending"))?;

        let journal = OperationJournal::open(&data)?;

        assert!(journal.admit("authority", &finished).is_err());
        assert!(journal.admit("authority", &pending).is_err());
        assert!(!record_path(&data, "pending").exists());
        assert_eq!(
            journal.admit("authority", &request("other", "pkg"))?,
            Admission::Admitted
        );
        Ok(())
    }

    #[test]
    fn record_missing_from_the_index_is_refused() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let request = request("op", "pkg");
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request)?;
        drop(journal);
        std::fs::write(
            journal_path(&data).join(INDEX_NAME),
            serde_json::to_vec(&Index {
                version: VERSION,
                operations: BTreeSet::new(),
            })?,
        )?;

        let journal = OperationJournal::open(&data)?;

        assert!(journal.admit("authority", &request).is_err());
        Ok(())
    }

    #[test]
    fn interrupted_admission_is_refused_and_leftovers_are_ignored() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let request = request("op", "pkg");
        let journal = OperationJournal::open(&data)?;
        drop(journal);
        // A crash after the index write and before the record write leaves the name listed with no record, and a crash
        // inside a write leaves a temporary file.
        let name = record_name("op");
        std::fs::write(
            journal_path(&data).join(INDEX_NAME),
            serde_json::to_vec(&Index {
                version: VERSION,
                operations: BTreeSet::from([name.clone()]),
            })?,
        )?;
        std::fs::write(journal_path(&data).join(format!(".{name}-stray.tmp")), b"partial")?;

        let journal = OperationJournal::open(&data)?;

        assert!(journal.admit("authority", &request).is_err());
        assert_eq!(
            journal.admit("authority", &self::request("other", "pkg"))?,
            Admission::Admitted
        );
        Ok(())
    }

    #[test]
    fn start_evidence_survives_restart_and_repeat_deliveries() -> anyhow::Result<()> {
        let (_dir, data) = data_dir()?;
        let (started, unproven) = (request("started", "pkg"), request("unproven", "pkg"));
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &started)?;
        journal.mark_started("authority", &started)?;
        journal.mark_started("authority", &started)?;
        journal.admit("authority", &unproven)?;
        drop(journal);

        // A pending record reads as unknown, keeping the evidence only where it was recorded.
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let journal = OperationJournal::open(&data)?;
        let expected = Settled {
            outcome: Outcome::Unknown,
            execution_started: Some(true),
        };
        assert_eq!(
            journal.admit("authority", &started)?,
            Admission::Recorded(expected.clone())
        );
        assert_eq!(
            journal.admit("authority", &unproven)?,
            Admission::Recorded(settled(Outcome::Unknown))
        );

        // A later outcome keeps the evidence.
        journal.complete("authority", &started, Outcome::Unknown)?;
        assert_eq!(journal.wait("authority", &started)?, expected);

        // Records written before the field existed carry no evidence.
        // oracle: mutant a record without start evidence is read back as proof that the operation started
        let path = record_path(&data, "unproven");
        let mut record: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        assert_eq!(
            record
                .as_object_mut()
                .expect("record is an object")
                .remove("execution_started"),
            Some(false.into())
        );
        std::fs::write(&path, serde_json::to_vec(&record)?)?;
        assert_eq!(journal.wait("authority", &unproven)?, settled(Outcome::Unknown));
        Ok(())
    }

    #[test]
    fn wholly_missing_journal_is_created_empty() -> anyhow::Result<()> {
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-remote-operations
        let (_dir, data) = data_dir()?;
        let request = request("op", "pkg");

        let journal = OperationJournal::open(&data)?;
        assert_eq!(journal.admit("authority", &request)?, Admission::Admitted);
        drop(journal);

        // The journal directory deleted whole, as by an operator, is created again without its history.
        std::fs::remove_dir_all(data.join(DIRECTORY_NAME))?;
        let journal = OperationJournal::open(&data)?;
        assert_eq!(journal.admit("authority", &request)?, Admission::Admitted);
        Ok(())
    }

    #[test]
    fn partially_missing_journal_fails_closed() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let request = request("op", "pkg");
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request)?;
        drop(journal);

        let records = journal_path(&data);
        std::fs::remove_file(records.join(INDEX_NAME))?;
        assert!(OperationJournal::open(&data).is_err());

        std::fs::remove_dir_all(&records)?;
        std::fs::write(data.join(DIRECTORY_NAME).join("stray"), b"x")?;
        assert!(OperationJournal::open(&data).is_err());
        Ok(())
    }

    #[test]
    fn existing_journal_without_records_directory_fails_closed() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request("op", "pkg"))?;
        drop(journal);
        std::fs::remove_dir_all(journal_path(&data))?;

        assert!(OperationJournal::open(&data).is_err());
        Ok(())
    }

    #[test]
    fn existing_journal_without_index_or_records_fails_closed() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request("op", "pkg"))?;
        drop(journal);
        std::fs::remove_file(record_path(&data, "op"))?;
        std::fs::remove_file(journal_path(&data).join(INDEX_NAME))?;

        assert!(OperationJournal::open(&data).is_err());
        Ok(())
    }

    #[test]
    fn interrupted_creation_fails_closed() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        drop(OperationJournal::open(&data)?);
        std::fs::remove_file(journal_path(&data).join(INDEX_NAME))?;

        assert!(OperationJournal::open(&data).is_err());
        Ok(())
    }

    #[test]
    fn concurrent_initialization_is_refused() -> anyhow::Result<()> {
        // oracle: mutant overlapping initializers can treat an existing journal as newly created
        let (_dir, data) = data_dir()?;
        let parent = Dir::create_base(&data, &directory_rule())?;
        let first = lock_file(&parent, INITIALIZATION_LOCK_NAME)?;

        assert!(OperationJournal::open(&data).is_err());
        drop(first);
        assert!(OperationJournal::open(&data).is_ok());
        Ok(())
    }

    #[test]
    fn second_owner_is_refused_until_the_first_drops_and_history_survives() -> anyhow::Result<()> {
        let (_dir, data) = data_dir()?;
        let request = request("op", "pkg");
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request)?;
        journal.complete("authority", &request, Outcome::Succeeded)?;

        // oracle: mutant a second journal owner opens the same directory and overwrites the first owner's admissions
        assert!(OperationJournal::open(&data).is_err());
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-remote-operations
        assert_eq!(
            journal.admit("authority", &request)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
        drop(journal);

        let journal = OperationJournal::open(&data)?;
        assert_eq!(
            journal.admit("authority", &request)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
        Ok(())
    }

    // UNTESTED: on Unix the owner lock is an `flock` on `.lock`, which no test here runs; when changing it, check that a
    // second opener in the same process and in another process fails instead of waiting or sharing.

    #[test]
    fn malformed_index_fails_closed() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        drop(OperationJournal::open(&data)?);
        std::fs::write(journal_path(&data).join(INDEX_NAME), b"{}")?;

        assert!(OperationJournal::open(&data).is_err());
        Ok(())
    }

    #[test]
    fn malformed_record_fails_closed() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let request = request("op", "pkg");
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request)?;
        std::fs::write(record_path(&data, "op"), b"not json")?;

        assert!(journal.admit("authority", &request).is_err());
        assert!(journal.complete("authority", &request, Outcome::Succeeded).is_err());
        Ok(())
    }

    #[test]
    fn record_of_another_operation_fails_closed() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request("other", "pkg"))?;
        let copy = record_path(&data, "op");
        std::fs::copy(record_path(&data, "other"), &copy)?;
        let mut index: Index = serde_json::from_slice(&std::fs::read(journal_path(&data).join(INDEX_NAME))?)?;
        index.operations.insert(record_name("op"));
        drop(journal);
        std::fs::write(journal_path(&data).join(INDEX_NAME), serde_json::to_vec(&index)?)?;

        let journal = OperationJournal::open(&data)?;

        assert!(journal.admit("authority", &request("op", "pkg")).is_err());
        Ok(())
    }

    #[test]
    fn empty_ids_are_errors() -> anyhow::Result<()> {
        // oracle: mutant an empty operation or authority ID is admitted and shares one record
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;

        assert!(journal.may_contain(""));
        assert!(journal.admit("authority", &request("", "pkg")).is_err());
        assert!(journal.admit("", &request("op", "pkg")).is_err());
        Ok(())
    }

    #[test]
    fn concurrent_deliveries_admit_once() -> anyhow::Result<()> {
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-remote-operations
        let (_dir, data) = data_dir()?;
        let journal = Arc::new(OperationJournal::open(&data)?);
        let request = Arc::new(request("op", "pkg"));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (journal, request) = (Arc::clone(&journal), Arc::clone(&request));
                std::thread::spawn(move || journal.admit("authority", &request))
            })
            .collect();
        let mut admissions = Vec::new();
        for handle in handles {
            admissions.push(handle.join().expect("delivery thread panicked")?);
        }

        assert_eq!(admissions.iter().filter(|a| **a == Admission::Admitted).count(), 1);
        assert_eq!(admissions.iter().filter(|a| **a == Admission::InFlight).count(), 7);
        Ok(())
    }

    // UNTESTED: a journal directory or record that is owned by another account, grants another account access, is a
    // link, or is replaced by one must be refused and never repaired.
    // These checks belong to `private-fs`, which the journal relies on through `open_dir`, `Existing::Check` and
    // `open_file`, and no test here creates another account's objects or links; when changing how directories or
    // records are opened, never call a repair.
}
