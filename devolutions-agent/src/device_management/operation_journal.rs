//! Durable record of package operations, keyed by authority operation ID.
//!
//! While its operation ID remains in a trusted journal, an operation is never executed twice, whichever authority delivers it.
//! Delivering the same ID and request again, whether after a restart or a re-enrollment, returns the recorded outcome.
//! Only the admitting authority can update that outcome.
//!
//! A pending record is durable before the caller may submit an operation.
//! A pending record found without a live submission in this journal means the outcome cannot be recovered, so it reads
//! as [`Outcome::Unknown`] and the operation is never submitted again.
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
//! The index is what keeps an operation from running twice; a record only holds its details and status.
//! A listed record that is missing or unreadable is an error for that operation alone, which reads as unknown, because
//! its index entry still prevents it from running again.
//! A record the index does not list, or an index or records directory that is missing, changed, corrupt or could not be
//! written, shows the index unreliable, and the journal refuses new operations until it is opened again and found
//! consistent.
//! Intact records still return their recorded outcomes during refusal, and pending records return [`Outcome::Unknown`].
//! The list is rewritten whole at each admission and is limited to [`MAX_INDEX_SIZE`] bytes, beyond which admission
//! fails closed.
//! The membership snapshot includes unlisted record names and is bounded by the same serialized size.
//! The journal refuses to open or admit another ID if the snapshot cannot fit.
//!
//! A wholly missing journal is created, so operations recorded in a journal that was deleted whole may execute again.
//! An existing journal that lacks its records directory or journal.json refuses new operations.

use std::collections::{BTreeSet, HashSet};
use std::ffi::OsStr;
use std::io::{Read as _, Write as _};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};

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
    /// [`OperationJournal::wait`] returns its outcome once recorded, or unknown if the journal becomes unavailable.
    InFlight,
    /// The operation was admitted before and ended with this outcome; submit nothing.
    ///
    /// A pending record found after a restart or during refusal returns [`Outcome::Unknown`] and keeps any start evidence.
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
    /// Once the index is shown unreliable, only reopening a consistent journal can allow admissions again.
    unavailable: bool,
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
    /// Publishes refusal without making channel dispatch wait for the journal I/O lock.
    unavailable: AtomicBool,
    // UNTESTED: Only the Agent writes the journal while it is open; the snapshot cannot see out-of-band writes.
    // When changing ownership, account for those writes before treating absence as proof.
    // Out-of-band records still present are discovered at the next open.
    membership: ArcSwap<Membership>,
    #[cfg(test)]
    index_write_hook: Mutex<Option<tests::IndexWriteHook>>,
    // Tests lower this limit to exercise its boundary with small files.
    index_size_limit: u64,
    recorded: Condvar,
    #[cfg(test)]
    failed_start_writes: AtomicUsize,
    #[cfg(test)]
    failed_completion_writes: AtomicUsize,
    #[cfg(test)]
    failed_completion_writes_after_install: AtomicUsize,
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

    #[cfg(windows)]
    pub(super) fn is_unavailable(&self) -> bool {
        self.unavailable.load(Ordering::Acquire)
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
    pub(super) fn lookup(&self, authority_id: &str, delivery: &DeliveryKey) -> anyhow::Result<Option<Admission>> {
        let name = delivery.locate(authority_id)?;
        let mut state = self.state.lock();
        self.read_admission(&mut state, &name, delivery)
    }

    /// Opens the journal, creating it when the data directory or the journal directory is missing.
    ///
    /// A journal deleted whole cannot be told from a first run, so operations recorded in it may execute again.
    /// An existing journal missing its records directory cannot be opened.
    /// If its index is unreliable, it refuses new operations while allowing intact records to be read.
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
                unavailable: false,
            }),
            unavailable: AtomicBool::new(false),
            membership: ArcSwap::from_pointee(Membership::new(BTreeSet::new(), limit)?),
            #[cfg(test)]
            index_write_hook: Mutex::new(None),
            index_size_limit: limit,
            recorded: Condvar::new(),
            #[cfg(test)]
            failed_start_writes: AtomicUsize::new(0),
            #[cfg(test)]
            failed_completion_writes: AtomicUsize::new(0),
            #[cfg(test)]
            failed_completion_writes_after_install: AtomicUsize::new(0),
        };
        match journal.load_index(was_missing) {
            Ok(admitted) => {
                journal.state.get_mut().admitted = admitted;
                if let Err(error) = journal.validate_records() {
                    journal.make_unavailable(&mut journal.state.lock(), &error);
                }
            }
            Err(error) if !was_missing => journal.make_unavailable(&mut journal.state.lock(), &error),
            Err(error) => return Err(error),
        }
        let mut membership = Membership::new(journal.state.get_mut().admitted.clone(), limit)?;
        for entry in journal.directory.entries().context("list package operation records")? {
            if let Some(name) = normalized_record_name(&entry.name)? {
                membership.insert(name, limit)?;
            }
        }
        journal.membership.store(Arc::new(membership));
        Ok(journal)
    }

    /// Fails when a record has no index entry, which shows that the index no longer lists every admitted operation.
    ///
    /// A listed record that is missing or unreadable is not checked here: its index entry still prevents it from
    /// running again, and a crash between the index and record writes leaves exactly that state.
    fn validate_records(&self) -> anyhow::Result<()> {
        let state = self.state.lock();
        for entry in self.directory.entries().context("list package operation records")? {
            let name = entry
                .name
                .to_str()
                .context("package operation record name is not UTF-8")?;
            ensure!(
                name == INDEX_NAME
                    || state.admitted.contains(name)
                    || (name.starts_with('.') && name.ends_with(".tmp")),
                "package operation record is not in the journal index, so the journal cannot vouch for it"
            );
        }
        Ok(())
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

        read_index(file)
    }

    fn check_live_index(&self, state: &State) -> anyhow::Result<()> {
        let directory = self
            ._lock
            .dir
            .open_dir(RECORDS_NAME, &directory_rule(), Share::Shared)
            .context("open package operation records directory")?
            .context("package operation records directory is missing")?;
        let current = directory
            .open_file(INDEX_NAME, &file_rule(), FileOptions::new().read(true))
            .context("open current package operation journal index")?
            .context("package operation journal index is missing")?;
        let retained = self
            .directory
            .open_file(INDEX_NAME, &file_rule(), FileOptions::new().read(true))
            .context("open retained package operation journal index")?
            .context("package operation journal index is missing")?;
        ensure!(
            file_identity(&current)? == file_identity(&retained)?,
            "package operation records directory or index changed while open"
        );
        ensure!(
            read_index(retained)? == state.admitted,
            "package operation journal index changed while open"
        );
        Ok(())
    }

    /// Decides whether this delivery of `request` for `authority_id` may submit its operation, persisting a pending
    /// record first when it may.
    ///
    /// While the journal is available, exactly one of any number of concurrent deliveries of a new ID is admitted.
    pub(super) fn admit(&self, authority_id: &str, request: &PackageOperationRequest) -> anyhow::Result<Admission> {
        let (name, encoded) = locate(authority_id, request)?;
        let mut state = self.state.lock();

        let delivery = DeliveryKey::from_encoded(&request.operation_id, &encoded);
        if let Some(admission) = self.read_admission(&mut state, &name, &delivery)? {
            return Ok(admission);
        }
        ensure!(
            !state.unavailable,
            "package operation journal requires recovery and Agent restart"
        );

        let mut admitted = state.admitted.clone();
        admitted.insert(name.clone());
        let mut membership = self.membership.load_full().as_ref().clone();
        membership.insert(name.clone(), self.index_size_limit)?;
        let bytes = index_bytes(&admitted, self.index_size_limit)?;
        self.membership.store(Arc::new(membership));
        state.admitted = admitted;
        // UNTESTED: A privileged writer can remove the index or replace the records directory after validation.
        // The write can then recreate the index or use a disconnected directory; check this window when changing it.
        let written = self
            .write_index(&bytes)
            .context("persist package operation journal index");
        self.refuse_on_error(&mut state, written)?;

        let record = Record {
            version: VERSION,
            authority_id: authority_id.to_owned(),
            operation_id: request.operation_id.clone(),
            request: encoded,
            outcome: None,
            execution_started: false,
        };
        // A failed record write leaves the name listed, so this operation reads as unknown and others continue.
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
        #[cfg(test)]
        if self
            .failed_start_writes
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |count| count.checked_sub(1))
            .is_ok()
        {
            bail!("injected start evidence write failure");
        }
        let (name, encoded) = locate(authority_id, request)?;
        let mut state = self.state.lock();

        let mut record = self
            .read(&mut state, &name, &request.operation_id)?
            .context("no package operation record to mark as started")?;
        ensure!(
            !state.unavailable || state.in_flight.contains(&name),
            "package operation journal requires recovery and Agent restart"
        );
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

    #[cfg(all(test, windows))]
    pub(super) fn fail_start_writes(&self, count: usize) {
        self.failed_start_writes.store(count, Ordering::SeqCst);
    }

    #[cfg(all(test, windows))]
    pub(super) fn fail_completion_writes(&self, count: usize) {
        self.failed_completion_writes.store(count, Ordering::SeqCst);
    }

    #[cfg(all(test, windows))]
    pub(super) fn fail_completion_writes_after_install(&self, count: usize) {
        self.failed_completion_writes_after_install
            .store(count, Ordering::SeqCst);
    }

    /// Durably records the end of an operation [`admitted`](Self::admit) for `request`, and wakes its waiters.
    ///
    /// While the journal is available, recording an already recorded outcome succeeds; a different outcome is an error.
    /// A failed outcome write ends the in-flight operation; waiters read the record as it exists.
    pub(super) fn complete(
        &self,
        authority_id: &str,
        request: &PackageOperationRequest,
        outcome: Outcome,
    ) -> anyhow::Result<()> {
        self.complete_with_started(authority_id, request, outcome, false)
    }

    /// Records an outcome together with any observed start evidence in the same durable write.
    pub(super) fn complete_with_started(
        &self,
        authority_id: &str,
        request: &PackageOperationRequest,
        outcome: Outcome,
        started: bool,
    ) -> anyhow::Result<()> {
        let (name, encoded) = locate(authority_id, request)?;
        let mut state = self.state.lock();

        let record = self.read(&mut state, &name, &request.operation_id);
        // An operation admitted before a refusal still records its outcome; the refusal stops only new admissions.
        if state.unavailable && !state.in_flight.contains(&name) {
            bail!("package operation journal requires recovery and Agent restart");
        }
        if let Ok(Some(record)) = &record {
            ensure!(
                record.authority_id == authority_id && record.request == encoded,
                "package operation record belongs to a different request"
            );
        }

        let completed = record.and_then(|record| {
            let mut record = record.context("no package operation record to complete")?;
            match &record.outcome {
                Some(recorded) if *recorded == outcome && (!started || record.execution_started) => Ok(()),
                Some(_) => bail!("package operation already has a different recorded outcome"),
                None => {
                    record.execution_started |= started;
                    record.outcome = Some(outcome);
                    self.write_outcome(&name, &record)
                }
            }
        });
        if state.in_flight.remove(&name) {
            self.recorded.notify_all();
        }
        completed
    }

    fn write_outcome(&self, name: &str, record: &Record) -> anyhow::Result<()> {
        #[cfg(test)]
        if self
            .failed_completion_writes
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |count| count.checked_sub(1))
            .is_ok()
        {
            bail!("injected completion write failure");
        }
        #[cfg(test)]
        if self
            .failed_completion_writes_after_install
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |count| count.checked_sub(1))
            .is_ok()
        {
            self.write_record(name, record, Replace::Allow)
                .context("persist package operation outcome")?;
            bail!("injected completion write failure after install");
        }
        self.write_record(name, record, Replace::Allow)
            .context("persist package operation outcome")
    }

    /// Blocks until the operation for `delivery` is no longer in flight or the journal becomes unavailable, then reads
    /// its outcome.
    ///
    /// Returns the recorded outcome, or [`Outcome::Unknown`] for a record without one, with the recorded start evidence.
    /// Call it off the async runtime.
    pub(super) fn wait(&self, authority_id: &str, delivery: &DeliveryKey) -> anyhow::Result<Settled> {
        let name = delivery.locate(authority_id)?;
        let mut state = self.state.lock();
        while !state.unavailable && state.in_flight.contains(&name) {
            self.recorded.wait(&mut state);
        }

        let record = self
            .read(&mut state, &name, &delivery.operation_id)?
            .context("no package operation record to wait for")?;
        ensure!(
            delivery.matches(&record.request),
            "package operation record belongs to a different request"
        );
        Ok(Settled::new(
            record.outcome.unwrap_or(Outcome::Unknown),
            record.execution_started,
        ))
    }

    fn read_admission(
        &self,
        state: &mut State,
        name: &str,
        delivery: &DeliveryKey,
    ) -> anyhow::Result<Option<Admission>> {
        let Some(record) = self.read(state, name, &delivery.operation_id)? else {
            return Ok(None);
        };
        if !delivery.matches(&record.request) {
            return Ok(Some(Admission::PayloadMismatch));
        }
        let started = record.execution_started;
        Ok(Some(match record.outcome {
            Some(outcome) => Admission::Recorded(Settled::new(outcome, started)),
            None if !state.unavailable && state.in_flight.contains(name) => Admission::InFlight,
            None => Admission::Recorded(Settled::new(Outcome::Unknown, started)),
        }))
    }

    /// Reads and validates `name`, and returns `None` only when the journal establishes that it is absent.
    ///
    /// A changed live index or a record that the index does not list latches refusal.
    /// A listed record that is missing or unreadable is an error for this operation alone.
    fn read(&self, state: &mut State, name: &str, operation_id: &str) -> anyhow::Result<Option<Record>> {
        if !state.unavailable
            && let Err(error) = self.check_live_index(state)
        {
            self.make_unavailable(state, &error);
        }
        let listed = state.admitted.contains(name);
        let Some(file) = self
            .directory
            .open_file(name, &file_rule(), FileOptions::new().read(true))
            .context("open package operation record")?
        else {
            ensure!(
                !listed,
                "package operation record is missing, so its outcome cannot be recovered"
            );
            ensure!(
                !state.unavailable && !self.membership.load().names.contains(name),
                "package operation journal requires recovery, so it cannot establish that a record is absent"
            );
            return Ok(None);
        };
        if !listed {
            let error =
                anyhow::anyhow!("package operation record is not in the journal index, so the index is unreliable");
            self.make_unavailable(state, &error);
        }
        let record = parse_record(file, name)?;
        ensure!(
            record.operation_id == operation_id,
            "package operation record belongs to another operation ID"
        );
        Ok(Some(record))
    }

    fn make_unavailable(&self, state: &mut State, error: &anyhow::Error) {
        if !state.unavailable {
            state.unavailable = true;
            self.unavailable.store(true, Ordering::Release);
            self.recorded.notify_all();
            error!(
                error = format!("{error:#}"),
                "Package operation journal is unrecoverable; package writes are unavailable"
            );
        }
    }

    fn refuse_on_error<T>(&self, state: &mut State, result: anyhow::Result<T>) -> anyhow::Result<T> {
        if let Err(error) = &result {
            self.make_unavailable(state, error);
        }
        result
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

fn read_index(file: std::fs::File) -> anyhow::Result<BTreeSet<String>> {
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

fn parse_record(file: std::fs::File, name: &str) -> anyhow::Result<Record> {
    let record: Record =
        serde_json::from_slice(&read_limited(file, MAX_RECORD_SIZE)?).context("parse package operation record")?;
    ensure!(
        record.version == VERSION,
        "unsupported package operation record version"
    );
    ensure!(
        !record.authority_id.is_empty(),
        "package operation record has an empty authority ID"
    );
    ensure!(
        !matches!(&record.outcome, Some(Outcome::Failed { error }) if error.is_empty()),
        "package operation failure has no error"
    );
    ensure!(
        record_name(&record.operation_id) == name,
        "package operation record name belongs to another operation ID"
    );
    let stored = hex::decode(&record.request).context("decode stored package operation request")?;
    let stored =
        PackageOperationRequest::decode(stored.as_slice()).context("parse stored package operation request")?;
    ensure!(
        stored.operation_id == record.operation_id,
        "stored package operation request has another operation ID"
    );
    Ok(record)
}

#[cfg(unix)]
fn file_identity(file: &std::fs::File) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn file_identity(file: &std::fs::File) -> anyhow::Result<(u64, [u8; 16])> {
    use std::os::windows::io::AsRawHandle as _;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx};

    let mut info = FILE_ID_INFO::default();
    let size = u32::try_from(size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO size fits in u32");
    // SAFETY: The file handle is open, and the output buffer has the required size.
    unsafe { GetFileInformationByHandleEx(HANDLE(file.as_raw_handle()), FileIdInfo, (&raw mut info).cast(), size) }
        .context("read package operation index file identity")?;
    Ok((info.VolumeSerialNumber, info.FileId.Identifier))
}

fn read_limited(file: std::fs::File, limit: u64) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .context("read package operation file")?;
    ensure!(bytes.len() as u64 <= limit, "package operation file is too large");
    Ok(bytes)
}

/// A delivery as lookups compare it: its operation ID and a SHA-256 digest of its channel encoding.
///
/// A delivery waiting for journal I/O keeps this instead of its request, so its size does not grow with the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DeliveryKey {
    operation_id: String,
    payload: [u8; 32],
}

impl DeliveryKey {
    pub(super) fn new(request: &PackageOperationRequest) -> Self {
        Self::from_encoded(&request.operation_id, &hex::encode(request.encode_to_vec()))
    }

    fn from_encoded(operation_id: &str, encoded: &str) -> Self {
        Self {
            operation_id: operation_id.to_owned(),
            payload: Sha256::digest(encoded.as_bytes()).into(),
        }
    }

    #[cfg(windows)]
    pub(super) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    fn matches(&self, encoded: &str) -> bool {
        <[u8; 32]>::from(Sha256::digest(encoded.as_bytes())) == self.payload
    }

    fn locate(&self, authority_id: &str) -> anyhow::Result<String> {
        ensure!(!authority_id.is_empty(), "authority ID is empty");
        ensure!(!self.operation_id.is_empty(), "operation ID is empty");
        Ok(record_name(&self.operation_id))
    }
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

    /// Leaves the membership index room for exactly `additional_names` more record names.
    #[cfg(windows)]
    pub(crate) fn limit_index_room_for_test(&mut self, additional_names: u64) {
        let entry_size = record_name("entry").len() as u64 + 3;
        self.index_size_limit = self.membership.load().index_size + additional_names * entry_size;
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
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-operation-journal
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
    fn membership_keeps_orphaned_records_while_new_admissions_are_refused() -> anyhow::Result<()> {
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
        assert_eq!(
            journal.lookup("authority", &DeliveryKey::new(&orphan))?,
            Some(Admission::Recorded(settled(Outcome::Unknown)))
        );
        assert_eq!(
            journal.admit("authority", &orphan)?,
            Admission::Recorded(settled(Outcome::Unknown))
        );
        assert!(journal.may_contain("recorded"));
        assert_eq!(
            journal.admit("authority", &recorded)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
        assert!(!journal.may_contain("new"));
        assert!(journal.admit("authority", &request("new", "pkg")).is_err());
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
        #[cfg(windows)]
        assert_eq!(
            journal.lookup("authority", &DeliveryKey::new(&orphan))?,
            Some(Admission::Recorded(settled(Outcome::Unknown)))
        );
        // Whether the differently cased record is found depends on the file system's case sensitivity.
        // Either way, the refused journal never proves it absent, so it is not dispatched again.
        #[cfg(not(windows))]
        assert!(!matches!(
            journal.lookup("authority", &DeliveryKey::new(&orphan)),
            Ok(None)
        ));
        assert!(journal.admit("authority", &request("new", "pkg")).is_err());
        assert!(journal.may_contain("orphan"));
        Ok(())
    }

    #[rstest::rstest]
    #[case::uppercase(record_name("recorded").to_ascii_uppercase())]
    #[case::malformed(format!("g{}", &record_name("recorded")[1..]))]
    #[case::invalid_length("not-a-record.json".to_owned())]
    fn noncanonical_index_entry_refuses_admission(#[case] indexed_name: String) -> anyhow::Result<()> {
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

        let journal = OperationJournal::open(&data)?;
        assert!(journal.admit("authority", &request("new", "pkg")).is_err());
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

        assert_eq!(journal.lookup("authority", &DeliveryKey::new(&request))?, None);
        assert_eq!(journal.admit("authority", &request)?, Admission::Admitted);
        assert_eq!(
            journal.lookup("another", &DeliveryKey::new(&request))?,
            Some(Admission::InFlight)
        );
        assert_eq!(
            journal.lookup("another", &DeliveryKey::new(&self::request("lookup", "other")))?,
            Some(Admission::PayloadMismatch)
        );
        journal.complete("authority", &request, Outcome::Succeeded)?;
        assert_eq!(
            journal.lookup("another", &DeliveryKey::new(&request))?,
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
        assert!(journal.lookup("authority", &DeliveryKey::new(&failed)).is_err());
        assert!(!record_path(&data, "failed").exists());
        assert!(journal.admit("authority", &request("other", "pkg")).is_err());
        drop(journal);

        let journal = OperationJournal::open(&data)?;
        assert!(journal.may_contain("failed"));
        assert!(journal.lookup("authority", &DeliveryKey::new(&failed)).is_err());
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

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-operation-journal
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
            reopened.lookup("authority", &DeliveryKey::new(&recorded))?,
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
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-operation-journal
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
            std::thread::spawn(move || journal.wait("authority", &DeliveryKey::new(&request)))
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
    fn journal_refusal_wakes_waiters_with_an_unknown_outcome() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = Arc::new(OperationJournal::open(&data)?);
        let pending = request("pending", "pkg");
        let new = request("new", "pkg");
        journal.admit("authority", &pending)?;

        let (sender, receiver) = mpsc::channel();
        let waiter = {
            let (journal, delivery) = (Arc::clone(&journal), DeliveryKey::new(&pending));
            std::thread::spawn(move || {
                let _ = sender.send(journal.wait("authority", &delivery));
            })
        };
        std::thread::sleep(Duration::from_millis(100));
        assert!(!waiter.is_finished());
        std::fs::remove_file(journal_path(&data).join(INDEX_NAME))?;
        assert!(journal.admit("authority", &new).is_err());

        let outcome = receiver.recv_timeout(Duration::from_secs(5));
        if outcome.is_err() {
            let _ = journal.complete("authority", &pending, Outcome::Unknown);
        }
        waiter.join().expect("waiter thread panicked");
        assert_eq!(outcome??, settled(Outcome::Unknown));
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
        // oracle: mutant a payload conflict incorrectly disables a healthy journal
        assert_eq!(
            journal.admit("authority", &request("another", "pkg"))?,
            Admission::Admitted
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
        assert_eq!(
            journal.wait("second", &DeliveryKey::new(&request))?,
            settled(Outcome::Succeeded)
        );
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
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-operation-journal
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
        assert_eq!(
            journal.wait("authority", &DeliveryKey::new(&request))?,
            settled(Outcome::Unknown)
        );
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

        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-operation-journal
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
        // oracle: mutant conflicting terminal completion incorrectly disables a healthy journal
        assert_eq!(
            journal.admit("authority", &self::request("another", "pkg"))?,
            Admission::Admitted
        );
        Ok(())
    }

    #[test]
    fn deleted_record_is_refused_alone_while_the_journal_is_open() -> anyhow::Result<()> {
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-operation-journal
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
        assert!(journal.wait("authority", &DeliveryKey::new(&finished)).is_err());
        assert!(journal.complete("authority", &pending, Outcome::Succeeded).is_err());
        assert!(!record_path(&data, "finished").exists());
        assert_eq!(
            journal.admit("authority", &request("other", "pkg"))?,
            Admission::Admitted
        );
        Ok(())
    }

    #[test]
    fn deleted_record_is_refused_alone_after_reopen() -> anyhow::Result<()> {
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-operation-journal
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
    fn unindexed_record_keeps_its_outcome_but_new_writes_are_refused() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let request = request("op", "pkg");
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request)?;
        journal.complete("authority", &request, Outcome::Succeeded)?;
        drop(journal);
        std::fs::write(
            journal_path(&data).join(INDEX_NAME),
            serde_json::to_vec(&Index {
                version: VERSION,
                operations: BTreeSet::new(),
            })?,
        )?;

        let journal = OperationJournal::open(&data)?;
        assert_eq!(
            journal.admit("authority", &request)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
        assert!(journal.admit("authority", &self::request("other", "pkg")).is_err());
        Ok(())
    }

    #[test]
    fn interrupted_admission_is_refused_alone_after_reopen() -> anyhow::Result<()> {
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-operation-journal
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
    fn leftover_temporary_file_does_not_disable_a_consistent_journal() -> anyhow::Result<()> {
        // oracle: mutant an interrupted temporary write is mistaken for an unindexed operation record
        let (_dir, data) = data_dir()?;
        drop(OperationJournal::open(&data)?);
        std::fs::write(journal_path(&data).join(".journal.json-stray.tmp"), b"partial")?;

        let journal = OperationJournal::open(&data)?;
        assert_eq!(
            journal.admit("authority", &request("other", "pkg"))?,
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
        assert_eq!(journal.wait("authority", &DeliveryKey::new(&started))?, expected);

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
        assert_eq!(
            journal.wait("authority", &DeliveryKey::new(&unproven))?,
            settled(Outcome::Unknown)
        );
        Ok(())
    }

    #[test]
    fn wholly_missing_journal_is_created_empty() -> anyhow::Result<()> {
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-operation-journal
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
        journal.complete("authority", &request, Outcome::Succeeded)?;
        drop(journal);

        let records = journal_path(&data);
        std::fs::remove_file(records.join(INDEX_NAME))?;
        let journal = OperationJournal::open(&data)?;
        assert_eq!(
            journal.admit("authority", &request)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
        assert!(journal.admit("authority", &self::request("other", "pkg")).is_err());
        drop(journal);

        std::fs::remove_dir_all(&records)?;
        std::fs::write(data.join(DIRECTORY_NAME).join("stray"), b"x")?;
        assert!(OperationJournal::open(&data).is_err());
        Ok(())
    }

    #[test]
    fn deleted_live_index_refuses_new_writes_without_recreating_it() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request("first", "pkg"))?;
        let index = journal_path(&data).join(INDEX_NAME);
        let saved = std::fs::read(&index)?;
        std::fs::remove_file(&index)?;

        assert!(journal.admit("authority", &request("second", "pkg")).is_err());
        assert!(!index.exists());
        let mut restored = journal
            .directory
            .create_file(INDEX_NAME, &file_rule(), FileOptions::new())?;
        restored.write_all(&saved)?;
        restored.sync_all()?;
        drop(restored);
        assert!(journal.admit("authority", &request("second", "pkg")).is_err());
        drop(journal);

        let journal = OperationJournal::open(&data)?;
        assert_eq!(
            journal.admit("authority", &request("second", "pkg"))?,
            Admission::Admitted
        );
        Ok(())
    }

    #[test]
    fn changed_live_index_refuses_new_writes_until_reopen() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let existing = request("existing", "pkg");
        journal.admit("authority", &existing)?;
        journal.complete("authority", &existing, Outcome::Succeeded)?;
        let index = journal_path(&data).join(INDEX_NAME);
        let saved = std::fs::read(&index)?;
        std::fs::write(
            &index,
            serde_json::to_vec(&Index {
                version: VERSION,
                operations: BTreeSet::new(),
            })?,
        )?;

        assert!(journal.admit("authority", &request("new", "pkg")).is_err());
        assert_eq!(
            journal.admit("authority", &existing)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
        std::fs::write(&index, saved)?;
        assert!(journal.admit("authority", &request("new", "pkg")).is_err());
        drop(journal);

        let journal = OperationJournal::open(&data)?;
        assert_eq!(journal.admit("authority", &request("new", "pkg"))?, Admission::Admitted);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removed_live_records_directory_refuses_new_writes() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let existing = request("existing", "pkg");
        journal.admit("authority", &existing)?;
        journal.complete("authority", &existing, Outcome::Succeeded)?;
        let records = journal_path(&data);
        std::fs::rename(&records, data.join(DIRECTORY_NAME).join("moved-records"))?;

        assert!(journal.admit("authority", &request("new", "pkg")).is_err());
        assert!(!records.exists());
        assert_eq!(
            journal.admit("authority", &existing)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn replaced_live_records_directory_refuses_new_writes() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let existing = request("existing", "pkg");
        journal.admit("authority", &existing)?;
        journal.complete("authority", &existing, Outcome::Succeeded)?;
        let records = journal_path(&data);
        let saved_index = std::fs::read(records.join(INDEX_NAME))?;
        std::fs::rename(&records, data.join(DIRECTORY_NAME).join("moved-records"))?;
        let replacement = journal
            ._lock
            .dir
            .create_dir(RECORDS_NAME, &directory_rule(), Existing::Check)?;
        let mut index = replacement.create_file(INDEX_NAME, &file_rule(), FileOptions::new())?;
        index.write_all(&saved_index)?;
        index.sync_all()?;
        drop(index);
        drop(replacement);

        assert!(journal.admit("authority", &request("new", "pkg")).is_err());
        assert_eq!(
            journal.admit("authority", &existing)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn failed_index_write_refuses_later_writes_after_access_is_restored() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let index = journal_path(&data).join(INDEX_NAME);
        let original = std::fs::metadata(&index)?.permissions();
        let mut read_only = original.clone();
        read_only.set_readonly(true);
        std::fs::set_permissions(&index, read_only)?;
        let first = journal.admit("authority", &request("first", "pkg"));
        std::fs::set_permissions(&index, original)?;

        assert!(first.is_err());
        assert!(journal.admit("authority", &request("second", "pkg")).is_err());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn failed_record_write_leaves_other_operations_writable() -> anyhow::Result<()> {
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-operation-journal
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let pending = request("pending", "pkg");
        journal.admit("authority", &pending)?;
        let path = record_path(&data, "pending");
        let original = std::fs::metadata(&path)?.permissions();
        let mut read_only = original.clone();
        read_only.set_readonly(true);
        std::fs::set_permissions(&path, read_only)?;
        let completed = journal.complete("authority", &pending, Outcome::Succeeded);
        std::fs::set_permissions(&path, original)?;

        assert!(completed.is_err());
        assert_eq!(
            journal.admit("authority", &pending)?,
            Admission::Recorded(settled(Outcome::Unknown))
        );
        assert_eq!(journal.admit("authority", &request("new", "pkg"))?, Admission::Admitted);
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

        let journal = OperationJournal::open(&data)?;
        assert!(journal.admit("authority", &request("new", "pkg")).is_err());
        Ok(())
    }

    #[test]
    fn interrupted_creation_fails_closed() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let (_dir, data) = data_dir()?;
        drop(OperationJournal::open(&data)?);
        std::fs::remove_file(journal_path(&data).join(INDEX_NAME))?;

        let journal = OperationJournal::open(&data)?;
        assert!(journal.admit("authority", &request("new", "pkg")).is_err());
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
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-operation-journal
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
        let existing = request("existing", "pkg");
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &existing)?;
        journal.complete("authority", &existing, Outcome::Succeeded)?;
        drop(journal);
        std::fs::write(journal_path(&data).join(INDEX_NAME), b"{}")?;

        let journal = OperationJournal::open(&data)?;
        assert_eq!(
            journal.admit("authority", &existing)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
        assert!(journal.admit("authority", &request("new", "pkg")).is_err());
        Ok(())
    }

    #[test]
    fn malformed_record_is_refused_alone() -> anyhow::Result<()> {
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-operation-journal
        let (_dir, data) = data_dir()?;
        let request = request("op", "pkg");
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request)?;
        std::fs::write(record_path(&data, "op"), b"not json")?;

        assert!(journal.admit("authority", &request).is_err());
        assert!(journal.complete("authority", &request, Outcome::Succeeded).is_err());
        assert_eq!(
            journal.admit("authority", &self::request("new", "pkg"))?,
            Admission::Admitted
        );
        drop(journal);

        let journal = OperationJournal::open(&data)?;
        assert!(journal.admit("authority", &request).is_err());
        assert_eq!(
            journal.admit("authority", &self::request("newer", "pkg"))?,
            Admission::Admitted
        );
        Ok(())
    }

    #[test]
    fn record_with_empty_authority_is_corrupt() -> anyhow::Result<()> {
        // oracle: mutant a record that lost its authority ID is accepted as an intact recorded result
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let existing = request("existing", "pkg");
        journal.admit("authority", &existing)?;
        journal.complete("authority", &existing, Outcome::Succeeded)?;
        let path = record_path(&data, "existing");
        let mut record: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        record["authority_id"] = "".into();
        std::fs::write(&path, serde_json::to_vec(&record)?)?;

        assert!(journal.admit("authority", &existing).is_err());
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
        // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-operation-journal
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
