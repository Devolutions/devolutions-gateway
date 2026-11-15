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
//!
//! A wholly missing journal is created, so operations recorded in a journal that was deleted whole may execute again.
//! A journal directory that exists but lacks its records directory or journal.json while holding other content is
//! corrupt, and opening it fails rather than creating a replacement.

use std::collections::{BTreeSet, HashSet};
use std::io::{Read as _, Write as _};

use agent_channel_proto::PackageOperationRequest;
use anyhow::{Context as _, bail, ensure};
use camino::Utf8Path;
use parking_lot::{Condvar, Mutex};
use private_fs::{Access, Account, Dir, Existing, Fallback, FileOptions, Replace, Rule, Share};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const DIRECTORY_NAME: &str = "package-operations";
const RECORDS_NAME: &str = "records";
const LOCK_FILE_NAME: &str = ".lock";
const INDEX_NAME: &str = "journal.json";
const VERSION: u32 = 1;
const MAX_RECORD_SIZE: u64 = 1024 * 1024;
const MAX_INDEX_SIZE: u64 = 64 * 1024 * 1024;

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

/// The journal of every authority of this Agent.
///
/// Hold one journal at a time: the directory handle can keep another open of it from sharing.
#[derive(Debug)]
pub(super) struct OperationJournal {
    /// The directory holding `journal.json` and the records.
    directory: Dir,
    state: Mutex<State>,
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

fn acquire_lock(data: &Dir, rule: &Rule) -> anyhow::Result<JournalLock> {
    let busy = "package operation journal is in use or unavailable";
    const EXCLUSIVE: Share = if cfg!(windows) { Share::Exclusive } else { Share::Shared };

    let dir = match data
        .open_dir(DIRECTORY_NAME, rule, EXCLUSIVE)
        .context(busy)
        .context("open package operation journal directory")?
    {
        Some(dir) => dir,
        None => {
            // The handle that creates the directory is not exclusive, so it is closed and the directory opened again
            // exclusively; the journal is read only after that, and a competing opener then fails the exclusive open or
            // the lock instead of reading.
            drop(
                data.create_dir(DIRECTORY_NAME, rule, Existing::Check)
                    .context("create package operation journal directory")?,
            );
            data.open_dir(DIRECTORY_NAME, rule, EXCLUSIVE)
                .context(busy)
                .context("open created package operation journal directory")?
                .context("package operation journal directory disappeared after its creation")?
        }
    };

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;

        let file = dir
            .open_or_create_file(LOCK_FILE_NAME, &file_rule(), FileOptions::new().read(true).write(true))
            .context("open package operation journal lock")?;
        // SAFETY: The file descriptor stays open until the lock is dropped.
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "{busy}: {}",
            std::io::Error::last_os_error()
        );
        Ok(JournalLock { dir, _file: file })
    }
    #[cfg(windows)]
    Ok(JournalLock { dir })
}

fn hashed(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn record_name(operation_id: &str) -> String {
    format!("{}.json", hashed(operation_id))
}

impl OperationJournal {
    /// Opens the journal, creating it when the data directory or the journal directory is missing.
    ///
    /// A journal deleted whole cannot be told from a first run, so operations recorded in it may execute again.
    /// A journal directory holding anything but its lock file, without its records directory or `journal.json`, is
    /// refused, as is one that is not private to the Agent's account.
    pub(super) fn open(data_dir: &Utf8Path) -> anyhow::Result<Self> {
        let rule = directory_rule();
        let data = Dir::create_base(data_dir, &rule).context("open data directory")?;
        let lock = acquire_lock(&data, &rule)?;
        let directory = match lock
            .dir
            .open_dir(RECORDS_NAME, &rule, Share::Shared)
            .context("open package operation records directory")?
        {
            Some(directory) => directory,
            None => {
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
            recorded: Condvar::new(),
        };
        let admitted = journal.load_index()?;
        journal.state.get_mut().admitted = admitted;
        Ok(journal)
    }

    fn load_index(&self) -> anyhow::Result<BTreeSet<String>> {
        let Some(file) = self
            .directory
            .open_file(INDEX_NAME, &file_rule(), FileOptions::new().read(true))
            .context("open package operation journal index")?
        else {
            ensure!(
                self.directory
                    .entries()
                    .context("list package operation journal directory")?
                    .is_empty(),
                "package operation journal has content but no index"
            );
            let admitted = BTreeSet::new();
            self.write_index(&admitted)
                .context("persist package operation journal index")?;
            return Ok(admitted);
        };

        let index: Index = serde_json::from_slice(&read_limited(file, MAX_INDEX_SIZE)?)
            .context("parse package operation journal index")?;
        ensure!(
            index.version == VERSION,
            "unsupported package operation journal version"
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

        let Some(record) = self.read(&state, &name, request)? else {
            let mut admitted = state.admitted.clone();
            admitted.insert(name.clone());
            self.write_index(&admitted)
                .context("persist package operation journal index")?;
            state.admitted = admitted;

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
            return Ok(Admission::Admitted);
        };

        if record.request != encoded {
            return Ok(Admission::PayloadMismatch);
        }
        let started = record.execution_started;
        Ok(match record.outcome {
            Some(outcome) => Admission::Recorded(Settled::new(outcome, started)),
            None if state.in_flight.contains(&name) => Admission::InFlight,
            None => Admission::Recorded(Settled::new(Outcome::Unknown, started)),
        })
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

    /// Reads and validates the record `name`, and returns `None` only when it neither exists nor is listed.
    fn read(&self, state: &State, name: &str, request: &PackageOperationRequest) -> anyhow::Result<Option<Record>> {
        let listed = state.admitted.contains(name);
        let Some(file) = self
            .directory
            .open_file(name, &file_rule(), FileOptions::new().read(true))
            .context("open package operation record")?
        else {
            ensure!(
                !listed,
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

    fn write_index(&self, admitted: &BTreeSet<String>) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(&Index {
            version: VERSION,
            operations: admitted.clone(),
        })
        .context("serialize package operation journal index")?;
        ensure!(
            bytes.len() as u64 <= MAX_INDEX_SIZE,
            "package operation journal index is too large"
        );
        self.write(INDEX_NAME, &bytes, Replace::Allow)
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
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use camino::Utf8PathBuf;

    use super::*;

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

    #[test]
    fn first_delivery_is_admitted_and_repeat_is_in_flight() -> anyhow::Result<()> {
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;
        let request = request("op", "pkg");

        assert_eq!(journal.admit("authority", &request)?, Admission::Admitted);
        assert_eq!(journal.admit("authority", &request)?, Admission::InFlight);
        Ok(())
    }

    #[test]
    fn repeat_after_completion_returns_recorded_outcome() -> anyhow::Result<()> {
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

        assert_eq!(
            journal.admit("authority", &request("op", "other"))?,
            Admission::PayloadMismatch
        );
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

        assert_eq!(
            journal.admit("authority", &request)?,
            Admission::Recorded(settled(Outcome::Succeeded))
        );
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
    fn interrupted_creation_is_completed() -> anyhow::Result<()> {
        let (_dir, data) = data_dir()?;
        drop(OperationJournal::open(&data)?);
        std::fs::remove_file(journal_path(&data).join(INDEX_NAME))?;

        assert_eq!(
            OperationJournal::open(&data)?.admit("authority", &request("op", "pkg"))?,
            Admission::Admitted
        );
        Ok(())
    }
    #[test]
    fn second_owner_is_refused_until_the_first_drops_and_history_survives() -> anyhow::Result<()> {
        let (_dir, data) = data_dir()?;
        let request = request("op", "pkg");
        let journal = OperationJournal::open(&data)?;
        journal.admit("authority", &request)?;
        journal.complete("authority", &request, Outcome::Succeeded)?;

        assert!(OperationJournal::open(&data).is_err());
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
        let (_dir, data) = data_dir()?;
        drop(OperationJournal::open(&data)?);
        std::fs::write(journal_path(&data).join(INDEX_NAME), b"{}")?;

        assert!(OperationJournal::open(&data).is_err());
        Ok(())
    }

    #[test]
    fn malformed_record_fails_closed() -> anyhow::Result<()> {
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
        let (_dir, data) = data_dir()?;
        let journal = OperationJournal::open(&data)?;

        assert!(journal.admit("authority", &request("", "pkg")).is_err());
        assert!(journal.admit("", &request("op", "pkg")).is_err());
        Ok(())
    }

    #[test]
    fn concurrent_deliveries_admit_once() -> anyhow::Result<()> {
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
