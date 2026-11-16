//! The persistent registry that maps a user's SID to the opaque UUID the Agent reports for that user.
//!
//! The registry lives in a directory only SYSTEM, and the account running the Agent, can access.
//! A UUID, once issued, stays with its user for as long as the store exists, so it is never reissued to another user.
//! A store that is absent when the registry opens gets a new random epoch, and its previous UUIDs are unknown to it.
//! A store that exists but cannot be read, or is malformed, fails the open instead of counting as absent.
//!
//! Restoring an older copy of a store keeps its epoch, so the epoch does not reveal a rollback.
//!
//! Methods perform blocking file I/O; async callers use `spawn_blocking`.
//! Nothing here logs or puts a SID or a UUID in an error, because both identify a user.

use std::fmt;
use std::fs::File;
use std::io::{Read as _, Write as _};

use anyhow::{Context as _, bail, ensure};
use camino::Utf8Path;
use parking_lot::Mutex;
use private_fs::{Access, Account, Dir, FileOptions, Replace, Rule};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

const STORE_NAME: &str = "users.json";
const TEMP_NAME: &str = "users.json.tmp";
const LOCK_NAME: &str = ".users.lock";
const FORMAT_VERSION: u32 = 1;
/// A store of a few thousand users is well under this, so a larger file is not one the registry wrote.
const MAX_STORE_BYTES: u64 = 4 * 1024 * 1024;
/// A SID with the maximum of 15 sub-authorities is far shorter.
const MAX_SID_LEN: usize = 184;

/// A user's SID in its canonical string form, such as `S-1-5-21-1-2-3-1001`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct UserSid(String);

impl UserSid {
    pub(crate) fn parse(sid: &str) -> anyhow::Result<Self> {
        let canonical = sid.to_ascii_uppercase();
        let valid = canonical.len() <= MAX_SID_LEN
            && canonical.strip_prefix("S-1-").is_some_and(|rest| {
                rest.split('-')
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
            });
        ensure!(valid, "not a SID");
        Ok(Self(canonical))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for UserSid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserSid(..)")
    }
}

/// The opaque UUID the Agent reports for a user.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct UserId(Uuid);

impl UserId {
    pub(crate) fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub(crate) fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserId(..)")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    version: u32,
    epoch: Uuid,
    users: Vec<StoreUser>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreUser {
    sid: String,
    id: Uuid,
}

struct State {
    epoch: Uuid,
    users: Vec<(UserSid, UserId)>,
}

impl State {
    fn new() -> Self {
        Self {
            epoch: Uuid::new_v4(),
            users: Vec::new(),
        }
    }

    fn id_of(&self, sid: &UserSid) -> Option<UserId> {
        self.users.iter().find(|(known, _)| known == sid).map(|(_, id)| *id)
    }

    fn to_file(&self) -> StoreFile {
        StoreFile {
            version: FORMAT_VERSION,
            epoch: self.epoch,
            users: self
                .users
                .iter()
                .map(|(sid, id)| StoreUser {
                    sid: sid.as_str().to_owned(),
                    id: id.as_uuid(),
                })
                .collect(),
        }
    }

    fn from_file(file: StoreFile) -> anyhow::Result<Self> {
        ensure!(file.version == FORMAT_VERSION, "unsupported registry version");
        ensure!(is_random_uuid(&file.epoch), "registry epoch is not a random UUID");
        let mut users: Vec<(UserSid, UserId)> = Vec::with_capacity(file.users.len());
        for user in file.users {
            let sid = UserSid::parse(&user.sid).context("registry holds an invalid SID")?;
            ensure!(sid.as_str() == user.sid, "registry holds a non-canonical SID");
            ensure!(is_random_uuid(&user.id), "registry holds a UUID that is not random");
            ensure!(
                user.id != file.epoch && users.iter().all(|(known, id)| *known != sid && id.as_uuid() != user.id),
                "registry holds a duplicate entry"
            );
            users.push((sid, UserId(user.id)));
        }
        Ok(Self {
            epoch: file.epoch,
            users,
        })
    }
}

fn is_random_uuid(uuid: &Uuid) -> bool {
    uuid.get_version_num() == 4 && uuid.get_variant() == uuid::Variant::RFC4122
}

/// The rule of the registry directory and its files: SYSTEM owns them, and only SYSTEM can access them, whichever
/// account runs the Agent.
///
/// An account other than SYSTEM cannot create what this rule describes, so the registry fails to open there.
// UNTESTED: only SYSTEM can read or write the registry on Windows. Tests run as an ordinary user with a test rule.
// Check, as SYSTEM, that the directory, the store and the lock file are owned by SYSTEM with a protected DACL that
// grants only SYSTEM, and that an ordinary user and an administrator's token without SYSTEM cannot open them.
#[cfg(windows)]
fn system_rule() -> Rule {
    Rule::new().owner(Account::System).grant(Account::System, Access::Full)
}

/// A user registry backed by a private directory, which one process at a time holds open.
pub(crate) struct UserRegistry {
    dir: Dir,
    rule: Rule,
    state: Mutex<State>,
    _lock: File,
}

impl UserRegistry {
    /// Opens the registry in `dir`, creating `dir` and a new store when neither exists.
    ///
    /// Fails when another registry holds `dir`, when `dir` or an existing store is not private to SYSTEM, when the
    /// caller cannot create what only SYSTEM may own, and when an existing store cannot be read or is malformed.
    #[cfg(windows)]
    pub(crate) fn open(dir: &Utf8Path) -> anyhow::Result<Self> {
        Self::open_with_rule(dir, system_rule())
    }

    fn open_with_rule(dir: &Utf8Path, rule: Rule) -> anyhow::Result<Self> {
        // An empty path would name the current directory.
        ensure!(!dir.as_str().is_empty(), "registry directory is empty");
        let dir = Dir::create_base(dir, &rule).context("create registry directory")?;
        dir.check(&rule).context("check registry directory")?;
        let lock = lock_directory(&dir, &rule)?;
        // The lock is held, so a temporary left in place was never installed.
        dir.remove_file(TEMP_NAME)
            .context("remove abandoned temporary registry file")?;
        let state = match read_state(&dir, &rule)? {
            Some(state) => state,
            None => {
                let state = State::new();
                write_state(&dir, &rule, &state, Replace::Refuse)?;
                state
            }
        };
        Ok(Self {
            dir,
            rule,
            state: Mutex::new(state),
            _lock: lock,
        })
    }

    /// Returns the epoch of the store this registry was opened on.
    pub(crate) fn epoch(&self) -> Uuid {
        self.state.lock().epoch
    }

    /// Returns the user's UUID, issuing and durably storing a new one first when the user has none.
    pub(crate) fn get_or_create(&self, sid: &UserSid) -> anyhow::Result<UserId> {
        let mut state = self.state.lock();
        if let Some(id) = state.id_of(sid) {
            return Ok(id);
        }
        let id = loop {
            let candidate = Uuid::new_v4();
            if candidate != state.epoch && state.users.iter().all(|(_, id)| id.as_uuid() != candidate) {
                break UserId(candidate);
            }
        };
        let mut next = State {
            epoch: state.epoch,
            users: state.users.clone(),
        };
        next.users.push((sid.clone(), id));
        // After a failure the store may or may not hold the new entry.
        // Nothing reported it, and the next call replaces it, so the registry keeps its previous state.
        write_state(&self.dir, &self.rule, &next, Replace::Allow)?;
        *state = next;
        Ok(id)
    }

    /// Returns the SID of the user `id` was issued to, or `None` when this store never issued `id`.
    pub(crate) fn resolve(&self, id: UserId) -> Option<UserSid> {
        let state = self.state.lock();
        state
            .users
            .iter()
            .find(|(_, known)| *known == id)
            .map(|(sid, _)| sid.clone())
    }
}

/// Reads the store, or returns `None` when it does not exist.
fn read_state(dir: &Dir, rule: &Rule) -> anyhow::Result<Option<State>> {
    let Some(file) = dir
        .open_file(STORE_NAME, rule, FileOptions::new().read(true))
        .context("open registry file")?
    else {
        return Ok(None);
    };
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_STORE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read registry file")?;
    ensure!(
        u64::try_from(bytes.len())? <= MAX_STORE_BYTES,
        "registry file is larger than {MAX_STORE_BYTES} bytes"
    );
    // The parse error would quote content of the file.
    let Ok(file) = serde_json::from_slice::<StoreFile>(&bytes) else {
        bail!("registry file is malformed");
    };
    State::from_file(file).map(Some)
}

/// Writes `state` to a temporary file and installs it under the store's name, durably.
fn write_state(dir: &Dir, rule: &Rule, state: &State, replace: Replace) -> anyhow::Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(&state.to_file()).context("encode registry")?);
    ensure!(
        u64::try_from(bytes.len())? <= MAX_STORE_BYTES,
        "registry file is larger than {MAX_STORE_BYTES} bytes"
    );
    let file = dir
        .create_file(TEMP_NAME, rule, FileOptions::new())
        .context("create temporary registry file")?;
    let installed = (&file).write_all(&bytes).context("write registry file").and_then(|()| {
        dir.persist(&file, TEMP_NAME, STORE_NAME, replace)
            .context("install registry file")
    });
    if let Err(error) = installed {
        let _ = dir.discard(&file, TEMP_NAME);
        return Err(error);
    }
    Ok(())
}

/// Opens the lock file with no sharing, so the lock lasts as long as the handle.
#[cfg(windows)]
fn lock_directory(dir: &Dir, rule: &Rule) -> anyhow::Result<File> {
    use private_fs::Share;

    dir.open_or_create_file(
        LOCK_NAME,
        rule,
        FileOptions::new().read(true).write(true).share(Share::Exclusive),
    )
    .context("lock registry directory; another registry may hold it")
}

#[cfg(unix)]
fn lock_directory(dir: &Dir, rule: &Rule) -> anyhow::Result<File> {
    use std::os::fd::AsRawFd as _;

    let file = dir
        .open_or_create_file(LOCK_NAME, rule, FileOptions::new().read(true).write(true))
        .context("open registry lock")?;
    // SAFETY: The file descriptor stays open until the lock guard is dropped.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error()).context("lock registry directory; another registry may hold it");
    }
    Ok(file)
}

#[cfg(test)]
impl UserRegistry {
    pub(super) fn open_for_test(dir: &Utf8Path) -> anyhow::Result<Self> {
        Self::open_with_rule(
            dir,
            Rule::new()
                .owner(Account::CurrentUser)
                .grant(Account::CurrentUser, Access::Full),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use camino::Utf8PathBuf;

    use super::*;

    const ALICE: &str = "S-1-5-21-1-2-3-1001";
    const BOB: &str = "S-1-5-21-1-2-3-1002";

    fn sid(value: &str) -> UserSid {
        UserSid::parse(value).expect("valid test SID")
    }

    /// A registry path inside a root removed with the guard.
    ///
    /// The registry creates the directory itself, since it checks an existing one against its rule.
    struct TestDir {
        root: Utf8PathBuf,
        dir: Utf8PathBuf,
    }

    impl std::ops::Deref for TestDir {
        type Target = Utf8PathBuf;

        fn deref(&self) -> &Utf8PathBuf {
            &self.dir
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// The system temporary directory can be writable by other accounts, which fails the check of the directories
    /// above the registry, so the root is under the user's local application data directory where there is one.
    fn registry_dir() -> TestDir {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = Utf8PathBuf::from_path_buf(base)
            .expect("UTF-8 base path")
            .join(format!("user-registry-test-{}", Uuid::new_v4().simple()));
        let dir = root.join("registry");
        TestDir { root, dir }
    }

    /// Opens the registry under a rule private to the current user, since only SYSTEM can create the production rule.
    fn open(dir: &Utf8Path) -> anyhow::Result<UserRegistry> {
        UserRegistry::open_for_test(dir)
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
    // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-discovery
    #[test]
    fn user_keeps_its_id_and_other_users_get_other_ids() {
        let dir = registry_dir();
        let registry = open(&dir).expect("open registry");

        let alice = registry.get_or_create(&sid(ALICE)).expect("alice");
        let bob = registry.get_or_create(&sid(BOB)).expect("bob");

        assert_eq!(registry.get_or_create(&sid(ALICE)).expect("alice again"), alice);
        assert_ne!(alice, bob);
        assert_eq!(registry.resolve(alice), Some(sid(ALICE)));
        assert_eq!(registry.resolve(bob), Some(sid(BOB)));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
    #[test]
    fn unknown_id_does_not_resolve() {
        let dir = registry_dir();
        let registry = open(&dir).expect("open registry");
        registry.get_or_create(&sid(ALICE)).expect("alice");

        assert_eq!(registry.resolve(UserId::from_uuid(Uuid::new_v4())), None);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
    #[test]
    fn restart_keeps_ids_and_epoch() {
        let dir = registry_dir();
        let first = open(&dir).expect("open registry");
        let alice = first.get_or_create(&sid(ALICE)).expect("alice");
        let epoch = first.epoch();
        drop(first);

        let second = open(&dir).expect("reopen registry");

        assert_eq!(second.epoch(), epoch);
        assert_eq!(second.get_or_create(&sid(ALICE)).expect("alice again"), alice);
        assert_eq!(second.resolve(alice), Some(sid(ALICE)));
    }

    // oracle: regression #2194
    #[test]
    fn full_registry_remains_readable_and_rejects_new_users() -> anyhow::Result<()> {
        const LIMIT: usize = 4 * 1024 * 1024;
        const MIN_SID_LEN: usize = 19;
        const MAX_SID_LEN: usize = 162;

        let dir = registry_dir();
        let registry = open(&dir)?;
        let epoch = registry.epoch();
        drop(registry);

        let row_overhead = format!(r#",{{"sid":"","id":"{}"}}"#, Uuid::nil()).len();
        let target = LIMIT - row_overhead - MAX_SID_LEN;
        let max_row = row_overhead + MAX_SID_LEN;
        let mut content = format!(r#"{{"version":1,"epoch":"{epoch}","users":["#);
        content.push_str(&entry(0, MAX_SID_LEN));
        let mut index = 1;
        while 2 * max_row < target - content.len() - 2 {
            content.push(',');
            content.push_str(&entry(index, MAX_SID_LEN));
            index += 1;
        }
        let remaining_sids = target - content.len() - 2 - 2 * row_overhead;
        let (first_len, second_len) = (MIN_SID_LEN..=MAX_SID_LEN)
            .filter(|length| *length != MIN_SID_LEN + 1)
            .find_map(|first| {
                let second = remaining_sids.checked_sub(first)?;
                ((MIN_SID_LEN..=MAX_SID_LEN).contains(&second) && second != MIN_SID_LEN + 1).then_some((first, second))
            })
            .expect("two valid SIDs fill the remaining bytes");
        content.push(',');
        content.push_str(&entry(index, first_len));
        content.push(',');
        content.push_str(&entry(index + 1, second_len));
        content.push_str("]}");
        assert_eq!(content.len(), target);
        fs::write(dir.join(STORE_NAME), content)?;

        let registry = open(&dir)?;
        let added_user = sid(&padded_sid(1_000_000, MAX_SID_LEN));
        let issued_id = registry.get_or_create(&added_user)?;
        let full_store = fs::read(dir.join(STORE_NAME))?;
        assert_eq!(full_store.len(), LIMIT);

        let error = registry
            .get_or_create(&sid(&padded_sid(2_000_000, MAX_SID_LEN)))
            .expect_err("a new user would exceed the limit");
        let message = format!("{error:#}");
        assert!(message.contains("registry") && message.contains(&LIMIT.to_string()));
        assert_eq!(fs::read(dir.join(STORE_NAME))?, full_store);
        assert!(!dir.join(TEMP_NAME).exists());

        fs::write(dir.join(TEMP_NAME), b"sentinel")?;
        let error = registry
            .get_or_create(&sid(&padded_sid(2_000_000, MAX_SID_LEN)))
            .expect_err("the oversized registry is rejected before creating a temporary file");
        let message = format!("{error:#}");
        assert!(message.contains("registry") && message.contains(&LIMIT.to_string()));
        assert_eq!(fs::read(dir.join(TEMP_NAME))?, b"sentinel");
        fs::remove_file(dir.join(TEMP_NAME))?;
        drop(registry);

        let reopened = open(&dir)?;
        assert_eq!(reopened.epoch(), epoch);
        assert_eq!(reopened.get_or_create(&added_user)?, issued_id);
        assert_eq!(reopened.resolve(issued_id), Some(added_user));
        return Ok(());

        fn entry(index: u32, length: usize) -> String {
            let sid = padded_sid(index, length);
            format!(r#"{{"sid":"{sid}","id":"{}"}}"#, Uuid::new_v4())
        }

        fn padded_sid(index: u32, length: usize) -> String {
            let mut sid = format!("S-1-5-21-{}", 1_000_000_000 + index);
            let mut remaining = length - sid.len();
            while remaining != 0 {
                let mut digits = (remaining - 1).min(10);
                if remaining == digits + 2 {
                    digits -= 1;
                }
                sid.push('-');
                sid.extend(std::iter::repeat_n('1', digits));
                remaining -= digits + 1;
            }
            sid
        }
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
    #[test]
    fn absent_store_gets_a_new_epoch_and_forgets_ids() {
        let dir = registry_dir();
        let first = open(&dir).expect("open registry");
        let alice = first.get_or_create(&sid(ALICE)).expect("alice");
        let epoch = first.epoch();
        drop(first);
        fs::remove_file(dir.join(STORE_NAME)).expect("remove store");

        let second = open(&dir).expect("reopen registry");

        assert_ne!(second.epoch(), epoch);
        assert_eq!(second.resolve(alice), None);
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-discovery
    // The case list is mutant: a corrupt store treated as empty would reissue UUIDs, but no source lists which
    // malformed contents count as corrupt.
    // oracle: mutant a corrupt or unreadable store is silently replaced by an empty one
    #[test]
    fn unreadable_store_fails_open_and_is_left_alone() {
        let epoch = Uuid::new_v4();
        let duplicate = Uuid::new_v4();
        let cases = [
            "".to_owned(),
            "not json".to_owned(),
            r#"{"version":2,"epoch":"4a7f0c6e-0b1e-4c63-8a53-3f1d6f0f5e11","users":[]}"#.to_owned(),
            r#"{"version":1,"epoch":"4a7f0c6e-0b1e-4c63-8a53-3f1d6f0f5e11","users":[],"extra":1}"#.to_owned(),
            format!(r#"{{"version":1,"epoch":"{epoch}","users":[{{"sid":"{ALICE}","id":"{epoch}"}}]}}"#),
            format!(
                r#"{{"version":1,"epoch":"{epoch}","users":[{{"sid":"{ALICE}","id":"{duplicate}"}},{{"sid":"{BOB}","id":"{duplicate}"}}]}}"#
            ),
            format!(r#"{{"version":1,"epoch":"{epoch}","users":[{{"sid":"not-a-sid","id":"{duplicate}"}}]}}"#),
        ];

        for content in cases {
            let dir = registry_dir();
            drop(open(&dir).expect("open registry"));
            fs::write(dir.join(STORE_NAME), &content).expect("corrupt store");

            assert!(open(&dir).is_err(), "accepted {content:?}");
            assert_eq!(fs::read_to_string(dir.join(STORE_NAME)).expect("read store"), content);
        }
    }

    // oracle: mutant an error message quotes a SID from the store
    #[test]
    fn errors_do_not_quote_the_store() {
        let dir = registry_dir();
        drop(open(&dir).expect("open registry"));
        fs::write(dir.join(STORE_NAME), format!("{{\"sid\":\"{ALICE}\"")).expect("corrupt store");

        let Err(error) = open(&dir) else {
            panic!("opened a corrupt store");
        };

        assert!(!format!("{error:#}").contains(ALICE));
    }

    // oracle: mutant two registries on one directory issue different UUIDs for one user
    #[test]
    fn second_open_of_a_held_directory_fails() {
        let dir = registry_dir();
        let _held = open(&dir).expect("open registry");

        assert!(open(&dir).is_err());
    }

    // oracle: mutant a crash between writing and installing leaves a temporary that blocks or leaks into the store
    #[test]
    fn abandoned_temporary_is_removed_and_a_write_leaves_none() {
        let dir = registry_dir();
        drop(open(&dir).expect("open registry"));
        fs::write(dir.join(TEMP_NAME), "abandoned").expect("write temporary");

        let registry = open(&dir).expect("reopen registry");
        assert!(!dir.join(TEMP_NAME).exists());
        registry.get_or_create(&sid(ALICE)).expect("alice");

        assert!(!dir.join(TEMP_NAME).exists());
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-discovery
    #[test]
    fn concurrent_get_or_create_issues_one_id_per_user() {
        let dir = registry_dir();
        let registry = open(&dir).expect("open registry");
        let alice = sid(ALICE);

        let ids: Vec<UserId> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| registry.get_or_create(&alice).expect("alice")))
                .collect();
            workers.into_iter().map(|worker| worker.join().expect("join")).collect()
        });

        assert!(ids.iter().all(|id| *id == ids[0]));
        let on_disk: StoreFile =
            serde_json::from_slice(&fs::read(dir.join(STORE_NAME)).expect("read store")).expect("parse store");
        assert_eq!(on_disk.users.len(), 1);
    }

    // oracle: spec MS-DTYP §2.4.2.1
    #[test]
    fn sid_syntax_is_validated() {
        for invalid in ["", "S-1-", "S-1-5-x", "S-2-5-18", "S-1-5--18", "alice"] {
            assert!(UserSid::parse(invalid).is_err(), "accepted {invalid:?}");
        }
    }
}
