use std::fs::File;
use std::io::{Read as _, Write as _};
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use camino::Utf8Path;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::Generate as _;
use p256::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use private_fs::{Access, Account, Dir, EntryKind, FileOptions, Replace, Rule, Share};
use secure_memory::ProtectedBytes;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{DeviceKey, name_matches_prefix, validate_name};

const LOCK_NAME: &str = ".device-key.lock";
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(25);
/// A P-256 key file takes about 140 bytes, so a file past this bound is not a key the crate wrote.
const MAX_KEY_FILE_LEN: u64 = 64 * 1024;

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

/// The rule of the directories the crate creates for keys: the caller's account owns them, and only it and SYSTEM
/// (root on Linux and macOS) can access them.
fn key_dir_rule() -> Rule {
    Rule::new()
        .owner(Account::CurrentUser)
        .grant(Account::CurrentUser, Access::Full)
        .grant(Account::System, Access::Full)
}

/// The rule of key files and of the lock file: only the caller's account and SYSTEM (root on Linux and macOS) can own
/// or access them.
///
/// A check accepts a file that gives these accounts less access, since the access rule asks only that no other account
/// can access a key.
fn key_file_rule() -> Rule {
    Rule::new()
        .owner(Account::CurrentUser)
        .owner(Account::System)
        .grant(Account::CurrentUser, Access::Full)
        .grant(Account::System, Access::Full)
}

const KEY_FILE_SUFFIX: &str = ".p8";

fn key_file_name(name: &str) -> String {
    format!("{name}{KEY_FILE_SUFFIX}")
}

#[cfg(windows)]
fn tombstone_name(name: &str) -> String {
    format!(".{name}-{}.deleted", Uuid::new_v4())
}

pub(super) fn generate(dir: &Utf8Path, name: &str) -> anyhow::Result<Box<dyn DeviceKey>> {
    // An empty path would name the current directory.
    ensure!(!dir.as_str().is_empty(), "key directory is empty");
    let dir = Dir::create_base(dir, &key_dir_rule()).context("create key directory")?;
    let _lock = lock_and_reconcile(&dir)?;
    let key = SigningKey::generate_from_rng(&mut rand::rng());
    let pkcs8 = key.to_pkcs8_der().context("encode device key")?;
    let public_key = *key.verifying_key();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&key.to_bytes());
    let scalar = ProtectedBytes::new(&mut bytes);
    drop(key);
    let temporary = format!(".{name}-{}.tmp", Uuid::new_v4());
    let file = dir
        .create_file(&temporary, &key_file_rule(), FileOptions::new())
        .context("create key file")?;
    let written = (&file).write_all(pkcs8.as_bytes()).context("write key file");
    drop(pkcs8);
    let installed = written.and_then(|()| {
        dir.persist(&file, &temporary, &key_file_name(name), Replace::Refuse)
            .context("install key file")
    });
    if let Err(error) = installed {
        // A temporary left behind is removed by the next operation on the key directory.
        let _ = dir.discard(&file, &temporary);
        return Err(error);
    }
    Ok(Box::new(FileKey {
        name: name.to_owned(),
        scalar,
        public_key,
    }))
}

pub(super) fn open(dir: &Utf8Path, name: &str) -> anyhow::Result<Option<Box<dyn DeviceKey>>> {
    let Some(dir) = open_key_directory(dir)? else {
        return Ok(None);
    };
    let _lock = lock_and_reconcile(&dir)?;
    let Some(file) = dir
        .open_file(&key_file_name(name), &key_file_rule(), FileOptions::new().read(true))
        .context("open key file")?
    else {
        return Ok(None);
    };
    // UNTESTED: reading stops one byte past the bound, into a buffer that never reallocates.
    // An unbounded read lets a large file exhaust memory.
    // A reallocation leaves an unzeroized copy of the key in freed memory.
    // When changing this read, keep the `take` limit and a capacity that holds all it can read.
    let mut pkcs8 = Zeroizing::new(Vec::with_capacity(usize::try_from(MAX_KEY_FILE_LEN + 1)?));
    file.take(MAX_KEY_FILE_LEN + 1)
        .read_to_end(&mut pkcs8)
        .context("read key file")?;
    ensure!(
        u64::try_from(pkcs8.len())? <= MAX_KEY_FILE_LEN,
        "key file is larger than {MAX_KEY_FILE_LEN} bytes"
    );
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
    let Some(dir) = open_key_directory(dir)? else {
        return Ok(());
    };
    let _lock = lock_and_reconcile(&dir)?;
    let file_name = key_file_name(name);
    if !listed_with_exact_name(&dir, &file_name)? {
        return Ok(());
    }
    let file_name = retire(&dir, &file_name, name).context("retire key file")?;
    dir.remove_file(&file_name).context("delete key file")?;
    Ok(())
}

pub(super) fn list(dir: &Utf8Path, prefix: &str) -> anyhow::Result<Vec<String>> {
    let Some(dir) = open_key_directory(dir)? else {
        return Ok(Vec::new());
    };
    // `crates/device-key/INTENT.md` ("Operations"): listing skips an unexpected entry, a lock file that fails its rule
    // included.
    // Listing needs the lock only to remove leftovers first, and their names never end in `.p8`, so without the lock it
    // lists the same keys and leaves the leftovers to a later operation.
    let _lock = match lock_directory(&dir) {
        Ok(lock) => {
            cleanup_abandoned(&dir)?;
            Some(lock)
        }
        Err(error)
            if error
                .chain()
                .filter_map(|cause| cause.downcast_ref::<private_fs::Error>())
                .any(private_fs::Error::is_refused) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    let mut names = dir
        .entries()
        .context("list key directory")?
        .into_iter()
        .filter(|entry| entry.kind == EntryKind::File)
        .filter_map(|entry| {
            let name = entry.name.to_str()?.strip_suffix(KEY_FILE_SUFFIX)?;
            name_matches_prefix(name, prefix).then(|| name.to_owned())
        })
        .collect::<Vec<_>>();
    names.sort_unstable();
    Ok(names)
}

/// Opens the key directory, or returns `None` when it doesn't exist.
fn open_key_directory(dir: &Utf8Path) -> anyhow::Result<Option<Dir>> {
    // An empty path would name the current directory, which holds no keys.
    if dir.as_str().is_empty() {
        return Ok(None);
    }
    Dir::open_base(dir, &key_dir_rule()).context("open key directory")
}

fn lock_and_reconcile(dir: &Dir) -> anyhow::Result<File> {
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

fn cleanup_abandoned(dir: &Dir) -> anyhow::Result<()> {
    // A creator holds this lock until it removes its temporary, so every remaining temporary is abandoned.
    for entry in dir.entries().context("inspect abandoned key files")? {
        // The crate creates only regular files, and anything else at one of its names is not its own.
        if entry.kind != EntryKind::File {
            continue;
        }
        let Some(file_name) = entry.name.to_str() else {
            continue;
        };
        let Some(name) = abandoned_name(file_name) else {
            continue;
        };
        // `crates/device-key/INTENT.md` ("Operations"): a leftover that can't be removed, as while another process
        // holds it open, is an unexpected entry, which an operation skips; a later operation removes it.
        // UNTESTED: on Linux and macOS, a leftover that can't be removed is skipped too.
        // Only root can make an entry of the caller's own key directory unremovable, for example with an immutable
        // attribute; when changing this, keep a failed removal from failing the operation on every platform.
        let file_name = if file_name.ends_with(".tmp") {
            match retire(dir, file_name, name) {
                Ok(file_name) => file_name,
                Err(_) => continue,
            }
        } else {
            file_name.to_owned()
        };
        let _ = dir.remove_file(&file_name);
    }
    Ok(())
}

/// Renames `file_name`, a file of the key `name`, to a tombstone on Windows, and returns the name to remove.
///
/// Where Windows can't remove a file with POSIX semantics, such as on FAT or before Windows 10 1709, a removed file keeps
/// its name until every handle on it is closed, so it is renamed first to free its name at once.
#[cfg(windows)]
fn retire(dir: &Dir, file_name: &str, name: &str) -> anyhow::Result<String> {
    let tombstone = tombstone_name(name);
    dir.rename(file_name, &tombstone, Replace::Refuse)?;
    Ok(tombstone)
}

#[cfg(not(windows))]
fn retire(_: &Dir, file_name: &str, _: &str) -> anyhow::Result<String> {
    Ok(file_name.to_owned())
}

fn lock_options() -> FileOptions {
    FileOptions::new().read(true).write(true).share(Share::Exclusive)
}

#[cfg(unix)]
fn lock_directory(dir: &Dir) -> anyhow::Result<File> {
    use std::io::ErrorKind;
    use std::os::fd::AsRawFd as _;

    let file = dir
        .open_or_create_file(LOCK_NAME, &key_file_rule(), lock_options())
        .context("open key-directory lock")?;
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

/// Opens the lock file with no sharing, which holds the lock until the handle is closed.
#[cfg(windows)]
fn lock_directory(dir: &Dir) -> anyhow::Result<File> {
    use windows::Win32::Foundation::ERROR_SHARING_VIOLATION;

    let sharing_violation = i32::try_from(ERROR_SHARING_VIOLATION.0)?;
    let deadline = Instant::now() + LOCK_TIMEOUT;
    loop {
        match dir.open_or_create_file(LOCK_NAME, &key_file_rule(), lock_options()) {
            Ok(file) => return Ok(file),
            Err(error)
                if matches!(
                    error.kind(),
                    private_fs::ErrorKind::Io { source, .. } if source.raw_os_error() == Some(sharing_violation)
                ) =>
            {
                wait_for_lock(deadline)?;
            }
            Err(error) => return Err(error).context("open key-directory lock"),
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

/// Reports whether `dir` lists `file_name` spelled exactly as given.
/// A case-insensitive file system, such as NTFS or APFS, also resolves `file_name` to a name that differs in case.
fn listed_with_exact_name(dir: &Dir, file_name: &str) -> anyhow::Result<bool> {
    Ok(dir
        .entries()
        .context("list key directory")?
        .iter()
        .any(|entry| entry.name == file_name))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use camino::Utf8PathBuf;
    use p256::ecdsa::signature::Verifier as _;

    use super::*;
    use crate::{KeyBackend, delete, generate, list, new_key_name, open};

    const TEST_PREFIX: &str = "devolutions-agent-test";

    struct KeyDirectory(Utf8PathBuf);

    impl KeyDirectory {
        /// Creates an empty key directory under the system's temporary directory.
        ///
        /// The key directory's ancestors must pass the crate's checks, which a build directory on a network or WSL
        /// volume may not.
        fn new() -> anyhow::Result<Self> {
            let temp = Utf8PathBuf::from_path_buf(std::env::temp_dir())
                .map_err(|path| anyhow::anyhow!("temporary directory {} is not UTF-8", path.display()))?;
            let dir = temp.join(format!("device-key-test-{}", Uuid::new_v4()));
            fs::create_dir_all(&dir)?;
            Ok(Self(dir))
        }

        fn backend(&self) -> KeyBackend {
            KeyBackend::File { dir: self.0.clone() }
        }

        fn open(&self) -> anyhow::Result<Dir> {
            Dir::open_base(&self.0, &key_dir_rule())?.context("missing key directory")
        }

        /// Creates the file `file_name` in the key directory as the crate creates a key file.
        fn create_file(&self, file_name: &str) -> anyhow::Result<File> {
            Ok(self
                .open()?
                .create_file(file_name, &key_file_rule(), FileOptions::new())?)
        }

        fn key_path(&self, name: &str) -> Utf8PathBuf {
            self.0.join(key_file_name(name))
        }
    }

    impl Drop for KeyDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Leaves the temporary of a creator that stopped before installing its key.
    fn create_leftover(directory: &KeyDirectory) -> anyhow::Result<Utf8PathBuf> {
        let file_name = format!(".{}-{}.tmp", new_key_name(TEST_PREFIX), Uuid::new_v4());
        directory
            .create_file(&file_name)?
            .write_all(b"unfinalized private key")?;
        Ok(directory.0.join(file_name))
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

            let mode = fs::metadata(dir.key_path(&name))?.permissions().mode();
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
        let mut file = dir.create_file(&key_file_name(&name))?;
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
        let orphan = format!(".{name}-{}.tmp", Uuid::new_v4());
        let mut file = directory.create_file(&orphan)?;
        file.write_all(b"unfinalized private key")?;
        file.sync_all()?;
        drop(file);

        let other_name = new_key_name("other");
        let other_orphan = format!(".{other_name}-{}.deleted", Uuid::new_v4());
        let mut file = directory.create_file(&other_orphan)?;
        file.write_all(b"abandoned key material")?;
        file.sync_all()?;
        drop(file);

        assert!(list(&backend, TEST_PREFIX)?.is_empty());
        assert!(!directory.0.join(orphan).exists());
        assert!(!directory.0.join(other_orphan).exists());
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
    fn files_outside_the_naming_scheme_survive_list_and_delete() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let name = new_key_name(TEST_PREFIX);
        generate(&backend, &name)?;
        let leftover = create_leftover(&directory)?;
        let uuid = || Uuid::new_v4().to_string();
        // RFC 9562 §4 places the version in the first digit of the third group and the variant in the first digit of the fourth.
        let uuid_with_digit = |index: usize, digit: &str| {
            let mut uuid = Uuid::new_v4().to_string();
            uuid.replace_range(index..=index, digit);
            uuid
        };
        // The crate names a key `{key name}.p8` and its copies `.{key name}-{lowercase version 4 UUID}.tmp` or `.deleted`.
        // Each name below falls outside that scheme.
        let outside_files = [
            "notes.txt".to_owned(),
            format!("{name}.p8.bak"),
            format!(".{name}.tmp"),
            format!(".{name}.deleted"),
            // A letter in the first digit, which encodes neither version nor variant, makes the uppercase form differ.
            format!(".{name}-{}.tmp", uuid_with_digit(0, "a").to_uppercase()),
            format!(".{name}-{}.tmp", uuid_with_digit(14, "1")),
            format!(".{name}-{}.tmp", uuid_with_digit(19, "c")),
            format!(".{}-{}.tmp", name.to_uppercase(), uuid()),
            format!("{name}-{}.tmp", uuid()),
        ];
        for file_name in &outside_files {
            directory.create_file(file_name)?;
        }

        // An operation may skip an unexpected entry or fail, so only what it leaves behind is checked.
        let _ = list(&backend, TEST_PREFIX);
        let _ = delete(&backend, &name);

        assert!(!leftover.exists());
        for file_name in &outside_files {
            assert!(directory.0.join(file_name).is_file(), "{file_name}");
        }
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn a_link_at_a_leftover_name_is_skipped_by_listing() -> anyhow::Result<()> {
        // Catches a cleanup that treats a link named like a leftover as one, which then fails every operation.
        let directory = KeyDirectory::new()?;
        let leftover = create_leftover(&directory)?;
        let target = directory.0.join("target");
        fs::create_dir(&target)?;
        let link = directory
            .0
            .join(format!(".{}-{}.tmp", new_key_name(TEST_PREFIX), Uuid::new_v4()));
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link)?;
        // A directory junction needs no privilege, unlike a symbolic link.
        #[cfg(windows)]
        ensure!(
            std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J", link.as_str(), target.as_str()])
                .output()?
                .status
                .success(),
            "create junction"
        );

        assert!(list(&directory.backend(), TEST_PREFIX)?.is_empty());
        assert!(!leftover.exists());
        assert!(fs::symlink_metadata(&link).is_ok());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn unexpected_entry_names_cause_no_panic() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let leftover = create_leftover(&directory)?;
        // Slicing these names by a UUID's or the prefix's length would land inside a character or past an end.
        let stray_names = [
            format!(".é{}.tmp", "0".repeat(35)),
            ".x.tmp".to_owned(),
            format!("{TEST_PREFIX}.p8"),
        ];
        for stray_name in &stray_names {
            directory.create_file(stray_name)?;
        }

        // An operation may skip an unexpected entry or fail; a panic fails this test.
        let _ = list(&directory.backend(), TEST_PREFIX);

        assert!(!leftover.exists());
        for stray_name in &stray_names {
            assert!(directory.0.join(stray_name).is_file(), "{stray_name}");
        }
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    // APFS refuses file names that are not UTF-8.
    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn entry_names_that_are_not_utf8_cause_no_panic() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let leftover = create_leftover(&directory)?;
        #[cfg(unix)]
        let stray_name = {
            use std::os::unix::ffi::OsStringExt as _;

            std::ffi::OsString::from_vec(b".\xff.tmp".to_vec())
        };
        // An unpaired surrogate is a valid NTFS file name but has no UTF-8 form.
        #[cfg(windows)]
        let stray_name = {
            use std::os::windows::ffi::OsStringExt as _;

            let wide = [u16::from(b'.'), 0xD800]
                .into_iter()
                .chain(".tmp".encode_utf16())
                .collect::<Vec<_>>();
            std::ffi::OsString::from_wide(&wide)
        };
        let stray = directory.0.as_std_path().join(stray_name);
        File::create(&stray)?;

        // An operation may skip an unexpected entry or fail; a panic fails this test.
        let _ = list(&directory.backend(), TEST_PREFIX);

        assert!(!leftover.exists());
        assert!(stray.is_file());
        Ok(())
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
        directory.create_file(&key_file_name("scope_INVALID"))?;

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
        let lock = lock_directory(&directory.open()?)?;
        let temporary = format!(".{}-{}.tmp", new_key_name(TEST_PREFIX), Uuid::new_v4());
        directory.create_file(&temporary)?;
        let temporary = directory.0.join(temporary);
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
        let lock = lock_directory(&directory.open()?)?;
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
    fn a_lock_file_that_fails_its_rule_stops_every_operation_but_listing() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let name = new_key_name(TEST_PREFIX);
        generate(&backend, &name)?;
        let lock = directory.0.join(LOCK_NAME);
        fs::remove_file(&lock)?;
        // Created outside the crate, the file is readable by other accounts: on Unix through its mode, and on Windows
        // through the entries it inherits from the key directory.
        fs::write(&lock, b"")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&lock, fs::Permissions::from_mode(0o644))?;
        }

        assert_eq!(list(&backend, TEST_PREFIX)?, std::slice::from_ref(&name));
        assert!(open(&backend, &name).is_err());
        assert!(generate(&backend, &new_key_name(TEST_PREFIX)).is_err());
        assert!(delete(&backend, &name).is_err());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[cfg(windows)]
    #[test]
    fn a_leftover_another_process_holds_open_is_skipped_by_listing() -> anyhow::Result<()> {
        use std::os::windows::fs::OpenOptionsExt as _;

        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let name = new_key_name(TEST_PREFIX);
        generate(&backend, &name)?;
        let leftover = create_leftover(&directory)?;
        // A handle that shares nothing makes the cleanup's rename of the leftover fail.
        let held = fs::OpenOptions::new().read(true).share_mode(0).open(&leftover)?;

        let listed = list(&backend, TEST_PREFIX);
        drop(held);

        assert_eq!(listed?, [name]);
        assert!(leftover.exists());
        assert!(list(&backend, TEST_PREFIX).is_ok());
        assert!(!leftover.exists());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn lock_wait_on_an_existing_lock_file_expires() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        // An earlier operation leaves the lock file behind, so the holder below opens it instead of creating it.
        list(&directory.backend(), TEST_PREFIX)?;
        let _lock = lock_directory(&directory.open()?)?;

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
        let path = directory.key_path(&name);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        assert!(open(&backend, &name).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert!(open(&backend, &name)?.is_some());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Access
    #[cfg(unix)]
    #[test]
    fn root_only_a_key_file_owned_by_another_account_cannot_be_opened() -> anyhow::Result<()> {
        // SAFETY: Reading the current effective UID has no preconditions.
        let user = unsafe { libc::geteuid() };
        if user != 0 {
            // The test harness captures `eprintln!` output from a passing test, but not direct writes to stderr.
            writeln!(
                std::io::stderr(),
                "SKIP: root_only_a_key_file_owned_by_another_account_cannot_be_opened needs root"
            )?;
            return Ok(());
        }
        let nobody = {
            let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
            let mut buffer: [libc::c_char; 1024] = [0; 1024];
            let mut found = std::ptr::null_mut();
            // SAFETY: The name is NUL-terminated, and the entry, buffer and result pointers are writable for the call.
            let status = unsafe {
                libc::getpwnam_r(
                    c"nobody".as_ptr(),
                    entry.as_mut_ptr(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut found,
                )
            };
            ensure!(status == 0 && !found.is_null(), "look up the nobody account");
            // SAFETY: A lookup that succeeded and found the account filled the entry.
            unsafe { entry.assume_init() }.pw_uid
        };
        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let name = new_key_name(TEST_PREFIX);
        let other_name = new_key_name(TEST_PREFIX);
        generate(&backend, &name)?;
        generate(&backend, &other_name)?;
        std::os::unix::fs::chown(directory.key_path(&name), Some(nobody), None)?;

        assert!(open(&backend, &name).is_err());
        // oracle: intent crates/device-key/INTENT.md §Operations
        assert!(list(&backend, TEST_PREFIX)?.contains(&other_name));
        // An operation may skip an unexpected entry or fail, so only what it leaves behind is checked.
        let _ = delete(&backend, &name);
        // The other key, created the same way but left with its owner, still opens.
        // oracle: intent crates/device-key/INTENT.md §Operations
        assert!(open(&backend, &other_name)?.is_some());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §File backend
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

    // oracle: intent crates/device-key/INTENT.md §File backend
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
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o100))?;
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
        let retired = format!(".{name}-{}.deleted", Uuid::new_v4());
        directory
            .open()?
            .rename(&key_file_name(&name), &retired, Replace::Refuse)?;

        assert!(open(&backend, &name)?.is_none());
        assert!(!directory.0.join(retired).exists());
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
        fs::hard_link(directory.key_path(&real_name), directory.key_path(&alias))?;
        assert!(open(&backend, &alias).is_err());
        assert!(open(&backend, &real_name).is_err());
        fs::remove_file(directory.key_path(&alias))?;
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
        let _holder = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(directory.key_path(&name))?;

        assert!(!matches!(open(&backend, &name), Ok(None)));
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Access
    #[cfg(windows)]
    #[test]
    fn a_key_file_another_account_can_read_cannot_be_opened() -> anyhow::Result<()> {
        use win_api_wrappers::identity::sid::Sid;
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
        let path = U16CString::from_str(directory.key_path(&name).as_str())?;
        set_named_security_info(&path, SE_FILE_OBJECT, None, None, Some(&dacl), None)?;

        assert!(open(&backend, &name).is_err());
        // oracle: intent crates/device-key/INTENT.md §Operations
        assert_eq!(list(&backend, TEST_PREFIX)?, vec![name.clone()]);
        delete(&backend, &name)?;
        assert!(list(&backend, TEST_PREFIX)?.is_empty());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Access
    #[cfg(windows)]
    #[test]
    fn elevated_only_a_key_file_owned_by_administrators_cannot_be_opened() -> anyhow::Result<()> {
        use win_api_wrappers::identity::sid::Sid;
        use win_api_wrappers::raw::Win32::Security::Authorization::SE_FILE_OBJECT;
        use win_api_wrappers::raw::Win32::Security::WinBuiltinAdministratorsSid;
        use win_api_wrappers::security::acl::set_named_security_info;
        use win_api_wrappers::str::U16CString;
        use win_api_wrappers::token::Token;

        // Only an elevated token can make BUILTIN\Administrators the owner without the restore privilege.
        if !Token::current_process_token().is_elevated()? {
            // The test harness captures `eprintln!` output from a passing test, but not direct writes to stderr.
            writeln!(
                std::io::stderr(),
                "SKIP: elevated_only_a_key_file_owned_by_administrators_cannot_be_opened needs elevation"
            )?;
            return Ok(());
        }
        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let name = new_key_name(TEST_PREFIX);
        let other_name = new_key_name(TEST_PREFIX);
        generate(&backend, &name)?;
        generate(&backend, &other_name)?;
        // The owner of a file can change its DACL, so an owner other than the caller's account or SYSTEM breaks the
        // access rule even when the DACL holds.
        let administrators = Sid::from_well_known(WinBuiltinAdministratorsSid, None)?;
        set_named_security_info(
            &U16CString::from_str(directory.key_path(&name).as_str())?,
            SE_FILE_OBJECT,
            Some(&administrators),
            None,
            None,
            None,
        )?;

        assert!(open(&backend, &name).is_err());
        // oracle: intent crates/device-key/INTENT.md §Operations
        assert_eq!(list(&backend, TEST_PREFIX)?.len(), 2);
        delete(&backend, &name)?;
        // oracle: intent crates/device-key/INTENT.md §Operations
        assert_eq!(list(&backend, TEST_PREFIX)?, vec![other_name.clone()]);
        assert!(open(&backend, &other_name)?.is_some());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[cfg(unix)]
    #[test]
    fn a_fifo_at_a_key_name_neither_blocks_open_nor_holds_the_lock() -> anyhow::Result<()> {
        use std::ffi::CString;

        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let name = new_key_name(TEST_PREFIX);
        let fifo = CString::new(directory.key_path(&name).as_str())?;
        // SAFETY: The path is NUL-terminated.
        let status = unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) };
        ensure!(status == 0, "create FIFO: {}", std::io::Error::last_os_error());
        let (sender, receiver) = std::sync::mpsc::channel();
        let opener_backend = backend.clone();
        // A blocked opener never finishes, so the test does not join it.
        std::thread::spawn(move || sender.send(open(&opener_backend, &name).map(|key| key.is_some())));

        // A blocked open would make every later operation wait out the five-second lock, so one second is ample.
        let opened = receiver.recv_timeout(Duration::from_secs(1));
        assert!(matches!(opened, Ok(Ok(false) | Err(_))), "{opened:?}");
        assert!(list(&backend, TEST_PREFIX)?.is_empty());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn a_key_file_name_with_an_uppercase_key_name_survives_delete() -> anyhow::Result<()> {
        let name = new_key_name(TEST_PREFIX);
        case_alias_survives_delete_and_list(&name, &format!("{}.p8", name.to_uppercase()))
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[test]
    fn a_key_file_name_with_an_uppercase_extension_survives_delete() -> anyhow::Result<()> {
        let name = new_key_name(TEST_PREFIX);
        case_alias_survives_delete_and_list(&name, &format!("{name}.P8"))
    }

    /// Leaves an alias, a file named like `name`'s key file but for case.
    /// A case-insensitive file system, such as NTFS or APFS, resolves the key file's path to the alias.
    fn case_alias_survives_delete_and_list(name: &str, alias: &str) -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        directory.create_file(alias)?;
        let alias = directory.0.join(alias);

        // An operation may skip an unexpected entry or fail, so only what it leaves behind is checked.
        let _ = delete(&backend, name);

        assert!(alias.is_file());
        assert!(list(&backend, TEST_PREFIX)?.is_empty());
        Ok(())
    }

    // oracle: intent crates/device-key/INTENT.md §File backend
    #[test]
    fn key_files_open_up_to_64_kib_and_are_refused_past_it() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let key = SigningKey::generate_from_rng(&mut rand::rng());
        let pkcs8 = key.to_pkcs8_der()?;
        let at_bound = pad_pkcs8(pkcs8.as_bytes(), 64 * 1024)?;
        let name = new_key_name(TEST_PREFIX);
        directory.create_file(&key_file_name(&name))?.write_all(&at_bound)?;
        let opened = open(&backend, &name)?.context("a 64 KiB key file was refused")?;
        // oracle: property round-trip
        assert_eq!(opened.public_key(), *key.verifying_key());

        // The first file is a valid key one byte past the bound.
        // A reader that stops at the bound sees the key above in the second.
        for past_bound in [
            pad_pkcs8(pkcs8.as_bytes(), 64 * 1024 + 1)?,
            [at_bound.as_slice(), &[0]].concat(),
        ] {
            let name = new_key_name(TEST_PREFIX);
            directory.create_file(&key_file_name(&name))?.write_all(&past_bound)?;
            // An operation may skip an unexpected entry or fail, but never returns it as a key.
            assert!(!matches!(open(&backend, &name), Ok(Some(_))));
        }
        Ok(())
    }

    /// Pads a PKCS#8 key to `len` bytes, near 64 KiB, with an attribute that keeps it a valid key.
    fn pad_pkcs8(pkcs8: &[u8], len: usize) -> anyhow::Result<Vec<u8>> {
        // The key is a version 1 PrivateKeyInfo, whose optional attributes come last (RFC 5208 §5).
        // An attribute appended to its fields therefore keeps it a valid key.
        let header_len = match pkcs8.get(1) {
            Some(&length) if length < 0x80 => 2,
            Some(&length) => 2 + usize::from(length & 0x7F),
            None => anyhow::bail!("PKCS#8 key has no length"),
        };
        let fields = pkcs8.get(header_len..).context("PKCS#8 key is truncated")?;
        // An attribute is a SEQUENCE of a type OID and a SET of values (X.501); its value is an OCTET STRING of zeros.
        // At these lengths, each element's header is a tag, 0x82, then a 2-byte length (X.690 §8.1.3.5).
        let zeros = len
            .checked_sub(
                4 /* PrivateKeyInfo header */
                    + fields.len()
                    + 4 /* attributes header */
                    + 4 /* Attribute header */
                    + 5 /* type OID */
                    + 4 /* SET header */
                    + 4, /* OCTET STRING header */
            )
            .context("PKCS#8 key is too long to pad")?;
        let attribute = der(
            0x30,
            &[
                der(0x06, &[0x2A, 0x03, 0x04])?,
                der(0x31, &der(0x04, &vec![0; zeros])?)?,
            ]
            .concat(),
        )?;
        let padded = der(0x30, &[fields, der(0xA0, &attribute)?.as_slice()].concat())?;
        ensure!(padded.len() == len, "padded PKCS#8 key is {} bytes", padded.len());
        Ok(padded)
    }

    /// Encodes one DER element with the definite, minimal length that X.690 §10.1 requires.
    fn der(tag: u8, content: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut element = vec![tag];
        if let Ok(length @ 0..0x80) = u8::try_from(content.len()) {
            element.push(length);
        } else {
            let length = content.len().to_be_bytes();
            let significant = &length[length.iter().take_while(|&&byte| byte == 0).count()..];
            element.push(0x80 | u8::try_from(significant.len())?);
            element.extend_from_slice(significant);
        }
        element.extend_from_slice(content);
        Ok(element)
    }

    // oracle: intent crates/device-key/INTENT.md §Operations
    #[cfg(unix)]
    #[test]
    fn key_symlink_cannot_be_opened() -> anyhow::Result<()> {
        let directory = KeyDirectory::new()?;
        let backend = directory.backend();
        let real_name = new_key_name(TEST_PREFIX);
        let alias = new_key_name(TEST_PREFIX);
        generate(&backend, &real_name)?;
        std::os::unix::fs::symlink(directory.key_path(&real_name), directory.key_path(&alias))?;
        assert!(open(&backend, &alias).is_err());
        assert_eq!(list(&backend, TEST_PREFIX)?, vec![real_name.clone()]);
        delete(&backend, &alias)?;
        assert!(open(&backend, &real_name)?.is_some());
        Ok(())
    }
}
