use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use der::{Decode as _, Encode as _, Reader as _};
#[cfg(any(unix, windows))]
use p256::ecdsa::SigningKey;
#[cfg(windows)]
use p256::ecdsa::VerifyingKey;
#[cfg(any(unix, windows))]
use p256::pkcs8::DecodePrivateKey as _;
use p256::pkcs8::EncodePublicKey as _;
use rand::RngExt as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::format_description::well_known::Rfc3339;
use tokio::io::AsyncWriteExt as _;
use tokio::process::{Child, Command};
use x509_cert::Certificate;

use crate::client::{
    INTERIOR_INVISIBLE_FORMAT_CHARACTERS, Target, Token, count, decoded_certificate, expect_error, expect_status,
    field, invisible_format_character_range_ends, is_invisible_format_character, token_bag, token_base_url,
    unlisted_format_character_neighbors, with_bag_url, with_upper_case_scheme,
};
use crate::dvls::{CertificateStatus, IdentityQuery, IdentityRecord, IdentityStatus, RotationDeadline};
use crate::{Context, key_storage};

#[cfg(windows)]
#[path = "system_fixture.rs"]
mod system_fixture;

/// Evaluates `attempt`, an async block yielding `anyhow::Result<Option<T>>`, every `step` until it yields `Some`, and evaluates to the value it holds.
/// The enclosing function returns an error when an attempt fails, when the agent of `case` has exited, and, once `wait` has elapsed, with the message `timeout`, evaluated after the last attempt.
///
/// A macro rather than a function taking an async closure: rustc cannot yet prove such a closure's future `Send` for every lifetime of the `&mut AgentCase` it borrows.
macro_rules! poll {
    ($case:expr, $wait:expr, $step:expr, $timeout:expr, async $attempt:block $(,)?) => {{
        let start = Instant::now();
        // Evaluated once, so that a wait computed from the clock does not shrink on every attempt.
        let wait: Duration = $wait;
        loop {
            let attempt: anyhow::Result<Option<_>> = async $attempt.await;
            if let Some(value) = attempt? {
                break value;
            }
            $case.check_running()?;
            ensure!(start.elapsed() < wait, "{}", $timeout);
            tokio::time::sleep($step).await;
        }
    }};
}

const WAIT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(100);

// Declared after `poll!`, which the cases use.
#[path = "agent_key_storage.rs"]
mod key_storage_cases;
pub(crate) use key_storage_cases::*;
const KNOWN_METADATA_KEYS: [&str; 10] = [
    "hostname",
    "fqdn",
    "domain",
    "os_name",
    "os_version",
    "arch",
    "agent_version",
    "machine_id",
    "key_storage",
    "key_storage_available",
];
const REQUIRED_METADATA_KEYS: [&str; 6] = [
    "hostname",
    "os_name",
    "os_version",
    "arch",
    "agent_version",
    "key_storage",
];
/// Each agent case's data directory, under the work directory, is this prefix and [`DATA_DIR_RANDOM_LEN`] random characters.
pub(crate) const DATA_DIR_PREFIX: &str = "identity-agent-";
pub(crate) const DATA_DIR_RANDOM_LEN: usize = 6;

pub(crate) fn token_file_id(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn valid_key_prefix(prefix: &str) -> bool {
    (1..=64).contains(&prefix.len())
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(crate) fn key_belongs_to_run(name: &str, prefix: &str) -> bool {
    name.split_once('_').is_some_and(|(candidate, _)| candidate == prefix)
}

pub(crate) fn validate_key_name(prefix: &str, name: &str) -> anyhow::Result<()> {
    ensure!(valid_key_prefix(prefix), "invalid device-key run prefix");
    let (_, key_uuid) = name.split_once('_').context("key name has no prefix separator")?;
    ensure!(
        key_belongs_to_run(name, prefix),
        "key name {name} does not belong to run prefix {prefix}"
    );
    let parsed = uuid::Uuid::parse_str(key_uuid).context("key name does not end with a UUID")?;
    ensure!(
        parsed.to_string() == key_uuid,
        "key name does not end with a lowercase hyphenated UUID"
    );
    Ok(())
}

/// The run's key name that a file name embeds, such as the name of a key-store file holding a copy of that key.
fn embedded_key_name<'a>(file_name: &'a str, prefix: &str) -> Option<&'a str> {
    let start = file_name.find(&format!("{prefix}_"))?;
    let name = file_name.get(start..start + prefix.len() + 1 + uuid::fmt::Hyphenated::LENGTH)?;
    validate_key_name(prefix, name).is_ok().then_some(name)
}

fn canonical_authority_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| uuid::Uuid::parse_str(name).ok().map(|id| id.to_string() == name))
        == Some(true)
}

fn contains_pkcs8_material(contents: &[u8]) -> bool {
    const PEM_MARKERS: [&[u8]; 2] = [b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN ENCRYPTED PRIVATE KEY-----"];
    PEM_MARKERS
        .iter()
        .any(|marker| contents.windows(marker.len()).any(|window| window == *marker))
        || p256::pkcs8::PrivateKeyInfoRef::try_from(contents).is_ok()
        || encrypted_pkcs8_der(contents).unwrap_or(false)
}

fn encrypted_pkcs8_der(contents: &[u8]) -> der::Result<bool> {
    let outer = <&der::asn1::SequenceRef>::from_der(contents)?;
    let mut fields = der::SliceReader::new(outer.as_bytes())?;
    let algorithm: &der::asn1::SequenceRef = fields.decode()?;
    let encrypted: &der::asn1::OctetStringRef = fields.decode()?;
    fields.finish()?;
    let mut algorithm_fields = der::SliceReader::new(algorithm.as_bytes())?;
    let oid: der::asn1::ObjectIdentifier = algorithm_fields.decode()?;
    let oid = oid.to_string();
    Ok(!encrypted.as_bytes().is_empty()
        && (oid.starts_with("1.2.840.113549.1.5.") || oid.starts_with("1.2.840.113549.1.12.1.")))
}

fn temporary_name(name: &str, expected: &str) -> bool {
    let name = name.strip_prefix('.').unwrap_or(name);
    let Some(suffix) = name
        .strip_prefix(expected)
        .and_then(|tail| tail.strip_prefix('.').or_else(|| tail.strip_prefix('-')))
    else {
        return false;
    };
    suffix.starts_with("tmp")
        || ["temp", "part", "new"].iter().any(|marker| {
            suffix.strip_prefix(marker).is_some_and(|rest| {
                rest.is_empty()
                    || rest.starts_with('.')
                    || rest.starts_with('-')
                    || rest.starts_with('_')
                    || rest.as_bytes().first().is_some_and(|byte| byte.is_ascii_digit())
            })
        })
        || [".tmp", ".temp", ".part", ".new"]
            .iter()
            .any(|extension| suffix.ends_with(extension))
}

fn is_temporary_sibling(path: &Path, documented: &HashSet<PathBuf>, key_prefix: &str) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if documented.iter().any(|file| {
        path.parent() == file.parent()
            && file
                .file_name()
                .and_then(|expected| expected.to_str())
                .is_some_and(|expected| temporary_name(name, expected))
    }) {
        return true;
    }
    let candidate = name.strip_prefix('.').unwrap_or(name);
    match path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|parent| parent.to_str())
    {
        Some("keys") => candidate
            .split_once(".p8.")
            .or_else(|| candidate.split_once(".p8-"))
            .is_some_and(|(key, _)| {
                validate_key_name(key_prefix, key).is_ok() && temporary_name(name, &format!("{key}.p8"))
            }),
        Some("pending") if candidate.len() >= 64 => {
            let (hash, _) = candidate.split_at(64);
            hash.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && [".json", ".dat", ".in-progress.json"]
                    .iter()
                    .any(|suffix| temporary_name(name, &format!("{hash}{suffix}")))
        }
        _ => false,
    }
}

/// Whether a temporary sibling, as [`is_temporary_sibling`] finds it, belongs to `identity.json` or an in-progress record.
///
/// The agent writes both records atomically, through a temporary file that it renames over the record ([agent intent], "Stored identities").
/// That keeps the record whole when stopping the agent cuts a write short, but nothing promises that the temporary file is then removed.
///
/// [agent intent]: ../../agent-identity/INTENT.md#stored-identities
fn is_record_temporary(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let candidate = name.strip_prefix('.').unwrap_or(name);
    temporary_name(name, "identity.json")
        || candidate
            .get(..64)
            .is_some_and(|hash| temporary_name(name, &format!("{hash}.in-progress.json")))
}

/// What the metadata check requires of the agent's `machine_id`.
///
/// [CONTRACT.agent-identity.md] §3.1 "Metadata sent by the agent" has the agent send a value only when the OS provides one, and the check can read the Linux value from the host alone.
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpectedMachineId {
    /// The host's value is not available to the check, so whatever the agent sent is accepted.
    NotCompared,
    /// The host provides no value, so the agent must omit the key.
    Absent,
    /// The host provides this value, so the agent must send exactly it.
    Value(String),
}

fn validate_agent_metadata(
    metadata: &Value,
    agent_version: Option<&str>,
    machine_id: &ExpectedMachineId,
) -> anyhow::Result<()> {
    let values = metadata.as_object().context("agent metadata is not an object")?;
    let mut total_bytes = 0;
    for (key, value) in values {
        ensure!(
            KNOWN_METADATA_KEYS.contains(&key.as_str()),
            "agent sent unknown metadata key {key}"
        );
        let value = value
            .as_str()
            .with_context(|| format!("agent metadata {key} is not a string"))?;
        ensure!(!value.is_empty(), "agent metadata {key} is empty");
        ensure!(value.len() <= 1024, "agent metadata {key} exceeds 1024 UTF-8 bytes");
        ensure!(
            !value.chars().any(removed_from_metadata),
            "agent metadata {key} contains a control character or an invisible format character"
        );
        total_bytes += key.len() + value.len();
    }
    ensure!(total_bytes <= 16 * 1024, "agent metadata exceeds 16 KiB");
    for key in REQUIRED_METADATA_KEYS {
        ensure!(
            values
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty()),
            "agent metadata is missing required {key}"
        );
    }
    ensure!(
        metadata["arch"] == std::env::consts::ARCH,
        "agent metadata arch differs from the test platform"
    );
    if let Some(expected) = agent_version {
        ensure!(
            metadata["agent_version"] == expected,
            "agent metadata version differs from --agent-version"
        );
    }
    check_key_storage_metadata(metadata)?;
    check_machine_id(metadata, machine_id)
}

/// Checks the key storage metadata ([CONTRACT.agent-identity.md] §3.1) against the key storages this platform can have.
///
/// Every enrollment key is in the built-in default ([agent intent], "Key storage"), so that storage is available wherever the agent enrolled, and the contract's table limits the Windows software provider to Windows.
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
/// [agent intent]: ../../agent-identity/INTENT.md#key-storage
fn check_key_storage_metadata(metadata: &Value) -> anyhow::Result<()> {
    let storage = metadata["key_storage"].as_str().unwrap_or_default();
    ensure!(
        key_storage::well_formed(storage),
        "agent metadata key_storage {storage:?} is not a key storage name"
    );
    let available = metadata["key_storage_available"]
        .as_str()
        .context("agent metadata omits key_storage_available although the agent enrolled with a key")?;
    let available = key_storage::available_names(available)?;
    ensure!(
        available.contains(&key_storage::builtin_default()),
        "agent metadata key_storage_available omits {}, where the agent creates its enrollment keys",
        key_storage::builtin_default()
    );
    ensure!(
        cfg!(windows) || !available.contains(&key_storage::WINDOWS_SOFTWARE_PROVIDER),
        "agent metadata reports the Windows software provider available off Windows"
    );
    Ok(())
}

/// Whether the agent removes `character` from every metadata value it sends, and the authority refuses it in one.
///
/// [CONTRACT.agent-identity.md] §3 "Metadata" excludes the C0, DEL, C1 and invisible format characters, and §3.1 "Metadata sent by the agent" has the agent remove them.
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
fn removed_from_metadata(character: char) -> bool {
    character < '\u{20}' || ('\u{7f}'..='\u{9f}').contains(&character) || is_invisible_format_character(character)
}

/// The `machine_id` check's expectation on this host: the Linux `/etc/machine-id` as the agent must report it, and nothing elsewhere.
///
/// Windows and macOS values are not compared, because the suite has no independent reading of the SMBIOS UUID or `IOPlatformUUID`.
fn host_machine_id() -> ExpectedMachineId {
    if !cfg!(target_os = "linux") {
        return ExpectedMachineId::NotCompared;
    }
    machine_id_expectation(std::fs::read_to_string("/etc/machine-id"))
}

/// The expectation from reading the Linux `/etc/machine-id`.
///
/// A missing file means the OS provides no value, so the agent must omit the key.
/// Any other failure, such as a permission denial, a directory at that path, or contents that are not UTF-8, leaves the suite unable to know what the host provides, so the value is not compared rather than the whole run aborted.
fn machine_id_expectation(read: std::io::Result<String>) -> ExpectedMachineId {
    match read {
        Ok(contents) => expected_machine_id(Some(&contents)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => expected_machine_id(None),
        Err(error) => {
            eprintln!("WARN cannot read the Linux machine ID, so the agent's machine_id is not compared: {error}");
            ExpectedMachineId::NotCompared
        }
    }
}

/// The `machine_id` an agent must report on a Linux host whose `/etc/machine-id` holds `host_contents`, which is `None` when the host has no such file.
///
/// The agent sends the file as-is ([CONTRACT.agent-identity.md] §3.1 "Metadata sent by the agent") after the removal every value goes through, so the expectation is what that leaves, without trimming.
/// An optional key left empty is omitted, so a missing or empty file expects no `machine_id` at all.
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
fn expected_machine_id(host_contents: Option<&str>) -> ExpectedMachineId {
    let mut sanitised = String::new();
    for character in host_contents
        .unwrap_or_default()
        .chars()
        .filter(|character| !removed_from_metadata(*character))
    {
        if sanitised.len() + character.len_utf8() <= 1024 {
            sanitised.push(character);
        } else {
            break;
        }
    }
    if sanitised.is_empty() {
        ExpectedMachineId::Absent
    } else {
        ExpectedMachineId::Value(sanitised)
    }
}

fn check_machine_id(metadata: &Value, expected: &ExpectedMachineId) -> anyhow::Result<()> {
    let sent = metadata.get("machine_id");
    match expected {
        ExpectedMachineId::NotCompared => {}
        ExpectedMachineId::Absent => ensure!(
            sent.is_none(),
            "agent metadata carries machine_id {sent:?} although the host provides none"
        ),
        ExpectedMachineId::Value(expected) => ensure!(
            sent == Some(&Value::String(expected.clone())),
            "agent metadata machine_id is {sent:?} instead of the host's {expected:?}"
        ),
    }
    Ok(())
}

fn assert_no_token_fragments(contents: &[u8], token: &str, path: &Path) -> anyhow::Result<()> {
    let mut parts = token.split('.');
    let _ = parts.next();
    let bag = parts.next().context("registered token has no bag")?;
    let secret = parts.next().context("registered token has no secret")?;
    for fragment in [token.as_bytes(), bag.as_bytes(), secret.as_bytes()] {
        if fragment.is_empty() {
            continue;
        }
        ensure!(
            !contents.windows(fragment.len()).any(|chunk| chunk == fragment),
            "enrollment token leaked into {}",
            path.display()
        );
    }
    for fragment in secret.as_bytes().windows(12) {
        ensure!(
            !contents.windows(12).any(|chunk| chunk == fragment),
            "twelve-character enrollment secret fragment leaked into {}",
            path.display()
        );
    }
    Ok(())
}

/// The SPKI of the leaf certificate that a stored key slot holds, or `None` while the slot holds no chain.
pub(crate) fn expected_spki(stored: &Value) -> anyhow::Result<Option<Vec<u8>>> {
    stored["certificate_chain"]
        .as_array()
        .map(|chain| -> anyhow::Result<Vec<u8>> {
            let leaf = chain
                .first()
                .and_then(Value::as_str)
                .context("stored certificate chain is empty")?;
            let certificate = Certificate::from_der(&decoded_certificate(leaf)?)?;
            Ok(certificate.tbs_certificate().subject_public_key_info().to_der()?)
        })
        .transpose()
}

/// A key with the key storage that a record names for it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct RecordedKey {
    name: String,
    storage: String,
}

impl RecordedKey {
    fn new(name: &str, storage: &str) -> Self {
        Self {
            name: name.to_owned(),
            storage: storage.to_owned(),
        }
    }
}

/// The key storage that a key slot or in-progress record names, which must be a well-formed name ([agent intent], "Stored identities").
///
/// [agent intent]: ../../agent-identity/INTENT.md#stored-identities
pub(crate) fn recorded_storage(record: &Value) -> anyhow::Result<&str> {
    let storage = record["key_storage"].as_str().context("key_storage is missing")?;
    ensure!(
        key_storage::well_formed(storage),
        "key_storage {storage:?} is not a key storage name"
    );
    Ok(storage)
}

/// An agent data directory, as the audits read it.
///
/// The suite audits the directory of each agent it runs, and the SYSTEM probe that of the agent it runs as SYSTEM, with the same checks.
pub(crate) struct DataDir<'a> {
    pub(crate) path: &'a Path,
    pub(crate) key_name_prefix: &'a str,
    /// The tokens of the pending-enrollment files written to the directory.
    pub(crate) tokens: &'a [String],
    /// Whether `identity/keys` may hold a leftover copy of a deleted key, which only warns.
    pub(crate) leftover_key_copies: bool,
}

impl DataDir<'_> {
    fn pending_path_for(&self, token: &str) -> PathBuf {
        #[cfg(windows)]
        let extension = "dat";
        #[cfg(not(windows))]
        let extension = "json";
        self.path
            .join("identity")
            .join("pending")
            .join(format!("{}.{extension}", token_file_id(token)))
    }

    fn identity_path(&self, authority_id: &str) -> PathBuf {
        self.path
            .join("identity")
            .join("authorities")
            .join(authority_id)
            .join("identity.json")
    }

    fn in_progress_path_for(&self, token: &str) -> PathBuf {
        self.path
            .join("identity")
            .join("pending")
            .join(format!("{}.in-progress.json", token_file_id(token)))
    }

    fn key_file_path(&self, name: &str) -> PathBuf {
        self.path.join("identity").join("keys").join(format!("{name}.p8"))
    }

    fn in_progress_for(&self, token: &str) -> anyhow::Result<Option<Value>> {
        let path = self.in_progress_path_for(token);
        if !path.exists() {
            return Ok(None);
        }
        let record: Value = serde_json::from_slice(&std::fs::read(path)?).context("read pending in-progress record")?;
        ensure!(record["version"] == 1, "in-progress enrollment has wrong version");
        ensure!(
            record["token_sha256"] == token_file_id(token),
            "in-progress record does not belong to its pending token"
        );
        validate_key_name(self.key_name_prefix, field(&record, "key_name")?)?;
        recorded_storage(&record).context("in-progress record")?;
        Ok(Some(record))
    }

    fn state(&self, authority_id: &str) -> anyhow::Result<Value> {
        // UNTESTED: on Windows, the suite reads the agent's files with read, write and delete sharing, the default of `std::fs`, so polling never blocks the agent's replace of a record.
        // A reader without delete sharing makes that replace fail until the reader closes the file, which delays the agent and keeps its temporary file meanwhile.
        // When reading the agent's files through another API, keep `FILE_SHARE_DELETE`.
        serde_json::from_slice(&std::fs::read(self.identity_path(authority_id))?).context("read stored identity")
    }

    pub(crate) fn audit_identity_tree(&self) -> anyhow::Result<()> {
        let identity = self.path.join("identity");
        let metadata = match std::fs::symlink_metadata(&identity) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        ensure!(
            metadata.file_type().is_dir(),
            "identity directory is not a real directory"
        );
        let authorities = identity.join("authorities");
        let keys = identity.join("keys");
        let pending = identity.join("pending");
        let recorded = self.recorded_keys()?;
        let recorded_files = recorded
            .iter()
            .filter(|key| key.storage == key_storage::FILE)
            .map(|key| self.key_file_path(&key.name))
            .collect::<HashSet<_>>();
        let recorded_keys = recorded.into_iter().map(|key| key.name).collect::<HashSet<_>>();
        let mut documented = recorded_files.clone();
        for token in self.tokens {
            documented.insert(self.pending_path_for(token));
            documented.insert(self.in_progress_path_for(token));
        }
        if authorities.exists() {
            for entry in std::fs::read_dir(&authorities)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() && canonical_authority_dir(&entry.path()) {
                    documented.insert(entry.path().join("identity.json"));
                }
            }
        }

        let mut directories = vec![identity];
        while let Some(directory) = directories.pop() {
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                let path = entry.path();
                let file_type = entry.file_type()?;
                let known_directory = path == pending
                    || path == keys
                    || path == authorities
                    || path.parent() == Some(authorities.as_path()) && canonical_authority_dir(&path);
                if file_type.is_dir() {
                    if !known_directory {
                        eprintln!("WARN unknown identity directory {}", path.display());
                    }
                    directories.push(path);
                    continue;
                }
                ensure!(
                    !known_directory,
                    "documented identity directory {} is not a directory",
                    path.display()
                );
                let recorded = recorded_files.contains(&path);
                ensure!(
                    !path
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("p8"))
                        || recorded,
                    "unrecorded private key file {}",
                    path.display()
                );
                let file_name = entry.file_name();
                let file_name = file_name.to_string_lossy();
                if self.leftover_key_copies
                    && path.parent() == Some(keys.as_path())
                    && let Some(key) = embedded_key_name(&file_name, self.key_name_prefix)
                    && !recorded_keys.contains(key)
                {
                    // A leftover copy of a deleted key survives only until a later operation in its key store (`crates/device-key/INTENT.md`, "Operations"), and the agent's last operation may have left it.
                    eprintln!("WARN leftover copy of deleted key {key}: {}", path.display());
                    continue;
                }
                let temporary = is_temporary_sibling(&path, &documented, self.key_name_prefix);
                // A record's atomic write can leave its temporary file when it does not complete, as when the agent is stopped mid-write (`is_record_temporary`); any other temporary sibling is a leftover.
                ensure!(
                    !temporary || is_record_temporary(&path),
                    "leftover identity temporary file {}",
                    path.display()
                );
                if file_type.is_file() && !recorded {
                    ensure!(
                        !contains_pkcs8_material(&std::fs::read(&path)?),
                        "unrecorded PKCS#8 private key in {}",
                        path.display()
                    );
                }
                if documented.contains(&path) {
                    ensure!(
                        file_type.is_file(),
                        "documented identity file {} is not a file",
                        path.display()
                    );
                } else if temporary {
                    eprintln!("WARN temporary file of an interrupted record write {}", path.display());
                } else {
                    eprintln!("WARN unknown identity file {}", path.display());
                }
            }
        }
        Ok(())
    }

    fn file_keys_with_prefix(&self) -> anyhow::Result<HashSet<String>> {
        let dir = self.path.join("identity").join("keys");
        let mut keys = HashSet::new();
        if dir.exists() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let file_name = entry.file_name();
                let Some(name) = file_name.to_str().and_then(|name| name.strip_suffix(".p8")) else {
                    continue;
                };
                if key_belongs_to_run(name, self.key_name_prefix) {
                    ensure!(
                        entry.file_type()?.is_file(),
                        "key file {} is not a regular file",
                        entry.path().display()
                    );
                    keys.insert(name.to_owned());
                }
            }
        }
        Ok(keys)
    }

    /// Every key that an `identity.json` slot or an in-progress record names, with the key storage it records.
    ///
    /// Each slot and record must name a well-formed key storage ([agent intent], "Stored identities").
    ///
    /// [agent intent]: ../../agent-identity/INTENT.md#stored-identities
    fn recorded_keys(&self) -> anyhow::Result<HashSet<RecordedKey>> {
        let mut recorded = HashSet::new();
        let authorities = self.path.join("identity").join("authorities");
        if authorities.exists() {
            for authority in std::fs::read_dir(authorities)? {
                let authority = authority?;
                if !authority.file_type()?.is_dir() || !canonical_authority_dir(&authority.path()) {
                    continue;
                }
                let path = authority.path().join("identity.json");
                if path.exists() {
                    let state: Value = serde_json::from_slice(&std::fs::read(&path)?)
                        .with_context(|| format!("read {}", path.display()))?;
                    for slot in ["current", "pending", "previous"] {
                        let stored = &state["keys"][slot];
                        if let Some(name) = stored["key_name"].as_str() {
                            validate_key_name(self.key_name_prefix, name)?;
                            let storage = recorded_storage(stored)
                                .with_context(|| format!("{slot} slot of {}", path.display()))?;
                            recorded.insert(RecordedKey::new(name, storage));
                        }
                    }
                }
            }
        }
        for token in self.tokens {
            if let Some(progress) = self.in_progress_for(token)? {
                recorded.insert(RecordedKey::new(
                    field(&progress, "key_name")?,
                    recorded_storage(&progress)?,
                ));
            }
        }
        Ok(recorded)
    }

    /// Every existing key with the run's prefix, in each key storage the suite can list.
    fn existing_keys(&self) -> anyhow::Result<HashSet<RecordedKey>> {
        let mut existing = self
            .file_keys_with_prefix()?
            .into_iter()
            .map(|name| RecordedKey::new(&name, key_storage::FILE))
            .collect::<HashSet<_>>();
        #[cfg(windows)]
        existing.extend(
            crate::windows::machine_keys_with_prefix(self.key_name_prefix)?
                .into_iter()
                .map(|name| RecordedKey::new(&name, key_storage::WINDOWS_SOFTWARE_PROVIDER)),
        );
        Ok(existing)
    }

    /// Fails for each key with the run's prefix that no record names with its key storage, since the agent records each key with its storage before creating it ([agent intent], "Stored identities").
    ///
    /// [agent intent]: ../../agent-identity/INTENT.md#stored-identities
    pub(crate) fn audit_orphan_keys(&self) -> anyhow::Result<()> {
        let recorded = self.recorded_keys()?;
        let mut orphaned = self
            .existing_keys()?
            .difference(&recorded)
            .map(|key| format!("{} in {}", key.name, key.storage))
            .collect::<Vec<_>>();
        orphaned.sort_unstable();
        ensure!(
            orphaned.is_empty(),
            "unrecorded identity keys with run prefix: {}",
            orphaned.join(", ")
        );
        Ok(())
    }

    fn audit_stored_keys(&self) -> anyhow::Result<()> {
        let authorities = self.path.join("identity").join("authorities");
        if !authorities.exists() {
            return Ok(());
        }
        for authority in std::fs::read_dir(authorities)? {
            let authority = authority?;
            if !authority.file_type()?.is_dir() || !canonical_authority_dir(&authority.path()) {
                continue;
            }
            let path = authority.path().join("identity.json");
            if path.exists() {
                let state: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                let id = field(&state, "authority_id")?;
                self.check_key_protection(id, &state, false)?;
            }
        }
        Ok(())
    }

    /// Checks every key that `state` names and that exists.
    ///
    /// The agent records a key's name before it creates the key, and deletes the key before it removes the name ([agent intent], "Stored identities"), so a record can name a key that does not exist.
    /// A missing key fails only as the current key of a settled identity (`require_current`) that the stored identity still names as current.
    /// When the stored identity names another current key, a renewal has retired the missing one, and the check runs again on the stored identity.
    ///
    /// [agent intent]: ../../agent-identity/INTENT.md#stored-identities
    pub(crate) fn check_key_protection(
        &self,
        authority_id: &str,
        state: &Value,
        require_current: bool,
    ) -> anyhow::Result<()> {
        // Each further read needs another renewal to have retired the current key meanwhile, and the agent renews at most every few seconds.
        const READS: usize = 3;

        let mut latest;
        let mut state = state;
        for _ in 0..READS {
            if require_current {
                ensure!(
                    state["keys"]["current"]["key_name"].is_string(),
                    "settled identity has no current key name"
                );
            }
            let mut missing_current = None;
            for slot in ["current", "pending", "previous"] {
                let Some(name) = state["keys"][slot]["key_name"].as_str() else {
                    continue;
                };
                let exists = self.check_key_if_exists(slot, name, &state["keys"][slot])?;
                if !exists && require_current && slot == "current" {
                    missing_current = Some(name.to_owned());
                }
            }
            let Some(missing) = missing_current else {
                return Ok(());
            };
            latest = self.state(authority_id)?;
            ensure!(
                latest["keys"]["current"]["key_name"] != missing,
                "settled current key {missing} is missing"
            );
            state = &latest;
        }
        anyhow::bail!("settled current key changed on each of {READS} reads of the stored identity")
    }

    /// Checks the key `name` that `slot` stores in the key storage it records, and returns `false` if the key does not exist there.
    fn check_key_if_exists(&self, slot: &str, name: &str, stored: &Value) -> anyhow::Result<bool> {
        validate_key_name(self.key_name_prefix, name)?;
        let storage = recorded_storage(stored).with_context(|| format!("stored {slot} slot"))?;
        match self.check_key(slot, name, storage, expected_spki(stored)?.as_deref()) {
            // UNTESTED: a key deleted during its checks counts as missing, not as a failed check.
            // Each check opens the key again, and a key deleted in between fails that check in a backend-specific way; the agent deletes keys during every renewal.
            // When changing the checks, keep attributing a failure to the deletion only when the key is gone afterwards.
            Err(_) if !self.key_exists_in(name, storage)? => Ok(false),
            checked => checked,
        }
    }

    /// Whether the key `name` exists in `storage`; a storage that the suite cannot inspect on this platform holds none.
    fn key_exists_in(&self, name: &str, storage: &str) -> anyhow::Result<bool> {
        validate_key_name(self.key_name_prefix, name)?;
        match storage {
            key_storage::FILE => Ok(self.key_file_path(name).exists()),
            #[cfg(windows)]
            key_storage::WINDOWS_SOFTWARE_PROVIDER => crate::windows::machine_key_exists(name),
            _ => Ok(false),
        }
    }

    /// Whether the key `name` exists in any key storage the suite can inspect.
    fn key_exists_anywhere(&self, name: &str) -> anyhow::Result<bool> {
        Ok(self.key_exists_in(name, key_storage::FILE)?
            || self.key_exists_in(name, key_storage::WINDOWS_SOFTWARE_PROVIDER)?)
    }

    /// Checks the key `name` that `slot` stores in `storage` against `expected_spki`, and returns `false` if the key does not exist there.
    ///
    /// A storage that the suite cannot inspect on this platform holds no key.
    pub(crate) fn check_key(
        &self,
        slot: &str,
        name: &str,
        storage: &str,
        expected_spki: Option<&[u8]>,
    ) -> anyhow::Result<bool> {
        #[cfg(windows)]
        if storage == key_storage::WINDOWS_SOFTWARE_PROVIDER {
            if !crate::windows::machine_key_exists(name)? {
                return Ok(false);
            }
            crate::windows::assert_non_exportable(name)?;
            crate::windows::assert_machine_key_acl(name)?;
            if let Some(expected) = expected_spki {
                let key = VerifyingKey::from_sec1_bytes(&crate::windows::machine_public_key(name)?)?;
                ensure!(
                    key.to_public_key_der()?.as_bytes() == expected,
                    "{slot} machine key does not match its leaf SPKI"
                );
            }
            return Ok(true);
        }
        #[cfg(any(unix, windows))]
        if storage == key_storage::FILE {
            let path = self.key_file_path(name);
            if !path.exists() {
                return Ok(false);
            }
            #[cfg(unix)]
            assert_file_key_access(&path)?;
            if let Some(expected) = expected_spki {
                let key = SigningKey::from_pkcs8_der(&std::fs::read(&path)?)?;
                ensure!(
                    key.verifying_key().to_public_key_der()?.as_bytes() == expected,
                    "{slot} file key does not match its leaf SPKI"
                );
            }
            return Ok(true);
        }
        #[cfg(not(any(unix, windows)))]
        let _ = (slot, name, expected_spki);
        Ok(false)
    }

    /// Checks that no file under `root`, other than `excluded` and the pending-enrollment files, holds a fragment of a token.
    pub(crate) fn audit_tokens(&self, root: &Path, excluded: Option<&Path>) -> anyhow::Result<()> {
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if excluded == Some(path.as_path())
                    || self.tokens.iter().any(|token| path == self.pending_path_for(token))
                {
                    continue;
                }
                let contents = std::fs::read(&path)?;
                for token in self.tokens {
                    assert_no_token_fragments(&contents, token, &path)?;
                }
            }
        }
        Ok(())
    }
}

struct AgentCase {
    ctx: Context,
    dir: tempfile::TempDir,
    child: Option<Child>,
    #[cfg(windows)]
    job: Option<crate::windows::AgentJob>,
    #[cfg(unix)]
    process_group: Option<i32>,
    tokens: Vec<String>,
    metadata_hostname: String,
    cleaned: bool,
    /// Whether dropping the case keeps its directory, with the agent's logs, as evidence: until the case passes, since a timeout drops it mid-test.
    keep: bool,
}

impl AgentCase {
    async fn new(ctx: Context, renewal_after_secs: Option<u64>, run: bool) -> anyhow::Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix(DATA_DIR_PREFIX)
            .rand_bytes(DATA_DIR_RANDOM_LEN)
            .tempdir_in(&ctx.work_dir)
            .context("create agent data dir")?;
        let metadata_hostname = "conformance-initial".to_owned();
        let metadata_override_path = dir.path().join("identity-metadata-override.json");
        std::fs::write(
            &metadata_override_path,
            serde_json::to_vec(&json!({ "hostname": metadata_hostname }))?,
        )?;
        let mut identity_debug = json!({
            "disable_jitter": true,
            "backoff_max_secs": 2,
            "pending_poll_interval_ms": 200,
            "check_in_interval_secs": 5,
            "channel_failure_check_in_after_secs": 3,
            "key_name_prefix": &ctx.key_name_prefix,
            "metadata_override_path": metadata_override_path
        });
        if let Some(seconds) = renewal_after_secs {
            identity_debug["renewal_after_secs"] = json!(seconds);
        }
        let first_root = ctx.target.ca_path.as_deref();
        let second_root = ctx.second.as_ref().and_then(|second| second.target.ca_path.as_deref());
        match (first_root, second_root) {
            (Some(first), Some(second)) => {
                let mut roots = std::fs::read(first)?;
                roots.push(b'\n');
                roots.extend_from_slice(&std::fs::read(second)?);
                let combined = dir.path().join("trusted-roots.pem");
                std::fs::write(&combined, roots)?;
                identity_debug["extra_trusted_root"] = json!(combined);
            }
            (Some(path), None) | (None, Some(path)) => {
                identity_debug["extra_trusted_root"] = json!(path);
            }
            (None, None) => {}
        }
        #[cfg(windows)]
        {
            identity_debug["acl_grant_current_user"] = json!(true);
        }
        let config = json!({
            "Identity": { "Enabled": true },
            "__debug__": {
                "log_directives": "debug,h2=info,hyper=info,rustls=info",
                "identity": identity_debug
            }
        });
        std::fs::write(dir.path().join("agent.json"), serde_json::to_vec_pretty(&config)?)?;
        let mut case = Self {
            ctx,
            dir,
            child: None,
            #[cfg(windows)]
            job: None,
            #[cfg(unix)]
            process_group: None,
            tokens: Vec::new(),
            metadata_hostname,
            cleaned: false,
            keep: true,
        };
        if run {
            case.start().await?;
        }
        Ok(case)
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn data_dir(&self) -> DataDir<'_> {
        DataDir {
            path: self.path(),
            key_name_prefix: &self.ctx.key_name_prefix,
            tokens: &self.tokens,
            leftover_key_copies: true,
        }
    }

    fn pending_path_for(&self, token: &str) -> PathBuf {
        self.data_dir().pending_path_for(token)
    }

    fn pending_path(&self) -> PathBuf {
        self.pending_path_for(self.tokens.last().expect("pending token is tracked"))
    }

    fn identity_path(&self, authority_id: &str) -> PathBuf {
        self.data_dir().identity_path(authority_id)
    }

    fn in_progress_path_for(&self, token: &str) -> PathBuf {
        self.data_dir().in_progress_path_for(token)
    }

    fn in_progress_path(&self) -> PathBuf {
        self.in_progress_path_for(self.tokens.last().expect("pending token is tracked"))
    }

    fn rejection_path_for(&self, token: &str) -> PathBuf {
        self.path()
            .join("identity")
            .join("rejected")
            .join(format!("{}.json", token_file_id(token)))
    }

    fn metadata_override_path(&self) -> PathBuf {
        self.path().join("identity-metadata-override.json")
    }

    fn set_metadata_hostname(&mut self, hostname: &str) -> anyhow::Result<()> {
        self.set_metadata_override(&json!({ "hostname": hostname }))?;
        self.metadata_hostname = hostname.to_owned();
        Ok(())
    }

    /// Replaces the metadata override with `values`, which the agent reads before its next send.
    ///
    /// It leaves `metadata_hostname`, the hostname that the metadata checks expect, to the caller.
    fn set_metadata_override(&self, values: &Value) -> anyhow::Result<()> {
        let replacement = self.path().join("identity-metadata-override-next.json");
        std::fs::write(&replacement, serde_json::to_vec(values)?)?;
        std::fs::rename(&replacement, self.metadata_override_path())?;
        Ok(())
    }

    #[cfg(windows)]
    fn set_acl_grant_current_user(&mut self, allowed: bool) -> anyhow::Result<()> {
        ensure!(
            self.child.is_none(),
            "key ACL setting must be set before starting the agent"
        );
        let path = self.path().join("agent.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        config["__debug__"]["identity"]["acl_grant_current_user"] = json!(allowed);
        std::fs::write(path, serde_json::to_vec_pretty(&config)?)?;
        Ok(())
    }

    /// Raises the agent's maximum retry delay, which also caps how long it honors `Retry-After`
    /// (CONTRACT.agent-identity.md §5.4).
    fn set_backoff_max_secs(&mut self, secs: u64) -> anyhow::Result<()> {
        ensure!(
            self.child.is_none(),
            "the retry cap must be set before starting the agent"
        );
        let path = self.path().join("agent.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        config["__debug__"]["identity"]["backoff_max_secs"] = json!(secs);
        std::fs::write(path, serde_json::to_vec_pretty(&config)?)?;
        Ok(())
    }

    /// Replaces the agent's 10-minute wait between renewals of one identity with `secs` seconds, 0 removing it (`devolutions-agent/src/identity/INTENT.md`, "Configuration").
    fn set_min_renewal_interval_secs(&mut self, secs: u64) -> anyhow::Result<()> {
        ensure!(
            self.child.is_none(),
            "the wait between renewals must be set before starting the agent"
        );
        let path = self.path().join("agent.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        config["__debug__"]["identity"]["min_renewal_interval_secs"] = json!(secs);
        std::fs::write(path, serde_json::to_vec_pretty(&config)?)?;
        Ok(())
    }

    /// Removes the renewal schedule override, so the agent renews at its scheduled time again.
    fn clear_renewal_after_secs(&mut self) -> anyhow::Result<()> {
        ensure!(
            self.child.is_none(),
            "the renewal schedule must be set before starting the agent"
        );
        let path = self.path().join("agent.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        config["__debug__"]["identity"]
            .as_object_mut()
            .context("agent configuration has no identity debug settings")?
            .remove("renewal_after_secs");
        std::fs::write(path, serde_json::to_vec_pretty(&config)?)?;
        Ok(())
    }

    /// Sets the agent's `__debug__.identity` setting `name` to `value`, which the agent reads when it starts.
    fn set_identity_debug(&mut self, name: &str, value: Value) -> anyhow::Result<()> {
        ensure!(
            self.child.is_none(),
            "identity debug settings must be set before starting the agent"
        );
        let path = self.path().join("agent.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        config["__debug__"]["identity"][name] = value;
        std::fs::write(path, serde_json::to_vec_pretty(&config)?)?;
        Ok(())
    }

    fn key_file_path(&self, name: &str) -> PathBuf {
        self.data_dir().key_file_path(name)
    }

    fn in_progress(&self) -> anyhow::Result<Option<Value>> {
        self.in_progress_for(self.tokens.last().expect("pending token is tracked"))
    }

    fn in_progress_for(&self, token: &str) -> anyhow::Result<Option<Value>> {
        self.data_dir().in_progress_for(token)
    }

    fn state(&self, authority_id: &str) -> anyhow::Result<Value> {
        self.data_dir().state(authority_id)
    }

    fn has_stored_identity(&self) -> anyhow::Result<bool> {
        let authorities = self.path().join("identity").join("authorities");
        if !authorities.exists() {
            return Ok(false);
        }
        for entry in std::fs::read_dir(authorities)? {
            if entry?.path().join("identity.json").exists() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn add_token(&mut self, token: &str) {
        self.tokens.push(token.to_owned());
    }

    fn observe_agent_metadata(&self, record: &IdentityRecord) -> anyhow::Result<()> {
        validate_agent_metadata(
            &serde_json::to_value(&record.metadata)?,
            self.ctx.agent_version.as_deref(),
            &host_machine_id(),
        )
    }

    /// The identity's full management API record, after checking the agent metadata it reports.
    async fn identity_record(&mut self, target: &Target, identity_id: &str) -> anyhow::Result<IdentityRecord> {
        let record = target.management().identity(identity_id).await?;
        self.observe_agent_metadata(&record)?;
        Ok(record)
    }

    /// Like [`Self::identity_record`], but `None` once the identity no longer exists.
    async fn find_identity_record(
        &mut self,
        target: &Target,
        identity_id: &str,
    ) -> anyhow::Result<Option<IdentityRecord>> {
        let record = target.management().find_identity(identity_id).await?;
        if let Some(record) = &record {
            self.observe_agent_metadata(record)?;
        }
        Ok(record)
    }

    fn write_pending(&mut self, token: &str) -> anyhow::Result<()> {
        self.add_token(token);
        let path = self.pending_path();
        let parent = path.parent().context("pending parent")?;
        // Some cases write a pending file before the agent's first start, and the agent refuses identity directories owned by another account.
        #[cfg(windows)]
        crate::windows::create_protected_dirs(parent)?;
        #[cfg(not(windows))]
        std::fs::create_dir_all(parent)?;
        write_pending_file(&path, &serde_json::to_vec(&json!({ "version": 1, "token": token }))?)?;
        #[cfg(windows)]
        crate::windows::pending_acl_is_protected(&path)?;
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        ensure!(self.child.is_none(), "agent is already running");
        let stdout = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path().join("agent-stdout.log"))?;
        let stderr = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path().join("agent-stderr.log"))?;
        let mut command = Command::new(&self.ctx.agent_bin);
        command
            .arg("run")
            .env("DAGENT_CONFIG_PATH", self.path())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.as_std_mut().process_group(0);
        }
        let process = command.spawn().context("spawn devolutions-agent run")?;
        #[cfg(windows)]
        let mut process = process;
        #[cfg(windows)]
        {
            let pid = process.id().context("agent has no process ID")?;
            match crate::windows::AgentJob::attach(pid) {
                Ok(job) => self.job = Some(job),
                Err(error) => {
                    let _ = process.kill().await;
                    let _ = process.wait().await;
                    return Err(error.context("attach agent to kill-on-close job"));
                }
            }
        }
        #[cfg(unix)]
        {
            self.process_group = Some(i32::try_from(process.id().context("agent has no process ID")?)?);
        }
        self.child = Some(process);
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        self.kill_process_tree();
        if let Some(mut child) = self.child.take() {
            if child.try_wait()?.is_none() {
                child.kill().await.context("stop agent")?;
            }
            let _ = child.wait().await;
        }
        Ok(())
    }

    fn kill_process_tree(&mut self) {
        #[cfg(windows)]
        drop(self.job.take());
        #[cfg(unix)]
        if let Some(group) = self.process_group.take() {
            // SAFETY: The agent was spawned as the leader of this new process group.
            let _ = unsafe { libc::kill(-group, libc::SIGKILL) };
        }
    }

    fn check_running(&mut self) -> anyhow::Result<()> {
        if let Some(child) = self.child.as_mut()
            && let Some(status) = child.try_wait()?
        {
            anyhow::bail!("agent exited before observing identity state ({status})");
        }
        Ok(())
    }

    /// Creates a token with `uses` uses, writes its pending-enrollment file, and waits until the agent enrolls with it.
    async fn enroll_new(&mut self, target: &Target, uses: u64) -> anyhow::Result<(String, Value)> {
        let token = new_token(self, uses).await?;
        self.write_pending(&token.text)?;
        self.enrolled(target, &token).await
    }

    async fn enrolled(&mut self, target: &Target, token: &Token) -> anyhow::Result<(String, Value)> {
        Ok(poll!(
            self,
            WAIT,
            POLL,
            "agent did not enroll and persist an identity within 20 seconds",
            async {
                let listing = target
                    .management()
                    .identities(&IdentityQuery::enrolled_with(token).full())
                    .await?;
                if let [record] = listing.items.as_slice() {
                    let id = record.id.clone();
                    let identity_dir = self.path().join("identity").join("authorities");
                    if identity_dir.exists() {
                        for path in std::fs::read_dir(identity_dir)? {
                            let authority = path?;
                            let json_path = authority.path().join("identity.json");
                            if json_path.exists() {
                                let state: Value = serde_json::from_slice(&std::fs::read(json_path)?)?;
                                if state["identity_id"] == id && !self.pending_path_for(&token.text).exists() {
                                    ensure!(
                                        slot_key_exists(self, &state, "current")?,
                                        "settled enrollment has no current identity key in its recorded key storage"
                                    );
                                    self.observe_agent_metadata(record)?;
                                    if let Some(known) = target.authority_id {
                                        ensure!(
                                            state["authority_id"] == known.to_string(),
                                            "agent stored an unexpected authority ID"
                                        );
                                    }
                                    return Ok(Some((id, state)));
                                }
                            }
                        }
                    }
                }
                Ok(None)
            },
        ))
    }

    async fn until_identity<F>(
        &mut self,
        target: &Target,
        identity_id: &str,
        what: &str,
        check: F,
    ) -> anyhow::Result<IdentityRecord>
    where
        F: Fn(&IdentityRecord) -> bool,
    {
        self.until_identity_within(target, identity_id, what, WAIT, check).await
    }

    /// Like [`Self::until_identity`], but waits up to `wait`.
    async fn until_identity_within<F>(
        &mut self,
        target: &Target,
        identity_id: &str,
        what: &str,
        wait: Duration,
        check: F,
    ) -> anyhow::Result<IdentityRecord>
    where
        F: Fn(&IdentityRecord) -> bool,
    {
        Ok(poll!(
            self,
            wait,
            POLL,
            format!("agent did not reach {what} within {} seconds", wait.as_secs()),
            async {
                if let Some(record) = self.find_identity_record(target, identity_id).await?
                    && check(&record)
                {
                    return Ok(Some(record));
                }
                Ok(None)
            },
        ))
    }

    async fn until_pending_deleted(
        &mut self,
        target: &Target,
        pending: &str,
        attempted: &Token,
        expected_identities: u64,
        expected_uses: u64,
    ) -> anyhow::Result<()> {
        poll!(
            self,
            WAIT,
            POLL,
            "agent kept a permanently invalid pending token, in-progress record, key or identity",
            async {
                ensure!(
                    target.management().identity_count(attempted).await? == expected_identities,
                    "permanently invalid pending token changed its identity count"
                );
                ensure!(
                    target.management().token(&attempted.id).await?.used_count == expected_uses,
                    "permanently invalid pending token consumed a use"
                );
                #[cfg(windows)]
                let machine_keys_gone = crate::windows::machine_keys_with_prefix(&self.ctx.key_name_prefix)?.is_empty();
                #[cfg(not(windows))]
                let machine_keys_gone = true;
                if !self.pending_path_for(pending).exists()
                    && !self.in_progress_path_for(pending).exists()
                    && self.rejection_path_for(pending).exists()
                    && !self.has_stored_identity()?
                    && self.data_dir().file_keys_with_prefix()?.is_empty()
                    && machine_keys_gone
                {
                    let marker: Value = serde_json::from_slice(&std::fs::read(self.rejection_path_for(pending))?)?;
                    ensure!(
                        marker["version"] == 1 && marker["token_sha256"] == token_file_id(pending),
                        "rejection marker has an invalid version or full-token hex hash"
                    );
                    time::OffsetDateTime::parse(field(&marker, "at")?, &Rfc3339)?;
                    return Ok(Some(()));
                }
                Ok(None)
            },
        );
        Ok(())
    }

    async fn until_rejected(
        &mut self,
        target: &Target,
        authority_id: &str,
        identity_id: &str,
        error: &str,
    ) -> anyhow::Result<Value> {
        Ok(poll!(
            self,
            WAIT,
            POLL,
            format!("agent did not persist rejected identity {error}"),
            async {
                let _ = self.find_identity_record(target, identity_id).await?;
                let state = self.state(authority_id)?;
                if state["rejected"]["code"] == error {
                    return Ok(Some(state));
                }
                Ok(None)
            },
        ))
    }

    async fn until_state<F>(
        &mut self,
        target: &Target,
        authority_id: &str,
        identity_id: &str,
        what: &str,
        check: F,
    ) -> anyhow::Result<Value>
    where
        F: Fn(&Value) -> bool,
    {
        Ok(poll!(
            self,
            WAIT,
            POLL,
            format!("agent did not persist {what} within 20 seconds"),
            async {
                let _ = self.find_identity_record(target, identity_id).await?;
                if let Ok(state) = self.state(authority_id)
                    && check(&state)
                {
                    return Ok(Some(state));
                }
                Ok(None)
            },
        ))
    }

    /// Waits until `done` holds for the agent's files, which the agent may still be changing after the authority answered.
    async fn until_files(&mut self, what: &str, done: impl Fn() -> bool) -> anyhow::Result<()> {
        poll!(
            self,
            WAIT,
            POLL,
            format!("agent did not complete {what} within 20 seconds"),
            async { Ok(done().then_some(())) },
        );
        Ok(())
    }

    /// Waits until the agent has deleted each token's pending file and in-progress record.
    ///
    /// On success the agent deletes both ([agent intent], "Pending-enrollment files"), but nothing orders their deletion before it stores the identity.
    ///
    /// [agent intent]: ../../agent-identity/INTENT.md#pending-enrollment-files
    async fn until_pending_consumed(&mut self, tokens: &[&Token]) -> anyhow::Result<()> {
        let paths = tokens
            .iter()
            .flat_map(|token| {
                [
                    self.pending_path_for(&token.text),
                    self.in_progress_path_for(&token.text),
                ]
            })
            .collect::<Vec<_>>();
        self.until_files("the deletion of the pending files and in-progress records", || {
            paths.iter().all(|path| !path.exists())
        })
        .await
    }

    async fn finish(&mut self) -> anyhow::Result<()> {
        let stopped = self.stop().await;
        let layout = self.data_dir().audit_identity_tree();
        let protected = self.data_dir().audit_stored_keys();
        let orphaned = self.data_dir().audit_orphan_keys();
        let tokens = self.audit_tokens();
        let cleaned = self.cleanup_run_keys();
        self.cleaned = cleaned.is_ok();
        stopped?;
        layout?;
        protected?;
        orphaned?;
        tokens?;
        cleaned
    }

    fn cleanup_run_keys(&self) -> anyhow::Result<()> {
        let files = self.data_dir().file_keys_with_prefix();
        #[cfg(windows)]
        let machine_cleanup = crate::windows::cleanup_machine_keys(&self.ctx.key_name_prefix);
        for name in files? {
            std::fs::remove_file(self.key_file_path(&name))
                .with_context(|| format!("delete run-owned file key {name}"))?;
        }
        #[cfg(windows)]
        machine_cleanup?;
        Ok(())
    }

    fn check_key_protection(&self, authority_id: &str, state: &Value) -> anyhow::Result<()> {
        self.data_dir().check_key_protection(authority_id, state, true)
    }

    fn audit_tokens(&self) -> anyhow::Result<()> {
        self.audit_tokens_excluding(None)
    }

    fn audit_tokens_excluding(&self, excluded: Option<&Path>) -> anyhow::Result<()> {
        self.data_dir().audit_tokens(self.path(), excluded)
    }
}

impl Drop for AgentCase {
    fn drop(&mut self) {
        self.kill_process_tree();
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            for _ in 0..100 {
                if child.try_wait().ok().flatten().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        if !self.cleaned {
            if let Err(error) = self.data_dir().audit_identity_tree() {
                eprintln!("agent-case identity tree audit failed: {error:#}");
            }
            if let Err(error) = self.data_dir().audit_orphan_keys() {
                eprintln!("agent-case orphan audit failed: {error:#}");
            }
            if let Err(error) = self.audit_tokens() {
                eprintln!("agent-case cleanup audit failed: {error:#}");
            }
            if let Err(error) = self.cleanup_run_keys() {
                eprintln!("agent-case key cleanup failed: {error:#}");
            }
        }
        if self.keep {
            // The run's keys are deleted above or by `finish`, and the path holds no secret.
            self.dir.disable_cleanup(true);
            println!("KEPT {} {}", self.ctx.test, self.path().display());
        }
    }
}

/// Runs `work` as one agent sub-case, with a new agent data directory that is audited once the agent stops.
///
/// On the mock, every sub-case starts from reset authorities, so it inherits no fault, setting, clock offset, barrier, token or identity from an earlier sub-case of the same test.
/// A sub-case therefore sets only the faults it needs and relies on the reset for every default.
/// DVLS has no reset, so an agent sub-case that runs on it changes no settings.
/// A sub-case that fails or times out keeps its directory, which [`AgentCase`]'s drop reports.
async fn with_agent(
    ctx: Context,
    renewal_after_secs: Option<u64>,
    run: bool,
    work: impl AsyncFnOnce(&mut AgentCase) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    reset_mocks(&ctx).await?;
    let mut case = AgentCase::new(ctx, renewal_after_secs, run).await?;
    let result = work(&mut case).await;
    let audit = case.finish().await;
    case.keep = result.is_err() || audit.is_err();
    match (result, audit) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(audit)) => anyhow::bail!("{error:#}; cleanup/audit: {audit:#}"),
    }
}

/// Writes a pending-enrollment file as an administrator does: DPAPI-protected on Windows, readable only by its owner on Unix.
fn write_pending_file(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    #[cfg(windows)]
    crate::windows::write_pending(path, contents)?;
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)?;
    }
    Ok(())
}

/// Resets each mock authority, the second one included, as `__mock__/reset` describes.
async fn reset_mocks(ctx: &Context) -> anyhow::Result<()> {
    if ctx.mock() {
        ctx.target.reset().await?;
        if let Some(second) = &ctx.second {
            second.target.reset().await?;
        }
    }
    Ok(())
}

async fn new_token(case: &AgentCase, uses: u64) -> anyhow::Result<Token> {
    case.ctx
        .target
        .management()
        .create_token(uses, Duration::from_secs(3600), None)
        .await
}

async fn dropped_enrollment(case: &mut AgentCase, token: &Token) -> anyhow::Result<(String, String)> {
    let target = case.ctx.target.clone();
    let before = count(&target.requests(Some(token)).await?, "enroll")?;
    expect_status(
        &target
            .control("retry-barrier", &json!({ "endpoint": "enroll", "pause": true }))
            .await?,
        200,
    )?;
    target.faults(&json!({ "drop_next_response": "enroll" })).await?;
    case.write_pending(&token.text)?;
    let mut unsettled = "agent did not commit a dropped-response enrollment and persist its key within 20 seconds";
    Ok(poll!(case, WAIT, POLL, unsettled, async {
        let requests = target.requests(Some(token)).await?;
        let attempts = count(&requests, "enroll")?;
        ensure!(
            attempts <= before + 1 + count(&requests, "enroll_retry_503")?,
            "agent retried enrollment successfully while the retry barrier was held"
        );
        let listing = target
            .management()
            .identities(&IdentityQuery::enrolled_with(token))
            .await?;
        let record = target.management().token(&token.id).await?;
        if listing.total_count == 1
            && record.used_count == 1
            && let Some(progress) = case.in_progress()?
        {
            ensure!(
                case.pending_path().exists(),
                "agent deleted the pending file before receiving a response"
            );
            ensure!(
                !case.has_stored_identity()?,
                "agent stored an identity before receiving a response"
            );
            ensure!(
                progress["token_sha256"] == token_file_id(&token.text),
                "in-progress enrollment has the wrong full-token hash"
            );
            let key = field(&progress, "key_name")?.to_owned();
            ensure!(
                case.data_dir().key_exists_in(&key, recorded_storage(&progress)?)?,
                "committed enrollment key is missing from its recorded key storage"
            );
            // The enrollment can commit between the counter and listing reads, and the mock's README orders neither its counters nor the fault's consumption before the commit, so wait for both.
            let consumed = target.control("faults", &json!({})).await?.body["drop_next_response"].is_null();
            if before < attempts && consumed {
                let id = listing
                    .items
                    .first()
                    .context("listing omitted the identity")?
                    .id
                    .clone();
                return Ok(Some((id, key)));
            }
            unsettled = if before < attempts {
                "the dropped enroll response fault was not consumed"
            } else {
                "enrollment committed without a recorded request"
            };
        }
        Ok(None)
    }))
}

async fn assert_terminal_stops(
    case: &mut AgentCase,
    target: &Target,
    authority: &str,
    identity_id: Option<&str>,
    error: &str,
    since: time::OffsetDateTime,
) -> anyhow::Result<()> {
    let first = case.state(authority)?;
    let at = field(&first["rejected"], "at")?.to_owned();
    let timestamp = time::OffsetDateTime::parse(&at, &Rfc3339)?;
    ensure!(
        timestamp >= since - time::Duration::seconds(2) && timestamp <= time::OffsetDateTime::now_utc(),
        "rejected.at was not newly set by this terminal error"
    );
    let counters = if case.ctx.mock() {
        Some(target.requests(None).await?)
    } else {
        None
    };
    let before_record = if let Some(id) = identity_id {
        Some(case.identity_record(target, id).await?)
    } else {
        None
    };
    for phase in 0..2 {
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            case.check_running()?;
            let state = case.state(authority)?;
            ensure!(
                state["rejected"]["code"] == error && state["rejected"]["at"] == at,
                "terminal rejection changed during backoff observation"
            );
            if let Some(before) = &counters {
                let after = target.requests(None).await?;
                ensure!(
                    after["renew"] == before["renew"]
                        && after["confirm"] == before["confirm"]
                        && after["check_in"] == before["check_in"]
                        && after["connect"] == before["connect"],
                    "rejected identity sent another signed request during backoff cycles"
                );
            }
            if let Some(id) = identity_id {
                let now = case.identity_record(target, id).await?;
                ensure!(
                    !now.connected
                        && before_record
                            .as_ref()
                            .is_some_and(|before| now.certificates == before.certificates),
                    "rejected identity reconnected or issued another certificate"
                );
            }
        }
        if phase == 0 {
            case.stop().await?;
            case.start().await?;
        }
    }
    Ok(())
}

fn assert_stored_identity(
    case: &AgentCase,
    token: &Token,
    state: &Value,
    record: &IdentityRecord,
) -> anyhow::Result<()> {
    ensure!(state["version"] == 1, "stored identity has wrong version");
    ensure!(
        state["identity_id"] == record.id,
        "stored identity has wrong identity ID"
    );
    let authority = field(state, "authority_id")?;
    ensure!(
        uuid::Uuid::parse_str(authority).is_ok(),
        "stored identity authority is not a UUID"
    );
    if let Some(known) = case.ctx.target.authority_id {
        ensure!(authority == known.to_string(), "stored identity has wrong authority ID");
    }
    ensure!(
        field(state, "base_url")? == case.ctx.target.base_url,
        "stored identity has wrong base URL"
    );
    let config = state["config"].as_object().context("stored identity config missing")?;
    ensure!(
        config.get("version") == Some(&json!(1)),
        "stored identity has wrong config version"
    );
    ensure!(
        config.get("revision").and_then(Value::as_u64).is_some(),
        "stored identity lacks config.revision"
    );
    if case.ctx.channel_available {
        let channel_url = field(&state["config"], "agent_channel_url")?;
        ensure!(
            reqwest::Url::parse(channel_url)?.scheme() == "https",
            "stored identity has an invalid config.agent_channel_url"
        );
        if case.ctx.mock() {
            ensure!(
                channel_url == case.ctx.target.base_url,
                "stored mock config.agent_channel_url does not match enrollment"
            );
        }
    } else {
        ensure!(
            config.get("agent_channel_url").is_none(),
            "unavailable config.agent_channel_url was stored"
        );
    }
    if case.ctx.mock() {
        let mut expected = json!({ "version": 1, "revision": config["revision"] });
        if case.ctx.channel_available {
            expected["agent_channel_url"] = json!(case.ctx.target.base_url);
        }
        ensure!(
            state["config"] == expected,
            "agent did not store the mock's enrollment config exactly"
        );
    }
    ensure!(state.get("rejected").is_none(), "new identity is already rejected");
    ensure!(
        state["token_sha256"] == token_file_id(&token.text),
        "stored identity has wrong full-token hash"
    );
    ensure!(
        record.metadata_value("hostname") == Some(&*case.metadata_hostname),
        "enrollment ignored the configured metadata hostname"
    );
    ensure!(
        state["keys"]["current"]["certificate_chain"]
            .as_array()
            .is_some_and(|chain| !chain.is_empty()),
        "stored identity has an empty current certificate chain"
    );
    // oracle: intent crates/agent-identity/INTENT.md §Key storage
    ensure!(
        state["keys"]["current"]["key_storage"] == key_storage::builtin_default(),
        "identity without a key storage policy has its current key outside {}",
        key_storage::builtin_default()
    );
    ensure!(
        slot_key_exists(case, state, "current")?,
        "enrolled identity's current key is missing from its recorded key storage"
    );
    let mut names = HashSet::new();
    for slot in ["current", "pending", "previous"] {
        if let Some(name) = state["keys"][slot]["key_name"].as_str() {
            validate_key_name(&case.ctx.key_name_prefix, name)
                .with_context(|| format!("stored {slot} key name is invalid"))?;
            ensure!(names.insert(name), "stored key slots refer to the same key");
            if let Some(chain) = state["keys"][slot]["certificate_chain"].as_array() {
                ensure!(!chain.is_empty(), "{slot} certificate chain is empty");
                ensure!(
                    chain.iter().all(|cert| cert.as_str().is_some()),
                    "{slot} certificate chain contains non-string entries"
                );
            }
        }
    }
    Ok(())
}

fn current_thumbprint(record: &IdentityRecord) -> anyhow::Result<&str> {
    record
        .certificate_with(CertificateStatus::Current)
        .map(|cert| cert.thumbprint.as_str())
        .context("no current certificate")
}

fn assert_check_in_triggers_renewal(requests: &Value, start: usize) -> anyhow::Result<()> {
    let sequence = requests["request_sequence"]
        .as_array()
        .context("mock request sequence missing")?;
    let steps = sequence
        .iter()
        .skip(start)
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let position = |name: &str| steps.iter().position(|step| *step == name);
    let (Some(check_in), Some(renew), Some(confirm)) = (position("check-in"), position("renew"), position("confirm"))
    else {
        anyhow::bail!("channelless request sequence omitted check-in, renew or confirm");
    };
    ensure!(
        check_in < renew && renew < confirm,
        "channelless renewal did not follow check-in → renew → confirm"
    );
    Ok(())
}

fn key_name<'a>(state: &'a Value, slot: &str) -> anyhow::Result<&'a str> {
    field(&state["keys"][slot], "key_name")
}

/// The thumbprint of the leaf stored on a key slot, or `None` while the slot holds no chain.
fn stored_leaf_thumbprint(state: &Value, slot: &str) -> anyhow::Result<Option<String>> {
    state["keys"][slot]["certificate_chain"][0]
        .as_str()
        .map(crate::signer::thumbprint)
        .transpose()
}

fn request_sequence(requests: &Value) -> anyhow::Result<&[Value]> {
    requests["request_sequence"]
        .as_array()
        .map(Vec::as_slice)
        .context("mock request sequence missing")
}

/// The renew and confirm attempts, with the mock's `confirm_204` markers, recorded after `earlier`.
///
/// Check-ins are left out: once a `confirm` has been answered, the contract does not order them against a renewal.
fn renew_and_confirm_steps_since<'a>(requests: &'a Value, earlier: &Value) -> anyhow::Result<Vec<&'a str>> {
    Ok(request_sequence(requests)?
        .iter()
        .skip(request_sequence(earlier)?.len())
        .filter_map(Value::as_str)
        .filter(|step| matches!(*step, "renew" | "confirm" | "confirm_204"))
        .collect())
}

fn renew_keyids(requests: &Value) -> anyhow::Result<&[Value]> {
    requests["renew_attempt_keyids"]
        .as_array()
        .map(Vec::as_slice)
        .context("mock renew signing-key trace missing")
}

/// The thumbprints that signed the renew attempts recorded after `earlier`, in order.
fn renew_keyids_since<'a>(requests: &'a Value, earlier: &Value) -> anyhow::Result<&'a [Value]> {
    Ok(renew_keyids(requests)?
        .get(renew_keyids(earlier)?.len()..)
        .unwrap_or_default())
}

/// Whether the key `name` exists in any key storage the suite can inspect.
fn key_exists(case: &AgentCase, name: &str) -> anyhow::Result<bool> {
    case.data_dir().key_exists_anywhere(name)
}

/// Whether the key that `slot` of `state` names exists in the key storage the slot records.
fn slot_key_exists(case: &AgentCase, state: &Value, slot: &str) -> anyhow::Result<bool> {
    let stored = &state["keys"][slot];
    case.data_dir()
        .key_exists_in(field(stored, "key_name")?, recorded_storage(stored)?)
}

#[cfg(unix)]
fn assert_file_key_access(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = std::fs::metadata(path)?;
    let mode = metadata.permissions().mode() & 0o777;
    ensure!(mode == 0o600, "{} has mode {mode:o}, expected 0600", path.display());
    // SAFETY: Calling geteuid reads the tester's effective uid, which the spawned agent inherits.
    let agent_uid = unsafe { libc::geteuid() };
    ensure!(
        metadata.uid() == agent_uid,
        "{} is owned by uid {}, expected agent uid {agent_uid}",
        path.display(),
        metadata.uid()
    );
    Ok(())
}

async fn wait_key_deleted(case: &mut AgentCase, name: &str) -> anyhow::Result<()> {
    poll!(
        case,
        WAIT,
        POLL,
        "old key survived successful identity replacement",
        async { Ok((!key_exists(case, name)?).then_some(())) },
    );
    Ok(())
}

/// The earliest moment the agent's schedule may renew a certificate issued after `issued_after` with `lifetime`, or `None` beyond the clock's range.
///
/// The agent renews `2/3 × lifetime` after the certificate's anchor ([agent intent], "Schedules"), and `disable_jitter` removes the jitter.
/// It sizes waits only, so it takes the anchor to be the issuance.
///
/// [agent intent]: ../../agent-identity/INTENT.md#schedules
fn earliest_renewal(issued_after: Instant, lifetime: Duration) -> Option<Instant> {
    issued_after.checked_add(lifetime.checked_mul(2)? / 3)
}

/// How long a step may take when the agent's schedule may renew a certificate issued after `issued_after` with `lifetime` during it.
///
/// The step gets [`WAIT`], plus another [`WAIT`] for the renewal when [`earliest_renewal`] comes before the first one ends: `WAIT × (1 + [issued_after + 2/3 × lifetime < now + WAIT])`.
/// It is a budget only: a test that waits with it asserts nothing about the renewal.
fn renewal_aware_wait(issued_after: Instant, lifetime: Duration) -> Duration {
    match earliest_renewal(issued_after, lifetime) {
        Some(renewal) if renewal < Instant::now() + WAIT => 2 * WAIT,
        _ => WAIT,
    }
}

/// Waits until the agent has stored a renewal that replaced `old_key`, holds no pending or previous key, and has deleted `old_key`.
///
/// The authority answers `confirm` before the agent stores its outcome and deletes the old key (`crates/agent-identity/INTENT.md`, "Stored identities"), so stopping the agent right after the `204` could interrupt those writes.
async fn until_renewal_settled(
    case: &mut AgentCase,
    target: &Target,
    authority: &str,
    identity_id: &str,
    old_key: &str,
) -> anyhow::Result<Value> {
    let state = case
        .until_state(target, authority, identity_id, "a settled renewal", |state| {
            key_name(state, "current").is_ok_and(|name| name != old_key)
                && state["keys"].get("pending").is_none()
                && state["keys"].get("previous").is_none()
        })
        .await?;
    wait_key_deleted(case, old_key).await?;
    Ok(state)
}

/// Fails if a file in the key store still holds a copy of the deleted key `name`.
///
/// No leftover copy of a private key survives a later operation in the same key store (`crates/device-key/INTENT.md`, "Operations"), so call this only after one.
fn assert_no_copy_of_deleted_key(case: &AgentCase, name: &str) -> anyhow::Result<()> {
    let keys = case.path().join("identity").join("keys");
    if !keys.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(keys)? {
        let file_name = entry?.file_name();
        ensure!(
            embedded_key_name(&file_name.to_string_lossy(), &case.ctx.key_name_prefix) != Some(name),
            "{} still holds a copy of deleted key {name} after a later key-store operation",
            file_name.to_string_lossy()
        );
    }
    Ok(())
}

async fn assert_new_auth_precedes_old_close(
    target: &Target,
    identity_id: &str,
    old_thumb: &str,
    new_thumb: &str,
) -> anyhow::Result<()> {
    let started = Instant::now();
    loop {
        let events = target.events(identity_id).await?;
        let confirmed = events.iter().find(|event| {
            event["type"] == "cert_status_changed" && event["cert_thumbprint"] == new_thumb && event["to"] == "current"
        });
        let new_auth = events
            .iter()
            .find(|event| event["type"] == "stream_authenticated" && event["cert_thumbprint"] == new_thumb);
        let old_close = events
            .iter()
            .find(|event| event["type"] == "stream_closed" && event["cert_thumbprint"] == old_thumb);
        if let (Some(confirmed), Some(new_auth), Some(old_close)) = (confirmed, new_auth, old_close) {
            ensure!(
                old_close["status"] == "OK"
                    && count(confirmed, "seq")? < count(new_auth, "seq")?
                    && count(new_auth, "seq")? < count(old_close, "seq")?,
                "confirm, new channel authentication and old stream close occurred out of order"
            );
            return Ok(());
        }
        ensure!(
            started.elapsed() < WAIT,
            "confirm, new authentication or old stream-closed event missing"
        );
        tokio::time::sleep(POLL).await;
    }
}

pub(crate) async fn a_pending_file_enroll_success(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let token = new_token(case, 2).await?;
        case.write_pending(&token.text)?;
        let (id, state) = case.enrolled(&target, &token).await?;
        ensure!(
            !case.pending_path().exists(),
            "pending file not deleted after enrollment"
        );
        let record = case.identity_record(&target, &id).await?;
        ensure!(record.id == id, "enrolled identity absent from the management API");
        assert_stored_identity(case, &token, &state, &record)?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_bad_pending_files_do_not_reject_valid_tokens(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let _ = case.enroll_new(&target, 1).await?;
        let token_a = new_token(case, 1).await?;
        let token_b = new_token(case, 1).await?;
        let token_c = new_token(case, 1).await?;
        case.add_token(&token_a.text);
        for (file_token, contents) in [
            (&token_b.text, json!({ "version": 1, "token": token_a.text })),
            (&token_c.text, json!({ "version": 2, "token": token_c.text })),
        ] {
            case.add_token(file_token);
            let path = case.pending_path_for(file_token);
            std::fs::create_dir_all(path.parent().context("pending directory")?)?;
            // Stage outside the watched directory so only the complete malformed record is observed.
            let staged = case
                .path()
                .join(format!("pending-fixture-{}.staged", uuid::Uuid::new_v4()));
            write_pending_file(&staged, &serde_json::to_vec(&contents)?)?;
            std::fs::rename(staged, &path)?;
            #[cfg(windows)]
            crate::windows::pending_acl_is_protected(&path)?;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        case.check_running()?;
        for (name, token) in [("A", &token_a), ("B", &token_b), ("C", &token_c)] {
            ensure!(
                !case.rejection_path_for(&token.text).exists(),
                "malformed pending file wrote a rejection marker for valid token {name}"
            );
        }
        case.stop().await?;
        for token in [&token_a, &token_b, &token_c] {
            case.write_pending(&token.text)?;
        }
        case.start().await?;
        poll!(
            case,
            WAIT,
            POLL,
            "correct pending files did not each enroll within 20 seconds",
            async {
                let mut all_enrolled = true;
                for (name, token) in [("A", &token_a), ("B", &token_b), ("C", &token_c)] {
                    ensure!(
                        !case.rejection_path_for(&token.text).exists(),
                        "pending file wrote a rejection marker for valid token {name}"
                    );
                    let identities = target.management().identity_count(token).await?;
                    let uses = target.management().token(&token.id).await?.used_count;
                    ensure!(
                        identities <= 1 && uses <= 1,
                        "correct pending token {name} created more than one identity"
                    );
                    all_enrolled &= identities == 1
                        && uses == 1
                        && !case.pending_path_for(&token.text).exists()
                        && !case.in_progress_path_for(&token.text).exists();
                }
                if all_enrolled {
                    return Ok(Some(()));
                }
                Ok(None)
            },
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_undecryptable_pending_file_does_not_reject_token(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[cfg(windows)]
    {
        return with_agent(ctx, None, false, async move |case| {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            let before = count(&target.requests(None).await?, "enroll_total")?;
            case.write_pending(&token.text)?;
            let pending = case.pending_path_for(&token.text);
            std::fs::write(&pending, b"not a DPAPI blob")?;
            crate::windows::pending_acl_is_protected(&pending)?;
            case.start().await?;
            poll!(
                case,
                WAIT,
                POLL,
                "agent did not delete the undecryptable pending file",
                async {
                    ensure!(
                        count(&target.requests(None).await?, "enroll_total")? == before,
                        "undecryptable pending file sent an enrollment request"
                    );
                    if !pending.exists() {
                        return Ok(Some(()));
                    }
                    Ok(None)
                },
            );
            ensure!(
                !case.rejection_path_for(&token.text).exists(),
                "undecryptable pending file wrote a rejection marker"
            );
            case.write_pending(&token.text)?;
            let _ = case.enrolled(&target, &token).await?;
            ensure!(
                !case.rejection_path_for(&token.text).exists()
                    && count(&target.requests(None).await?, "enroll_total")? == before + 1,
                "valid token did not enroll once after an undecryptable pending file"
            );
            Ok(())
        })
        .await;
    }
    #[cfg(not(windows))]
    {
        let _ = ctx;
        Err(crate::NotApplicable("DPAPI pending files require Windows").into())
    }
}

pub(crate) async fn a_untrusted_tls_server_keeps_pending_token(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: intent crates/agent-identity/INTENT.md §Trust and transport
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, false, async move |case| {
        let target = case.ctx.target.clone();
        let second = &case
            .ctx
            .second
            .as_ref()
            .context("second mock authority required")?
            .target;
        let root = second.ca_path.as_ref().context("second mock TLS CA required")?;
        let path = case.path().join("agent.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        config["__debug__"]["identity"]["extra_trusted_root"] = json!(root);
        std::fs::write(path, serde_json::to_vec_pretty(&config)?)?;
        let token = new_token(case, 1).await?;
        let before = count(&target.requests(None).await?, "enroll_total")?;
        case.start().await?;
        case.write_pending(&token.text)?;
        poll!(
            case,
            WAIT,
            POLL,
            "agent did not process the pending token for TLS validation",
            async {
                if case.in_progress_for(&token.text)?.is_some() {
                    return Ok(Some(()));
                }
                Ok(None)
            },
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        case.check_running()?;
        ensure!(
            count(&target.requests(None).await?, "enroll_total")? == before
                && case.pending_path_for(&token.text).exists()
                && !case.rejection_path_for(&token.text).exists(),
            "untrusted TLS did not preserve the processed pending token"
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_enroll_lost_response_retried_across_restart(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let token = new_token(case, 1).await?;
        let (id, key) = dropped_enrollment(case, &token).await?;
        case.stop().await?;
        let requests = target.requests(Some(&token)).await?;
        ensure!(
            count(&requests, "enroll")? == 1 + count(&requests, "enroll_retry_503")?,
            "agent received an enrollment retry before it could be restarted"
        );
        ensure!(
            case.in_progress()?
                .as_ref()
                .and_then(|record| record["key_name"].as_str())
                == Some(key.as_str())
                && case.pending_path().exists(),
            "pending enrollment key was not persisted across agent stop"
        );
        let before_restart = count(&requests, "enroll")?;
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "enroll", "pause": false }))
                .await?,
            200,
        )?;
        case.start().await?;
        let (recovered_id, state) = case.enrolled(&target, &token).await?;
        ensure!(recovered_id == id, "retry created a second identity");
        ensure!(
            count(&target.requests(Some(&token)).await?, "enroll")? > before_restart,
            "agent did not retry enrollment after restart"
        );
        ensure!(
            target.management().token(&token.id).await?.used_count == 1,
            "retry consumed a second token use"
        );
        ensure!(
            key_name(&state, "current")? == key,
            "agent did not reuse the in-progress key"
        );
        case.until_pending_consumed(&[&token]).await?;
        let record = case.identity_record(&target, &id).await?;
        assert_stored_identity(case, &token, &state, &record)?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_two_pending_tokens_same_authority_last_wins(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, false, async move |case| {
        // The first token's retry must wait out the second token's enrollment.
        case.set_backoff_max_secs(10)?;
        case.start().await?;
        let target = case.ctx.target.clone();
        let original_token = new_token(case, 1).await?;
        let replacement = new_token(case, 1).await?;
        target
            .faults(&json!({
                "fail_next_response": {
                    "endpoint": "enroll",
                    "status": 503,
                    "retry_after_secs": 8
                }
            }))
            .await?;
        case.write_pending(&original_token.text)?;
        let original_key = poll!(
            case,
            WAIT,
            POLL,
            "agent did not persist its first pending enrollment during transient backoff",
            async {
                if count(&target.requests(Some(&original_token)).await?, "enroll")? >= 1
                    && target.control("faults", &json!({})).await?.body["fail_next_response"].is_null()
                    && let Some(progress) = case.in_progress_for(&original_token.text)?
                {
                    let name = field(&progress, "key_name")?;
                    if key_exists(case, name)? {
                        return Ok(Some(name.to_owned()));
                    }
                }
                Ok(None)
            },
        );
        ensure!(
            case.pending_path_for(&original_token.text).exists(),
            "first pending file vanished during transient backoff"
        );
        case.write_pending(&replacement.text)?;
        let (replacement_id, replacement_state) = case.enrolled(&target, &replacement).await?;
        let replacement_key = key_name(&replacement_state, "current")?.to_owned();
        ensure!(
            replacement_key != original_key
                && replacement_state["token_sha256"] == token_file_id(&replacement.text)
                && case.pending_path_for(&original_token.text).exists()
                && case.in_progress_for(&original_token.text)?.is_some()
                && key_exists(case, &original_key)?,
            "second token displaced the first pending file or in-progress key"
        );
        let (original_id, state) = case.enrolled(&target, &original_token).await?;
        ensure!(
            original_id != replacement_id
                && state["token_sha256"] == token_file_id(&original_token.text)
                && key_name(&state, "current")? == original_key,
            "last completing token did not become the stored identity for its authority"
        );
        wait_key_deleted(case, &replacement_key).await?;
        case.until_pending_consumed(&[&original_token, &replacement]).await?;
        ensure!(
            target.management().identity_count(&original_token).await? == 1
                && target.management().identity_count(&replacement).await? == 1
                && target.management().token(&original_token.id).await?.used_count == 1
                && target.management().token(&replacement.id).await?.used_count == 1,
            "independent pending tokens were not both consumed"
        );
        let record = case.identity_record(&target, &original_id).await?;
        assert_stored_identity(case, &original_token, &state, &record)?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_two_pending_tokens_different_authorities_progress_independently(
    ctx: Context,
) -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    // oracle: intent crates/agent-identity/INTENT.md §Identities
    with_agent(ctx, None, false, async move |case| {
        // The first authority's retry must wait out the second authority's enrollment.
        case.set_backoff_max_secs(10)?;
        case.start().await?;
        let first = case.ctx.target.clone();
        let second = case.ctx.second.clone().context("second authority required")?.target;
        let first_token = first
            .management()
            .create_token(1, Duration::from_secs(3600), None)
            .await?;
        let second_token = second
            .management()
            .create_token(1, Duration::from_secs(3600), None)
            .await?;
        first
            .faults(&json!({
                "fail_next_response": {
                    "endpoint": "enroll",
                    "status": 503,
                    "retry_after_secs": 8
                }
            }))
            .await?;
        case.write_pending(&first_token.text)?;
        let first_key = poll!(
            case,
            WAIT,
            POLL,
            "first authority did not persist a pending key during transient backoff",
            async {
                if count(&first.requests(Some(&first_token)).await?, "enroll")? >= 1
                    && first.control("faults", &json!({})).await?.body["fail_next_response"].is_null()
                    && let Some(progress) = case.in_progress_for(&first_token.text)?
                {
                    let name = field(&progress, "key_name")?;
                    if key_exists(case, name)? {
                        return Ok(Some(name.to_owned()));
                    }
                }
                Ok(None)
            },
        );
        case.write_pending(&second_token.text)?;
        let (second_id, second_state) = case.enrolled(&second, &second_token).await?;
        ensure!(
            case.pending_path_for(&first_token.text).exists()
                && case.in_progress_for(&first_token.text)?.is_some()
                && key_exists(case, &first_key)?
                && key_name(&second_state, "current")? != first_key,
            "first authority backoff blocked or displaced the second pending token"
        );
        let (first_id, first_state) = case.enrolled(&first, &first_token).await?;
        case.until_pending_consumed(&[&first_token, &second_token]).await?;
        let first_authority = field(&first_state, "authority_id")?;
        let second_authority = field(&second_state, "authority_id")?;
        ensure!(
            first_authority != second_authority
                && first_state["identity_id"] == first_id
                && second_state["identity_id"] == second_id
                && case.state(first_authority)?["identity_id"] == first_id
                && case.state(second_authority)?["identity_id"] == second_id
                && first.management().token(&first_token.id).await?.used_count == 1
                && second.management().token(&second_token.id).await?.used_count == 1,
            "independent authorities did not both enroll and retain their keys"
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_enroll_revoked_before_response_is_permanent(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let token = new_token(case, 1).await?;
        let (id, key) = dropped_enrollment(case, &token).await?;
        target.management().revoke(&id).await?;
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "enroll", "pause": false }))
                .await?,
            200,
        )?;
        let mut unmet = String::new();
        let attempts = poll!(
            case,
            WAIT,
            POLL,
            format!(
                "agent did not remove the revoked enrollment, in-progress record and key within 20 seconds (unmet: {unmet})"
            ),
            async {
                let requests = target.requests(Some(&token)).await?;
                let attempts = count(&requests, "enroll")?;
                let rejections = count(&requests, "enroll_identity_revoked")?;
                ensure!(
                    rejections <= 1,
                    "agent retried enrollment again after receiving identity_revoked"
                );
                let conditions = [
                    (rejections == 1, "identity_revoked recorded"),
                    (!case.pending_path().exists(), "pending file deleted"),
                    (!case.in_progress_path().exists(), "in-progress record deleted"),
                    (!key_exists(case, &key)?, "enrollment key deleted"),
                    (!case.has_stored_identity()?, "no identity stored"),
                ];
                if conditions.iter().all(|(met, _)| *met) {
                    return Ok(Some(attempts));
                }
                unmet = conditions
                    .iter()
                    .filter_map(|(met, name)| (!met).then_some(*name))
                    .collect::<Vec<_>>()
                    .join(", ");
                Ok(None)
            },
        );
        ensure!(attempts >= 2, "agent did not retry the revoked enrollment");
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            case.check_running()?;
            ensure!(
                count(&target.requests(Some(&token)).await?, "enroll")? == attempts,
                "agent sent another enrollment request after identity_revoked"
            );
        }
        case.stop().await?;
        case.start().await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        case.check_running()?;
        ensure!(
            count(&target.requests(Some(&token)).await?, "enroll")? == attempts
                && !case.pending_path().exists()
                && !case.in_progress_path().exists()
                && !key_exists(case, &key)?
                && !case.has_stored_identity()?,
            "permanently revoked enrollment resumed after restart"
        );
        ensure!(
            target.management().token(&token.id).await?.used_count == 1
                && target.management().identity_count(&token).await? == 1,
            "revoked enrollment created another identity or consumed another use"
        );
        let marker_path = case.rejection_path_for(&token.text);
        let marker: Value = serde_json::from_slice(
            &std::fs::read(&marker_path)
                .with_context(|| format!("read rejection marker {}", marker_path.display()))?,
        )?;
        ensure!(
            marker["code"] == "identity_revoked",
            "rejection marker records {} instead of identity_revoked",
            marker["code"]
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_pending_file_deleted_on_permanent_error(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    // Each case names the rejection code its marker records.
    for (reason, code) in [
        ("token_invalid", "token_invalid"),
        ("token_exhausted", "token_exhausted"),
        ("token_expired", "token_expired"),
        ("token_malformed", "token_malformed"),
        ("token_malformed, user name in u", "token_malformed"),
        ("token_malformed, empty user name in u", "token_malformed"),
        ("token_malformed, @ in the path of u", "token_malformed"),
        ("token_malformed, non-ASCII host in u", "token_malformed"),
    ] {
        if reason == "token_expired" && !ctx.mock() {
            continue;
        }
        with_agent(ctx.clone(), None, true, async move |case| {
            let target = case.ctx.target.clone();
            let token = new_token(case, 2).await?;
            // The rewritten token keeps the valid bag fields and secret, so only its new `u` can make it malformed.
            let rest = field(&token_bag(&token.text)?, "u")?
                .strip_prefix("https://")
                .context("token base URL is not https")?
                .to_owned();
            let issued = token.text.clone();
            let with_u = |u: String| with_bag_url(&issued, &u);
            let (pending, attempted, identities, used) = match reason {
                "token_invalid" => {
                    let (prefix, _) = token.text.rsplit_once('.').context("token structure")?;
                    (format!("{prefix}.{}", URL_SAFE_NO_PAD.encode([0x49; 32])), token, 0, 0)
                }
                "token_exhausted" => {
                    let once = target
                        .management()
                        .create_token(1, Duration::from_secs(3600), None)
                        .await?;
                    let key = crate::signer::KeyPair::generate()?;
                    expect_status(&target.enroll(&once.text, &key, &json!({})).await?, 200)?;
                    (once.text.clone(), once, 1, 1)
                }
                "token_expired" => {
                    let expiring = target
                        .management()
                        .create_token(1, Duration::from_secs(2), None)
                        .await?;
                    target.advance(4).await?;
                    (expiring.text.clone(), expiring, 0, 0)
                }
                "token_malformed" => {
                    let mut secret = [0u8; 32];
                    rand::rng().fill(&mut secret[..]);
                    (
                        format!("dvaet1.not-base64!.{}", URL_SAFE_NO_PAD.encode(secret)),
                        token,
                        0,
                        0,
                    )
                }
                "token_malformed, user name in u" => {
                    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
                    (with_u(format!("https://user@{rest}"))?, token, 0, 0)
                }
                "token_malformed, empty user name in u" => {
                    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
                    (with_u(format!("https://@{rest}"))?, token, 0, 0)
                }
                "token_malformed, @ in the path of u" => {
                    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
                    // `u` may carry a path, so the `@` lies outside the authority, where a URL parser sees no user name.
                    (
                        with_u(format!("https://{}/a@b", rest.trim_end_matches('/')))?,
                        token,
                        0,
                        0,
                    )
                }
                "token_malformed, non-ASCII host in u" => {
                    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
                    // `u` is ASCII, with an internationalized host in its `xn--` form, so that the certificates' `IA5String` can name it.
                    (with_u("https://bücher.example/x".to_owned())?, token, 0, 0)
                }
                _ => anyhow::bail!("unknown permanent error"),
            };
            let ingress = if code == "token_malformed" && case.ctx.mock() {
                Some(count(&target.requests(None).await?, "enroll_total")?)
            } else {
                None
            };
            case.write_pending(&pending)?;
            case.until_pending_deleted(&target, &pending, &attempted, identities, used)
                .await?;
            if let Some(before) = ingress {
                ensure!(
                    count(&target.requests(None).await?, "enroll_total")? == before,
                    "malformed token was sent to the server instead of rejected locally"
                );
            }
            let marker_path = case.rejection_path_for(&pending);
            let marker: Value = serde_json::from_slice(
                &std::fs::read(&marker_path)
                    .with_context(|| format!("read rejection marker {}", marker_path.display()))?,
            )?;
            ensure!(
                marker["code"] == code,
                "rejection marker records {} instead of {code}",
                marker["code"]
            );
            Ok(())
        })
        .await
        .with_context(|| format!("permanent error {reason}"))?;
    }
    Ok(())
}

pub(crate) async fn a_pending_file_kept_on_transient_error(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx.clone(), None, true, async move |case| {
        let target = case.ctx.target.clone();
        let token = new_token(case, 1).await?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let offline = with_bag_url(&token.text, &format!("https://127.0.0.1:{port}/mock"))?;
        case.write_pending(&offline)?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        ensure!(
            target.management().identity_count(&token).await? == 0,
            "unreachable enrollment created an identity"
        );
        ensure!(
            case.pending_path().exists(),
            "unreachable enrollment deleted the pending file"
        );
        case.check_running()?;
        Ok(())
    })
    .await?;
    if ctx.mock() {
        with_agent(ctx, None, true, async move |case| {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            let initial = count(&target.requests(Some(&token)).await?, "enroll")?;
            for (index, response) in [
                json!({ "endpoint": "enroll", "status": 503 }),
                json!({ "endpoint": "enroll", "status": 400, "error": "invalid_request" }),
                json!({ "endpoint": "enroll", "status": 429, "retry_after_secs": 3 }),
                json!({ "endpoint": "enroll", "status": 302 }),
                json!({ "endpoint": "enroll", "status": 503 }),
            ]
            .into_iter()
            .enumerate()
            {
                target.faults(&json!({ "fail_next_response": response })).await?;
                if index == 0 {
                    case.write_pending(&token.text)?;
                }
                poll!(
                    case,
                    WAIT,
                    POLL,
                    "agent did not retry the transient enrollment error",
                    async {
                        let attempts = count(&target.requests(Some(&token)).await?, "enroll")?;
                        ensure!(
                            attempts <= initial + index as u64 + 1,
                            "agent retried before the next transient response was configured"
                        );
                        if attempts == initial + index as u64 + 1
                            && target.control("faults", &json!({})).await?.body["fail_next_response"].is_null()
                        {
                            return Ok(Some(()));
                        }
                        Ok(None)
                    },
                );
                let observed_failure = Instant::now();
                ensure!(
                    case.pending_path().exists(),
                    "transient HTTP error deleted the pending file"
                );
                ensure!(
                    target.management().identity_count(&token).await? == 0
                        && target.management().token(&token.id).await?.used_count == 0,
                    "transient HTTP error created an identity or consumed a token use"
                );
                if response["retry_after_secs"] == 3 {
                    // Probe near the two-second cap without racing the next retry.
                    tokio::time::sleep_until((observed_failure + Duration::from_millis(1_700)).into()).await;
                    ensure!(
                        count(&target.requests(Some(&token)).await?, "enroll")? == initial + index as u64 + 1,
                        "agent retried before the capped Retry-After delay"
                    );
                }
                if response["status"] == 302 {
                    tokio::time::sleep(POLL).await;
                    ensure!(
                        count(&target.requests(None).await?, "redirect_hits")? == 0,
                        "agent followed the injected redirect"
                    );
                }
                case.check_running()?;
            }
            let _ = case.enrolled(&target, &token).await?;
            ensure!(
                target.management().token(&token.id).await?.used_count == 1,
                "retry consumed an additional token use"
            );
            ensure!(
                count(&target.requests(Some(&token)).await?, "enroll")? >= initial + 6,
                "agent did not survive five transient failures and retry successfully"
            );
            Ok(())
        })
        .await?;
    }
    Ok(())
}

/// CONTRACT.agent-identity.md §5.2: "The agent refuses, as a permanent outcome, a response whose leaf lacks the enrollment URL extension, carries it more than once or not as an `IA5String`, or whose value, read as text, is not its token's `u` without trailing slashes", which the agent records with the local marker code `authority_url_mismatch`.
///
/// A trailing slash or an upper-case scheme makes a value whose text is not the token's `u`, so the agent refuses it like another host.
/// The mock issues each leaf through its `malformed_enrollment_url` fault, which still creates the identity and counts the use, as a nonconforming authority would.
pub(crate) async fn a_enrollment_leaf_naming_another_url_refused(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    /// The fault value for a token whose `u` is the argument.
    type Fault = fn(&str) -> anyhow::Result<Value>;

    let cases: [(&str, Fault); 6] = [
        ("without the extension", |_| Ok(json!("missing"))),
        ("with the extension twice", |_| Ok(json!("repeated"))),
        ("with the URL as a UTF8String", |_| Ok(json!("not_ia5"))),
        ("naming another host", |_| {
            Ok(other_url("https://relay.invalid/mock".to_owned()))
        }),
        ("naming the URL with a trailing slash", |url| {
            Ok(other_url(format!("{url}/")))
        }),
        ("naming the URL with an upper-case scheme", |url| {
            Ok(other_url(with_upper_case_scheme(url)?))
        }),
    ];
    for (shape, fault) in cases {
        with_agent(ctx.clone(), None, true, async move |case| {
            let target = case.ctx.target.clone();
            let token = new_token(case, 2).await?;
            target
                .faults(&json!({ "malformed_enrollment_url": fault(&token_base_url(&token.text)?)? }))
                .await?;
            case.write_pending(&token.text)?;
            poll!(case, WAIT, POLL, "the mock did not enroll the agent", async {
                Ok((target.management().identity_count(&token).await? == 1).then_some(()))
            });
            case.until_pending_deleted(&target, &token.text, &token, 1, 1).await?;
            let marker_path = case.rejection_path_for(&token.text);
            let marker: Value = serde_json::from_slice(
                &std::fs::read(&marker_path)
                    .with_context(|| format!("read rejection marker {}", marker_path.display()))?,
            )?;
            ensure!(
                marker["code"] == "authority_url_mismatch",
                "rejection marker records {} instead of authority_url_mismatch",
                marker["code"]
            );
            ensure!(
                count(&target.requests(Some(&token)).await?, "enroll")? == 1,
                "agent retried the enrollment it refused permanently"
            );
            target.faults(&json!({ "malformed_enrollment_url": null })).await
        })
        .await
        .with_context(|| format!("enrollment leaf {shape}"))?;
    }
    return Ok(());

    fn other_url(url: String) -> Value {
        json!({ "other_url": url })
    }
}

/// A server holding another authority's token relays a device's enrollment from its own address, so the token's `u` names the relay, and so does the agent's CSR, which the authority refuses with `token_url_mismatch` ([CONTRACT.agent-identity.md] §4 "Certificates").
/// `token_url_mismatch` is permanent (§5.4 "Errors"), so the agent never retries the token, deletes its pending file, in-progress record and enrollment key, and records the code in a rejection marker, while the authority creates nothing.
///
/// The mock's TLS certificate names both `127.0.0.1` and `localhost`, and the mock never reads a token's bag, so the token rewritten to the other name reaches the same mock as a relay reaches the authority.
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
pub(crate) async fn a_relayed_enrollment_refused(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let token = new_token(case, 1).await?;
        let relay = if let Some(rest) = target.base_url.strip_prefix("https://127.0.0.1:") {
            format!("https://localhost:{rest}")
        } else if let Some(rest) = target.base_url.strip_prefix("https://localhost:") {
            format!("https://127.0.0.1:{rest}")
        } else {
            anyhow::bail!("the mock's base URL names neither 127.0.0.1 nor localhost");
        };
        let relayed = with_bag_url(&token.text, &relay)?;
        let initial = count(&target.requests(Some(&token)).await?, "enroll")?;
        case.write_pending(&relayed)?;
        case.until_pending_deleted(&target, &relayed, &token, 0, 0).await?;
        let marker_path = case.rejection_path_for(&relayed);
        let marker: Value = serde_json::from_slice(
            &std::fs::read(&marker_path).with_context(|| format!("read rejection marker {}", marker_path.display()))?,
        )?;
        ensure!(
            marker["code"] == "token_url_mismatch",
            "rejection marker records {} instead of token_url_mismatch",
            marker["code"]
        );
        ensure!(
            count(&target.requests(Some(&token)).await?, "enroll")? == initial + 1,
            "agent did not send the relayed enrollment exactly once"
        );
        // The agent's request reached the mock, and this one shows the answer it got.
        expect_error(
            &target
                .enroll(&relayed, &crate::signer::KeyPair::generate()?, &json!({}))
                .await?,
            403,
            "token_url_mismatch",
        )
        .context("the mock did not refuse a CSR naming the relay")?;
        case.check_running()
    })
    .await
}

/// Removes the ANSI escape sequences that colour the agent's console log, which it writes even when its output is a file.
fn without_ansi_escapes(line: &str) -> String {
    let mut plain = String::with_capacity(line.len());
    let mut characters = line.chars();
    while let Some(character) = characters.next() {
        if character != '\u{1b}' {
            plain.push(character);
            continue;
        }
        // A control sequence ends at its first byte in `@`..=`~` (ECMA-48 §5.4).
        if characters.next() == Some('[') {
            characters
                .by_ref()
                .find(|final_character| ('@'..='~').contains(final_character));
        }
    }
    plain
}

fn is_error_level_log_line(line: &str) -> bool {
    let line = without_ansi_escapes(line);
    if let Ok(entry) = serde_json::from_str::<Value>(&line) {
        return entry["level"]
            .as_str()
            .is_some_and(|level| level.eq_ignore_ascii_case("error"));
    }
    let levels = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
    line.split_whitespace()
        .take(3)
        .map(|field| field.trim_matches(&['[', ']', ':'][..]))
        .find(|field| levels.contains(field))
        == Some("ERROR")
}

async fn wait_for_injected_attempt(
    case: &mut AgentCase,
    target: &Target,
    counter: &str,
    before: u64,
) -> anyhow::Result<()> {
    poll!(
        case,
        WAIT,
        POLL,
        format!("{counter} did not receive the injected error"),
        async {
            let attempts = count(&target.requests(None).await?, counter)?;
            ensure!(
                attempts <= before + 1,
                "{counter} retried before the injected error was observed"
            );
            if attempts == before + 1
                && target.control("faults", &json!({})).await?.body["fail_next_response"].is_null()
            {
                return Ok(Some(()));
            }
            Ok(None)
        },
    );
    Ok(())
}

pub(crate) async fn a_renew_transient_failures_retry_without_state_change(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    // oracle: intent devolutions-agent/src/identity/INTENT.md §Configuration
    with_agent(ctx, None, false, async move |case| {
        let target = case.ctx.target.clone();
        // The three renewals follow one another in one run, faster than the agent's wait between renewals of one identity (`crates/agent-identity/INTENT.md`, "Schedules"), so the case removes that wait.
        case.set_min_renewal_interval_secs(0)?;
        case.start().await?;
        let (id, initial) = case.enroll_new(&target, 1).await?;
        let authority = field(&initial, "authority_id")?.to_owned();
        case.until_identity(&target, &id, "working channel for renewal faults", |record| {
            record.connected
        })
        .await?;
        for status in [302, 429, 503] {
            let before = target.requests(None).await?;
            let record_before = case.identity_record(&target, &id).await?;
            let stored_before = case.state(&authority)?;
            let old_thumb = current_thumbprint(&record_before)?.to_owned();
            let old_key = key_name(&stored_before, "current")?.to_owned();
            let attempts = count(&before, "renew")?;
            let mut fault = json!({ "endpoint": "renew", "status": status });
            if status == 429 {
                fault["retry_after_secs"] = json!(3);
            }
            target.faults(&json!({ "fail_next_response": fault })).await?;
            target.management().request_renewal(&id).await?;
            wait_for_injected_attempt(case, &target, "renew", attempts).await?;
            let failed_at = Instant::now();
            let failed = case.identity_record(&target, &id).await?;
            let stored = case.state(&authority)?;
            // The injected failure rejects the renewal before the authority processes it (mock README, `fail_next_response`), and only `confirm` promotes a certificate (CONTRACT.agent-identity.md §5.5).
            // The request-renewal flag stays set until the identity confirms a newer certificate (§8.2).
            // Metadata and the last-seen time are left out, because the agent's channel traffic legitimately updates them: the authority replaces metadata on the `Hello` of the reconnect after the previous `confirm` (§3, §8.1 step 4), and moves the last-seen time on that `Hello` and on the `Ack` of `RenewRequested` (§7.3 step 5; shared intent, "Configuration and metadata").
            ensure!(
                failed.certificates == record_before.certificates && failed.renewal_requested,
                "injected renew {status} changed the identity's certificates or request-renewal flag"
            );
            // The old certificate remains in use after a transient renew error (§8.1, "Failure handling"), a transient error is never terminal (§5.4), and a renew response carries no config (§5.3).
            ensure!(
                stored["keys"]["current"] == stored_before["keys"]["current"]
                    && stored["keys"]["previous"] == stored_before["keys"]["previous"]
                    && stored["config"] == stored_before["config"]
                    && stored.get("rejected").is_none(),
                "injected renew {status} changed the agent's committed identity state"
            );
            // The agent records the pending key before sending the renewal and stores a chain only once renew succeeds (agent intent, "Stored identities"), and it retries with the same CSR (§8.1 step 2).
            ensure!(
                stored["keys"]["pending"]["key_name"].is_string()
                    && stored["keys"]["pending"]["certificate_chain"].is_null(),
                "agent did not keep a pending key without a chain after the injected renew {status}"
            );
            if status == 429 {
                // The agent waits for `Retry-After` up to its maximum retry delay (CONTRACT.agent-identity.md §5.4), which `backoff_max_secs: 2` caps, so the retry comes after about two seconds.
                tokio::time::sleep_until((failed_at + Duration::from_millis(1_500)).into()).await;
                ensure!(
                    count(&target.requests(None).await?, "renew")? == attempts + 1,
                    "renew retried before the Retry-After delay capped at two seconds"
                );
            }
            let renewed = case
                .until_identity(&target, &id, "renew retry confirmed", |record| {
                    current_thumbprint(record).is_ok_and(|thumb| thumb != old_thumb) && record.connected
                })
                .await?;
            let settled = until_renewal_settled(case, &target, &authority, &id, &old_key).await?;
            ensure!(
                count(&target.requests(None).await?, "renew")? >= attempts + 2
                    && count(&target.requests(None).await?, "redirect_hits")? == count(&before, "redirect_hits")?
                    && !renewed.renewal_requested
                    && settled.get("rejected").is_none(),
                "renew {status} was followed as a redirect or not retried to completion"
            );
        }
        Ok(())
    })
    .await
}

pub(crate) async fn a_check_in_transient_failures_retry_without_state_change(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §check-in
    with_agent(ctx, None, false, async move |case| {
        let target = case.ctx.target.clone();
        target.faults(&json!({ "channel_available": false })).await?;
        let config_path = case.path().join("agent.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path)?)?;
        config["__debug__"]["identity"]["check_in_interval_secs"] = json!(60);
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
        case.start().await?;
        let (id, initial) = case.enroll_new(&target, 1).await?;
        let authority = field(&initial, "authority_id")?.to_owned();
        poll!(case, WAIT, POLL, "initial check-in never completed", async {
            if target
                .events(&id)
                .await?
                .iter()
                .any(|event| event["type"] == "check_in_received")
            {
                return Ok(Some(()));
            }
            Ok(None)
        });
        for status in [302, 429, 503] {
            case.stop().await?;
            let before = target.requests(None).await?;
            let record_before = case.identity_record(&target, &id).await?;
            let stored_before = case.state(&authority)?;
            let completed_before = target
                .events(&id)
                .await?
                .iter()
                .filter(|event| event["type"] == "check_in_received")
                .count();
            let hostname = format!("check-in-after-{status}");
            case.set_metadata_hostname(&hostname)?;
            let attempts = count(&before, "check_in")?;
            let mut fault = json!({ "endpoint": "check-in", "status": status });
            if status == 429 {
                fault["retry_after_secs"] = json!(3);
            }
            target.faults(&json!({ "fail_next_response": fault })).await?;
            case.start().await?;
            wait_for_injected_attempt(case, &target, "check_in", attempts).await?;
            let failed_at = Instant::now();
            let failed = case.identity_record(&target, &id).await?;
            let stored = case.state(&authority)?;
            ensure!(
                failed.certificates == record_before.certificates
                    && failed.metadata == record_before.metadata
                    && failed.last_seen_at == record_before.last_seen_at
                    && stored["config"] == stored_before["config"]
                    && stored["keys"] == stored_before["keys"]
                    && stored.get("rejected").is_none(),
                "injected check-in {status} changed server or committed identity state"
            );
            if status == 429 {
                // The agent waits for `Retry-After` up to its maximum retry delay (CONTRACT.agent-identity.md §5.4), which `backoff_max_secs: 2` caps, so the retry comes after about two seconds.
                tokio::time::sleep_until((failed_at + Duration::from_millis(1_500)).into()).await;
                ensure!(
                    count(&target.requests(None).await?, "check_in")? == attempts + 1,
                    "check-in retried before the Retry-After delay capped at two seconds"
                );
            }
            poll!(
                case,
                Duration::from_secs(10),
                POLL,
                format!("check-in {status} was not retried before the next 60-second periodic send"),
                async {
                    let current = count(&target.requests(None).await?, "check_in")?;
                    ensure!(
                        current <= attempts + 2,
                        "check-in sent extra requests before the retry was observed"
                    );
                    if current == attempts + 2
                        && case.identity_record(&target, &id).await?.metadata_value("hostname") == Some(&*hostname)
                    {
                        return Ok(Some(()));
                    }
                    Ok(None)
                },
            );
            ensure!(
                target
                    .events(&id)
                    .await?
                    .iter()
                    .filter(|event| event["type"] == "check_in_received")
                    .count()
                    == completed_before + 1
                    && count(&target.requests(None).await?, "redirect_hits")? == count(&before, "redirect_hits")?,
                "check-in {status} was followed as a redirect or not retried to completion"
            );
        }
        Ok(())
    })
    .await
}

pub(crate) async fn a_token_never_logged(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Security invariants
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let _ = case.enroll_new(&target, 1).await?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_same_token_no_enrollment(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let token = new_token(case, 2).await?;
        case.write_pending(&token.text)?;
        let (id, old) = case.enrolled(&target, &token).await?;
        ensure!(!case.pending_path().exists(), "initial pending file still exists");
        let uses = target.management().token(&token.id).await?.used_count;
        let attempts = if case.ctx.mock() {
            Some(count(&target.requests(Some(&token)).await?, "enroll")?)
        } else {
            None
        };
        case.write_pending(&token.text)?;
        poll!(case, WAIT, POLL, "same token pending file was not discarded", async {
            if !case.pending_path().exists() {
                return Ok(Some(()));
            }
            ensure!(
                target.management().identity_count(&token).await? == 1,
                "duplicate token enrolled another identity"
            );
            Ok(None)
        });
        ensure!(
            case.state(field(&old, "authority_id")?)?["identity_id"] == id,
            "same token replaced identity"
        );
        ensure!(
            target.management().token(&token.id).await?.used_count == uses,
            "same token used again"
        );
        let final_identities = target
            .management()
            .identities(&IdentityQuery::enrolled_with(&token))
            .await?;
        ensure!(
            final_identities.total_count == 1 && final_identities.items.first().is_some_and(|row| row.id == id),
            "same token created a new identity"
        );
        if let Some(attempts) = attempts {
            ensure!(
                count(&target.requests(Some(&token)).await?, "enroll")? == attempts,
                "same token caused another enrollment request"
            );
        }
        Ok(())
    })
    .await
}

#[derive(Clone, Copy)]
enum PermanentTokenOutcome {
    Exhausted,
    Invalid,
    Malformed,
}

async fn same_token_after_permanent_outcome(ctx: Context, outcome: PermanentTokenOutcome) -> anyhow::Result<()> {
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let token = new_token(case, 1).await?;
        let (pending, expected_identities, expected_uses) = match outcome {
            PermanentTokenOutcome::Exhausted => {
                let key = crate::signer::KeyPair::generate()?;
                expect_status(&target.enroll(&token.text, &key, &json!({})).await?, 200)?;
                (token.text.clone(), 1, 1)
            }
            PermanentTokenOutcome::Invalid => {
                let (prefix, secret) = token.text.rsplit_once('.').context("token structure")?;
                let mut bytes = URL_SAFE_NO_PAD.decode(secret)?;
                bytes[0] ^= 1;
                (format!("{prefix}.{}", URL_SAFE_NO_PAD.encode(bytes)), 0, 0)
            }
            PermanentTokenOutcome::Malformed => {
                let (_, secret) = token.text.rsplit_once('.').context("token structure")?;
                (format!("dvaet1.not-base64!.{secret}"), 0, 0)
            }
        };
        let before = if case.ctx.mock() {
            Some(count(&target.requests(None).await?, "enroll_total")?)
        } else {
            None
        };
        case.write_pending(&pending)?;
        case.until_pending_deleted(&target, &pending, &token, expected_identities, expected_uses)
            .await?;
        if let Some(before) = before {
            let expected = before + u64::from(!matches!(outcome, PermanentTokenOutcome::Malformed));
            ensure!(
                count(&target.requests(None).await?, "enroll_total")? == expected,
                "initial permanent outcome sent the wrong number of enrollment requests"
            );
        }
        assert_same_token_replay_dropped(case, &target, &token, &pending, expected_identities, expected_uses).await
    })
    .await
}

async fn assert_same_token_replay_dropped(
    case: &mut AgentCase,
    target: &Target,
    token: &Token,
    pending: &str,
    expected_identities: u64,
    expected_uses: u64,
) -> anyhow::Result<()> {
    let attempts = if case.ctx.mock() {
        Some(count(&target.requests(None).await?, "enroll_total")?)
    } else {
        None
    };
    case.write_pending(pending)?;
    poll!(
        case,
        WAIT,
        POLL,
        "agent did not discard the rewritten permanently failed token within 20 seconds",
        async {
            assert_replay_unchanged(target, token, expected_identities, expected_uses, attempts).await?;
            if !case.pending_path_for(pending).exists() && !case.in_progress_path_for(pending).exists() {
                return Ok(Some(()));
            }
            Ok(None)
        },
    );
    let settled = Instant::now();
    while settled.elapsed() < Duration::from_secs(3) {
        assert_replay_unchanged(target, token, expected_identities, expected_uses, attempts).await?;
        ensure!(
            !case.pending_path_for(pending).exists() && !case.in_progress_path_for(pending).exists(),
            "rewritten permanently failed token reappeared"
        );
        case.check_running()?;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(())
}

async fn assert_replay_unchanged(
    target: &Target,
    token: &Token,
    expected_identities: u64,
    expected_uses: u64,
    attempts: Option<u64>,
) -> anyhow::Result<()> {
    ensure!(
        target.management().identity_count(token).await? == expected_identities,
        "rewritten permanently failed token created another identity"
    );
    let record = target.management().token(&token.id).await?;
    ensure!(
        record.used_count == expected_uses,
        "rewritten permanently failed token consumed another use"
    );
    if let Some(attempts) = attempts {
        ensure!(
            count(&target.requests(None).await?, "enroll_total")? == attempts,
            "rewritten permanently failed token sent an enrollment request"
        );
    }
    Ok(())
}

pub(crate) async fn a_same_token_after_token_exhausted_no_enrollment(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    same_token_after_permanent_outcome(ctx, PermanentTokenOutcome::Exhausted).await
}

pub(crate) async fn a_same_token_after_token_invalid_no_enrollment(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    same_token_after_permanent_outcome(ctx, PermanentTokenOutcome::Invalid).await
}

pub(crate) async fn a_same_token_after_token_malformed_no_enrollment(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    same_token_after_permanent_outcome(ctx, PermanentTokenOutcome::Malformed).await
}

pub(crate) async fn a_same_token_after_identity_revoked_no_enrollment(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let token = new_token(case, 1).await?;
        let (id, key) = dropped_enrollment(case, &token).await?;
        target.management().revoke(&id).await?;
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "enroll", "pause": false }))
                .await?,
            200,
        )?;
        case.until_pending_deleted(&target, &token.text, &token, 1, 1).await?;
        ensure!(
            count(&target.requests(Some(&token)).await?, "enroll_identity_revoked")? == 1
                && !key_exists(case, &key)?
                && target.management().identity(&id).await?.status == IdentityStatus::Revoked,
            "lost response was not followed by a permanent identity_revoked outcome"
        );
        assert_same_token_replay_dropped(case, &target, &token, &token.text, 1, 1).await
    })
    .await
}

pub(crate) async fn a_same_token_rejected_identity_no_enrollment(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity/INTENT.md §Identities
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let token = new_token(case, 3).await?;
        case.write_pending(&token.text)?;
        let (id, state) = case.enrolled(&target, &token).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        case.until_identity(&target, &id, "connected", |record| record.connected)
            .await?;
        target.management().revoke(&id).await?;
        case.until_rejected(&target, &authority, &id, "identity_revoked")
            .await?;
        let attempts = if case.ctx.mock() {
            Some(count(&target.requests(Some(&token)).await?, "enroll")?)
        } else {
            None
        };
        case.write_pending(&token.text)?;
        poll!(
            case,
            WAIT,
            POLL,
            "same token was not discarded after rejection",
            async {
                if !case.pending_path().exists() {
                    return Ok(Some(()));
                }
                let _ = target.management().identity_count(&token).await?;
                Ok(None)
            },
        );
        ensure!(
            target.management().token(&token.id).await?.used_count == 1,
            "rejected identity consumed another token use"
        );
        let final_identities = target
            .management()
            .identities(&IdentityQuery::enrolled_with(&token))
            .await?;
        ensure!(
            final_identities.total_count == 1 && final_identities.items.first().is_some_and(|row| row.id == id),
            "same token created a new identity after rejection"
        );
        ensure!(
            case.state(&authority)?["rejected"]["code"] == "identity_revoked",
            "rejection was cleared"
        );
        if let Some(attempts) = attempts {
            ensure!(
                count(&target.requests(Some(&token)).await?, "enroll")? == attempts,
                "rejected identity sent another enrollment request"
            );
        }
        Ok(())
    })
    .await
}

pub(crate) async fn a_different_token_replaces_identity(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let (first_id, first_state) = case.enroll_new(&target, 1).await?;
        let authority = field(&first_state, "authority_id")?.to_owned();
        let original_key = key_name(&first_state, "current")?.to_owned();
        let next_token = new_token(case, 1).await?;
        case.write_pending(&next_token.text)?;
        let (next_id, next_state) = case.enrolled(&target, &next_token).await?;
        ensure!(first_id != next_id, "different token did not replace the identity");
        ensure!(
            next_state["authority_id"] == authority,
            "same mock changed authority on re-enrollment"
        );
        ensure!(
            next_state["token_sha256"] == token_file_id(&next_token.text)
                && next_state["token_sha256"] != first_state["token_sha256"],
            "replacement did not store the new token hash"
        );
        wait_key_deleted(case, &original_key).await?;
        ensure!(
            case.state(&authority)?["identity_id"] == next_id,
            "stored identity not replaced"
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_rejected_identity_replaced(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity/INTENT.md §Identities
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let (old_id, old_state) = case.enroll_new(&target, 1).await?;
        let authority = field(&old_state, "authority_id")?.to_owned();
        let old_key = key_name(&old_state, "current")?.to_owned();
        case.until_identity(&target, &old_id, "old connection", |record| record.connected)
            .await?;
        target.management().revoke(&old_id).await?;
        case.until_rejected(&target, &authority, &old_id, "identity_revoked")
            .await?;
        let replacement = new_token(case, 1).await?;
        case.write_pending(&replacement.text)?;
        let (new_id, new_state) = case.enrolled(&target, &replacement).await?;
        ensure!(new_id != old_id, "new token reused the revoked identity ID");
        ensure!(
            new_state["authority_id"] == authority,
            "replacement changed authorities"
        );
        ensure!(
            new_state.get("rejected").is_none(),
            "new token retained the old rejection"
        );
        ensure!(
            new_state["token_sha256"] == token_file_id(&replacement.text)
                && new_state["token_sha256"] != old_state["token_sha256"],
            "rejected identity replacement did not store the new token hash"
        );
        wait_key_deleted(case, &old_key).await?;
        case.until_identity(&target, &new_id, "replacement connection", |record| record.connected)
            .await?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_cli_identity_enroll_writes_pending_file(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent devolutions-agent/src/identity/INTENT.md §CLI
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, false, async move |case| {
        let token = new_token(case, 1).await?;
        case.add_token(&token.text);
        let output = enroll_cli_from_stdin(case, format!("{}\n", token.text).as_bytes()).await?;
        ensure!(output.status.success(), "identity enroll CLI rejected a valid token");
        ensure!(
            case.pending_path().exists(),
            "identity enroll CLI did not write the pending file"
        );
        #[cfg(windows)]
        crate::windows::pending_acl_is_protected(&case.pending_path())?;
        ensure!(
            String::from_utf8_lossy(&output.stdout).contains(&case.pending_path().to_string_lossy().to_string()),
            "identity enroll CLI did not print the pending file path"
        );
        #[cfg(windows)]
        let data = {
            let encrypted = std::fs::read(case.pending_path())?;
            crate::windows::assert_machine_scope(&encrypted)?;
            crate::windows::unprotect_pending(&encrypted)?
        };
        #[cfg(unix)]
        let data = std::fs::read(case.pending_path())?;
        let contents: Value = serde_json::from_slice(&data)?;
        ensure!(
            contents["version"] == 1 && contents["token"] == token.text,
            "CLI pending file malformed"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(case.pending_path())?.permissions().mode() & 0o777;
            ensure!(mode == 0o600, "CLI pending file is not mode 0600");
        }
        std::fs::remove_file(case.pending_path())?;
        let (prefix, secret) = token.text.rsplit_once('.').context("token secret")?;
        let bag = prefix.rsplit_once('.').context("token bag")?.1;
        let invalid = [
            ("wrong prefix", format!("dvaet2.{bag}.{secret}")),
            ("missing secret", format!("dvaet1.{bag}")),
            ("invalid bag", format!("dvaet1.!invalid.{secret}")),
            (
                "invalid JSON bag",
                format!("dvaet1.{}.{secret}", URL_SAFE_NO_PAD.encode("not-json")),
            ),
            (
                "bag without URL",
                format!("dvaet1.{}.{secret}", URL_SAFE_NO_PAD.encode("{}")),
            ),
            (
                "HTTP URL",
                format!(
                    "dvaet1.{}.{secret}",
                    URL_SAFE_NO_PAD.encode(r#"{"u":"http://localhost/mock"}"#)
                ),
            ),
            (
                "URL with query",
                format!(
                    "dvaet1.{}.{secret}",
                    URL_SAFE_NO_PAD.encode(r#"{"u":"https://localhost/mock?q=1"}"#)
                ),
            ),
            (
                "URL with fragment",
                format!(
                    "dvaet1.{}.{secret}",
                    URL_SAFE_NO_PAD.encode(r##"{"u":"https://localhost/mock#frag"}"##)
                ),
            ),
            ("short secret", format!("dvaet1.{bag}.{}", &secret[..secret.len() - 1])),
            ("padded secret", format!("dvaet1.{bag}.{secret}=")),
            (
                "overlong token",
                format!(
                    "dvaet1.{}.{secret}",
                    URL_SAFE_NO_PAD.encode(serde_json::to_vec(
                        &json!({ "u": format!("https://localhost/{}", "a".repeat(5000)) })
                    )?)
                ),
            ),
        ];
        for (reason, candidate) in invalid {
            let result = enroll_cli_from_stdin(case, format!("{candidate}\n").as_bytes())
                .await
                .with_context(|| format!("identity enroll CLI for {reason}"))?;
            ensure!(!result.status.success(), "identity enroll CLI accepted {reason}");
            ensure!(
                !case.pending_path_for(&candidate).exists() && !case.in_progress_path_for(&candidate).exists(),
                "{reason} wrote pending enrollment state"
            );
        }
        Ok(())
    })
    .await
}

async fn enroll_cli_from_stdin(case: &AgentCase, input: &[u8]) -> anyhow::Result<std::process::Output> {
    enroll_cli(&case.ctx.agent_bin, case.path(), &["-"], input, Duration::from_secs(10)).await
}

/// Runs `identity enroll` followed by `args` against the case configuration in `case_dir`, writing `input` to its standard input.
///
/// Appends the command's output to the case's CLI logs, which the token audit then reads.
async fn enroll_cli(
    agent_bin: &Path,
    case_dir: &Path,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
) -> anyhow::Result<std::process::Output> {
    let output = tokio::time::timeout(timeout, async {
        let mut child = Command::new(agent_bin)
            .args(["identity", "enroll"])
            .args(args)
            .env("DAGENT_CONFIG_PATH", case_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("start identity enroll CLI")?;
        let mut stdin = child.stdin.take().context("identity enroll CLI has no stdin")?;
        if let Err(error) = stdin.write_all(input).await {
            ensure!(
                error.kind() == std::io::ErrorKind::BrokenPipe,
                "write token to identity enroll CLI stdin: {error}"
            );
        }
        drop(stdin);
        child.wait_with_output().await.context("wait for identity enroll CLI")
    })
    .await
    .context("identity enroll CLI timed out")??;
    use std::io::Write as _;
    for (name, contents) in [("cli-stdout.log", &output.stdout), ("cli-stderr.log", &output.stderr)] {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(case_dir.join(name))?
            .write_all(contents)?;
    }
    Ok(output)
}

fn assert_no_pending_files(case: &AgentCase, input: &str) -> anyhow::Result<()> {
    let dir = case.path().join("identity").join("pending");
    if dir.exists() {
        ensure!(
            std::fs::read_dir(dir)?.next().is_none(),
            "identity enroll CLI created pending or in-progress state for {input}"
        );
    }
    Ok(())
}

pub(crate) async fn a_cli_identity_enroll_stdin(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent devolutions-agent/src/identity/INTENT.md §CLI
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, false, async move |case| {
        let token = new_token(case, 1).await?;
        case.add_token(&token.text);
        let output = enroll_cli_from_stdin(case, format!(" \t{} \r\n", token.text).as_bytes()).await?;
        ensure!(
            output.status.success(),
            "identity enroll CLI rejected a valid token on stdin"
        );
        let pending = case.pending_path();
        ensure!(
            pending.exists(),
            "identity enroll CLI did not write stdin token's pending file"
        );
        ensure!(
            String::from_utf8_lossy(&output.stdout).contains(&pending.to_string_lossy().to_string()),
            "identity enroll CLI did not print the stdin token's pending path"
        );
        #[cfg(windows)]
        crate::windows::pending_acl_is_protected(&pending)?;
        #[cfg(windows)]
        let data = crate::windows::unprotect_pending(&std::fs::read(&pending)?)?;
        #[cfg(unix)]
        let data = std::fs::read(&pending)?;
        let contents: Value = serde_json::from_slice(&data)?;
        ensure!(
            contents["version"] == 1 && contents["token"] == token.text,
            "CLI did not trim stdin to exactly the enrollment token"
        );
        std::fs::remove_file(pending)?;
        let (prefix, secret) = token.text.rsplit_once('.').context("token structure")?;
        let bag = prefix.rsplit_once('.').context("token bag")?.1;
        let invalid = format!("dvaet2.{bag}.{secret}");
        for (name, input) in [
            ("invalid token", format!("{invalid}\r\n").into_bytes()),
            ("immediate EOF", Vec::new()),
            ("whitespace-only line", b" \t \r\n".to_vec()),
        ] {
            let output = enroll_cli_from_stdin(case, &input).await?;
            ensure!(!output.status.success(), "identity enroll CLI accepted {name} on stdin");
            assert_no_pending_files(case, &format!("{name} on stdin"))?;
        }
        Ok(())
    })
    .await
}

pub(crate) async fn a_cli_identity_enroll_token_argument_refused(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent devolutions-agent/src/identity/INTENT.md §CLI
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, false, async move |case| {
        let token = new_token(case, 1).await?;
        case.add_token(&token.text);
        let line = format!("{}\n", token.text);
        // Each run differs from the accepting control below only in its arguments, standard input carrying the same token.
        for (name, args) in [
            ("the token as the argument", &[token.text.as_str()][..]),
            ("the token after -", &["-", token.text.as_str()][..]),
        ] {
            let output = enroll_cli(
                &case.ctx.agent_bin,
                case.path(),
                args,
                line.as_bytes(),
                Duration::from_secs(10),
            )
            .await
            .with_context(|| format!("identity enroll CLI with {name}"))?;
            ensure!(!output.status.success(), "identity enroll CLI accepted {name}");
            assert_no_pending_files(case, name)?;
            for (stream, contents) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
                assert_no_token_fragments(
                    contents,
                    &token.text,
                    Path::new(&format!("identity enroll CLI {stream} for {name}")),
                )?;
            }
        }
        // The refusals above are for the arguments alone: the same token on standard input is accepted.
        let output = enroll_cli_from_stdin(case, line.as_bytes()).await?;
        ensure!(
            output.status.success(),
            "identity enroll CLI rejected the token on stdin after refusing it as an argument"
        );
        let pending = case.pending_path();
        ensure!(
            pending.exists(),
            "identity enroll CLI did not write the pending file for the token on stdin"
        );
        std::fs::remove_file(pending)?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_renewal_happy_path(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: intent crates/agent-identity/INTENT.md §Schedules
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx, Some(2), true, async move |case| {
        let target = case.ctx.target.clone();
        let lifetime = case.ctx.leaf_lifetime();
        // Every certificate of this identity is issued after its token is created.
        let issued_after = Instant::now();
        let (id, initial) = case.enroll_new(&target, 1).await?;
        let authority = field(&initial, "authority_id")?.to_owned();
        let old_key = key_name(&initial, "current")?.to_owned();
        let before = case.identity_record(&target, &id).await?;
        let old_thumb = current_thumbprint(&before)?.to_owned();
        let name = before.friendly_name.as_str().to_owned();
        let renewed = poll!(
            case,
            WAIT,
            POLL,
            "agent did not confirm a new current certificate",
            async {
                let record = case.identity_record(&target, &id).await?;
                if current_thumbprint(&record).is_ok_and(|thumb| thumb != old_thumb) {
                    return Ok(Some(record));
                }
                if let Ok(state) = case.state(&authority) {
                    case.data_dir().check_key_protection(&authority, &state, false)?;
                }
                if !key_exists(case, &old_key)? {
                    let confirmed = current_thumbprint(&case.identity_record(&target, &id).await?)
                        .is_ok_and(|thumb| thumb != old_thumb);
                    ensure!(
                        confirmed,
                        "old key was deleted before the server confirmed its replacement"
                    );
                }
                Ok(None)
            },
        );
        ensure!(renewed.friendly_name == name, "friendly name changed on renewal");
        ensure!(
            renewed.certificates.as_ref().is_some_and(|items| items
                .iter()
                .any(|cert| cert.thumbprint == old_thumb && cert.status == CertificateStatus::Retired)),
            "old certificate not retired"
        );
        let final_state = case
            .until_state(
                &target,
                &authority,
                &id,
                "settled new stored current certificate",
                |state| {
                    key_name(state, "current").is_ok_and(|name| name != old_key)
                        && state["keys"].get("pending").is_none()
                        && state["keys"].get("previous").is_none()
                },
            )
            .await?;
        ensure!(
            key_name(&final_state, "current")? != old_key,
            "old key remained current"
        );
        ensure!(
            final_state["keys"].get("pending").is_none() && final_state["keys"].get("previous").is_none(),
            "renewal left pending or previous key slots after confirm"
        );
        let current_chain = final_state["keys"]["current"]["certificate_chain"]
            .as_array()
            .context("renewed current certificate chain missing")?;
        ensure!(
            !current_chain.is_empty()
                && crate::signer::thumbprint(current_chain[0].as_str().context("renewed leaf")?)?
                    == current_thumbprint(&renewed)?,
            "stored current certificate does not match the authenticated new leaf"
        );
        case.check_key_protection(&authority, &final_state)?;
        wait_key_deleted(case, &old_key).await?;
        let new_thumb = current_thumbprint(&renewed)?.to_owned();
        if case.ctx.mock() {
            ensure!(
                target.events(&id).await?.iter().any(|event| {
                    event["type"] == "cert_status_changed"
                        && event["cert_thumbprint"] == new_thumb
                        && event["to"] == "current"
                }),
                "old key was deleted without a server-side confirm event"
            );
            assert_new_auth_precedes_old_close(&target, &id, &old_thumb, &new_thumb).await?;
        }
        case.stop().await?;
        case.until_identity(&target, &id, "offline channel after restart", |record| {
            !record.connected
        })
        .await?;
        // The restarted agent would renew at once, since its certificate is older than `renewal_after_secs`.
        case.clear_renewal_after_secs()?;
        case.start().await?;
        // oracle: intent crates/agent-identity/INTENT.md §Stored identities
        // oracle: intent crates/agent-identity/INTENT.md §Schedules
        // The test's leaves outlast it, so the persisted certificate is not due for renewal and the restarted agent connects with it.
        let resumed = case
            .until_identity_within(
                &target,
                &id,
                "reconnected with persisted key",
                renewal_aware_wait(issued_after, lifetime),
                |record| record.connected && current_thumbprint(record).is_ok_and(|thumb| thumb == new_thumb),
            )
            .await?;
        ensure!(
            resumed.issuer() == renewed.issuer(),
            "agent changed issuer while loading the persisted key"
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_renewal_lost_response_retried(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §renew
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        let old_key = key_name(&state, "current")?.to_owned();
        let before = case.identity_record(&target, &id).await?;
        let old_thumb = current_thumbprint(&before)?.to_owned();
        case.until_identity(&target, &id, "channel before requested renewal", |record| {
            record.connected
        })
        .await?;
        let counters = target.requests(None).await?;
        let attempts = count(&counters, "renew")?;
        let confirmed_before = count(&counters, "confirm")?;
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "renew", "pause": true }))
                .await?,
            200,
        )?;
        target.faults(&json!({ "drop_next_response": "renew" })).await?;
        target.management().request_renewal(&id).await?;
        let mut unsettled = "agent did not persist the first pending renewal";
        let (pending_thumb, pending_key) = poll!(case, WAIT, POLL, unsettled, async {
            let record = case.identity_record(&target, &id).await?;
            let state = case.state(&authority)?;
            let requests = target.requests(None).await?;
            let renew_count = count(&requests, "renew")?;
            ensure!(
                renew_count <= attempts + 1 + count(&requests, "renew_retry_503")?,
                "renewal retry succeeded while the retry barrier was held"
            );
            let pending = record
                .certificates
                .as_ref()
                .context("missing certificates")?
                .iter()
                .find(|cert| cert.status == CertificateStatus::Pending);
            if renew_count > attempts
                && let Some(pending) = pending
                && let Ok(key) = key_name(&state, "pending")
            {
                // The mock's README does not order the fault's consumption before the renewal it commits.
                if target.control("faults", &json!({})).await?.body["drop_next_response"].is_null() {
                    return Ok(Some((pending.thumbprint.clone(), key.to_owned())));
                }
                unsettled = "drop-next-renew fault was not consumed";
            }
            Ok(None)
        });
        case.stop().await?;
        let requests = target.requests(None).await?;
        ensure!(
            count(&requests, "renew")? == attempts + 1 + count(&requests, "renew_retry_503")?,
            "renewal retry succeeded before the agent was stopped"
        );
        ensure!(
            key_name(&case.state(&authority)?, "pending")? == pending_key,
            "pending CSR key was not persisted across stop"
        );
        let before_restart = count(&requests, "renew")?;
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "renew", "pause": false }))
                .await?,
            200,
        )?;
        case.start().await?;
        let renewed = case
            .until_identity(&target, &id, "retried renewal after restart", |record| {
                current_thumbprint(record).is_ok_and(|thumb| thumb == pending_thumb) && !record.renewal_requested
            })
            .await?;
        ensure!(
            renewed.certificates.as_ref().is_some_and(|certs| certs.len() == 2) && old_thumb != pending_thumb,
            "lost renewal response created multiple new certificates"
        );
        ensure!(
            count(&target.requests(None).await?, "renew")? > before_restart,
            "lost renewal response was not retried after restart"
        );
        ensure!(
            count(&target.requests(None).await?, "confirm")? > confirmed_before,
            "retried renewal was not confirmed with the new key"
        );
        let state = case
            .until_state(
                &target,
                &authority,
                &id,
                "the retried renewal's key as current",
                |state| {
                    key_name(state, "current").is_ok_and(|name| name == pending_key)
                        && state["keys"].get("pending").is_none()
                        && state["keys"].get("previous").is_none()
                },
            )
            .await?;
        wait_key_deleted(case, &old_key).await?;
        case.check_key_protection(&authority, &state)?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_renewal_lost_confirm_response_retried(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §confirm
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        let old_key = key_name(&state, "current")?.to_owned();
        let old = case
            .until_identity(&target, &id, "old-key channel", |record| record.connected)
            .await?;
        let old_thumb = current_thumbprint(&old)?.to_owned();
        let before = target.requests(None).await?;
        let renew_before = count(&before, "renew")?;
        let connect_before = count(&before, "connect")?;
        let confirm_before = count(&before, "confirm")?;
        let sequence_before = before["request_sequence"]
            .as_array()
            .context("mock request sequence missing")?
            .len();
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": true }))
                .await?,
            200,
        )?;
        target.faults(&json!({ "drop_next_response": "confirm" })).await?;
        target.management().request_renewal(&id).await?;
        let (new_thumb, pending_key) = poll!(case, WAIT, POLL, "agent did not retry the dropped confirm", async {
            let record = case.identity_record(&target, &id).await?;
            let stored = case.state(&authority)?;
            let requests = target.requests(None).await?;
            if count(&requests, "confirm")? > confirm_before
                && count(&requests, "confirm_retry_503")? >= 2
                && let Ok(thumb) = current_thumbprint(&record)
                && thumb != old_thumb
                && let Ok(pending_key) = key_name(&stored, "pending")
            {
                ensure!(
                    key_name(&stored, "current")? == old_key && key_exists(case, &old_key)?,
                    "agent discarded the old key before receiving confirm 204"
                );
                return Ok(Some((thumb.to_owned(), pending_key.to_owned())));
            }
            Ok(None)
        });
        ensure!(
            target.control("faults", &json!({})).await?.body["drop_next_response"].is_null(),
            "drop-next-confirm fault was not consumed"
        );
        let blocked = target.requests(None).await?;
        ensure!(
            count(&blocked, "renew")? == renew_before + 1 && count(&blocked, "connect")? == connect_before,
            "agent renewed again or opened a stream while confirm outcome was unknown"
        );
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                .await?,
            200,
        )?;
        let settled = case
            .until_state(
                &target,
                &authority,
                &id,
                "confirmed new key after dropped response",
                |state| {
                    key_name(state, "current").is_ok_and(|name| name == pending_key)
                        && state["keys"].get("pending").is_none()
                        && state["keys"].get("previous").is_none()
                },
            )
            .await?;
        ensure!(
            key_name(&settled, "current")? == pending_key,
            "agent used a different key for its confirm retry"
        );
        wait_key_deleted(case, &old_key).await?;
        case.until_identity(&target, &id, "new channel after confirm retry", |record| {
            record.connected && current_thumbprint(record).is_ok_and(|thumb| thumb == new_thumb)
        })
        .await?;
        let requests = target.requests(None).await?;
        let sequence = requests["request_sequence"]
            .as_array()
            .context("mock request sequence missing")?;
        let completed = sequence
            .iter()
            .enumerate()
            .skip(sequence_before)
            .filter_map(|(idx, value)| (value == "confirm_204").then_some(idx))
            .take(2)
            .collect::<Vec<_>>();
        ensure!(
            completed.len() == 2,
            "dropped confirm or successful retry was not processed"
        );
        ensure!(
            completed[1] > completed[0] + 1
                && sequence[completed[0] + 1..completed[1]]
                    .iter()
                    .all(|entry| entry == "confirm")
                && count(&requests, "renew")? == renew_before + 1,
            "agent sent renew or connect between the dropped confirm and its successful retry"
        );
        let events = target.events(&id).await?;
        ensure!(
            events
                .iter()
                .filter(|event| {
                    event["type"] == "cert_status_changed"
                        && event["cert_thumbprint"] == new_thumb
                        && event["to"] == "current"
                })
                .count()
                == 1,
            "lost confirm response promoted the pending certificate more than once"
        );
        assert_new_auth_precedes_old_close(&target, &id, &old_thumb, &new_thumb).await?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_confirm_barrier_blocks_channelless_traffic(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §confirm
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        target.faults(&json!({ "channel_available": false })).await?;
        let (id, initial) = case.enroll_new(&target, 1).await?;
        let authority = field(&initial, "authority_id")?.to_owned();
        let original = case.identity_record(&target, &id).await?;
        let old_thumb = current_thumbprint(&original)?.to_owned();
        poll!(case, WAIT, POLL, "initial channelless check-in did not run", async {
            if count(&target.requests(None).await?, "check_in")? > 0 {
                return Ok(Some(()));
            }
            Ok(None)
        });
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": true }))
                .await?,
            200,
        )?;
        target
            .faults(&json!({ "fail_next_response": { "endpoint": "confirm", "status": 503 } }))
            .await?;
        target.management().request_renewal(&id).await?;
        let blocked = poll!(
            case,
            WAIT,
            POLL,
            "confirm retry never reached the channelless barrier",
            async {
                let requests = target.requests(None).await?;
                let state = case.state(&authority)?;
                if count(&requests, "confirm_retry_503")? > 0 && state["keys"]["pending"]["key_name"].is_string() {
                    return Ok(Some(requests));
                }
                Ok(None)
            },
        );
        let sequence_start = blocked["request_sequence"]
            .as_array()
            .context("mock request sequence missing")?
            .iter()
            .position(|entry| entry == "confirm")
            .context("confirm barrier observed no confirm attempt")?;
        let blocked_certificates = case.identity_record(&target, &id).await?.certificates.clone();
        tokio::time::sleep(Duration::from_secs(11)).await;
        case.check_running()?;
        let after = target.requests(None).await?;
        ensure!(
            count(&after, "confirm")? > count(&blocked, "confirm")?
                && count(&after, "renew")? == count(&blocked, "renew")?
                && count(&after, "check_in")? == count(&blocked, "check_in")?
                && count(&after, "connect")? == count(&blocked, "connect")?
                && after["request_sequence"]
                    .as_array()
                    .context("mock request sequence missing")?
                    .iter()
                    .skip(sequence_start)
                    .all(|entry| entry == "confirm")
                && case.identity_record(&target, &id).await?.certificates == blocked_certificates,
            "unknown confirm outcome permitted check-in, renew, connect or certificate promotion"
        );
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                .await?,
            200,
        )?;
        case.until_identity(&target, &id, "channelless confirm resolved", |record| {
            current_thumbprint(record).is_ok_and(|thumb| thumb != old_thumb) && !record.renewal_requested
        })
        .await?;
        let settled = until_renewal_settled(case, &target, &authority, &id, key_name(&initial, "current")?).await?;
        ensure!(
            settled.get("rejected").is_none(),
            "an unknown confirm outcome rejected the identity"
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_confirm_expired_pending_renews_with_fresh_key(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx.clone(), Some(3), true, async move |case| {
        let target = case.ctx.target.clone();
        target
            .faults(&json!({ "channel_available": false, "leaf_lifetime_secs": 30 }))
            .await?;
        let token = new_token(case, 1).await?;
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": true }))
                .await?,
            200,
        )?;
        target.faults(&json!({ "drop_next_response": "confirm" })).await?;
        let before = target.requests(None).await?;
        case.write_pending(&token.text)?;
        let (id, state) = case.enrolled(&target, &token).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        let old_key = key_name(&state, "current")?.to_owned();
        let old_thumb = crate::signer::thumbprint(
            state["keys"]["current"]["certificate_chain"][0]
                .as_str()
                .context("original enrolled leaf missing")?,
        )?;
        let (first_thumb, first_key) = poll!(
            case,
            WAIT,
            POLL,
            "agent did not retain its key after a dropped confirm",
            async {
                let record = case.identity_record(&target, &id).await?;
                let stored = case.state(&authority)?;
                let requests = target.requests(None).await?;
                if count(&requests, "confirm_retry_503")? > count(&before, "confirm_retry_503")?
                    && let Ok(thumb) = current_thumbprint(&record)
                    && thumb != old_thumb
                    && let Ok(pending_key) = key_name(&stored, "pending")
                    && stored_leaf_thumbprint(&stored, "pending")?.as_deref() == Some(thumb)
                {
                    ensure!(
                        key_exists(case, &old_key)? && key_name(&stored, "current")? == old_key,
                        "lost confirm response already discarded the old local current key"
                    );
                    return Ok(Some((thumb.to_owned(), pending_key.to_owned())));
                }
                Ok(None)
            },
        );
        case.stop().await?;
        ensure!(
            target.control("faults", &json!({})).await?.body["drop_next_response"].is_null()
                && case
                    .identity_record(&target, &id)
                    .await?
                    .has_certificate(&first_thumb, CertificateStatus::Current),
            "dropped confirm did not promote the pending certificate server-side"
        );
        let expiry = case
            .identity_record(&target, &id)
            .await?
            .not_after()
            .context("identity has no current certificate")?
            .unix_timestamp();
        let now = target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
            .as_i64()
            .context("mock time missing")?;
        let secs = expiry - now + 1;
        ensure!(
            secs > 0 && secs < 60,
            "pending key did not approach expiry before retry"
        );
        target.advance(secs).await?;
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                .await?,
            200,
        )?;
        let restart = target.requests(None).await?;
        case.start().await?;
        let confirmed_record = case
            .until_identity(&target, &id, "fresh-key renewal after rejected confirm", |record| {
                current_thumbprint(record).is_ok_and(|thumb| thumb != old_thumb && thumb != first_thumb)
                    && record.has_certificate(&first_thumb, CertificateStatus::Retired)
                    && !record.renewal_requested
            })
            .await?;
        let new_thumb = current_thumbprint(&confirmed_record)?.to_owned();
        let settled = case
            .until_state(&target, &authority, &id, "settled fresh confirmed key", |state| {
                key_name(state, "current").is_ok_and(|name| name != old_key && name != first_key)
                    && state["keys"].get("pending").is_none()
                    && state["keys"].get("previous").is_none()
            })
            .await?;
        ensure!(
            key_name(&settled, "current")? != first_key,
            "agent reused the expired pending key after confirm rejected it"
        );
        wait_key_deleted(case, &first_key).await?;
        wait_key_deleted(case, &old_key).await?;
        // `renewal_after_secs` starts the next renewal three seconds after this one, so stop at the settled state.
        case.stop().await?;
        let requests = target.requests(None).await?;
        ensure!(
            renew_and_confirm_steps_since(&requests, &restart)?.starts_with(&[
                "confirm",
                "renew",
                "confirm",
                "confirm_204"
            ]) && renew_keyids_since(&requests, &restart)?.starts_with(&[json!(first_thumb)]),
            "agent did not retry confirm, renew signed with the expired pending key, then confirm a fresh CSR"
        );
        let events = target.events(&id).await?;
        ensure!(
            events
                .iter()
                .any(|event| event["type"] == "renew_received" && event["cert_thumbprint"] == first_thumb)
                && events.iter().any(|event| {
                    event["type"] == "cert_status_changed"
                        && event["cert_thumbprint"] == first_thumb
                        && event["from"] == "current"
                        && event["to"] == "retired"
                })
                && events.iter().any(|event| {
                    event["type"] == "cert_status_changed"
                        && event["cert_thumbprint"] == new_thumb
                        && event["to"] == "current"
                }),
            "the failed pending certificate was not retired before confirming the new key"
        );
        Ok(())
    })
    .await?;

    with_agent(ctx, Some(3), true, async move |case| {
        let target = case.ctx.target.clone();
        target
            .faults(&json!({ "channel_available": false, "leaf_lifetime_secs": 30 }))
            .await?;
        let token = new_token(case, 1).await?;
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": true }))
                .await?,
            200,
        )?;
        target
            .faults(&json!({ "fail_next_response": { "endpoint": "confirm", "status": 503 } }))
            .await?;
        let before = target.requests(None).await?;
        case.write_pending(&token.text)?;
        let (id, state) = case.enrolled(&target, &token).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        let old_key = key_name(&state, "current")?.to_owned();
        let old_thumb = crate::signer::thumbprint(
            state["keys"]["current"]["certificate_chain"][0]
                .as_str()
                .context("original enrolled leaf missing")?,
        )?;
        let (first_thumb, first_key) = poll!(
            case,
            WAIT,
            POLL,
            "agent did not persist a pending key after confirm 503",
            async {
                let record = case.identity_record(&target, &id).await?;
                let stored = case.state(&authority)?;
                let requests = target.requests(None).await?;
                if count(&requests, "confirm_retry_503")? > count(&before, "confirm_retry_503")?
                    && let Some(pending) = record
                        .certificates
                        .as_ref()
                        .and_then(|certs| certs.iter().find(|cert| cert.status == CertificateStatus::Pending))
                    && let Ok(key) = key_name(&stored, "pending")
                    && stored_leaf_thumbprint(&stored, "pending")?.as_deref() == Some(pending.thumbprint.as_str())
                {
                    ensure!(
                        current_thumbprint(&record)? == old_thumb,
                        "injected confirm failure promoted the pending certificate"
                    );
                    return Ok(Some((pending.thumbprint.clone(), key.to_owned())));
                }
                Ok(None)
            },
        );
        case.stop().await?;
        let pending = case.identity_record(&target, &id).await?;
        let certificate = pending
            .certificates
            .as_ref()
            .context("identity certificates missing")?
            .iter()
            .find(|cert| cert.thumbprint == first_thumb)
            .context("pending certificate missing")?;
        let expiry = certificate.not_after.unix_timestamp();
        let now = target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
            .as_i64()
            .context("mock time missing")?;
        let secs = expiry - now + 1;
        ensure!(
            secs > 0 && secs < 60,
            "pending key did not approach expiry before retry"
        );
        target.advance(secs).await?;
        target
            .faults(&json!({
                "fail_next_response": {
                    "endpoint": "renew",
                    "status": 401,
                    "error": "identity_unknown"
                }
            }))
            .await?;
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                .await?,
            200,
        )?;
        let restart = target.requests(None).await?;
        case.start().await?;
        let renewed = case
            .until_identity(
                &target,
                &id,
                "fallback renewal after pending-key identity_unknown",
                |record| {
                    current_thumbprint(record).is_ok_and(|thumb| thumb != old_thumb && thumb != first_thumb)
                        && record.has_certificate(&first_thumb, CertificateStatus::Retired)
                },
            )
            .await?;
        let settled = case
            .until_state(&target, &authority, &id, "confirmed fallback key", |state| {
                key_name(state, "current").is_ok_and(|name| name != old_key && name != first_key)
                    && state["keys"].get("pending").is_none()
                    && state["keys"].get("previous").is_none()
                    && state.get("rejected").is_none()
            })
            .await?;
        ensure!(
            stored_leaf_thumbprint(&settled, "current")?.as_deref() == Some(current_thumbprint(&renewed)?),
            "agent did not persist the fallback-renewed certificate"
        );
        wait_key_deleted(case, &first_key).await?;
        wait_key_deleted(case, &old_key).await?;
        // `renewal_after_secs` starts the next renewal three seconds after this one, so stop at the settled state.
        case.stop().await?;
        let requests = target.requests(None).await?;
        ensure!(
            renew_and_confirm_steps_since(&requests, &restart)?.starts_with(&[
                "confirm",
                "renew",
                "renew",
                "confirm",
                "confirm_204"
            ]) && renew_keyids_since(&requests, &restart)?.starts_with(&[json!(first_thumb), json!(old_thumb)])
                && target
                    .events(&id)
                    .await?
                    .iter()
                    .any(|event| event["type"] == "renew_received" && event["cert_thumbprint"] == old_thumb),
            "identity_unknown on pending-key renew did not fall back to the old current key"
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_confirm_expired_pending_beyond_grace_rejects(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    with_agent(ctx, Some(3), true, async move |case| {
        let target = case.ctx.target.clone();
        target
            .faults(&json!({ "channel_available": false, "leaf_lifetime_secs": 30 }))
            .await?;
        let token = new_token(case, 1).await?;
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": true }))
                .await?,
            200,
        )?;
        target
            .faults(&json!({ "fail_next_response": { "endpoint": "confirm", "status": 503 } }))
            .await?;
        case.write_pending(&token.text)?;
        let (id, initial) = case.enrolled(&target, &token).await?;
        let authority = field(&initial, "authority_id")?.to_owned();
        let old_key = key_name(&initial, "current")?.to_owned();
        let (pending_thumb, pending_certificate) =
            poll!(case, WAIT, POLL, "pending certificate was not held at confirm", async {
                let record = case.identity_record(&target, &id).await?;
                let stored = case.state(&authority)?;
                if count(&target.requests(None).await?, "confirm_retry_503")? > 0
                    && let Some(pending) = record
                        .certificates
                        .as_ref()
                        .and_then(|certs| certs.iter().find(|cert| cert.status == CertificateStatus::Pending))
                    && stored["keys"]["pending"]["key_name"].is_string()
                {
                    return Ok(Some((pending.thumbprint.clone(), pending.clone())));
                }
                Ok(None)
            });
        case.stop().await?;
        let before = target.requests(None).await?;
        let certificates = case.identity_record(&target, &id).await?.certificates.clone();
        let not_before = pending_certificate.not_before.unix_timestamp();
        let not_after = pending_certificate.not_after.unix_timestamp();
        let now = target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
            .as_i64()
            .context("mock time missing")?;
        let secs = not_after + (not_after - not_before) + 1 - now;
        ensure!(
            secs > 0 && secs < 120,
            "pending certificate did not approach its grace limit"
        );
        target.advance(secs).await?;
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                .await?,
            200,
        )?;
        let since = time::OffsetDateTime::now_utc();
        case.start().await?;
        let rejected = case
            .until_rejected(&target, &authority, &id, "certificate_expired")
            .await?;
        let after = target.requests(None).await?;
        let renew_index = usize::try_from(count(&before, "renew")?)?;
        ensure!(
            rejected["rejected"]["code"] == "certificate_expired"
                && key_name(&rejected, "current")? == old_key
                && after["renew_attempt_keyids"][renew_index] == pending_thumb
                && count(&after, "renew")? == count(&before, "renew")? + 1
                && count(&after, "confirm")? > count(&before, "confirm")?
                && case.identity_record(&target, &id).await?.certificates == certificates,
            "beyond-grace pending-key renew did not reject without issuing or promoting a certificate"
        );
        assert_terminal_stops(case, &target, &authority, Some(&id), "certificate_expired", since).await
    })
    .await
}

pub(crate) async fn a_expired_current_renews_in_grace_or_rejects_beyond(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx.clone(), None, true, async move |case| {
        let target = case.ctx.target.clone();
        target.faults(&json!({ "leaf_lifetime_secs": 30 })).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        let old_key = key_name(&state, "current")?.to_owned();
        let original = case
            .until_identity(&target, &id, "old certificate channel", |record| record.connected)
            .await?;
        let old_thumb = current_thumbprint(&original)?.to_owned();
        let expiry = original
            .not_after()
            .context("identity has no current certificate")?
            .unix_timestamp();
        let before = target.requests(None).await?;
        case.stop().await?;
        case.until_identity(&target, &id, "offline expired channel", |record| !record.connected)
            .await?;
        let now = target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
            .as_i64()
            .context("mock time missing")?;
        let secs = expiry - now + 1;
        ensure!(secs > 0 && secs < 60, "old certificate is not approaching expiry");
        target.advance(secs).await?;
        case.start().await?;
        let renewed = case
            .until_identity(&target, &id, "within-grace renewal and reconnect", |record| {
                current_thumbprint(record).is_ok_and(|thumb| thumb != old_thumb) && record.connected
            })
            .await?;
        ensure!(
            renewed.issuer() == original.issuer()
                && count(&target.requests(None).await?, "renew")? > count(&before, "renew")?
                && count(&target.requests(None).await?, "confirm")? > count(&before, "confirm")?
                && target
                    .events(&id)
                    .await?
                    .iter()
                    .any(|event| event["type"] == "renew_received" && event["cert_thumbprint"] == old_thumb)
                && case.state(&authority)?["rejected"].is_null(),
            "expired-within-grace certificate did not sign renew and confirm before reconnecting"
        );
        until_renewal_settled(case, &target, &authority, &id, &old_key).await?;
        Ok(())
    })
    .await?;

    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        target.faults(&json!({ "leaf_lifetime_secs": 30 })).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        case.until_identity(&target, &id, "old certificate channel", |record| record.connected)
            .await?;
        let before = count(&target.requests(None).await?, "renew")?;
        case.stop().await?;
        target.advance(61).await?;
        let since = time::OffsetDateTime::now_utc();
        case.start().await?;
        let rejected = case
            .until_rejected(&target, &authority, &id, "certificate_expired")
            .await?;
        ensure!(
            rejected["rejected"]["code"] == "certificate_expired"
                && count(&target.requests(None).await?, "renew")? > before,
            "agent did not mark an expired-beyond-grace identity rejected"
        );
        assert_terminal_stops(case, &target, &authority, Some(&id), "certificate_expired", since).await?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_channel_connected_and_metadata(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
    // oracle: intent Devolutions/RDM@0acd9d2474bf9fd4a030e146a28097bf4ddf391a:DVLS/Server/server/Common/AgentIdentity/INTENT.md §Identities
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        if case.ctx.mock() {
            expect_status(&target.control("handshake", &json!({ "pause": true })).await?, 200)?;
        }
        let (id, initial_state) = case.enroll_new(&target, 1).await?;
        let authority = field(&initial_state, "authority_id")?.to_owned();
        let enrolled = case.identity_record(&target, &id).await?;
        ensure!(
            enrolled.metadata_value("hostname") == Some(&*case.metadata_hostname),
            "enrollment ignored the metadata override"
        );
        let connected = if case.ctx.mock() {
            ensure!(
                !enrolled.connected,
                "Hello authenticated before enrollment metadata was observed"
            );
            poll!(case, WAIT, POLL, "agent did not reach the held Hello proof", async {
                if count(&target.requests(None).await?, "paused_hellos")? > 0 {
                    return Ok(Some(()));
                }
                Ok(None)
            });
            let held = case.identity_record(&target, &id).await?;
            ensure!(
                !held.connected && held.metadata == enrolled.metadata,
                "enrollment metadata changed before Hello authenticated"
            );
            target.advance(2).await?;
            expect_status(&target.control("handshake", &json!({ "pause": false })).await?, 200)?;
            let connected = case
                .until_identity(&target, &id, "authenticated Hello", |record| record.connected)
                .await?;
            ensure!(
                count(&target.requests(None).await?, "authenticated_connects")? > 0,
                "released Hello did not authenticate"
            );
            connected
        } else {
            case.until_identity(&target, &id, "connected channel", |record| record.connected)
                .await?
        };
        ensure!(
            connected.last_seen_at.is_some(),
            "channel did not update the last-seen time"
        );
        ensure!(
            connected.metadata_value("hostname") == Some(&*case.metadata_hostname),
            "initial Hello ignored the metadata override"
        );
        for key in REQUIRED_METADATA_KEYS {
            ensure!(
                connected.metadata_value(key).is_some_and(|value| !value.is_empty()),
                "Hello omitted required {key} metadata"
            );
        }
        ensure!(
            case.state(&authority)?.get("rejected").is_none(),
            "successful Hello rejected the stored identity"
        );
        if case.ctx.mock() {
            ensure!(
                connected.last_seen_at.is_some() && connected.last_seen_at != enrolled.last_seen_at,
                "authenticated Hello did not refresh the last-seen time"
            );
        }
        Ok(())
    })
    .await
}

/// [CONTRACT.agent-identity.md] §3.1 "Metadata sent by the agent": the agent "removes [...] the invisible format characters of §3" from each value it sends, and "A required key that ends up empty gets the value `unknown`".
///
/// The metadata override replaces collected values before each send (the agent's intent, "Configuration"), so the values this test sets go through that removal.
/// The hostname holds every end of a listed range, and code points inside the ranges that a list kept in pieces would miss, before, between and after code points that the list leaves out, which the agent keeps.
/// The OS name, a required key, and the domain, an optional one, hold only listed code points, so the agent sends `unknown` for the first and omits the second.
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
pub(crate) async fn a_metadata_invisible_format_characters_removed(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
    // oracle: intent devolutions-agent/src/identity/INTENT.md §Configuration
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let listed = invisible_format_character_range_ends()
            .into_iter()
            .chain(INTERIOR_INVISIBLE_FORMAT_CHARACTERS)
            .collect::<Vec<_>>();
        let only_listed = listed.iter().collect::<String>();
        let mut hostname = format!("{only_listed}host");
        let mut expected = "host".to_owned();
        for (separator, kept) in listed.iter().cycle().zip(unlisted_format_character_neighbors()) {
            hostname.push(*separator);
            hostname.push(kept);
            expected.push(kept);
        }
        hostname.push_str("name");
        hostname.push_str(&only_listed);
        expected.push_str("name");
        case.set_metadata_override(&json!({ "hostname": hostname, "os_name": only_listed, "domain": only_listed }))?;
        let (id, _) = case.enroll_new(&target, 1).await?;
        let record = case.identity_record(&target, &id).await?;
        ensure!(
            record.metadata_value("hostname") == Some(&*expected),
            "agent sent hostname {:?} instead of {expected:?}",
            record.metadata_value("hostname")
        );
        ensure!(
            record.metadata_value("os_name") == Some("unknown"),
            "agent sent os_name {:?} for a value made only of invisible format characters",
            record.metadata_value("os_name")
        );
        ensure!(
            record.metadata_value("domain").is_none(),
            "agent sent domain {:?} for a value made only of invisible format characters",
            record.metadata_value("domain")
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_make_before_break_on_renewal(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx, Some(2), true, async move |case| {
        let target = case.ctx.target.clone();
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        let old_key = key_name(&state, "current")?.to_owned();
        let connected = case
            .until_identity(&target, &id, "first connection", |record| record.connected)
            .await?;
        let old_thumb = current_thumbprint(&connected)?.to_owned();
        let new_thumb = poll!(
            case,
            WAIT,
            Duration::from_millis(50),
            "agent did not renew over a live channel",
            async {
                let record = case.identity_record(&target, &id).await?;
                ensure!(record.connected, "agent disconnected during make-before-break");
                if let Ok(thumb) = current_thumbprint(&record)
                    && thumb != old_thumb
                {
                    ensure!(
                        record.certificates.as_ref().is_some_and(|certs| certs
                            .iter()
                            .any(|cert| cert.thumbprint == old_thumb && cert.status == CertificateStatus::Retired)),
                        "old certificate not retired after new one connected"
                    );
                    return Ok(Some(thumb.to_owned()));
                }
                Ok(None)
            },
        );
        if case.ctx.mock() {
            assert_new_auth_precedes_old_close(&target, &id, &old_thumb, &new_thumb).await?;
        }
        until_renewal_settled(case, &target, &authority, &id, &old_key).await?;
        // `renewal_after_secs` starts the next renewal two seconds after this one, so stop at the settled state.
        case.stop().await?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_old_key_deleted_after_confirm_without_channel(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx, Some(8), true, async move |case| {
        let target = case.ctx.target.clone();
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        let old_key = key_name(&state, "current")?.to_owned();
        let enrolled_revision = count(&state["config"], "revision")?;
        let first = case
            .until_identity(&target, &id, "old-root channel", |record| record.connected)
            .await?;
        ensure!(
            first.metadata_value("hostname") == Some(&*case.metadata_hostname),
            "initial Hello ignored the metadata override"
        );
        let old_thumb = current_thumbprint(&first)?.to_owned();
        let renewed_hostname = "conformance-renew";
        case.set_metadata_hostname(renewed_hostname)?;
        target.faults(&json!({ "channel_available": false })).await?;
        case.until_state(&target, &authority, &id, "removed channel URL", |state| {
            state["config"]["revision"]
                .as_u64()
                .is_some_and(|revision| revision > enrolled_revision)
                && state["config"].get("agent_channel_url").is_none()
        })
        .await?;
        case.until_identity(&target, &id, "closed old channel before offline renewal", |record| {
            !record.connected
        })
        .await?;
        target.management().request_renewal(&id).await?;
        let confirmed = poll!(
            case,
            WAIT,
            POLL,
            "agent did not confirm renewal without the channel",
            async {
                let record = case.identity_record(&target, &id).await?;
                if current_thumbprint(&record).is_ok_and(|thumb| thumb != old_thumb) {
                    return Ok(Some(record));
                }
                if !key_exists(case, &old_key)? {
                    let refreshed = case.identity_record(&target, &id).await?;
                    ensure!(
                        current_thumbprint(&refreshed).is_ok_and(|thumb| thumb != old_thumb),
                        "old key was deleted before confirm while the channel was unavailable"
                    );
                }
                Ok(None)
            },
        );
        let new_thumb = current_thumbprint(&confirmed)?.to_owned();
        ensure!(
            confirmed.metadata_value("hostname") == Some(renewed_hostname)
                && !confirmed.renewal_requested
                && confirmed.certificates.as_ref().is_some_and(|certs| {
                    certs
                        .iter()
                        .any(|cert| cert.thumbprint == old_thumb && cert.status == CertificateStatus::Retired)
                }),
            "HTTP renewal did not finish through confirm while the channel was unavailable"
        );
        let events = target.events(&id).await?;
        ensure!(
            events.iter().any(|event| {
                event["type"] == "cert_status_changed"
                    && event["cert_thumbprint"] == new_thumb
                    && event["to"] == "current"
            }) && events
                .iter()
                .all(|event| event["type"] != "stream_authenticated" || event["cert_thumbprint"] != new_thumb),
            "new key was promoted by the channel instead of confirm"
        );
        let requests = target.requests(None).await?;
        ensure!(
            count(&requests, "renew")? >= 1 && count(&requests, "confirm")? >= 1,
            "agent did not send both renew and confirm while the channel was unavailable"
        );
        wait_key_deleted(case, &old_key).await?;
        let stored = case
            .until_state(&target, &authority, &id, "settled confirmed key", |state| {
                key_name(state, "current").is_ok_and(|name| name != old_key)
                    && state["keys"].get("pending").is_none()
                    && state["keys"].get("previous").is_none()
            })
            .await?;
        ensure!(
            crate::signer::thumbprint(
                stored["keys"]["current"]["certificate_chain"][0]
                    .as_str()
                    .context("confirmed leaf missing")?
            )? == new_thumb,
            "agent stored a different key after confirm"
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_request_renewal_connected(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let lifetime = case.ctx.leaf_lifetime();
        // Every certificate of this identity is issued after its token is created.
        let issued_after = Instant::now();
        let (id, state) = case.enroll_new(&target, 1).await?;
        let record = case
            .until_identity_within(
                &target,
                &id,
                "connected channel",
                renewal_aware_wait(issued_after, lifetime),
                |record| record.connected,
            )
            .await?;
        let original = current_thumbprint(&record)?.to_owned();
        let acknowledgments = if case.ctx.mock() {
            Some(count(&target.requests(None).await?, "correlated_acks")?)
        } else {
            None
        };
        target.management().request_renewal(&id).await?;
        let renewed = case
            .until_identity_within(
                &target,
                &id,
                "requested renewal",
                renewal_aware_wait(issued_after, lifetime),
                |record| current_thumbprint(record).is_ok_and(|thumb| thumb != original) && !record.renewal_requested,
            )
            .await?;
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
        // The agent opens its next stream before closing the old one, and the test's leaves outlast it, so no expiry closes a stream.
        ensure!(renewed.connected, "requested renewal broke the channel");
        if let Some(before) = acknowledgments {
            let start = Instant::now();
            loop {
                if count(&target.requests(None).await?, "correlated_acks")? > before {
                    break;
                }
                ensure!(
                    start.elapsed() < Duration::from_secs(2),
                    "agent did not Ack RenewRequested"
                );
                tokio::time::sleep(POLL).await;
            }
        }
        until_renewal_settled(
            case,
            &target,
            field(&state, "authority_id")?,
            &id,
            key_name(&state, "current")?,
        )
        .await?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_renewal_waits_between_renewals(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity/INTENT.md §Schedules
    // oracle: intent devolutions-agent/src/identity/INTENT.md §Configuration
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §check-in
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §server-certificate-state
    with_agent(ctx, None, false, async move |case| {
        let target = case.ctx.target.clone();
        // The test-only setting shortens the 10-minute wait, and `renewal_after_secs`, which is exempt from it, stays unset.
        let wait = Duration::from_secs(15);
        // The second request reaches the authority at least this long before the wait ends.
        // An agent that renews at once then passes the lower bound below only if its renew takes longer than this to show in the mock's requests.
        let margin = Duration::from_secs(4);
        // How late after the wait ends the deferred renewal may still arrive: it covers a new key and the renew request itself.
        let slack = Duration::from_secs(10);
        // How long the agent must hold one connected stream before the second request, so that no reconnect still under way lands after it.
        let stable = Duration::from_millis(1_500);
        case.set_min_renewal_interval_secs(wait.as_secs())?;
        case.start().await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        case.until_identity(&target, &id, "connected channel", |record| record.connected)
            .await?;
        let before_first = target.requests(None).await?;
        // Every confirm, the one answered 204 included, arrives after this moment, taken before the request below, and after the start of the last poll that recorded none.
        // The agent completes the renewal only once its confirm is answered (§8.1 step 4), so the later of the two is a lower bound on the completion.
        let mut completed_after = Instant::now();
        target.management().request_renewal(&id).await?;
        poll!(case, WAIT, POLL, "agent did not confirm the first requested renewal", async {
            let polled_at = Instant::now();
            let requests = target.requests(None).await?;
            let steps = renew_and_confirm_steps_since(&requests, &before_first)?;
            if steps.contains(&"confirm_204") {
                return Ok(Some(()));
            }
            if !steps.contains(&"confirm") {
                completed_after = polled_at;
            }
            Ok(None)
        });
        let settled = until_renewal_settled(case, &target, &authority, &id, key_name(&state, "current")?).await?;
        // The agent opens its new stream before closing the old one after `confirm` (§8.1 step 4), and may reconnect again on the authority's `Reconnect` to the retired stream (§7.4).
        // Wait until it has held one connected stream, with no further authenticated connect, for `stable`, so that the push below reaches the one stream that stays open.
        let connects_before_first = count(&before_first, "authenticated_connects")?;
        let mut held_since: Option<(Instant, u64)> = None;
        let before_second = poll!(case, WAIT, POLL, "agent did not settle on one connected stream after renewing", async {
            let connected = case.identity_record(&target, &id).await?.connected;
            let requests = target.requests(None).await?;
            let connects = count(&requests, "authenticated_connects")?;
            if !(connected && connects_before_first < connects && count(&requests, "active_streams")? == 1) {
                held_since = None;
                return Ok(None);
            }
            match held_since {
                Some((since, held)) if held == connects => Ok((stable <= since.elapsed()).then_some(requests)),
                _ => {
                    held_since = Some((Instant::now(), connects));
                    Ok(None)
                }
            }
        });
        let events_before_second = target
            .events(&id)
            .await?
            .iter()
            .filter_map(|event| event["seq"].as_u64())
            .max()
            .unwrap_or(0);
        // The authority may ask for a renewal again at once: an administrator's request sets the request-renewal flag (§8.2), and the mock pushes `RenewRequested` to live streams when it does (mock README, `request-renewal`).
        target.management().request_renewal(&id).await?;
        let requested_by = Instant::now();
        ensure!(
            requested_by + margin < completed_after + wait,
            "the second renewal request came {:?} after the last poll before the first confirm, too late to tell a {wait:?} wait between renewals from none",
            requested_by.duration_since(completed_after)
        );
        let renewed_within = (requested_by + wait + slack).saturating_duration_since(Instant::now());
        poll!(
            case,
            renewed_within,
            POLL,
            format!("agent did not renew within {slack:?} after the {wait:?} wait between renewals ended"),
            async {
                let requests = target.requests(None).await?;
                Ok(renew_and_confirm_steps_since(&requests, &before_second)?
                    .contains(&"renew")
                    .then_some(()))
            },
        );
        // The renew arrived before this moment, so the time since `completed_after` is at least the time between the agent's completion and its next renew.
        let since_completion = completed_after.elapsed();
        ensure!(
            wait <= since_completion,
            "agent renewed within {since_completion:?} of the last poll before its previous renewal's confirm, before the {wait:?} wait between renewals ended"
        );
        // A renewal request reaches the agent through the push on a live stream, a `RenewRequested` after a new stream's `Welcome` (§7.3 step 5), or check-in (§5.6), and the test's leaves outlast it, so no schedule asks for one.
        // With no stream opened and no check-in between the second request and the renew, in the mock's event order, the pushed request is what the agent deferred.
        let events = target.events(&id).await?;
        let since_second = events
            .iter()
            .filter(|event| event["seq"].as_u64().is_some_and(|seq| events_before_second < seq))
            .collect::<Vec<_>>();
        let renew_at = since_second
            .iter()
            .position(|event| event["type"] == "renew_received")
            .context("mock recorded no renew_received event after the second renewal request")?;
        ensure!(
            !since_second[..renew_at].iter().any(|event| matches!(
                event["type"].as_str(),
                Some("stream_opened" | "stream_authenticated" | "check_in_received")
            )),
            "agent opened a stream or checked in before renewing, so the deferred renewal did not come from the request pushed during the wait"
        );
        until_renewal_settled(case, &target, &authority, &id, key_name(&settled, "current")?).await?;
        // The agent replies `Ack` to `RenewRequested` (§7.3 step 5), which sets no deadline for it, so the case looks for the `Ack` only once the renewal it asked for has settled, within the suite's usual wait, not before the wait between renewals ends.
        // The renewal clears the request-renewal flag (§8.2), so no later stream receives the request again.
        let acks_before = count(&before_second, "correlated_acks")?;
        poll!(case, WAIT, POLL, "agent did not Ack the renewal request pushed during the wait between renewals", async {
            Ok((acks_before < count(&target.requests(None).await?, "correlated_acks")?).then_some(()))
        });
        Ok(())
    })
    .await
}

pub(crate) async fn a_request_renewal_while_offline(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §server-certificate-state
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let (id, state) = case.enroll_new(&target, 1).await?;
        let first = case
            .until_identity(&target, &id, "initial connection", |record| record.connected)
            .await?;
        let original = current_thumbprint(&first)?.to_owned();
        case.stop().await?;
        let _ = case
            .until_identity(&target, &id, "offline channel", |record| !record.connected)
            .await?;
        target.management().request_renewal(&id).await?;
        ensure!(
            case.identity_record(&target, &id).await?.renewal_requested,
            "offline renewal flag missing"
        );
        case.start().await?;
        // The test's leaves outlast it, so only the requested renewal replaces the original certificate, and no expiry closes a stream.
        let renewed = case
            .until_identity(&target, &id, "renewal after reconnect", |record| {
                current_thumbprint(record).is_ok_and(|thumb| thumb != original) && !record.renewal_requested
            })
            .await?;
        ensure!(renewed.connected, "agent did not reconnect after offline request");
        until_renewal_settled(
            case,
            &target,
            field(&state, "authority_id")?,
            &id,
            key_name(&state, "current")?,
        )
        .await?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_request_renewal_without_channel(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §check-in
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    // oracle: intent crates/device-key/INTENT.md §Operations
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        if case.ctx.mock() {
            target.faults(&json!({ "channel_available": false })).await?;
        } else {
            ensure!(!case.ctx.channel_available, "DVLS target offers an agent channel");
        }
        let (id, state) = case.enroll_new(&target, 1).await?;
        let initial = case.identity_record(&target, &id).await?;
        ensure!(
            state["config"].get("agent_channel_url").is_none() && !initial.connected,
            "no-channel renewal fixture unexpectedly offers a channel"
        );
        let original = current_thumbprint(&initial)?.to_owned();
        let before = if case.ctx.mock() {
            Some(target.requests(None).await?)
        } else {
            None
        };
        target.management().request_renewal(&id).await?;
        ensure!(
            case.identity_record(&target, &id).await?.renewal_requested,
            "channelless renewal flag was not persisted"
        );
        case.until_identity(&target, &id, "check-in-triggered channelless renewal", |record| {
            current_thumbprint(record).is_ok_and(|thumb| thumb != original)
                && !record.renewal_requested
                && !record.connected
        })
        .await?;
        if let Some(before) = before {
            let sequence_start = before["request_sequence"]
                .as_array()
                .context("mock request sequence missing")?
                .len();
            let requests = target.requests(None).await?;
            ensure!(
                count(&requests, "check_in")? > count(&before, "check_in")?
                    && count(&requests, "renew")? >= 1
                    && count(&requests, "confirm")? >= 1
                    && count(&requests, "connect")? == 0
                    && count(&requests, "channel_attempts")? == 0
                    && target
                        .events(&id)
                        .await?
                        .iter()
                        .any(|event| event["type"] == "check_in_received" && event["renewal_requested"] == true),
                "channelless renewal did not start at check-in and finish with confirm"
            );
            assert_check_in_triggers_renewal(&requests, sequence_start)?;
        }
        let authority = field(&state, "authority_id")?;
        let old_key = key_name(&state, "current")?;
        until_renewal_settled(case, &target, authority, &id, old_key).await?;
        if case.ctx.mock() {
            let check_ins = count(&target.requests(None).await?, "check_in")?;
            case.stop().await?;
            case.start().await?;
            // Signing the check-in opens the current key, an operation in the key store later than the old key's deletion.
            poll!(case, WAIT, POLL, "restarted agent did not check in", async {
                Ok((count(&target.requests(None).await?, "check_in")? != check_ins).then_some(()))
            });
            assert_no_copy_of_deleted_key(case, old_key)?;
        }
        Ok(())
    })
    .await
}

pub(crate) async fn a_reconnect_make_before_break(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let (id, _) = case.enroll_new(&target, 1).await?;
        case.until_identity(&target, &id, "first channel", |record| record.connected)
            .await?;
        ensure!(
            case.identity_record(&target, &id).await?.metadata_value("hostname") == Some(&*case.metadata_hostname),
            "first Hello did not send the current metadata override"
        );
        case.set_metadata_hostname("reconnected-host")?;
        let before = target.requests(None).await?;
        expect_status(&target.control("reconnect", &json!({ "identity_id": id })).await?, 202)?;
        poll!(
            case,
            WAIT,
            Duration::from_millis(50),
            "agent did not make-before-break on Reconnect",
            async {
                let current = case.identity_record(&target, &id).await?;
                ensure!(current.connected, "agent disconnected before replacement stream opened");
                let observed = target.requests(None).await?;
                if count(&observed, "connect")? > count(&before, "connect")?
                    && count(&observed, "overlap_open")? > count(&before, "overlap_open")?
                    && count(&observed, "authenticated_connects")? > count(&before, "authenticated_connects")?
                    && count(&observed, "active_streams")? == 1
                {
                    return Ok(Some(()));
                }
                Ok(None)
            },
        );
        let events = target.events(&id).await?;
        let authenticated = events
            .iter()
            .filter(|event| event["type"] == "stream_authenticated")
            .collect::<Vec<_>>();
        ensure!(
            authenticated.len() >= 2,
            "Reconnect never authenticated a replacement stream"
        );
        ensure!(
            case.identity_record(&target, &id).await?.metadata_value("hostname") == Some("reconnected-host"),
            "replacement Hello reused the previous metadata override"
        );
        let old_stream = field(authenticated[0], "stream_id")?;
        let new_seq = count(authenticated[1], "seq")?;
        ensure!(
            events.iter().any(|event| {
                event["type"] == "stream_closed"
                    && event["stream_id"] == old_stream
                    && event["status"] == "OK"
                    && event["seq"].as_u64().is_some_and(|seq| seq > new_seq)
            }),
            "Reconnect closed the old stream before the replacement authenticated"
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_revocation_stops_agent(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // oracle: intent crates/agent-identity/INTENT.md §Identities
    with_agent(ctx, Some(2), true, async move |case| {
        let target = case.ctx.target.clone();
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        case.until_identity(&target, &id, "initial connection", |record| record.connected)
            .await?;
        ensure!(
            state.get("rejected").is_none(),
            "identity was rejected before revocation"
        );
        let before = time::OffsetDateTime::now_utc();
        target.management().revoke(&id).await?;
        let _ = case
            .until_rejected(&target, &authority, &id, "identity_revoked")
            .await?;
        let revoked = case.identity_record(&target, &id).await?;
        ensure!(!revoked.connected, "revoked agent remains connected");
        assert_terminal_stops(case, &target, &authority, Some(&id), "identity_revoked", before).await?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_identity_unknown_recorded(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // oracle: intent crates/agent-identity/INTENT.md §Identities
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        case.until_identity(&target, &id, "connection before reset", |record| record.connected)
            .await?;
        ensure!(state.get("rejected").is_none(), "identity was rejected before reset");
        let before = time::OffsetDateTime::now_utc();
        target.reset().await?;
        ensure!(
            case.find_identity_record(&target, &id).await?.is_none(),
            "identity still exists"
        );
        let rejected = case
            .until_rejected(&target, &authority, &id, "identity_unknown")
            .await?;
        ensure!(rejected["rejected"]["at"].as_str().is_some(), "rejection time missing");
        assert_terminal_stops(case, &target, &authority, None, "identity_unknown", before).await?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_signed_rejection_without_live_stream(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // oracle: intent crates/agent-identity/INTENT.md §Identities
    with_agent(ctx.clone(), None, true, async move |case| {
        let target = case.ctx.target.clone();
        target.faults(&json!({ "channel_available": false })).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        ensure!(
            !case.identity_record(&target, &id).await?.connected,
            "signed-request rejection fixture unexpectedly opened a channel"
        );
        let before = target.requests(None).await?;
        ensure!(
            count(&before, "renew")? == 0,
            "check-in rejection fixture renewed before revocation"
        );
        let since = time::OffsetDateTime::now_utc();
        target.management().revoke(&id).await?;
        case.until_rejected(&target, &authority, &id, "identity_revoked")
            .await?;
        let after = target.requests(None).await?;
        ensure!(
            count(&after, "check_in")? > count(&before, "check_in")?
                && count(&after, "renew")? == count(&before, "renew")?,
            "agent did not record identity_revoked from check-in before any renewal"
        );
        assert_terminal_stops(case, &target, &authority, Some(&id), "identity_revoked", since).await?;
        Ok(())
    })
    .await?;
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        target.faults(&json!({ "channel_broken": true })).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        ensure!(
            state["config"]["agent_channel_url"] == target.base_url,
            "channel-open rejection fixture offers no channel"
        );
        ensure!(
            !case.identity_record(&target, &id).await?.connected,
            "channel-open rejection fixture authenticated prematurely"
        );
        let since = time::OffsetDateTime::now_utc();
        target.reset().await?;
        let rejected = case
            .until_rejected(&target, &authority, &id, "identity_unknown")
            .await?;
        ensure!(
            rejected["rejected"]["code"] == "identity_unknown" && count(&target.requests(None).await?, "connect")? > 0,
            "agent did not record identity_unknown from a channel-open rejection"
        );
        assert_terminal_stops(case, &target, &authority, None, "identity_unknown", since).await?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_no_channel_when_absent(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §check-in
    // oracle: intent crates/agent-identity/INTENT.md §Schedules
    let invalid_url_case = ctx.clone();
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        target.faults(&json!({ "channel_available": false })).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        ensure!(
            state["config"].get("agent_channel_url").is_none(),
            "agent stored config.agent_channel_url despite its absence from enrollment"
        );
        poll!(case, WAIT, POLL, "first channelless check-in did not complete", async {
            let requests = target.requests(None).await?;
            Ok(
                (count(&requests, "check_in")? > 0 && completed_check_ins(&target.events(&id).await?) > 0)
                    .then_some(()),
            )
        });
        ensure!(
            case.identity_record(&target, &id).await?.metadata_value("hostname") == Some(&*case.metadata_hostname),
            "first check-in did not send the current metadata override"
        );
        case.set_metadata_hostname("second-check-in-host")?;
        // The agent collects metadata when it sends a check-in (CONTRACT.agent-identity.md §3.1), and a scheduled check-in can have collected it just before the override changed, so the first check-in completed after the change may still carry the old value.
        // Check-ins come `check_in_interval_secs` apart, so the second one completed after the change was collected after it.
        let changed = completed_check_ins(&target.events(&id).await?);
        poll!(
            case,
            WAIT,
            POLL,
            "agent did not complete a check-in after the metadata override changed",
            async {
                let completed = completed_check_ins(&target.events(&id).await?);
                if case.identity_record(&target, &id).await?.metadata["hostname"] == "second-check-in-host" {
                    return Ok(Some(()));
                }
                // A third check-in, counted before the record was read, shows that the second had been answered by then.
                ensure!(
                    completed < changed + 3,
                    "the second check-in after the metadata override changed used stale metadata"
                );
                Ok(None)
            },
        );
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            case.check_running()?;
            ensure!(
                !case.identity_record(&target, &id).await?.connected,
                "agent opened an unavailable channel"
            );
            let requests = target.requests(None).await?;
            ensure!(
                count(&requests, "connect")? == 0 && count(&requests, "channel_attempts")? == 0,
                "agent attempted a channel despite absent config.agent_channel_url"
            );
        }
        Ok(())
    })
    .await?;
    let insecure_url = invalid_url_case.target.base_url.replacen("https://", "http://", 1);
    no_channel_for_malformed_url(invalid_url_case, "HTTP scheme", json!(true), insecure_url).await
}

async fn no_channel_for_malformed_url(
    ctx: Context,
    variant: &'static str,
    fault: Value,
    expected_url: String,
) -> anyhow::Result<()> {
    with_agent(ctx, None, false, async move |case| {
        let target = case.ctx.target.clone();
        target.faults(&json!({ "malformed_channel_url": fault })).await?;
        let config_path = case.path().join("agent.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path)?)?;
        config["__debug__"]["identity"]["channel_failure_check_in_after_secs"] = json!(120);
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
        case.start().await?;
        let before = target.requests(None).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        ensure!(
            state["config"]["agent_channel_url"] == expected_url,
            "mock did not inject config.agent_channel_url with {variant}"
        );
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            case.check_running()?;
            let requests = target.requests(None).await?;
            ensure!(
                count(&requests, "connect")? == count(&before, "connect")?
                    && count(&requests, "channel_attempts")? == count(&before, "channel_attempts")?,
                "agent attempted a channel with {variant} in config.agent_channel_url"
            );
            ensure!(
                !case.identity_record(&target, &id).await?.connected,
                "agent authenticated a channel with {variant} in config.agent_channel_url"
            );
        }
        ensure!(
            count(&target.requests(None).await?, "check_in")? > count(&before, "check_in")?
                && target
                    .events(&id)
                    .await?
                    .iter()
                    .any(|event| event["type"] == "check_in_received"),
            "agent did not check in for {variant} before the delayed broken-channel fallback"
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_no_channel_url_with_query(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-url
    let expected_url = format!("{}?identity_probe=1", ctx.target.base_url);
    no_channel_for_malformed_url(ctx, "query", json!("query"), expected_url).await
}

pub(crate) async fn a_no_channel_url_with_fragment(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-url
    let expected_url = format!("{}#identity_probe", ctx.target.base_url);
    no_channel_for_malformed_url(ctx, "fragment", json!("fragment"), expected_url).await
}

pub(crate) async fn a_config_update_disables_channel(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: intent crates/agent-identity/INTENT.md §Schedules
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        case.until_identity(&target, &id, "initial channel", |record| record.connected)
            .await?;
        let before = target.requests(None).await?;
        ensure!(
            count(&before, "check_in")? == 0,
            "agent checked in over HTTP while its channel was working"
        );
        let initial_revision = count(&state["config"], "revision")?;
        target.faults(&json!({ "channel_available": false })).await?;
        let stored = case
            .until_state(&target, &authority, &id, "disabled channel config", |state| {
                state["config"]["revision"]
                    .as_u64()
                    .is_some_and(|revision| revision > initial_revision)
                    && state["config"].get("agent_channel_url").is_none()
            })
            .await?;
        let disabled_revision = count(&stored["config"], "revision")?;
        case.until_identity(&target, &id, "closed channel after config update", |record| {
            !record.connected
        })
        .await?;
        let events = target.events(&id).await?;
        ensure!(
            events
                .iter()
                .any(|event| event["type"] == "config_update_sent" && event["revision"] == disabled_revision)
                && events
                    .iter()
                    .any(|event| event["type"] == "stream_closed" && event["status"] == "OK"),
            "channel was not cleanly closed after the higher config revision"
        );
        let connects = count(&target.requests(None).await?, "connect")?;
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            case.check_running()?;
            ensure!(
                count(&target.requests(None).await?, "connect")? == connects
                    && !case.identity_record(&target, &id).await?.connected
                    && count(&case.state(&authority)?["config"], "revision")? == disabled_revision,
                "agent retried the channel after its URL was removed"
            );
        }
        Ok(())
    })
    .await
}

pub(crate) async fn a_check_in_enables_channel(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §check-in
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        target.faults(&json!({ "channel_available": false })).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        let enrolled_revision = count(&state["config"], "revision")?;
        ensure!(
            state["config"].get("agent_channel_url").is_none() && !case.identity_record(&target, &id).await?.connected,
            "agent was enrolled with a channel URL despite disabled availability"
        );
        poll!(
            case,
            WAIT,
            POLL,
            "agent did not check in without a channel URL",
            async {
                if count(&target.requests(None).await?, "check_in")? >= 1 {
                    return Ok(Some(()));
                }
                Ok(None)
            },
        );
        let before = count(&target.requests(None).await?, "check_in")?;
        target.faults(&json!({ "channel_available": true })).await?;
        let stored = case
            .until_state(
                &target,
                &authority,
                &id,
                "enabled channel config from check-in",
                |state| {
                    state["config"]["revision"]
                        .as_u64()
                        .is_some_and(|revision| revision > enrolled_revision)
                        && state["config"]["agent_channel_url"] == target.base_url
                },
            )
            .await?;
        ensure!(
            count(&target.requests(None).await?, "check_in")? > before,
            "agent did not learn the enabled URL through check-in"
        );
        case.until_identity(&target, &id, "channel opened from check-in config", |record| {
            record.connected
        })
        .await?;
        ensure!(
            stored["config"]["agent_channel_url"] == target.base_url
                && target
                    .events(&id)
                    .await?
                    .iter()
                    .any(|event| event["type"] == "check_in_received"),
            "agent did not persist the check-in revision before opening a channel"
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_check_in_recovers_broken_channel(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §check-in
    // oracle: intent crates/agent-identity/INTENT.md §Schedules
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        target.faults(&json!({ "channel_broken": true })).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        let enrolled_revision = count(&state["config"], "revision")?;
        ensure!(
            state["config"]["agent_channel_url"] == target.base_url,
            "broken transport incorrectly changed the effective config"
        );
        poll!(
            case,
            WAIT,
            POLL,
            "agent did not check in after its channel remained broken",
            async {
                let requests = target.requests(None).await?;
                if count(&requests, "connect")? >= 1 && count(&requests, "check_in")? >= 1 {
                    return Ok(Some(()));
                }
                Ok(None)
            },
        );
        ensure!(
            !case.identity_record(&target, &id).await?.connected
                && count(&case.state(&authority)?["config"], "revision")? == enrolled_revision,
            "broken channel was treated as an effective config change"
        );
        let before = count(&target.requests(None).await?, "check_in")?;
        target.faults(&json!({ "channel_available": false })).await?;
        let stored = case
            .until_state(
                &target,
                &authority,
                &id,
                "disabled config after broken-channel check-in",
                |state| {
                    state["config"]["revision"]
                        .as_u64()
                        .is_some_and(|revision| revision > enrolled_revision)
                        && state["config"].get("agent_channel_url").is_none()
                },
            )
            .await?;
        ensure!(
            count(&target.requests(None).await?, "check_in")? > before
                && stored["config"].get("agent_channel_url").is_none(),
            "agent did not learn the disabled URL through check-in"
        );
        let connects = count(&target.requests(None).await?, "connect")?;
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            case.check_running()?;
            ensure!(
                count(&target.requests(None).await?, "connect")? == connects
                    && !case.identity_record(&target, &id).await?.connected,
                "agent kept reconnecting after check-in removed its channel URL"
            );
        }
        Ok(())
    })
    .await
}

pub(crate) async fn a_config_unknown_fields_and_hello_revision(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        case.until_identity(&target, &id, "initial channel", |record| record.connected)
            .await?;
        let initial_revision = count(&state["config"], "revision")?;
        let before = target.events(&id).await?;
        let authenticated_before = before
            .iter()
            .filter(|event| event["type"] == "stream_authenticated")
            .collect::<Vec<_>>();
        ensure!(
            authenticated_before
                .iter()
                .any(|event| event["applied_config_revision"] == initial_revision)
                && count(&target.requests(None).await?, "check_in")? == 0,
            "working channel did not report its stored revision or checked in over HTTP"
        );
        let acks_before = count(&target.requests(None).await?, "correlated_acks")?;
        expect_status(
            &target
                .control(
                    "config",
                    &json!({ "fields": { "product_hint": { "mode": "preserved" } } }),
                )
                .await?,
            200,
        )?;
        let stored = case
            .until_state(&target, &authority, &id, "unknown pushed config field", |state| {
                state["config"]["revision"]
                    .as_u64()
                    .is_some_and(|revision| revision > initial_revision)
                    && state["config"]["product_hint"] == json!({ "mode": "preserved" })
            })
            .await?;
        let revision = count(&stored["config"], "revision")?;
        poll!(case, WAIT, POLL, "agent did not acknowledge ConfigUpdate", async {
            if count(&target.requests(None).await?, "correlated_acks")? > acks_before {
                return Ok(Some(()));
            }
            Ok(None)
        });
        ensure!(
            count(&target.requests(None).await?, "check_in")? == 0
                && target
                    .events(&id)
                    .await?
                    .iter()
                    .any(|event| event["type"] == "config_update_sent" && event["revision"] == revision),
            "agent polled HTTP despite a working channel config update"
        );
        let acks_before_stale = count(&target.requests(None).await?, "correlated_acks")?;
        let injected_reply = target
            .control(
                "config/stale",
                &json!({ "identity_id": id, "revision": initial_revision }),
            )
            .await?;
        expect_status(&injected_reply, 200)?;
        ensure!(injected_reply.body["sent"] == 1, "stale ConfigUpdate was not delivered");
        poll!(
            case,
            WAIT,
            POLL,
            "agent did not acknowledge the stale ConfigUpdate",
            async {
                if count(&target.requests(None).await?, "correlated_acks")? > acks_before_stale {
                    return Ok(Some(()));
                }
                Ok(None)
            },
        );
        let after_stale = case.state(&authority)?;
        ensure!(
            after_stale["config"] == stored["config"]
                && after_stale["config"].get("mock_stale_marker").is_none()
                && target.events(&id).await?.iter().any(|event| {
                    event["type"] == "stale_config_update_sent" && event["revision"] == initial_revision
                }),
            "agent applied a decreasing config revision"
        );
        expect_status(&target.control("reconnect", &json!({ "identity_id": id })).await?, 202)?;
        poll!(case, WAIT, POLL, "agent did not reconnect after mock push", async {
            let events = target.events(&id).await?;
            let authenticated = events
                .iter()
                .filter(|event| event["type"] == "stream_authenticated")
                .collect::<Vec<_>>();
            if authenticated.len() > authenticated_before.len() {
                ensure!(
                    authenticated
                        .last()
                        .is_some_and(|event| event["applied_config_revision"] == revision),
                    "reconnected Hello did not report the stored config revision"
                );
                return Ok(Some(()));
            }
            Ok(None)
        });
        ensure!(
            count(&target.requests(None).await?, "check_in")? == 0
                && case.state(&authority)?["config"]["product_hint"] == json!({ "mode": "preserved" }),
            "agent lost the unknown config field or checked in with a working channel"
        );
        // Hold the healthy channel beyond two five-second check-in intervals.
        tokio::time::sleep(Duration::from_secs(12)).await;
        case.check_running()?;
        ensure!(
            count(&target.requests(None).await?, "check_in")? == 0
                && case.identity_record(&target, &id).await?.connected,
            "agent checked in periodically despite a working channel"
        );
        Ok(())
    })
    .await
}

fn completed_check_ins(events: &[Value]) -> usize {
    events
        .iter()
        .filter(|event| event["type"] == "check_in_received")
        .count()
}

pub(crate) async fn a_config_unsupported_version_keeps_stored_config(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        target.faults(&json!({ "channel_available": false })).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        let stored = state["config"].clone();
        let stored_revision = count(&stored, "revision")?;
        ensure!(
            stored["version"] == 1,
            "agent stored an enrollment config whose version is not 1"
        );
        poll!(case, WAIT, POLL, "agent did not check in without a channel", async {
            Ok((completed_check_ins(&target.events(&id).await?) != 0).then_some(()))
        });
        target.faults(&json!({ "config_version": 2 })).await?;
        let baseline = completed_check_ins(&target.events(&id).await?);
        poll!(
            case,
            WAIT,
            POLL,
            "agent stopped checking in after receiving an unsupported config version",
            async {
                if completed_check_ins(&target.events(&id).await?) >= baseline + 2 {
                    return Ok(Some(()));
                }
                let current = case.state(&authority)?;
                ensure!(
                    current["config"] == stored && current.get("rejected").is_none(),
                    "agent replaced its stored config with an unsupported config version"
                );
                Ok(None)
            },
        );
        ensure!(
            case.state(&authority)?["config"] == stored,
            "agent replaced its stored config with an unsupported config version"
        );
        target.faults(&json!({ "config_version": null })).await?;
        let updated = case
            .until_state(&target, &authority, &id, "the supported config version", |state| {
                state["config"]["version"] == 1
                    && state["config"]["revision"]
                        .as_u64()
                        .is_some_and(|revision| revision > stored_revision)
            })
            .await?;
        ensure!(
            updated.get("rejected").is_none(),
            "agent recorded a rejection after an unsupported config version"
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_config_unsupported_version_on_enroll_keeps_pending(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        target
            .faults(&json!({ "channel_available": false, "config_version": 2 }))
            .await?;
        let token = new_token(case, 1).await?;
        case.write_pending(&token.text)?;
        poll!(
            case,
            WAIT,
            POLL,
            "agent did not retry an enrollment answered with an unsupported config version",
            async {
                if count(&target.requests(Some(&token)).await?, "enroll")? >= 2 {
                    return Ok(Some(()));
                }
                ensure!(
                    case.pending_path().exists() && !case.has_stored_identity()?,
                    "agent stored an identity or dropped its pending file for an unsupported config version"
                );
                Ok(None)
            },
        );
        ensure!(
            case.pending_path().exists()
                && !case.has_stored_identity()?
                && !case.rejection_path_for(&token.text).exists(),
            "agent treated an unsupported config version on enrollment as final"
        );
        target.faults(&json!({ "config_version": null })).await?;
        let (_, state) = case.enrolled(&target, &token).await?;
        ensure!(
            state["config"]["version"] == 1,
            "agent stored an enrollment config whose version is not 1"
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_multi_authority(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity/INTENT.md §Identities
    with_agent(ctx, None, true, async move |case| {
        // oracle: intent crates/agent-identity/INTENT.md §Identities
        let first = case.ctx.target.clone();
        let first_lifetime = case.ctx.leaf_lifetime();
        let second = case.ctx.second.clone().context("second authority required")?;
        let second_lifetime = second.leaf_lifetime();
        let second = second.target;
        // Every certificate of an identity is issued after its token is created.
        let first_issued_after = Instant::now();
        let first_token = first
            .management()
            .create_token(1, Duration::from_secs(3600), None)
            .await?;
        case.write_pending(&first_token.text)?;
        let (first_id, first_state) = case.enrolled(&first, &first_token).await?;
        let first_authority = field(&first_state, "authority_id")?.to_owned();
        case.until_identity_within(
            &first,
            &first_id,
            "first connection",
            renewal_aware_wait(first_issued_after, first_lifetime),
            |record| record.connected,
        )
        .await?;
        let second_issued_after = Instant::now();
        let second_token = second
            .management()
            .create_token(1, Duration::from_secs(3600), None)
            .await?;
        case.write_pending(&second_token.text)?;
        let (second_id, second_state) = case.enrolled(&second, &second_token).await?;
        let second_authority = field(&second_state, "authority_id")?.to_owned();
        ensure!(
            first_authority != second_authority,
            "two mocks returned the same authority ID"
        );
        case.until_identity_within(
            &second,
            &second_id,
            "second connection",
            renewal_aware_wait(second_issued_after, second_lifetime),
            |record| record.connected,
        )
        .await?;
        // Enrolling with the second authority leaves the first identity alone, and the test's leaves outlast it, so no expiry closes its stream.
        ensure!(
            case.identity_record(&first, &first_id).await?.connected,
            "first authority was disconnected"
        );
        ensure!(
            case.identity_path(&first_authority).exists(),
            "first identity not stored"
        );
        ensure!(
            case.identity_path(&second_authority).exists(),
            "second identity not stored"
        );
        ensure!(
            first_state["token_sha256"] == token_file_id(&first_token.text)
                && second_state["token_sha256"] == token_file_id(&second_token.text),
            "multi-authority token hashes are incorrect"
        );
        case.stop().await?;
        case.until_identity(&first, &first_id, "first authority offline", |record| !record.connected)
            .await?;
        case.until_identity(&second, &second_id, "second authority offline", |record| {
            !record.connected
        })
        .await?;
        case.start().await?;
        case.until_identity_within(
            &first,
            &first_id,
            "first authority reconnected",
            renewal_aware_wait(first_issued_after, first_lifetime),
            |record| record.connected,
        )
        .await?;
        case.until_identity_within(
            &second,
            &second_id,
            "second authority reconnected",
            renewal_aware_wait(second_issued_after, second_lifetime),
            |record| record.connected,
        )
        .await?;
        ensure!(
            case.state(&first_authority)?["token_sha256"] == first_state["token_sha256"]
                && case.state(&second_authority)?["token_sha256"] == second_state["token_sha256"],
            "multi-authority identities changed across restart"
        );
        Ok(())
    })
    .await
}

pub(crate) async fn a_key_non_exportable(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent crates/device-key/INTENT.md §Private keys
    // oracle: intent crates/device-key/INTENT.md §Access
    #[cfg(windows)]
    {
        with_agent(ctx.clone(), None, true, async move |case| {
            let target = case.ctx.target.clone();
            let (id, state) = case.enroll_new(&target, 1).await?;
            crate::windows::assert_non_exportable(key_name(&state, "current")?)?;
            crate::windows::assert_machine_key_acl(key_name(&state, "current")?)?;
            case.check_key_protection(field(&state, "authority_id")?, &state)?;
            if case.ctx.channel_available {
                case.until_identity(&target, &id, "signed channel Hello", |record| record.connected)
                    .await?;
            } else {
                case.set_metadata_hostname("acl-signing-probe")?;
                case.until_identity(&target, &id, "signed check-in", |record| {
                    record.metadata_value("hostname") == Some("acl-signing-probe")
                })
                .await?;
            }
            Ok(())
        })
        .await?;
        if !crate::windows::running_as_system()? {
            if !crate::windows::running_as_elevated_administrator()? {
                return Err(crate::Incomplete("requires an elevated administrator for the SYSTEM fixture").into());
            }
            return system_fixture::run(ctx).await;
        }
        return with_agent(ctx, None, false, async move |case| {
            case.set_acl_grant_current_user(false)?;
            case.start().await?;
            let target = case.ctx.target.clone();
            let (id, state) = case.enroll_new(&target, 1).await?;
            let key = key_name(&state, "current")?;
            crate::windows::assert_non_exportable(key)?;
            crate::windows::assert_machine_key_acl(key)?;
            case.check_key_protection(field(&state, "authority_id")?, &state)?;
            if case.ctx.channel_available {
                case.until_identity(&target, &id, "SYSTEM-only key signed channel Hello", |record| {
                    record.connected
                })
                .await?;
            } else {
                case.set_metadata_hostname("system-acl-signing-probe")?;
                case.until_identity(&target, &id, "SYSTEM-only key signed check-in", |record| {
                    record.metadata_value("hostname") == Some("system-acl-signing-probe")
                })
                .await?;
            }
            Ok(())
        })
        .await;
    }
    #[cfg(not(windows))]
    {
        let _ = ctx;
        anyhow::bail!("non-exportable key test is Windows-only")
    }
}

pub(crate) async fn a_file_backend_permissions(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent crates/device-key/INTENT.md §Access
    // oracle: intent crates/device-key/INTENT.md §File backend
    #[cfg(unix)]
    {
        return with_agent(ctx, None, true, async move |case| {
            let target = case.ctx.target.clone();
            let (_, state) = case.enroll_new(&target, 1).await?;
            let name = key_name(&state, "current")?;
            let key_file = case.key_file_path(name);
            assert_file_key_access(&key_file)?;
            Ok(())
        })
        .await;
    }
    #[cfg(not(unix))]
    {
        let _ = ctx;
        anyhow::bail!("file permission test is Unix-only")
    }
}

pub(crate) async fn a_rotation_migrates_connected_agent(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §root-rotation
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    ensure!(
        ctx.mock() || ctx.disposable_dvls_target,
        "DVLS rotation requires --disposable-dvls-target"
    );
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let (id, initial_state) = case.enroll_new(&target, 1).await?;
        let authority = field(&initial_state, "authority_id")?.to_owned();
        let old = case
            .until_identity(&target, &id, "old-root connection", |record| record.connected)
            .await?;
        let old_root = old.issuer().context("identity has no current certificate")?.to_owned();
        let started = if case.ctx.mock() {
            target.management().rotate(RotationDeadline::Default).await?
        } else {
            crate::protocol::wait_rotation_idle(&target, case.ctx.dvls_rotation_window_secs).await?;
            let deadline = time::OffsetDateTime::now_utc()
                + time::Duration::seconds(i64::try_from(case.ctx.dvls_rotation_window_secs)?);
            target.management().rotate(RotationDeadline::At(deadline)).await?
        };
        let initial = started.active_identities_on_old_root;
        ensure!(initial >= 1, "the agent's old-root identity was not counted");
        // The test's leaves outlast it, so only the rotation renews the old-root certificate, and no expiry closes a stream.
        let new = case
            .until_identity(&target, &id, "connected new-root certificate", |record| {
                record.issuer() != Some(&*old_root)
                    && record.connected
                    && record
                        .certificates
                        .as_ref()
                        .is_some_and(|items| items.iter().any(|cert| cert.status == CertificateStatus::Retired))
            })
            .await?;
        ensure!(new.issuer() != Some(&*old_root), "agent did not migrate roots");
        let new_root = new.issuer().context("identity has no current certificate")?.to_owned();
        let stored = case
            .until_state(&target, &authority, &id, "stored new-root chain", |state| {
                state["keys"]["current"]["certificate_chain"]
                    .as_array()
                    .and_then(|chain| chain.last())
                    .and_then(Value::as_str)
                    .and_then(|root| crate::signer::thumbprint(root).ok())
                    .is_some_and(|issuer| issuer == new_root)
                    && state["keys"].get("pending").is_none()
                    && state["keys"].get("previous").is_none()
            })
            .await?;
        ensure!(
            stored["keys"]["current"]["certificate_chain"]
                .as_array()
                .is_some_and(|chain| chain.len() >= 2),
            "migrated agent did not persist the new-root chain"
        );
        case.stop().await?;
        case.until_identity(&target, &id, "offline new-root channel", |record| !record.connected)
            .await?;
        let authenticated_before = if case.ctx.mock() {
            Some(count(&target.requests(None).await?, "authenticated_connects")?)
        } else {
            None
        };
        case.start().await?;
        case.until_identity(&target, &id, "new-root channel after restart", |record| {
            record.connected && record.issuer() == Some(&*new_root)
        })
        .await?;
        if let Some(before) = authenticated_before {
            ensure!(
                count(&target.requests(None).await?, "authenticated_connects")? > before,
                "restarted agent did not authenticate its new-root channel"
            );
        }
        let rotation = target.management().rotation().await?;
        if rotation.rotating() {
            ensure!(
                rotation.active_identities_on_old_root < initial,
                "agent migration did not reduce the old-root count"
            );
        }
        if !case.ctx.mock() {
            crate::protocol::wait_rotation_idle(&target, case.ctx.dvls_rotation_window_secs).await?;
        }
        Ok(())
    })
    .await
}

pub(crate) async fn a_rotation_migrates_through_check_in(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §root-rotation
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §check-in
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        target.faults(&json!({ "channel_available": false })).await?;
        let (id, initial_state) = case.enroll_new(&target, 1).await?;
        let authority = field(&initial_state, "authority_id")?.to_owned();
        let before = case.identity_record(&target, &id).await?;
        ensure!(!before.connected, "channel unavailable but agent connected");
        let old_root = before
            .issuer()
            .context("identity has no current certificate")?
            .to_owned();
        let before_requests = target.requests(None).await?;
        let confirms_before = count(&before_requests, "confirm")?;
        let blocked_before = count(&before_requests, "confirm_retry_503")?;
        let check_ins_before = count(&before_requests, "check_in")?;
        let rotation_sequence_start = before_requests["request_sequence"]
            .as_array()
            .context("mock request sequence missing")?
            .len();
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": true }))
                .await?,
            200,
        )?;
        target
            .faults(&json!({ "fail_next_response": { "endpoint": "confirm", "status": 503 } }))
            .await?;
        target.management().rotate(RotationDeadline::Default).await?;
        let new = case
            .until_identity(&target, &id, "check-in-triggered new-root renewal", |record| {
                record.certificates.as_ref().is_some_and(|certs| {
                    certs
                        .iter()
                        .any(|cert| cert.issuer != old_root && cert.status == CertificateStatus::Pending)
                })
            })
            .await?;
        ensure!(
            count(&target.requests(None).await?, "check_in")? > check_ins_before
                && target
                    .events(&id)
                    .await?
                    .iter()
                    .any(|event| event["type"] == "check_in_received" && event["renewal_requested"] == true),
            "channelless rotation did not request renewal through check-in"
        );
        ensure!(!new.connected, "scheduled renewal unexpectedly required a channel");
        let pending = new
            .certificates
            .as_ref()
            .context("scheduled certificates missing")?
            .iter()
            .find(|cert| cert.issuer != old_root && cert.status == CertificateStatus::Pending)
            .context("new-root pending certificate missing")?;
        let new_root = pending.issuer.clone();
        let pending_thumb = pending.thumbprint.clone();
        let stored = case
            .until_state(&target, &authority, &id, "stored pending new-root chain", |state| {
                state["keys"]["pending"]["certificate_chain"]
                    .as_array()
                    .and_then(|chain| chain.last())
                    .and_then(Value::as_str)
                    .and_then(|root| crate::signer::thumbprint(root).ok())
                    .is_some_and(|issuer| issuer == new_root)
            })
            .await?;
        let pending_key = key_name(&stored, "pending")?.to_owned();
        poll!(
            case,
            WAIT,
            POLL,
            "agent did not retry confirm after new-root renewal",
            async {
                let requests = target.requests(None).await?;
                if count(&requests, "confirm")? > confirms_before
                    && count(&requests, "confirm_retry_503")? > blocked_before
                    && target.control("faults", &json!({})).await?.body["fail_next_response"].is_null()
                {
                    return Ok(Some(()));
                }
                Ok(None)
            },
        );
        case.stop().await?;
        ensure!(
            key_name(&case.state(&authority)?, "pending")? == pending_key
                && case
                    .identity_record(&target, &id)
                    .await?
                    .has_certificate(&pending_thumb, CertificateStatus::Pending),
            "new-root pending key was not persisted across restart"
        );
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                .await?,
            200,
        )?;
        let before_restart = target.requests(None).await?;
        let restart_sequence_start = before_restart["request_sequence"]
            .as_array()
            .context("mock request sequence missing")?
            .len();
        let confirms = count(&before_restart, "confirm")?;
        case.start().await?;
        case.until_identity(&target, &id, "confirmed new-root key after restart", |record| {
            record.issuer() == Some(&*new_root) && current_thumbprint(record).is_ok_and(|thumb| thumb == pending_thumb)
        })
        .await?;
        let requests = target.requests(None).await?;
        ensure!(
            count(&requests, "confirm")? > confirms
                && requests["request_sequence"]
                    .as_array()
                    .and_then(|sequence| sequence.get(restart_sequence_start))
                    .is_some_and(|entry| entry == "confirm"),
            "agent did not retry confirm first with its persisted pending key"
        );
        assert_check_in_triggers_renewal(&requests, rotation_sequence_start)?;
        case.until_state(
            &target,
            &authority,
            &id,
            "the confirmed new-root chain after restart",
            |state| {
                key_name(state, "current").is_ok_and(|name| name == pending_key)
                    && state["keys"]["current"]["certificate_chain"]
                        .as_array()
                        .and_then(|chain| chain.last())
                        .and_then(Value::as_str)
                        .is_some_and(|root| crate::signer::thumbprint(root).is_ok_and(|issuer| issuer == new_root))
                    && state["keys"].get("pending").is_none()
                    && state["keys"].get("previous").is_none()
            },
        )
        .await?;
        Ok(())
    })
    .await
}

pub(crate) async fn a_rotation_migrates_on_schedule(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §root-rotation
    // oracle: intent crates/agent-identity/INTENT.md §Schedules
    with_agent(ctx, Some(50), false, async move |case| {
        let target = case.ctx.target.clone();
        target.faults(&json!({ "channel_available": false })).await?;
        let config_path = case.path().join("agent.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path)?)?;
        // Keep the next check-in later than scheduled renewal so it cannot deliver the rotation request.
        config["__debug__"]["identity"]["check_in_interval_secs"] = json!(120);
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;

        let token = new_token(case, 1).await?;
        case.write_pending(&token.text)?;
        case.start().await?;
        let (id, state) = case.enrolled(&target, &token).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        ensure!(
            state["config"].get("agent_channel_url").is_none(),
            "scheduled-rotation fixture unexpectedly offers a channel"
        );
        let old = case.identity_record(&target, &id).await?;
        ensure!(!old.connected, "scheduled-rotation fixture connected");
        let old_root = old.issuer().context("identity has no current certificate")?.to_owned();
        let old_thumb = current_thumbprint(&old)?.to_owned();
        poll!(
            case,
            WAIT,
            POLL,
            "agent did not check in before scheduled rotation",
            async {
                if count(&target.requests(None).await?, "check_in")? > 0 {
                    return Ok(Some(()));
                }
                Ok(None)
            },
        );
        let before = target.requests(None).await?;
        ensure!(
            count(&before, "renew")? == 0 && count(&before, "confirm")? == 0,
            "agent renewed before rotation began"
        );
        target.management().rotate(RotationDeadline::Default).await?;
        let migrated = poll!(
            case,
            Duration::from_secs(70),
            POLL,
            "agent did not migrate roots on schedule before the next check-in",
            async {
                let record = case.identity_record(&target, &id).await?;
                if record.issuer() != Some(&*old_root) && !record.renewal_requested && !record.connected {
                    return Ok(Some(record));
                }
                Ok(None)
            },
        );
        let new_root = migrated
            .issuer()
            .context("identity has no current certificate")?
            .to_owned();
        let after = target.requests(None).await?;
        ensure!(
            count(&after, "check_in")? == count(&before, "check_in")?
                && count(&after, "renew")? > count(&before, "renew")?
                && count(&after, "confirm")? > count(&before, "confirm")?
                && count(&after, "channel_attempts")? == 0
                && target
                    .events(&id)
                    .await?
                    .iter()
                    .any(|event| event["type"] == "renew_received" && event["cert_thumbprint"] == old_thumb),
            "agent did not renew under the new root on schedule before another check-in"
        );
        case.until_state(&target, &authority, &id, "stored scheduled new-root chain", |state| {
            state["keys"]["current"]["certificate_chain"]
                .as_array()
                .and_then(|chain| chain.last())
                .and_then(Value::as_str)
                .and_then(|root| crate::signer::thumbprint(root).ok())
                .is_some_and(|issuer| issuer == new_root)
                && state["keys"].get("pending").is_none()
                && state["keys"].get("previous").is_none()
        })
        .await?;
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::Generate as _;
    use p256::pkcs8::EncodePrivateKey as _;

    use super::*;

    /// Agent metadata that conforms to [CONTRACT.agent-identity.md] §3.1 "Metadata sent by the agent", apart from the `machine_id` that each caller decides.
    ///
    /// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
    fn agent_metadata(hostname: &str) -> Value {
        json!({
            "hostname": hostname,
            "os_name": "os",
            "os_version": "1",
            "arch": std::env::consts::ARCH,
            "agent_version": "1",
            "key_storage": key_storage::builtin_default(),
            "key_storage_available": key_storage::builtin_default(),
        })
    }

    #[test]
    fn agent_metadata_check_refuses_listed_format_characters_only() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
        validate_agent_metadata(
            &agent_metadata("host\u{2070}name"),
            None,
            &ExpectedMachineId::NotCompared,
        )
        .expect("U+2070 is outside the list");
        let listed = invisible_format_character_range_ends()
            .into_iter()
            .chain(INTERIOR_INVISIBLE_FORMAT_CHARACTERS);
        for character in listed {
            let refused = validate_agent_metadata(
                &agent_metadata(&format!("host{character}name")),
                None,
                &ExpectedMachineId::NotCompared,
            )
            .expect_err(&format!("U+{:04X} is listed", u32::from(character)));
            assert!(
                refused.to_string().contains("invisible format character"),
                "U+{:04X} was refused for another reason: {refused}",
                u32::from(character)
            );
        }
    }

    #[test]
    fn agent_metadata_check_refuses_c0_del_and_c1_characters_only() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
        for character in ['\u{0}', '\u{1F}', '\u{7F}', '\u{80}', '\u{9F}'] {
            validate_agent_metadata(
                &agent_metadata(&format!("host{character}name")),
                None,
                &ExpectedMachineId::NotCompared,
            )
            .expect_err(&format!("U+{:04X} is a control character", u32::from(character)));
        }
        for character in [' ', '~', '\u{A0}'] {
            let accepted = validate_agent_metadata(
                &agent_metadata(&format!("host{character}name")),
                None,
                &ExpectedMachineId::NotCompared,
            );
            assert!(
                accepted.is_ok(),
                "U+{:04X} is not a control character, yet was refused: {accepted:?}",
                u32::from(character)
            );
        }
    }

    #[test]
    fn key_names_require_this_runs_prefix_and_a_canonical_uuid() -> anyhow::Result<()> {
        // oracle: intent crates/device-key/INTENT.md §Key name
        // oracle: intent crates/agent-identity/INTENT.md §Stored identities
        // oracle: intent devolutions-agent/src/identity/INTENT.md §Configuration
        let prefix = format!("conformance-{}", uuid::Uuid::new_v4().simple());
        let key_uuid = uuid::Uuid::new_v4();
        let name = format!("{prefix}_{key_uuid}");
        validate_key_name(&prefix, &name)?;
        validate_key_name(
            "devolutions-agent-identity",
            &format!("devolutions-agent-identity_{key_uuid}"),
        )?;
        ensure!(
            validate_key_name(&prefix, &format!("{prefix}_{}", key_uuid.to_string().to_uppercase())).is_err(),
            "uppercase UUID was accepted"
        );
        ensure!(
            validate_key_name(&prefix, &format!("devolutions-agent-identity_{key_uuid}")).is_err(),
            "a key without the run prefix was accepted"
        );
        ensure!(
            validate_key_name(&prefix, &format!("{prefix}_{key_uuid}.p8")).is_err(),
            "a key name with a file extension was accepted"
        );
        ensure!(
            validate_key_name(&prefix, &format!("{prefix}{key_uuid}")).is_err(),
            "a key name without the underscore separator was accepted"
        );
        ensure!(
            validate_key_name(&prefix, &format!("{prefix}-other_{key_uuid}")).is_err()
                && !key_belongs_to_run(&format!("{prefix}-other_{key_uuid}"), &prefix),
            "a longer prefix was treated as this run's prefix"
        );
        for invalid in ["", "Conformance", "conformance_", "conformance.dot"] {
            ensure!(
                validate_key_name(invalid, &format!("{invalid}_{key_uuid}")).is_err(),
                "invalid device-key prefix {invalid:?} was accepted"
            );
        }
        let too_long = "a".repeat(65);
        let max_length = "a".repeat(64);
        validate_key_name(&max_length, &format!("{max_length}_{key_uuid}"))?;
        ensure!(
            validate_key_name(&too_long, &format!("{too_long}_{key_uuid}")).is_err(),
            "a device-key prefix longer than 64 characters was accepted"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn error_log_level_is_distinct_from_message_text() {
        // oracle: mutant a log line counts as an error when `ERROR` appears anywhere in it, including its message
        assert!(is_error_level_log_line(
            "2026-10-19T00:00:00Z ERROR devolutions_agent: unavailable backend"
        ));
        assert!(is_error_level_log_line(
            r#"{"level":"error","fields":{"message":"unavailable backend"}}"#
        ));
        assert!(!is_error_level_log_line(
            "2026-10-19T00:00:00Z INFO devolutions_agent: ERROR was returned"
        ));
        assert!(is_error_level_log_line(
            "\u{1b}[2m2026-10-19T00:00:00Z\u{1b}[0m \u{1b}[31mERROR\u{1b}[0m \u{1b}[2mdevolutions_agent\u{1b}[0m\u{1b}[2m:\u{1b}[0m unavailable backend"
        ));
        assert!(!is_error_level_log_line(
            "\u{1b}[2m2026-10-19T00:00:00Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2mdevolutions_agent\u{1b}[0m\u{1b}[2m:\u{1b}[0m ERROR was returned"
        ));
    }

    #[tokio::test]
    async fn orphan_audit_accepts_both_records_and_cleanup_is_prefix_scoped() -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
        // oracle: intent crates/agent-identity/INTENT.md §Stored identities
        // oracle: intent crates/device-key/INTENT.md §Operations
        // oracle: intent devolutions-agent/src/identity/INTENT.md §Configuration
        let mut case = file_backend_case().await?;
        let prefix = case.ctx.key_name_prefix.clone();
        let fixture_token = "dvaet1.fixturebag.fixturesecret";
        let fixture_hash = token_file_id(fixture_token);
        case.add_token(fixture_token);
        let pending_name = case
            .pending_path()
            .file_name()
            .context("pending filename")?
            .to_string_lossy()
            .to_string();
        ensure!(
            pending_name.starts_with(&token_file_id(fixture_token)) && token_file_id(fixture_token).len() == 64,
            "pending filename is not keyed by the full token SHA-256"
        );
        let config: Value = serde_json::from_slice(&std::fs::read(case.path().join("agent.json"))?)?;
        ensure!(
            config["__debug__"]["identity"]["key_name_prefix"] == prefix,
            "agent.json omitted the run prefix"
        );
        ensure!(
            config["__debug__"]["identity"]["metadata_override_path"]
                == case.metadata_override_path().to_string_lossy().as_ref(),
            "agent.json omitted the metadata override path"
        );
        case.set_metadata_hostname("refreshed-host")?;
        ensure!(
            serde_json::from_slice::<Value>(&std::fs::read(case.metadata_override_path())?)?["hostname"]
                == "refreshed-host",
            "metadata override was not refreshed"
        );
        let name = format!("{prefix}_{}", uuid::Uuid::new_v4());
        let foreign = format!("devolutions-agent-identity_{}", uuid::Uuid::new_v4());
        let overlapping = format!("{prefix}-other_{}", uuid::Uuid::new_v4());
        std::fs::create_dir_all(case.key_file_path(&name).parent().context("key directory")?)?;
        let write_run_key = |path: &Path| -> anyhow::Result<()> {
            #[cfg(unix)]
            {
                use std::io::Write as _;
                use std::os::unix::fs::OpenOptionsExt as _;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)?;
                file.write_all(b"run-owned-key")?;
            }
            #[cfg(not(unix))]
            std::fs::write(path, b"run-owned-key")?;
            Ok(())
        };
        write_run_key(&case.key_file_path(&name))?;
        std::fs::write(case.key_file_path(&foreign), b"foreign-key")?;
        std::fs::write(case.key_file_path(&overlapping), b"other-run-key")?;
        ensure!(
            case.data_dir().audit_identity_tree().is_err(),
            "an unexpected key file in the identity tree was accepted"
        );
        ensure!(
            case.data_dir().audit_orphan_keys().is_err(),
            "an unrecorded file-backed key was accepted"
        );
        std::fs::create_dir_all(case.in_progress_path().parent().context("pending directory")?)?;
        std::fs::write(
            case.in_progress_path(),
            serde_json::to_vec(
                &json!({ "version": 1, "token_sha256": fixture_hash, "key_name": name, "key_storage": "file" }),
            )?,
        )?;
        case.data_dir().audit_orphan_keys()?;
        std::fs::remove_file(case.key_file_path(&foreign))?;
        std::fs::remove_file(case.key_file_path(&overlapping))?;
        case.data_dir().audit_identity_tree()?;
        // A record that names the key with another key storage leaves the key file unrecorded.
        std::fs::write(
            case.in_progress_path(),
            serde_json::to_vec(
                &json!({ "version": 1, "token_sha256": fixture_hash, "key_name": name, "key_storage": key_storage::UNLISTED }),
            )?,
        )?;
        ensure!(
            case.data_dir().audit_identity_tree().is_err(),
            "a key file recorded in another key storage was accepted"
        );
        ensure!(
            case.data_dir().audit_orphan_keys().is_err(),
            "a key recorded in another key storage was accepted as recorded"
        );
        for record in [
            json!({ "version": 1, "token_sha256": fixture_hash, "key_name": name }),
            json!({ "version": 1, "token_sha256": fixture_hash, "key_name": name, "key_storage": "File" }),
        ] {
            std::fs::write(case.in_progress_path(), serde_json::to_vec(&record)?)?;
            ensure!(
                case.data_dir().audit_orphan_keys().is_err(),
                "an in-progress record without a well-formed key_storage was accepted: {record}"
            );
        }
        write_run_key(&case.key_file_path(&foreign))?;
        write_run_key(&case.key_file_path(&overlapping))?;
        std::fs::remove_file(case.in_progress_path())?;
        let identity = case.identity_path(&uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(identity.parent().context("authority directory")?)?;
        std::fs::write(
            &identity,
            serde_json::to_vec(&json!({ "keys": { "current": { "key_name": name, "key_storage": "file" } } }))?,
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o600))?;
        }
        let stored: Value = serde_json::from_slice(&std::fs::read(&identity)?)?;
        let authority = identity
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            .context("fixture authority")?;
        case.check_key_protection(authority, &stored)?;
        std::fs::remove_file(case.key_file_path(&name))?;
        ensure!(
            case.check_key_protection(authority, &stored).is_err(),
            "settled identity accepted a missing current key"
        );
        write_run_key(&case.key_file_path(&name))?;
        case.data_dir().audit_orphan_keys()?;
        std::fs::remove_file(&identity)?;
        std::fs::write(
            case.in_progress_path(),
            serde_json::to_vec(
                &json!({ "version": 1, "token_sha256": fixture_hash, "key_name": name, "key_storage": "file" }),
            )?,
        )?;
        case.cleanup_run_keys()?;
        ensure!(!case.key_file_path(&name).exists(), "run-owned key survived cleanup");
        ensure!(
            case.key_file_path(&foreign).exists(),
            "cleanup deleted a key outside the run prefix"
        );
        ensure!(
            case.key_file_path(&overlapping).exists(),
            "cleanup deleted a key with a longer prefix"
        );
        std::fs::remove_file(case.key_file_path(&foreign))?;
        std::fs::remove_file(case.key_file_path(&overlapping))?;
        case.data_dir().audit_identity_tree()?;
        let unknown = case.path().join("identity").join("notes").join("unknown.bin");
        std::fs::create_dir_all(unknown.parent().context("unknown entry parent")?)?;
        std::fs::write(&unknown, b"non-key data")?;
        case.data_dir().audit_identity_tree()?;
        let unexpected_key = unknown.with_file_name("other.p8");
        std::fs::write(&unexpected_key, b"not even a PKCS#8 key")?;
        ensure!(
            case.data_dir().audit_identity_tree().is_err(),
            "nested unrecorded .p8 file was accepted"
        );
        std::fs::remove_file(unexpected_key)?;
        let pkcs8 = p256::SecretKey::generate_from_rng(&mut rand::rng()).to_pkcs8_der()?;
        std::fs::write(&unknown, pkcs8.as_bytes())?;
        ensure!(
            case.data_dir().audit_identity_tree().is_err(),
            "unrecorded PKCS#8 DER was accepted"
        );
        std::fs::write(
            &unknown,
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                base64::engine::general_purpose::STANDARD.encode(pkcs8.as_bytes())
            ),
        )?;
        ensure!(
            case.data_dir().audit_identity_tree().is_err(),
            "unrecorded PKCS#8 PEM was accepted"
        );
        let encrypted_pkcs8 = base64::engine::general_purpose::STANDARD.decode(
            "MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBBDtKK//RHOS2x0YBSFGGtPAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQKvLa4jZ8A4WkKva7UtVXYQSBkEduwKFQc7aMPm4ZYJQGbaBB72cZ+GZ3lsNoaJaVZcwLNBLXwUgfQEnx6o5L7LAa8/L2G+6X6uJxnxyQzH4yhvW7RqambZYzGluT8kf3uxdu/TBlAfjKRZQht0Q5niBAmut2MbKgfAk4JryXi/mKvQ0QAMDN6grm1Nlq2xa5ZgCILNnfErEQbRexpKQiSLSW9w==",
        )?;
        std::fs::write(&unknown, encrypted_pkcs8)?;
        ensure!(
            case.data_dir().audit_identity_tree().is_err(),
            "unrecorded encrypted PKCS#8 DER was accepted"
        );
        std::fs::remove_file(unknown)?;
        let unrelated = identity.with_file_name(".identity.json.notes");
        std::fs::write(&unrelated, b"not a temporary file")?;
        case.data_dir().audit_identity_tree()?;
        std::fs::remove_file(unrelated)?;
        let template = identity.with_file_name(".identity.json.template");
        std::fs::write(&template, b"also not a temporary file")?;
        case.data_dir().audit_identity_tree()?;
        std::fs::remove_file(template)?;
        // A record's atomic write can leave its temporary file when the agent is stopped mid-write.
        for leftover in [
            identity.with_file_name(format!(".identity.json-{}.tmp", uuid::Uuid::new_v4())),
            case.in_progress_path().with_extension("json.tmp"),
        ] {
            std::fs::write(&leftover, b"temp")?;
            case.data_dir()
                .audit_identity_tree()
                .with_context(|| format!("temporary record file {} was rejected", leftover.display()))?;
            std::fs::write(&leftover, pkcs8.as_bytes())?;
            ensure!(
                case.data_dir().audit_identity_tree().is_err(),
                "a temporary record file holding a private key was accepted"
            );
            std::fs::remove_file(leftover)?;
        }
        for leftover in [
            case.pending_path()
                .with_extension(if cfg!(windows) { "dat.tmp" } else { "json.tmp" }),
            case.key_file_path(&name).with_extension("p8.tmp"),
        ] {
            std::fs::write(&leftover, b"temp")?;
            ensure!(
                case.data_dir().audit_identity_tree().is_err(),
                "leftover pending or key-file sibling was accepted"
            );
            std::fs::remove_file(leftover)?;
        }
        std::fs::remove_file(case.in_progress_path())?;
        ensure!(
            case.data_dir().recorded_keys()?.is_empty(),
            "the removed key is still recorded"
        );
        let untracked_pending = case
            .path()
            .join("identity")
            .join("pending")
            .join(format!("{}.json.tmp", token_file_id("untracked-token")));
        std::fs::write(&untracked_pending, b"partial temporary file")?;
        ensure!(
            case.data_dir().audit_identity_tree().is_err(),
            "temporary sibling survived after its record was removed"
        );
        std::fs::remove_file(untracked_pending)?;
        for copy in [
            case.key_file_path(&name).with_extension("p8.tmp"),
            case.key_file_path(&name)
                .with_file_name(format!(".{name}-{}.deleted", uuid::Uuid::new_v4())),
        ] {
            std::fs::write(&copy, pkcs8.as_bytes())?;
            case.data_dir()
                .audit_identity_tree()
                .context("a leftover copy of a deleted key before a later key-store operation was rejected")?;
            ensure!(
                assert_no_copy_of_deleted_key(&case, &name).is_err(),
                "a leftover copy of a deleted key was not reported"
            );
            std::fs::remove_file(copy)?;
        }
        case.data_dir().audit_identity_tree()?;
        let unknown_authority = case
            .path()
            .join("identity")
            .join("authorities")
            .join("not-an-authority");
        std::fs::create_dir_all(&unknown_authority)?;
        std::fs::write(unknown_authority.join("identity.json"), b"not an identity")?;
        case.data_dir().audit_identity_tree()?;
        case.data_dir().audit_stored_keys()?;
        case.data_dir().audit_orphan_keys()?;
        std::fs::remove_dir_all(unknown_authority)?;
        case.finish().await?;
        Ok(())
    }

    #[tokio::test]
    async fn settled_key_check_accepts_a_current_key_retired_after_the_snapshot() -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity/INTENT.md §Stored identities
        let case = file_backend_case().await?;
        let authority = uuid::Uuid::new_v4().to_string();
        let (retired, retired_key) = new_file_key(&case)?;
        let (renewed, renewed_key) = new_file_key(&case)?;
        let snapshot = json!({ "keys": { "current": key_slot(&retired, &retired_key)? } });
        // After `confirm`, the retired key moves to `previous` and is deleted before its name leaves the record.
        write_identity(
            &case,
            &authority,
            &json!({ "keys": {
                "current": key_slot(&renewed, &renewed_key)?,
                "previous": key_slot(&retired, &retired_key)?
            } }),
        )?;
        std::fs::remove_file(case.key_file_path(&retired))?;
        case.check_key_protection(&authority, &snapshot)
    }

    #[tokio::test]
    async fn settled_key_check_still_checks_the_current_key_of_the_latest_record() -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity-conformance/INTENT.md §Coverage
        let case = file_backend_case().await?;
        let authority = uuid::Uuid::new_v4().to_string();
        let (retired, retired_key) = new_file_key(&case)?;
        let (renewed, renewed_key) = new_file_key(&case)?;
        let other_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let snapshot = json!({ "keys": { "current": key_slot(&retired, &retired_key)? } });
        std::fs::remove_file(case.key_file_path(&retired))?;
        // The two records differ only in the leaf of their current key, so only that leaf decides the outcome.
        write_identity(
            &case,
            &authority,
            &json!({ "keys": { "current": key_slot(&renewed, &renewed_key)? } }),
        )?;
        case.check_key_protection(&authority, &snapshot)
            .context("a current key that matches the latest record's leaf was refused")?;
        write_identity(
            &case,
            &authority,
            &json!({ "keys": { "current": key_slot(&renewed, &other_key)? } }),
        )?;
        ensure!(
            case.check_key_protection(&authority, &snapshot).is_err(),
            "a current key that does not match the latest record's leaf was accepted"
        );
        Ok(())
    }

    /// A failed or timed-out case must leave its directory, with the agent's logs, for diagnosis, while a passing one must not leave clutter.
    #[tokio::test]
    async fn a_case_keeps_its_directory_only_until_it_passes() -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity-conformance/INTENT.md §Shape
        let mut failed = file_backend_case().await?;
        failed.keep = true;
        let kept = failed.path().to_path_buf();
        std::fs::write(kept.join("agent-stdout.log"), b"evidence")?;
        drop(failed);
        let survived = std::fs::read(kept.join("agent-stdout.log"));
        std::fs::remove_dir_all(&kept)?;
        assert_eq!(survived?, b"evidence");
        let passed = file_backend_case().await?;
        let removed = passed.path().to_path_buf();
        drop(passed);
        assert!(!removed.exists(), "a passing case left {}", removed.display());
        Ok(())
    }

    /// A host without a `machine_id` provides none for the agent to send, so the agent must omit the key, because [CONTRACT.agent-identity.md] §3.1 "Metadata sent by the agent" has it sent "when the OS provides a value".
    ///
    /// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
    #[test]
    fn machine_id_is_refused_when_the_host_provides_none() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
        for host_contents in [None, Some(""), Some("\n"), Some("\u{200B}\n")] {
            let expected = expected_machine_id(host_contents);
            assert_eq!(
                expected,
                ExpectedMachineId::Absent,
                "host contents {host_contents:?} leave nothing for the agent to send"
            );
            validate_agent_metadata(&agent_metadata("host"), None, &expected).unwrap_or_else(|error| {
                panic!("an agent that omits machine_id on a host with contents {host_contents:?} was refused: {error}")
            });
            let mut invented = agent_metadata("host");
            invented["machine_id"] = json!("invented");
            validate_agent_metadata(&invented, None, &expected).expect_err(&format!(
                "a machine_id the host does not provide, with host contents {host_contents:?}"
            ));
        }
    }

    /// A host with a `machine_id` has the agent send exactly that value ([CONTRACT.agent-identity.md] §3.1 "Metadata sent by the agent"), so a different value and a missing key both fail.
    ///
    /// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
    #[test]
    fn machine_id_must_equal_the_host_value() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
        let expected = ExpectedMachineId::Value("0123abcd".to_owned());
        let mut sent = agent_metadata("host");
        sent["machine_id"] = json!("0123abcd");
        validate_agent_metadata(&sent, None, &expected).expect("the host's value, sent as-is");
        sent["machine_id"] = json!("4567ef01");
        let mismatch = validate_agent_metadata(&sent, None, &expected)
            .expect_err("machine_id 4567ef01 against the host's 0123abcd")
            .to_string();
        assert!(
            mismatch.contains("4567ef01") && mismatch.contains("0123abcd"),
            "the mismatch message names neither the sent nor the expected value: {mismatch}"
        );
        sent["machine_id"] = json!(" 0123abcd ");
        validate_agent_metadata(&sent, None, &expected).expect_err("machine_id padded with spaces against 0123abcd");
        sent.as_object_mut().expect("fixture is an object").remove("machine_id");
        validate_agent_metadata(&sent, None, &expected).expect_err("a missing machine_id against the host's 0123abcd");
    }

    /// Where the check cannot read the host's value, the agent's `machine_id` is accepted whether it is present or not.
    #[test]
    fn machine_id_is_not_compared_when_the_host_value_is_unavailable() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
        let mut sent = agent_metadata("host");
        validate_agent_metadata(&sent, None, &ExpectedMachineId::NotCompared).expect("a missing machine_id");
        sent["machine_id"] = json!("any-value");
        validate_agent_metadata(&sent, None, &ExpectedMachineId::NotCompared).expect("machine_id any-value");
    }

    /// The agent sends `/etc/machine-id` "as-is" ([CONTRACT.agent-identity.md] §3.1 "Metadata sent by the agent") after the removal every value goes through, which drops control characters and trims nothing.
    ///
    /// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
    #[test]
    fn expected_machine_id_removes_control_characters_and_trims_nothing() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
        for (host_contents, expected) in [
            ("0123abcd\n", "0123abcd"),
            (" 0123abcd \u{7f}\n", " 0123abcd "),
            ("0123\u{80}abcd\u{9f}", "0123abcd"),
            ("0123\u{ad}abcd", "0123abcd"),
        ] {
            assert_eq!(
                expected_machine_id(Some(host_contents)),
                ExpectedMachineId::Value(expected.to_owned()),
                "host contents {host_contents:?}"
            );
        }
    }

    /// A missing `/etc/machine-id` means the OS provides no value, so the agent must omit the key ([CONTRACT.agent-identity.md] §3.1 "Metadata sent by the agent"), while a file the suite cannot read tells it nothing about what the host provides.
    ///
    /// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
    #[test]
    fn machine_id_expectation_follows_how_the_host_file_read_ended() {
        use std::io::{Error, ErrorKind};

        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
        assert_eq!(
            machine_id_expectation(Ok(String::from("0123abcd\n"))),
            ExpectedMachineId::Value("0123abcd".to_owned())
        );
        assert_eq!(
            machine_id_expectation(Err(Error::from(ErrorKind::NotFound))),
            ExpectedMachineId::Absent
        );
        // oracle: mutant an unreadable file aborting the run, or being read as a file that is absent
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidData,
            ErrorKind::IsADirectory,
        ] {
            assert_eq!(
                machine_id_expectation(Err(Error::from(kind))),
                ExpectedMachineId::NotCompared,
                "read error {kind:?}"
            );
        }
    }

    /// The agent truncates a value to 1024 UTF-8 bytes on a character boundary ([CONTRACT.agent-identity.md] §3.1 "Metadata sent by the agent"), so the expectation does too.
    ///
    /// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
    #[test]
    fn expected_machine_id_is_truncated_on_a_character_boundary() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
        let host = format!("{}\u{e9}", "a".repeat(1023));
        assert_eq!(
            expected_machine_id(Some(&host)),
            ExpectedMachineId::Value("a".repeat(1023)),
            "1023 bytes, then a two-byte character that does not fit"
        );
    }

    #[test]
    fn agent_metadata_requires_c14_fields_and_stable_platform_values() -> anyhow::Result<()> {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
        let mut metadata = json!({
            "hostname": "test-host",
            "os_name": "Windows",
            "os_version": "11",
            "arch": std::env::consts::ARCH,
            "agent_version": "2026.3.0",
            "key_storage": key_storage::builtin_default(),
            "key_storage_available": key_storage::builtin_default()
        });
        let not_compared = ExpectedMachineId::NotCompared;
        validate_agent_metadata(&metadata, Some("2026.3.0"), &not_compared)?;
        for key in REQUIRED_METADATA_KEYS {
            let mut missing = metadata.clone();
            missing.as_object_mut().context("fixture metadata")?.remove(key);
            ensure!(
                validate_agent_metadata(&missing, Some("2026.3.0"), &not_compared).is_err(),
                "missing {key} was accepted"
            );
        }
        let mut unknown = metadata.clone();
        unknown["custom"] = json!("value");
        ensure!(
            validate_agent_metadata(&unknown, None, &not_compared).is_err(),
            "unknown metadata key was accepted"
        );
        metadata["arch"] = json!("wrong-platform");
        ensure!(
            validate_agent_metadata(&metadata, None, &not_compared).is_err(),
            "wrong architecture was accepted"
        );
        metadata["arch"] = json!(std::env::consts::ARCH);
        ensure!(
            validate_agent_metadata(&metadata, Some("different-version"), &not_compared).is_err(),
            "wrong agent version was accepted"
        );
        Ok(())
    }

    /// The agent reports where its key is and which key storages it can create keys in; a wrong report misleads the authority's choice of policy.
    #[test]
    fn agent_metadata_reports_key_storages_this_platform_can_have() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
        // oracle: intent crates/agent-identity/INTENT.md §Key storage
        let not_compared = ExpectedMachineId::NotCompared;
        let with = |key: &str, value: Option<&str>| {
            let mut metadata = agent_metadata("host");
            match value {
                Some(value) => metadata[key] = json!(value),
                None => {
                    metadata.as_object_mut().expect("fixture metadata").remove(key);
                }
            }
            metadata
        };
        let default = key_storage::builtin_default();
        let both = "file,windows_software_provider";
        let accepted = [
            ("unlisted key storage", with("key_storage", Some(key_storage::UNLISTED))),
            (
                "another available storage",
                with("key_storage_available", Some(&format!("{default},zz_unlisted_storage"))),
            ),
        ];
        for (case, metadata) in accepted {
            assert!(
                validate_agent_metadata(&metadata, None, &not_compared).is_ok(),
                "{case}"
            );
        }
        let refused = [
            ("key_storage missing", with("key_storage", None)),
            ("key_storage not a name", with("key_storage", Some("File"))),
            ("key_storage_available missing", with("key_storage_available", None)),
            (
                "key_storage_available descending",
                with("key_storage_available", Some(&format!("zz_unlisted_storage,{default}"))),
            ),
            (
                "key_storage_available repeated",
                with("key_storage_available", Some(&format!("{default},{default}"))),
            ),
            (
                "key_storage_available without the built-in default",
                with("key_storage_available", Some(key_storage::UNLISTED)),
            ),
        ];
        for (case, metadata) in refused {
            assert!(
                validate_agent_metadata(&metadata, None, &not_compared).is_err(),
                "{case}"
            );
        }
        assert_eq!(
            validate_agent_metadata(&with("key_storage_available", Some(both)), None, &not_compared).is_ok(),
            cfg!(windows),
            "the Windows software provider is available only on Windows"
        );
    }

    /// An agent case whose agent never starts.
    async fn file_backend_case() -> anyhow::Result<AgentCase> {
        let work_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("agent-identity-conformance-tests");
        std::fs::create_dir_all(&work_dir)?;
        let target = Target::new(
            "https://localhost/mock".to_owned(),
            crate::dvls::AppCredential::new("test".to_owned(), "test".to_owned()),
            None,
            None,
        )?;
        let mut case = AgentCase::new(
            Context {
                test: "harness",
                target,
                second: None,
                target_kind: crate::TargetKind::Mock,
                disposable_dvls_target: false,
                dvls_rotation_window_secs: 60,
                leaf_lifetime_secs: 90 * 24 * 3600,
                expect_channel: true,
                channel_available: true,
                key_name_prefix: format!("conformance-{}", uuid::Uuid::new_v4().simple()),
                agent_version: None,
                unprivileged: None,
                agent_bin: PathBuf::new(),
                work_dir,
            },
            None,
            false,
        )
        .await?;
        case.keep = false;
        Ok(case)
    }

    /// Stores a new P-256 file key with an owner-only mode, under a new name with the case's run prefix.
    fn new_file_key(case: &AgentCase) -> anyhow::Result<(String, rcgen::KeyPair)> {
        use std::io::Write as _;

        let name = format!("{}_{}", case.ctx.key_name_prefix, uuid::Uuid::new_v4());
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let path = case.key_file_path(&name);
        std::fs::create_dir_all(path.parent().context("key directory")?)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(path)?.write_all(&key.serialize_der())?;
        Ok((name, key))
    }

    /// A stored key slot that names `name` and holds a self-signed leaf for `key`.
    fn key_slot(name: &str, key: &rcgen::KeyPair) -> anyhow::Result<Value> {
        let leaf = rcgen::CertificateParams::new(Vec::<String>::new())?.self_signed(key)?;
        Ok(json!({
            "key_name": name,
            "key_storage": key_storage::FILE,
            "certificate_chain": [base64::engine::general_purpose::STANDARD.encode(leaf.der())]
        }))
    }

    fn write_identity(case: &AgentCase, authority_id: &str, state: &Value) -> anyhow::Result<()> {
        let path = case.identity_path(authority_id);
        std::fs::create_dir_all(path.parent().context("authority directory")?)?;
        std::fs::write(path, serde_json::to_vec(state)?)?;
        Ok(())
    }
}
