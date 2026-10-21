use std::collections::HashSet;
use std::fs;
use std::io::{ErrorKind, Read as _};

use anyhow::{Context as _, ensure};
use camino::{Utf8Path, Utf8PathBuf};
use device_key::{self as keys, DeviceKey, KeyBackend};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;
use uuid::{Uuid, Variant};

use crate::token::Token;
use crate::{pending, private_file, rejected, state_lock};

const MAX_IDENTITY_BYTES: u64 = 2 * 1024 * 1024;
pub const IDENTITY_KEY_PREFIX: &str = "devolutions-agent-identity";
/// The rejection code of an identity whose current key no longer exists in its key store.
pub const KEY_LOST: &str = "key_lost";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredIdentity {
    pub version: u8,
    pub authority_id: Uuid,
    pub identity_id: Uuid,
    pub base_url: Url,
    pub config: Value,
    pub token_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected: Option<Rejection>,
    pub keys: KeySlots,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rejection {
    pub code: String,
    pub at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeySlots {
    pub current: KeyRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<KeyRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<KeyRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRecord {
    pub key_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_chain: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentDiscardReason {
    IdentityRevoked,
    TokenInvalid,
    TokenExhausted,
    TokenExpired,
    TokenMalformed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingDiscard {
    MalformedToken,
    Unusable,
    #[cfg(windows)]
    Undecryptable,
}

impl EnrollmentDiscardReason {
    fn code(self) -> &'static str {
        match self {
            Self::IdentityRevoked => "identity_revoked",
            Self::TokenInvalid => "token_invalid",
            Self::TokenExhausted => "token_exhausted",
            Self::TokenExpired => "token_expired",
            Self::TokenMalformed => "token_malformed",
        }
    }
}

pub struct Store {
    data_dir: Utf8PathBuf,
    backend: KeyBackend,
    key_prefix: String,
    acl_grant_current_user: bool,
}

impl Store {
    pub fn new(
        data_dir: Utf8PathBuf,
        backend: KeyBackend,
        key_prefix: String,
        acl_grant_current_user: bool,
    ) -> anyhow::Result<Self> {
        keys::validate_prefix(&key_prefix)?;
        match &backend {
            KeyBackend::File { dir } => {
                ensure!(
                    *dir == data_dir.join("identity").join("keys"),
                    "invalid device key directory"
                );
            }
            KeyBackend::WindowsSoftwareProvider => {}
        }
        keys::list(&backend, &key_prefix)?;
        {
            let _lock = state_lock::acquire(&data_dir, acl_grant_current_user)?;
            private_file::protect_authority_directories(&data_dir, acl_grant_current_user)?;
        }
        Ok(Self {
            data_dir,
            backend,
            key_prefix,
            acl_grant_current_user,
        })
    }

    pub fn file_backend(data_dir: &Utf8Path) -> KeyBackend {
        KeyBackend::File {
            dir: data_dir.join("identity").join("keys"),
        }
    }

    pub fn key_backend(&self) -> &KeyBackend {
        &self.backend
    }

    pub fn identity_path(&self, authority_id: Uuid) -> Utf8PathBuf {
        self.data_dir
            .join("identity")
            .join("authorities")
            .join(authority_id.to_string())
            .join("identity.json")
    }

    pub fn read_identity(&self, authority_id: Uuid) -> anyhow::Result<Option<StoredIdentity>> {
        let path = self.identity_path(authority_id);
        if !private_file::check_owned_directory(
            path.parent().context("identity file has no parent")?,
            self.acl_grant_current_user,
        )? {
            return Ok(None);
        }
        let file = match private_file::open_read(&path) {
            Ok(file) => file,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) if private_file::is_untrusted(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        ensure!(
            file.metadata()?.len() <= MAX_IDENTITY_BYTES,
            "stored identity exceeds size limit"
        );
        let mut bytes = Vec::new();
        file.take(MAX_IDENTITY_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_IDENTITY_BYTES,
            "stored identity exceeds size limit"
        );
        let identity: StoredIdentity =
            serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid stored identity"))?;
        self.validate_identity(&identity)?;
        ensure!(
            identity.authority_id == authority_id,
            "stored identity authority mismatch"
        );
        Ok(Some(identity))
    }

    pub fn list_identities(&self) -> anyhow::Result<Vec<StoredIdentity>> {
        let authorities = self.data_dir.join("identity").join("authorities");
        let entries = match fs::read_dir(&authorities) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error).context("list stored identities"),
        };
        let mut identities = Vec::new();
        for entry in entries {
            let entry = entry.context("read stored identity entry")?;
            let name = entry.file_name();
            let Some(authority_id) = name
                .to_str()
                .and_then(|name| Uuid::parse_str(name).ok().filter(|uuid| uuid.to_string() == name))
            else {
                continue;
            };
            let path =
                Utf8PathBuf::from_path_buf(entry.path()).map_err(|_| anyhow::anyhow!("non-UTF-8 authority path"))?;
            ensure!(
                private_file::check_owned_directory(&path, self.acl_grant_current_user)?,
                "stored identity directory is untrusted"
            );
            if let Some(identity) = self.read_identity(authority_id)? {
                identities.push(identity);
            } else {
                match fs::symlink_metadata(self.identity_path(authority_id)) {
                    Ok(_) => anyhow::bail!("stored identity file is untrusted"),
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => return Err(error).context("inspect stored identity file"),
                }
            }
        }
        identities.sort_by_key(|identity| identity.authority_id);
        Ok(identities)
    }

    /// Creates an identity only if its authority has no stored identity yet.
    pub fn write_identity(&self, identity: &StoredIdentity) -> anyhow::Result<()> {
        let _lock = state_lock::acquire(&self.data_dir, self.acl_grant_current_user)?;
        self.write_identity_locked(None, identity)
    }

    /// Replaces an identity only while the expected snapshot is still current.
    pub fn replace_identity(&self, previous: &StoredIdentity, identity: &StoredIdentity) -> anyhow::Result<()> {
        let _lock = state_lock::acquire(&self.data_dir, self.acl_grant_current_user)?;
        self.write_identity_locked(Some(previous), identity)
    }

    fn write_identity_locked(
        &self,
        previous: Option<&StoredIdentity>,
        identity: &StoredIdentity,
    ) -> anyhow::Result<()> {
        self.validate_identity(identity)?;
        ensure!(
            previous.is_none_or(|previous| previous.authority_id == identity.authority_id),
            "stored identity authority changed"
        );
        let existing = self.read_identity(identity.authority_id)?;
        if existing.is_none() {
            match fs::symlink_metadata(self.identity_path(identity.authority_id)) {
                Ok(_) => anyhow::bail!("stored identity file is untrusted"),
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect stored identity file"),
            }
        }
        ensure!(
            existing.as_ref() == previous,
            "stored identity changed; reload before updating"
        );
        if let Some(existing) = &existing
            && (existing.identity_id == identity.identity_id || existing.token_sha256 == identity.token_sha256)
        {
            let previous_revision = config_revision(&existing.config)?;
            let incoming_revision = config_revision(&identity.config)?;
            ensure!(
                incoming_revision > previous_revision
                    || incoming_revision == previous_revision && identity.config == existing.config,
                "stored identity config must not lose its revision"
            );
        }
        let old_names: HashSet<&str> = existing
            .as_ref()
            .into_iter()
            .flat_map(|old| old.keys.records().map(|key| key.key_name.as_str()))
            .collect();
        let new_names: HashSet<&str> = identity.keys.records().map(|key| key.key_name.as_str()).collect();
        for name in &new_names {
            if !old_names.contains(name)
                && keys::open(&self.backend, name)?.is_some()
                && !pending::list_in_progress(&self.data_dir)?
                    .iter()
                    .any(|(_, record)| record.key_name == *name && record.token_sha256 == identity.token_sha256)
            {
                anyhow::bail!("existing device key has no prior record");
            }
        }
        if let Some(old) = &existing {
            for key in old.keys.records() {
                if !new_names.contains(key.key_name.as_str()) {
                    keys::delete(&self.backend, &key.key_name)?;
                }
            }
        }
        let bytes = serde_json::to_vec(identity).context("encode stored identity")?;
        private_file::write_atomic(
            &self.data_dir,
            &self.identity_path(identity.authority_id),
            &bytes,
            self.acl_grant_current_user,
        )
    }

    pub fn update_config(&self, identity: &mut StoredIdentity, config: Value) -> anyhow::Result<bool> {
        ensure!(
            config.get("version").and_then(Value::as_u64) == Some(1),
            "unsupported config version"
        );
        let _lock = state_lock::acquire(&self.data_dir, self.acl_grant_current_user)?;
        let latest = self
            .read_identity(identity.authority_id)?
            .context("stored identity is missing")?;
        ensure!(
            latest.identity_id == identity.identity_id && latest.token_sha256 == identity.token_sha256,
            "stored identity was replaced"
        );
        let revision = config_revision(&config)?;
        if revision <= config_revision(&latest.config)? {
            *identity = latest;
            return Ok(false);
        }
        let mut updated = latest.clone();
        updated.config = config;
        self.write_identity_locked(Some(&latest), &updated)?;
        *identity = updated;
        Ok(true)
    }

    /// Records a pending key's name durably before generating its private key.
    pub fn create_pending_key(&self, identity: &mut StoredIdentity) -> anyhow::Result<Box<dyn DeviceKey>> {
        ensure!(identity.keys.pending.is_none(), "identity already has a pending key");
        let name = keys::new_key_name(&self.key_prefix);
        let previous = identity.clone();
        let mut updated = previous.clone();
        updated.keys.pending = Some(KeyRecord {
            key_name: name.clone(),
            certificate_chain: None,
        });
        let _lock = state_lock::acquire(&self.data_dir, self.acl_grant_current_user)?;
        self.write_identity_locked(Some(&previous), &updated)?;
        *identity = updated;
        keys::generate(&self.backend, &name)
    }

    pub fn remove_pending_key(&self, identity: &mut StoredIdentity) -> anyhow::Result<()> {
        if identity.keys.pending.is_some() {
            let previous = identity.clone();
            let mut updated = previous.clone();
            updated.keys.pending = None;
            let _lock = state_lock::acquire(&self.data_dir, self.acl_grant_current_user)?;
            self.write_identity_locked(Some(&previous), &updated)?;
            *identity = updated;
        }
        Ok(())
    }

    /// Stores the chain that renew returned for the pending key.
    pub fn store_pending_chain(&self, identity: &mut StoredIdentity, chain: Vec<String>) -> anyhow::Result<()> {
        self.update(
            identity,
            |updated| {
                let pending = updated.keys.pending.as_mut().context("identity has no pending key")?;
                pending.certificate_chain = Some(chain);
                Ok(())
            },
            || Ok(()),
        )
    }

    /// Makes the confirmed pending key current and keeps the old key as `previous` until it is deleted.
    pub fn promote_pending(&self, identity: &mut StoredIdentity) -> anyhow::Result<()> {
        self.update(
            identity,
            |updated| {
                ensure!(updated.keys.previous.is_none(), "identity still has a previous key");
                let pending = updated.keys.pending.take().context("identity has no pending key")?;
                ensure!(
                    pending.certificate_chain.is_some(),
                    "pending identity key has no certificate chain"
                );
                updated.keys.previous = Some(std::mem::replace(&mut updated.keys.current, pending));
                Ok(())
            },
            || Ok(()),
        )
    }

    /// Moves the expired pending key to `previous` and records a fresh pending key before generating it.
    ///
    /// [`crates/agent-identity/INTENT.md`] ("Stored identities"): if recovery must start again before a `confirm`
    /// succeeds, the newest expired pending key replaces the one in `previous` and the older one is deleted, because
    /// the server holds the newest as pending or current and accepts it to sign the next recovery renewal within grace.
    ///
    /// [`crates/agent-identity/INTENT.md`]: ../INTENT.md
    pub fn begin_recovery(&self, identity: &mut StoredIdentity) -> anyhow::Result<Box<dyn DeviceKey>> {
        let name = keys::new_key_name(&self.key_prefix);
        self.update(
            identity,
            |updated| {
                let expired = updated.keys.pending.take().context("identity has no pending key")?;
                ensure!(
                    expired.certificate_chain.is_some(),
                    "pending identity key has no certificate chain"
                );
                updated.keys.previous = Some(expired);
                updated.keys.pending = Some(KeyRecord {
                    key_name: name.clone(),
                    certificate_chain: None,
                });
                Ok(())
            },
            || keys::generate(&self.backend, &name),
        )
    }

    /// Deletes an unusable pending key and its slot, then records a fresh pending key before generating it.
    pub fn replace_pending_key(&self, identity: &mut StoredIdentity) -> anyhow::Result<Box<dyn DeviceKey>> {
        let name = keys::new_key_name(&self.key_prefix);
        self.update(
            identity,
            |updated| {
                ensure!(updated.keys.pending.is_some(), "identity has no pending key");
                updated.keys.pending = Some(KeyRecord {
                    key_name: name.clone(),
                    certificate_chain: None,
                });
                Ok(())
            },
            || keys::generate(&self.backend, &name),
        )
    }

    /// Records that the authority permanently rejected the identity.
    pub fn reject_identity(&self, identity: &mut StoredIdentity, code: &str) -> anyhow::Result<()> {
        let at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("format rejection timestamp")?;
        self.update(
            identity,
            |updated| {
                updated.rejected = Some(Rejection {
                    code: code.to_owned(),
                    at,
                });
                Ok(())
            },
            || Ok(()),
        )
    }

    /// Writes a changed snapshot of the identity, then runs `then` under the same state lock.
    ///
    /// UNTESTED: generating a key in `then` keeps a concurrent replacement of the identity from unrecording its name
    /// before the key exists; when changing this, keep record and generation in one critical section.
    fn update<T>(
        &self,
        identity: &mut StoredIdentity,
        change: impl FnOnce(&mut StoredIdentity) -> anyhow::Result<()>,
        then: impl FnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let mut updated = identity.clone();
        change(&mut updated)?;
        let _lock = state_lock::acquire(&self.data_dir, self.acl_grant_current_user)?;
        self.write_identity_locked(Some(identity), &updated)?;
        *identity = updated;
        then()
    }

    pub fn remove_previous_key(&self, identity: &mut StoredIdentity) -> anyhow::Result<()> {
        if identity.keys.previous.is_some() {
            let previous = identity.clone();
            let mut updated = previous.clone();
            updated.keys.previous = None;
            let _lock = state_lock::acquire(&self.data_dir, self.acl_grant_current_user)?;
            self.write_identity_locked(Some(&previous), &updated)?;
            *identity = updated;
        }
        Ok(())
    }

    pub fn remove_identity(&self, identity: &StoredIdentity) -> anyhow::Result<()> {
        let _lock = state_lock::acquire(&self.data_dir, self.acl_grant_current_user)?;
        self.remove_identity_locked(identity)
    }

    fn remove_identity_locked(&self, identity: &StoredIdentity) -> anyhow::Result<()> {
        ensure!(
            self.read_identity(identity.authority_id)?.as_ref() == Some(identity),
            "stored identity changed; reload before deleting"
        );
        for key in identity.keys.records() {
            keys::delete(&self.backend, &key.key_name)?;
        }
        private_file::remove_file(&self.identity_path(identity.authority_id))
    }

    /// Reuses an enrollment key, or skips a token already represented by an identity or rejection marker.
    pub fn begin_enrollment(&self, token: &Token) -> anyhow::Result<Option<(pending::InProgress, Box<dyn DeviceKey>)>> {
        let _lock = state_lock::acquire(&self.data_dir, self.acl_grant_current_user)?;
        let hash_hex = token.sha256_hex();
        if rejected::is_rejected(&self.data_dir, &hash_hex)?
            || self
                .list_identities()?
                .iter()
                .any(|identity| identity.token_sha256 == hash_hex)
        {
            self.discard_pending_state_locked(&hash_hex)?;
            return Ok(None);
        }
        let path = pending::file_path(&self.data_dir, &hash_hex)?;
        let pending::PendingRead::Ready(current) = pending::read(&path, self.acl_grant_current_user)? else {
            anyhow::bail!("pending enrollment changed before creating its key")
        };
        ensure!(
            current.sha256_hex() == hash_hex,
            "pending enrollment changed before creating its key"
        );
        let record = match pending::read_in_progress(&self.data_dir, &hash_hex)? {
            Some(record) => record,
            None => {
                let record = pending::InProgress {
                    version: 1,
                    token_sha256: hash_hex.clone(),
                    key_name: keys::new_key_name(&self.key_prefix),
                };
                pending::write_in_progress(&self.data_dir, &hash_hex, &record, self.acl_grant_current_user)?;
                record
            }
        };
        self.validate_key_name(&record.key_name)?;
        let key = match keys::open(&self.backend, &record.key_name)? {
            Some(key) => key,
            None => keys::generate(&self.backend, &record.key_name)?,
        };
        Ok(Some((record, key)))
    }

    /// Persists a permanent-outcome marker before deleting the token, key, and in-progress record.
    /// The caller supplies the hash of a token read from its matching pending file.
    pub fn discard_enrollment(&self, hash_hex: &str, reason: EnrollmentDiscardReason) -> anyhow::Result<()> {
        let _lock = state_lock::acquire(&self.data_dir, self.acl_grant_current_user)?;
        rejected::mark_rejected(&self.data_dir, hash_hex, reason.code(), self.acl_grant_current_user)?;
        self.discard_pending_state_locked(hash_hex)
    }

    fn discard_pending_state_locked(&self, hash_hex: &str) -> anyhow::Result<()> {
        pending::remove_file(&self.data_dir, hash_hex, self.acl_grant_current_user)?;
        if let Some(record) = pending::read_in_progress(&self.data_dir, hash_hex)? {
            self.validate_key_name(&record.key_name)?;
            if let Some(identity) = self
                .list_identities()?
                .into_iter()
                .find(|identity| identity.keys.records().any(|key| key.key_name == record.key_name))
            {
                ensure!(
                    identity.token_sha256 == record.token_sha256,
                    "enrollment key belongs to another identity"
                );
                pending::remove_in_progress(&self.data_dir, hash_hex)?;
                return Ok(());
            }
            keys::delete(&self.backend, &record.key_name)?;
            pending::remove_in_progress(&self.data_dir, hash_hex)?;
        }
        Ok(())
    }

    /// Rechecks an unusable pending file under the lock before removing it.
    pub fn discard_pending_file(&self, path: &Utf8Path) -> anyhow::Result<Option<PendingDiscard>> {
        let _lock = state_lock::acquire(&self.data_dir, self.acl_grant_current_user)?;
        let directory = pending::directory(&self.data_dir);
        ensure!(
            path.parent() == Some(directory.as_path()),
            "pending path is outside its directory"
        );
        let name = path.file_name().context("pending path has no filename")?;
        ensure!(
            !name.ends_with(".in-progress.json"),
            "pending path is an in-progress record"
        );
        let extension = if cfg!(windows) { ".dat" } else { ".json" };
        let hash_hex = name
            .strip_suffix(extension)
            .context("pending path has wrong extension")?;
        ensure!(
            pending::file_path(&self.data_dir, hash_hex)? == path,
            "pending path has wrong name"
        );
        // The writer may have replaced the file since the caller classified it.
        let discard = match pending::read(path, self.acl_grant_current_user) {
            Ok(pending::PendingRead::MalformedToken) => {
                rejected::mark_rejected(
                    &self.data_dir,
                    hash_hex,
                    EnrollmentDiscardReason::TokenMalformed.code(),
                    self.acl_grant_current_user,
                )?;
                self.discard_pending_state_locked(hash_hex)?;
                PendingDiscard::MalformedToken
            }
            Ok(pending::PendingRead::Unusable) => {
                private_file::remove_pending_file(path, self.acl_grant_current_user)?;
                PendingDiscard::Unusable
            }
            #[cfg(windows)]
            Ok(pending::PendingRead::Undecryptable) => {
                private_file::remove_pending_file(path, self.acl_grant_current_user)?;
                PendingDiscard::Undecryptable
            }
            Ok(pending::PendingRead::Ready(_)) => return Ok(None),
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        Ok(Some(discard))
    }

    /// Removes a completed enrollment's pending state only after its key belongs to the saved identity.
    pub fn finish_enrollment(&self, hash_hex: &str, authority_id: Uuid) -> anyhow::Result<()> {
        let _lock = state_lock::acquire(&self.data_dir, self.acl_grant_current_user)?;
        self.finish_enrollment_locked(hash_hex, authority_id)
    }

    fn finish_enrollment_locked(&self, hash_hex: &str, authority_id: Uuid) -> anyhow::Result<()> {
        let identity = self
            .read_identity(authority_id)?
            .context("stored enrollment identity is missing")?;
        ensure!(
            identity.token_sha256 == hash_hex,
            "stored identity belongs to a different enrollment"
        );
        let record = pending::read_in_progress(&self.data_dir, hash_hex)?;
        if let Some(record) = &record {
            ensure!(
                identity.keys.current.key_name == record.key_name,
                "enrollment key does not belong to stored identity"
            );
        }
        pending::remove_file(&self.data_dir, hash_hex, self.acl_grant_current_user)?;
        if record.is_some() {
            pending::remove_in_progress(&self.data_dir, hash_hex)?;
        }
        Ok(())
    }

    /// Repairs missing unissued keys and drops keys no longer covered by a durable record.
    pub fn reconcile(&self) -> anyhow::Result<()> {
        let _lock = state_lock::acquire(&self.data_dir, self.acl_grant_current_user)?;
        private_file::cleanup_temporary_files(
            &pending::directory(&self.data_dir),
            pending::is_owned_temporary_stem,
            |path, stem| {
                if stem.ends_with(".dat") {
                    // An interrupted add-only submission can leave an administrator-owned staging file.
                    private_file::remove_pending_file(path, self.acl_grant_current_user)
                } else {
                    private_file::remove_file(path)
                }
            },
        )?;
        rejected::cleanup_temporary(&self.data_dir)?;
        for hash_hex in rejected::list_rejected(&self.data_dir)? {
            self.discard_pending_state_locked(&hash_hex)?;
        }
        let authorities = self.data_dir.join("identity").join("authorities");
        let entries = match fs::read_dir(&authorities) {
            Ok(entries) => Some(entries),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("list authority directories"),
        };
        if let Some(entries) = entries {
            for entry in entries {
                let entry = entry.context("read authority directory entry")?;
                if entry.file_type()?.is_dir()
                    && entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| Uuid::parse_str(name).is_ok_and(|uuid| uuid.to_string() == name))
                {
                    let path = Utf8PathBuf::from_path_buf(entry.path())
                        .map_err(|_| anyhow::anyhow!("non-UTF-8 authority path"))?;
                    if private_file::check_owned_directory(&path, self.acl_grant_current_user)? {
                        private_file::cleanup_temporary_files(
                            &path,
                            |stem| stem == ".identity.json",
                            |path, _| private_file::remove_file(path),
                        )?;
                    }
                }
            }
        }
        for mut identity in self.list_identities()? {
            // `crates/agent-identity/INTENT.md` ("Identities"): a rejected identity keeps its keys and slots until it
            // is replaced; its key names still count as recorded below.
            if identity.rejected.is_some() {
                continue;
            }
            if keys::open(&self.backend, &identity.keys.current.key_name)?.is_none() {
                // The identity is kept so that its token stays a no-op and recovery needs a different token.
                let previous = identity.clone();
                identity.rejected = Some(Rejection {
                    code: KEY_LOST.to_owned(),
                    at: OffsetDateTime::now_utc()
                        .format(&Rfc3339)
                        .context("format key-lost timestamp")?,
                });
                self.write_identity_locked(Some(&previous), &identity)?;
                continue;
            }
            // A key refused when opened is left to the identity's runner, which replaces it, so that one unusable key
            // never stops the other identities.
            if let Some(pending) = &identity.keys.pending
                && matches!(keys::open(&self.backend, &pending.key_name), Ok(None))
            {
                if pending.certificate_chain.is_none() {
                    keys::generate(&self.backend, &pending.key_name)?;
                } else {
                    // `crates/agent-identity/INTENT.md` ("Stored identities"): a missing pending key is unusable and is
                    // replaced by a fresh one, which keeps the pending slot, and with it the `confirm` barrier, until a
                    // renewal is confirmed.
                    let previous = identity.clone();
                    let name = keys::new_key_name(&self.key_prefix);
                    identity.keys.pending = Some(KeyRecord {
                        key_name: name.clone(),
                        certificate_chain: None,
                    });
                    self.write_identity_locked(Some(&previous), &identity)?;
                    keys::generate(&self.backend, &name)?;
                }
            }
            if let Some(previous) = &identity.keys.previous
                && matches!(keys::open(&self.backend, &previous.key_name), Ok(None))
            {
                let previous = identity.clone();
                identity.keys.previous = None;
                self.write_identity_locked(Some(&previous), &identity)?;
            }
        }

        let identities = self.list_identities()?;
        let mut recorded: HashSet<String> = identities
            .iter()
            .flat_map(|identity| identity.keys.records().map(|record| record.key_name.clone()))
            .collect();
        for (hash_hex, record) in pending::list_in_progress(&self.data_dir)? {
            self.validate_key_name(&record.key_name)?;
            let path = pending::file_path(&self.data_dir, &hash_hex)?;
            let pending_file_is_missing = match pending::read(&path, self.acl_grant_current_user) {
                Ok(pending::PendingRead::Ready(_)) => false,
                Ok(_) => {
                    recorded.insert(record.key_name);
                    continue;
                }
                Err(error) if is_not_found(&error) => true,
                Err(_) => {
                    recorded.insert(record.key_name);
                    continue;
                }
            };
            if pending_file_is_missing {
                if !recorded.contains(&record.key_name) {
                    keys::delete(&self.backend, &record.key_name)?;
                }
                pending::remove_in_progress(&self.data_dir, &hash_hex)?;
                continue;
            }
            if keys::open(&self.backend, &record.key_name)?.is_none() {
                keys::generate(&self.backend, &record.key_name)?;
            }
            recorded.insert(record.key_name);
        }
        for name in keys::list(&self.backend, &self.key_prefix)? {
            if !recorded.contains(&name) {
                keys::delete(&self.backend, &name)?;
            }
        }
        Ok(())
    }

    fn validate_identity(&self, identity: &StoredIdentity) -> anyhow::Result<()> {
        ensure!(identity.version == 1, "unsupported stored identity version");
        ensure!(
            identity.base_url.scheme() == "https"
                && identity.base_url.has_host()
                && identity.base_url.query().is_none()
                && identity.base_url.fragment().is_none(),
            "invalid stored identity base URL"
        );
        ensure!(
            config_revision(&identity.config).is_ok(),
            "invalid stored identity config"
        );
        ensure!(
            pending::valid_hash_hex(&identity.token_sha256),
            "invalid stored identity token hash"
        );
        for key in identity.keys.records() {
            self.validate_key_name(&key.key_name)?;
        }
        ensure!(
            identity
                .keys
                .current
                .certificate_chain
                .as_ref()
                .is_some_and(|chain| !chain.is_empty()),
            "current identity key has no certificate chain"
        );
        ensure!(
            identity
                .keys
                .previous
                .as_ref()
                .is_none_or(|key| key.certificate_chain.as_ref().is_some_and(|chain| !chain.is_empty())),
            "previous identity key has no certificate chain"
        );
        ensure!(
            identity
                .keys
                .pending
                .as_ref()
                .is_none_or(|key| key.certificate_chain.as_ref().is_none_or(|chain| !chain.is_empty())),
            "pending identity key has an empty certificate chain"
        );
        Ok(())
    }

    fn validate_key_name(&self, name: &str) -> anyhow::Result<()> {
        let (prefix, suffix) = name.split_once('_').context("invalid device key name")?;
        ensure!(prefix == self.key_prefix, "key has wrong name prefix");
        let uuid = Uuid::parse_str(suffix).context("invalid device key name")?;
        ensure!(
            uuid.get_version_num() == 4 && uuid.get_variant() == Variant::RFC4122 && uuid.to_string() == suffix,
            "invalid device key name"
        );
        Ok(())
    }
}

impl KeySlots {
    fn records(&self) -> impl Iterator<Item = &KeyRecord> {
        std::iter::once(&self.current)
            .chain(self.pending.iter())
            .chain(self.previous.iter())
    }
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|source| source.kind() == ErrorKind::NotFound)
}

fn config_revision(config: &Value) -> anyhow::Result<u64> {
    config
        .as_object()
        .and_then(|object| object.get("revision"))
        .and_then(Value::as_u64)
        .context("config is missing its revision")
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    use super::*;

    struct TestDir(Utf8PathBuf);

    impl TestDir {
        fn new() -> anyhow::Result<Self> {
            // The system temporary directory keeps the deepest state path, a deleted key's tombstone, under Windows'
            // 260-character limit wherever the repository is checked out.
            let path = Utf8PathBuf::from_path_buf(std::env::temp_dir())
                .map_err(|_| anyhow::anyhow!("the temporary directory path is not UTF-8"))?
                .join(format!("ai-{}", Uuid::new_v4().simple()));
            fs::create_dir_all(&path)?;
            Ok(Self(path))
        }

        fn supports_owner_only_files(&self) -> anyhow::Result<bool> {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;

                Ok(fs::metadata(&self.0)?.permissions().mode() & 0o022 == 0)
            }
            #[cfg(not(unix))]
            {
                Ok(fs::metadata(&self.0)?.is_dir())
            }
        }

        fn store(&self) -> anyhow::Result<Store> {
            Store::new(self.0.clone(), Store::file_backend(&self.0), "ai".into(), true)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn unavailable_backend_reaches_store_initialization_without_touching_state() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        let error = Store::new(
            directory.0.clone(),
            KeyBackend::WindowsSoftwareProvider,
            IDENTITY_KEY_PREFIX.to_owned(),
            false,
        )
        .err()
        .context("unavailable backend was accepted")?;
        assert_eq!(
            error
                .downcast_ref::<keys::BackendUnavailable>()
                .map(|backend| backend.backend),
            Some("WindowsSoftwareProvider")
        );
        assert!(!directory.0.join("identity").exists());
        Ok(())
    }

    fn test_token() -> anyhow::Result<Token> {
        Token::parse(&format!(
            "dvaet1.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"u":"https://example.test"}"#),
            "A".repeat(43)
        ))
    }

    fn enroll_locally(store: &Store, data_dir: &Utf8Path) -> anyhow::Result<StoredIdentity> {
        let token = test_token()?;
        pending::write(data_dir, &token, true).context("write test pending token")?;
        let (progress, _key) = store
            .begin_enrollment(&token)?
            .context("new token was already processed")?;
        let identity = StoredIdentity {
            version: 1,
            authority_id: Uuid::new_v4(),
            identity_id: Uuid::new_v4(),
            base_url: token.base_url().clone(),
            config: json!({"version": 1, "revision": 7}),
            token_sha256: token.sha256_hex(),
            rejected: None,
            keys: KeySlots {
                current: KeyRecord {
                    key_name: progress.key_name,
                    certificate_chain: Some(vec!["YWJj".into()]),
                },
                pending: None,
                previous: None,
            },
        };
        store.write_identity(&identity).context("persist initial identity")?;
        store
            .finish_enrollment(&token.sha256_hex(), identity.authority_id)
            .context("finish initial identity")?;
        Ok(identity)
    }

    #[test]
    fn identity_json_preserves_config_and_accepts_null_optionals() -> anyhow::Result<()> {
        let json = json!({
            "version": 1,
            "authority_id": "a54f680c-9612-4b5e-a84f-2e1f79615067",
            "identity_id": "28a70de9-724e-4ffb-8e8d-09f56971765d",
            "base_url": "https://example.test/dvls",
            "config": {"version": 1, "revision": 7, "future": {"nested": [1, null, true]}},
            "token_sha256": hex::encode([1u8; 32]),
            "rejected": null,
            "keys": {
                "current": {
                    "key_name": keys::new_key_name(IDENTITY_KEY_PREFIX),
                    "certificate_chain": ["YWJj"]
                },
                "pending": {
                    "key_name": keys::new_key_name(IDENTITY_KEY_PREFIX),
                    "certificate_chain": null
                },
                "previous": null
            }
        });
        let identity: StoredIdentity = serde_json::from_value(json.clone())?;
        assert_eq!(identity.config, json["config"]);
        assert_eq!(
            identity
                .keys
                .pending
                .as_ref()
                .and_then(|key| key.certificate_chain.as_ref()),
            None
        );
        let encoded = serde_json::to_value(&identity)?;
        assert_eq!(encoded["config"], json["config"]);
        assert!(encoded.get("rejected").is_none());
        assert!(encoded["keys"].get("previous").is_none());
        assert!(encoded["keys"]["pending"].get("certificate_chain").is_none());
        let rebuilt: StoredIdentity = serde_json::from_value(encoded)?;
        assert_eq!(rebuilt, identity);
        Ok(())
    }

    #[test]
    fn interrupted_permanent_cleanup_does_not_regenerate_an_enrollment_key() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let token = test_token()?;
        pending::write(&directory.0, &token, true)?;
        let (progress, _key) = store
            .begin_enrollment(&token)?
            .context("new token was already processed")?;
        assert!(keys::open(store.key_backend(), &progress.key_name)?.is_some());

        pending::remove_file(&directory.0, &token.sha256_hex(), true)?;
        store.reconcile()?;
        assert!(pending::read_in_progress(&directory.0, &token.sha256_hex())?.is_none());
        assert!(keys::open(store.key_backend(), &progress.key_name)?.is_none());
        Ok(())
    }

    #[test]
    fn revoked_token_cannot_enroll_again_after_a_replayed_install() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let token = test_token()?;
        let hash_hex = token.sha256_hex();
        let path = pending::write(&directory.0, &token, true)?;
        let (record, _key) = store
            .begin_enrollment(&token)?
            .context("new token was already processed")?;
        store.discard_enrollment(&hash_hex, EnrollmentDiscardReason::IdentityRevoked)?;
        assert!(!path.exists());
        assert!(pending::read_in_progress(&directory.0, &hash_hex)?.is_none());
        assert!(keys::open(store.key_backend(), &record.key_name)?.is_none());
        let marker_path = directory
            .0
            .join("identity")
            .join("rejected")
            .join(format!("{hash_hex}.json"));
        let marker = fs::read_to_string(marker_path)?;
        assert!(!marker.contains(token.as_str()));
        assert_eq!(serde_json::from_str::<Value>(&marker)?["code"], "identity_revoked");
        assert_eq!(pending::write(&directory.0, &token, true)?, path);

        let body = serde_json::to_vec(&json!({"version": 1, "token": token.as_str()}))?;
        private_file::write_atomic(&directory.0, &path, &body, true)?;
        let restarted = directory.store()?;
        assert!(restarted.begin_enrollment(&token)?.is_none());
        assert!(!path.exists());
        private_file::write_atomic(&directory.0, &path, &body, true)?;
        restarted.reconcile()?;
        assert!(!path.exists());
        assert!(keys::open(store.key_backend(), &record.key_name)?.is_none());
        assert_eq!(pending::write(&directory.0, &token, true)?, path);
        assert!(restarted.begin_enrollment(&token)?.is_none());
        let replacement = Token::parse(&format!(
            "dvaet1.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"u":"https://other.test"}"#),
            "A".repeat(43)
        ))?;
        let replacement_path = pending::write(&directory.0, &replacement, true)?;
        assert!(replacement_path.exists());
        Ok(())
    }

    #[test]
    fn malformed_token_marks_only_its_matching_hash() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let raw = "not a token";
        let hash_hex = crate::token::sha256_hex(raw);
        let path = pending::file_path(&directory.0, &hash_hex)?;
        let malformed = serde_json::to_vec(&json!({"version": 1, "token": raw}))?;
        #[cfg(windows)]
        let contents = crate::windows::protect(&malformed)?;
        #[cfg(not(windows))]
        let contents = malformed;
        private_file::write_atomic(&directory.0, &path, &contents, true)?;
        assert!(matches!(
            pending::read(&path, true)?,
            pending::PendingRead::MalformedToken
        ));
        assert_eq!(store.discard_pending_file(&path)?, Some(PendingDiscard::MalformedToken));
        assert!(!path.exists());
        let marker_path = directory
            .0
            .join("identity")
            .join("rejected")
            .join(format!("{hash_hex}.json"));
        let marker: Value = serde_json::from_slice(&fs::read(marker_path)?)?;
        assert_eq!(marker["code"], "token_malformed");
        assert_eq!(marker["token_sha256"], hash_hex);
        Ok(())
    }

    #[test]
    fn unusable_pending_keeps_its_record_until_reconciliation() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let token = test_token()?;
        let hash_hex = token.sha256_hex();
        let path = pending::write(&directory.0, &token, true)?;
        let (record, _key) = store.begin_enrollment(&token)?.context("begin enrollment")?;
        let unusable = br#"{"version":1,"token":null}"#;
        #[cfg(windows)]
        let contents = crate::windows::protect(unusable)?;
        #[cfg(not(windows))]
        let contents = unusable.to_vec();
        private_file::write_atomic(&directory.0, &path, &contents, true)?;
        assert!(matches!(pending::read(&path, true)?, pending::PendingRead::Unusable));
        assert_eq!(store.discard_pending_file(&path)?, Some(PendingDiscard::Unusable));
        assert!(!path.exists());
        assert!(rejected::list_rejected(&directory.0)?.is_empty());
        assert!(pending::read_in_progress(&directory.0, &hash_hex)?.is_some());
        assert!(keys::open(store.key_backend(), &record.key_name)?.is_some());
        store.reconcile()?;
        assert!(pending::read_in_progress(&directory.0, &hash_hex)?.is_none());
        assert!(keys::open(store.key_backend(), &record.key_name)?.is_none());
        #[cfg(windows)]
        {
            pending::write(&directory.0, &token, true)?;
            let (record, _key) = store.begin_enrollment(&token)?.context("begin enrollment")?;
            private_file::write_atomic(&directory.0, &path, b"not encrypted", true)?;
            assert!(matches!(
                pending::read(&path, true)?,
                pending::PendingRead::Undecryptable
            ));
            assert_eq!(store.discard_pending_file(&path)?, Some(PendingDiscard::Undecryptable));
            assert!(!path.exists());
            assert!(rejected::list_rejected(&directory.0)?.is_empty());
            assert!(pending::read_in_progress(&directory.0, &hash_hex)?.is_some());
            assert!(keys::open(store.key_backend(), &record.key_name)?.is_some());
            store.reconcile()?;
            assert!(pending::read_in_progress(&directory.0, &hash_hex)?.is_none());
            assert!(keys::open(store.key_backend(), &record.key_name)?.is_none());
        }
        Ok(())
    }

    #[test]
    fn unusable_read_cannot_discard_a_rewritten_valid_pending_token() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let token = test_token()?;
        let path = pending::write(&directory.0, &token, true)?;
        let (record, _key) = store
            .begin_enrollment(&token)?
            .context("new token was already processed")?;
        let malformed_body = serde_json::to_vec(&json!({"version": 2, "token": token.as_str()}))?;
        #[cfg(windows)]
        let contents = crate::windows::protect(&malformed_body)?;
        #[cfg(not(windows))]
        let contents = malformed_body;
        private_file::write_atomic(&directory.0, &path, &contents, true)?;
        assert!(matches!(pending::read(&path, true)?, pending::PendingRead::Unusable));
        pending::write(&directory.0, &token, true)?;

        assert_eq!(store.discard_pending_file(&path)?, None);
        assert!(matches!(
            pending::read(&path, true)?,
            pending::PendingRead::Ready(found) if found.sha256_hex() == token.sha256_hex()
        ));
        assert!(pending::read_in_progress(&directory.0, &token.sha256_hex())?.is_some());
        assert!(keys::open(store.key_backend(), &record.key_name)?.is_some());
        assert!(
            !directory
                .0
                .join("identity")
                .join("rejected")
                .join(format!("{}.json", token.sha256_hex()))
                .exists()
        );
        Ok(())
    }

    #[test]
    fn wrong_filename_is_deleted_without_a_marker() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let token = test_token()?;
        let wrong_hash = "0".repeat(64);
        let path = pending::file_path(&directory.0, &wrong_hash)?;
        let payload = serde_json::to_vec(&json!({"version": 1, "token": token.as_str()}))?;
        #[cfg(windows)]
        let contents = crate::windows::protect(&payload)?;
        #[cfg(not(windows))]
        let contents = payload;
        private_file::write_atomic(&directory.0, &path, &contents, true)?;
        assert!(matches!(pending::read(&path, true)?, pending::PendingRead::Unusable));
        assert_eq!(store.discard_pending_file(&path)?, Some(PendingDiscard::Unusable));
        assert!(!path.exists());
        assert!(rejected::list_rejected(&directory.0)?.is_empty());
        Ok(())
    }

    #[test]
    fn untrusted_state_files_cannot_reject_or_supply_an_enrollment_key() -> anyhow::Result<()> {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let token = test_token()?;
        let hash = token.sha256_hex();
        pending::write(&directory.0, &token, true)?;

        let marker_path = directory
            .0
            .join("identity")
            .join("rejected")
            .join(format!("{hash}.json"));
        fs::write(
            &marker_path,
            serde_json::to_vec(&json!({
                "version": 1,
                "token_sha256": token.sha256_hex(),
                "code": "identity_revoked",
                "at": "2026-09-24T12:00:00Z"
            }))?,
        )?;
        #[cfg(unix)]
        fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o644))?;
        #[cfg(windows)]
        let held_marker = {
            use std::os::windows::fs::OpenOptionsExt as _;

            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .open(&marker_path)?
        };

        let fake_key_name = keys::new_key_name("ai");
        let record_path = pending::in_progress_path(&directory.0, &hash)?;
        fs::write(
            &record_path,
            serde_json::to_vec(&pending::InProgress {
                version: 1,
                token_sha256: token.sha256_hex(),
                key_name: fake_key_name.clone(),
            })?,
        )?;
        #[cfg(unix)]
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o644))?;

        let (record, _key) = store
            .begin_enrollment(&token)?
            .context("untrusted marker rejected the pending token")?;
        #[cfg(windows)]
        drop(held_marker);
        assert_ne!(record.key_name, fake_key_name);
        assert!(keys::open(store.key_backend(), &fake_key_name)?.is_none());
        assert!(marker_path.exists());

        let authority_id = Uuid::new_v4();
        let identity_path = store.identity_path(authority_id);
        fs::create_dir_all(identity_path.parent().context("identity path has no directory")?)?;
        fs::write(&identity_path, b"not a stored identity")?;
        #[cfg(unix)]
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o644))?;
        assert!(store.read_identity(authority_id)?.is_none());
        let replacement = StoredIdentity {
            version: 1,
            authority_id,
            identity_id: Uuid::new_v4(),
            base_url: token.base_url().clone(),
            config: json!({"version": 1, "revision": 1}),
            token_sha256: token.sha256_hex(),
            rejected: None,
            keys: KeySlots {
                current: KeyRecord {
                    key_name: record.key_name.clone(),
                    certificate_chain: Some(vec!["YWJj".into()]),
                },
                pending: None,
                previous: None,
            },
        };
        assert!(store.write_identity(&replacement).is_err());
        assert!(
            store.reconcile().is_err(),
            "untrusted identity file did not stop reconciliation"
        );
        assert!(keys::open(store.key_backend(), &record.key_name)?.is_some());
        fs::remove_file(&identity_path)?;

        let pending_path = pending::file_path(&directory.0, &hash)?;
        #[cfg(windows)]
        private_file::write_atomic(&directory.0, &pending_path, b"not encrypted", true)?;
        #[cfg(unix)]
        fs::set_permissions(&pending_path, fs::Permissions::from_mode(0o644))?;
        store.reconcile()?;
        assert!(pending::read_in_progress(&directory.0, &hash)?.is_some());
        assert!(keys::open(store.key_backend(), &record.key_name)?.is_some());
        Ok(())
    }

    #[test]
    fn untrusted_lock_file_is_never_used_for_state_changes() -> anyhow::Result<()> {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let _store = directory.store()?;
        let path = directory.0.join("identity").join(".agent-identity.lock");
        fs::write(&path, [])?;
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        #[cfg(windows)]
        let held = {
            use std::os::windows::fs::OpenOptionsExt as _;

            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .open(&path)?
        };
        #[cfg(unix)]
        assert!(state_lock::acquire(&directory.0, true).is_err());
        #[cfg(windows)]
        {
            let lock = state_lock::acquire(&directory.0, true)?;
            crate::windows::verify_protected_directory(&lock, true, false)?;
        }
        #[cfg(windows)]
        drop(held);
        fs::remove_file(&path)?;
        let lock = state_lock::acquire(&directory.0, true)?;
        #[cfg(windows)]
        crate::windows::verify_protected_directory(&lock, true, false)?;
        drop(lock);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn directory_inspection_failure_preserves_recorded_identity_key() -> anyhow::Result<()> {
        if crate::windows::is_system()? {
            return Ok(());
        }
        let directory = TestDir::new()?;
        let store = directory.store()?;
        let identity = enroll_locally(&store, &directory.0)?;
        let path = store.identity_path(identity.authority_id);
        let authority = path.parent().context("identity has no authority directory")?;
        crate::windows::set_test_directory_access(authority, false)?;
        let result = store.reconcile();
        crate::windows::set_test_directory_access(authority, true)?;
        assert!(result.is_err(), "inaccessible authority directory was silently ignored");
        assert!(keys::open(store.key_backend(), &identity.keys.current.key_name)?.is_some());
        assert_eq!(store.read_identity(identity.authority_id)?, Some(identity));
        Ok(())
    }

    #[test]
    fn permanent_token_errors_create_markers_and_skip_replayed_pending_files() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        for (index, reason, expected_code) in [
            (1u8, EnrollmentDiscardReason::TokenInvalid, "token_invalid"),
            (2u8, EnrollmentDiscardReason::TokenExhausted, "token_exhausted"),
            (3u8, EnrollmentDiscardReason::TokenExpired, "token_expired"),
        ] {
            let token = Token::parse(&format!(
                "dvaet1.{}.{}",
                URL_SAFE_NO_PAD.encode(r#"{"u":"https://example.test"}"#),
                URL_SAFE_NO_PAD.encode([index; 32])
            ))?;
            let hash_hex = token.sha256_hex();
            let path = pending::write(&directory.0, &token, true)?;
            store.discard_enrollment(&hash_hex, reason)?;
            assert!(!path.exists());
            let marker_path = directory
                .0
                .join("identity")
                .join("rejected")
                .join(format!("{hash_hex}.json"));
            let marker: Value = serde_json::from_slice(&fs::read(marker_path)?)?;
            assert_eq!(marker["code"], expected_code);
            assert_eq!(marker["token_sha256"], token.sha256_hex());
            pending::write(&directory.0, &token, true)?;
            assert!(store.begin_enrollment(&token)?.is_none());
            assert!(!path.exists());
        }
        Ok(())
    }

    #[test]
    fn stale_config_and_key_snapshots_cannot_destroy_a_promoted_key() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let mut fresh = enroll_locally(&store, &directory.0)?;
        let already_enrolled = test_token()?;
        pending::write(&directory.0, &already_enrolled, true)?;
        assert!(store.begin_enrollment(&already_enrolled)?.is_none());
        assert!(keys::open(store.key_backend(), &fresh.keys.current.key_name)?.is_some());
        let mut stale = fresh.clone();
        assert!(store.update_config(&mut fresh, json!({"version": 1, "revision": 9}))?);
        assert!(!store.update_config(&mut stale, json!({"version": 1, "revision": 8}))?);
        assert_eq!(stale.config["revision"], 9);

        let pending_key = store.create_pending_key(&mut fresh).context("record renewal key")?;
        let original_name = fresh.keys.current.key_name.clone();
        let new_name = pending_key.name().to_owned();
        let mut promoted = fresh.clone();
        promoted.keys.previous = Some(promoted.keys.current.clone());
        promoted.keys.current = KeyRecord {
            key_name: new_name.clone(),
            certificate_chain: Some(vec!["bmV3".into()]),
        };
        promoted.keys.pending = None;
        store
            .replace_identity(&fresh, &promoted)
            .context("promote renewal key")?;
        let mut rollback = promoted.clone();
        rollback.config = json!({"version": 1, "revision": 8});
        rollback.keys.previous = None;
        assert!(store.replace_identity(&promoted, &rollback).is_err());
        assert!(keys::open(store.key_backend(), &original_name)?.is_some());
        let mut same_revision = promoted.clone();
        same_revision.config = json!({"version": 1, "revision": 9, "changed": true});
        assert!(store.replace_identity(&promoted, &same_revision).is_err());
        assert_eq!(
            store
                .read_identity(promoted.authority_id)?
                .context("identity disappeared")?,
            promoted
        );
        assert!(store.remove_pending_key(&mut fresh).is_err());
        assert!(keys::open(store.key_backend(), &new_name)?.is_some());

        assert!(store.update_config(&mut stale, json!({"version": 1, "revision": 10}))?);
        assert_eq!(stale.keys.current.key_name, new_name);
        let mut stale_replacement = promoted.clone();
        stale_replacement.config = json!({"version": 1, "revision": 11});
        assert!(store.replace_identity(&promoted, &stale_replacement).is_err());
        store.remove_previous_key(&mut stale)?;
        assert!(keys::open(store.key_backend(), &original_name)?.is_none());
        assert!(keys::open(store.key_backend(), &new_name)?.is_some());
        assert_eq!(
            store
                .read_identity(stale.authority_id)?
                .context("identity disappeared")?
                .config["revision"],
            10
        );
        Ok(())
    }

    #[test]
    fn missing_current_key_rejects_the_identity_as_key_lost() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Identities", "Stored identities"): a missing current key records
        // `rejected { code: "key_lost" }` and keeps the identity, so the same token stays a no-op.
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let identity = enroll_locally(&store, &directory.0)?;
        keys::delete(store.key_backend(), &identity.keys.current.key_name)?;

        store.reconcile()?;

        let stored = store
            .read_identity(identity.authority_id)?
            .context("identity with a lost key was deleted")?;
        let rejection = stored
            .rejected
            .clone()
            .context("identity with a lost key is not rejected")?;
        assert_eq!(rejection.code, "key_lost");
        let at = OffsetDateTime::parse(&rejection.at, &Rfc3339)?;
        assert_eq!(at.offset(), time::UtcOffset::UTC);
        assert_eq!(
            StoredIdentity {
                rejected: None,
                ..stored
            },
            identity
        );
        let token = test_token()?;
        pending::write(&directory.0, &token, true)?;
        assert!(store.begin_enrollment(&token)?.is_none());
        Ok(())
    }

    #[test]
    fn recovery_keeps_the_expired_pending_key_as_previous_until_the_fresh_key_is_confirmed() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Stored identities"): during pending-key recovery the expired pending key
        // moves to `previous` and the fresh key is recorded as `pending`; once the next `confirm` succeeds, the agent
        // deletes the expired pending key, then promotes as usual.
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let mut identity = enroll_locally(&store, &directory.0)?;
        let current = identity.keys.current.clone();
        store.create_pending_key(&mut identity)?;
        store.store_pending_chain(&mut identity, vec!["ZXhwaXJlZA==".into()])?;
        let expired = identity.keys.pending.clone().context("pending key disappeared")?;

        let fresh_name = store.begin_recovery(&mut identity)?.name().to_owned();

        let stored = store
            .read_identity(identity.authority_id)?
            .context("identity disappeared")?;
        assert_eq!(stored.keys.current, current);
        assert_eq!(stored.keys.previous.as_ref(), Some(&expired));
        assert_eq!(
            stored.keys.pending,
            Some(KeyRecord {
                key_name: fresh_name.clone(),
                certificate_chain: None,
            })
        );
        for name in [&current.key_name, &expired.key_name, &fresh_name] {
            assert!(keys::open(store.key_backend(), name)?.is_some(), "{name}");
        }

        store.store_pending_chain(&mut identity, vec!["ZnJlc2g=".into()])?;
        store.remove_previous_key(&mut identity)?;
        store.promote_pending(&mut identity)?;
        store.remove_previous_key(&mut identity)?;
        assert!(keys::open(store.key_backend(), &expired.key_name)?.is_none());
        assert!(keys::open(store.key_backend(), &current.key_name)?.is_none());
        assert_eq!(identity.keys.current.key_name, fresh_name);
        Ok(())
    }

    #[test]
    fn repeated_recovery_keeps_the_newest_expired_pending_key_and_deletes_the_older() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Stored identities"): if recovery must start again before a `confirm`
        // succeeds, the newest expired pending key replaces the one in `previous` and the older one is deleted, so the
        // newest signs the next recovery renewal; the runner signs that renewal with `previous`.
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let mut identity = enroll_locally(&store, &directory.0)?;
        let current = identity.keys.current.clone();
        store.create_pending_key(&mut identity)?;
        store.store_pending_chain(&mut identity, vec!["b2xkZXI=".into()])?;
        let older = identity.keys.pending.clone().context("pending key disappeared")?;
        store.begin_recovery(&mut identity)?;
        store.store_pending_chain(&mut identity, vec!["bmV3ZXN0".into()])?;
        let newest = identity.keys.pending.clone().context("recovery lost its pending key")?;

        let fresh_name = store.begin_recovery(&mut identity)?.name().to_owned();

        let stored = store
            .read_identity(identity.authority_id)?
            .context("identity disappeared")?;
        assert_eq!(stored.keys.current, current);
        assert_eq!(stored.keys.previous.as_ref(), Some(&newest));
        assert_eq!(
            stored.keys.pending,
            Some(KeyRecord {
                key_name: fresh_name.clone(),
                certificate_chain: None,
            })
        );
        assert!(keys::open(store.key_backend(), &older.key_name)?.is_none());
        for name in [&current.key_name, &newest.key_name, &fresh_name] {
            assert!(keys::open(store.key_backend(), name)?.is_some(), "{name}");
        }
        Ok(())
    }

    fn key_file(directory: &TestDir, key_name: &str) -> Utf8PathBuf {
        directory.0.join("identity").join("keys").join(format!("{key_name}.p8"))
    }

    #[test]
    fn startup_replaces_a_missing_certified_pending_key_with_a_fresh_one() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Stored identities"): a pending key missing from its store is unusable,
        // and the agent deletes it and its slot before renewing with a fresh key; the pending slot keeps the
        // `confirm` barrier of `CONTRACT.agent-identity.md` §8.1 until that renewal is confirmed.
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let mut identity = enroll_locally(&store, &directory.0)?;
        let certified = store.create_pending_key(&mut identity)?.name().to_owned();
        store.store_pending_chain(&mut identity, vec!["cGVuZGluZw==".into()])?;
        keys::delete(store.key_backend(), &certified)?;

        store.reconcile()?;

        let stored = store
            .read_identity(identity.authority_id)?
            .context("identity disappeared")?;
        assert_eq!(stored.keys.current, identity.keys.current);
        assert_eq!(stored.keys.previous, None);
        let pending = stored.keys.pending.context("start-up dropped the pending slot")?;
        assert_ne!(pending.key_name, certified);
        assert_eq!(pending.certificate_chain, None);
        assert!(keys::open(store.key_backend(), &pending.key_name)?.is_some());
        Ok(())
    }

    #[test]
    fn startup_leaves_a_refused_pending_key_to_its_runner() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Stored identities"): a pending key refused when opened is unusable and is
        // replaced before a fresh-key renewal; start-up must not stop on it, or no identity would run.
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let mut identity = enroll_locally(&store, &directory.0)?;
        let refused = store.create_pending_key(&mut identity)?.name().to_owned();
        store.store_pending_chain(&mut identity, vec!["cGVuZGluZw==".into()])?;
        fs::write(key_file(&directory, &refused), b"not a PKCS#8 key")?;
        assert!(keys::open(store.key_backend(), &refused).is_err());

        store.reconcile()?;

        assert_eq!(store.read_identity(identity.authority_id)?, Some(identity));
        Ok(())
    }

    #[test]
    fn startup_leaves_a_rejected_identity_s_slots_unchanged() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Identities"): a rejected identity keeps its keys and slots until a new
        // identity replaces it or the agent is uninstalled.
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let mut identity = enroll_locally(&store, &directory.0)?;
        let pending = store.create_pending_key(&mut identity)?.name().to_owned();
        store.store_pending_chain(&mut identity, vec!["cGVuZGluZw==".into()])?;
        store.reject_identity(&mut identity, "identity_revoked")?;
        keys::delete(store.key_backend(), &pending)?;

        store.reconcile()?;

        assert_eq!(store.read_identity(identity.authority_id)?, Some(identity));
        Ok(())
    }

    #[test]
    fn restart_resumes_recovery_when_the_fresh_pending_key_is_missing() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Stored identities"): a restart resumes pending-key recovery from the file,
        // and the expired pending key in `previous` is kept until the next `confirm` succeeds; an unusable pending key
        // is replaced by a fresh one.
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let mut identity = enroll_locally(&store, &directory.0)?;
        store.create_pending_key(&mut identity)?;
        store.store_pending_chain(&mut identity, vec!["ZXhwaXJlZA==".into()])?;
        let fresh_name = store.begin_recovery(&mut identity)?.name().to_owned();
        store.store_pending_chain(&mut identity, vec!["ZnJlc2g=".into()])?;
        let expired = identity
            .keys
            .previous
            .clone()
            .context("expired pending key disappeared")?;
        keys::delete(store.key_backend(), &fresh_name)?;

        store.reconcile()?;

        let stored = store
            .read_identity(identity.authority_id)?
            .context("identity disappeared")?;
        assert_eq!(stored.keys.previous, Some(expired));
        let pending = stored.keys.pending.context("recovery lost its pending slot")?;
        assert_ne!(pending.key_name, fresh_name);
        assert_eq!(pending.certificate_chain, None);
        assert!(keys::open(store.key_backend(), &pending.key_name)?.is_some());
        Ok(())
    }

    #[test]
    fn promotion_keeps_the_old_key_as_previous_until_it_is_deleted() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Stored identities"): when `confirm` succeeds, `pending` becomes `current`
        // and the old key moves to `previous` until it is deleted.
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let mut identity = enroll_locally(&store, &directory.0)?;
        let old = identity.keys.current.clone();
        let new_name = store.create_pending_key(&mut identity)?.name().to_owned();
        store.store_pending_chain(&mut identity, vec!["bmV3".into()])?;

        store.promote_pending(&mut identity)?;

        let expected_current = KeyRecord {
            key_name: new_name.clone(),
            certificate_chain: Some(vec!["bmV3".into()]),
        };
        let stored = store
            .read_identity(identity.authority_id)?
            .context("identity disappeared")?;
        assert_eq!(stored.keys.current, expected_current);
        assert_eq!(stored.keys.previous.as_ref(), Some(&old));
        assert_eq!(stored.keys.pending, None);
        assert!(keys::open(store.key_backend(), &old.key_name)?.is_some());
        store.remove_previous_key(&mut identity)?;
        assert!(keys::open(store.key_backend(), &old.key_name)?.is_none());
        assert!(keys::open(store.key_backend(), &new_name)?.is_some());
        Ok(())
    }

    #[test]
    fn config_with_a_version_other_than_1_keeps_the_stored_config() -> anyhow::Result<()> {
        // `CONTRACT.agent-identity.md` §5.2: the agent keeps its stored config when it receives a config whose
        // `version` is not 1.
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let mut identity = enroll_locally(&store, &directory.0)?;
        let stored = identity.clone();

        assert!(
            store
                .update_config(&mut identity, json!({"version": 2, "revision": 99}))
                .is_err()
        );

        assert_eq!(store.read_identity(stored.authority_id)?, Some(stored));
        Ok(())
    }
}
