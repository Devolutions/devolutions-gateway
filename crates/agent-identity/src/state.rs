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
use uuid::{Uuid, Variant};

pub use crate::private_file::UntrustedStoredIdentity;
use crate::token::Token;
use crate::{chain, pending, private_file, rejected, state_lock};

const MAX_IDENTITY_BYTES: u64 = 2 * 1024 * 1024;
pub const IDENTITY_KEY_PREFIX: &str = "devolutions-agent-identity";
/// The rejection code of an identity whose current key no longer exists in its key store.
pub const KEY_LOST: &str = "key_lost";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredIdentity {
    pub version: u8,
    pub authority_id: Uuid,
    pub identity_id: Uuid,
    /// The token's `u` as received, without its trailing slashes ([CONTRACT.agent-identity.md §2 "Enrollment
    /// token"][contract] and `crates/agent-identity/INTENT.md`, "Stored identities").
    ///
    /// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#enrollment-token
    pub base_url: String,
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

impl KeyRecord {
    /// A key slot recorded before the authority issued a certificate for it.
    fn unissued(key_name: String) -> Self {
        Self {
            key_name,
            certificate_chain: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentDiscardReason {
    IdentityRevoked,
    TokenInvalid,
    TokenExhausted,
    TokenExpired,
    TokenUrlMismatch,
    TokenMalformed,
    AuthorityConflict,
    AuthorityUrlMismatch,
}

/// What [`Store::store_enrolled_identity`] did with the identity an enrollment returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrolledIdentity {
    /// The identity is stored.
    Stored,
    /// The enrollment is discarded as `authority_conflict`, and the held identity is unchanged.
    AuthorityConflict,
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
            Self::TokenUrlMismatch => "token_url_mismatch",
            Self::TokenMalformed => "token_malformed",
            Self::AuthorityConflict => "authority_conflict",
            Self::AuthorityUrlMismatch => "authority_url_mismatch",
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
            private_file::check_stored_identities(&data_dir, acl_grant_current_user)?;
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

    /// Checks, without changing anything, that every authority directory and its `identity.json` are owned by the agent's
    /// account and protected from other users.
    ///
    /// [`crates/agent-identity/INTENT.md`] ("Local state"): one that fails the check is never repaired or read as absent,
    /// and stops all identity processing until it is fixed, so every read and state change of the store runs this check
    /// first.
    ///
    /// [`crates/agent-identity/INTENT.md`]: ../INTENT.md
    pub fn check_stored_identities(&self) -> anyhow::Result<()> {
        private_file::check_stored_identities(&self.data_dir, self.acl_grant_current_user).map(drop)
    }

    /// Takes the state lock once every stored identity passes [`Store::check_stored_identities`].
    fn lock(&self) -> anyhow::Result<fs::File> {
        let lock = state_lock::acquire(&self.data_dir, self.acl_grant_current_user)?;
        self.check_stored_identities()?;
        Ok(lock)
    }

    pub fn read_identity(&self, authority_id: Uuid) -> anyhow::Result<Option<StoredIdentity>> {
        self.check_stored_identities()?;
        self.read_stored_identity(authority_id)
    }

    /// Reads an identity once every stored identity has passed [`Store::check_stored_identities`].
    fn read_stored_identity(&self, authority_id: Uuid) -> anyhow::Result<Option<StoredIdentity>> {
        let path = self.identity_path(authority_id);
        if !private_file::check_authority_directory(
            path.parent().context("identity file has no parent")?,
            self.acl_grant_current_user,
        )? {
            return Ok(None);
        }
        let Some(file) = private_file::open_identity_file(&path, self.acl_grant_current_user)? else {
            return Ok(None);
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
        let mut identities = Vec::new();
        for authority_id in private_file::check_stored_identities(&self.data_dir, self.acl_grant_current_user)? {
            identities.extend(self.read_stored_identity(authority_id)?);
        }
        identities.sort_by_key(|identity| identity.authority_id);
        Ok(identities)
    }

    /// Creates an identity only if its authority has no stored identity yet.
    ///
    /// Test-only: production stores enrolled identities through [`Store::store_enrolled_identity`], which applies the
    /// rule on a known authority ID at another base URL.
    #[cfg(test)]
    pub(crate) fn write_identity(&self, identity: &StoredIdentity) -> anyhow::Result<()> {
        let _lock = self.lock()?;
        self.write_identity_locked(None, identity)
    }

    /// Replaces an identity only while the expected snapshot is still current.
    ///
    /// Test-only, like [`Store::write_identity`].
    #[cfg(test)]
    pub(crate) fn replace_identity(&self, previous: &StoredIdentity, identity: &StoredIdentity) -> anyhow::Result<()> {
        let _lock = self.lock()?;
        self.write_identity_locked(Some(previous), identity)
    }

    /// Stores the identity an enrollment returned, replacing any identity held for its authority, unless that identity
    /// is held for another base URL and the returned chain doesn't verify against a root it holds.
    ///
    /// [`crates/agent-identity/INTENT.md`] ("Pending-enrollment files"): such an enrollment is a permanent outcome,
    /// recorded as `authority_conflict`, that keeps the held identity and its keys.
    /// The roots of a held identity are the last certificates of its chains.
    /// The caller supplies an identity whose `token_sha256` is the hash of a token read from its matching pending file.
    ///
    /// UNTESTED: the held identity is read, checked, and replaced or kept under one state lock, so that a concurrent
    /// change to it, such as a renewal that stores a chain from a new root, can't land between the check and the write.
    /// No test can interleave a change there; when changing this, keep the read, the check and the write or discard in
    /// one critical section.
    ///
    /// [`crates/agent-identity/INTENT.md`]: ../INTENT.md
    pub fn store_enrolled_identity(&self, identity: &StoredIdentity) -> anyhow::Result<EnrolledIdentity> {
        let _lock = self.lock()?;
        let held = self.read_stored_identity(identity.authority_id)?;
        if let Some(held) = &held
            && held.base_url != identity.base_url
            && !chain::verifies_against(
                identity.keys.current.certificate_chain.as_deref().unwrap_or_default(),
                &held
                    .keys
                    .records()
                    .filter_map(|key| key.certificate_chain.as_ref()?.last().map(String::as_str))
                    .collect::<Vec<_>>(),
            )
        {
            rejected::mark_rejected(
                &self.data_dir,
                &identity.token_sha256,
                EnrollmentDiscardReason::AuthorityConflict.code(),
                self.acl_grant_current_user,
            )?;
            self.discard_pending_state_locked(&identity.token_sha256)?;
            return Ok(EnrolledIdentity::AuthorityConflict);
        }
        self.write_identity_locked(held.as_ref(), identity)?;
        Ok(EnrolledIdentity::Stored)
    }

    fn write_identity_locked(
        &self,
        previous: Option<&StoredIdentity>,
        identity: &StoredIdentity,
    ) -> anyhow::Result<()> {
        self.validate_identity(identity)?;
        // Checked before any key is deleted, so a refused identity leaves the previous file and its keys intact.
        let bytes = serde_json::to_vec(identity).context("encode stored identity")?;
        ensure!(
            bytes.len() as u64 <= MAX_IDENTITY_BYTES,
            "stored identity exceeds size limit"
        );
        ensure!(
            previous.is_none_or(|previous| previous.authority_id == identity.authority_id),
            "stored identity authority changed"
        );
        let existing = self.read_stored_identity(identity.authority_id)?;
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
        let _lock = self.lock()?;
        let latest = self
            .read_stored_identity(identity.authority_id)?
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
        let name = keys::new_key_name(&self.key_prefix);
        self.update(
            identity,
            |updated| {
                ensure!(updated.keys.pending.is_none(), "identity already has a pending key");
                updated.keys.pending = Some(KeyRecord::unissued(name.clone()));
                Ok(())
            },
            || keys::generate(&self.backend, &name),
        )
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
                updated.keys.pending = Some(KeyRecord::unissued(name.clone()));
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
                updated.keys.pending = Some(KeyRecord::unissued(name.clone()));
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
        let _lock = self.lock()?;
        self.write_identity_locked(Some(identity), &updated)?;
        *identity = updated;
        then()
    }

    pub fn remove_previous_key(&self, identity: &mut StoredIdentity) -> anyhow::Result<()> {
        if identity.keys.previous.is_none() {
            return Ok(());
        }
        self.update(
            identity,
            |updated| {
                updated.keys.previous = None;
                Ok(())
            },
            || Ok(()),
        )
    }

    /// Reuses an enrollment key, or skips a token already represented by an identity or rejection marker.
    pub fn begin_enrollment(&self, token: &Token) -> anyhow::Result<Option<(pending::InProgress, Box<dyn DeviceKey>)>> {
        let _lock = self.lock()?;
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
        let _lock = self.lock()?;
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
        let _lock = self.lock()?;
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
        let _lock = self.lock()?;
        self.finish_enrollment_locked(hash_hex, authority_id)
    }

    fn finish_enrollment_locked(&self, hash_hex: &str, authority_id: Uuid) -> anyhow::Result<()> {
        let identity = self
            .read_stored_identity(authority_id)?
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
        let _lock = self.lock()?;
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
        for authority_id in private_file::check_stored_identities(&self.data_dir, self.acl_grant_current_user)? {
            let path = self.identity_path(authority_id);
            private_file::cleanup_temporary_files(
                path.parent().context("identity file has no parent")?,
                |stem| stem == ".identity.json",
                |path, _| private_file::remove_file(path),
            )?;
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
                    identity.keys.pending = Some(KeyRecord::unissued(name.clone()));
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
            crate::token::is_base_url(&identity.base_url),
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
    use std::time::{Duration, UNIX_EPOCH};

    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use der::asn1::{Any, BitString, OctetString};
    use der::flagset::FlagSet;
    use der::{Decode as _, Encode as _, Tag};
    use p256::ecdsa::{DerSignature, SigningKey};
    use p256::pkcs8::EncodePublicKey as _;
    use serde_json::json;
    use sha2::{Digest, Sha256, Sha384};
    use signature::Keypair as _;
    use signature::hazmat::PrehashSigner as _;
    use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
    use x509_cert::Certificate;
    use x509_cert::builder::profile::BuilderProfile;
    use x509_cert::builder::{Builder as _, CertificateBuilder};
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
    use x509_cert::ext::{Extension, ToExtension as _};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};

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

        fn authority(&self, authority_id: Uuid) -> Utf8PathBuf {
            self.0
                .join("identity")
                .join("authorities")
                .join(authority_id.to_string())
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // oracle: intent crates/agent-identity/INTENT.md §Identities
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
        token_for("https://example.test")
    }

    fn token_for(base_url: &str) -> anyhow::Result<Token> {
        Token::parse(&format!(
            "dvaet1.{}.{}",
            URL_SAFE_NO_PAD.encode(json!({ "u": base_url }).to_string()),
            "A".repeat(43)
        ))
    }

    fn identity_at(base_url: &str) -> StoredIdentity {
        StoredIdentity {
            version: 1,
            authority_id: Uuid::new_v4(),
            identity_id: Uuid::new_v4(),
            base_url: base_url.to_owned(),
            config: json!({"version": 1, "revision": 7}),
            token_sha256: hex::encode([1u8; 32]),
            rejected: None,
            keys: KeySlots {
                current: KeyRecord {
                    key_name: keys::new_key_name(IDENTITY_KEY_PREFIX),
                    certificate_chain: Some(vec!["YWJj".into()]),
                },
                pending: None,
                previous: None,
            },
        }
    }

    fn enroll_locally(store: &Store, data_dir: &Utf8Path) -> anyhow::Result<StoredIdentity> {
        enroll_with_chain(store, data_dir, vec!["YWJj".into()])
    }

    /// Enrolls an identity with `test_token`, whose current key holds `chain`.
    fn enroll_with_chain(store: &Store, data_dir: &Utf8Path, chain: Vec<String>) -> anyhow::Result<StoredIdentity> {
        let token = test_token()?;
        pending::write(data_dir, &token, true).context("write test pending token")?;
        let (progress, _key) = store
            .begin_enrollment(&token)?
            .context("new token was already processed")?;
        let identity = StoredIdentity {
            version: 1,
            authority_id: Uuid::new_v4(),
            identity_id: Uuid::new_v4(),
            base_url: token.base_url().to_owned(),
            config: json!({"version": 1, "revision": 7}),
            token_sha256: token.sha256_hex(),
            rejected: None,
            keys: KeySlots {
                current: KeyRecord {
                    key_name: progress.key_name,
                    certificate_chain: Some(chain),
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

    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
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

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    #[test]
    fn stores_the_token_base_url_without_trailing_slashes() -> anyhow::Result<()> {
        for (u, stored) in [
            ("https://example.test", "https://example.test"),
            ("https://example.test/", "https://example.test"),
            ("https://example.test//", "https://example.test"),
            ("https://example.test/dvls/", "https://example.test/dvls"),
            ("https://example.test/dvls//", "https://example.test/dvls"),
        ] {
            let identity = identity_at(token_for(u)?.base_url());
            assert_eq!(serde_json::to_value(&identity)?["base_url"], stored, "{u}");
        }
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    #[test]
    fn stores_the_token_base_url_as_received() -> anyhow::Result<()> {
        let identity = identity_at(token_for("https://EXAMPLE.test:443/Dv%20ls/")?.base_url());
        assert_eq!(
            serde_json::to_value(&identity)?["base_url"],
            "https://EXAMPLE.test:443/Dv%20ls"
        );
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
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

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
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

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn an_enrollment_refused_for_its_url_is_discarded_as_permanent() -> anyhow::Result<()> {
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

        store.discard_enrollment(&hash_hex, EnrollmentDiscardReason::AuthorityUrlMismatch)?;

        assert!(!path.exists());
        assert!(pending::read_in_progress(&directory.0, &hash_hex)?.is_none());
        assert!(keys::open(store.key_backend(), &record.key_name)?.is_none());
        assert!(store.list_identities()?.is_empty());
        let marker_path = directory
            .0
            .join("identity")
            .join("rejected")
            .join(format!("{hash_hex}.json"));
        let marker: Value = serde_json::from_slice(&fs::read(marker_path)?)?;
        assert_eq!(marker["code"], "authority_url_mismatch");
        assert_eq!(marker["token_sha256"], hash_hex);
        pending::write(&directory.0, &token, true)?;
        assert!(store.begin_enrollment(&token)?.is_none());
        assert!(!path.exists());
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
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

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
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

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
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

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
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

        // oracle: intent crates/agent-identity/INTENT.md §Local state
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
        private_file::create_authority_directory(
            identity_path.parent().context("identity path has no directory")?,
            true,
        )?;
        fs::write(&identity_path, b"not a stored identity")?;
        #[cfg(unix)]
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o644))?;
        // oracle: intent crates/agent-identity/INTENT.md §Local state
        let read = store
            .read_identity(authority_id)
            .err()
            .context("an untrusted identity file read as absent")?;
        assert_eq!(untrusted_path(&read), Some(identity_path.as_path()));
        let replacement = StoredIdentity {
            version: 1,
            authority_id,
            identity_id: Uuid::new_v4(),
            base_url: token.base_url().to_owned(),
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
        // oracle: intent crates/agent-identity/INTENT.md §Local state
        let write = store
            .write_identity(&replacement)
            .err()
            .context("an untrusted identity file was replaced")?;
        let reconciliation = store
            .reconcile()
            .err()
            .context("an untrusted identity file did not stop reconciliation")?;
        assert_eq!(untrusted_path(&write), Some(identity_path.as_path()));
        assert_eq!(untrusted_path(&reconciliation), Some(identity_path.as_path()));
        assert_eq!(fs::read(&identity_path)?, b"not a stored identity");
        // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
        assert!(keys::open(store.key_backend(), &record.key_name)?.is_some());
        fs::remove_file(&identity_path)?;

        let pending_path = pending::file_path(&directory.0, &hash)?;
        #[cfg(windows)]
        private_file::write_atomic(&directory.0, &pending_path, b"not encrypted", true)?;
        #[cfg(unix)]
        fs::set_permissions(&pending_path, fs::Permissions::from_mode(0o644))?;
        store.reconcile()?;
        // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
        assert!(pending::read_in_progress(&directory.0, &hash)?.is_some());
        assert!(keys::open(store.key_backend(), &record.key_name)?.is_some());
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
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

    // oracle: intent crates/agent-identity/INTENT.md §Local state
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

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
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
            // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
            (4u8, EnrollmentDiscardReason::TokenUrlMismatch, "token_url_mismatch"),
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

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[cfg(windows)]
    #[test]
    fn a_rejection_marker_that_cannot_be_read_keeps_its_token_from_enrolling() -> anyhow::Result<()> {
        use std::os::windows::fs::OpenOptionsExt as _;

        let directory = TestDir::new()?;
        let store = directory.store()?;
        let token = test_token()?;
        let hash_hex = token.sha256_hex();
        pending::write(&directory.0, &token, true)?;
        store.discard_enrollment(&hash_hex, EnrollmentDiscardReason::TokenInvalid)?;
        let marker_path = directory
            .0
            .join("identity")
            .join("rejected")
            .join(format!("{hash_hex}.json"));
        // A reader that shares nothing makes the agent's own marker unreadable without making it untrusted.
        let held_marker = fs::OpenOptions::new().read(true).share_mode(0).open(&marker_path)?;
        let path = pending::write(&directory.0, &token, true)?;

        let result = store.begin_enrollment(&token).map(|progress| progress.is_some());
        drop(held_marker);

        assert!(
            result.is_err(),
            "an unreadable rejection marker was read as absent: {result:?}"
        );
        assert!(path.exists());
        assert!(pending::read_in_progress(&directory.0, &hash_hex)?.is_none());
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    #[test]
    fn a_crash_after_removing_a_finished_pending_file_keeps_the_identity_key() -> anyhow::Result<()> {
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
        let mut identity = identity_at(token.base_url());
        identity.token_sha256 = token.sha256_hex();
        identity.keys.current.key_name = progress.key_name.clone();
        store.write_identity(&identity)?;
        pending::remove_file(&directory.0, &token.sha256_hex(), true)?;

        store.reconcile()?;

        assert!(pending::read_in_progress(&directory.0, &token.sha256_hex())?.is_none());
        assert!(keys::open(store.key_backend(), &progress.key_name)?.is_some());
        assert_eq!(store.read_identity(identity.authority_id)?, Some(identity));
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    #[test]
    fn an_identity_outside_the_stored_format_is_never_written() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let valid = || {
            let mut identity = identity_at("https://example.test/dvls");
            identity.keys.current.key_name = keys::new_key_name("ai");
            identity
        };
        store.write_identity(&valid())?;
        type Change = fn(&mut StoredIdentity);
        let invalid: [(&str, Change); 7] = [
            ("version 2", |identity| identity.version = 2),
            ("http base URL", |identity| {
                identity.base_url = "http://example.test/dvls".to_owned()
            }),
            // The stored base URL is the token's `u`, which never carries a user name or password.
            // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
            ("base URL with a user name and password", |identity| {
                identity.base_url = "https://user:pw@example.test/dvls".to_owned()
            }),
            // The token's `u` is read as text, so an upper-case scheme doesn't begin with `https://`.
            // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
            ("base URL with an upper-case scheme", |identity| {
                identity.base_url = "HTTPS://example.test/dvls".to_owned()
            }),
            ("upper-case token hash", |identity| {
                identity.token_sha256 = "AB".repeat(32)
            }),
            ("current key without a chain", |identity| {
                identity.keys.current.certificate_chain = None
            }),
            ("key name without the agent's prefix", |identity| {
                identity.keys.current.key_name = keys::new_key_name("other")
            }),
        ];
        for (case, change) in invalid {
            let mut identity = valid();
            change(&mut identity);
            assert!(store.write_identity(&identity).is_err(), "{case}");
            assert_eq!(store.read_identity(identity.authority_id)?, None, "{case}");
        }
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn a_restart_before_an_enrollment_finishes_keeps_the_stored_identity_s_key() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let token = test_token()?;
        let path = pending::write(&directory.0, &token, true)?;
        let (progress, _key) = store
            .begin_enrollment(&token)?
            .context("new token was already processed")?;
        let mut identity = identity_at(token.base_url());
        identity.token_sha256 = token.sha256_hex();
        identity.keys.current.key_name = progress.key_name.clone();
        store.write_identity(&identity)?;

        let restarted = directory.store()?;

        assert!(restarted.begin_enrollment(&token)?.is_none());
        assert!(!path.exists());
        assert!(pending::read_in_progress(&directory.0, &token.sha256_hex())?.is_none());
        assert!(keys::open(restarted.key_backend(), &progress.key_name)?.is_some());
        assert_eq!(restarted.read_identity(identity.authority_id)?, Some(identity));
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn an_identity_file_of_exactly_2_mib_is_read() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let identity = enroll_locally(&store, &directory.0)?;
        let path = store.identity_path(identity.authority_id);
        let json = serde_json::to_vec(&identity)?;
        // JSON allows leading white space, which pads the file to an exact size.
        for (size, readable) in [(2 * 1024 * 1024, true), (2 * 1024 * 1024 + 1, false)] {
            let mut padded = vec![b' '; size - json.len()];
            padded.extend_from_slice(&json);
            private_file::write_atomic(&directory.0, &path, &padded, true)?;
            assert_eq!(
                store
                    .read_identity(identity.authority_id)
                    .is_ok_and(|read| read.as_ref() == Some(&identity)),
                readable,
                "{size}"
            );
        }
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn an_identity_past_2_mib_is_never_written() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let old = enroll_locally(&store, &directory.0)?;
        let path = store.identity_path(old.authority_id);
        let old_bytes = fs::read(&path)?;
        let token = token_for("https://other.test")?;
        pending::write(&directory.0, &token, true)?;
        let (progress, _key) = store
            .begin_enrollment(&token)?
            .context("new token was already processed")?;
        let mut new = old.clone();
        new.identity_id = Uuid::new_v4();
        new.token_sha256 = token.sha256_hex();
        new.keys.current.key_name = progress.key_name;
        // A second chain entry pads the serialized identity to an exact size: `,"` before it and `"` after it.
        let unpadded = serde_json::to_vec(&new)?.len();
        let sized = |size: usize| {
            let mut identity = new.clone();
            let padding = "A".repeat(size - unpadded - r#","""#.len());
            identity.keys.current.certificate_chain = Some(vec!["YWJj".into(), padding]);
            identity
        };
        let oversized = sized(2 * 1024 * 1024 + 1);
        assert_eq!(serde_json::to_vec(&oversized)?.len(), 2 * 1024 * 1024 + 1);

        assert!(store.replace_identity(&old, &oversized).is_err());

        assert_eq!(fs::read(&path)?, old_bytes);
        // oracle: mutant size check moved after the replaced identity's keys are deleted
        assert!(keys::open(store.key_backend(), &old.keys.current.key_name)?.is_some());

        let at_limit = sized(2 * 1024 * 1024);
        store.replace_identity(&old, &at_limit)?;
        assert_eq!(fs::read(&path)?.len(), 2 * 1024 * 1024);
        assert_eq!(store.read_identity(old.authority_id)?, Some(at_limit));
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn a_new_enrollment_replaces_its_authority_s_identity_whatever_its_config_revision() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let old = enroll_locally(&store, &directory.0)?;
        let token = token_for("https://other.test")?;
        pending::write(&directory.0, &token, true)?;
        let (progress, _key) = store
            .begin_enrollment(&token)?
            .context("new token was already processed")?;
        let new = StoredIdentity {
            version: 1,
            authority_id: old.authority_id,
            identity_id: Uuid::new_v4(),
            base_url: token.base_url().to_owned(),
            config: json!({"version": 1, "revision": 1}),
            token_sha256: token.sha256_hex(),
            rejected: None,
            keys: KeySlots {
                current: KeyRecord {
                    key_name: progress.key_name,
                    certificate_chain: Some(vec!["bmV3".into()]),
                },
                pending: None,
                previous: None,
            },
        };

        store.replace_identity(&old, &new)?;

        assert_eq!(store.read_identity(old.authority_id)?, Some(new));
        assert!(keys::open(store.key_backend(), &old.keys.current.key_name)?.is_none());
        Ok(())
    }

    const HELD_ROOT: &str = "CN=Held root";

    /// `ecdsa-with-SHA256` ([RFC 5758 §3.2]).
    ///
    /// [RFC 5758 §3.2]: https://www.rfc-editor.org/rfc/rfc5758#section-3.2
    const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

    /// `ecdsa-with-SHA384` ([RFC 5758 §3.2]).
    ///
    /// [RFC 5758 §3.2]: https://www.rfc-editor.org/rfc/rfc5758#section-3.2
    const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

    /// A test certificate and its key, made in the test, so that whether a chain verifies follows from how the test
    /// signed it.
    struct TestCertificate {
        key: TestKey,
        name: Name,
        /// The certificate, `base64` DER.
        der: String,
    }

    impl TestCertificate {
        /// A self-signed CA certificate for a P-256 key.
        fn root(seed: u8, name: &str) -> anyhow::Result<Self> {
            Self::root_for(TestKey::p256(seed)?, name)
        }

        /// A self-signed CA certificate for `key`.
        fn root_for(key: TestKey, name: &str) -> anyhow::Result<Self> {
            let name: Name = name.parse()?;
            let der = test_certificate(&key, &name, &name, &key, vec![ca(None)?])?;
            Ok(Self { key, name, der })
        }

        /// A certificate this one signs, with basicConstraints `cA` set when `ca` holds, and no extension otherwise.
        fn issue(&self, seed: u8, name: &str, ca: bool) -> anyhow::Result<Self> {
            let extensions = if ca { vec![self::ca(None)?] } else { Vec::new() };
            self.issue_with(seed, name, extensions)
        }

        /// A certificate for a P-256 key that this one signs, with `extensions`.
        fn issue_with(&self, seed: u8, name: &str, extensions: Vec<Extension>) -> anyhow::Result<Self> {
            self.issue_for(TestKey::p256(seed)?, name, extensions)
        }

        /// A certificate for `key` that this one signs, with `extensions`.
        fn issue_for(&self, key: TestKey, name: &str, extensions: Vec<Extension>) -> anyhow::Result<Self> {
            let name: Name = name.parse()?;
            let der = test_certificate(&self.key, &self.name, &name, &key, extensions)?;
            Ok(Self { key, name, der })
        }
    }

    /// The key of a test certificate, which signs with the algorithm the contract pairs with its type.
    enum TestKey {
        /// Signs with `ecdsa-with-SHA256`.
        P256(SigningKey),
        /// Signs with `ecdsa-with-SHA384`.
        P384(p384::ecdsa::SigningKey),
        /// Signs with `sha256WithRSAEncryption`.
        Rsa(rsa::pkcs1v15::SigningKey<Sha256>),
    }

    impl TestKey {
        fn p256(seed: u8) -> anyhow::Result<Self> {
            Ok(Self::P256(SigningKey::from_slice(&[seed; 32])?))
        }

        fn p384(seed: u8) -> anyhow::Result<Self> {
            Ok(Self::P384(p384::ecdsa::SigningKey::from_slice(&[seed; 48])?))
        }

        /// An RSA key whose primes are the Mersenne primes 2^521 - 1 and 2^607 - 1, so that no slow key generation
        /// runs; whether a chain may use RSA doesn't depend on the key's strength.
        fn rsa() -> anyhow::Result<Self> {
            let mersenne_prime = |exponent: usize| {
                let mut bytes = vec![0xffu8; exponent.div_ceil(8)];
                bytes[0] >>= 8 * bytes.len() - exponent;
                rsa::BoxedUint::from_be_slice_vartime(&bytes)
            };
            let key = rsa::RsaPrivateKey::from_p_q(
                mersenne_prime(521),
                mersenne_prime(607),
                rsa::BoxedUint::from(65_537u32),
            )?;
            Ok(Self::Rsa(rsa::pkcs1v15::SigningKey::new(key)))
        }

        fn public_key(&self) -> anyhow::Result<SubjectPublicKeyInfoOwned> {
            let der = match self {
                Self::P256(key) => key.verifying_key().to_public_key_der()?,
                Self::P384(key) => key.verifying_key().to_public_key_der()?,
                Self::Rsa(key) => key.verifying_key().to_public_key_der()?,
            };
            Ok(SubjectPublicKeyInfoOwned::try_from(der.as_bytes())?)
        }

        /// Signs the `D` digest of `message` with this ECDSA key, whether or not `D` is the digest the contract pairs with
        /// its curve.
        fn sign_ecdsa_digest<D: Digest>(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
            let digest = D::digest(message);
            Ok(match self {
                Self::P256(key) => {
                    let signature: p256::ecdsa::Signature = key.sign_prehash(&digest)?;
                    signature.to_der().as_bytes().to_vec()
                }
                Self::P384(key) => {
                    let signature: p384::ecdsa::Signature = key.sign_prehash(&digest)?;
                    signature.to_der().as_bytes().to_vec()
                }
                Self::Rsa(_) => anyhow::bail!("an RSA key does not sign with ECDSA"),
            })
        }
    }

    /// Returns `certificate` with its signed part naming `signed` as its signature algorithm, signed again by `sign`, and
    /// with `outer` as its signatureAlgorithm.
    ///
    /// `signed` must encode to the length of the algorithm it replaces, as every `ecdsa-with-SHA*` identifier does.
    fn re_signed(
        certificate: &str,
        signed: ObjectIdentifier,
        outer: ObjectIdentifier,
        sign: impl FnOnce(&[u8]) -> anyhow::Result<Vec<u8>>,
    ) -> anyhow::Result<String> {
        let algorithm = |oid| AlgorithmIdentifierOwned { oid, parameters: None }.to_der();
        let certificate = Certificate::from_der(&STANDARD.decode(certificate)?)?;
        let mut tbs = certificate.tbs_certificate().to_der()?;
        let current = certificate.tbs_certificate().signature().to_der()?;
        let replacement = algorithm(signed)?;
        ensure!(
            replacement.len() == current.len(),
            "the signature algorithms differ in length"
        );
        // The signature algorithm is the first algorithm identifier of the signed part, after its version and serial
        // number.
        let position = tbs
            .windows(current.len())
            .position(|window| window == current)
            .context("signed part without its signature algorithm")?;
        tbs[position..position + current.len()].copy_from_slice(&replacement);
        let signature = BitString::from_bytes(&sign(&tbs)?)?.to_der()?;
        let contents = [tbs, algorithm(outer)?, signature].concat();
        Ok(STANDARD.encode(Any::new(Tag::Sequence, contents)?.to_der()?))
    }

    /// basicConstraints with `cA` set and `path_len` as its pathLenConstraint.
    fn ca(path_len: Option<u8>) -> anyhow::Result<Extension> {
        let constraints = BasicConstraints {
            ca: true,
            path_len_constraint: path_len,
        };
        Ok(constraints.to_extension(&Name::default(), &[])?)
    }

    fn key_usage(usages: FlagSet<KeyUsages>) -> anyhow::Result<Extension> {
        Ok(KeyUsage(usages).to_extension(&Name::default(), &[])?)
    }

    struct TestProfile {
        issuer: Name,
        subject: Name,
        extensions: Vec<Extension>,
    }

    impl BuilderProfile for TestProfile {
        fn get_issuer(&self, _subject: &Name) -> Name {
            self.issuer.clone()
        }

        fn get_subject(&self) -> Name {
            self.subject.clone()
        }

        fn build_extensions(
            &self,
            _spk: spki::SubjectPublicKeyInfoRef<'_>,
            _issuer_spk: spki::SubjectPublicKeyInfoRef<'_>,
            _tbs: &x509_cert::certificate::TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            Ok(self.extensions.clone())
        }
    }

    /// Returns a `base64` DER certificate for `key` named `subject`, which `signer` signs under the issuer name `issuer`.
    fn test_certificate(
        signer: &TestKey,
        issuer: &Name,
        subject: &Name,
        key: &TestKey,
        extensions: Vec<Extension>,
    ) -> anyhow::Result<String> {
        let profile = TestProfile {
            issuer: issuer.clone(),
            subject: subject.clone(),
            extensions,
        };
        let validity = Validity::new(
            Time::try_from(UNIX_EPOCH + Duration::from_secs(1_700_000_000))?,
            Time::try_from(UNIX_EPOCH + Duration::from_secs(1_900_000_000))?,
        );
        let builder = CertificateBuilder::new(profile, SerialNumber::from(1u64), validity, key.public_key()?)?;
        let certificate = match signer {
            TestKey::P256(signer) => builder.build::<_, DerSignature>(signer)?,
            TestKey::P384(signer) => builder.build::<_, p384::ecdsa::DerSignature>(signer)?,
            TestKey::Rsa(signer) => builder.build::<_, rsa::pkcs1v15::Signature>(signer)?,
        };
        Ok(STANDARD.encode(certificate.to_der()?))
    }

    /// Stores an identity at `https://example.test` whose chain ends in its root.
    fn hold_identity_under(
        store: &Store,
        data_dir: &Utf8Path,
        root: &TestCertificate,
    ) -> anyhow::Result<StoredIdentity> {
        let leaf = root.issue(11, "CN=Held identity", false)?;
        enroll_with_chain(store, data_dir, vec![leaf.der, root.der.clone()])
    }

    /// Begins an enrollment with `token` and returns the identity it stores once the authority answers with
    /// `authority_id` and `chain`.
    fn enrollment_answer(
        store: &Store,
        data_dir: &Utf8Path,
        token: &Token,
        authority_id: Uuid,
        chain: Vec<String>,
    ) -> anyhow::Result<StoredIdentity> {
        pending::write(data_dir, token, true)?;
        let (progress, _key) = store
            .begin_enrollment(token)?
            .context("new token was already processed")?;
        Ok(StoredIdentity {
            version: 1,
            authority_id,
            identity_id: Uuid::new_v4(),
            base_url: token.base_url().to_owned(),
            config: json!({"version": 1, "revision": 1}),
            token_sha256: token.sha256_hex(),
            rejected: None,
            keys: KeySlots {
                current: KeyRecord {
                    key_name: progress.key_name,
                    certificate_chain: Some(chain),
                },
                pending: None,
                previous: None,
            },
        })
    }

    /// Returns a chain that has no signature path to `held`, the root of the held identity.
    type ChainOutsideHeldRoots = fn(&TestCertificate) -> anyhow::Result<Vec<String>>;

    fn chain_from_another_root(_held: &TestCertificate) -> anyhow::Result<Vec<String>> {
        let root = TestCertificate::root(30, "CN=Other root")?;
        Ok(vec![root.issue(31, "CN=Claimed identity", false)?.der, root.der])
    }

    fn chain_from_a_root_with_the_held_root_s_name(_held: &TestCertificate) -> anyhow::Result<Vec<String>> {
        let impostor = TestCertificate::root(32, HELD_ROOT)?;
        Ok(vec![
            impostor.issue(33, "CN=Claimed identity", false)?.der,
            impostor.der,
        ])
    }

    fn chain_signed_by_the_held_root_s_key_under_another_issuer_name(
        held: &TestCertificate,
    ) -> anyhow::Result<Vec<String>> {
        let leaf = test_certificate(
            &held.key,
            &"CN=Other root".parse()?,
            &"CN=Claimed identity".parse()?,
            &TestKey::p256(34)?,
            Vec::new(),
        )?;
        Ok(vec![leaf, held.der.clone()])
    }

    fn chain_through_a_leaf_of_the_held_root(held: &TestCertificate) -> anyhow::Result<Vec<String>> {
        // The leaf of another device, shaped as the contract's leaves are, signs with that device's key.
        let device = held.issue_with(
            35,
            "CN=Other device",
            vec![key_usage(KeyUsages::DigitalSignature.into())?],
        )?;
        let leaf = device.issue(36, "CN=Claimed identity", false)?;
        Ok(vec![leaf.der, device.der, held.der.clone()])
    }

    fn chain_through_a_certificate_without_basic_constraints(held: &TestCertificate) -> anyhow::Result<Vec<String>> {
        let signer = held.issue(37, "CN=Not a CA", false)?;
        let leaf = signer.issue(38, "CN=Claimed identity", false)?;
        Ok(vec![leaf.der, signer.der, held.der.clone()])
    }

    fn chain_through_a_ca_without_key_cert_sign(held: &TestCertificate) -> anyhow::Result<Vec<String>> {
        let extensions = vec![ca(None)?, key_usage(KeyUsages::DigitalSignature.into())?];
        let signer = held.issue_with(39, "CN=Intermediate", extensions)?;
        let leaf = signer.issue(40, "CN=Claimed identity", false)?;
        Ok(vec![leaf.der, signer.der, held.der.clone()])
    }

    fn chain_past_a_path_length_constraint(held: &TestCertificate) -> anyhow::Result<Vec<String>> {
        // No CA certificate may follow one whose pathLenConstraint is 0.
        let limited = held.issue_with(41, "CN=Limited intermediate", vec![ca(Some(0))?])?;
        let below = limited.issue(42, "CN=Intermediate", true)?;
        let leaf = below.issue(43, "CN=Claimed identity", false)?;
        Ok(vec![leaf.der, below.der, limited.der, held.der.clone()])
    }

    fn chain_through_a_ca_with_an_unreadable_key_usage(held: &TestCertificate) -> anyhow::Result<Vec<String>> {
        // A critical keyUsage whose value is a NULL rather than a BIT STRING.
        let mut key_usage = key_usage(KeyUsages::KeyCertSign.into())?;
        key_usage.critical = true;
        key_usage.extn_value = OctetString::new([0x05, 0x00])?;
        let signer = held.issue_with(50, "CN=Intermediate", vec![ca(None)?, key_usage])?;
        let leaf = signer.issue(51, "CN=Claimed identity", false)?;
        Ok(vec![leaf.der, signer.der, held.der.clone()])
    }

    fn chain_with_a_leaf_naming_another_signature_algorithm(held: &TestCertificate) -> anyhow::Result<Vec<String>> {
        // The held root signs the leaf with `ecdsa-with-SHA256` (1.2.840.10045.4.3.2), whose DER is this; the last copy
        // is the leaf's signatureAlgorithm, outside the signed part, and its last byte turns it into `ecdsa-with-SHA384`
        // (1.2.840.10045.4.3.3).
        const ECDSA_WITH_SHA256_DER: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let mut leaf = STANDARD.decode(held.issue(52, "CN=Claimed identity", false)?.der)?;
        let algorithm = leaf
            .windows(ECDSA_WITH_SHA256_DER.len())
            .rposition(|window| window == ECDSA_WITH_SHA256_DER)
            .context("leaf without ecdsa-with-SHA256")?;
        leaf[algorithm + ECDSA_WITH_SHA256_DER.len() - 1] = 0x03;
        Ok(vec![STANDARD.encode(leaf), held.der.clone()])
    }

    fn chain_with_a_leaf_whose_signed_part_names_another_signature_algorithm(
        held: &TestCertificate,
    ) -> anyhow::Result<Vec<String>> {
        // The signature verifies under the algorithm the leaf's signatureAlgorithm names, not under the one its signed
        // part names.
        let leaf = held.issue(64, "CN=Claimed identity", false)?;
        let leaf = re_signed(&leaf.der, ECDSA_WITH_SHA384, ECDSA_WITH_SHA256, |tbs| {
            held.key.sign_ecdsa_digest::<Sha256>(tbs)
        })?;
        Ok(vec![leaf, held.der.clone()])
    }

    fn chain_with_a_leaf_the_held_p256_root_signs_with_sha384(held: &TestCertificate) -> anyhow::Result<Vec<String>> {
        let leaf = held.issue(60, "CN=Claimed identity", false)?;
        let leaf = re_signed(&leaf.der, ECDSA_WITH_SHA384, ECDSA_WITH_SHA384, |tbs| {
            held.key.sign_ecdsa_digest::<Sha384>(tbs)
        })?;
        Ok(vec![leaf, held.der.clone()])
    }

    fn chain_through_a_p384_intermediate_signing_with_sha256(held: &TestCertificate) -> anyhow::Result<Vec<String>> {
        let intermediate = held.issue_for(TestKey::p384(61)?, "CN=Intermediate", vec![ca(None)?])?;
        let leaf = intermediate.issue(62, "CN=Claimed identity", false)?;
        let leaf = re_signed(&leaf.der, ECDSA_WITH_SHA256, ECDSA_WITH_SHA256, |tbs| {
            intermediate.key.sign_ecdsa_digest::<Sha256>(tbs)
        })?;
        Ok(vec![leaf, intermediate.der, held.der.clone()])
    }

    fn chain_through_an_rsa_intermediate(held: &TestCertificate) -> anyhow::Result<Vec<String>> {
        let intermediate = held.issue_for(TestKey::rsa()?, "CN=Intermediate", vec![ca(None)?])?;
        let leaf = intermediate.issue(63, "CN=Claimed identity", false)?;
        Ok(vec![leaf.der, intermediate.der, held.der.clone()])
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[rstest::rstest]
    #[case::from_another_root(chain_from_another_root)]
    #[case::from_a_root_with_the_held_root_s_name(chain_from_a_root_with_the_held_root_s_name)]
    // oracle: spec RFC 5280 §6.1.3
    #[case::under_another_issuer_name(chain_signed_by_the_held_root_s_key_under_another_issuer_name)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[case::through_a_leaf_of_the_held_root(chain_through_a_leaf_of_the_held_root)]
    // oracle: spec RFC 5280 §6.1.4
    #[case::through_a_certificate_without_basic_constraints(chain_through_a_certificate_without_basic_constraints)]
    // oracle: spec RFC 5280 §6.1.4
    #[case::through_a_ca_without_key_cert_sign(chain_through_a_ca_without_key_cert_sign)]
    // oracle: spec RFC 5280 §6.1.4
    #[case::past_a_path_length_constraint(chain_past_a_path_length_constraint)]
    // A critical extension that the agent cannot process rejects its certificate.
    // oracle: spec RFC 5280 §4.2
    #[case::through_a_ca_with_an_unreadable_key_usage(chain_through_a_ca_with_an_unreadable_key_usage)]
    // A signature verifies only under the algorithm its certificate names, which must be the one in the signed part.
    // oracle: spec RFC 5280 §4.1.1.2
    #[case::with_a_leaf_naming_another_signature_algorithm(chain_with_a_leaf_naming_another_signature_algorithm)]
    // oracle: spec RFC 5280 §4.1.1.2
    #[case::with_a_signed_part_naming_another_signature_algorithm(
        chain_with_a_leaf_whose_signed_part_names_another_signature_algorithm
    )]
    // A P-256 key signs only with `ecdsa-with-SHA256`, and a P-384 key only with `ecdsa-with-SHA384`.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[case::with_a_p256_key_signing_with_sha384(chain_with_a_leaf_the_held_p256_root_signs_with_sha384)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[case::with_a_p384_key_signing_with_sha256(chain_through_a_p384_intermediate_signing_with_sha256)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[case::through_an_rsa_intermediate(chain_through_an_rsa_intermediate)]
    fn an_enrollment_claiming_a_held_authority_from_another_base_url_without_a_held_root_is_refused(
        #[case] claimed_chain: ChainOutsideHeldRoots,
    ) -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let root = TestCertificate::root(10, HELD_ROOT)?;
        let held = hold_identity_under(&store, &directory.0, &root)?;
        let held_file = fs::read_to_string(store.identity_path(held.authority_id))?;
        let token = token_for("https://other.test")?;
        let hash_hex = token.sha256_hex();
        let claim = enrollment_answer(&store, &directory.0, &token, held.authority_id, claimed_chain(&root)?)?;

        let outcome = store.store_enrolled_identity(&claim)?;

        assert_eq!(fs::read_to_string(store.identity_path(held.authority_id))?, held_file);
        assert_eq!(outcome, EnrolledIdentity::AuthorityConflict);
        assert!(keys::open(store.key_backend(), &held.keys.current.key_name)?.is_some());
        let marker_path = directory
            .0
            .join("identity")
            .join("rejected")
            .join(format!("{hash_hex}.json"));
        let marker: Value = serde_json::from_slice(&fs::read(marker_path)?)?;
        assert_eq!(marker["code"], "authority_conflict");
        assert!(!pending::file_path(&directory.0, &hash_hex)?.exists());
        assert!(pending::read_in_progress(&directory.0, &hash_hex)?.is_none());
        assert!(keys::open(store.key_backend(), &claim.keys.current.key_name)?.is_none());
        Ok(())
    }

    /// Stores an identity and returns it with a chain that has a signature path to one of its roots.
    type HeldAndVerifiedChain = fn(&Store, &Utf8Path) -> anyhow::Result<(StoredIdentity, Vec<String>)>;

    fn chain_from_the_held_root(store: &Store, data_dir: &Utf8Path) -> anyhow::Result<(StoredIdentity, Vec<String>)> {
        let root = TestCertificate::root(10, HELD_ROOT)?;
        let held = hold_identity_under(store, data_dir, &root)?;
        Ok((held, vec![root.issue(40, "CN=Claimed identity", false)?.der, root.der]))
    }

    fn chain_through_an_intermediate_of_the_held_root(
        store: &Store,
        data_dir: &Utf8Path,
    ) -> anyhow::Result<(StoredIdentity, Vec<String>)> {
        let root = TestCertificate::root(10, HELD_ROOT)?;
        let held = hold_identity_under(store, data_dir, &root)?;
        let intermediate = root.issue(41, "CN=Intermediate", true)?;
        let leaf = intermediate.issue(42, "CN=Claimed identity", false)?;
        Ok((held, vec![leaf.der, intermediate.der, root.der]))
    }

    fn chain_through_an_intermediate_limited_to_no_further_ca(
        store: &Store,
        data_dir: &Utf8Path,
    ) -> anyhow::Result<(StoredIdentity, Vec<String>)> {
        let root = TestCertificate::root(10, HELD_ROOT)?;
        let held = hold_identity_under(store, data_dir, &root)?;
        let extensions = vec![ca(Some(0))?, key_usage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)?];
        let intermediate = root.issue_with(47, "CN=Limited intermediate", extensions)?;
        let leaf = intermediate.issue(48, "CN=Claimed identity", false)?;
        Ok((held, vec![leaf.der, intermediate.der, root.der]))
    }

    fn chain_through_a_self_issued_ca_below_an_intermediate_limited_to_no_further_ca(
        store: &Store,
        data_dir: &Utf8Path,
    ) -> anyhow::Result<(StoredIdentity, Vec<String>)> {
        let root = TestCertificate::root(10, HELD_ROOT)?;
        let held = hold_identity_under(store, data_dir, &root)?;
        let limited = root.issue_with(53, "CN=Limited intermediate", vec![ca(Some(0))?])?;
        // Self-issued: the limited intermediate's name over a new key, as when a CA changes keys.
        let rekeyed = limited.issue(54, "CN=Limited intermediate", true)?;
        let leaf = rekeyed.issue(55, "CN=Claimed identity", false)?;
        Ok((held, vec![leaf.der, rekeyed.der, limited.der, root.der]))
    }

    fn chain_from_a_new_root_the_held_root_cross_signed(
        store: &Store,
        data_dir: &Utf8Path,
    ) -> anyhow::Result<(StoredIdentity, Vec<String>)> {
        let root = TestCertificate::root(10, HELD_ROOT)?;
        let held = hold_identity_under(store, data_dir, &root)?;
        let cross_signed = root.issue(43, "CN=New root", true)?;
        let leaf = cross_signed.issue(44, "CN=Claimed identity", false)?;
        Ok((held, vec![leaf.der, cross_signed.der]))
    }

    fn chain_from_the_root_of_the_previous_slot(
        store: &Store,
        data_dir: &Utf8Path,
    ) -> anyhow::Result<(StoredIdentity, Vec<String>)> {
        let old_root = TestCertificate::root(10, HELD_ROOT)?;
        let new_root = TestCertificate::root(12, "CN=Rotated root")?;
        let mut held = hold_identity_under(store, data_dir, &old_root)?;
        store.create_pending_key(&mut held)?;
        let renewed = new_root.issue(13, "CN=Held identity", false)?;
        store.store_pending_chain(&mut held, vec![renewed.der, new_root.der])?;
        store.promote_pending(&mut held)?;
        Ok((
            held,
            vec![old_root.issue(45, "CN=Claimed identity", false)?.der, old_root.der],
        ))
    }

    fn chain_from_the_root_of_the_pending_slot(
        store: &Store,
        data_dir: &Utf8Path,
    ) -> anyhow::Result<(StoredIdentity, Vec<String>)> {
        let root = TestCertificate::root(10, HELD_ROOT)?;
        let pending_root = TestCertificate::root(12, "CN=Rotated root")?;
        let mut held = hold_identity_under(store, data_dir, &root)?;
        store.create_pending_key(&mut held)?;
        let renewed = pending_root.issue(13, "CN=Held identity", false)?;
        store.store_pending_chain(&mut held, vec![renewed.der, pending_root.der.clone()])?;
        Ok((
            held,
            vec![
                pending_root.issue(46, "CN=Claimed identity", false)?.der,
                pending_root.der,
            ],
        ))
    }

    fn chain_through_a_p384_intermediate_of_the_held_root(
        store: &Store,
        data_dir: &Utf8Path,
    ) -> anyhow::Result<(StoredIdentity, Vec<String>)> {
        let root = TestCertificate::root(10, HELD_ROOT)?;
        let held = hold_identity_under(store, data_dir, &root)?;
        let intermediate = root.issue_for(TestKey::p384(56)?, "CN=Intermediate", vec![ca(None)?])?;
        let leaf = intermediate.issue(57, "CN=Claimed identity", false)?;
        Ok((held, vec![leaf.der, intermediate.der, root.der]))
    }

    fn chain_from_a_held_p384_root(
        store: &Store,
        data_dir: &Utf8Path,
    ) -> anyhow::Result<(StoredIdentity, Vec<String>)> {
        let root = TestCertificate::root_for(TestKey::p384(58)?, HELD_ROOT)?;
        let held = hold_identity_under(store, data_dir, &root)?;
        Ok((held, vec![root.issue(59, "CN=Claimed identity", false)?.der, root.der]))
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[rstest::rstest]
    #[case::from_the_held_root(chain_from_the_held_root)]
    #[case::through_an_intermediate(chain_through_an_intermediate_of_the_held_root)]
    // oracle: spec RFC 5280 §6.1.4
    #[case::through_an_intermediate_limited_to_no_further_ca(chain_through_an_intermediate_limited_to_no_further_ca)]
    // A pathLenConstraint counts no self-issued certificate.
    // oracle: spec RFC 5280 §6.1.4
    #[case::through_a_self_issued_ca_below_a_limited_intermediate(
        chain_through_a_self_issued_ca_below_an_intermediate_limited_to_no_further_ca
    )]
    #[case::from_a_cross_signed_new_root(chain_from_a_new_root_the_held_root_cross_signed)]
    #[case::from_the_root_of_the_previous_slot(chain_from_the_root_of_the_previous_slot)]
    #[case::from_the_root_of_the_pending_slot(chain_from_the_root_of_the_pending_slot)]
    // A P-384 key signs with `ecdsa-with-SHA384`.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[case::through_a_p384_intermediate(chain_through_a_p384_intermediate_of_the_held_root)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[case::from_a_held_p384_root(chain_from_a_held_p384_root)]
    fn an_enrollment_claiming_a_held_authority_from_another_base_url_through_a_held_root_replaces_it(
        #[case] held_and_chain: HeldAndVerifiedChain,
    ) -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let (held, chain) = held_and_chain(&store, &directory.0)?;
        let token = token_for("https://other.test")?;
        let claim = enrollment_answer(&store, &directory.0, &token, held.authority_id, chain)?;

        let outcome = store.store_enrolled_identity(&claim)?;

        assert_eq!(outcome, EnrolledIdentity::Stored);
        assert_eq!(store.read_identity(held.authority_id)?, Some(claim));
        for key in held.keys.records() {
            assert!(
                keys::open(store.key_backend(), &key.key_name)?.is_none(),
                "{}",
                key.key_name
            );
        }
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn an_enrollment_claiming_a_held_authority_from_its_base_url_replaces_it_whatever_its_chain() -> anyhow::Result<()>
    {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let root = TestCertificate::root(10, HELD_ROOT)?;
        let held = hold_identity_under(&store, &directory.0, &root)?;
        // Another secret makes another token for the same base URL.
        let token = Token::parse(&format!(
            "dvaet1.{}.{}",
            URL_SAFE_NO_PAD.encode(json!({ "u": held.base_url }).to_string()),
            URL_SAFE_NO_PAD.encode([2u8; 32])
        ))?;
        let claim = enrollment_answer(
            &store,
            &directory.0,
            &token,
            held.authority_id,
            chain_from_another_root(&root)?,
        )?;

        let outcome = store.store_enrolled_identity(&claim)?;

        assert_eq!(outcome, EnrolledIdentity::Stored);
        assert_eq!(store.read_identity(held.authority_id)?, Some(claim));
        assert!(keys::open(store.key_backend(), &held.keys.current.key_name)?.is_none());
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn an_identity_cannot_take_the_key_of_another_pending_enrollment() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let token = test_token()?;
        let other = token_for("https://other.test")?;
        for pending_token in [&token, &other] {
            pending::write(&directory.0, pending_token, true)?;
        }
        store
            .begin_enrollment(&token)?
            .context("new token was already processed")?;
        let (other_progress, _key) = store
            .begin_enrollment(&other)?
            .context("new token was already processed")?;
        let mut identity = identity_at(token.base_url());
        identity.token_sha256 = token.sha256_hex();
        identity.keys.current.key_name = other_progress.key_name.clone();

        assert!(store.write_identity(&identity).is_err());

        assert_eq!(store.read_identity(identity.authority_id)?, None);
        assert!(keys::open(store.key_backend(), &other_progress.key_name)?.is_some());
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
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
        let mut without_pending = fresh.clone();
        without_pending.keys.pending = None;
        assert!(store.replace_identity(&fresh, &without_pending).is_err());
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

    // oracle: intent crates/agent-identity/INTENT.md §Identities
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
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

    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
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

    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
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

    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
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

    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
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

    // oracle: intent crates/agent-identity/INTENT.md §Identities
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

    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
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

    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
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

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
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

    /// Who besides the agent's account a test lets into an authority directory.
    #[derive(Clone, Copy, Debug)]
    enum OtherUsers {
        /// The directory's group on Unix, and the Users group on Windows.
        Group,
        /// Every other user.
        Everyone,
    }

    fn open_to(path: &Utf8Path, others: OtherUsers) -> anyhow::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = match others {
                OtherUsers::Group => 0o750,
                OtherUsers::Everyone => 0o705,
            };
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        }
        #[cfg(windows)]
        crate::windows::grant_test_directory_access(
            path,
            match others {
                OtherUsers::Group => ::windows::Win32::Security::WinBuiltinUsersSid,
                OtherUsers::Everyone => ::windows::Win32::Security::WinWorldSid,
            },
        )?;
        Ok(())
    }

    /// Returns what the trust check reads from `path`: its owner and mode on Unix, its owner and DACL on Windows.
    #[cfg(unix)]
    fn protection(path: &Utf8Path) -> anyhow::Result<(u32, u32)> {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = fs::symlink_metadata(path)?;
        Ok((metadata.uid(), metadata.mode()))
    }

    #[cfg(windows)]
    fn protection(path: &Utf8Path) -> anyhow::Result<String> {
        crate::windows::test_security(path)
    }

    fn untrusted_path(error: &anyhow::Error) -> Option<&Utf8Path> {
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<UntrustedStoredIdentity>())
            .map(|untrusted| untrusted.path.as_path())
    }

    fn close_to_other_users(path: &Utf8Path) -> anyhow::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(windows)]
        crate::windows::set_test_directory_access(path, true)?;
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn an_authority_directory_open_to_other_users_stops_every_store_use_until_it_is_fixed() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Local state"): an authority directory that fails the check is never
        // repaired, and stops all identity processing, for every authority, until it is fixed.
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let mut trusted = enroll_locally(&store, &directory.0)?;
        let mut other = trusted.clone();
        other.authority_id = Uuid::new_v4();
        other.identity_id = Uuid::new_v4();
        other.token_sha256 = hex::encode([7u8; 32]);
        other.keys.current.key_name = keys::new_key_name("ai");
        store.write_identity(&other)?;
        let untrusted = directory.authority(other.authority_id);
        open_to(&untrusted, OtherUsers::Group)?;
        let opened = protection(&untrusted)?;
        let token = Token::parse(&format!(
            "dvaet1.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"u":"https://new.test"}"#),
            URL_SAFE_NO_PAD.encode([2u8; 32])
        ))?;
        let pending_path = pending::write(&directory.0, &token, true)?;

        for (operation, result) in [
            (
                "reading another identity",
                store.read_identity(trusted.authority_id).map(drop),
            ),
            ("listing identities", store.list_identities().map(drop)),
            ("beginning an enrollment", store.begin_enrollment(&token).map(drop)),
            (
                "updating another identity's config",
                store
                    .update_config(&mut trusted, json!({"version": 1, "revision": 8}))
                    .map(drop),
            ),
            ("reconciling", store.reconcile()),
        ] {
            let error = result
                .err()
                .with_context(|| format!("{operation} ignored an untrusted authority directory"))?;
            assert_eq!(untrusted_path(&error), Some(untrusted.as_path()), "{operation}");
        }
        assert!(pending_path.exists());
        assert!(pending::read_in_progress(&directory.0, &token.sha256_hex())?.is_none());
        assert_eq!(protection(&untrusted)?, opened);

        close_to_other_users(&untrusted)?;
        assert_eq!(store.read_identity(trusted.authority_id)?, Some(trusted));
        Ok(())
    }

    /// Opens a file to its group on Unix, and to the Users group on Windows.
    fn open_file_to_group(path: &Utf8Path) -> anyhow::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(path, fs::Permissions::from_mode(0o640))?;
        }
        #[cfg(windows)]
        crate::windows::set_test_file_access(path, &[::windows::Win32::Security::WinBuiltinUsersSid])?;
        Ok(())
    }

    fn close_file_to_other_users(path: &Utf8Path) -> anyhow::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(windows)]
        crate::windows::set_test_file_access(path, &[])?;
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn an_identity_file_open_to_other_users_stops_every_store_use_until_it_is_fixed() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let hidden = enroll_locally(&store, &directory.0)?;
        let mut trusted = hidden.clone();
        trusted.authority_id = Uuid::new_v4();
        trusted.identity_id = Uuid::new_v4();
        trusted.token_sha256 = hex::encode([7u8; 32]);
        trusted.keys.current.key_name = keys::new_key_name("ai");
        store.write_identity(&trusted)?;
        let untrusted = store.identity_path(hidden.authority_id);
        open_file_to_group(&untrusted)?;
        let opened = (protection(&untrusted)?, fs::read(&untrusted)?);
        // Read as absent, the hidden identity would let its own token enroll again.
        let token = test_token()?;
        let pending_path = pending::write(&directory.0, &token, true)?;

        for (operation, result) in [
            ("starting up", directory.store().map(drop)),
            (
                "reading another identity",
                store.read_identity(trusted.authority_id).map(drop),
            ),
            ("listing identities", store.list_identities().map(drop)),
            (
                "beginning the hidden identity's enrollment again",
                store.begin_enrollment(&token).map(drop),
            ),
            (
                "updating another identity's config",
                store
                    .update_config(&mut trusted, json!({"version": 1, "revision": 8}))
                    .map(drop),
            ),
            ("reconciling", store.reconcile()),
        ] {
            let error = result
                .err()
                .with_context(|| format!("{operation} ignored an untrusted identity file"))?;
            assert_eq!(untrusted_path(&error), Some(untrusted.as_path()), "{operation}");
        }
        assert!(pending_path.exists());
        assert!(pending::read_in_progress(&directory.0, &token.sha256_hex())?.is_none());
        assert_eq!((protection(&untrusted)?, fs::read(&untrusted)?), opened);

        close_file_to_other_users(&untrusted)?;
        assert_eq!(store.read_identity(hidden.authority_id)?, Some(hidden));
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[cfg(windows)]
    #[test]
    fn an_identity_file_closed_to_other_users_still_needs_the_dacl_the_agent_provisions() -> anyhow::Result<()> {
        if crate::windows::is_system()? {
            // For SYSTEM, the current user alone is the DACL the agent provisions.
            return Ok(());
        }
        let directory = TestDir::new()?;
        let store = directory.store()?;
        let identity = enroll_locally(&store, &directory.0)?;
        let path = store.identity_path(identity.authority_id);
        // Without SYSTEM, no other user can access the file, but the agent provisions SYSTEM too.
        crate::windows::set_test_file_access_for_current_user_only(&path)?;

        let error = store
            .read_identity(identity.authority_id)
            .err()
            .context("an identity file without the DACL the agent provisions passed the check")?;

        assert_eq!(untrusted_path(&error), Some(path.as_path()));
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn an_authority_directory_named_in_upper_case_is_checked_too() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Local state"): every authority directory is checked; on a case-insensitive
        // file system, such as Windows', an upper-case name is the same directory, and skipping it would let its token
        // enroll again.
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let identity = enroll_locally(&store, &directory.0)?;
        let canonical = directory.authority(identity.authority_id);
        open_to(&canonical, OtherUsers::Group)?;
        let upper_case = canonical.with_file_name(identity.authority_id.to_string().to_uppercase());
        fs::rename(&canonical, &upper_case)?;
        let token = test_token()?;
        pending::write(&directory.0, &token, true)?;

        let start_up = directory
            .store()
            .err()
            .context("start-up skipped an upper-case authority directory")?;
        let enrollment = store
            .begin_enrollment(&token)
            .err()
            .context("an upper-case authority directory let its token begin another enrollment")?;

        assert_eq!(untrusted_path(&start_up), Some(upper_case.as_path()));
        assert_eq!(untrusted_path(&enrollment), Some(upper_case.as_path()));
        assert!(pending::read_in_progress(&directory.0, &token.sha256_hex())?.is_none());
        Ok(())
    }

    /// What a test puts in place of an authority directory.
    #[derive(Clone, Copy, Debug)]
    enum Replacement {
        /// A link to a trusted directory elsewhere.
        Link,
        File,
    }

    fn replace_directory(path: &Utf8Path, target: &Utf8Path, replacement: Replacement) -> std::io::Result<()> {
        match replacement {
            #[cfg(unix)]
            Replacement::Link => std::os::unix::fs::symlink(target, path),
            #[cfg(windows)]
            Replacement::Link => std::os::windows::fs::symlink_dir(target, path),
            Replacement::File => fs::write(path, b""),
        }
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn a_link_or_file_in_place_of_an_authority_directory_is_never_an_absent_identity() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Local state"): an authority directory that fails the check stops all
        // identity processing; reading it as absent would let a local attacker hide an identity, so that its token
        // enrolls again.
        for replacement in [Replacement::Link, Replacement::File] {
            let directory = TestDir::new()?;
            if !directory.supports_owner_only_files()? {
                return Ok(());
            }
            let store = directory.store()?;
            let identity = enroll_locally(&store, &directory.0)?;
            let authority = directory.authority(identity.authority_id);
            let moved = directory.0.join("moved");
            fs::rename(&authority, &moved)?;
            match replace_directory(&authority, &moved, replacement) {
                // Windows creates a link only under Developer Mode or elevation.
                Err(error) if error.kind() == ErrorKind::PermissionDenied => continue,
                result => result?,
            }

            let read = store
                .read_identity(identity.authority_id)
                .err()
                .with_context(|| format!("{replacement:?} read as an absent identity"))?;
            let start_up = directory
                .store()
                .err()
                .with_context(|| format!("start-up accepted a {replacement:?}"))?;

            assert_eq!(untrusted_path(&read), Some(authority.as_path()), "{replacement:?}");
            assert_eq!(untrusted_path(&start_up), Some(authority.as_path()), "{replacement:?}");
        }
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn a_directory_in_place_of_an_identity_file_is_never_an_absent_identity() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let identity = enroll_locally(&store, &directory.0)?;
        let path = store.identity_path(identity.authority_id);
        fs::remove_file(&path)?;
        fs::create_dir(&path)?;

        let error = store
            .read_identity(identity.authority_id)
            .err()
            .context("a directory in place of identity.json read as an absent identity")?;

        assert_eq!(untrusted_path(&error), Some(path.as_path()));
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn start_up_stops_on_an_authority_directory_open_to_other_users_and_leaves_it_unchanged() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Local state"): an authority directory that is not protected from other
        // users is never repaired, and stops all identity processing until it is fixed.
        for others in [OtherUsers::Group, OtherUsers::Everyone] {
            let directory = TestDir::new()?;
            if !directory.supports_owner_only_files()? {
                return Ok(());
            }
            let identity = enroll_locally(&directory.store()?, &directory.0)?;
            let authority = directory.authority(identity.authority_id);
            open_to(&authority, others)?;
            let opened = protection(&authority)?;

            let error = directory
                .store()
                .err()
                .context("start-up accepted an authority directory open to other users")?;

            assert_eq!(untrusted_path(&error), Some(authority.as_path()), "{others:?}");
            assert_eq!(protection(&authority)?, opened, "{others:?}");
        }
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[cfg(windows)]
    #[test]
    fn start_up_stops_on_a_foreign_owned_authority_directory_and_leaves_it_unchanged() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Local state"): an authority directory owned by another account is never
        // repaired, and stops all identity processing until it is fixed.
        let directory = TestDir::new()?;
        let identity = enroll_locally(&directory.store()?, &directory.0)?;
        let authority = directory.authority(identity.authority_id);
        if crate::windows::set_test_owner(&authority, ::windows::Win32::Security::WinBuiltinAdministratorsSid).is_err()
        {
            // Only an elevated token can give the directory another owner.
            return Ok(());
        }
        let owned = protection(&authority)?;

        let error = directory
            .store()
            .err()
            .context("start-up accepted a foreign-owned authority directory")?;

        assert_eq!(untrusted_path(&error), Some(authority.as_path()));
        assert_eq!(protection(&authority)?, owned);
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[cfg(windows)]
    #[test]
    fn repairing_the_authorities_directory_leaves_an_untrusted_authority_directory_unchanged() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Local state"): start-up resets wrong permissions on the agent's own
        // directories, but never repairs an authority directory, including the entries it inherits from them.
        let directory = TestDir::new()?;
        drop(directory.store()?);
        let authorities = directory.0.join("identity").join("authorities");
        crate::windows::grant_test_directory_access(&authorities, ::windows::Win32::Security::WinBuiltinUsersSid)?;
        let authority = directory.authority(Uuid::new_v4());
        fs::create_dir(&authority)?;
        let inherited = protection(&authority)?;

        let error = directory
            .store()
            .err()
            .context("start-up accepted an authority directory with inherited access")?;

        assert_eq!(untrusted_path(&error), Some(authority.as_path()));
        assert_eq!(protection(&authority)?, inherited);
        Ok(())
    }
}
