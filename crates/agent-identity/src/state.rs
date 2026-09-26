use std::collections::HashSet;
use std::fs;
use std::io::{ErrorKind, Read as _};

use agent_identity_keys::{self as keys, IdentityKey, KeyBackend, KeyOptions};
use anyhow::{Context as _, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use uuid::{Uuid, Variant};

use crate::token::Token;
use crate::{pending, private_file, rejected, state_lock};

const MAX_IDENTITY_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredIdentity {
    pub version: u8,
    pub authority_id: Uuid,
    pub device_id: Uuid,
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
    DeviceRevoked,
    TokenInvalid,
    TokenExhausted,
    TokenExpired,
    TokenMalformed,
}

impl EnrollmentDiscardReason {
    fn code(self) -> &'static str {
        match self {
            Self::DeviceRevoked => "device_revoked",
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
    key_options: KeyOptions,
}

impl Store {
    pub fn new(
        data_dir: Utf8PathBuf,
        backend: KeyBackend,
        key_prefix: String,
        key_options: KeyOptions,
    ) -> anyhow::Result<Self> {
        ensure!(
            (1..=96).contains(&key_prefix.len())
                && key_prefix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "invalid key name prefix"
        );
        match &backend {
            KeyBackend::File { dir } => {
                ensure!(
                    *dir == data_dir.join("identity").join("keys"),
                    "invalid device key directory"
                );
            }
            #[cfg(windows)]
            KeyBackend::KeyStore => {}
        }
        {
            let _lock = state_lock::acquire(&data_dir, key_options.acl_grant_current_user)?;
            private_file::protect_authority_directories(&data_dir, key_options.acl_grant_current_user)?;
        }
        Ok(Self {
            data_dir,
            backend,
            key_prefix,
            key_options,
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
            self.key_options.acl_grant_current_user,
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
                private_file::check_owned_directory(&path, self.key_options.acl_grant_current_user)?,
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
        let _lock = state_lock::acquire(&self.data_dir, self.key_options.acl_grant_current_user)?;
        self.write_identity_locked(None, identity)
    }

    /// Replaces an identity only while the expected snapshot is still current.
    pub fn replace_identity(&self, previous: &StoredIdentity, identity: &StoredIdentity) -> anyhow::Result<()> {
        let _lock = state_lock::acquire(&self.data_dir, self.key_options.acl_grant_current_user)?;
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
            && (existing.device_id == identity.device_id || existing.token_sha256 == identity.token_sha256)
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
            self.key_options.acl_grant_current_user,
        )
    }

    pub fn update_config(&self, identity: &mut StoredIdentity, config: Value) -> anyhow::Result<bool> {
        let _lock = state_lock::acquire(&self.data_dir, self.key_options.acl_grant_current_user)?;
        let latest = self
            .read_identity(identity.authority_id)?
            .context("stored identity is missing")?;
        ensure!(
            latest.device_id == identity.device_id && latest.token_sha256 == identity.token_sha256,
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
    pub fn create_pending_key(&self, identity: &mut StoredIdentity) -> anyhow::Result<Box<dyn IdentityKey>> {
        ensure!(identity.keys.pending.is_none(), "identity already has a pending key");
        let name = keys::new_key_name(&self.key_prefix);
        let previous = identity.clone();
        let mut updated = previous.clone();
        updated.keys.pending = Some(KeyRecord {
            key_name: name.clone(),
            certificate_chain: None,
        });
        let _lock = state_lock::acquire(&self.data_dir, self.key_options.acl_grant_current_user)?;
        self.write_identity_locked(Some(&previous), &updated)?;
        *identity = updated;
        keys::generate(&self.backend, &name, &self.key_options)
    }

    pub fn remove_pending_key(&self, identity: &mut StoredIdentity) -> anyhow::Result<()> {
        if identity.keys.pending.is_some() {
            let previous = identity.clone();
            let mut updated = previous.clone();
            updated.keys.pending = None;
            let _lock = state_lock::acquire(&self.data_dir, self.key_options.acl_grant_current_user)?;
            self.write_identity_locked(Some(&previous), &updated)?;
            *identity = updated;
        }
        Ok(())
    }

    pub fn remove_previous_key(&self, identity: &mut StoredIdentity) -> anyhow::Result<()> {
        if identity.keys.previous.is_some() {
            let previous = identity.clone();
            let mut updated = previous.clone();
            updated.keys.previous = None;
            let _lock = state_lock::acquire(&self.data_dir, self.key_options.acl_grant_current_user)?;
            self.write_identity_locked(Some(&previous), &updated)?;
            *identity = updated;
        }
        Ok(())
    }

    pub fn remove_identity(&self, identity: &StoredIdentity) -> anyhow::Result<()> {
        let _lock = state_lock::acquire(&self.data_dir, self.key_options.acl_grant_current_user)?;
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
    pub fn begin_enrollment(
        &self,
        token: &Token,
    ) -> anyhow::Result<Option<(pending::InProgress, Box<dyn IdentityKey>)>> {
        let _lock = state_lock::acquire(&self.data_dir, self.key_options.acl_grant_current_user)?;
        let hash_hex = token.sha256_hex();
        if rejected::is_rejected(&self.data_dir, &hash_hex)?
            || self
                .list_identities()?
                .iter()
                .any(|identity| identity.token_sha256 == token.sha256_base64url())
        {
            self.discard_pending_state_locked(&hash_hex)?;
            return Ok(None);
        }
        let path = pending::file_path(&self.data_dir, &hash_hex)?;
        let pending::PendingRead::Ready(current) = pending::read(&path, self.key_options.acl_grant_current_user)?
        else {
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
                    token_sha256: token.sha256_base64url(),
                    key_name: keys::new_key_name(&self.key_prefix),
                };
                pending::write_in_progress(
                    &self.data_dir,
                    &hash_hex,
                    &record,
                    self.key_options.acl_grant_current_user,
                )?;
                record
            }
        };
        self.validate_key_name(&record.key_name)?;
        let key = match keys::open(&self.backend, &record.key_name)? {
            Some(key) => key,
            None => keys::generate(&self.backend, &record.key_name, &self.key_options)?,
        };
        Ok(Some((record, key)))
    }

    /// Persists a permanent-outcome marker before deleting the token, key, and in-progress record.
    /// For a token rejected by local parsing, hash its raw text with [`crate::token::sha256_hex`].
    pub fn discard_enrollment(&self, hash_hex: &str, reason: EnrollmentDiscardReason) -> anyhow::Result<()> {
        let _lock = state_lock::acquire(&self.data_dir, self.key_options.acl_grant_current_user)?;
        rejected::mark_rejected(
            &self.data_dir,
            hash_hex,
            reason.code(),
            self.key_options.acl_grant_current_user,
        )?;
        self.discard_pending_state_locked(hash_hex)
    }

    fn discard_pending_state_locked(&self, hash_hex: &str) -> anyhow::Result<()> {
        pending::remove_file(&self.data_dir, hash_hex, self.key_options.acl_grant_current_user)?;
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

    /// Rechecks a malformed payload under the lock before marking it and deleting its pending state.
    pub fn discard_pending_file(&self, path: &Utf8Path) -> anyhow::Result<()> {
        let _lock = state_lock::acquire(&self.data_dir, self.key_options.acl_grant_current_user)?;
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
        // The writer may have replaced the file since the caller classified it.
        let malformed = match pending::read(path, self.key_options.acl_grant_current_user) {
            Ok(pending::PendingRead::Malformed(malformed)) => malformed,
            Ok(pending::PendingRead::Ready(_)) => return Ok(()),
            Err(error) if is_not_found(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        rejected::mark_rejected(
            &self.data_dir,
            malformed.rejection_hash_hex(),
            EnrollmentDiscardReason::TokenMalformed.code(),
            self.key_options.acl_grant_current_user,
        )?;
        if let Ok(expected) = pending::file_path(&self.data_dir, hash_hex)
            && expected == path
        {
            self.discard_pending_state_locked(hash_hex)
        } else {
            private_file::remove_pending_file(path, self.key_options.acl_grant_current_user)
        }
    }

    /// Removes a completed enrollment's pending state only after its key belongs to the saved identity.
    pub fn finish_enrollment(&self, hash_hex: &str, authority_id: Uuid) -> anyhow::Result<()> {
        let _lock = state_lock::acquire(&self.data_dir, self.key_options.acl_grant_current_user)?;
        self.finish_enrollment_locked(hash_hex, authority_id)
    }

    fn finish_enrollment_locked(&self, hash_hex: &str, authority_id: Uuid) -> anyhow::Result<()> {
        let identity = self
            .read_identity(authority_id)?
            .context("stored enrollment identity is missing")?;
        ensure!(
            identity.token_sha256 == pending_hash_base64url(hash_hex)?,
            "stored identity belongs to a different enrollment"
        );
        let record = pending::read_in_progress(&self.data_dir, hash_hex)?;
        if let Some(record) = &record {
            ensure!(
                identity.keys.current.key_name == record.key_name,
                "enrollment key does not belong to stored identity"
            );
        }
        pending::remove_file(&self.data_dir, hash_hex, self.key_options.acl_grant_current_user)?;
        if record.is_some() {
            pending::remove_in_progress(&self.data_dir, hash_hex)?;
        }
        Ok(())
    }

    /// Repairs missing unissued keys and drops keys no longer covered by a durable record.
    pub fn reconcile(&self) -> anyhow::Result<()> {
        let _lock = state_lock::acquire(&self.data_dir, self.key_options.acl_grant_current_user)?;
        private_file::cleanup_temporary_files(
            &pending::directory(&self.data_dir),
            pending::is_owned_temporary_stem,
            |path, stem| {
                if stem.ends_with(".dat") {
                    // An interrupted add-only submission can leave an administrator-owned staging file.
                    private_file::remove_pending_file(path, self.key_options.acl_grant_current_user)
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
                    if private_file::check_owned_directory(&path, self.key_options.acl_grant_current_user)? {
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
            if keys::open(&self.backend, &identity.keys.current.key_name)?.is_none() {
                self.remove_identity_locked(&identity)?;
                continue;
            }
            if let Some(pending) = &identity.keys.pending
                && keys::open(&self.backend, &pending.key_name)?.is_none()
            {
                if pending.certificate_chain.is_none() {
                    keys::generate(&self.backend, &pending.key_name, &self.key_options)?;
                } else {
                    let previous = identity.clone();
                    identity.keys.pending = None;
                    self.write_identity_locked(Some(&previous), &identity)?;
                }
            }
            if let Some(previous) = &identity.keys.previous
                && keys::open(&self.backend, &previous.key_name)?.is_none()
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
            let pending_file_is_missing = match pending::read(&path, self.key_options.acl_grant_current_user) {
                Ok(pending::PendingRead::Ready(_)) => false,
                Ok(pending::PendingRead::Malformed(_)) => {
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
                keys::generate(&self.backend, &record.key_name, &self.key_options)?;
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
            URL_SAFE_NO_PAD
                .decode(&identity.token_sha256)
                .is_ok_and(|bytes| bytes.len() == 32),
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
        let suffix = name
            .strip_prefix(&self.key_prefix)
            .context("key has wrong name prefix")?;
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

fn pending_hash_base64url(hex: &str) -> anyhow::Result<String> {
    ensure!(
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid pending enrollment hash"
    );
    Ok(URL_SAFE_NO_PAD.encode(hex::decode(hex)?))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    use super::*;

    struct TestDir(Utf8PathBuf);

    impl TestDir {
        fn new() -> anyhow::Result<Self> {
            let path = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("state-tests")
                .join(Uuid::new_v4().to_string());
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
            Store::new(
                self.0.clone(),
                Store::file_backend(&self.0),
                "AI-".into(),
                KeyOptions {
                    acl_grant_current_user: true,
                },
            )
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
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
            device_id: Uuid::new_v4(),
            base_url: token.base_url().clone(),
            config: json!({"version": 1, "revision": 7}),
            token_sha256: token.sha256_base64url(),
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
            "device_id": "28a70de9-724e-4ffb-8e8d-09f56971765d",
            "base_url": "https://example.test/dvls",
            "config": {"version": 1, "revision": 7, "future": {"nested": [1, null, true]}},
            "token_sha256": URL_SAFE_NO_PAD.encode([1u8; 32]),
            "rejected": null,
            "keys": {
                "current": {
                    "key_name": keys::new_key_name(keys::DEFAULT_KEY_NAME_PREFIX),
                    "certificate_chain": ["YWJj"]
                },
                "pending": {
                    "key_name": keys::new_key_name(keys::DEFAULT_KEY_NAME_PREFIX),
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
        store.discard_enrollment(&hash_hex, EnrollmentDiscardReason::DeviceRevoked)?;
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
        assert_eq!(serde_json::from_str::<Value>(&marker)?["code"], "device_revoked");
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
    fn malformed_pending_payload_creates_a_token_malformed_marker() -> anyhow::Result<()> {
        let directory = TestDir::new()?;
        if !directory.supports_owner_only_files()? {
            return Ok(());
        }
        let store = directory.store()?;
        let token = test_token()?;
        let hash_hex = token.sha256_hex();
        let path = pending::write(&directory.0, &token, true)?;
        let malformed = serde_json::to_vec(&json!({"version": 2, "token": token.as_str()}))?;
        #[cfg(windows)]
        let contents = crate::windows::protect(&malformed)?;
        #[cfg(not(windows))]
        let contents = malformed;
        private_file::write_atomic(&directory.0, &path, &contents, true)?;
        let pending::PendingRead::Malformed(malformed) = pending::read(&path, true)? else {
            anyhow::bail!("wrong pending version was accepted")
        };
        assert_eq!(malformed.rejection_hash_hex(), hash_hex);
        store.discard_pending_file(&path)?;
        assert!(!path.exists());
        let marker_path = directory
            .0
            .join("identity")
            .join("rejected")
            .join(format!("{hash_hex}.json"));
        let marker: Value = serde_json::from_slice(&fs::read(marker_path)?)?;
        assert_eq!(marker["code"], "token_malformed");
        assert_eq!(marker["token_sha256"], token.sha256_base64url());
        pending::write(&directory.0, &token, true)?;
        assert!(store.begin_enrollment(&token)?.is_none());
        assert!(!path.exists());

        let other = Token::parse(&format!(
            "dvaet1.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"u":"https://other.test"}"#),
            "A".repeat(43)
        ))?;
        let other_path = pending::write(&directory.0, &other, true)?;
        let raw = br#"{"version":1,"token":null}"#;
        let raw_hash = hex::encode(Sha256::digest(raw));
        #[cfg(windows)]
        let contents = crate::windows::protect(raw)?;
        #[cfg(not(windows))]
        let contents = raw.to_vec();
        private_file::write_atomic(&directory.0, &other_path, &contents, true)?;
        let pending::PendingRead::Malformed(malformed) = pending::read(&other_path, true)? else {
            anyhow::bail!("non-string pending token was accepted")
        };
        assert_eq!(malformed.rejection_hash_hex(), raw_hash);
        store.discard_pending_file(&other_path)?;
        assert!(!other_path.exists());
        let marker_path = directory
            .0
            .join("identity")
            .join("rejected")
            .join(format!("{raw_hash}.json"));
        let marker: Value = serde_json::from_slice(&fs::read(marker_path)?)?;
        assert_eq!(marker["token_sha256"], URL_SAFE_NO_PAD.encode(Sha256::digest(raw)));
        assert_eq!(marker["code"], "token_malformed");
        Ok(())
    }

    #[test]
    fn malformed_read_cannot_discard_a_rewritten_valid_pending_token() -> anyhow::Result<()> {
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
        let pending::PendingRead::Malformed(_) = pending::read(&path, true)? else {
            anyhow::bail!("wrong pending version was accepted")
        };
        pending::write(&directory.0, &token, true)?;

        store.discard_pending_file(&path)?;
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
    fn wrong_filename_marks_the_token_not_the_payload() -> anyhow::Result<()> {
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
        let contents = payload.clone();
        private_file::write_atomic(&directory.0, &path, &contents, true)?;
        let pending::PendingRead::Malformed(malformed) = pending::read(&path, true)? else {
            anyhow::bail!("wrong-filename pending token was accepted")
        };
        assert_eq!(malformed.rejection_hash_hex(), token.sha256_hex());
        store.discard_pending_file(&path)?;
        assert!(!path.exists());
        let marker = directory
            .0
            .join("identity")
            .join("rejected")
            .join(format!("{}.json", token.sha256_hex()));
        assert!(marker.exists());
        assert!(
            !directory
                .0
                .join("identity")
                .join("rejected")
                .join(format!("{}.json", hex::encode(Sha256::digest(&payload))))
                .exists()
        );
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
                "token_sha256": token.sha256_base64url(),
                "code": "device_revoked",
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

        let fake_key_name = keys::new_key_name("AI-");
        let record_path = pending::in_progress_path(&directory.0, &hash)?;
        fs::write(
            &record_path,
            serde_json::to_vec(&pending::InProgress {
                version: 1,
                token_sha256: token.sha256_base64url(),
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
            device_id: Uuid::new_v4(),
            base_url: token.base_url().clone(),
            config: json!({"version": 1, "revision": 1}),
            token_sha256: token.sha256_base64url(),
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
            assert_eq!(marker["token_sha256"], token.sha256_base64url());
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
}
