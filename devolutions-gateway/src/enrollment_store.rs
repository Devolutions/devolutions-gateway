use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use base64::Engine as _;
use camino::Utf8PathBuf;
use parking_lot::RwLock;
use rand::RngCore as _;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::get_data_dir;

const ENROLLMENT_TOKEN_STORE_FILE_NAME: &str = "wireguard-enrollment-tokens.json";
const CONSUMED_TOKEN_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentTokenRecord {
    pub token_id: Uuid,
    pub token_hash: String,
    pub requested_name: Option<String>,
    pub expires_at_unix: u64,
    pub consumed_at_unix: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct EnrollmentTokenIssue {
    pub token: String,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct EnrollmentTokenClaims {
    pub token_id: Uuid,
    pub requested_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EnrollmentTokenStore {
    path: Utf8PathBuf,
    records: Arc<RwLock<BTreeMap<Uuid, EnrollmentTokenRecord>>>,
}

impl EnrollmentTokenStore {
    pub fn load_default() -> anyhow::Result<Self> {
        Self::load(get_data_dir().join(ENROLLMENT_TOKEN_STORE_FILE_NAME))
    }

    pub fn load(path: Utf8PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent))?;
        }

        let records = if path.exists() {
            let file = File::open(&path).with_context(|| format!("failed to open {}", path))?;
            let reader = BufReader::new(file);
            let records = serde_json::from_reader::<_, Vec<EnrollmentTokenRecord>>(reader)
                .with_context(|| format!("failed to deserialize {}", path))?;
            records.into_iter().map(|record| (record.token_id, record)).collect()
        } else {
            BTreeMap::new()
        };

        Ok(Self {
            path,
            records: Arc::new(RwLock::new(records)),
        })
    }

    pub fn issue_token(
        &self,
        requested_name: Option<String>,
        lifetime: Duration,
    ) -> anyhow::Result<EnrollmentTokenIssue> {
        let token_id = Uuid::new_v4();
        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_bytes);
        let token = format!("{token_id}.{secret}");
        let expires_at_unix = now_unix() + lifetime.as_secs();
        let record = EnrollmentTokenRecord {
            token_id,
            token_hash: sha256_hex(&token),
            requested_name,
            expires_at_unix,
            consumed_at_unix: None,
        };

        {
            let mut records = self.records.write();
            prune_stale_records(&mut records);
            records.insert(token_id, record);
            persist_records(&self.path, &records)?;
        }

        Ok(EnrollmentTokenIssue { token, expires_at_unix })
    }

    pub fn validate_and_consume_token(&self, token: &str) -> anyhow::Result<EnrollmentTokenClaims> {
        let (token_id, _) = split_token(token)?;
        let mut records = self.records.write();
        prune_stale_records(&mut records);

        let claims = {
            let record = records
                .get_mut(&token_id)
                .with_context(|| format!("unknown enrollment token {}", token_id))?;

            anyhow::ensure!(record.token_hash == sha256_hex(token), "invalid enrollment token");
            anyhow::ensure!(record.consumed_at_unix.is_none(), "enrollment token already consumed");
            anyhow::ensure!(record.expires_at_unix > now_unix(), "enrollment token expired");

            record.consumed_at_unix = Some(now_unix());

            EnrollmentTokenClaims {
                token_id,
                requested_name: record.requested_name.clone(),
            }
        };

        if let Err(error) = persist_records(&self.path, &records) {
            if let Some(record) = records.get_mut(&token_id) {
                record.consumed_at_unix = None;
            }

            return Err(error);
        }

        Ok(claims)
    }

    pub fn restore_token(&self, token_id: Uuid) -> anyhow::Result<()> {
        let mut records = self.records.write();
        let previous_consumed_at = {
            let record = records
                .get_mut(&token_id)
                .with_context(|| format!("unknown enrollment token {}", token_id))?;
            let previous_consumed_at = record.consumed_at_unix;
            record.consumed_at_unix = None;
            previous_consumed_at
        };

        if let Err(error) = persist_records(&self.path, &records) {
            if let Some(record) = records.get_mut(&token_id) {
                record.consumed_at_unix = previous_consumed_at;
            }

            return Err(error);
        }

        Ok(())
    }
}

fn split_token(token: &str) -> anyhow::Result<(Uuid, &str)> {
    let (token_id, secret) = token.split_once('.').context("invalid enrollment token format")?;

    let token_id = token_id.parse().context("invalid enrollment token id")?;
    anyhow::ensure!(!secret.is_empty(), "invalid enrollment token secret");

    Ok((token_id, secret))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_secs()
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(digest)
}

fn prune_stale_records(records: &mut BTreeMap<Uuid, EnrollmentTokenRecord>) {
    let now = now_unix();
    records.retain(|_, record| {
        let expired = record.expires_at_unix <= now;
        let consumed_and_old = record
            .consumed_at_unix
            .is_some_and(|consumed_at| consumed_at + CONSUMED_TOKEN_RETENTION.as_secs() <= now);

        !(expired || consumed_and_old)
    });
}

fn persist_records(path: &Utf8PathBuf, records: &BTreeMap<Uuid, EnrollmentTokenRecord>) -> anyhow::Result<()> {
    let snapshot = records.values().cloned().collect::<Vec<_>>();
    let file = File::create(path).with_context(|| format!("failed to create {}", path))?;
    let mut writer = BufWriter::new(&file);
    serde_json::to_writer_pretty(&mut writer, &snapshot).with_context(|| format!("failed to serialize {}", path))?;
    std::io::Write::flush(&mut writer).with_context(|| format!("failed to flush {}", path))?;
    file.sync_all().with_context(|| format!("failed to sync {}", path))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store_path(file_name: &str) -> Utf8PathBuf {
        let unique = Uuid::new_v4();
        let path = std::env::temp_dir().join(format!("dgw-enrollment-store-{unique}-{file_name}"));
        Utf8PathBuf::from_path_buf(path).expect("temp path should be utf-8")
    }

    #[test]
    fn issued_token_validates_and_can_be_consumed() {
        let store = EnrollmentTokenStore::load(temp_store_path("issue.json")).expect("store should load");
        let issued = store
            .issue_token(Some("branch-a".to_owned()), Duration::from_secs(300))
            .expect("token should issue");

        let claims = store
            .validate_and_consume_token(&issued.token)
            .expect("token should validate");
        assert_eq!(claims.requested_name.as_deref(), Some("branch-a"));
        assert!(store.validate_and_consume_token(&issued.token).is_err());
    }

    #[test]
    fn restore_token_makes_consumed_token_usable_again() {
        let store = EnrollmentTokenStore::load(temp_store_path("restore.json")).expect("store should load");
        let issued = store
            .issue_token(Some("branch-b".to_owned()), Duration::from_secs(300))
            .expect("token should issue");

        let claims = store
            .validate_and_consume_token(&issued.token)
            .expect("token should validate");
        store.restore_token(claims.token_id).expect("restore should succeed");

        assert!(store.validate_and_consume_token(&issued.token).is_ok());
    }
}
