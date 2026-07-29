use std::collections::HashMap;
use std::sync::{Arc, Weak};

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use parking_lot::Mutex;
use uuid::Uuid;

use crate::credential::{AppCredentialMapping, CleartextAppCredentialMapping};

#[derive(Debug)]
pub(crate) struct ProvisioningEntry {
    pub(crate) mapping: Option<AppCredentialMapping>,
}

#[derive(Debug)]
pub(crate) struct ProvisioningRecord {
    pub(crate) token: String,
    pub(crate) value: ProvisioningEntry,
    pub(crate) expires_at: time::OffsetDateTime,
}

pub(crate) type ArcProvisioningEntry = Arc<ProvisioningRecord>;
pub(crate) type WeakProvisioningEntry = Weak<ProvisioningRecord>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum InsertError {
    #[error("invalid token")]
    InvalidToken(#[source] anyhow::Error),
    #[error("credential encryption failed")]
    Internal(#[source] anyhow::Error),
}

/// Stores credentials and target options provisioned for a session, keyed by association-token JTI.
///
/// This is the credential boundary: cleartext mappings are encrypted on the way in, so the stored
/// records only ever hold encrypted material and the master key never leaves this module's
/// dependency graph.
#[derive(Debug, Clone)]
pub struct ProvisioningStore {
    entries: Arc<Mutex<HashMap<Uuid, ArcProvisioningEntry>>>,
}

impl Default for ProvisioningStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvisioningStore {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn insert(
        &self,
        token: String,
        mapping: Option<CleartextAppCredentialMapping>,
        time_to_live: time::Duration,
    ) -> Result<Option<ArcProvisioningEntry>, InsertError> {
        let jti = crate::token::extract_jti(&token)
            .context("failed to extract token ID")
            .map_err(InsertError::InvalidToken)?;
        let mapping = mapping
            .map(CleartextAppCredentialMapping::encrypt)
            .transpose()
            .map_err(InsertError::Internal)?;
        let record = ProvisioningRecord {
            token,
            value: ProvisioningEntry { mapping },
            expires_at: time::OffsetDateTime::now_utc() + time_to_live,
        };

        Ok(self.entries.lock().insert(jti, Arc::new(record)))
    }

    /// Look up a provisioned record by its token JTI.
    ///
    /// This may return a record that is already past its `expires_at`: eviction is asynchronous
    /// (see [`ProvisioningStore::cleanup_task`]), so a caller that cares about freshness must check
    /// `expires_at` itself.
    pub(crate) fn get(&self, jti: Uuid) -> Option<ArcProvisioningEntry> {
        self.entries.lock().get(&jti).map(Arc::clone)
    }

    fn remove_expired(&self, now: time::OffsetDateTime) {
        self.entries.lock().retain(|_, entry| now < entry.expires_at);
    }

    pub fn cleanup_task(&self) -> impl Task<Output = anyhow::Result<()>> + 'static + use<> {
        CleanupTask { store: self.clone() }
    }
}

struct CleanupTask {
    store: ProvisioningStore,
}

#[async_trait]
impl Task for CleanupTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "provisioning cleanup";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        cleanup_task(self.store, shutdown_signal).await;
        Ok(())
    }
}

#[instrument(skip_all)]
async fn cleanup_task(store: ProvisioningStore, mut shutdown_signal: ShutdownSignal) {
    use tokio::time::{Duration, sleep};

    const TASK_INTERVAL: Duration = Duration::from_secs(60 * 15);

    debug!("Task started");

    loop {
        tokio::select! {
            _ = sleep(TASK_INTERVAL) => {}
            _ = shutdown_signal.wait() => {
                break;
            }
        }

        store.remove_expired(time::OffsetDateTime::now_utc());
    }

    debug!("Task terminated");
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

    fn token(jti: Uuid) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = engine.encode(r#"{"alg":"RS256"}"#);
        let payload = engine
            .encode(serde_json::to_vec(&serde_json::json!({ "jti": jti })).expect("token payload should serialize"));
        let signature = engine.encode(b"signature");
        format!("{header}.{payload}.{signature}")
    }

    #[test]
    fn indexes_records_by_token_jti() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();

        let previous = store
            .insert(token(jti), None, time::Duration::minutes(5))
            .expect("record inserts");

        assert!(previous.is_none());
        assert!(store.get(jti).is_some(), "record must be indexed by its JTI");
    }

    #[test]
    fn removes_expired_records() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        store
            .insert(token(jti), None, time::Duration::seconds(-1))
            .expect("record inserts");

        store.remove_expired(time::OffsetDateTime::now_utc());

        assert!(store.get(jti).is_none());
    }
}
