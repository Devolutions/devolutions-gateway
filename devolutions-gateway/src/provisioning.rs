use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use parking_lot::Mutex;
use tracing::{debug, instrument, warn};
use uuid::Uuid;

use crate::credential::{AppCredentialMapping, CleartextAppCredentialMapping};
use crate::target_connection_options::TargetConnectionOptions;

/// Error returned when inserting provisioned credentials.
#[derive(Debug)]
pub enum InsertError {
    /// The provided token is invalid (e.g., missing or malformed JTI).
    InvalidToken(anyhow::Error),
    /// Credential encryption failed.
    CredentialEncryption(anyhow::Error),
}

impl fmt::Display for InsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidToken(e) => e.fmt(f),
            Self::CredentialEncryption(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for InsertError {}

/// Combined, point-in-time view of everything provisioned for a session.
///
/// Assembled on read from the two independent stores. Credentials are always present when this
/// value exists; connection options are optional (never provisioned, or expired first).
#[derive(Debug)]
pub struct ProvisioningEntry {
    pub(crate) token: String,
    pub(crate) mapping: AppCredentialMapping,
    pub(crate) connection_options: Option<TargetConnectionOptions>,
}

pub type ArcProvisioningEntry = Arc<ProvisioningEntry>;

#[derive(Debug, Clone)]
struct CredentialsEntry {
    token: String,
    mapping: AppCredentialMapping,
    expires_at: time::OffsetDateTime,
}

#[derive(Debug, Clone)]
struct ConnectionOptionsEntry {
    connection_options: TargetConnectionOptions,
    expires_at: time::OffsetDateTime,
}

/// Two independent token-keyed stores that together provision a session.
///
/// The credentials store is the encryption boundary: cleartext mappings are encrypted on the way
/// in, so entries only ever hold encrypted material. The connection-options store holds plaintext
/// routing metadata only and has no crypto dependency — keeping the two apart preserves that
/// property.
///
/// Both are keyed by the association-token JTI. The halves are provisioned by separate preflight
/// operations and may arrive, expire, or be replaced independently.
#[derive(Debug, Clone)]
pub struct ProvisioningStore {
    credentials: Arc<Mutex<HashMap<Uuid, CredentialsEntry>>>,
    connection_options: Arc<Mutex<HashMap<Uuid, ConnectionOptionsEntry>>>,
}

impl Default for ProvisioningStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvisioningStore {
    pub fn new() -> Self {
        Self {
            credentials: Arc::new(Mutex::new(HashMap::new())),
            connection_options: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Insert or replace the credentials half. Returns whether a prior entry was replaced.
    pub(crate) fn insert_credentials(
        &self,
        token: String,
        mapping: CleartextAppCredentialMapping,
        time_to_live: time::Duration,
    ) -> Result<bool, InsertError> {
        let jti = crate::token::extract_jti(&token)
            .context("failed to extract token ID")
            .map_err(InsertError::InvalidToken)?;
        let mapping = mapping
            .encrypt()
            .context("encrypt provisioned credentials")
            .map_err(InsertError::CredentialEncryption)?;

        let entry = CredentialsEntry {
            token,
            mapping,
            expires_at: time::OffsetDateTime::now_utc() + time_to_live,
        };

        Ok(self.credentials.lock().insert(jti, entry).is_some())
    }

    /// Insert or replace the connection-options half. Returns whether a prior entry was replaced.
    pub(crate) fn insert_connection_options(
        &self,
        jti: Uuid,
        connection_options: TargetConnectionOptions,
        time_to_live: time::Duration,
    ) -> bool {
        let entry = ConnectionOptionsEntry {
            connection_options,
            expires_at: time::OffsetDateTime::now_utc() + time_to_live,
        };

        self.connection_options.lock().insert(jti, entry).is_some()
    }

    /// Assemble the provisioned view for a session.
    ///
    /// Returns `None` unless the credentials half is present and live. Folds in connection options
    /// when that half is also present and live. Entries live until TTL, not until first use.
    pub(crate) fn get(&self, jti: Uuid) -> Option<ArcProvisioningEntry> {
        let now = time::OffsetDateTime::now_utc();

        let (token, mapping) = {
            let entries = self.credentials.lock();
            let entry = entries.get(&jti)?;
            if now >= entry.expires_at {
                warn!(%jti, "Provisioned credentials expired before the connection arrived");
                return None;
            }
            (entry.token.clone(), entry.mapping.clone())
        };

        let connection_options = self.get_live_connection_options(jti, now);

        Some(Arc::new(ProvisioningEntry {
            token,
            mapping,
            connection_options,
        }))
    }

    fn get_live_connection_options(&self, jti: Uuid, now: time::OffsetDateTime) -> Option<TargetConnectionOptions> {
        let entries = self.connection_options.lock();
        let entry = entries.get(&jti)?;
        if now >= entry.expires_at {
            warn!(%jti, "Provisioned connection options expired before the connection arrived");
            return None;
        }
        Some(entry.connection_options.clone())
    }
}

pub struct CleanupTask {
    pub handle: ProvisioningStore,
}

#[async_trait]
impl Task for CleanupTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "provisioning store cleanup";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        cleanup_task(self.handle, shutdown_signal).await;
        Ok(())
    }
}

#[instrument(skip_all)]
async fn cleanup_task(handle: ProvisioningStore, mut shutdown_signal: ShutdownSignal) {
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

        let now = time::OffsetDateTime::now_utc();
        handle.credentials.lock().retain(|_, entry| now < entry.expires_at);
        handle
            .connection_options
            .lock()
            .retain(|_, entry| now < entry.expires_at);
    }

    debug!("Task terminated");
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use uuid::Uuid;

    use super::*;
    use crate::credential::CleartextAppCredential;

    fn mapping() -> CleartextAppCredentialMapping {
        CleartextAppCredentialMapping {
            proxy: CleartextAppCredential::UsernamePassword {
                username: "proxy".to_owned(),
                password: SecretString::from("pwd"),
            },
            target: CleartextAppCredential::UsernamePassword {
                username: "target".to_owned(),
                password: SecretString::from("pwd"),
            },
        }
    }

    fn association_token(jti: Uuid) -> String {
        use base64::Engine as _;
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = engine.encode(r#"{"alg":"RS256"}"#);
        let payload = engine.encode(
            serde_json::to_vec(&serde_json::json!({
                "jti": jti,
                "dst_hst": "target.example:3389"
            }))
            .expect("payload serializes"),
        );
        let signature = engine.encode(b"signature");
        format!("{header}.{payload}.{signature}")
    }

    fn options() -> TargetConnectionOptions {
        serde_json::from_value(serde_json::json!({ "krb_kdc": "tcp://dc.example:88" })).expect("options")
    }

    #[test]
    fn get_returns_live_credentials_without_options() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        store
            .insert_credentials(association_token(jti), mapping(), time::Duration::minutes(5))
            .expect("insert");
        let entry = store.get(jti).expect("live entry");
        assert!(entry.connection_options.is_none());
    }

    #[test]
    fn get_folds_in_live_connection_options() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        store
            .insert_credentials(association_token(jti), mapping(), time::Duration::minutes(5))
            .expect("insert credentials");
        assert!(!store.insert_connection_options(jti, options(), time::Duration::minutes(5)));
        let entry = store.get(jti).expect("live entry");
        assert!(entry.connection_options.is_some());
    }

    #[test]
    fn get_treats_expired_credentials_as_absent() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        store
            .insert_credentials(association_token(jti), mapping(), time::Duration::seconds(-1))
            .expect("insert");
        assert!(store.get(jti).is_none());
    }

    #[test]
    fn credentials_and_options_replace_independently() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        assert!(!store
            .insert_credentials(association_token(jti), mapping(), time::Duration::minutes(5))
            .expect("insert"));
        assert!(store
            .insert_credentials(association_token(jti), mapping(), time::Duration::minutes(5))
            .expect("replace"));

        assert!(!store.insert_connection_options(jti, options(), time::Duration::minutes(5)));
        assert!(store.insert_connection_options(jti, options(), time::Duration::minutes(5)));
    }
}
