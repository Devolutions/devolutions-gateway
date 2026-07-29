use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use parking_lot::Mutex;
use uuid::Uuid;

use crate::credential::{AppCredentials, CleartextAppCredentials};
use crate::target_connection_options::TargetConnectionOptions;

/// A combined, point-in-time view of everything provisioned for a session, assembled on read from
/// the two independent stores.
///
/// Credentials are always present; connection options are optional and may be absent — never
/// provisioned, or expired before the credentials half.
#[derive(Debug, Clone)]
pub(crate) struct ProvisionedConnection {
    pub(crate) credentials: AppCredentials,
    pub(crate) connection_options: Option<TargetConnectionOptions>,
    pub(crate) target_hostname: String,
}

#[derive(Debug, Clone)]
struct CredentialsEntry {
    credentials: AppCredentials,
    target_hostname: String,
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
/// in, so entries only ever hold encrypted material and the master key never leaves the credential
/// module's dependency graph. The connection-options store holds plaintext routing metadata only
/// and has no crypto dependency at all — keeping the two apart is what preserves that property.
///
/// Both are keyed by the association-token JTI, but the two halves are provisioned by separate
/// preflight operations and may arrive, expire, or be replaced independently.
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

    pub(crate) fn insert_credentials(
        &self,
        token_data: crate::token::CredentialInjectionTokenData,
        credentials: CleartextAppCredentials,
        time_to_live: time::Duration,
    ) -> anyhow::Result<bool> {
        let credentials = credentials.encrypt().context("encrypt provisioned credentials")?;
        let entry = CredentialsEntry {
            credentials,
            target_hostname: token_data.target_hostname,
            expires_at: time::OffsetDateTime::now_utc() + time_to_live,
        };

        Ok(self.credentials.lock().insert(token_data.jti, entry).is_some())
    }

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
    /// Returns `None` unless the credentials half is present and live; folds in the connection-options
    /// half when it too is present. Entries live until their TTL, not until first use: a jti names a
    /// session, and the token layer allows several connections per session (reconnects), each of which
    /// needs the same materials. Either half is treated as absent once expired; the cleanup task
    /// reclaims them.
    pub(crate) fn get(&self, jti: Uuid) -> Option<ProvisionedConnection> {
        let now = time::OffsetDateTime::now_utc();

        let (credentials, target_hostname) = {
            let entries = self.credentials.lock();
            let entry = entries.get(&jti)?;
            if now >= entry.expires_at {
                warn!(%jti, "Provisioned credentials expired before the connection arrived");
                return None;
            }
            (entry.credentials.clone(), entry.target_hostname.clone())
        };

        let connection_options = self.get_live_connection_options(jti, now);

        Some(ProvisionedConnection {
            credentials,
            connection_options,
            target_hostname,
        })
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

    pub fn cleanup_task(&self) -> impl Task<Output = anyhow::Result<()>> + 'static + use<> {
        CleanupTask {
            credentials: Arc::clone(&self.credentials),
            connection_options: Arc::clone(&self.connection_options),
        }
    }
}

struct CleanupTask {
    credentials: Arc<Mutex<HashMap<Uuid, CredentialsEntry>>>,
    connection_options: Arc<Mutex<HashMap<Uuid, ConnectionOptionsEntry>>>,
}

#[async_trait]
impl Task for CleanupTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "provisioning cleanup";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        cleanup_task(self.credentials, self.connection_options, shutdown_signal).await;
        Ok(())
    }
}

#[instrument(skip_all)]
async fn cleanup_task(
    credentials: Arc<Mutex<HashMap<Uuid, CredentialsEntry>>>,
    connection_options: Arc<Mutex<HashMap<Uuid, ConnectionOptionsEntry>>>,
    mut shutdown_signal: ShutdownSignal,
) {
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
        credentials.lock().retain(|_, entry| now < entry.expires_at);
        connection_options.lock().retain(|_, entry| now < entry.expires_at);
    }

    debug!("Task terminated");
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use uuid::Uuid;

    use super::*;
    use crate::credential::CleartextAppCredential;
    use crate::token::CredentialInjectionTokenData;

    fn credentials() -> CleartextAppCredentials {
        CleartextAppCredentials {
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

    fn token_data(jti: Uuid) -> CredentialInjectionTokenData {
        CredentialInjectionTokenData {
            jti,
            target_hostname: "target.example".to_owned(),
        }
    }

    #[test]
    fn get_returns_a_live_entry() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        store
            .insert_credentials(token_data(jti), credentials(), time::Duration::minutes(5))
            .expect("entry inserts");
        assert_eq!(store.get(jti).expect("live entry").target_hostname, "target.example");
    }

    #[test]
    fn get_treats_an_expired_entry_as_absent() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        store
            .insert_credentials(token_data(jti), credentials(), time::Duration::seconds(-1))
            .expect("entry inserts");
        assert!(store.get(jti).is_none(), "an expired entry must read as absent");
    }
}
