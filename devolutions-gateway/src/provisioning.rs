use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use parking_lot::Mutex;
use uuid::Uuid;

use crate::credential::{AppCredentialMapping, CleartextAppCredentialMapping};
use crate::target_connection_options::TargetConnectionOptions;

/// Error returned by [`ProvisioningStore::insert`].
#[derive(Debug)]
pub enum InsertError {
    /// The provided token is invalid (e.g., missing or malformed JTI).
    ///
    /// This is a client-side error: the caller supplied bad input.
    InvalidToken(anyhow::Error),
    /// An internal error occurred (e.g., encryption failure).
    Internal(anyhow::Error),
}

impl fmt::Display for InsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidToken(e) => e.fmt(f),
            Self::Internal(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for InsertError {}

/// Data provisioned ahead of a connection, keyed by association-token JTI.
///
/// Credentials are the encryption boundary: cleartext material is encrypted on the way in, so
/// entries only ever hold encrypted passwords.
#[derive(Debug, Clone)]
pub struct ProvisioningStore(Arc<Mutex<ProvisioningEntries>>);

impl Default for ProvisioningStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvisioningStore {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(ProvisioningEntries::new())))
    }

    pub(crate) fn insert(
        &self,
        token: String,
        mapping: Option<CleartextAppCredentialMapping>,
        connection_options: Option<TargetConnectionOptions>,
        time_to_live: time::Duration,
    ) -> Result<Option<ArcProvisioningEntry>, InsertError> {
        let mapping = mapping
            .map(CleartextAppCredentialMapping::encrypt)
            .transpose()
            .map_err(InsertError::Internal)?;
        self.0.lock().insert(token, mapping, connection_options, time_to_live)
    }

    pub(crate) fn get(&self, token_id: Uuid) -> Option<ArcProvisioningEntry> {
        self.0.lock().get(token_id)
    }
}

#[derive(Debug)]
struct ProvisioningEntries {
    entries: HashMap<Uuid, ArcProvisioningEntry>,
}

#[derive(Debug)]
pub struct ProvisioningEntry {
    pub(crate) token: String,
    pub(crate) mapping: Option<AppCredentialMapping>,
    pub(crate) connection_options: Option<TargetConnectionOptions>,
    pub(crate) expires_at: time::OffsetDateTime,
}

pub type ArcProvisioningEntry = Arc<ProvisioningEntry>;

impl ProvisioningEntries {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn insert(
        &mut self,
        token: String,
        mapping: Option<AppCredentialMapping>,
        connection_options: Option<TargetConnectionOptions>,
        time_to_live: time::Duration,
    ) -> Result<Option<ArcProvisioningEntry>, InsertError> {
        let jti = crate::token::extract_jti(&token)
            .context("failed to extract token ID")
            .map_err(InsertError::InvalidToken)?;

        let entry = ProvisioningEntry {
            token,
            mapping,
            connection_options,
            expires_at: time::OffsetDateTime::now_utc() + time_to_live,
        };

        let previous_entry = self.entries.insert(jti, Arc::new(entry));

        Ok(previous_entry)
    }

    fn get(&self, token_id: Uuid) -> Option<ArcProvisioningEntry> {
        self.entries.get(&token_id).map(Arc::clone)
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

    const TASK_INTERVAL: Duration = Duration::from_secs(60 * 15); // 15 minutes

    debug!("Task started");

    loop {
        tokio::select! {
            _ = sleep(TASK_INTERVAL) => {}
            _ = shutdown_signal.wait() => {
                break;
            }
        }

        let now = time::OffsetDateTime::now_utc();

        handle.0.lock().entries.retain(|_, src| now < src.expires_at);
    }

    debug!("Task terminated");
}
