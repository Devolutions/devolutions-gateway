mod crypto;

#[rustfmt::skip]
pub use crypto::EncryptedPassword;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use parking_lot::Mutex;
use secrecy::{ExposeSecret as _, SecretString};
use uuid::Uuid;

use self::crypto::MASTER_KEY;

/// Credential at the application protocol level
#[derive(Debug, Clone)]
pub enum AppCredential {
    UsernamePassword {
        username: String,
        password: EncryptedPassword,
    },
}

impl AppCredential {
    pub(crate) fn username(&self) -> &str {
        match self {
            AppCredential::UsernamePassword { username, password: _ } => username,
        }
    }

    /// Decrypt the password using the global master key.
    ///
    /// Returns the username and a short-lived decrypted password that zeroizes on drop.
    pub fn decrypt_password(&self) -> anyhow::Result<(String, SecretString)> {
        match self {
            AppCredential::UsernamePassword { username, password } => {
                let decrypted = MASTER_KEY.lock().decrypt(password)?;
                Ok((username.clone(), decrypted))
            }
        }
    }
}

/// Application protocol level credential mapping
#[derive(Debug, Clone)]
pub struct AppCredentialMapping {
    pub proxy: AppCredential,
    pub target: AppCredential,
}

/// Cleartext credential received from the API, used for deserialization only.
///
/// Passwords are encrypted and stored as [`AppCredential`] inside the credential store.
/// This type is never stored directly — hand it to [`CredentialStoreHandle::insert`].
#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
pub(crate) enum CleartextAppCredential {
    #[serde(rename = "username-password")]
    UsernamePassword { username: String, password: SecretString },
}

impl CleartextAppCredential {
    fn encrypt(self) -> anyhow::Result<AppCredential> {
        match self {
            CleartextAppCredential::UsernamePassword { username, password } => {
                let encrypted = MASTER_KEY.lock().encrypt(password.expose_secret())?;
                Ok(AppCredential::UsernamePassword {
                    username,
                    password: encrypted,
                })
            }
        }
    }
}

/// Cleartext credential mapping received from the API, used for deserialization only.
///
/// Passwords are encrypted on write. Hand this directly to [`CredentialStoreHandle::insert`].
#[derive(Debug, Deserialize)]
pub(crate) struct CleartextAppCredentialMapping {
    #[serde(rename = "proxy_credential")]
    pub(crate) proxy: CleartextAppCredential,
    #[serde(rename = "target_credential")]
    pub(crate) target: CleartextAppCredential,
}

impl CleartextAppCredentialMapping {
    pub(crate) fn encrypt(self) -> anyhow::Result<AppCredentialMapping> {
        Ok(AppCredentialMapping {
            proxy: self.proxy.encrypt()?,
            target: self.target.encrypt()?,
        })
    }

    /// Expose the proxy-side username without dropping ownership of the rest of the mapping.
    ///
    /// Used by the preflight layer to derive per-session Kerberos material before the mapping
    /// is moved into the credential store. The password is not exposed.
    pub(crate) fn proxy_username(&self) -> &str {
        match &self.proxy {
            CleartextAppCredential::UsernamePassword { username, password: _ } => username,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CredentialStoreHandle(Arc<Mutex<CredentialStore>>);

impl Default for CredentialStoreHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStoreHandle {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(CredentialStore::new())))
    }

    /// Insert a credential entry for the association token whose JTI is `jti`.
    ///
    /// The caller is responsible for extracting `jti` from a token whose signature has already
    /// been validated upstream. `injection` carries the optional `provision-credentials` payload:
    /// the cleartext mapping and the parsed RDP target hostname. The store has no other
    /// dependency on the token's JWT shape.
    pub(crate) fn insert(
        &self,
        jti: Uuid,
        token: String,
        injection: Option<(CleartextAppCredentialMapping, String)>,
        time_to_live: time::Duration,
    ) -> anyhow::Result<Option<ArcCredentialEntry>> {
        let injection = injection
            .map(|(mapping, target_hostname)| -> anyhow::Result<InjectionState> {
                Ok(InjectionState {
                    mapping: mapping.encrypt()?,
                    target_hostname,
                })
            })
            .transpose()?;
        Ok(self.0.lock().insert(jti, token, injection, time_to_live))
    }

    pub(crate) fn get(&self, jti: Uuid) -> Option<ArcCredentialEntry> {
        self.0.lock().get(jti)
    }
}

#[derive(Debug)]
struct CredentialStore {
    entries: HashMap<Uuid, ArcCredentialEntry>,
}

#[derive(Debug)]
pub(crate) struct CredentialEntry {
    /// The association token's JTI. Doubles as the credential-store key and as the value the
    /// matching KDC token's `jet_cred_id` claim points back to.
    pub(crate) jti: Uuid,
    pub(crate) token: String,
    pub(crate) expires_at: time::OffsetDateTime,
    /// Credential-injection state for this entry, set when (and only when) the entry was
    /// provisioned via `provision-credentials`. Plain `provision-token` entries leave this `None`
    /// and are inert from the routing layer's perspective. Grouping the three correlated fields
    /// into one option captures the "all set or all unset" invariant in the type system.
    pub(crate) injection: Option<InjectionState>,
}

#[derive(Debug)]
pub(crate) struct InjectionState {
    pub(crate) mapping: AppCredentialMapping,
    /// Hostname of the target RDP server, parsed from the association token's `dst_hst` claim
    /// at preflight. Fake-KDC validates client TGS-REQ sname against `TERMSRV/<target_hostname>`;
    /// without it the SPN check would silently fall back to Gateway's own hostname, so the
    /// preflight handler rejects `provision-credentials` requests with missing/malformed `dst_hst`
    /// or with alternate targets (`dst_alt`) until credential injection supports target failover.
    pub(crate) target_hostname: String,
}

pub(crate) type ArcCredentialEntry = Arc<CredentialEntry>;

impl CredentialStore {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn insert(
        &mut self,
        jti: Uuid,
        token: String,
        injection: Option<InjectionState>,
        time_to_live: time::Duration,
    ) -> Option<ArcCredentialEntry> {
        let entry = CredentialEntry {
            jti,
            token,
            expires_at: time::OffsetDateTime::now_utc() + time_to_live,
            injection,
        };

        self.entries.insert(jti, Arc::new(entry))
    }

    fn get(&self, jti: Uuid) -> Option<ArcCredentialEntry> {
        // Filter expired entries at lookup. The 15-minute cleanup task is best-effort;
        // without this filter an expired entry remains usable until the next sweep, which
        // makes `time_to_live` a soft hint rather than a hard limit.
        self.entries
            .get(&jti)
            .filter(|entry| time::OffsetDateTime::now_utc() < entry.expires_at)
            .map(Arc::clone)
    }
}

pub struct CleanupTask {
    pub handle: CredentialStoreHandle,
}

#[async_trait]
impl Task for CleanupTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "credential store cleanup";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        cleanup_task(self.handle, shutdown_signal).await;
        Ok(())
    }
}

#[instrument(skip_all)]
async fn cleanup_task(handle: CredentialStoreHandle, mut shutdown_signal: ShutdownSignal) {
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

#[cfg(test)]
mod tests;
