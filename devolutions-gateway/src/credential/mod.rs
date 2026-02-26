mod crypto;

#[rustfmt::skip]
pub use crypto::{DecryptedPassword, EncryptedPassword};

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use parking_lot::Mutex;
use secrecy::ExposeSecret as _;
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
    /// Decrypt the password using the global master key.
    ///
    /// Returns the username and a short-lived decrypted password that zeroizes on drop.
    pub fn decrypt_password(&self) -> anyhow::Result<(String, DecryptedPassword)> {
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

/// Cleartext credential wrapper used only for deserialization.
///
/// This type is converted to `AppCredential` (with encrypted password) immediately after deserialization.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
pub enum CleartextAppCredential {
    #[serde(rename = "username-password")]
    UsernamePassword {
        username: String,
        password: secrecy::SecretString,
    },
}

impl CleartextAppCredential {
    /// Encrypt the password and convert to storage-ready `AppCredential`.
    pub fn encrypt(self) -> anyhow::Result<AppCredential> {
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

/// Cleartext credential mapping wrapper used only for deserialization.
///
/// This type is converted to `AppCredentialMapping` (with encrypted passwords) immediately after deserialization.
#[derive(Debug, Deserialize)]
pub struct CleartextAppCredentialMapping {
    #[serde(rename = "proxy_credential")]
    pub proxy: CleartextAppCredential,
    #[serde(rename = "target_credential")]
    pub target: CleartextAppCredential,
}

impl CleartextAppCredentialMapping {
    /// Encrypt passwords and convert to storage-ready `AppCredentialMapping`.
    pub fn encrypt(self) -> anyhow::Result<AppCredentialMapping> {
        Ok(AppCredentialMapping {
            proxy: self.proxy.encrypt()?,
            target: self.target.encrypt()?,
        })
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

    pub fn insert(
        &self,
        token: String,
        mapping: Option<AppCredentialMapping>,
        time_to_live: time::Duration,
    ) -> anyhow::Result<Option<ArcCredentialEntry>> {
        self.0.lock().insert(token, mapping, time_to_live)
    }

    pub fn get(&self, token_id: Uuid) -> Option<ArcCredentialEntry> {
        self.0.lock().get(token_id)
    }
}

#[derive(Debug)]
struct CredentialStore {
    entries: HashMap<Uuid, ArcCredentialEntry>,
}

#[derive(Debug)]
pub struct CredentialEntry {
    pub token: String,
    pub mapping: Option<AppCredentialMapping>,
    pub expires_at: time::OffsetDateTime,
}

pub type ArcCredentialEntry = Arc<CredentialEntry>;

impl CredentialStore {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn insert(
        &mut self,
        token: String,
        mapping: Option<AppCredentialMapping>,
        time_to_live: time::Duration,
    ) -> anyhow::Result<Option<ArcCredentialEntry>> {
        let jti = crate::token::extract_jti(&token).context("failed to extract token ID")?;

        let entry = CredentialEntry {
            token,
            mapping,
            expires_at: time::OffsetDateTime::now_utc() + time_to_live,
        };

        let previous_entry = self.entries.insert(jti, Arc::new(entry));

        Ok(previous_entry)
    }

    fn get(&self, token_id: Uuid) -> Option<ArcCredentialEntry> {
        self.entries.get(&token_id).map(Arc::clone)
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
