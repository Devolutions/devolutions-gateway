use core::fmt;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use parking_lot::Mutex;
use serde::{de, ser};
use uuid::Uuid;

/// Credential at the application protocol level
#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
pub enum AppCredential {
    #[serde(rename = "username-password")]
    UsernamePassword {
        username: String,
        domain: Option<String>,
        password: Password,
    },
}

/// Application protocol level credential mapping
#[derive(Debug, Deserialize)]
pub struct AppCredentialMapping {
    #[serde(rename = "proxy_credential")]
    pub proxy: AppCredential,
    #[serde(rename = "target_credential")]
    pub target: AppCredential,
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

#[derive(PartialEq, Eq, Clone, zeroize::Zeroize)]
pub struct Password(String);

impl Password {
    /// Do not copy the return value without wrapping into some "Zeroize"able structure
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Password {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for Password {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Password").finish_non_exhaustive()
    }
}

impl<'de> de::Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;

        impl de::Visitor<'_> for V {
            type Value = Password;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Password(v))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Password(v.to_owned()))
            }
        }

        let password = deserializer.deserialize_string(V)?;

        Ok(password)
    }
}

impl ser::Serialize for Password {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
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
