mod crypto;

#[rustfmt::skip]
pub use crypto::EncryptedPassword;

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use parking_lot::Mutex;
use secrecy::ExposeSecret as _;
use serde::{Deserialize as _, de};
use uuid::Uuid;

use self::crypto::MASTER_KEY;

/// Error returned by [`CredentialStoreHandle::insert`].
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
    pub fn decrypt_password(&self) -> anyhow::Result<(String, secrecy::SecretString)> {
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
    /// Real KDC for Kerberos-enforced injection, provisioned alongside the credentials.
    ///
    /// The Gateway's target-side CredSSP leg uses this to obtain a real Kerberos ticket; realm is
    /// derived from the target credential, so only the address is stored. `None` for NTLM targets.
    pub krb_kdc: Option<crate::target_addr::TargetAddr>,
}

/// Cleartext credential received from the API, used for deserialization only.
///
/// Passwords are encrypted and stored as [`AppCredential`] inside the credential store.
/// This type is never stored directly — hand it to [`CredentialStoreHandle::insert`].
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
pub struct CleartextAppCredentialMapping {
    #[serde(rename = "proxy_credential")]
    pub proxy: CleartextAppCredential,
    #[serde(rename = "target_credential")]
    pub target: CleartextAppCredential,
    /// Real KDC for Kerberos-enforced injection, provisioned in the same call as the credentials.
    /// Optional: absent for NTLM targets.
    #[serde(default, deserialize_with = "deserialize_optional_kdc_addr")]
    pub krb_kdc: Option<crate::target_addr::TargetAddr>,
}

fn deserialize_optional_kdc_addr<'de, D>(deserializer: D) -> Result<Option<crate::target_addr::TargetAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let krb_kdc = Option::<crate::target_addr::TargetAddr>::deserialize(deserializer)?;

    if let Some(krb_kdc) = &krb_kdc {
        match krb_kdc.scheme() {
            "tcp" | "udp" => {}
            unsupported => return Err(de::Error::custom(format!("unsupported KDC protocol: {unsupported}"))),
        }
    }

    Ok(krb_kdc)
}

impl CleartextAppCredentialMapping {
    fn encrypt(self) -> anyhow::Result<AppCredentialMapping> {
        Ok(AppCredentialMapping {
            proxy: self.proxy.encrypt()?,
            target: self.target.encrypt()?,
            krb_kdc: self.krb_kdc,
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
        mapping: Option<CleartextAppCredentialMapping>,
        time_to_live: time::Duration,
    ) -> Result<Option<ArcCredentialEntry>, InsertError> {
        let mapping = mapping
            .map(CleartextAppCredentialMapping::encrypt)
            .transpose()
            .map_err(InsertError::Internal)?;
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
    ) -> Result<Option<ArcCredentialEntry>, InsertError> {
        let jti = crate::token::extract_jti(&token)
            .context("failed to extract token ID")
            .map_err(InsertError::InvalidToken)?;

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

#[cfg(test)]
mod tests {
    use super::CleartextAppCredentialMapping;

    const CREDENTIAL_MAPPING: &str = r#"
        {
            "proxy_credential": {
                "kind": "username-password",
                "username": "proxy",
                "password": "proxy-password"
            },
            "target_credential": {
                "kind": "username-password",
                "username": "target",
                "password": "target-password"
            }
        }
    "#;

    #[test]
    fn credential_mapping_accepts_supported_kdc_protocols() {
        for krb_kdc in ["tcp://dc.example.com:88", "udp://dc.example.com:88"] {
            let mapping = CREDENTIAL_MAPPING.replace(
                "\n        }\n    ",
                &format!(",\n            \"krb_kdc\": \"{krb_kdc}\"\n        }}\n    "),
            );

            let mapping: CleartextAppCredentialMapping =
                serde_json::from_str(&mapping).expect("supported KDC protocol should deserialize");

            assert_eq!(
                mapping.krb_kdc.expect("KDC address should be present").as_str(),
                krb_kdc
            );
        }
    }

    #[test]
    fn credential_mapping_allows_missing_kdc() {
        let mapping: CleartextAppCredentialMapping =
            serde_json::from_str(CREDENTIAL_MAPPING).expect("credential mapping without KDC should deserialize");

        assert!(mapping.krb_kdc.is_none());
    }

    #[test]
    fn credential_mapping_rejects_unsupported_kdc_protocol() {
        let mapping = CREDENTIAL_MAPPING.replace(
            "\n        }\n    ",
            ",\n            \"krb_kdc\": \"http://dc.example.com:88\"\n        }\n    ",
        );

        let error = serde_json::from_str::<CleartextAppCredentialMapping>(&mapping)
            .expect_err("unsupported KDC protocol should be rejected");

        assert!(error.to_string().contains("unsupported KDC protocol: http"));
    }
}
