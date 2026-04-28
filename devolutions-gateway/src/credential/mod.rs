mod crypto;

#[rustfmt::skip]
pub use crypto::EncryptedPassword;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::aead::rand_core::RngCore as _;
use devolutions_gateway_task::{ShutdownSignal, Task};
use parking_lot::Mutex;
use secrecy::ExposeSecret as _;
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
}

impl CleartextAppCredentialMapping {
    fn encrypt_with_kerberos(self, cred_injection_id: Uuid) -> anyhow::Result<(AppCredentialMapping, SessionKerberos)> {
        let CleartextAppCredentialMapping { proxy, target } = self;

        let proxy_username = match &proxy {
            CleartextAppCredential::UsernamePassword { username, password: _ } => username.clone(),
        };

        let kerberos = SessionKerberos {
            krbtgt_key: random_32_bytes(),
            service_long_term_key: random_32_bytes(),
            service_user_name: "jet".to_owned(),
            service_user_password: hex::encode(random_32_bytes()),
            realm: realm_from_username(&proxy_username).unwrap_or_else(|| synthetic_realm(cred_injection_id)),
        };

        Ok((
            AppCredentialMapping {
                proxy: proxy.encrypt()?,
                target: target.encrypt()?,
            },
            kerberos,
        ))
    }
}

#[derive(Debug)]
pub struct SessionKerberos {
    pub krbtgt_key: Vec<u8>,
    pub service_long_term_key: Vec<u8>,
    pub service_user_name: String,
    pub service_user_password: String,
    pub realm: String,
}

pub fn build_session_kdc_config(
    kerberos: &SessionKerberos,
    mapping: &AppCredentialMapping,
    realm: &str,
) -> anyhow::Result<kdc::config::KerberosServer> {
    let (proxy_user_name, proxy_password) = mapping.proxy.decrypt_password()?;
    let proxy_user_name = principal_for_realm(&proxy_user_name, realm);
    let service_user_name = principal_for_realm(&kerberos.service_user_name, realm);

    Ok(kdc::config::KerberosServer {
        realm: realm.to_owned(),
        users: vec![
            kdc::config::DomainUser {
                username: proxy_user_name.clone(),
                password: proxy_password.expose_secret().to_owned(),
                salt: kerberos_salt(realm, &proxy_user_name),
            },
            kdc::config::DomainUser {
                username: service_user_name.clone(),
                password: kerberos.service_user_password.clone(),
                salt: kerberos_salt(realm, &service_user_name),
            },
        ],
        max_time_skew: 300,
        krbtgt_key: kerberos.krbtgt_key.clone(),
        ticket_decryption_key: Some(kerberos.service_long_term_key.clone()),
        service_user: Some(kdc::config::DomainUser {
            username: service_user_name.clone(),
            password: kerberos.service_user_password.clone(),
            salt: kerberos_salt(realm, &service_user_name),
        }),
    })
}

fn principal_for_realm(user_name: &str, realm: &str) -> String {
    if user_name.contains('@') {
        user_name.to_owned()
    } else {
        format!("{user_name}@{realm}")
    }
}

fn kerberos_salt(realm: &str, principal: &str) -> String {
    let local_name = principal.split('@').next().unwrap_or(principal);
    format!("{}{local_name}", realm.to_ascii_uppercase())
}

fn realm_from_username(user_name: &str) -> Option<String> {
    user_name
        .split_once('@')
        .map(|(_, realm)| realm)
        .filter(|realm| !realm.is_empty())
        .map(str::to_owned)
}

fn synthetic_realm(cred_injection_id: Uuid) -> String {
    format!("CRED-{}.INVALID", cred_injection_id.simple()).to_ascii_uppercase()
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
        cred_injection_id: Option<Uuid>,
        time_to_live: time::Duration,
    ) -> Result<(Uuid, Option<ArcCredentialEntry>), InsertError> {
        let cred_injection_id = cred_injection_id.unwrap_or_else(Uuid::new_v4);
        let mapping_and_kerberos = mapping
            .map(|mapping| mapping.encrypt_with_kerberos(cred_injection_id))
            .transpose()
            .map_err(InsertError::Internal)?;
        self.0
            .lock()
            .insert(token, mapping_and_kerberos, cred_injection_id, time_to_live)
    }

    pub fn get(&self, cred_injection_id: Uuid) -> Option<ArcCredentialEntry> {
        self.0.lock().get(cred_injection_id)
    }

    pub fn get_by_token(&self, token: &str) -> Option<ArcCredentialEntry> {
        self.0.lock().get_by_token(token)
    }
}

#[derive(Debug)]
struct CredentialStore {
    entries: HashMap<Uuid, ArcCredentialEntry>,
    association_token_index: HashMap<Uuid, Uuid>,
}

#[derive(Debug)]
pub struct CredentialEntry {
    pub cred_injection_id: Uuid,
    pub association_token_jti: Uuid,
    pub token: String,
    pub mapping: Option<AppCredentialMapping>,
    pub expires_at: time::OffsetDateTime,
    pub kerberos: Option<Arc<SessionKerberos>>,
    /// Hostname of the target RDP server, parsed from the association token's `dst_hst` claim.
    /// Fake-KDC validates client TGS-REQ sname against `TERMSRV/<target_hostname>`.
    pub target_hostname: Option<String>,
}

pub type ArcCredentialEntry = Arc<CredentialEntry>;

impl CredentialStore {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            association_token_index: HashMap::new(),
        }
    }

    fn insert(
        &mut self,
        token: String,
        mapping_and_kerberos: Option<(AppCredentialMapping, SessionKerberos)>,
        cred_injection_id: Uuid,
        time_to_live: time::Duration,
    ) -> Result<(Uuid, Option<ArcCredentialEntry>), InsertError> {
        let jti = crate::token::extract_jti(&token)
            .context("failed to extract token ID")
            .map_err(InsertError::InvalidToken)?;

        // Best-effort target hostname for fake-KDC sname validation; missing/malformed dst_hst is
        // not fatal at insert time (only TGS-REQ paths need it, and they fail loudly downstream
        // with a clear error rather than silently masking the SPN as Gateway's own hostname).
        //
        // We default to RDP's port 3389 because credential injection only fires for RDP today
        // (see `GenericClient::serve` and `rd_clean_path::handle`). A bare hostname or
        // `host:port` form is therefore valid; matches how the association-token deserializer
        // resolves `dst_hst` (token.rs `parse_target_address` for jmux / association claims).
        const DEFAULT_DST_PORT: u16 = 3389;
        let target_hostname = crate::token::extract_dst_hst(&token)
            .ok()
            .flatten()
            .and_then(|raw| crate::target_addr::TargetAddr::parse(&raw, DEFAULT_DST_PORT).ok())
            .map(|addr| addr.host().to_owned());

        let (mapping, kerberos) = match mapping_and_kerberos {
            Some((mapping, kerberos)) => (Some(mapping), Some(Arc::new(kerberos))),
            None => (None, None),
        };

        let entry = CredentialEntry {
            cred_injection_id,
            association_token_jti: jti,
            token,
            mapping,
            expires_at: time::OffsetDateTime::now_utc() + time_to_live,
            kerberos,
            target_hostname,
        };

        let previous_by_id = self.entries.insert(cred_injection_id, Arc::new(entry));

        if let Some(previous) = &previous_by_id
            && previous.association_token_jti != jti
            && self
                .association_token_index
                .get(&previous.association_token_jti)
                .is_some_and(|id| *id == cred_injection_id)
        {
            self.association_token_index.remove(&previous.association_token_jti);
        }

        let previous_by_token = self
            .association_token_index
            .insert(jti, cred_injection_id)
            .and_then(|old_id| {
                if old_id == cred_injection_id {
                    None
                } else {
                    self.entries.remove(&old_id)
                }
            });

        Ok((cred_injection_id, previous_by_id.or(previous_by_token)))
    }

    fn get(&self, cred_injection_id: Uuid) -> Option<ArcCredentialEntry> {
        self.entries.get(&cred_injection_id).map(Arc::clone)
    }

    fn get_by_token(&self, token: &str) -> Option<ArcCredentialEntry> {
        crate::token::extract_jti(token)
            .ok()
            .and_then(|jti| self.association_token_index.get(&jti))
            .and_then(|cred_injection_id| self.entries.get(cred_injection_id))
            .map(Arc::clone)
    }
}

fn random_32_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
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

        let mut store = handle.0.lock();
        store.entries.retain(|_, src| now < src.expires_at);
        let live_entries = store.entries.keys().copied().collect::<HashSet<_>>();
        store
            .association_token_index
            .retain(|_, cred_injection_id| live_entries.contains(cred_injection_id));
    }

    debug!("Task terminated");
}

#[cfg(test)]
mod tests;
