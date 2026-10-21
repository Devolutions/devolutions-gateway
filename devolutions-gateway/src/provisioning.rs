use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use parking_lot::Mutex;
use tokio::sync::Notify;
use tracing::{debug, instrument, warn};
use uuid::Uuid;

use crate::credential::{AppCredentialMapping, CleartextAppCredentialMapping};
use crate::target_connection_options::TargetConnectionOptions;

/// Error returned when inserting into the credentials half of the provisioning store.
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
/// Assembled on read from the two independent stores. The credentials half may be token-only
/// (`mapping` is `None`, as with `provision-token`) or carry a credential mapping
/// (`provision-credentials`). Connection options are optional and may be absent.
#[derive(Debug)]
pub struct ProvisioningEntry {
    pub(crate) token: String,
    pub(crate) mapping: Option<AppCredentialMapping>,
    pub(crate) connection_options: Option<TargetConnectionOptions>,
    pub(crate) generation: u64,
    pub(crate) kdc_expires_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Clone)]
struct CredentialsEntry {
    token: String,
    mapping: Option<AppCredentialMapping>,
    expires_at: time::OffsetDateTime,
    required_until: Option<time::OffsetDateTime>,
    generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MappingStatus {
    Available,
    Absent,
}

#[derive(Debug, Clone)]
struct ConnectionOptionsEntry {
    connection_options: TargetConnectionOptions,
    expires_at: time::OffsetDateTime,
}

/// Two independent token-keyed stores that together provision a session.
///
/// The credentials store is the encryption boundary: cleartext mappings are encrypted on the way
/// in, so entries only ever hold encrypted material. Token-only rows (`mapping = None`) match the
/// existing `provision-token` behavior on master. The connection-options store holds plaintext
/// routing metadata only and has no crypto dependency.
///
/// Both are keyed by the association-token JTI. The halves are provisioned by separate preflight
/// operations and may arrive, expire, or be replaced independently.
#[derive(Debug, Clone)]
pub struct ProvisioningStore {
    credentials: Arc<Mutex<HashMap<Uuid, CredentialsEntry>>>,
    connection_options: Arc<Mutex<HashMap<Uuid, ConnectionOptionsEntry>>>,
    cleanup_notify: Arc<Notify>,
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
            cleanup_notify: Arc::new(Notify::new()),
        }
    }

    /// Insert or replace the credentials half (token-only or with a mapping).
    ///
    /// `provision-token` passes `mapping = None`; `provision-credentials` passes `Some(mapping)`.
    ///
    /// For mapped rows, `time_to_live` is the staging wait for first checkout.
    /// The first successful [`Self::get_mapping`] then keeps the mapping until the token acceptance
    /// deadline.
    pub(crate) fn insert_credentials(
        &self,
        token: String,
        mapping: Option<CleartextAppCredentialMapping>,
        time_to_live: time::Duration,
    ) -> Result<bool, InsertError> {
        let jti = crate::token::extract_jti(&token)
            .context("failed to extract token ID")
            .map_err(InsertError::InvalidToken)?;
        let now = time::OffsetDateTime::now_utc();
        let staging_expires = now + time_to_live;
        let required_until = if mapping.is_some() {
            let exp = crate::token::extract_exp(&token)
                .context("failed to extract token expiration")
                .map_err(InsertError::InvalidToken)?;
            Some(
                crate::token::token_acceptance_deadline(exp)
                    .context("invalid token expiration")
                    .map_err(InsertError::InvalidToken)?,
            )
        } else {
            None
        };
        let mapping = mapping
            .map(CleartextAppCredentialMapping::encrypt)
            .transpose()
            .context("encrypt provisioned credentials")
            .map_err(InsertError::CredentialEncryption)?;

        let mut credentials = self.credentials.lock();
        let generation = credentials
            .get(&jti)
            .map_or(1, |entry| entry.generation.wrapping_add(1));
        let replaced = credentials
            .insert(
                jti,
                CredentialsEntry {
                    token,
                    mapping,
                    expires_at: staging_expires,
                    required_until,
                    generation,
                },
            )
            .is_some();

        self.cleanup_notify.notify_one();

        Ok(replaced)
    }

    /// Insert or replace the connection-options half. Returns whether a prior entry was replaced.
    pub(crate) fn insert_connection_options(
        &self,
        jti: Uuid,
        connection_options: TargetConnectionOptions,
        time_to_live: time::Duration,
    ) -> bool {
        let now = time::OffsetDateTime::now_utc();
        let entry = ConnectionOptionsEntry {
            connection_options,
            expires_at: now + time_to_live,
        };

        let replaced = self.connection_options.lock().insert(jti, entry).is_some();
        self.cleanup_notify.notify_one();
        replaced
    }

    /// State of the credential-injection mapping for `jti`.
    pub(crate) fn mapping_status(&self, jti: Uuid) -> MappingStatus {
        let now = time::OffsetDateTime::now_utc();
        let mut credentials = self.credentials.lock();

        let Some(entry) = credentials.get(&jti) else {
            return MappingStatus::Absent;
        };
        if now >= entry.expires_at {
            credentials.remove(&jti);
            return MappingStatus::Absent;
        }

        if entry.mapping.is_some() {
            MappingStatus::Available
        } else {
            MappingStatus::Absent
        }
    }

    /// Test helper that takes either a token-only or mapped entry.
    #[cfg(test)]
    pub(crate) fn take(&self, jti: Uuid) -> Option<ProvisioningEntry> {
        let now = time::OffsetDateTime::now_utc();

        let (token, mapping, generation, kdc_expires_at) = {
            let mut credentials = self.credentials.lock();
            let entry = credentials.remove(&jti)?;
            if now >= entry.expires_at {
                warn!(%jti, "Provisioned credentials expired before the connection arrived");
                return None;
            }
            (entry.token, entry.mapping, entry.generation, entry.required_until)
        };

        let connection_options = {
            let mut entries = self.connection_options.lock();
            match entries.remove(&jti) {
                Some(entry) if now < entry.expires_at => Some(entry.connection_options),
                Some(_) => {
                    warn!(%jti, "Provisioned connection options expired before the connection arrived");
                    None
                }
                None => None,
            }
        };

        Some(ProvisioningEntry {
            token,
            mapping,
            connection_options,
            generation,
            kdc_expires_at,
        })
    }

    /// Clone injection material for this `jti`.
    ///
    /// The first successful lookup extends retention to the token acceptance deadline so reconnects
    /// authorized by `jet_reuse` can still inject.
    pub(crate) fn get_mapping(&self, jti: Uuid, token: &str) -> anyhow::Result<ProvisioningEntry> {
        let now = time::OffsetDateTime::now_utc();

        let (token, mapping, generation, required_until, expiry_changed) = {
            let mut credentials = self.credentials.lock();
            let entry = credentials
                .get_mut(&jti)
                .context("provisioned credential-injection material is missing")?;

            anyhow::ensure!(token == entry.token, "token mismatch");
            let Some(deadline) = entry.required_until else {
                anyhow::bail!("provisioned entry has no credential mapping");
            };
            anyhow::ensure!(entry.mapping.is_some(), "provisioned entry has no credential mapping");

            if now >= entry.expires_at {
                credentials.remove(&jti);
                anyhow::bail!("credential-injection material for {jti} is missing or expired; re-provision to retry");
            }

            let expiry_changed = entry.expires_at != deadline;
            entry.expires_at = deadline;

            (
                entry.token.clone(),
                entry.mapping.clone(),
                entry.generation,
                entry.required_until,
                expiry_changed,
            )
        };

        if expiry_changed {
            self.cleanup_notify.notify_one();
        }

        let connection_options = {
            let entries = self.connection_options.lock();
            match entries.get(&jti) {
                Some(entry) if now < entry.expires_at => Some(entry.connection_options.clone()),
                Some(_) => {
                    warn!(%jti, "Provisioned connection options expired before the connection arrived");
                    None
                }
                None => None,
            }
        };

        Ok(ProvisioningEntry {
            token,
            mapping,
            connection_options,
            generation,
            kdc_expires_at: required_until,
        })
    }

    #[cfg(test)]
    pub(crate) fn credentials_expires_at(&self, jti: Uuid) -> Option<time::OffsetDateTime> {
        self.credentials.lock().get(&jti).map(|entry| entry.expires_at)
    }

    #[cfg(test)]
    pub(crate) fn connection_options_expires_at(&self, jti: Uuid) -> Option<time::OffsetDateTime> {
        self.connection_options.lock().get(&jti).map(|entry| entry.expires_at)
    }

    fn remove_expired(&self, now: time::OffsetDateTime) {
        self.credentials.lock().retain(|_, entry| now < entry.expires_at);
        self.connection_options.lock().retain(|_, entry| now < entry.expires_at);
    }

    fn next_expiry(&self) -> Option<time::OffsetDateTime> {
        let credentials_expiry = self.credentials.lock().values().map(|entry| entry.expires_at).min();
        let options_expiry = self
            .connection_options
            .lock()
            .values()
            .map(|entry| entry.expires_at)
            .min();
        credentials_expiry.into_iter().chain(options_expiry).min()
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
    debug!("Task started");

    loop {
        let now = time::OffsetDateTime::now_utc();
        handle.remove_expired(now);

        match handle.next_expiry() {
            Some(deadline) => {
                let delay = (deadline - now).try_into().unwrap_or_default();
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = handle.cleanup_notify.notified() => {}
                    _ = shutdown_signal.wait() => break,
                }
            }
            None => {
                tokio::select! {
                    _ = handle.cleanup_notify.notified() => {}
                    _ = shutdown_signal.wait() => break,
                }
            }
        }
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

    fn association_token_with_exp(jti: Uuid, exp: i64) -> String {
        use base64::Engine as _;
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = engine.encode(r#"{"alg":"RS256"}"#);
        let payload = engine.encode(
            serde_json::to_vec(&serde_json::json!({
                "jti": jti,
                "dst_hst": "target.example:3389",
                "exp": exp
            }))
            .expect("payload serializes"),
        );
        let signature = engine.encode(b"signature");
        format!("{header}.{payload}.{signature}")
    }

    fn association_token(jti: Uuid) -> String {
        association_token_with_exp(jti, time::OffsetDateTime::now_utc().unix_timestamp() + 3600)
    }

    fn options() -> TargetConnectionOptions {
        serde_json::from_value(serde_json::json!({ "krb_kdc": "tcp://dc.example:88" })).expect("options")
    }

    #[test]
    fn take_returns_token_only_entry() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        store
            .insert_credentials(association_token(jti), None, time::Duration::minutes(5))
            .expect("insert");
        let entry = store.take(jti).expect("live entry");
        assert!(entry.mapping.is_none());
        assert!(entry.connection_options.is_none());
        assert!(store.take(jti).is_none(), "second take is empty");
    }

    #[test]
    fn take_returns_live_credentials_without_options() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        store
            .insert_credentials(association_token(jti), Some(mapping()), time::Duration::minutes(5))
            .expect("insert");
        let entry = store.take(jti).expect("live entry");
        assert!(entry.mapping.is_some());
        assert!(entry.connection_options.is_none());
    }

    #[test]
    fn take_folds_in_and_consumes_connection_options() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        store
            .insert_credentials(association_token(jti), Some(mapping()), time::Duration::minutes(5))
            .expect("insert credentials");
        assert!(!store.insert_connection_options(jti, options(), time::Duration::minutes(5)));
        let entry = store.take(jti).expect("live entry");
        assert!(entry.connection_options.is_some());
        assert!(store.take(jti).is_none());
        assert!(!store.insert_connection_options(jti, options(), time::Duration::minutes(5)));
        assert!(store.take(jti).is_none());
    }

    #[test]
    fn take_treats_expired_credentials_as_absent() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        store
            .insert_credentials(association_token(jti), Some(mapping()), time::Duration::seconds(-1))
            .expect("insert");
        assert!(store.take(jti).is_none());
    }

    #[test]
    fn credentials_and_options_replace_independently() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        assert!(
            !store
                .insert_credentials(association_token(jti), Some(mapping()), time::Duration::minutes(5))
                .expect("insert")
        );
        assert!(
            store
                .insert_credentials(association_token(jti), Some(mapping()), time::Duration::minutes(5))
                .expect("replace")
        );

        assert!(!store.insert_connection_options(jti, options(), time::Duration::minutes(5)));
        assert!(store.insert_connection_options(jti, options(), time::Duration::minutes(5)));
    }

    #[test]
    fn reprovision_before_checkout_replaces_staged_mapping() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        let token = association_token(jti);
        store
            .insert_credentials(token.clone(), Some(mapping()), time::Duration::minutes(5))
            .expect("insert");

        store
            .insert_credentials(token.clone(), Some(mapping()), time::Duration::minutes(5))
            .expect("re-provision");
        let first = store.get_mapping(jti, &token).expect("checkout replacement");
        assert_eq!(first.generation, 2);
    }

    #[test]
    fn checked_out_mapping_is_reusable() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        let token = association_token(jti);
        store
            .insert_credentials(token.clone(), Some(mapping()), time::Duration::minutes(5))
            .expect("insert");

        let first = store.get_mapping(jti, &token).expect("first checkout");
        let second = store.get_mapping(jti, &token).expect("second checkout");
        assert_eq!(first.generation, second.generation);
    }

    #[test]
    fn token_mismatch_does_not_drop_mapping() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        let token = association_token(jti);
        store
            .insert_credentials(token.clone(), Some(mapping()), time::Duration::minutes(5))
            .expect("insert");

        let error = store.get_mapping(jti, "different token").expect_err("mismatch");
        assert!(format!("{error:#}").contains("token mismatch"));
        assert_eq!(store.mapping_status(jti), MappingStatus::Available);
        store.get_mapping(jti, &token).expect("valid checkout");
    }

    #[test]
    fn concurrent_mapping_checkout_all_succeed() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        let token = association_token(jti);
        store
            .insert_credentials(token.clone(), Some(mapping()), time::Duration::minutes(5))
            .expect("insert");

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let store = store.clone();
                let token = token.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store.get_mapping(jti, &token)
                })
            })
            .collect();
        barrier.wait();

        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 2);
    }

    #[test]
    fn staging_expiry_before_first_use_removes_mapping() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        let token = association_token(jti);
        store
            .insert_credentials(token.clone(), Some(mapping()), time::Duration::seconds(-1))
            .expect("insert");

        assert_eq!(store.mapping_status(jti), MappingStatus::Absent);
        assert!(store.credentials_expires_at(jti).is_none());
        let error = store.get_mapping(jti, &token).expect_err("expired staging");
        assert!(format!("{error:#}").contains("missing"));
    }

    #[test]
    fn first_get_extends_expiry_to_token_deadline() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        let exp = time::OffsetDateTime::now_utc().unix_timestamp() + 3600;
        let token = association_token_with_exp(jti, exp);
        store
            .insert_credentials(token.clone(), Some(mapping()), time::Duration::seconds(30))
            .expect("insert");

        let before = store.credentials_expires_at(jti).expect("inserted");
        store.get_mapping(jti, &token).expect("activate");
        let after = store.credentials_expires_at(jti).expect("activated");
        assert!(after > before);
        assert_eq!(after, crate::token::token_acceptance_deadline(exp).expect("deadline"));
    }

    #[test]
    fn staging_lifetime_uses_provisioning_ttl() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        let exp = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = association_token_with_exp(jti, exp);
        store
            .insert_credentials(token, Some(mapping()), time::Duration::hours(2))
            .expect("insert");

        let expires_at = store.credentials_expires_at(jti).expect("inserted");
        let deadline = crate::token::token_acceptance_deadline(exp).expect("deadline");
        assert!(expires_at > deadline);
    }

    #[test]
    fn credential_lifetime_does_not_change_connection_options_lifetime() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        let token = association_token(jti);
        store.insert_connection_options(jti, options(), time::Duration::minutes(5));
        let options_expires_at = store.connection_options_expires_at(jti).expect("options");

        store
            .insert_credentials(token.clone(), Some(mapping()), time::Duration::minutes(1))
            .expect("insert");
        assert_eq!(store.connection_options_expires_at(jti), Some(options_expires_at));

        store.get_mapping(jti, &token).expect("checkout");
        assert_eq!(store.connection_options_expires_at(jti), Some(options_expires_at));
    }

    #[test]
    fn mapped_insert_rejects_out_of_range_expiration() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        let token = association_token_with_exp(jti, i64::MAX);

        let error = store
            .insert_credentials(token, Some(mapping()), time::Duration::minutes(5))
            .expect_err("invalid expiration");

        assert!(format!("{error:#}").contains("supported timestamp range"));
        assert_eq!(store.mapping_status(jti), MappingStatus::Absent);
    }

    #[test]
    fn mapped_insert_requires_exp() {
        let store = ProvisioningStore::new();
        let jti = Uuid::new_v4();
        use base64::Engine as _;
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let token = format!(
            "{}.{}.{}",
            engine.encode(r#"{"alg":"RS256"}"#),
            engine.encode(
                serde_json::to_vec(&serde_json::json!({
                    "jti": jti,
                    "dst_hst": "target.example:3389"
                }))
                .expect("payload")
            ),
            engine.encode(b"signature")
        );
        let error = store
            .insert_credentials(token, Some(mapping()), time::Duration::minutes(5))
            .expect_err("missing exp");
        assert!(format!("{error:#}").contains("exp"));
    }
}
