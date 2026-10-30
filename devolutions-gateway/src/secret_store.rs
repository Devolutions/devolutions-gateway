use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use parking_lot::Mutex;
use secrecy::SecretString;
use tokio::sync::Notify;
use tracing::{debug, instrument};
use uuid::Uuid;

use crate::credential::EncryptedSecret;

/// The key a caller picks for its secret.
///
/// It wraps the caller's own ID, so the caller says which IDs it uses and they can't be mixed up with JTIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecretId(pub Uuid);

#[derive(Debug)]
struct SecretEntry {
    secret: EncryptedSecret,
    expires_at: time::OffsetDateTime,
}

/// Opaque secrets that must stay in memory only and never be written to disk.
/// Each is keyed by a caller-chosen ID, encrypted with the in-memory master key,
/// replaced on re-insert, and kept until it is removed or reaches its expiry.
#[derive(Debug, Clone, Default)]
pub struct SecretStore {
    entries: Arc<Mutex<HashMap<SecretId, SecretEntry>>>,
    cleanup_notify: Arc<Notify>,
}

impl SecretStore {
    /// Encrypts and stores `secret` under `id` until `expires_at`,
    /// replacing any earlier secret with the same ID.
    pub fn insert(&self, id: SecretId, secret: &SecretString, expires_at: time::OffsetDateTime) -> anyhow::Result<()> {
        let secret = crate::credential::encrypt_secret(secret).context("encrypt the secret")?;

        self.entries.lock().insert(id, SecretEntry { secret, expires_at });
        self.cleanup_notify.notify_one();

        Ok(())
    }

    /// Returns the decrypted secret of `id`, or `None` once it is removed or expired.
    ///
    /// The returned value zeroizes on drop; keep it only as long as it is needed.
    pub fn get(&self, id: SecretId) -> anyhow::Result<Option<SecretString>> {
        self.get_at(id, time::OffsetDateTime::now_utc())
    }

    fn get_at(&self, id: SecretId, now: time::OffsetDateTime) -> anyhow::Result<Option<SecretString>> {
        let encrypted = {
            let mut entries = self.entries.lock();

            let Some(entry) = entries.get(&id) else {
                return Ok(None);
            };
            if entry.expires_at <= now {
                entries.remove(&id);
                return Ok(None);
            }

            entry.secret.clone()
        };

        crate::credential::decrypt_secret(&encrypted)
            .context("decrypt the secret")
            .map(Some)
    }

    /// Removes the secret of `id`.
    pub fn remove(&self, id: SecretId) {
        self.entries.lock().remove(&id);
    }

    fn remove_expired(&self, now: time::OffsetDateTime) {
        self.entries.lock().retain(|_, entry| now < entry.expires_at);
    }

    fn next_expiry(&self) -> Option<time::OffsetDateTime> {
        self.entries.lock().values().map(|entry| entry.expires_at).min()
    }
}

pub struct CleanupTask {
    pub handle: SecretStore,
}

#[async_trait]
impl Task for CleanupTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "secret store cleanup";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        cleanup_task(self.handle, shutdown_signal).await;
        Ok(())
    }
}

#[instrument(skip_all)]
async fn cleanup_task(handle: SecretStore, mut shutdown_signal: ShutdownSignal) {
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
    use secrecy::ExposeSecret as _;

    use super::*;

    #[test]
    fn secret_is_read_back_and_replaced() {
        let store = SecretStore::default();
        let id = SecretId(Uuid::new_v4());
        let now = time::OffsetDateTime::now_utc();

        store
            .insert(id, &SecretString::from("secret-a"), now + time::Duration::hours(1))
            .expect("insert");

        // oracle: intent devolutions-gateway/src/secret_store.intent.md §secrets
        assert!(
            !format!("{store:?}").contains("secret-a"),
            "the store's Debug output never shows the secret"
        );
        let secret = store.get_at(id, now).expect("decrypt").expect("present");
        // oracle: property round-trip
        assert_eq!(secret.expose_secret(), "secret-a");

        store
            .insert(id, &SecretString::from("secret-b"), now + time::Duration::hours(1))
            .expect("replace");
        let secret = store.get_at(id, now).expect("decrypt").expect("present");
        // oracle: intent devolutions-gateway/src/secret_store.intent.md §replacement
        assert_eq!(secret.expose_secret(), "secret-b");
    }

    // oracle: intent devolutions-gateway/src/secret_store.intent.md §secrets
    #[test]
    fn secret_goes_away_when_removed_or_expired() {
        let store = SecretStore::default();
        let now = time::OffsetDateTime::now_utc();
        let removed = SecretId(Uuid::new_v4());
        let expired = SecretId(Uuid::new_v4());
        let expiring = SecretId(Uuid::new_v4());

        store
            .insert(removed, &SecretString::from("a"), now + time::Duration::hours(1))
            .expect("insert");
        store.insert(expired, &SecretString::from("b"), now).expect("insert");
        store
            .insert(expiring, &SecretString::from("c"), now + time::Duration::minutes(1))
            .expect("insert");

        store.remove(removed);
        assert!(store.get_at(removed, now).expect("read").is_none());
        assert!(
            store.get_at(expired, now).expect("read").is_none(),
            "a secret is gone once its expiry is reached"
        );
        assert!(
            !store.entries.lock().contains_key(&expired),
            "reading an expired secret drops it"
        );

        store.remove_expired(now + time::Duration::minutes(1));
        assert!(store.entries.lock().is_empty(), "the cleanup pass removes it");
    }
}
