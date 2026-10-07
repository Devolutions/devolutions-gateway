//! API keys of the Tasks that call an AI provider, kept in memory only.
//!
//! Nobody wants an API key sitting on disk, so the key lives here from the moment its Task is created until the Task
//! ends, and never longer than the Task deadline. A restart forgets every key, so the Tasks still waiting fail instead
//! of running without one.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use parking_lot::Mutex;
use secrecy::SecretString;
use time::OffsetDateTime;
use tokio::sync::Notify;
use url::Url;
use uuid::Uuid;

/// What a Task needs to reach its AI provider and must never write to disk.
///
/// The key is wiped from memory when the last copy is dropped.
#[derive(Debug, Clone)]
pub struct AiAccess {
    pub api_key: SecretString,
    pub base_url: Option<Url>,
}

#[derive(Debug)]
struct Entry {
    access: AiAccess,
    expires_at: OffsetDateTime,
}

/// Task ID → [`AiAccess`], each entry dropped when its Task ends or at its deadline.
#[derive(Debug, Clone, Default)]
pub struct AiKeyStore {
    entries: Arc<Mutex<HashMap<Uuid, Entry>>>,
    cleanup_notify: Arc<Notify>,
}

impl AiKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, task_id: Uuid, access: AiAccess, expires_at: OffsetDateTime) {
        self.entries.lock().insert(task_id, Entry { access, expires_at });
        self.cleanup_notify.notify_one();
    }

    /// Returns `None` once the entry is removed or past its expiry.
    pub fn get(&self, task_id: Uuid, now: OffsetDateTime) -> Option<AiAccess> {
        let mut entries = self.entries.lock();
        let entry = entries.get(&task_id)?;

        if now >= entry.expires_at {
            entries.remove(&task_id);
            return None;
        }

        Some(entry.access.clone())
    }

    pub fn remove(&self, task_id: Uuid) {
        self.entries.lock().remove(&task_id);
    }

    fn remove_expired(&self, now: OffsetDateTime) {
        self.entries.lock().retain(|_, entry| now < entry.expires_at);
    }

    fn next_expiry(&self) -> Option<OffsetDateTime> {
        self.entries.lock().values().map(|entry| entry.expires_at).min()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().len()
    }
}

pub struct CleanupTask {
    pub handle: AiKeyStore,
}

#[async_trait]
impl Task for CleanupTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "AI key store cleanup";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        cleanup_task(self.handle, shutdown_signal).await;
        Ok(())
    }
}

#[instrument(skip_all)]
async fn cleanup_task(handle: AiKeyStore, mut shutdown_signal: ShutdownSignal) {
    debug!("Task started");

    loop {
        let now = OffsetDateTime::now_utc();
        handle.remove_expired(now);

        match handle.next_expiry() {
            Some(deadline) => {
                let delay = (deadline - now).try_into().unwrap_or_default();
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    () = handle.cleanup_notify.notified() => {}
                    () = shutdown_signal.wait() => break,
                }
            }
            None => {
                tokio::select! {
                    () = handle.cleanup_notify.notified() => {}
                    () = shutdown_signal.wait() => break,
                }
            }
        }
    }

    debug!("Task terminated");
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;
    use time::Duration;

    use super::*;

    fn access(key: &str) -> AiAccess {
        AiAccess {
            api_key: SecretString::from(key),
            base_url: None,
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("valid timestamp")
    }

    #[test]
    fn key_is_kept_until_removed() {
        let store = AiKeyStore::new();
        let task_id = Uuid::new_v4();
        store.insert(task_id, access("sk-1"), now() + Duration::hours(2));

        let found = store.get(task_id, now()).expect("key is there");
        assert_eq!(found.api_key.expose_secret(), "sk-1");

        store.remove(task_id);
        assert!(store.get(task_id, now()).is_none());
    }

    #[test]
    fn key_expires_at_the_task_deadline() {
        let store = AiKeyStore::new();
        let task_id = Uuid::new_v4();
        let deadline = now() + Duration::hours(2);
        store.insert(task_id, access("sk-1"), deadline);

        assert!(store.get(task_id, deadline - Duration::seconds(1)).is_some());
        assert!(store.get(task_id, deadline).is_none());
        assert_eq!(store.len(), 0, "an expired key is dropped when read");
    }

    #[test]
    fn cleanup_drops_expired_keys_only() {
        let store = AiKeyStore::new();
        let expired = Uuid::new_v4();
        let live = Uuid::new_v4();
        store.insert(expired, access("sk-1"), now() - Duration::seconds(1));
        store.insert(live, access("sk-2"), now() + Duration::hours(1));

        assert_eq!(store.next_expiry(), Some(now() - Duration::seconds(1)));
        store.remove_expired(now());

        assert_eq!(store.len(), 1);
        assert!(store.get(live, now()).is_some());
        assert_eq!(store.next_expiry(), Some(now() + Duration::hours(1)));
    }

    #[test]
    fn debug_output_hides_the_key() {
        let store = AiKeyStore::new();
        store.insert(Uuid::new_v4(), access("sk-secret-value"), now());

        assert!(!format!("{store:?}").contains("sk-secret-value"));
    }
}
