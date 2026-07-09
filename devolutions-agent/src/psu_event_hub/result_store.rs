use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::psu_powershell::PowerShellWorkerResponse;

const RESULT_TTL: Duration = Duration::from_secs(15 * 60);
const MAX_RESULTS: usize = 1024;

#[derive(Debug, Clone)]
pub(super) struct ResultStore {
    inner: Arc<Mutex<ResultStoreInner>>,
    ttl: Duration,
    max_results: usize,
}

impl ResultStore {
    fn new(ttl: Duration, max_results: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ResultStoreInner::default())),
            ttl,
            max_results,
        }
    }

    pub(super) fn insert(&self, execution_id: String, response: PowerShellWorkerResponse) {
        let mut inner = self.inner.lock();
        let now = Instant::now();

        inner.remove_expired(now, self.ttl);
        inner.results.insert(
            execution_id.clone(),
            StoredResult {
                inserted_at: now,
                response,
            },
        );
        inner.order.push_back(execution_id);
        inner.enforce_limit(self.max_results);
    }

    pub(super) fn take(&self, execution_id: &str) -> PowerShellWorkerResponse {
        let mut inner = self.inner.lock();
        inner.remove_expired(Instant::now(), self.ttl);
        inner
            .results
            .remove(execution_id)
            .map(|stored| stored.response)
            .unwrap_or_else(PowerShellWorkerResponse::pending)
    }
}

impl Default for ResultStore {
    fn default() -> Self {
        Self::new(RESULT_TTL, MAX_RESULTS)
    }
}

#[derive(Debug, Default)]
struct ResultStoreInner {
    results: HashMap<String, StoredResult>,
    order: VecDeque<String>,
}

impl ResultStoreInner {
    fn remove_expired(&mut self, now: Instant, ttl: Duration) {
        while let Some(execution_id) = self.order.front() {
            let Some(result) = self.results.get(execution_id) else {
                self.order.pop_front();
                continue;
            };

            if now.duration_since(result.inserted_at) < ttl {
                break;
            }

            let execution_id = self.order.pop_front().expect("front exists");
            self.results.remove(&execution_id);
        }
    }

    fn enforce_limit(&mut self, max_results: usize) {
        while self.results.len() > max_results {
            let Some(execution_id) = self.order.pop_front() else {
                break;
            };

            self.results.remove(&execution_id);
        }
    }
}

#[derive(Debug)]
struct StoredResult {
    inserted_at: Instant,
    response: PowerShellWorkerResponse,
}

#[cfg(test)]
mod tests {
    use super::*;

    impl ResultStore {
        fn test_with_limits(ttl: Duration, max_results: usize) -> Self {
            Self::new(ttl, max_results)
        }
    }

    #[test]
    fn take_removes_result_after_first_read() {
        let store = ResultStore::default();
        store.insert(
            "execution-id".to_owned(),
            PowerShellWorkerResponse {
                complete: true,
                ..PowerShellWorkerResponse::default()
            },
        );

        assert!(store.take("execution-id").complete);
        assert!(!store.take("execution-id").complete);
    }

    #[test]
    fn insert_evicts_oldest_result_when_limit_is_reached() {
        let store = ResultStore::test_with_limits(Duration::from_secs(60), 1);
        store.insert(
            "first".to_owned(),
            PowerShellWorkerResponse {
                complete: true,
                ..PowerShellWorkerResponse::default()
            },
        );
        store.insert(
            "second".to_owned(),
            PowerShellWorkerResponse {
                complete: true,
                ..PowerShellWorkerResponse::default()
            },
        );

        assert!(!store.take("first").complete);
        assert!(store.take("second").complete);
    }

    #[test]
    fn take_ignores_expired_results() {
        let store = ResultStore::test_with_limits(Duration::ZERO, 10);
        store.insert(
            "execution-id".to_owned(),
            PowerShellWorkerResponse {
                complete: true,
                ..PowerShellWorkerResponse::default()
            },
        );

        assert!(!store.take("execution-id").complete);
    }
}
