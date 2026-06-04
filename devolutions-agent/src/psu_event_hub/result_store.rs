use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::psu_event_hub::models::WebsocketEventResponse;

#[derive(Debug, Clone, Default)]
pub(super) struct ResultStore {
    inner: Arc<Mutex<HashMap<String, WebsocketEventResponse>>>,
}

impl ResultStore {
    pub(super) fn insert(&self, execution_id: String, response: WebsocketEventResponse) {
        self.inner.lock().insert(execution_id, response);
    }

    pub(super) fn take(&self, execution_id: &str) -> WebsocketEventResponse {
        self.inner
            .lock()
            .remove(execution_id)
            .unwrap_or_else(WebsocketEventResponse::pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_removes_result_after_first_read() {
        let store = ResultStore::default();
        store.insert(
            "execution-id".to_owned(),
            WebsocketEventResponse {
                complete: true,
                ..WebsocketEventResponse::default()
            },
        );

        assert!(store.take("execution-id").complete);
        assert!(!store.take("execution-id").complete);
    }
}
