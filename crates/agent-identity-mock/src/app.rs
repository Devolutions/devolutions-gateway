//! Shared application handle and time helpers.

use std::sync::Arc;

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::clock::MockClock;
use crate::state::State;

pub struct App {
    /// Stable for the lifetime of the process, including across resets (§5.2).
    pub authority_id: Uuid,
    /// e.g. `https://127.0.0.1:8443/mock`.
    pub base_url: String,
    /// e.g. `/mock`.
    pub prefix: String,
    pub admin_token: String,
    pub clock: MockClock,
    pub state: Mutex<State>,
}

impl App {
    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    /// Lazy rotation-deadline handling, run at the start of every request (§9.3).
    pub async fn tick(self: &Arc<Self>) {
        let now = self.now();
        self.state.lock().await.tick(now);
    }
}

/// RFC 3339 UTC with a `Z` designator, as in the contract's examples (§1).
pub fn rfc3339(unix_secs: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    match time::OffsetDateTime::from_unix_timestamp(unix_secs) {
        Ok(t) => t.format(&Rfc3339).unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
        Err(_) => "1970-01-01T00:00:00Z".to_owned(),
    }
}

/// Parses an RFC 3339 timestamp to Unix seconds.
pub fn parse_rfc3339(value: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .map(time::OffsetDateTime::unix_timestamp)
}
