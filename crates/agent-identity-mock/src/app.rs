//! Shared application handle and time helpers.

use std::sync::Arc;

use tokio::sync::{Mutex, watch};
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
    /// The management API secret; see the README for the credentials derived from it.
    pub admin_token: String,
    pub clock: MockClock,
    /// Mock-only barrier for proving that a key survives until Hello authenticates.
    pub handshake_gate: watch::Sender<bool>,
    pub state: Mutex<State>,
}

impl App {
    /// Builds an app with admin token `admin` under the `/mock` prefix, for handler tests.
    #[cfg(test)]
    pub(crate) fn for_test() -> anyhow::Result<Arc<Self>> {
        let clock = MockClock::new();
        let state = State::with_root(clock.now())?;
        Ok(Arc::new(App {
            authority_id: Uuid::new_v4(),
            base_url: "https://127.0.0.1:1/mock".to_owned(),
            prefix: "/mock".to_owned(),
            admin_token: "admin".to_owned(),
            clock,
            handshake_gate: watch::channel(true).0,
            state: Mutex::new(state),
        }))
    }

    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    /// Re-evaluates certificate expiry and rotation completion before each request.
    pub async fn tick(self: &Arc<Self>) {
        let mut state = self.state.lock().await;
        state.tick(self.now());
    }
}

/// RFC 3339 UTC with a `Z` designator, as in the contract's examples (§1).
pub(crate) fn rfc3339(unix_secs: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    match time::OffsetDateTime::from_unix_timestamp(unix_secs) {
        Ok(t) => t.format(&Rfc3339).unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
        Err(_) => "1970-01-01T00:00:00Z".to_owned(),
    }
}

const NANOS_PER_SEC: i128 = 1_000_000_000;

/// Converts Unix seconds to Unix nanoseconds, the precision of management API date-times.
pub(crate) fn nanos(unix_secs: i64) -> i128 {
    i128::from(unix_secs) * NANOS_PER_SEC
}

/// RFC 3339 UTC with a `Z` designator and only the fractional digits the instant needs.
pub(crate) fn rfc3339_nanos(unix_nanos: i128) -> String {
    use time::format_description::well_known::Rfc3339;
    match time::OffsetDateTime::from_unix_timestamp_nanos(unix_nanos) {
        Ok(t) => t.format(&Rfc3339).unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
        Err(_) => "1970-01-01T00:00:00Z".to_owned(),
    }
}

/// Parses a management API date-time to Unix nanoseconds, keeping its fraction of a second: RFC 3339, or ISO 8601
/// without an offset, which is UTC.
/// DVLS's OpenAPI document reads every date-time "UTC unless an offset is given".
pub(crate) fn parse_date_time(value: &str) -> Option<i128> {
    use time::format_description::well_known::{Iso8601, Rfc3339};
    time::OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .or_else(|| {
            time::PrimitiveDateTime::parse(value, &Iso8601::DEFAULT)
                .ok()
                .map(time::PrimitiveDateTime::assume_utc)
        })
        .map(time::OffsetDateTime::unix_timestamp_nanos)
}
