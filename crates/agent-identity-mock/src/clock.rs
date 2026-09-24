//! Mock clock (CONTRACT.md §11): real time plus a manually advanced offset and a
//! fault-injected skew. Used for everything time-related in the mock.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct MockClock {
    advance_secs: AtomicI64,
    skew_secs: AtomicI64,
}

impl MockClock {
    pub fn new() -> Self {
        Self {
            advance_secs: AtomicI64::new(0),
            skew_secs: AtomicI64::new(0),
        }
    }

    /// Current mock time as Unix seconds.
    pub fn now(&self) -> i64 {
        let real = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        real + self.advance_secs.load(Ordering::Relaxed) + self.skew_secs.load(Ordering::Relaxed)
    }

    /// `__mock__/time/advance`.
    pub fn advance_by(&self, secs: i64) {
        self.advance_secs.fetch_add(secs, Ordering::Relaxed);
    }

    /// `faults.clock_skew_secs`; `None` clears the skew.
    pub fn set_skew(&self, secs: Option<i64>) {
        self.skew_secs.store(secs.unwrap_or(0), Ordering::Relaxed);
    }

    /// `__mock__/reset`.
    pub fn reset(&self) {
        self.advance_secs.store(0, Ordering::Relaxed);
        self.skew_secs.store(0, Ordering::Relaxed);
    }
}

impl Default for MockClock {
    fn default() -> Self {
        Self::new()
    }
}
