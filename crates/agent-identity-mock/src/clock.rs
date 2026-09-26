//! Mock clock (CONTRACT.md §11): real time plus a manually advanced offset and a
//! fault-injected skew. Used for everything time-related in the mock.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const UNFROZEN: i64 = i64::MIN;

#[derive(Debug)]
pub struct MockClock {
    advance_secs: AtomicI64,
    skew_secs: AtomicI64,
    fixed_secs: AtomicI64,
}

impl MockClock {
    pub fn new() -> Self {
        Self {
            advance_secs: AtomicI64::new(0),
            skew_secs: AtomicI64::new(0),
            fixed_secs: AtomicI64::new(UNFROZEN),
        }
    }

    /// Current mock time as Unix seconds.
    pub fn now(&self) -> i64 {
        let skew = self.skew_secs.load(Ordering::Relaxed);
        let fixed = self.fixed_secs.load(Ordering::Relaxed);
        if fixed != UNFROZEN {
            return fixed.saturating_add(skew);
        }
        let real = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        real + self.advance_secs.load(Ordering::Relaxed) + skew
    }

    /// `__mock__/time/advance`.
    pub(crate) fn advance_by(&self, secs: i64) {
        if self.fixed_secs.load(Ordering::Relaxed) == UNFROZEN {
            self.advance_secs.fetch_add(secs, Ordering::Relaxed);
        } else {
            self.fixed_secs.fetch_add(secs, Ordering::Relaxed);
        }
    }

    /// Pins time for an atomic mock-only boundary observation.
    pub(crate) fn freeze_at(&self, now: i64) {
        let skew = self.skew_secs.load(Ordering::Relaxed);
        self.fixed_secs.store(now.saturating_sub(skew), Ordering::Relaxed);
    }

    /// `faults.clock_skew_secs`; `None` clears the skew.
    pub(crate) fn set_skew(&self, secs: Option<i64>) {
        self.skew_secs.store(secs.unwrap_or(0), Ordering::Relaxed);
    }

    /// `__mock__/reset`.
    pub(crate) fn reset(&self) {
        self.advance_secs.store(0, Ordering::Relaxed);
        self.skew_secs.store(0, Ordering::Relaxed);
        self.fixed_secs.store(UNFROZEN, Ordering::Relaxed);
    }
}

impl Default for MockClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_clock_keeps_exact_seconds_until_reset() {
        let clock = MockClock::new();
        clock.freeze_at(1_790_000_000);
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(clock.now(), 1_790_000_000);
        clock.advance_by(1);
        assert_eq!(clock.now(), 1_790_000_001);
        clock.set_skew(Some(2));
        assert_eq!(clock.now(), 1_790_000_003);
        clock.reset();
        let real = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_secs(),
        )
        .expect("Unix time fits i64");
        assert!((clock.now() - real).abs() <= 1);
    }
}
