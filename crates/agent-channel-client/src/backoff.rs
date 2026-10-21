//! The reconnect backoff ([`crates/agent-channel-client/INTENT.md`]).
//!
//! [`crates/agent-channel-client/INTENT.md`]: ../INTENT.md

use std::sync::Arc;
use std::time::Duration;

use rand::RngExt as _;

use crate::TransientKind;

const NO_GRPC_PATH_CAP: Duration = Duration::from_secs(3600);
const OUTAGE_CAP: Duration = Duration::from_secs(300);

/// When a channel reopens its stream after a transient closure.
///
/// The `n`-th consecutive closure waits `2^(n-1)` seconds times a jitter factor, then at most the cap of its
/// [`TransientKind`]; an authenticated stream starts the count again.
#[derive(Clone)]
pub struct Backoff {
    /// The cap when the response shows the path can't carry gRPC.
    pub no_grpc_path_cap: Duration,
    /// The cap after every other transient closure.
    pub outage_cap: Duration,
    /// A lower cap for every closure, such as the agent's `backoff_max_secs`.
    pub max: Option<Duration>,
    /// Draws the factor each delay is multiplied by.
    ///
    /// The default is [`uniform_jitter`]; `|| 1.0` disables jitter.
    pub jitter: Arc<dyn Fn() -> f64 + Send + Sync>,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            no_grpc_path_cap: NO_GRPC_PATH_CAP,
            outage_cap: OUTAGE_CAP,
            max: None,
            jitter: Arc::new(uniform_jitter),
        }
    }
}

/// Draws a jitter factor uniformly from `[0.5, 1.5]`.
pub fn uniform_jitter() -> f64 {
    rand::rng().random_range(0.5..=1.5)
}

/// Counts the consecutive closures since the last authenticated stream.
#[derive(Default)]
pub(crate) struct BackoffState {
    closures: u32,
}

impl BackoffState {
    /// Returns the delay before reopening after one more transient closure of `kind`.
    pub(crate) fn next_delay(&mut self, backoff: &Backoff, kind: TransientKind) -> Duration {
        self.closures = self.closures.saturating_add(1);
        let cap = match kind {
            TransientKind::NoGrpcPath => backoff.no_grpc_path_cap,
            TransientKind::Outage => backoff.outage_cap,
        };
        let cap = backoff.max.map_or(cap, |max| cap.min(max));
        // The exponent stops at 62 so that `2^62` s times any sane jitter still fits a `Duration`.
        let exponent = (self.closures - 1).min(62);
        let delay = Duration::from_secs(1 << exponent).as_secs_f64() * (backoff.jitter)();
        // A jitter that makes the delay negative, infinite or not a number waits the cap.
        Duration::try_from_secs_f64(delay).map_or(cap, |delay| delay.min(cap))
    }

    /// Starts the count again after an authenticated stream.
    pub(crate) fn reset(&mut self) {
        self.closures = 0;
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn delays(backoff: &Backoff, kind: TransientKind, count: usize) -> Vec<Duration> {
        let mut state = BackoffState::default();
        (0..count).map(|_| state.next_delay(backoff, kind)).collect()
    }

    fn seconds(values: &[f64]) -> Vec<Duration> {
        values.iter().copied().map(Duration::from_secs_f64).collect()
    }

    fn without_jitter() -> Backoff {
        Backoff {
            jitter: Arc::new(|| 1.0),
            ..Backoff::default()
        }
    }

    // crates/agent-channel-client/INTENT.md: the channel reconnects "with a jittered exponential backoff from 1 s".
    // "The backoff grows to 1 h when the response shows the path cannot carry gRPC, such as a reverse proxy that answers
    // without HTTP/2 or gRPC, and to 5 min after network errors, server downtime, and any other transient refusal or
    // closure of the stream".
    #[rstest]
    #[case::outage(
        TransientKind::Outage,
        &[1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 300.0, 300.0]
    )]
    #[case::no_grpc_path(
        TransientKind::NoGrpcPath,
        &[1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0, 2048.0, 3600.0, 3600.0]
    )]
    fn doubles_from_one_second_up_to_the_cap_of_the_closure(#[case] kind: TransientKind, #[case] expected: &[f64]) {
        assert_eq!(delays(&without_jitter(), kind, expected.len()), seconds(expected));
    }

    #[rstest]
    #[case::low(0.5, &[0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 300.0])]
    #[case::high(1.5, &[1.5, 3.0, 6.0, 12.0, 24.0, 48.0, 96.0, 192.0, 300.0, 300.0])]
    fn scales_each_delay_by_the_jitter_before_the_cap(#[case] factor: f64, #[case] expected: &[f64]) {
        let backoff = Backoff {
            jitter: Arc::new(move || factor),
            ..Backoff::default()
        };
        assert_eq!(
            delays(&backoff, TransientKind::Outage, expected.len()),
            seconds(expected)
        );
    }

    #[rstest]
    #[case::outage(TransientKind::Outage)]
    #[case::no_grpc_path(TransientKind::NoGrpcPath)]
    fn the_callers_maximum_lowers_every_cap(#[case] kind: TransientKind) {
        let backoff = Backoff {
            max: Some(Duration::from_secs(3)),
            ..without_jitter()
        };
        assert_eq!(delays(&backoff, kind, 4), seconds(&[1.0, 2.0, 3.0, 3.0]));
    }

    // oracle: intent crates/agent-channel-client/INTENT.md §Connection
    #[test]
    fn stays_at_its_cap_however_many_closures_follow() {
        let delays = delays(&without_jitter(), TransientKind::NoGrpcPath, 100);
        assert!(
            delays[12..].iter().all(|delay| *delay == Duration::from_secs(3600)),
            "{delays:?}"
        );
    }

    #[test]
    fn the_default_jitter_stays_within_half_and_one_and_a_half() {
        let draws: Vec<f64> = (0..1000).map(|_| uniform_jitter()).collect();
        assert!(draws.iter().all(|draw| (0.5..=1.5).contains(draw)));
        assert!(draws.iter().any(|draw| *draw < 0.9) && draws.iter().any(|draw| 1.1 < *draw));
    }
}
