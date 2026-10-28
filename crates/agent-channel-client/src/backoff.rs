//! The reconnect backoff ([`crates/agent-channel-client/INTENT.md`]).
//!
//! [`crates/agent-channel-client/INTENT.md`]: ../INTENT.md

use std::sync::Arc;
use std::time::Duration;

use rand::RngExt as _;
use tokio::time::Instant;

use crate::TransientKind;

const NO_GRPC_PATH_CAP: Duration = Duration::from_secs(3600);
const OUTAGE_CAP: Duration = Duration::from_secs(300);
const STABLE_AFTER: Duration = Duration::from_secs(60);
const SPREAD_MAX: Duration = Duration::from_secs(30);

/// When a channel reopens its stream after a transient closure.
///
/// The `n`-th consecutive closure waits `2^(n-1)` seconds times a jitter factor, then at most the cap of its
/// [`TransientKind`].
/// A stream that stays authenticated for [`stable_after`](Self::stable_after) starts the count again, and the first
/// closure after it waits a [`spread`](Self::spread) draw instead, at most the same cap.
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
    /// How long a stream stays authenticated before the count starts again.
    pub stable_after: Duration,
    /// Draws the wait before reopening after a stream that stayed authenticated for `stable_after`.
    ///
    /// The default is [`uniform_spread`].
    pub spread: Arc<dyn Fn() -> Duration + Send + Sync>,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            no_grpc_path_cap: NO_GRPC_PATH_CAP,
            outage_cap: OUTAGE_CAP,
            max: None,
            jitter: Arc::new(uniform_jitter),
            stable_after: STABLE_AFTER,
            spread: Arc::new(uniform_spread),
        }
    }
}

/// Draws a jitter factor uniformly from `[0.5, 1.5]`.
pub fn uniform_jitter() -> f64 {
    rand::rng().random_range(0.5..=1.5)
}

/// Draws a wait uniformly from `[0, 30 s]`.
pub fn uniform_spread() -> Duration {
    SPREAD_MAX.mul_f64(rand::rng().random_range(0.0..=1.0))
}

/// Counts the consecutive closures since the last stream that stayed authenticated for [`Backoff::stable_after`].
#[derive(Default)]
pub(crate) struct BackoffState {
    closures: u32,
    /// When the current stream authenticated, until its closure.
    authenticated_at: Option<Instant>,
}

impl BackoffState {
    /// Returns the delay before reopening after one more transient closure of `kind`, which happened at `now`.
    pub(crate) fn next_delay(&mut self, backoff: &Backoff, kind: TransientKind, now: Instant) -> Duration {
        let cap = match kind {
            TransientKind::NoGrpcPath => backoff.no_grpc_path_cap,
            TransientKind::Outage => backoff.outage_cap,
        };
        let cap = backoff.max.map_or(cap, |max| cap.min(max));
        if let Some(authenticated_at) = self.authenticated_at.take()
            && backoff.stable_after <= now.saturating_duration_since(authenticated_at)
        {
            self.closures = 0;
            return (backoff.spread)().min(cap);
        }
        self.closures = self.closures.saturating_add(1);
        // The exponent stops at 62 so that `2^62` s times any sane jitter still fits a `Duration`.
        let exponent = (self.closures - 1).min(62);
        let delay = Duration::from_secs(1 << exponent).as_secs_f64() * (backoff.jitter)();
        // A jitter that makes the delay negative, infinite or not a number waits the cap.
        Duration::try_from_secs_f64(delay).map_or(cap, |delay| delay.min(cap))
    }

    /// Records that a stream authenticated at `at`.
    pub(crate) fn authenticated(&mut self, at: Instant) {
        self.authenticated_at = Some(at);
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn delays(backoff: &Backoff, kind: TransientKind, count: usize) -> Vec<Duration> {
        let mut state = BackoffState::default();
        delays_of(&mut state, backoff, kind, count)
    }

    fn delays_of(state: &mut BackoffState, backoff: &Backoff, kind: TransientKind, count: usize) -> Vec<Duration> {
        (0..count)
            .map(|_| state.next_delay(backoff, kind, Instant::now()))
            .collect()
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

    // oracle: intent crates/agent-channel-client/INTENT.md §Connection
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

    // oracle: intent crates/agent-channel-client/INTENT.md §Connection
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

    // oracle: intent crates/agent-channel-client/INTENT.md §Connection
    // oracle: intent devolutions-agent/src/identity/INTENT.md §Configuration
    // The agent passes its `backoff_max_secs` as `max`.
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

    // oracle: intent crates/agent-channel-client/INTENT.md §Connection
    #[test]
    fn the_default_jitter_stays_within_half_and_one_and_a_half() {
        let draws: Vec<f64> = (0..1000).map(|_| uniform_jitter()).collect();
        assert!(draws.iter().all(|draw| (0.5..=1.5).contains(draw)));
        assert!(draws.iter().any(|draw| *draw < 0.9) && draws.iter().any(|draw| 1.1 < *draw));
    }

    /// A backoff without jitter whose spread always draws 17 s.
    fn with_spread() -> Backoff {
        Backoff {
            spread: Arc::new(|| Duration::from_secs(17)),
            ..without_jitter()
        }
    }

    // oracle: intent crates/agent-channel-client/INTENT.md §Connection
    #[test]
    fn keeps_growing_after_a_stream_authenticated_for_less_than_60_s() {
        let backoff = with_spread();
        let mut state = BackoffState::default();
        delays_of(&mut state, &backoff, TransientKind::Outage, 3);
        let authenticated = Instant::now();
        state.authenticated(authenticated);

        let closed = authenticated + Duration::from_secs(60) - Duration::from_millis(1);
        assert_eq!(
            state.next_delay(&backoff, TransientKind::Outage, closed),
            Duration::from_secs(8)
        );
    }

    // oracle: intent crates/agent-channel-client/INTENT.md §Connection
    #[test]
    fn spreads_the_first_reconnect_after_a_stream_authenticated_for_60_s_then_restarts_from_1_s() {
        let backoff = with_spread();
        let mut state = BackoffState::default();
        delays_of(&mut state, &backoff, TransientKind::Outage, 3);
        let authenticated = Instant::now();
        state.authenticated(authenticated);

        let closed = authenticated + Duration::from_secs(60);
        assert_eq!(
            state.next_delay(&backoff, TransientKind::Outage, closed),
            Duration::from_secs(17)
        );
        assert_eq!(
            delays_of(&mut state, &backoff, TransientKind::Outage, 2),
            seconds(&[1.0, 2.0])
        );
    }

    // oracle: intent crates/agent-channel-client/INTENT.md §Connection
    // oracle: intent devolutions-agent/src/identity/INTENT.md §Configuration
    // The agent passes its `backoff_max_secs` as `max`.
    #[test]
    fn the_callers_maximum_lowers_the_spread() {
        let backoff = Backoff {
            max: Some(Duration::from_secs(3)),
            ..with_spread()
        };
        let mut state = BackoffState::default();
        let authenticated = Instant::now();
        state.authenticated(authenticated);

        let closed = authenticated + Duration::from_secs(60);
        assert_eq!(
            state.next_delay(&backoff, TransientKind::Outage, closed),
            Duration::from_secs(3)
        );
    }

    // oracle: intent crates/agent-channel-client/INTENT.md §Connection
    #[test]
    fn the_default_spread_stays_within_0_and_30_s() {
        let draws: Vec<Duration> = (0..1000).map(|_| uniform_spread()).collect();
        assert!(draws.iter().all(|draw| *draw <= Duration::from_secs(30)), "{draws:?}");
        assert!(
            draws.iter().any(|draw| *draw < Duration::from_secs(5))
                && draws.iter().any(|draw| Duration::from_secs(25) < *draw)
        );
    }
}
