//! The wait for a UniGetUI rescan once a package operation has its final result.
//!
//! See "Inventory rescan" in the package-management contract.
//! The rescan lets the next inventory show what the operation changed.
//! It is best effort: its outcome is logged and never changes the operation's recorded result.

use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::time::Instant;

/// Longest time an operation's report is held back for the rescan.
const RESCAN_WAIT: Duration = Duration::from_secs(3 * 60);

/// Operations that may wait for a rescan at the same time.
#[cfg(windows)]
const MAX_WAITING_RESCANS: usize = 8;

/// Returns the process-wide permits of the operations that wait for a rescan.
///
/// The pool is separate from the request workers', so a wait never takes a slot that serves a request.
// UNTESTED: At most `MAX_WAITING_RESCANS` operations wait for a rescan at once, which bounds how many reports are held back.
// The tests pass their own pool; check that every wait takes its permit from this one when changing the callers.
#[cfg(windows)]
#[cfg_attr(test, expect(dead_code, reason = "called by the package-operation path"))]
pub(super) fn waiting_rescans() -> &'static Semaphore {
    static WAITING_RESCANS: Semaphore = Semaphore::const_new(MAX_WAITING_RESCANS);
    &WAITING_RESCANS
}

/// The UniGetUI connection that carried a package operation.
pub(super) trait RescanEndpoint {
    /// Asks UniGetUI to reload its package lists and resolves with its answer.
    async fn rescan(&self) -> anyhow::Result<()>;
}

// UNTESTED: The rescan goes out on the registered connection it is asked on, never on another one of the same user.
// The tests cannot build a registered endpoint; check a rescan against a running UniGetUI when changing this.
#[cfg(windows)]
impl RescanEndpoint for now_package_broker::registration::RegisteredEndpoint {
    async fn rescan(&self) -> anyhow::Result<()> {
        Ok(self.rescan_inventory().await?)
    }
}

/// Asks UniGetUI for a rescan and holds the caller back until it is answered, the wait gives up or `shutdown` resolves.
///
/// The caller has recorded the final result of an operation that it sent on `endpoint`, and reports it afterwards.
/// `deadline` is the latest time that report may be held back to.
/// The wait gives up after [`RESCAN_WAIT`] or at `deadline`, whichever comes first.
/// The rescan is requested even when `deadline` has passed, because a later inventory still benefits from it.
/// For the same reason, a wait that ends before the answer does not withdraw the rescan.
/// A permit from `waiting` is held for the duration of the wait, and no rescan is requested when none is free.
/// Nothing is returned, because no outcome of the rescan changes the recorded result.
pub(super) async fn after_operation(
    waiting: &Semaphore,
    endpoint: &impl RescanEndpoint,
    deadline: Instant,
    shutdown: impl Future<Output = ()>,
) {
    // UNTESTED: The cap applied to operations is `RESCAN_WAIT`, and a longer one delays every operation's result.
    // The tests cannot pause the clock to observe three minutes; check that this argument stays `RESCAN_WAIT`.
    wait_for_rescan(waiting, endpoint, RESCAN_WAIT, deadline, shutdown).await;
}

/// Performs the wait of [`after_operation`], giving up after `longest` or at `deadline`, whichever comes first.
async fn wait_for_rescan(
    waiting: &Semaphore,
    endpoint: &impl RescanEndpoint,
    longest: Duration,
    deadline: Instant,
    shutdown: impl Future<Output = ()>,
) {
    let Ok(_permit) = waiting.try_acquire() else {
        warn!("Too many operations wait for a UniGetUI rescan, so none is requested");
        return;
    };

    // Shutdown is polled first, so a stop that is already signalled requests no rescan.
    // The rescan is polled before the timer, so it is requested even when the wait has no time left.
    // UNTESTED: Each ending but a completed rescan and a shutdown is logged as a warning, the only trace that a rescan is missing.
    // The tests do not capture logs; keep a warning on the rejected, unanswered and no-permit paths when changing them.
    tokio::select! {
        biased;
        () = shutdown => debug!("Stopped waiting for the UniGetUI rescan because the Agent is shutting down"),
        outcome = endpoint.rescan() => match outcome {
            Ok(()) => debug!("UniGetUI rescan completed"),
            Err(error) => warn!(error = format!("{error:#}"), "UniGetUI rescan did not complete"),
        },
        () = tokio::time::sleep_until(wait_end(Instant::now(), longest, deadline)) => {
            warn!("UniGetUI rescan was not answered in time");
        }
    }
}

/// Returns when a wait of at most `longest` that starts at `now` gives up.
fn wait_end(now: Instant, longest: Duration, deadline: Instant) -> Instant {
    deadline.min(now + longest)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::future::pending;

    use rstest::rstest;

    use super::*;

    /// A UniGetUI connection that counts the rescans it is asked for.
    struct FakeEndpoint {
        /// The delay and the answer of every rescan; `None` never answers.
        answer: Option<(Duration, Result<(), &'static str>)>,
        asked: Cell<u32>,
    }

    impl FakeEndpoint {
        fn answering(after: Duration, answer: Result<(), &'static str>) -> Self {
            Self {
                answer: Some((after, answer)),
                asked: Cell::new(0),
            }
        }

        fn silent() -> Self {
            Self {
                answer: None,
                asked: Cell::new(0),
            }
        }
    }

    impl RescanEndpoint for FakeEndpoint {
        async fn rescan(&self) -> anyhow::Result<()> {
            self.asked.set(self.asked.get() + 1);
            let Some((after, answer)) = self.answer else {
                return pending().await;
            };
            tokio::time::sleep(after).await;
            answer.map_err(anyhow::Error::msg)
        }
    }

    const THIRTY_MINUTES: Duration = Duration::from_secs(30 * 60);

    /// Longest real time a wait may take in a test, far below the three minutes it must not reach.
    const GUARD: Duration = Duration::from_secs(20);

    /// Runs the wait and returns how long it took.
    async fn wait_time(
        waiting: &Semaphore,
        endpoint: &FakeEndpoint,
        deadline: Instant,
        shutdown: impl Future<Output = ()>,
    ) -> Duration {
        let start = Instant::now();
        tokio::time::timeout(GUARD, after_operation(waiting, endpoint, deadline, shutdown))
            .await
            .expect("the wait ends long before three minutes");
        start.elapsed()
    }

    #[rstest]
    #[case::completed(Ok(()))]
    #[case::rejected(Err("rejected with code UnsupportedCommand"))]
    #[tokio::test]
    async fn response_ends_the_wait_without_another_request(#[case] answer: Result<(), &'static str>) {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let endpoint = FakeEndpoint::answering(Duration::from_millis(50), answer);
        let deadline = Instant::now() + THIRTY_MINUTES;

        let waited = wait_time(&Semaphore::new(1), &endpoint, deadline, pending()).await;

        assert!(Duration::from_millis(50) <= waited, "{waited:?}");
        assert_eq!(endpoint.asked.get(), 1);
    }

    #[rstest]
    #[case::deadline_far_away(THIRTY_MINUTES, Duration::from_secs(3 * 60))]
    #[case::deadline_sooner_than_three_minutes(Duration::from_secs(40), Duration::from_secs(40))]
    fn wait_gives_up_after_three_minutes_or_at_the_deadline(#[case] time_left: Duration, #[case] longest: Duration) {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let now = Instant::now();

        assert_eq!(wait_end(now, RESCAN_WAIT, now + time_left), now + longest);
    }

    #[tokio::test]
    async fn unanswered_rescan_holds_the_wait_no_longer_than_its_cap() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let waiting = Semaphore::new(1);
        let endpoint = FakeEndpoint::silent();
        let longest = Duration::from_millis(50);
        let start = Instant::now();
        let deadline = start + THIRTY_MINUTES;

        let wait = wait_for_rescan(&waiting, &endpoint, longest, deadline, pending());
        tokio::time::timeout(GUARD, wait)
            .await
            .expect("the wait gives up long before the deadline");

        let waited = start.elapsed();
        assert!(longest <= waited, "{waited:?}");
        assert_eq!(endpoint.asked.get(), 1);
    }

    #[tokio::test]
    async fn unanswered_rescan_holds_the_wait_until_the_deadline() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let endpoint = FakeEndpoint::silent();
        let deadline = Instant::now() + Duration::from_millis(100);

        wait_time(&Semaphore::new(1), &endpoint, deadline, pending()).await;

        assert!(deadline <= Instant::now(), "the wait lasts until the deadline");
        assert_eq!(endpoint.asked.get(), 1);
    }

    #[tokio::test]
    async fn passed_deadline_still_requests_the_rescan() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let endpoint = FakeEndpoint::silent();
        let deadline = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("the clock started more than a second ago");

        wait_time(&Semaphore::new(1), &endpoint, deadline, pending()).await;

        assert_eq!(endpoint.asked.get(), 1);
    }

    #[tokio::test]
    async fn shutdown_ends_the_wait() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let endpoint = FakeEndpoint::silent();
        let deadline = Instant::now() + THIRTY_MINUTES;
        let shutdown = tokio::time::sleep(Duration::from_millis(50));

        wait_time(&Semaphore::new(1), &endpoint, deadline, shutdown).await;

        assert_eq!(endpoint.asked.get(), 1);
    }

    #[tokio::test]
    async fn call_without_a_free_permit_requests_no_rescan() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let waiting = Semaphore::new(1);
        let _held = waiting.try_acquire().expect("the permit is free");
        let endpoint = FakeEndpoint::silent();
        let deadline = Instant::now() + THIRTY_MINUTES;

        wait_time(&waiting, &endpoint, deadline, pending()).await;

        assert_eq!(endpoint.asked.get(), 0);
    }

    #[tokio::test]
    async fn wait_holds_one_permit_and_returns_it() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let waiting = Semaphore::new(2);
        let endpoint = FakeEndpoint::silent();
        let deadline = Instant::now() + THIRTY_MINUTES;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let shutdown = async {
            let _ = stopped.await;
        };

        let (_, free_while_waiting) = tokio::join!(wait_time(&waiting, &endpoint, deadline, shutdown), async {
            while endpoint.asked.get() == 0 {
                tokio::task::yield_now().await;
            }
            let free = waiting.available_permits();
            let _ = stop.send(());
            free
        });

        assert_eq!(free_while_waiting, 1);
        assert_eq!(waiting.available_permits(), 2);
    }
}
