//! Named pipe transport for Windows.
//!
//! Creates a named pipe server with appropriate ACLs and accepts connections,
//! forwarding them to the HTTP server.

use std::sync::Arc;

use anyhow::Context as _;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::security::acl::{Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee};
use win_api_wrappers::security::attributes::SecurityAttributesInit;
use windows::Win32::Foundation::GENERIC_ALL;
use windows::Win32::Security;
use windows::Win32::Security::Authorization::SET_ACCESS;
use windows::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};

use crate::auth::PipeClient;
use crate::server::{BrokerState, build_router_for_client, serve_connection};

/// Default pipe name for the package broker.
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\Devolutions.Now.PackageBroker.v1";

/// Maximum number of concurrently served pipe connections.
///
/// Connection setup performs unauthenticated work (client process identity lookups)
/// before any signature gate, so a connection flood could otherwise trigger unbounded
/// work and task spawning. While all slots are taken, no pipe instance is listening and
/// further clients fail to connect until a slot frees up.
const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Deadline for serving a single pipe connection, from accept to response completion.
///
/// Each connection serves exactly one HTTP request (`keep_alive` is disabled) and all
/// endpoints respond without blocking on package operations (execution is asynchronous,
/// tracked via the operation tracker), so a healthy exchange completes well within this
/// deadline. Without it, idle clients holding their connection open without sending a
/// request would each pin a connection slot indefinitely and could exhaust the pool.
const CONNECTION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// How long shutdown waits for the connections that are still serving a request, then for the
/// aborted ones to actually stop.
///
/// A healthy exchange completes in milliseconds, and each connection is already bounded by
/// `CONNECTION_DEADLINE`, so this only has to cover the tail of a request already in progress;
/// connections still stuck at the end of it are aborted rather than allowed to hold the shutdown.
/// The same budget then bounds the wait for those aborts to take effect, so a connection stuck in
/// synchronous work costs the shutdown one grace period. Each connection holds an audit lease for
/// its whole lifetime, so the queued events of a connection the shutdown gave up on are flushed
/// instead of being dropped (see [`crate::audit::AuditLease`]).
const CONNECTION_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Start the named pipe server and accept connections until shutdown.
pub async fn run_pipe_server(state: Arc<BrokerState>, shutdown: CancellationToken) -> anyhow::Result<()> {
    // Serving a connection can record policy audit events, and the caller stops the audit recorder
    // as soon as this function returns, so a connection that outlives it must be known to the
    // recorder. Each connection holds an audit lease for as long as it can record, which keeps its
    // terminal event from being rejected. The accept loop runs in its own function, so that every
    // one of its exit paths, including a failure to create the next pipe instance, reaches the
    // drain below instead of returning straight out.
    let mut connections = tokio::task::JoinSet::new();
    let result = accept_connections(&state, &shutdown, &mut connections).await;

    drain_after_accept_loop(&mut connections, CONNECTION_SHUTDOWN_GRACE, result).await
}

/// Accept connections until `shutdown` is cancelled or the next pipe instance cannot be created.
async fn accept_connections(
    state: &Arc<BrokerState>,
    shutdown: &CancellationToken,
    connections: &mut tokio::task::JoinSet<()>,
) -> anyhow::Result<()> {
    let pipe_name = state.pipe_name.clone();
    info!(%pipe_name, "Starting named pipe server");

    let connection_permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    let mut first_instance = true;
    loop {
        // Reap the connections that already finished, so completed tasks do not accumulate here
        // for the lifetime of the process.
        while connections.try_join_next().is_some() {}

        // Wait for a free connection slot before exposing a new pipe instance,
        // bounding the number of concurrently served connections.
        let permit = tokio::select! {
            permit = Arc::clone(&connection_permits).acquire_owned() => {
                permit.expect("the semaphore is never closed")
            }
            _ = shutdown.cancelled() => break,
        };

        // Create a new pipe instance for each connection.
        let server = create_pipe_instance(&pipe_name, first_instance)?;
        first_instance = false;

        tokio::select! {
            result = server.connect() => {
                match result {
                    Ok(()) => {
                        let state = Arc::clone(state);
                        connections.spawn(async move {
                            // Serving this connection can commit a policy and record its terminal
                            // event, which is blocking work the shutdown cannot interrupt, so the
                            // lease keeps the recorder from closing the queue under that event.
                            let _audit_lease = crate::audit::AuditLease::acquire();

                            let serve = async move {
                                // Keep blocking unauthenticated capture off the accept loop and
                                // retain the connection slot until the work actually completes.
                                let capture = spawn_bounded_capture(permit, move || {
                                    let client = PipeClient::from_connected_pipe(&server);
                                    (server, client)
                                });
                                let (_permit, server, client) = match capture.await {
                                    Ok((permit, (server, Ok(client)))) => (permit, server, client),
                                    Ok((_permit, (_server, Err(error)))) => {
                                        warn!(error = format!("{error:#}"), "Rejected named pipe client");
                                        return;
                                    }
                                    Err(error) => {
                                        error!(
                                            error = format!("{error:#}"),
                                            "Named pipe client identity capture task failed"
                                        );
                                        return;
                                    }
                                };

                                info!("Client connected to named pipe");
                                let router = build_router_for_client(state, client);
                                serve_connection(server, router).await;
                                info!("Client disconnected from named pipe");
                            };

                            // Enforce a deadline so idle or slow clients cannot pin
                            // a connection slot indefinitely.
                            if tokio::time::timeout(CONNECTION_DEADLINE, serve).await.is_err() {
                                warn!("Closed named pipe connection: deadline exceeded");
                            }
                        });
                    }
                    Err(error) => {
                        error!(%error, "Failed to accept pipe connection");
                    }
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }

    info!("Pipe server shutting down");

    Ok(())
}

/// Drain the connections the accept loop spawned, then report what the loop returned.
///
/// An accept loop that fails after accepting a connection has to wait for that connection too,
/// rather than let the `?` on the failing call drop the set and abandon a served request mid-flight.
async fn drain_after_accept_loop(
    connections: &mut tokio::task::JoinSet<()>,
    grace: std::time::Duration,
    loop_result: anyhow::Result<()>,
) -> anyhow::Result<()> {
    wait_for_connections(connections, grace).await;

    loop_result
}

/// Wait for the connection tasks to finish, then abort the ones that outlive the grace.
///
/// Waiting is bounded on both sides: a task inside synchronous work, such as authenticating a
/// client or writing the policy storage, never reaches a cancellation point, so the settle after
/// the abort cannot be left unbounded either. A connection given up on here holds an audit lease,
/// so the recorder flushes its queued events and keeps accepting, rather than closing the queue
/// under the terminal event of the policy write that connection is still finishing. The agent
/// gives the whole shutdown a fixed budget before it stops the runtime.
async fn wait_for_connections(connections: &mut tokio::task::JoinSet<()>, grace: std::time::Duration) {
    let drained = tokio::time::timeout(grace, async { while connections.join_next().await.is_some() {} }).await;

    if drained.is_err() {
        warn!("Aborted named pipe connections still serving at shutdown");
        connections.abort_all();

        let settled = tokio::time::timeout(grace, async { while connections.join_next().await.is_some() {} }).await;

        if settled.is_err() {
            error!(
                "Named pipe connections are still running blocking work; their policy audit events may not reach the Windows Event Log before the agent stops the process"
            );
        }
    }
}

fn spawn_bounded_capture<T, F>(permit: OwnedSemaphorePermit, capture: F) -> JoinHandle<(OwnedSemaphorePermit, T)>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(move || (permit, capture()))
}

fn create_pipe_instance(pipe_name: &str, first_instance: bool) -> anyhow::Result<NamedPipeServer> {
    let security_attributes = build_pipe_security_attributes().context("failed to build pipe security attributes")?;

    // SAFETY: `create_with_security_attributes_raw` requires a pointer to a valid
    // `SECURITY_ATTRIBUTES` that stays alive for the duration of the call. The pointer
    // comes from `security_attributes` (a `win_api_wrappers::security::SecurityAttributes`),
    // a local binding that owns the structure and its security descriptor and is dropped
    // only at the end of this function, well after the call returns. `CreateNamedPipeW`
    // copies the descriptor at creation, so the pointer is not retained afterwards.
    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first_instance)
            .create_with_security_attributes_raw(pipe_name, security_attributes.as_mut_ptr().cast())
    }?;

    Ok(server)
}

/// Build a security descriptor that grants:
/// - SYSTEM: full control
/// - Administrators: full control
/// - BUILTIN\Users: read + write (allows interactive users to connect)
fn build_pipe_security_attributes() -> anyhow::Result<win_api_wrappers::security::attributes::SecurityAttributes> {
    let system_sid = Sid::from_well_known(Security::WinLocalSystemSid, None).context("failed to create SYSTEM SID")?;
    let admins_sid = Sid::from_well_known(Security::WinBuiltinAdministratorsSid, None)
        .context("failed to create Administrators SID")?;
    let users_sid = Sid::from_well_known(Security::WinBuiltinUsersSid, None).context("failed to create Users SID")?;

    let entries = [
        ExplicitAccess {
            access_permissions: GENERIC_ALL.0,
            access_mode: SET_ACCESS,
            inheritance: Security::ACE_FLAGS(0),
            trustee: Trustee::Sid(system_sid),
        },
        ExplicitAccess {
            access_permissions: GENERIC_ALL.0,
            access_mode: SET_ACCESS,
            inheritance: Security::ACE_FLAGS(0),
            trustee: Trustee::Sid(admins_sid),
        },
        ExplicitAccess {
            access_permissions: FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            access_mode: SET_ACCESS,
            inheritance: Security::ACE_FLAGS(0),
            trustee: Trustee::Sid(users_sid),
        },
    ];

    let empty_acl = Acl::new().context("failed to create empty ACL")?;
    let dacl = empty_acl.set_entries(&entries).context("failed to set ACL entries")?;

    let attrs = SecurityAttributesInit {
        dacl: Some(InheritableAcl {
            kind: InheritableAclKind::Protected,
            acl: dacl,
        }),
        ..Default::default()
    }
    .init();

    Ok(attrs)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use tokio::task::JoinSet;

    use super::*;

    /// Blocking work a connection can be stuck in that aborting it cannot interrupt.
    const NON_ABORTABLE_CONNECTION_WORK: Duration = Duration::from_secs(1);

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_capture_keeps_its_permit_until_blocking_work_finishes() {
        let permits = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&permits).acquire_owned().await.expect("acquire permit");
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let capture = spawn_bounded_capture(permit, move || {
            started_tx.send(()).expect("signal capture start");
            release_rx.recv().expect("wait for capture release");
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("blocking capture should start");

        assert!(tokio::time::timeout(Duration::from_millis(10), capture).await.is_err());
        assert_eq!(permits.available_permits(), 0);

        release_tx.send(()).expect("release blocking capture");
        for _ in 0..100 {
            if permits.available_permits() == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("detached capture did not release its permit after completing");
    }

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_waits_for_the_connections_that_are_still_serving() {
        let release = CancellationToken::new();
        let mut connections = JoinSet::new();
        connections.spawn({
            let release = release.clone();
            async move { release.cancelled().await }
        });

        let waited = tokio::spawn(async move {
            wait_for_connections(&mut connections, Duration::from_secs(30)).await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !waited.is_finished(),
            "the wait must last as long as a connection is being served"
        );

        release.cancel();
        tokio::time::timeout(Duration::from_secs(5), waited)
            .await
            .expect("the wait completes once the connection is done")
            .expect("the wait task does not panic");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_aborts_the_connections_that_outlive_the_grace() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mut connections = JoinSet::new();
        connections.spawn({
            let dropped = Arc::clone(&dropped);
            async move {
                let _flag = DropFlag(dropped);
                std::future::pending::<()>().await;
            }
        });

        let started = Instant::now();
        wait_for_connections(&mut connections, Duration::from_millis(200)).await;

        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "the grace must elapse first"
        );
        assert!(dropped.load(Ordering::SeqCst), "the connection task must be aborted");
        assert!(connections.is_empty(), "no connection task may outlive shutdown");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shutdown_gives_up_on_a_connection_stuck_in_blocking_work() {
        // A connection inside synchronous work, such as authenticating a client or reading the
        // policy storage, never reaches a cancellation point, so aborting it does not stop it.
        // The wait still has to return, because the caller drains the audit queue right after.
        let mut connections = JoinSet::new();
        connections.spawn(async {
            tokio::task::block_in_place(|| std::thread::sleep(NON_ABORTABLE_CONNECTION_WORK));
        });

        let started = Instant::now();
        wait_for_connections(&mut connections, Duration::from_millis(200)).await;

        // Returning with the task still in the set is the regression: an unbounded settle only
        // returns once every connection has finished.
        assert!(
            !connections.is_empty(),
            "the wait must not be held by a connection that cannot be aborted"
        );
        assert!(
            started.elapsed() < NON_ABORTABLE_CONNECTION_WORK,
            "the wait must return long before the blocking work is over"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_accept_loop_failure_waits_for_the_connections_it_accepted() {
        // Mirrors `create_pipe_instance` failing after a connection was accepted: the error may
        // reach the caller only once no connection can still record an audit event.
        let dropped = Arc::new(AtomicBool::new(false));
        let mut connections = JoinSet::new();
        connections.spawn({
            let dropped = Arc::clone(&dropped);
            async move {
                let _flag = DropFlag(dropped);
                std::future::pending::<()>().await;
            }
        });

        let started = Instant::now();
        let result = drain_after_accept_loop(
            &mut connections,
            Duration::from_millis(200),
            Err(anyhow::anyhow!("failed to create the next pipe instance")),
        )
        .await;

        assert!(result.is_err(), "the accept loop failure is still reported");
        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "the accepted connections have to settle first"
        );
        assert!(dropped.load(Ordering::SeqCst), "the connection task must be aborted");
        assert!(connections.is_empty(), "no connection task may outlive the accept loop");
    }

    #[tokio::test]
    async fn completed_capture_returns_its_permit_to_the_connection_task() {
        let permits = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&permits).acquire_owned().await.expect("acquire permit");

        let (permit, value) = spawn_bounded_capture(permit, || 42)
            .await
            .expect("join blocking capture");

        assert_eq!(value, 42);
        assert_eq!(permits.available_permits(), 0);
        drop(permit);
        assert_eq!(permits.available_permits(), 1);
    }
}
