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
use windows::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA};

use crate::auth::PipeClient;
use crate::server::{BrokerState, build_router_for_client, serve_connection};

/// Default pipe name for the package broker.
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\Devolutions.Now.PackageBroker.v1";

/// Maximum number of concurrently served pipe connections.
///
/// Connection setup performs unauthenticated work (client process identity lookups)
/// before any signature gate, so a connection flood could otherwise trigger unbounded
/// work and task spawning. While all slots are taken, further clients are accepted and
/// immediately disconnected, so a server instance keeps listening on the pipe name.
const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Initial delay before retrying after a pipe instance could not be created or recycled.
const INSTANCE_RETRY_INITIAL_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

/// Maximum delay between pipe instance retries.
const INSTANCE_RETRY_MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(30);

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
    // one of its exit paths reaches the drain below instead of returning straight out.
    let mut connections = tokio::task::JoinSet::new();
    let result = accept_connections(&state, &shutdown, &mut connections).await;

    drain_after_accept_loop(&mut connections, CONNECTION_SHUTDOWN_GRACE, result).await
}

/// Accept connections until `shutdown` is cancelled.
async fn accept_connections(
    state: &Arc<BrokerState>,
    shutdown: &CancellationToken,
    connections: &mut tokio::task::JoinSet<()>,
) -> anyhow::Result<()> {
    let pipe_name = state.pipe_name.clone();
    info!(%pipe_name, "Starting named pipe server");

    accept_loop(
        &pipe_name,
        shutdown,
        MAX_CONCURRENT_CONNECTIONS,
        &create_pipe_instance,
        RetryDelay::default(),
        |server, permit| {
            // Reap the connections that already finished, so completed tasks do not accumulate here
            // for the lifetime of the process.
            while connections.try_join_next().is_some() {}

            let state = Arc::clone(state);
            let connection_deadline = tokio::time::Instant::now() + CONNECTION_DEADLINE;
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
                if tokio::time::timeout_at(connection_deadline, serve).await.is_err() {
                    warn!("Closed named pipe connection: deadline exceeded");
                }
            });
        },
    )
    .await;

    info!("Pipe server shutting down");

    Ok(())
}

/// Accept clients on `pipe_name` until `shutdown` is cancelled, handing each one to `dispatch`.
///
/// The pipe name always keeps a listening server instance owned by this loop:
/// the next instance is created before a connected one is handed off, and a client
/// that cannot be served is disconnected so that its instance listens again.
/// Instance failures are retried with backoff instead of ending the loop.
/// While a failed next-instance creation is backing off, the loop keeps listening and
/// disconnects the clients that arrive in the meantime.
async fn accept_loop(
    pipe_name: &str,
    shutdown: &CancellationToken,
    max_connections: usize,
    create_instance: &(dyn Fn(&str, bool) -> anyhow::Result<NamedPipeServer> + Sync),
    mut retry: RetryDelay,
    mut dispatch: impl FnMut(NamedPipeServer, OwnedSemaphorePermit),
) {
    let connection_permits = Arc::new(Semaphore::new(max_connections));

    // The first instance claims the pipe name, so it alone is created with `first_pipe_instance`.
    let mut server = loop {
        match create_instance(pipe_name, true) {
            Ok(server) => break server,
            Err(error) => {
                error!(
                    error = format!("{error:#}"),
                    %pipe_name,
                    "Failed to create the first named pipe instance; retrying"
                );
                if !retry.wait(shutdown).await {
                    return;
                }
            }
        }
    };
    retry.reset();
    let mut next_instance_retry_at: Option<tokio::time::Instant> = None;

    loop {
        let result = tokio::select! {
            result = server.connect() => result,
            _ = shutdown.cancelled() => return,
        };

        if let Err(error) = result {
            error!(%error, "Failed to accept pipe connection");
            if !recycle_instance(pipe_name, &mut server, create_instance) && !retry.wait(shutdown).await {
                return;
            }
            continue;
        }

        let Ok(permit) = Arc::clone(&connection_permits).try_acquire_owned() else {
            warn!("Rejected named pipe client: too many concurrent connections");
            if !recycle_instance(pipe_name, &mut server, create_instance) && !retry.wait(shutdown).await {
                return;
            }
            continue;
        };

        if next_instance_retry_at.is_some_and(|retry_at| tokio::time::Instant::now() < retry_at) {
            warn!("Rejected named pipe client: waiting to retry the next named pipe instance");
            drop(permit);
            if !recycle_instance(pipe_name, &mut server, create_instance) && !retry.wait(shutdown).await {
                return;
            }
            continue;
        }

        // Create the next listening instance before handing off the connected one.
        let next = match create_instance(pipe_name, false) {
            Ok(next) => next,
            Err(error) => {
                error!(
                    error = format!("{error:#}"),
                    "Failed to create the next named pipe instance; disconnecting the client"
                );
                drop(permit);
                // Keep listening on this instance while the retry delay elapses.
                next_instance_retry_at = Some(tokio::time::Instant::now() + retry.advance());
                if !recycle_instance(pipe_name, &mut server, create_instance) && !retry.wait(shutdown).await {
                    return;
                }
                continue;
            }
        };
        retry.reset();
        next_instance_retry_at = None;

        dispatch(std::mem::replace(&mut server, next), permit);
    }
}

/// Make `server` listen again after a client that is not served.
///
/// Disconnects the client and reuses the instance. If that fails, the instance is replaced
/// by a new one created before the old one closes. Returns `false` when neither worked.
fn recycle_instance(
    pipe_name: &str,
    server: &mut NamedPipeServer,
    create_instance: &(dyn Fn(&str, bool) -> anyhow::Result<NamedPipeServer> + Sync),
) -> bool {
    let Err(error) = server.disconnect() else {
        return true;
    };

    warn!(%error, "Failed to disconnect named pipe instance; replacing it");
    match create_instance(pipe_name, false) {
        Ok(next) => {
            *server = next;
            true
        }
        Err(error) => {
            error!(
                error = format!("{error:#}"),
                "Failed to create a replacement named pipe instance"
            );
            false
        }
    }
}

/// Exponential backoff between pipe instance retries.
struct RetryDelay {
    initial: std::time::Duration,
    max: std::time::Duration,
    next: std::time::Duration,
}

impl Default for RetryDelay {
    fn default() -> Self {
        Self::new(INSTANCE_RETRY_INITIAL_DELAY, INSTANCE_RETRY_MAX_DELAY)
    }
}

impl RetryDelay {
    fn new(initial: std::time::Duration, max: std::time::Duration) -> Self {
        Self {
            initial,
            max,
            next: initial,
        }
    }

    fn reset(&mut self) {
        self.next = self.initial;
    }

    /// Return the current delay and double the next one.
    fn advance(&mut self) -> std::time::Duration {
        let delay = self.next;
        self.next = (self.next * 2).min(self.max);
        delay
    }

    /// Sleep for the current delay, then double it. Returns `false` when `shutdown` is cancelled first.
    async fn wait(&mut self, shutdown: &CancellationToken) -> bool {
        let delay = self.advance();

        tokio::select! {
            () = tokio::time::sleep(delay) => true,
            () = shutdown.cancelled() => false,
        }
    }
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

/// Access granted to `BUILTIN\Users` on the broker pipe.
///
/// Clients need to read, write data, and set the pipe read mode through `FILE_WRITE_ATTRIBUTES`.
/// `FILE_GENERIC_WRITE` is deliberately not granted because it includes `FILE_APPEND_DATA`,
/// which for named pipes is `FILE_CREATE_PIPE_INSTANCE`.
const PIPE_CLIENT_ACCESS: u32 = FILE_GENERIC_READ.0 | FILE_WRITE_DATA.0 | FILE_WRITE_ATTRIBUTES.0;

/// Build a security descriptor that grants:
/// - SYSTEM: full control
/// - Administrators: full control
/// - BUILTIN\Users: client read and write access, without the right to create pipe instances
fn build_pipe_security_attributes() -> anyhow::Result<win_api_wrappers::security::attributes::SecurityAttributes> {
    let users_sid = Sid::from_well_known(Security::WinBuiltinUsersSid, None).context("failed to create Users SID")?;
    let admins_sid = Sid::from_well_known(Security::WinBuiltinAdministratorsSid, None)
        .context("failed to create Administrators SID")?;

    build_security_attributes(Some(admins_sid), users_sid)
}

fn build_security_attributes(
    full_control_sid: Option<Sid>,
    client_sid: Sid,
) -> anyhow::Result<win_api_wrappers::security::attributes::SecurityAttributes> {
    let system_sid = Sid::from_well_known(Security::WinLocalSystemSid, None).context("failed to create SYSTEM SID")?;

    let mut entries = vec![ExplicitAccess {
        access_permissions: GENERIC_ALL.0,
        access_mode: SET_ACCESS,
        inheritance: Security::ACE_FLAGS(0),
        trustee: Trustee::Sid(system_sid),
    }];
    if let Some(full_control_sid) = full_control_sid {
        entries.push(ExplicitAccess {
            access_permissions: GENERIC_ALL.0,
            access_mode: SET_ACCESS,
            inheritance: Security::ACE_FLAGS(0),
            trustee: Trustee::Sid(full_control_sid),
        });
    }
    entries.push(ExplicitAccess {
        access_permissions: PIPE_CLIENT_ACCESS,
        access_mode: SET_ACCESS,
        inheritance: Security::ACE_FLAGS(0),
        trustee: Trustee::Sid(client_sid),
    });

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

    fn current_user_sid() -> Sid {
        use win_api_wrappers::process::Process;
        use windows::Win32::Security::TOKEN_QUERY;

        Process::current_process()
            .token(TOKEN_QUERY)
            .expect("open current process token")
            .sid_and_attributes()
            .expect("query current token user")
            .sid
    }

    fn unique_pipe_name(tag: &str) -> String {
        format!(
            r"\\.\pipe\Devolutions.Now.PackageBroker.test.{tag}.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos()
        )
    }

    /// Create a first pipe instance granting only client access to the current user,
    /// without the Administrators entry, so that the checks below hold for elevated test runs too.
    fn create_client_access_pipe(pipe_name: &str) -> NamedPipeServer {
        let security_attributes =
            build_security_attributes(None, current_user_sid()).expect("build pipe security attributes");

        // SAFETY: `security_attributes` owns a valid `SECURITY_ATTRIBUTES` that outlives the call.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .create_with_security_attributes_raw(pipe_name, security_attributes.as_mut_ptr().cast())
        }
        .expect("create first pipe instance")
    }

    /// Open a broker pipe client with the access the broker grants to standard users.
    fn open_client(pipe_name: &str) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
        use std::os::windows::fs::OpenOptionsExt as _;
        use std::os::windows::io::IntoRawHandle as _;

        use windows::Win32::Foundation::GENERIC_READ;
        use windows::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, SECURITY_IDENTIFICATION};

        let file = std::fs::OpenOptions::new()
            .access_mode(GENERIC_READ.0 | FILE_WRITE_DATA.0)
            .custom_flags(FILE_FLAG_OVERLAPPED.0)
            .security_qos_flags(SECURITY_IDENTIFICATION.0)
            .open(pipe_name)?;

        // SAFETY: The handle is a freshly opened, exclusively owned overlapped named pipe client handle.
        unsafe { tokio::net::windows::named_pipe::NamedPipeClient::from_raw_handle(file.into_raw_handle()) }
    }

    /// Open a client, waiting while the pipe does not exist yet or its instance is not listening.
    async fn open_client_when_listening(pipe_name: &str) -> tokio::net::windows::named_pipe::NamedPipeClient {
        use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY};

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match open_client(pipe_name) {
                Ok(client) => return client,
                Err(error)
                    if Instant::now() < deadline
                        && (error.raw_os_error() == Some(ERROR_PIPE_BUSY.0.cast_signed())
                            || error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND.0.cast_signed())) =>
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("failed to open {pipe_name}: {error}"),
            }
        }
    }

    type Dispatched = (NamedPipeServer, OwnedSemaphorePermit);

    /// Create an instance with the broker client ACE, plus full control for the current user
    /// so that a non-elevated test process can create additional instances like the service does.
    fn create_owned_test_instance(pipe_name: &str, first_instance: bool) -> anyhow::Result<NamedPipeServer> {
        let users_sid = Sid::from_well_known(Security::WinBuiltinUsersSid, None).context("Users SID")?;
        let security_attributes = build_security_attributes(Some(current_user_sid()), users_sid)?;

        // SAFETY: `security_attributes` owns a valid `SECURITY_ATTRIBUTES` that outlives the call.
        let server = unsafe {
            ServerOptions::new()
                .first_pipe_instance(first_instance)
                .create_with_security_attributes_raw(pipe_name, security_attributes.as_mut_ptr().cast())
        }?;

        Ok(server)
    }

    fn spawn_accept_loop(
        pipe_name: &str,
        max_connections: usize,
    ) -> (
        CancellationToken,
        tokio::sync::mpsc::UnboundedReceiver<Dispatched>,
        JoinHandle<()>,
    ) {
        spawn_accept_loop_with(
            pipe_name,
            max_connections,
            create_owned_test_instance,
            RetryDelay::default(),
        )
    }

    fn spawn_accept_loop_with(
        pipe_name: &str,
        max_connections: usize,
        create_instance: impl Fn(&str, bool) -> anyhow::Result<NamedPipeServer> + Send + Sync + 'static,
        retry: RetryDelay,
    ) -> (
        CancellationToken,
        tokio::sync::mpsc::UnboundedReceiver<Dispatched>,
        JoinHandle<()>,
    ) {
        let shutdown = CancellationToken::new();
        let (dispatched_tx, dispatched_rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn({
            let pipe_name = pipe_name.to_owned();
            let shutdown = shutdown.clone();
            async move {
                accept_loop(
                    &pipe_name,
                    &shutdown,
                    max_connections,
                    &create_instance,
                    retry,
                    move |server, permit| {
                        dispatched_tx.send((server, permit)).expect("test holds the receiver");
                    },
                )
                .await;
            }
        });
        (shutdown, dispatched_rx, task)
    }

    async fn next_dispatched(dispatched: &mut tokio::sync::mpsc::UnboundedReceiver<Dispatched>) -> Dispatched {
        tokio::time::timeout(Duration::from_secs(10), dispatched.recv())
            .await
            .expect("a connection is dispatched")
            .expect("the accept loop is running")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_loop_keeps_a_listening_instance_while_connections_are_held() {
        use tokio::io::AsyncReadExt as _;

        let pipe_name = unique_pipe_name("listen");
        let (shutdown, mut dispatched, task) = spawn_accept_loop(&pipe_name, 2);

        let _first_client = open_client_when_listening(&pipe_name).await;
        let first = next_dispatched(&mut dispatched).await;

        // The next instance exists before the connected one is handed off, so no wait is needed.
        let _second_client = open_client(&pipe_name).expect("a listening instance follows each handoff");
        let _second = next_dispatched(&mut dispatched).await;

        // Over the limit, the client is accepted and disconnected, and the loop keeps listening.
        let mut rejected = open_client(&pipe_name).expect("over-limit clients still find a listening instance");
        let mut buffer = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(10), rejected.read(&mut buffer))
            .await
            .expect("an over-limit client is disconnected promptly");
        assert!(matches!(read, Ok(0) | Err(_)), "unexpected read: {read:?}");
        assert!(
            dispatched.try_recv().is_err(),
            "an over-limit client must not be dispatched"
        );

        drop(first);
        let _third_client = open_client_when_listening(&pipe_name).await;
        let _third = next_dispatched(&mut dispatched).await;

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the accept loop stops on shutdown")
            .expect("the accept loop does not panic");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_loop_keeps_listening_while_next_instance_creation_backs_off() {
        use std::sync::atomic::AtomicUsize;

        use tokio::io::AsyncReadExt as _;

        let pipe_name = unique_pipe_name("backoff");
        let next_instance_attempts = Arc::new(AtomicUsize::new(0));
        let (shutdown, mut dispatched, task) = spawn_accept_loop_with(
            &pipe_name,
            4,
            {
                let next_instance_attempts = Arc::clone(&next_instance_attempts);
                move |pipe_name, first_instance| {
                    if first_instance {
                        create_owned_test_instance(pipe_name, true)
                    } else {
                        next_instance_attempts.fetch_add(1, Ordering::SeqCst);
                        anyhow::bail!("injected next instance failure")
                    }
                }
            },
            // Long enough that every client below arrives during the backoff.
            RetryDelay::new(Duration::from_secs(60), Duration::from_secs(60)),
        );

        for attempt in 0..3 {
            // The instance must be listening again promptly, well before the retry delay ends.
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut client = loop {
                match open_client(&pipe_name) {
                    Ok(client) => break client,
                    Err(_) if Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(10)).await,
                    Err(error) => panic!("no listening instance during backoff (attempt {attempt}): {error}"),
                }
            };
            let mut buffer = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buffer))
                .await
                .expect("the client is disconnected promptly");
            assert!(matches!(read, Ok(0) | Err(_)), "unexpected read: {read:?}");
        }

        assert_eq!(
            next_instance_attempts.load(Ordering::SeqCst),
            1,
            "next instance creation is not retried before the delay elapses"
        );
        assert!(
            dispatched.try_recv().is_err(),
            "no client is dispatched without a next instance"
        );

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the accept loop stops on shutdown")
            .expect("the accept loop does not panic");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_loop_retries_until_it_owns_the_first_instance() {
        let pipe_name = unique_pipe_name("retry");
        let squatter = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)
            .expect("create the competing first instance");

        let (shutdown, mut dispatched, task) = spawn_accept_loop(&pipe_name, 1);
        tokio::time::sleep(INSTANCE_RETRY_INITIAL_DELAY * 3).await;
        assert!(!task.is_finished(), "a failed first instance must be retried");
        drop(squatter);

        let _client = open_client_when_listening(&pipe_name).await;
        let _connection = next_dispatched(&mut dispatched).await;

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the accept loop stops on shutdown")
            .expect("the accept loop does not panic");
    }

    #[tokio::test]
    async fn retry_delay_doubles_up_to_the_maximum_and_resets() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let mut retry = RetryDelay::default();

        let mut delays = Vec::new();
        for _ in 0..12 {
            delays.push(retry.next);
            assert!(!retry.wait(&shutdown).await, "a cancelled shutdown interrupts the wait");
        }

        assert_eq!(delays[0], INSTANCE_RETRY_INITIAL_DELAY);
        assert_eq!(delays[1], INSTANCE_RETRY_INITIAL_DELAY * 2);
        assert_eq!(*delays.last().expect("delays"), INSTANCE_RETRY_MAX_DELAY);
        retry.reset();
        assert_eq!(retry.next, INSTANCE_RETRY_INITIAL_DELAY);
    }

    #[test]
    fn pipe_client_access_never_includes_pipe_instance_creation() {
        use windows::Win32::Storage::FileSystem::{FILE_APPEND_DATA, FILE_CREATE_PIPE_INSTANCE, FILE_GENERIC_WRITE};

        assert_eq!(PIPE_CLIENT_ACCESS & FILE_CREATE_PIPE_INSTANCE.0, 0);
        assert_eq!(PIPE_CLIENT_ACCESS & FILE_APPEND_DATA.0, 0);
        assert_ne!(PIPE_CLIENT_ACCESS & FILE_GENERIC_WRITE.0, FILE_GENERIC_WRITE.0);
    }

    #[tokio::test]
    async fn client_access_cannot_create_additional_pipe_instances() {
        let pipe_name = unique_pipe_name("instance");
        let _server = create_client_access_pipe(&pipe_name);

        let error = ServerOptions::new()
            .create(&pipe_name)
            .expect_err("client access must not allow creating another pipe instance");
        assert_eq!(
            error.raw_os_error(),
            Some(windows::Win32::Foundation::ERROR_ACCESS_DENIED.0.cast_signed())
        );
    }

    #[tokio::test]
    async fn client_access_allows_read_and_write_data_clients() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let pipe_name = unique_pipe_name("client");
        let mut server = create_client_access_pipe(&pipe_name);

        let mut client = open_client(&pipe_name).expect("open the pipe with GENERIC_READ | FILE_WRITE_DATA");
        server.connect().await.expect("accept the client");

        client.write_all(b"ping").await.expect("client write");
        let mut request = [0u8; 4];
        server.read_exact(&mut request).await.expect("server read");
        assert_eq!(&request, b"ping");

        server.write_all(b"pong").await.expect("server write");
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await.expect("client read");
        assert_eq!(&response, b"pong");
    }

    #[tokio::test]
    async fn client_access_rejects_generic_write_clients() {
        use tokio::net::windows::named_pipe::ClientOptions;

        let pipe_name = unique_pipe_name("generic");
        let _server = create_client_access_pipe(&pipe_name);

        let error = ClientOptions::new()
            .open(&pipe_name)
            .expect_err("GENERIC_WRITE requests FILE_CREATE_PIPE_INSTANCE, which clients are not granted");
        assert_eq!(
            error.raw_os_error(),
            Some(windows::Win32::Foundation::ERROR_ACCESS_DENIED.0.cast_signed())
        );
    }

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
