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
use tracing::{debug, error, info, warn};
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::security::acl::{Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee};
use win_api_wrappers::security::attributes::SecurityAttributesInit;
use windows::Win32::Foundation::GENERIC_ALL;
use windows::Win32::Security;
use windows::Win32::Security::Authorization::SET_ACCESS;
use windows::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA};

use crate::auth::{PipeClient, connected_pipe_client_user_sid};
use crate::server::{BrokerState, build_busy_router, build_router_for_client, serve_connection};

/// Default pipe name for the package broker.
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\Devolutions.Now.PackageBroker.v1";

/// Maximum number of concurrently served pipe connections.
///
/// Connection setup performs unauthenticated work (client process identity lookups)
/// before any signature gate, so a connection flood could otherwise trigger unbounded
/// work and task spawning. While all slots are taken, further clients receive a busy
/// reply, so a server instance keeps listening on the pipe name.
const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Maximum number of concurrently served connections per client user.
///
/// Keeps a single user from holding every connection slot.
const MAX_CONCURRENT_CONNECTIONS_PER_USER: usize = 4;

/// Maximum number of concurrent busy replies to clients over the connection limit.
///
/// Beyond this, further clients are disconnected without a reply.
const MAX_CONCURRENT_BUSY_REPLIES: usize = 16;

/// Deadline for sending a busy reply, from accept to response completion.
const BUSY_REPLY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Consecutive connect failures tolerated before the accept loop backs off.
const CONNECT_FAILURES_BEFORE_BACKOFF: u32 = 3;

/// Initial and maximum delays between connect attempts after repeated connect failures.
const CONNECT_RETRY_INITIAL_DELAY: std::time::Duration = std::time::Duration::from_millis(10);
const CONNECT_RETRY_MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// Minimum interval between two connect failure log entries.
const CONNECT_FAILURE_REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

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

    let user_slots = Arc::new(UserConnectionSlots::new(MAX_CONCURRENT_CONNECTIONS_PER_USER));
    let busy_replies = Arc::new(Semaphore::new(MAX_CONCURRENT_BUSY_REPLIES));

    accept_loop(
        &pipe_name,
        shutdown,
        AcceptLimits {
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            busy_replies: Arc::clone(&busy_replies),
        },
        &create_pipe_instance,
        RetryDelay::default(),
        |server, admission| {
            // Reap the connections that already finished, so completed tasks do not accumulate here
            // for the lifetime of the process.
            while connections.try_join_next().is_some() {}

            let permit = match admission {
                Admission::Serve(permit) => permit,
                Admission::Busy(permit) => {
                    connections.spawn(send_busy_reply(server, permit));
                    return;
                }
            };

            let state = Arc::clone(state);
            let user_slots = Arc::clone(&user_slots);
            let busy_replies = Arc::clone(&busy_replies);
            let connection_deadline = tokio::time::Instant::now() + CONNECTION_DEADLINE;
            connections.spawn(async move {
                // Serving this connection can commit a policy and record its terminal
                // event, which is blocking work the shutdown cannot interrupt, so the
                // lease keeps the recorder from closing the queue under that event.
                let _audit_lease = crate::audit::AuditLease::acquire();

                let serve = async move {
                    // Keep blocking unauthenticated work off the accept loop and retain
                    // the connection slots until that work actually completes. The client
                    // user is looked up first, so that the per-user limit applies before
                    // the expensive identity capture.
                    let lookup = spawn_bounded_capture(permit, move || {
                        let user_sid = connected_pipe_client_user_sid(&server);
                        (server, user_sid)
                    });
                    let (permit, server, user_sid) = match lookup.await {
                        Ok((permit, (server, Ok(user_sid)))) => (permit, server, user_sid),
                        Ok((_permit, (_server, Err(error)))) => {
                            warn!(error = format!("{error:#}"), "Rejected named pipe client");
                            return;
                        }
                        Err(error) => {
                            error!(
                                error = format!("{error:#}"),
                                "Named pipe client user lookup task failed"
                            );
                            return;
                        }
                    };

                    let Some(user_slot) = user_slots.try_acquire(&user_sid) else {
                        warn!(
                            %user_sid,
                            "Rejected named pipe client: too many concurrent connections for the user"
                        );
                        // Release the connection slot so the busy reply cannot hold it for other users.
                        drop(permit);
                        if let Ok(busy_permit) = Arc::clone(&busy_replies).try_acquire_owned() {
                            send_busy_reply(server, busy_permit).await;
                        }
                        return;
                    };

                    let capture = spawn_bounded_capture((permit, user_slot), move || {
                        let client = PipeClient::from_connected_pipe(&server);
                        (server, client)
                    });
                    let (_slots, server, client) = match capture.await {
                        Ok((slots, (server, Ok(client)))) => (slots, server, client),
                        Ok((_slots, (_server, Err(error)))) => {
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
                    if *client.user_sid() != user_sid {
                        warn!(
                            %user_sid,
                            captured_user_sid = %client.user_sid(),
                            "Rejected named pipe client: user changed while its identity was captured"
                        );
                        return;
                    }

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

/// Concurrency limits applied by [`accept_loop`].
struct AcceptLimits {
    /// Connections served concurrently.
    max_connections: usize,
    /// Slots for busy replies to clients over a connection limit, shared with the per-user limit.
    busy_replies: Arc<Semaphore>,
}

/// Answer a client over a connection limit with a busy reply, holding a busy reply slot.
async fn send_busy_reply(server: NamedPipeServer, permit: OwnedSemaphorePermit) {
    let _permit = permit;
    if tokio::time::timeout(BUSY_REPLY_DEADLINE, serve_connection(server, build_busy_router()))
        .await
        .is_err()
    {
        debug!("Closed named pipe busy reply: deadline exceeded");
    }
}

/// How a connected client handed off by [`accept_loop`] must be handled.
enum Admission {
    /// Serve the client, holding a connection slot.
    Serve(OwnedSemaphorePermit),
    /// Send the client a busy reply, holding a busy reply slot.
    Busy(OwnedSemaphorePermit),
}

/// Accept clients on `pipe_name` until `shutdown` is cancelled, handing each one to `dispatch`.
///
/// The pipe name always keeps a listening server instance owned by this loop.
/// Two instances listen at once, so that a client can connect while the other one is
/// handed off: the remaining instance keeps listening and a new spare is created right
/// after the handoff. A burst of more simultaneous clients than listening instances can
/// still briefly see `ERROR_PIPE_BUSY`, which clients wait out with `WaitNamedPipeW`,
/// as `NamedPipeClientStream.Connect` does.
/// A client that cannot be handed off is disconnected so that its instance listens again.
/// Clients over the connection limit are handed off for a busy reply while busy reply
/// slots remain. Instance failures are retried with backoff instead of ending the loop.
/// While a failed spare creation is backing off, the loop keeps listening and disconnects
/// the clients that arrive in the meantime. Repeated connect failures are rate-limited in
/// the log and slowed down with backoff.
async fn accept_loop(
    pipe_name: &str,
    shutdown: &CancellationToken,
    limits: AcceptLimits,
    create_instance: &(dyn Fn(&str, bool) -> anyhow::Result<NamedPipeServer> + Sync),
    mut retry: RetryDelay,
    mut dispatch: impl FnMut(NamedPipeServer, Admission),
) {
    let connection_permits = Arc::new(Semaphore::new(limits.max_connections));
    let busy_permits = limits.busy_replies;
    let mut connect_failures = ConnectFailures::default();

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
    let mut spare = SpareInstance::default();
    spare.replenish(pipe_name, create_instance, &mut retry);

    loop {
        let spare_retry_at = spare.retry_at;
        let (spare_connected, result) = tokio::select! {
            result = server.connect() => (false, result),
            result = async {
                match spare.instance.as_ref() {
                    Some(instance) => instance.connect().await,
                    None => std::future::pending().await,
                }
            } => (true, result),
            () = async move {
                match spare_retry_at {
                    Some(retry_at) => tokio::time::sleep_until(retry_at).await,
                    None => std::future::pending().await,
                }
            } => {
                spare.replenish(pipe_name, create_instance, &mut retry);
                continue;
            }
            _ = shutdown.cancelled() => return,
        };
        if spare_connected {
            // Continue with the connected instance as `server`, and the other one as the listening spare.
            if let Some(instance) = spare.instance.as_mut() {
                std::mem::swap(&mut server, instance);
            }
        }

        if let Err(error) = result {
            let action = connect_failures.record(std::time::Instant::now());
            match action.report {
                Some(0) => error!(%error, "Failed to accept pipe connection"),
                Some(suppressed) => error!(
                    %error,
                    suppressed,
                    "Failed to accept pipe connection; similar failures were suppressed"
                ),
                None => {}
            }
            if !recycle_instance(pipe_name, &mut server, create_instance) && !retry.wait(shutdown).await {
                return;
            }
            if let Some(delay) = action.delay {
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    () = shutdown.cancelled() => return,
                }
            }
            continue;
        }
        if let Some(suppressed) = connect_failures.reset() {
            warn!(
                suppressed,
                "Named pipe connections are accepted again after repeated failures"
            );
        }

        let admission = match Arc::clone(&connection_permits).try_acquire_owned() {
            Ok(permit) => Admission::Serve(permit),
            Err(_) => match Arc::clone(&busy_permits).try_acquire_owned() {
                Ok(permit) => {
                    warn!("Replying busy to named pipe client: too many concurrent connections");
                    Admission::Busy(permit)
                }
                Err(_) => {
                    warn!("Rejected named pipe client: too many concurrent connections and busy replies");
                    if !recycle_instance(pipe_name, &mut server, create_instance) && !retry.wait(shutdown).await {
                        return;
                    }
                    continue;
                }
            },
        };

        if spare
            .retry_at
            .is_some_and(|retry_at| tokio::time::Instant::now() >= retry_at)
        {
            spare.replenish(pipe_name, create_instance, &mut retry);
        }
        let Some(next) = spare.instance.take() else {
            warn!("Rejected named pipe client: waiting to retry the spare named pipe instance");
            drop(admission);
            if !recycle_instance(pipe_name, &mut server, create_instance) && !retry.wait(shutdown).await {
                return;
            }
            continue;
        };

        // The spare keeps listening, so the connected instance can be handed off.
        dispatch(std::mem::replace(&mut server, next), admission);
        spare.replenish(pipe_name, create_instance, &mut retry);
    }
}

/// A second listening pipe instance, so that clients can connect while another one is handed off.
#[derive(Default)]
struct SpareInstance {
    instance: Option<NamedPipeServer>,
    /// When to retry creating the spare after a failure, if it is missing.
    retry_at: Option<tokio::time::Instant>,
}

impl SpareInstance {
    /// Create the spare instance, or schedule another attempt with backoff.
    fn replenish(
        &mut self,
        pipe_name: &str,
        create_instance: &(dyn Fn(&str, bool) -> anyhow::Result<NamedPipeServer> + Sync),
        retry: &mut RetryDelay,
    ) {
        match create_instance(pipe_name, false) {
            Ok(instance) => {
                self.instance = Some(instance);
                self.retry_at = None;
                retry.reset();
            }
            Err(error) => {
                error!(
                    error = format!("{error:#}"),
                    "Failed to create a spare named pipe instance; retrying"
                );
                self.retry_at = Some(tokio::time::Instant::now() + retry.advance());
            }
        }
    }
}

/// What the accept loop does after a connect failure.
#[derive(Debug, PartialEq, Eq)]
struct ConnectFailureAction {
    /// Log the failure, with the number of failures suppressed since the last report.
    report: Option<u64>,
    /// Wait before listening again.
    delay: Option<std::time::Duration>,
}

/// Tracks consecutive connect failures to rate-limit their logs and slow the loop down.
struct ConnectFailures {
    consecutive: u32,
    suppressed: u64,
    last_report: Option<std::time::Instant>,
    delay: RetryDelay,
}

impl Default for ConnectFailures {
    fn default() -> Self {
        Self {
            consecutive: 0,
            suppressed: 0,
            last_report: None,
            delay: RetryDelay::new(CONNECT_RETRY_INITIAL_DELAY, CONNECT_RETRY_MAX_DELAY),
        }
    }
}

impl ConnectFailures {
    fn record(&mut self, now: std::time::Instant) -> ConnectFailureAction {
        self.consecutive = self.consecutive.saturating_add(1);

        let report = if self
            .last_report
            .is_none_or(|last| now.saturating_duration_since(last) >= CONNECT_FAILURE_REPORT_INTERVAL)
        {
            self.last_report = Some(now);
            Some(std::mem::take(&mut self.suppressed))
        } else {
            self.suppressed += 1;
            None
        };

        let delay = (self.consecutive > CONNECT_FAILURES_BEFORE_BACKOFF).then(|| self.delay.advance());

        ConnectFailureAction { report, delay }
    }

    /// Record a successful connect. Returns the number of unreported failures, if any.
    fn reset(&mut self) -> Option<u64> {
        if self.consecutive == 0 {
            return None;
        }
        self.consecutive = 0;
        self.delay.reset();
        let suppressed = std::mem::take(&mut self.suppressed);
        (suppressed > 0).then_some(suppressed)
    }
}

/// Per-user count of concurrently served connections.
struct UserConnectionSlots {
    max_per_user: usize,
    counts: parking_lot::Mutex<std::collections::HashMap<String, usize>>,
}

impl UserConnectionSlots {
    fn new(max_per_user: usize) -> Self {
        Self {
            max_per_user,
            counts: parking_lot::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Take a connection slot for `user_sid`, unless the user already holds all of theirs.
    fn try_acquire(self: &Arc<Self>, user_sid: &Sid) -> Option<UserConnectionSlot> {
        let key = user_sid.to_string();
        let mut counts = self.counts.lock();
        let count = counts.entry(key.clone()).or_insert(0);
        if *count >= self.max_per_user {
            return None;
        }
        *count += 1;

        Some(UserConnectionSlot {
            slots: Arc::clone(self),
            key,
        })
    }
}

/// A connection slot held by one user, released on drop.
struct UserConnectionSlot {
    slots: Arc<UserConnectionSlots>,
    key: String,
}

impl Drop for UserConnectionSlot {
    fn drop(&mut self) {
        let mut counts = self.slots.counts.lock();
        if let Some(count) = counts.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.key);
            }
        }
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

/// Run blocking `capture` work while holding `slots`, which are released only once the work completes.
fn spawn_bounded_capture<S, T, F>(slots: S, capture: F) -> JoinHandle<(S, T)>
where
    S: Send + 'static,
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(move || (slots, capture()))
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

    type Dispatched = (NamedPipeServer, Admission);

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

    fn limits(max_connections: usize, max_busy_replies: usize) -> AcceptLimits {
        AcceptLimits {
            max_connections,
            busy_replies: Arc::new(Semaphore::new(max_busy_replies)),
        }
    }

    fn spawn_accept_loop(
        pipe_name: &str,
        limits: AcceptLimits,
    ) -> (
        CancellationToken,
        tokio::sync::mpsc::UnboundedReceiver<Dispatched>,
        JoinHandle<()>,
    ) {
        spawn_accept_loop_with(pipe_name, limits, create_owned_test_instance, RetryDelay::default())
    }

    fn spawn_accept_loop_with(
        pipe_name: &str,
        limits: AcceptLimits,
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
                    limits,
                    &create_instance,
                    retry,
                    move |server, admission| {
                        dispatched_tx
                            .send((server, admission))
                            .expect("test holds the receiver");
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
        let (shutdown, mut dispatched, task) = spawn_accept_loop(&pipe_name, limits(2, 1));

        let _first_client = open_client_when_listening(&pipe_name).await;
        let first = next_dispatched(&mut dispatched).await;
        assert!(matches!(first.1, Admission::Serve(_)));

        // The next instance exists before the connected one is handed off, so no wait is needed.
        let _second_client = open_client(&pipe_name).expect("a listening instance follows each handoff");
        let second = next_dispatched(&mut dispatched).await;
        assert!(matches!(second.1, Admission::Serve(_)));

        // Over the connection limit, the client is handed off for a busy reply.
        let _busy_client = open_client(&pipe_name).expect("over-limit clients still find a listening instance");
        let busy = next_dispatched(&mut dispatched).await;
        assert!(matches!(busy.1, Admission::Busy(_)));

        // Over both limits, the client is accepted and disconnected, and the loop keeps listening.
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
    async fn accept_loop_keeps_a_spare_instance_for_clients_arriving_during_a_handoff() {
        use std::sync::atomic::AtomicUsize;

        let pipe_name = unique_pipe_name("spare");
        let created = Arc::new(AtomicUsize::new(0));
        let (shutdown, mut dispatched, task) = spawn_accept_loop_with(
            &pipe_name,
            limits(8, 0),
            {
                let created = Arc::clone(&created);
                move |pipe_name, first_instance| {
                    let instance = create_owned_test_instance(pipe_name, first_instance)?;
                    created.fetch_add(1, Ordering::SeqCst);
                    Ok(instance)
                }
            },
            RetryDelay::default(),
        );

        for round in 1..=2 {
            // Wait until the listening instance and its spare both exist.
            let expected = round * 2;
            let deadline = Instant::now() + Duration::from_secs(10);
            while created.load(Ordering::SeqCst) < expected {
                assert!(
                    Instant::now() < deadline,
                    "the spare instance is created (round {round})"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            // Two clients arriving at once both connect, without waiting for the loop to catch up.
            let _first = open_client(&pipe_name).expect("the listening instance accepts a client");
            let _second = open_client(&pipe_name).expect("the spare instance accepts a concurrent client");
            next_dispatched(&mut dispatched).await;
            next_dispatched(&mut dispatched).await;
        }

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the accept loop stops on shutdown")
            .expect("the accept loop does not panic");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_loop_keeps_listening_while_spare_instance_creation_backs_off() {
        use std::sync::atomic::AtomicUsize;

        use tokio::io::AsyncReadExt as _;

        let pipe_name = unique_pipe_name("backoff");
        let spare_attempts = Arc::new(AtomicUsize::new(0));
        let (shutdown, mut dispatched, task) = spawn_accept_loop_with(
            &pipe_name,
            limits(4, 4),
            {
                let spare_attempts = Arc::clone(&spare_attempts);
                move |pipe_name, first_instance| {
                    if first_instance {
                        create_owned_test_instance(pipe_name, true)
                    } else {
                        spare_attempts.fetch_add(1, Ordering::SeqCst);
                        anyhow::bail!("injected spare instance failure")
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
            spare_attempts.load(Ordering::SeqCst),
            1,
            "spare instance creation is not retried before the delay elapses"
        );
        assert!(
            dispatched.try_recv().is_err(),
            "no client is dispatched without a spare instance"
        );

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the accept loop stops on shutdown")
            .expect("the accept loop does not panic");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_loop_survives_a_connect_and_close_storm() {
        let pipe_name = unique_pipe_name("storm");
        let (shutdown, mut dispatched, task) = spawn_accept_loop(&pipe_name, limits(64, 0));

        drop(open_client_when_listening(&pipe_name).await);
        for _ in 0..50 {
            if let Ok(client) = open_client(&pipe_name) {
                drop(client);
            }
        }

        // Some storm clients may have been handed off; a regular client is still served afterwards.
        let _client = open_client_when_listening(&pipe_name).await;
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let (server, _admission) = next_dispatched(&mut dispatched).await;
            drop(server);
            if dispatched.is_empty() {
                break;
            }
        }
        assert!(!task.is_finished(), "the accept loop keeps running");

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the accept loop stops on shutdown")
            .expect("the accept loop does not panic");
    }

    #[test]
    fn connect_failures_back_off_and_rate_limit_their_log() {
        let mut failures = ConnectFailures::default();
        let start = Instant::now();

        let actions: Vec<_> = (0..6).map(|_| failures.record(start)).collect();
        assert_eq!(actions[0].report, Some(0), "the first failure is logged");
        assert!(
            actions[1..].iter().all(|action| action.report.is_none()),
            "repeats are suppressed"
        );
        let delays: Vec<_> = actions.iter().map(|action| action.delay).collect();
        assert_eq!(
            delays,
            [
                None,
                None,
                None,
                Some(CONNECT_RETRY_INITIAL_DELAY),
                Some(CONNECT_RETRY_INITIAL_DELAY * 2),
                Some(CONNECT_RETRY_INITIAL_DELAY * 4),
            ]
        );

        let later = failures.record(start + CONNECT_FAILURE_REPORT_INTERVAL);
        assert_eq!(
            later.report,
            Some(5),
            "a periodic report counts the suppressed failures"
        );

        assert_eq!(failures.reset(), None, "everything was reported");
        assert_eq!(failures.reset(), None);
        let after_reset = failures.record(start + CONNECT_FAILURE_REPORT_INTERVAL);
        assert_eq!(after_reset.delay, None, "backoff restarts after a success");
        assert_eq!(after_reset.report, None, "the log stays rate-limited across a success");
        assert_eq!(
            failures.reset(),
            Some(1),
            "unreported failures are summarized on recovery"
        );
    }

    #[test]
    fn user_connection_slots_are_capped_per_user() {
        let slots = Arc::new(UserConnectionSlots::new(2));
        let alice = Sid::from_well_known(Security::WinLocalSystemSid, None).expect("SYSTEM SID");
        let bob = Sid::from_well_known(Security::WinBuiltinUsersSid, None).expect("Users SID");

        let first = slots.try_acquire(&alice).expect("first slot");
        let _second = slots.try_acquire(&alice).expect("second slot");
        assert!(slots.try_acquire(&alice).is_none(), "the per-user cap is enforced");
        let _other = slots.try_acquire(&bob).expect("other users are not affected");

        drop(first);
        let _third = slots.try_acquire(&alice).expect("a released slot can be reused");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn busy_reply_is_a_well_formed_service_unavailable_response() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let pipe_name = unique_pipe_name("busy");
        let server = create_client_access_pipe(&pipe_name);
        let mut client = open_client(&pipe_name).expect("open client");
        server.connect().await.expect("accept client");
        let serving = tokio::spawn(serve_connection(server, build_busy_router()));

        client
            .write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut response))
            .await
            .expect("the busy reply completes promptly")
            .expect("read busy reply");
        let response = String::from_utf8(response).expect("UTF-8 response");

        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(
            response.to_ascii_lowercase().contains("\r\nretry-after: 1\r\n"),
            "{response}"
        );
        let body = response.split_once("\r\n\r\n").expect("response body").1;
        let error: now_policy_api::ErrorResponse = serde_json::from_str(body).expect("JSON error response");
        assert_eq!(error.code, now_policy_api::ErrorCode::BrokerPaused);

        serving.await.expect("serving task");
    }

    #[tokio::test]
    async fn connected_client_user_is_looked_up_from_the_pipe() {
        let pipe_name = unique_pipe_name("user");
        let server = create_client_access_pipe(&pipe_name);
        let _client = open_client(&pipe_name).expect("open client");
        server.connect().await.expect("accept client");

        let user_sid = connected_pipe_client_user_sid(&server).expect("look up the client user");

        assert!(user_sid == current_user_sid());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_connections_are_closed_after_the_header_timeout() {
        use tokio::io::AsyncReadExt as _;

        let pipe_name = unique_pipe_name("idle");
        let server = create_client_access_pipe(&pipe_name);
        let mut client = open_client(&pipe_name).expect("open client");
        server.connect().await.expect("accept client");

        let started = Instant::now();
        tokio::time::timeout(
            Duration::from_secs(10),
            crate::server::serve_connection_with_header_timeout(
                server,
                build_busy_router(),
                Duration::from_millis(200),
            ),
        )
        .await
        .expect("an idle connection is closed after the header timeout");
        assert!(started.elapsed() >= Duration::from_millis(200));

        let mut buffer = Vec::new();
        let _ = client.read_to_end(&mut buffer).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_loop_retries_until_it_owns_the_first_instance() {
        let pipe_name = unique_pipe_name("retry");
        let squatter = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)
            .expect("create the competing first instance");

        let (shutdown, mut dispatched, task) = spawn_accept_loop(&pipe_name, limits(1, 0));
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
