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

/// Start the named pipe server and accept connections until shutdown.
pub async fn run_pipe_server(state: Arc<BrokerState>, shutdown: CancellationToken) -> anyhow::Result<()> {
    let pipe_name = state.pipe_name.clone();
    info!(%pipe_name, "Starting named pipe server");

    let connection_permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    let mut first_instance = true;
    loop {
        // Wait for a free connection slot before exposing a new pipe instance,
        // bounding the number of concurrently served connections.
        let permit = tokio::select! {
            permit = Arc::clone(&connection_permits).acquire_owned() => {
                permit.expect("the semaphore is never closed")
            }
            _ = shutdown.cancelled() => {
                info!("Pipe server shutting down");
                return Ok(());
            }
        };

        // Create a new pipe instance for each connection.
        let server = create_pipe_instance(&pipe_name, first_instance)?;
        first_instance = false;

        tokio::select! {
            result = server.connect() => {
                match result {
                    Ok(()) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            let serve = async move {
                                // Capture may open a network-backed executable path. Keep
                                // that blocking work off the accept loop and retain the
                                // connection slot until it completes, even after a timeout.
                                let skip_signature_validation = state.skip_signature_validation;
                                let capture = spawn_bounded_capture(permit, move || {
                                    let client = PipeClient::from_connected_pipe(&server, skip_signature_validation);
                                    (server, client)
                                });
                                let (_permit, server, client) = match capture.await {
                                    Ok((permit, (server, Ok(client)))) => (permit, server, client),
                                    Ok((_permit, (_server, Err(error)))) => {
                                        warn!(%error, "Rejected named pipe client");
                                        return;
                                    }
                                    Err(error) => {
                                        error!(%error, "Named pipe client identity capture task failed");
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
            _ = shutdown.cancelled() => {
                info!("Pipe server shutting down");
                return Ok(());
            }
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
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

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
