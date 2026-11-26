//! UniGetUI registration server.
//!
//! Serves the UniGetUI registration pipe described in the package-management contract.
//! A client is registered only after its connected process and pipe impersonation token agree on its identity.
//! Only then does the Agent send it `Request` frames, and it accepts a `Response` only for an outstanding request.
//! Registration itself issues no grant, and a response never establishes the identity of whoever wrote it.

mod dispatch;
mod protocol;
mod state;

use std::os::windows::io::AsRawHandle as _;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use win_api_wrappers::handle::HandleWrapper as _;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::security::acl::{Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee};
use win_api_wrappers::security::attributes::{SecurityAttributes, SecurityAttributesInit};
use win_api_wrappers::thread::Thread;
use win_api_wrappers::token::Token;
use windows::Win32::Foundation::{GENERIC_ALL, HANDLE};
use windows::Win32::Security::Authorization::{DENY_ACCESS, SET_ACCESS};
use windows::Win32::Security::{
    self, GetTokenInformation, SECURITY_IMPERSONATION_LEVEL, SecurityIdentification, TOKEN_QUERY,
    TokenImpersonationLevel,
};
use windows::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_WRITE_DATA};

pub use self::dispatch::RequestError;
use self::dispatch::{Dispatcher, Event};
pub use self::protocol::RemoteError;
use self::protocol::{Frame, MAX_FRAME_LEN, MAX_HELLO_LEN, OutgoingFrame, PROTOCOL_VERSION, ReadError};
use self::state::{Candidate, ProcessKey, Registry, Reservation};
pub use self::state::{RegisteredEndpoint, RegistrationHandle, RegistrationUnavailable};
use crate::auth::PipeClient;
use crate::impersonation::ThreadImpersonation;
use crate::pipe::spawn_bounded_capture;

/// Name of the registration pipe, separate from the broker execution pipe.
pub const DEFAULT_REGISTRATION_PIPE_NAME: &str = r"\\.\pipe\Devolutions.Now.PackageBroker.Registration.v1";

/// Time a client has to deliver `Hello` after connecting.
const HELLO_DEADLINE: Duration = Duration::from_secs(10);

/// Time the identity checks of a client that sent `Hello` may take.
const AUTHENTICATION_DEADLINE: Duration = Duration::from_secs(30);

/// Time a frame write may take before the peer is considered stalled.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Silence after which the Agent sends `Ping`.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Silence from the client after which the connection closes.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Connections that are still being identified.
///
/// Identification opens the client process and verifies its image, so unauthenticated clients must not queue unbounded work.
/// A client that connects while all slots are taken is disconnected and retries with backoff.
const MAX_PENDING_HANDSHAKES: usize = 16;

/// Delay before retrying after a pipe instance could not be created or accepted.
const INSTANCE_RETRY_DELAY: Duration = Duration::from_secs(1);

/// How long shutdown waits for connections before aborting them.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Name of the only executable that registers.
const UNIGETUI_EXECUTABLE: &str = "UniGetUI.exe";

/// Serves the registration pipe until `shutdown` is cancelled.
///
/// Fails without serving when the first pipe instance cannot be created, for example because another process owns the name.
/// The handle reports [`RegistrationUnavailable`] unless this function is serving.
pub async fn run_registration_server(
    handle: &RegistrationHandle,
    pipe_name: &str,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let first_instance =
        create_pipe_instance(pipe_name, true).context("failed to create the first registration pipe instance")?;

    let registry = Arc::clone(handle.registry());
    registry.set_available(true);
    let _unavailable_on_exit = UnavailableOnDrop(Arc::clone(&registry));
    info!(%pipe_name, "Serving UniGetUI registration");

    let handshakes = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    let mut connections = JoinSet::new();
    let mut listener = Some(first_instance);

    loop {
        // Reap finished connections so that completed tasks do not accumulate.
        while connections.try_join_next().is_some() {}

        let server = match listener.take() {
            Some(server) => server,
            None => match create_pipe_instance(pipe_name, false) {
                Ok(server) => server,
                Err(error) => {
                    error!(
                        error = format!("{error:#}"),
                        "Failed to create a registration pipe instance"
                    );
                    if !sleep_unless_cancelled(INSTANCE_RETRY_DELAY, &shutdown).await {
                        break;
                    }
                    continue;
                }
            },
        };

        let connected = tokio::select! {
            result = server.connect() => result,
            () = shutdown.cancelled() => break,
        };
        if let Err(error) = connected {
            warn!(%error, "Failed to accept a registration connection");
            if !sleep_unless_cancelled(INSTANCE_RETRY_DELAY, &shutdown).await {
                break;
            }
            continue;
        }

        // Keep an instance listening while this connection is served.
        listener = create_pipe_instance(pipe_name, false)
            .inspect_err(|error| {
                error!(
                    error = format!("{error:#}"),
                    "Failed to create a registration pipe instance"
                )
            })
            .ok();

        let Ok(permit) = Arc::clone(&handshakes).try_acquire_owned() else {
            debug!("Dropped a registration connection: too many connections are being identified");
            continue;
        };
        connections.spawn(serve_connection(
            Arc::clone(&registry),
            server,
            permit,
            shutdown.child_token(),
        ));
    }

    info!("UniGetUI registration is shutting down");
    let drained = tokio::time::timeout(SHUTDOWN_GRACE, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        connections.abort_all();
    }

    Ok(())
}

struct UnavailableOnDrop(Arc<Registry>);

impl Drop for UnavailableOnDrop {
    fn drop(&mut self) {
        self.0.set_available(false);
    }
}

async fn sleep_unless_cancelled(delay: Duration, shutdown: &CancellationToken) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => true,
        () = shutdown.cancelled() => false,
    }
}

async fn serve_connection(
    registry: Arc<Registry>,
    server: NamedPipeServer,
    permit: OwnedSemaphorePermit,
    shutdown: CancellationToken,
) {
    let result = tokio::select! {
        result = register_client(&registry, server, permit, &shutdown) => result,
        () = shutdown.cancelled() => return,
    };

    match result {
        Ok(()) => debug!("Closed a registration connection"),
        Err(error) => warn!(error = format!("{error:#}"), "Closed a registration connection"),
    }
}

/// Identifies the client, registers it and serves its connection until it closes.
///
/// Nothing is written and nothing is registered before the client is authenticated.
async fn register_client(
    registry: &Arc<Registry>,
    server: NamedPipeServer,
    permit: OwnedSemaphorePermit,
    shutdown: &CancellationToken,
) -> anyhow::Result<()> {
    let hello_deadline = Instant::now() + HELLO_DEADLINE;

    // The process is opened right after the connection, before any frame is read.
    // A timeout abandons the capture, whose task still holds the permit and the pipe until it finishes.
    let capture = spawn_bounded_capture(permit, move || {
        let client = PipeClient::from_connected_pipe(&server);
        (server, client)
    });
    let (permit, (mut server, client)) = tokio::time::timeout_at(hello_deadline, capture)
        .await
        .context("client process capture timed out")?
        .context("client process capture task failed")?;
    let client = client.context(
        "failed to capture the client process; UniGetUI requires an administrator-protected installation directory",
    )?;

    // Only a bounded Hello is read before impersonating the client, whose context is that of the last message read.
    let hello = tokio::time::timeout_at(hello_deadline, protocol::read_frame(&mut server, MAX_HELLO_LEN))
        .await
        .context("hello was not received in time")?
        .map_err(|error| anyhow::anyhow!("invalid first frame: {error}"))?;
    match hello {
        Frame::Hello {
            protocol_version: PROTOCOL_VERSION,
            ..
        } => {}
        Frame::Hello { .. } => bail!("unsupported protocol version"),
        Frame::Ping | Frame::Pong | Frame::Response { .. } => bail!("first frame is not hello"),
    }

    // The checks block on the process and local file system, so they run off the async threads.
    let authentication = spawn_bounded_capture(permit, move || {
        let identity = authenticate(&server, &client);
        (server, client, identity)
    });
    let (permit, (mut server, client, identity)) = tokio::time::timeout(AUTHENTICATION_DEADLINE, authentication)
        .await
        .context("client authentication timed out")?
        .context("client authentication task failed")?;
    let identity = identity.context("failed to authenticate the client")?;

    let live_client = client.clone();
    let reservation = registry
        .reserve(Candidate {
            process: ProcessKey {
                process_id: client.process_id(),
                creation_time: client.process_creation_time(),
            },
            user_sid: identity.user_sid,
            session_id: identity.session_id,
            display_name: identity.display_name,
            is_live: Arc::new(move || live_client.ensure_process_instance().is_ok()),
        })
        .map_err(|rejection| anyhow::anyhow!("connection limit reached: {rejection:?}"))?;

    send_frame(&mut server, OutgoingFrame::Welcome)
        .await
        .context("failed to send welcome")?;
    reservation.activate();
    drop(permit);
    info!(
        process_id = client.process_id(),
        session_id = identity.session_id,
        "Registered a UniGetUI endpoint"
    );

    // The process and image guards stay in `client` until the connection closes.
    let outcome = run_connection(server, &reservation, shutdown).await;
    drop(client);
    outcome
}

struct AuthenticatedClient {
    user_sid: Sid,
    session_id: u32,
    display_name: Option<String>,
}

/// Verifies the client process and the identity that the pipe itself attests.
///
/// UNTESTED: The checks below need a signed `UniGetUI.exe` running in a logged-on user session.
/// Check a signed unelevated, a signed elevated and an unsigned client in real sessions when changing them.
fn authenticate(server: &NamedPipeServer, client: &PipeClient) -> anyhow::Result<AuthenticatedClient> {
    let (pipe_sid, pipe_session_id) = pipe_client_identity(server)?;

    // The process ID only names the process that connected, so the token it holds must agree with the pipe's.
    let session_id = client.session_id();
    if pipe_sid != *client.user_sid() || pipe_session_id != session_id {
        bail!("pipe client identity does not match its process token");
    }

    // Never skipped, whatever the broker's debug setting for its execution pipe.
    client.validate_connection(false)?;

    let is_unigetui = client
        .executable_path()
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(UNIGETUI_EXECUTABLE));
    if !is_unigetui {
        bail!("client executable is not {UNIGETUI_EXECUTABLE}");
    }
    if client.is_elevated() {
        bail!("client is elevated");
    }
    crate::executor::ensure_session_user(session_id, &pipe_sid)?;
    client.ensure_process_instance()?;

    let display_name = client
        .display_name()
        .inspect_err(|error| {
            debug!(
                error = format!("{error:#}"),
                "Failed to resolve the registered account name"
            )
        })
        .ok();

    Ok(AuthenticatedClient {
        user_sid: pipe_sid,
        session_id,
        display_name,
    })
}

/// Returns the user SID and session of the pipe client, read from its impersonation token.
///
/// The server must have read from the pipe, and the client must connect with at least `SECURITY_IDENTIFICATION`.
/// The thread reverts to its own identity before this function returns.
fn pipe_client_identity(server: &NamedPipeServer) -> anyhow::Result<(Sid, u32)> {
    let (level, user_sid, session_id) = {
        let _impersonation = ThreadImpersonation::enter_named_pipe_client(HANDLE(server.as_raw_handle()))?;
        let token = Thread::current()
            .token(TOKEN_QUERY, true)
            .context("failed to open the pipe client impersonation token")?;
        (
            impersonation_level(&token)?,
            token
                .sid_and_attributes()
                .context("failed to query the pipe client user")?
                .sid,
            token.session_id().context("failed to query the pipe client session")?,
        )
    };
    ensure_identification_level(level)?;

    Ok((user_sid, session_id))
}

fn impersonation_level(token: &Token) -> anyhow::Result<SECURITY_IMPERSONATION_LEVEL> {
    let mut level = SECURITY_IMPERSONATION_LEVEL::default();
    let mut returned = 0;

    // SAFETY: The token is open for query and the buffer has the size of the requested information.
    unsafe {
        GetTokenInformation(
            token.handle().raw(),
            TokenImpersonationLevel,
            Some((&raw mut level).cast()),
            u32::try_from(size_of::<SECURITY_IMPERSONATION_LEVEL>()).expect("impersonation level size fits in u32"),
            &mut returned,
        )
    }
    .context("failed to query the pipe client impersonation level")?;

    Ok(level)
}

fn ensure_identification_level(level: SECURITY_IMPERSONATION_LEVEL) -> anyhow::Result<()> {
    if level.0 < SecurityIdentification.0 {
        bail!("pipe client does not allow identification");
    }
    Ok(())
}

/// Serves a registered connection: sends the queued requests, correlates their responses, answers pings and enforces liveness.
///
/// A `Response` that answers no outstanding request, a `Hello` and a `Request` close the connection, as does a request that times out.
/// Returns `Ok` when the client closes, a newer connection from its process replaces this one, or `shutdown` is cancelled.
async fn run_connection<IO>(io: IO, reservation: &Reservation, shutdown: &CancellationToken) -> anyhow::Result<()>
where
    IO: AsyncRead + AsyncWrite + Send + 'static,
{
    let mut dispatcher = Dispatcher::new(reservation.take_commands());
    let (mut reader, mut writer) = tokio::io::split(io);
    let (frames_tx, mut frames) = mpsc::channel(1);
    let _reader = AbortOnDrop(tokio::spawn(async move {
        loop {
            let frame = protocol::read_frame(&mut reader, MAX_FRAME_LEN).await;
            let last = frame.is_err();
            if frames_tx.send(frame).await.is_err() || last {
                break;
            }
        }
    }));

    let mut last_received = Instant::now();
    let mut last_sent = last_received;

    loop {
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = reservation.replaced() => {
                debug!("Replaced a registration connection of the same process");
                return Ok(());
            }
            () = tokio::time::sleep_until(last_received + IDLE_TIMEOUT) => bail!("no frame received within the idle timeout"),
            () = tokio::time::sleep_until(last_sent + PING_INTERVAL) => {
                send_frame(&mut writer, OutgoingFrame::Ping).await?;
                last_sent = Instant::now();
            }
            event = dispatcher.next_event() => match event {
                Event::Expired => {
                    dispatcher.fail_expired();
                    bail!("request timed out");
                }
                Event::Command(command) => {
                    if let Some(frame) = dispatcher.begin(command) {
                        send_bytes(&mut writer, &frame).await?;
                        last_sent = Instant::now();
                    }
                }
            },
            frame = frames.recv() => match frame {
                None => return Ok(()),
                Some(Err(ReadError::Io(error))) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Some(Err(error)) => bail!("{error}"),
                Some(Ok(frame)) => {
                    last_received = Instant::now();
                    match frame {
                        Frame::Ping => {
                            send_frame(&mut writer, OutgoingFrame::Pong).await?;
                            last_sent = Instant::now();
                        }
                        Frame::Pong => {}
                        Frame::Response { id, outcome } => {
                            if !dispatcher.complete(id, outcome) {
                                bail!("response answers no outstanding request");
                            }
                        }
                        Frame::Hello { .. } => bail!("unexpected hello frame"),
                    }
                }
            },
        }
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn send_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: OutgoingFrame) -> anyhow::Result<()> {
    send_bytes(writer, &protocol::encode_frame(frame)).await
}

async fn send_bytes<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> anyhow::Result<()> {
    tokio::time::timeout(WRITE_TIMEOUT, async {
        writer.write_all(bytes).await?;
        writer.flush().await
    })
    .await
    .context("frame write timed out")?
    .context("failed to write a frame")
}

fn create_pipe_instance(pipe_name: &str, first_instance: bool) -> anyhow::Result<NamedPipeServer> {
    let admins_sid = Sid::from_well_known(Security::WinBuiltinAdministratorsSid, None)
        .context("failed to create the Administrators SID")?;
    let users_sid =
        Sid::from_well_known(Security::WinBuiltinUsersSid, None).context("failed to create the Users SID")?;
    let security_attributes = build_security_attributes(Some(admins_sid), users_sid)?;

    // SAFETY: `security_attributes` owns a valid `SECURITY_ATTRIBUTES` that outlives the call, and `CreateNamedPipeW` copies the descriptor.
    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first_instance)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(pipe_name, security_attributes.as_mut_ptr().cast())
    }?;

    Ok(server)
}

/// Access granted to `BUILTIN\Users`.
///
/// `FILE_APPEND_DATA` is excluded: for a pipe it is `FILE_CREATE_PIPE_INSTANCE`, which would let a user serve the pipe name.
const PIPE_USER_ACCESS: u32 = FILE_GENERIC_READ.0 | FILE_WRITE_DATA.0;

/// Builds a descriptor that denies NETWORK, grants SYSTEM and `full_control_sid` full control, and grants `users_sid` read and write.
///
/// UNTESTED: Remote clients are rejected by `reject_remote_clients` and the NETWORK deny entry together.
/// Check a connection from another machine when changing either.
fn build_security_attributes(full_control_sid: Option<Sid>, users_sid: Sid) -> anyhow::Result<SecurityAttributes> {
    let system_sid =
        Sid::from_well_known(Security::WinLocalSystemSid, None).context("failed to create the SYSTEM SID")?;
    let network_sid =
        Sid::from_well_known(Security::WinNetworkSid, None).context("failed to create the NETWORK SID")?;

    let allow = |access_permissions, sid| ExplicitAccess {
        access_permissions,
        access_mode: SET_ACCESS,
        inheritance: Security::ACE_FLAGS(0),
        trustee: Trustee::Sid(sid),
    };

    let mut entries = vec![
        ExplicitAccess {
            access_permissions: GENERIC_ALL.0,
            access_mode: DENY_ACCESS,
            inheritance: Security::ACE_FLAGS(0),
            trustee: Trustee::Sid(network_sid),
        },
        allow(GENERIC_ALL.0, system_sid),
    ];
    if let Some(full_control_sid) = full_control_sid {
        entries.push(allow(GENERIC_ALL.0, full_control_sid));
    }
    entries.push(allow(PIPE_USER_ACCESS, users_sid));

    let dacl = Acl::new()
        .context("failed to create an empty ACL")?
        .set_entries(&entries)
        .context("failed to set ACL entries")?;

    Ok(SecurityAttributesInit {
        dacl: Some(InheritableAcl {
            kind: InheritableAclKind::Protected,
            acl: dacl,
        }),
        ..Default::default()
    }
    .init())
}

#[cfg(test)]
mod tests;
