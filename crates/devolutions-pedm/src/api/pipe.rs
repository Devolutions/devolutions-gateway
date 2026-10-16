//! PEDM named pipe server instances.

use std::convert::Infallible;
use std::os::windows::io::AsRawHandle as _;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use devolutions_pedm_shared::pipe::CLIENT_ACCESS;
use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;
use parking_lot::Mutex;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tracing::{error, info, warn};
use win_api_wrappers::handle::Handle;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::raw::Win32::Foundation::{GENERIC_ALL, HANDLE};
use win_api_wrappers::raw::Win32::Security::Authorization::SET_ACCESS;
use win_api_wrappers::raw::Win32::Security::{ACE_FLAGS, WinBuiltinUsersSid, WinLocalSystemSid};
use win_api_wrappers::security::acl::{Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee};
use win_api_wrappers::security::attributes::{SecurityAttributes, SecurityAttributesInit};
use win_api_wrappers::token::Token;

/// Number of pipe instances waiting for clients.
pub(super) const LISTENING_INSTANCES: usize = 4;

/// Initial delay before retrying after a pipe instance could not be created.
const INSTANCE_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(100);

/// Maximum delay between pipe instance retries.
const INSTANCE_RETRY_MAX_DELAY: Duration = Duration::from_secs(30);

/// Create a PEDM pipe instance with its security descriptor.
///
/// The first instance claims the pipe name and fails if the pipe already exists.
pub(super) fn create_pipe_instance(pipe_name: &str, first_instance: bool) -> anyhow::Result<NamedPipeServer> {
    let service_sid = Token::current_process_token()
        .sid_and_attributes()
        .context("failed to query the service identity")?
        .sid;
    let users_sid = Sid::from_well_known(WinBuiltinUsersSid, None).context("failed to create Users SID")?;
    let security_attributes = security_attributes(service_sid, users_sid)?.init();

    create_instance_with(pipe_name, first_instance, &security_attributes)
}

fn create_instance_with(
    pipe_name: &str,
    first_instance: bool,
    security_attributes: &SecurityAttributes,
) -> anyhow::Result<NamedPipeServer> {
    // SAFETY: `security_attributes` owns a valid `SECURITY_ATTRIBUTES` and its security descriptor,
    // and outlives the call. `CreateNamedPipeW` copies the descriptor, so the pointer is not retained.
    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first_instance)
            .create_with_security_attributes_raw(pipe_name, security_attributes.as_mut_ptr().cast())
    }?;

    Ok(server)
}

/// Build a security descriptor with a protected DACL that grants:
/// - SYSTEM and the service identity: full control;
/// - `client_sid`: [`CLIENT_ACCESS`], which does not allow creating pipe instances.
///
/// The owner is the default owner of the service token, which is Administrators for LocalSystem.
fn security_attributes(service_sid: Sid, client_sid: Sid) -> anyhow::Result<SecurityAttributesInit> {
    let system_sid = Sid::from_well_known(WinLocalSystemSid, None).context("failed to create SYSTEM SID")?;

    let entries = [
        (system_sid, GENERIC_ALL.0),
        (service_sid, GENERIC_ALL.0),
        (client_sid, CLIENT_ACCESS),
    ]
    .into_iter()
    .map(|(sid, access_permissions)| ExplicitAccess {
        access_permissions,
        access_mode: SET_ACCESS,
        inheritance: ACE_FLAGS(0),
        trustee: Trustee::Sid(sid),
    })
    .collect::<Vec<_>>();

    let dacl = Acl::new()
        .context("failed to create empty ACL")?
        .set_entries(&entries)
        .context("failed to set ACL entries")?;

    Ok(SecurityAttributesInit {
        dacl: Some(InheritableAcl {
            kind: InheritableAclKind::Protected,
            acl: dacl,
        }),
        ..Default::default()
    })
}

/// Keeps a pipe instance of this server open until dropped, through a duplicate of its handle.
///
/// The pipe name exists as long as one of these is alive, so instances created meanwhile join this server's pipe.
pub(super) struct OpenInstance {
    handle: Option<Handle>,
    open_instances: Arc<Mutex<usize>>,
}

impl OpenInstance {
    /// Create the next instance of `pipe_name`, claiming the name if this server has no open instance.
    fn create(
        pipe_name: &str,
        open_instances: &Arc<Mutex<usize>>,
        create_instance: &(dyn Fn(&str, bool) -> anyhow::Result<NamedPipeServer> + Sync),
    ) -> (bool, anyhow::Result<(NamedPipeServer, Self)>) {
        // Hold the lock across creation, so the last open instance cannot close in between.
        let mut count = open_instances.lock();
        let first_instance = *count == 0;

        let result = create_instance(pipe_name, first_instance).and_then(|server| {
            let handle = Handle::new_borrowed(HANDLE(server.as_raw_handle().cast()))?
                .try_clone()
                .context("failed to duplicate the pipe instance handle")?;
            *count += 1;
            Ok((
                server,
                Self {
                    handle: Some(handle),
                    open_instances: Arc::clone(open_instances),
                },
            ))
        });

        (first_instance, result)
    }
}

impl Drop for OpenInstance {
    fn drop(&mut self) {
        let mut count = self.open_instances.lock();
        drop(self.handle.take());
        *count -= 1;
    }
}

/// Accept clients on `pipe_name` forever, handing each one to `dispatch`.
///
/// Up to `listening_instances` instances wait for clients, and they are replenished as soon as clients connect.
/// Whenever none of this server's instances is open, the next one claims the pipe name again as a first instance,
/// so the server never joins a pipe it did not create.
/// Instance creation failures are logged and retried with backoff.
pub(super) async fn accept_loop(
    pipe_name: &str,
    listening_instances: usize,
    create_instance: &(dyn Fn(&str, bool) -> anyhow::Result<NamedPipeServer> + Sync),
    mut retry: RetryDelay,
    mut dispatch: impl FnMut(NamedPipeServer, OpenInstance),
) -> Infallible {
    let open_instances = Arc::new(Mutex::new(0));

    info!(%pipe_name, listening_instances, "Starting named pipe server");

    let mut listening = FuturesUnordered::new();

    loop {
        while listening.len() < listening_instances {
            match OpenInstance::create(pipe_name, &open_instances, create_instance) {
                (_, Ok((server, instance))) => {
                    retry.reset();
                    listening.push(async move {
                        let result = server.connect().await;
                        (server, instance, result)
                    });
                }
                (first_instance, Err(error)) => {
                    error!(
                        error = format!("{error:#}"),
                        %pipe_name,
                        first_instance,
                        "Failed to create a named pipe instance; retrying"
                    );
                    // Wait before retrying only when no instance is listening; otherwise retry after the next client.
                    if listening.is_empty() {
                        retry.wait().await;
                    }
                    break;
                }
            }
        }

        let Some((server, instance, result)) = listening.next().await else {
            continue;
        };

        match result {
            Ok(()) => dispatch(server, instance),
            Err(error) => warn!(%error, "Failed to accept a named pipe connection"),
        }
    }
}

/// Exponential backoff between pipe instance retries.
pub(super) struct RetryDelay {
    initial: Duration,
    max: Duration,
    next: Duration,
}

impl Default for RetryDelay {
    fn default() -> Self {
        Self::new(INSTANCE_RETRY_INITIAL_DELAY, INSTANCE_RETRY_MAX_DELAY)
    }
}

impl RetryDelay {
    fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max,
            next: initial,
        }
    }

    fn reset(&mut self) {
        self.next = self.initial;
    }

    /// Sleep for the current delay, then double the next one.
    async fn wait(&mut self) {
        let delay = self.next;
        self.next = (self.next * 2).min(self.max);
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::AsRawHandle as _;
    use std::time::Instant;

    use devolutions_pedm_shared::pipe::{
        open_client, server_process_id, service_process_id, verify_server, verify_server_process,
        verify_service_running,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use win_api_wrappers::handle::Handle;
    use win_api_wrappers::raw::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GENERIC_WRITE, HANDLE,
    };
    use win_api_wrappers::raw::Win32::Security::{SECURITY_IMPERSONATION_LEVEL, SecurityImpersonation, TOKEN_QUERY};
    use win_api_wrappers::raw::Win32::Storage::FileSystem::{
        FILE_APPEND_DATA, FILE_CREATE_PIPE_INSTANCE, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA,
        READ_CONTROL, SYNCHRONIZE,
    };
    use win_api_wrappers::thread::Thread;
    use win_api_wrappers::utils::Pipe;

    use super::*;

    fn current_user_sid() -> Sid {
        Token::current_process_token()
            .sid_and_attributes()
            .expect("query the current user")
            .sid
    }

    fn system_sid() -> Sid {
        Sid::from_well_known(WinLocalSystemSid, None).expect("SYSTEM SID")
    }

    fn users_sid() -> Sid {
        Sid::from_well_known(WinBuiltinUsersSid, None).expect("Users SID")
    }

    fn unique_pipe_name(tag: &str) -> String {
        format!(
            r"\\.\pipe\DevolutionsPEDM.test.{tag}.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos()
        )
    }

    /// Create a first instance with the production DACL, the service identity being SYSTEM,
    /// so the test process only gets the access granted to `BUILTIN\Users`.
    fn create_client_access_pipe(pipe_name: &str) -> NamedPipeServer {
        let security_attributes = security_attributes(system_sid(), users_sid())
            .expect("build pipe security attributes")
            .init();

        create_instance_with(pipe_name, true, &security_attributes).expect("create the first pipe instance")
    }

    /// Create an instance with the production DACL, the service identity being the current user,
    /// so a non-elevated test process can create instances like the service does.
    fn create_owned_test_instance(pipe_name: &str, first_instance: bool) -> anyhow::Result<NamedPipeServer> {
        let security_attributes = security_attributes(current_user_sid(), users_sid())?.init();

        create_instance_with(pipe_name, first_instance, &security_attributes)
    }

    async fn open_client_when_listening(pipe_name: &str) -> NamedPipeClient {
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

    type Dispatched = (NamedPipeServer, OpenInstance);

    fn spawn_accept_loop(
        pipe_name: &str,
        listening_instances: usize,
        create_instance: impl Fn(&str, bool) -> anyhow::Result<NamedPipeServer> + Send + Sync + 'static,
        retry: RetryDelay,
    ) -> (mpsc::UnboundedReceiver<Dispatched>, JoinHandle<()>) {
        let (dispatched_tx, dispatched_rx) = mpsc::unbounded_channel();
        let pipe_name = pipe_name.to_owned();
        let task = tokio::spawn(async move {
            let _ = accept_loop(
                &pipe_name,
                listening_instances,
                &create_instance,
                retry,
                move |server, instance| {
                    dispatched_tx
                        .send((server, instance))
                        .expect("the test holds the receiver");
                },
            )
            .await;
        });
        (dispatched_rx, task)
    }

    async fn next_dispatched(dispatched: &mut mpsc::UnboundedReceiver<Dispatched>) -> Dispatched {
        tokio::time::timeout(Duration::from_secs(10), dispatched.recv())
            .await
            .expect("a connection is dispatched")
            .expect("the accept loop is running")
    }

    #[test]
    fn client_access_does_not_allow_creating_pipe_instances() {
        assert_eq!(
            CLIENT_ACCESS,
            FILE_READ_DATA.0 | FILE_WRITE_DATA.0 | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0 | READ_CONTROL.0
        );
        assert_eq!(FILE_CREATE_PIPE_INSTANCE, FILE_APPEND_DATA);
        assert_eq!(CLIENT_ACCESS & FILE_APPEND_DATA.0, 0);
        assert_eq!(CLIENT_ACCESS & GENERIC_WRITE.0, 0);
    }

    #[tokio::test]
    async fn clients_can_exchange_data_and_be_identified() {
        let pipe_name = unique_pipe_name("client");
        let mut server = create_client_access_pipe(&pipe_name);

        let mut client = open_client(&pipe_name).expect("open the pipe with the client access");
        server.connect().await.expect("accept the client");

        client.write_all(b"ping").await.expect("client write");
        let mut request = [0u8; 4];
        server.read_exact(&mut request).await.expect("server read");
        assert_eq!(&request, b"ping");

        // The server needs a primary token of the client to serve its requests.
        let pipe = Pipe {
            handle: Handle::new_borrowed(HANDLE(server.as_raw_handle().cast())).expect("valid pipe handle"),
        };
        let token = pipe.client_primary_token().expect("obtain the client token");
        assert_eq!(
            token.sid_and_attributes().expect("query the client user").sid,
            current_user_sid()
        );
        assert_eq!(
            impersonated_level(&pipe),
            SecurityImpersonation,
            "the verified server can act as the client"
        );

        server.write_all(b"pong").await.expect("server write");
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await.expect("client read");
        assert_eq!(&response, b"pong");
    }

    #[tokio::test]
    async fn clients_cannot_create_pipe_instances() {
        let pipe_name = unique_pipe_name("instance");
        let _server = create_client_access_pipe(&pipe_name);

        let error = ServerOptions::new()
            .create(&pipe_name)
            .expect_err("a client cannot create another instance");
        assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED.0.cast_signed()));

        let error = ClientOptions::new()
            .open(&pipe_name)
            .expect_err("a client cannot open the pipe with GENERIC_WRITE");
        assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED.0.cast_signed()));
    }

    /// Impersonate the client connected to `pipe` and return the level its token grants the server.
    fn impersonated_level(pipe: &Pipe) -> SECURITY_IMPERSONATION_LEVEL {
        let _impersonation = pipe.impersonate_client().expect("impersonate the client");
        Thread::current()
            .token(TOKEN_QUERY, false)
            .expect("open the effective thread token")
            .statistics()
            .expect("query the token statistics")
            .ImpersonationLevel
    }

    #[tokio::test]
    async fn clients_reject_pipes_owned_by_a_standard_user() {
        let pipe_name = unique_pipe_name("owner");
        // Set the owner explicitly: an elevated test process would default to Administrators.
        let security_attributes = SecurityAttributesInit {
            owner: Some(current_user_sid()),
            ..security_attributes(current_user_sid(), users_sid()).expect("build pipe security attributes")
        }
        .init();
        let server = create_instance_with(&pipe_name, true, &security_attributes).expect("create the pipe");

        let client = open_client(&pipe_name).expect("open the pipe");
        server.connect().await.expect("accept the client");

        verify_server(&client).expect_err("the pipe is not owned by SYSTEM or Administrators");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_loop_keeps_several_instances_listening() {
        let pipe_name = unique_pipe_name("listening");
        let (mut dispatched, task) = spawn_accept_loop(
            &pipe_name,
            LISTENING_INSTANCES,
            create_owned_test_instance,
            RetryDelay::default(),
        );

        let _first_client = open_client_when_listening(&pipe_name).await;
        let _first = next_dispatched(&mut dispatched).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // While the first client is still served, a burst of clients connects without waiting.
        let _clients = (0..LISTENING_INSTANCES)
            .map(|_| open_client(&pipe_name).expect("an instance is listening"))
            .collect::<Vec<_>>();
        for _ in 0..LISTENING_INSTANCES {
            let _connection = next_dispatched(&mut dispatched).await;
        }

        task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_loop_retries_until_it_owns_the_first_instance() {
        let pipe_name = unique_pipe_name("squatted");
        let squatter = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)
            .expect("create the competing first instance");

        let attempts = Arc::new(Mutex::new(Vec::new()));
        let (mut dispatched, task) = spawn_accept_loop(
            &pipe_name,
            LISTENING_INSTANCES,
            {
                let attempts = Arc::clone(&attempts);
                move |pipe_name, first_instance| {
                    let result = create_owned_test_instance(pipe_name, first_instance);
                    attempts.lock().push((first_instance, result.is_ok()));
                    result
                }
            },
            RetryDelay::new(Duration::from_millis(10), Duration::from_millis(10)),
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!task.is_finished(), "a failed first instance is retried");
        {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                {
                    let attempts = attempts.lock();
                    if attempts.len() >= 2 {
                        assert!(
                            attempts.iter().all(|&attempt| attempt == (true, false)),
                            "the server never joins a pipe it did not create: {attempts:?}"
                        );
                        break;
                    }
                    assert!(
                        Instant::now() < deadline && !task.is_finished(),
                        "the server does not retry the first instance: {attempts:?}"
                    );
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        drop(squatter);

        let _client = open_client_when_listening(&pipe_name).await;
        let _connection = next_dispatched(&mut dispatched).await;

        task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_loop_claims_the_pipe_again_once_no_instance_is_open() {
        let pipe_name = unique_pipe_name("reclaim");
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let (mut dispatched, task) = spawn_accept_loop(
            &pipe_name,
            1,
            {
                let attempts = Arc::clone(&attempts);
                move |pipe_name, first_instance| {
                    let mut attempts = attempts.lock();
                    attempts.push(first_instance);
                    // Fail the two attempts that follow the first connection, leaving no instance listening.
                    if matches!(attempts.len(), 2 | 3) {
                        anyhow::bail!("injected instance creation failure");
                    }
                    create_owned_test_instance(pipe_name, first_instance)
                }
            },
            RetryDelay::new(Duration::from_millis(300), Duration::from_millis(300)),
        );

        let first_client = open_client_when_listening(&pipe_name).await;
        let first = next_dispatched(&mut dispatched).await;
        drop(first_client);
        drop(first);

        let _second_client = open_client_when_listening(&pipe_name).await;
        let _second = next_dispatched(&mut dispatched).await;

        let attempts = attempts.lock().clone();
        assert!(attempts[0]);
        assert!(
            attempts[3],
            "no instance was open, so the pipe is claimed again: {attempts:?}"
        );

        task.abort();
    }

    #[tokio::test]
    async fn the_pipe_name_stays_claimed_until_the_last_instance_is_released() {
        let pipe_name = unique_pipe_name("handover");
        let open_instances = Arc::new(Mutex::new(0));

        let (first_instance, created) = OpenInstance::create(&pipe_name, &open_instances, &create_owned_test_instance);
        assert!(first_instance);
        let (first_server, first) = created.expect("create the first instance");
        let first_server = Mutex::new(Some(first_server));

        // Close the last server handle while the next instance is created, then try to claim the name in between.
        let squatted = Mutex::new(None);
        let (first_instance, created) =
            OpenInstance::create(&pipe_name, &open_instances, &|pipe_name, first_instance| {
                drop(first_server.lock().take());
                let claimed = ServerOptions::new().first_pipe_instance(true).create(pipe_name);
                *squatted.lock() = Some(claimed.is_ok());
                create_owned_test_instance(pipe_name, first_instance)
            });
        assert!(!first_instance);
        assert_eq!(
            *squatted.lock(),
            Some(false),
            "nobody else can claim the name meanwhile"
        );
        let (second_server, second) = created.expect("the next instance joins the server's pipe");

        drop(second_server);
        drop(first);
        drop(second);
        assert_eq!(*open_instances.lock(), 0);
        ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)
            .expect("the name is released with the last instance");
    }

    #[tokio::test]
    async fn clients_identify_the_server_process() {
        let pipe_name = unique_pipe_name("process");
        let server = create_client_access_pipe(&pipe_name);
        let client = open_client(&pipe_name).expect("open the pipe");
        server.connect().await.expect("accept the client");

        assert_eq!(
            server_process_id(&client).expect("query the server process"),
            std::process::id()
        );
    }

    #[test]
    fn standard_users_can_query_the_process_of_a_running_service() {
        // The Windows Event Log service always runs, and its default security descriptor lets interactive users query it.
        let process_id = service_process_id("EventLog").expect("query the EventLog service process");
        assert_ne!(process_id, 0);
        assert_ne!(process_id, std::process::id());

        service_process_id("DevolutionsPEDM.test.missing").expect_err("an unknown service is rejected");
    }

    #[test]
    fn the_client_refuses_to_connect_while_the_service_is_not_running() {
        // The pre-connect check must fail closed, so a client never opens the pipe while the Agent service is stopped.
        verify_service_running("DevolutionsPEDM.test.missing").expect_err("an unknown service is rejected");

        // The Windows Event Log service always runs, and its default security descriptor lets interactive users query it.
        verify_service_running("EventLog").expect("a running service passes the pre-connect check");
    }

    #[tokio::test]
    async fn clients_reject_pipes_not_served_by_the_service_process() {
        let pipe_name = unique_pipe_name("impostor");
        let server = create_client_access_pipe(&pipe_name);
        let client = open_client(&pipe_name).expect("open the pipe");
        server.connect().await.expect("accept the client");

        verify_server_process(&client, "EventLog").expect_err("the test process is not the service process");
        verify_server_process(&client, "DevolutionsPEDM.test.missing").expect_err("an unknown service is rejected");
    }
}
