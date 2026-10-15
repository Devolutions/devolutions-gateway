//! PEDM named pipe server instances.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use devolutions_pedm_shared::pipe::CLIENT_ACCESS;
use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tracing::{error, info, warn};
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::raw::Win32::Foundation::GENERIC_ALL;
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

/// Marks a pipe instance of this server as open until dropped.
pub(super) struct OpenInstance {
    _count: Arc<()>,
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
    let open_instances = Arc::new(());

    info!(%pipe_name, listening_instances, "Starting named pipe server");

    let mut listening = FuturesUnordered::new();

    loop {
        while listening.len() < listening_instances {
            let first_instance = Arc::strong_count(&open_instances) == 1;
            match create_instance(pipe_name, first_instance) {
                Ok(server) => {
                    retry.reset();
                    let instance = OpenInstance {
                        _count: Arc::clone(&open_instances),
                    };
                    listening.push(async move {
                        let result = server.connect().await;
                        (server, instance, result)
                    });
                }
                Err(error) => {
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
    use std::sync::Mutex;
    use std::time::Instant;

    use devolutions_pedm_shared::pipe::{open_client, verify_server};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use win_api_wrappers::handle::Handle;
    use win_api_wrappers::raw::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GENERIC_WRITE, HANDLE,
    };
    use win_api_wrappers::raw::Win32::Storage::FileSystem::{
        FILE_APPEND_DATA, FILE_CREATE_PIPE_INSTANCE, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA,
        READ_CONTROL, SYNCHRONIZE,
    };
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
                    attempts.lock().expect("lock").push((first_instance, result.is_ok()));
                    result
                }
            },
            RetryDelay::new(Duration::from_millis(10), Duration::from_millis(10)),
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!task.is_finished(), "a failed first instance is retried");
        {
            let attempts = attempts.lock().expect("lock");
            assert!(attempts.len() >= 2);
            assert!(
                attempts.iter().all(|&attempt| attempt == (true, false)),
                "the server never joins a pipe it did not create: {attempts:?}"
            );
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
                    let mut attempts = attempts.lock().expect("lock");
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

        let attempts = attempts.lock().expect("lock").clone();
        assert!(attempts[0]);
        assert!(
            attempts[3],
            "no instance was open, so the pipe is claimed again: {attempts:?}"
        );

        task.abort();
    }
}
