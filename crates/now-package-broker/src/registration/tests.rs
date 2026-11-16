use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::IntoRawHandle as _;
use std::time::{Duration, SystemTime};

use tokio::io::AsyncReadExt as _;
use tokio::net::windows::named_pipe::{NamedPipeClient, ServerOptions};
use win_api_wrappers::process::Process;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GENERIC_READ, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SecurityAnonymous, SecurityDelegation,
};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, SECURITY_ANONYMOUS, SECURITY_IDENTIFICATION};
use windows::core::PWSTR;

use super::*;

fn framed(body: &str) -> Vec<u8> {
    let mut bytes = u32::try_from(body.len())
        .expect("test body fits")
        .to_le_bytes()
        .to_vec();
    bytes.extend_from_slice(body.as_bytes());
    bytes
}

fn candidate(process_id: u32) -> Candidate {
    Candidate {
        process: ProcessKey {
            process_id,
            creation_time: SystemTime::UNIX_EPOCH,
        },
        user_sid: current_user_sid(),
        session_id: 1,
        display_name: None,
        is_live: Arc::new(|| true),
    }
}

fn reserve(registry: &Arc<Registry>, process_id: u32) -> Reservation {
    registry.reserve(candidate(process_id)).expect("reserve a slot")
}

fn current_user_sid() -> Sid {
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
        r"\\.\pipe\Devolutions.Now.PackageBroker.Registration.test.{tag}.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos()
    )
}

fn open_client_with(pipe_name: &str, qos: u32) -> std::io::Result<NamedPipeClient> {
    let file = std::fs::OpenOptions::new()
        .access_mode(GENERIC_READ.0 | FILE_WRITE_DATA.0)
        .custom_flags(FILE_FLAG_OVERLAPPED.0)
        .security_qos_flags(qos)
        .open(pipe_name)?;

    // SAFETY: The handle is a freshly opened, exclusively owned overlapped named pipe client handle.
    unsafe { NamedPipeClient::from_raw_handle(file.into_raw_handle()) }
}

async fn open_client_when_listening(pipe_name: &str) -> NamedPipeClient {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match open_client_with(pipe_name, SECURITY_IDENTIFICATION.0) {
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

fn dacl_sddl(security_attributes: &SecurityAttributes) -> String {
    // SAFETY: The attributes own a valid descriptor that outlives the call.
    let descriptor = unsafe { (*security_attributes.as_mut_ptr()).lpSecurityDescriptor };
    let mut sddl = PWSTR::null();

    // SAFETY: `descriptor` is valid and `sddl` receives a LocalAlloc'd string that is freed below.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            PSECURITY_DESCRIPTOR(descriptor),
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut sddl,
            None,
        )
    }
    .expect("convert descriptor to SDDL");

    // SAFETY: `sddl` is a valid NUL-terminated string allocated by the call above.
    let text = unsafe { sddl.to_string() }.expect("SDDL is UTF-16");
    // SAFETY: `sddl` was allocated with LocalAlloc.
    unsafe { LocalFree(Some(HLOCAL(sddl.0.cast()))) };
    text
}

#[test]
fn pipe_dacl_denies_network_and_never_grants_users_pipe_instance_creation() {
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
    let users = Sid::from_well_known(Security::WinBuiltinUsersSid, None).expect("Users SID");
    let admins = Sid::from_well_known(Security::WinBuiltinAdministratorsSid, None).expect("Administrators SID");

    let sddl = dacl_sddl(&build_security_attributes(Some(admins), users).expect("build attributes"));

    let deny_network = sddl.find("(D;;GA;;;NU)").expect("NETWORK is denied");
    let allow_users = sddl
        .find("(A;;0x12008b;;;BU)")
        .unwrap_or_else(|| panic!("Users get read and write data only: {sddl}"));
    assert!(deny_network < sddl.find("(A;").expect("allow entries"), "{sddl}");
    assert!(sddl.contains("(A;;GA;;;SY)") && sddl.contains("(A;;GA;;;BA)"), "{sddl}");
    assert!(allow_users > deny_network, "{sddl}");
}

#[tokio::test]
async fn user_can_connect_but_cannot_serve_the_pipe() {
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
    let pipe_name = unique_pipe_name("acl");
    let security_attributes = build_security_attributes(None, current_user_sid()).expect("build attributes");
    // SAFETY: `security_attributes` owns a valid `SECURITY_ATTRIBUTES` that outlives the call.
    let _first = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(&pipe_name, security_attributes.as_mut_ptr().cast())
    }
    .expect("create the first instance");

    open_client_with(&pipe_name, SECURITY_IDENTIFICATION.0).expect("a user can open the pipe for read and write data");
    let squatter = ServerOptions::new().create(&pipe_name);

    assert_eq!(
        squatter.expect_err("a user cannot create an instance").kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[tokio::test]
async fn pipe_client_identity_is_read_from_the_impersonation_token() {
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
    let pipe_name = unique_pipe_name("identity");
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)
        .expect("create pipe");
    let mut client = open_client_with(&pipe_name, SECURITY_IDENTIFICATION.0).expect("connect client");
    server.connect().await.expect("accept client");
    client.write_all(b"x").await.expect("write");
    server.read_exact(&mut [0]).await.expect("read");

    let (sid, session_id) = pipe_client_identity(&server).expect("identity");

    let token = Process::current_process()
        .token(TOKEN_QUERY)
        .expect("open current token");
    assert_eq!(sid, current_user_sid());
    assert_eq!(session_id, token.session_id().expect("current session"));
    crate::impersonation::tests::assert_thread_not_impersonating();
}

#[tokio::test]
async fn anonymous_pipe_client_is_rejected() {
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
    let pipe_name = unique_pipe_name("anonymous");
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)
        .expect("create pipe");
    let mut client = open_client_with(&pipe_name, SECURITY_ANONYMOUS.0).expect("connect client");
    server.connect().await.expect("accept client");
    client.write_all(b"x").await.expect("write");
    server.read_exact(&mut [0]).await.expect("read");

    pipe_client_identity(&server).expect_err("an anonymous client has no identity");

    crate::impersonation::tests::assert_thread_not_impersonating();
}

#[test]
fn only_identification_or_higher_is_accepted() {
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
    ensure_identification_level(SecurityAnonymous).expect_err("anonymous is rejected");
    ensure_identification_level(SecurityIdentification).expect("identification is accepted");
    ensure_identification_level(SecurityDelegation).expect("delegation is accepted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_client_gets_no_welcome_and_is_not_registered() {
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
    let pipe_name = unique_pipe_name("unauthenticated");
    let handle = RegistrationHandle::new();
    let shutdown = CancellationToken::new();
    let server = tokio::spawn({
        let (handle, pipe_name, shutdown) = (handle.clone(), pipe_name.clone(), shutdown.clone());
        async move { run_registration_server(&handle, &pipe_name, shutdown).await }
    });
    let mut client = open_client_when_listening(&pipe_name).await;
    client
        .write_all(&framed(
            r#"{"kind":"Hello","protocolVersion":1,"clientVersion":"test"}"#,
        ))
        .await
        .expect("write hello");

    let mut reply = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(20), client.read(&mut reply))
        .await
        .expect("the server closes the connection");

    assert!(
        !matches!(read, Ok(1..)),
        "no frame is sent to an unauthenticated client"
    );
    assert!(handle.snapshot().expect("registration is served").is_empty());
    shutdown.cancel();
    server.await.expect("server task").expect("server result");
    assert_eq!(handle.snapshot().err(), Some(RegistrationUnavailable));
}

#[tokio::test]
async fn claimed_pipe_name_makes_registration_unavailable() {
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
    let pipe_name = unique_pipe_name("claimed");
    let _squatter = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)
        .expect("claim the name");
    let handle = RegistrationHandle::new();

    run_registration_server(&handle, &pipe_name, CancellationToken::new())
        .await
        .expect_err("the name is claimed");

    assert_eq!(handle.snapshot().err(), Some(RegistrationUnavailable));
}

mod connection {
    use serde_json::{Value, json};

    use super::*;

    const PING: &[u8] = b"\x0f\0\0\0{\"kind\":\"Ping\"}";
    const PONG: &[u8] = b"\x0f\0\0\0{\"kind\":\"Pong\"}";
    const OTHER_ID: &str = "0b9d6a1e-5c7e-4f43-9d2a-3f1c6a5e8b10";

    fn serve(registry: &Arc<Registry>, process_id: u32) -> (tokio::io::DuplexStream, JoinHandle<anyhow::Result<()>>) {
        let (server_io, client_io) = tokio::io::duplex(4096);
        let reservation = reserve(registry, process_id);
        registry.set_available(true);
        reservation.activate();
        let task =
            tokio::spawn(async move { run_connection(server_io, &reservation, &CancellationToken::new()).await });
        (client_io, task)
    }

    #[tokio::test(start_paused = true)]
    async fn ping_is_sent_after_thirty_seconds_of_silence() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let start = Instant::now();

        let mut ping = [0u8; PING.len()];
        client.read_exact(&mut ping).await.expect("ping");

        assert_eq!(ping, PING);
        assert_eq!(start.elapsed(), Duration::from_secs(30));
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn connection_closes_after_ninety_seconds_without_a_frame() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        let (_client, task) = serve(&registry, 1);
        let start = Instant::now();

        let result = task.await.expect("connection task");

        result.expect_err("an idle client is closed");
        assert_eq!(start.elapsed(), Duration::from_secs(90));
    }

    #[tokio::test(start_paused = true)]
    async fn ping_is_answered_with_pong_and_defers_the_idle_timeout() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        tokio::time::sleep(Duration::from_secs(80)).await;

        client
            .write_all(&framed(r#"{"kind":"Ping"}"#))
            .await
            .expect("write ping");
        let mut reply = [0u8; PONG.len()];
        loop {
            client.read_exact(&mut reply).await.expect("reply");
            if reply == PONG {
                break;
            }
            assert_eq!(reply, PING, "only pings may precede the pong");
        }
        tokio::time::sleep(Duration::from_secs(80)).await;

        assert!(!task.is_finished(), "the ping restarted the 90 second window");
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn response_and_request_frames_close_the_connection() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        for body in [
            r#"{"kind":"Response","id":"x","ok":true,"result":1}"#,
            r#"{"kind":"Response","id":"0b9d6a1e-5c7e-4f43-9d2a-3f1c6a5e8b10","ok":true,"result":1}"#,
            r#"{"kind":"Request","id":"x","command":"c","arguments":{}}"#,
            r#"{"kind":"Hello","protocolVersion":1,"clientVersion":"x"}"#,
            "not json",
        ] {
            let registry = Arc::new(Registry::default());
            let (mut client, task) = serve(&registry, 1);

            client.write_all(&framed(body)).await.expect("write frame");

            task.await.expect("connection task").expect_err(body);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn replaced_connection_closes_without_error() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        let (_client, task) = serve(&registry, 1);
        tokio::task::yield_now().await;

        let _newer = reserve(&registry, 1);

        task.await
            .expect("connection task")
            .expect("replacement is not an error");
    }

    fn endpoint(registry: &Arc<Registry>) -> RegisteredEndpoint {
        registry.snapshot().expect("available").remove(0)
    }

    async fn read_json(client: &mut tokio::io::DuplexStream) -> Value {
        let mut prefix = [0u8; 4];
        client.read_exact(&mut prefix).await.expect("length prefix");
        let mut body = vec![0u8; usize::try_from(u32::from_le_bytes(prefix)).expect("fits")];
        client.read_exact(&mut body).await.expect("frame body");
        serde_json::from_slice(&body).expect("JSON frame")
    }

    async fn respond(client: &mut tokio::io::DuplexStream, response: Value) {
        client
            .write_all(&framed(&response.to_string()))
            .await
            .expect("write response");
    }

    fn id_of(request: &Value) -> String {
        request["id"].as_str().expect("request id").to_owned()
    }

    fn request_error(result: anyhow::Result<Value>) -> RequestError {
        result
            .expect_err("the request fails")
            .downcast::<RequestError>()
            .expect("a request error")
    }

    #[tokio::test(start_paused = true)]
    async fn request_is_correlated_with_its_response_while_heartbeats_continue() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let call = tokio::spawn({
            let endpoint = endpoint.clone();
            async move { endpoint.request("GetInventorySnapshot", json!({})).await }
        });

        let request = read_json(&mut client).await;
        assert_eq!(request["kind"], "Request");
        assert_eq!(request["command"], "GetInventorySnapshot");
        assert_eq!(request["arguments"], json!({}));
        client
            .write_all(&framed(r#"{"kind":"Ping"}"#))
            .await
            .expect("write ping");
        assert_eq!(read_json(&mut client).await, json!({"kind": "Pong"}));
        assert!(!call.is_finished(), "a pong is not a response");
        respond(
            &mut client,
            json!({"kind": "Response", "id": id_of(&request), "ok": true, "result": {"managers": []}}),
        )
        .await;

        let result = call.await.expect("call task").expect("response result");

        assert_eq!(result, json!({"managers": []}));
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn out_of_order_responses_reach_their_own_requests() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let first = tokio::spawn({
            let endpoint = endpoint.clone();
            async move { endpoint.request("GetInventorySnapshot", json!({})).await }
        });
        let first_request = read_json(&mut client).await;
        let second = tokio::spawn({
            let endpoint = endpoint.clone();
            async move { endpoint.request("GetInventorySnapshot", json!({})).await }
        });
        let second_request = read_json(&mut client).await;
        assert_ne!(id_of(&first_request), id_of(&second_request));

        respond(
            &mut client,
            json!({"kind": "Response", "id": id_of(&second_request), "ok": true, "result": "inventory"}),
        )
        .await;
        respond(
            &mut client,
            json!({"kind": "Response", "id": id_of(&first_request), "ok": true, "result": "first"}),
        )
        .await;

        assert_eq!(second.await.expect("task").expect("result"), json!("inventory"));
        assert_eq!(first.await.expect("task").expect("result"), json!("first"));
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn at_most_eight_requests_are_outstanding() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let mut calls = Vec::new();
        let mut ids = Vec::new();
        for _ in 0..8 {
            calls.push(tokio::spawn({
                let endpoint = endpoint.clone();
                async move { endpoint.request("GetInventorySnapshot", json!({})).await }
            }));
            ids.push(id_of(&read_json(&mut client).await));
        }

        let ninth = request_error(endpoint.request("GetInventorySnapshot", json!({})).await);
        assert!(!ninth.may_have_been_sent(), "the ninth request is not written");
        respond(
            &mut client,
            json!({"kind": "Response", "id": ids[0], "ok": true, "result": []}),
        )
        .await;
        calls.remove(0).await.expect("task").expect("first result");

        let replacement = tokio::spawn({
            let endpoint = endpoint.clone();
            async move { endpoint.request("GetInventorySnapshot", json!({})).await }
        });
        read_json(&mut client).await;
        assert!(!replacement.is_finished());
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn rejection_by_the_client_is_reported_with_its_code() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let call = tokio::spawn(async move { endpoint.request("ExecutePackageOperation", json!({})).await });
        let request = read_json(&mut client).await;

        respond(
            &mut client,
            json!({"kind": "Response", "id": id_of(&request), "ok": false,
                "error": {"code": "InvalidArguments", "message": "bad"}}),
        )
        .await;

        let error = request_error(call.await.expect("call task"));
        assert!(matches!(&error, RequestError::Rejected(remote) if remote.code == "InvalidArguments"));
        assert!(error.may_have_been_sent());
        assert!(!task.is_finished(), "an error response is a valid answer");
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn response_without_a_matching_request_fails_outstanding_requests_as_unanswered() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let call = tokio::spawn({
            let endpoint = endpoint.clone();
            async move { endpoint.request("ExecutePackageOperation", json!({})).await }
        });
        let request = read_json(&mut client).await;
        assert_ne!(id_of(&request), OTHER_ID);

        respond(
            &mut client,
            json!({"kind": "Response", "id": OTHER_ID, "ok": true, "result": {}}),
        )
        .await;

        task.await.expect("connection task").expect_err("unsolicited response");
        let error = request_error(call.await.expect("call task"));
        assert!(matches!(error, RequestError::Unanswered(_)));
        assert!(error.may_have_been_sent());
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_response_to_one_request_closes_the_connection() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let call = tokio::spawn(async move { endpoint.request("GetInventorySnapshot", json!({})).await });
        let request = read_json(&mut client).await;
        let response = json!({"kind": "Response", "id": id_of(&request), "ok": true, "result": []});

        respond(&mut client, response.clone()).await;
        call.await.expect("call task").expect("first response");
        respond(&mut client, response).await;

        task.await.expect("connection task").expect_err("duplicate response");
    }

    #[tokio::test(start_paused = true)]
    async fn unanswered_request_times_out_while_pings_keep_the_connection_alive() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let call = tokio::spawn(async move { endpoint.request("GetInventorySnapshot", json!({})).await });
        read_json(&mut client).await;
        let pinger = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(45)).await;
                if client.write_all(&framed(r#"{"kind":"Ping"}"#)).await.is_err() {
                    break;
                }
            }
        });

        let error = request_error(call.await.expect("call task"));

        assert_eq!(error, RequestError::Unanswered("request timed out"));
        task.await
            .expect("connection task")
            .expect_err("timeout closes the connection");
        pinger.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn closed_connection_reports_unanswered_in_flight_and_not_sent_afterwards() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let call = tokio::spawn({
            let endpoint = endpoint.clone();
            async move { endpoint.request("ExecutePackageOperation", json!({})).await }
        });
        read_json(&mut client).await;

        drop(client);

        task.await.expect("connection task").expect("client closed");
        assert!(matches!(
            request_error(call.await.expect("call task")),
            RequestError::Unanswered(_)
        ));
        let later = request_error(endpoint.request("GetInventorySnapshot", json!({})).await);
        assert!(!later.may_have_been_sent());
    }

    #[tokio::test(start_paused = true)]
    async fn request_never_falls_back_to_another_connection() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        let (first_client, first_task) = serve(&registry, 1);
        let (mut second_client, second_task) = serve(&registry, 2);
        let endpoint = endpoint(&registry);
        drop(first_client);
        first_task.await.expect("connection task").expect("client closed");

        let error = request_error(endpoint.request("GetInventorySnapshot", json!({})).await);

        assert!(!error.may_have_been_sent());
        let mut byte = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(5), second_client.read_exact(&mut byte))
            .await
            .expect_err("nothing is written to the other connection");
        second_task.abort();
    }

    #[tokio::test]
    async fn invalid_requests_are_not_sent() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        registry.set_available(true);
        let reservation = reserve(&registry, 1);
        reservation.activate();
        let endpoint = endpoint(&registry);

        for (command, arguments) in [
            ("GetInventorySnapshot", json!([])),
            ("GetInventorySnapshot", Value::Null),
            ("", json!({})),
            ("GetInventorySnapshot", json!({"padding": "x".repeat(2_000_000)})),
        ] {
            let error = request_error(endpoint.request(command, arguments).await);
            assert!(!error.may_have_been_sent());
        }
    }

    fn rescan(endpoint: &RegisteredEndpoint) -> JoinHandle<Result<(), RequestError>> {
        let endpoint = endpoint.clone();
        tokio::spawn(async move { endpoint.rescan_inventory().await })
    }

    fn rescan_done(id: &str) -> Value {
        json!({"kind": "Response", "id": id, "ok": true, "result": {}})
    }

    fn rejection(id: &str, code: &str) -> Value {
        json!({"kind": "Response", "id": id, "ok": false, "error": {"code": code, "message": "not done"}})
    }

    /// Lets every task run until it waits, then checks that the Agent wrote no frame.
    async fn assert_nothing_written(client: &mut tokio::io::DuplexStream) {
        let mut byte = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut byte))
            .await
            .expect_err("no frame is written");
    }

    #[tokio::test(start_paused = true)]
    async fn rescan_is_one_request_without_arguments_answered_by_an_empty_result() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let call = rescan(&endpoint(&registry));

        let request = read_json(&mut client).await;
        assert_eq!(request["kind"], "Request");
        assert_eq!(request["command"], "RescanInventory");
        assert_eq!(request["arguments"], json!({}));
        respond(&mut client, rescan_done(&id_of(&request))).await;

        assert_eq!(call.await.expect("call task"), Ok(()));
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn callers_arriving_during_a_rescan_share_one_sent_after_it_is_answered() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let first = rescan(&endpoint);
        let first_request = read_json(&mut client).await;

        let second = rescan(&endpoint);
        let third = rescan(&endpoint);
        assert_nothing_written(&mut client).await;
        respond(&mut client, rescan_done(&id_of(&first_request))).await;

        assert_eq!(first.await.expect("call task"), Ok(()));
        let shared_request = read_json(&mut client).await;
        assert_eq!(shared_request["command"], "RescanInventory");
        assert_ne!(id_of(&shared_request), id_of(&first_request));
        assert_nothing_written(&mut client).await;
        assert!(
            !second.is_finished() && !third.is_finished(),
            "a response to a request sent before a caller arrived does not answer that caller"
        );
        respond(&mut client, rescan_done(&id_of(&shared_request))).await;
        assert_eq!(second.await.expect("call task"), Ok(()));
        assert_eq!(third.await.expect("call task"), Ok(()));
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn rescan_rejected_as_unsupported_leaves_the_connection_usable() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let call = rescan(&endpoint);
        let request = read_json(&mut client).await;

        respond(&mut client, rejection(&id_of(&request), "UnsupportedCommand")).await;

        let error = call.await.expect("call task").expect_err("the rescan is rejected");
        assert!(matches!(&error, RequestError::Rejected(remote) if remote.code == "UnsupportedCommand"));
        let snapshot = tokio::spawn(async move { endpoint.request("GetInventorySnapshot", json!({})).await });
        let request = read_json(&mut client).await;
        assert_eq!(request["command"], "GetInventorySnapshot");
        respond(
            &mut client,
            json!({"kind": "Response", "id": id_of(&request), "ok": true, "result": {"managers": []}}),
        )
        .await;
        assert_eq!(
            snapshot.await.expect("call task").expect("snapshot result"),
            json!({"managers": []})
        );
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn caller_that_gives_up_leaves_its_rescan_outstanding() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let first = rescan(&endpoint);
        let first_request = read_json(&mut client).await;

        first.abort();
        first.await.expect_err("the first caller gave up");
        let second = rescan(&endpoint);
        assert_nothing_written(&mut client).await;
        respond(&mut client, rescan_done(&id_of(&first_request))).await;

        let second_request = read_json(&mut client).await;
        assert_eq!(second_request["command"], "RescanInventory");
        assert_ne!(id_of(&second_request), id_of(&first_request));
        respond(&mut client, rescan_done(&id_of(&second_request))).await;
        assert_eq!(second.await.expect("call task"), Ok(()));
        assert!(!task.is_finished(), "both responses answered an outstanding request");
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn held_rescan_is_sent_after_its_callers_gave_up() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let first = rescan(&endpoint);
        let first_request = read_json(&mut client).await;
        let second = rescan(&endpoint);
        assert_nothing_written(&mut client).await;

        second.abort();
        second.await.expect_err("the second caller gave up");
        respond(&mut client, rescan_done(&id_of(&first_request))).await;

        assert_eq!(first.await.expect("call task"), Ok(()));
        let held_request = read_json(&mut client).await;
        assert_eq!(held_request["command"], "RescanInventory");
        assert_ne!(id_of(&held_request), id_of(&first_request));
        respond(&mut client, rescan_done(&id_of(&held_request))).await;
        assert_nothing_written(&mut client).await;
        assert!(!task.is_finished(), "the response answered an outstanding request");
        let later = rescan(&endpoint);
        let later_request = read_json(&mut client).await;
        assert_eq!(later_request["command"], "RescanInventory");
        assert_ne!(id_of(&later_request), id_of(&held_request));
        respond(&mut client, rescan_done(&id_of(&later_request))).await;
        assert_eq!(later.await.expect("call task"), Ok(()));
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn closed_connection_ends_the_outstanding_rescan_and_drops_the_held_one() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let first = rescan(&endpoint);
        read_json(&mut client).await;
        let second = rescan(&endpoint);
        assert_nothing_written(&mut client).await;

        client.shutdown().await.expect("close the client's side");

        task.await.expect("connection task").expect("client closed");
        let first_error = first.await.expect("call task").expect_err("the rescan is unanswered");
        assert!(matches!(first_error, RequestError::Unanswered(_)), "{first_error:?}");
        let second_error = second.await.expect("call task").expect_err("the held rescan fails");
        assert!(!second_error.may_have_been_sent(), "{second_error:?}");
        let mut written = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut written))
            .await
            .expect("the Agent's side closes")
            .expect("read what the Agent wrote");
        assert!(written.is_empty(), "no further frame is written");
    }

    #[tokio::test(start_paused = true)]
    async fn queued_rescan_is_sent_after_the_outstanding_one_is_rejected() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let first = rescan(&endpoint);
        let first_request = read_json(&mut client).await;
        let second = rescan(&endpoint);
        assert_nothing_written(&mut client).await;

        respond(&mut client, rejection(&id_of(&first_request), "Failed")).await;

        let error = first.await.expect("call task").expect_err("the rescan is rejected");
        assert!(matches!(&error, RequestError::Rejected(remote) if remote.code == "Failed"));
        let second_request = read_json(&mut client).await;
        assert_eq!(second_request["command"], "RescanInventory");
        respond(&mut client, rescan_done(&id_of(&second_request))).await;
        assert_eq!(second.await.expect("call task"), Ok(()));
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn caller_arriving_after_the_held_rescan_was_sent_waits_for_the_next_one() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let endpoint = endpoint(&registry);
        let _first = rescan(&endpoint);
        let first_request = read_json(&mut client).await;
        let second = rescan(&endpoint);
        assert_nothing_written(&mut client).await;
        respond(&mut client, rescan_done(&id_of(&first_request))).await;
        let second_request = read_json(&mut client).await;

        let third = rescan(&endpoint);
        assert_nothing_written(&mut client).await;
        respond(&mut client, rescan_done(&id_of(&second_request))).await;

        assert_eq!(second.await.expect("call task"), Ok(()));
        let third_request = read_json(&mut client).await;
        assert_eq!(third_request["command"], "RescanInventory");
        respond(&mut client, rescan_done(&id_of(&third_request))).await;
        assert_eq!(third.await.expect("call task"), Ok(()));
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn rescan_unanswered_for_thirty_minutes_closes_the_connection() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let call = rescan(&endpoint(&registry));
        read_json(&mut client).await;
        let start = Instant::now();
        let pinger = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(45)).await;
                if client.write_all(&framed(r#"{"kind":"Ping"}"#)).await.is_err() {
                    break;
                }
            }
        });

        let outcome = call.await.expect("call task");

        assert_eq!(start.elapsed(), Duration::from_secs(30 * 60));
        assert!(matches!(outcome, Err(RequestError::Unanswered(_))), "{outcome:?}");
        task.await
            .expect("connection task")
            .expect_err("the deadline closes the connection");
        pinger.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn unanswered_rescan_stays_outstanding_past_the_read_timeout() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
        let registry = Arc::new(Registry::default());
        let (mut client, task) = serve(&registry, 1);
        let call = rescan(&endpoint(&registry));
        let request = read_json(&mut client).await;
        let start = Instant::now();

        // Pings keep the connection from idling out while the request stays unanswered.
        while start.elapsed() < Duration::from_secs(5 * 60) {
            tokio::time::sleep(Duration::from_secs(45)).await;
            assert!(!call.is_finished(), "the rescan is still awaited");
            assert!(!task.is_finished(), "the connection is still open");
            client
                .write_all(&framed(r#"{"kind":"Ping"}"#))
                .await
                .expect("write ping");
        }
        respond(&mut client, rescan_done(&id_of(&request))).await;

        assert_eq!(call.await.expect("call task"), Ok(()));
        assert!(!task.is_finished(), "the late response answers an outstanding request");
        task.abort();
    }
}
