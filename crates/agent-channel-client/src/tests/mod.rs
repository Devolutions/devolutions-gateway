mod authority;
mod proxy;
mod socks;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_channel_proto::server_message::Payload;
use agent_channel_proto::{Ack, ConfigUpdate, Reconnect, RenewRequested, Welcome, agent_message};
use anyhow::anyhow;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::StatusCode;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey as _;
use rstest::rstest;
use signature::Verifier as _;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tonic::{Code, Status};

use self::authority::{Mode, Pki, ServerStream, TestAuthority, WAIT, vectors};
use self::proxy::TestProxy;
use self::socks::{SocksRequest, TestSocksProxy};
use super::*;

const CHANNEL_PROOF_DOMAIN: &[u8] = b"devolutions-agent-identity/v1/channel-proof";

/// A device key from the shared test vectors.
struct TestKey {
    name: String,
    key: SigningKey,
    fail_proofs: bool,
}

impl DeviceKey for TestKey {
    fn name(&self) -> &str {
        &self.name
    }

    fn public_key(&self) -> VerifyingKey {
        *self.key.verifying_key()
    }

    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        if self.fail_proofs && message.starts_with(CHANNEL_PROOF_DOMAIN) {
            return Err(signature::Error::new());
        }
        signature::Signer::<Signature>::try_sign(&self.key, message)
    }
}

/// A device key and certificate from the test vectors.
struct Identity {
    key: Arc<TestKey>,
    certificate: Vec<u8>,
    thumbprint: String,
}

impl Identity {
    fn from_vectors(name: &str) -> anyhow::Result<Self> {
        let vectors = vectors()?;
        let vector = vectors["keys"]
            .as_array()
            .and_then(|keys| keys.iter().find(|key| key["name"] == name))
            .ok_or_else(|| anyhow!("missing vector key {name}"))?;
        let field = |field: &str| {
            vector[field]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("missing vector field {field}"))
        };
        let private_key = STANDARD.decode(field("private_key_pkcs8")?)?;
        Ok(Self {
            key: Arc::new(TestKey {
                name: name.to_owned(),
                key: SigningKey::from_pkcs8_der(&private_key)?,
                fail_proofs: false,
            }),
            certificate: STANDARD.decode(field("certificate")?)?,
            thumbprint: field("thumbprint")?,
        })
    }

    fn target(&self, url: &Url) -> Target {
        self.target_with_hello(url, hello_fields())
    }

    fn target_with_hello(&self, url: &Url, hello: Arc<dyn Fn() -> HelloFields + Send + Sync>) -> Target {
        Target {
            url: url.clone(),
            key: Arc::clone(&self.key) as Arc<dyn DeviceKey>,
            leaf_certificate_der: self.certificate.clone(),
            hello,
        }
    }
}

fn client(authority: &TestAuthority, settings: Settings) -> anyhow::Result<ChannelClient> {
    ChannelClient::new(ProxyConfig::Off, std::slice::from_ref(&authority.ca), settings)
}

fn hello_fields() -> Arc<dyn Fn() -> HelloFields + Send + Sync> {
    Arc::new(|| HelloFields {
        metadata: HashMap::from([("hostname".to_owned(), "test-host".to_owned())]),
        config_revision: 7,
    })
}

/// Waits until `condition` holds, for at most [`WAIT`].
async fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let polled = async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(WAIT, polled)
        .await
        .unwrap_or_else(|_| panic!("{what} did not happen in time"));
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

async fn next_event(channel: &mut Channel) -> Event {
    tokio::time::timeout(WAIT, channel.next_event())
        .await
        .expect("no channel event in time")
        .expect("channel stopped")
}

/// Waits for the next closure.
async fn next_closure(channel: &mut Channel) -> (Closure, Option<Duration>) {
    match next_event(channel).await {
        Event::Closed { closure, reopen_after } => (closure, reopen_after),
        event => panic!("expected a closure, got {event:?}"),
    }
}

const SERVER_TIME: &str = "2026-10-21T00:00:00Z";

/// A gRPC status as the authority closes a stream with it ([CONTRACT.agent-identity.md] §7.4).
fn closing_status(code: Code, error_code: Option<&str>) -> Status {
    let mut status = Status::new(code, "closed by the test authority");
    if let Some(error_code) = error_code {
        let metadata = status.metadata_mut();
        metadata.insert("error-code", error_code.parse().expect("ASCII error code"));
        metadata.insert("server-time", SERVER_TIME.parse().expect("ASCII time"));
    }
    status
}

async fn assert_no_event(channel: &mut Channel) {
    if let Ok(event) = tokio::time::timeout(Duration::from_millis(300), channel.next_event()).await {
        panic!("unexpected channel event {event:?}");
    }
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-url
#[tokio::test]
async fn opens_a_signed_stream_under_the_url_path_and_waits_for_the_challenge() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let _channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;

    // The URL path prefixes the RPC path, and the opening carries a `connect` signature.
    let opening = authority.next_opening().await;
    assert_eq!(opening.path, "/dvls/devolutions.agent.channel.v1.AgentChannel/Connect");
    let signature_input = opening.signature_input().to_owned();
    assert!(signature_input.contains(";tag=\"connect\""), "{signature_input}");
    assert!(opening.headers.contains_key("signature"));
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
    assert!(
        signature_input.contains(&format!(";keyid=\"{}\"", identity.thumbprint)),
        "{signature_input}"
    );

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // Step 1: the agent sends nothing until it receives `Challenge`.
    let mut stream = opening.accept();
    assert!(stream.receive_within(Duration::from_millis(300)).await.is_none());
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
#[tokio::test]
async fn answers_the_challenge_with_a_hello_proving_the_device_key() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let hostname = Arc::new(Mutex::new("at-connect".to_owned()));
    let hello_hostname = Arc::clone(&hostname);
    let hello = Arc::new(move || HelloFields {
        metadata: HashMap::from([(
            "hostname".to_owned(),
            hello_hostname.lock().expect("hostname lock").clone(),
        )]),
        config_revision: 7,
    });
    let _channel =
        client(&authority, Settings::default())?.connect(identity.target_with_hello(&authority.url, hello))?;
    let mut stream = authority.next_opening().await.accept();

    // Metadata is collected when the `Hello` is sent, so the `Hello` carries the hostname set after the opening.
    *hostname.lock().expect("hostname lock") = "at-hello".to_owned();
    let challenge = [0x5a; 32];
    let challenge_id = stream.challenge(&challenge).await;
    let message = stream.receive().await;

    // Step 3.
    assert_eq!(message.correlation_id.as_deref(), Some(challenge_id.as_str()));
    let Some(agent_message::Payload::Hello(hello)) = message.payload else {
        panic!("expected Hello, got {message:?}");
    };
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
    assert_eq!(
        hello.metadata,
        HashMap::from([("hostname".to_owned(), "at-hello".to_owned())])
    );
    // Step 7.
    assert_eq!(hello.applied_state_versions, HashMap::from([("config".to_owned(), 7)]));
    // Step 3.
    let mut proven = CHANNEL_PROOF_DOMAIN.to_vec();
    proven.push(0x00);
    proven.extend_from_slice(&challenge);
    proven.extend_from_slice(stream.nonce.as_bytes());
    assert_eq!(hello.proof.len(), 64, "raw r||s");
    identity
        .key
        .public_key()
        .verify(&proven, &Signature::from_slice(&hello.proof)?)?;
    Ok(())
}

// oracle: intent docs/agent-identity/INTENT.agent-identity.md §Conformance
#[test]
fn channel_proof_input_matches_the_shared_vector() -> anyhow::Result<()> {
    let vectors = vectors()?;
    let vector = &vectors["channel_proof"];
    let field = |name: &str| {
        vector[name]
            .as_str()
            .ok_or_else(|| anyhow!("missing vector field {name}"))
    };
    let challenge = STANDARD.decode(field("challenge")?)?;
    let input = stream::channel_proof_input(&challenge, field("connect_nonce")?);
    assert_eq!(hex(&input), field("message_hex")?);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// oracle: intent crates/agent-channel-client/INTENT.md §Handshake
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
#[tokio::test]
async fn authenticates_only_on_the_welcome_answering_its_hello() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    send_unexpected(&stream).await;
    stream.challenge(&[1; 32]).await;
    let hello = stream.receive().await;

    // Nothing counts before the challenge succeeds (INTENT.agent-identity.md, security invariant 7).
    send_unexpected(&stream).await;
    assert_no_event(&mut channel).await;

    stream
        .send(
            &new_id(),
            Some(&hello.id),
            Payload::Welcome(Welcome { server_time: None }),
        )
        .await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);
    assert_no_event(&mut channel).await;
    Ok(())
}

/// Sends a renewal request and a `Welcome` that answers no `Hello`, neither of which counts before the handshake ends.
async fn send_unexpected(stream: &ServerStream) {
    stream
        .send(
            &new_id(),
            None,
            Payload::RenewRequested(RenewRequested {
                reason: "admin".to_owned(),
            }),
        )
        .await;
    stream
        .send(
            &new_id(),
            Some(&new_id()),
            Payload::Welcome(Welcome { server_time: None }),
        )
        .await;
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
#[tokio::test]
async fn reports_pushes_with_their_envelope_ids_and_ignores_unknown_payloads() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    // Unknown payloads are ignored.
    stream.send_unknown(&new_id()).await;
    stream.send(&new_id(), Some(&new_id()), Payload::Ack(Ack {})).await;
    let (renew_id, reconnect_id, config_id) = (new_id(), new_id(), new_id());
    stream
        .send(
            &renew_id,
            None,
            Payload::RenewRequested(RenewRequested {
                reason: "rotation".to_owned(),
            }),
        )
        .await;
    stream
        .send(
            &reconnect_id,
            None,
            Payload::Reconnect(Reconnect {
                reason: "certificate_rotated".to_owned(),
            }),
        )
        .await;
    let config_json = r#"{"version":1,"revision":8,"agent_channel_url":"https://host/dvls"}"#;
    stream
        .send(
            &config_id,
            None,
            Payload::ConfigUpdate(ConfigUpdate {
                config_json: config_json.to_owned(),
            }),
        )
        .await;

    assert_eq!(
        next_event(&mut channel).await,
        Event::RenewRequested {
            id: renew_id,
            reason: "rotation".to_owned()
        }
    );
    assert_eq!(
        next_event(&mut channel).await,
        Event::Reconnect {
            id: reconnect_id,
            reason: "certificate_rotated".to_owned()
        }
    );
    assert_eq!(
        next_event(&mut channel).await,
        Event::ConfigUpdate {
            id: config_id,
            config_json: config_json.to_owned()
        }
    );
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
#[tokio::test]
async fn processes_a_message_as_large_as_an_envelope_may_be() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    let id = new_id();
    stream.send_encoded(&padded_renewal(&id, 65_536));

    assert_eq!(
        next_event(&mut channel).await,
        Event::RenewRequested {
            id,
            reason: "admin".to_owned()
        }
    );
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn closes_without_reporting_a_message_larger_than_an_envelope_may_be() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, quick_reopening())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    stream.send_encoded(&padded_renewal(&new_id(), 65_537));

    // Without a `RenewRequested` event, the caller has nothing to acknowledge.
    let (closure, reopen_after) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert_eq!(reopen_after, Some(Duration::from_micros(15_625)));
    assert!(!matches!(stream.receive_within(WAIT).await, Some(Ok(Some(_)))));
    Ok(())
}

/// Encodes a `RenewRequested` under the envelope `id`, padded to `len` bytes with a field the agent doesn't know, as a
/// newer authority may add.
fn padded_renewal(id: &str, len: usize) -> Vec<u8> {
    let mut message = encoded_renewal(id);
    let padding = len - message.len() - 2 /* key of field 1000 */ - 3 /* length of the padding */;
    message.extend(length_delimited(1000, &vec![0; padding]));
    assert_eq!(message.len(), len);
    message
}

/// Encodes a protobuf record of wire type `LEN` (protobuf encoding, "Length-Delimited Records").
fn length_delimited(field: u32, value: &[u8]) -> Vec<u8> {
    let mut record = varint(u64::from((field << 3) | 2));
    record.extend(varint(u64::try_from(value.len()).expect("length fits 64 bits")));
    record.extend_from_slice(value);
    record
}

/// Encodes a protobuf base-128 varint (protobuf encoding, "Base 128 Varints").
fn varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    while 0x80 <= value {
        bytes.push(u8::try_from(value & 0x7f).expect("7 bits") | 0x80);
        value >>= 7;
    }
    bytes.push(u8::try_from(value).expect("7 bits"));
    bytes
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
#[tokio::test]
async fn acknowledges_a_message_under_a_fresh_uuid() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    let hello = stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);
    let renew_id = new_id();
    stream
        .send(
            &renew_id,
            None,
            Payload::RenewRequested(RenewRequested {
                reason: "admin".to_owned(),
            }),
        )
        .await;
    next_event(&mut channel).await;

    channel.ack(&renew_id);

    // Step 5: `Ack` with `correlation_id` = message `id`.
    let ack = stream.receive().await;
    assert_eq!(ack.correlation_id.as_deref(), Some(renew_id.as_str()));
    assert_eq!(ack.payload, Some(agent_message::Payload::Ack(Ack {})));
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    // Envelope IDs are lowercase hyphenated UUIDs.
    for id in [&hello.id, &ack.id] {
        let uuid = uuid::Uuid::parse_str(id)?;
        assert_eq!(&uuid.hyphenated().to_string(), id);
    }
    // oracle: spec RFC 9562 §1
    // A UUID is unique, so the acknowledgement's ID is neither the Hello's nor the acknowledged message's.
    assert_ne!(ack.id, hello.id);
    assert_ne!(ack.id, renew_id);
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn pings_the_connection_at_the_keepalive_interval() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let settings = Settings {
        keepalive_interval: Duration::from_millis(100),
        ..Settings::default()
    };
    let mut channel = client(&authority, settings)?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    let start = tokio::time::Instant::now();
    let before = authority.pings();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let pings = authority.pings() - before;
    let window = start.elapsed();
    // oracle: reference hyper 1.10 `src/proto/h2/ping.rs`, which sends each ping one interval after the last frame read
    // Pings are thus at least 100 ms apart, and the window holds at most one more ping than whole intervals.
    let most = usize::try_from(window.as_millis() / 100)? + 1;
    // A timer only promises not to fire early (`tokio::time::sleep`), so the lower bound lets each ping run up to one
    // interval late; the 30 s default would send none.
    assert!(
        (5..=most).contains(&pings),
        "{pings} pings in {window:?} at a 100 ms interval"
    );
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[rstest]
#[case::identity_revoked(
    Code::PermissionDenied,
    "identity_revoked",
    ClosureClass::Terminal(TerminalCode::IdentityRevoked)
)]
#[case::identity_unknown(
    Code::Unauthenticated,
    "identity_unknown",
    ClosureClass::Terminal(TerminalCode::IdentityUnknown)
)]
#[case::certificate_expired(Code::Unauthenticated, "certificate_expired", ClosureClass::CertificateExpired)]
#[case::signature_invalid(
    Code::Unauthenticated,
    "signature_invalid",
    ClosureClass::Transient(TransientKind::Outage)
)]
#[case::invalid_request(
    Code::InvalidArgument,
    "invalid_request",
    ClosureClass::Transient(TransientKind::Outage)
)]
#[case::unavailable(Code::Unavailable, "unavailable", ClosureClass::Transient(TransientKind::Outage))]
#[case::unknown_code(
    Code::Unauthenticated,
    "unknown_to_the_agent",
    ClosureClass::Transient(TransientKind::Outage)
)]
#[tokio::test]
async fn reports_a_refused_opening_with_its_status_trailers_and_class(
    #[case] code: Code,
    #[case] error_code: &str,
    #[case] class: ClosureClass,
) -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;

    // The error code classifies the closure, and every transient refusal is an outage.
    authority
        .next_opening()
        .await
        .refuse(closing_status(code, Some(error_code)));
    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, class);
    assert_eq!(closure.grpc_code, Some(code));
    assert_eq!(closure.error_code.as_deref(), Some(error_code));
    assert_eq!(closure.server_time.as_deref(), Some(SERVER_TIME));
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[rstest]
#[case::revoked(
    Code::PermissionDenied,
    Some("identity_revoked"),
    ClosureClass::Terminal(TerminalCode::IdentityRevoked)
)]
#[case::expired(Code::Unauthenticated, Some("certificate_expired"), ClosureClass::CertificateExpired)]
#[case::rotated(Code::Ok, None, ClosureClass::Transient(TransientKind::Outage))]
#[case::without_error_code(Code::Internal, None, ClosureClass::Transient(TransientKind::Outage))]
#[tokio::test]
async fn reports_the_closure_of_an_authenticated_stream(
    #[case] code: Code,
    #[case] error_code: Option<&str>,
    #[case] class: ClosureClass,
) -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    stream.close(closing_status(code, error_code)).await;
    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, class);
    assert_eq!(closure.grpc_code, Some(code));
    assert_eq!(closure.error_code.as_deref(), error_code);
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
#[rstest]
#[case::revoked(Code::PermissionDenied, "identity_revoked")]
#[case::unknown(Code::Unauthenticated, "identity_unknown")]
#[case::expired(Code::Unauthenticated, "certificate_expired")]
#[tokio::test]
async fn stops_after_a_terminal_or_expired_certificate_closure(
    #[case] code: Code,
    #[case] error_code: &str,
) -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;

    // The agent reconnects unless the identity is terminal, and renews after `certificate_expired` before it retries.
    authority
        .next_opening()
        .await
        .refuse(closing_status(code, Some(error_code)));
    let (_, reopen_after) = next_closure(&mut channel).await;
    assert_eq!(reopen_after, None);
    let end = tokio::time::timeout(WAIT, channel.next_event()).await?;
    assert_eq!(end, None, "the channel keeps running");
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
#[rstest]
#[case::identity_revoked(TerminalCode::IdentityRevoked, "identity_revoked")]
#[case::identity_unknown(TerminalCode::IdentityUnknown, "identity_unknown")]
fn names_each_terminal_code_as_the_contract_does(#[case] code: TerminalCode, #[case] name: &str) {
    assert_eq!(code.as_str(), name);
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn a_refused_connection_is_an_outage() -> anyhow::Result<()> {
    let authority = TestAuthority::start(Mode::Grpc).await?;
    let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = Url::parse(&format!("https://127.0.0.1:{}/dvls", unused.local_addr()?.port()))?;
    drop(unused);
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&url))?;

    // A network error is transient, and no authority sent a gRPC status.
    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert_eq!(closure.grpc_code, None);
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
// oracle: intent crates/agent-identity/INTENT.md §Trust and transport
// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn an_untrusted_server_certificate_is_an_outage() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let other_root = Pki::generate()?.ca;
    let client = ChannelClient::new(ProxyConfig::Off, &[other_root], Settings::default())?;
    let mut channel = client.connect(identity.target(&authority.url))?;

    // A TLS error is transient, and the opening never reaches a server the agent does not trust.
    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert!(authority.opening_within(Duration::ZERO).await.is_none());
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[rstest]
#[case::html_over_http2(Mode::Http2Page(StatusCode::NOT_FOUND, "text/html"))]
#[case::html_with_success_over_http2(Mode::Http2Page(StatusCode::OK, "text/html"))]
// oracle: spec gRPC Web (grpc/grpc doc/PROTOCOL-WEB.md) §Protocol differences vs gRPC over HTTP2
#[case::grpc_web_over_http2(Mode::Http2Page(StatusCode::NOT_FOUND, "application/grpc-web"))]
#[case::http1_without_alpn(Mode::Http1WithoutAlpn)]
#[case::http1_alpn(Mode::Http1Alpn)]
#[tokio::test]
async fn a_path_that_cannot_carry_grpc_is_reported_as_such(#[case] mode: Mode) -> anyhow::Result<()> {
    let authority = TestAuthority::start(mode).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;

    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::NoGrpcPath));
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
// oracle: spec RFC 9110 §15.6
// A 5xx status reports a failure of the server, such as a reverse proxy whose upstream is down, not a path that can't
// carry gRPC.
#[rstest]
#[case::internal_server_error(StatusCode::INTERNAL_SERVER_ERROR)]
#[case::bad_gateway(StatusCode::BAD_GATEWAY)]
#[case::service_unavailable(StatusCode::SERVICE_UNAVAILABLE)]
#[case::gateway_timeout(StatusCode::GATEWAY_TIMEOUT)]
#[tokio::test]
async fn a_non_grpc_server_error_is_an_outage(#[case] status: StatusCode) -> anyhow::Result<()> {
    let authority = TestAuthority::start(Mode::Http2Page(status, "text/html")).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;

    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[rstest]
// oracle: spec gRPC over HTTP2 (grpc/grpc doc/PROTOCOL-HTTP2.md) §Requests
#[case::with_a_message_format("application/grpc+proto")]
// oracle: spec RFC 9110 §8.3.1
#[case::in_upper_case("Application/GRPC")]
#[tokio::test]
async fn authenticates_whatever_form_the_grpc_content_type_takes(
    #[case] content_type: &'static str,
) -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::GrpcAs(content_type)).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;

    authority.next_opening().await.accept().authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Handshake
#[rstest]
#[case::shorter(31)]
#[case::longer(33)]
#[tokio::test]
async fn closes_without_hello_when_the_challenge_is_not_32_bytes(#[case] length: usize) -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();

    stream.challenge(&vec![1; length]).await;
    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert!(!matches!(stream.receive_within(WAIT).await, Some(Ok(Some(_)))));
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[rstest]
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
#[case::empty_id(encoded_challenge(""))]
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
#[case::upper_case_id(encoded_challenge("0F5D2C8E-3B1A-4C6D-9E7F-1A2B3C4D5E6F"))]
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
#[case::id_without_hyphens(encoded_challenge("0f5d2c8e3b1a4c6d9e7f1a2b3c4d5e6f"))]
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
#[case::id_longer_than_a_reply_may_echo(encoded_challenge(&long_id()))]
#[case::undecodable(truncated(encoded_challenge(&new_id())))]
#[tokio::test]
async fn closes_without_hello_on_a_challenge_it_cannot_trust(#[case] message: Vec<u8>) -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, quick_reopening())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
    assert!(message.len() <= 65_536, "the authority may send this message");
    stream.send_encoded(&message);

    assert!(!matches!(stream.receive_within(WAIT).await, Some(Ok(Some(_)))));
    let (closure, reopen_after) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert_eq!(reopen_after, Some(Duration::from_micros(15_625)));
    authority.next_opening().await;
    Ok(())
}

/// Settings whose backoff jitter of 1/64 keeps the delays short and exact: 1 s becomes 15.625 ms.
fn quick_reopening() -> Settings {
    Settings {
        backoff: Backoff {
            jitter: Arc::new(|| 1.0 / 64.0),
            ..Backoff::default()
        },
        ..Settings::default()
    }
}

/// An `id` that fills a `Challenge` envelope to the 65,536 bytes an envelope may take, which a reply that echoes it
/// would exceed ([CONTRACT.agent-identity.md] §7.1).
///
/// The `Challenge` takes 1 (key of `id`) + 3 (length) + 65,496 (`id`) + 36 (`challenge` record of 32 bytes) bytes.
/// An `Ack` that echoes it takes 38 (`id` record of a UUID) + 1 (key of `correlation_id`) + 3 (length) + 65,496
/// (`correlation_id`) + 2 (empty `ack` record) = 65,540 bytes, and a `Hello` more.
fn long_id() -> String {
    "a".repeat(65_496)
}

/// Encodes a `Challenge` of 32 bytes under the envelope `id`.
fn encoded_challenge(id: &str) -> Vec<u8> {
    let mut message = length_delimited(1 /* id */, id.as_bytes());
    message.extend(length_delimited(
        14, /* challenge */
        &length_delimited(1 /* challenge */, &[1; 32]),
    ));
    message
}

/// Removes the last byte of an encoded message, which leaves its last record shorter than its length says.
fn truncated(mut message: Vec<u8>) -> Vec<u8> {
    message.pop();
    message
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[rstest]
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
#[case::empty_id(encoded_renewal(""))]
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
#[case::upper_case_id(encoded_renewal("0F5D2C8E-3B1A-4C6D-9E7F-1A2B3C4D5E6F"))]
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
#[case::id_without_hyphens(encoded_renewal("0f5d2c8e3b1a4c6d9e7f1a2b3c4d5e6f"))]
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
#[case::id_longer_than_an_ack_may_echo(encoded_renewal(&long_id()))]
#[case::undecodable(truncated(encoded_renewal(&new_id())))]
#[tokio::test]
async fn closes_without_reporting_a_message_it_cannot_trust(#[case] message: Vec<u8>) -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, quick_reopening())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
    assert!(message.len() <= 65_536, "the authority may send this message");
    stream.send_encoded(&message);

    // Without a `RenewRequested` event, the caller has nothing to acknowledge.
    let (closure, reopen_after) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert_eq!(reopen_after, Some(Duration::from_micros(15_625)));
    assert!(!matches!(stream.receive_within(WAIT).await, Some(Ok(Some(_)))));
    authority.next_opening().await;
    Ok(())
}

/// Encodes a `RenewRequested` under the envelope `id`.
fn encoded_renewal(id: &str) -> Vec<u8> {
    let mut message = length_delimited(1 /* id */, id.as_bytes());
    message.extend(length_delimited(
        12, /* renew_requested */
        &length_delimited(1 /* reason */, b"admin"),
    ));
    message
}

// oracle: intent crates/device-key/INTENT.md §Signing
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn a_proof_signing_failure_closes_the_stream_as_an_outage() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let mut identity = Identity::from_vectors("device-a")?;
    identity.key = Arc::new(TestKey {
        name: identity.key.name.clone(),
        key: identity.key.key.clone(),
        fail_proofs: true,
    });
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();

    // Signing can fail, a failure the contract does not name is transient, and without a proof there is no `Hello`.
    stream.challenge(&[1; 32]).await;
    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert!(!matches!(stream.receive_within(WAIT).await, Some(Ok(Some(_)))));
    Ok(())
}

/// The `created` parameter of an opening signature.
fn created(opening: &authority::Opening) -> i64 {
    opening
        .signature_input()
        .split_once(";created=")
        .and_then(|(_, rest)| rest.split(';').next())
        .and_then(|created| created.parse().ok())
        .expect("signature-input without created")
}

fn clock_skew_refusal(server_time: OffsetDateTime) -> Status {
    let mut status = Status::new(Code::Unauthenticated, "clock skew");
    let metadata = status.metadata_mut();
    metadata.insert("error-code", "clock_skew".parse().expect("ASCII error code"));
    metadata.insert(
        "server-time",
        server_time
            .format(&Rfc3339)
            .expect("RFC 3339 time")
            .parse()
            .expect("ASCII time"),
    );
    status
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
#[tokio::test]
async fn retries_a_clock_skew_refusal_once_at_the_server_time() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let local_time = OffsetDateTime::now_utc();
    let server_time = local_time + Duration::from_secs(7200);

    authority.next_opening().await.refuse(clock_skew_refusal(server_time));

    // The retry offsets `created` by `server_time − local_time`, from the `server-time` trailer.
    // The agent reads its clock after `local_time` and signs before the retry arrives, so `created` exceeds the server
    // time by at most the whole seconds that passed meanwhile.
    let retry = authority.next_opening().await;
    let elapsed = OffsetDateTime::now_utc().unix_timestamp() - local_time.unix_timestamp();
    let retry_created = created(&retry);
    let expected = server_time.unix_timestamp();
    assert!(
        (expected..=expected + elapsed).contains(&retry_created),
        "created {retry_created}, server time {expected}, {elapsed} s elapsed"
    );
    retry.accept().authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn a_second_clock_skew_refusal_is_transient() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let server_time = OffsetDateTime::now_utc() + Duration::from_secs(7200);

    authority.next_opening().await.refuse(clock_skew_refusal(server_time));
    authority.next_opening().await.refuse(clock_skew_refusal(server_time));

    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert_eq!(closure.error_code.as_deref(), Some("clock_skew"));
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn reopens_after_each_transient_closure_once_its_growing_delay_has_passed() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    // A jitter of 1/64 keeps the delays short and exact: 1 s becomes 15.625 ms.
    let settings = Settings {
        backoff: Backoff {
            jitter: Arc::new(|| 1.0 / 64.0),
            ..Backoff::default()
        },
        ..Settings::default()
    };
    let mut channel = client(&authority, settings)?.connect(identity.target(&authority.url))?;

    // A timer never fires early (`tokio::time::sleep`), so each reopening comes at least its delay after the closure.
    let mut opening = authority.next_opening().await;
    for delay in [15_625, 31_250, 62_500].map(Duration::from_micros) {
        let refused = tokio::time::Instant::now();
        opening.refuse(closing_status(Code::Unavailable, Some("unavailable")));
        let (_, reopen_after) = next_closure(&mut channel).await;
        assert_eq!(reopen_after, Some(delay));
        opening = authority.next_opening().await;
        assert!(delay <= refused.elapsed());
    }
    Ok(())
}

/// Settings that reopen quickly, count a stream as long-lived after `stable_after`, and draw a spread of 40 ms.
fn quick_reopening_stable_after(stable_after: Duration) -> Settings {
    let settings = quick_reopening();
    Settings {
        backoff: Backoff {
            stable_after,
            spread: Arc::new(|| Duration::from_millis(40)),
            ..settings.backoff
        },
        ..settings
    }
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn keeps_backing_off_after_a_stream_that_drops_soon_after_authenticating() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let settings = quick_reopening_stable_after(Duration::from_secs(3));
    let mut channel = client(&authority, settings)?.connect(identity.target(&authority.url))?;
    authority
        .next_opening()
        .await
        .refuse(closing_status(Code::Unavailable, Some("unavailable")));
    assert_eq!(next_closure(&mut channel).await.1, Some(Duration::from_micros(15_625)));

    // The opening outlasts the stable time, which counts only from `Welcome`.
    let mut stream = authority.next_opening().await.accept();
    stream.challenge(&[7; 32]).await;
    let hello = stream.receive().await;
    // The 3 s stable time leaves a scheduling stall between `Welcome` and the closure room to pass.
    tokio::time::sleep(Duration::from_millis(3500)).await;
    stream
        .send(
            &new_id(),
            Some(&hello.id),
            Payload::Welcome(Welcome { server_time: None }),
        )
        .await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);
    stream
        .close(closing_status(Code::Unavailable, Some("unavailable")))
        .await;

    assert_eq!(next_closure(&mut channel).await.1, Some(Duration::from_micros(31_250)));
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn spreads_the_reconnect_after_a_stream_that_stayed_authenticated() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let settings = quick_reopening_stable_after(Duration::from_millis(300));
    let mut channel = client(&authority, settings)?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    tokio::time::sleep(Duration::from_millis(400)).await;
    stream
        .close(closing_status(Code::Unavailable, Some("unavailable")))
        .await;

    assert_eq!(next_closure(&mut channel).await.1, Some(Duration::from_millis(40)));
    authority.next_opening().await;
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Handshake
// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn an_opening_without_welcome_in_time_is_an_outage() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    // The client must send its `Hello` before the opening times out, which a loaded machine has taken more than 300 ms
    // to do; the closure must still come well within `WAIT`.
    let settings = Settings {
        opening_timeout: Duration::from_secs(2),
        ..Settings::default()
    };
    let mut channel = client(&authority, settings)?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.challenge(&[1; 32]).await;
    stream.receive().await;

    // A network error, which no gRPC status explains.
    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert_eq!(closure.grpc_code, None);
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
// oracle: intent crates/agent-channel-client/INTENT.md §Closing
#[tokio::test]
async fn opens_a_new_stream_while_the_current_one_stays_open() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let client = client(&authority, Settings::default())?;
    let mut current = client.connect(Identity::from_vectors("device-a")?.target(&authority.url))?;
    let mut current_stream = authority.next_opening().await.accept();
    current_stream.authenticate().await;
    assert_eq!(next_event(&mut current).await, Event::Authenticated);

    // Step 6 of §7.3 and step 4 of §8.1: the new stream, here for a renewed key, opens before the old one closes.
    let mut next = client.connect(Identity::from_vectors("device-b")?.target(&authority.url))?;
    let mut next_stream = authority.next_opening().await.accept();
    next_stream.authenticate().await;
    assert_eq!(next_event(&mut next).await, Event::Authenticated);
    assert!(
        current_stream
            .receive_within(Duration::from_millis(300))
            .await
            .is_none(),
        "the current stream ended before the caller closed it"
    );

    drop(current);
    assert!(matches!(
        current_stream.receive_within(WAIT).await,
        Some(Ok(None) | Err(_))
    ));
    assert!(next_stream.receive_within(Duration::from_millis(300)).await.is_none());
    Ok(())
}

fn manual_proxy(proxy: &str, exclude: &[&str]) -> anyhow::Result<ProxyConfig> {
    Ok(ProxyConfig::Manual(http_client_proxy::ManualProxyConfig {
        https: Some(Url::parse(proxy)?),
        exclude: exclude.iter().map(|pattern| (*pattern).to_owned()).collect(),
        ..Default::default()
    }))
}

/// The value of the header `name` in an HTTP/1.1 request head.
fn header<'head>(head: &'head str, name: &str) -> Option<&'head str> {
    head.lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

fn authority_address(authority: &TestAuthority) -> String {
    format!("127.0.0.1:{}", authority.url.port().expect("authority port"))
}

// oracle: intent crates/agent-identity/INTENT.md §Trust and transport
// oracle: reference reqwest 0.12.28 `IntoProxy`, which reads a proxy URL without a scheme as an `http://` URL
// Identity requests go through such a proxy, so the channel must too.
#[tokio::test]
async fn tunnels_through_a_proxy_set_without_a_scheme_as_an_http_proxy() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let proxy = TestProxy::start(None).await?;
    let port = proxy.host.rsplit_once(':').ok_or_else(|| anyhow!("proxy port"))?.1;
    let identity = Identity::from_vectors("device-a")?;
    let client = ChannelClient::new(
        manual_proxy(&format!("localhost:{port}"), &[])?,
        std::slice::from_ref(&authority.ca),
        Settings::default(),
    )?;
    let mut channel = client.connect(identity.target(&authority.url))?;
    authority.next_opening().await.accept().authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);
    assert_eq!(proxy.heads().len(), 1);
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[rstest]
// oracle: reference hyper-util 0.1.20 proxy matcher, which percent-decodes the user info for reqwest
// The user info decodes to `agent@corp` and `p:ss`.
#[case::user_and_password("agent%40corp:p%3Ass", "agent@corp:p:ss")]
// oracle: reference hyper-util 0.1.20 `test_parse_http_auth_without_password`, the proxy parser of reqwest
#[case::user_only("Aladdin", "Aladdin:")]
#[tokio::test]
async fn tunnels_through_an_http_proxy_with_the_credentials_of_its_url(
    #[case] user_info: &str,
    #[case] credentials: &str,
) -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let proxy = TestProxy::start(None).await?;
    let identity = Identity::from_vectors("device-a")?;
    let proxy_config = manual_proxy(&format!("http://{user_info}@{}", proxy.host), &[])?;
    let client = ChannelClient::new(proxy_config, std::slice::from_ref(&authority.ca), Settings::default())?;
    let mut channel = client.connect(identity.target(&authority.url))?;
    authority.next_opening().await.accept().authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    let heads = proxy.heads();
    assert_eq!(heads.len(), 1);
    let head = &heads[0];
    // oracle: spec RFC 9110 §9.3.6
    assert!(
        head.starts_with(&format!("CONNECT {} HTTP/1.1\r\n", authority_address(&authority))),
        "{head}"
    );
    // oracle: spec RFC 7617 §2
    // Basic credentials are the Base64 of the user ID, a colon and the password.
    let authorization = format!("Basic {}", STANDARD.encode(credentials));
    assert_eq!(header(head, "proxy-authorization"), Some(authorization.as_str()));
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn tunnels_through_an_https_proxy() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let proxy_pki = Pki::generate()?;
    // oracle: spec RFC 7301 §3.2
    // A proxy that also offers HTTP/2 would select it if the agent offered it, and then expect HTTP/2.
    let proxy = TestProxy::start(Some(proxy_pki.server_config(&[b"h2", b"http/1.1"])?)).await?;
    let identity = Identity::from_vectors("device-a")?;
    let proxy_config = manual_proxy(&format!("https://{}", proxy.host), &[])?;
    let roots = [authority.ca.clone(), proxy_pki.ca.clone()];
    let mut channel =
        ChannelClient::new(proxy_config, &roots, Settings::default())?.connect(identity.target(&authority.url))?;
    authority.next_opening().await.accept().authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    let heads = proxy.heads();
    assert_eq!(heads.len(), 1);
    // oracle: spec RFC 9110 §9.3.6
    assert!(
        heads[0].starts_with(&format!("CONNECT {} HTTP/1.1\r\n", authority_address(&authority))),
        "{}",
        heads[0]
    );
    assert_eq!(header(&heads[0], "proxy-authorization"), None);
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn connects_directly_to_a_host_the_proxy_excludes() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let proxy = TestProxy::start(None).await?;
    let identity = Identity::from_vectors("device-a")?;
    let proxy_config = manual_proxy(&format!("http://{}", proxy.host), &["127.0.0.1"])?;
    let client = ChannelClient::new(proxy_config, std::slice::from_ref(&authority.ca), Settings::default())?;
    let mut channel = client.connect(identity.target(&authority.url))?;
    authority.next_opening().await.accept().authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);
    assert!(proxy.heads().is_empty());
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
// oracle: reference reqwest 0.12.28 `connect_socks`, which resolves the name locally for `socks5` but not `socks5h`
#[rstest]
#[case::socks5("socks5://agent%40corp:p%3Ass@", Some(("agent@corp", "p:ss")), None)]
#[case::socks5h("socks5h://", None, Some("localhost"))]
#[tokio::test]
async fn tunnels_through_a_socks5_proxy_resolving_the_name_where_its_scheme_says(
    #[case] proxy_prefix: &str,
    #[case] credentials: Option<(&str, &str)>,
    #[case] domain: Option<&str>,
) -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let proxy = TestSocksProxy::start().await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut url = authority.url.clone();
    url.set_host(Some("localhost"))?;
    let proxy_config = manual_proxy(&format!("{proxy_prefix}{}", proxy.host), &[])?;
    let client = ChannelClient::new(proxy_config, std::slice::from_ref(&authority.ca), Settings::default())?;
    let mut channel = client.connect(identity.target(&url))?;
    authority.next_opening().await.accept().authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    let expected = SocksRequest {
        credentials: credentials.map(|(user, password)| (user.to_owned(), password.to_owned())),
        domain: domain.map(str::to_owned),
    };
    assert_eq!(proxy.requests(), [expected]);
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
// oracle: reference reqwest 0.12.28 `connect_socks`, which resolves the name locally for `socks4`
#[tokio::test]
async fn sends_a_socks4_proxy_the_address_of_the_authority() -> anyhow::Result<()> {
    let authority = TestAuthority::start(Mode::Grpc).await?;
    let proxy = TestSocksProxy::start().await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut url = authority.url.clone();
    url.set_host(Some("localhost"))?;
    let proxy_config = manual_proxy(&format!("socks4://{}", proxy.host), &[])?;
    let client = ChannelClient::new(proxy_config, std::slice::from_ref(&authority.ca), Settings::default())?;
    let _channel = client.connect(identity.target(&url))?;

    // Only the request counts: the NUL that hyper-util adds after the user ID reaches the authority through the tunnel,
    // as the known limitation in `Transport::tunnel` says.
    wait_until("a SOCKS request", || !proxy.requests().is_empty()).await;
    let expected = SocksRequest {
        credentials: None,
        domain: None,
    };
    assert_eq!(proxy.requests().first(), Some(&expected));
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
#[tokio::test]
async fn an_unsupported_proxy_scheme_is_an_outage_without_a_connection() -> anyhow::Result<()> {
    let authority = TestAuthority::start(Mode::Grpc).await?;
    let proxy = TestProxy::start(None).await?;
    let identity = Identity::from_vectors("device-a")?;
    let proxy_config = manual_proxy(&format!("ftp://{}", proxy.host), &[])?;
    let client = ChannelClient::new(proxy_config, std::slice::from_ref(&authority.ca), Settings::default())?;
    let mut channel = client.connect(identity.target(&authority.url))?;

    // The channel connects only through the configured proxy, which can't carry it here, so it fails without a
    // connection, neither through the proxy nor around it; a failure the contract does not name is transient.
    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert!(proxy.heads().is_empty());
    Ok(())
}

fn unreadable_system_proxy(_: &Url) -> anyhow::Result<Option<String>> {
    anyhow::bail!("system proxy settings unreadable")
}

fn unparseable_system_proxy(_: &Url) -> anyhow::Result<Option<String>> {
    // The port is out of range.
    Ok(Some("http://proxy.test:99999".to_owned()))
}

// oracle: intent crates/agent-channel-client/INTENT.md §Connection
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
#[rstest]
#[case::detection_fails(unreadable_system_proxy)]
#[case::unparseable_proxy(unparseable_system_proxy)]
#[tokio::test]
async fn a_system_proxy_the_channel_cannot_read_is_an_outage_without_a_connection(
    #[case] system_proxy: fn(&Url) -> anyhow::Result<Option<String>>,
) -> anyhow::Result<()> {
    // The authority counts the connections it receives and closes each one.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = Url::parse(&format!("https://127.0.0.1:{}/dvls", listener.local_addr()?.port()))?;
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&connections);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    let identity = Identity::from_vectors("device-a")?;
    let mut client = ChannelClient::new(ProxyConfig::System, &[], Settings::default())?;
    Arc::get_mut(&mut client.shared)
        .ok_or_else(|| anyhow!("client shared"))?
        .transport
        .system_proxy = system_proxy;
    let mut channel = client.connect(identity.target(&url))?;

    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert_eq!(connections.load(Ordering::SeqCst), 0);
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-url
#[tokio::test]
async fn refuses_a_channel_url_without_tls() -> anyhow::Result<()> {
    let authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut url = authority.url.clone();
    url.set_scheme("http").expect("http is a valid scheme");

    // The channel URL is an `https` URL.
    assert!(
        client(&authority, Settings::default())?
            .connect(identity.target(&url))
            .is_err()
    );
    Ok(())
}

#[test]
fn the_default_timings_are_the_documented_ones() {
    let settings = Settings::default();
    // oracle: intent crates/agent-channel-client/INTENT.md §Connection
    assert_eq!(settings.keepalive_interval, Duration::from_secs(30));
    // oracle: intent crates/agent-channel-client/INTENT.md §Handshake
    assert_eq!(settings.opening_timeout, Duration::from_secs(30));
}

// oracle: intent crates/agent-channel-client/INTENT.md §Closing
#[tokio::test]
async fn sends_the_acknowledgements_queued_before_the_channel_is_dropped() -> anyhow::Result<()> {
    // The agent stores a config, replies `Ack`, then applies it, which may close the stream (contract §7.3, step 7).
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);
    let update_id = new_id();
    stream
        .send(
            &update_id,
            None,
            Payload::ConfigUpdate(ConfigUpdate {
                config_json: r#"{"version":1,"revision":2}"#.to_owned(),
            }),
        )
        .await;
    next_event(&mut channel).await;

    channel.ack(&update_id);
    drop(channel);

    let ack = stream.receive_within(WAIT).await;
    assert!(
        matches!(&ack, Some(Ok(Some(message))) if message.correlation_id.as_deref() == Some(update_id.as_str())),
        "{ack:?}"
    );
    // The agent then ends its side, which the authority reads as the end of the stream rather than a reset.
    let end = stream.receive_within(WAIT).await;
    assert!(matches!(end, Some(Ok(None))), "{end:?}");
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Closing
#[tokio::test]
async fn dropping_the_channel_stops_an_opening_at_once() -> anyhow::Result<()> {
    // An opening signed with a key that a `confirm` retired draws the terminal `identity_unknown` (contract §6, step
    // 4), so the caller's drop must end it.
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();

    drop(channel);

    assert!(matches!(stream.receive_within(WAIT).await, Some(Ok(None) | Err(_))));
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Closing
#[tokio::test]
async fn dropping_the_channel_stops_it_from_reopening() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let settings = Settings {
        backoff: Backoff {
            jitter: Arc::new(|| 0.5),
            ..Backoff::default()
        },
        ..Settings::default()
    };
    let mut channel = client(&authority, settings)?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);
    stream
        .close(closing_status(Code::Unavailable, Some("unavailable")))
        .await;
    let (_, reopen_after) = next_closure(&mut channel).await;
    assert_eq!(reopen_after, Some(Duration::from_millis(500)));

    drop(channel);

    // Without the drop, the channel would reopen 500 ms after the closure, well within this wait.
    assert!(authority.opening_within(Duration::from_secs(2)).await.is_none());
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Closing
#[tokio::test]
async fn dropping_the_channel_ends_its_wait_to_reopen_at_once() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    // A jitter of 1000 makes the first wait 1000 s, which the cap shortens to 5 min, far beyond the test's wait.
    let settings = Settings {
        backoff: Backoff {
            jitter: Arc::new(|| 1000.0),
            ..Backoff::default()
        },
        ..Settings::default()
    };
    let hello = hello_fields();
    let target = identity.target_with_hello(&authority.url, Arc::clone(&hello));
    let mut channel = client(&authority, settings)?.connect(target)?;
    authority
        .next_opening()
        .await
        .refuse(closing_status(Code::Unavailable, Some("unavailable")));
    let (_, reopen_after) = next_closure(&mut channel).await;
    assert_eq!(reopen_after, Some(Duration::from_secs(300)));

    drop(channel);

    // A stopped channel no longer holds its target.
    wait_until("the release of the target", || Arc::strong_count(&hello) == 1).await;
    Ok(())
}

// oracle: intent crates/agent-channel-client/INTENT.md §Closing
#[tokio::test]
async fn a_dropped_channel_stops_waiting_for_an_authority_that_keeps_its_side_open() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let hello = hello_fields();
    let target = identity.target_with_hello(&authority.url, Arc::clone(&hello));
    let mut channel = client(&authority, Settings::default())?.connect(target)?;
    let mut stream = authority.next_opening().await.accept();
    stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    drop(channel);

    // The authority's side stays open while `stream` lives; the channel gives it 5 s, less than `WAIT`.
    wait_until("the release of the target", || Arc::strong_count(&hello) == 1).await;
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
#[tokio::test]
async fn drops_an_acknowledgement_of_a_closed_stream() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let settings = Settings {
        backoff: Backoff {
            jitter: Arc::new(|| 1.0 / 64.0),
            ..Backoff::default()
        },
        ..Settings::default()
    };
    let mut channel = client(&authority, settings)?.connect(identity.target(&authority.url))?;
    let renew = |reason: &str| {
        Payload::RenewRequested(RenewRequested {
            reason: reason.to_owned(),
        })
    };

    let mut first = authority.next_opening().await.accept();
    first.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);
    let old_id = new_id();
    first.send(&old_id, None, renew("admin")).await;
    next_event(&mut channel).await;
    first
        .close(closing_status(Code::Unavailable, Some("unavailable")))
        .await;
    next_closure(&mut channel).await;
    channel.ack(&old_id);

    // An `Ack` replies to a message of its own stream (step 5), so the next stream carries only the new one.
    let mut second = authority.next_opening().await.accept();
    second.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);
    let new_id = new_id();
    second.send(&new_id, None, renew("rotation")).await;
    next_event(&mut channel).await;
    channel.ack(&new_id);
    assert_eq!(second.receive().await.correlation_id, Some(new_id));
    Ok(())
}

/// Checks that a closure with gRPC status OK keeps its trailers and, with an unknown error code, stays transient.
fn assert_ok_closure_with_trailers(closure: &Closure) {
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert_eq!(closure.grpc_code, Some(Code::Ok));
    assert_eq!(closure.error_code.as_deref(), Some("future_code"));
    assert_eq!(closure.server_time.as_deref(), Some(SERVER_TIME));
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn reports_the_trailers_of_an_opening_refused_with_ok() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;

    authority
        .next_opening()
        .await
        .refuse(closing_status(Code::Ok, Some("future_code")));
    assert_ok_closure_with_trailers(&next_closure(&mut channel).await.0);
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn reports_the_trailers_of_a_stream_closed_with_ok_before_welcome() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.challenge(&[1; 32]).await;
    stream.receive().await;

    stream.close(closing_status(Code::Ok, Some("future_code"))).await;
    assert_ok_closure_with_trailers(&next_closure(&mut channel).await.0);
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
// oracle: intent crates/agent-channel-client/INTENT.md §Connection
#[tokio::test]
async fn reports_the_trailers_of_a_stream_closed_with_ok_after_welcome() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    // A retired certificate's streams are closed with OK.
    stream.close(closing_status(Code::Ok, Some("future_code"))).await;
    assert_ok_closure_with_trailers(&next_closure(&mut channel).await.0);
    Ok(())
}
