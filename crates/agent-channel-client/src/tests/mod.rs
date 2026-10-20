mod authority;
mod proxy;
mod socks;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_channel_proto::server_message::Payload;
use agent_channel_proto::{Ack, ConfigUpdate, Reconnect, RenewRequested, Welcome, agent_message};
use anyhow::anyhow;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey as _;
use rstest::rstest;
use signature::Verifier as _;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tonic::{Code, Status};

use self::authority::{Mode, Pki, TestAuthority, WAIT, vectors};
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
        self.target_with_hello(
            url,
            Arc::new(|| HelloFields {
                metadata: HashMap::from([("hostname".to_owned(), "test-host".to_owned())]),
                config_revision: 7,
            }),
        )
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

/// A gRPC status as the authority closes a stream with it ([CONTRACT.md] §7.4).
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

#[tokio::test]
async fn opens_a_signed_stream_under_the_url_path_and_waits_for_the_challenge() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let _channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;

    // CONTRACT.md §7.2: the URL path prefixes the RPC path, and the opening carries a `connect` signature.
    let opening = authority.next_opening().await;
    assert_eq!(opening.path, "/dvls/devolutions.agent.channel.v1.AgentChannel/Connect");
    let signature_input = opening.signature_input().to_owned();
    assert!(signature_input.contains(";tag=\"connect\""), "{signature_input}");
    assert!(
        signature_input.contains(&format!(";keyid=\"{}\"", identity.thumbprint)),
        "{signature_input}"
    );
    assert!(opening.headers.contains_key("signature"));

    // CONTRACT.md §7.3 step 1: the agent sends nothing until it receives `Challenge`.
    let mut stream = opening.accept();
    assert!(stream.receive_within(Duration::from_millis(300)).await.is_none());
    Ok(())
}

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

    // CONTRACT.md §3.1: metadata is collected when the `Hello` is sent.
    *hostname.lock().expect("hostname lock") = "at-hello".to_owned();
    let challenge = [0x5a; 32];
    let challenge_id = stream.challenge(&challenge).await;
    let message = stream.receive().await;

    // CONTRACT.md §7.3 step 3.
    assert_eq!(message.correlation_id.as_deref(), Some(challenge_id.as_str()));
    let Some(agent_message::Payload::Hello(hello)) = message.payload else {
        panic!("expected Hello, got {message:?}");
    };
    assert_eq!(
        hello.metadata,
        HashMap::from([("hostname".to_owned(), "at-hello".to_owned())])
    );
    assert_eq!(hello.applied_state_versions, HashMap::from([("config".to_owned(), 7)]));
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

    // INTENT.agent-identity.md ("Conformance"): the signature need not match the vector's bytes, only verify.
    let identity = Identity::from_vectors(field("device")?)?;
    let public_key = VerifyingKey::from_sec1_bytes(&STANDARD.decode(field("public_key_sec1")?)?)?;
    let proof = identity.key.try_sign(&input)?;
    public_key.verify(&input, &proof)?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
#[tokio::test]
async fn authenticates_only_on_the_welcome_answering_its_hello() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.challenge(&[1; 32]).await;
    let hello = stream.receive().await;

    // INTENT.agent-identity.md, invariant 7: nothing counts before the challenge succeeds.
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

#[tokio::test]
async fn reports_pushes_with_their_envelope_ids_and_ignores_unknown_payloads() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    // CONTRACT.md §7.3: unknown payloads are ignored.
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

    // CONTRACT.md §7.3 step 5: `Ack` with `correlation_id` = message `id`.
    let ack = stream.receive().await;
    assert_eq!(ack.correlation_id.as_deref(), Some(renew_id.as_str()));
    assert_eq!(ack.payload, Some(agent_message::Payload::Ack(Ack {})));
    // CONTRACT.md §1 and §7.3: envelope IDs are lowercase hyphenated UUIDs.
    for id in [&hello.id, &ack.id] {
        let uuid = uuid::Uuid::parse_str(id)?;
        assert_eq!(&uuid.hyphenated().to_string(), id);
    }
    assert_ne!(hello.id, ack.id);
    Ok(())
}

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

    let before = authority.pings();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let pings = authority.pings() - before;
    assert!((5..=12).contains(&pings), "{pings} pings in 1 s at a 100 ms interval");
    Ok(())
}

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

    // CONTRACT.md §7.4 and §5.4 classify the closure.
    // A transient one is an outage: crates/agent-channel-client/INTENT.md caps the backoff at 5 min "after network
    // errors, server downtime, and any other transient refusal or closure of the stream".
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

    // CONTRACT.md §7.4: the agent reconnects unless the identity is terminal; §5.4: it renews before retrying.
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

#[tokio::test]
async fn a_refused_connection_is_an_outage() -> anyhow::Result<()> {
    let authority = TestAuthority::start(Mode::Grpc).await?;
    let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = Url::parse(&format!("https://127.0.0.1:{}/dvls", unused.local_addr()?.port()))?;
    drop(unused);
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&url))?;

    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert_eq!(closure.grpc_code, None);
    Ok(())
}

#[tokio::test]
async fn an_untrusted_server_certificate_is_an_outage() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let other_root = Pki::generate()?.ca;
    let client = ChannelClient::new(ProxyConfig::Off, &[other_root], Settings::default())?;
    let mut channel = client.connect(identity.target(&authority.url))?;

    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert!(authority.opening_within(Duration::ZERO).await.is_none());
    Ok(())
}

#[rstest]
#[case::html_over_http2(Mode::HtmlOverHttp2)]
#[case::http1_without_alpn(Mode::Http1WithoutAlpn)]
#[case::http1_alpn(Mode::Http1Alpn)]
#[tokio::test]
async fn a_path_that_cannot_carry_grpc_is_reported_as_such(#[case] mode: Mode) -> anyhow::Result<()> {
    let authority = TestAuthority::start(mode).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;

    // crates/agent-channel-client/INTENT.md: "a reverse proxy that answers without HTTP/2 or gRPC".
    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::NoGrpcPath));
    Ok(())
}

#[tokio::test]
async fn closes_without_hello_when_the_challenge_is_not_32_bytes() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();

    // CONTRACT.md §7.3 step 3 proves a 32-byte challenge.
    stream.challenge(&[1; 31]).await;
    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert!(!matches!(stream.receive_within(WAIT).await, Some(Ok(Some(_)))));
    Ok(())
}

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

#[tokio::test]
async fn retries_a_clock_skew_refusal_once_at_the_server_time() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let server_time = OffsetDateTime::now_utc() + Duration::from_secs(7200);

    authority.next_opening().await.refuse(clock_skew_refusal(server_time));

    // CONTRACT.md §6: the retry offsets `created` by `server_time − local_time`, from the `server-time` trailer.
    let retry = authority.next_opening().await;
    let retry_created = created(&retry);
    let expected = server_time.unix_timestamp();
    assert!(
        (expected..=expected + 5).contains(&retry_created),
        "created {retry_created}, server time {expected}"
    );
    retry.accept().authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);
    Ok(())
}

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

    let mut opening = authority.next_opening().await;
    for delay in [15_625, 31_250, 62_500].map(Duration::from_micros) {
        let refused = tokio::time::Instant::now();
        opening.refuse(closing_status(Code::Unavailable, Some("unavailable")));
        let (_, reopen_after) = next_closure(&mut channel).await;
        assert_eq!(reopen_after, Some(delay));
        opening = authority.next_opening().await;
        assert!(delay <= refused.elapsed());
    }

    // An authenticated stream starts the backoff from 1 s again.
    let mut stream = opening.accept();
    stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);
    stream
        .close(closing_status(Code::Unavailable, Some("unavailable")))
        .await;
    let (_, reopen_after) = next_closure(&mut channel).await;
    assert_eq!(reopen_after, Some(Duration::from_micros(15_625)));
    authority.next_opening().await;
    Ok(())
}

#[tokio::test]
async fn an_opening_without_welcome_in_time_is_an_outage() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let settings = Settings {
        opening_timeout: Duration::from_millis(300),
        ..Settings::default()
    };
    let mut channel = client(&authority, settings)?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.challenge(&[1; 32]).await;
    stream.receive().await;

    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert_eq!(closure.grpc_code, None);
    Ok(())
}

#[tokio::test]
async fn opens_a_new_stream_while_the_current_one_stays_open() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let client = client(&authority, Settings::default())?;
    let mut current = client.connect(Identity::from_vectors("device-a")?.target(&authority.url))?;
    let mut current_stream = authority.next_opening().await.accept();
    current_stream.authenticate().await;
    assert_eq!(next_event(&mut current).await, Event::Authenticated);

    // CONTRACT.md §7.3 step 6 and §8.1 step 4: the new stream, here for a renewed key, opens before the old one closes.
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

#[tokio::test]
async fn tunnels_through_an_http_proxy_with_the_credentials_of_its_url() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let proxy = TestProxy::start(None).await?;
    let identity = Identity::from_vectors("device-a")?;
    // The user info decodes to `agent@corp` and `p:ss`.
    let proxy_config = manual_proxy(&format!("http://agent%40corp:p%3Ass@{}", proxy.host), &[])?;
    let client = ChannelClient::new(proxy_config, std::slice::from_ref(&authority.ca), Settings::default())?;
    let mut channel = client.connect(identity.target(&authority.url))?;
    authority.next_opening().await.accept().authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    let heads = proxy.heads();
    assert_eq!(heads.len(), 1);
    let head = &heads[0];
    assert!(
        head.starts_with(&format!("CONNECT {} HTTP/1.1\r\n", authority_address(&authority))),
        "{head}"
    );
    let credentials = STANDARD.encode("agent@corp:p:ss");
    assert_eq!(
        header(head, "proxy-authorization"),
        Some(format!("Basic {credentials}").as_str())
    );
    Ok(())
}

#[tokio::test]
async fn tunnels_through_an_https_proxy() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let proxy_pki = Pki::generate()?;
    let proxy = TestProxy::start(Some(proxy_pki.server_config(&[])?)).await?;
    let identity = Identity::from_vectors("device-a")?;
    let proxy_config = manual_proxy(&format!("https://{}", proxy.host), &[])?;
    let roots = [authority.ca.clone(), proxy_pki.ca.clone()];
    let mut channel =
        ChannelClient::new(proxy_config, &roots, Settings::default())?.connect(identity.target(&authority.url))?;
    authority.next_opening().await.accept().authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    let heads = proxy.heads();
    assert_eq!(heads.len(), 1);
    assert!(
        heads[0].starts_with(&format!("CONNECT {} HTTP/1.1\r\n", authority_address(&authority))),
        "{}",
        heads[0]
    );
    assert_eq!(header(&heads[0], "proxy-authorization"), None);
    Ok(())
}

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

    // reqwest, which sends the agent's identity requests, resolves the name locally for `socks5` and leaves it to the
    // proxy for `socks5h`.
    let expected = SocksRequest {
        credentials: credentials.map(|(user, password)| (user.to_owned(), password.to_owned())),
        domain: domain.map(str::to_owned),
    };
    assert_eq!(proxy.requests(), [expected]);
    Ok(())
}

#[tokio::test]
async fn an_unsupported_proxy_scheme_is_an_outage_without_a_connection() -> anyhow::Result<()> {
    let authority = TestAuthority::start(Mode::Grpc).await?;
    let proxy = TestProxy::start(None).await?;
    let identity = Identity::from_vectors("device-a")?;
    let proxy_config = manual_proxy(&format!("ftp://{}", proxy.host), &[])?;
    let client = ChannelClient::new(proxy_config, std::slice::from_ref(&authority.ca), Settings::default())?;
    let mut channel = client.connect(identity.target(&authority.url))?;

    let (closure, _) = next_closure(&mut channel).await;
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert!(proxy.heads().is_empty());
    Ok(())
}

#[tokio::test]
async fn refuses_a_channel_url_without_tls() -> anyhow::Result<()> {
    let authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut url = authority.url.clone();
    url.set_scheme("http").expect("http is a valid scheme");

    // The channel runs over HTTP/2 and TLS only.
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
    // crates/agent-channel-client/INTENT.md: an HTTP/2 keepalive every 30 s.
    assert_eq!(settings.keepalive_interval, Duration::from_secs(30));
    // 30 s from the TCP connection to `Welcome`, like the identity HTTP client's request timeout.
    assert_eq!(settings.opening_timeout, Duration::from_secs(30));
}

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

/// Checks that a closure with gRPC status OK keeps its trailers and stays transient.
fn assert_ok_closure_with_trailers(closure: &Closure) {
    assert_eq!(closure.class, ClosureClass::Transient(TransientKind::Outage));
    assert_eq!(closure.grpc_code, Some(Code::Ok));
    assert_eq!(closure.error_code.as_deref(), Some("future_code"));
    assert_eq!(closure.server_time.as_deref(), Some(SERVER_TIME));
}

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

#[tokio::test]
async fn reports_the_trailers_of_a_stream_closed_with_ok_after_welcome() -> anyhow::Result<()> {
    let mut authority = TestAuthority::start(Mode::Grpc).await?;
    let identity = Identity::from_vectors("device-a")?;
    let mut channel = client(&authority, Settings::default())?.connect(identity.target(&authority.url))?;
    let mut stream = authority.next_opening().await.accept();
    stream.authenticate().await;
    assert_eq!(next_event(&mut channel).await, Event::Authenticated);

    // CONTRACT.md §7.4: a retired certificate's streams are closed with OK.
    stream.close(closing_status(Code::Ok, Some("future_code"))).await;
    assert_ok_closure_with_trailers(&next_closure(&mut channel).await.0);
    Ok(())
}
