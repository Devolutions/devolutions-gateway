mod authority;

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
use signature::Verifier as _;

use self::authority::{Mode, TestAuthority, WAIT, vectors};
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
    ChannelClient::new(ProxyConfig::Off, &[authority.ca.clone()], settings)
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
