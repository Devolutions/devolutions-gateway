//! The task behind one [`Channel`](crate::Channel): it opens, authenticates and reopens the stream.

use std::collections::HashMap;
use std::sync::Arc;

use agent_channel_proto::agent_channel_client::AgentChannelClient;
use agent_channel_proto::server_message::Payload;
use agent_channel_proto::{Ack, AgentMessage, Hello, ServerMessage, agent_message};
use agent_identity_httpsig::{ChannelLayer, OpeningNonce, RequestSigner};
use anyhow::Context as _;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Streaming;
use tower::Layer as _;
use uuid::Uuid;

use crate::transport::endpoint;
use crate::{Event, Shared, Target};

const CHANNEL_PROOF_DOMAIN: &[u8] = b"devolutions-agent-identity/v1/channel-proof";

pub(crate) async fn run(
    shared: Arc<Shared>,
    target: Target,
    events: mpsc::Sender<Event>,
    mut acks: mpsc::UnboundedReceiver<String>,
) {
    let Ok(mut opened) = open(&shared, &target).await else {
        return;
    };
    if authenticate(&target, &mut opened).await.is_err() {
        return;
    }
    if events.send(Event::Authenticated).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            message = opened.inbound.message() => match message {
                Ok(Some(message)) => {
                    if let Some(event) = push_event(message)
                        && events.send(event).await.is_err()
                    {
                        return;
                    }
                }
                Ok(None) | Err(_) => return,
            },
            Some(correlation_id) = acks.recv() => {
                let ack = AgentMessage {
                    id: Uuid::new_v4().to_string(),
                    correlation_id: Some(correlation_id),
                    payload: Some(agent_message::Payload::Ack(Ack {})),
                };
                if opened.outbound.send(ack).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Answers the challenge and waits for `Welcome` ([CONTRACT.md] §7.3 steps 2–4).
///
/// Until `Welcome` answers the `Hello`, every other message is ignored, so that nothing counts before the
/// authority has verified the proof.
///
/// [CONTRACT.md]: ../../docs/agent-identity/CONTRACT.md
async fn authenticate(target: &Target, opened: &mut Opened) -> anyhow::Result<()> {
    let (challenge_id, challenge) = loop {
        match opened.inbound.message().await? {
            Some(ServerMessage {
                id,
                payload: Some(Payload::Challenge(challenge)),
                ..
            }) => break (id, challenge.challenge),
            Some(_) => {}
            None => anyhow::bail!("stream closed before Challenge"),
        }
    };
    let hello = hello(target, &challenge_id, &challenge, &opened.nonce)?;
    let hello_id = hello.id.clone();
    opened.outbound.send(hello).await.context("send Hello")?;
    loop {
        match opened.inbound.message().await? {
            Some(ServerMessage {
                correlation_id: Some(correlation_id),
                payload: Some(Payload::Welcome(_)),
                ..
            }) if correlation_id == hello_id => return Ok(()),
            Some(_) => {}
            None => anyhow::bail!("stream closed before Welcome"),
        }
    }
}

/// Returns the event that reports a message on the authenticated stream, if the caller acts on it.
fn push_event(message: ServerMessage) -> Option<Event> {
    match message.payload? {
        Payload::RenewRequested(request) => Some(Event::RenewRequested {
            id: message.id,
            reason: request.reason,
        }),
        Payload::Reconnect(request) => Some(Event::Reconnect {
            id: message.id,
            reason: request.reason,
        }),
        Payload::ConfigUpdate(update) => Some(Event::ConfigUpdate {
            id: message.id,
            config_json: update.config_json,
        }),
        Payload::Welcome(_) | Payload::Ack(_) | Payload::Challenge(_) => None,
    }
}

/// A stream whose opening the authority accepted.
struct Opened {
    outbound: mpsc::Sender<AgentMessage>,
    inbound: Streaming<ServerMessage>,
    /// The nonce of the opening signature, which the channel proof binds.
    nonce: String,
}

/// Builds the `Hello` that answers a challenge ([CONTRACT.md] §7.3 step 3).
///
/// [CONTRACT.md]: ../../docs/agent-identity/CONTRACT.md
fn hello(target: &Target, challenge_id: &str, challenge: &[u8], nonce: &str) -> anyhow::Result<AgentMessage> {
    let proof = target
        .key
        .try_sign(&channel_proof_input(challenge, nonce))
        .context("sign channel proof")?;
    let fields = (target.hello)();
    Ok(AgentMessage {
        id: Uuid::new_v4().to_string(),
        correlation_id: Some(challenge_id.to_owned()),
        payload: Some(agent_message::Payload::Hello(Hello {
            metadata: fields.metadata,
            capabilities: Vec::new(),
            applied_state_versions: HashMap::from([("config".to_owned(), fields.config_revision)]),
            proof: proof.to_bytes().to_vec(),
        })),
    })
}

/// Sends the signed opening request ([CONTRACT.md] §7.3 step 1).
///
/// [CONTRACT.md]: ../../docs/agent-identity/CONTRACT.md
async fn open(shared: &Shared, target: &Target) -> anyhow::Result<Opened> {
    let service = shared.transport.connect(&target.url).await?;
    let signer = RequestSigner::new(Arc::clone(&target.key), &target.leaf_certificate_der);
    let service = ChannelLayer::new(signer, &target.url).layer(service);
    let (_, origin) = endpoint(&target.url)?;
    let mut client = AgentChannelClient::with_origin(service, origin);
    let (outbound, outbound_receiver) = mpsc::channel(16);
    let (handoff, nonce) = OpeningNonce::new();
    let mut request = tonic::Request::new(ReceiverStream::new(outbound_receiver));
    request.extensions_mut().insert(handoff);
    let inbound = client
        .connect(request)
        .await
        .context("open channel stream")?
        .into_inner();
    Ok(Opened {
        outbound,
        inbound,
        nonce: nonce.await.context("receive opening nonce")?,
    })
}

/// Returns the bytes a channel proof signs ([CONTRACT.md] §7.3 step 3).
///
/// [CONTRACT.md]: ../../docs/agent-identity/CONTRACT.md
pub(crate) fn channel_proof_input(challenge: &[u8], connect_nonce: &str) -> Vec<u8> {
    let mut input =
        Vec::with_capacity(CHANNEL_PROOF_DOMAIN.len() + 1 /* separator */ + challenge.len() + connect_nonce.len());
    input.extend_from_slice(CHANNEL_PROOF_DOMAIN);
    input.push(0x00);
    input.extend_from_slice(challenge);
    input.extend_from_slice(connect_nonce.as_bytes());
    input
}
