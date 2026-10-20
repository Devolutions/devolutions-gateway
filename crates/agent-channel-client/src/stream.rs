//! The task behind one [`Channel`](crate::Channel): it opens, authenticates and reopens the stream.

use std::collections::HashMap;
use std::sync::Arc;

use agent_channel_proto::agent_channel_client::AgentChannelClient;
use agent_channel_proto::server_message::Payload;
use agent_channel_proto::{Ack, AgentMessage, Hello, ServerMessage, agent_message};
use agent_identity_httpsig::{ChannelLayer, OpeningNonce, RequestSigner};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Status, Streaming};
use tower::Layer as _;
use uuid::Uuid;

use crate::closure::Closure;
use crate::transport::endpoint;
use crate::{Event, Shared, Target};

const CHANNEL_PROOF_DOMAIN: &[u8] = b"devolutions-agent-identity/v1/channel-proof";
const CHALLENGE_LEN: usize = 32;

pub(crate) async fn run(
    shared: Arc<Shared>,
    target: Target,
    events: mpsc::Sender<Event>,
    mut acks: mpsc::UnboundedReceiver<String>,
) {
    let Some(closure) = stream_once(&shared, &target, &events, &mut acks).await else {
        return;
    };
    let _ = events
        .send(Event::Closed {
            closure,
            reopen_after: None,
        })
        .await;
}

/// Runs one stream until it closes, or returns `None` once the caller has dropped the channel.
async fn stream_once(
    shared: &Shared,
    target: &Target,
    events: &mpsc::Sender<Event>,
    acks: &mut mpsc::UnboundedReceiver<String>,
) -> Option<Closure> {
    let mut opened = match open(shared, target).await {
        Ok(opened) => opened,
        Err(closure) => return Some(closure),
    };
    if let Err(closure) = authenticate(target, &mut opened).await {
        return Some(closure);
    }
    events.send(Event::Authenticated).await.ok()?;
    loop {
        tokio::select! {
            message = opened.inbound.message() => match message {
                Ok(Some(message)) => {
                    if let Some(event) = push_event(message) {
                        events.send(event).await.ok()?;
                    }
                }
                Ok(None) => return Some(Closure::from_status(&Status::ok("stream ended"))),
                Err(status) => return Some(Closure::from_status(&status)),
            },
            Some(correlation_id) = acks.recv() => {
                let ack = AgentMessage {
                    id: Uuid::new_v4().to_string(),
                    correlation_id: Some(correlation_id),
                    payload: Some(agent_message::Payload::Ack(Ack {})),
                };
                // A stream that can't take the acknowledgement has closed, which its next message reports.
                let _ = opened.outbound.send(ack).await;
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
async fn authenticate(target: &Target, opened: &mut Opened) -> Result<(), Closure> {
    let (challenge_id, challenge) = loop {
        if let ServerMessage {
            id,
            payload: Some(Payload::Challenge(challenge)),
            ..
        } = opened.next_message("Challenge").await?
        {
            break (id, challenge.challenge);
        }
    };
    if challenge.len() != CHALLENGE_LEN {
        return Err(Closure::outage("challenge is not 32 bytes"));
    }
    let hello = hello(target, &challenge_id, &challenge, &opened.nonce)?;
    let hello_id = hello.id.clone();
    opened
        .outbound
        .send(hello)
        .await
        .map_err(|_| Closure::outage("stream closed before Hello"))?;
    loop {
        if let ServerMessage {
            correlation_id: Some(correlation_id),
            payload: Some(Payload::Welcome(_)),
            ..
        } = opened.next_message("Welcome").await?
            && correlation_id == hello_id
        {
            return Ok(());
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

impl Opened {
    /// Receives the next message of a stream that must not end before `awaited` arrives.
    async fn next_message(&mut self, awaited: &str) -> Result<ServerMessage, Closure> {
        match self.inbound.message().await {
            Ok(Some(message)) => Ok(message),
            Ok(None) => Err(Closure::from_status(&Status::ok(format!(
                "stream ended before {awaited}"
            )))),
            Err(status) => Err(Closure::from_status(&status)),
        }
    }
}

/// Builds the `Hello` that answers a challenge ([CONTRACT.md] §7.3 step 3).
///
/// [CONTRACT.md]: ../../docs/agent-identity/CONTRACT.md
fn hello(target: &Target, challenge_id: &str, challenge: &[u8], nonce: &str) -> Result<AgentMessage, Closure> {
    let proof = target
        .key
        .try_sign(&channel_proof_input(challenge, nonce))
        .map_err(|error| Closure::outage(format!("sign channel proof: {error}")))?;
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
async fn open(shared: &Shared, target: &Target) -> Result<Opened, Closure> {
    let service = shared
        .transport
        .connect(&target.url, shared.settings.keepalive_interval)
        .await?;
    let signer = RequestSigner::new(Arc::clone(&target.key), &target.leaf_certificate_der);
    let service = ChannelLayer::new(signer, &target.url).layer(service);
    let (_, origin) = endpoint(&target.url).map_err(|error| Closure::outage(format!("{error:#}")))?;
    let mut client = AgentChannelClient::with_origin(service, origin);
    let (outbound, outbound_receiver) = mpsc::channel(16);
    let (handoff, nonce) = OpeningNonce::new();
    let mut request = tonic::Request::new(ReceiverStream::new(outbound_receiver));
    request.extensions_mut().insert(handoff);
    let inbound = client
        .connect(request)
        .await
        .map_err(|status| Closure::from_status(&status))?
        .into_inner();
    Ok(Opened {
        outbound,
        inbound,
        nonce: nonce
            .await
            .map_err(|_| Closure::outage("opening signed without a nonce"))?,
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
