//! The task behind one [`Channel`](crate::Channel): it opens, authenticates and reopens the stream.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use agent_channel_proto::agent_channel_client::AgentChannelClient;
use agent_channel_proto::server_message::Payload;
use agent_channel_proto::{Ack, AgentMessage, Hello, ServerMessage, agent_message};
use agent_identity_httpsig::{ChannelLayer, OpeningNonce, RequestSigner};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataMap;
use tonic::{Code, Status, Streaming};
use tower::Layer as _;
use uuid::Uuid;

use crate::backoff::BackoffState;
use crate::closure::{Closure, ClosureClass};
use crate::transport::endpoint;
use crate::{Event, Shared, Target};

const CHANNEL_PROOF_DOMAIN: &[u8] = b"devolutions-agent-identity/v1/channel-proof";
const CHALLENGE_LEN: usize = 32;
/// How long a stream the caller dropped waits for the authority to end its side.
// UNTESTED: a dropped channel's stream releases its connection as soon as the authority ends its side.
// Waiting out the whole timeout would hold a connection that the authority has already finished with.
// When changing `close`, keep reading until the authority's side ends.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn run(
    shared: Arc<Shared>,
    target: Target,
    events: mpsc::Sender<Event>,
    mut acks: mpsc::UnboundedReceiver<String>,
) {
    let mut backoff = BackoffState::default();
    loop {
        let Some(closure) = stream_once(&shared, &target, &events, &mut acks, &mut backoff).await else {
            return;
        };
        let reopen_after = match closure.class {
            ClosureClass::Transient(kind) => Some(backoff.next_delay(&shared.settings.backoff, kind)),
            ClosureClass::Terminal(_) | ClosureClass::CertificateExpired => None,
        };
        if events.send(Event::Closed { closure, reopen_after }).await.is_err() {
            return;
        }
        let Some(delay) = reopen_after else {
            return;
        };
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = dropped(&mut acks) => return,
        }
    }
}

/// Runs one stream until it closes, or returns `None` once the caller has dropped the channel.
async fn stream_once(
    shared: &Shared,
    target: &Target,
    events: &mpsc::Sender<Event>,
    acks: &mut mpsc::UnboundedReceiver<String>,
    backoff: &mut BackoffState,
) -> Option<Closure> {
    let mut opened = tokio::select! {
        opened = authenticated_stream(shared, target) => match opened {
            Ok(opened) => opened,
            Err(closure) => return Some(closure),
        },
        () = dropped(acks) => return None,
    };
    backoff.reset();
    // Acknowledgements sent before this stream authenticated answer an earlier stream's messages.
    while acks.try_recv().is_ok() {}
    events.send(Event::Authenticated).await.ok()?;
    loop {
        tokio::select! {
            // Acknowledgements come first, so that those queued before the caller dropped the channel are sent.
            biased;
            correlation_id = acks.recv() => {
                let Some(correlation_id) = correlation_id else {
                    close(opened).await;
                    return None;
                };
                let ack = AgentMessage {
                    id: Uuid::new_v4().to_string(),
                    correlation_id: Some(correlation_id),
                    payload: Some(agent_message::Payload::Ack(Ack {})),
                };
                // A stream that can't take the acknowledgement has closed, which its next message reports.
                let _ = opened.outbound.send(ack).await;
            }
            message = opened.inbound.message() => match trusted(message) {
                Ok(Some(message)) => {
                    if let Some(event) = push_event(message) {
                        // Without a caller the event is lost, and the caller's drop also closes the acknowledgement
                        // queue, which closes the stream once its acknowledgements are sent.
                        let _ = events.send(event).await;
                    }
                }
                Ok(None) => return Some(ended_with_ok(&mut opened.inbound, &opened.headers, "stream ended").await),
                Err(closure) => return Some(closure),
            },
        }
    }
}

/// Waits until the caller drops the channel, discarding the acknowledgements it queued, which no stream carries now.
async fn dropped(acks: &mut mpsc::UnboundedReceiver<String>) {
    while acks.recv().await.is_some() {}
}

/// Closes an authenticated stream that the caller dropped: ends the agent's side after its queued messages, then lets
/// the authority end its side, for at most [`CLOSE_TIMEOUT`].
///
/// Dropping the response first would reset the stream, which discards the messages still queued, such as an
/// acknowledgement the caller sent just before ([CONTRACT.agent-identity.md §7.3 "Sequence"][contract], step 7).
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#73-sequence
async fn close(opened: Opened) {
    let Opened {
        outbound, mut inbound, ..
    } = opened;
    drop(outbound);
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, async {
        while let Ok(Some(_)) = inbound.message().await {}
    })
    .await;
}

/// Answers the challenge and waits for `Welcome` ([CONTRACT.agent-identity.md §7.3 "Sequence"][contract], steps 3–4).
///
/// Until `Welcome` answers the `Hello`, every other message is ignored, so that nothing counts before the
/// authority has verified the proof.
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#73-sequence
async fn authenticate(target: &Target, opened: &mut Opened) -> Result<(), Closure> {
    if opened.challenge.len() != CHALLENGE_LEN {
        return Err(Closure::outage("challenge is not 32 bytes"));
    }
    let hello = hello(target, &opened.challenge_id, &opened.challenge, &opened.nonce)?;
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
        } = next_message(&mut opened.inbound, &opened.headers, "Welcome").await?
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

/// A stream whose opening the authority accepted with a `Challenge`.
struct Opened {
    outbound: mpsc::Sender<AgentMessage>,
    inbound: Streaming<ServerMessage>,
    /// The response headers, which hold the status of a trailers-only response.
    headers: MetadataMap,
    /// The nonce of the opening signature, which the channel proof binds.
    nonce: String,
    challenge_id: String,
    challenge: Vec<u8>,
}

/// Receives the next message of a stream that must not end before `awaited` arrives.
async fn next_message(
    inbound: &mut Streaming<ServerMessage>,
    headers: &MetadataMap,
    awaited: &str,
) -> Result<ServerMessage, Closure> {
    match trusted(inbound.message().await)? {
        Some(message) => Ok(message),
        None => Err(ended_with_ok(inbound, headers, &format!("stream ended before {awaited}")).await),
    }
}

/// Returns what a stream received, or the closure of a stream whose message the client can't trust.
///
/// A message that can't be decoded, or whose `id` is not a UUID ([CONTRACT.agent-identity.md §1 "Protocol
/// conventions"][conventions]), closes the stream, so that no reply echoes an unchecked `id` or grows past the
/// envelope limit ([§7.1 "Service"][service]).
///
/// [conventions]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#1-protocol-conventions
/// [service]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#71-service
fn trusted(received: Result<Option<ServerMessage>, Status>) -> Result<Option<ServerMessage>, Closure> {
    match received {
        Ok(Some(message)) if !is_uuid(&message.id) => Err(Closure::outage("message id is not a UUID")),
        Ok(message) => Ok(message),
        Err(status) => Err(Closure::from_status(&status)),
    }
}

/// Returns whether `id` is a UUID in lowercase hyphenated form.
fn is_uuid(id: &str) -> bool {
    Uuid::try_parse(id).is_ok_and(|uuid| *uuid.hyphenated().encode_lower(&mut Uuid::encode_buffer()) == *id)
}

/// Classifies a stream that ended with gRPC status OK, with the trailers it ended with.
///
/// A trailers-only response carries them in `headers`.
async fn ended_with_ok(inbound: &mut Streaming<ServerMessage>, headers: &MetadataMap, reason: &str) -> Closure {
    let metadata = match inbound.trailers().await {
        Ok(Some(trailers)) => trailers,
        Ok(None) | Err(_) => headers.clone(),
    };
    Closure::from_status(&Status::with_metadata(Code::Ok, reason, metadata))
}

/// Builds the `Hello` that answers a challenge ([CONTRACT.agent-identity.md §7.3 "Sequence"][contract], step 3).
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#73-sequence
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

/// Opens and authenticates a stream, and retries once at the authority's time when it refuses the opening with
/// `clock_skew` ([CONTRACT.agent-identity.md §6 "RFC 9421 profile"][contract]).
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#6-rfc-9421-profile
async fn authenticated_stream(shared: &Shared, target: &Target) -> Result<Opened, Closure> {
    match authenticated_stream_at(shared, target, 0).await {
        Err(closure) => match clock_offset(&closure) {
            Some(offset) => authenticated_stream_at(shared, target, offset).await,
            None => Err(closure),
        },
        opened => opened,
    }
}

/// Opens and authenticates a stream whose signature is offset by `clock_offset` seconds, within the opening timeout.
async fn authenticated_stream_at(shared: &Shared, target: &Target, clock_offset: i64) -> Result<Opened, Closure> {
    let opening = async {
        let mut opened = open(shared, target, clock_offset).await?;
        authenticate(target, &mut opened).await?;
        Ok(opened)
    };
    tokio::time::timeout(shared.settings.opening_timeout, opening)
        .await
        .unwrap_or_else(|_| Err(Closure::outage("no Welcome within the opening timeout")))
}

/// Returns `server_time − local_time` in seconds for a `clock_skew` refusal with a `server-time` trailer.
fn clock_offset(closure: &Closure) -> Option<i64> {
    if closure.error_code.as_deref() != Some("clock_skew") {
        return None;
    }
    let server_time = OffsetDateTime::parse(closure.server_time.as_deref()?, &Rfc3339).ok()?;
    Some(server_time.unix_timestamp() - OffsetDateTime::now_utc().unix_timestamp())
}

/// Sends the signed opening request, with its `created` time offset by `clock_offset` seconds, and waits for the
/// `Challenge` ([CONTRACT.agent-identity.md §7.3 "Sequence"][contract], steps 1–2).
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#73-sequence
async fn open(shared: &Shared, target: &Target, clock_offset: i64) -> Result<Opened, Closure> {
    let service = shared
        .transport
        .connect(&target.url, shared.settings.keepalive_interval)
        .await?;
    let signer = RequestSigner::new(Arc::clone(&target.key), &target.leaf_certificate_der);
    let service = ChannelLayer::new(signer, &target.url)
        .with_clock_offset(clock_offset)
        .layer(service);
    let (_, origin) = endpoint(&target.url).map_err(|error| Closure::outage(format!("{error:#}")))?;
    let mut client = AgentChannelClient::with_origin(service, origin);
    let (outbound, outbound_receiver) = mpsc::channel(16);
    let (handoff, nonce) = OpeningNonce::new();
    let mut request = tonic::Request::new(ReceiverStream::new(outbound_receiver));
    request.extensions_mut().insert(handoff);
    let response = client
        .connect(request)
        .await
        .map_err(|status| Closure::from_status(&status))?;
    let headers = response.metadata().clone();
    let mut inbound = response.into_inner();
    let nonce = nonce
        .await
        .map_err(|_| Closure::outage("opening signed without a nonce"))?;
    loop {
        if let ServerMessage {
            id,
            payload: Some(Payload::Challenge(challenge)),
            ..
        } = next_message(&mut inbound, &headers, "Challenge").await?
        {
            return Ok(Opened {
                outbound,
                inbound,
                headers,
                nonce,
                challenge_id: id,
                challenge: challenge.challenge,
            });
        }
    }
}

/// Returns the bytes a channel proof signs ([CONTRACT.agent-identity.md §7.3 "Sequence"][contract], step 3).
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#73-sequence
pub(crate) fn channel_proof_input(challenge: &[u8], connect_nonce: &str) -> Vec<u8> {
    let mut input =
        Vec::with_capacity(CHANNEL_PROOF_DOMAIN.len() + 1 /* separator */ + challenge.len() + connect_nonce.len());
    input.extend_from_slice(CHANNEL_PROOF_DOMAIN);
    input.push(0x00);
    input.extend_from_slice(challenge);
    input.extend_from_slice(connect_nonce.as_bytes());
    input
}
