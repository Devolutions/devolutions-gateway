//! Channel service (CONTRACT.agent-identity.md §7): tonic `AgentChannel/Connect` bidi stream with the
//! opening-signature check (§6, `tag="connect"`), the challenge/proof handshake
//! (§7.3), and contract-driven termination (§7.4).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use agent_channel_proto::agent_channel_server::AgentChannel;
use agent_channel_proto::{
    AgentMessage, Challenge, ConfigUpdate, Reconnect, RenewRequested, ServerMessage, Welcome, agent_message,
    server_message,
};
use futures::StreamExt as _;
use rand::RngExt as _;
use serde_json::{Map, Value};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::{AsciiMetadataValue, MetadataMap};
use tonic::{Code, Request, Response, Status, Streaming};
use uuid::Uuid;

use crate::app::{App, rfc3339};
use crate::name_eval;
use crate::oracle::{CertStatus, Endpoint, Rejection, verify_channel_proof, verify_request};
use crate::state::{State, StreamHandle, StreamPush, stream_expired};

/// §7.3: the agent must answer the challenge within 10 s (real time).
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// How often a stream awaiting `Hello` checks its certificate's `notAfter`, well within one mock-clock second.
const EXPIRY_CHECK_PERIOD: Duration = Duration::from_millis(250);

#[derive(Clone)]
pub(crate) struct ChannelService {
    pub(crate) app: Arc<App>,
}

/// Builds a stream failure status with the `error-code` and `server-time` trailers
/// ([CONTRACT.agent-identity.md][contract], "7.4 Termination").
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#74-termination
fn error_status(code: Code, error_code: &'static str, now: i64) -> Status {
    let mut metadata = MetadataMap::new();
    metadata.insert("error-code", AsciiMetadataValue::from_static(error_code));
    let server_time = AsciiMetadataValue::try_from(rfc3339(now)).expect("RFC 3339 timestamps are ASCII");
    metadata.insert("server-time", server_time);
    Status::with_metadata(code, error_code, metadata)
}

fn rejection_status(rejection: Rejection, now: i64) -> Status {
    let code = match rejection {
        Rejection::IdentityRevoked => Code::PermissionDenied,
        _ => Code::Unauthenticated,
    };
    error_status(code, rejection.code(), now)
}

#[tonic::async_trait]
impl AgentChannel for ChannelService {
    type ConnectStream = ReceiverStream<Result<ServerMessage, Status>>;

    async fn connect(
        &self,
        request: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        let app = Arc::clone(&self.app);
        let metadata = request.metadata();
        let duplicate_signature = metadata.get_all("signature-input").iter().count() != 1
            || metadata.get_all("signature").iter().count() != 1;
        let header_bytes = |name: &str| metadata.get(name).map(|v| v.as_bytes().to_vec());
        let signature_input = header_bytes("signature-input");
        let signature = header_bytes("signature");

        let now = app.now();
        let stream_id = Uuid::new_v4();
        let (out_tx, out_rx) = mpsc::channel(32);
        let (push_tx, push_rx) = mpsc::unbounded_channel();
        let auth = {
            let mut state = app.state.lock().await;
            state.tick(now);
            state.requests.connect += 1;
            state.requests.request_sequence.push("connect");
            if !state.channel_offered() || state.faults.channel_broken {
                // The mock control and the `isAgentChannelEnabled` setting can make the channel unavailable, and the
                // mock control can break it.
                return Err(Status::unavailable("channel not available"));
            }
            let result = if duplicate_signature {
                Err(Rejection::SignatureInvalid)
            } else {
                let State {
                    identities,
                    cert_index,
                    nonces,
                    ..
                } = &mut *state;
                let mut lookup = |keyid: &str| crate::state::lookup_cert(identities, cert_index, keyid);
                verify_request(
                    Endpoint::Connect,
                    "POST",
                    signature_input.as_deref(),
                    signature.as_deref(),
                    None,
                    &[],
                    now,
                    &mut lookup,
                    nonces,
                )
            };
            if let Ok(auth) = &result {
                state.challenged_streams.insert(
                    stream_id,
                    StreamHandle {
                        identity_id: auth.identity_id(),
                        cert_thumbprint: auth.cert_thumbprint().to_owned(),
                        tx: push_tx.clone(),
                        retire_at: None,
                    },
                );
                state.record_event(
                    auth.identity_id(),
                    "stream_opened",
                    serde_json::json!({
                        "stream_id": stream_id,
                        "cert_thumbprint": auth.cert_thumbprint(),
                    }),
                );
            }
            result.map(|auth| {
                let not_after = state
                    .lookup_cert(auth.cert_thumbprint())
                    .expect("the opening certificate is registered")
                    .not_after;
                Opening { auth, not_after }
            })
        };
        let opening = auth.map_err(|rejection| rejection_status(rejection, now))?;

        tokio::spawn(run_stream(
            app,
            stream_id,
            opening,
            request.into_inner(),
            push_tx,
            push_rx,
            out_tx,
        ));
        Ok(Response::new(ReceiverStream::new(out_rx)))
    }
}

/// A channel stream whose opening request passed §6.
struct Opening {
    auth: crate::oracle::AuthenticatedIdentity,
    /// The `notAfter` of the certificate that signed the opening request.
    /// It bounds the stream (§7.4) even after deletion removes that certificate's record.
    not_after: i64,
}

fn server_message(id: String, correlation_id: Option<String>, payload: server_message::Payload) -> ServerMessage {
    ServerMessage {
        id,
        correlation_id,
        payload: Some(payload),
    }
}

async fn send(out: &mpsc::Sender<Result<ServerMessage, Status>>, message: ServerMessage) -> bool {
    out.send(Ok(message)).await.is_ok()
}

async fn close_with(out: &mpsc::Sender<Result<ServerMessage, Status>>, status: Status) {
    let _ = out.send(Err(status)).await;
}

async fn finish_stream(
    app: &App,
    stream_id: Uuid,
    identity_id: Uuid,
    cert_thumbprint: &str,
    status: &str,
    error_code: Option<&str>,
) {
    app.state
        .lock()
        .await
        .close_stream(stream_id, identity_id, cert_thumbprint, status, error_code);
}

/// Closes a stream for an authentication failure or a §7.4 closure.
async fn close_rejected(
    app: &App,
    out: &mpsc::Sender<Result<ServerMessage, Status>>,
    stream_id: Uuid,
    identity_id: Uuid,
    cert_thumbprint: &str,
    rejection: Rejection,
) {
    close_with(out, rejection_status(rejection, app.now())).await;
    let status = if rejection == Rejection::IdentityRevoked {
        "PERMISSION_DENIED"
    } else {
        "UNAUTHENTICATED"
    };
    finish_stream(
        app,
        stream_id,
        identity_id,
        cert_thumbprint,
        status,
        Some(rejection.code()),
    )
    .await;
}

/// Checks a stream awaiting `Hello` against the closures of [CONTRACT.agent-identity.md][contract] ("7.4 Termination"),
/// on the identity first, then on the certificate that opened the stream, and returns that certificate's status when
/// none applies.
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#74-termination
fn awaiting_closure(
    state: &State,
    identity_id: Uuid,
    cert_thumbprint: &str,
    now: i64,
) -> Result<CertStatus, Rejection> {
    let cert = state
        .lookup_cert(cert_thumbprint)
        .filter(|cert| cert.identity_id == identity_id)
        .ok_or(Rejection::IdentityUnknown)?;
    if cert.revoked {
        return Err(Rejection::IdentityRevoked);
    }
    if stream_expired(cert.not_after, now) {
        return Err(Rejection::CertificateExpired);
    }
    Ok(cert.status)
}

/// The §7.4 closure due to a stream awaiting `Hello` once the clock reaches `not_after`, its [`Opening`] deadline.
/// Revocation and deletion still win over expiry then, as [`awaiting_closure`] orders them.
async fn expiry_closure(app: &App, identity_id: Uuid, cert_thumbprint: &str, not_after: i64) -> Option<Rejection> {
    let now = app.now();
    if !stream_expired(not_after, now) {
        return None;
    }
    let closure = awaiting_closure(&*app.state.lock().await, identity_id, cert_thumbprint, now);
    Some(closure.err().unwrap_or(Rejection::CertificateExpired))
}

async fn close_opening_push(
    app: &App,
    out: &mpsc::Sender<Result<ServerMessage, Status>>,
    stream_id: Uuid,
    identity_id: Uuid,
    cert_thumbprint: &str,
    push: Option<StreamPush>,
) {
    let (code, error_code) = match push {
        Some(StreamPush::CloseExpired) => (Code::Unauthenticated, "certificate_expired"),
        Some(StreamPush::CloseUnknown) => (Code::Unauthenticated, "identity_unknown"),
        Some(StreamPush::CloseRevoked) => (Code::PermissionDenied, "identity_revoked"),
        Some(StreamPush::CloseOk) => {
            finish_stream(app, stream_id, identity_id, cert_thumbprint, "OK", None).await;
            return;
        }
        _ => (Code::Unauthenticated, "signature_invalid"),
    };
    close_with(out, error_status(code, error_code, app.now())).await;
    finish_stream(
        app,
        stream_id,
        identity_id,
        cert_thumbprint,
        if code == Code::PermissionDenied {
            "PERMISSION_DENIED"
        } else {
            "UNAUTHENTICATED"
        },
        Some(error_code),
    )
    .await;
}

async fn run_stream(
    app: Arc<App>,
    stream_id: Uuid,
    opening: Opening,
    mut client: Streaming<AgentMessage>,
    push_tx: mpsc::UnboundedSender<StreamPush>,
    mut push_rx: mpsc::UnboundedReceiver<StreamPush>,
    out: mpsc::Sender<Result<ServerMessage, Status>>,
) {
    let Opening { auth, not_after } = opening;
    let identity_id = auth.identity_id();
    let cert_thumbprint = auth.cert_thumbprint().to_owned();

    // §7.3 step 2: the Challenge is the first server message.
    let mut challenge = [0u8; 32];
    rand::rng().fill(&mut challenge[..]);
    let challenge_id = Uuid::new_v4().to_string();
    let challenge_msg = server_message(
        challenge_id.clone(),
        None,
        server_message::Payload::Challenge(Challenge {
            challenge: challenge.to_vec(),
        }),
    );
    if !send(&out, challenge_msg).await {
        finish_stream(&app, stream_id, identity_id, &cert_thumbprint, "OK", None).await;
        return;
    }
    // §7.4 closes a stream no later than its certificate's `notAfter`, which §6 still accepts for opening,
    // so a stream opened at `notAfter` closes right after its `Challenge`.
    {
        let now = app.now();
        app.state.lock().await.tick(now);
    }

    // Step 3: wait for the Hello, bound to this stream's challenge and the connect nonce.
    // §7.4 closes the stream no later than `notAfter` even when no request applies the clock to the mock.
    let mut expiry_check = tokio::time::interval(EXPIRY_CHECK_PERIOD);
    expiry_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let hello = {
        let hello_wait = tokio::time::timeout(HELLO_TIMEOUT, client.next());
        tokio::pin!(hello_wait);
        loop {
            tokio::select! {
                result = &mut hello_wait => break match result {
                    Ok(Some(Ok(message))) => Some(message),
                    Ok(Some(Err(_))) | Ok(None) | Err(_) => None,
                },
                push = push_rx.recv() => {
                    close_opening_push(&app, &out, stream_id, identity_id, &cert_thumbprint, push).await;
                    return;
                }
                _ = expiry_check.tick() => {
                    if let Some(rejection) = expiry_closure(&app, identity_id, &cert_thumbprint, not_after).await {
                        close_rejected(&app, &out, stream_id, identity_id, &cert_thumbprint, rejection).await;
                        return;
                    }
                }
            }
        }
    };
    // §7.4: revocation, deletion and `notAfter` close a stream awaiting `Hello` ahead of the step 4 failures.
    let closure = {
        let now = app.now();
        awaiting_closure(&*app.state.lock().await, identity_id, &cert_thumbprint, now)
    };
    if let Err(rejection) = closure {
        close_rejected(&app, &out, stream_id, identity_id, &cert_thumbprint, rejection).await;
        return;
    }
    let hello = hello.filter(|hello| {
        hello.correlation_id.as_deref() == Some(challenge_id.as_str())
            && match &hello.payload {
                Some(agent_message::Payload::Hello(hello)) => {
                    verify_channel_proof(auth.public_key(), &challenge, auth.nonce(), &hello.proof)
                }
                _ => false,
            }
    });
    let Some(AgentMessage {
        id: hello_id,
        payload: Some(agent_message::Payload::Hello(hello_payload)),
        ..
    }) = hello
    else {
        close_with(
            &out,
            error_status(Code::Unauthenticated, "signature_invalid", app.now()),
        )
        .await;
        finish_stream(
            &app,
            stream_id,
            identity_id,
            &cert_thumbprint,
            "UNAUTHENTICATED",
            Some("signature_invalid"),
        )
        .await;
        return;
    };
    let applied_config_revision = hello_payload.applied_state_versions.get("config").copied().unwrap_or(0);

    let metadata: Map<String, Value> = hello_payload
        .metadata
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    if name_eval::validate_metadata(&metadata).is_err() {
        close_with(&out, error_status(Code::InvalidArgument, "invalid_request", app.now())).await;
        finish_stream(
            &app,
            stream_id,
            identity_id,
            &cert_thumbprint,
            "INVALID_ARGUMENT",
            Some("invalid_request"),
        )
        .await;
        return;
    }

    let mut gate = app.handshake_gate.subscribe();
    if !*gate.borrow() {
        app.state.lock().await.paused_hellos.insert(stream_id);
        loop {
            if *gate.borrow_and_update() {
                break;
            }
            tokio::select! {
                changed = gate.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                push = push_rx.recv() => {
                    close_opening_push(&app, &out, stream_id, identity_id, &cert_thumbprint, push).await;
                    return;
                }
                message = client.next() => {
                    if message.is_none_or(|message| message.is_err()) {
                        finish_stream(&app, stream_id, identity_id, &cert_thumbprint, "OK", None).await;
                        return;
                    }
                }
                _ = expiry_check.tick() => {
                    if let Some(rejection) = expiry_closure(&app, identity_id, &cert_thumbprint, not_after).await {
                        close_rejected(&app, &out, stream_id, identity_id, &cert_thumbprint, rejection).await;
                        return;
                    }
                }
            }
        }
        app.state.lock().await.paused_hellos.remove(&stream_id);
    }

    // Step 4: only now does anything happen server-side.
    // A Hello held by the handshake barrier is checked against the §7.4 closures again when it is released.
    let authentication = {
        let now = app.now();
        let mut state = app.state.lock().await;
        state.tick(now);
        let closure = awaiting_closure(&state, identity_id, &cert_thumbprint, now);
        if let Err(rejection) = closure {
            Err(rejection)
        } else {
            state.challenged_streams.remove(&stream_id);
            if state.is_connected(identity_id) {
                state.requests.overlap_open += 1;
            }
            state.record_event(
                identity_id,
                "stream_authenticated",
                serde_json::json!({
                    "stream_id": stream_id,
                    "cert_thumbprint": cert_thumbprint,
                    "applied_config_revision": applied_config_revision,
                }),
            );
            let (reason, config_update) = state
                .identities
                .get_mut(&identity_id)
                .map(|identity| {
                    identity.metadata = metadata;
                    identity.last_seen_at = Some(now);
                    let update = identity.config_update_after(applied_config_revision);
                    (identity.renewal_requested.as_ref().map(|f| f.reason.as_str()), update)
                })
                .expect("authenticated identity exists");
            // §7.4: once the handshake completes, a stream whose certificate was retired while it awaited `Hello`
            // gets the retired streams' `Reconnect`, after `Welcome`, and closes 60 s after it.
            let retired = closure == Ok(CertStatus::Retired);
            if retired && push_tx.send(StreamPush::Reconnect("certificate_rotated")).is_ok() {
                state.record_event(
                    identity_id,
                    "reconnect_sent",
                    serde_json::json!({
                        "stream_id": stream_id,
                        "cert_thumbprint": cert_thumbprint,
                        "reason": "certificate_rotated",
                    }),
                );
            }
            state.streams.insert(
                stream_id,
                StreamHandle {
                    identity_id,
                    cert_thumbprint: cert_thumbprint.clone(),
                    tx: push_tx,
                    retire_at: retired.then(|| now.saturating_add(60)),
                },
            );
            state.requests.authenticated_connects += 1;
            Ok((reason, config_update))
        }
    };
    let (renewal_reason, config_update) = match authentication {
        Ok(result) => result,
        Err(rejection) => {
            close_rejected(&app, &out, stream_id, identity_id, &cert_thumbprint, rejection).await;
            return;
        }
    };

    let now = app.now();
    let welcome = server_message(
        Uuid::new_v4().to_string(),
        Some(hello_id),
        server_message::Payload::Welcome(Welcome {
            server_time: Some(prost_types::Timestamp { seconds: now, nanos: 0 }),
        }),
    );
    if !send(&out, welcome).await {
        finish_stream(&app, stream_id, identity_id, &cert_thumbprint, "OK", None).await;
        return;
    }

    // §7.3: reconcile config and the renewal flag after Welcome.
    let mut awaiting_ack = HashSet::new();
    if let Some((config_json, revision)) = config_update {
        let message = server_message(
            Uuid::new_v4().to_string(),
            None,
            server_message::Payload::ConfigUpdate(ConfigUpdate { config_json }),
        );
        awaiting_ack.insert(message.id.clone());
        if !send(&out, message).await {
            finish_stream(&app, stream_id, identity_id, &cert_thumbprint, "OK", None).await;
            return;
        }
        app.state.lock().await.record_event(
            identity_id,
            "config_update_sent",
            serde_json::json!({ "stream_id": stream_id, "revision": revision }),
        );
    }
    if let Some(reason) = renewal_reason {
        let message = server_message(
            Uuid::new_v4().to_string(),
            None,
            server_message::Payload::RenewRequested(RenewRequested {
                reason: reason.to_owned(),
            }),
        );
        awaiting_ack.insert(message.id.clone());
        if !send(&out, message).await {
            finish_stream(&app, stream_id, identity_id, &cert_thumbprint, "OK", None).await;
            return;
        }
    }

    // §7.4 termination handling.
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut termination = ("OK", None);
    loop {
        tokio::select! {
            message = client.next() => {
                match message {
                    Some(Ok(message)) => {
                        let now = app.now();
                        let mut state = app.state.lock().await;
                        // UNTESTED: any authenticated message, even an unknown payload, refreshes `last_seen_at`.
                        // The timestamp tracks key possession and drives the management API's last-seen filters.
                        // When changing this branch, check `lastSeenOn` after an `Ack` and an unknown payload.
                        if let Some(identity) = state.identities.get_mut(&identity_id) {
                            identity.last_seen_at = Some(now);
                        }
                        if let AgentMessage {
                            correlation_id: Some(correlation),
                            payload: Some(agent_message::Payload::Ack(_)),
                            ..
                        } = message
                            && awaiting_ack.remove(&correlation)
                        {
                            state.requests.correlated_acks += 1;
                        }
                    }
                    Some(Err(_)) | None => break,
                }
            }
            push = push_rx.recv() => {
                match push {
                    Some(StreamPush::ConfigUpdate(config_json)) => {
                        let message = server_message(
                            Uuid::new_v4().to_string(),
                            None,
                            server_message::Payload::ConfigUpdate(ConfigUpdate { config_json }),
                        );
                        awaiting_ack.insert(message.id.clone());
                        if !send(&out, message).await {
                            break;
                        }
                    }
                    Some(StreamPush::RenewRequested(reason)) => {
                        let message = server_message(
                            Uuid::new_v4().to_string(),
                            None,
                            server_message::Payload::RenewRequested(RenewRequested {
                                reason: reason.to_owned(),
                            }),
                        );
                        awaiting_ack.insert(message.id.clone());
                        if !send(&out, message).await {
                            break;
                        }
                    }
                    Some(StreamPush::Reconnect(reason)) => {
                        let message = server_message(
                            Uuid::new_v4().to_string(),
                            None,
                            server_message::Payload::Reconnect(Reconnect {
                                reason: reason.to_owned(),
                            }),
                        );
                        if !send(&out, message).await {
                            break;
                        }
                    }
                    // Make-before-break: end of stream with OK.
                    Some(StreamPush::CloseOk) => break,
                    Some(StreamPush::CloseRevoked) => {
                        close_with(&out, error_status(Code::PermissionDenied, "identity_revoked", app.now())).await;
                        termination = ("PERMISSION_DENIED", Some("identity_revoked"));
                        break;
                    }
                    Some(StreamPush::CloseUnknown) => {
                        close_with(&out, error_status(Code::Unauthenticated, "identity_unknown", app.now())).await;
                        termination = ("UNAUTHENTICATED", Some("identity_unknown"));
                        break;
                    }
                    Some(StreamPush::CloseExpired) => {
                        close_with(&out, error_status(Code::Unauthenticated, "certificate_expired", app.now())).await;
                        termination = ("UNAUTHENTICATED", Some("certificate_expired"));
                        break;
                    }
                    None => break,
                }
            }
            _ = ticker.tick() => {
                // The mock clock can jump (time/advance), so cert expiry, revocation
                // races and resets are re-evaluated on a real-time ticker.
                let now = app.now();
                let outcome = {
                    let state = app.state.lock().await;
                    match state.lookup_cert(&cert_thumbprint) {
                        None => Some(Rejection::IdentityUnknown),
                        Some(cert) if cert.revoked => Some(Rejection::IdentityRevoked),
                        Some(cert) if stream_expired(cert.not_after, now) => Some(Rejection::CertificateExpired),
                        Some(_) => None,
                    }
                };
                if let Some(rejection) = outcome {
                    close_with(&out, rejection_status(rejection, app.now())).await;
                    termination = (
                        if rejection == Rejection::IdentityRevoked {
                            "PERMISSION_DENIED"
                        } else {
                            "UNAUTHENTICATED"
                        },
                        Some(rejection.code()),
                    );
                    break;
                }
            }
        }
    }

    finish_stream(
        &app,
        stream_id,
        identity_id,
        &cert_thumbprint,
        termination.0,
        termination.1,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::time::Duration;

    use agent_channel_proto::{AgentMessage, Hello, ServerMessage, agent_message, server_message};
    use axum::body::Bytes;
    use axum::http;
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use http_body_util::combinators::UnsyncBoxBody;
    use http_body_util::{BodyExt as _, Full, StreamBody};
    use hyper::body::Frame;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey as _;
    use prost::Message as _;
    use rstest::rstest;
    use serde_json::{Map, Value};
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::Code;
    use uuid::Uuid;

    use super::error_status;
    use crate::app::App;
    use crate::oracle::CertStatus;
    use crate::server::Dispatcher;
    use crate::state::{Cert, State};

    type ServerBody = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

    /// How long a stream stays silent before a test reads it as waiting.
    const QUIET: Duration = Duration::from_millis(500);

    #[test]
    fn stream_failure_carries_error_code_and_server_time_trailers() {
        let status = error_status(Code::Unauthenticated, "clock_skew", 1_790_000_000);
        let trailer = |name: &str| status.metadata().get(name).and_then(|value| value.to_str().ok());

        assert_eq!(status.code(), Code::Unauthenticated);
        assert_eq!(trailer("error-code"), Some("clock_skew"));
        assert_eq!(trailer("server-time"), Some("2026-09-21T14:13:20Z"));
    }

    /// A server event on a channel stream, as the agent sees it.
    #[derive(Debug, PartialEq, Eq)]
    enum Seen {
        Challenge,
        Welcome,
        Reconnect(String),
        /// The `grpc-status` and `error-code` trailers.
        Closed(String, String),
    }

    /// A freshly enrolled identity whose certificate key the test holds.
    struct Enrolled {
        app: Arc<App>,
        identity_id: Uuid,
        key: SigningKey,
        keyid: String,
        not_before: i64,
        not_after: i64,
    }

    impl Enrolled {
        async fn new() -> anyhow::Result<Self> {
            let app = App::for_test()?;
            let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
            let vector = &vectors["csr"]["valid"];
            let key = SigningKey::from_pkcs8_der(
                &STANDARD.decode(vector["private_key_pkcs8"].as_str().unwrap_or_default())?,
            )?;
            let csr = STANDARD.decode(vector["csr"].as_str().unwrap_or_default())?;
            let mut state = app.state.lock().await;
            let now = app.now();
            let (_, secret) = state.create_token("test".to_owned(), 1, crate::app::nanos(now + 3600), None, None, now);
            let identity_id = state
                .enroll(&secret, &csr, Map::new(), now, &app.base_url)
                .expect("enrollment succeeds")
                .identity_id;
            let cert = state
                .identities
                .get(&identity_id)
                .and_then(|identity| identity.certs.first())
                .expect("issued certificate");
            let (keyid, not_before, not_after) = (cert.thumbprint.clone(), cert.not_before, cert.not_after);
            drop(state);
            Ok(Self {
                app,
                identity_id,
                key,
                keyid,
                not_before,
                not_after,
            })
        }

        /// Registers a pending certificate for `key`, as a renewal would (CONTRACT.agent-identity.md §5.3), and returns its thumbprint.
        async fn add_pending(&self, key: &SigningKey) -> String {
            let mut state = self.app.state.lock().await;
            let thumbprint = crate::ca::thumbprint(b"pending certificate");
            let issuer = state.issuing_root().thumbprint.clone();
            let issued_seq = state.serial_seq;
            state.serial_seq += 1;
            state.cert_index.insert(thumbprint.clone(), self.identity_id);
            state
                .identities
                .get_mut(&self.identity_id)
                .expect("enrolled identity")
                .certs
                .push(Cert {
                    thumbprint: thumbprint.clone(),
                    der: Vec::new(),
                    public_key: *key.verifying_key(),
                    serial: format!("{issued_seq:x}"),
                    not_before: self.not_before,
                    not_after: self.not_after,
                    issuer,
                    status: CertStatus::Pending,
                    issued_seq,
                });
            thumbprint
        }

        /// Sends `POST confirm` with `body`, signed by `key` (CONTRACT.agent-identity.md §5.5), and returns the response
        /// status with its §5.4 error code, if any.
        async fn confirm(
            &self,
            key: &SigningKey,
            keyid: &str,
            body: &'static str,
        ) -> anyhow::Result<(http::StatusCode, Option<String>)> {
            let (_, signature_input, signature) = sign(key, keyid, "confirm", self.app.now())?;
            let request = http::Request::post("/mock/api/agent-identity/v1/confirm")
                .header("signature-input", signature_input)
                .header("signature", signature)
                .body(Full::new(Bytes::from_static(body.as_bytes())))?;
            let response = Dispatcher::new(Arc::clone(&self.app))
                .handle(request)
                .await
                .expect("the mock answers");
            let status = response.status();
            let body = response.into_body().collect().await.expect("readable body").to_bytes();
            let code = serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|body| body["error"].as_str().map(str::to_owned));
            Ok((status, code))
        }

        /// Moves the mock clock to `now` and applies it, as `__mock__/time/advance` does.
        async fn advance_to(&self, now: i64) {
            self.app.clock.freeze_at(now);
            self.app.tick().await;
        }
    }

    /// Signs a `("@method")` request for `tag` at mock time `now` (CONTRACT.agent-identity.md §6), and returns its
    /// nonce and its `signature-input` and `signature` header values.
    fn sign(key: &SigningKey, keyid: &str, tag: &str, now: i64) -> anyhow::Result<(String, String, String)> {
        let nonce = URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes());
        let params = format!(
            "(\"@method\");created={now};expires={};nonce=\"{nonce}\";keyid=\"{keyid}\";alg=\"ecdsa-p256-sha256\";tag=\"{tag}\"",
            now + 60,
        );
        let signature: Signature =
            key.try_sign(format!("\"@method\": POST\n\"@signature-params\": {params}").as_bytes())?;
        let signature = format!("sig=:{}:", STANDARD.encode(signature.to_bytes()));
        Ok((nonce, format!("sig={params}"), signature))
    }

    /// The closing status in `headers`, which carry an RFC 3339 `server-time` with any status but `OK` (CONTRACT.agent-identity.md §7.4).
    fn closed(headers: &http::HeaderMap) -> Option<Seen> {
        let value = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        };
        let status = headers.contains_key("grpc-status").then(|| value("grpc-status"))?;
        if status != "0" {
            let server_time = value("server-time");
            let parsed = time::OffsetDateTime::parse(&server_time, &time::format_description::well_known::Rfc3339);
            assert!(parsed.is_ok(), "`server-time` {server_time:?} is not RFC 3339");
        }
        Some(Seen::Closed(status, value("error-code")))
    }

    /// How the agent answers the `Challenge`; each answer fails CONTRACT.agent-identity.md §7.3 step 4.
    #[derive(Clone, Copy, Debug)]
    enum Answer {
        Nothing,
        BadProof,
        WrongCorrelation,
        InvalidMetadata,
    }

    /// A channel stream as the agent sees it.
    struct Channel {
        agent: mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
        body: Option<ServerBody>,
        received: Vec<u8>,
        seen: VecDeque<Seen>,
        nonce: String,
        /// The last `Challenge`'s envelope `id` and bytes.
        challenge: (String, Vec<u8>),
    }

    impl Channel {
        /// Opens a stream signed by the enrolled certificate at the current mock time (CONTRACT.agent-identity.md §7.3
        /// step 1).
        async fn open(enrolled: &Enrolled) -> anyhow::Result<Self> {
            let (nonce, signature_input, signature) =
                sign(&enrolled.key, &enrolled.keyid, "connect", enrolled.app.now())?;
            let (agent, agent_messages) = mpsc::channel(4);
            let request = http::Request::post(format!("/mock/{}/Connect", agent_channel_proto::SERVICE_NAME))
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .header("signature-input", signature_input)
                .header("signature", signature)
                .body(StreamBody::new(ReceiverStream::new(agent_messages)))?;
            let response = Dispatcher::new(Arc::clone(&enrolled.app))
                .handle(request)
                .await
                .expect("the mock answers");
            let mut seen = VecDeque::new();
            let body = match closed(response.headers()) {
                Some(refused) => {
                    seen.push_back(refused);
                    None
                }
                None => Some(response.into_body()),
            };
            Ok(Self {
                agent,
                body,
                received: Vec::new(),
                seen,
                nonce,
                challenge: Default::default(),
            })
        }

        /// Reads the next server event, or `None` once the stream has closed or stays silent for `quiet`.
        async fn next(&mut self, quiet: Duration) -> anyhow::Result<Option<Seen>> {
            while self.seen.is_empty() {
                let Some(body) = &mut self.body else {
                    break;
                };
                let frame = match tokio::time::timeout(quiet, body.frame()).await {
                    Err(_) => break,
                    Ok(None) => {
                        self.body = None;
                        continue;
                    }
                    Ok(Some(frame)) => frame.map_err(|error| anyhow::anyhow!("{error}"))?,
                };
                if let Some(trailers) = frame.trailers_ref() {
                    self.seen.extend(closed(trailers));
                    self.body = None;
                } else if let Some(data) = frame.data_ref() {
                    self.received.extend_from_slice(data);
                    self.decode_received()?;
                }
            }
            Ok(self.seen.pop_front())
        }

        /// Every server event until the stream closes or stays silent for `quiet`.
        async fn drain(&mut self, quiet: Duration) -> anyhow::Result<Vec<Seen>> {
            let mut seen = Vec::new();
            while let Some(event) = self.next(quiet).await? {
                seen.push(event);
            }
            Ok(seen)
        }

        /// Decodes each complete gRPC message received so far: a compression flag, a 4-byte big-endian length, then
        /// the message.
        fn decode_received(&mut self) -> anyhow::Result<()> {
            while let Some(&[_, a, b, c, d]) = self.received.get(..5) {
                let end = 5 + usize::try_from(u32::from_be_bytes([a, b, c, d]))?;
                let Some(bytes) = self.received.get(5..end) else {
                    break;
                };
                let message = ServerMessage::decode(bytes)?;
                self.received.drain(..end);
                let seen = match message.payload {
                    Some(server_message::Payload::Challenge(challenge)) => {
                        self.challenge = (message.id, challenge.challenge);
                        Seen::Challenge
                    }
                    Some(server_message::Payload::Welcome(_)) => Seen::Welcome,
                    Some(server_message::Payload::Reconnect(reconnect)) => Seen::Reconnect(reconnect.reason),
                    other => anyhow::bail!("unexpected server message {other:?}"),
                };
                self.seen.push_back(seen);
            }
            Ok(())
        }

        /// Sends one agent message.
        async fn send(&self, message: AgentMessage) -> anyhow::Result<()> {
            self.send_encoded(&message.encode_to_vec()).await
        }

        /// Sends `message` as one gRPC message, whether or not it decodes.
        async fn send_encoded(&self, message: &[u8]) -> anyhow::Result<()> {
            let mut framed = vec![0];
            framed.extend_from_slice(&u32::try_from(message.len())?.to_be_bytes());
            framed.extend_from_slice(message);
            // A stream the mock already closed has dropped its receiver; its trailers tell the outcome.
            let _ = self.agent.send(Ok(Frame::data(Bytes::from(framed)))).await;
            Ok(())
        }

        /// A `Hello` answering the last `Challenge` with a proof by `key` (CONTRACT.agent-identity.md §7.3 step 3).
        fn hello(&self, key: &SigningKey) -> anyhow::Result<AgentMessage> {
            let mut proven = b"devolutions-agent-identity/v1/channel-proof\0".to_vec();
            proven.extend_from_slice(&self.challenge.1);
            proven.extend_from_slice(self.nonce.as_bytes());
            let proof: Signature = key.try_sign(&proven)?;
            Ok(AgentMessage {
                id: Uuid::new_v4().to_string(),
                correlation_id: Some(self.challenge.0.clone()),
                payload: Some(agent_message::Payload::Hello(Hello {
                    metadata: HashMap::new(),
                    capabilities: Vec::new(),
                    applied_state_versions: HashMap::from([("config".to_owned(), 1)]),
                    proof: proof.to_bytes().to_vec(),
                })),
            })
        }

        async fn answer(&self, answer: Answer, key: &SigningKey) -> anyhow::Result<()> {
            let mut message = self.hello(key)?;
            let Some(agent_message::Payload::Hello(hello)) = &mut message.payload else {
                unreachable!("a Hello message");
            };
            match answer {
                Answer::Nothing => return Ok(()),
                Answer::BadProof => hello.proof = vec![0; 64],
                Answer::WrongCorrelation => message.correlation_id = Some(Uuid::new_v4().to_string()),
                Answer::InvalidMetadata => {
                    hello
                        .metadata
                        .insert("hostname".to_owned(), "control\u{1}character".to_owned());
                }
            }
            self.send(message).await
        }
    }

    /// Opens a channel stream signed by a freshly enrolled certificate, with the mock clock frozen at `notAfter + offset`
    /// or `notBefore + offset`, and never sends a `Hello`.
    async fn open_at(from_not_after: bool, offset: i64) -> anyhow::Result<Vec<Seen>> {
        let enrolled = Enrolled::new().await?;
        let at = if from_not_after {
            enrolled.not_after
        } else {
            enrolled.not_before
        } + offset;
        enrolled.app.clock.freeze_at(at);
        Channel::open(&enrolled).await?.drain(QUIET).await
    }

    /// CONTRACT.agent-identity.md §6 accepts a `connect` signed by a certificate while `now ≤ notAfter`, whatever its
    /// `notBefore`, and §7.3 step 2 then sends `Challenge`; §7.4 closes the stream no later than `notAfter`.
    #[rstest]
    #[case::before_not_before(false, -10, vec![Seen::Challenge])]
    #[case::before_not_after(true, -1, vec![Seen::Challenge])]
    #[case::at_not_after(true, 0, vec![Seen::Challenge, Seen::Closed("16".to_owned(), "certificate_expired".to_owned())])]
    #[case::after_not_after(true, 1, vec![Seen::Closed("16".to_owned(), "certificate_expired".to_owned())])]
    #[tokio::test]
    async fn opening_follows_the_certificate_expiry_boundary(
        #[case] from_not_after: bool,
        #[case] offset: i64,
        #[case] expected: Vec<Seen>,
    ) -> anyhow::Result<()> {
        assert_eq!(open_at(from_not_after, offset).await?, expected);
        Ok(())
    }

    /// Appends field 1 (`id`) holding a byte that never occurs in UTF-8: `0x0a` is the tag of field 1 with wire type 2
    /// (length-delimited), `0x01` the length, and `0xff` the value.
    fn append_invalid_utf8_id(encoded: &mut Vec<u8>) {
        encoded.extend_from_slice(&[0x0a, 0x01, 0xff]);
    }

    /// Drops the last byte, which belongs to the message's last field, its payload, so that the payload claims one
    /// byte more than the message holds.
    fn truncate_payload(encoded: &mut Vec<u8>) {
        encoded.pop();
    }

    /// CONTRACT.agent-identity.md §7.3 step 4: a first agent message "that cannot be decoded" is not a `Hello`, so the
    /// server "closes the stream with `UNAUTHENTICATED` + `error-code: signature_invalid`" (gRPC code 16), and the
    /// failure doesn't change the identity's state.
    /// Each message corrupts a `Hello` the mock would accept, sent a minute after enrollment with new metadata, so that
    /// a mock reading it would change the identity's metadata or last-seen time.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §7.3
    #[rstest]
    #[case::invalid_utf8_in_a_string_field(append_invalid_utf8_id)]
    #[case::truncated(truncate_payload)]
    #[tokio::test]
    async fn undecodable_first_message_is_signature_invalid(#[case] corrupt: fn(&mut Vec<u8>)) -> anyhow::Result<()> {
        let enrolled = Enrolled::new().await?;
        let identity_state = |state: &State| {
            let identity = &state.identities[&enrolled.identity_id];
            (identity.metadata.clone(), identity.last_seen_at)
        };
        let enrolled_state = identity_state(&*enrolled.app.state.lock().await);
        enrolled.app.clock.freeze_at(enrolled.app.now() + 60);
        let mut channel = Channel::open(&enrolled).await?;
        assert_eq!(channel.next(QUIET).await?, Some(Seen::Challenge));

        let mut hello = channel.hello(&enrolled.key)?;
        let Some(agent_message::Payload::Hello(payload)) = &mut hello.payload else {
            unreachable!("a Hello message");
        };
        payload.metadata.insert("hostname".to_owned(), "agent-host".to_owned());
        let mut encoded = hello.encode_to_vec();
        corrupt(&mut encoded);
        channel.send_encoded(&encoded).await?;

        let closure = Seen::Closed("16".to_owned(), "signature_invalid".to_owned());
        assert_eq!(channel.drain(QUIET).await?, [closure]);
        assert_eq!(identity_state(&*enrolled.app.state.lock().await), enrolled_state);
        Ok(())
    }

    fn revoke(enrolled: &Enrolled, state: &mut State) {
        assert!(state.revoke(enrolled.identity_id, enrolled.app.now()).is_ok());
    }

    fn revoke_then_delete(enrolled: &Enrolled, state: &mut State) {
        revoke(enrolled, state);
        assert!(state.delete_identity(enrolled.identity_id, enrolled.app.now()).is_ok());
    }

    /// Real time passes `notAfter` without any request applying the clock to the mock.
    fn pass_not_after(enrolled: &Enrolled, _: &mut State) {
        enrolled.app.clock.freeze_at(enrolled.not_after + 1);
    }

    /// CONTRACT.agent-identity.md §7.4: the revocation and `notAfter` closures "also apply to a stream still awaiting `Hello`, ahead of
    /// the failures of §7.3 step 4; an identity revoked and then deleted during that wait gets `UNAUTHENTICATED` +
    /// `error-code: identity_unknown`".
    /// gRPC codes: 7 is `PERMISSION_DENIED` and 16 is `UNAUTHENTICATED`.
    #[rstest]
    #[case::revoked(revoke, "7", "identity_revoked")]
    #[case::revoked_then_deleted(revoke_then_delete, "16", "identity_unknown")]
    #[case::not_after_passed(pass_not_after, "16", "certificate_expired")]
    #[tokio::test(start_paused = true)]
    async fn closure_during_the_hello_wait_wins_over_the_handshake_failures(
        #[case] close: fn(&Enrolled, &mut State),
        #[case] status: &str,
        #[case] error_code: &str,
        #[values(Answer::Nothing, Answer::BadProof, Answer::WrongCorrelation, Answer::InvalidMetadata)] answer: Answer,
    ) -> anyhow::Result<()> {
        let enrolled = Enrolled::new().await?;
        enrolled.app.clock.freeze_at(enrolled.not_before);
        let mut channel = Channel::open(&enrolled).await?;
        assert_eq!(channel.next(QUIET).await?, Some(Seen::Challenge));

        close(&enrolled, &mut *enrolled.app.state.lock().await);
        channel.answer(answer, &enrolled.key).await?;

        // Waiting past the 10 s `Hello` timeout costs nothing on tokio's paused clock.
        let closure = Seen::Closed(status.to_owned(), error_code.to_owned());
        assert_eq!(channel.drain(Duration::from_secs(11)).await?, [closure]);
        Ok(())
    }

    /// CONTRACT.agent-identity.md §7.4: "A stream closes no later than its certificate's `notAfter`", which "also"
    /// applies "to a stream still awaiting `Hello`", even when no request applies the clock to the mock.
    #[tokio::test(start_paused = true)]
    async fn stream_awaiting_hello_closes_at_not_after() -> anyhow::Result<()> {
        let enrolled = Enrolled::new().await?;
        enrolled.app.clock.freeze_at(enrolled.not_after - 1);
        let mut channel = Channel::open(&enrolled).await?;
        assert_eq!(channel.next(QUIET).await?, Some(Seen::Challenge));

        enrolled.app.clock.freeze_at(enrolled.not_after);

        // Two seconds is well within the 10 s `Hello` timeout.
        let closure = Seen::Closed("16".to_owned(), "certificate_expired".to_owned());
        assert_eq!(channel.drain(Duration::from_secs(2)).await?, [closure]);
        Ok(())
    }

    /// CONTRACT.agent-identity.md §7.4 applies revocation to a stream awaiting `Hello` as well as `notAfter`.
    /// The identity's state comes before its certificate's, since `identity_revoked` is terminal (§5.4) where
    /// `certificate_expired` asks for a renewal.
    #[tokio::test(start_paused = true)]
    async fn revocation_wins_over_not_after_for_a_stream_awaiting_hello() -> anyhow::Result<()> {
        let enrolled = Enrolled::new().await?;
        enrolled.app.clock.freeze_at(enrolled.not_before);
        let mut channel = Channel::open(&enrolled).await?;
        assert_eq!(channel.next(QUIET).await?, Some(Seen::Challenge));

        {
            let mut state = enrolled.app.state.lock().await;
            revoke(&enrolled, &mut state);
            enrolled.app.clock.freeze_at(enrolled.not_after);
            state.tick(enrolled.not_after);
        }

        let closure = Seen::Closed("7".to_owned(), "identity_revoked".to_owned());
        assert_eq!(channel.drain(QUIET).await?, [closure]);
        let state = enrolled.app.state.lock().await;
        let closed = state
            .events
            .iter()
            .rev()
            .find(|event| event.body["type"] == "stream_closed");
        assert_eq!(
            closed.map(|event| &event.body["error_code"]),
            Some(&Value::from("identity_revoked"))
        );
        Ok(())
    }

    /// Revokes and deletes the identity of `channel`'s stream, then moves the mock clock to its certificate's
    /// `notAfter`, and returns what the stream shows within the next two seconds, well within the 10 s `Hello` timeout.
    async fn delete_then_reach_not_after(enrolled: &Enrolled, channel: &mut Channel) -> anyhow::Result<Vec<Seen>> {
        revoke_then_delete(enrolled, &mut *enrolled.app.state.lock().await);
        enrolled.advance_to(enrolled.not_after).await;
        channel.drain(Duration::from_secs(2)).await
    }

    /// CONTRACT.agent-identity.md §7.4: a stream awaiting `Hello` closes "no later than its certificate's `notAfter`",
    /// and "an identity revoked and then deleted during that wait gets `UNAUTHENTICATED` + `error-code:
    /// identity_unknown`".
    #[tokio::test(start_paused = true)]
    async fn deleted_identity_closes_a_stream_awaiting_hello_at_not_after() -> anyhow::Result<()> {
        let enrolled = Enrolled::new().await?;
        enrolled.app.clock.freeze_at(enrolled.not_after - 1);
        let mut channel = Channel::open(&enrolled).await?;
        assert_eq!(channel.next(QUIET).await?, Some(Seen::Challenge));

        let closure = Seen::Closed("16".to_owned(), "identity_unknown".to_owned());
        assert_eq!(delete_then_reach_not_after(&enrolled, &mut channel).await?, [closure]);
        Ok(())
    }

    /// As above, for a valid `Hello` that the `__mock__/handshake` pause holds, which no `Hello` timeout ends.
    #[tokio::test(start_paused = true)]
    async fn deleted_identity_closes_a_held_hello_at_not_after() -> anyhow::Result<()> {
        let enrolled = Enrolled::new().await?;
        enrolled.app.clock.freeze_at(enrolled.not_after - 1);
        enrolled.app.handshake_gate.send_replace(false);
        let mut channel = Channel::open(&enrolled).await?;
        assert_eq!(channel.next(QUIET).await?, Some(Seen::Challenge));
        channel.send(channel.hello(&enrolled.key)?).await?;
        let held = async {
            while enrolled.app.state.lock().await.paused_hellos.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(1), held).await?;

        let closure = Seen::Closed("16".to_owned(), "identity_unknown".to_owned());
        assert_eq!(delete_then_reach_not_after(&enrolled, &mut channel).await?, [closure]);
        Ok(())
    }

    /// CONTRACT.agent-identity.md §7.4: "A stream whose certificate is retired while it awaits `Hello` still completes
    /// the handshake, then gets the same treatment" as the streams of a certificate `confirm` retires: they "get
    /// `Reconnect{reason:"certificate_rotated"}` and are closed with `OK` 60 s later if still open".
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §7.4
    #[tokio::test(start_paused = true)]
    async fn certificate_retired_during_the_hello_wait_completes_the_handshake_then_rotates() -> anyhow::Result<()> {
        let enrolled = Enrolled::new().await?;
        let opened_at = enrolled.not_before;
        enrolled.app.clock.freeze_at(opened_at);
        let mut channel = Channel::open(&enrolled).await?;
        assert_eq!(channel.next(QUIET).await?, Some(Seen::Challenge));

        let pending_key = SigningKey::from_slice(&[8; 32]).expect("valid P-256 scalar");
        let pending_keyid = enrolled.add_pending(&pending_key).await;
        assert_eq!(
            enrolled.confirm(&pending_key, &pending_keyid, "").await?,
            (http::StatusCode::NO_CONTENT, None)
        );

        // The 60 s run from the `Reconnect`, which comes 30 s after the `confirm`.
        let hello_at = opened_at + 30;
        enrolled.app.clock.freeze_at(hello_at);
        channel.send(channel.hello(&enrolled.key)?).await?;
        let reconnect = Seen::Reconnect("certificate_rotated".to_owned());
        assert_eq!(channel.drain(QUIET).await?, [Seen::Welcome, reconnect]);

        enrolled.advance_to(hello_at + 59).await;
        assert_eq!(channel.drain(QUIET).await?, Vec::new());
        enrolled.advance_to(hello_at + 60).await;
        assert_eq!(
            channel.drain(QUIET).await?,
            [Seen::Closed("0".to_owned(), String::new())]
        );
        Ok(())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.5
    #[tokio::test]
    async fn confirm_with_a_body_is_invalid_request_and_promotes_nothing() -> anyhow::Result<()> {
        let enrolled = Enrolled::new().await?;
        let pending_key = SigningKey::from_slice(&[8; 32]).expect("valid P-256 scalar");
        let pending_keyid = enrolled.add_pending(&pending_key).await;

        assert_eq!(
            enrolled.confirm(&pending_key, &pending_keyid, "{}").await?,
            (http::StatusCode::BAD_REQUEST, Some("invalid_request".to_owned()))
        );
        let state = enrolled.app.state.lock().await;
        let statuses = state.identities[&enrolled.identity_id]
            .certs
            .iter()
            .map(|cert| cert.status)
            .collect::<Vec<_>>();
        assert_eq!(statuses, [CertStatus::Current, CertStatus::Pending]);
        Ok(())
    }
}
