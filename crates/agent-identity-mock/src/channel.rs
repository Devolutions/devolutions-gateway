//! Channel service (CONTRACT.md §7): tonic `AgentChannel/Connect` bidi stream with the
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
use crate::state::{StreamHandle, StreamPush, stream_expired};

/// §7.3: the agent must answer the challenge within 10 s (real time).
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub(crate) struct ChannelService {
    pub(crate) app: Arc<App>,
}

/// Builds a stream failure status with the `error-code` and `server-time` trailers
/// ([CONTRACT.md][contract], "7.4 Termination").
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.md#74-termination
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
                let crate::state::State {
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
            result
        };
        let auth = auth.map_err(|rejection| rejection_status(rejection, now))?;

        tokio::spawn(run_stream(
            app,
            stream_id,
            auth,
            request.into_inner(),
            push_tx,
            push_rx,
            out_tx,
        ));
        Ok(Response::new(ReceiverStream::new(out_rx)))
    }
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
    auth: crate::oracle::AuthenticatedIdentity,
    mut client: Streaming<AgentMessage>,
    push_tx: mpsc::UnboundedSender<StreamPush>,
    mut push_rx: mpsc::UnboundedReceiver<StreamPush>,
    out: mpsc::Sender<Result<ServerMessage, Status>>,
) {
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
    let hello = tokio::select! {
        result = tokio::time::timeout(HELLO_TIMEOUT, client.next()) => match result {
            Ok(Some(Ok(message))) => message,
            Ok(Some(Err(_))) | Ok(None) | Err(_) => {
                close_with(&out, error_status(Code::Unauthenticated, "signature_invalid", app.now())).await;
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
            }
        },
        push = push_rx.recv() => {
            close_opening_push(&app, &out, stream_id, identity_id, &cert_thumbprint, push).await;
            return;
        }
    };
    let hello_id = hello.id.clone();
    let hello_ok = hello.correlation_id.as_deref() == Some(challenge_id.as_str())
        && match &hello.payload {
            Some(agent_message::Payload::Hello(hello)) => {
                verify_channel_proof(auth.public_key(), &challenge, auth.nonce(), &hello.proof)
            }
            _ => false,
        };
    if !hello_ok {
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
    }
    let Some(agent_message::Payload::Hello(hello_payload)) = hello.payload else {
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
            }
        }
        app.state.lock().await.paused_hellos.remove(&stream_id);
    }

    // Step 4: only now does anything happen server-side.
    let authentication = {
        let now = app.now();
        let mut state = app.state.lock().await;
        state.tick(now);
        let rejection = match state.lookup_cert(&cert_thumbprint) {
            Some(cert)
                if cert.identity_id == identity_id
                    && matches!(cert.status, CertStatus::Current | CertStatus::Pending) =>
            {
                if cert.revoked {
                    Some(Rejection::IdentityRevoked)
                } else if stream_expired(cert.not_after, now) {
                    Some(Rejection::CertificateExpired)
                } else {
                    None
                }
            }
            _ => Some(Rejection::IdentityUnknown),
        };
        if let Some(rejection) = rejection {
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
            state.streams.insert(
                stream_id,
                StreamHandle {
                    identity_id,
                    cert_thumbprint: cert_thumbprint.clone(),
                    tx: push_tx,
                    retire_at: None,
                },
            );
            state.requests.authenticated_connects += 1;
            Ok((reason, config_update))
        }
    };
    let (renewal_reason, config_update) = match authentication {
        Ok(result) => result,
        Err(rejection) => {
            close_with(&out, rejection_status(rejection, app.now())).await;
            finish_stream(
                &app,
                stream_id,
                identity_id,
                &cert_thumbprint,
                if rejection == Rejection::IdentityRevoked {
                    "PERMISSION_DENIED"
                } else {
                    "UNAUTHENTICATED"
                },
                Some(rejection.code()),
            )
            .await;
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
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::time::Duration;

    use agent_channel_proto::{ServerMessage, server_message};
    use axum::body::Bytes;
    use axum::http;
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use http_body_util::{BodyExt as _, StreamBody};
    use hyper::body::Frame;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};
    use prost::Message as _;
    use rstest::rstest;
    use serde_json::{Map, Value};
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::Code;

    use super::error_status;
    use crate::app::App;
    use crate::server::Dispatcher;

    #[test]
    fn stream_failure_carries_error_code_and_server_time_trailers() {
        let status = error_status(Code::Unauthenticated, "clock_skew", 1_790_000_000);
        let trailer = |name: &str| status.metadata().get(name).and_then(|value| value.to_str().ok());

        assert_eq!(status.code(), Code::Unauthenticated);
        assert_eq!(trailer("error-code"), Some("clock_skew"));
        assert_eq!(trailer("server-time"), Some("2026-09-21T14:13:20Z"));
    }

    /// Server events on a stream opened at `now`, until it closes or goes quiet for 500 ms.
    #[derive(Debug, PartialEq, Eq)]
    enum Seen {
        Challenge,
        Closed(String, String),
    }

    /// Opens a channel stream signed by a freshly enrolled certificate, with the mock clock frozen at `notAfter + offset`
    /// or `notBefore + offset`, and never sends a `Hello`.
    async fn open_at(from_not_after: bool, offset: i64) -> anyhow::Result<Vec<Seen>> {
        let app = App::for_test()?;
        let key = SigningKey::from_slice(&[7; 32]).expect("valid P-256 scalar");
        let (keyid, now) = {
            let mut state = app.state.lock().await;
            let now = app.now();
            let (_, secret) = state.create_token("test".to_owned(), 1, crate::app::nanos(now + 3600), None, None, now);
            let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
            let csr = STANDARD.decode(vectors["csr"]["valid"]["csr"].as_str().expect("valid CSR vector"))?;
            let identity_id = state
                .enroll(&secret, &csr, Map::new(), now, &app.base_url)
                .expect("enrollment succeeds")
                .identity_id;
            // The test signs with its own key, so that key replaces the enrolled one.
            let cert = state
                .identities
                .get_mut(&identity_id)
                .and_then(|identity| identity.certs.first_mut())
                .expect("issued certificate");
            cert.public_key = *key.verifying_key();
            let at = if from_not_after {
                cert.not_after
            } else {
                cert.not_before
            } + offset;
            (cert.thumbprint.clone(), at)
        };
        app.clock.freeze_at(now);

        let params = format!(
            "(\"@method\");created={now};expires={};nonce=\"{}\";keyid=\"{keyid}\";alg=\"ecdsa-p256-sha256\";tag=\"connect\"",
            now + 60,
            URL_SAFE_NO_PAD.encode([0u8; 16])
        );
        let signature: Signature =
            key.try_sign(format!("\"@method\": POST\n\"@signature-params\": {params}").as_bytes())?;
        let (_agent, agent_messages) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(1);
        let request = http::Request::post(format!("/mock/{}/Connect", agent_channel_proto::SERVICE_NAME))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("signature-input", format!("sig={params}"))
            .header("signature", format!("sig=:{}:", STANDARD.encode(signature.to_bytes())))
            .body(StreamBody::new(ReceiverStream::new(agent_messages)))?;
        let response = Dispatcher::new(Arc::clone(&app))
            .handle(request)
            .await
            .expect("the mock answers");

        let closed = |headers: &http::HeaderMap| {
            let value = |name: &str| {
                headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned()
            };
            headers
                .contains_key("grpc-status")
                .then(|| Seen::Closed(value("grpc-status"), value("error-code")))
        };
        let mut seen = Vec::new();
        if let Some(refused) = closed(response.headers()) {
            seen.push(refused);
            return Ok(seen);
        }
        let mut body = response.into_body();
        while let Ok(Some(frame)) = tokio::time::timeout(Duration::from_millis(500), body.frame()).await {
            let frame = frame.map_err(|error| anyhow::anyhow!("{error}"))?;
            if let Some(data) = frame.data_ref() {
                let message = ServerMessage::decode(&data[5..])?;
                assert!(matches!(message.payload, Some(server_message::Payload::Challenge(_))));
                seen.push(Seen::Challenge);
            } else if let Some(trailers) = frame.trailers_ref() {
                seen.extend(closed(trailers));
                break;
            }
        }
        Ok(seen)
    }

    /// CONTRACT.md §6 accepts a `connect` signed by a certificate while `now ≤ notAfter`, whatever its `notBefore`,
    /// and §7.3 step 2 then sends `Challenge`; §7.4 closes the stream no later than `notAfter`.
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
}
