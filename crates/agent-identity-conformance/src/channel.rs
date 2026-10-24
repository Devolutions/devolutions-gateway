use std::time::Duration;

use agent_channel_proto::{Ack, AgentMessage, Hello, ServerMessage, agent_message, server_message};
use anyhow::{Context as _, ensure};
use http::Request as HttpRequest;
use http::uri::PathAndQuery;
use prost::Message as _;
use prost::bytes::{Buf as _, BufMut as _};
use time::format_description::well_known::Rfc3339;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::body::BoxBody;
use tonic::client::Grpc;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};
use tonic::{Code, Request, Status, Streaming};
use tower::{Service as _, ServiceExt as _, service_fn};

use crate::client::{Identity, Target};
use crate::signer::SignedHeaders;

/// The largest envelope either side of the channel accepts or sends, in bytes of serialized protobuf without gRPC's 5-byte message prefix.
///
/// See [CONTRACT.agent-identity.md] §7.1 "Service".
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
pub(crate) const MAX_ENVELOPE_LEN: usize = 65_536;

/// The `:path` of `AgentChannel.Connect` below the channel URL's path.
///
/// See [CONTRACT.agent-identity.md] §7.2 "URL and path prefix".
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
const CONNECT_PATH: &str = "/devolutions.agent.channel.v1.AgentChannel/Connect";

/// The key of `AgentMessage.id`, field 1 with wire type 2 (`LEN`): `1 << 3 | 2`.
const ID_KEY: [u8; 1] = [0x0A];

/// The key of field 99 with wire type 2 (`LEN`), which `AgentMessage` does not define: `99 << 3 | 2` = 794, the varint `0x9A 0x06`.
const PADDING_KEY: [u8; 2] = [0x9A, 0x06];

pub(crate) struct ChannelStream {
    sender: mpsc::Sender<Vec<u8>>,
    pub(crate) stream: Streaming<ServerMessage>,
    pub(crate) headers: SignedHeaders,
}

impl ChannelStream {
    pub(crate) async fn challenge(&mut self) -> anyhow::Result<ServerMessage> {
        let message = self.next().await?;
        ensure!(
            matches!(message.payload.as_ref(), Some(server_message::Payload::Challenge(_))),
            "first channel message is not a challenge"
        );
        ensure!(
            message.payload.as_ref().and_then(|p| match p {
                server_message::Payload::Challenge(challenge) => Some(challenge.challenge.len()),
                _ => None,
            }) == Some(32),
            "channel challenge is not 32 bytes"
        );
        Ok(message)
    }

    pub(crate) async fn send_hello(
        &mut self,
        identity: &Identity,
        challenge: &ServerMessage,
        metadata: &[(&str, &str)],
        proof_override: Option<Vec<u8>>,
    ) -> anyhow::Result<String> {
        let revision = config_revision(identity)?;
        self.send_hello_with_revision(identity, challenge, metadata, proof_override, revision)
            .await
    }

    pub(crate) async fn send_hello_with_revision(
        &mut self,
        identity: &Identity,
        challenge: &ServerMessage,
        metadata: &[(&str, &str)],
        proof_override: Option<Vec<u8>>,
        revision: u64,
    ) -> anyhow::Result<String> {
        let message = self.hello_message(identity, challenge, metadata, proof_override, revision)?;
        self.send(&message).await.context("send channel Hello")?;
        Ok(message.id)
    }

    /// Serializes the `Hello` that [`Self::send_hello`] sends, as [`agent_message_frame`] does with `id` and `len`.
    pub(crate) fn hello_frame(
        &self,
        identity: &Identity,
        challenge: &ServerMessage,
        metadata: &[(&str, &str)],
        id: &[u8],
        len: usize,
    ) -> anyhow::Result<Vec<u8>> {
        let message = self.hello_message(identity, challenge, metadata, None, config_revision(identity)?)?;
        agent_message_frame(id, &message, len)
    }

    fn hello_message(
        &self,
        identity: &Identity,
        challenge: &ServerMessage,
        metadata: &[(&str, &str)],
        proof_override: Option<Vec<u8>>,
        revision: u64,
    ) -> anyhow::Result<AgentMessage> {
        let Some(server_message::Payload::Challenge(payload)) = challenge.payload.as_ref() else {
            anyhow::bail!("expected a channel challenge");
        };
        let proof =
            proof_override.unwrap_or_else(|| identity.key.channel_proof(&payload.challenge, &self.headers.nonce));
        Ok(AgentMessage {
            id: uuid::Uuid::new_v4().to_string(),
            correlation_id: Some(challenge.id.clone()),
            payload: Some(agent_message::Payload::Hello(Hello {
                metadata: metadata
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect(),
                capabilities: Vec::new(),
                applied_state_versions: [("config".to_owned(), revision)].into_iter().collect(),
                proof,
            })),
        })
    }

    pub(crate) async fn send(&mut self, message: &AgentMessage) -> anyhow::Result<()> {
        self.send_frame(message.encode_to_vec()).await
    }

    /// Sends `frame` as one gRPC message, whether or not it decodes as an `AgentMessage`.
    pub(crate) async fn send_frame(&mut self, frame: Vec<u8>) -> anyhow::Result<()> {
        self.sender.send(frame).await.context("send channel frame")
    }

    pub(crate) async fn hello(&mut self, identity: &Identity, metadata: &[(&str, &str)]) -> anyhow::Result<()> {
        let challenge = self.challenge().await?;
        let hello_id = self.send_hello(identity, &challenge, metadata, None).await?;
        let welcome = self.next().await?;
        ensure!(
            matches!(welcome.payload, Some(server_message::Payload::Welcome(_)))
                && welcome.correlation_id.as_deref() == Some(&hello_id),
            "channel Welcome missing or incorrectly correlated"
        );
        Ok(())
    }

    pub(crate) async fn ack(&mut self, message: &ServerMessage) -> anyhow::Result<()> {
        self.send(&AgentMessage {
            id: uuid::Uuid::new_v4().to_string(),
            correlation_id: Some(message.id.clone()),
            payload: Some(agent_message::Payload::Ack(Ack {})),
        })
        .await
        .context("acknowledge channel message")
    }

    pub(crate) async fn next(&mut self) -> anyhow::Result<ServerMessage> {
        self.next_with_timeout(Duration::from_secs(5)).await
    }

    pub(crate) async fn next_with_timeout(&mut self, timeout: Duration) -> anyhow::Result<ServerMessage> {
        tokio::time::timeout(timeout, self.stream.message())
            .await
            .context("timed out waiting for channel message")??
            .context("channel closed unexpectedly")
    }

    pub(crate) async fn closing_status(&mut self, timeout: Duration) -> anyhow::Result<Status> {
        match tokio::time::timeout(timeout, self.stream.message())
            .await
            .context("channel did not close")?
        {
            Err(status) => Ok(status),
            Ok(Some(_)) => anyhow::bail!("channel sent a message instead of closing"),
            Ok(None) => anyhow::bail!("channel closed without a gRPC error"),
        }
    }
}

pub(crate) fn expect_status(status: &Status, grpc_code: Code, error_code: &str) -> anyhow::Result<()> {
    ensure!(
        status.code() == grpc_code,
        "expected gRPC {grpc_code:?}, got {:?} ({:?})",
        status.code(),
        status.message()
    );
    ensure!(
        status
            .metadata()
            .get("error-code")
            .and_then(|value| value.to_str().ok())
            == Some(error_code),
        "expected gRPC error-code {error_code}, got {:?}",
        status.metadata().get("error-code")
    );
    Ok(())
}

/// Checks a channel opening refused before `Challenge`, whose trailers carry the §5.4 code and the authority's time.
///
/// See [CONTRACT.agent-identity.md] §7.4 "Termination" and §1 "Protocol conventions".
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
pub(crate) fn expect_refused_opening(status: &Status, grpc_code: Code, error_code: &str) -> anyhow::Result<()> {
    expect_status(status, grpc_code, error_code)?;
    expect_server_time(status)
}

/// Awaits `opening`, fails with `accepted` if it opens a stream, and checks its refusal with [`expect_refused_opening`].
pub(crate) async fn expect_opening_refused(
    opening: impl Future<Output = anyhow::Result<ChannelStream>>,
    accepted: impl std::fmt::Display + Send + Sync + 'static,
    grpc_code: Code,
    error_code: &str,
) -> anyhow::Result<Status> {
    let failure = opening.await.err().context(accepted)?;
    let status = failure.downcast::<Status>().ok().context("missing gRPC status")?;
    expect_refused_opening(&status, grpc_code, error_code)?;
    Ok(status)
}

/// Checks that an authentication failure, at opening or while the stream awaits `Hello`, carries the authority's time.
///
/// See [CONTRACT.agent-identity.md] §7.4 "Termination" and §1 "Protocol conventions".
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
pub(crate) fn expect_server_time(status: &Status) -> anyhow::Result<()> {
    let server_time = status
        .metadata()
        .get("server-time")
        .context("authentication failure has no server-time trailer")?
        .to_str()
        .context("server-time trailer is not ASCII")?;
    ensure!(
        server_time.ends_with('Z'),
        "server-time trailer {server_time:?} does not end in Z"
    );
    time::OffsetDateTime::parse(server_time, &Rfc3339).context("server-time trailer is not RFC 3339")?;
    Ok(())
}

pub(crate) async fn open(target: &Target, identity: &Identity) -> anyhow::Result<ChannelStream> {
    let headers = identity.key.sign_now(&identity.thumbprint, "connect", None);
    open_with_headers(target, identity, headers).await
}

pub(crate) async fn open_with_headers(
    target: &Target,
    identity: &Identity,
    headers: SignedHeaders,
) -> anyhow::Result<ChannelStream> {
    let channel_url = identity
        .agent_channel_url
        .as_deref()
        .context("enrollment omitted config.agent_channel_url")?;
    open_at_url(target, channel_url, headers, None).await
}

pub(crate) async fn open_with_duplicate_header(
    target: &Target,
    identity: &Identity,
    name: &'static str,
) -> anyhow::Result<ChannelStream> {
    let channel_url = identity
        .agent_channel_url
        .as_deref()
        .context("enrollment omitted config.agent_channel_url")?;
    let headers = identity.key.sign_now(&identity.thumbprint, "connect", None);
    open_at_url(target, channel_url, headers, Some(name)).await
}

pub(crate) async fn probe_unavailable(target: &Target, identity: &Identity) -> anyhow::Result<ChannelStream> {
    let headers = identity.key.sign_now(&identity.thumbprint, "connect", None);
    open_at_url(target, &target.base_url, headers, None).await
}

async fn open_at_url(
    target: &Target,
    channel_url: &str,
    headers: SignedHeaders,
    duplicate: Option<&'static str>,
) -> anyhow::Result<ChannelStream> {
    let url = reqwest::Url::parse(channel_url)?;
    let origin = url.origin().ascii_serialization();
    let mut endpoint = Endpoint::from_shared(origin)?.connect_timeout(Duration::from_secs(5));
    let mut tls = ClientTlsConfig::new().with_webpki_roots();
    if let Some(ca_path) = &target.ca_path {
        tls = tls.ca_certificate(Certificate::from_pem(std::fs::read(ca_path)?));
    }
    endpoint = endpoint.tls_config(tls)?;
    let transport = endpoint.connect().await.context("connect channel transport")?;
    let prefix = url.path().trim_end_matches('/').to_owned();
    let service = service_fn(move |mut request: HttpRequest<BoxBody>| {
        let mut transport = transport.clone();
        let path = format!(
            "{prefix}{}",
            request.uri().path_and_query().map_or("/", |value| value.as_str())
        );
        async move {
            *request.uri_mut() = path
                .parse()
                .map_err(|error: http::uri::InvalidUri| Status::internal(format!("invalid channel path: {error}")))?;
            transport
                .ready()
                .await
                .map_err(|error| Status::from_error(Box::new(error)))?;
            transport
                .call(request)
                .await
                .map_err(|error| Status::from_error(Box::new(error)))
        }
    });
    let mut grpc = Grpc::new(service);
    let (sender, receiver) = mpsc::channel(8);
    let mut request = Request::new(ReceiverStream::new(receiver));
    request.metadata_mut().insert(
        "signature-input",
        headers.input.parse().context("encode signature input")?,
    );
    request
        .metadata_mut()
        .insert("signature", headers.signature.parse().context("encode signature")?);
    if let Some(digest) = &headers.digest {
        request
            .metadata_mut()
            .insert("content-digest", digest.parse().context("encode content digest")?);
    }
    if let Some(name) = duplicate {
        let value = match name {
            "signature-input" => &headers.input,
            "signature" => &headers.signature,
            _ => anyhow::bail!("unknown duplicate metadata {name}"),
        };
        request
            .metadata_mut()
            .append(name, value.parse().context("duplicate signature metadata")?);
    }
    grpc.ready().await?;
    let stream = grpc
        .streaming(request, PathAndQuery::from_static(CONNECT_PATH), FrameCodec)
        .await?
        .into_inner();
    Ok(ChannelStream {
        sender,
        stream,
        headers,
    })
}

fn config_revision(identity: &Identity) -> anyhow::Result<u64> {
    identity.config["revision"]
        .as_u64()
        .context("identity config has no revision")
}

/// Serializes `message` with `id` in place of its own, as bytes that need not be UTF-8, and pads it with an unknown field to exactly `len` bytes.
///
/// A protobuf decoder skips a field its schema does not define, so the padding changes no decoded value.
pub(crate) fn agent_message_frame(id: &[u8], message: &AgentMessage, len: usize) -> anyhow::Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(len);
    frame.extend_from_slice(&ID_KEY);
    prost::encode_length_delimiter(id.len(), &mut frame)?;
    frame.extend_from_slice(id);
    AgentMessage {
        id: String::new(),
        ..message.clone()
    }
    .encode(&mut frame)?;
    let room = len
        .checked_sub(frame.len() + PADDING_KEY.len())
        .context("the message leaves no room for padding")?;
    // The padding's length prefix takes part of the room, and a varint takes at most 10 bytes.
    let padding = (1..=10)
        .filter_map(|prefix_len| room.checked_sub(prefix_len))
        .find(|&padding| padding + prost::length_delimiter_len(padding) == room)
        .with_context(|| format!("no padding makes the frame {len} bytes"))?;
    frame.extend_from_slice(&PADDING_KEY);
    prost::encode_length_delimiter(padding, &mut frame)?;
    frame.extend(std::iter::repeat_n(0, padding));
    ensure!(frame.len() == len, "padded frame is {} bytes, not {len}", frame.len());
    Ok(frame)
}

/// Sends each frame's bytes as they are, so that a test can send a message that does not decode, and decodes server messages within the envelope limit.
struct FrameCodec;

impl Codec for FrameCodec {
    type Encode = Vec<u8>;
    type Decode = ServerMessage;
    type Encoder = FrameCodec;
    type Decoder = FrameCodec;

    fn encoder(&mut self) -> Self::Encoder {
        FrameCodec
    }

    fn decoder(&mut self) -> Self::Decoder {
        FrameCodec
    }
}

impl Encoder for FrameCodec {
    type Item = Vec<u8>;
    type Error = Status;

    fn encode(&mut self, frame: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        dst.put_slice(&frame);
        Ok(())
    }
}

impl Decoder for FrameCodec {
    type Item = ServerMessage;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<ServerMessage>, Status> {
        // The buffer holds exactly one message, without its gRPC prefix.
        let len = src.remaining();
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
        // UNTESTED: a server message over the envelope limit fails the read that receives it.
        // No authority under test sends one, so a broken check still passes every run.
        // When changing this decoder, lower the limit below a `Challenge` and see every channel test fail.
        if MAX_ENVELOPE_LEN < len {
            return Err(Status::internal(format!(
                "server message of {len} bytes exceeds the {MAX_ENVELOPE_LEN}-byte envelope limit"
            )));
        }
        ServerMessage::decode(src)
            .map(Some)
            .map_err(|error| Status::internal(format!("undecodable server message: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use tonic::metadata::MetadataMap;

    use super::*;

    fn refusal(server_time: Option<&str>) -> anyhow::Result<Status> {
        let mut metadata = MetadataMap::new();
        metadata.insert("error-code", "clock_skew".parse()?);
        if let Some(server_time) = server_time {
            metadata.insert("server-time", server_time.parse()?);
        }
        Ok(Status::with_metadata(Code::Unauthenticated, "skewed", metadata))
    }

    #[test]
    fn refused_opening_requires_a_z_server_time_trailer() -> anyhow::Result<()> {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        expect_refused_opening(
            &refusal(Some("2026-09-24T12:00:00Z"))?,
            Code::Unauthenticated,
            "clock_skew",
        )?;
        for server_time in [None, Some("2026-09-24T12:00:00+00:00"), Some("not a time")] {
            ensure!(
                expect_refused_opening(&refusal(server_time)?, Code::Unauthenticated, "clock_skew").is_err(),
                "refused opening with server-time {server_time:?} was accepted"
            );
        }
        Ok(())
    }
}
