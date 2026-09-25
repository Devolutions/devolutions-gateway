use std::time::Duration;

use agent_identity_channel_proto::agent_channel_client::AgentChannelClient;
use agent_identity_channel_proto::{Ack, AgentMessage, Hello, ServerMessage, agent_message, server_message};
use anyhow::{Context as _, ensure};
use http::Request as HttpRequest;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::body::BoxBody;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};
use tonic::{Code, Request, Status, Streaming};
use tower::{Service as _, ServiceExt as _, service_fn};

use crate::client::{Identity, Target};
use crate::signer::SignedHeaders;

pub(crate) struct ChannelStream {
    pub(crate) sender: mpsc::Sender<AgentMessage>,
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
        let Some(server_message::Payload::Challenge(payload)) = challenge.payload.as_ref() else {
            anyhow::bail!("expected a channel challenge");
        };
        let id = uuid::Uuid::new_v4().to_string();
        let proof =
            proof_override.unwrap_or_else(|| identity.key.channel_proof(&payload.challenge, &self.headers.nonce));
        self.sender
            .send(AgentMessage {
                id: id.clone(),
                correlation_id: Some(challenge.id.clone()),
                payload: Some(agent_message::Payload::Hello(Hello {
                    metadata: metadata
                        .iter()
                        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                        .collect(),
                    capabilities: Vec::new(),
                    applied_state_versions: Default::default(),
                    proof,
                })),
            })
            .await
            .context("send channel Hello")?;
        Ok(id)
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
        let sender = self.sender.clone();
        sender
            .send(AgentMessage {
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
        "expected gRPC {grpc_code:?}, got {:?}",
        status.code()
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
        .channel_url
        .as_deref()
        .context("enrollment omitted channel_url")?;
    open_at_url(target, channel_url, headers).await
}

pub(crate) async fn probe_unavailable(target: &Target, identity: &Identity) -> anyhow::Result<ChannelStream> {
    let headers = identity.key.sign_now(&identity.thumbprint, "connect", None);
    open_at_url(target, &target.base_url, headers).await
}

async fn open_at_url(target: &Target, channel_url: &str, headers: SignedHeaders) -> anyhow::Result<ChannelStream> {
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
    let mut client = AgentChannelClient::new(service);
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
    let stream = client.connect(request).await?.into_inner();
    Ok(ChannelStream {
        sender,
        stream,
        headers,
    })
}
