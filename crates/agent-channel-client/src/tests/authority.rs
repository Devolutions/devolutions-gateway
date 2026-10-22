//! An in-process authority for the channel tests, built from `agent-channel-proto`.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use agent_channel_proto::agent_channel_server::{AgentChannel, AgentChannelServer};
use agent_channel_proto::server_message::Payload;
use agent_channel_proto::{AgentMessage, Challenge, ServerMessage, Welcome};
use anyhow::Context as _;
use hyper::body::{Bytes, Frame};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tower::Service as _;
use url::Url;

/// How long a test waits for something the client must do.
pub(super) const WAIT: Duration = Duration::from_secs(10);

const URL_PATH: &str = "/dvls";

/// What the authority's TLS endpoint speaks.
#[derive(Clone, Copy)]
pub(super) enum Mode {
    /// A gRPC authority over HTTP/2.
    Grpc,
    /// A gRPC authority over HTTP/2 whose responses carry this content type.
    GrpcAs(&'static str),
    /// HTTP/2 that answers every request with a page of this status and content type, like a reverse proxy without a
    /// gRPC route or in front of a server that is down.
    Http2Page(http::StatusCode, &'static str),
    /// HTTP/1.1 without ALPN, like a reverse proxy that ignores the offer of HTTP/2.
    Http1WithoutAlpn,
    /// A server whose only ALPN protocol is `http/1.1`.
    Http1Alpn,
}

/// A TLS server CA and a certificate it issued for `127.0.0.1` and `localhost`.
pub(super) struct Pki {
    pub(super) ca: CertificateDer<'static>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivatePkcs8KeyDer<'static>,
}

impl Pki {
    pub(super) fn generate() -> anyhow::Result<Self> {
        let ca_key = rcgen::KeyPair::generate()?;
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "agent-channel-client test CA");
        let ca = ca_params.self_signed(&ca_key)?;
        let leaf_key = rcgen::KeyPair::generate()?;
        let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned(), "localhost".to_owned()])?
            .signed_by(&leaf_key, &ca, &ca_key)?;
        Ok(Self {
            ca: ca.der().clone(),
            chain: vec![leaf.der().clone()],
            key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
        })
    }

    pub(super) fn server_config(&self, alpn: &[&[u8]]) -> anyhow::Result<rustls::ServerConfig> {
        let mut config =
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(self.chain.clone(), PrivateKeyDer::Pkcs8(self.key.clone_key()))?;
        config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
        Ok(config)
    }
}

/// An authority listening on loopback; every stream opening is handed to the test.
pub(super) struct TestAuthority {
    /// The `agent_channel_url`, with a path prefix.
    pub(super) url: Url,
    /// The root that issued the server certificate.
    pub(super) ca: CertificateDer<'static>,
    openings: mpsc::UnboundedReceiver<Opening>,
    pings: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl TestAuthority {
    pub(super) async fn start(mode: Mode) -> anyhow::Result<Self> {
        let pki = Pki::generate()?;
        let alpn: &[&[u8]] = match mode {
            Mode::Grpc | Mode::GrpcAs(_) | Mode::Http2Page(..) => &[b"h2"],
            Mode::Http1WithoutAlpn => &[],
            Mode::Http1Alpn => &[b"http/1.1"],
        };
        let acceptor = TlsAcceptor::from(Arc::new(pki.server_config(alpn)?));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let (opening_sender, openings) = mpsc::unbounded_channel();
        let grpc = AgentChannelServer::new(Handler {
            openings: opening_sender,
        });
        let pings = Arc::new(AtomicUsize::new(0));
        let counted_pings = Arc::clone(&pings);
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let grpc = grpc.clone();
                let pings = Arc::clone(&counted_pings);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let io = PingCounter::new(tls, pings);
                    match mode {
                        Mode::Grpc => serve_grpc(io, grpc, None).await,
                        Mode::GrpcAs(content_type) => serve_grpc(io, grpc, Some(content_type)).await,
                        Mode::Http2Page(status, content_type) => serve_page(io, status, content_type).await,
                        Mode::Http1WithoutAlpn | Mode::Http1Alpn => answer_http1(io).await,
                    }
                });
            }
        });
        Ok(Self {
            url: Url::parse(&format!("https://127.0.0.1:{port}{URL_PATH}"))?,
            ca: pki.ca,
            openings,
            pings,
            task,
        })
    }

    /// Waits for the client's next stream opening.
    pub(super) async fn next_opening(&mut self) -> Opening {
        tokio::time::timeout(WAIT, self.openings.recv())
            .await
            .expect("no stream opening arrived in time")
            .expect("authority stopped")
    }

    /// Returns whether a stream opening arrives within `wait`.
    pub(super) async fn opening_within(&mut self, wait: Duration) -> Option<Opening> {
        tokio::time::timeout(wait, self.openings.recv()).await.ok().flatten()
    }

    /// The number of HTTP/2 PING frames, acknowledgements excluded, that clients have sent.
    pub(super) fn pings(&self) -> usize {
        self.pings.load(Ordering::SeqCst)
    }
}

impl Drop for TestAuthority {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A stream opening the test accepts or refuses.
pub(super) struct Opening {
    /// The request `:path`.
    pub(super) path: String,
    pub(super) headers: http::HeaderMap,
    inbound: Streaming<AgentMessage>,
    reply: oneshot::Sender<Result<mpsc::Receiver<Result<ServerMessage, Status>>, Status>>,
    encoded: mpsc::UnboundedSender<Bytes>,
}

impl Opening {
    pub(super) fn signature_input(&self) -> &str {
        self.headers
            .get("signature-input")
            .and_then(|value| value.to_str().ok())
            .expect("opening without signature-input")
    }

    /// The `nonce` parameter of the opening signature.
    pub(super) fn nonce(&self) -> String {
        self.signature_input()
            .split_once(";nonce=\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(nonce, _)| nonce.to_owned())
            .expect("signature-input without nonce")
    }

    /// Refuses the opening with `status`, sent as a trailers-only response.
    pub(super) fn refuse(self, status: Status) {
        let _ = self.reply.send(Err(status));
    }

    pub(super) fn accept(self) -> ServerStream {
        let nonce = self.nonce();
        let (outbound, receiver) = mpsc::channel(16);
        let _ = self.reply.send(Ok(receiver));
        ServerStream {
            nonce,
            inbound: self.inbound,
            outbound,
            encoded: self.encoded,
        }
    }
}

/// The authority's side of an accepted stream.
pub(super) struct ServerStream {
    /// The nonce of the opening signature.
    pub(super) nonce: String,
    inbound: Streaming<AgentMessage>,
    outbound: mpsc::Sender<Result<ServerMessage, Status>>,
    /// Messages the test encoded itself, sent as they are.
    encoded: mpsc::UnboundedSender<Bytes>,
}

impl ServerStream {
    pub(super) async fn send(&self, id: &str, correlation_id: Option<&str>, payload: Payload) {
        self.send_message(ServerMessage {
            id: id.to_owned(),
            correlation_id: correlation_id.map(str::to_owned),
            payload: Some(payload),
        })
        .await;
    }

    /// Sends a message whose payload the client can't decode, as a payload added by a newer authority looks.
    pub(super) async fn send_unknown(&self, id: &str) {
        self.send_message(ServerMessage {
            id: id.to_owned(),
            correlation_id: None,
            payload: None,
        })
        .await;
    }

    async fn send_message(&self, message: ServerMessage) {
        self.outbound.send(Ok(message)).await.expect("stream closed");
    }

    /// Sends `message`, which the test encoded as protobuf itself, as one gRPC message ("Length-Prefixed-Message" in
    /// gRPC over HTTP2).
    pub(super) fn send_encoded(&self, message: &[u8]) {
        let length = u32::try_from(message.len()).expect("message shorter than 4 GiB");
        let mut frame = vec![0 /* Compressed-Flag */];
        frame.extend_from_slice(&length.to_be_bytes() /* Message-Length */);
        frame.extend_from_slice(message);
        self.encoded.send(Bytes::from(frame)).expect("stream closed");
    }

    /// Closes the stream with `status` in its trailers.
    pub(super) async fn close(self, status: Status) {
        self.outbound.send(Err(status)).await.expect("stream closed");
    }

    /// Waits for the client's next message.
    pub(super) async fn receive(&mut self) -> AgentMessage {
        tokio::time::timeout(WAIT, self.inbound.message())
            .await
            .expect("no client message arrived in time")
            .expect("client stream failed")
            .expect("client stream ended")
    }

    /// Returns the client's next message, end of stream or error if one arrives within `wait`.
    pub(super) async fn receive_within(&mut self, wait: Duration) -> Option<Result<Option<AgentMessage>, Status>> {
        tokio::time::timeout(wait, self.inbound.message()).await.ok()
    }

    /// Sends a `Challenge` and returns the challenge's envelope ID.
    pub(super) async fn challenge(&self, challenge: &[u8]) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        self.send(
            &id,
            None,
            Payload::Challenge(Challenge {
                challenge: challenge.to_vec(),
            }),
        )
        .await;
        id
    }

    /// Runs the handshake and returns the client's `Hello`.
    pub(super) async fn authenticate(&mut self) -> AgentMessage {
        self.challenge(&[7; 32]).await;
        let hello = self.receive().await;
        self.send(
            &uuid::Uuid::new_v4().to_string(),
            Some(&hello.id),
            Payload::Welcome(Welcome { server_time: None }),
        )
        .await;
        hello
    }
}

/// The request `:path` before the authority strips its URL path.
#[derive(Clone)]
struct OriginalPath(String);

/// Where a stream's handler queues the messages its test encodes itself.
#[derive(Clone)]
struct EncodedMessages(mpsc::UnboundedSender<Bytes>);

/// A response body that sends the messages a test encoded itself between the messages of the gRPC service.
struct WithEncodedMessages {
    body: tonic::body::BoxBody,
    encoded: mpsc::UnboundedReceiver<Bytes>,
}

impl hyper::body::Body for WithEncodedMessages {
    type Data = Bytes;
    type Error = Status;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        if let Poll::Ready(Some(message)) = self.encoded.poll_recv(cx) {
            return Poll::Ready(Some(Ok(Frame::data(message))));
        }
        Pin::new(&mut self.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.encoded.is_closed() && self.body.is_end_stream()
    }
}

struct Handler {
    openings: mpsc::UnboundedSender<Opening>,
}

#[tonic::async_trait]
impl AgentChannel for Handler {
    type ConnectStream = ReceiverStream<Result<ServerMessage, Status>>;

    async fn connect(
        &self,
        request: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        let path = request
            .extensions()
            .get::<OriginalPath>()
            .map(|path| path.0.clone())
            .unwrap_or_default();
        let encoded = request
            .extensions()
            .get::<EncodedMessages>()
            .map(|encoded| encoded.0.clone())
            .expect("a queue for encoded messages");
        let headers = request.metadata().clone().into_headers();
        let (reply, decision) = oneshot::channel();
        self.openings
            .send(Opening {
                path,
                headers,
                inbound: request.into_inner(),
                reply,
                encoded,
            })
            .map_err(|_| Status::internal("test ended"))?;
        let outbound = decision.await.map_err(|_| Status::internal("opening dropped"))??;
        Ok(Response::new(ReceiverStream::new(outbound)))
    }
}

/// Serves the authority's gRPC service, replacing the content type of its responses with `content_type` if any.
async fn serve_grpc<IO>(io: IO, grpc: AgentChannelServer<Handler>, content_type: Option<&'static str>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |mut request: http::Request<hyper::body::Incoming>| {
        let mut grpc = grpc.clone();
        async move {
            let path = request.uri().path().to_owned();
            if let Some(rpc_path) = path.strip_prefix(URL_PATH) {
                *request.uri_mut() = rpc_path.parse().expect("valid RPC path");
            }
            request.extensions_mut().insert(OriginalPath(path));
            let (encoded, encoded_messages) = mpsc::unbounded_channel();
            request.extensions_mut().insert(EncodedMessages(encoded));
            let mut response = grpc.call(request).await?;
            if let Some(content_type) = content_type {
                response
                    .headers_mut()
                    .insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static(content_type));
            }
            Ok::<_, Infallible>(response.map(|body| WithEncodedMessages {
                body,
                encoded: encoded_messages,
            }))
        }
    });
    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(io), service)
        .await;
}

async fn serve_page<IO>(io: IO, status: http::StatusCode, content_type: &'static str)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |_request: http::Request<hyper::body::Incoming>| async move {
        let response = http::Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, content_type)
            .body(tonic::body::empty_body())
            .expect("valid response");
        Ok::<_, Infallible>(response)
    });
    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(io), service)
        .await;
}

async fn answer_http1<IO>(mut io: IO)
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let _ = io
        .write_all(
            b"HTTP/1.1 404 Not Found\r\ncontent-type: text/html\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
        .await;
    let _ = io.shutdown().await;
}

/// Counts the HTTP/2 PING frames a client sends, by scanning the decrypted bytes it writes.
struct PingCounter<S> {
    inner: S,
    pings: Arc<AtomicUsize>,
    scan: FrameScan,
}

impl<S> PingCounter<S> {
    fn new(inner: S, pings: Arc<AtomicUsize>) -> Self {
        Self {
            inner,
            pings,
            scan: FrameScan {
                preface_left: 24, /* client connection preface */
                header: [0; 9],
                header_len: 0,
                payload_left: 0,
            },
        }
    }
}

struct FrameScan {
    preface_left: usize,
    header: [u8; 9],
    header_len: usize,
    payload_left: usize,
}

impl FrameScan {
    const PING: u8 = 0x6;
    const ACK: u8 = 0x1;

    fn feed(&mut self, mut bytes: &[u8], pings: &AtomicUsize) {
        while !bytes.is_empty() {
            let skip = if 0 < self.preface_left {
                &mut self.preface_left
            } else if 0 < self.payload_left {
                &mut self.payload_left
            } else {
                let taken = bytes.len().min(self.header.len() - self.header_len);
                self.header[self.header_len..self.header_len + taken].copy_from_slice(&bytes[..taken]);
                self.header_len += taken;
                bytes = &bytes[taken..];
                if self.header_len == self.header.len() {
                    let [len0, len1, len2, frame_type, flags, ..] = self.header;
                    if frame_type == Self::PING && flags & Self::ACK == 0 {
                        pings.fetch_add(1, Ordering::SeqCst);
                    }
                    self.payload_left = usize::from(len0) << 16 | usize::from(len1) << 8 | usize::from(len2);
                    self.header_len = 0;
                }
                continue;
            };
            let taken = bytes.len().min(*skip);
            *skip -= taken;
            bytes = &bytes[taken..];
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PingCounter<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let this = &mut *self;
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = result {
            this.scan.feed(&buf.filled()[before..], &this.pings);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PingCounter<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Reads a JSON test vector file shared with the authority implementations.
pub(super) fn vectors() -> anyhow::Result<serde_json::Value> {
    serde_json::from_str(include_str!("../../../../docs/agent-identity/test-vectors.json"))
        .context("parse test vectors")
}
