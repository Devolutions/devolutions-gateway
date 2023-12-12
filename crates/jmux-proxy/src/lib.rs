//! [Specification document](https://github.com/awakecoding/qmux/blob/protocol-update/SPEC.md)

#[macro_use]
extern crate tracing;

mod codec;
mod config;
mod id_allocator;

pub use self::config::{FilteringRule, JmuxConfig};
pub use jmux_proto::DestinationUrl;

use self::codec::JmuxCodec;
use self::id_allocator::IdAllocator;
use crate::codec::MAXIMUM_PACKET_SIZE_IN_BYTES;
use anyhow::Context as _;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use jmux_proto::{ChannelData, DistantChannelId, Header, LocalChannelId, Message, ReasonCode};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{Instrument as _, Span};

pub type ApiResponseSender = oneshot::Sender<JmuxApiResponse>;
pub type ApiResponseReceiver = oneshot::Receiver<JmuxApiResponse>;
pub type ApiRequestSender = mpsc::Sender<JmuxApiRequest>;
pub type ApiRequestReceiver = mpsc::Receiver<JmuxApiRequest>;

#[derive(Debug)]
pub enum JmuxApiRequest {
    OpenChannel {
        destination_url: DestinationUrl,
        api_response_tx: ApiResponseSender,
    },
    Start {
        id: LocalChannelId,
        stream: TcpStream,
        /// Leftover bytes to be sent to target
        leftover: Option<Bytes>,
    },
}

#[derive(Debug)]
pub enum JmuxApiResponse {
    Success {
        id: LocalChannelId,
    },
    Failure {
        id: LocalChannelId,
        reason_code: ReasonCode,
    },
}

pub struct JmuxProxy {
    cfg: JmuxConfig,
    api_request_rx: Option<ApiRequestReceiver>,
    jmux_reader: Box<dyn AsyncRead + Unpin + Send>,
    jmux_writer: Box<dyn AsyncWrite + Unpin + Send>,
}

impl JmuxProxy {
    pub fn new(
        jmux_reader: Box<dyn AsyncRead + Unpin + Send>,
        jmux_writer: Box<dyn AsyncWrite + Unpin + Send>,
    ) -> Self {
        Self {
            cfg: JmuxConfig::default(),
            api_request_rx: None,
            jmux_reader,
            jmux_writer,
        }
    }

    pub fn with_config(mut self, cfg: JmuxConfig) -> Self {
        self.cfg = cfg;
        self
    }

    pub fn with_requester_api(mut self, api_request_rx: ApiRequestReceiver) -> Self {
        self.api_request_rx = Some(api_request_rx);
        self
    }

    // TODO: consider using something like ChildTask<T> more widely in Devolutions Gateway
    pub fn spawn(self) -> JoinHandle<anyhow::Result<()>> {
        let fut = self.run();
        tokio::spawn(fut)
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let span = Span::current();
        run_proxy_impl(self, span.clone()).instrument(span).await
    }
}

async fn run_proxy_impl(proxy: JmuxProxy, span: Span) -> anyhow::Result<()> {
    let JmuxProxy {
        cfg,
        api_request_rx,
        jmux_reader,
        jmux_writer,
    } = proxy;

    let (msg_to_send_tx, msg_to_send_rx) = mpsc::unbounded_channel::<Message>();

    let jmux_stream = FramedRead::new(jmux_reader, JmuxCodec);
    let jmux_sink = FramedWrite::new(jmux_writer, JmuxCodec);

    let sender_task_handle = JmuxSenderTask {
        jmux_sink,
        msg_to_send_rx,
    }
    .spawn(span.clone());

    let api_request_rx = api_request_rx.unwrap_or_else(|| mpsc::channel(1).1);

    let scheduler_task_handle = JmuxSchedulerTask {
        cfg,
        jmux_stream,
        msg_to_send_tx,
        api_request_rx,
        parent_span: span,
    }
    .spawn();

    match tokio::try_join!(scheduler_task_handle.join(), sender_task_handle.join()).context("task join failed")? {
        (Ok(_), Err(e)) => debug!("Sender task failed: {}", e),
        (Err(e), Ok(_)) => debug!("Scheduler task failed: {}", e),
        (Err(scheduler_e), Err(sender_e)) => {
            // Usually, it's only of interest when both tasks are failed.
            anyhow::bail!("both scheduler and sender tasks failed: {} & {}", scheduler_e, sender_e)
        }
        (Ok(_), Ok(_)) => {}
    }

    Ok(())
}

// === implementation details === //

#[derive(PartialEq, Eq, Debug)]
enum JmuxChannelState {
    Streaming,
    Eof,
    Closed,
}

#[derive(Debug)]
struct JmuxChannelCtx {
    distant_id: DistantChannelId,
    distant_state: JmuxChannelState,

    local_id: LocalChannelId,
    local_state: JmuxChannelState,

    initial_window_size: u32,
    window_size_updated: Arc<Notify>,
    window_size: Arc<AtomicUsize>,

    maximum_packet_size: u16,

    span: Span,
}

struct JmuxCtx {
    id_allocator: IdAllocator<LocalChannelId>,
    channels: HashMap<LocalChannelId, JmuxChannelCtx>,
}

impl JmuxCtx {
    fn new() -> Self {
        Self {
            id_allocator: IdAllocator::<LocalChannelId>::new(),
            channels: HashMap::new(),
        }
    }

    fn allocate_id(&mut self) -> Option<LocalChannelId> {
        self.id_allocator.alloc()
    }

    fn register_channel(&mut self, channel: JmuxChannelCtx) -> anyhow::Result<()> {
        if let Some(replaced_channel) = self.channels.insert(channel.local_id, channel) {
            anyhow::bail!(
                "detected two streams with the same local ID {}",
                replaced_channel.local_id
            );
        };
        Ok(())
    }

    fn get_channel(&mut self, id: LocalChannelId) -> Option<&JmuxChannelCtx> {
        self.channels.get(&id)
    }

    fn get_channel_mut(&mut self, id: LocalChannelId) -> Option<&mut JmuxChannelCtx> {
        self.channels.get_mut(&id)
    }

    fn unregister(&mut self, id: LocalChannelId) {
        self.channels.remove(&id);
        self.id_allocator.free(id);
    }
}

type MessageReceiver = mpsc::UnboundedReceiver<Message>;
type MessageSender = mpsc::UnboundedSender<Message>;
type DataReceiver = mpsc::UnboundedReceiver<Vec<u8>>;
type DataSender = mpsc::UnboundedSender<Vec<u8>>;
type InternalMessageSender = mpsc::UnboundedSender<InternalMessage>;

#[derive(Debug)]
enum InternalMessage {
    Eof { id: LocalChannelId },
    StreamResolved { channel: JmuxChannelCtx, stream: TcpStream },
}

// === internal tasks === //

// ---------------------- //

struct JmuxSenderTask<T: AsyncWrite + Unpin + Send + 'static> {
    jmux_sink: FramedWrite<T, JmuxCodec>,
    msg_to_send_rx: MessageReceiver,
}

impl<T: AsyncWrite + Unpin + Send + 'static> JmuxSenderTask<T> {
    fn spawn(self, span: Span) -> ChildTask<anyhow::Result<()>> {
        let fut = self.run().instrument(span);
        ChildTask(tokio::spawn(fut))
    }

    #[instrument("sender", skip_all)]
    async fn run(self) -> anyhow::Result<()> {
        let Self {
            mut jmux_sink,
            mut msg_to_send_rx,
        } = self;

        while let Some(msg) = msg_to_send_rx.recv().await {
            trace!(?msg, "Send channel message");
            jmux_sink.feed(msg).await?;
            jmux_sink.flush().await?;
        }

        info!("Closing JMUX sender task...");

        Ok(())
    }
}

// ---------------------- //

struct JmuxSchedulerTask<T: AsyncRead + Unpin + Send + 'static> {
    cfg: JmuxConfig,
    jmux_stream: FramedRead<T, JmuxCodec>,
    msg_to_send_tx: MessageSender,
    api_request_rx: ApiRequestReceiver,
    parent_span: Span,
}

impl<T: AsyncRead + Unpin + Send + 'static> JmuxSchedulerTask<T> {
    fn spawn(self) -> ChildTask<anyhow::Result<()>> {
        let parent_span = self.parent_span.clone();
        let fut = scheduler_task_impl(self).instrument(parent_span);
        ChildTask(tokio::spawn(fut))
    }
}

#[instrument("scheduler", skip_all)]
async fn scheduler_task_impl<T: AsyncRead + Unpin + Send + 'static>(task: JmuxSchedulerTask<T>) -> anyhow::Result<()> {
    let JmuxSchedulerTask {
        cfg,
        mut jmux_stream,
        msg_to_send_tx,
        mut api_request_rx,
        parent_span,
    } = task;

    let mut jmux_ctx = JmuxCtx::new();
    let mut data_senders: HashMap<LocalChannelId, DataSender> = HashMap::new();
    let mut pending_channels: HashMap<LocalChannelId, (DestinationUrl, ApiResponseSender)> = HashMap::new();
    let (internal_msg_tx, mut internal_msg_rx) = mpsc::unbounded_channel::<InternalMessage>();

    // Safety net against poor AsyncRead trait implementations.
    const MAX_CONSECUTIVE_PIPE_FAILURES: u8 = 5;
    let mut nb_consecutive_pipe_failures = 0;

    loop {
        // NOTE: Current task is the "jmux scheduler" or "jmux orchestrator".
        // It handles the JMUX context and communicates with other tasks.
        // As such, it should process messages continuously and never wait during processing: no `await` keyword
        // must be seen inside this select block.
        // It's also expected to be resilient and `?` operator should be used only for
        // unrecoverable failures.

        tokio::select! {
            Some(request) = api_request_rx.recv() => {
                match request {
                    JmuxApiRequest::OpenChannel { destination_url, api_response_tx } => {
                        match jmux_ctx.allocate_id() {
                            Some(id) => {
                                trace!("Allocated local ID {}", id);
                                debug!("{} request {}", id, destination_url);
                                pending_channels.insert(id, (destination_url.clone(), api_response_tx));
                                msg_to_send_tx
                                    .send(Message::open(id, MAXIMUM_PACKET_SIZE_IN_BYTES as u16, destination_url))
                                    .context("couldn’t send CHANNEL OPEN message through mpsc channel")?;
                            }
                            None => warn!("Couldn’t allocate ID for API request: {}", destination_url),
                        }
                    }
                    JmuxApiRequest::Start { id, stream, leftover } => {
                        let channel = jmux_ctx.get_channel(id).with_context(|| format!("couldn’t find channel with id {id}"))?;

                        let (data_tx, data_rx) = mpsc::unbounded_channel::<Vec<u8>>();

                        if data_senders.insert(id, data_tx).is_some() {
                            anyhow::bail!("detected two streams with the same ID {}", id);
                        }

                        // Send leftover bytes if any
                        if let Some(leftover) = leftover {
                            if let Err(error) = msg_to_send_tx.send(Message::data(channel.distant_id, leftover.to_vec())) {
                                error!(%error, "Couldn't send leftover bytes");
                            }                               ;
                        }

                        let (reader, writer) = stream.into_split();

                        DataWriterTask {
                            writer,
                            data_rx,
                        }
                        .spawn(channel.span.clone())
                        .detach();

                        DataReaderTask {
                            reader,
                            local_id: channel.local_id,
                            distant_id: channel.distant_id,
                            window_size_updated: Arc::clone(&channel.window_size_updated),
                            window_size: Arc::clone(&channel.window_size),
                            maximum_packet_size: channel.maximum_packet_size,
                            msg_to_send_tx: msg_to_send_tx.clone(),
                            internal_msg_tx: internal_msg_tx.clone(),
                        }
                        .spawn(channel.span.clone())
                        .detach();
                    }
                }
            }
            Some(internal_msg) = internal_msg_rx.recv() => {
                match internal_msg {
                    InternalMessage::Eof { id } => {
                        let channel = jmux_ctx.get_channel_mut(id).with_context(|| format!("couldn’t find channel with id {id}"))?;
                        let channel_span = channel.span.clone();
                        let local_id = channel.local_id;
                        let distant_id = channel.distant_id;

                        match channel.distant_state {
                            JmuxChannelState::Streaming => {
                                channel.local_state = JmuxChannelState::Eof;
                                msg_to_send_tx
                                    .send(Message::eof(distant_id))
                                    .context("couldn’t send EOF message")?;
                            },
                            JmuxChannelState::Eof => {
                                channel.local_state = JmuxChannelState::Closed;
                                msg_to_send_tx
                                    .send(Message::close(distant_id))
                                    .context("couldn’t send CLOSE message")?;
                            },
                            JmuxChannelState::Closed => {
                                jmux_ctx.unregister(local_id);
                                msg_to_send_tx
                                    .send(Message::close(distant_id))
                                    .context("couldn’t send CLOSE message")?;
                                channel_span.in_scope(|| {
                                    debug!("Channel closed");
                                });
                            },
                        }
                    }
                    InternalMessage::StreamResolved {
                        channel, stream
                    } => {
                        let local_id = channel.local_id;
                        let distant_id = channel.distant_id;
                        let initial_window_size = channel.initial_window_size;
                        let maximum_packet_size = channel.maximum_packet_size;
                        let window_size_updated = Arc::clone(&channel.window_size_updated);
                        let window_size = Arc::clone(&channel.window_size);
                        let channel_span = channel.span.clone();

                        let (data_tx, data_rx) = mpsc::unbounded_channel::<Vec<u8>>();

                        if data_senders.insert(channel.local_id, data_tx).is_some() {
                            anyhow::bail!("detected two streams with the same local ID {}", channel.local_id);
                        };

                        jmux_ctx.register_channel(channel)?;

                        msg_to_send_tx
                            .send(Message::open_success(distant_id, local_id, initial_window_size, maximum_packet_size))
                            .context("couldn’t send OPEN SUCCESS message through mpsc channel")?;

                        channel_span.in_scope(|| {
                            debug!("Channel accepted");
                        });

                        let (reader, writer) = stream.into_split();

                        DataWriterTask {
                            writer,
                            data_rx,
                        }
                        .spawn(channel_span.clone())
                        .detach();

                        DataReaderTask {
                            reader,
                            local_id,
                            distant_id,
                            window_size_updated,
                            window_size,
                            maximum_packet_size,
                            msg_to_send_tx: msg_to_send_tx.clone(),
                            internal_msg_tx: internal_msg_tx.clone(),
                        }
                        .spawn(channel_span)
                        .detach();
                    }
                }
            }
            msg = jmux_stream.next() => {
                let msg = match msg {
                    Some(msg) => msg,
                    None => {
                        info!("JMUX pipe was closed by peer");
                        break;
                    }
                };

                let msg = match msg {
                    Ok(msg) => {
                        nb_consecutive_pipe_failures = 0;
                        msg
                    },
                    Err(error) => {
                        let really_an_error = is_really_an_error(&error);

                        let error = anyhow::Error::new(error);

                        if really_an_error {
                            error!(error = format!("{error:#}"), "JMUX pipe error");
                        } else {
                            info!(reason = format!("{error:#}"), "JMUX pipe closed abruptly");
                        }

                        nb_consecutive_pipe_failures += 1;
                        if nb_consecutive_pipe_failures > MAX_CONSECUTIVE_PIPE_FAILURES {
                            // Some underlying `AsyncRead` implementations might handle errors poorly
                            // and cause infinite polling on errors such as broken pipe (this should
                            // stop instead of returning the same error indefinitely).
                            // Hence, this safety net to escape from such infinite loops.
                            anyhow::bail!("forced JMUX proxy shutdown because of too many consecutive pipe failures");
                        } else {
                            continue;
                        }
                    }
                };

                trace!(?msg, "Received channel message");

                match msg {
                    Message::Open(msg) => {
                        let peer_id = DistantChannelId::from(msg.sender_channel_id);

                        if let Err(error) = cfg.filtering.validate_destination(&msg.destination_url) {
                            debug!(%error, %msg.destination_url, %peer_id, "Invalid destination requested");
                            msg_to_send_tx
                                .send(Message::open_failure(peer_id, ReasonCode::CONNECTION_NOT_ALLOWED_BY_RULESET, error.to_string()))
                                .context("couldn’t send OPEN FAILURE message through mpsc channel")?;
                            continue;
                        }

                        let local_id = match jmux_ctx.allocate_id() {
                            Some(id) => id,
                            None => {
                                warn!("Couldn’t allocate local ID for distant peer {}: no more ID available", peer_id);
                                msg_to_send_tx
                                    .send(Message::open_failure(peer_id, ReasonCode::GENERAL_FAILURE, "no more ID available"))
                                    .context("couldn’t send OPEN FAILURE message through mpsc channel")?;
                                continue;
                            }
                        };

                        trace!("Allocated ID {} for peer {}", local_id, peer_id);
                        info!("({} {}) request {}", local_id, peer_id, msg.destination_url);

                        let channel_span = info_span!(parent: parent_span.clone(), "channel", %local_id, %peer_id, url = %msg.destination_url);

                        let window_size_updated = Arc::new(Notify::new());
                        let window_size = Arc::new(AtomicUsize::new(usize::try_from(msg.initial_window_size).unwrap()));

                        let channel = JmuxChannelCtx {
                            distant_id: peer_id,
                            distant_state: JmuxChannelState::Streaming,

                            local_id,
                            local_state: JmuxChannelState::Streaming,

                            initial_window_size: msg.initial_window_size,
                            window_size_updated: window_size_updated.clone(),
                            window_size: window_size.clone(),

                            maximum_packet_size: msg.maximum_packet_size,

                            span: channel_span,
                        };

                        StreamResolverTask {
                            channel,
                            destination_url: msg.destination_url,
                            internal_msg_tx: internal_msg_tx.clone(),
                            msg_to_send_tx: msg_to_send_tx.clone(),
                        }
                        .spawn()
                        .detach();
                    }
                    Message::OpenSuccess(msg) => {
                        let local_id = LocalChannelId::from(msg.recipient_channel_id);
                        let peer_id = DistantChannelId::from(msg.sender_channel_id);

                        let (destination_url, api_response_tx) = match pending_channels.remove(&local_id) {
                            Some(pending) => pending,
                            None => {
                                warn!("Couldn’t find pending channel for {}", local_id);
                                continue;
                            },
                        };

                        let channel_span = info_span!(parent: parent_span.clone(), "channel", %local_id, %peer_id, url = %destination_url).entered();

                        trace!("Successfully opened channel");

                        if api_response_tx.send(JmuxApiResponse::Success { id: local_id }).is_err() {
                            warn!("Couldn’t send success API response through mpsc channel");
                            continue;
                        }

                        jmux_ctx.register_channel(JmuxChannelCtx {
                            distant_id: peer_id,
                            distant_state: JmuxChannelState::Streaming,

                            local_id,
                            local_state: JmuxChannelState::Streaming,

                            initial_window_size: msg.initial_window_size,
                            window_size_updated: Arc::new(Notify::new()),
                            window_size: Arc::new(AtomicUsize::new(usize::try_from(msg.initial_window_size).unwrap())),

                            maximum_packet_size: msg.maximum_packet_size,

                            span: channel_span.exit(),
                        })?;
                    }
                    Message::WindowAdjust(msg) => {
                        if let Some(ctx) = jmux_ctx.get_channel_mut(LocalChannelId::from(msg.recipient_channel_id)) {
                            ctx.window_size.fetch_add(usize::try_from(msg.window_adjustment).unwrap(), Ordering::SeqCst);
                            ctx.window_size_updated.notify_one();
                        }
                    }
                    Message::Data(msg) => {
                        let id = LocalChannelId::from(msg.recipient_channel_id);
                        let data_length = u32::try_from(msg.transfer_data.len()).unwrap();
                        let distant_id = match jmux_ctx.get_channel(id) {
                            Some(channel) => channel.distant_id,
                            None => {
                                warn!("Couldn’t find channel with id {}", id);
                                continue;
                            },
                        };

                        let data_tx = match data_senders.get_mut(&id) {
                            Some(sender) => sender,
                            None => {
                                warn!("Received data but associated data sender is missing");
                                continue;
                            }
                        };

                        let _ = data_tx.send(msg.transfer_data);

                        // Simplest flow control logic for now: just send back a WINDOW ADJUST message to
                        // increase back peer’s window size.
                        msg_to_send_tx.send(Message::window_adjust(distant_id, data_length))
                            .context("couldn’t send WINDOW ADJUST message")?;
                    }
                    Message::Eof(msg) => {
                        // Per the spec:
                        // > No explicit response is sent to this message.
                        // > However, the application may send EOF to whatever is at the other end of the channel.
                        // > Note that the channel remains open after this message, and more data may still be sent in the other direction.
                        // > This message does not consume window space and can be sent even if no window space is available.

                        let id = LocalChannelId::from(msg.recipient_channel_id);
                        let channel = match jmux_ctx.get_channel_mut(id) {
                            Some(channel) => channel,
                            None => {
                                warn!("Couldn’t find channel with id {}", id);
                                continue;
                            },
                        };

                        channel.distant_state = JmuxChannelState::Eof;
                        channel.span.in_scope(|| {
                            debug!("Distant peer EOFed");
                        });

                        // Remove associated data sender
                        data_senders.remove(&id);

                        match channel.local_state {
                            JmuxChannelState::Streaming => {},
                            JmuxChannelState::Eof => {
                                channel.local_state = JmuxChannelState::Closed;
                                msg_to_send_tx
                                    .send(Message::close(channel.distant_id))
                                    .context("couldn’t send CLOSE message")?;
                            },
                            JmuxChannelState::Closed => {},
                        }
                    }
                    Message::OpenFailure(msg) => {
                        let id = LocalChannelId::from(msg.recipient_channel_id);

                        let (destination_url, api_response_tx) = match pending_channels.remove(&id) {
                            Some(pending) => pending,
                            None => {
                                warn!("Couldn’t find pending channel {}", id);
                                continue;
                            },
                        };

                        warn!(local_id = %id, %destination_url, %msg.reason_code, "Channel opening failed: {}", msg.description);

                        let _ = api_response_tx.send(JmuxApiResponse::Failure { id, reason_code: msg.reason_code });
                    }
                    Message::Close(msg) => {
                        let local_id = LocalChannelId::from(msg.recipient_channel_id);
                        let channel = match jmux_ctx.get_channel_mut(local_id) {
                            Some(channel) => channel,
                            None => {
                                warn!("Couldn’t find channel with id {}", local_id);
                                continue;
                            },
                        };
                        let distant_id = channel.distant_id;
                        let channel_span = channel.span.clone();
                        let _enter = channel_span.enter();

                        channel.distant_state = JmuxChannelState::Closed;
                        debug!("Distant peer closed");

                        // This will also shutdown the associated TCP stream.
                        data_senders.remove(&local_id);

                        if channel.local_state == JmuxChannelState::Eof {
                            channel.local_state = JmuxChannelState::Closed;
                            msg_to_send_tx
                                .send(Message::close(distant_id))
                                .context("couldn’t send CLOSE message")?;
                        }

                        if channel.local_state == JmuxChannelState::Closed {
                            jmux_ctx.unregister(local_id);
                            trace!("Channel closed");
                        }
                    }
                }
            }
        }
    }

    info!("Closing JMUX scheduler task...");

    Ok(())
}

// ---------------------- //

struct DataReaderTask {
    reader: OwnedReadHalf,
    local_id: LocalChannelId,
    distant_id: DistantChannelId,
    window_size_updated: Arc<Notify>,
    window_size: Arc<AtomicUsize>,
    maximum_packet_size: u16,
    msg_to_send_tx: MessageSender,
    internal_msg_tx: InternalMessageSender,
}

impl DataReaderTask {
    fn spawn(self, span: Span) -> ChildTask<()> {
        let handle = tokio::spawn(
            async move {
                if let Err(error) = self.run().await {
                    debug!(%error, "Reader task failed");
                }
            }
            .instrument(span),
        );
        ChildTask(handle)
    }

    async fn run(self) -> anyhow::Result<()> {
        let Self {
            reader,
            local_id,
            distant_id,
            window_size_updated,
            window_size,
            maximum_packet_size,
            msg_to_send_tx,
            internal_msg_tx,
        } = self;

        let codec = tokio_util::codec::BytesCodec::new();
        let mut bytes_stream = FramedRead::new(reader, codec);
        let maximum_packet_size = usize::try_from(maximum_packet_size).unwrap();

        trace!("Started forwarding");

        while let Some(bytes) = bytes_stream.next().await {
            let bytes = match bytes {
                Ok(bytes) => bytes,
                Err(error) if is_really_an_error(&error) => {
                    return Err(anyhow::Error::new(error).context("couldn’t read next bytes from stream"))
                }
                Err(error) => {
                    debug!(%error, "Couldn’t read next bytes from stream (not really an error)");
                    break;
                }
            };

            let chunk_size = maximum_packet_size - Header::SIZE - ChannelData::FIXED_PART_SIZE;

            let queue: Vec<Vec<u8>> = bytes.chunks(chunk_size).map(|slice| slice.to_vec()).collect();

            for mut bytes in queue {
                loop {
                    let window_size_now = window_size.load(Ordering::SeqCst);
                    if window_size_now < bytes.len() {
                        trace!(
                            window_size_now,
                            full_packet_size = bytes.len(),
                            "Window size insufficient to send full packet. Truncate and wait."
                        );

                        if window_size_now > 0 {
                            let bytes_to_send_now: Vec<u8> = bytes.drain(..window_size_now).collect();
                            window_size.fetch_sub(bytes_to_send_now.len(), Ordering::SeqCst);
                            msg_to_send_tx
                                .send(Message::data(distant_id, bytes_to_send_now))
                                .context("couldn’t send DATA message")?;
                        }

                        window_size_updated.notified().await;
                    } else {
                        window_size.fetch_sub(bytes.len(), Ordering::SeqCst);
                        msg_to_send_tx
                            .send(Message::data(distant_id, bytes))
                            .context("couldn’t send DATA message")?;
                        break;
                    }
                }
            }
        }

        trace!("Finished forwarding (EOF)");

        // Attempt to send the EOF message to the JMUX peer.
        // When the JMUX pipe is closed, it is common for the internal channel receiver to have already been dropped and closed.
        // Therefore, we ignore the "SendError" returned by `send`.
        let _ = internal_msg_tx.send(InternalMessage::Eof { id: local_id });

        Ok(())
    }
}

// ---------------------- //

struct DataWriterTask {
    writer: OwnedWriteHalf,
    data_rx: DataReceiver,
}

impl DataWriterTask {
    fn spawn(self, span: Span) -> ChildTask<()> {
        let Self {
            mut writer,
            mut data_rx,
        } = self;

        let handle = tokio::spawn(
            async move {
                while let Some(data) = data_rx.recv().await {
                    if let Err(error) = writer.write_all(&data).await {
                        warn!(%error, "Writer task failed");
                        break;
                    }
                }
            }
            .instrument(span),
        );

        ChildTask(handle)
    }
}

// ---------------------- //

struct StreamResolverTask {
    channel: JmuxChannelCtx,
    destination_url: DestinationUrl,
    internal_msg_tx: InternalMessageSender,
    msg_to_send_tx: MessageSender,
}

impl StreamResolverTask {
    fn spawn(self) -> ChildTask<()> {
        let span = self.channel.span.clone();

        let handle = tokio::spawn(
            async move {
                if let Err(error) = self.run().await {
                    warn!(%error, "Resolver task failed");
                }
            }
            .instrument(span),
        );

        ChildTask(handle)
    }

    async fn run(self) -> anyhow::Result<()> {
        let Self {
            channel,
            destination_url,
            internal_msg_tx,
            msg_to_send_tx,
        } = self;

        let scheme = destination_url.scheme();
        let host = destination_url.host();
        let port = destination_url.port();

        match scheme {
            "tcp" => match TcpStream::connect((host, port)).await {
                Ok(stream) => {
                    internal_msg_tx
                        .send(InternalMessage::StreamResolved { channel, stream })
                        .context("could't send back resolved stream through internal mpsc channel")?;
                }
                Err(error) => {
                    debug!(?error, "TcpStream::connect failed");
                    msg_to_send_tx
                        .send(Message::open_failure(
                            channel.distant_id,
                            ReasonCode::from(error.kind()),
                            error.to_string(),
                        ))
                        .context("couldn’t send OPEN FAILURE message through mpsc channel")?;
                    anyhow::bail!("couldn’t open TCP stream to {}:{}: {}", host, port, error);
                }
            },
            _ => anyhow::bail!("unsupported scheme: {}", scheme),
        }

        Ok(())
    }
}

/// Aborts the running task when dropped.
/// Also see https://github.com/tokio-rs/tokio/issues/1830 for some background.
#[must_use]
struct ChildTask<T>(JoinHandle<T>);

impl<T> ChildTask<T> {
    async fn join(mut self) -> Result<T, tokio::task::JoinError> {
        (&mut self.0).await
    }

    fn abort(&self) {
        self.0.abort()
    }

    fn detach(self) {
        core::mem::forget(self);
    }
}

impl<T> Drop for ChildTask<T> {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Walks source chain and check for status codes like ECONNRESET or ECONNABORTED that we don’t consider to be actual errors
fn is_really_an_error(original_error: &(dyn std::error::Error + 'static)) -> bool {
    let mut dyn_error: Option<&dyn std::error::Error> = Some(original_error);

    while let Some(source_error) = dyn_error.take() {
        if let Some(io_error) = source_error.downcast_ref::<io::Error>() {
            match io_error.kind() {
                io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionAborted => {
                    return false;
                }
                _ => {}
            }
        }

        dyn_error = source_error.source();
    }

    true
}
