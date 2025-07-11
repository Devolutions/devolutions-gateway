//! [Specification document][source]
//!
//! [source]: https://github.com/Devolutions/devolutions-gateway/blob/master/docs/JMUX-spec.md

#[macro_use]
extern crate tracing;

mod codec;
mod config;
mod id_allocator;

pub use self::config::{FilteringRule, JmuxConfig};
pub use jmux_proto::DestinationUrl;

use self::codec::JmuxCodec;
use self::id_allocator::IdAllocator;
use anyhow::Context as _;
use bytes::Bytes;
use jmux_proto::{ChannelData, DistantChannelId, Header, LocalChannelId, Message, ReasonCode};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::codec::FramedRead;
use tracing::{Instrument as _, Span};

const MAXIMUM_PACKET_SIZE_IN_BYTES: u16 = 4 * 1024; // 4 kiB
const WINDOW_ADJUSTMENT_THRESHOLD: u32 = 4 * 1024; // 4 kiB

// The JMUX channel will require at most `MAXIMUM_PACKET_SIZE_IN_BYTES × JMUX_MESSAGE_CHANNEL_SIZE` bytes to be kept alive.
const JMUX_MESSAGE_MPSC_CHANNEL_SIZE: usize = 512;
const CHANNEL_DATA_MPSC_CHANNEL_SIZE: usize = 256;
const INTERNAL_MPSC_CHANNEL_SIZE: usize = 32;

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
    #[must_use]
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

    #[must_use]
    pub fn with_config(mut self, cfg: JmuxConfig) -> Self {
        self.cfg = cfg;
        self
    }

    #[must_use]
    pub fn with_requester_api(mut self, api_request_rx: ApiRequestReceiver) -> Self {
        self.api_request_rx = Some(api_request_rx);
        self
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

    let (msg_to_send_tx, msg_to_send_rx) = mpsc::channel::<Message>(JMUX_MESSAGE_MPSC_CHANNEL_SIZE);

    let jmux_stream = FramedRead::new(jmux_reader, JmuxCodec);

    let sender_task_handle = JmuxSenderTask {
        jmux_writer,
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
        (Ok(_), Err(e)) => debug!("Sender task failed: {e:#}"),
        (Err(e), Ok(_)) => debug!("Scheduler task failed: {e:#}"),
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
    remote_window_size: u32,

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

type MessageReceiver = mpsc::Receiver<Message>;
type MessageSender = mpsc::Sender<Message>;
type DataReceiver = mpsc::Receiver<Bytes>;
type DataSender = mpsc::Sender<Bytes>;
type InternalMessageSender = mpsc::Sender<InternalMessage>;

#[derive(Debug)]
enum InternalMessage {
    Eof { id: LocalChannelId },
    StreamResolved { channel: JmuxChannelCtx, stream: TcpStream },
}

// === internal tasks === //

// ---------------------- //

struct JmuxSenderTask<T: AsyncWrite + Unpin + Send + 'static> {
    jmux_writer: T,
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
            jmux_writer,
            mut msg_to_send_rx,
        } = self;

        let mut jmux_writer = tokio::io::BufWriter::with_capacity(16 * 1024, jmux_writer);
        let mut buf = bytes::BytesMut::new();
        let mut needs_flush = false;

        loop {
            tokio::select! {
                msg = msg_to_send_rx.recv() => {
                    let Some(msg) = msg else {
                        break;
                    };

                    trace!(?msg, "Send channel message");

                    buf.clear();
                    msg.encode(&mut buf)?;

                    jmux_writer.write_all(&buf).await?;
                    needs_flush = true;
                }
                _ = tokio::time::sleep(core::time::Duration::from_millis(10)), if needs_flush => {
                    jmux_writer.flush().await?;
                    needs_flush = false;
                }
            }
        }

        info!("Closing JMUX sender task...");

        jmux_writer.flush().await?;

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
    use futures_util::StreamExt as _;

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
    let mut needs_window_adjustment: HashSet<LocalChannelId> = HashSet::new();
    let (internal_msg_tx, mut internal_msg_rx) = mpsc::channel::<InternalMessage>(INTERNAL_MPSC_CHANNEL_SIZE);

    // Safety net against poor AsyncRead trait implementations.
    const MAX_CONSECUTIVE_PIPE_FAILURES: u8 = 5;
    let mut nb_consecutive_pipe_failures = 0;

    loop {
        // NOTE: Current task is the "jmux scheduler" or "jmux orchestrator".
        // It handles the JMUX context and communicates with other tasks.
        // As such, it should process messages continuously and never `await` for long-running tasks during processing inside the select block.
        // It’s okay to use the `await` keyword on mpsc channels for backpressure: those will typically return immediately, and
        // when they do not, it means that the JMUX proxy is already under very high load as the subtasks are not able to follow.
        // It's also expected to be resilient and `?` operator should be used only for unrecoverable failures.

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
                                    .send(Message::open(id, MAXIMUM_PACKET_SIZE_IN_BYTES, destination_url))
                                    .await
                                    .context("couldn’t send CHANNEL OPEN message through mpsc channel")?;
                            }
                            None => warn!("Couldn’t allocate ID for API request: {}", destination_url),
                        }
                    }
                    JmuxApiRequest::Start { id, stream, leftover } => {
                        let channel = jmux_ctx.get_channel(id).with_context(|| format!("couldn’t find channel with id {id}"))?;

                        let (data_tx, data_rx) = mpsc::channel::<Bytes>(CHANNEL_DATA_MPSC_CHANNEL_SIZE);

                        if data_senders.insert(id, data_tx).is_some() {
                            anyhow::bail!("detected two streams with the same ID {}", id);
                        }

                        // Send leftover bytes if any.
                        if let Some(leftover) = leftover {
                            if let Err(error) = msg_to_send_tx.send(Message::data(channel.distant_id, leftover)).await {
                                error!(%error, "Couldn't send leftover bytes");
                            }
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
                                    .await
                                    .context("couldn’t send EOF message")?;
                            },
                            JmuxChannelState::Eof => {
                                channel.local_state = JmuxChannelState::Closed;
                                msg_to_send_tx
                                    .send(Message::close(distant_id))
                                    .await
                                    .context("couldn’t send CLOSE message")?;
                            },
                            JmuxChannelState::Closed => {
                                jmux_ctx.unregister(local_id);
                                msg_to_send_tx
                                    .send(Message::close(distant_id))
                                    .await
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

                        let (data_tx, data_rx) = mpsc::channel::<Bytes>(CHANNEL_DATA_MPSC_CHANNEL_SIZE);

                        if data_senders.insert(channel.local_id, data_tx).is_some() {
                            anyhow::bail!("detected two streams with the same local ID {}", channel.local_id);
                        };

                        jmux_ctx.register_channel(channel)?;

                        msg_to_send_tx
                            .send(Message::open_success(distant_id, local_id, initial_window_size, maximum_packet_size))
                            .await
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
                            // Some underlying `AsyncRead` implementations might handle errors poorly and cause infinite polling on errors such as broken pipe.
                            // (This should stop instead of returning the same error indefinitely.)
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
                            debug!(error = format!("{error:#}"), %msg.destination_url, %peer_id, "Invalid destination requested");
                            msg_to_send_tx
                                .send(Message::open_failure(peer_id, ReasonCode::CONNECTION_NOT_ALLOWED_BY_RULESET, error.to_string()))
                                .await
                                .context("couldn’t send OPEN FAILURE message through mpsc channel")?;
                            continue;
                        }

                        let local_id = match jmux_ctx.allocate_id() {
                            Some(id) => id,
                            None => {
                                warn!("Couldn’t allocate local ID for distant peer {}: no more ID available", peer_id);
                                msg_to_send_tx
                                    .send(Message::open_failure(peer_id, ReasonCode::GENERAL_FAILURE, "no more ID available"))
                                    .await
                                    .context("couldn’t send OPEN FAILURE message through mpsc channel")?;
                                continue;
                            }
                        };

                        trace!("Allocated ID {} for peer {}", local_id, peer_id);
                        info!("({} {}) request {}", local_id, peer_id, msg.destination_url);

                        let channel_span = info_span!(parent: parent_span.clone(), "channel", %local_id, %peer_id, url = %msg.destination_url);

                        let window_size_updated = Arc::new(Notify::new());
                        let window_size = Arc::new(AtomicUsize::new(usize::try_from(msg.initial_window_size).expect("usize-to-u32")));

                        let channel = JmuxChannelCtx {
                            distant_id: peer_id,
                            distant_state: JmuxChannelState::Streaming,

                            local_id,
                            local_state: JmuxChannelState::Streaming,

                            initial_window_size: msg.initial_window_size,
                            window_size_updated: Arc::clone(&window_size_updated),
                            window_size: Arc::clone(&window_size),
                            remote_window_size: msg.initial_window_size,

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

                        let Some((destination_url, api_response_tx)) = pending_channels.remove(&local_id) else {
                            warn!(channel.id = %local_id, "Couldn’t find pending channel");
                            continue;
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
                            window_size: Arc::new(AtomicUsize::new(usize::try_from(msg.initial_window_size).expect("u32-to-usize"))),
                            remote_window_size: msg.initial_window_size,

                            maximum_packet_size: msg.maximum_packet_size,

                            span: channel_span.exit(),
                        })?;
                    }
                    Message::WindowAdjust(msg) => {
                        let id = LocalChannelId::from(msg.recipient_channel_id);
                        let Some(channel) = jmux_ctx.get_channel_mut(id) else {
                            warn!(channel.id = %id, "Couldn’t find channel");
                            continue;
                        };

                        channel.window_size.fetch_add(usize::try_from(msg.window_adjustment).expect("u32-to-usize"), Ordering::SeqCst);
                        channel.window_size_updated.notify_one();
                    }
                    Message::Data(msg) => {
                        let id = LocalChannelId::from(msg.recipient_channel_id);
                        let Some(channel) = jmux_ctx.get_channel_mut(id) else {
                            warn!(channel.id = %id, "Couldn’t find channel");
                            continue;
                        };

                        let payload_size = u32::try_from(msg.transfer_data.len()).expect("packet length is found by decoding a u16 in decoder");
                        channel.remote_window_size = channel.remote_window_size.saturating_sub(payload_size);

                        let packet_size = Header::SIZE + msg.size();
                        if usize::from(channel.maximum_packet_size) < packet_size {
                            channel.span.in_scope(|| {
                                warn!(packet_size, "Packet's size is exceeding the maximum size for this channel and was dropped");
                            });
                            continue;
                        }

                        let Some(data_tx) = data_senders.get_mut(&id) else {
                            channel.span.in_scope(|| {
                                warn!("Received data but associated data sender is missing");
                            });
                            continue;
                        };

                        let _ = data_tx.send(msg.transfer_data).await;

                        needs_window_adjustment.insert(id);
                    }
                    Message::Eof(msg) => {
                        // Per the spec:
                        // > No explicit response is sent to this message.
                        // > However, the application may send EOF to whatever is at the other end of the channel.
                        // > Note that the channel remains open after this message, and more data may still be sent in the other direction.
                        // > This message does not consume window space and can be sent even if no window space is available.

                        let id = LocalChannelId::from(msg.recipient_channel_id);
                        let Some(channel) = jmux_ctx.get_channel_mut(id) else {
                            warn!(channel.id = %id, "Couldn’t find channel");
                            continue;
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
                                    .await
                                    .context("couldn’t send CLOSE message")?;
                            },
                            JmuxChannelState::Closed => {},
                        }
                    }
                    Message::OpenFailure(msg) => {
                        let id = LocalChannelId::from(msg.recipient_channel_id);

                        let Some((destination_url, api_response_tx)) = pending_channels.remove(&id) else {
                            warn!(channel.id = %id, "Couldn’t find pending channel");
                            continue;
                        };

                        warn!(local_id = %id, %destination_url, %msg.reason_code, "Channel opening failed: {}", msg.description);

                        let _ = api_response_tx.send(JmuxApiResponse::Failure { id, reason_code: msg.reason_code });
                    }
                    Message::Close(msg) => {
                        let local_id = LocalChannelId::from(msg.recipient_channel_id);
                        let Some(channel) = jmux_ctx.get_channel_mut(local_id) else {
                            warn!(channel.id = %local_id, "Couldn’t find channel");
                            continue;
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
                                .await
                                .context("couldn’t send CLOSE message")?;
                        }

                        if channel.local_state == JmuxChannelState::Closed {
                            jmux_ctx.unregister(local_id);
                            trace!("Channel closed");
                        }
                    }
                }
            }
            _ = core::future::ready(()), if !needs_window_adjustment.is_empty() => {
                for channel_id in needs_window_adjustment.drain() {
                    let Some(channel) = jmux_ctx.get_channel_mut(channel_id) else {
                        continue;
                    };

                    let window_adjustment = channel.initial_window_size - channel.remote_window_size;

                    if window_adjustment > WINDOW_ADJUSTMENT_THRESHOLD {
                        msg_to_send_tx
                            .send(Message::window_adjust(channel.distant_id, window_adjustment))
                            .await
                            .context("couldn’t send WINDOW ADJUST message")?;

                        channel.remote_window_size = channel.initial_window_size;
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
                    debug!(error = format!("{error:#}"), "Reader task failed");
                }
            }
            .instrument(span),
        );
        ChildTask(handle)
    }

    async fn run(self) -> anyhow::Result<()> {
        use futures_util::StreamExt as _;

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
        let maximum_packet_size = usize::from(maximum_packet_size);

        trace!("Started forwarding");

        while let Some(bytes) = bytes_stream.next().await {
            let mut bytes = match bytes {
                Ok(bytes) => bytes,
                Err(error) if is_really_an_error(&error) => {
                    return Err(anyhow::Error::new(error).context("couldn’t read next bytes from stream"));
                }
                Err(error) => {
                    debug!(%error, "Couldn’t read next bytes from stream (not really an error)");
                    break;
                }
            };

            let chunk_size = maximum_packet_size - Header::SIZE - ChannelData::FIXED_PART_SIZE;

            while !bytes.is_empty() {
                let split_at = core::cmp::min(chunk_size, bytes.len());
                let mut chunk = bytes.split_to(split_at);

                loop {
                    let window_size_now = window_size.load(Ordering::SeqCst);

                    if window_size_now < chunk.len() {
                        debug!(
                            window_size_now,
                            chunk_length = chunk.len(),
                            "Window size insufficient to send full chunk; truncate and wait"
                        );

                        if window_size_now > 0 {
                            let to_send_now = chunk.split_to(window_size_now);
                            window_size.fetch_sub(to_send_now.len(), Ordering::SeqCst);
                            msg_to_send_tx
                                .send(Message::data(distant_id, to_send_now.freeze()))
                                .await
                                .context("couldn’t send DATA message")?;
                        }

                        window_size_updated.notified().await;
                    } else {
                        window_size.fetch_sub(chunk.len(), Ordering::SeqCst);
                        msg_to_send_tx
                            .send(Message::data(distant_id, chunk.freeze()))
                            .await
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
        let _ = internal_msg_tx.send(InternalMessage::Eof { id: local_id }).await;

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
                    warn!(error = format!("{error:#}"), "Resolver task failed");
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
                        .await
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
                        .await
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
