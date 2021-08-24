//! [Specification document](https://github.com/awakecoding/qmux/blob/protocol-update/SPEC.md)

pub mod listener;

mod codec;
mod id;
mod proto;

use self::codec::JmuxCodec;
use self::id::{DistantChannelId, IdAllocator, LocalChannelId};
use self::proto::{Message, ReasonCode};
use crate::pipe::PipeMode;
use crate::proxy::ProxyConfig;
use anyhow::Context as _;
use futures_util::{SinkExt, StreamExt};
use slog::{debug, error, info, o, trace, warn, Logger};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::Notify;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug)]
pub enum JmuxApiRequest {
    OpenChannel {
        stream: TcpStream,
        addr: SocketAddr,
        destination_url: String,
        api_response_sender: UnboundedSender<JmuxApiResponse>,
    },
    Eof {
        // FIXME: only used internally
        id: LocalChannelId,
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

pub async fn start_proxy(
    api_request_sender: UnboundedSender<JmuxApiRequest>,
    api_request_receiver: UnboundedReceiver<JmuxApiRequest>,
    pipe_mode: PipeMode,
    proxy_cfg: Option<ProxyConfig>,
    log: Logger,
) -> anyhow::Result<()> {
    use crate::pipe::open_pipe;

    let (jmux_msg_to_send_sender, jmux_msg_to_send_receiver) = mpsc::unbounded_channel::<Message>();

    // Open generic pipe to exchange JMUX channel messages on
    let pipe_log = log.new(o!("open pipe" => "JMUX pipe"));
    let pipe = open_pipe(pipe_mode, proxy_cfg, pipe_log).await?;
    let jmux_msg_stream = FramedRead::new(pipe.read, JmuxCodec);
    let jmux_msg_sink = FramedWrite::new(pipe.write, JmuxCodec);
    let _handle = pipe._handle;

    // JMUX pipe sender task
    let sender_log = log.new(o!("JMUX" => "sender"));
    let sender_task_handle =
        tokio::spawn(async move { jmux_sender_task(jmux_msg_sink, jmux_msg_to_send_receiver, sender_log).await });

    // JMUX pipe receiver task
    let receiver_log = log.new(o!("JMUX" => "receiver"));
    let receiver_task_fut = jmux_receiver_task(
        jmux_msg_stream,
        jmux_msg_to_send_sender,
        api_request_sender,
        api_request_receiver,
        receiver_log,
    );

    tokio::select! {
        receiver_task_result = receiver_task_fut => {
            receiver_task_result.context("Receiver task failed")?;
            info!(log, "Receiver task ended first.");
        }
        sender_task_result = sender_task_handle => {
            sender_task_result.context("Couldn’t join on sender task")?.context("Sender task failed")?;
            info!(log, "Sender task ended first.");
        }
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

struct JmuxChannelCtx {
    distant_id: DistantChannelId,
    distant_state: JmuxChannelState,

    local_id: LocalChannelId,
    local_state: JmuxChannelState,

    window_size_updated: Arc<Notify>,
    window_size: Arc<AtomicUsize>,
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
                "Detected two streams with the same local ID {}",
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

async fn jmux_sender_task<T: AsyncWrite + Unpin>(
    mut jmux_msg_sink: FramedWrite<T, JmuxCodec>,
    mut jmux_msg_to_send_receiver: UnboundedReceiver<Message>,
    log: Logger,
) -> anyhow::Result<()> {
    while let Some(jmux_msg) = jmux_msg_to_send_receiver.recv().await {
        jmux_msg_sink.feed(jmux_msg).await?;
        jmux_msg_sink.flush().await?;
    }

    info!(log, "Closing JMUX sender task...");

    Ok(())
}

async fn jmux_receiver_task<T: AsyncRead + Unpin>(
    mut jmux_msg_stream: FramedRead<T, JmuxCodec>,
    jmux_msg_to_send_sender: UnboundedSender<Message>,
    api_request_sender: UnboundedSender<JmuxApiRequest>,
    mut api_request_receiver: UnboundedReceiver<JmuxApiRequest>,
    log: Logger,
) -> anyhow::Result<()> {
    let mut jmux_ctx = JmuxCtx::new();
    let mut writers: HashMap<LocalChannelId, OwnedWriteHalf> = HashMap::new();
    let mut pending_channels: HashMap<LocalChannelId, (OwnedReadHalf, UnboundedSender<JmuxApiResponse>)> =
        HashMap::new();

    // TODO: use channel log context when possible

    loop {
        tokio::select! {
            request_opt = api_request_receiver.recv() => {
                let request = match request_opt {
                    Some(request) => request,
                    None => {
                        warn!(log, "Ran out of requesters");
                        break;
                    }
                };

                match request {
                    JmuxApiRequest::OpenChannel { stream, addr, destination_url, api_response_sender } => {
                        info!(log, "New stream from {} requesting {}", addr, destination_url);

                        let (reader, writer) = stream.into_split();
                        match jmux_ctx.allocate_id() {
                            Some(id) => {
                                if writers.insert(id, writer).is_some() {
                                    anyhow::bail!("Detected two streams with the same ID {}", id);
                                }
                                info!(log, "Allocated ID {} for {}", id, addr);

                                pending_channels.insert(id, (reader, api_response_sender));

                                jmux_msg_to_send_sender
                                    .send(Message::open(id, destination_url.clone()))
                                    .context("Couldn’t send CHANNEL OPEN message through mpsc channel")?;
                            }
                            None => warn!(log, "Couldn’t allocate ID for {}", addr),
                        }
                    }
                    JmuxApiRequest::Eof { id } => {
                        let channel = jmux_ctx.get_channel_mut(id).with_context(|| format!("Couldn’t find channel with id {}", id))?;
                        let local_id = channel.local_id;
                        let distant_id = channel.distant_id;

                        match channel.distant_state {
                            JmuxChannelState::Streaming => {
                                channel.local_state = JmuxChannelState::Eof;
                                jmux_msg_to_send_sender
                                    .send(Message::eof(distant_id))
                                    .context("Couldn’t send EOF message")?;
                            },
                            JmuxChannelState::Eof => {
                                channel.local_state = JmuxChannelState::Closed;
                                jmux_msg_to_send_sender
                                    .send(Message::close(distant_id))
                                    .context("Couldn’t send CLOSE message")?;
                            },
                            JmuxChannelState::Closed => {
                                jmux_ctx.unregister(local_id);
                                jmux_msg_to_send_sender
                                    .send(Message::close(distant_id))
                                    .context("Couldn’t send CLOSE message")?;
                                info!(log, "Closed channel ({} {})", local_id, distant_id);
                            },
                        }
                    }
                }
            }
            jmux_msg_result = jmux_msg_stream.next() => {
                let channel_msg_result = match jmux_msg_result {
                    Some(channel_msg_result) => channel_msg_result,
                    None => {
                        info!(log, "JMUX pipe was closed by peer");
                        break;
                    }
                };

                let channel_msg = match channel_msg_result {
                    Ok(channel_msg) => channel_msg,
                    Err(e) => {
                        error!(log, "JMUX pipe error: {:?}", e);
                        continue;
                    }
                };

                trace!(log, "Received channel message: {:?}", channel_msg);

                match channel_msg {
                    Message::Open(msg) => {
                        let peer_id = DistantChannelId::from(msg.sender_channel_id);

                        let local_id = match jmux_ctx.allocate_id() {
                            Some(id) => id,
                            None => {
                                warn!(log, "Couldn’t allocate local ID for distant peer {}: no more ID available", peer_id);
                                jmux_msg_to_send_sender
                                    .send(Message::open_failure(peer_id, ReasonCode::GENERAL_FAILURE, "no more ID available"))
                                    .context("Couldn’t send OPEN FAILURE message through mpsc channel")?;
                                continue;
                            }
                        };
                        info!(log, "Allocated ID {} for peer {}", local_id, peer_id);

                        // FIXME: move lookup / connect section into a dedicated task

                        let mut addrs = match tokio::net::lookup_host(&msg.destination_url).await {
                            Ok(addrs) => addrs,
                            Err(e) => {
                                warn!(log, "Couldn’t resolve host {}: {}", msg.destination_url, e);
                                jmux_msg_to_send_sender
                                    .send(Message::open_failure(peer_id, ReasonCode::HOST_UNREACHABLE, "couldn’t resolve host"))
                                    .context("Couldn’t send OPEN FAILURE message through mpsc channel")?;
                                continue;
                            }
                        };
                        let socket_addr = addrs.next().expect("at least one resolved address should be present");

                        let (reader, writer) = match TcpStream::connect(socket_addr).await {
                            Ok(tcp_connection) => tcp_connection.into_split(),
                            Err(e) => {
                                warn!(log, "Couldn’t connect TCP socket to {}: {}", msg.destination_url, e);
                                jmux_msg_to_send_sender.send(Message::open_failure(
                                    peer_id,
                                    error_kind_to_reason_code(e.kind()),
                                    e.to_string(),
                                )).context("Couldn’t send OPEN FAILURE message through mpsc channel")?;
                                continue;
                            }
                        };

                        if writers.insert(local_id, writer).is_some() {
                            anyhow::bail!("Detected two streams with the same local ID {}", local_id);
                        };

                        let window_size_updated = Arc::new(Notify::new());
                        let window_size = Arc::new(AtomicUsize::new(usize::try_from(msg.initial_window_size).unwrap()));
                        let maximum_packet_size = msg.maximum_packet_size;

                        jmux_ctx.register_channel(JmuxChannelCtx {
                            distant_id: peer_id,
                            distant_state: JmuxChannelState::Streaming,

                            local_id,
                            local_state: JmuxChannelState::Streaming,

                            window_size_updated: window_size_updated.clone(),
                            window_size: window_size.clone(),
                        })?;

                        jmux_msg_to_send_sender
                            .send(Message::open_success(peer_id, local_id, msg.initial_window_size, msg.maximum_packet_size))
                            .context("Couldn’t send OPEN SUCCESS message through mpsc channel")?;

                        let jmux_msg_sender = jmux_msg_to_send_sender.clone();
                        let api_request_sender = api_request_sender.clone();
                        let read_forward_log = log.new(o!("reader" => format!("{}", local_id)));
                        tokio::spawn(async move {
                            forward_stream_data_task(
                                reader, local_id, peer_id, window_size_updated, window_size, maximum_packet_size, jmux_msg_sender, api_request_sender, read_forward_log
                            ).await
                        });

                        info!(log, "Accepted new channel ({} {})", local_id, peer_id);
                    }
                    Message::OpenSuccess(msg) => {
                        let local_id = LocalChannelId::from(msg.recipient_channel_id);
                        let peer_id = DistantChannelId::from(msg.sender_channel_id);

                        let window_size_updated = Arc::new(Notify::new());
                        let window_size = Arc::new(AtomicUsize::new(usize::try_from(msg.initial_window_size).unwrap()));

                        jmux_ctx.register_channel(JmuxChannelCtx {
                            distant_id: peer_id,
                            distant_state: JmuxChannelState::Streaming,

                            local_id,
                            local_state: JmuxChannelState::Streaming,

                            window_size_updated: window_size_updated.clone(),
                            window_size: window_size.clone(),
                        })?;

                        info!(log, "Successfully opened channel ({} {})", local_id, peer_id);

                        let (reader, api_response_sender) = pending_channels.remove(&local_id).with_context(|| format!("Couldn’t find pending reader for {}", local_id))?;
                        let jmux_msg_sender = jmux_msg_to_send_sender.clone();
                        let api_request_sender = api_request_sender.clone();
                        let read_forward_log = log.new(o!("reader" => format!("{}", local_id)));
                        tokio::spawn(async move {
                            forward_stream_data_task(
                                reader, local_id, peer_id, window_size_updated, window_size, msg.maximum_packet_size, jmux_msg_sender, api_request_sender, read_forward_log
                            ).await
                        });
                        let _ = api_response_sender.send(JmuxApiResponse::Success { id: local_id });
                    }
                    Message::WindowAdjust(msg) => {
                        if let Some(ctx) = jmux_ctx.get_channel_mut(LocalChannelId::from(msg.recipient_channel_id)) {
                            ctx.window_size.fetch_add(usize::try_from(msg.window_adjustment).unwrap(), Ordering::SeqCst);
                            ctx.window_size_updated.notify_one();
                        }
                    }
                    Message::Data(msg) => {
                        let id = LocalChannelId::from(msg.recipient_channel_id);

                        // TODO: writer task
                        // ^ Maybe a single task managing a given peer’s writer and reader to be spawned
                        // and communicated with using a mpsc channel.
                        // Current task should be a kind of "jmux scheduler" or "jmux orchestrator"
                        // handling the JMUX context and communicating to the other tasks.
                        if let Some(writer) = writers.get_mut(&id) {
                            // TODO: Here, just close the channel or something on error
                            writer.write_all(&msg.transfer_data).await?;
                        }

                        let distant_id = jmux_ctx.get_channel(id).with_context(|| format!("Couldn’t find channel for {}", id))?.distant_id;

                        // Simplest approach for now: just send back a WINDOW ADJUST message to
                        // increase back peer’s window size.
                        jmux_msg_to_send_sender.send(Message::window_adjust(distant_id, u32::try_from(msg.transfer_data.len()).unwrap()))
                            .context("Couldn’t send WINDOW ADJUST message")?;
                    }
                    Message::Eof(msg) => {
                        // Per the spec:
                        // > No explicit response is sent to this message.
                        // > However, the application may send EOF to whatever is at the other end of the channel.
                        // > Note that the channel remains open after this message, and more data may still be sent in the other direction.
                        // > This message does not consume window space and can be sent even if no window space is available.

                        let id = LocalChannelId::from(msg.recipient_channel_id);
                        let channel = jmux_ctx.get_channel_mut(id).with_context(|| format!("Couldn’t find channel with id {}", id))?;

                        channel.distant_state = JmuxChannelState::Eof;
                        info!(log, "Distant peer {} EOFed", channel.distant_id);

                        match channel.local_state {
                            JmuxChannelState::Streaming => {},
                            JmuxChannelState::Eof => {
                                channel.local_state = JmuxChannelState::Closed;
                                jmux_msg_to_send_sender
                                    .send(Message::close(channel.distant_id))
                                    .context("Couldn’t send CLOSE message")?;
                            },
                            JmuxChannelState::Closed => {},
                        }
                    }
                    Message::OpenFailure(msg) => {
                        let id = LocalChannelId::from(msg.recipient_channel_id);

                        warn!(log, "Couldn’t open channel for {} because of error {}: {}", id, msg.reason_code, msg.description);

                        // As per `tokio 1.10.0` doc:
                        // > Dropping the write half will shut down the write half of the TCP stream.
                        // > This is equivalent to calling shutdown() on the TcpStream.
                        // So, this will close the reader side as well.
                        writers.remove(&id);

                        let (_, api_response_sender) = pending_channels.remove(&id).with_context(|| format!("Couldn’t find pending channel {}", id))?;
                        let _ = api_response_sender.send(JmuxApiResponse::Failure { id, reason_code: msg.reason_code });

                        jmux_ctx.unregister(id);
                    }
                    Message::Close(msg) => {
                        let local_id = LocalChannelId::from(msg.recipient_channel_id);

                        let channel = jmux_ctx.get_channel_mut(local_id).with_context(|| format!("Couldn’t find channel with id {}", local_id))?;
                        let distant_id = channel.distant_id;

                        channel.distant_state = JmuxChannelState::Closed;
                        info!(log, "Distant peer {} closed", distant_id);

                        // Close TCP stream.
                        writers.remove(&local_id);

                        if channel.local_state == JmuxChannelState::Eof {
                            channel.local_state = JmuxChannelState::Closed;
                            jmux_msg_to_send_sender
                                .send(Message::close(distant_id))
                                .context("Couldn’t send CLOSE message")?;
                        }

                        if channel.local_state == JmuxChannelState::Closed {
                            jmux_ctx.unregister(local_id);
                            info!(log, "Closed channel ({} {})", local_id, distant_id);
                        }
                    }
                }
            }
        }
    }

    info!(log, "Closing JMUX receiver task...");

    Ok(())
}

async fn forward_stream_data_task(
    stream: OwnedReadHalf,
    local_id: LocalChannelId,
    distant_id: DistantChannelId,
    window_size_updated: Arc<Notify>,
    window_size: Arc<AtomicUsize>,
    maximum_packet_size: u16,
    jmux_msg_to_send_sender: UnboundedSender<Message>,
    jmux_api_request_sender: UnboundedSender<JmuxApiRequest>,
    log: Logger,
) -> anyhow::Result<()> {
    let codec = tokio_util::codec::BytesCodec::new();
    let mut bytes_stream = FramedRead::new(stream, codec);

    debug!(log, "Started forwarding");

    while let Some(bytes) = bytes_stream.next().await {
        let bytes = bytes.context("Couldn’t read next bytes from stream")?;

        let queue: Vec<Vec<u8>> = bytes
            .chunks(usize::try_from(maximum_packet_size).unwrap())
            .map(|slice| slice.to_vec())
            .collect();

        for mut bytes in queue {
            loop {
                let window_size_now = window_size.load(Ordering::SeqCst);
                if window_size_now < bytes.len() {
                    debug!(
                        log,
                        "Window size ({} bytes) insufficient to send full packet ({} bytes). Truncate packet and wait.",
                        window_size_now,
                        bytes.len()
                    );

                    if window_size_now > 0 {
                        let bytes_to_send_now: Vec<u8> = bytes.drain(..window_size_now).collect();
                        window_size.fetch_sub(bytes_to_send_now.len(), Ordering::SeqCst);
                        jmux_msg_to_send_sender
                            .send(Message::data(distant_id, bytes_to_send_now))
                            .context("Couldn’t send DATA message")?;
                    }

                    window_size_updated.notified().await;
                } else {
                    window_size.fetch_sub(bytes.len(), Ordering::SeqCst);
                    jmux_msg_to_send_sender
                        .send(Message::data(distant_id, bytes))
                        .context("Couldn’t send DATA message")?;
                    break;
                }
            }
        }
    }

    debug!(log, "Finished forwarding (EOF)");

    jmux_api_request_sender
        .send(JmuxApiRequest::Eof { id: local_id })
        .context("Couldn’t send EOF API message")?;

    Ok(())
}

pub fn error_kind_to_reason_code(e: std::io::ErrorKind) -> ReasonCode {
    match e {
        std::io::ErrorKind::ConnectionRefused => ReasonCode::CONNECTION_REFUSED,
        _ => ReasonCode::GENERAL_FAILURE,
    }
}
