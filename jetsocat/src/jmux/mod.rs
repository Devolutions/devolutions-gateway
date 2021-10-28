//! [Specification document](https://github.com/awakecoding/qmux/blob/protocol-update/SPEC.md)

// FIXME: probably too much of INFO level logs

pub mod listener;

mod codec;
mod id;
mod proto;

use self::codec::JmuxCodec;
use self::id::{DistantChannelId, IdAllocator, LocalChannelId};
use self::proto::{Message, ReasonCode};
use crate::jmux::proto::{ChannelData, Header};
use crate::pipe::PipeMode;
use crate::proxy::ProxyConfig;
use anyhow::Context as _;
use futures_util::{SinkExt, StreamExt};
use slog::{debug, error, info, o, trace, warn, Logger};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};

pub type ApiResponseSender = UnboundedSender<JmuxApiResponse>;
pub type ApiResponseReceiver = UnboundedReceiver<JmuxApiResponse>;
pub type ApiRequestSender = UnboundedSender<JmuxApiRequest>;
pub type ApiRequestReceiver = UnboundedReceiver<JmuxApiRequest>;

#[derive(Debug)]
pub enum JmuxApiRequest {
    OpenChannel {
        destination_url: String,
        api_response_sender: ApiResponseSender,
    },
    Start {
        id: LocalChannelId,
        stream: TcpStream,
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
    request_sender: ApiRequestSender,
    request_receiver: ApiRequestReceiver,
    pipe_mode: PipeMode,
    proxy_cfg: Option<ProxyConfig>,
    log: Logger,
) -> anyhow::Result<()> {
    use crate::pipe::open_pipe;

    let (msg_sender, msg_receiver) = mpsc::unbounded_channel::<Message>();

    // Open generic pipe to exchange JMUX channel messages on
    let pipe_log = log.new(o!("open pipe" => "JMUX pipe"));
    let pipe = open_pipe(pipe_mode, proxy_cfg, pipe_log).await?;
    let msg_stream = FramedRead::new(pipe.read, JmuxCodec);
    let msg_sink = FramedWrite::new(pipe.write, JmuxCodec);
    let _handle = pipe._handle;

    let sender_task_handle = JmuxSenderTask {
        msg_sink,
        msg_receiver,
        log: log.new(o!("JMUX task" => "sender")),
    }
    .spawn();

    let scheduler_task_handle = JmuxSchedulerTask {
        msg_stream,
        msg_sender,
        request_sender,
        request_receiver,
        log: log.new(o!("JMUX task" => "scheduler")),
    }
    .spawn();

    tokio::select! {
        receiver_task_result = scheduler_task_handle => {
            receiver_task_result.context("Couldn't join on scheduler task")?.context("Receiver task failed")?;
        }
        sender_task_result = sender_task_handle => {
            sender_task_result.context("Couldn’t join on sender task")?.context("Sender task failed")?;
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

    log: Logger,
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

type MessageReceiver = UnboundedReceiver<Message>;
type MessageSender = UnboundedSender<Message>;
type DataReceiver = UnboundedReceiver<Vec<u8>>;
type DataSender = UnboundedSender<Vec<u8>>;
type InternalMessageSender = UnboundedSender<InternalMessage>;

#[derive(Debug)]
enum InternalMessage {
    Eof { id: LocalChannelId },
    StreamResolved { channel: JmuxChannelCtx, stream: TcpStream },
}

// === internal tasks === //

// ---------------------- //

struct JmuxSenderTask<T: AsyncWrite + Unpin + Send + 'static> {
    msg_sink: FramedWrite<T, JmuxCodec>,
    msg_receiver: MessageReceiver,
    log: Logger,
}

impl<T: AsyncWrite + Unpin + Send + 'static> JmuxSenderTask<T> {
    fn spawn(self) -> JoinHandle<anyhow::Result<()>> {
        let fut = self.run();
        tokio::spawn(fut)
    }

    async fn run(self) -> anyhow::Result<()> {
        let Self {
            mut msg_sink,
            mut msg_receiver,
            log,
        } = self;

        while let Some(msg) = msg_receiver.recv().await {
            msg_sink.feed(msg).await?;
            msg_sink.flush().await?;
        }

        info!(log, "Closing JMUX sender task...");

        Ok(())
    }
}

// ---------------------- //

struct JmuxSchedulerTask<T: AsyncRead + Unpin + Send + 'static> {
    msg_stream: FramedRead<T, JmuxCodec>,
    msg_sender: MessageSender,
    request_sender: ApiRequestSender,
    request_receiver: ApiRequestReceiver,
    log: Logger,
}

impl<T: AsyncRead + Unpin + Send + 'static> JmuxSchedulerTask<T> {
    fn spawn(self) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        let fut = scheduler_task_impl(self);
        tokio::spawn(fut)
    }
}

async fn scheduler_task_impl<T: AsyncRead + Unpin + Send + 'static>(task: JmuxSchedulerTask<T>) -> anyhow::Result<()> {
    let JmuxSchedulerTask {
        mut msg_stream,
        msg_sender,
        request_sender,
        mut request_receiver,
        log,
    } = task;

    // Keep the handle in current scope but prevent usage
    let _ = request_sender;

    let mut jmux_ctx = JmuxCtx::new();
    let mut data_senders: HashMap<LocalChannelId, DataSender> = HashMap::new();
    let mut pending_channels: HashMap<LocalChannelId, (String, ApiResponseSender)> = HashMap::new();
    let (internal_sender, mut internal_receiver) = mpsc::unbounded_channel::<InternalMessage>();

    loop {
        // NOTE: Current task is the "jmux scheduler" or "jmux orchestrator".
        // It handles the JMUX context and communicates with other tasks.
        // As such, it should process messages continuously and never wait during processing: no `await` keyword
        // must be seen inside this select block.
        // It's also expected to be resilient and `?` operator should be used only for
        // unrecoverable failures.

        tokio::select! {
            request = request_receiver.recv() => {
                // This should never panic as long as we have a sender handle always in scope
                let request = request.expect("ran out of senders");

                match request {
                    JmuxApiRequest::OpenChannel { destination_url, api_response_sender } => {
                        match jmux_ctx.allocate_id() {
                            Some(id) => {
                                debug!(log, "Allocated local ID {}", id);
                                debug!(log, "{} request {}", id, destination_url);
                                pending_channels.insert(id, (destination_url.clone(), api_response_sender));
                                msg_sender
                                    .send(Message::open(id, destination_url))
                                    .context("Couldn’t send CHANNEL OPEN message through mpsc channel")?;
                            }
                            None => warn!(log, "Couldn’t allocate ID for API request: {}", destination_url),
                        }
                    }
                    JmuxApiRequest::Start { id, stream } => {
                        let channel = jmux_ctx.get_channel(id).with_context(|| format!("Couldn’t find channel with id {}", id))?;

                        let (data_sender, data_receiver) = mpsc::unbounded_channel::<Vec<u8>>();

                        if data_senders.insert(id, data_sender).is_some() {
                            anyhow::bail!("Detected two streams with the same ID {}", id);
                        }

                        let (reader, writer) = stream.into_split();

                        DataWriterTask {
                            writer,
                            data_receiver,
                            log: channel.log.clone(),
                        }.spawn();

                        DataReaderTask {
                            reader,
                            local_id: channel.local_id,
                            distant_id: channel.distant_id,
                            window_size_updated: Arc::clone(&channel.window_size_updated),
                            window_size: Arc::clone(&channel.window_size),
                            maximum_packet_size: channel.maximum_packet_size,
                            msg_sender: msg_sender.clone(),
                            internal_sender: internal_sender.clone(),
                            log: channel.log.clone()
                        }.spawn();
                    }
                }
            }
            internal_msg = internal_receiver.recv() => {
                // This should never panic as long as we don't drop `eof_notification_sender` handle explicitely
                let internal_msg = internal_msg.expect("ran out of senders");

                match internal_msg {
                    InternalMessage::Eof { id } => {
                        let channel = jmux_ctx.get_channel_mut(id).with_context(|| format!("Couldn’t find channel with id {}", id))?;
                        let channel_log = channel.log.clone();
                        let local_id = channel.local_id;
                        let distant_id = channel.distant_id;

                        match channel.distant_state {
                            JmuxChannelState::Streaming => {
                                channel.local_state = JmuxChannelState::Eof;
                                msg_sender
                                    .send(Message::eof(distant_id))
                                    .context("Couldn’t send EOF message")?;
                                },
                            JmuxChannelState::Eof => {
                                channel.local_state = JmuxChannelState::Closed;
                                msg_sender
                                    .send(Message::close(distant_id))
                                    .context("Couldn’t send CLOSE message")?;
                                },
                            JmuxChannelState::Closed => {
                                jmux_ctx.unregister(local_id);
                                msg_sender
                                    .send(Message::close(distant_id))
                                    .context("Couldn’t send CLOSE message")?;
                                debug!(channel_log, "Channel closed");
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
                        let channel_log = channel.log.clone();

                        let (data_sender, data_receiver) = mpsc::unbounded_channel::<Vec<u8>>();

                        if data_senders.insert(channel.local_id, data_sender).is_some() {
                            anyhow::bail!("Detected two streams with the same local ID {}", channel.local_id);
                        };

                        jmux_ctx.register_channel(channel)?;

                        msg_sender
                            .send(Message::open_success(distant_id, local_id, initial_window_size, maximum_packet_size))
                            .context("Couldn’t send OPEN SUCCESS message through mpsc channel")?;

                        debug!(channel_log, "Channel accepted");

                        let (reader, writer) = stream.into_split();

                        DataWriterTask {
                            writer,
                            data_receiver,
                            log: channel_log.clone(),
                        }.spawn();

                        let reader_task = DataReaderTask {
                            reader,
                            local_id,
                            distant_id,
                            window_size_updated,
                            window_size,
                            maximum_packet_size,
                            msg_sender: msg_sender.clone(),
                            internal_sender: internal_sender.clone(),
                            log: channel_log,
                        };

                        reader_task.spawn();
                    }
                }
            }
            channel_msg = msg_stream.next() => {
                let channel_msg = match channel_msg {
                    Some(msg) => msg,
                    None => {
                        info!(log, "JMUX pipe was closed by peer");
                        break;
                    }
                };

                let channel_msg = match channel_msg {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!(log, "JMUX pipe error: {:?}", e);
                        continue;
                    }
                };

                trace!(log, "Received channel message: {:?}", channel_msg);

                match channel_msg {
                    Message::Open(msg) => {
                        let peer_id = DistantChannelId::from(msg.sender_channel_id);

                        info!(log, "{} request {}", peer_id, msg.destination_url);
                        let local_id = match jmux_ctx.allocate_id() {
                            Some(id) => id,
                            None => {
                                warn!(log, "Couldn’t allocate local ID for distant peer {}: no more ID available", peer_id);
                                msg_sender
                                    .send(Message::open_failure(peer_id, ReasonCode::GENERAL_FAILURE, "no more ID available"))
                                    .context("Couldn’t send OPEN FAILURE message through mpsc channel")?;
                                continue;
                            }
                        };
                        debug!(log, "Allocated ID {} for peer {}", local_id, peer_id);


                        let window_size_updated = Arc::new(Notify::new());
                        let window_size = Arc::new(AtomicUsize::new(usize::try_from(msg.initial_window_size).unwrap()));

                        let channel_log = log.new(o!("channel" => format!("({} {})", local_id, peer_id), "url" => msg.destination_url.clone()));

                        let channel = JmuxChannelCtx {
                            distant_id: peer_id,
                            distant_state: JmuxChannelState::Streaming,

                            local_id,
                            local_state: JmuxChannelState::Streaming,

                            initial_window_size: msg.initial_window_size,
                            window_size_updated: window_size_updated.clone(),
                            window_size: window_size.clone(),

                            maximum_packet_size: msg.maximum_packet_size,

                            log: channel_log,
                        };

                        StreamResolverTask {
                            channel,
                            destination_url: msg.destination_url,
                            internal_sender: internal_sender.clone(),
                            msg_sender: msg_sender.clone(),
                        }
                        .spawn();
                    }
                    Message::OpenSuccess(msg) => {
                        let local_id = LocalChannelId::from(msg.recipient_channel_id);
                        let peer_id = DistantChannelId::from(msg.sender_channel_id);

                        let (destination_url, api_response_sender) = match pending_channels.remove(&local_id) {
                            Some(pending) => pending,
                            None => {
                                warn!(log, "Couldn’t find pending channel for {}", local_id);
                                continue;
                            },
                        };

                        let channel_log = log.new(o!("channel" => format!("({} {})", local_id, peer_id), "url" => destination_url));

                        debug!(channel_log, "Successfully opened channel");

                        if let Err(e) = api_response_sender.send(JmuxApiResponse::Success { id: local_id }) {
                            warn!(channel_log, "Couldn’t send success API response through mpsc channel: {}", e);
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

                            log: channel_log,
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
                                warn!(log, "Couldn’t find channel with id {}", id);
                                continue;
                            },
                        };

                        let sender = match data_senders.get_mut(&id) {
                            Some(sender) => sender,
                            None => {
                                warn!(log, "received data but associated data sender is missing");
                                continue;
                            }
                        };

                        let _ = sender.send(msg.transfer_data);

                        // TODO: implement better flow control logic
                        // Simplest approach for now: just send back a WINDOW ADJUST message to
                        // increase back peer’s window size.
                        msg_sender.send(Message::window_adjust(distant_id, data_length))
                            .context("Couldn’t send WINDOW ADJUST message")?;
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
                                warn!(log, "Couldn’t find channel with id {}", id);
                                continue;
                            },
                        };

                        channel.distant_state = JmuxChannelState::Eof;
                        debug!(channel.log, "Distant peer EOFed");

                        // Remove associated data sender
                        data_senders.remove(&id);

                        match channel.local_state {
                            JmuxChannelState::Streaming => {},
                            JmuxChannelState::Eof => {
                                channel.local_state = JmuxChannelState::Closed;
                                msg_sender
                                    .send(Message::close(channel.distant_id))
                                    .context("Couldn’t send CLOSE message")?;
                            },
                            JmuxChannelState::Closed => {},
                        }
                    }
                    Message::OpenFailure(msg) => {
                        let id = LocalChannelId::from(msg.recipient_channel_id);

                        warn!(log, "Couldn’t open channel for {} because of error {}: {}", id, msg.reason_code, msg.description);

                        jmux_ctx.unregister(id);

                        let api_response_sender = match pending_channels.remove(&id) {
                            Some((_, sender)) => sender,
                            None => {
                                warn!(log, "Couldn’t find pending channel {}", id);
                                continue;
                            },
                        };

                        // It's fine to just ignore error here since the channel is closed anyway
                        let _ = api_response_sender.send(JmuxApiResponse::Failure { id, reason_code: msg.reason_code });
                    }
                    Message::Close(msg) => {
                        let local_id = LocalChannelId::from(msg.recipient_channel_id);
                        let channel = match jmux_ctx.get_channel_mut(local_id) {
                            Some(channel) => channel,
                            None => {
                                warn!(log, "Couldn’t find channel with id {}", local_id);
                                continue;
                            },
                        };
                        let distant_id = channel.distant_id;
                        let channel_log = channel.log.clone();

                        channel.distant_state = JmuxChannelState::Closed;
                        debug!(channel_log, "Distant peer closed");

                        // This will also shutdown the associated TCP stream.
                        data_senders.remove(&local_id);

                        if channel.local_state == JmuxChannelState::Eof {
                            channel.local_state = JmuxChannelState::Closed;
                            msg_sender
                                .send(Message::close(distant_id))
                                .context("Couldn’t send CLOSE message")?;
                        }

                        if channel.local_state == JmuxChannelState::Closed {
                            jmux_ctx.unregister(local_id);
                            debug!(channel_log, "Channel closed");
                        }
                    }
                }
            }
        }
    }

    info!(log, "Closing JMUX scheduler task...");

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
    msg_sender: MessageSender,
    internal_sender: InternalMessageSender,
    log: Logger,
}

impl DataReaderTask {
    fn spawn(self) {
        tokio::spawn(async move {
            let log = self.log.clone();
            if let Err(e) = self.run().await {
                warn!(log, "reader task failed: {}", e);
            }
        });
    }

    async fn run(self) -> anyhow::Result<()> {
        let Self {
            reader,
            local_id,
            distant_id,
            window_size_updated,
            window_size,
            maximum_packet_size,
            msg_sender,
            internal_sender,
            log,
        } = self;

        let codec = tokio_util::codec::BytesCodec::new();
        let mut bytes_stream = FramedRead::new(reader, codec);
        let maximum_packet_size = usize::try_from(maximum_packet_size).unwrap();

        debug!(log, "Started forwarding");

        while let Some(bytes) = bytes_stream.next().await {
            let bytes = bytes.context("Couldn’t read next bytes from stream")?;

            let chunk_size = maximum_packet_size - Header::SIZE - ChannelData::FIXED_PART_SIZE;

            let queue: Vec<Vec<u8>> = bytes.chunks(chunk_size).map(|slice| slice.to_vec()).collect();

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
                            msg_sender
                                .send(Message::data(distant_id, bytes_to_send_now))
                                .context("Couldn’t send DATA message")?;
                        }

                        window_size_updated.notified().await;
                    } else {
                        window_size.fetch_sub(bytes.len(), Ordering::SeqCst);
                        msg_sender
                            .send(Message::data(distant_id, bytes))
                            .context("Couldn’t send DATA message")?;
                        break;
                    }
                }
            }
        }

        debug!(log, "Finished forwarding (EOF)");
        internal_sender
            .send(InternalMessage::Eof { id: local_id })
            .context("Couldn’t send EOF notification")?;

        Ok(())
    }
}

// ---------------------- //

struct DataWriterTask {
    writer: OwnedWriteHalf,
    data_receiver: DataReceiver,
    log: Logger,
}

impl DataWriterTask {
    fn spawn(self) {
        let Self {
            mut writer,
            mut data_receiver,
            log,
        } = self;

        tokio::spawn(async move {
            while let Some(data) = data_receiver.recv().await {
                if let Err(e) = writer.write_all(&data).await {
                    warn!(log, "writer task failed: {}", e);
                    break;
                }
            }
        });
    }
}

// ---------------------- //

struct StreamResolverTask {
    channel: JmuxChannelCtx,
    destination_url: String,
    internal_sender: InternalMessageSender,
    msg_sender: MessageSender,
}

impl StreamResolverTask {
    fn spawn(self) {
        tokio::spawn(async move {
            let log = self.channel.log.clone();
            if let Err(e) = self.run().await {
                warn!(log, "resolver task failed: {}", e);
            }
        });
    }

    async fn run(self) -> anyhow::Result<()> {
        let Self {
            channel,
            destination_url,
            internal_sender,
            msg_sender,
        } = self;

        let mut addrs = match tokio::net::lookup_host(&destination_url).await {
            Ok(addrs) => addrs,
            Err(e) => {
                msg_sender
                    .send(Message::open_failure(
                        channel.distant_id,
                        ReasonCode::from(e.kind()),
                        e.to_string(),
                    ))
                    .context("Couldn’t send OPEN FAILURE message through mpsc channel")?;
                anyhow::bail!("Couldn't resolve host {}: {}", destination_url, e);
            }
        };
        let socket_addr = addrs.next().expect("at least one resolved address should be present");

        match TcpStream::connect(socket_addr).await {
            Ok(stream) => {
                internal_sender
                    .send(InternalMessage::StreamResolved { channel, stream })
                    .context("Could't send back resolved stream through internal mpsc channel")?;
            }
            Err(e) => {
                msg_sender
                    .send(Message::open_failure(
                        channel.distant_id,
                        ReasonCode::from(e.kind()),
                        e.to_string(),
                    ))
                    .context("Couldn’t send OPEN FAILURE message through mpsc channel")?;
                anyhow::bail!("Couldn’t connect TCP socket to {}: {}", destination_url, e);
            }
        };

        Ok(())
    }
}
