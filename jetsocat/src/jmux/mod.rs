pub mod packets_processing;
pub mod proto;

use crate::jmux::packets_processing::{JmuxChannelMsg, JmuxReceiver, JmuxSender};
use crate::jmux::proto::{
    JmuxMsgChannelClose, JmuxMsgChannelData, JmuxMsgChannelEof, JmuxMsgChannelOpen, JmuxMsgChannelOpenFailure,
    JmuxMsgChannelOpenSuccess, JmuxMsgChannelWindowAdjust,
};
use crate::pipe::Pipe;
use anyhow::Result;
use idalloc::Slab;
use slog::{debug, info, trace, Logger};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::duplex;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::sync::{Mutex, Notify};

const DUPLEX_BUF_SIZE: usize = 64 * 1024;

pub async fn jmux_listen_loop(arg: String, log: Logger) -> Result<Pipe> {
    use anyhow::Context as _;
    use tokio::net::TcpListener;

    let (outgoing_read_pipe, incoming_write_pipe) = duplex(DUPLEX_BUF_SIZE);
    let (incoming_read_pipe, outgoing_write_pipe) = duplex(DUPLEX_BUF_SIZE);

    info!(log, "Binding TCP on {}", arg);

    let listener = TcpListener::bind(arg)
        .await
        .with_context(|| "Failed to bind TCP listener")?;

    let clients: Arc<Mutex<HashMap<u32, TcpStream>>> = Arc::new(Mutex::new(HashMap::new()));
    let jmux_sender = JmuxSender::new(Box::new(incoming_write_pipe));
    let id_allocator = Arc::new(Mutex::new(idalloc::Slab::<u32>::new()));

    // Listen Task
    tokio::spawn({
        let jmux_sender = jmux_sender.clone();
        let clients = clients.clone();
        let id_allocator = id_allocator.clone();
        let log = log.clone();

        async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let id = { id_allocator.as_ref().lock().await.next() };

                info!(log, "Received new connection with id #{}", id);

                jmux_sender
                    .send(&JmuxMsgChannelOpen::new(id))
                    .await
                    .unwrap_or_else(|e| panic!("Failed to send channel OPEN: {}", e));

                let clients = &mut *clients.as_ref().lock().await;
                clients.insert(id, tcp);
            }
        }
    });

    // Jmux receiver task
    tokio::spawn({
        let log = log.clone();
        let jmux_receiver = JmuxReceiver::new(Box::new(incoming_read_pipe));
        let jmux_context = JmuxContext::new(jmux_sender, id_allocator.clone(), log.clone());

        async move {
            loop {
                match jmux_receiver.receive().await {
                    Ok(result) => match result {
                        JmuxChannelMsg::OpenSuccess(msg) => {
                            debug!(log, "Listen Loop - got {:?}", msg);

                            let connection_id = msg.sender_channel_id;
                            let initial_window_size = msg.initial_window_size;
                            let maximum_packet_size = msg.maximum_packet_size;
                            let recipient_channel_id = msg.recipient_channel_id;

                            let (read_half, write_half) = {
                                let clients = &mut *clients.as_ref().lock().await;
                                let tcp = clients
                                    .remove(&connection_id)
                                    .unwrap_or_else(|| panic!("Cannot find TCP stream by ID {:?}", connection_id));

                                tcp.into_split()
                            };

                            jmux_context
                                .channel_forward_read(
                                    read_half,
                                    recipient_channel_id,
                                    initial_window_size,
                                    maximum_packet_size,
                                )
                                .await;
                            jmux_context.channel_forward_write(write_half, connection_id).await;
                        }
                        JmuxChannelMsg::OpenFailure(msg) => {
                            debug!(log, "Listen Loop - got {:?}", msg);

                            let connection_id = msg.recipient_channel_id;
                            let clients = &mut *clients.as_ref().lock().await;
                            clients
                                .remove(&connection_id)
                                .unwrap_or_else(|| panic!("Cannot find TCP stream by ID {:?}", connection_id));

                            let mut id_allocator = id_allocator.as_ref().lock().await;
                            id_allocator.free(connection_id);
                        }
                        JmuxChannelMsg::Open(msg) => panic!("Unexpect {:?}", msg),
                        msg => jmux_context.handle_general_jmux_message(msg).await,
                    },
                    Err(e) => panic!("Unexpect error from jmux receiver {:?}", e),
                }
            }
        }
    });

    Ok(Pipe::new(
        "jmux-tcp-listen",
        Box::new(outgoing_read_pipe),
        Box::new(outgoing_write_pipe),
    ))
}

pub async fn jmux_connect_loop(address: String, log: Logger) -> Result<Pipe> {
    info!(log, "Starting Accept loop");

    let (outgoing_read_pipe, incoming_write_pipe) = duplex(DUPLEX_BUF_SIZE);
    let (incoming_read_pipe, outgoing_write_pipe) = duplex(DUPLEX_BUF_SIZE);

    tokio::spawn({
        let jmux_receiver = JmuxReceiver::new(Box::new(incoming_read_pipe));
        let jmux_sender = JmuxSender::new(Box::new(incoming_write_pipe));
        let id_allocator = Arc::new(Mutex::new(idalloc::Slab::<u32>::new()));

        let jmux_context = JmuxContext::new(jmux_sender.clone(), id_allocator.clone(), log.clone());

        async move {
            loop {
                match jmux_receiver.receive().await {
                    Ok(msg) => {
                        match msg {
                            JmuxChannelMsg::Open(msg) => {
                                debug!(log, "Accept Loop - got {:?}", msg);

                                let recipient_channel_id = { id_allocator.lock().await.next() };
                                let jmux_sender = jmux_sender.clone();
                                let address = address.clone();

                                tokio::spawn({
                                    let jmux_context = jmux_context.clone();
                                    let connection_id = msg.sender_channel_id;
                                    let window_size = msg.initial_window_size;
                                    let maximum_packet_size = msg.maximum_packet_size;

                                    async move {
                                        let (read_half, write_half) = match TcpStream::connect(address.clone()).await {
                                            Ok(tcp_connection) => tcp_connection.into_split(),
                                            Err(e) => {
                                                jmux_sender
                                                    .send(&JmuxMsgChannelOpenFailure::new(
                                                        connection_id,
                                                        h_error_kind_to_socks5_error(e.kind()),
                                                        e.to_string(),
                                                    ))
                                                    .await
                                                    .unwrap();
                                                return;
                                            }
                                        };

                                        jmux_context
                                            .channel_forward_read(
                                                read_half,
                                                connection_id,
                                                window_size,
                                                maximum_packet_size,
                                            )
                                            .await;
                                        jmux_context
                                            .channel_forward_write(write_half, recipient_channel_id)
                                            .await;

                                        jmux_sender
                                            .send(&JmuxMsgChannelOpenSuccess::new(recipient_channel_id, connection_id))
                                            .await
                                            .unwrap();
                                    }
                                });
                            }
                            JmuxChannelMsg::OpenSuccess(_) | JmuxChannelMsg::OpenFailure(_) => {
                                panic!("Unexpect {:?}", msg)
                            }
                            other_msg => jmux_context.handle_general_jmux_message(other_msg).await,
                        };
                    }
                    Err(e) => {
                        debug!(log, "JMUX receive ended: {}", e);
                        return;
                    }
                };
            }
        }
    });

    Ok(Pipe::new(
        "jmux-tcp-accept",
        Box::new(outgoing_read_pipe),
        Box::new(outgoing_write_pipe),
    ))
}

#[derive(Clone)]
struct JmuxContext {
    pub jmux_sender: JmuxSender,
    pub adjust_window_event_senders: Arc<Mutex<HashMap<u32, UnboundedSender<u32>>>>,
    pub message_data_event_senders: Arc<Mutex<HashMap<u32, UnboundedSender<JmuxMsgChannelData>>>>,
    pub read_stop_signal: Arc<Mutex<HashMap<u32, Arc<Notify>>>>,
    pub id_allocator: Arc<Mutex<Slab<u32>>>,
    pub log: Logger,
}

impl JmuxContext {
    fn new(jmux_sender: JmuxSender, id_allocator: Arc<Mutex<Slab<u32>>>, log: Logger) -> Self {
        Self {
            jmux_sender,
            adjust_window_event_senders: Default::default(),
            message_data_event_senders: Default::default(),
            read_stop_signal: Default::default(),
            id_allocator,
            log,
        }
    }

    async fn channel_forward_read(
        &self,
        mut reader: OwnedReadHalf,
        channel_id: u32,
        mut window_size: u32,
        maximum_packet_size: u32,
    ) {
        let (adjust_window_event_sender, mut adjust_window_event_receiver) = mpsc::unbounded_channel();
        {
            let mut adjust_window_event_senders = self.adjust_window_event_senders.lock().await;
            adjust_window_event_senders.insert(channel_id, adjust_window_event_sender);
        }

        let read_stop_notify = {
            let notify = Arc::new(Notify::new());
            let mut read_stop_signal = self.read_stop_signal.lock().await;
            read_stop_signal.insert(channel_id, notify.clone());
            notify
        };

        tokio::spawn({
            let jmux_sender = self.jmux_sender.clone();
            let log = self.log.clone();

            async move {
                use min_max::min;
                use tokio::io::AsyncReadExt as _;

                let mut buf = [0u8; 1024];

                'main: loop {
                    tokio::select! {
                        _ = read_stop_notify.notified() => {
                            break;
                        }
                        bytes_read = reader.read(&mut buf) => {
                            if let Ok(bytes_read) = bytes_read {
                                if bytes_read == 0 {
                                    jmux_sender
                                            .send(&JmuxMsgChannelEof::new(channel_id))
                                            .await
                                            .unwrap_or_else(|e| panic!("Failed to send EOF to #{}: {}", channel_id, e));

                                    break 'main;
                                }

                                let mut bytes_sent = 0;
                                while bytes_sent != bytes_read {
                                    if window_size == 0 {
                                        match adjust_window_event_receiver.recv().await {
                                            Some(size) => window_size += size,
                                            None => {
                                                trace!(log, "No JMUX_MSG_CHANNEL_WINDOW_ADJUST expected, \
                                                              so channel is closing  without sending the \
                                                              remaining data");
                                                break 'main;
                                            }
                                        }
                                    }

                                    let data_to_send = min!(bytes_read, window_size as usize, maximum_packet_size as usize);
                                    trace!(log, "Sending {} bytes to #{}", data_to_send, &channel_id);
                                    jmux_sender
                                        .send(&JmuxMsgChannelData::new(channel_id, buf[..data_to_send].to_vec()))
                                        .await
                                        .unwrap_or_else(|e| panic!("Failed to send data to #{}: {}", channel_id, e));

                                    bytes_sent += data_to_send;
                                }
                            }
                        }
                    }
                }

                jmux_sender
                    .send(&JmuxMsgChannelClose::new(channel_id))
                    .await
                    .unwrap_or_else(|e| panic!("Failed to send Close to #{}: {}", channel_id, e));
            }
        });
    }

    async fn channel_forward_write(&self, mut writer: OwnedWriteHalf, channel_id: u32) {
        use tokio::io::AsyncWriteExt;

        let (message_data_sender, mut message_data_receiver) = mpsc::unbounded_channel();
        {
            let mut message_data_senders = self.message_data_event_senders.lock().await;
            message_data_senders.insert(channel_id, message_data_sender);
        }

        let log = self.log.clone();
        let jmux_sender = self.jmux_sender.clone();

        tokio::spawn({
            async move {
                while let Some(data) = message_data_receiver.recv().await {
                    if let Err(e) = writer.write_all(&data.transfer_data[..data.data_length as usize]).await {
                        debug!(
                            log,
                            "Failed to write data to socket #{}: {}", data.recipient_channel_id, e
                        );
                        return;
                    }

                    jmux_sender
                        .send(&JmuxMsgChannelWindowAdjust::new(
                            data.recipient_channel_id,
                            data.data_length as u32,
                        ))
                        .await
                        .unwrap_or_else(|e| panic!("Failed to send Adjust to #{}: {}", channel_id, e));
                }
            }
        });
    }

    async fn handle_general_jmux_message(&self, general_jmux_message: JmuxChannelMsg) {
        match general_jmux_message {
            JmuxChannelMsg::WindowAdjust(window_adjust) => {
                trace!(
                    self.log,
                    "Received WindowAdjust message for {}",
                    window_adjust.recipient_channel_id
                );
                let adjust_window_event_senders = self.adjust_window_event_senders.lock().await;
                if let Some(adjust_window_event_sender) =
                    adjust_window_event_senders.get(&window_adjust.recipient_channel_id)
                {
                    adjust_window_event_sender.send(window_adjust.window_adjustment).ok();
                }
            }
            JmuxChannelMsg::Data(data) => {
                trace!(self.log, "Received Data message for {}", data.recipient_channel_id);

                let message_data_event_senders = self.message_data_event_senders.lock().await;
                let message_data_event_sender = message_data_event_senders.get(&data.recipient_channel_id).unwrap();
                message_data_event_sender.send(data).ok();
            }
            JmuxChannelMsg::Eof(eof) => {
                debug!(self.log, "Received Eof message for {}", eof.recipient_channel_id);

                let mut message_data_event_senders = self.message_data_event_senders.lock().await;
                message_data_event_senders.remove(&eof.recipient_channel_id);
            }
            JmuxChannelMsg::Close(close) => {
                debug!(self.log, "Received Close message for {}", close.recipient_channel_id);

                let recipient_channel_id = close.recipient_channel_id;
                {
                    let mut message_data_event_senders = self.adjust_window_event_senders.lock().await;
                    message_data_event_senders.remove(&recipient_channel_id);
                }

                {
                    let read_stop_signal = self.read_stop_signal.lock().await;
                    if let Some(notify) = read_stop_signal.get(&close.recipient_channel_id) {
                        notify.notify_one();
                    }
                }

                let mut id_allocator = self.id_allocator.lock().await;
                id_allocator.free(close.recipient_channel_id);
            }
            msg => {
                panic!("Got unexpected JMUX non-general message {:?}", msg)
            }
        }
    }
}

fn h_error_kind_to_socks5_error(e: std::io::ErrorKind) -> u32 {
    match e {
        std::io::ErrorKind::ConnectionRefused => 5,
        _ => 1,
    }
}
