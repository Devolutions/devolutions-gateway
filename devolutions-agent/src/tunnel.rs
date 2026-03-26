//! QUIC-based Agent Tunnel client implementation.
//!
//! This module implements a QUIC client that connects to the Gateway's agent tunnel
//! endpoint, advertises reachable subnets, and handles incoming TCP proxy requests.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;

use agent_tunnel_proto::{ConnectMessage, ConnectResponse, ControlMessage};
use anyhow::{Context as _, Result, bail};
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use ipnetwork::Ipv4Network;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::config::ConfHandle;

struct SessionStream {
    tcp_to_quic_rx: mpsc::Receiver<Vec<u8>>,
    quic_to_tcp_tx: mpsc::Sender<Vec<u8>>,
    _task_handle: tokio::task::JoinHandle<()>,
    pending_quic_writes: VecDeque<Vec<u8>>,
    finish_quic_write: bool,
}

pub struct TunnelTask {
    conf_handle: ConfHandle,
}

impl TunnelTask {
    pub fn new(conf_handle: ConfHandle) -> Self {
        Self { conf_handle }
    }
}

#[async_trait]
impl Task for TunnelTask {
    type Output = Result<()>;
    const NAME: &'static str = "tunnel";

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> Result<()> {
        let agent_conf = self.conf_handle.get_conf();
        let tunnel_conf = &agent_conf.tunnel;

        info!("Starting QUIC agent tunnel");

        let cert_path = tunnel_conf
            .client_cert_path
            .as_ref()
            .context("client_cert_path not configured")?;
        let key_path = tunnel_conf
            .client_key_path
            .as_ref()
            .context("client_key_path not configured")?;
        let ca_path = tunnel_conf
            .gateway_ca_cert_path
            .as_ref()
            .context("gateway_ca_cert_path not configured")?;

        let advertise_subnets: Vec<Ipv4Network> = tunnel_conf
            .advertise_subnets
            .iter()
            .map(|subnet| subnet.parse())
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse advertise_subnets")?;

        if advertise_subnets.is_empty() {
            warn!("No subnets configured to advertise");
        }

        let mut quiche_config =
            quiche::Config::new(quiche::PROTOCOL_VERSION).context("failed to create quiche config")?;

        quiche_config
            .set_application_protos(&[b"devolutions-agent-tunnel"])
            .context("failed to set application protos")?;
        quiche_config
            .load_cert_chain_from_pem_file(cert_path.as_str())
            .context("failed to load certificate")?;
        quiche_config
            .load_priv_key_from_pem_file(key_path.as_str())
            .context("failed to load private key")?;
        quiche_config
            .load_verify_locations_from_file(ca_path.as_str())
            .context("failed to load CA certificate")?;
        quiche_config.verify_peer(true);

        let gateway_addr = tokio::net::lookup_host(&tunnel_conf.gateway_endpoint)
            .await
            .context("failed to resolve gateway endpoint")?
            .next()
            .context("no addresses resolved for gateway endpoint")?;

        info!(gateway_addr = %gateway_addr, "Connecting to gateway");

        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .context("failed to bind UDP socket")?;
        let local_addr = socket.local_addr()?;

        let mut scid = vec![0u8; quiche::MAX_CONN_ID_LEN];
        rand::Rng::fill(&mut rand::thread_rng(), &mut scid[..]);
        let scid = quiche::ConnectionId::from_vec(scid);

        let mut conn = quiche::connect(None, &scid, local_addr, gateway_addr, &mut quiche_config)
            .context("failed to create QUIC connection")?;

        let mut send_buf = vec![0u8; 65535];
        complete_handshake(&socket, &mut conn, gateway_addr, &mut send_buf).await?;
        info!("QUIC connection established");

        let route_advertise_interval_secs = tunnel_conf.route_advertise_interval_secs.unwrap_or(30);
        let heartbeat_interval_secs = tunnel_conf.heartbeat_interval_secs.unwrap_or(60);

        let mut route_advertise_interval = tokio::time::interval(Duration::from_secs(route_advertise_interval_secs));
        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(heartbeat_interval_secs));
        let mut tcp_poll_interval = tokio::time::interval(Duration::from_millis(10));

        route_advertise_interval.tick().await;
        heartbeat_interval.tick().await;
        tcp_poll_interval.tick().await;

        let mut recv_buf = vec![0u8; 65535];
        let mut control_buf = Vec::new();
        let mut pending_connect_messages: HashMap<u64, Vec<u8>> = HashMap::new();
        let mut session_streams: HashMap<u64, SessionStream> = HashMap::new();
        let mut epoch = 0u64;

        epoch += 1;
        send_control_message(
            &mut conn,
            &socket,
            gateway_addr,
            &ControlMessage::route_advertise(epoch, advertise_subnets.clone()),
            &mut send_buf,
        )
        .await?;
        info!(epoch, "Sent initial RouteAdvertise");

        loop {
            let timeout = conn.timeout().unwrap_or(Duration::from_secs(1));

            tokio::select! {
                biased;

                _ = shutdown_signal.wait() => {
                    info!("Tunnel task shutting down");
                    break;
                }

                _ = route_advertise_interval.tick() => {
                    epoch += 1;
                    let message = ControlMessage::route_advertise(epoch, advertise_subnets.clone());
                    if let Err(error) = send_control_message(&mut conn, &socket, gateway_addr, &message, &mut send_buf).await {
                        error!(%error, epoch, "Failed to send RouteAdvertise");
                    } else {
                        trace!(epoch, "Sent RouteAdvertise");
                    }
                }

                _ = heartbeat_interval.tick() => {
                    let active_stream_count =
                        u32::try_from(session_streams.len()).expect("active session stream count should fit in u32");
                    let message = ControlMessage::heartbeat(current_time_millis(), active_stream_count);
                    if let Err(error) = send_control_message(&mut conn, &socket, gateway_addr, &message, &mut send_buf).await {
                        error!(%error, active_stream_count, "Failed to send Heartbeat");
                    } else {
                        trace!(active_stream_count, "Sent Heartbeat");
                    }
                }

                _ = tcp_poll_interval.tick() => {}

                result = socket.recv_from(&mut recv_buf) => {
                    let (len, peer_addr) = result?;

                    if peer_addr != gateway_addr {
                        warn!(peer_addr = %peer_addr, "Received packet from unexpected peer");
                        continue;
                    }

                    let recv_info = quiche::RecvInfo {
                        from: peer_addr,
                        to: local_addr,
                    };

                    if let Err(error) = conn.recv(&mut recv_buf[..len], recv_info) {
                        error!(%error, "Failed to process received packet");
                        continue;
                    }

                    let readable: Vec<u64> = conn.readable().collect();
                    for stream_id in readable {
                        if stream_id == 0 {
                            if let Err(error) = handle_control_stream(&mut conn, stream_id, &mut control_buf).await {
                                error!(%error, "Failed to handle control stream");
                            }
                            continue;
                        }

                        if let Some(session) = session_streams.get_mut(&stream_id) {
                            if let Err(error) = read_from_quic_to_tcp(&mut conn, stream_id, session).await {
                                trace!(stream_id, %error, "Session stream closed");
                                session_streams.remove(&stream_id);
                            }
                            continue;
                        }

                        let pending = pending_connect_messages.entry(stream_id).or_default();
                        match handle_pending_session_stream(
                            &mut conn,
                            stream_id,
                            pending,
                            &advertise_subnets,
                            &mut send_buf,
                            &socket,
                        )
                        .await
                        {
                            Ok(Some(session)) => {
                                info!(stream_id, "Session stream started");
                                pending_connect_messages.remove(&stream_id);
                                session_streams.insert(stream_id, session);
                            }
                            Ok(None) => {}
                            Err(error) => {
                                error!(stream_id, %error, "Failed to start session stream");
                                pending_connect_messages.remove(&stream_id);
                            }
                        }
                    }
                }

                _ = tokio::time::sleep(timeout) => {
                    conn.on_timeout();
                }
            }

            let stream_ids: Vec<u64> = session_streams.keys().copied().collect();
            for stream_id in stream_ids {
                if let Some(session) = session_streams.get_mut(&stream_id)
                    && let Err(error) = read_from_tcp_to_quic(&mut conn, stream_id, session).await
                {
                    trace!(stream_id, %error, "TCP side finished");
                    session_streams.remove(&stream_id);
                }
            }

            flush_outbound_packets(&mut conn, &socket, &mut send_buf).await?;

            if conn.is_closed() {
                warn!("QUIC connection closed");
                break;
            }
        }

        if !conn.is_closed() {
            let _ = conn.close(true, 0x00, b"shutting down");
            flush_outbound_packets(&mut conn, &socket, &mut send_buf).await?;
        }

        info!("Tunnel task stopped");
        Ok(())
    }
}

async fn complete_handshake(
    socket: &tokio::net::UdpSocket,
    conn: &mut quiche::Connection,
    peer_addr: SocketAddr,
    send_buf: &mut [u8],
) -> Result<()> {
    let mut recv_buf = vec![0u8; 65535];
    let local_addr = socket.local_addr()?;

    while !conn.is_established() {
        flush_outbound_packets(conn, socket, send_buf).await?;

        let timeout = conn.timeout().unwrap_or(Duration::from_secs(5));
        let result = tokio::time::timeout(timeout, socket.recv_from(&mut recv_buf)).await;

        match result {
            Ok(Ok((len, from))) => {
                if from == peer_addr {
                    let recv_info = quiche::RecvInfo { from, to: local_addr };
                    conn.recv(&mut recv_buf[..len], recv_info)?;
                }
            }
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => conn.on_timeout(),
        }

        if conn.is_closed() {
            bail!("QUIC connection closed during handshake");
        }
    }

    Ok(())
}

async fn send_control_message(
    conn: &mut quiche::Connection,
    socket: &tokio::net::UdpSocket,
    _peer_addr: SocketAddr,
    message: &ControlMessage,
    send_buf: &mut [u8],
) -> Result<()> {
    let mut encoded = Vec::new();
    message
        .encode(&mut encoded)
        .await
        .context("failed to encode control message")?;

    send_all_stream_data(conn, socket, 0, &encoded, send_buf)
        .await
        .context("failed to send control message")?;

    Ok(())
}

async fn handle_control_stream(conn: &mut quiche::Connection, stream_id: u64, control_buf: &mut Vec<u8>) -> Result<()> {
    read_stream_into_buffer(conn, stream_id, control_buf)?;

    while let Some((message, consumed)) = try_decode_length_prefixed::<ControlMessage>(control_buf)? {
        control_buf.drain(..consumed);

        match message {
            ControlMessage::HeartbeatAck { timestamp_ms, .. } => {
                let rtt = current_time_millis().saturating_sub(timestamp_ms);
                debug!(rtt_ms = rtt, "Received HeartbeatAck");
            }
            unexpected => {
                warn!(message = ?unexpected, "Unexpected control message from gateway");
            }
        }
    }

    Ok(())
}

async fn handle_pending_session_stream(
    conn: &mut quiche::Connection,
    stream_id: u64,
    pending_buf: &mut Vec<u8>,
    advertise_subnets: &[Ipv4Network],
    send_buf: &mut [u8],
    socket: &tokio::net::UdpSocket,
) -> Result<Option<SessionStream>> {
    let fin = read_stream_into_buffer(conn, stream_id, pending_buf)?;

    let Some((connect_msg, consumed)) = try_decode_length_prefixed::<ConnectMessage>(pending_buf)? else {
        if fin {
            bail!("session stream closed before ConnectMessage was fully received");
        }

        return Ok(None);
    };

    let leftover = pending_buf[consumed..].to_vec();
    pending_buf.clear();

    let session = start_session_stream(
        conn,
        stream_id,
        connect_msg,
        leftover,
        advertise_subnets,
        send_buf,
        socket,
    )
    .await?;

    Ok(Some(session))
}

async fn start_session_stream(
    conn: &mut quiche::Connection,
    stream_id: u64,
    connect_msg: ConnectMessage,
    initial_payload: Vec<u8>,
    advertise_subnets: &[Ipv4Network],
    send_buf: &mut [u8],
    socket: &tokio::net::UdpSocket,
) -> Result<SessionStream> {
    info!(
        stream_id,
        session_id = %connect_msg.session_id,
        target = %connect_msg.target,
        "Received ConnectMessage"
    );

    let target_candidates = resolve_target_candidates(&connect_msg.target, advertise_subnets)
        .await
        .with_context(|| format!("resolve target {}", connect_msg.target))?;

    let (tcp_stream, selected_target) = connect_to_target(&target_candidates)
        .await
        .with_context(|| format!("connect to target {}", connect_msg.target))?;

    info!(stream_id, target = %selected_target, "TCP connection established");

    let response = ConnectResponse::success();
    send_connect_response(conn, socket, stream_id, &response, send_buf)
        .await
        .context("send ConnectResponse")?;

    let (quic_to_tcp_tx, quic_to_tcp_rx) = mpsc::channel::<Vec<u8>>(32);
    let (tcp_to_quic_tx, tcp_to_quic_rx) = mpsc::channel::<Vec<u8>>(32);

    if !initial_payload.is_empty() {
        quic_to_tcp_tx
            .send(initial_payload)
            .await
            .context("forward initial session payload")?;
    }

    let task_handle = tokio::spawn(async move {
        if let Err(error) = tcp_proxy_task(tcp_stream, quic_to_tcp_rx, tcp_to_quic_tx).await {
            debug!(stream_id, %error, "TCP proxy task ended");
        }
    });

    Ok(SessionStream {
        tcp_to_quic_rx,
        quic_to_tcp_tx,
        _task_handle: task_handle,
        pending_quic_writes: VecDeque::new(),
        finish_quic_write: false,
    })
}

async fn send_connect_response(
    conn: &mut quiche::Connection,
    socket: &tokio::net::UdpSocket,
    stream_id: u64,
    response: &ConnectResponse,
    send_buf: &mut [u8],
) -> Result<()> {
    let mut encoded = Vec::new();
    response
        .encode(&mut encoded)
        .await
        .context("failed to encode ConnectResponse")?;

    send_all_stream_data(conn, socket, stream_id, &encoded, send_buf)
        .await
        .context("failed to send ConnectResponse")?;

    Ok(())
}

async fn send_all_stream_data(
    conn: &mut quiche::Connection,
    socket: &tokio::net::UdpSocket,
    stream_id: u64,
    data: &[u8],
    send_buf: &mut [u8],
) -> Result<()> {
    let mut offset = 0;

    while offset < data.len() {
        match conn.stream_send(stream_id, &data[offset..], false) {
            Ok(written) => {
                offset += written;
                if offset < data.len() {
                    flush_outbound_packets(conn, socket, send_buf).await?;
                }
            }
            Err(quiche::Error::Done) => {
                flush_outbound_packets(conn, socket, send_buf).await?;
                tokio::task::yield_now().await;
            }
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}

fn read_stream_into_buffer(conn: &mut quiche::Connection, stream_id: u64, buffer: &mut Vec<u8>) -> Result<bool> {
    let mut temp = vec![0u8; 65535];
    let mut fin = false;

    loop {
        match conn.stream_recv(stream_id, &mut temp) {
            Ok((len, stream_fin)) => {
                if len > 0 {
                    buffer.extend_from_slice(&temp[..len]);
                }

                fin |= stream_fin;

                if len == 0 {
                    break;
                }
            }
            Err(quiche::Error::Done) => break,
            Err(error) => return Err(error.into()),
        }
    }

    Ok(fin)
}

fn try_decode_length_prefixed<T>(buffer: &[u8]) -> Result<Option<(T, usize)>>
where
    T: DeserializeOwned,
{
    if buffer.len() < 4 {
        return Ok(None);
    }

    let message_len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    if buffer.len() < 4 + message_len {
        return Ok(None);
    }

    let message = bincode::deserialize::<T>(&buffer[4..4 + message_len]).context("deserialize framed message")?;
    Ok(Some((message, 4 + message_len)))
}

async fn resolve_target_candidates(target: &str, advertise_subnets: &[Ipv4Network]) -> Result<Vec<SocketAddr>> {
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host(target)
        .await
        .with_context(|| format!("resolve target {target}"))?
        .collect();

    if resolved.is_empty() {
        bail!("no addresses resolved for target {target}");
    }

    let reachable: Vec<SocketAddr> = resolved
        .into_iter()
        .filter(|addr| match addr.ip() {
            std::net::IpAddr::V4(ipv4) => advertise_subnets.iter().any(|subnet| subnet.contains(ipv4)),
            std::net::IpAddr::V6(_) => false,
        })
        .collect();

    if reachable.is_empty() {
        bail!("target {target} is not in advertised subnets");
    }

    Ok(reachable)
}

async fn connect_to_target(candidates: &[SocketAddr]) -> Result<(TcpStream, SocketAddr)> {
    let mut last_error = None;

    for candidate in candidates {
        match TcpStream::connect(candidate).await {
            Ok(stream) => return Ok((stream, *candidate)),
            Err(error) => last_error = Some((candidate, error)),
        }
    }

    let Some((candidate, error)) = last_error else {
        bail!("no target candidates available");
    };

    Err(error).with_context(|| format!("TCP connect failed for {candidate}"))
}

async fn read_from_quic_to_tcp(
    conn: &mut quiche::Connection,
    stream_id: u64,
    session: &mut SessionStream,
) -> Result<()> {
    let mut temp = vec![0u8; 65535];

    loop {
        match conn.stream_recv(stream_id, &mut temp) {
            Ok((len, fin)) => {
                if len > 0 {
                    session
                        .quic_to_tcp_tx
                        .send(temp[..len].to_vec())
                        .await
                        .context("failed to send data to TCP task")?;
                }

                if fin {
                    return Err(anyhow::anyhow!("QUIC stream finished"));
                }

                if len == 0 {
                    break;
                }
            }
            Err(quiche::Error::Done) => break,
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}

async fn read_from_tcp_to_quic(
    conn: &mut quiche::Connection,
    stream_id: u64,
    session: &mut SessionStream,
) -> Result<()> {
    flush_session_writes(conn, stream_id, session)?;

    while session.pending_quic_writes.is_empty() {
        match session.tcp_to_quic_rx.try_recv() {
            Ok(data) => {
                if !data.is_empty() {
                    session.pending_quic_writes.push_back(data);
                    flush_session_writes(conn, stream_id, session)?;
                }
            }
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                session.finish_quic_write = true;
                break;
            }
        }
    }

    flush_session_writes(conn, stream_id, session)?;

    if session.finish_quic_write && session.pending_quic_writes.is_empty() {
        match conn.stream_send(stream_id, b"", true) {
            Ok(_) => return Err(anyhow::anyhow!("TCP task ended")),
            Err(quiche::Error::Done) => {}
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}

fn flush_session_writes(conn: &mut quiche::Connection, stream_id: u64, session: &mut SessionStream) -> Result<()> {
    while let Some(chunk) = session.pending_quic_writes.front_mut() {
        match conn.stream_send(stream_id, chunk, false) {
            Ok(written) => {
                if written >= chunk.len() {
                    session.pending_quic_writes.pop_front();
                } else {
                    let remainder = chunk[written..].to_vec();
                    *chunk = remainder;
                    break;
                }
            }
            Err(quiche::Error::Done) => break,
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}

async fn tcp_proxy_task(
    mut tcp_stream: TcpStream,
    mut quic_to_tcp_rx: mpsc::Receiver<Vec<u8>>,
    tcp_to_quic_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp_stream.split();

    let read_task = async {
        let mut buf = vec![0u8; 65535];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(read) => {
                    if tcp_to_quic_tx.send(buf[..read].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(error) => {
                    error!(%error, "TCP read error");
                    break;
                }
            }
        }
    };

    let write_task = async {
        while let Some(data) = quic_to_tcp_rx.recv().await {
            if let Err(error) = tcp_write.write_all(&data).await {
                error!(%error, "TCP write error");
                break;
            }
        }
    };

    tokio::select! {
        _ = read_task => {}
        _ = write_task => {}
    }

    Ok(())
}

async fn flush_outbound_packets(
    conn: &mut quiche::Connection,
    socket: &tokio::net::UdpSocket,
    send_buf: &mut [u8],
) -> Result<()> {
    loop {
        match conn.send(send_buf) {
            Ok((len, send_info)) => {
                socket.send_to(&send_buf[..len], send_info.to).await?;
            }
            Err(quiche::Error::Done) => break,
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}

fn current_time_millis() -> u64 {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after unix epoch");

    u64::try_from(elapsed.as_millis()).expect("millisecond timestamp should fit in u64")
}
