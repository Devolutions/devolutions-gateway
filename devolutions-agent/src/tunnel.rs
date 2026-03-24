//! QUIC-based Agent Tunnel client implementation.
//!
//! This module implements a QUIC client that connects to the Gateway's agent tunnel
//! endpoint, advertises reachable subnets, and handles incoming TCP proxy requests.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use agent_tunnel_proto::{ConnectMessage, ConnectResponse, ControlMessage};
use anyhow::{Context as _, Result};
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use ipnetwork::Ipv4Network;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::config::ConfHandle;

/// 会话流状态
struct SessionStream {
    #[allow(dead_code)]
    stream_id: u64,
    /// 从 TCP 任务接收数据，发送到 QUIC
    tcp_to_quic_rx: mpsc::Receiver<Vec<u8>>,
    /// 发送数据到 TCP 任务
    quic_to_tcp_tx: mpsc::Sender<Vec<u8>>,
    /// TCP 任务句柄
    #[allow(dead_code)]
    task_handle: tokio::task::JoinHandle<()>,
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

        // 加载证书
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

        // 解析子网
        let advertise_subnets: Vec<Ipv4Network> = tunnel_conf
            .advertise_subnets
            .iter()
            .map(|s| s.parse())
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse advertise_subnets")?;

        if advertise_subnets.is_empty() {
            warn!("No subnets configured to advertise");
        }

        // 配置 quiche
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

        // 连接到 Gateway
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

        // 生成随机 connection ID
        let mut scid = vec![0u8; quiche::MAX_CONN_ID_LEN];
        rand::Rng::fill(&mut rand::thread_rng(), &mut scid[..]);

        let scid = quiche::ConnectionId::from_vec(scid);

        let mut conn = quiche::connect(None, &scid, local_addr, gateway_addr, &mut quiche_config)
            .context("failed to create QUIC connection")?;

        // 完成握手
        complete_handshake(&socket, &mut conn, gateway_addr).await?;
        info!("QUIC connection established");

        // 打开控制流（stream 0）并发送初始数据
        // 注意：在 quiche 中，客户端发起的双向流从 0 开始
        // 控制流是 stream 0

        // 定期任务间隔
        let route_advertise_interval_secs = tunnel_conf.route_advertise_interval_secs.unwrap_or(30);
        let heartbeat_interval_secs = tunnel_conf.heartbeat_interval_secs.unwrap_or(60);

        let mut route_advertise_interval = tokio::time::interval(Duration::from_secs(route_advertise_interval_secs));
        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(heartbeat_interval_secs));

        // 跳过第一次 tick（立即执行）
        route_advertise_interval.tick().await;
        heartbeat_interval.tick().await;

        let mut recv_buf = vec![0u8; 65535];
        let mut send_buf = vec![0u8; 65535];

        let mut epoch = 0u64;
        let mut session_streams: HashMap<u64, SessionStream> = HashMap::new();

        // 立即发送 RouteAdvertise
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

        // 主事件循环
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
                    let msg = ControlMessage::route_advertise(epoch, advertise_subnets.clone());
                    if let Err(e) = send_control_message(&mut conn, &socket, gateway_addr, &msg, &mut send_buf).await {
                        error!(error = %e, "Failed to send RouteAdvertise");
                    } else {
                        trace!(epoch, "Sent RouteAdvertise");
                    }
                }

                _ = heartbeat_interval.tick() => {
                    let timestamp_ms = current_time_millis();
                    let active_stream_count =
                        u32::try_from(session_streams.len()).expect("active session stream count should fit in u32");
                    let msg = ControlMessage::heartbeat(timestamp_ms, active_stream_count);
                    if let Err(e) = send_control_message(&mut conn, &socket, gateway_addr, &msg, &mut send_buf).await {
                        error!(error = %e, "Failed to send Heartbeat");
                    } else {
                        trace!(active_streams = active_stream_count, "Sent Heartbeat");
                    }
                }

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

                    if let Err(e) = conn.recv(&mut recv_buf[..len], recv_info) {
                        error!(error = %e, "Failed to process received packet");
                        continue;
                    }

                    // 处理可读流
                    for stream_id in conn.readable() {
                        if stream_id == 0 {
                            // 控制流
                            if let Err(e) = handle_control_stream(&mut conn, stream_id).await {
                                error!(error = %e, "Failed to handle control stream");
                            }
                        } else {
                            // 会话流
                            if let std::collections::hash_map::Entry::Vacant(entry) = session_streams.entry(stream_id) {
                                // 新会话流，读取 ConnectMessage
                                match handle_new_session_stream(&mut conn, stream_id, &advertise_subnets).await {
                                    Ok(session) => {
                                        info!(stream_id, "Session stream started");
                                        entry.insert(session);
                                    }
                                    Err(e) => {
                                        error!(stream_id, error = %e, "Failed to start session stream");
                                    }
                                }
                            } else {
                                // 现有会话流，读取数据并转发到 TCP
                                if let Some(session) = session_streams.get_mut(&stream_id)
                                    && let Err(e) = read_from_quic_to_tcp(&mut conn, stream_id, session).await
                                {
                                    error!(stream_id, error = %e, "Failed to read from QUIC stream");
                                    session_streams.remove(&stream_id);
                                }
                            }
                        }
                    }

                    // 从 TCP 读取数据并写入 QUIC 流
                    let stream_ids: Vec<u64> = session_streams.keys().copied().collect();
                    for stream_id in stream_ids {
                        if let Some(session) = session_streams.get_mut(&stream_id)
                            && let Err(e) = read_from_tcp_to_quic(&mut conn, stream_id, session).await
                        {
                            trace!(stream_id, error = %e, "Session stream closed");
                            session_streams.remove(&stream_id);
                        }
                    }

                    // 发送待发送的数据
                    while let Ok((len, send_info)) = conn.send(&mut send_buf) {
                        if let Err(e) = socket.send_to(&send_buf[..len], send_info.to).await {
                            error!(error = %e, "Failed to send packet");
                            break;
                        }
                    }
                }

                _ = tokio::time::sleep(timeout) => {
                    conn.on_timeout();
                    while let Ok((len, send_info)) = conn.send(&mut send_buf) {
                        if let Err(e) = socket.send_to(&send_buf[..len], send_info.to).await {
                            error!(error = %e, "Failed to send packet on timeout");
                            break;
                        }
                    }
                }
            }

            // 检查连接状态
            if conn.is_closed() {
                warn!("QUIC connection closed");
                break;
            }
        }

        // 优雅关闭
        if !conn.is_closed() {
            let _ = conn.close(true, 0x00, b"shutting down");
            while let Ok((len, send_info)) = conn.send(&mut send_buf) {
                let _ = socket.send_to(&send_buf[..len], send_info.to).await;
            }
        }

        info!("Tunnel task stopped");
        Ok(())
    }
}

/// 完成 QUIC 握手
async fn complete_handshake(
    socket: &tokio::net::UdpSocket,
    conn: &mut quiche::Connection,
    peer_addr: SocketAddr,
) -> Result<()> {
    let mut recv_buf = vec![0u8; 65535];
    let mut send_buf = vec![0u8; 65535];
    let local_addr = socket.local_addr()?;

    while !conn.is_established() {
        // 发送握手数据
        while let Ok((len, send_info)) = conn.send(&mut send_buf) {
            socket.send_to(&send_buf[..len], send_info.to).await?;
        }

        // 接收握手响应
        let timeout = conn.timeout().unwrap_or(Duration::from_secs(5));
        let result = tokio::time::timeout(timeout, socket.recv_from(&mut recv_buf)).await;

        match result {
            Ok(Ok((len, from))) => {
                if from == peer_addr {
                    let recv_info = quiche::RecvInfo { from, to: local_addr };
                    conn.recv(&mut recv_buf[..len], recv_info)?;
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                // 超时，触发 on_timeout
                conn.on_timeout();
            }
        }

        if conn.is_closed() {
            anyhow::bail!("QUIC connection closed during handshake");
        }
    }

    Ok(())
}

/// 通过控制流发送消息
async fn send_control_message(
    conn: &mut quiche::Connection,
    socket: &tokio::net::UdpSocket,
    _peer_addr: SocketAddr,
    msg: &ControlMessage,
    send_buf: &mut [u8],
) -> Result<()> {
    // 编码消息
    let mut encoded_buf = Vec::new();
    msg.encode(&mut encoded_buf)
        .await
        .context("failed to encode control message")?;

    // 发送到 stream 0
    let written = conn
        .stream_send(0, &encoded_buf, false)
        .context("failed to send on control stream")?;

    if written != encoded_buf.len() {
        anyhow::bail!(
            "incomplete control message send: {} of {} bytes",
            written,
            encoded_buf.len()
        );
    }

    // 发送数据包
    while let Ok((len, send_info)) = conn.send(send_buf) {
        socket.send_to(&send_buf[..len], send_info.to).await?;
    }

    Ok(())
}

/// 处理控制流消息
async fn handle_control_stream(conn: &mut quiche::Connection, stream_id: u64) -> Result<()> {
    let mut buf = vec![0u8; 65535];

    loop {
        match conn.stream_recv(stream_id, &mut buf) {
            Ok((len, _fin)) => {
                if len == 0 {
                    break;
                }

                // 尝试解码消息
                let msg = ControlMessage::decode(&mut &buf[..len])
                    .await
                    .context("failed to decode control message")?;

                match msg {
                    ControlMessage::HeartbeatAck { timestamp_ms, .. } => {
                        let rtt = current_time_millis().saturating_sub(timestamp_ms);
                        debug!(rtt_ms = rtt, "Received HeartbeatAck");
                    }
                    other => {
                        warn!(msg = ?other, "Unexpected control message from gateway");
                    }
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

/// 获取当前时间戳（毫秒）
fn current_time_millis() -> u64 {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after unix epoch");

    u64::try_from(elapsed.as_millis()).expect("millisecond timestamp should fit in u64")
}

/// 处理新会话流：读取 ConnectMessage，建立 TCP 连接，启动代理任务
async fn handle_new_session_stream(
    conn: &mut quiche::Connection,
    stream_id: u64,
    advertise_subnets: &[Ipv4Network],
) -> Result<SessionStream> {
    // 读取 ConnectMessage
    let mut buf = vec![0u8; 65535];
    let (len, _fin) = conn
        .stream_recv(stream_id, &mut buf)
        .context("failed to read from session stream")?;

    let connect_msg = ConnectMessage::decode(&mut &buf[..len])
        .await
        .context("failed to decode ConnectMessage")?;

    info!(
        stream_id,
        session_id = %connect_msg.session_id,
        target = %connect_msg.target,
        "Received ConnectMessage"
    );

    // 验证目标地址格式
    let target_addr: SocketAddr = connect_msg.target.parse().context("invalid target address format")?;

    // 验证目标在 advertise_subnets 中
    let can_reach = advertise_subnets.iter().any(|subnet| {
        if let std::net::IpAddr::V4(ip) = target_addr.ip() {
            subnet.contains(ip)
        } else {
            false
        }
    });

    if !can_reach {
        let error_msg = format!("Target {} not in advertised subnets", connect_msg.target);
        warn!(stream_id, target = %connect_msg.target, "Target not reachable");

        // 发送错误响应
        let response = ConnectResponse::error(&error_msg);
        send_connect_response(conn, stream_id, &response).await?;

        anyhow::bail!(error_msg);
    }

    // 建立 TCP 连接
    let tcp_stream = match TcpStream::connect(&target_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            let error_msg = format!("TCP connect failed: {}", e);
            error!(stream_id, target = %target_addr, error = %e, "Failed to connect to target");

            // 发送错误响应
            let response = ConnectResponse::error(&error_msg);
            send_connect_response(conn, stream_id, &response).await?;

            return Err(e.into());
        }
    };

    info!(stream_id, target = %target_addr, "TCP connection established");

    // 发送成功响应
    let response = ConnectResponse::success();
    send_connect_response(conn, stream_id, &response).await?;

    // 创建通道用于 TCP 任务通信
    let (quic_to_tcp_tx, quic_to_tcp_rx) = mpsc::channel::<Vec<u8>>(32);
    let (tcp_to_quic_tx, tcp_to_quic_rx) = mpsc::channel::<Vec<u8>>(32);

    // 启动 TCP 代理任务
    let task_handle = tokio::spawn(async move {
        if let Err(e) = tcp_proxy_task(tcp_stream, quic_to_tcp_rx, tcp_to_quic_tx).await {
            debug!(stream_id, error = %e, "TCP proxy task ended");
        }
    });

    Ok(SessionStream {
        stream_id,
        tcp_to_quic_rx,
        quic_to_tcp_tx,
        task_handle,
    })
}

/// 发送 ConnectResponse 到 QUIC 流
async fn send_connect_response(
    conn: &mut quiche::Connection,
    stream_id: u64,
    response: &ConnectResponse,
) -> Result<()> {
    let mut encoded_buf = Vec::new();
    response
        .encode(&mut encoded_buf)
        .await
        .context("failed to encode ConnectResponse")?;

    let written = conn
        .stream_send(stream_id, &encoded_buf, false)
        .context("failed to send ConnectResponse")?;

    if written != encoded_buf.len() {
        anyhow::bail!(
            "incomplete ConnectResponse send: {} of {} bytes",
            written,
            encoded_buf.len()
        );
    }

    Ok(())
}

/// 从 QUIC 流读取数据并发送到 TCP 任务
async fn read_from_quic_to_tcp(
    conn: &mut quiche::Connection,
    stream_id: u64,
    session: &mut SessionStream,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];

    loop {
        match conn.stream_recv(stream_id, &mut buf) {
            Ok((len, fin)) => {
                if len > 0 {
                    // 发送到 TCP 任务
                    session
                        .quic_to_tcp_tx
                        .send(buf[..len].to_vec())
                        .await
                        .context("failed to send data to TCP task")?;
                }

                if fin {
                    // 流结束，关闭 TCP 写入
                    drop(session.quic_to_tcp_tx.clone());
                    return Err(anyhow::anyhow!("QUIC stream finished"));
                }

                if len == 0 {
                    break;
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

/// 从 TCP 任务读取数据并写入 QUIC 流
async fn read_from_tcp_to_quic(
    conn: &mut quiche::Connection,
    stream_id: u64,
    session: &mut SessionStream,
) -> Result<()> {
    // 非阻塞地尝试接收 TCP 数据
    match session.tcp_to_quic_rx.try_recv() {
        Ok(data) => {
            // 写入 QUIC 流
            let written = conn
                .stream_send(stream_id, &data, false)
                .context("failed to write to QUIC stream")?;

            if written != data.len() {
                // 数据没有完全写入，这在 QUIC 中可能发生（流控）
                // 为简化，我们暂时忽略这个问题
                warn!(stream_id, written, total = data.len(), "Partial write to QUIC stream");
            }

            Ok(())
        }
        Err(mpsc::error::TryRecvError::Empty) => Ok(()),
        Err(mpsc::error::TryRecvError::Disconnected) => {
            // TCP 任务结束，发送 FIN
            conn.stream_send(stream_id, b"", true).context("failed to send FIN")?;
            Err(anyhow::anyhow!("TCP task ended"))
        }
    }
}

/// TCP 代理任务：双向转发 TCP 数据
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
                Ok(0) => break, // EOF
                Ok(n) => {
                    if tcp_to_quic_tx.send(buf[..n].to_vec()).await.is_err() {
                        break; // 通道关闭
                    }
                }
                Err(e) => {
                    error!(error = %e, "TCP read error");
                    break;
                }
            }
        }
    };

    let write_task = async {
        while let Some(data) = quic_to_tcp_rx.recv().await {
            if let Err(e) = tcp_write.write_all(&data).await {
                error!(error = %e, "TCP write error");
                break;
            }
        }
    };

    tokio::select! {
        _ = read_task => {},
        _ = write_task => {},
    }

    Ok(())
}
