use crate::{
    pipe::{pipe_with_ws, PipeCmd},
    proxy::ProxyConfig,
};
use anyhow::{anyhow, Context as _, Result};
use slog::{debug, error, info, o, Logger};
use std::net::SocketAddr;
use tokio::net::TcpStream;

const TCP_ROUTING_HOST_SCHEME: &str = "tcp";

pub struct TcpServer {
    pub association_id: uuid::Uuid,
    pub candidate_id: uuid::Uuid,
    pub listener_url: SocketAddr,
    pub routing_socket: SocketAddr,
}

impl TcpServer {
    pub async fn serve(self, log: Logger) -> Result<()> {
        info!(log, "Staring proxy");

        let mut jet_server_stream = TcpStream::connect(self.listener_url).await?;
        let server_stream = TcpStream::connect(self.routing_socket).await?;

        let log = log.clone();

        self.send_jet_accept_request(&mut jet_server_stream).await?;
        self.process_jet_accept_response(&mut jet_server_stream).await?;

        run_proxy(jet_server_stream, server_stream, log).await?;

        Ok(())
    }
    async fn send_jet_accept_request(&self, jet_server_stream: &mut TcpStream) -> Result<()> {
        use jet_proto::{accept::JetAcceptReq, JetMessage};
        use tokio::io::AsyncWriteExt;

        let jet_accept_request = JetMessage::JetAcceptReq(JetAcceptReq {
            version: 2,
            host: self.listener_url.to_string(),
            association: self.association_id,
            candidate: self.candidate_id,
        });

        let mut buffer: Vec<u8> = Vec::new();
        jet_accept_request.write_to(&mut buffer)?;
        jet_server_stream.write_all(&buffer).await?;

        Ok(())
    }

    async fn process_jet_accept_response(&self, jet_server_stream: &mut TcpStream) -> Result<()> {
        use jet_proto::JetMessage;
        use tokio::io::AsyncReadExt;

        let mut buffer = [0u8; 1024];

        let read_bytes_count = jet_server_stream.read(&mut buffer).await?;

        if read_bytes_count == 0 {
            return Err(anyhow!("Failed to read JetConnectResponse"));
        }

        let mut buffer: &[u8] = &buffer[0..read_bytes_count];
        let response = JetMessage::read_accept_response(&mut buffer)?;
        match response {
            JetMessage::JetAcceptRsp(rsp) => {
                if rsp.status_code != 200 {
                    return Err(anyhow!("Devolutions-Gateway sent bad accept response"));
                }
                Ok(())
            }
            other_message => {
                return Err(anyhow!(
                    "Devolutions-Gateway sent {:?} message instead of JetAcceptRsp",
                    other_message
                ))
            }
        }
    }
}

async fn run_proxy(jet_server_stream: TcpStream, tcp_server_transport: TcpStream, log: Logger) -> Result<()> {
    use crate::io::read_and_write;
    use futures_util::try_join;

    debug!(
        log,
        "{}",
        format!(
            "Running proxy. JetServer {}, TcpServer on {}.",
            jet_server_stream.peer_addr().unwrap(),
            tcp_server_transport.peer_addr().unwrap()
        )
    );

    let (mut client_read_half, mut client_write_half) = jet_server_stream.into_split();
    let (mut server_read_half, mut server_write_half) = tcp_server_transport.into_split();

    let client_server_logger = log.new(o!("client" => " -> server"));
    let server_client_logger = log.new(o!("client" => " <- server"));

    let client_to_server = read_and_write(&mut client_read_half, &mut server_write_half, client_server_logger);
    let server_to_client = read_and_write(&mut server_read_half, &mut client_write_half, server_client_logger);

    if let Err(e) = try_join!(client_to_server, server_to_client) {
        error!(log, "tcp proxy failed: {}", e);
    }

    Ok(())
}

pub fn resolve_url_to_tcp_socket_addr(listener_url: String) -> Result<SocketAddr> {
    use url::Url;

    let url = Url::parse(&listener_url)?;

    if url.scheme() != TCP_ROUTING_HOST_SCHEME {
        return Err(anyhow!("Incorrect routing host scheme, it should start with `tcp://`"));
    }

    if !url.path().is_empty() {
        return Err(anyhow!("Incorrect Url: Url should have empty path"));
    }

    if url.port().is_none() {
        return Err(anyhow!("Incorrect Url: Port is missing"));
    }

    let socket_addrs = url.socket_addrs(|| None)?;
    let socket_addr = socket_addrs.first().unwrap();

    Ok(*socket_addr)
}

pub async fn accept(addr: String, pipe: PipeCmd, proxy_cfg: Option<ProxyConfig>, log: slog::Logger) -> Result<()> {
    use crate::utils::ws_connect_async;

    let accept_log = log.new(o!("accept" => addr.clone()));

    debug!(accept_log, "Connecting");
    let (ws_stream, rsp) = ws_connect_async(addr, proxy_cfg).await?;
    debug!(accept_log, "Connected: {:?}", rsp);

    pipe_with_ws(ws_stream, pipe, accept_log)
        .await
        .with_context(|| "Failed to pipe")?;

    Ok(())
}

pub async fn listen(addr: String, pipe: PipeCmd, log: slog::Logger) -> Result<()> {
    use async_tungstenite::tokio::accept_async;
    use tokio::net::TcpListener;

    let listen_log = log.new(o!("listen" => addr.clone()));
    debug!(listen_log, "Bind listener");
    let listener = TcpListener::bind(addr).await?;
    debug!(listen_log, "Ready to accept");

    let (socket, peer_addr) = listener.accept().await?;
    let peer_log = listen_log.new(o!("peer" => peer_addr));
    debug!(peer_log, "Connected to {}", peer_addr);

    let ws_stream = accept_async(socket).await?;

    pipe_with_ws(ws_stream, pipe, peer_log)
        .await
        .with_context(|| "Failed to pipe")?;

    Ok(())
}
