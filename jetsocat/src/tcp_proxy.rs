use anyhow::{anyhow, Context as _, Result};
use slog::{debug, o, Logger};
use std::net::SocketAddr;
use tokio::{net::TcpStream, pin};
use uuid::Uuid;
use futures_util::FutureExt;

#[derive(Debug)]
pub struct TcpProxyCmd {
    pub source_addr: String,
    pub association_id: String,
    pub candidate_id: String,
}

struct TcpServer {
    source_addr: SocketAddr,
    jet_listener_addr: SocketAddr,
    association_id: uuid::Uuid,
    candidate_id: uuid::Uuid,
}

impl TcpServer {
    pub fn new(
        source_addr: SocketAddr,
        jet_listener_addr: SocketAddr,
        association_id: uuid::Uuid,
        candidate_id: uuid::Uuid
    ) -> Self {
        Self {
            source_addr,
            jet_listener_addr,
            association_id,
            candidate_id,
        }
    }

    pub async fn serve(self, log: Logger) -> Result<()> {
        debug!(log, "Performing rendezvous connect...");

        loop
        {
            let mut jet_server_stream = TcpStream::connect(self.jet_listener_addr).await?;
            let server_stream = TcpStream::connect(self.source_addr).await?;

            let log = log.clone();

            debug!(log, "Sending jet accept request...");

            self.send_jet_accept_request(&mut jet_server_stream).await?;
            self.process_jet_accept_response(&mut jet_server_stream).await?;

            debug!(log, "Starting tcp forwarding...");

            run_proxy(jet_server_stream, server_stream, log).await?
        }
    }
    async fn send_jet_accept_request(&self, jet_server_stream: &mut TcpStream) -> Result<()> {
        use jet_proto::{accept::JetAcceptReq, JetMessage};
        use tokio::io::AsyncWriteExt;

        let jet_accept_request = JetMessage::JetAcceptReq(JetAcceptReq {
            version: 2,
            host: "jetsocat".to_string(),
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
    use futures_util::select;

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

    let client_to_server = read_and_write(&mut client_read_half, &mut server_write_half, client_server_logger).fuse();
    let server_to_client = read_and_write(&mut server_read_half, &mut client_write_half, server_client_logger).fuse();

    pin!(client_to_server);
    pin!(server_to_client);


    select! {
            result = client_to_server => {
                match result {
                    Ok(()) =>  {
                        // Detected
                        println!("client_to_server disconnected gracefully");
                    }
                    Err(e) => {
                        println!("client_to_server disconnected with error: {}", e);
                    }
                }
            },
            result = server_to_client => {
                match result {
                    Ok(()) =>  {
                        println!("server_to_client disconnected gracefully");
                    }
                    Err(e) => {
                        println!("server_to_client disconnected with error: {}", e);
                    }
                }
            },
        };

    Ok(())

    /*
    join!(client_to_server, server_to_client)
        .map(|_| ())
        .map_err(|e| anyhow!("tcp proxy failed: {}", e))
     */
}

pub async fn proxy(addr: String, cmd: TcpProxyCmd, log: slog::Logger) -> Result<()> {
    let jet_listener_addr = crate::utils::resolve_url_to_tcp_socket_addr(addr).await?;
    let source_addr = cmd.source_addr
        .parse()
        .with_context(|| format!("Invalid source addr {}", cmd.source_addr))?;

    let association_id = Uuid::parse_str(&cmd.association_id)
        .with_context(|| "Failed to parse jet association id")?;

    let candidate_id = Uuid::parse_str(&cmd.candidate_id)
        .with_context(|| "Failed to parse jet candidate id")?;

    TcpServer::new(source_addr, jet_listener_addr, association_id, candidate_id)
        .serve(log).await
}
