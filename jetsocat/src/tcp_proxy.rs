use anyhow::{anyhow, Context as _, Result};
use futures_util::FutureExt;
use jet_proto::JET_VERSION_V2;
use slog::{debug, o, Logger};
use tokio::pin;
use uuid::Uuid;
use jetsocat_proxy::{DestAddr, ToDestAddr};
use crate::{
    proxy::ProxyConfig,
    utils::{AsyncStream, tcp_connect_async},
};

pub struct JetTcpAcceptCmd {
    pub forward_addr: String,
    pub association_id: String,
    pub candidate_id: String,
    pub max_reconnection_count: usize,
}

struct TcpServer {
    forward_addr: DestAddr,
    jet_listener_addr: DestAddr,
    association_id: uuid::Uuid,
    candidate_id: uuid::Uuid,
    max_reconnection_count: usize,
    proxy_cfg: Option<ProxyConfig>,
}

impl TcpServer {
    pub fn new(
        forward_addr: DestAddr,
        jet_listener_addr: DestAddr,
        association_id: uuid::Uuid,
        candidate_id: uuid::Uuid,
        max_reconnection_count: usize,
        proxy_cfg: Option<ProxyConfig>,
    ) -> Self {
        Self {
            forward_addr,
            jet_listener_addr,
            association_id,
            candidate_id,
            max_reconnection_count,
            proxy_cfg,
        }
    }

    pub async fn serve(self, log: Logger) -> Result<()> {
        debug!(log, "Performing rendezvous connect...");

        for _ in 0..=self.max_reconnection_count {


            let mut jet_server_stream =
                tcp_connect_async(&self.jet_listener_addr, self.proxy_cfg.clone()).await?;
            // forward_addr points to local machine/network, proxy should be ignored
            let server_stream =
                tcp_connect_async(&self.forward_addr, None).await?;

            let log = log.clone();

            debug!(log, "Sending jet accept request...");

            self.send_jet_accept_request(&mut jet_server_stream).await?;
            self.process_jet_accept_response(&mut jet_server_stream).await?;

            debug!(log, "Starting tcp forwarding...");

            run_proxy(jet_server_stream, server_stream, log).await?;
        }

        Ok(())
    }

    async fn send_jet_accept_request(&self, jet_server_stream: &mut AsyncStream) -> Result<()> {
        use jet_proto::{accept::JetAcceptReq, JetMessage};
        use tokio::io::AsyncWriteExt;

        let jet_accept_request = JetMessage::JetAcceptReq(JetAcceptReq {
            version: JET_VERSION_V2 as u32,
            host: "jetsocat".to_string(),
            association: self.association_id,
            candidate: self.candidate_id,
        });

        let mut buffer: Vec<u8> = Vec::new();
        jet_accept_request.write_to(&mut buffer)?;
        jet_server_stream.write_all(&buffer).await?;

        Ok(())
    }

    async fn process_jet_accept_response(&self, jet_server_stream: &mut AsyncStream) -> Result<()> {
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

async fn run_proxy(
    jet_server_stream: AsyncStream,
    tcp_server_transport: AsyncStream,
    log: Logger
) -> Result<()> {
    use crate::io::read_and_write;
    use futures_util::select;

    debug!(log, "{}", "Running jet tcp proxy");

    let (mut client_read_half, mut client_write_half) = tokio::io::split(jet_server_stream);
    let (mut server_read_half, mut server_write_half) = tokio::io::split(tcp_server_transport);

    let client_server_logger = log.new(o!("client" => " -> server"));
    let server_client_logger = log.new(o!("client" => " <- server"));

    let client_to_server = read_and_write(&mut client_read_half, &mut server_write_half, client_server_logger).fuse();
    let server_to_client = read_and_write(&mut server_read_half, &mut client_write_half, server_client_logger).fuse();

    pin!(client_to_server, server_to_client);

    select! {
        result = client_to_server => {
            match result {
                Ok(()) =>  {
                    debug!(log, "client_to_server disconnected gracefully");
                }
                Err(e) => {
                    debug!(log, "client_to_server disconnected with error: {}", e);
                }
            }
        },
        result = server_to_client => {
            match result {
                Ok(()) =>  {
                    debug!(log, "server_to_client disconnected gracefully");
                }
                Err(e) => {
                    debug!(log, "server_to_client disconnected with error: {}", e);
                }
            }
        },
    };

    Ok(())
}

pub async fn jet_tcp_accept(addr: String, cmd: JetTcpAcceptCmd, proxy_cfg: Option<ProxyConfig>, log: slog::Logger) -> Result<()> {
    let jet_listener_addr = addr
        .as_str()
        .to_dest_addr()
        .with_context(|| "Invalid jet listener address")?;
    let forward_addr = cmd.forward_addr
        .as_str()
        .to_dest_addr()
        .with_context(|| "Invalid forward address")?;

    let association_id = Uuid::parse_str(&cmd.association_id).with_context(|| "Failed to parse jet association id")?;

    let candidate_id = Uuid::parse_str(&cmd.candidate_id).with_context(|| "Failed to parse jet candidate id")?;

    TcpServer::new(
        forward_addr,
        jet_listener_addr,
        association_id,
        candidate_id,
        cmd.max_reconnection_count,
        proxy_cfg
    )
    .serve(log)
    .await
}
