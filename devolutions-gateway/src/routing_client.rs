use crate::config::Config;
use crate::proxy::Proxy;
use crate::token::ApplicationProtocol;
use crate::utils::TargetAddr;
use crate::{ConnectionModeDetails, GatewaySessionInfo};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use url::Url;

pub struct Client {
    routing_url: Url,
    config: Arc<Config>,
}

impl Client {
    pub fn new(routing_url: Url, config: Arc<Config>) -> Self {
        Client { routing_url, config }
    }

    pub async fn serve<T>(self, client_addr: SocketAddr, client_transport: T) -> anyhow::Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let (server_addr, server_transport) = crate::utils::tcp_transport_connect_with_url(&self.routing_url).await?;

        let destination_host = TargetAddr::try_from(&self.routing_url)?;

        Proxy::new(
            self.config.clone(),
            GatewaySessionInfo::new(
                uuid::Uuid::new_v4(),
                ApplicationProtocol::Unknown,
                ConnectionModeDetails::Fwd { destination_host },
            ),
            client_addr,
            server_addr,
        )
        .select_dissector_and_forward(client_transport, server_transport)
        .await
    }
}
