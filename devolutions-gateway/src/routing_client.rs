use crate::config::Config;
use crate::proxy::Proxy;
use crate::token::ApplicationProtocol;
use crate::transport::tcp::TcpTransport;
use crate::transport::Transport;
use crate::utils::TargetAddr;
use crate::{ConnectionModeDetails, GatewaySessionInfo};
use std::io;
use std::sync::Arc;
use url::Url;

pub struct Client {
    routing_url: Url,
    config: Arc<Config>,
}

impl Client {
    pub fn new(routing_url: Url, config: Arc<Config>) -> Self {
        Client { routing_url, config }
    }

    pub async fn serve<T>(self, client_transport: T) -> Result<(), io::Error>
    where
        T: 'static + Transport + Send,
    {
        let server_transport = TcpTransport::connect(&self.routing_url).await?;

        let destination_host =
            TargetAddr::try_from(&self.routing_url).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Proxy::new(
            self.config.clone(),
            GatewaySessionInfo::new(
                uuid::Uuid::new_v4(),
                ApplicationProtocol::Unknown,
                ConnectionModeDetails::Fwd { destination_host },
            ),
        )
        .build(server_transport, client_transport)
        .await
    }
}
