use std::{io, sync::Arc};

use url::Url;

use crate::{
    config::Config,
    proxy::Proxy,
    transport::{tcp::TcpTransport, Transport},
};

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

        Proxy::new(self.config.clone())
            .build(server_transport, client_transport)
            .await
    }
}
