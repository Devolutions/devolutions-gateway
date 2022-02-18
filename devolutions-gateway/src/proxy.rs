use crate::config::{Config, Protocol};
use crate::interceptor::pcap::PcapInspector;
use crate::interceptor::{Dissector, DummyDissector, Interceptor, WaykDissector};
use crate::{add_session_in_progress, remove_session_in_progress, GatewaySessionInfo};
use camino::Utf8PathBuf;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct Proxy {
    config: Arc<Config>,
    gateway_session_info: GatewaySessionInfo,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
}

impl Proxy {
    pub fn new(
        config: Arc<Config>,
        gateway_session_info: GatewaySessionInfo,
        client_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Self {
        Proxy {
            config,
            gateway_session_info,
            client_addr,
            server_addr,
        }
    }

    pub async fn select_dissector_and_forward<A, B>(self, a: A, b: B) -> anyhow::Result<()>
    where
        A: AsyncWrite + AsyncRead + Unpin,
        B: AsyncWrite + AsyncRead + Unpin,
    {
        match self.config.protocol {
            Protocol::Wayk => {
                debug!("WaykMessageReader will be used to interpret application protocol.");
                self.forward_using_dissector(a, b, WaykDissector).await
            }
            // Protocol::Rdp => {
            //     debug!("RdpMessageReader will be used to interpret application protocol");
            //     self.build_with_message_reader(
            //         server_transport,
            //         client_transport,
            //         Some(Box::new(RdpMessageReader::new(
            //             HashMap::new(),
            //             Some(DvcManager::with_allowed_channels(vec![
            //                 RDP8_GRAPHICS_PIPELINE_NAME.to_string()
            //             ])),
            //         ))),
            //     )
            //     .await
            // }
            Protocol::Unknown | Protocol::Rdp => {
                debug!("Protocol is unknown. Data received will not be split to get application message.");
                self.forward_using_dissector(a, b, DummyDissector).await
            }
        }
    }

    pub async fn forward_using_dissector<A, B, D>(self, a: A, b: B, dissector: D) -> anyhow::Result<()>
    where
        A: AsyncWrite + AsyncRead + Unpin,
        B: AsyncWrite + AsyncRead + Unpin,
        D: Dissector + Send + 'static,
    {
        if let Some(capture_path) = self.config.capture_path.as_ref() {
            let filename = format!(
                "{}({})-to-{}({})-at-{}.pcap",
                self.client_addr.ip(),
                self.client_addr.port(),
                self.server_addr.ip(),
                self.server_addr.port(),
                chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
            );
            let mut path = Utf8PathBuf::from(capture_path);
            path.push(filename);

            let (client_inspector, server_inspector) =
                PcapInspector::init(self.client_addr, self.server_addr, path, dissector)?;

            let mut client = Interceptor::new(a);
            client.inspectors.push(Box::new(client_inspector));

            let mut server = Interceptor::new(b);
            server.inspectors.push(Box::new(server_inspector));

            self.forward(client, server).await
        } else {
            self.forward(a, b).await
        }
    }

    pub async fn forward<A, B>(self, a: A, b: B) -> anyhow::Result<()>
    where
        A: AsyncWrite + AsyncRead + Unpin,
        B: AsyncWrite + AsyncRead + Unpin,
    {
        add_session_in_progress(self.gateway_session_info.clone()).await;
        let res = transport::forward_bidirectional(a, b).await;
        remove_session_in_progress(self.gateway_session_info.id()).await;
        res.map(|_| ())
    }
}
