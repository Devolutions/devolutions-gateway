use crate::config::{Config, Protocol};
use crate::interceptor::pcap::PcapInspector;
use crate::interceptor::{Dissector, DummyDissector, Interceptor, WaykDissector};
use crate::{add_session_in_progress, remove_session_in_progress, GatewaySessionInfo};
use camino::Utf8PathBuf;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct IsMissing;

pub struct HasConfig(Arc<Config>);

pub struct HasSessionInfo(GatewaySessionInfo);

pub struct HasTransports<A, B> {
    a: A,
    b: B,
}

pub struct HasAddresses {
    a: SocketAddr,
    b: SocketAddr,
}

pub struct Proxy<CONF, INFO, TRANSPORT, ADDR> {
    pub config: CONF,
    pub session_info: INFO,
    pub transports: TRANSPORT,
    pub addrs: ADDR,
}

impl Proxy<IsMissing, IsMissing, IsMissing, IsMissing> {
    pub fn init() -> Self {
        Self {
            config: IsMissing,
            session_info: IsMissing,
            transports: IsMissing,
            addrs: IsMissing,
        }
    }
}

impl<INFO, TRANSPORT, ADDR> Proxy<IsMissing, INFO, TRANSPORT, ADDR> {
    pub fn config(self, config: Arc<Config>) -> Proxy<HasConfig, INFO, TRANSPORT, ADDR> {
        Proxy {
            config: HasConfig(config),
            session_info: self.session_info,
            transports: self.transports,
            addrs: self.addrs,
        }
    }
}

impl<CONF, TRANSPORT, ADDR> Proxy<CONF, IsMissing, TRANSPORT, ADDR> {
    pub fn session_info(self, info: GatewaySessionInfo) -> Proxy<CONF, HasSessionInfo, TRANSPORT, ADDR> {
        Proxy {
            config: self.config,
            session_info: HasSessionInfo(info),
            transports: self.transports,
            addrs: self.addrs,
        }
    }
}

impl<CONF, INFO, ADDR> Proxy<CONF, INFO, IsMissing, ADDR> {
    pub fn transports<A, B>(self, a: A, b: B) -> Proxy<CONF, INFO, HasTransports<A, B>, ADDR> {
        Proxy {
            config: self.config,
            session_info: self.session_info,
            transports: HasTransports { a, b },
            addrs: self.addrs,
        }
    }
}

impl<CONF, INFO, TRANSPORT> Proxy<CONF, INFO, TRANSPORT, IsMissing> {
    pub fn addrs(self, a: SocketAddr, b: SocketAddr) -> Proxy<CONF, INFO, TRANSPORT, HasAddresses> {
        Proxy {
            config: self.config,
            session_info: self.session_info,
            transports: self.transports,
            addrs: HasAddresses { a, b },
        }
    }
}

impl<A, B> Proxy<HasConfig, HasSessionInfo, HasTransports<A, B>, HasAddresses>
where
    A: AsyncWrite + AsyncRead + Unpin,
    B: AsyncWrite + AsyncRead + Unpin,
{
    pub async fn select_dissector_and_forward(self) -> anyhow::Result<()> {
        match self.config.0.protocol {
            Protocol::Wayk => {
                debug!("WaykMessageReader will be used to interpret application protocol.");
                self.forward_using_dissector(WaykDissector).await
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
                self.forward_using_dissector(DummyDissector).await
            }
        }
    }

    pub async fn forward_using_dissector<D>(self, dissector: D) -> anyhow::Result<()>
    where
        D: Dissector + Send + 'static,
    {
        if let Some(capture_path) = self.config.0.capture_path.as_ref() {
            let filename = format!(
                "{}({})-to-{}({})-at-{}.pcap",
                self.addrs.a.ip(),
                self.addrs.a.port(),
                self.addrs.b.ip(),
                self.addrs.b.port(),
                chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
            );
            let mut path = Utf8PathBuf::from(capture_path);
            path.push(filename);

            let (client_inspector, server_inspector) =
                PcapInspector::init(self.addrs.a, self.addrs.b, path, dissector)?;

            let mut a = Interceptor::new(self.transports.a);
            a.inspectors.push(Box::new(client_inspector));

            let mut b = Interceptor::new(self.transports.b);
            b.inspectors.push(Box::new(server_inspector));

            Proxy {
                config: self.config,
                session_info: self.session_info,
                transports: HasTransports { a, b },
                addrs: self.addrs,
            }
            .forward()
            .await
        } else {
            self.forward().await
        }
    }
}

impl<A, B, CONF, ADDR> Proxy<CONF, HasSessionInfo, HasTransports<A, B>, ADDR>
where
    A: AsyncWrite + AsyncRead + Unpin,
    B: AsyncWrite + AsyncRead + Unpin,
{
    pub async fn forward(self) -> anyhow::Result<()> {
        let session_id = self.session_info.0.id();

        add_session_in_progress(self.session_info.0).await;
        let res = transport::forward_bidirectional(self.transports.a, self.transports.b).await;
        remove_session_in_progress(session_id).await;

        res.map(|_| ())
    }
}
