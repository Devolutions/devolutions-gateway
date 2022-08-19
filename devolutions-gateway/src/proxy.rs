use crate::config::Conf;
use crate::interceptor::pcap::PcapInspector;
use crate::interceptor::{Dissector, DummyDissector, Interceptor, WaykDissector};
use crate::subscriber::SubscriberSender;
use crate::token::{ApplicationProtocol, Protocol};
use crate::GatewaySessionInfo;
use camino::Utf8PathBuf;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct IsMissing;

pub struct HasConf(Arc<Conf>);

pub struct HasSessionInfo(GatewaySessionInfo);

pub struct HasTransports<A, B> {
    a: A,
    b: B,
}

pub struct HasAddresses {
    a: SocketAddr,
    b: SocketAddr,
}

pub struct HasSubscriber {
    tx: SubscriberSender,
}

pub struct Proxy<CONF, INFO, TRANSPORT, ADDR, SUBSCRIBER> {
    pub conf: CONF,
    pub session_info: INFO,
    pub transports: TRANSPORT,
    pub addrs: ADDR,
    pub subscriber: SUBSCRIBER,
}

impl Proxy<IsMissing, IsMissing, IsMissing, IsMissing, IsMissing> {
    pub fn init() -> Self {
        Self {
            conf: IsMissing,
            session_info: IsMissing,
            transports: IsMissing,
            addrs: IsMissing,
            subscriber: IsMissing,
        }
    }
}

impl<INFO, TRANSPORT, ADDR, SUBSCRIBER> Proxy<IsMissing, INFO, TRANSPORT, ADDR, SUBSCRIBER> {
    pub fn conf(self, conf: Arc<Conf>) -> Proxy<HasConf, INFO, TRANSPORT, ADDR, SUBSCRIBER> {
        Proxy {
            conf: HasConf(conf),
            session_info: self.session_info,
            transports: self.transports,
            addrs: self.addrs,
            subscriber: self.subscriber,
        }
    }
}

impl<CONF, TRANSPORT, ADDR, SUBSCRIBER> Proxy<CONF, IsMissing, TRANSPORT, ADDR, SUBSCRIBER> {
    pub fn session_info(self, info: GatewaySessionInfo) -> Proxy<CONF, HasSessionInfo, TRANSPORT, ADDR, SUBSCRIBER> {
        Proxy {
            conf: self.conf,
            session_info: HasSessionInfo(info),
            transports: self.transports,
            addrs: self.addrs,
            subscriber: self.subscriber,
        }
    }
}

impl<CONF, INFO, ADDR, SUBSCRIBER> Proxy<CONF, INFO, IsMissing, ADDR, SUBSCRIBER> {
    pub fn transports<A, B>(self, a: A, b: B) -> Proxy<CONF, INFO, HasTransports<A, B>, ADDR, SUBSCRIBER> {
        Proxy {
            conf: self.conf,
            session_info: self.session_info,
            transports: HasTransports { a, b },
            addrs: self.addrs,
            subscriber: self.subscriber,
        }
    }
}

impl<CONF, INFO, TRANSPORT, SUBSCRIBER> Proxy<CONF, INFO, TRANSPORT, IsMissing, SUBSCRIBER> {
    pub fn addrs(self, a: SocketAddr, b: SocketAddr) -> Proxy<CONF, INFO, TRANSPORT, HasAddresses, SUBSCRIBER> {
        Proxy {
            conf: self.conf,
            session_info: self.session_info,
            transports: self.transports,
            addrs: HasAddresses { a, b },
            subscriber: self.subscriber,
        }
    }
}

impl<CONF, INFO, TRANSPORT, ADDRS> Proxy<CONF, INFO, TRANSPORT, ADDRS, IsMissing> {
    pub fn subscriber(self, tx: SubscriberSender) -> Proxy<CONF, INFO, TRANSPORT, ADDRS, HasSubscriber> {
        Proxy {
            conf: self.conf,
            session_info: self.session_info,
            transports: self.transports,
            addrs: self.addrs,
            subscriber: HasSubscriber { tx },
        }
    }
}

impl<A, B> Proxy<HasConf, HasSessionInfo, HasTransports<A, B>, HasAddresses, HasSubscriber>
where
    A: AsyncWrite + AsyncRead + Unpin,
    B: AsyncWrite + AsyncRead + Unpin,
{
    pub async fn select_dissector_and_forward(self) -> anyhow::Result<()> {
        match self.session_info.0.application_protocol {
            ApplicationProtocol::Known(Protocol::Wayk) => {
                trace!("WaykDissector will be used to interpret application protocol.");
                self.forward_using_dissector(WaykDissector).await
            }
            // ApplicationProtocol::Known(Protocol::Rdp) => {
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
            _ => {
                trace!("No dissector available for this protocol. Data received will not be split to get application message.");
                self.forward_using_dissector(DummyDissector).await
            }
        }
    }

    pub async fn forward_using_dissector<D>(self, dissector: D) -> anyhow::Result<()>
    where
        D: Dissector + Send + 'static,
    {
        if let Some(capture_path) = self.conf.0.capture_path.as_ref() {
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
                conf: self.conf,
                session_info: self.session_info,
                transports: HasTransports { a, b },
                addrs: self.addrs,
                subscriber: self.subscriber,
            }
            .forward()
            .await
        } else {
            self.forward().await
        }
    }
}

impl<CONF, A, B, ADDR> Proxy<CONF, HasSessionInfo, HasTransports<A, B>, ADDR, HasSubscriber>
where
    A: AsyncWrite + AsyncRead + Unpin,
    B: AsyncWrite + AsyncRead + Unpin,
{
    pub async fn forward(self) -> anyhow::Result<()> {
        let session_id = self.session_info.0.id();

        crate::add_session_in_progress(&self.subscriber.tx, self.session_info.0);
        let res = transport::forward_bidirectional(self.transports.a, self.transports.b).await;
        crate::remove_session_in_progress(&self.subscriber.tx, session_id);

        res.map(|_| ())
    }
}
