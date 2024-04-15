use crate::config::Conf;
use crate::interceptor::pcap::PcapInspector;
use crate::interceptor::{Dissector, DummyDissector, Interceptor, WaykDissector};
use crate::session::{SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;
use crate::token::{ApplicationProtocol, Protocol};
use camino::Utf8PathBuf;
use futures::future::Either;
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::Notify;
use typed_builder::TypedBuilder;

#[derive(TypedBuilder)]
pub struct Proxy<A, B> {
    conf: Arc<Conf>,
    session_info: SessionInfo,
    transport_a: A,
    address_a: SocketAddr,
    transport_b: B,
    address_b: SocketAddr,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    #[builder(default = None)]
    buffer_size: Option<usize>,
}

impl<A, B> Proxy<A, B>
where
    A: AsyncWrite + AsyncRead + Unpin,
    B: AsyncWrite + AsyncRead + Unpin,
{
    pub async fn select_dissector_and_forward(self) -> anyhow::Result<()> {
        match self.session_info.application_protocol {
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
        if let Some(capture_path) = self.conf.debug.capture_path.as_ref() {
            let format = time::format_description::parse("[year]-[month]-[day]_[hour]-[minute]-[second]")
                .expect("valid hardcoded format");

            let filename = format!(
                "{}({})-to-{}({})-at-{}.pcap",
                self.address_a.ip(),
                self.address_a.port(),
                self.address_b.ip(),
                self.address_b.port(),
                time::OffsetDateTime::now_utc().format(&format)?
            );
            let mut path = Utf8PathBuf::from(capture_path);
            path.push(filename);

            let (client_inspector, server_inspector) =
                PcapInspector::init(self.address_a, self.address_b, path, dissector)?;

            let mut a = Interceptor::new(self.transport_a);
            a.inspectors.push(Box::new(client_inspector));

            let mut b = Interceptor::new(self.transport_b);
            b.inspectors.push(Box::new(server_inspector));

            Proxy {
                transport_a: a,
                transport_b: b,
                conf: self.conf,
                session_info: self.session_info,
                address_a: self.address_a,
                address_b: self.address_b,
                sessions: self.sessions,
                subscriber_tx: self.subscriber_tx,
                buffer_size: self.buffer_size,
            }
            .forward()
            .await
        } else {
            self.forward().await
        }
    }

    pub async fn forward(self) -> anyhow::Result<()> {
        let mut transport_a = self.transport_a;
        let mut transport_b = self.transport_b;

        let session_id = self.session_info.id();
        let notify_kill = Arc::new(Notify::new());

        crate::session::add_session_in_progress(
            &self.sessions,
            &self.subscriber_tx,
            self.session_info,
            notify_kill.clone(),
        )
        .await?;

        // NOTE(DGW-86): when recording is required, should we wait for it to start before we forward, or simply spawn
        // a timer to check if the recording is started within a few seconds?

        let kill_notified = notify_kill.notified();

        let res = if let Some(buffer_size) = self.buffer_size {
            // Use our for of copy_bidirectional because tokio doesn't have an API to set the buffer size.
            // See https://github.com/tokio-rs/tokio/issues/6454.
            let forward_fut = transport::copy_bidirectional(&mut transport_a, &mut transport_b, buffer_size, buffer_size);
            match futures::future::select(pin!(forward_fut), pin!(kill_notified)).await {
                Either::Left((res, _)) => res.map(|_| ()),
                Either::Right(_) => Ok(()),
            }
        } else {
            let forward_fut = tokio::io::copy_bidirectional(&mut transport_a, &mut transport_b);
            match futures::future::select(pin!(forward_fut), pin!(kill_notified)).await {
                Either::Left((res, _)) => res.map(|_| ()),
                Either::Right(_) => Ok(()),
            }
        };

        // Ensure we close the transports cleanly at the end (ignore errors at this point)
        let _ = tokio::join!(transport_a.shutdown(), transport_b.shutdown());

        crate::session::remove_session_in_progress(&self.sessions, &self.subscriber_tx, session_id).await?;

        match res {
            Ok(()) => {
                info!("Forwarding ended");
                Ok(())
            }
            Err(error) => {
                let really_an_error = is_really_an_error(&error);

                let error = anyhow::Error::new(error);

                if really_an_error {
                    Err(error.context("forward"))
                } else {
                    info!(reason = format!("{error:#}"), "Forwarding ended abruptly");
                    Ok(())
                }
            }
        }
    }
}

/// Walks source chain and check for status codes like ECONNRESET or ECONNABORTED that we don’t consider to be actual errors
fn is_really_an_error(original_error: &io::Error) -> bool {
    use std::error::Error as _;

    let mut dyn_error: Option<&dyn std::error::Error> = Some(original_error);

    while let Some(source_error) = dyn_error.take() {
        if let Some(io_error) = source_error.downcast_ref::<io::Error>() {
            match io_error.kind() {
                io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionAborted => {
                    return false;
                }
                io::ErrorKind::Other => {
                    dyn_error = io_error.source();
                }
                _ => {
                    return true;
                }
            }
        } else if let Some(tungstenite_error) = source_error.downcast_ref::<tungstenite::Error>() {
            match tungstenite_error {
                tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => return false,
                tungstenite::Error::Protocol(tungstenite::error::ProtocolError::ResetWithoutClosingHandshake) => {
                    return false
                }
                tungstenite::Error::Io(io_error) => dyn_error = Some(io_error),
                _ => return true,
            }
        } else {
            dyn_error = source_error.source();
        }
    }

    true
}
