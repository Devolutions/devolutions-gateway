mod connection_sequence_future;
mod filter;
mod identities_proxy;
mod sequence_future;

use std::io;

use futures::Future;
use slog::{error, info, Drain};
use tokio_tcp::TcpStream;
use tokio_tls::TlsAcceptor;
use url::Url;

use self::{connection_sequence_future::ConnectionSequenceFuture, identities_proxy::IdentitiesProxy};
use crate::{config::Config, transport::tcp::TcpTransport, Proxy};

#[allow(unused)]
pub struct RdpClient {
    routing_url: Url,
    config: Config,
    tls_public_key: Vec<u8>,
    tls_acceptor: TlsAcceptor,
}

const LOGGER_TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

fn create_client_logger(client_addr: String) -> slog::Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator)
        .use_custom_timestamp(|output: &mut dyn io::Write| -> io::Result<()> {
            write!(output, "{}", chrono::Utc::now().format(LOGGER_TIMESTAMP_FORMAT))
        })
        .build()
        .fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    slog::Logger::root(drain, slog::o!("client" => client_addr))
}

impl RdpClient {
    pub fn new(routing_url: Url, config: Config, tls_public_key: Vec<u8>, tls_acceptor: TlsAcceptor) -> Self {
        Self {
            routing_url,
            config,
            tls_public_key,
            tls_acceptor,
        }
    }

    pub fn serve(self, client: TcpStream) -> Box<dyn Future<Item = (), Error = io::Error> + Send> {
        let client_addr = client
            .peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| String::from("unknown"));
        let client_logger = create_client_logger(client_addr);
        let client_logger_clone = client_logger.clone();

        let config_clone = self.config.clone();
        let tls_acceptor = self.tls_acceptor;
        let tls_public_key = self.tls_public_key;
        let identities_filename = if let Some(identities_filename) = self.config.identities_filename() {
            identities_filename
        } else {
            error!(client_logger, "Identities file is not present");

            return Box::new(futures::future::err(io::Error::new(
                io::ErrorKind::Other,
                "identities file is not present",
            )));
        };

        let connection_sequence_future = ConnectionSequenceFuture::new(
            client,
            tls_public_key,
            tls_acceptor,
            IdentitiesProxy::new(identities_filename),
            client_logger.clone(),
        )
        .map_err(move |e| {
            error!(client_logger_clone, "RDP Connection Sequence failed: {}", e);

            io::Error::new(io::ErrorKind::Other, e)
        })
        .and_then(move |(client_tls, server_tls, _joined_static_channels)| {
            info!(client_logger, "RDP Connection Sequence finished");

            Proxy::new(config_clone)
                .build(TcpTransport::new_tls(server_tls), TcpTransport::new_tls(client_tls))
                .map_err(move |e| {
                    error!(client_logger, "Proxy error: {}", e);
                    e
                })
        });

        Box::new(connection_sequence_future)
    }
}
