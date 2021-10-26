use crate::config::Config;
use crate::jet_client::JetAssociationsMap;
use crate::jet_rendezvous_tcp_proxy::JetRendezvousTcpProxy;
use crate::preconnection_pdu::{extract_association_claims, read_preconnection_pdu};
use crate::rdp::RdpClient;
use crate::token::{ApplicationProtocol, ConnectionMode};
use crate::transport::tcp::TcpTransport;
use crate::transport::{JetTransport, Transport as _};
use crate::Proxy;
use std::io;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use url::Url;

const DEFAULT_ROUTING_HOST_SCHEME: &str = "tcp://";

pub struct GenericClient {
    pub config: Arc<Config>,
    pub tls_public_key: Vec<u8>,
    pub tls_acceptor: TlsAcceptor,
    pub jet_associations: JetAssociationsMap,
}

impl GenericClient {
    pub async fn serve(self, mut client_stream: TcpStream) -> io::Result<()> {
        let Self {
            config,
            tls_public_key,
            tls_acceptor,
            jet_associations,
        } = self;

        let (pdu, mut leftover_bytes) = read_preconnection_pdu(&mut client_stream).await?;
        let association_claims = extract_association_claims(&pdu, &config)?;

        match association_claims.jet_ap {
            // We currently special case this because it may be the "RDP-TLS" protocol
            ApplicationProtocol::Rdp => {
                RdpClient {
                    config,
                    tls_public_key,
                    tls_acceptor,
                    jet_associations,
                }
                .serve_with_association_claims_and_leftover_bytes(client_stream, association_claims, leftover_bytes)
                .await
            }
            // everything else is pretty much the same
            _ => match association_claims.jet_cm {
                ConnectionMode::Rdv => {
                    info!(
                        "Starting TCP rendezvous redirection for application protocol {:?}",
                        association_claims.jet_ap
                    );
                    JetRendezvousTcpProxy::new(
                        jet_associations,
                        JetTransport::new_tcp(client_stream),
                        association_claims.jet_aid,
                    )
                    .proxy(config, &*leftover_bytes)
                    .await
                }
                ConnectionMode::Fwd {
                    ref dst_hst,
                    creds: None,
                } => {
                    info!(
                        "Starting plain TCP forward redirection for application protocol {:?}",
                        association_claims.jet_ap
                    );

                    let dst_hst = if dst_hst.starts_with(DEFAULT_ROUTING_HOST_SCHEME) {
                        dst_hst.clone()
                    } else {
                        format!("{}{}", DEFAULT_ROUTING_HOST_SCHEME, dst_hst)
                    };

                    let dst_hst = Url::parse(&dst_hst).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Failed to parse routing URL in JWT token: {}", e),
                        )
                    })?;

                    if dst_hst.port().is_none() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid dst_hst claim: destination port is missing",
                        ));
                    }

                    let mut server_conn = TcpTransport::connect(&dst_hst).await?;
                    let client_transport = TcpTransport::new(client_stream);

                    server_conn.write_buf(&mut leftover_bytes).await.map_err(|e| {
                        error!("Failed to write leftover bytes: {}", e);
                        e
                    })?;

                    Proxy::new(config, association_claims.into())
                        .build(server_conn, client_transport)
                        .await
                        .map_err(|e| {
                            error!("Encountered a failure during plain tcp traffic proxying: {}", e);
                            e
                        })
                }
                ConnectionMode::Fwd { creds: Some(_), .. } => {
                    // Credentials handling should be special cased (e.g.: RDP-TLS)
                    Err(io::Error::new(io::ErrorKind::Other, "unexpected credentials"))
                }
            },
        }
    }
}
