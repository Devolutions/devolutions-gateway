mod credssp_future;
mod filter;
mod identities_proxy;
mod mcs_future;
mod rdp_future;

use std::{io, iter, net::SocketAddr};

use bytes::BytesMut;
use failure::Fail;
use futures::{Future, Stream};
use native_tls::TlsConnector;
use slog::{debug, error, info, Drain};
use tokio::{
    codec::{Decoder, Framed},
    net::tcp::ConnectFuture,
    prelude::*,
};
use tokio_tcp::TcpStream;
use tokio_tls::{TlsAcceptor, TlsStream};
use url::Url;

use self::{
    credssp_future::{CredSspClientFuture, CredSspServerFuture},
    filter::{Filter, FilterConfig},
    identities_proxy::{IdentitiesProxy, RdpIdentity},
    mcs_future::McsFuture,
    rdp_future::RdpFuture,
};
use crate::{
    config::Config,
    transport::{mcs::McsTransport, tcp::TcpTransport, tsrequest::TsRequestTransport, x224::X224Transport},
    utils::get_tls_peer_pubkey,
    Proxy,
};
use rdp_proto::PduParsing;

const DEFAULT_NTLM_VERSION: [u8; rdp_proto::NTLM_VERSION_SIZE] = [0x00; rdp_proto::NTLM_VERSION_SIZE];

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

        let tls_acceptor = self.tls_acceptor;
        let proxy_public_key = self.tls_public_key;
        let identities_filename = self
            .config
            .identities_filename()
            .expect("identities file is not present");
        let config_clone = self.config.clone();

        let client_future = negotiate_with_client(client, client_logger.clone())
            .map_err(move |e| {
                error!(client_logger_clone, "failed to negotiate with client: {}", e);
                e
            })
            .and_then(move |(client_transport, request_protocol, request_flags)| {
                info!(client_logger, "successfully negotiated with client");
                let client = client_transport.into_inner();
                let client_logger_clone = client_logger.clone();

                establish_tls_connection_with_client(client, tls_acceptor)
                    .map_err(move |e| {
                        error!(client_logger_clone, "failed to accept a tls connection: {}", e);
                        e
                    })
                    .and_then(move |client_tls| Ok((client_tls, client_logger, request_protocol, request_flags)))
            })
            .and_then(move |(client_tls, client_logger, request_protocol, request_flags)| {
                info!(client_logger, "TLS connection has been established with client");
                let identities_proxy = IdentitiesProxy::new(identities_filename);
                let client_logger_clone = client_logger.clone();

                process_cred_ssp_with_client(client_tls, proxy_public_key, identities_proxy)
                    .map_err(move |e| {
                        error!(
                            client_logger_clone,
                            "failed to process CredSSP phase with client: {}", e
                        );
                        e
                    })
                    .and_then(move |(client_transport, target_identity)| {
                        info!(client_logger, "CredSSP has been finished with client");
                        let client_tls = client_transport.into_inner();

                        Ok((
                            client_tls,
                            target_identity,
                            client_logger,
                            request_protocol,
                            request_flags,
                        ))
                    })
            });

        let future = client_future
            .and_then(
                move |(client_tls, rdp_identity, client_logger, request_protocol, request_flags)| {
                    let target_identity = rdp_identity.target.clone();
                    let destination = rdp_identity.destination.clone();
                    let client_logger_clone = client_logger.clone();

                    let server_addr = destination.parse().map_err(move |e| {
                        error!(
                            client_logger_clone,
                            "invalid target destination ({}): {}", destination, e
                        );
                        io::Error::new(io::ErrorKind::Other, e)
                    })?;
                    let server = TcpStream::connect(&server_addr);
                    let client_logger_clone = client_logger.clone();

                    let negotiate_with_server_fut =
                        negotiate_with_server(server, target_identity.clone(), request_protocol, request_flags)
                            .and_then(move |(server_transport, nego_flags)| {
                                process_negotiation_response_from_server(server_transport, client_logger.clone())
                                    .and_then(move |(server_transport, selected_protocol)| {
                                        if let Some(protocol) = selected_protocol {
                                            info!(client_logger, "successfully negotiated with server");
                                            let server = server_transport.into_inner();

                                            Ok((
                                                server,
                                                client_tls,
                                                protocol,
                                                nego_flags,
                                                rdp_identity,
                                                server_addr,
                                                client_logger,
                                            ))
                                        } else {
                                            Err(io::Error::new(
                                                io::ErrorKind::Other,
                                                "server returned negotiation error",
                                            ))
                                        }
                                    })
                            })
                            .map_err(move |e| {
                                error!(client_logger_clone, "failed to negotiate with server: {}", e);
                                e
                            });

                    Ok(negotiate_with_server_fut)
                },
            )
            .and_then(|nego_fut| nego_fut)
            .and_then(
                move |(server, client_tls, selected_protocol, nego_flags, rdp_identity, server_addr, client_logger)| {
                    let target_identity = rdp_identity.target.clone();
                    match selected_protocol {
                        rdp_proto::SecurityProtocol::HYBRID
                        | rdp_proto::SecurityProtocol::HYBRID_EX
                        | rdp_proto::SecurityProtocol::SSL => {
                            let accept_invalid_certs_and_hostnames = match selected_protocol {
                                rdp_proto::SecurityProtocol::HYBRID | rdp_proto::SecurityProtocol::HYBRID_EX => true,
                                _ => false,
                            };
                            let client_logger_clone = client_logger.clone();

                            Ok(establish_tls_connection_with_server(
                                server,
                                server_addr,
                                accept_invalid_certs_and_hostnames,
                            )
                            .map_err(move |e| {
                                error!(client_logger_clone, "failed to accept a tls connection: {}", e);
                                e
                            })
                            .and_then(move |server_tls| {
                                info!(client_logger, "TLS connection has been established with server");
                                let client_logger_clone = client_logger.clone();
                                let server_fut = match selected_protocol {
                                    rdp_proto::SecurityProtocol::HYBRID | rdp_proto::SecurityProtocol::HYBRID_EX => {
                                        let client_logger_clone = client_logger.clone();
                                        future::Either::A(
                                            process_cred_ssp_with_server(server_tls, target_identity, nego_flags)
                                                .map_err(move |e| {
                                                    error!(client_logger_clone, "CredSSP failed: {}", e);
                                                    e
                                                })
                                                .and_then(move |server_transport| {
                                                    info!(client_logger, "CredSSP has been finished with server");
                                                    let server_tls = server_transport.into_inner();

                                                    Ok(server_tls)
                                                }),
                                        )
                                    }
                                    _ => future::Either::B(future::ok(server_tls)),
                                };

                                server_fut.and_then(move |server_tls| {
                                    Ok((
                                        client_tls,
                                        server_tls,
                                        rdp_identity,
                                        client_logger_clone,
                                        selected_protocol,
                                    ))
                                })
                            }))
                        }
                        _ => Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            format!("unsupported security protocol: {:?}", selected_protocol),
                        )),
                    }
                },
            )
            .and_then(move |either_fut| {
                either_fut.and_then(
                    |(client_tls, server_tls, rdp_identity, client_logger, selected_protocol)| {
                        let client_logger_clone = client_logger.clone();
                        let fut = if selected_protocol == rdp_proto::SecurityProtocol::HYBRID_EX {
                            future::Either::A(process_early_auth_result(client_tls, server_tls).map_err(move |e| {
                                error!(
                                    client_logger_clone,
                                    "Failed to process  Early User Authorization Result PDU: {}", e
                                );
                                e
                            }))
                        } else {
                            future::Either::B(future::ok((client_tls, server_tls)))
                        };

                        fut.and_then(move |(client_tls, server_tls)| {
                            Ok((client_tls, server_tls, rdp_identity, client_logger))
                        })
                    },
                )
            })
            .and_then(|(client_tls, server_tls, rdp_identity, client_logger)| {
                let filter_config = FilterConfig::new(rdp_identity.proxy.clone());
                let client_logger_clone = client_logger.clone();
                let client_transport = X224Transport::new().framed(client_tls);
                let server_transport = X224Transport::new().framed(server_tls);

                process_mcs_connect_initial(client_transport, server_transport, filter_config, client_logger.clone())
                    .map_err(move |e| {
                        error!(client_logger_clone, "MCS Connect Initial failed: {}", e);
                        e
                    })
                    .and_then(
                        move |(client_transport, server_transport, connect_initial, filter_config)| {
                            info!(client_logger, "MCS Connect Initial redirected successfully");
                            Ok((
                                client_transport,
                                server_transport,
                                connect_initial,
                                filter_config,
                                client_logger,
                            ))
                        },
                    )
            })
            .and_then(
                move |(client_transport, server_transport, connect_initial, filter_config, client_logger)| {
                    let client_logger_clone = client_logger.clone();

                    process_mcs_connect_response(
                        client_transport,
                        server_transport,
                        filter_config,
                        client_logger.clone(),
                    )
                    .map_err(move |e| {
                        error!(client_logger_clone, "MCS Connect Initial failed: {}", e);
                        e
                    })
                    .and_then(
                        move |(client_transport, server_transport, connect_response, filter_config)| {
                            info!(client_logger, "MCS Connect Response redirected successfully");
                            Ok((
                                client_transport,
                                server_transport,
                                connect_initial,
                                connect_response,
                                filter_config,
                                client_logger,
                            ))
                        },
                    )
                },
            )
            .and_then(
                move |(
                    client_transport,
                    server_transport,
                    connect_initial,
                    connect_response,
                    filter_config,
                    client_logger,
                )| {
                    let client_logger_clone = client_logger.clone();
                    let client_transport = McsTransport::default().framed(client_transport.into_inner());
                    let server_transport = McsTransport::default().framed(server_transport.into_inner());

                    let channel_names = connect_initial.channel_names();
                    let channel_ids = connect_response.channel_ids();
                    let global_channel_id = connect_response.global_channel_id();
                    let channels = channel_ids
                        .into_iter()
                        .zip(channel_names.into_iter().map(|v| v.name))
                        .chain(iter::once((
                            global_channel_id,
                            mcs_future::GLOBAL_CHANNEL_NAME.to_string(),
                        )))
                        .collect::<mcs_future::StaticChannels>();

                    McsFuture::new(client_transport, server_transport, channels, client_logger.clone())
                        .map_err(move |e| {
                            error!(client_logger_clone, "MCS Connection Sequence failed: {}", e);
                            io::Error::new(io::ErrorKind::Other, e.compat())
                        })
                        .and_then(|(client_transport, server_transport, static_channels)| {
                            debug!(client_logger, "Static channels: {:?}", static_channels);
                            info!(
                                client_logger,
                                "MCS Connection Sequence finished, static channels collected"
                            );

                            Ok((
                                client_transport,
                                server_transport,
                                static_channels,
                                filter_config,
                                client_logger,
                            ))
                        })
                },
            )
            .and_then(
                move |(client_transport, server_transport, static_channels, filter_config, client_logger)| {
                    let client_logger_clone = client_logger.clone();

                    RdpFuture::new(client_transport, server_transport, filter_config, client_logger.clone())
                        .map_err(move |e| {
                            error!(client_logger_clone, "RDP Connection Sequence failed: {}", e);
                            io::Error::new(io::ErrorKind::Other, e.compat())
                        })
                        .and_then(move |(client_transport, server_transport, filter_config)| {
                            info!(client_logger, "RDP Connection Sequence finished");

                            Ok((
                                client_transport,
                                server_transport,
                                static_channels,
                                filter_config,
                                client_logger,
                            ))
                        })
                },
            )
            .and_then(
                move |(client_transport, server_transport, _static_channels, _filter, client_logger)| {
                    let client_tls = client_transport.into_inner();
                    let server_tls = server_transport.into_inner();

                    Proxy::new(config_clone)
                        .build(TcpTransport::new_tls(server_tls), TcpTransport::new_tls(client_tls))
                        .map_err(move |e| {
                            error!(client_logger, "proxy error: {}", e);
                            e
                        })
                },
            )
            .map_err(move |e| io::Error::new(io::ErrorKind::Other, format!("RDP failed: {}", e)));

        Box::new(future) as Box<dyn Future<Item = (), Error = io::Error> + Send>
    }
}

fn negotiate_with_client(
    client: TcpStream,
    client_logger: slog::Logger,
) -> impl Future<
    Item = (
        Framed<TcpStream, X224Transport>,
        rdp_proto::SecurityProtocol,
        rdp_proto::NegotiationRequestFlags,
    ),
    Error = io::Error,
> + Send {
    let client_transport = X224Transport::new().framed(client);
    client_transport
        .into_future()
        .map_err(|(e, _)| e)
        .and_then(move |(req, client_transport)| {
            if let Some((code, buf)) = req {
                let (nego_data, request_protocol, request_flags) =
                    rdp_proto::parse_negotiation_request(code, buf.as_ref())?;
                let (routing_token, cookie) = match nego_data {
                    Some(rdp_proto::NegoData::RoutingToken(routing_token)) => (Some(routing_token), None),
                    Some(rdp_proto::NegoData::Cookie(cookie)) => (None, Some(cookie)),
                    None => (None, None),
                };
                info!(
                    client_logger,
                    "processing request (routing_token: {:?}, cookie: {:?}, protocol: {:?}, flags: {:?})",
                    routing_token,
                    cookie,
                    request_protocol,
                    request_flags
                );

                // For now, do not add EXTENDED_CLIENT_DATA_SUPPORTED flag to reduce optional GCC blocks
                let response_flags = rdp_proto::NegotiationResponseFlags::DYNVC_GFX_PROTOCOL_SUPPORTED
                    | rdp_proto::NegotiationResponseFlags::RDP_NEG_RSP_RESERVED
                    | rdp_proto::NegotiationResponseFlags::RESTRICTED_ADMIN_MODE_SUPPORTED
                    | rdp_proto::NegotiationResponseFlags::REDIRECTED_AUTHENTICATION_MODE_SUPPORTED;
                let response_protocol = if request_protocol.contains(rdp_proto::SecurityProtocol::HYBRID_EX) {
                    rdp_proto::SecurityProtocol::HYBRID_EX
                } else {
                    rdp_proto::SecurityProtocol::HYBRID
                };

                let mut response_data = BytesMut::new();
                response_data.resize(rdp_proto::NEGOTIATION_RESPONSE_LEN, 0);
                rdp_proto::write_negotiation_response(response_data.as_mut(), response_flags, response_protocol)?;

                Ok(client_transport
                    .send((rdp_proto::X224TPDUType::ConnectionConfirm, response_data))
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("failed to send negotiation response: {}", e),
                        )
                    })
                    .and_then(move |client_transport| Ok((client_transport, request_protocol, request_flags))))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client closed connection before sending complete negotiation request",
                ))
            }
        })
        .and_then(|f| f)
}

fn establish_tls_connection_with_client(
    client: TcpStream,
    tls_acceptor: TlsAcceptor,
) -> impl Future<Item = TlsStream<TcpStream>, Error = io::Error> + Send {
    tls_acceptor.accept(client).map_err(move |e| {
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("failed to accept a client connection: {}", e),
        )
    })
}

fn process_cred_ssp_with_client(
    client: TlsStream<TcpStream>,
    proxy_public_key: Vec<u8>,
    identities_proxy: IdentitiesProxy,
) -> impl Future<Item = (Framed<TlsStream<TcpStream>, TsRequestTransport>, RdpIdentity), Error = io::Error> + Send {
    future::lazy(move || {
        let client_transport = TsRequestTransport::new().framed(client);

        let server_context = CredSspServerFuture::new(
            client_transport,
            rdp_proto::CredSspServer::new(proxy_public_key, identities_proxy, DEFAULT_NTLM_VERSION.to_vec())?,
        );

        let client_future = server_context.and_then(|(client_transport, rdp_identity, client_credentials)| {
            let expected_credentials = &rdp_identity.proxy;
            if expected_credentials.username == client_credentials.username
                && expected_credentials.password == client_credentials.password
            {
                Ok((client_transport, rdp_identity))
            } else {
                Err(rdp_proto::SspiError::new(
                    rdp_proto::SspiErrorType::MessageAltered,
                    String::from("Got invalid credentials from the client"),
                )
                .into())
            }
        });

        Ok(client_future)
    })
    .and_then(|f| f)
}

fn negotiate_with_server(
    server: ConnectFuture,
    credentials: rdp_proto::Credentials,
    protocol: rdp_proto::SecurityProtocol,
    flags: rdp_proto::NegotiationRequestFlags,
) -> impl Future<Item = (Framed<TcpStream, X224Transport>, rdp_proto::NegotiationRequestFlags), Error = io::Error> + Send
{
    server
        .and_then(move |server| {
            let cookie: &str = credentials.username.as_ref();
            let mut request_data = BytesMut::new();
            request_data.resize(rdp_proto::NEGOTIATION_REQUEST_LEN + cookie.len(), 0);
            rdp_proto::write_negotiation_request(request_data.as_mut(), cookie, protocol, flags)?;

            let server_transport = X224Transport::new().framed(server);

            Ok(server_transport
                .send((rdp_proto::X224TPDUType::ConnectionRequest, request_data))
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to send negotiation request from server: {}", e),
                    )
                })
                .and_then(move |server_transport| Ok((server_transport, flags))))
        })
        .and_then(|f| f)
}

fn process_negotiation_response_from_server(
    server_transport: Framed<TcpStream, X224Transport>,
    client_logger: slog::Logger,
) -> impl Future<Item = (Framed<TcpStream, X224Transport>, Option<rdp_proto::SecurityProtocol>), Error = io::Error> + Send
{
    server_transport
        .into_future()
        .map_err(|(e, _)| e)
        .and_then(move |(req, server_transport)| {
            if let Some((code, buf)) = req {
                if buf.is_empty() {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "invalid negotiation response",
                    ))
                } else {
                    let protocol = match rdp_proto::parse_negotiation_response(code, buf.as_ref()) {
                        Ok((selected_protocol, flags)) => {
                            info!(
                                client_logger,
                                "received negotiation response from server (protocol: {:?}, flags: {:?})",
                                selected_protocol,
                                flags
                            );

                            Some(selected_protocol)
                        }
                        Err(rdp_proto::NegotiationError::NegotiationFailure(code)) => {
                            info!(
                                client_logger,
                                "received negotiation failure from server (code: {:?})", code
                            );

                            None
                        }
                        Err(rdp_proto::NegotiationError::IOError(e)) => return Err(e),
                    };

                    Ok((server_transport, protocol))
                }
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "server closed connection before sending complete negotiation response to client",
                ))
            }
        })
}

fn establish_tls_connection_with_server(
    server: TcpStream,
    server_addr: SocketAddr,
    accept_invalid_certs_and_hostnames: bool,
) -> impl Future<Item = TlsStream<TcpStream>, Error = io::Error> + Send {
    let tls_connector = TlsConnector::builder()
        .danger_accept_invalid_certs(accept_invalid_certs_and_hostnames)
        .danger_accept_invalid_hostnames(accept_invalid_certs_and_hostnames)
        .build()
        .unwrap();
    let tls_connector = tokio_tls::TlsConnector::from(tls_connector);
    tls_connector
        .connect(&server_addr.ip().to_string(), server)
        .map_err(move |e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("failed to handshake with a server: {}", e),
            )
        })
}

fn process_cred_ssp_with_server(
    server_tls: TlsStream<TcpStream>,
    target_identity: rdp_proto::Credentials,
    nego_flags: rdp_proto::NegotiationRequestFlags,
) -> impl Future<Item = Framed<TlsStream<TcpStream>, TsRequestTransport>, Error = io::Error> + Send {
    future::lazy(move || {
        let client_public_key = get_tls_peer_pubkey(&server_tls)?;
        let server_transport = TsRequestTransport::new().framed(server_tls);

        let client_context = CredSspClientFuture::new(
            server_transport,
            rdp_proto::CredSspClient::new(
                client_public_key,
                target_identity,
                DEFAULT_NTLM_VERSION.to_vec(),
                nego_flags,
            )?,
        );

        Ok(client_context)
    })
    .and_then(|f| f)
}

fn process_early_auth_result(
    client_tls: TlsStream<TcpStream>,
    server_tls: TlsStream<TcpStream>,
) -> impl Future<Item = (TlsStream<TcpStream>, TlsStream<TcpStream>), Error = io::Error> + Send {
    future::lazy(|| {
        let buffer = [0; rdp_proto::EARLY_USER_AUTH_RESULT_PDU_SIZE];
        tokio::io::read_exact(server_tls, buffer)
            .and_then(
                move |(server_tls, buffer)| match rdp_proto::EarlyUserAuthResult::from_buffer(buffer.as_ref())? {
                    rdp_proto::EarlyUserAuthResult::Success => Ok(tokio::io::write_all(client_tls, buffer)
                        .and_then(move |(client_tls, _)| Ok((client_tls, server_tls)))),
                    _ => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "The user does not have permission to access the server",
                    )),
                },
            )
            .and_then(|f| f)
    })
}

fn process_mcs_connect_initial(
    client_transport: Framed<TlsStream<TcpStream>, X224Transport>,
    server_transport: Framed<TlsStream<TcpStream>, X224Transport>,
    filter_config: FilterConfig,
    client_logger: slog::Logger,
) -> impl Future<
    Item = (
        Framed<TlsStream<TcpStream>, X224Transport>,
        Framed<TlsStream<TcpStream>, X224Transport>,
        rdp_proto::ConnectInitial,
        FilterConfig,
    ),
    Error = io::Error,
> + Send {
    let client_logger_clone = client_logger.clone();

    client_transport
        .into_future()
        .map_err(|(e, _)| e)
        .and_then(move |(req, client_transport)| {
            if let Some((code, buf)) = req {
                if code == rdp_proto::X224TPDUType::Data {
                    let mut connect_initial =
                        rdp_proto::ConnectInitial::from_buffer(buf.as_ref()).map_err(move |e| {
                            error!(client_logger_clone, "MCS Connect Initial failed: {}", e);
                            io::Error::new(io::ErrorKind::Other, format!("{}", e))
                        })?;
                    debug!(client_logger, "Connect Initial PDU: {:?}", connect_initial);

                    connect_initial.filter(&filter_config);
                    debug!(client_logger, "Filtered Connect Initial PDU: {:?}", connect_initial);

                    let mut response_data = BytesMut::new();
                    response_data.resize(connect_initial.buffer_length(), 0);
                    connect_initial.to_buffer(response_data.as_mut()).map_err(move |e| {
                        error!(client_logger, "MCS Connect Initial failed: {}", e);
                        io::Error::new(io::ErrorKind::Other, format!("{}", e))
                    })?;

                    Ok(server_transport
                        .send((rdp_proto::X224TPDUType::Data, buf))
                        .map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("failed to send negotiation response: {}", e),
                            )
                        })
                        .and_then(move |server_transport| {
                            Ok((client_transport, server_transport, connect_initial, filter_config))
                        }))
                } else {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "client sent invalid PDU"))
                }
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client closed connection before sending complete MCS Connect Initial PDU",
                ))
            }
        })
        .and_then(|f| f)
}

fn process_mcs_connect_response(
    client_transport: Framed<TlsStream<TcpStream>, X224Transport>,
    server_transport: Framed<TlsStream<TcpStream>, X224Transport>,
    filter_config: FilterConfig,
    client_logger: slog::Logger,
) -> impl Future<
    Item = (
        Framed<TlsStream<TcpStream>, X224Transport>,
        Framed<TlsStream<TcpStream>, X224Transport>,
        rdp_proto::ConnectResponse,
        FilterConfig,
    ),
    Error = io::Error,
> + Send {
    let client_logger_clone = client_logger.clone();

    server_transport
        .into_future()
        .map_err(|(e, _)| e)
        .and_then(move |(req, server_transport)| {
            if let Some((code, buf)) = req {
                if code == rdp_proto::X224TPDUType::Data {
                    let mut connect_response =
                        rdp_proto::ConnectResponse::from_buffer(buf.as_ref()).map_err(move |e| {
                            error!(client_logger_clone, "MCS Connect Response failed: {}", e);
                            io::Error::new(io::ErrorKind::Other, format!("{}", e))
                        })?;
                    debug!(client_logger, "Connect Response PDU: {:?}", connect_response);

                    connect_response.filter(&filter_config);
                    debug!(client_logger, "Filtered Connect Response PDU: {:?}", connect_response);

                    let mut response_data = BytesMut::new();
                    response_data.resize(connect_response.buffer_length(), 0);
                    connect_response.to_buffer(response_data.as_mut()).map_err(move |e| {
                        error!(client_logger, "MCS Connect Response failed: {}", e);
                        io::Error::new(io::ErrorKind::Other, format!("{}", e))
                    })?;

                    Ok(client_transport
                        .send((rdp_proto::X224TPDUType::Data, response_data))
                        .map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("failed to send negotiation response: {}", e),
                            )
                        })
                        .and_then(move |client_transport| {
                            Ok((client_transport, server_transport, connect_response, filter_config))
                        }))
                } else {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "server sent invalid PDU"))
                }
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "server closed connection before sending complete MCS Connect Response PDU",
                ))
            }
        })
        .and_then(|f| f)
}
