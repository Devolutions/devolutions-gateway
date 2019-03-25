mod credssp_stream;

use std::{fs::File, io, io::prelude::*};

use bytes::BytesMut;
use futures::{Future, Stream};
use native_tls::TlsConnector;
use serde_derive::{Deserialize, Serialize};
use slog::{error, info, Drain};
use tokio::{
    codec::{Decoder, Framed},
    net::tcp::ConnectFuture,
    prelude::*,
    runtime::TaskExecutor,
};
use tokio_tcp::TcpStream;
use tokio_tls::{TlsAcceptor, TlsStream};
use url::Url;

use self::credssp_stream::{CredSspManagerResult, CredSspStream};
use crate::{
    config::Config,
    transport::{tcp::TcpTransport, tsrequest::TsRequestTransport, x224::X224Transport},
    utils::{get_tls_peer_pubkey, url_to_socket_arr},
    Proxy,
};

const DEFAULT_NTLM_VERSION: [u8; rdp_proto::NTLM_VERSION_SIZE] = [0x00; rdp_proto::NTLM_VERSION_SIZE];

pub struct RdpClient {
    routing_url: Url,
    config: Config,
    executor_handle: TaskExecutor,
    tls_public_key: Vec<u8>,
    tls_acceptor: TlsAcceptor,
}

#[derive(Serialize, Deserialize)]
struct Identities {
    pub proxy: rdp_proto::Credentials,
    pub targets: Vec<rdp_proto::Credentials>,
}

const LOGGER_TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

struct NegotiationResponseResult {
    protocol: Option<rdp_proto::SecurityProtocol>,
    send_future: futures::sink::Send<Framed<TcpStream, X224Transport>>,
}

fn create_client_logger(client_addr: String) -> slog::Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator)
        .use_custom_timestamp(|output: &mut io::Write| -> io::Result<()> {
            write!(output, "{}", chrono::Utc::now().format(LOGGER_TIMESTAMP_FORMAT))
        })
        .build()
        .fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    slog::Logger::root(drain, slog::o!("client" => client_addr))
}

fn read_identities(identities_file_name: &str) -> io::Result<Identities> {
    let mut f = File::open(identities_file_name)?;
    let mut contents = String::new();
    f.read_to_string(&mut contents)?;

    Ok(serde_json::from_str(&contents).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to read the json data: {}", e),
        )
    })?)
}

impl RdpClient {
    pub fn new(
        routing_url: Url,
        config: Config,
        executor_handle: TaskExecutor,
        tls_public_key: Vec<u8>,
        tls_acceptor: TlsAcceptor,
    ) -> Self {
        Self {
            routing_url,
            config,
            executor_handle,
            tls_public_key,
            tls_acceptor,
        }
    }

    pub fn serve(self, transport: TcpStream) -> Box<dyn Future<Item = (), Error = io::Error> + Send> {
        let client_addr = transport
            .peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| String::from("unknown"));
        let client_logger = create_client_logger(client_addr);

        let client = X224Transport::new().framed(transport);
        let routing_url = self.routing_url.clone();

        let future = client.into_future().map_err(|(e, _)| e).and_then(move |(req, client)| {
            if let Some((code, buf)) = req {
                let (cookie, protocol, flags) = rdp_proto::parse_negotiation_request(code, buf.as_ref())?;
                info!(
                    client_logger,
                    "processing request (cookie: {}, protocol: {:?}, flags: {:?})", cookie, protocol, flags
                );

                let server_addr = url_to_socket_arr(&routing_url);
                let server = TcpStream::connect(&server_addr);
                let client_logger_clone = client_logger.clone();
                let config_clone = self.config.clone();

                let identities_filename = self
                    .config
                    .identities_filename()
                    .expect("Identities file name is present");
                let identities = read_identities(identities_filename.as_ref())?;
                let proxy_identity = identities.proxy.clone();
                let target_identity = identities
                    .targets
                    .iter()
                    .find(|credentials| credentials.username == cookie)
                    .ok_or_else(|| {
                        rdp_proto::SspiError::new(
                            rdp_proto::SspiErrorType::TargetUnknown,
                            format!("Failed to find credentials with the username: {}", cookie),
                        )
                    })?
                    .clone();
                let tls_public_key = self.tls_public_key;
                let tls_acceptor = self.tls_acceptor;

                let server_fut = negotiate_with_server(server, client, client_logger.clone(), cookie, protocol, flags)
                    .map_err(move |e| {
                        io::Error::new(io::ErrorKind::Other, format!("negotiation of client failed: {}", e))
                    })
                    .and_then(move |(protocol, server, client_fut)| {
                        client_fut
                            .map_err(move |e| {
                                io::Error::new(io::ErrorKind::Other, format!("negotiation of server failed: {}", e))
                            })
                            .and_then(move |client| {
                                let client = client.into_inner();
                                let server = server.into_inner();
                                let create_proxy = move |client_transport, server_transport| {
                                    Proxy::new(config_clone)
                                        .build(server_transport, client_transport)
                                        .map_err(move |e| {
                                            io::Error::new(io::ErrorKind::Other, format!("Proxy error: {}", e))
                                        })
                                };

                                match protocol {
                                    rdp_proto::SecurityProtocol::HYBRID
                                    | rdp_proto::SecurityProtocol::HYBRID_EX
                                    | rdp_proto::SecurityProtocol::SSL => {
                                        let accept_invalid_certs_and_hostnames = match protocol {
                                            rdp_proto::SecurityProtocol::HYBRID
                                            | rdp_proto::SecurityProtocol::HYBRID_EX => true,
                                            _ => false,
                                        };
                                        Ok(future::Either::A(
                                            establish_tls_connection(
                                                client,
                                                server,
                                                client_logger_clone.clone(),
                                                tls_acceptor,
                                                routing_url,
                                                accept_invalid_certs_and_hostnames,
                                            )
                                            .and_then(
                                                move |(client_tls, server_tls)| {
                                                    let fut = match protocol {
                                                        rdp_proto::SecurityProtocol::HYBRID
                                                        | rdp_proto::SecurityProtocol::HYBRID_EX => future::Either::A(
                                                            process_credssp_phase(
                                                                client_tls,
                                                                server_tls,
                                                                target_identity,
                                                                proxy_identity,
                                                                flags,
                                                                tls_public_key,
                                                            )
                                                            .map_err(move |e| {
                                                                io::Error::new(
                                                                    io::ErrorKind::Other,
                                                                    format!("CredSSP failed: {}", e),
                                                                )
                                                            })
                                                            .and_then(move |(client_tls, server_tls)| {
                                                                info!(client_logger_clone, "CredSSP phase finished");
                                                                future::ok((client_tls, server_tls))
                                                            }),
                                                        ),
                                                        _ => future::Either::B(future::ok((client_tls, server_tls))),
                                                    };

                                                    fut.and_then(move |(client_tls, server_tls)| {
                                                        create_proxy(
                                                            TcpTransport::new_tls(client_tls),
                                                            TcpTransport::new_tls(server_tls),
                                                        )
                                                    })
                                                },
                                            ),
                                        ))
                                    }
                                    rdp_proto::SecurityProtocol::RDP => Ok(future::Either::B(create_proxy(
                                        TcpTransport::new(client),
                                        TcpTransport::new(server),
                                    ))),
                                    _ => Err(io::Error::new(
                                        io::ErrorKind::NotConnected,
                                        "cannot connect security layer because no protocol has been selected yet",
                                    )),
                                }
                            })
                            .and_then(|fut| fut)
                    })
                    .map_err(move |e| error!(client_logger, "RDP error: {}", e));

                self.executor_handle.spawn(server_fut);

                Ok(())
            } else {
                error!(
                    client_logger,
                    "client closed connection before sending complete negotiation request"
                );
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected end of client stream",
                ))
            }
        });

        Box::new(future) as Box<Future<Item = (), Error = io::Error> + Send>
    }
}

fn negotiate_with_server(
    server: ConnectFuture,
    client: Framed<TcpStream, X224Transport>,
    client_logger: slog::Logger,
    cookie: String,
    protocol: rdp_proto::SecurityProtocol,
    flags: rdp_proto::NegotiationRequestFlags,
) -> impl Future<
    Item = (
        rdp_proto::SecurityProtocol,
        Framed<TcpStream, X224Transport>,
        impl Future<Item = Framed<TcpStream, X224Transport>, Error = io::Error> + Send,
    ),
    Error = io::Error,
> + Send {
    server
        .and_then(move |server_conn| {
            let mut request_data = BytesMut::new();
            request_data.resize(rdp_proto::NEGOTIATION_REQUEST_LEN + cookie.len(), 0);
            rdp_proto::write_negotiation_request(request_data.as_mut(), &cookie, protocol, flags).unwrap();

            let server = X224Transport::new().framed(server_conn);
            server.send((rdp_proto::X224TPDUType::ConnectionRequest, request_data))
        })
        .and_then(move |server| {
            server.into_future().map_err(|(e, _)| e).and_then(move |(req, server)| {
                if let Some((code, buf)) = req {
                    let negotiation_response_result =
                        process_negotiation_response(buf, client, client_logger.clone(), code, protocol)?;

                    if let Some(protocol) = negotiation_response_result.protocol {
                        Ok((protocol, server, negotiation_response_result.send_future))
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::Other,
                            "server returned negotiation error",
                        ))
                    }
                } else {
                    error!(
                        client_logger,
                        "server closed connection before sending complete negotiation response to client"
                    );
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected end of server stream",
                    ))
                }
            })
        })
}

fn process_negotiation_response(
    buf: BytesMut,
    client: Framed<TcpStream, X224Transport>,
    client_logger: slog::Logger,
    code: rdp_proto::X224TPDUType,
    protocol: rdp_proto::SecurityProtocol,
) -> io::Result<NegotiationResponseResult> {
    if buf.is_empty() {
        if protocol == rdp_proto::SecurityProtocol::RDP {
            info!(
                client_logger,
                "received negotiation response for client (protocol: {:?})", protocol
            );
            Ok(NegotiationResponseResult {
                protocol: Some(rdp_proto::SecurityProtocol::RDP),
                send_future: client.send((rdp_proto::X224TPDUType::ConnectionConfirm, buf)),
            })
        } else {
            error!(client_logger, "invalid negotiation response");
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "invalid negotiation response",
            ))
        }
    } else {
        let mut response_data = BytesMut::new();
        response_data.resize(rdp_proto::NEGOTIATION_RESPONSE_LEN, 0);

        match rdp_proto::parse_negotiation_response(code, buf.as_ref()) {
            Ok((selected_protocol, flags)) => {
                info!(
                    client_logger,
                    "received negotiation response for client (protocol: {:?}, flags: {:?})", selected_protocol, flags
                );

                rdp_proto::write_negotiation_response(response_data.as_mut(), flags, selected_protocol).unwrap();
                Ok(NegotiationResponseResult {
                    protocol: Some(selected_protocol),
                    send_future: client.send((rdp_proto::X224TPDUType::ConnectionConfirm, response_data)),
                })
            }
            Err(rdp_proto::NegotiationError::NegotiationFailure(code)) => {
                info!(
                    client_logger,
                    "received negotiation failure from the server (code: {:?})", code
                );

                rdp_proto::write_negotiation_response_error(response_data.as_mut(), code).unwrap();
                Ok(NegotiationResponseResult {
                    protocol: None,
                    send_future: client.send((rdp_proto::X224TPDUType::ConnectionConfirm, response_data)),
                })
            }
            Err(rdp_proto::NegotiationError::IOError(e)) => Err(e),
        }
    }
}

fn establish_tls_connection(
    client: TcpStream,
    server: TcpStream,
    client_logger: slog::Logger,
    tls_acceptor: TlsAcceptor,
    routing_url: Url,
    accept_invalid_certs_and_hostnames: bool,
) -> impl Future<Item = (TlsStream<TcpStream>, TlsStream<TcpStream>), Error = io::Error> + Send {
    tls_acceptor
        .accept(client)
        .map_err(move |e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("failed to accept client connection: {}", e),
            )
        })
        .and_then(move |client_tls| {
            info!(client_logger, "tls connection has been created with client");

            let tls_connector = TlsConnector::builder()
                .danger_accept_invalid_certs(accept_invalid_certs_and_hostnames)
                .danger_accept_invalid_hostnames(accept_invalid_certs_and_hostnames)
                .build()
                .unwrap();
            let tls_connector = tokio_tls::TlsConnector::from(tls_connector);

            let tls_handshake = tls_connector
                .connect(routing_url.host_str().unwrap(), server)
                .map_err(move |e| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("failed to handshake with a server: {}", e),
                    )
                });

            tls_handshake.and_then(move |server_tls| {
                info!(client_logger, "tls connection has been created with server");

                future::ok((client_tls, server_tls))
            })
        })
}

fn process_credssp_phase(
    client_tls: TlsStream<TcpStream>,
    server_tls: TlsStream<TcpStream>,
    target_identity: rdp_proto::Credentials,
    proxy_identity: rdp_proto::Credentials,
    nego_flags: rdp_proto::NegotiationRequestFlags,
    proxy_public_key: Vec<u8>,
) -> impl Future<Item = (TlsStream<TcpStream>, TlsStream<TcpStream>), Error = io::Error> + Send {
    future::lazy(move || {
        let client_public_key = get_tls_peer_pubkey(&server_tls)?;
        let client_transport = TsRequestTransport::new().framed(client_tls);
        let server_transport = TsRequestTransport::new().framed(server_tls);

        let client_context = CredSspStream::new_for_client(
            server_transport,
            rdp_proto::CredSspClient::new(
                client_public_key,
                target_identity,
                DEFAULT_NTLM_VERSION.to_vec(),
                nego_flags,
            )?,
        );
        let server_context = CredSspStream::new_for_server(
            client_transport,
            rdp_proto::CredSspServer::new(proxy_public_key, proxy_identity, DEFAULT_NTLM_VERSION.to_vec())?,
        );

        let credssp_phase = client_context
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("error in client CredSSP phase: {}", e)))
            .zip(
                server_context
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("error in server CredSSP phase: {}", e))),
            )
            .skip_while(|result| match result {
                (CredSspManagerResult::Done(_), CredSspManagerResult::Done(_)) => future::ok(false),
                _ => future::ok(true),
            })
            .collect();

        let credssp_result = credssp_phase.and_then(move |mut result| {
            let result = result.pop().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "A client or server did not finish CredSSP phase properly",
                )
            })?;
            match result {
                (CredSspManagerResult::Done(client_stream), CredSspManagerResult::Done(server_stream)) => {
                    Ok((client_stream, server_stream))
                }
                _ => unreachable!(),
            }
        });

        Ok(credssp_result)
    })
    .and_then(|cred_ssp_fut| cred_ssp_fut)
}
