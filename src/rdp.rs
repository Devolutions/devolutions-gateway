use std::io;

use bytes::BytesMut;
use futures::Future;
use log::{error, info};
use tokio::{
    codec::{Decoder, Framed},
    net::tcp::ConnectFuture,
    prelude::*,
    runtime::TaskExecutor,
};
use tokio_tcp::TcpStream;
use url::Url;

use crate::{transport::x224::X224Transport, utils::url_to_socket_arr};

pub struct RdpClient {
    routing_url: Url,
    executor_handle: TaskExecutor,
}

impl RdpClient {
    pub fn new(routing_url: Url, executor_handle: TaskExecutor) -> Self {
        Self {
            routing_url,
            executor_handle,
        }
    }

    pub fn serve(self, transport: TcpStream) -> Box<dyn Future<Item = (), Error = io::Error> + Send> {
        let peer_addr = transport
            .peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| String::from("unknown"));
        let client = X224Transport::new().framed(transport);
        let executor_handle = self.executor_handle.clone();
        let future = client.into_future().map_err(|(e, _)| e).and_then(move |(req, client)| {
            if let Some((code, buf)) = req {
                let (cookie, flags, protocol) = rdp_proto::parse_negotiation_request(code, buf.as_ref())?;
                info!(
                    "processing request from {} (cookie: {}, flags: {:?}, protocol: {:?})",
                    peer_addr, cookie, flags, protocol
                );

                let server_addr = url_to_socket_arr(&self.routing_url);
                let server = TcpStream::connect(&server_addr);
                let server_task = negotiate_with_server(server, client, executor_handle, cookie, protocol, flags)
                    .map_err(|e| error!("negotiation failed: {}", e))
                    .and_then(|_| future::ok(()));
                self.executor_handle.spawn(server_task);

                Ok(())
            } else {
                error!(
                    "client {} closed connection before sending complete negotiation request",
                    peer_addr
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
    executor_handle: TaskExecutor,
    cookie: String,
    protocol: rdp_proto::SecurityProtocol,
    flags: rdp_proto::NegotiationRequestFlags,
) -> impl Future<Item = Framed<TcpStream, X224Transport>, Error = io::Error> + Send {
    server
        .and_then(move |server_conn| {
            info!("connected to the server");

            let mut request_data = BytesMut::new();
            request_data.resize(rdp_proto::NEGOTIATION_REQUEST_LEN + cookie.len(), 0);
            rdp_proto::write_negotiation_request(request_data.as_mut(), &cookie, protocol, flags).unwrap();

            let server = X224Transport::new().framed(server_conn);
            server.send((rdp_proto::X224TPDUType::ConnectionRequest, request_data))
        })
        .and_then(move |server| {
            server.into_future().map_err(|(e, _)| e).and_then(move |(req, server)| {
                if let Some((code, buf)) = req {
                    let f = process_negotiation_response(buf, client, code, protocol)?;
                    executor_handle.spawn(
                        f.map(|_| ())
                            .map_err(|e| error!("failed to send negotiation response: {}", e)),
                    );

                    Ok(server)
                } else {
                    error!("server closed connection before sending complete negotiation response",);
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
    code: rdp_proto::X224TPDUType,
    protocol: rdp_proto::SecurityProtocol,
) -> io::Result<futures::sink::Send<Framed<TcpStream, X224Transport>>> {
    if buf.is_empty() {
        if protocol == rdp_proto::SecurityProtocol::RDP {
            info!(
                "received negotiation response from the server (protocol: {:?})",
                protocol
            );
            Ok(client.send((rdp_proto::X224TPDUType::ConnectionConfirm, buf)))
        } else {
            error!("invalid negotiation response");
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "invalid negotiation response",
            ))
        }
    } else {
        match rdp_proto::parse_negotiation_response(code, buf.as_ref()) {
            Ok((selected_protocol, flags)) => {
                info!(
                    "received negotiation response from the server (protocol: {:?}, flags: {:?})",
                    selected_protocol, flags
                );

                let mut response_data = BytesMut::new();
                response_data.resize(rdp_proto::NEGOTIATION_RESPONSE_LEN, 0);
                rdp_proto::write_negotiation_response(response_data.as_mut(), flags, selected_protocol).unwrap();
                Ok(client.send((rdp_proto::X224TPDUType::ConnectionConfirm, response_data)))
            }
            Err(rdp_proto::NegotiationError::NegotiationFailure(code)) => {
                info!("received negotiation failure from the server (code: {:?})", code,);

                let mut response_data = BytesMut::new();
                response_data.resize(rdp_proto::NEGOTIATION_RESPONSE_LEN, 0);
                rdp_proto::write_negotiation_response_error(response_data.as_mut(), code).unwrap();
                Ok(client.send((rdp_proto::X224TPDUType::ConnectionConfirm, response_data)))
            }
            Err(rdp_proto::NegotiationError::IOError(e)) => Err(e),
        }
    }
}
