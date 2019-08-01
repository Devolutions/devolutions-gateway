use std::io;

use futures::{try_ready, Future};
use ironrdp::{NegotiationRequestFlags, SecurityProtocol};
use tokio::{codec::Decoder, prelude::*};
use tokio_tcp::{ConnectFuture, TcpStream};
use tokio_tls::{TlsAcceptor, TlsStream};

use crate::{
    rdp::{
        filter::FilterConfig,
        identities_proxy::{IdentitiesProxy, RdpIdentity},
        sequence_future::{
            create_negotiation_request, FutureState, McsFuture, McsFutureTransport, McsInitialFuture,
            NegotiationWithClientFuture, NegotiationWithClientFutureResponse, NegotiationWithServerFuture,
            NlaWithClientFuture, NlaWithServerFuture, PostMcs, SequenceFuture, StaticChannels,
        },
    },
    transport::{mcs::McsTransport, x224::X224Transport},
};

pub struct ConnectionSequenceFuture {
    state: ConnectionSequenceFutureState,
    client_tls: Option<TlsStream<TcpStream>>,
    tls_proxy_pubkey: Option<Vec<u8>>,
    tls_acceptor: Option<TlsAcceptor>,
    identities_proxy: Option<IdentitiesProxy>,
    client_request_protocol: SecurityProtocol,
    client_request_flags: NegotiationRequestFlags,
    rdp_identity: Option<RdpIdentity>,
    filter_config: Option<FilterConfig>,
    joined_static_channels: Option<StaticChannels>,
    client_logger: slog::Logger,
}

impl ConnectionSequenceFuture {
    pub fn new(
        client: TcpStream,
        tls_proxy_pubkey: Vec<u8>,
        tls_acceptor: TlsAcceptor,
        identities_proxy: IdentitiesProxy,
        client_logger: slog::Logger,
    ) -> Self {
        Self {
            state: ConnectionSequenceFutureState::NegotiationWithClient(Box::new(SequenceFuture {
                future: NegotiationWithClientFuture::new(),
                client: Some(X224Transport::default().framed(client)),
                server: None,
                send_future: None,
                pdu: None,
                future_state: FutureState::GetMessage,
                client_logger: client_logger.clone(),
            })),
            client_tls: None,
            tls_proxy_pubkey: Some(tls_proxy_pubkey),
            tls_acceptor: Some(tls_acceptor),
            identities_proxy: Some(identities_proxy),
            client_request_protocol: SecurityProtocol::empty(),
            client_request_flags: NegotiationRequestFlags::empty(),
            rdp_identity: None,
            filter_config: None,
            joined_static_channels: None,
            client_logger,
        }
    }

    fn create_nla_client_future(
        &mut self,
        client: TcpStream,
        client_response_protocol: SecurityProtocol,
    ) -> NlaWithClientFuture {
        NlaWithClientFuture::new(
            client,
            client_response_protocol,
            self.tls_proxy_pubkey
                .take()
                .expect("TLS proxy public key must be set in the constructor"),
            self.identities_proxy
                .take()
                .expect("Identities proxy must be set in the constructor"),
            self.tls_acceptor
                .take()
                .expect("TLS acceptor must be set in the constructor"),
            self.client_logger.clone(),
        )
    }
    fn create_connect_server_future(&self) -> io::Result<ConnectFuture> {
        let destination = self
            .rdp_identity
            .as_ref()
            .expect("The RDP identity must be set after the client negotiation")
            .destination
            .clone();
        let destination_addr = destination.parse().map_err(move |e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Invalid target destination ({}): {}", destination, e),
            )
        })?;

        Ok(TcpStream::connect(&destination_addr))
    }
    fn create_server_negotiation_future(
        &self,
        server: TcpStream,
    ) -> io::Result<SequenceFuture<NegotiationWithServerFuture, TcpStream, X224Transport>> {
        let server_transport = X224Transport::default().framed(server);

        let target_credentials = self.rdp_identity
            .as_ref()
            .expect("The RDP identity must be set after the client negotiation and be taken by reference in the connect server state")
            .target.clone();
        let pdu = create_negotiation_request(
            target_credentials,
            self.client_request_protocol,
            self.client_request_flags,
        )?;
        let send_future = Some(server_transport.send(pdu));

        Ok(SequenceFuture {
            future: NegotiationWithServerFuture::new(),
            client: None,
            server: None,
            send_future,
            pdu: None,
            future_state: FutureState::SendMessage,
            client_logger: self.client_logger.clone(),
        })
    }
    fn create_nla_server_future(
        &self,
        server: TcpStream,
        server_response_protocol: SecurityProtocol,
    ) -> io::Result<NlaWithServerFuture> {
        NlaWithServerFuture::new(
            server,
            self.client_request_flags,
            server_response_protocol,
            self.rdp_identity
                .as_ref()
                .expect("The RDP identity must be set after the client negotiation and be taken by reference in the server negotiation state").target.clone(),
            true,
            self.client_logger.clone(),
        )
    }
    fn create_mcs_initial_future(
        &mut self,
        server_tls: TlsStream<TcpStream>,
    ) -> SequenceFuture<McsInitialFuture, TlsStream<TcpStream>, X224Transport> {
        let client_tls = self
            .client_tls
            .take()
            .expect("For the McsInitial state, the client TLS stream must be set after the client negotiation");

        SequenceFuture {
            future: McsInitialFuture::new(FilterConfig::new(
                self.rdp_identity
                    .as_ref()
                    .expect("the RDP identity must be set after the server NLA")
                    .proxy
                    .clone(),
            )),
            client: Some(X224Transport::default().framed(client_tls)),
            server: Some(X224Transport::default().framed(server_tls)),
            send_future: None,
            pdu: None,
            future_state: FutureState::GetMessage,
            client_logger: self.client_logger.clone(),
        }
    }
    fn create_mcs_future(
        &mut self,
        server_tls: TlsStream<TcpStream>,
        static_channels: StaticChannels,
    ) -> SequenceFuture<McsFuture, TlsStream<TcpStream>, McsTransport> {
        let client_tls = self
            .client_tls
            .take()
            .expect("the client TLS stream must be set after the MCS initial");

        SequenceFuture {
            future: McsFuture::new(static_channels),
            client: Some(McsTransport::default().framed(client_tls)),
            server: Some(McsTransport::default().framed(server_tls)),
            send_future: None,
            pdu: None,
            future_state: FutureState::GetMessage,
            client_logger: self.client_logger.clone(),
        }
    }
    fn create_rdp_future(
        &mut self,
        client_transport: McsFutureTransport,
        server_transport: McsFutureTransport,
    ) -> SequenceFuture<PostMcs, TlsStream<TcpStream>, McsTransport> {
        SequenceFuture {
            future: PostMcs::new(
                self.filter_config
                    .take()
                    .expect("the filter config must be set after the MCS initial"),
            ),
            client: Some(client_transport),
            server: Some(server_transport),
            send_future: None,
            pdu: None,
            future_state: FutureState::GetMessage,
            client_logger: self.client_logger.clone(),
        }
    }
}

impl Future for ConnectionSequenceFuture {
    type Item = (TlsStream<TcpStream>, TlsStream<TcpStream>, StaticChannels);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match &mut self.state {
                ConnectionSequenceFutureState::NegotiationWithClient(negotiation_future) => {
                    let NegotiationWithClientFutureResponse {
                        transport,
                        client_request_protocol,
                        client_request_flags,
                        client_response_protocol,
                        ..
                    } = try_ready!(negotiation_future.poll());
                    self.client_request_protocol = client_request_protocol;
                    self.client_request_flags = client_request_flags;

                    let client = transport.into_inner();

                    self.state = ConnectionSequenceFutureState::NlaWithClient(Box::new(
                        self.create_nla_client_future(client, client_response_protocol),
                    ));
                }
                ConnectionSequenceFutureState::NlaWithClient(nla_future) => {
                    let (client_tls, rdp_identity) = try_ready!(nla_future.poll());
                    self.client_tls = Some(client_tls);
                    self.rdp_identity = Some(rdp_identity);

                    self.state = ConnectionSequenceFutureState::ConnectToServer(self.create_connect_server_future()?);
                }
                ConnectionSequenceFutureState::ConnectToServer(connect_future) => {
                    let server = try_ready!(connect_future.poll());

                    self.state = ConnectionSequenceFutureState::NegotiationWithServer(Box::new(
                        self.create_server_negotiation_future(server)?,
                    ));
                }
                ConnectionSequenceFutureState::NegotiationWithServer(negotiation_future) => {
                    let (server_transport, response_protocol, _response_flags) = try_ready!(negotiation_future.poll());

                    let server = server_transport.into_inner();

                    self.state = ConnectionSequenceFutureState::NlaWithServer(Box::new(
                        self.create_nla_server_future(server, response_protocol)?,
                    ));
                }
                ConnectionSequenceFutureState::NlaWithServer(nla_future) => {
                    let server_tls = try_ready!(nla_future.poll());

                    self.state =
                        ConnectionSequenceFutureState::McsInitial(Box::new(self.create_mcs_initial_future(server_tls)))
                }
                ConnectionSequenceFutureState::McsInitial(mcs_initial_future) => {
                    let (client_transport, server_transport, filter_config, static_channels) =
                        try_ready!(mcs_initial_future.poll());
                    self.filter_config = Some(filter_config);
                    self.client_tls = Some(client_transport.into_inner());

                    let server_tls = server_transport.into_inner();

                    self.state = ConnectionSequenceFutureState::Mcs(Box::new(
                        self.create_mcs_future(server_tls, static_channels),
                    ));
                }
                ConnectionSequenceFutureState::Mcs(mcs_future) => {
                    let (client_transport, server_transport, joined_static_channels) = try_ready!(mcs_future.poll());
                    self.joined_static_channels = Some(joined_static_channels);

                    self.state = ConnectionSequenceFutureState::PostMcs(Box::new(
                        self.create_rdp_future(client_transport, server_transport),
                    ));
                }
                ConnectionSequenceFutureState::PostMcs(rdp_future) => {
                    let (client_transport, server_transport, _filter_config) = try_ready!(rdp_future.poll());

                    let client_tls = client_transport.into_inner();
                    let server_tls = server_transport.into_inner();

                    return Ok(Async::Ready((
                        client_tls,
                        server_tls,
                        self.joined_static_channels.take().expect(
                            "During RDP connection sequence, the joined static channels must exist in the RDP state",
                        ),
                    )));
                }
            }
        }
    }
}

enum ConnectionSequenceFutureState {
    NegotiationWithClient(Box<SequenceFuture<NegotiationWithClientFuture, TcpStream, X224Transport>>),
    NlaWithClient(Box<NlaWithClientFuture>),
    ConnectToServer(ConnectFuture),
    NegotiationWithServer(Box<SequenceFuture<NegotiationWithServerFuture, TcpStream, X224Transport>>),
    NlaWithServer(Box<NlaWithServerFuture>),
    McsInitial(Box<SequenceFuture<McsInitialFuture, TlsStream<TcpStream>, X224Transport>>),
    Mcs(Box<SequenceFuture<McsFuture, TlsStream<TcpStream>, McsTransport>>),
    PostMcs(Box<SequenceFuture<PostMcs, TlsStream<TcpStream>, McsTransport>>),
}
